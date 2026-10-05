//! File calls: stat, list, read, write. Every open goes through `open_checked`, which
//! refuses to follow a symlink that appeared after the policy resolved the path, and
//! in Folders mode refuses to land outside the granted folder.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use sync_policy::Permit;
use sync_proto::methods::{FileKind, ListEntry, ListResult, StatResult, WriteResult};
use sync_proto::{RpcError, code};

/// Most bytes `fs.read` returns; pi's read tool reads whole files.
pub const MAX_READ: u64 = 64 * 1024 * 1024;
/// Most bytes `fs.write` accepts.
pub const MAX_WRITE: u64 = 64 * 1024 * 1024;
/// Most entries `fs.list` returns.
pub const MAX_LIST: usize = 20_000;

pub fn sha256_hex(data: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn io_error(e: io::Error) -> RpcError {
    match e.kind() {
        io::ErrorKind::NotFound => RpcError::new(code::NOT_FOUND, e.to_string()),
        io::ErrorKind::PermissionDenied => RpcError::new(code::IO, e.to_string()),
        _ => {
            #[cfg(unix)]
            if e.raw_os_error() == Some(libc::EXDEV) || e.raw_os_error() == Some(libc::ELOOP) {
                return RpcError::denied(
                    "the path changed under the call (a symlink or a way out of the folder)",
                );
            }
            RpcError::new(code::IO, e.to_string())
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Metadata only (no read access needed, never blocks on a FIFO).
    Path,
    /// A directory to list.
    Dir,
    Read,
    /// Write, creating or truncating.
    Write,
}

#[cfg(target_os = "linux")]
mod imp {
    use super::OpenMode;
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    fn openat2(dirfd: i32, path: &Path, flags: i32, mode: u32, resolve: u64) -> io::Result<File> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::other("path contains a NUL byte"))?;
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC) as u64,
            mode: u64::from(mode),
            resolve,
        };
        // SAFETY: `c` and `how` live across the call; the kernel copies them.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                c.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the syscall returned a new descriptor we own.
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd as i32) }))
    }

    /// Opens a resolved path without following any symlink; with `root`, only
    /// beneath it (`RESOLVE_BENEATH`).
    pub fn open(path: &Path, root: Option<&Path>, mode: OpenMode) -> io::Result<File> {
        let flags = match mode {
            OpenMode::Path => libc::O_PATH,
            OpenMode::Dir => libc::O_RDONLY | libc::O_DIRECTORY,
            OpenMode::Read => libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK,
            OpenMode::Write => libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOCTTY,
        };
        let resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
        // openat2 refuses a mode without O_CREAT.
        let perm = if mode == OpenMode::Write { 0o666 } else { 0 };
        match root {
            Some(root) => {
                let dir = openat2(
                    libc::AT_FDCWD,
                    root,
                    libc::O_PATH | libc::O_DIRECTORY,
                    0,
                    resolve,
                )?;
                let rel = path
                    .strip_prefix(root)
                    .map_err(|_| io::Error::from_raw_os_error(libc::EXDEV))?;
                let rel = if rel.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    rel
                };
                use std::os::fd::AsRawFd;
                openat2(dir.as_raw_fd(), rel, flags, perm, resolve | RESOLVE_BENEATH)
            }
            None => openat2(libc::AT_FDCWD, path, flags, perm, resolve),
        }
    }

    /// Lists the directory behind an open descriptor (not its path, which could
    /// have been swapped since).
    pub fn read_dir(dir: &File) -> io::Result<std::fs::ReadDir> {
        use std::os::fd::AsRawFd;
        std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
    }
}

#[cfg(windows)]
mod imp {
    use super::OpenMode;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW,
    };

    fn final_path(f: &File) -> io::Result<String> {
        let mut buf = vec![0u16; 1024];
        loop {
            // SAFETY: the handle is open and `buf` holds `len` u16s.
            let n = unsafe {
                GetFinalPathNameByHandleW(
                    f.as_raw_handle() as _,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    FILE_NAME_NORMALIZED,
                )
            } as usize;
            if n == 0 {
                return Err(io::Error::last_os_error());
            }
            if n < buf.len() {
                return Ok(String::from_utf16_lossy(&buf[..n]));
            }
            buf.resize(n + 1, 0);
        }
    }

    /// Opens the path, then checks where the handle really points: a junction or
    /// symlink that appeared after the policy check makes the call fail.
    pub fn open(path: &Path, root: Option<&Path>, mode: OpenMode) -> io::Result<File> {
        let mut o = OpenOptions::new();
        match mode {
            OpenMode::Path | OpenMode::Dir => {
                o.read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
            }
            OpenMode::Read => {
                o.read(true);
            }
            OpenMode::Write => {
                // Not truncated on open: a junction swapped in would have emptied
                // the file outside before the check below could refuse it.
                o.write(true).create(true).truncate(false);
            }
        }
        let f = o.open(path)?;
        let real = final_path(&f)?;
        let p = path.to_string_lossy();
        let same = sync_policy::paths::win::within(&real, &p)
            && sync_policy::paths::win::within(&p, &real);
        let inside =
            root.is_none_or(|r| sync_policy::paths::win::within(&real, &r.to_string_lossy()));
        if !same || !inside {
            return Err(io::Error::other(
                "the path changed under the call (a link or a way out of the folder)",
            ));
        }
        if mode == OpenMode::Write {
            f.set_len(0)?;
        }
        Ok(f)
    }

    pub fn read_dir_path(path: &Path) -> io::Result<std::fs::ReadDir> {
        std::fs::read_dir(path)
    }
}

pub fn open_checked(permit: &Permit, mode: OpenMode) -> io::Result<File> {
    imp::open(&permit.path, permit.root.as_deref(), mode)
}

fn kind_of(ft: fs::FileType) -> FileKind {
    if ft.is_symlink() {
        FileKind::Symlink
    } else if ft.is_dir() {
        FileKind::Dir
    } else if ft.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    }
}

fn mtime_ms(m: &fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn perm_bits(_m: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _m.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        if _m.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

pub fn stat(permit: &Permit) -> Result<StatResult, RpcError> {
    let f = open_checked(permit, OpenMode::Path).map_err(io_error)?;
    let m = f.metadata().map_err(io_error)?;
    Ok(StatResult {
        kind: kind_of(m.file_type()),
        size: m.len(),
        mtime_ms: mtime_ms(&m),
        mode: perm_bits(&m),
    })
}

pub fn list(permit: &Permit) -> Result<ListResult, RpcError> {
    #[cfg(target_os = "linux")]
    let rd = {
        let dir = open_checked(permit, OpenMode::Dir).map_err(io_error)?;
        imp::read_dir(&dir).map_err(io_error)?
    };
    #[cfg(windows)]
    let rd = {
        open_checked(permit, OpenMode::Dir).map_err(io_error)?;
        imp::read_dir_path(&permit.path).map_err(io_error)?
    };
    let mut entries = Vec::new();
    let mut truncated = false;
    for e in rd {
        let e = e.map_err(io_error)?;
        if entries.len() >= MAX_LIST {
            truncated = true;
            break;
        }
        let kind = e.file_type().map(kind_of).unwrap_or(FileKind::Other);
        entries.push(ListEntry {
            name: e.file_name().to_string_lossy().into_owned(),
            kind,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ListResult { entries, truncated })
}

/// Reads a whole regular file. Returns the content and its sha256.
pub fn read(permit: &Permit) -> Result<(Vec<u8>, String), RpcError> {
    let mut f = open_checked(permit, OpenMode::Read).map_err(io_error)?;
    let m = f.metadata().map_err(io_error)?;
    if !m.is_file() {
        return Err(RpcError::new(code::IO, "not a regular file"));
    }
    if m.len() > MAX_READ {
        return Err(RpcError::new(
            code::TOO_LARGE,
            format!("{} bytes is over the read limit of {MAX_READ}", m.len()),
        ));
    }
    let mut data = Vec::with_capacity(m.len() as usize);
    Read::by_ref(&mut f)
        .take(MAX_READ + 1)
        .read_to_end(&mut data)
        .map_err(io_error)?;
    if data.len() as u64 > MAX_READ {
        return Err(RpcError::new(
            code::TOO_LARGE,
            "file grew over the read limit",
        ));
    }
    let sha = sha256_hex(&data);
    Ok((data, sha))
}

/// Writes `data`, failing with `CONFLICT` when `if_match` no longer matches the
/// current content (pi's edit: read, patch, write).
pub fn write(
    permit: &Permit,
    data: &[u8],
    if_match: Option<&str>,
    create_dirs: bool,
) -> Result<WriteResult, RpcError> {
    if let Some(expected) = if_match {
        let current = match read(permit) {
            Ok((_, sha)) => sha,
            Err(e) if e.code == code::NOT_FOUND => String::new(),
            Err(e) => return Err(e),
        };
        if !current.eq_ignore_ascii_case(expected) {
            return Err(RpcError::new(
                code::CONFLICT,
                "the file changed since it was read",
            ));
        }
    }
    if create_dirs && let Some(parent) = permit.path.parent() {
        // The parent is a resolved path, and the open below refuses any symlink in it.
        create_parents(parent, permit.root.as_deref()).map_err(io_error)?;
    }
    let mut f = open_checked(permit, OpenMode::Write).map_err(io_error)?;
    f.write_all(data).map_err(io_error)?;
    f.flush().map_err(io_error)?;
    Ok(WriteResult {
        size: data.len() as u64,
        sha256: sha256_hex(data),
    })
}

fn create_parents(dir: &Path, root: Option<&Path>) -> io::Result<()> {
    if let Some(root) = root
        && !sync_policy::paths::within(dir, root)
    {
        return Err(io::Error::other("outside the folder"));
    }
    fs::create_dir_all(dir)
}
