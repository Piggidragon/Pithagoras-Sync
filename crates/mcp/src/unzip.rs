//! Unpacking the zip files of a Windows server install: the embeddable CPython
//! and the wheels (which are zip files with a `.dist-info`). By hand, stored and
//! deflated entries only, because the client has no zip library and needs no
//! more than this: what it unpacks was checked against its sha256 pin before.
//!
//! Every name is checked before anything is written: no absolute path, drive
//! letter, `..`, backslash or control character, no link, no entry twice, and
//! the whole of it bounded in count and size, so even a pinned file that
//! turned out hostile cannot write outside the folder or fill the disk.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Most entries one archive may hold.
pub const MAX_ENTRIES: usize = 100_000;
/// Most bytes one archive may unpack to.
pub const MAX_UNPACKED: u64 = 1 << 30;

/// One file of an archive, unpacked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name inside the archive, `/`-separated and checked.
    pub name: String,
    pub data: Vec<u8>,
}

fn u16_at(d: &[u8], i: usize) -> Result<u16, String> {
    d.get(i..i + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| "the zip file is cut short".to_string())
}

fn u32_at(d: &[u8], i: usize) -> Result<u32, String> {
    d.get(i..i + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "the zip file is cut short".to_string())
}

/// A name from an archive, if it is one the device writes: relative, `/`
/// separated, no `.` or `..` part, nothing Windows would read differently.
pub fn safe_name(name: &str) -> Result<(), String> {
    let bad = || Err(format!("the zip file holds an unsafe name {name:?}"));
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.contains(':')
        || name.chars().any(char::is_control)
    {
        return bad();
    }
    for part in name.trim_end_matches('/').split('/') {
        if part.is_empty() || part == "." || part == ".." || part.ends_with(['.', ' ']) {
            return bad();
        }
    }
    Ok(())
}

/// The files of a zip archive (folders are implied by the names). Refuses
/// links, encrypted entries, zip64, other compression methods, bad CRCs and
/// anything over the limits.
pub fn entries(data: &[u8]) -> Result<Vec<Entry>, String> {
    // The end of central directory record, searched from the back (it may be
    // followed by a comment of up to 64 KiB).
    let min = data.len().saturating_sub(22 + 65_535);
    let eocd = (min..=data.len().saturating_sub(22))
        .rev()
        .find(|&i| data[i..].starts_with(&[0x50, 0x4b, 0x05, 0x06]))
        .ok_or("not a zip file (no end record)")?;
    let count = u16_at(data, eocd + 10)? as usize;
    let cd_size = u32_at(data, eocd + 12)? as usize;
    let cd_start = u32_at(data, eocd + 16)? as usize;
    if count == 0xffff || cd_start == 0xffff_ffff {
        return Err("zip64 archives are not taken".into());
    }
    if count > MAX_ENTRIES {
        return Err(format!(
            "the zip file holds more than {MAX_ENTRIES} entries"
        ));
    }
    if cd_start.checked_add(cd_size).is_none_or(|e| e > eocd) {
        return Err("the zip file's directory is out of place".into());
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0u64;
    let mut at = cd_start;
    for _ in 0..count {
        if u32_at(data, at)? != 0x0201_4b50 {
            return Err("the zip file's directory is broken".into());
        }
        let made_by = u16_at(data, at + 4)?;
        let flags = u16_at(data, at + 8)?;
        let method = u16_at(data, at + 10)?;
        let crc = u32_at(data, at + 16)?;
        let csize = u32_at(data, at + 20)? as usize;
        let usize_ = u32_at(data, at + 24)? as u64;
        let name_len = u16_at(data, at + 28)? as usize;
        let extra_len = u16_at(data, at + 30)? as usize;
        let comment_len = u16_at(data, at + 32)? as usize;
        let external = u32_at(data, at + 38)?;
        let local = u32_at(data, at + 42)? as usize;
        let name_bytes = data
            .get(at + 46..at + 46 + name_len)
            .ok_or("the zip file is cut short")?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| "the zip file holds a name that is not UTF-8")?
            .to_string();
        at += 46 + name_len + extra_len + comment_len;
        safe_name(&name)?;
        if flags & 1 != 0 {
            return Err(format!("{name}: encrypted entries are not taken"));
        }
        // Unix mode in the high half when made on Unix: a link is refused.
        if made_by >> 8 == 3 && (external >> 16) & 0o170000 == 0o120000 {
            return Err(format!("{name}: links are not taken"));
        }
        if name.ends_with('/') {
            continue;
        }
        if !seen.insert(name.to_lowercase()) {
            return Err(format!("{name} is in the zip file twice"));
        }
        total += usize_;
        if total > MAX_UNPACKED {
            return Err(format!(
                "the zip file unpacks to more than {MAX_UNPACKED} bytes"
            ));
        }
        if u32_at(data, local)? != 0x0403_4b50 {
            return Err(format!("{name}: its local header is missing"));
        }
        let lname = u16_at(data, local + 26)? as usize;
        let lextra = u16_at(data, local + 28)? as usize;
        let start = local + 30 + lname + lextra;
        let raw = data
            .get(start..start.checked_add(csize).ok_or("bad size")?)
            .ok_or("the zip file is cut short")?;
        let content = match method {
            0 => raw.to_vec(),
            8 => {
                crate::inflate::inflate(raw, usize_ as usize).map_err(|e| format!("{name}: {e}"))?
            }
            m => return Err(format!("{name}: compression method {m} is not taken")),
        };
        if content.len() as u64 != usize_ {
            return Err(format!("{name}: its size does not match"));
        }
        if crc32(&content) != crc {
            return Err(format!("{name}: its checksum does not match"));
        }
        out.push(Entry {
            name,
            data: content,
        });
    }
    Ok(out)
}

/// Writes `entries` below `dir`, which must not exist yet beyond what this
/// creates. Folders 0700 and files 0644 on Unix (the server's files are only
/// read by the user's own Python), never following a link.
pub fn write_all(dir: &Path, entries: &[Entry]) -> Result<(), String> {
    for e in entries {
        safe_name(&e.name)?;
        let path: PathBuf = e.name.split('/').fold(dir.to_path_buf(), |p, c| p.join(c));
        if let Some(parent) = path.parent() {
            crate::fsutil::private_dirs(dir, parent)?;
        }
        crate::fsutil::write_new(&path, &e.data, false)?;
    }
    Ok(())
}

/// CRC-32 (IEEE), as zip uses it.
pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, t) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *t = c;
    }
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}

/// A zip file of `files`, stored (not compressed): for tests, which need
/// archives without a compressor.
pub fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let mut local = Vec::new();
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&local);
        out.extend_from_slice(data);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_start = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `zipfile` of CPython 3, `ZIP_DEFLATED`: `a.txt` (text that compresses)
    /// and `pkg/b.bin` (stored, 3 bytes).
    const DEFLATED: &[u8] = include_bytes!("../tests/data/deflated.zip");

    #[test]
    fn unpacks_stored_and_deflated_entries() {
        let z = stored_zip(&[("x/y.txt", b"hello"), ("z", b"")]);
        let e = entries(&z).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(
            (e[0].name.as_str(), e[0].data.as_slice()),
            ("x/y.txt", &b"hello"[..])
        );
        let e = entries(DEFLATED).unwrap();
        let a = e.iter().find(|e| e.name == "a.txt").unwrap();
        assert_eq!(a.data, "pithagoras sync ".repeat(200).as_bytes());
        let b = e.iter().find(|e| e.name == "pkg/b.bin").unwrap();
        assert_eq!(b.data, [1, 2, 3]);
    }

    #[test]
    fn unsafe_names_and_broken_archives_are_refused() {
        for name in [
            "../x",
            "/etc/x",
            "a/../../x",
            "C:/x",
            "a\\..\\x",
            "a/./b",
            "a/b.",
            "a\u{1b}",
            "",
        ] {
            assert!(entries(&stored_zip(&[(name, b"x")])).is_err(), "{name:?}");
        }
        assert!(entries(&stored_zip(&[("a", b"1"), ("A", b"2")])).is_err());
        let mut z = stored_zip(&[("a", b"hello")]);
        // A flipped byte of the content fails the checksum.
        let i = z.windows(5).position(|w| w == b"hello").unwrap();
        z[i] = b'j';
        assert!(entries(&z).unwrap_err().contains("checksum"));
        assert!(entries(b"not a zip").is_err());
        let z = stored_zip(&[("a", b"hello")]);
        assert!(entries(&z[..z.len() - 30]).is_err());
    }

    #[test]
    fn writes_below_the_folder_only() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("out");
        let e = entries(&stored_zip(&[("a/b/c.txt", b"x"), ("d", b"y")])).unwrap();
        write_all(&dir, &e).unwrap();
        assert_eq!(std::fs::read(dir.join("a/b/c.txt")).unwrap(), b"x");
        let bad = [Entry {
            name: "../escape".into(),
            data: vec![],
        }];
        assert!(write_all(&dir, &bad).is_err());
        assert!(!t.path().join("escape").exists());
    }

    #[test]
    fn crc_matches_the_standard() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
