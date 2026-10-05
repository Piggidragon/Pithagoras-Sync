//! Files only the client's user can read: the config, the token and the audit log.
//!
//! On Unix that is mode 0600 in a 0700 directory. On Windows the files live in the
//! user's profile (`%APPDATA%`, `%LOCALAPPDATA%`), whose inherited ACL already limits
//! them to the user, SYSTEM and administrators.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;

/// Creates `dir` (and its parents) and makes it private.
pub fn private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Open options that create a file private to the user.
pub fn private_options() -> OpenOptions {
    #[allow(unused_mut)]
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}
