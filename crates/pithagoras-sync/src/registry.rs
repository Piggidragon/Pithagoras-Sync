//! The few registry writes `install` makes on Windows: the `pithagoras-sync://`
//! link handler under `HKEY_CURRENT_USER\Software\Classes`. Only the current
//! user's hive is ever opened, so no write needs, or reaches, other users.
//! Not run by the tests, which use the fake runner; tried by hand (windows.md).

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegSetValueExW,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn error(code: u32) -> String {
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

pub fn set_string(key: &str, name: &str, value: &str) -> Result<(), String> {
    let k = wide(key);
    let mut h: HKEY = std::ptr::null_mut();
    // SAFETY: a NUL-terminated key name; the handle is closed below.
    let r = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            k.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut h,
            std::ptr::null_mut(),
        )
    };
    if r != ERROR_SUCCESS {
        return Err(error(r));
    }
    let n = wide(name);
    let v = wide(value);
    // SAFETY: the data is the value with its NUL, as REG_SZ wants, in bytes.
    let r = unsafe {
        RegSetValueExW(
            h,
            n.as_ptr(),
            0,
            REG_SZ,
            v.as_ptr().cast(),
            (v.len() * 2) as u32,
        )
    };
    // SAFETY: the handle is ours.
    unsafe { RegCloseKey(h) };
    if r != ERROR_SUCCESS {
        return Err(error(r));
    }
    Ok(())
}

pub fn delete_tree(key: &str) -> Result<(), String> {
    let k = wide(key);
    // SAFETY: a NUL-terminated key name.
    let r = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, k.as_ptr()) };
    if r != ERROR_SUCCESS && r != ERROR_FILE_NOT_FOUND {
        return Err(error(r));
    }
    Ok(())
}

pub fn exists(key: &str) -> bool {
    let k = wide(key);
    let mut h: HKEY = std::ptr::null_mut();
    // SAFETY: a NUL-terminated key name; the handle is closed below.
    let r = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, k.as_ptr(), 0, KEY_QUERY_VALUE, &mut h) };
    if r == ERROR_SUCCESS {
        // SAFETY: the handle is ours.
        unsafe { RegCloseKey(h) };
    }
    r == ERROR_SUCCESS
}
