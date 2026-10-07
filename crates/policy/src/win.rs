//! A helper for the Windows API, shared by the keyring here and the binary's
//! registry writes and message boxes.

/// `s` as a NUL-terminated UTF-16 string. A NUL inside `s` would end it early,
/// so it becomes a space.
pub fn wide(s: &str) -> Vec<u16> {
    s.replace('\0', " ")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn ends_with_one_nul() {
        assert_eq!(super::wide("a\0b"), [97, 32, 98, 0]);
    }
}
