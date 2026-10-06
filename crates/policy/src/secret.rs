//! The elevation secret: the OS password the owner types on the device so that
//! `sudo` commands can run. It never leaves the device: not over the wire, not in
//! a command's argv or environment, not in the audit log or the client's own log.
//! Wherever text from a command or about one leaves the device, the `Scrubber`
//! takes the secret out first.

use serde::{Deserialize, Serialize};

/// A secret string: prints as `<secret>`, and its bytes are overwritten when it
/// is dropped (copies the allocator made while it grew are out of reach).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Secret {
        Secret(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<secret>")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: zero bytes keep the string valid UTF-8.
        unsafe { self.0.as_bytes_mut() }.fill(0);
    }
}

/// Where the running client keeps the elevation secret, shared by everything that
/// injects it or scrubs it out.
#[derive(Default)]
pub struct SecretSlot(std::sync::RwLock<Option<Secret>>);

impl SecretSlot {
    pub fn get(&self) -> Option<Secret> {
        self.0.read().unwrap().clone()
    }

    pub fn set(&self, s: Secret) {
        *self.0.write().unwrap() = (!s.is_empty()).then_some(s);
    }

    pub fn clear(&self) {
        *self.0.write().unwrap() = None;
    }

    pub fn is_set(&self) -> bool {
        self.0.read().unwrap().is_some()
    }

    /// `text` with the secret taken out (unchanged when none is set).
    pub fn scrub(&self, text: &str) -> String {
        match &*self.0.read().unwrap() {
            Some(s) => scrub_text(text, s),
            None => text.to_string(),
        }
    }

    /// Bytes with the secret taken out.
    pub fn scrub_bytes(&self, data: &[u8]) -> Vec<u8> {
        match &*self.0.read().unwrap() {
            Some(s) => {
                let mut sc = Scrubber::new(s);
                let mut out = sc.push(data);
                out.extend(sc.finish());
                out
            }
            None => data.to_vec(),
        }
    }
}

impl std::fmt::Debug for SecretSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretSlot(set: {})", self.is_set())
    }
}

/// Whether a debugger (or anything else) traces this process. The secret is only
/// taken in by a process nobody traces, after it made itself undumpable.
#[cfg(target_os = "linux")]
pub fn traced() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("TracerPid:"))
                .map(|v| v.trim() != "0")
        })
        .unwrap_or(true)
}

/// Makes this process undumpable: other processes of the same user can no longer
/// read its memory, attach to it or open its files through /proc.
#[cfg(target_os = "linux")]
pub fn undumpable() {
    // SAFETY: prctl with integer arguments.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
}

/// What replaces the secret in text that leaves the device.
pub const REDACTED: &str = "[redacted]";

/// Takes every occurrence of the secret out of text, also when it arrives split
/// across chunks of a command's output.
pub struct Scrubber {
    needle: Vec<u8>,
    /// The end of the last chunk that could be the start of the secret, held back
    /// until the next chunk shows whether it is.
    held: Vec<u8>,
}

impl Scrubber {
    pub fn new(secret: &Secret) -> Scrubber {
        Scrubber {
            needle: secret.expose().as_bytes().to_vec(),
            held: Vec::new(),
        }
    }

    /// The chunk with the secret replaced; may hold back up to its length minus one
    /// byte for the next call (or `finish`).
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.needle.is_empty() {
            return chunk.to_vec();
        }
        let mut data = std::mem::take(&mut self.held);
        data.extend_from_slice(chunk);
        let mut out = replace_all(&data, &self.needle);
        // Hold back the longest tail that is a start of the secret.
        let keep = (1..self.needle.len())
            .rev()
            .find(|&n| n <= out.len() && out.ends_with(&self.needle[..n]))
            .unwrap_or(0);
        self.held = out.split_off(out.len() - keep);
        out
    }

    /// What was held back at the end of the output.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

impl Drop for Scrubber {
    fn drop(&mut self) {
        self.needle.fill(0);
        self.held.fill(0);
    }
}

fn replace_all(data: &[u8], needle: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(needle) {
            out.extend_from_slice(REDACTED.as_bytes());
            i += needle.len();
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

/// Text with the secret taken out: as it is, and as JSON escapes it (a password
/// with `"` or `\` in it looks different inside a JSON string).
pub fn scrub_text(text: &str, secret: &Secret) -> String {
    let s = secret.expose();
    if s.is_empty() {
        return text.to_string();
    }
    let mut out = text.replace(s, REDACTED);
    if let Ok(quoted) = serde_json::to_string(s) {
        let escaped = &quoted[1..quoted.len() - 1];
        if escaped != s {
            out = out.replace(escaped, REDACTED);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_across_chunk_borders() {
        let s = Secret::new("hunter2".into());
        let mut sc = Scrubber::new(&s);
        let mut out = Vec::new();
        for chunk in [&b"pass: hun"[..], b"ter", b"2 and hunter", b"2!", b" hun"] {
            out.extend(sc.push(chunk));
        }
        out.extend(sc.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "pass: [redacted] and [redacted]! hun"
        );
    }

    #[test]
    fn scrubs_the_json_escaped_form_and_never_prints() {
        let s = Secret::new("a\"b\\c".into());
        let json = serde_json::to_string(&serde_json::json!({"m": "x a\"b\\c y"})).unwrap();
        assert!(!scrub_text(&json, &s).contains(r#"a\"b\\c"#));
        assert_eq!(scrub_text("x a\"b\\c y", &s), "x [redacted] y");
        assert_eq!(format!("{s:?}"), "<secret>");
    }
}
