//! Approvals: how the engine asks the owner. Phase 1 asks through the portal and
//! the local `approve` command (`queue::ApprovalQueue`); the freedesktop
//! notification approver stays for the device's own prompts of phase 2.

use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// `s` as the owner may safely read it before answering: every control character
/// (C0 with newlines and tabs, DEL, C1), every bidirectional-text control and the
/// line and paragraph separators (U+2028, U+2029, where notification servers
/// break lines) are written as visible escapes. Text of an approval comes from the portal, and a
/// terminal or notification would otherwise let it move the cursor, redraw lines
/// or reorder characters, so the owner would approve something other than what
/// they read.
pub fn visible(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || is_bidi_control(c) || matches!(c, '\u{2028}' | '\u{2029}') => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// The three characters markup gives a meaning (`&`, `<`, `>`), as entities:
/// for a notification server or dialog program that reads Pango or HTML-like
/// markup, so outside text cannot style or hide what the owner reads.
pub fn markup_escaped(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{61c}')
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalRequest {
    /// The JSON-RPC id of the waiting portal call.
    pub call: Option<sync_proto::Id>,
    pub chat: String,
    pub tool: String,
    /// The path or command.
    pub target: String,
    /// The folder a command runs in (commands only).
    pub cwd: Option<String>,
    /// Why it asks (mode, protected path, pattern, taint).
    pub reasons: Vec<String>,
    /// A short preview of what a write puts there.
    pub preview: Option<String>,
    /// Whether "allow for this chat" and "for a time" may be offered (file tools in
    /// Ask mode only; a standing approval of the shell would cover any command).
    pub offer_chat: bool,
    /// The longest "for a time" answer.
    pub max_minutes: u32,
    /// When the engine stops waiting (Unix ms).
    pub expires_ms: i64,
    /// Whether the call goes ahead when nobody answers.
    pub on_timeout_allow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Once,
    ForChat,
    /// Calls of this kind from this chat, for this many minutes.
    ForTime(u32),
    Deny,
}

pub trait Approver: Send + Sync {
    /// Whether anyone can answer at all. When not, prompts are denied unasked.
    fn can_prompt(&self) -> bool;
    /// Asks the owner. The caller applies the timeout and drops the future then;
    /// dropping it must withdraw the prompt.
    fn ask<'a>(&'a self, req: &'a ApprovalRequest) -> BoxFuture<'a, Answer>;
    /// The device paused: every open question is answered with deny.
    fn cancel_all(&self) {}
}

/// Nobody can answer: headless, or no notification service with actions.
pub struct NoApprover {
    pub why: &'static str,
}

impl Approver for NoApprover {
    fn can_prompt(&self) -> bool {
        false
    }

    fn ask<'a>(&'a self, _req: &'a ApprovalRequest) -> BoxFuture<'a, Answer> {
        Box::pin(async { Answer::Deny })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_escapes_what_a_terminal_would_act_on() {
        let s = "a\x1b[2A\x1b[2Kb\nc\r\td\u{7f}\u{9b}e\u{202e}f\\g é";
        assert_eq!(
            visible(s),
            "a\\u{1b}[2A\\u{1b}[2Kb\\nc\\r\\td\\u{7f}\\u{9b}e\\u{202e}f\\g é"
        );
        assert!(!visible(s).chars().any(|c| c.is_control()));
        assert_eq!(visible("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c");
    }
}
