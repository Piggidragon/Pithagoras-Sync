//! Approvals: how the engine asks the owner. Phase 1 asks through the portal and
//! the local `approve` command (`queue::ApprovalQueue`); the freedesktop
//! notification approver stays for the device's own prompts of phase 2.

use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalRequest {
    /// The JSON-RPC id of the waiting portal call.
    pub call: Option<sync_proto::Id>,
    pub chat: String,
    pub tool: String,
    /// The path or command.
    pub target: String,
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
