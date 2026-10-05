//! Approvals: native prompts on the device. Phase 1 has no window of its own, so a
//! desktop asks through the freedesktop notification service (Allow / Deny); with
//! no such service, or headless, nobody can answer and prompts are denied.

use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalRequest {
    pub chat: String,
    pub tool: String,
    /// The path or command.
    pub target: String,
    /// Why it asks (mode, protected path, pattern, taint).
    pub reasons: Vec<String>,
    /// A short preview of what a write puts there.
    pub preview: Option<String>,
    /// Whether "allow for this chat" may be offered (file tools in Ask mode only;
    /// a standing approval of the shell would cover any command).
    pub offer_chat: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Once,
    ForChat,
    Deny,
}

pub trait Approver: Send + Sync {
    /// Whether anyone can answer at all. When not, prompts are denied unasked.
    fn can_prompt(&self) -> bool;
    /// Asks the owner. The caller applies the timeout and drops the future then;
    /// dropping it must withdraw the prompt.
    fn ask<'a>(&'a self, req: &'a ApprovalRequest) -> BoxFuture<'a, Answer>;
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
