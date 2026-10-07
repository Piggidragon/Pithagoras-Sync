//! The approvals waiting for the owner. The engine's questions land here; the
//! connector sends each one to the portal (`approval.requested`) and passes the
//! portal's `approval.answer` back, and the local CLI (`approvals`, `approve`,
//! `deny`) answers the same queue over the control socket. The first answer wins.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use sync_proto::methods::{
    ApprovalInfo, ApprovalResolved, Choice, MAX_APPROVAL_LIST, MAX_APPROVAL_TEXT,
};
use tokio::sync::{broadcast, oneshot};

use crate::approve::{Answer, ApprovalRequest, Approver, BoxFuture};
use crate::engine::Clock;

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalEvent {
    Requested(ApprovalInfo),
    Resolved(ApprovalResolved),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerError {
    /// No such approval waits (answered, timed out, or never asked).
    NotFound(u64),
    /// The approval does not take this answer.
    Invalid(String),
}

impl std::fmt::Display for AnswerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnswerError::NotFound(id) => write!(f, "no approval {id} is waiting"),
            AnswerError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

struct Pending {
    info: ApprovalInfo,
    tx: oneshot::Sender<Answer>,
}

#[derive(Default)]
struct Inner {
    next: u64,
    pending: BTreeMap<u64, Pending>,
}

pub struct ApprovalQueue {
    inner: Mutex<Inner>,
    events: broadcast::Sender<ApprovalEvent>,
    clock: Clock,
}

impl ApprovalQueue {
    pub fn new(clock: Clock) -> Arc<ApprovalQueue> {
        let (events, _) = broadcast::channel(256);
        Arc::new(ApprovalQueue {
            inner: Mutex::new(Inner::default()),
            events,
            clock,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalEvent> {
        self.events.subscribe()
    }

    /// The approvals waiting now, oldest first, as they are shown (cut).
    pub fn list(&self) -> Vec<ApprovalInfo> {
        let inner = self.inner.lock().unwrap();
        inner.pending.values().map(|p| p.info.shown()).collect()
    }

    /// `list` as far as `MAX_APPROVAL_LIST` bytes of JSON hold it, so it fits one
    /// message; and how many approvals were left out.
    pub fn list_within(&self) -> (Vec<ApprovalInfo>, usize) {
        let all = self.list();
        let total = all.len();
        let mut used = 0usize;
        let mut out = Vec::new();
        for a in all {
            let n = serde_json::to_string(&a).map_or(usize::MAX, |s| s.len() + 1);
            if used.saturating_add(n) > MAX_APPROVAL_LIST {
                break;
            }
            used += n;
            out.push(a);
        }
        let left_out = total - out.len();
        (out, left_out)
    }

    /// Answers approval `id`. `by` says who (`portal`, `device`, ...) for the
    /// `approval.resolved` notification and the audit log.
    pub fn answer(
        &self,
        id: u64,
        choice: Choice,
        minutes: Option<u32>,
        by: &str,
    ) -> Result<(), AnswerError> {
        let mut inner = self.inner.lock().unwrap();
        let p = inner.pending.get(&id).ok_or(AnswerError::NotFound(id))?;
        if !p.info.choices.contains(&choice) {
            return Err(AnswerError::Invalid(format!(
                "approval {id} takes {}",
                names(&p.info.choices)
            )));
        }
        let answer = match (choice, minutes) {
            (Choice::Time, Some(m)) if m >= 1 && m <= p.info.max_minutes => Answer::ForTime(m),
            (Choice::Time, _) => {
                return Err(AnswerError::Invalid(format!(
                    "a time answer needs minutes from 1 to {}",
                    p.info.max_minutes
                )));
            }
            (_, Some(_)) => {
                return Err(AnswerError::Invalid(
                    "minutes go with a time answer only".into(),
                ));
            }
            (Choice::Once, None) => Answer::Once,
            (Choice::Chat, None) => Answer::ForChat,
            (Choice::Deny, None) => Answer::Deny,
        };
        let p = inner.pending.remove(&id).expect("checked above");
        drop(inner);
        let _ = p.tx.send(answer);
        let _ = self.events.send(ApprovalEvent::Resolved(ApprovalResolved {
            id,
            chat: p.info.chat,
            answer: choice,
            minutes,
            by: by.to_string(),
        }));
        Ok(())
    }

    fn resolve_unanswered(&self, id: u64, answer: Choice, by: &str) {
        let removed = self.inner.lock().unwrap().pending.remove(&id);
        if let Some(p) = removed {
            let _ = p.tx.send(if answer == Choice::Once {
                Answer::Once
            } else {
                Answer::Deny
            });
            let _ = self.events.send(ApprovalEvent::Resolved(ApprovalResolved {
                id,
                chat: p.info.chat,
                answer,
                minutes: None,
                by: by.to_string(),
            }));
        }
    }
}

fn names(choices: &[Choice]) -> String {
    choices
        .iter()
        .map(|c| match c {
            Choice::Once => "once",
            Choice::Chat => "chat",
            Choice::Time => "time",
            Choice::Deny => "deny",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Withdraws an approval whose caller stopped waiting (the engine's timeout, or a
/// closed connection), so it does not linger in lists and the portal hears of it.
struct Withdraw<'a> {
    queue: &'a ApprovalQueue,
    id: u64,
    expires_ms: i64,
    on_timeout_allow: bool,
}

impl Drop for Withdraw<'_> {
    fn drop(&mut self) {
        if (self.queue.clock)() >= self.expires_ms {
            let answer = if self.on_timeout_allow {
                Choice::Once
            } else {
                Choice::Deny
            };
            self.queue.resolve_unanswered(self.id, answer, "timeout");
        } else {
            self.queue
                .resolve_unanswered(self.id, Choice::Deny, "withdrawn");
        }
    }
}

impl Approver for ApprovalQueue {
    fn can_prompt(&self) -> bool {
        true
    }

    fn ask<'a>(&'a self, req: &'a ApprovalRequest) -> BoxFuture<'a, Answer> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            // What nobody can read whole cannot be allowed, from anywhere.
            let cut = req.target.len() > MAX_APPROVAL_TEXT
                || req
                    .cwd
                    .as_ref()
                    .is_some_and(|c| c.len() > MAX_APPROVAL_TEXT);
            let choices = if cut {
                vec![Choice::Deny]
            } else {
                let mut c = vec![Choice::Once];
                if req.offer_chat {
                    c.push(Choice::Chat);
                }
                if req.offer_time {
                    c.push(Choice::Time);
                }
                c.push(Choice::Deny);
                c
            };
            let info = {
                let mut inner = self.inner.lock().unwrap();
                inner.next += 1;
                let id = inner.next;
                let info = ApprovalInfo {
                    id,
                    call: req.call.clone(),
                    chat: req.chat.clone(),
                    tool: req.tool.clone(),
                    target: req.target.clone(),
                    cwd: req.cwd.clone(),
                    reasons: req.reasons.clone(),
                    preview: req.preview.clone(),
                    choices,
                    max_minutes: req.max_minutes,
                    created_ms: (self.clock)(),
                    expires_ms: req.expires_ms,
                    cut,
                };
                inner.pending.insert(
                    id,
                    Pending {
                        info: info.clone(),
                        tx,
                    },
                );
                info
            };
            let _guard = Withdraw {
                queue: self,
                id: info.id,
                expires_ms: req.expires_ms,
                on_timeout_allow: req.on_timeout_allow,
            };
            let _ = self.events.send(ApprovalEvent::Requested(info.shown()));
            rx.await.unwrap_or(Answer::Deny)
        })
    }

    fn cancel_all(&self) {
        let ids: Vec<u64> = self.inner.lock().unwrap().pending.keys().copied().collect();
        for id in ids {
            self.resolve_unanswered(id, Choice::Deny, "pause");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(offer_chat: bool) -> ApprovalRequest {
        ApprovalRequest {
            call: None,
            chat: "c1".into(),
            tool: "write".into(),
            target: "/w/a".into(),
            cwd: None,
            reasons: vec!["Ask mode".into()],
            preview: None,
            offer_chat,
            offer_time: offer_chat,
            max_minutes: 60,
            expires_ms: i64::MAX,
            on_timeout_allow: false,
        }
    }

    fn queue() -> Arc<ApprovalQueue> {
        ApprovalQueue::new(Arc::new(|| 0))
    }

    #[tokio::test]
    async fn answers_reach_the_waiting_call() {
        let q = queue();
        let mut ev = q.subscribe();
        let r = req(true);
        let ask = q.ask(&r);
        let waiter = async {
            let ApprovalEvent::Requested(info) = ev.recv().await.unwrap() else {
                panic!()
            };
            assert_eq!(q.list().len(), 1);
            assert_eq!(
                q.answer(info.id, Choice::Time, Some(61), "portal"),
                Err(AnswerError::Invalid(
                    "a time answer needs minutes from 1 to 60".into()
                ))
            );
            q.answer(info.id, Choice::Time, Some(30), "portal").unwrap();
            assert_eq!(
                q.answer(info.id, Choice::Deny, None, "device"),
                Err(AnswerError::NotFound(info.id))
            );
        };
        let (answer, ()) = tokio::join!(ask, waiter);
        assert_eq!(answer, Answer::ForTime(30));
        assert!(q.list().is_empty());
        let ApprovalEvent::Resolved(r) = ev.recv().await.unwrap() else {
            panic!()
        };
        assert_eq!((r.answer, r.by.as_str()), (Choice::Time, "portal"));
    }

    #[tokio::test]
    async fn a_shell_question_takes_once_or_deny_only() {
        let q = queue();
        let mut ev = q.subscribe();
        let r = req(false);
        let ask = q.ask(&r);
        let waiter = async {
            let ApprovalEvent::Requested(info) = ev.recv().await.unwrap() else {
                panic!()
            };
            assert_eq!(info.choices, [Choice::Once, Choice::Deny]);
            assert!(q.answer(info.id, Choice::Chat, None, "portal").is_err());
            q.answer(info.id, Choice::Deny, None, "device").unwrap();
        };
        let (answer, ()) = tokio::join!(ask, waiter);
        assert_eq!(answer, Answer::Deny);
    }

    #[tokio::test]
    async fn long_targets_are_cut_and_the_list_fits_one_message() {
        use sync_proto::methods::ApprovalListResult;
        let q = queue();
        let mut ev = q.subscribe();
        // Two heredocs of 2.5 MiB, and twenty commands whose 64 KiB of control
        // characters take six times as much as JSON escapes.
        let mut reqs = Vec::new();
        for i in 0..22 {
            let mut r = req(true);
            r.tool = "exec".into();
            r.target = if i < 2 {
                "x".repeat(5 << 19)
            } else {
                "\u{1}".repeat(MAX_APPROVAL_TEXT)
            };
            reqs.push(r);
        }
        let n = reqs.len();
        let mut asks = tokio::task::JoinSet::new();
        for r in reqs {
            let q = q.clone();
            asks.spawn(async move { q.ask(&r).await });
        }
        let check = async {
            let mut seen = Vec::new();
            while seen.len() < n {
                if let ApprovalEvent::Requested(i) = ev.recv().await.unwrap() {
                    seen.push(i);
                }
            }
            let big = seen.iter().find(|i| i.target.starts_with('x')).unwrap();
            assert!(big.cut && big.target.len() <= MAX_APPROVAL_TEXT);
            assert_eq!(big.choices, [Choice::Deny]);
            assert!(matches!(
                q.answer(big.id, Choice::Once, None, "portal"),
                Err(AnswerError::Invalid(_))
            ));
            // Exactly at the limit: shown whole, and it may be allowed.
            let whole = seen.iter().find(|i| i.target.starts_with('\u{1}')).unwrap();
            assert!(!whole.cut && whole.choices.contains(&Choice::Once));
            let (approvals, left_out) = q.list_within();
            assert!(left_out > 0 && !approvals.is_empty());
            assert_eq!(approvals.len() + left_out, n);
            let json = serde_json::to_string(&ApprovalListResult {
                approvals,
                left_out,
            })
            .unwrap();
            assert!(json.len() <= MAX_APPROVAL_LIST, "{}", json.len());
            q.cancel_all();
        };
        check.await;
        let answers = asks.join_all().await;
        assert_eq!(answers.len(), n);
        assert!(answers.iter().all(|a| *a == Answer::Deny));
    }

    #[tokio::test]
    async fn a_dropped_question_is_withdrawn_and_pause_denies() {
        let q = queue();
        let mut ev = q.subscribe();
        let r = req(true);
        drop(tokio::time::timeout(std::time::Duration::from_millis(10), q.ask(&r)).await);
        assert!(q.list().is_empty());
        let _ = ev.recv().await.unwrap();
        let ApprovalEvent::Resolved(res) = ev.recv().await.unwrap() else {
            panic!()
        };
        assert_eq!((res.answer, res.by.as_str()), (Choice::Deny, "withdrawn"));

        let ask = q.ask(&r);
        let pauser = async {
            let _ = ev.recv().await.unwrap();
            q.cancel_all();
        };
        let (answer, ()) = tokio::join!(ask, pauser);
        assert_eq!(answer, Answer::Deny);
    }
}
