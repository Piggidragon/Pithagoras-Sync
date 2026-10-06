//! Approvals as desktop notifications with actions, over the session bus
//! (`org.freedesktop.Notifications`). Whether KDE and GNOME show the actions the way
//! this expects is not verified yet; the tests drive a fake notification server.

use std::collections::HashMap;

use futures_util::StreamExt;
use zbus::zvariant::Value;

use crate::approve::{Answer, ApprovalRequest, Approver, BoxFuture, visible};

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
pub trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    fn get_capabilities(&self) -> zbus::Result<Vec<String>>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

pub struct NotifyApprover {
    proxy: NotificationsProxy<'static>,
    markup: bool,
}

impl NotifyApprover {
    /// Connects to the session bus. `None` when there is no bus, no notification
    /// service, or one that cannot show actions: then nobody can answer.
    pub async fn connect() -> Option<NotifyApprover> {
        let conn = zbus::Connection::session().await.ok()?;
        NotifyApprover::with_connection(&conn).await
    }

    pub async fn with_connection(conn: &zbus::Connection) -> Option<NotifyApprover> {
        let proxy = NotificationsProxy::new(conn).await.ok()?;
        let caps = proxy.get_capabilities().await.ok()?;
        if !caps.iter().any(|c| c == "actions") {
            return None;
        }
        let markup = caps.iter().any(|c| c == "body-markup");
        Some(NotifyApprover { proxy, markup })
    }

    fn body(&self, req: &ApprovalRequest) -> String {
        // Control characters as visible escapes first (the text comes from the
        // portal), then markup where the server reads it.
        let esc = |s: &str| {
            let s = visible(s);
            if self.markup {
                s.replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            } else {
                s
            }
        };
        let target = if fits(&req.target) {
            esc(&req.target)
        } else {
            format!(
                "{}\n(too long to show here: answer with `pithagoras-sync approvals` or in the portal)",
                esc(&clip(&req.target, MAX_TARGET))
            )
        };
        // Where a command runs; cut like the chat id, the target says the rest.
        let cwd = req
            .cwd
            .as_ref()
            .map(|c| format!("\nin {}", esc(&clip(c, MAX_TARGET))))
            .unwrap_or_default();
        let mut body = format!(
            "Chat {}\n{target}{cwd}\n{}",
            esc(&clip(&req.chat, MAX_CHAT)),
            esc(&req.reasons.join("; "))
        );
        if let Some(p) = &req.preview {
            body.push_str("\n\n");
            // Line by line, so the preview keeps its lines but nothing else.
            let lines: Vec<String> = clip(p, 800).lines().map(esc).collect();
            body.push_str(&lines.join("\n"));
        }
        body
    }
}

/// Shows a message as a plain notification (no actions), for a program that has
/// no other way to reach the owner (`gui` without a dialog program). The text
/// goes through `visible`, and is escaped for servers that read markup.
pub async fn show(summary: &str, body: &str) -> Result<(), String> {
    let conn = zbus::Connection::session()
        .await
        .map_err(|e| format!("no session bus: {e}"))?;
    let proxy = NotificationsProxy::new(&conn)
        .await
        .map_err(|e| e.to_string())?;
    let caps = proxy.get_capabilities().await.map_err(|e| e.to_string())?;
    let mut body = clip(&visible(body), 2 * MAX_TARGET);
    if caps.iter().any(|c| c == "body-markup") {
        body = body
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
    }
    proxy
        .notify(
            "Pithagoras Sync",
            0,
            "pithagoras-sync",
            &visible(summary),
            &body,
            &[],
            HashMap::new(),
            -1,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Longest target a notification shows whole; a longer one offers no Allow, since
/// the owner could not read what they allow.
const MAX_TARGET: usize = 400;
/// Longest chat id shown.
const MAX_CHAT: usize = 64;

/// Counted as shown, escapes included: a target of many separators or control
/// characters is as long as what the owner would have to read.
fn fits(target: &str) -> bool {
    visible(target).chars().count() <= MAX_TARGET
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

/// Withdraws the notification when the approval is dropped (answered or timed out).
struct Withdraw {
    proxy: NotificationsProxy<'static>,
    id: u32,
}

impl Drop for Withdraw {
    fn drop(&mut self) {
        let proxy = self.proxy.clone();
        let id = self.id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = proxy.close_notification(id).await;
            });
        }
    }
}

impl Approver for NotifyApprover {
    fn can_prompt(&self) -> bool {
        true
    }

    fn ask<'a>(&'a self, req: &'a ApprovalRequest) -> BoxFuture<'a, Answer> {
        Box::pin(async move {
            // Subscribe before showing it, so a fast answer is not missed.
            let Ok(mut actions) = self.proxy.receive_action_invoked().await else {
                return Answer::Deny;
            };
            let Ok(mut closed) = self.proxy.receive_notification_closed().await else {
                return Answer::Deny;
            };
            let allow = fits(&req.target);
            let mut keys = Vec::new();
            if allow {
                keys.extend(["allow", "Allow once"]);
                if req.offer_chat {
                    keys.extend(["allow-chat", "Allow for this chat"]);
                }
            }
            keys.extend(["deny", "Deny"]);
            let mut hints = HashMap::new();
            hints.insert("urgency", Value::U8(2));
            hints.insert("resident", Value::Bool(true));
            let summary = format!("Pithagoras Sync: allow {}?", req.tool);
            let Ok(id) = self
                .proxy
                .notify(
                    "Pithagoras Sync",
                    0,
                    "dialog-question",
                    &summary,
                    &self.body(req),
                    &keys,
                    hints,
                    0,
                )
                .await
            else {
                return Answer::Deny;
            };
            let _withdraw = Withdraw {
                proxy: self.proxy.clone(),
                id,
            };
            loop {
                tokio::select! {
                    a = actions.next() => {
                        let Some(a) = a else { return Answer::Deny };
                        let Ok(args) = a.args() else { continue };
                        if args.id != id {
                            continue;
                        }
                        return match args.action_key.as_str() {
                            "allow" if allow => Answer::Once,
                            "allow-chat" if allow && req.offer_chat => Answer::ForChat,
                            _ => Answer::Deny,
                        };
                    }
                    c = closed.next() => {
                        let Some(c) = c else { return Answer::Deny };
                        if c.args().map(|a| a.id == id).unwrap_or(false) {
                            return Answer::Deny;
                        }
                    }
                }
            }
        })
    }
}
