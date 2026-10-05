//! Approvals as desktop notifications with actions, over the session bus
//! (`org.freedesktop.Notifications`). Whether KDE and GNOME show the actions the way
//! this expects is not verified yet; the tests drive a fake notification server.

use std::collections::HashMap;

use futures_util::StreamExt;
use zbus::zvariant::Value;

use crate::approve::{Answer, ApprovalRequest, Approver, BoxFuture};

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
        let esc = |s: &str| {
            if self.markup {
                s.replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            } else {
                s.to_string()
            }
        };
        let mut body = format!(
            "Chat {}\n{}\n{}",
            esc(&req.chat),
            esc(&clip(&req.target, 400)),
            esc(&req.reasons.join("; "))
        );
        if let Some(p) = &req.preview {
            body.push_str("\n\n");
            body.push_str(&esc(&clip(p, 800)));
        }
        body
    }
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
            let mut keys = vec!["allow", "Allow once"];
            if req.offer_chat {
                keys.extend(["allow-chat", "Allow for this chat"]);
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
                            "allow" => Answer::Once,
                            "allow-chat" if req.offer_chat => Answer::ForChat,
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
