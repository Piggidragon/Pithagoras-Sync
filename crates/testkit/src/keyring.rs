//! A fake Secret Service (`org.freedesktop.secrets`) on a private D-Bus daemon:
//! the keyring code is tried against it, so no test reads or writes a real
//! keyring. It keeps items in memory, can be locked, and answers an unlock prompt
//! the way the test says (unlock, dismiss, or never).

use std::collections::HashMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

const ROOT: &str = "/org/freedesktop/secrets";
const COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
const PROMPT: &str = "/org/freedesktop/secrets/prompt/p1";
const SESSION: &str = "/org/freedesktop/secrets/session/s1";

#[derive(Default)]
pub struct State {
    /// (path, attributes, value)
    pub items: Vec<(String, HashMap<String, String>, Vec<u8>)>,
    pub locked: bool,
    /// What the "owner" does at an unlock prompt: `None` never answers.
    pub answer: Option<bool>,
    pub prompts: u32,
    pub next: u32,
    /// The secrets as the service received them, for the checks below.
    pub labels: Vec<String>,
}

pub type Shared = Arc<Mutex<State>>;

struct Service(Shared);

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn open_session(
        &self,
        algorithm: String,
        _input: OwnedValue,
    ) -> (OwnedValue, OwnedObjectPath) {
        assert_eq!(algorithm, "plain");
        (
            OwnedValue::try_from(Value::from("")).unwrap(),
            ObjectPath::try_from(SESSION).unwrap().into(),
        )
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let s = self.0.lock().unwrap();
        let found: Vec<OwnedObjectPath> = s
            .items
            .iter()
            .filter(|(_, a, _)| attributes.iter().all(|(k, v)| a.get(k) == Some(v)))
            .map(|(p, ..)| ObjectPath::try_from(p.as_str()).unwrap().into())
            .collect();
        if s.locked {
            (Vec::new(), found)
        } else {
            (found, Vec::new())
        }
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        if self.0.lock().unwrap().locked {
            (Vec::new(), ObjectPath::try_from(PROMPT).unwrap().into())
        } else {
            (objects, ObjectPath::try_from("/").unwrap().into())
        }
    }

    async fn read_alias(&self, name: String) -> OwnedObjectPath {
        assert_eq!(name, "default");
        ObjectPath::try_from(COLLECTION).unwrap().into()
    }
}

struct Collection(Shared);

#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    async fn create_item(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        properties: HashMap<String, OwnedValue>,
        secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String),
        replace: bool,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        assert!(replace);
        assert_eq!(secret.0.as_str(), SESSION);
        let attrs: HashMap<String, String> = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .unwrap()
            .try_clone()
            .unwrap()
            .try_into()
            .unwrap();
        let label: String = properties
            .get("org.freedesktop.Secret.Item.Label")
            .unwrap()
            .try_clone()
            .unwrap()
            .try_into()
            .unwrap();
        let path = {
            let mut s = self.0.lock().unwrap();
            if s.locked {
                return Err(zbus::fdo::Error::Failed("locked".into()));
            }
            s.labels.push(label);
            s.items.retain(|(_, a, _)| *a != attrs);
            s.next += 1;
            let path = format!("{COLLECTION}/{}", s.next);
            s.items.push((path.clone(), attrs, secret.2));
            path
        };
        server
            .at(path.as_str(), Item(self.0.clone(), path.clone()))
            .await
            .unwrap();
        Ok((
            ObjectPath::try_from(path).unwrap().into(),
            ObjectPath::try_from("/").unwrap().into(),
        ))
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.0.lock().unwrap().locked
    }
}

struct Item(Shared, String);

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        let mut s = self.0.lock().unwrap();
        if s.locked {
            return Err(zbus::fdo::Error::Failed("locked".into()));
        }
        s.items.retain(|(p, ..)| *p != self.1);
        Ok(ObjectPath::try_from("/").unwrap().into())
    }

    async fn get_secret(
        &self,
        session: OwnedObjectPath,
    ) -> zbus::fdo::Result<(OwnedObjectPath, Vec<u8>, Vec<u8>, String)> {
        let s = self.0.lock().unwrap();
        if s.locked {
            return Err(zbus::fdo::Error::Failed("locked".into()));
        }
        let value = s
            .items
            .iter()
            .find(|(p, ..)| *p == self.1)
            .map(|(.., v)| v.clone())
            .ok_or_else(|| zbus::fdo::Error::Failed("gone".into()))?;
        Ok((session, Vec::new(), value, "text/plain".into()))
    }
}

struct Prompt(Shared);

#[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(&self, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>, _window_id: String) {
        let answer = {
            let mut s = self.0.lock().unwrap();
            s.prompts += 1;
            s.answer
        };
        let Some(unlock) = answer else { return };
        let state = self.0.clone();
        let emitter = emitter.to_owned();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if unlock {
                state.lock().unwrap().locked = false;
            }
            let _ = Prompt::completed(&emitter, !unlock, Value::from("")).await;
        });
    }

    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

pub struct Bus {
    child: Child,
    pub address: String,
    _dir: tempfile::TempDir,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A private bus with no service directories, so nothing real can be activated.
pub fn private_bus() -> Option<Bus> {
    if !Path::new("/usr/bin/dbus-daemon").exists() {
        eprintln!("dbus-daemon not installed; skipping");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus");
    let config = dir.path().join("bus.conf");
    std::fs::write(
        &config,
        format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>"#,
            sock.display()
        ),
    )
    .unwrap();
    let child = Command::new("/usr/bin/dbus-daemon")
        .arg(format!("--config-file={}", config.display()))
        .arg("--nofork")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(Bus {
        child,
        address: format!("unix:path={}", sock.display()),
        _dir: dir,
    })
}

/// Serves the fake keyring on `bus` until the connection is dropped.
pub async fn serve(bus: &Bus, state: Shared) -> zbus::Connection {
    zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.secrets")
        .unwrap()
        .serve_at(ROOT, Service(state.clone()))
        .unwrap()
        .serve_at(COLLECTION, Collection(state.clone()))
        .unwrap()
        .serve_at(PROMPT, Prompt(state))
        .unwrap()
        .build()
        .await
        .unwrap()
}
