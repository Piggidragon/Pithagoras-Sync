//! The OS keyring, for the connector token and (opt-in, Linux) the elevation
//! password: the Secret Service over the session bus on Linux, the Credential
//! Manager on Windows. Both sit behind `SecretStore`, so the tests use `FakeStore`
//! and a fake Secret Service and never touch a real keyring.
//!
//! A keyring unlocked for this user hands its secrets to every process of the
//! user, an unconfined command of the agent included; it protects against other
//! users and a stolen disk, not against the agent. So memory stays the default for
//! the password, and a keyring the owner chose never falls back silently to
//! anything else: no keyring, a locked one or a cancelled prompt is an error.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::approve::BoxFuture;
use crate::secret::Secret;

/// What every entry of this client carries, so it finds its own and only those.
pub const APPLICATION: &str = "pithagoras-sync";

/// Set (to anything), the client uses no keyring at all: an explicit `keyring`
/// setting then fails, and the Windows default keeps the token in its file. The
/// tests set it, so a run never writes to the keyring of the machine it runs on.
pub const NO_KEYRING_ENV: &str = "PITHAGORAS_SYNC_NO_KEYRING";

/// Secrets by name (`token`, `elevation`).
pub trait SecretStore: Send + Sync {
    /// The secret, or `None` when there is none.
    fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Secret>, String>>;
    /// Stores the secret, replacing one of the same name.
    fn set<'a>(&'a self, name: &'a str, value: &'a Secret) -> BoxFuture<'a, Result<(), String>>;
    /// Removes it; none there is no error.
    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), String>>;
}

/// The keyring of this platform and session.
pub fn system() -> Arc<dyn SecretStore> {
    if std::env::var_os(NO_KEYRING_ENV).is_some() {
        return Arc::new(Unavailable(format!("no keyring: {NO_KEYRING_ENV} is set")));
    }
    #[cfg(windows)]
    return Arc::new(credentials::CredentialManager);
    #[cfg(unix)]
    return Arc::new(secret_service::SecretService::session());
    #[allow(unreachable_code)]
    Arc::new(Unavailable(
        "this system has no keyring the client knows".into(),
    ))
}

/// A keyring that is not there: every call fails with the reason.
pub struct Unavailable(pub String);

impl SecretStore for Unavailable {
    fn get<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<Option<Secret>, String>> {
        Box::pin(async { Err(self.0.clone()) })
    }

    fn set<'a>(&'a self, _name: &'a str, _value: &'a Secret) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Err(self.0.clone()) })
    }

    fn delete<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Err(self.0.clone()) })
    }
}

/// A keyring in memory, for tests. `fail` makes every call fail with that text,
/// as a locked keyring whose prompt was cancelled would.
#[derive(Default)]
pub struct FakeStore {
    pub entries: Mutex<HashMap<String, Secret>>,
    pub fail: Mutex<Option<String>>,
}

impl FakeStore {
    fn check(&self) -> Result<(), String> {
        match &*self.fail.lock().unwrap() {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

impl SecretStore for FakeStore {
    fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Secret>, String>> {
        Box::pin(async move {
            self.check()?;
            Ok(self.entries.lock().unwrap().get(name).cloned())
        })
    }

    fn set<'a>(&'a self, name: &'a str, value: &'a Secret) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.check()?;
            self.entries
                .lock()
                .unwrap()
                .insert(name.to_string(), value.clone());
            Ok(())
        })
    }

    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.check()?;
            self.entries.lock().unwrap().remove(name);
            Ok(())
        })
    }
}

/// Text from the keyring as a secret; bytes that are not text are wiped.
fn secret_from_bytes(bytes: Vec<u8>) -> Result<Secret, String> {
    String::from_utf8(bytes).map(Secret::new).map_err(|e| {
        e.into_bytes().fill(0);
        "the keyring entry is not text".to_string()
    })
}

/// The Secret Service (`org.freedesktop.secrets`): GNOME Keyring, KWallet and
/// KeePassXC serve it. Items carry `application=pithagoras-sync` and `name=<name>`
/// and live in the default collection. The `plain` session is used: the bus is
/// this user's own, and the other algorithm only hides the secret from someone
/// who can read that bus, who could ask the service for it as well.
#[cfg(unix)]
pub mod secret_service {
    use std::collections::HashMap;
    use std::time::Duration;

    use futures_util::StreamExt;
    use zbus::proxy::CacheProperties;
    use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

    use super::{APPLICATION, SecretStore, secret_from_bytes};
    use crate::approve::BoxFuture;
    use crate::secret::Secret;

    /// How long one call to the service may take.
    const CALL: Duration = Duration::from_secs(10);
    /// How long an unlock prompt waits for the owner; unanswered means no.
    pub const PROMPT: Duration = Duration::from_secs(120);

    #[zbus::proxy(
        interface = "org.freedesktop.Secret.Service",
        default_service = "org.freedesktop.secrets",
        default_path = "/org/freedesktop/secrets"
    )]
    trait Service {
        fn open_session(
            &self,
            algorithm: &str,
            input: &Value<'_>,
        ) -> zbus::Result<(OwnedValue, OwnedObjectPath)>;

        fn search_items(
            &self,
            attributes: HashMap<&str, &str>,
        ) -> zbus::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)>;

        fn unlock(
            &self,
            objects: &[ObjectPath<'_>],
        ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;

        fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    }

    #[zbus::proxy(
        interface = "org.freedesktop.Secret.Collection",
        default_service = "org.freedesktop.secrets"
    )]
    trait Collection {
        fn create_item(
            &self,
            properties: HashMap<&str, Value<'_>>,
            secret: &(ObjectPath<'_>, Vec<u8>, Vec<u8>, &str),
            replace: bool,
        ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;

        #[zbus(property)]
        fn locked(&self) -> zbus::Result<bool>;
    }

    #[zbus::proxy(
        interface = "org.freedesktop.Secret.Item",
        default_service = "org.freedesktop.secrets"
    )]
    trait Item {
        fn delete(&self) -> zbus::Result<OwnedObjectPath>;

        fn get_secret(
            &self,
            session: &ObjectPath<'_>,
        ) -> zbus::Result<(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>;
    }

    #[zbus::proxy(
        interface = "org.freedesktop.Secret.Prompt",
        default_service = "org.freedesktop.secrets"
    )]
    trait Prompt {
        fn prompt(&self, window_id: &str) -> zbus::Result<()>;

        #[zbus(signal)]
        fn completed(&self, dismissed: bool, result: Value<'_>) -> zbus::Result<()>;
    }

    #[zbus::proxy(
        interface = "org.freedesktop.Secret.Session",
        default_service = "org.freedesktop.secrets"
    )]
    trait Session {
        fn close(&self) -> zbus::Result<()>;
    }

    /// The Secret Service on the session bus, or on a given connection (tests).
    pub struct SecretService {
        conn: Option<zbus::Connection>,
    }

    impl SecretService {
        /// Connects to the session bus at each use: a client that started before
        /// the desktop's keyring finds it later.
        pub fn session() -> SecretService {
            SecretService { conn: None }
        }

        pub fn with_connection(conn: zbus::Connection) -> SecretService {
            SecretService { conn: Some(conn) }
        }

        async fn connect(&self) -> Result<zbus::Connection, String> {
            match &self.conn {
                Some(c) => Ok(c.clone()),
                None => timed(zbus::Connection::session())
                    .await
                    .map_err(|e| format!("no session bus for the keyring: {e}")),
            }
        }
    }

    fn attributes(name: &str) -> HashMap<&str, &str> {
        HashMap::from([("application", APPLICATION), ("name", name)])
    }

    /// A call with the time limit, its error in words.
    async fn timed<T>(f: impl Future<Output = zbus::Result<T>>) -> Result<T, String> {
        match tokio::time::timeout(CALL, f).await {
            Ok(r) => r.map_err(describe),
            Err(_) => Err("the keyring did not answer".into()),
        }
    }

    fn describe(e: zbus::Error) -> String {
        match &e {
            zbus::Error::MethodError(name, ..)
                if matches!(
                    name.as_str(),
                    "org.freedesktop.DBus.Error.ServiceUnknown"
                        | "org.freedesktop.DBus.Error.NameHasNoOwner"
                ) =>
            {
                "no keyring service (org.freedesktop.secrets) on the session bus".into()
            }
            _ => format!("keyring: {e}"),
        }
    }

    fn none(p: &ObjectPath<'_>) -> bool {
        p.as_str() == "/"
    }

    /// Lets the service ask the owner (an unlock password, a confirmation) and
    /// waits for the answer. Dismissed or unanswered is an error.
    async fn prompt(conn: &zbus::Connection, path: &ObjectPath<'_>) -> Result<(), String> {
        let p = timed(
            PromptProxy::builder(conn)
                .path(path.to_owned())
                .map_err(describe)?
                .build(),
        )
        .await?;
        // Subscribed before the prompt shows, so a quick answer is not missed.
        let mut done = timed(p.receive_completed()).await?;
        timed(p.prompt("")).await?;
        match tokio::time::timeout(PROMPT, done.next()).await {
            Ok(Some(s)) => match s.args() {
                Ok(a) if !a.dismissed => Ok(()),
                Ok(_) => Err("the keyring prompt was cancelled".into()),
                Err(e) => Err(describe(e)),
            },
            Ok(None) => Err("the keyring went away during its prompt".into()),
            Err(_) => Err("the keyring prompt was not answered in time".into()),
        }
    }

    async fn unlock(
        conn: &zbus::Connection,
        service: &ServiceProxy<'_>,
        paths: &[OwnedObjectPath],
    ) -> Result<(), String> {
        if paths.is_empty() {
            return Ok(());
        }
        let refs: Vec<ObjectPath<'_>> = paths.iter().map(|p| p.as_ref()).collect();
        let (_, p) = timed(service.unlock(&refs)).await?;
        if none(&p) {
            return Ok(());
        }
        prompt(conn, &p)
            .await
            .map_err(|e| format!("the keyring stayed locked: {e}"))
    }

    /// A `plain` session, closed when dropped.
    struct OpenSession {
        proxy: SessionProxy<'static>,
        path: OwnedObjectPath,
    }

    impl Drop for OpenSession {
        fn drop(&mut self) {
            let proxy = self.proxy.clone();
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                h.spawn(async move {
                    let _ = proxy.close().await;
                });
            }
        }
    }

    async fn open(
        conn: &zbus::Connection,
        service: &ServiceProxy<'_>,
    ) -> Result<OpenSession, String> {
        let (_, path) = timed(service.open_session("plain", &Value::from(""))).await?;
        let proxy = timed(
            SessionProxy::builder(conn)
                .path(path.clone())
                .map_err(describe)?
                .build(),
        )
        .await?;
        Ok(OpenSession { proxy, path })
    }

    impl SecretService {
        async fn get_secret(&self, name: &str) -> Result<Option<Secret>, String> {
            let conn = self.connect().await?;
            let service = timed(ServiceProxy::new(&conn)).await?;
            let (unlocked, locked) = timed(service.search_items(attributes(name))).await?;
            let item = match (unlocked.first(), locked.first()) {
                (Some(i), _) => i.clone(),
                (None, Some(i)) => {
                    unlock(&conn, &service, std::slice::from_ref(i)).await?;
                    i.clone()
                }
                (None, None) => return Ok(None),
            };
            let session = open(&conn, &service).await?;
            let item = timed(
                ItemProxy::builder(&conn)
                    .path(item)
                    .map_err(describe)?
                    .build(),
            )
            .await?;
            let (_, _, value, _) = timed(item.get_secret(&session.path)).await?;
            secret_from_bytes(value).map(Some)
        }

        async fn set_secret(&self, name: &str, value: &Secret) -> Result<(), String> {
            let conn = self.connect().await?;
            let service = timed(ServiceProxy::new(&conn)).await?;
            let collection = timed(service.read_alias("default")).await?;
            if none(&collection) {
                return Err("the keyring has no default collection to keep it in".into());
            }
            let c = timed(
                CollectionProxy::builder(&conn)
                    .path(collection.clone())
                    .map_err(describe)?
                    .cache_properties(CacheProperties::No)
                    .build(),
            )
            .await?;
            if timed(c.locked()).await? {
                unlock(&conn, &service, &[collection]).await?;
            }
            let session = open(&conn, &service).await?;
            let attrs: HashMap<String, String> = attributes(name)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let props = HashMap::from([
                (
                    "org.freedesktop.Secret.Item.Label",
                    Value::from(format!("Pithagoras Sync: {name}")),
                ),
                ("org.freedesktop.Secret.Item.Attributes", Value::from(attrs)),
            ]);
            let mut bytes = value.expose().as_bytes().to_vec();
            let secret = (
                session.path.as_ref(),
                Vec::new(),
                bytes.clone(),
                "text/plain",
            );
            bytes.fill(0);
            let created = timed(c.create_item(props, &secret, true)).await;
            let (_, _, mut sent, _) = secret;
            sent.fill(0);
            let (item, p) = created?;
            if none(&item) && !none(&p) {
                prompt(&conn, &p).await?;
            }
            Ok(())
        }

        async fn delete_secret(&self, name: &str) -> Result<(), String> {
            let conn = self.connect().await?;
            let service = timed(ServiceProxy::new(&conn)).await?;
            let (unlocked, locked) = timed(service.search_items(attributes(name))).await?;
            unlock(&conn, &service, &locked).await?;
            for path in unlocked.into_iter().chain(locked) {
                let item = timed(
                    ItemProxy::builder(&conn)
                        .path(path)
                        .map_err(describe)?
                        .build(),
                )
                .await?;
                let p = timed(item.delete()).await?;
                if !none(&p) {
                    prompt(&conn, &p).await?;
                }
            }
            Ok(())
        }
    }

    impl SecretStore for SecretService {
        fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Secret>, String>> {
            Box::pin(self.get_secret(name))
        }

        fn set<'a>(
            &'a self,
            name: &'a str,
            value: &'a Secret,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(self.set_secret(name, value))
        }

        fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(self.delete_secret(name))
        }
    }
}

/// The Windows Credential Manager: generic credentials named
/// `pithagoras-sync/<name>`, kept for this user on this machine
/// (`CRED_PERSIST_LOCAL_MACHINE`, not roamed). `cmdkey /list` shows them. Not run
/// by the tests (they run on Linux, or set `NO_KEYRING_ENV`).
#[cfg(windows)]
pub mod credentials {
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, FILETIME, GetLastError};
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree,
        CredReadW, CredWriteW,
    };

    use super::{APPLICATION, SecretStore, secret_from_bytes};
    use crate::approve::BoxFuture;
    use crate::secret::Secret;

    pub struct CredentialManager;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn target(name: &str) -> Vec<u16> {
        wide(&format!("{APPLICATION}/{name}"))
    }

    fn get(name: &str) -> Result<Option<Secret>, String> {
        let target = target(name);
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: the target is NUL-terminated; on success `cred` is freed below.
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) } == 0 {
            // SAFETY: no preconditions.
            let err = unsafe { GetLastError() };
            if err == ERROR_NOT_FOUND {
                return Ok(None);
            }
            return Err(format!(
                "Credential Manager: {}",
                std::io::Error::from_raw_os_error(err as i32)
            ));
        }
        // SAFETY: CredReadW returned a valid credential whose blob holds
        // CredentialBlobSize bytes; it is copied before CredFree.
        let bytes = unsafe {
            let c = &*cred;
            let b = if c.CredentialBlob.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec()
            };
            CredFree(cred.cast());
            b
        };
        secret_from_bytes(bytes).map(Some)
    }

    fn set(name: &str, value: &Secret) -> Result<(), String> {
        let mut target = target(name);
        let mut user = wide(APPLICATION);
        let mut blob = value.expose().as_bytes().to_vec();
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            Comment: std::ptr::null_mut(),
            LastWritten: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: user.as_mut_ptr(),
        };
        // SAFETY: every pointer in `cred` points into a buffer that outlives the call.
        let ok = unsafe { CredWriteW(&cred, 0) };
        let err = std::io::Error::last_os_error();
        blob.fill(0);
        if ok == 0 {
            return Err(format!("Credential Manager: {err}"));
        }
        Ok(())
    }

    fn delete(name: &str) -> Result<(), String> {
        let target = target(name);
        // SAFETY: the target is NUL-terminated.
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            // SAFETY: no preconditions.
            let err = unsafe { GetLastError() };
            if err != ERROR_NOT_FOUND {
                return Err(format!(
                    "Credential Manager: {}",
                    std::io::Error::from_raw_os_error(err as i32)
                ));
            }
        }
        Ok(())
    }

    impl SecretStore for CredentialManager {
        fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Secret>, String>> {
            Box::pin(async move { get(name) })
        }

        fn set<'a>(
            &'a self,
            name: &'a str,
            value: &'a Secret,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move { set(name, value) })
        }

        fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move { delete(name) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_fake_keeps_and_fails_like_a_keyring() {
        let s = FakeStore::default();
        assert_eq!(s.get("token").await, Ok(None));
        s.set("token", &Secret::new("t1".into())).await.unwrap();
        assert_eq!(s.get("token").await.unwrap().unwrap().expose(), "t1");
        *s.fail.lock().unwrap() = Some("locked".into());
        assert_eq!(s.get("token").await, Err("locked".into()));
        *s.fail.lock().unwrap() = None;
        s.delete("token").await.unwrap();
        assert_eq!(s.get("token").await, Ok(None));
        s.delete("token").await.unwrap();
    }

    #[tokio::test]
    async fn no_keyring_when_told_so() {
        // SAFETY: tests in this binary do not read this variable concurrently.
        unsafe { std::env::set_var(NO_KEYRING_ENV, "1") };
        let e = system().get("token").await.unwrap_err();
        assert!(e.contains(NO_KEYRING_ENV), "{e}");
        assert!(secret_from_bytes(vec![0xff]).is_err());
    }
}
