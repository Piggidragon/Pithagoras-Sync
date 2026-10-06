//! Where the connector token is kept: the 0600 file, or the OS keyring
//! (`token_storage`). The daemon, `pair`, `unpair`, `uninstall --purge`, `status`
//! and the switch between the two all go through `TokenStore`.
//!
//! The default is the file on Linux and the keyring on Windows. Only that Windows
//! default may fall back to the file when the keyring fails; a `keyring` the owner
//! chose never does, it fails instead.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sync_policy::config::TokenStorage;
use sync_policy::keyring::SecretStore;
use sync_policy::secret::Secret;

use crate::pair::{load_token, save_token, valid_token};

/// The token's name in the keyring.
pub const KEYRING_NAME: &str = "token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    File,
    /// `explicit`: the owner chose it, so it never falls back.
    Keyring {
        explicit: bool,
    },
}

pub struct TokenStore {
    file: PathBuf,
    place: Place,
    keyring: Arc<dyn SecretStore>,
}

impl TokenStore {
    /// The store `choice` names, with this platform's default when it is unset.
    pub fn new(file: PathBuf, choice: Option<TokenStorage>, keyring: Arc<dyn SecretStore>) -> Self {
        TokenStore::for_platform(file, choice, keyring, cfg!(windows))
    }

    /// As `new`, with the default of Windows (`keyring_default`) or Linux.
    pub fn for_platform(
        file: PathBuf,
        choice: Option<TokenStorage>,
        keyring: Arc<dyn SecretStore>,
        keyring_default: bool,
    ) -> Self {
        let place = match choice {
            Some(TokenStorage::File) => Place::File,
            Some(TokenStorage::Keyring) => Place::Keyring { explicit: true },
            None if keyring_default => Place::Keyring { explicit: false },
            None => Place::File,
        };
        TokenStore {
            file,
            place,
            keyring,
        }
    }

    pub fn file(&self) -> &Path {
        &self.file
    }

    pub fn uses_keyring(&self) -> bool {
        matches!(self.place, Place::Keyring { .. })
    }

    /// For `status`: where the token is meant to be.
    pub fn describe(&self) -> &'static str {
        match self.place {
            Place::File => "file",
            Place::Keyring { explicit: true } => "keyring",
            Place::Keyring { explicit: false } => "keyring (the default here)",
        }
    }

    async fn read_keyring(&self) -> Result<Option<String>, String> {
        match self.keyring.get(KEYRING_NAME).await {
            Ok(Some(s)) if valid_token(s.expose()) => Ok(Some(s.expose().to_string())),
            Ok(Some(_)) => Err("the keyring holds no usable token".into()),
            Ok(None) => Ok(None),
            Err(e) => Err(format!("cannot read the token from the keyring: {e}")),
        }
    }

    /// The token, for the link.
    pub async fn load(&self) -> Result<String, String> {
        match self.place {
            Place::File => load_token(&self.file),
            // A token the default fell back to, or one from before the keyring
            // was the default, keeps working.
            Place::Keyring { explicit: false } if self.file.exists() => load_token(&self.file),
            Place::Keyring { explicit } => match self.read_keyring().await? {
                Some(t) => Ok(t),
                None if explicit => {
                    Err("no token in the keyring (token_storage = keyring): pair again".into())
                }
                None => Err("no token in the keyring: pair again".into()),
            },
        }
    }

    /// Where the token is now, wherever this store may have put it; `None`
    /// when there is none.
    async fn current(&self) -> Result<Option<String>, String> {
        if self.file.exists() {
            return load_token(&self.file).map(Some);
        }
        if self.uses_keyring() {
            return self.read_keyring().await;
        }
        Ok(None)
    }

    /// Writes the token to this store's place. `Ok(true)` when it is in the
    /// keyring, `Ok(false)` in the file, with a note when the default fell back.
    async fn write(&self, token: &str) -> Result<(bool, Option<String>), String> {
        match self.place {
            Place::File => save_token(&self.file, token).map(|()| (false, None)),
            Place::Keyring { explicit } => {
                let secret = Secret::new(token.to_string());
                match self.keyring.set(KEYRING_NAME, &secret).await {
                    Ok(()) => Ok((true, None)),
                    Err(e) if explicit => Err(format!(
                        "cannot keep the token in the keyring (token_storage = keyring): {e}"
                    )),
                    Err(e) => {
                        save_token(&self.file, token)?;
                        Ok((
                            false,
                            Some(format!(
                                "the keyring did not take the token ({e}); it is kept in {}",
                                self.file.display()
                            )),
                        ))
                    }
                }
            }
        }
    }

    fn remove_file(&self) -> Result<(), String> {
        match std::fs::remove_file(&self.file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(format!("{}: {e}", self.file.display()))
            }
            _ => Ok(()),
        }
    }

    /// Keeps a new token (`pair`). Returns a note for the owner when the
    /// Windows default fell back to the file.
    pub async fn save(&self, token: &str) -> Result<Option<String>, String> {
        let (in_keyring, note) = self.write(token).await?;
        // The old file would otherwise win over the keyring at the next start.
        if in_keyring {
            self.remove_file()?;
        }
        Ok(note)
    }

    /// Forgets the token (`unpair`, `uninstall --purge`): the file, and the
    /// keyring entry where this store uses the keyring. A store on the file
    /// leaves the keyring alone, so it never asks to unlock one.
    pub async fn delete(&self) -> Result<(), String> {
        self.remove_file()?;
        if self.uses_keyring() {
            self.keyring
                .delete(KEYRING_NAME)
                .await
                .map_err(|e| format!("cannot remove the token from the keyring: {e}"))?;
        }
        Ok(())
    }

    /// Moves the token from this store to `to` (`config set token_storage`): it
    /// is written to the new place first, then `commit` saves the setting, and
    /// only then does the old place lose it. A failure before `commit` leaves
    /// the token and the setting as they were.
    pub async fn switch(
        &self,
        to: &TokenStore,
        commit: impl FnOnce() -> Result<(), String>,
    ) -> Result<Option<String>, String> {
        let Some(token) = self.current().await? else {
            commit()?;
            return Ok(None);
        };
        let (in_keyring, note) = to.write(&token).await?;
        commit()?;
        if in_keyring {
            self.remove_file()?;
        } else if self.uses_keyring() {
            self.keyring.delete(KEYRING_NAME).await.map_err(|e| {
                format!("the token is in the file now, but its keyring entry stays: {e}")
            })?;
        }
        Ok(note)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync_policy::keyring::FakeStore;

    const T1: &str = "tttttttttttttttttttttttttttttttt1";
    const T2: &str = "tttttttttttttttttttttttttttttttt2";

    fn store(
        dir: &Path,
        choice: Option<TokenStorage>,
        ks: &Arc<FakeStore>,
        windows: bool,
    ) -> TokenStore {
        TokenStore::for_platform(dir.join("token"), choice, ks.clone(), windows)
    }

    fn in_keyring(ks: &FakeStore) -> Option<String> {
        ks.entries
            .lock()
            .unwrap()
            .get(KEYRING_NAME)
            .map(|s| s.expose().to_string())
    }

    #[tokio::test]
    async fn linux_keeps_the_file_and_never_asks_the_keyring() {
        let t = tempfile::tempdir().unwrap();
        let ks = Arc::new(FakeStore::default());
        // A keyring that would fail: the file store must not need it.
        *ks.fail.lock().unwrap() = Some("locked".into());
        let s = store(t.path(), None, &ks, false);
        assert_eq!(s.save(T1).await, Ok(None));
        assert_eq!(s.load().await.unwrap(), T1);
        assert_eq!(s.describe(), "file");
        s.delete().await.unwrap();
        assert!(!t.path().join("token").exists());
    }

    #[tokio::test]
    async fn the_windows_default_uses_the_keyring_and_falls_back_to_the_file() {
        let t = tempfile::tempdir().unwrap();
        let ks = Arc::new(FakeStore::default());
        let s = store(t.path(), None, &ks, true);
        assert_eq!(s.save(T1).await, Ok(None));
        assert_eq!(in_keyring(&ks).as_deref(), Some(T1));
        assert!(!t.path().join("token").exists());
        assert_eq!(s.load().await.unwrap(), T1);
        // The keyring fails: the token goes to the file, with one note.
        *ks.fail.lock().unwrap() = Some("no service".into());
        let note = s.save(T2).await.unwrap().unwrap();
        assert!(
            note.contains("no service") && note.contains("token"),
            "{note}"
        );
        assert_eq!(s.load().await.unwrap(), T2);
        // An existing token file keeps working, even with a keyring that answers.
        *ks.fail.lock().unwrap() = None;
        assert_eq!(s.load().await.unwrap(), T2);
    }

    #[tokio::test]
    async fn an_explicit_keyring_never_falls_back() {
        let t = tempfile::tempdir().unwrap();
        let ks = Arc::new(FakeStore::default());
        *ks.fail.lock().unwrap() = Some("the prompt was cancelled".into());
        for windows in [false, true] {
            let s = store(t.path(), Some(TokenStorage::Keyring), &ks, windows);
            let e = s.save(T1).await.unwrap_err();
            assert!(
                e.contains("cancelled") && e.contains("token_storage = keyring"),
                "{e}"
            );
            assert!(!t.path().join("token").exists(), "no silent fallback");
            assert!(s.load().await.unwrap_err().contains("cancelled"));
        }
        // An empty keyring is no token, not a reason to read a file.
        *ks.fail.lock().unwrap() = None;
        save_token(&t.path().join("token"), T1).unwrap();
        let s = store(t.path(), Some(TokenStorage::Keyring), &ks, false);
        assert!(s.load().await.unwrap_err().contains("pair again"));
    }

    #[tokio::test]
    async fn switching_moves_the_token_both_ways_without_losing_it() {
        let t = tempfile::tempdir().unwrap();
        let ks = Arc::new(FakeStore::default());
        let file = store(t.path(), Some(TokenStorage::File), &ks, false);
        let keyring = store(t.path(), Some(TokenStorage::Keyring), &ks, false);
        file.save(T1).await.unwrap();
        let mut committed = false;
        file.switch(&keyring, || {
            // The new place has it before the setting changes.
            assert_eq!(in_keyring(&ks).as_deref(), Some(T1));
            assert!(t.path().join("token").exists());
            committed = true;
            Ok(())
        })
        .await
        .unwrap();
        assert!(committed);
        assert!(!t.path().join("token").exists());
        assert_eq!(keyring.load().await.unwrap(), T1);
        keyring
            .switch(&file, || {
                assert!(t.path().join("token").exists());
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(in_keyring(&ks), None);
        assert_eq!(file.load().await.unwrap(), T1);
    }

    #[tokio::test]
    async fn a_failed_switch_keeps_the_token_where_it_was() {
        let t = tempfile::tempdir().unwrap();
        let ks = Arc::new(FakeStore::default());
        let file = store(t.path(), Some(TokenStorage::File), &ks, false);
        let keyring = store(t.path(), Some(TokenStorage::Keyring), &ks, false);
        file.save(T1).await.unwrap();
        *ks.fail.lock().unwrap() = Some("locked".into());
        let e = file
            .switch(&keyring, || panic!("the setting must not change"))
            .await
            .unwrap_err();
        assert!(e.contains("locked"), "{e}");
        assert_eq!(file.load().await.unwrap(), T1);
        // The setting cannot be saved: the old place keeps it.
        *ks.fail.lock().unwrap() = None;
        let e = file
            .switch(&keyring, || Err("disk full".into()))
            .await
            .unwrap_err();
        assert_eq!(e, "disk full");
        assert_eq!(file.load().await.unwrap(), T1);
        // Not paired: only the setting changes.
        let empty = tempfile::tempdir().unwrap();
        let none = store(empty.path(), Some(TokenStorage::File), &ks, false);
        let mut committed = false;
        none.switch(&keyring, || {
            committed = true;
            Ok(())
        })
        .await
        .unwrap();
        assert!(committed);
    }

    #[tokio::test]
    async fn unpair_removes_the_keyring_entry_too() {
        let t = tempfile::tempdir().unwrap();
        let ks = Arc::new(FakeStore::default());
        let s = store(t.path(), Some(TokenStorage::Keyring), &ks, false);
        s.save(T1).await.unwrap();
        s.delete().await.unwrap();
        assert_eq!(in_keyring(&ks), None);
        // A file store leaves a keyring it does not use alone.
        ks.entries
            .lock()
            .unwrap()
            .insert(KEYRING_NAME.into(), Secret::new(T2.into()));
        store(t.path(), None, &ks, false).delete().await.unwrap();
        assert_eq!(in_keyring(&ks).as_deref(), Some(T2));
    }
}
