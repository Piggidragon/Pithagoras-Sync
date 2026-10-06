#![cfg(unix)]
//! The Secret Service client against a private D-Bus daemon and the fake keyring
//! service of the testkit, so no real keyring is ever read or written by the tests.

use sync_policy::keyring::SecretStore;
use sync_policy::keyring::secret_service::SecretService;
use sync_policy::secret::Secret;
use sync_testkit::keyring::{Bus, Shared, answer_waiting, private_bus, serve};

async fn client(bus: &Bus) -> SecretService {
    client_of(bus, "/home/someone/.config/pithagoras-sync").await
}

/// The keyring as the client with its config in `config` sees it.
async fn client_of(bus: &Bus, config: &str) -> SecretService {
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    SecretService::with_connection(conn, config.into())
}

fn secret(s: &str) -> Secret {
    Secret::new(s.into())
}

#[tokio::test]
async fn set_get_and_delete_in_the_default_collection() {
    let Some(bus) = private_bus() else { return };
    let state = Shared::default();
    let _server = serve(&bus, state.clone()).await;
    let ks = client(&bus).await;
    assert_eq!(ks.get("token").await, Ok(None));
    ks.set("token", &secret("tok-1")).await.unwrap();
    ks.set("elevation", &secret("pw one")).await.unwrap();
    // Replaced, not added.
    ks.set("token", &secret("tok-2")).await.unwrap();
    assert_eq!(ks.get("token").await.unwrap().unwrap().expose(), "tok-2");
    assert_eq!(
        ks.get("elevation").await.unwrap().unwrap().expose(),
        "pw one"
    );
    {
        let s = state.lock().unwrap();
        assert_eq!(s.items.len(), 2);
        for (_, attrs, _) in &s.items {
            assert_eq!(attrs["application"], "pithagoras-sync");
        }
        // The label names the entry, never its value.
        assert!(
            s.labels
                .iter()
                .all(|l| !l.contains("tok-") && !l.contains("pw one"))
        );
    }
    ks.delete("token").await.unwrap();
    assert_eq!(ks.get("token").await, Ok(None));
    assert!(ks.get("elevation").await.unwrap().is_some());
    ks.delete("token").await.unwrap();
}

#[tokio::test]
async fn a_locked_keyring_is_unlocked_through_its_prompt() {
    let Some(bus) = private_bus() else { return };
    let state = Shared::default();
    let _server = serve(&bus, state.clone()).await;
    let ks = client(&bus).await;
    ks.set("token", &secret("tok-1")).await.unwrap();
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.answer = Some(true);
    }
    assert_eq!(ks.get("token").await.unwrap().unwrap().expose(), "tok-1");
    assert_eq!(state.lock().unwrap().prompts, 1);
    // Writing to a locked collection unlocks it first, too.
    state.lock().unwrap().locked = true;
    ks.set("token", &secret("tok-3")).await.unwrap();
    assert_eq!(state.lock().unwrap().prompts, 2);
    state.lock().unwrap().locked = true;
    ks.delete("token").await.unwrap();
    assert!(state.lock().unwrap().items.is_empty());
}

#[tokio::test]
async fn a_dismissed_prompt_is_an_error_not_an_empty_keyring() {
    let Some(bus) = private_bus() else { return };
    let state = Shared::default();
    let _server = serve(&bus, state.clone()).await;
    let ks = client(&bus).await;
    ks.set("token", &secret("tok-1")).await.unwrap();
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.answer = Some(false);
    }
    let e = ks.get("token").await.unwrap_err();
    assert!(e.contains("locked") && e.contains("cancelled"), "{e}");
    let e = ks.set("token", &secret("tok-2")).await.unwrap_err();
    assert!(e.contains("cancelled"), "{e}");
    let e = ks.delete("token").await.unwrap_err();
    assert!(e.contains("cancelled"), "{e}");
    let s = state.lock().unwrap();
    assert_eq!(s.items.len(), 1);
    assert_eq!(s.items[0].2, b"tok-1");
}

/// Two clients of one user, each with its own config folder: neither reads,
/// replaces or removes what the other keeps.
#[tokio::test]
async fn each_config_folder_has_its_own_entries() {
    let Some(bus) = private_bus() else { return };
    let state = Shared::default();
    let _server = serve(&bus, state.clone()).await;
    let a = client_of(&bus, "/home/someone/.config/pithagoras-sync").await;
    let b = client_of(&bus, "/home/someone/test/pithagoras-sync").await;
    a.set("token", &secret("tok-a")).await.unwrap();
    assert_eq!(b.get("token").await, Ok(None));
    assert_eq!(b.has("token").await, Ok(false));
    b.set("token", &secret("tok-b")).await.unwrap();
    b.delete("token").await.unwrap();
    assert_eq!(a.get("token").await.unwrap().unwrap().expose(), "tok-a");
    let s = state.lock().unwrap();
    assert_eq!(s.items.len(), 1);
    assert_eq!(
        s.items[0].1["config"],
        "/home/someone/.config/pithagoras-sync"
    );
}

/// Two reads find the keyring locked at once (the token and the password at
/// the client's start): the owner sees one prompt, and its answer counts for
/// both, unlocked or not.
#[tokio::test]
async fn two_reads_at_once_show_one_prompt() {
    let Some(bus) = private_bus() else { return };
    let state = Shared::default();
    let _server = serve(&bus, state.clone()).await;
    let ks = std::sync::Arc::new(client(&bus).await);
    ks.set("token", &secret("tok-1")).await.unwrap();
    ks.set("elevation", &secret("pw one")).await.unwrap();
    for unlock in [true, false] {
        {
            let mut s = state.lock().unwrap();
            s.locked = true;
            s.answer = None;
            s.prompts = 0;
        }
        let reads = ["token", "elevation"].map(|name| {
            let ks = ks.clone();
            tokio::spawn(async move { ks.get(name).await })
        });
        // The first prompt is up; the other read waits, or shows its own.
        while state.lock().unwrap().waiting.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        answer_waiting(&state, unlock).await;
        let mut got = Vec::new();
        for r in reads {
            got.push(r.await.unwrap());
        }
        assert_eq!(state.lock().unwrap().prompts, 1, "unlock {unlock}");
        if unlock {
            assert_eq!(got[0].as_ref().unwrap().as_ref().unwrap().expose(), "tok-1");
            assert_eq!(
                got[1].as_ref().unwrap().as_ref().unwrap().expose(),
                "pw one"
            );
        } else {
            assert!(
                got.iter()
                    .all(|r| r.as_ref().unwrap_err().contains("stayed locked")),
                "{got:?}"
            );
        }
    }
}

/// `has` tells whether an entry is there without a prompt, even locked.
#[tokio::test]
async fn whether_there_is_an_entry_asks_nobody() {
    let Some(bus) = private_bus() else { return };
    let state = Shared::default();
    let _server = serve(&bus, state.clone()).await;
    let ks = client(&bus).await;
    assert_eq!(ks.has("elevation").await, Ok(false));
    ks.set("elevation", &secret("pw")).await.unwrap();
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.answer = Some(false);
    }
    assert_eq!(ks.has("elevation").await, Ok(true));
    assert_eq!(ks.has("token").await, Ok(false));
    assert_eq!(state.lock().unwrap().prompts, 0);
}

#[tokio::test]
async fn no_service_on_the_bus_is_an_error() {
    let Some(bus) = private_bus() else { return };
    let ks = client(&bus).await;
    let e = ks.get("token").await.unwrap_err();
    assert!(e.contains("no keyring service"), "{e}");
    let e = ks.set("token", &secret("t")).await.unwrap_err();
    assert!(e.contains("no keyring service"), "{e}");
}
