//! Linux Secret Service (`org.freedesktop.secrets`) backend for [`KeyStore`].
//!
//! Drives the `secret-service` async API through zbus's synchronous driver for the running
//! D-Bus Secret Service implementation (GNOME Keyring / KWallet /
//! `keepassxc-secret-service`). Items live in the user's default
//! collection (`/org/freedesktop/secrets/aliases/default`) and are tagged
//! with two attributes:
//!
//! - `service = "arkret.<application_id>"` — namespaces items so multiple Arkret-using apps on the
//!   same desktop don't collide.
//! - `account = <key_id>` — the caller-supplied opaque key id.
//!
//! Collisions on `(service, account)` are resolved by overwriting the
//! existing item (the Secret Service `replace` flag). SDK mutations take a
//! namespaced D-Bus lease on the same bus as the Secret Service session.
//! This serializes cooperating SDK processes even with different filesystem
//! homes. Direct external writers must not mutate this namespace concurrently.

use futures_util::StreamExt;
use secret_service::{EncryptionType, SecretService};
use sha2::{Digest, Sha256};
use zbus::Connection;
use zbus::fdo::{DBusProxy, RequestNameReply};

use crate::contract::{KeyBytes, Result, service_name, validate_id};
use crate::{KeyStore, KeyStoreError};

/// Linux Secret Service-backed [`KeyStore`].
pub struct LinuxSecretServiceKeyStore {
    service: String,
}

impl LinuxSecretServiceKeyStore {
    /// Construct a keystore for the given application id, using the
    /// default collection.
    pub fn new(application_id: &str) -> std::result::Result<Self, KeyStoreError> {
        if application_id.is_empty() {
            return Err(KeyStoreError::invalid_id(
                "application_id must be non-empty",
            ));
        }
        // Probe the bus once so a missing Secret Service surfaces at
        // construction time rather than per call.
        Self::connect()?;
        Ok(Self {
            service: service_name(application_id),
        })
    }

    fn connect() -> std::result::Result<SecretService<'static>, KeyStoreError> {
        zbus::block_on(async {
            SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(|err| KeyStoreError::backend(format!("secret-service: {err}")))
        })
    }

    fn attrs<'a>(&'a self, id: &'a str) -> std::collections::HashMap<&'a str, &'a str> {
        let mut a = std::collections::HashMap::new();
        a.insert("service", self.service.as_str());
        a.insert("account", id);
        a
    }
}

// The bus owns this lease: disconnect/crash releases it without a stale file.
struct MutationLease(Connection);

impl Drop for MutationLease {
    fn drop(&mut self) {
        // Close even if Secret Service or proxy clones remain after a failure.
        let _ = zbus::block_on(self.0.clone().close());
    }
}

impl LinuxSecretServiceKeyStore {
    fn mutation_session(&self) -> Result<(MutationLease, SecretService<'static>)> {
        let connection = zbus::block_on(Connection::session()).map_err(bus_error)?;
        let lease = MutationLease(connection);
        let session = zbus::block_on(async {
            let digest = Sha256::digest(self.service.as_bytes());
            let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            let name = format!("org.arkret.KeyStore.n{suffix}");
            {
                let proxy = DBusProxy::new(&lease.0).await.map_err(bus_error)?;
                // Subscribe before queueing so rapid acquisition cannot be lost.
                let mut acquired = proxy.receive_name_acquired().await.map_err(bus_error)?;
                // RequestName flags = 0: queue; neither replace nor allow replacement.
                let reply: RequestNameReply = proxy
                    .inner()
                    .call("RequestName", &(name.as_str(), 0u32))
                    .await
                    .map_err(bus_error)?;
                match reply {
                    RequestNameReply::PrimaryOwner => {}
                    RequestNameReply::InQueue => loop {
                        let signal = acquired.next().await.ok_or_else(|| {
                            KeyStoreError::backend("key-store bus lease connection closed")
                        })?;
                        if signal.args().map_err(bus_error)?.name.as_str() == name {
                            break;
                        }
                    },
                    _ => {
                        return Err(KeyStoreError::backend(
                            "key-store bus lease was not acquired",
                        ));
                    }
                }
            }
            let session = SecretService::connect_with_existing(EncryptionType::Dh, lease.0.clone())
                .await
                .map_err(|error| KeyStoreError::backend(format!("secret-service: {error}")))?;
            Ok(session)
        })?;
        Ok((lease, session))
    }

    fn load_from(&self, ss: &SecretService<'_>, id: &str) -> Result<KeyBytes> {
        zbus::block_on(async {
            let items = ss
                .search_items(self.attrs(id))
                .await
                .map_err(|error| KeyStoreError::backend(format!("search items: {error}")))?;
            let mut items = items.unlocked.into_iter().chain(items.locked);
            let item = items.next().ok_or_else(|| KeyStoreError::not_found(id))?;
            if items.next().is_some() {
                return Err(KeyStoreError::backend("ambiguous Secret Service key id"));
            }
            if item
                .is_locked()
                .await
                .map_err(|error| KeyStoreError::backend(format!("item lock: {error}")))?
            {
                item.unlock()
                    .await
                    .map_err(|error| KeyStoreError::backend(format!("unlock item: {error}")))?;
            }
            item.get_secret()
                .await
                .map(KeyBytes::new)
                .map_err(|error| KeyStoreError::backend(format!("get secret: {error}")))
        })
    }

    fn write_to(&self, ss: &SecretService<'_>, id: &str, key: &[u8], replace: bool) -> Result<()> {
        zbus::block_on(async {
            let collection = ss
                .get_collection_by_alias("default")
                .await
                .map_err(|error| KeyStoreError::backend(format!("get collection: {error}")))?;
            if collection
                .is_locked()
                .await
                .map_err(|error| KeyStoreError::backend(format!("collection lock: {error}")))?
            {
                collection.unlock().await.map_err(|error| {
                    KeyStoreError::backend(format!("unlock collection: {error}"))
                })?;
            }
            let label = format!("{}/{}", self.service, id);
            collection
                .create_item(&label, self.attrs(id), key, replace, "text/plain")
                .await
                .map_err(|error| KeyStoreError::backend(format!("create item: {error}")))?;
            Ok(())
        })
    }
}

fn bus_error(error: impl std::fmt::Display) -> KeyStoreError {
    KeyStoreError::backend(format!("key-store bus lease: {error}"))
}

impl KeyStore for LinuxSecretServiceKeyStore {
    fn load(&self, id: &str) -> Result<KeyBytes> {
        validate_id(id)?;
        self.load_from(&Self::connect()?, id)
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<()> {
        validate_id(id)?;
        let (_lease, ss) = self.mutation_session()?;
        self.write_to(&ss, id, key, true)
    }

    fn create_if_absent(&self, id: &str, key: &[u8]) -> Result<KeyBytes> {
        validate_id(id)?;
        let (_lease, ss) = self.mutation_session()?;
        match self.load_from(&ss, id) {
            Ok(existing) => Ok(existing),
            Err(error) if error.is_not_found() => {
                self.write_to(&ss, id, key, false)?;
                self.load_from(&ss, id)
            }
            Err(error) => Err(error),
        }
    }

    fn list(&self) -> Result<Vec<String>> {
        let ss = Self::connect()?;
        zbus::block_on(async {
            let mut attrs = std::collections::HashMap::new();
            attrs.insert("service", self.service.as_str());
            let items = ss
                .search_items(attrs)
                .await
                .map_err(|error| KeyStoreError::backend(format!("search items: {error}")))?;
            let mut ids = Vec::new();
            for item in items.unlocked.iter().chain(items.locked.iter()) {
                if let Ok(item_attrs) = item.get_attributes().await
                    && let Some(id) = item_attrs.get("account")
                {
                    ids.push(id.clone());
                }
            }
            ids.sort();
            ids.dedup();
            Ok(ids)
        })
    }

    fn delete(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        let (_lease, ss) = self.mutation_session()?;
        zbus::block_on(async {
            let items = ss
                .search_items(self.attrs(id))
                .await
                .map_err(|error| KeyStoreError::backend(format!("search items: {error}")))?;
            for item in items.unlocked.into_iter().chain(items.locked) {
                item.delete()
                    .await
                    .map_err(|error| KeyStoreError::backend(format!("delete item: {error}")))?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    //! Skipped automatically off-Linux. On Linux CI without a running
    //! D-Bus Secret Service these tests fail at construction with
    //! `KeyStoreError::Backend`; gate `ARKRET_TEST_LINUX_KEYSTORE=1`
    //! before running.

    use super::*;

    fn enabled() -> bool {
        std::env::var("ARKRET_TEST_LINUX_KEYSTORE").as_deref() == Ok("1")
    }

    fn unique_app_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("test.{nanos:x}")
    }

    #[test]
    fn duplicate_items_are_rejected_without_overwriting_either_secret() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        let ss = LinuxSecretServiceKeyStore::connect().unwrap();
        store.write_to(&ss, "duplicate", b"first", false).unwrap();
        store.write_to(&ss, "duplicate", b"second", false).unwrap();
        assert!(
            store
                .load("duplicate")
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
        assert!(store.create_if_absent("duplicate", b"replacement").is_err());
        let items = zbus::block_on(ss.search_items(store.attrs("duplicate"))).unwrap();
        let mut secrets = items
            .unlocked
            .iter()
            .chain(items.locked.iter())
            .map(|item| zbus::block_on(item.get_secret()).unwrap())
            .collect::<Vec<_>>();
        secrets.sort();
        assert_eq!(secrets, [b"first".to_vec(), b"second".to_vec()]);
        store.delete("duplicate").unwrap();
    }

    #[test]
    fn dropping_lease_closes_connection_and_releases_ownership() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        let (lease, ss) = store.mutation_session().unwrap();
        let retained_connection = lease.0.clone();
        drop(lease);
        // Even retained library references cannot keep the lease alive.
        assert!(
            zbus::block_on(async {
                DBusProxy::new(&retained_connection)
                    .await?
                    .list_names()
                    .await
            })
            .is_err()
        );
        drop(ss);
        let (_next_lease, _next_ss) = store.mutation_session().unwrap();
    }

    #[test]
    fn round_trip_store_load_delete() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        let id = "arkret:signer:alice:k1";
        store.store(id, b"linux-secret-1").unwrap();
        assert_eq!(store.load(id).unwrap().as_slice(), b"linux-secret-1");
        store.delete(id).unwrap();
        let err = store.load(id).unwrap_err();
        assert!(err.is_not_found());
    }

    #[test]
    fn store_overwrites_existing_id() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        let id = "arkret:signer:bob:k1";
        store.store(id, b"first").unwrap();
        store.store(id, b"second").unwrap();
        assert_eq!(store.load(id).unwrap().as_slice(), b"second");
        store.delete(id).unwrap();
    }

    #[test]
    fn delete_missing_id_is_idempotent() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        store.delete("never-stored").unwrap();
    }

    #[test]
    fn rejects_empty_id() {
        if !enabled() {
            return;
        }
        let store = LinuxSecretServiceKeyStore::new(&unique_app_id()).unwrap();
        assert!(store.store("", b"x").is_err());
    }

    #[test]
    fn list_returns_only_keys_in_service_namespace() {
        if !enabled() {
            return;
        }
        let app_a = unique_app_id();
        let app_b = unique_app_id();
        let store_a = LinuxSecretServiceKeyStore::new(&app_a).unwrap();
        let store_b = LinuxSecretServiceKeyStore::new(&app_b).unwrap();
        store_a.store("k-a-1", b"a1").unwrap();
        store_a.store("k-a-2", b"a2").unwrap();
        store_b.store("k-b-1", b"b1").unwrap();

        let listed_a = store_a.list().unwrap();
        assert!(listed_a.contains(&"k-a-1".to_owned()));
        assert!(listed_a.contains(&"k-a-2".to_owned()));
        assert!(!listed_a.contains(&"k-b-1".to_owned()));

        store_a.delete("k-a-1").unwrap();
        store_a.delete("k-a-2").unwrap();
        store_b.delete("k-b-1").unwrap();
    }
}
