//! Per-admin signing key store: KeyStore-backed key addressing keyed by
//! `(application_id, admin_did)`.
//!
//! Admin operations (notary reconfiguration, compaction submission, bottom
//! repair, etc.) are signed today by the service identity — the same key the
//! NotaryWorker uses to sign normal seals. [`AdminKeyStore`] lets principal
//! servers move to a **per-admin** signing model: it addresses signing keys by
//! `(application_id, admin_did)` pair via [`AdminKeyStore::key_id`], backed by
//! any [`KeyStore`] impl — `InMemoryKeyStore` for tests, `PlatformDefault` for
//! production. The store itself doesn't know about DIDs; the helper just builds
//! canonical key ids so different admins' keys can never collide.
//!
//! Together with the introspection data half
//! (`arkret_models_identity::admin_grant::SessionGrantIntrospection`): the
//! principal server receives a session grant, introspects it to learn
//! `(admin_did, admin_scopes)`, loads the per-admin signing key via
//! `AdminKeyStore::load_admin_key(admin_did)`, and signs the admin operation
//! with that key. The Seal's `verification_method` reflects the admin's DID,
//! not the service signer's DID — giving per-admin attribution in the audit
//! chain.

use arkret_keystore::{KeyBytes, KeyStore, KeyStoreError};
use arkret_wire::DidFullId;

use crate::Result;

/// KeyStore wrapper that addresses keys by `(application_id, admin_did)`
/// pair. Build with [`AdminKeyStore::new`]; the underlying [`KeyStore`]
/// is stored as a boxed trait object so the wrapper works with every
/// platform backend.
pub struct AdminKeyStore {
    application_id: String,
    inner: Box<dyn KeyStore>,
}

impl AdminKeyStore {
    /// Wrap `inner` with the given `application_id` namespace. The
    /// `application_id` MUST be the same one passed to
    /// `arkret_keystore::platform_default_keystore_with_kind` when building
    /// `inner`, otherwise key ids will reference a different namespace
    /// than the backend's service-name suffix.
    pub fn new(application_id: impl Into<String>, inner: Box<dyn KeyStore>) -> Self {
        Self {
            application_id: application_id.into(),
            inner,
        }
    }

    /// Canonical key id for a given admin DID. Format:
    /// `arkret:signer:admin:<application_id>:<did>`. Stable across
    /// processes so a key written by one server boot is readable by the
    /// next.
    pub fn key_id(application_id: &str, admin_did: &DidFullId) -> String {
        format!(
            "arkret:signer:admin:{application_id}:{}",
            admin_did.as_str()
        )
    }

    /// Load the raw signing seed for `admin_did`. Returns
    /// `KeyStoreError::NotFound` (wrapped in [`crate::AuthError::KeyStore`])
    /// when no key has been provisioned.
    pub fn load_admin_key(&self, admin_did: &DidFullId) -> Result<KeyBytes> {
        let id = Self::key_id(&self.application_id, admin_did);
        Ok(self.inner.load(&id)?)
    }

    /// Persist `key` as the signing seed for `admin_did`. Overwrites
    /// any existing key for the same admin.
    pub fn store_admin_key(&self, admin_did: &DidFullId, key: &[u8]) -> Result<()> {
        let id = Self::key_id(&self.application_id, admin_did);
        Ok(self.inner.store(&id, key)?)
    }

    /// Drop the signing seed for `admin_did`. Idempotent.
    pub fn delete_admin_key(&self, admin_did: &DidFullId) -> Result<()> {
        let id = Self::key_id(&self.application_id, admin_did);
        Ok(self.inner.delete(&id)?)
    }

    /// True if `admin_did` has a signing key provisioned.
    pub fn has_admin_key(&self, admin_did: &DidFullId) -> Result<bool> {
        let id = Self::key_id(&self.application_id, admin_did);
        match self.inner.load(&id) {
            Ok(_) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(other) => Err(other.into()),
        }
    }

    /// Enumerate admin DIDs known to this store. Walks the backend's
    /// id list and filters by the per-admin id prefix.
    pub fn list_admin_dids(&self) -> Result<Vec<DidFullId>> {
        let prefix = format!("arkret:signer:admin:{}:", self.application_id);
        let ids = self.inner.list()?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(did_str) = id.strip_prefix(&prefix) {
                let did = DidFullId::new(did_str.to_owned()).map_err(|e| {
                    KeyStoreError::backend(format!("admin key id {id} has invalid DID suffix: {e}"))
                })?;
                out.push(did);
            }
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use arkret_keystore::InMemoryKeyStore;

    use super::*;
    use crate::AuthError;

    fn admin(did: &str) -> DidFullId {
        DidFullId::new(did.to_owned()).unwrap()
    }

    #[test]
    fn admin_key_id_format_is_stable() {
        let did = admin("did:webvh:z6mkfixture:alice.example");
        assert_eq!(
            AdminKeyStore::key_id("soland.demo", &did),
            "arkret:signer:admin:soland.demo:did:webvh:z6mkfixture:alice.example"
        );
    }

    #[test]
    fn admin_key_round_trips_through_in_memory_store() {
        let store = AdminKeyStore::new("soland.demo", Box::new(InMemoryKeyStore::new()));
        let did = admin("did:webvh:z6mkfixture:alice.example");
        let seed = vec![0x42; 32];
        assert!(!store.has_admin_key(&did).unwrap());
        store.store_admin_key(&did, &seed).unwrap();
        assert!(store.has_admin_key(&did).unwrap());
        assert_eq!(
            store.load_admin_key(&did).unwrap().as_slice(),
            seed.as_slice()
        );
        store.delete_admin_key(&did).unwrap();
        assert!(!store.has_admin_key(&did).unwrap());
    }

    #[test]
    fn admin_key_isolated_per_application_id() {
        // First wrapper: store a key under application_id "soland.demo".
        let store_a = AdminKeyStore::new("soland.demo", Box::new(InMemoryKeyStore::new()));
        let did = admin("did:webvh:z6mkfixture:alice.example");
        store_a.store_admin_key(&did, b"app1-seed").unwrap();
        assert!(store_a.has_admin_key(&did).unwrap());

        // Second wrapper: different application_id, fresh backend —
        // MUST NOT observe the first store's key. (In production each
        // application_id maps to a separate KeyStore instance; the
        // wrapper's namespacing is just a defense-in-depth so a shared
        // backend can't accidentally cross-load keys.)
        let store_b = AdminKeyStore::new("other.app", Box::new(InMemoryKeyStore::new()));
        assert!(store_b.list_admin_dids().unwrap().is_empty());
        assert!(!store_b.has_admin_key(&did).unwrap());
    }

    #[test]
    fn admin_key_list_returns_provisioned_dids_sorted() {
        let store = AdminKeyStore::new("soland.demo", Box::new(InMemoryKeyStore::new()));
        let alice = admin("did:webvh:z6mkfixture:alice.example");
        let bob = admin("did:webvh:z6mkfixture:bob.example");
        let carol = admin("did:webvh:z6mkfixture:carol.example");
        store.store_admin_key(&bob, b"k").unwrap();
        store.store_admin_key(&alice, b"k").unwrap();
        store.store_admin_key(&carol, b"k").unwrap();
        let list = store.list_admin_dids().unwrap();
        assert_eq!(list, vec![alice, bob, carol]);
    }

    #[test]
    fn admin_key_load_missing_returns_not_found() {
        let store = AdminKeyStore::new("soland.demo", Box::new(InMemoryKeyStore::new()));
        let err = store
            .load_admin_key(&admin("did:webvh:z6mkfixture:nobody.example"))
            .unwrap_err();
        assert!(matches!(err, AuthError::KeyStore(ref e) if e.is_not_found()));
    }
}
