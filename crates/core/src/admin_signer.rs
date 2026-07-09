//! Per-admin signing key + session-grant introspection helpers.
//!
//! Admin operations (notary reconfiguration, compaction submission,
//! bottom repair, etc.) are signed today by the service identity — the
//! same key the NotaryWorker uses to sign normal seals. This module
//! provides the SDK primitives that let principal servers move to a
//! **per-admin** signing model:
//!
//! 1. [`AdminKeyStore`] addresses signing keys by `(application_id, admin_did)` pair via
//!    [`AdminKeyStore::key_id`]. Backed by any [`KeyStore`] impl — `InMemoryKeyStore` for tests,
//!    `PlatformDefault` for production. The store itself doesn't know about DIDs; the helper just
//!    builds canonical key ids so different admins' keys can never collide.
//!
//! 2. [`SessionGrantIntrospection`] is the typed form of an OAuth-style introspection response
//!    carrying admin context (the operator's principal DID, the granted admin scopes, the expiry).
//!    Principal servers receive this as an HTTP response from coauth (or another upstream IdP) and
//!    use it to bind a signed admin operation to the operator's identity.
//!
//! Together: the principal server receives a session grant, introspects
//! it to learn `(admin_did, admin_scopes)`, loads the per-admin signing
//! key via `AdminKeyStore::load_admin_key(admin_did)`, and signs the
//! admin operation with that key. The Seal's `verification_method`
//! reflects the admin's DID, not the service signer's DID — giving
//! per-admin attribution in the audit chain.

use serde::{Deserialize, Serialize};

use crate::keystore::KeyStoreError;
use crate::{Did, KeyBytes, KeyStore, Result};

/// Conventional admin-scope identifiers. These mirror the operations
/// soland already gates on `require_admin_principal`. Servers MAY add
/// custom scopes; the introspection helper does not enforce a closed
/// set.
pub mod admin_scopes {
    /// Submit a Move that reconfigures a Space's notary cell.
    pub const NOTARY_RECONFIGURE: &str = "notary.reconfigure";
    /// Rotate the notary signing key for a Space.
    pub const NOTARY_ROTATE_SIGNING_KEY: &str = "notary.rotate_signing_key";
    /// Trigger a compaction seal (MAL-11).
    pub const SEAL_COMPACT: &str = "seal.compact";
    /// Prune historical seals via `SealStore::prune_predecessor`.
    pub const SEAL_PRUNE: &str = "seal.prune";
    /// Submit a manual repair Move for a bottom cell.
    pub const BOTTOM_REPAIR: &str = "bottom.repair";
    /// Read admin-scoped collection surfaces (accounts, spaces, etc.).
    pub const ADMIN_READ: &str = "admin.read";
}

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
    pub fn key_id(application_id: &str, admin_did: &Did) -> String {
        format!(
            "arkret:signer:admin:{application_id}:{}",
            admin_did.as_str()
        )
    }

    /// Load the raw signing seed for `admin_did`. Returns
    /// `KeyStoreError::NotFound` (wrapped in [`crate::Error::KeyStore`])
    /// when no key has been provisioned.
    pub fn load_admin_key(&self, admin_did: &Did) -> Result<KeyBytes> {
        let id = Self::key_id(&self.application_id, admin_did);
        self.inner.load(&id)
    }

    /// Persist `key` as the signing seed for `admin_did`. Overwrites
    /// any existing key for the same admin.
    pub fn store_admin_key(&self, admin_did: &Did, key: &[u8]) -> Result<()> {
        let id = Self::key_id(&self.application_id, admin_did);
        self.inner.store(&id, key)
    }

    /// Drop the signing seed for `admin_did`. Idempotent.
    pub fn delete_admin_key(&self, admin_did: &Did) -> Result<()> {
        let id = Self::key_id(&self.application_id, admin_did);
        self.inner.delete(&id)
    }

    /// True if `admin_did` has a signing key provisioned.
    pub fn has_admin_key(&self, admin_did: &Did) -> Result<bool> {
        let id = Self::key_id(&self.application_id, admin_did);
        match self.inner.load(&id) {
            Ok(_) => Ok(true),
            Err(err) if err.is_key_store_not_found() => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// Enumerate admin DIDs known to this store. Walks the backend's
    /// id list and filters by the per-admin id prefix.
    pub fn list_admin_dids(&self) -> Result<Vec<Did>> {
        let prefix = format!("arkret:signer:admin:{}:", self.application_id);
        let ids = self.inner.list()?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(did_str) = id.strip_prefix(&prefix) {
                let did = Did::new(did_str.to_owned()).map_err(|e| {
                    KeyStoreError::backend(format!("admin key id {id} has invalid DID suffix: {e}"))
                })?;
                out.push(did);
            }
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }
}

/// Typed view of an OAuth-style session-grant introspection response.
///
/// Principal servers receive this from their upstream IdP (coauth, by
/// convention) when introspecting a bearer token. The fields are a
/// strict subset of the RFC 7662 introspection response plus the
/// `org.arkret.*` extensions soland already uses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantIntrospection {
    /// Whether the bearer token is currently valid. Receivers MUST
    /// reject any introspection where `active=false`.
    pub active: bool,
    /// The operator's principal ID. Populated from
    /// `org.arkret.principal_id` (or `sub`) on the IdP side.
    pub principal_id: Did,
    /// Granted admin scopes — e.g.
    /// [`admin_scopes::NOTARY_RECONFIGURE`]. Receivers gate
    /// individual admin operations on whether the relevant scope is
    /// present here.
    #[serde(default)]
    pub admin_scopes: Vec<String>,
    /// Unix seconds when this grant expires. `None` means the IdP did
    /// not assert an expiry; receivers SHOULD fall back to their own
    /// session-record TTL.
    #[serde(default)]
    pub expires_at_unix: Option<i64>,
    /// Optional device-id binding. When present, the bearer token can
    /// only sign from this device.
    #[serde(default)]
    pub device_id: Option<String>,
    /// Free-form audit context the IdP passed through (request id,
    /// origin, etc.). Receivers MAY surface this in audit logs.
    #[serde(default)]
    pub audit_context: serde_json::Value,
}

impl SessionGrantIntrospection {
    /// True iff the grant is active and not expired (when `now_unix` is
    /// later than `expires_at_unix`).
    pub fn is_currently_active(&self, now_unix: i64) -> bool {
        if !self.active {
            return false;
        }
        !matches!(self.expires_at_unix, Some(exp) if exp <= now_unix)
    }

    /// True iff the grant lists `scope`. Note: this is **exact match**;
    /// hierarchical scopes (`seal.*` covering `seal.compact`) MUST
    /// be expanded by the IdP before introspection.
    pub fn has_admin_scope(&self, scope: &str) -> bool {
        self.admin_scopes.iter().any(|s| s == scope)
    }

    /// Returns Err with `capability_denied`-shaped diagnostic when the
    /// grant lacks `scope`. Convenience for `?`-style gating in
    /// handlers.
    pub fn require_admin_scope(&self, scope: &str) -> Result<()> {
        if self.has_admin_scope(scope) {
            Ok(())
        } else {
            Err(crate::Error::Protocol(format!(
                "session grant lacks admin scope {scope}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::InMemoryKeyStore;

    fn admin(did: &str) -> Did {
        Did::new(did.to_owned()).unwrap()
    }

    // ── AdminKeyStore ─────────────────────────────────────────────────

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
        assert!(err.is_key_store_not_found());
    }

    // ── SessionGrantIntrospection ─────────────────────────────────────

    fn grant_active(scopes: &[&str]) -> SessionGrantIntrospection {
        SessionGrantIntrospection {
            active: true,
            principal_id: admin("did:webvh:z6mkfixture:alice.example"),
            admin_scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            expires_at_unix: Some(2_000_000_000),
            device_id: None,
            audit_context: serde_json::Value::Null,
        }
    }

    #[test]
    fn inactive_grant_never_currently_active() {
        let mut g = grant_active(&[]);
        g.active = false;
        assert!(!g.is_currently_active(0));
    }

    #[test]
    fn expired_grant_not_currently_active() {
        let g = grant_active(&[]);
        // Expires at 2_000_000_000, query at 3_000_000_000.
        assert!(!g.is_currently_active(3_000_000_000));
        assert!(g.is_currently_active(1_000_000_000));
    }

    #[test]
    fn grant_without_expiry_is_active_when_active() {
        let mut g = grant_active(&[]);
        g.expires_at_unix = None;
        assert!(g.is_currently_active(i64::MAX));
    }

    #[test]
    fn has_admin_scope_exact_match() {
        let g = grant_active(&[admin_scopes::NOTARY_RECONFIGURE]);
        assert!(g.has_admin_scope(admin_scopes::NOTARY_RECONFIGURE));
        assert!(!g.has_admin_scope(admin_scopes::SEAL_COMPACT));
    }

    #[test]
    fn require_admin_scope_rejects_missing() {
        let g = grant_active(&[admin_scopes::ADMIN_READ]);
        let err = g.require_admin_scope(admin_scopes::SEAL_PRUNE).unwrap_err();
        assert!(format!("{err}").contains("seal.prune"));
    }

    #[test]
    fn require_admin_scope_ok_when_present() {
        let g = grant_active(&[admin_scopes::NOTARY_RECONFIGURE]);
        g.require_admin_scope(admin_scopes::NOTARY_RECONFIGURE)
            .unwrap();
    }

    #[test]
    fn introspection_serializes_with_defaults() {
        let g = SessionGrantIntrospection {
            active: true,
            principal_id: admin("did:webvh:z6mkfixture:alice.example"),
            admin_scopes: vec![],
            expires_at_unix: None,
            device_id: None,
            audit_context: serde_json::json!({}),
        };
        let s = serde_json::to_string(&g).unwrap();
        let back: SessionGrantIntrospection = serde_json::from_str(&s).unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn introspection_deserializes_minimal_envelope() {
        // Only `active` and `principal_id` required; the rest default.
        let s = r#"{"active":true,"principal_id":"did:webvh:z6mkfixture:alice.example"}"#;
        let g: SessionGrantIntrospection = serde_json::from_str(s).unwrap();
        assert!(g.active);
        assert!(g.admin_scopes.is_empty());
        assert!(g.expires_at_unix.is_none());
        assert!(g.device_id.is_none());
    }
}
