//! Session-grant introspection wire shape + the admin-scope vocabulary.
//!
//! [`SessionGrantIntrospection`] is the typed form of an OAuth-style
//! introspection response carrying admin context (the operator's principal
//! DID, the granted admin scopes, the expiry). Principal servers receive this
//! as an HTTP response from coauth (or another upstream IdP) and use it to bind
//! a signed admin operation to the operator's identity.
//!
//! This is the pure introspection **data** half of the per-admin signing model;
//! the KeyStore-backed [`arkret_keystore`]-consuming behavior (addressing signing
//! keys by `(application_id, admin_did)`) lives in `arkret-auth` as
//! `AdminKeyStore`.

use arkret_wire::{Did, Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

/// Typed view of an OAuth-style session-grant introspection response.
///
/// Principal servers receive this from their upstream IdP (coauth, by
/// convention) when introspecting a bearer token. The fields are a
/// strict subset of the RFC 7662 introspection response plus the
/// `org.arkret.*` extensions soland already uses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Canonical Arkret instant when this grant expires. `None` means the IdP did
    /// not assert an expiry; receivers SHOULD fall back to their own
    /// session-record TTL.
    #[serde(default)]
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
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
    /// later than `expires_at`). `now_unix` is process-internal Unix seconds,
    /// not a wire representation.
    pub fn is_currently_active(&self, now_unix: i64) -> bool {
        if !self.active {
            return false;
        }
        !matches!(self.expires_at, Some(exp) if exp.timestamp() <= now_unix)
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
            Err(Error::Protocol(format!(
                "session grant lacks admin scope {scope}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin(did: &str) -> Did {
        Did::new(did.to_owned()).unwrap()
    }

    fn grant_active(scopes: &[&str]) -> SessionGrantIntrospection {
        SessionGrantIntrospection {
            active: true,
            principal_id: admin("did:webvh:z6mkfixture:alice.example"),
            admin_scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            expires_at: Some(DateTime::from_timestamp(2_000_000_000, 0).unwrap()),
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
        g.expires_at = None;
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
            expires_at: None,
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
        assert!(g.expires_at.is_none());
        assert!(g.device_id.is_none());
    }
}
