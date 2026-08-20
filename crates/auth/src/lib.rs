//! Arkret v1 authentication behavior: sessions, session grants, claims,
//! and passwords.
//!
//! Depends only on the wire / model / signature data crates; the umbrella
//! `arkret` crate re-exports this surface under `arkret::auth::*`.

use arkret_wire::DidCoreId;
pub mod admin_key;
mod claims;
mod error;
mod grants;
mod helpers;
mod manager;
pub mod session_grant;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

pub use admin_key::AdminKeyStore;
use arkret_models_identity::SignedSessionGrantClaims;
use arkret_wire::{DeviceId, EventKind, RealmId};
use chrono::{DateTime, Duration, Utc};
pub use claims::*;
use error::AuthError as Error;
pub use error::{AuthError, Result};
pub use grants::*;
pub use manager::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Registered password user.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordUser {
    /// Username.
    pub username: String,
    /// User DID.
    pub user_id: DidCoreId,
    /// Password hash.
    pub password_hash: String,
}

impl fmt::Debug for PasswordUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordUser")
            .field("username", &self.username)
            .field("user_id", &self.user_id)
            .field("password_hash", &"<redacted>")
            .finish()
    }
}

/// Account state enforced before issuing or refreshing sessions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountAuthState {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
}

impl AccountAuthState {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Refresh/session credential metadata safe for durable storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalCredentialMetadata {
    pub session_id: String,
    pub user_id: DidCoreId,
    pub device_id: DeviceId,
    pub session_credential_hash: String,
    pub renewal_credential_hash: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Durable revocation-list entry for a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRevocation {
    pub session_id: String,
    pub user_id: DidCoreId,
    pub device_id: DeviceId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

/// Session-to-DID principal binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPrincipalBinding {
    pub session_id: String,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Returns `true` when `event_kind` MUST be pinned to a principal
/// control Realm per `key-management.md` §4.1. Resolvers and federation
/// peers MUST refuse these events in any other Realm.
pub fn is_principal_control_event(event_kind: &EventKind) -> bool {
    matches!(
        event_kind,
        EventKind::DeviceAuthorize | EventKind::DeviceRevoke
    )
}

/// Validate that a control event is being submitted under the correct
/// Realm. Returns `Err(Error::Protocol("principal_control_realm_mismatch"))` when
/// `event_kind` MUST live in the principal control Realm but the
/// `realm_id` does not match.
pub fn assert_control_realm_pinning(
    event_kind: &EventKind,
    principal_control_realm_id: &RealmId,
    realm_id: &str,
) -> Result<()> {
    if !is_principal_control_event(event_kind) {
        return Ok(());
    }
    if realm_id == principal_control_realm_id.as_str() {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "principal_control_realm_mismatch: '{event_kind}' must be pinned to '{principal_control_realm_id}', got '{realm_id}'"
        )))
    }
}

/// Canonical OAuth2 scope prefix for binding a Arkret client device to a session.
pub const ARKRET_DEVICE_SCOPE_PREFIX: &str = "urn:arkret:client:device:";

/// Build the canonical Arkret device scope token for a device.
pub fn arkret_device_scope(device_id: &DeviceId) -> String {
    format!("{ARKRET_DEVICE_SCOPE_PREFIX}{device_id}")
}

/// Extract a device ID from a canonical Arkret device scope token.
pub fn device_id_from_scope_token(scope_token: &str) -> Option<DeviceId> {
    let raw = scope_token.strip_prefix(ARKRET_DEVICE_SCOPE_PREFIX)?;
    DeviceId::new(raw).ok()
}

/// Return the first device ID encoded in a set of scope tokens.
pub fn primary_device_id_from_scopes<I, S>(scopes: I) -> Option<DeviceId>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    scopes
        .into_iter()
        .find_map(|scope| device_id_from_scope_token(scope.as_ref()))
}
