//! Authentication flow and session management helpers.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{DeviceId, Did, Error, Result, identity::DidDocument, model::Proof};

mod claims;
mod grants;
mod helpers;
mod manager;
#[cfg(test)]
mod tests;
mod verification;

pub use claims::*;
pub use grants::*;
pub use manager::*;
pub use verification::*;

/// Registered password user.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordUser {
    /// Username.
    pub username: String,
    /// User DID.
    pub user_id: Did,
    /// Password hash.
    pub password_hash: String,
    /// Whether MFA is required.
    pub mfa_enabled: bool,
}

impl fmt::Debug for PasswordUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordUser")
            .field("username", &self.username)
            .field("user_id", &self.user_id)
            .field("password_hash", &"<redacted>")
            .field("mfa_enabled", &self.mfa_enabled)
            .finish()
    }
}

/// OIDC authorization request metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcAuthReqBody {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub authorization_url: String,
}

/// Passkey challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyChallenge {
    pub user_id: Did,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

/// MFA challenge.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaChallenge {
    pub user_id: Did,
    pub code: String,
    pub expires_at: DateTime<Utc>,
    pub verified: bool,
}

impl fmt::Debug for MfaChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MfaChallenge")
            .field("user_id", &self.user_id)
            .field("code", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("verified", &self.verified)
            .finish()
    }
}

/// Account recovery method types.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRecoveryMethod {
    DidProof { verification_method: String },
    PasswordReset { reset_token_hash: String },
    PasskeyWebAuthnRebinding { credential_id: String },
}

impl fmt::Debug for AccountRecoveryMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DidProof { verification_method } => f
                .debug_struct("DidProof")
                .field("verification_method", verification_method)
                .finish(),
            Self::PasswordReset { .. } => {
                f.debug_struct("PasswordReset").field("reset_token_hash", &"<redacted>").finish()
            }
            Self::PasskeyWebAuthnRebinding { credential_id } => f
                .debug_struct("PasskeyWebAuthnRebinding")
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

/// Account recovery request tracked by the auth layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecoveryReqBody {
    pub request_id: String,
    pub user_id: Did,
    pub method: AccountRecoveryMethod,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
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

/// Refresh/access token metadata safe for durable storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenMetadata {
    pub session_id: String,
    pub user_id: Did,
    pub device_id: DeviceId,
    pub access_token_hash: String,
    pub refresh_token_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Durable revocation-list entry for a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRevocation {
    pub session_id: String,
    pub user_id: Did,
    pub device_id: DeviceId,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

/// Persisted session metadata. Token material is represented only by hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedAuthSession {
    pub session_id: String,
    pub user_id: Did,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
    pub access_token_hash: String,
    pub refresh_token_hash: String,
}

/// Auth state contract for applications that back `AuthManager` with durable storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStateSnapshot {
    pub password_users: BTreeMap<String, PasswordUser>,
    pub sessions: Vec<PersistedAuthSession>,
    pub account_states: BTreeMap<Did, AccountAuthState>,
    pub refresh_tokens: BTreeMap<String, RefreshTokenMetadata>,
    pub revoked_sessions: BTreeMap<String, SessionRevocation>,
    pub recovery_requests: BTreeMap<String, AccountRecoveryReqBody>,
}

/// Session-to-DID principal binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPrincipalBinding {
    pub session_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Canonical event kinds for the principal control space
/// (`key-management.md` §4.1). These events MUST be written into the
/// principal's dedicated control space; resolvers and federation peers
/// MUST refuse them in any other Space.
pub const CX_DEVICE_AUTHORIZED: &str = "cx.device.authorize";
pub const CX_DEVICE_REVOKED: &str = "cx.device.revoke";
pub const CX_SESSION_GRANT: &str = "cx.session.grant";

/// Derive the canonical principal control space ID from a principal DID.
///
/// The format is `cx:space:control:<did>`; downstream code MUST treat
/// this as opaque. This space holds the principal's device ledger, key
/// log, and session grants.
pub fn principal_control_space_id(principal_id: &Did) -> String {
    format!("cx:space:control:{}", principal_id.as_str())
}

/// Returns `true` when `event_kind` MUST be pinned to a principal
/// control space per `key-management.md` §4.1.
pub fn is_principal_control_event(event_kind: &str) -> bool {
    matches!(event_kind, CX_DEVICE_AUTHORIZED | CX_DEVICE_REVOKED | CX_SESSION_GRANT)
}

/// Validate that a control event is being submitted under the correct
/// space. Returns `Err(Error::Protocol("control_space_mismatch"))` when
/// `event_kind` MUST live in the principal control space but the
/// `space_id` does not match.
pub fn assert_control_space_pinning(
    event_kind: &str,
    principal_id: &Did,
    space_id: &str,
) -> Result<()> {
    if !is_principal_control_event(event_kind) {
        return Ok(());
    }
    let expected = principal_control_space_id(principal_id);
    if space_id == expected {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "control_space_mismatch: '{event_kind}' must be pinned to '{expected}', got '{space_id}'"
        )))
    }
}

/// Canonical OAuth2 scope prefix for binding a Contrix client device to a session.
pub const CONTRIX_DEVICE_SCOPE_PREFIX: &str = "urn:contrix:client:device:";

/// Build the canonical Contrix device scope token for a device.
pub fn contrix_device_scope(device_id: &DeviceId) -> String {
    format!("{CONTRIX_DEVICE_SCOPE_PREFIX}{device_id}")
}

/// Extract a device ID from a canonical Contrix device scope token.
pub fn device_id_from_scope_token(scope_token: &str) -> Option<DeviceId> {
    let raw = scope_token.strip_prefix(CONTRIX_DEVICE_SCOPE_PREFIX)?;
    DeviceId::new(raw).ok()
}

/// Return the first device ID encoded in a set of scope tokens.
pub fn primary_device_id_from_scopes<I, S>(scopes: I) -> Option<DeviceId>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    scopes.into_iter().find_map(|scope| device_id_from_scope_token(scope.as_ref()))
}
