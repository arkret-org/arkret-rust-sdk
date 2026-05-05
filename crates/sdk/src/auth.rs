//! Authentication flow and session management helpers.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{DeviceId, Did, Error, Result, identity::DidDocument, model::Proof};

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
pub struct OidcAuthRequest {
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
pub struct AccountRecoveryRequest {
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
    pub recovery_requests: BTreeMap<String, AccountRecoveryRequest>,
}

/// Session-to-DID principal binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPrincipalBinding {
    pub session_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub created_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// Canonical event kinds for the principal control space
/// (`key-management.md` §4.1). These events MUST be written into the
/// principal's dedicated control space; resolvers and federation peers
/// MUST refuse them in any other Space.
pub const CX_DEVICE_AUTHORIZED: &str = "cx.device.authorized";
pub const CX_DEVICE_REVOKED: &str = "cx.device.revoked";
pub const CX_SESSION_GRANT: &str = "cx.session.grant";

/// Derive the canonical principal control space ID from a principal DID.
///
/// The format is `cx:space:control:<did>`; downstream code MUST treat
/// this as opaque. This space holds the principal's device ledger, key
/// log, and session grants.
pub fn principal_control_space_id(principal_id: &crate::Did) -> String {
    format!("cx:space:control:{}", principal_id.as_str())
}

/// Returns `true` when `event_kind` MUST be pinned to a principal
/// control space per `key-management.md` §4.1.
pub fn is_principal_control_event(event_kind: &str) -> bool {
    matches!(
        event_kind,
        CX_DEVICE_AUTHORIZED | CX_DEVICE_REVOKED | CX_SESSION_GRANT
    )
}

/// Validate that a control event is being submitted under the correct
/// space. Returns `Err(Error::Protocol("control_space_mismatch"))` when
/// `event_kind` MUST live in the principal control space but the
/// `space_id` does not match.
pub fn assert_control_space_pinning(
    event_kind: &str,
    principal_id: &crate::Did,
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

/// Session grant payload issued by an identity provider to a Principal Server.
///
/// This is the stable contract shared by coauth, soland and admin tooling. It
/// intentionally excludes private session key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrantPayload {
    pub issuer: Did,
    pub subject: Did,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub audience: Vec<String>,
    pub scopes: Vec<String>,
    pub session_id: String,
    pub grant_jti: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revocation_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_public_key: Option<String>,
}

impl SessionGrantPayload {
    /// Validate the payload before it is signed or persisted.
    pub fn validate(&self) -> Result<()> {
        if self.audience.is_empty() {
            return Err(Error::Protocol("session grant audience must not be empty".to_owned()));
        }
        if self.scopes.is_empty() {
            return Err(Error::Protocol("session grant scopes must not be empty".to_owned()));
        }
        if self.session_id.trim().is_empty() {
            return Err(Error::Protocol("session grant session_id must not be empty".to_owned()));
        }
        if self.grant_jti.trim().is_empty() {
            return Err(Error::Protocol("session grant grant_jti must not be empty".to_owned()));
        }
        if self.revocation_ref.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant revocation_ref must not be empty".to_owned(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(Error::Protocol(
                "session grant expires_at must be after issued_at".to_owned(),
            ));
        }
        Ok(())
    }

    /// Return the Principal Server session binding represented by this grant.
    pub fn principal_binding(&self) -> SessionPrincipalBinding {
        SessionPrincipalBinding {
            session_id: self.session_id.clone(),
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            created_at: self.issued_at,
            valid_until: self.expires_at,
        }
    }
}

/// Issued session grant. Debug output redacts the serialized grant token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrant {
    pub payload: SessionGrantPayload,
    pub grant_jwt: String,
    pub grant_hash: String,
}

impl fmt::Debug for SessionGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionGrant")
            .field("payload", &self.payload)
            .field("grant_jwt", &"<redacted>")
            .field("grant_hash", &self.grant_hash)
            .finish()
    }
}

impl SessionGrant {
    /// Create a grant and hash the serialized grant token for durable storage.
    pub fn new(payload: SessionGrantPayload, grant_jwt: impl Into<String>) -> Result<Self> {
        payload.validate()?;
        let grant_jwt = grant_jwt.into();
        if grant_jwt.trim().is_empty() {
            return Err(Error::Protocol("session grant JWT must not be empty".to_owned()));
        }
        let grant_hash = sha256_hex(grant_jwt.as_bytes());
        Ok(Self { payload, grant_jwt, grant_hash })
    }

    /// Convert this issued grant into a durable record without token material.
    pub fn into_record(self) -> SessionGrantRecord {
        SessionGrantRecord {
            payload: self.payload,
            grant_hash: self.grant_hash,
            created_at: Utc::now(),
            revoked_at: None,
            revoke_reason: None,
        }
    }
}

/// Host-owned JWS signer for session grants.
pub trait SessionGrantSigner {
    fn sign_session_grant(&self, payload: &SessionGrantPayload) -> Result<String>;
}

impl<F> SessionGrantSigner for F
where
    F: Fn(&SessionGrantPayload) -> Result<String>,
{
    fn sign_session_grant(&self, payload: &SessionGrantPayload) -> Result<String> {
        self(payload)
    }
}

/// Verified session grant returned by a host-owned JWS verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrantVerification {
    pub payload: SessionGrantPayload,
    pub grant_hash: String,
    pub verified: bool,
}

impl SessionGrantVerification {
    pub fn validate(&self) -> Result<()> {
        self.payload.validate()?;
        if !self.verified {
            return Err(Error::Protocol("session grant JWS was not verified".to_owned()));
        }
        if self.grant_hash.trim().is_empty() {
            return Err(Error::Protocol("session grant hash must not be empty".to_owned()));
        }
        Ok(())
    }
}

/// Host-owned JWS verifier for session grants.
pub trait SessionGrantVerifier {
    fn verify_session_grant(&self, grant_jwt: &str) -> Result<SessionGrantVerification>;
}

impl<F> SessionGrantVerifier for F
where
    F: Fn(&str) -> Result<SessionGrantVerification>,
{
    fn verify_session_grant(&self, grant_jwt: &str) -> Result<SessionGrantVerification> {
        self(grant_jwt)
    }
}

/// Issue a session grant through a host-owned JWS signer.
pub fn issue_session_grant_with_signer(
    payload: SessionGrantPayload,
    signer: &impl SessionGrantSigner,
) -> Result<SessionGrant> {
    let grant_jwt = signer.sign_session_grant(&payload)?;
    SessionGrant::new(payload, grant_jwt)
}

/// Verify a serialized grant through a host-owned JWS verifier.
pub fn verify_session_grant_with_verifier(
    grant_jwt: &str,
    verifier: &impl SessionGrantVerifier,
) -> Result<SessionGrantVerification> {
    let verification = verifier.verify_session_grant(grant_jwt)?;
    verification.validate()?;
    Ok(verification)
}

/// Durable session grant record. Token material is represented by hash only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrantRecord {
    pub payload: SessionGrantPayload,
    pub grant_hash: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_reason: Option<String>,
}

impl SessionGrantRecord {
    pub fn active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && now < self.payload.expires_at
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>, reason: impl Into<String>) {
        self.revoked_at = Some(revoked_at);
        self.revoke_reason = Some(reason.into());
    }
}

/// Principal Server notification type for session grant lifecycle changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantNotificationKind {
    Created,
    Revoked,
}

/// Idempotent notification sent from an identity provider to Principal Servers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalSessionGrantNotification {
    pub request_id: String,
    pub kind: SessionGrantNotificationKind,
    pub record: SessionGrantRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_actor: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PrincipalSessionGrantNotification {
    pub fn validate(&self) -> Result<()> {
        if self.request_id.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant notification request_id is empty".to_owned(),
            ));
        }
        self.record.payload.validate()?;
        if matches!(self.kind, SessionGrantNotificationKind::Revoked)
            && self.record.revoked_at.is_none()
        {
            return Err(Error::Protocol(
                "revoked session grant notification must include revoked_at".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Principal Server response for a session grant notification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalSessionGrantNotificationResponse {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Delivery state for a service-owned session grant outbox entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantOutboxState {
    Pending,
    Delivered,
    Failed,
    DeadLettered,
}

/// Retry policy metadata for durable service-owned outboxes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrantRetryPolicy {
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub max_attempts: u32,
}

impl Default for SessionGrantRetryPolicy {
    fn default() -> Self {
        Self { initial_backoff_ms: 1_000, max_backoff_ms: 60_000, max_attempts: 8 }
    }
}

impl SessionGrantRetryPolicy {
    pub fn next_delay_ms(&self, attempts: u32) -> Option<u64> {
        if attempts >= self.max_attempts {
            return None;
        }
        let shift = attempts.min(31);
        Some(self.initial_backoff_ms.saturating_mul(1u64 << shift).min(self.max_backoff_ms))
    }
}

/// Durable outbox item shape; services own persistence and scheduling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrantOutboxEntry {
    pub notification: PrincipalSessionGrantNotification,
    pub state: SessionGrantOutboxState,
    pub attempts: u32,
    pub next_attempt_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl SessionGrantOutboxEntry {
    pub fn new(
        notification: PrincipalSessionGrantNotification,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        notification.validate()?;
        Ok(Self {
            notification,
            state: SessionGrantOutboxState::Pending,
            attempts: 0,
            next_attempt_at: now,
            last_error: None,
        })
    }

    pub fn due(&self, now: DateTime<Utc>) -> bool {
        matches!(self.state, SessionGrantOutboxState::Pending | SessionGrantOutboxState::Failed)
            && self.next_attempt_at <= now
    }

    pub fn record_delivery(&mut self) {
        self.state = SessionGrantOutboxState::Delivered;
        self.last_error = None;
    }

    pub fn record_failure(
        &mut self,
        error: impl Into<String>,
        now: DateTime<Utc>,
        policy: SessionGrantRetryPolicy,
    ) {
        self.attempts = self.attempts.saturating_add(1);
        self.last_error = Some(error.into());
        if let Some(delay_ms) = policy.next_delay_ms(self.attempts) {
            self.state = SessionGrantOutboxState::Failed;
            self.next_attempt_at = now + Duration::milliseconds(delay_ms as i64);
        } else {
            self.state = SessionGrantOutboxState::DeadLettered;
            self.next_attempt_at = now;
        }
    }
}

/// In-memory contract helper for tests; production services should persist this queue.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySessionGrantOutbox {
    entries: VecDeque<SessionGrantOutboxEntry>,
}

impl MemorySessionGrantOutbox {
    pub fn enqueue(
        &mut self,
        notification: PrincipalSessionGrantNotification,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.entries.push_back(SessionGrantOutboxEntry::new(notification, now)?);
        Ok(())
    }

    pub fn due(&self, now: DateTime<Utc>) -> Vec<&SessionGrantOutboxEntry> {
        self.entries.iter().filter(|entry| entry.due(now)).collect()
    }

    pub fn entries(&self) -> impl Iterator<Item = &SessionGrantOutboxEntry> {
        self.entries.iter()
    }
}

/// Host-supplied notifier for Principal Server session-grant propagation.
///
/// TODO: real coauth/soland integrations should wrap this trait with a durable
/// outbox, idempotency-key persistence and retry/backoff policy. The SDK only
/// defines the stable request/response contract.
pub trait PrincipalSessionGrantNotifier {
    fn notify_session_grant(
        &self,
        notification: &PrincipalSessionGrantNotification,
    ) -> Result<PrincipalSessionGrantNotificationResponse>;
}

impl<F> PrincipalSessionGrantNotifier for F
where
    F: Fn(&PrincipalSessionGrantNotification) -> Result<PrincipalSessionGrantNotificationResponse>,
{
    fn notify_session_grant(
        &self,
        notification: &PrincipalSessionGrantNotification,
    ) -> Result<PrincipalSessionGrantNotificationResponse> {
        self(notification)
    }
}

/// Auth operation category supplied to rate-limit hooks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRateLimitAction {
    PasswordLogin,
    OidcLogin,
    PasskeyLogin,
    MfaVerify,
    RecoveryStart,
    RecoveryComplete,
}

/// Context passed to an auth rate-limit hook.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRateLimitContext {
    pub action: AuthRateLimitAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub now: DateTime<Utc>,
}

/// Synchronous rate-limit hook used by embedding applications.
pub type AuthRateLimitHook = fn(&AuthRateLimitContext) -> Result<()>;

/// Password hash algorithm expected by a password verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordHashAlgorithm {
    Argon2id,
    AppSupplied(String),
}

/// Password hash verification request supplied to provider adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordVerificationRequest {
    pub username: String,
    pub user_id: Did,
    pub password: String,
    pub password_hash: String,
    pub algorithm: PasswordHashAlgorithm,
}

/// Result returned by a password hash verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordVerification {
    pub verified: bool,
    pub rehash_needed: bool,
}

/// Application-supplied password hash verifier.
pub trait PasswordHashVerifier {
    fn verify_password(
        &self,
        request: &PasswordVerificationRequest,
    ) -> Result<PasswordVerification>;
}

impl<F> PasswordHashVerifier for F
where
    F: Fn(&PasswordVerificationRequest) -> Result<PasswordVerification>,
{
    fn verify_password(
        &self,
        request: &PasswordVerificationRequest,
    ) -> Result<PasswordVerification> {
        self(request)
    }
}

/// OIDC issuer metadata needed by application verifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcIssuerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// JWKS material fetched or pinned by the embedding application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcJwks {
    pub keys: Value,
}

/// OIDC credential presented for verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum OidcCredential {
    AuthorizationCode { code: String, redirect_uri: String },
    IdToken { id_token: String },
    AccessToken { access_token: String },
}

/// OIDC verification request with issuer metadata and JWKS hooks already resolved by the app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcVerificationRequest {
    pub issuer_metadata: OidcIssuerMetadata,
    pub jwks: OidcJwks,
    pub client_id: String,
    pub expected_nonce: Option<String>,
    pub credential: OidcCredential,
}

/// Verified OIDC identity returned by an application verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcVerifiedIdentity {
    pub user_id: Did,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Application-supplied OIDC code or token verifier.
pub trait OidcVerifier {
    fn verify_oidc(&self, request: &OidcVerificationRequest) -> Result<OidcVerifiedIdentity>;
}

impl<F> OidcVerifier for F
where
    F: Fn(&OidcVerificationRequest) -> Result<OidcVerifiedIdentity>,
{
    fn verify_oidc(&self, request: &OidcVerificationRequest) -> Result<OidcVerifiedIdentity> {
        self(request)
    }
}

/// WebAuthn/passkey authenticator response supplied by an application verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnPasskeyResponse {
    pub credential_id: String,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// WebAuthn/passkey ceremony verification request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyVerificationRequest {
    pub user_id: Did,
    pub challenge: PasskeyChallenge,
    pub response: WebAuthnPasskeyResponse,
    pub origin: String,
    pub relying_party_id: String,
    pub now: DateTime<Utc>,
}

/// Verified passkey identity returned by an application verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyVerification {
    pub verified: bool,
    pub user_id: Did,
    pub credential_id: String,
}

/// Application-supplied WebAuthn/passkey response verifier.
pub trait PasskeyVerifier {
    fn verify_passkey(&self, request: &PasskeyVerificationRequest) -> Result<PasskeyVerification>;
}

impl<F> PasskeyVerifier for F
where
    F: Fn(&PasskeyVerificationRequest) -> Result<PasskeyVerification>,
{
    fn verify_passkey(&self, request: &PasskeyVerificationRequest) -> Result<PasskeyVerification> {
        self(request)
    }
}

/// DID proof verification request against a DID document verification method.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidProofVerificationRequest {
    pub subject: Did,
    pub did_document: DidDocument,
    pub verification_method: String,
    pub public_key: String,
    pub proof: Proof,
}

/// DID proof verification result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidProofVerification {
    pub verified: bool,
    pub subject: Did,
    pub verification_method: String,
}

/// Application-supplied DID proof verifier.
pub trait DidProofVerifier {
    fn verify_did_proof(
        &self,
        request: &DidProofVerificationRequest,
    ) -> Result<DidProofVerification>;
}

impl<F> DidProofVerifier for F
where
    F: Fn(&DidProofVerificationRequest) -> Result<DidProofVerification>,
{
    fn verify_did_proof(
        &self,
        request: &DidProofVerificationRequest,
    ) -> Result<DidProofVerification> {
        self(request)
    }
}

/// Standard claim type names used by auth and progressive disclosure helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthClaimType {
    VerifiedHandle,
    EmailDomain,
    OrganizationMembership,
    OrganizationRole,
    GuardianController,
    DeviceTrust,
    MfaLevel,
    RiskLevel,
}

impl AuthClaimType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedHandle => "verified_handle",
            Self::EmailDomain => "email_domain",
            Self::OrganizationMembership => "organization_membership",
            Self::OrganizationRole => "organization_role",
            Self::GuardianController => "guardian_controller",
            Self::DeviceTrust => "device_trust",
            Self::MfaLevel => "mfa_level",
            Self::RiskLevel => "risk_level",
        }
    }
}

/// Claim presented to satisfy an auth or policy disclosure request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PresentedClaim {
    pub claim_id: String,
    pub subject: Did,
    pub issuer: Did,
    pub claim_type: String,
    pub value: Value,
    pub issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub disclosed_fields: BTreeSet<String>,
}

impl PresentedClaim {
    pub fn new(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        claim_type: impl Into<String>,
        value: Value,
    ) -> Self {
        Self {
            claim_id: claim_id.into(),
            subject,
            issuer,
            claim_type: claim_type.into(),
            value,
            issued_at: Utc::now(),
            refreshed_at: None,
            expires_at: None,
            revoked_at: None,
            disclosed_fields: BTreeSet::new(),
        }
    }

    pub fn verified_handle(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        handle: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimType::VerifiedHandle.as_str(),
            serde_json::json!({ "handle": handle.into() }),
        )
    }

    pub fn email_domain(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        domain: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimType::EmailDomain.as_str(),
            serde_json::json!({ "domain": domain.into() }),
        )
    }

    pub fn organization_membership(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        organization: Did,
        roles: Vec<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimType::OrganizationMembership.as_str(),
            serde_json::json!({ "organization": organization, "roles": roles }),
        )
    }

    pub fn device_trust(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        device_id: DeviceId,
        trust_state: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimType::DeviceTrust.as_str(),
            serde_json::json!({ "device_id": device_id, "trust_state": trust_state.into() }),
        )
    }

    pub fn guardian_controller(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        guardian: Did,
        controller: Did,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimType::GuardianController.as_str(),
            serde_json::json!({ "guardian": guardian, "controller": controller }),
        )
    }

    pub fn mfa_level(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        level: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimType::MfaLevel.as_str(),
            serde_json::json!({ "level": level.into() }),
        )
    }

    pub fn risk_level(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        level: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimType::RiskLevel.as_str(),
            serde_json::json!({ "level": level.into() }),
        )
    }
}

/// One claim requested by a progressive disclosure policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimDisclosureRequirement {
    pub claim_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_issuers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reveal_fields: Vec<String>,
    #[serde(default = "default_true")]
    pub required: bool,
}

/// Policy describing the minimum claims to disclose for a flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosurePolicy {
    pub policy_id: String,
    pub requirements: Vec<ClaimDisclosureRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<Duration>,
    #[serde(default = "default_true")]
    pub fail_closed: bool,
}

/// Presentation request sent to a wallet or identity provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresentationRequest {
    pub request_id: String,
    pub subject: Did,
    pub audience: String,
    pub nonce: String,
    pub policy: DisclosurePolicy,
    pub created_at: DateTime<Utc>,
    /// Verifier DID requesting the disclosure
    /// (`progressive-disclosure.md` §4). Wallets MUST authenticate this
    /// DID and refuse to disclose anything to an unverified verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_did: Option<Did>,
    /// Organization the verifier claims to represent. When set, the
    /// wallet MUST trace `verifier_did → represented_org` through the
    /// verifier authority chain before disclosure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub represented_org: Option<Did>,
    /// Authority links proving `verifier_did` is acting on behalf of
    /// `represented_org`. Empty means "verifier acts for itself"; a
    /// non-empty list MUST chain back to `represented_org`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_authority_chain: Vec<VerifierAuthorityLink>,
}

/// One link in the verifier authority chain (verifier → org).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierAuthorityLink {
    /// Subject of this link — the entity that delegated to the next.
    pub from: Did,
    /// Recipient of the delegation.
    pub to: Did,
    /// Capability or role token transferred (`org_member`, `verifier`,
    /// etc.).
    pub capability: String,
    /// Detached proof for the delegation (JWS, signed CBOR, etc.).
    pub proof: String,
    /// Expiry timestamp; expired links MUST be rejected.
    pub expires_at: DateTime<Utc>,
}

impl PresentationRequest {
    /// Validate the verifier authority chain per
    /// `progressive-disclosure.md` §4.
    ///
    /// Returns `Ok(())` when:
    ///
    /// 1. If `verifier_did` is `None`, the request is rejected.
    /// 2. If `represented_org` is `None`, the chain MUST be empty
    ///    (verifier acts for itself).
    /// 3. Otherwise the chain MUST start at `verifier_did`, end at
    ///    `represented_org`, and every link MUST be unexpired at `now`.
    ///
    /// This validator does NOT verify the cryptographic proofs — it
    /// only enforces the chain shape. Callers SHOULD additionally
    /// verify each link's `proof` against the issuer's DID document.
    pub fn validate_verifier_authority(&self, now: DateTime<Utc>) -> Result<()> {
        let Some(verifier) = &self.verifier_did else {
            return Err(Error::Protocol(
                "presentation request missing verifier_did".to_owned(),
            ));
        };
        let Some(org) = &self.represented_org else {
            if self.verifier_authority_chain.is_empty() {
                return Ok(());
            }
            return Err(Error::Protocol(
                "verifier_authority_chain present without represented_org".to_owned(),
            ));
        };
        if self.verifier_authority_chain.is_empty() {
            // Verifier IS the org — accept.
            if verifier == org {
                return Ok(());
            }
            return Err(Error::Protocol(
                "represented_org differs from verifier_did but no authority chain provided"
                    .to_owned(),
            ));
        }
        // Walk the chain: every link MUST be unexpired and `to`
        // MUST connect to the next link's `from`.
        let chain = &self.verifier_authority_chain;
        if &chain[0].from != verifier {
            return Err(Error::Protocol(
                "verifier_authority_chain does not start at verifier_did".to_owned(),
            ));
        }
        for window in chain.windows(2) {
            if window[0].to != window[1].from {
                return Err(Error::Protocol(
                    "verifier_authority_chain has a broken link".to_owned(),
                ));
            }
        }
        if &chain[chain.len() - 1].to != org {
            return Err(Error::Protocol(
                "verifier_authority_chain does not end at represented_org".to_owned(),
            ));
        }
        for link in chain {
            if now >= link.expires_at {
                return Err(Error::Protocol(format!(
                    "verifier_authority_chain link from {} to {} is expired",
                    link.from, link.to
                )));
            }
        }
        Ok(())
    }
}

/// External selective-disclosure proof format accepted through an adapter boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureProofFormat {
    SdJwt,
    Bbs,
    Custom(String),
}

/// Format-neutral boundary object passed to SD-JWT, BBS or host-provided verifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureProofAdapterBoundary {
    pub format: DisclosureProofFormat,
    pub holder: Did,
    pub issuer: Did,
    pub audience: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub encoded_presentation: String,
}

impl DisclosureProofAdapterBoundary {
    /// Validate request binding before delegating to a format-specific verifier.
    pub fn validate_request_binding(
        &self,
        request: &PresentationRequest,
        expected_domain: Option<&str>,
    ) -> Result<()> {
        if self.holder != request.subject {
            return Err(Error::Protocol("disclosure proof holder mismatch".to_owned()));
        }
        if self.audience != request.audience {
            return Err(Error::Protocol("disclosure proof audience mismatch".to_owned()));
        }
        if self.nonce != request.nonce {
            return Err(Error::Protocol("disclosure proof nonce mismatch".to_owned()));
        }
        if expected_domain != self.domain.as_deref() {
            return Err(Error::Protocol("disclosure proof domain mismatch".to_owned()));
        }
        if self.encoded_presentation.trim().is_empty() {
            return Err(Error::Protocol("disclosure proof payload is empty".to_owned()));
        }
        Ok(())
    }
}

/// Rejected claim detail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedClaim {
    pub claim_id: String,
    pub claim_type: String,
    pub reason: String,
}

/// Progressive disclosure validation result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PresentationValidation {
    pub accepted: bool,
    pub disclosed_claims: Vec<PresentedClaim>,
    pub missing_required: Vec<String>,
    pub rejected_claims: Vec<RejectedClaim>,
}

/// Validate claims against issuer trust, subject, expiry, revocation and disclosure policy.
pub fn validate_presentation(
    request: &PresentationRequest,
    claims: &[PresentedClaim],
    revoked_claim_ids: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> PresentationValidation {
    let mut disclosed_claims = Vec::new();
    let mut missing_required = Vec::new();
    let mut rejected_claims = Vec::new();

    // Verifier authority MUST be authenticated before any claim
    // processing per `progressive-disclosure.md` §4. A verifier with
    // no `verifier_did` is treated as anonymous; only requests that
    // explicitly opt in to anonymous disclosure (via empty policy
    // requirements) reach the loop below.
    if let Some(verifier) = &request.verifier_did
        && let Err(reason) = request.validate_verifier_authority(now)
    {
        rejected_claims.push(RejectedClaim {
            claim_id: format!("verifier_authority:{verifier}"),
            claim_type: "verifier_authority".to_owned(),
            reason: reason.to_string(),
        });
        return PresentationValidation {
            accepted: false,
            disclosed_claims,
            missing_required,
            rejected_claims,
        };
    }

    for requirement in &request.policy.requirements {
        let mut matched = false;
        for claim in claims.iter().filter(|claim| claim.claim_type == requirement.claim_type) {
            match validate_presented_claim(request, requirement, claim, revoked_claim_ids, now) {
                Ok(()) => {
                    disclosed_claims.push(disclose_claim(claim, &requirement.reveal_fields));
                    matched = true;
                    break;
                }
                Err(reason) => rejected_claims.push(RejectedClaim {
                    claim_id: claim.claim_id.clone(),
                    claim_type: claim.claim_type.clone(),
                    reason,
                }),
            }
        }
        if !matched && requirement.required {
            missing_required.push(requirement.claim_type.clone());
        }
    }

    let accepted =
        missing_required.is_empty() && (!request.policy.fail_closed || rejected_claims.is_empty());
    PresentationValidation { accepted, disclosed_claims, missing_required, rejected_claims }
}

/// Authenticated session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_id: String,
    pub user_id: Did,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthSession")
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Auth and session manager.
#[derive(Clone, Debug)]
pub struct AuthManager {
    password_users: BTreeMap<String, PasswordUser>,
    sessions: BTreeMap<String, AuthSession>,
    sessions_by_user: BTreeMap<Did, VecDeque<String>>,
    account_states: BTreeMap<Did, AccountAuthState>,
    refresh_tokens: BTreeMap<String, RefreshTokenMetadata>,
    revoked_sessions: BTreeMap<String, SessionRevocation>,
    passkey_challenges: BTreeMap<Did, PasskeyChallenge>,
    mfa_challenges: BTreeMap<Did, MfaChallenge>,
    recovery_requests: BTreeMap<String, AccountRecoveryRequest>,
    rate_limit_hook: Option<AuthRateLimitHook>,
    session_limit: usize,
}

impl AuthManager {
    /// Create an auth manager.
    pub fn new(session_limit: usize) -> Self {
        Self {
            password_users: BTreeMap::new(),
            sessions: BTreeMap::new(),
            sessions_by_user: BTreeMap::new(),
            account_states: BTreeMap::new(),
            refresh_tokens: BTreeMap::new(),
            revoked_sessions: BTreeMap::new(),
            passkey_challenges: BTreeMap::new(),
            mfa_challenges: BTreeMap::new(),
            recovery_requests: BTreeMap::new(),
            rate_limit_hook: None,
            session_limit,
        }
    }

    /// Set an application-supplied rate-limit hook for login, MFA and recovery flows.
    pub fn set_rate_limit_hook(&mut self, hook: Option<AuthRateLimitHook>) {
        self.rate_limit_hook = hook;
    }

    /// Return a manager with an application-supplied rate-limit hook.
    pub fn with_rate_limit_hook(mut self, hook: AuthRateLimitHook) -> Self {
        self.rate_limit_hook = Some(hook);
        self
    }

    /// Register a username/password identity with the built-in local hash helper.
    pub fn register_password_user(
        &mut self,
        username: impl Into<String>,
        password: &str,
        user_id: Did,
    ) -> Result<PasswordUser> {
        self.register_password_hash(username, sha256_hex(password.as_bytes()), user_id)
    }

    /// Register a username/password identity with an application-supplied password hash.
    pub fn register_password_hash(
        &mut self,
        username: impl Into<String>,
        password_hash: impl Into<String>,
        user_id: Did,
    ) -> Result<PasswordUser> {
        let username = username.into();
        if self.password_users.contains_key(&username) {
            return Err(Error::Protocol("username already registered".to_owned()));
        }
        let user = PasswordUser {
            username: username.clone(),
            user_id,
            password_hash: password_hash.into(),
            mfa_enabled: false,
        };
        self.account_states.entry(user.user_id.clone()).or_insert(AccountAuthState::Active);
        self.password_users.insert(username, user.clone());
        Ok(user)
    }

    /// Enable MFA for a password user.
    pub fn enable_mfa(&mut self, username: &str) -> Result<()> {
        let user = self
            .password_users
            .get_mut(username)
            .ok_or_else(|| Error::Protocol("user not found".to_owned()))?;
        user.mfa_enabled = true;
        Ok(())
    }

    /// Login with username/password using the built-in local hash helper.
    pub fn login_password(
        &mut self,
        username: &str,
        password: &str,
        device_id: DeviceId,
    ) -> Result<AuthSession> {
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::PasswordLogin,
            subject: Some(username.to_owned()),
            user_id: None,
            device_id: Some(device_id.clone()),
            now: Utc::now(),
        })?;
        let user = self
            .password_users
            .get(username)
            .ok_or_else(|| Error::Protocol("user not found".to_owned()))?;
        if !constant_time_eq(&user.password_hash, &sha256_hex(password.as_bytes())) {
            return Err(Error::Protocol("invalid password".to_owned()));
        }
        if user.mfa_enabled
            && !self
                .mfa_challenges
                .get(&user.user_id)
                .map(|challenge| challenge.verified && challenge.expires_at > Utc::now())
                .unwrap_or(false)
        {
            return Err(Error::Protocol("mfa required".to_owned()));
        }
        self.create_session(user.user_id.clone(), device_id)
    }

    /// Login with an application-supplied password hash verifier.
    pub fn login_password_with_verifier<V>(
        &mut self,
        username: &str,
        password: &str,
        algorithm: PasswordHashAlgorithm,
        device_id: DeviceId,
        verifier: &V,
    ) -> Result<AuthSession>
    where
        V: PasswordHashVerifier + ?Sized,
    {
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::PasswordLogin,
            subject: Some(username.to_owned()),
            user_id: None,
            device_id: Some(device_id.clone()),
            now: Utc::now(),
        })?;
        let user = self
            .password_users
            .get(username)
            .ok_or_else(|| Error::Protocol("user not found".to_owned()))?;
        let verification = verifier.verify_password(&PasswordVerificationRequest {
            username: user.username.clone(),
            user_id: user.user_id.clone(),
            password: password.to_owned(),
            password_hash: user.password_hash.clone(),
            algorithm,
        })?;
        if !verification.verified {
            return Err(Error::Protocol("invalid password".to_owned()));
        }
        if user.mfa_enabled
            && !self
                .mfa_challenges
                .get(&user.user_id)
                .map(|challenge| challenge.verified && challenge.expires_at > Utc::now())
                .unwrap_or(false)
        {
            return Err(Error::Protocol("mfa required".to_owned()));
        }
        self.create_session(user.user_id.clone(), device_id)
    }

    /// Build an OIDC authorization URL.
    pub fn start_oidc(
        &self,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        state: impl Into<String>,
    ) -> OidcAuthRequest {
        let issuer = issuer.into();
        let client_id = client_id.into();
        let redirect_uri = redirect_uri.into();
        let state = state.into();
        let authorization_url = format!(
            "{issuer}/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&state={state}"
        );
        OidcAuthRequest { issuer, client_id, redirect_uri, state, authorization_url }
    }

    /// Complete an OIDC/OAuth2 login after upstream verification.
    pub fn complete_oidc(&mut self, user_id: Did, device_id: DeviceId) -> Result<AuthSession> {
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::OidcLogin,
            subject: None,
            user_id: Some(user_id.clone()),
            device_id: Some(device_id.clone()),
            now: Utc::now(),
        })?;
        self.create_session(user_id, device_id)
    }

    /// Complete an OIDC/OAuth2 login using an application-supplied verifier.
    pub fn complete_oidc_with_verifier<V>(
        &mut self,
        request: OidcVerificationRequest,
        device_id: DeviceId,
        verifier: &V,
    ) -> Result<AuthSession>
    where
        V: OidcVerifier + ?Sized,
    {
        let verified = verifier.verify_oidc(&request)?;
        if verified.issuer != request.issuer_metadata.issuer {
            return Err(Error::Protocol("oidc issuer mismatch".to_owned()));
        }
        if let Some(expires_at) = verified.expires_at
            && expires_at <= Utc::now()
        {
            return Err(Error::Protocol("oidc credential expired".to_owned()));
        }
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::OidcLogin,
            subject: Some(verified.subject.clone()),
            user_id: Some(verified.user_id.clone()),
            device_id: Some(device_id.clone()),
            now: Utc::now(),
        })?;
        self.create_session(verified.user_id, device_id)
    }

    /// Start a passkey challenge.
    pub fn start_passkey(&mut self, user_id: Did) -> PasskeyChallenge {
        let challenge = PasskeyChallenge {
            challenge: format!("passkey:{}", Ulid::new()),
            user_id: user_id.clone(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        self.passkey_challenges.insert(user_id, challenge.clone());
        challenge
    }

    /// Verify a passkey response with the built-in local challenge helper.
    pub fn verify_passkey(
        &mut self,
        user_id: &Did,
        response: &str,
        device_id: DeviceId,
    ) -> Result<AuthSession> {
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::PasskeyLogin,
            subject: None,
            user_id: Some(user_id.clone()),
            device_id: Some(device_id.clone()),
            now: Utc::now(),
        })?;
        let challenge = self
            .passkey_challenges
            .get(user_id)
            .ok_or_else(|| Error::Protocol("passkey challenge not found".to_owned()))?;
        if challenge.expires_at <= Utc::now() {
            return Err(Error::Protocol("passkey challenge expired".to_owned()));
        }
        if !constant_time_eq(response, &sha256_hex(challenge.challenge.as_bytes())) {
            return Err(Error::Protocol("invalid passkey response".to_owned()));
        }
        self.create_session(user_id.clone(), device_id)
    }

    /// Verify a passkey response with an application-supplied WebAuthn verifier.
    pub fn verify_passkey_with_verifier<V>(
        &mut self,
        user_id: &Did,
        response: WebAuthnPasskeyResponse,
        origin: impl Into<String>,
        relying_party_id: impl Into<String>,
        device_id: DeviceId,
        verifier: &V,
    ) -> Result<AuthSession>
    where
        V: PasskeyVerifier + ?Sized,
    {
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::PasskeyLogin,
            subject: None,
            user_id: Some(user_id.clone()),
            device_id: Some(device_id.clone()),
            now: Utc::now(),
        })?;
        let challenge = self
            .passkey_challenges
            .get(user_id)
            .ok_or_else(|| Error::Protocol("passkey challenge not found".to_owned()))?
            .clone();
        let now = Utc::now();
        if challenge.expires_at <= now {
            return Err(Error::Protocol("passkey challenge expired".to_owned()));
        }
        let verified = verifier.verify_passkey(&PasskeyVerificationRequest {
            user_id: user_id.clone(),
            challenge,
            response,
            origin: origin.into(),
            relying_party_id: relying_party_id.into(),
            now,
        })?;
        if !verified.verified || &verified.user_id != user_id {
            return Err(Error::Protocol("invalid passkey response".to_owned()));
        }
        self.create_session(user_id.clone(), device_id)
    }

    /// Issue an MFA challenge.
    pub fn issue_mfa(&mut self, user_id: Did) -> MfaChallenge {
        let code = sha256_hex(format!("{}:{}", user_id, Ulid::new()).as_bytes())[..6].to_owned();
        let challenge = MfaChallenge {
            user_id: user_id.clone(),
            code,
            expires_at: Utc::now() + Duration::minutes(5),
            verified: false,
        };
        self.mfa_challenges.insert(user_id, challenge.clone());
        challenge
    }

    /// Verify an MFA challenge.
    pub fn verify_mfa(&mut self, user_id: &Did, code: &str) -> Result<()> {
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::MfaVerify,
            subject: None,
            user_id: Some(user_id.clone()),
            device_id: None,
            now: Utc::now(),
        })?;
        let challenge = self
            .mfa_challenges
            .get_mut(user_id)
            .ok_or_else(|| Error::Protocol("mfa challenge not found".to_owned()))?;
        if challenge.expires_at <= Utc::now() {
            return Err(Error::Protocol("mfa challenge expired".to_owned()));
        }
        if !constant_time_eq(&challenge.code, code) {
            return Err(Error::Protocol("invalid mfa code".to_owned()));
        }
        challenge.verified = true;
        Ok(())
    }

    /// Create a session and enforce the concurrent session limit.
    pub fn create_session(&mut self, user_id: Did, device_id: DeviceId) -> Result<AuthSession> {
        self.ensure_account_active(&user_id)?;
        let now = Utc::now();
        let session = AuthSession {
            session_id: format!("sess_{}", Ulid::new()),
            access_token: format!("atk_{}", Ulid::new()),
            refresh_token: format!("rtk_{}", Ulid::new()),
            expires_at: now + Duration::hours(1),
            revoked: false,
            created_at: now,
            user_id: user_id.clone(),
            principal_id: user_id.clone(),
            device_id: device_id.clone(),
        };
        self.refresh_tokens.insert(
            session.session_id.clone(),
            RefreshTokenMetadata {
                session_id: session.session_id.clone(),
                user_id: user_id.clone(),
                device_id,
                access_token_hash: sha256_hex(session.access_token.as_bytes()),
                refresh_token_hash: sha256_hex(session.refresh_token.as_bytes()),
                issued_at: now,
                expires_at: session.expires_at,
                revoked_at: None,
            },
        );
        self.sessions.insert(session.session_id.clone(), session.clone());
        let session_ids = self.sessions_by_user.entry(user_id).or_default();
        session_ids.push_back(session.session_id.clone());
        while session_ids.len() > self.session_limit {
            if let Some(oldest) = session_ids.pop_front()
                && let Some(session) = self.sessions.get_mut(&oldest)
            {
                session.revoked = true;
                if let Some(metadata) = self.refresh_tokens.get_mut(&oldest) {
                    metadata.revoked_at = Some(now);
                }
                self.revoked_sessions.insert(
                    oldest.clone(),
                    SessionRevocation {
                        session_id: oldest,
                        user_id: session.user_id.clone(),
                        device_id: session.device_id.clone(),
                        revoked_at: now,
                        reason: "session limit exceeded".to_owned(),
                    },
                );
            }
        }
        Ok(session)
    }

    /// Refresh a session token.
    pub fn refresh_session(
        &mut self,
        session_id: &str,
        refresh_token: &str,
    ) -> Result<AuthSession> {
        let snapshot = self
            .sessions
            .get(session_id)
            .ok_or_else(|| Error::Protocol("session not found".to_owned()))?;
        self.ensure_account_active(&snapshot.user_id)?;
        if snapshot.revoked || self.revoked_sessions.contains_key(session_id) {
            return Err(Error::Protocol("session revoked".to_owned()));
        }
        if snapshot.expires_at <= Utc::now() {
            return Err(Error::Protocol("session expired".to_owned()));
        }
        let supplied_hash = sha256_hex(refresh_token.as_bytes());
        if let Some(metadata) = self.refresh_tokens.get(session_id) {
            if metadata.revoked_at.is_some() {
                return Err(Error::Protocol("session revoked".to_owned()));
            }
            if !constant_time_eq(&metadata.refresh_token_hash, &supplied_hash) {
                return Err(Error::Protocol("invalid refresh token".to_owned()));
            }
        } else if !constant_time_eq(&snapshot.refresh_token, refresh_token) {
            return Err(Error::Protocol("invalid refresh token".to_owned()));
        }
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::Protocol("session not found".to_owned()))?;
        session.access_token = format!("atk_{}", Ulid::new());
        if session.refresh_token == "<redacted>" {
            session.refresh_token = refresh_token.to_owned();
        }
        session.expires_at = Utc::now() + Duration::hours(1);
        if let Some(metadata) = self.refresh_tokens.get_mut(session_id) {
            metadata.access_token_hash = sha256_hex(session.access_token.as_bytes());
            metadata.refresh_token_hash = supplied_hash;
            metadata.expires_at = session.expires_at;
        }
        Ok(session.clone())
    }

    /// Revoke a session.
    pub fn revoke_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::Protocol("session not found".to_owned()))?;
        session.revoked = true;
        let revoked_at = Utc::now();
        if let Some(metadata) = self.refresh_tokens.get_mut(session_id) {
            metadata.revoked_at = Some(revoked_at);
        }
        self.revoked_sessions.insert(
            session_id.to_owned(),
            SessionRevocation {
                session_id: session_id.to_owned(),
                user_id: session.user_id.clone(),
                device_id: session.device_id.clone(),
                revoked_at,
                reason: "explicit revoke".to_owned(),
            },
        );
        Ok(())
    }

    /// Active sessions for a user.
    pub fn active_sessions(&self, user_id: &Did) -> Vec<&AuthSession> {
        self.sessions_by_user
            .get(user_id)
            .map(|session_ids| {
                session_ids
                    .iter()
                    .filter_map(|session_id| self.sessions.get(session_id))
                    .filter(|session| !session.revoked && session.expires_at > Utc::now())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Create a DID principal binding for an active session.
    pub fn session_principal_binding(&self, session_id: &str) -> Result<SessionPrincipalBinding> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| Error::Protocol("session not found".to_owned()))?;
        if session.revoked || session.expires_at <= Utc::now() {
            return Err(Error::Protocol("session inactive".to_owned()));
        }
        Ok(SessionPrincipalBinding {
            session_id: session.session_id.clone(),
            principal_id: session.principal_id.clone(),
            device_id: session.device_id.clone(),
            created_at: session.created_at,
            valid_until: session.expires_at,
        })
    }

    /// Validate access-token and device binding for an active session.
    pub fn validate_session(
        &self,
        session_id: &str,
        access_token: &str,
        device_id: &DeviceId,
    ) -> Result<SessionPrincipalBinding> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| Error::Protocol("session not found".to_owned()))?;
        self.ensure_account_active(&session.user_id)?;
        if session.revoked || self.revoked_sessions.contains_key(session_id) {
            return Err(Error::Protocol("session revoked".to_owned()));
        }
        if session.expires_at <= Utc::now() {
            return Err(Error::Protocol("session expired".to_owned()));
        }
        if &session.device_id != device_id {
            return Err(Error::Protocol("session device binding mismatch".to_owned()));
        }
        let supplied_hash = sha256_hex(access_token.as_bytes());
        if let Some(metadata) = self.refresh_tokens.get(session_id) {
            if !constant_time_eq(&metadata.access_token_hash, &supplied_hash) {
                return Err(Error::Protocol("invalid access token".to_owned()));
            }
        } else if !constant_time_eq(&session.access_token, access_token) {
            return Err(Error::Protocol("invalid access token".to_owned()));
        }
        self.session_principal_binding(session_id)
    }

    /// Set an account state. Non-active states fail closed for login and refresh.
    pub fn set_account_state(&mut self, user_id: Did, state: AccountAuthState) {
        self.account_states.insert(user_id, state);
    }

    /// Current account state. Missing state fails closed.
    pub fn account_state(&self, user_id: &Did) -> AccountAuthState {
        self.account_states.get(user_id).copied().unwrap_or(AccountAuthState::Suspended)
    }

    /// Export durable auth state without raw access or refresh token material.
    pub fn export_state(&self) -> AuthStateSnapshot {
        let sessions = self
            .sessions
            .values()
            .map(|session| {
                let metadata = self.refresh_tokens.get(&session.session_id);
                PersistedAuthSession {
                    session_id: session.session_id.clone(),
                    user_id: session.user_id.clone(),
                    principal_id: session.principal_id.clone(),
                    device_id: session.device_id.clone(),
                    expires_at: session.expires_at,
                    revoked: session.revoked,
                    created_at: session.created_at,
                    access_token_hash: metadata
                        .map(|metadata| metadata.access_token_hash.clone())
                        .unwrap_or_else(|| sha256_hex(session.access_token.as_bytes())),
                    refresh_token_hash: metadata
                        .map(|metadata| metadata.refresh_token_hash.clone())
                        .unwrap_or_else(|| sha256_hex(session.refresh_token.as_bytes())),
                }
            })
            .collect();
        AuthStateSnapshot {
            password_users: self.password_users.clone(),
            sessions,
            account_states: self.account_states.clone(),
            refresh_tokens: self.refresh_tokens.clone(),
            revoked_sessions: self.revoked_sessions.clone(),
            recovery_requests: self.recovery_requests.clone(),
        }
    }

    /// Import durable auth state exported by `export_state`.
    pub fn import_state(&mut self, snapshot: AuthStateSnapshot) -> Result<()> {
        self.password_users = snapshot.password_users;
        self.sessions.clear();
        self.sessions_by_user.clear();
        self.account_states = snapshot.account_states;
        self.refresh_tokens = snapshot.refresh_tokens;
        self.revoked_sessions = snapshot.revoked_sessions;
        self.recovery_requests = snapshot.recovery_requests;

        for persisted in snapshot.sessions {
            let session = AuthSession {
                session_id: persisted.session_id.clone(),
                user_id: persisted.user_id.clone(),
                principal_id: persisted.principal_id,
                device_id: persisted.device_id.clone(),
                access_token: "<redacted>".to_owned(),
                refresh_token: "<redacted>".to_owned(),
                expires_at: persisted.expires_at,
                revoked: persisted.revoked,
                created_at: persisted.created_at,
            };
            self.refresh_tokens.entry(persisted.session_id.clone()).or_insert(
                RefreshTokenMetadata {
                    session_id: persisted.session_id.clone(),
                    user_id: persisted.user_id.clone(),
                    device_id: persisted.device_id,
                    access_token_hash: persisted.access_token_hash,
                    refresh_token_hash: persisted.refresh_token_hash,
                    issued_at: persisted.created_at,
                    expires_at: persisted.expires_at,
                    revoked_at: if persisted.revoked { Some(Utc::now()) } else { None },
                },
            );
            self.sessions_by_user
                .entry(persisted.user_id)
                .or_default()
                .push_back(persisted.session_id.clone());
            self.sessions.insert(persisted.session_id, session);
        }
        Ok(())
    }

    /// Start account recovery with a supported recovery method.
    pub fn start_recovery(
        &mut self,
        user_id: Did,
        method: AccountRecoveryMethod,
    ) -> Result<AccountRecoveryRequest> {
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::RecoveryStart,
            subject: None,
            user_id: Some(user_id.clone()),
            device_id: None,
            now: Utc::now(),
        })?;
        let request = AccountRecoveryRequest {
            request_id: format!("recovery_{}", Ulid::new()),
            user_id,
            method,
            expires_at: Utc::now() + Duration::minutes(15),
            completed_at: None,
        };
        self.recovery_requests.insert(request.request_id.clone(), request.clone());
        Ok(request)
    }

    /// Complete a pending account recovery request after caller-supplied proof verification.
    pub fn complete_recovery(
        &mut self,
        request_id: &str,
        proof: &str,
    ) -> Result<AccountRecoveryRequest> {
        let request = self
            .recovery_requests
            .get(request_id)
            .ok_or_else(|| Error::Protocol("recovery request not found".to_owned()))?;
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::RecoveryComplete,
            subject: Some(request_id.to_owned()),
            user_id: Some(request.user_id.clone()),
            device_id: None,
            now: Utc::now(),
        })?;
        if request.expires_at <= Utc::now() {
            return Err(Error::Protocol("recovery request expired".to_owned()));
        }
        if request.completed_at.is_some() {
            return Err(Error::Protocol("recovery request already completed".to_owned()));
        }
        if !recovery_proof_matches(&request.method, proof) {
            return Err(Error::Protocol("invalid recovery proof".to_owned()));
        }

        let request = self
            .recovery_requests
            .get_mut(request_id)
            .ok_or_else(|| Error::Protocol("recovery request not found".to_owned()))?;
        request.completed_at = Some(Utc::now());
        Ok(request.clone())
    }

    /// Complete DID-proof recovery using an application-supplied DID proof verifier.
    pub fn complete_recovery_with_did_verifier<V>(
        &mut self,
        request_id: &str,
        did_document: DidDocument,
        proof: Proof,
        verifier: &V,
    ) -> Result<AccountRecoveryRequest>
    where
        V: DidProofVerifier + ?Sized,
    {
        let request = self
            .recovery_requests
            .get(request_id)
            .ok_or_else(|| Error::Protocol("recovery request not found".to_owned()))?;
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::RecoveryComplete,
            subject: Some(request_id.to_owned()),
            user_id: Some(request.user_id.clone()),
            device_id: None,
            now: Utc::now(),
        })?;
        if request.expires_at <= Utc::now() {
            return Err(Error::Protocol("recovery request expired".to_owned()));
        }
        if request.completed_at.is_some() {
            return Err(Error::Protocol("recovery request already completed".to_owned()));
        }
        let AccountRecoveryMethod::DidProof { verification_method } = &request.method else {
            return Err(Error::Protocol("recovery method is not did proof".to_owned()));
        };
        if did_document.id != request.user_id {
            return Err(Error::Protocol("did document subject mismatch".to_owned()));
        }
        did_document.validate()?;
        let public_key = did_document
            .verification_methods
            .get(verification_method)
            .ok_or_else(|| Error::Protocol("verification method not found".to_owned()))?
            .clone();
        if proof.verification_method != *verification_method {
            return Err(Error::Protocol("proof verification method mismatch".to_owned()));
        }
        let verification = verifier.verify_did_proof(&DidProofVerificationRequest {
            subject: request.user_id.clone(),
            did_document,
            verification_method: verification_method.clone(),
            public_key,
            proof,
        })?;
        if !verification.verified
            || verification.subject != request.user_id
            || verification.verification_method != *verification_method
        {
            return Err(Error::Protocol("invalid did proof".to_owned()));
        }

        let request = self
            .recovery_requests
            .get_mut(request_id)
            .ok_or_else(|| Error::Protocol("recovery request not found".to_owned()))?;
        request.completed_at = Some(Utc::now());
        Ok(request.clone())
    }

    fn check_rate_limit(&self, ctx: AuthRateLimitContext) -> Result<()> {
        if let Some(hook) = self.rate_limit_hook {
            hook(&ctx)?;
        }
        Ok(())
    }

    fn ensure_account_active(&self, user_id: &Did) -> Result<()> {
        let state = self.account_state(user_id);
        if state.is_active() {
            Ok(())
        } else {
            Err(Error::Protocol(format!("account is not active: {state:?}")))
        }
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new(8)
    }
}

fn default_true() -> bool {
    true
}

fn validate_presented_claim(
    request: &PresentationRequest,
    requirement: &ClaimDisclosureRequirement,
    claim: &PresentedClaim,
    revoked_claim_ids: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> std::result::Result<(), String> {
    if claim.subject != request.subject {
        return Err("claim subject mismatch".to_owned());
    }
    if !requirement.trusted_issuers.is_empty()
        && !requirement.trusted_issuers.contains(&claim.issuer)
    {
        return Err("claim issuer is not trusted".to_owned());
    }
    if revoked_claim_ids.contains(&claim.claim_id) {
        return Err("claim is revoked".to_owned());
    }
    if claim.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
        return Err("claim is revoked".to_owned());
    }
    if claim.expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Err("claim is expired".to_owned());
    }
    if let Some(max_age) = request.policy.max_age {
        let basis = claim.refreshed_at.unwrap_or(claim.issued_at);
        if now - basis > max_age {
            return Err("claim is stale".to_owned());
        }
    }
    Ok(())
}

fn disclose_claim(claim: &PresentedClaim, reveal_fields: &[String]) -> PresentedClaim {
    let mut disclosed = claim.clone();
    disclosed.disclosed_fields = reveal_fields.iter().cloned().collect();
    if reveal_fields.is_empty() {
        disclosed.value = Value::Null;
        return disclosed;
    }
    if reveal_fields.iter().any(|field| field == "*") {
        return disclosed;
    }
    let Some(object) = claim.value.as_object() else {
        disclosed.value = Value::Null;
        return disclosed;
    };
    let mut filtered = serde_json::Map::new();
    for field in reveal_fields {
        if let Some(value) = object.get(field) {
            filtered.insert(field.clone(), value.clone());
        }
    }
    disclosed.value = Value::Object(filtered);
    disclosed
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for idx in 0..max_len {
        let left_byte = left.get(idx).copied().unwrap_or(0);
        let right_byte = right.get(idx).copied().unwrap_or(0);
        diff |= (left_byte ^ right_byte) as usize;
    }

    diff == 0
}

fn recovery_proof_matches(method: &AccountRecoveryMethod, proof: &str) -> bool {
    match method {
        AccountRecoveryMethod::DidProof { verification_method } => {
            constant_time_eq(proof, &sha256_hex(verification_method.as_bytes()))
        }
        AccountRecoveryMethod::PasswordReset { reset_token_hash } => {
            constant_time_eq(proof, reset_token_hash)
        }
        AccountRecoveryMethod::PasskeyWebAuthnRebinding { credential_id } => {
            constant_time_eq(proof, &sha256_hex(credential_id.as_bytes()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn device(id: &str) -> DeviceId {
        DeviceId::new(format!("dev_{id}")).unwrap()
    }

    fn deny_password_login(ctx: &AuthRateLimitContext) -> Result<()> {
        if ctx.action == AuthRateLimitAction::PasswordLogin {
            Err(Error::Protocol("rate limited".to_owned()))
        } else {
            Ok(())
        }
    }

    #[test]
    fn auth_handles_password_mfa_and_sessions() {
        let alice = did("alice");
        let mut auth = AuthManager::new(1);
        auth.register_password_user("alice", "secret", alice.clone()).unwrap();
        auth.enable_mfa("alice").unwrap();
        assert!(auth.login_password("alice", "secret", device("1")).is_err());

        let mfa = auth.issue_mfa(alice.clone());
        auth.verify_mfa(&alice, &mfa.code).unwrap();
        let first = auth.login_password("alice", "secret", device("1")).unwrap();
        let second = auth.login_password("alice", "secret", device("2")).unwrap();

        assert_eq!(auth.active_sessions(&alice).len(), 1);
        let binding = auth.session_principal_binding(&second.session_id).unwrap();
        assert_eq!(binding.principal_id, alice);
        assert!(auth.refresh_session(&second.session_id, &second.refresh_token).is_ok());
        assert!(auth.refresh_session(&first.session_id, &first.refresh_token).is_err());
        auth.revoke_session(&second.session_id).unwrap();
        assert!(auth.active_sessions(&alice).is_empty());
    }

    #[test]
    fn auth_handles_oidc_and_passkeys() {
        let alice = did("alice");
        let mut auth = AuthManager::default();
        auth.set_account_state(alice.clone(), AccountAuthState::Active);
        let oidc = auth.start_oidc("https://issuer.example", "client", "https://app/cb", "state");
        assert!(oidc.authorization_url.contains("response_type=code"));
        assert!(auth.complete_oidc(alice.clone(), device("oidc")).is_ok());

        let challenge = auth.start_passkey(alice.clone());
        let response = sha256_hex(challenge.challenge.as_bytes());
        let session = auth.verify_passkey(&alice, &response, device("passkey")).unwrap();
        assert_eq!(session.user_id, alice);
    }

    #[test]
    fn auth_uses_provider_password_verifier() {
        let alice = did("alice");
        let mut auth = AuthManager::default();
        auth.register_password_hash("alice", "$argon2id$hash", alice.clone()).unwrap();

        let verifier = |request: &PasswordVerificationRequest| {
            assert_eq!(request.username, "alice");
            assert_eq!(request.user_id, alice);
            assert_eq!(request.password_hash, "$argon2id$hash");
            assert_eq!(request.algorithm, PasswordHashAlgorithm::Argon2id);
            Ok(PasswordVerification {
                verified: request.password == "secret",
                rehash_needed: false,
            })
        };

        let session = auth
            .login_password_with_verifier(
                "alice",
                "secret",
                PasswordHashAlgorithm::Argon2id,
                device("password-provider"),
                &verifier,
            )
            .unwrap();
        assert_eq!(session.user_id, did("alice"));

        assert!(
            auth.login_password_with_verifier(
                "alice",
                "wrong",
                PasswordHashAlgorithm::Argon2id,
                device("password-provider-2"),
                &verifier,
            )
            .is_err()
        );
    }

    #[test]
    fn auth_uses_provider_oidc_verifier_with_metadata_and_jwks() {
        let alice = did("alice");
        let mut auth = AuthManager::default();
        auth.set_account_state(alice.clone(), AccountAuthState::Active);
        let request = OidcVerificationRequest {
            issuer_metadata: OidcIssuerMetadata {
                issuer: "https://issuer.example".to_owned(),
                authorization_endpoint: "https://issuer.example/authorize".to_owned(),
                token_endpoint: "https://issuer.example/token".to_owned(),
                jwks_uri: "https://issuer.example/jwks".to_owned(),
            },
            jwks: OidcJwks { keys: serde_json::json!({ "keys": [] }) },
            client_id: "client".to_owned(),
            expected_nonce: Some("nonce".to_owned()),
            credential: OidcCredential::IdToken { id_token: "token".to_owned() },
        };
        let verifier = |request: &OidcVerificationRequest| {
            assert_eq!(request.issuer_metadata.jwks_uri, "https://issuer.example/jwks");
            Ok(OidcVerifiedIdentity {
                user_id: alice.clone(),
                issuer: request.issuer_metadata.issuer.clone(),
                subject: "sub-123".to_owned(),
                email: Some("alice@example.com".to_owned()),
                email_verified: true,
                expires_at: Some(Utc::now() + Duration::minutes(5)),
            })
        };

        let session =
            auth.complete_oidc_with_verifier(request, device("oidc-provider"), &verifier).unwrap();
        assert_eq!(session.user_id, alice);
    }

    #[test]
    fn auth_uses_provider_passkey_verifier() {
        let alice = did("alice");
        let mut auth = AuthManager::default();
        auth.set_account_state(alice.clone(), AccountAuthState::Active);
        let challenge = auth.start_passkey(alice.clone());
        let response = WebAuthnPasskeyResponse {
            credential_id: "credential-1".to_owned(),
            client_data_json: br#"{"type":"webauthn.get"}"#.to_vec(),
            authenticator_data: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            user_handle: None,
        };
        let verifier = |request: &PasskeyVerificationRequest| {
            assert_eq!(request.challenge.challenge, challenge.challenge);
            assert_eq!(request.origin, "https://app.example");
            assert_eq!(request.relying_party_id, "app.example");
            Ok(PasskeyVerification {
                verified: true,
                user_id: request.user_id.clone(),
                credential_id: request.response.credential_id.clone(),
            })
        };

        let session = auth
            .verify_passkey_with_verifier(
                &alice,
                response,
                "https://app.example",
                "app.example",
                device("passkey-provider"),
                &verifier,
            )
            .unwrap();
        assert_eq!(session.user_id, alice);
    }

    #[test]
    fn auth_models_account_recovery_methods() {
        let mut auth = AuthManager::default();
        let verification_method = "did:web:alice.example#key-1";
        let request = auth
            .start_recovery(
                did("alice"),
                AccountRecoveryMethod::DidProof {
                    verification_method: verification_method.to_owned(),
                },
            )
            .unwrap();
        assert!(request.request_id.starts_with("recovery_"));
        assert!(request.completed_at.is_none());

        let completed = auth
            .complete_recovery(&request.request_id, &sha256_hex(verification_method.as_bytes()))
            .unwrap();
        assert!(completed.completed_at.is_some());
        assert!(auth.complete_recovery(&request.request_id, "wrong").is_err());
    }

    #[test]
    fn auth_exports_safe_state_and_enforces_device_binding_and_account_state() {
        let alice = did("alice");
        let mut auth = AuthManager::default();
        assert_eq!(auth.account_state(&alice), AccountAuthState::Suspended);
        auth.register_password_user("alice", "secret", alice.clone()).unwrap();

        let session = auth.login_password("alice", "secret", device("desktop")).unwrap();
        auth.validate_session(&session.session_id, &session.access_token, &device("desktop"))
            .unwrap();
        assert!(
            auth.validate_session(&session.session_id, &session.access_token, &device("phone"))
                .is_err()
        );

        let snapshot = auth.export_state();
        assert_eq!(snapshot.sessions.len(), 1);
        assert!(!serde_json::to_string(&snapshot).unwrap().contains(&session.refresh_token));

        let mut restored = AuthManager::default();
        restored.import_state(snapshot).unwrap();
        restored
            .validate_session(&session.session_id, &session.access_token, &device("desktop"))
            .unwrap();
        restored.set_account_state(alice, AccountAuthState::Locked);
        assert!(restored.refresh_session(&session.session_id, &session.refresh_token).is_err());
    }

    #[test]
    fn session_grant_contract_redacts_and_notifies_principal_servers() {
        let now = Utc::now();
        let payload = SessionGrantPayload {
            issuer: did("coauth"),
            subject: did("alice"),
            principal_id: did("alice"),
            device_id: device("desktop"),
            audience: vec!["did:web:soland.example".to_owned()],
            scopes: vec!["urn:contrix:principal-server:session.bind".to_owned()],
            session_id: "browser-session-1".to_owned(),
            grant_jti: "grant-1".to_owned(),
            issued_at: now,
            expires_at: now + Duration::minutes(10),
            revocation_ref: "https://coauth.example/api/admin/v1/session-grants/grant-1".to_owned(),
            session_public_key: Some("session-public-key".to_owned()),
        };
        payload.validate().unwrap();
        let binding = payload.principal_binding();
        assert_eq!(binding.device_id, device("desktop"));

        let signer = |payload: &SessionGrantPayload| {
            payload.validate()?;
            Ok(format!("signed.{}.jwt", payload.grant_jti))
        };
        let issued = issue_session_grant_with_signer(payload.clone(), &signer).unwrap();
        let verifier = |grant_jwt: &str| {
            Ok(SessionGrantVerification {
                payload: payload.clone(),
                grant_hash: sha256_hex(grant_jwt.as_bytes()),
                verified: grant_jwt.starts_with("signed."),
            })
        };
        let verified = verify_session_grant_with_verifier(&issued.grant_jwt, &verifier).unwrap();
        assert_eq!(verified.grant_hash, issued.grant_hash);

        let grant = SessionGrant::new(payload, "signed.jwt.value").unwrap();
        assert!(!format!("{grant:?}").contains("signed.jwt.value"));
        let mut record = grant.into_record();
        assert!(record.active(now));
        record.revoke(now + Duration::minutes(1), "logout");

        let notification = PrincipalSessionGrantNotification {
            request_id: "request-1".to_owned(),
            kind: SessionGrantNotificationKind::Revoked,
            record,
            admin_actor: Some(did("admin")),
            reason: Some("logout".to_owned()),
        };
        notification.validate().unwrap();

        let notifier = |notification: &PrincipalSessionGrantNotification| {
            notification.validate()?;
            Ok(PrincipalSessionGrantNotificationResponse {
                accepted: true,
                audit_id: Some("audit-1".to_owned()),
                retry_after_ms: None,
            })
        };
        let response = notifier.notify_session_grant(&notification).unwrap();
        assert!(response.accepted);

        let mut outbox = MemorySessionGrantOutbox::default();
        outbox.enqueue(notification, now).unwrap();
        assert_eq!(outbox.due(now).len(), 1);
        let policy = SessionGrantRetryPolicy {
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
            max_attempts: 2,
        };
        let mut entry = outbox.entries().next().unwrap().clone();
        entry.record_failure("temporary", now, policy);
        assert_eq!(entry.state, SessionGrantOutboxState::Failed);
        entry.record_failure("still failing", now, policy);
        assert_eq!(entry.state, SessionGrantOutboxState::DeadLettered);
    }

    #[test]
    fn device_scope_helpers_accept_only_contrix_scope() {
        let device = device("phone");
        let scope = contrix_device_scope(&device);
        assert_eq!(device_id_from_scope_token(&scope).unwrap(), device);
        assert_eq!(primary_device_id_from_scopes(["openid", scope.as_str()]).unwrap(), device);

        assert!(device_id_from_scope_token("urn:matrix:client:device:dev_phone").is_none());
    }

    #[test]
    fn auth_validates_progressive_disclosure_claims_fail_closed() {
        let alice = did("alice");
        let issuer = did("issuer");
        let org = did("org");
        let guardian = did("guardian");
        let controller = did("controller");
        let request = PresentationRequest {
            request_id: "presentation-1".to_owned(),
            subject: alice.clone(),
            audience: "contrix-auth".to_owned(),
            nonce: "nonce".to_owned(),
            policy: DisclosurePolicy {
                policy_id: "policy-1".to_owned(),
                requirements: vec![
                    ClaimDisclosureRequirement {
                        claim_type: AuthClaimType::VerifiedHandle.as_str().to_owned(),
                        trusted_issuers: vec![issuer.clone()],
                        reveal_fields: vec!["handle".to_owned()],
                        required: true,
                    },
                    ClaimDisclosureRequirement {
                        claim_type: AuthClaimType::OrganizationMembership.as_str().to_owned(),
                        trusted_issuers: vec![issuer.clone()],
                        reveal_fields: vec!["organization".to_owned()],
                        required: true,
                    },
                    ClaimDisclosureRequirement {
                        claim_type: AuthClaimType::GuardianController.as_str().to_owned(),
                        trusted_issuers: vec![issuer.clone()],
                        reveal_fields: vec!["guardian".to_owned(), "controller".to_owned()],
                        required: true,
                    },
                ],
                max_age: Some(Duration::days(1)),
                fail_closed: true,
            },
            created_at: Utc::now(),
            verifier_did: None,
            represented_org: None,
            verifier_authority_chain: Vec::new(),
        };
        let mut handle =
            PresentedClaim::verified_handle("claim-handle", alice.clone(), issuer.clone(), "alice");
        handle.issued_at = Utc::now();
        let membership = PresentedClaim::organization_membership(
            "claim-org",
            alice.clone(),
            issuer.clone(),
            org,
            vec!["writer".to_owned()],
        );
        let guardian_controller = PresentedClaim::guardian_controller(
            "claim-guardian",
            alice.clone(),
            issuer.clone(),
            guardian.clone(),
            controller.clone(),
        );

        let accepted = validate_presentation(
            &request,
            &[handle.clone(), membership, guardian_controller],
            &BTreeSet::new(),
            Utc::now(),
        );
        assert!(accepted.accepted);
        assert_eq!(accepted.disclosed_claims[0].value, serde_json::json!({"handle": "alice"}));
        assert_eq!(
            accepted.disclosed_claims[1].value,
            serde_json::json!({"organization": "did:web:org.example"})
        );
        assert_eq!(
            accepted.disclosed_claims[2].value,
            serde_json::json!({
                "guardian": guardian,
                "controller": controller
            })
        );
        let boundary = DisclosureProofAdapterBoundary {
            format: DisclosureProofFormat::SdJwt,
            holder: alice,
            issuer,
            audience: request.audience.clone(),
            nonce: request.nonce.clone(),
            domain: Some("contrix-auth".to_owned()),
            encoded_presentation: "compact.sd-jwt".to_owned(),
        };
        boundary.validate_request_binding(&request, Some("contrix-auth")).unwrap();
        let mut wrong_audience = boundary;
        wrong_audience.audience = "other-audience".to_owned();
        assert!(wrong_audience.validate_request_binding(&request, Some("contrix-auth")).is_err());

        let rejected = validate_presentation(
            &request,
            &[handle],
            &BTreeSet::from(["claim-handle".to_owned()]),
            Utc::now(),
        );
        assert!(!rejected.accepted);
        assert!(rejected.rejected_claims.iter().any(|claim| claim.reason == "claim is revoked"));
    }

    #[test]
    fn auth_uses_provider_did_proof_verifier_for_recovery() {
        let alice = did("alice");
        let verification_method = "did:web:alice.example#key-1";
        let mut auth = AuthManager::default();
        let request = auth
            .start_recovery(
                alice.clone(),
                AccountRecoveryMethod::DidProof {
                    verification_method: verification_method.to_owned(),
                },
            )
            .unwrap();
        let document = DidDocument::new(alice.clone(), verification_method, "public-key");
        let proof = Proof {
            kind: "did-proof".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.to_owned(),
            payload_hash: crate::Hash::new(format!("sha256:{}", sha256_hex(b"payload"))).unwrap(),
            created_at: Utc::now(),
            domain: Some("contrix-auth".to_owned()),
            audience: None,
            jws: "signed-proof".to_owned(),
        };
        let verifier = |request: &DidProofVerificationRequest| {
            assert_eq!(request.subject, alice);
            assert_eq!(request.public_key, "public-key");
            assert_eq!(request.proof.jws, "signed-proof");
            Ok(DidProofVerification {
                verified: true,
                subject: request.subject.clone(),
                verification_method: request.verification_method.clone(),
            })
        };

        let completed = auth
            .complete_recovery_with_did_verifier(&request.request_id, document, proof, &verifier)
            .unwrap();
        assert!(completed.completed_at.is_some());
    }

    #[test]
    fn auth_redacts_secrets_in_debug_output() {
        let alice = did("alice");
        let mut auth = AuthManager::default();
        let user = auth.register_password_user("alice", "secret", alice.clone()).unwrap();
        let session = auth.login_password("alice", "secret", device("desktop")).unwrap();
        let challenge = auth.issue_mfa(alice);

        assert!(!format!("{user:?}").contains(&user.password_hash));
        assert!(!format!("{session:?}").contains(&session.access_token));
        assert!(!format!("{session:?}").contains(&session.refresh_token));
        assert!(!format!("{challenge:?}").contains(&challenge.code));
    }

    #[test]
    fn auth_rate_limit_hook_can_deny_login() {
        let alice = did("alice");
        let mut auth = AuthManager::default().with_rate_limit_hook(deny_password_login);
        auth.register_password_user("alice", "secret", alice).unwrap();

        let err = auth.login_password("alice", "secret", device("desktop")).unwrap_err();
        assert!(err.to_string().contains("rate limited"));
    }
}
