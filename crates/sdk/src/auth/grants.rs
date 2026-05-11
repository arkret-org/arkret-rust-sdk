use super::helpers::sha256_hex;
use super::*;

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
