use super::helpers::sha256_hex;
use super::*;

/// Session grant payload issued by an identity provider to a Principal Server.
///
/// This is the stable contract shared by coauth, soland and admin tooling. It
/// intentionally excludes private session key material and server-derived
/// identity metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrantPayload {
    /// Principal or agent DID authorized by this grant.
    pub subject: Did,
    pub audience: Did,
    pub scopes: Vec<String>,
    pub session_id: String,
    pub grant_jti: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<SessionGrantConfirmation>,
}

/// RFC 9449 / RFC 7800 confirmation claim for DPoP-bound session grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrantConfirmation {
    pub jkt: String,
}

impl SessionGrantPayload {
    /// Validate the payload before it is signed or persisted.
    pub fn validate(&self) -> Result<()> {
        if self.scopes.is_empty() {
            return Err(Error::Protocol(
                "session grant scopes must not be empty".to_owned(),
            ));
        }
        if self.session_id.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant session_id must not be empty".to_owned(),
            ));
        }
        if self.grant_jti.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant grant_jti must not be empty".to_owned(),
            ));
        }
        if let Some(cnf) = &self.cnf
            && cnf.jkt.trim().is_empty()
        {
            return Err(Error::Protocol(
                "session grant cnf.jkt must not be empty".to_owned(),
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
    pub fn principal_binding(&self) -> Result<SessionPrincipalBinding> {
        let device_id = primary_device_id_from_scopes(&self.scopes).ok_or_else(|| {
            Error::Protocol("session grant has no device scope for principal binding".to_owned())
        })?;
        Ok(SessionPrincipalBinding {
            session_id: self.session_id.clone(),
            principal_id: self.subject.clone(),
            device_id,
            created_at: self.issued_at,
            expires_at: self.expires_at,
        })
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
            return Err(Error::Protocol(
                "session grant JWT must not be empty".to_owned(),
            ));
        }
        let grant_hash = sha256_hex(grant_jwt.as_bytes());
        Ok(Self {
            payload,
            grant_jwt,
            grant_hash,
        })
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
            return Err(Error::Protocol(
                "session grant JWS was not verified".to_owned(),
            ));
        }
        if self.grant_hash.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant hash must not be empty".to_owned(),
            ));
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
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
pub struct PrincipalSessionGrantNotificationOutcome {
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
        Self {
            initial_backoff_ms: 1_000,
            max_backoff_ms: 60_000,
            max_attempts: 8,
        }
    }
}

impl SessionGrantRetryPolicy {
    pub fn next_delay_ms(&self, attempts: u32) -> Option<u64> {
        if attempts >= self.max_attempts {
            return None;
        }
        let shift = attempts.min(31);
        Some(
            self.initial_backoff_ms
                .saturating_mul(1u64 << shift)
                .min(self.max_backoff_ms),
        )
    }
}

/// Durable outbox item shape; services own persistence and scheduling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrantOutboxEntry {
    pub notification: PrincipalSessionGrantNotification,
    pub state: SessionGrantOutboxState,
    pub attempts: u32,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
        matches!(
            self.state,
            SessionGrantOutboxState::Pending | SessionGrantOutboxState::Failed
        ) && self.next_attempt_at <= now
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

/// Pluggable session-grant outbox boundary.
///
/// Identity providers can use the default in-memory implementation for tests
/// and inject a durable implementation (Postgres, queue table, etc.) through
/// [`SessionGrantOutboxSlot`] in service integrations.
pub trait SessionGrantOutbox: Send + Sync {
    fn enqueue(
        &mut self,
        notification: PrincipalSessionGrantNotification,
        now: DateTime<Utc>,
    ) -> Result<()>;

    fn due(&self, now: DateTime<Utc>) -> Result<Vec<SessionGrantOutboxEntry>>;

    fn entries(&self) -> Result<Vec<SessionGrantOutboxEntry>>;

    fn record_delivery(&mut self, request_id: &str) -> Result<bool>;

    fn record_failure(
        &mut self,
        request_id: &str,
        error: String,
        now: DateTime<Utc>,
        policy: SessionGrantRetryPolicy,
    ) -> Result<bool>;
}

/// Boxed outbox slot used by hosts that want to swap persistence backends.
pub struct SessionGrantOutboxSlot {
    inner: Box<dyn SessionGrantOutbox>,
}

impl fmt::Debug for SessionGrantOutboxSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionGrantOutboxSlot")
            .finish_non_exhaustive()
    }
}

impl Default for SessionGrantOutboxSlot {
    fn default() -> Self {
        Self::memory()
    }
}

impl SessionGrantOutboxSlot {
    pub fn new(inner: Box<dyn SessionGrantOutbox>) -> Self {
        Self { inner }
    }

    pub fn memory() -> Self {
        Self::new(Box::<MemorySessionGrantOutbox>::default())
    }

    pub fn enqueue(
        &mut self,
        notification: PrincipalSessionGrantNotification,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.inner.enqueue(notification, now)
    }

    pub fn due(&self, now: DateTime<Utc>) -> Result<Vec<SessionGrantOutboxEntry>> {
        self.inner.due(now)
    }

    pub fn entries(&self) -> Result<Vec<SessionGrantOutboxEntry>> {
        self.inner.entries()
    }

    pub fn record_delivery(&mut self, request_id: &str) -> Result<bool> {
        self.inner.record_delivery(request_id)
    }

    pub fn record_failure(
        &mut self,
        request_id: &str,
        error: impl Into<String>,
        now: DateTime<Utc>,
        policy: SessionGrantRetryPolicy,
    ) -> Result<bool> {
        self.inner
            .record_failure(request_id, error.into(), now, policy)
    }
}

/// In-memory contract helper for tests and single-process prototypes.
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
        self.entries
            .push_back(SessionGrantOutboxEntry::new(notification, now)?);
        Ok(())
    }

    pub fn due(&self, now: DateTime<Utc>) -> Vec<&SessionGrantOutboxEntry> {
        self.entries.iter().filter(|entry| entry.due(now)).collect()
    }

    pub fn entries(&self) -> impl Iterator<Item = &SessionGrantOutboxEntry> {
        self.entries.iter()
    }

    pub fn record_delivery(&mut self, request_id: &str) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.notification.request_id == request_id)
        else {
            return false;
        };
        entry.record_delivery();
        true
    }

    pub fn record_failure(
        &mut self,
        request_id: &str,
        error: impl Into<String>,
        now: DateTime<Utc>,
        policy: SessionGrantRetryPolicy,
    ) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.notification.request_id == request_id)
        else {
            return false;
        };
        entry.record_failure(error, now, policy);
        true
    }
}

impl SessionGrantOutbox for MemorySessionGrantOutbox {
    fn enqueue(
        &mut self,
        notification: PrincipalSessionGrantNotification,
        now: DateTime<Utc>,
    ) -> Result<()> {
        MemorySessionGrantOutbox::enqueue(self, notification, now)
    }

    fn due(&self, now: DateTime<Utc>) -> Result<Vec<SessionGrantOutboxEntry>> {
        Ok(MemorySessionGrantOutbox::due(self, now)
            .into_iter()
            .cloned()
            .collect())
    }

    fn entries(&self) -> Result<Vec<SessionGrantOutboxEntry>> {
        Ok(MemorySessionGrantOutbox::entries(self).cloned().collect())
    }

    fn record_delivery(&mut self, request_id: &str) -> Result<bool> {
        Ok(MemorySessionGrantOutbox::record_delivery(self, request_id))
    }

    fn record_failure(
        &mut self,
        request_id: &str,
        error: String,
        now: DateTime<Utc>,
        policy: SessionGrantRetryPolicy,
    ) -> Result<bool> {
        Ok(MemorySessionGrantOutbox::record_failure(
            self, request_id, error, now, policy,
        ))
    }
}

/// Host-supplied notifier for Principal Server session-grant propagation.
///
/// Pair with [`SessionGrantOutbox`] for idempotency-key persistence and
/// retry/backoff scheduling.
pub trait PrincipalSessionGrantNotifier {
    fn notify_session_grant(
        &self,
        notification: &PrincipalSessionGrantNotification,
    ) -> Result<PrincipalSessionGrantNotificationOutcome>;
}

impl<F> PrincipalSessionGrantNotifier for F
where
    F: Fn(&PrincipalSessionGrantNotification) -> Result<PrincipalSessionGrantNotificationOutcome>,
{
    fn notify_session_grant(
        &self,
        notification: &PrincipalSessionGrantNotification,
    ) -> Result<PrincipalSessionGrantNotificationOutcome> {
        self(notification)
    }
}
