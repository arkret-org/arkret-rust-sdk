use arkret_wire::DidCoreId;

use super::helpers::{hash_password, sha256_hex, verify_password};
use super::*;

/// Authenticated session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_id: String,
    pub user_id: DidCoreId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub session_credential: String,
    pub renewal_credential: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthSession")
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("session_credential", &"<redacted>")
            .field("renewal_credential", &"<redacted>")
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
    sessions_by_user: BTreeMap<DidCoreId, VecDeque<String>>,
    account_states: BTreeMap<DidCoreId, AccountAuthState>,
    renewal_credentials: BTreeMap<String, RenewalCredentialMetadata>,
    revoked_sessions: BTreeMap<String, SessionRevocation>,
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
            renewal_credentials: BTreeMap::new(),
            revoked_sessions: BTreeMap::new(),
            session_limit,
        }
    }

    /// Register a username/password identity with the built-in local hash helper.
    pub fn register_password_user(
        &mut self,
        username: impl Into<String>,
        password: &str,
        user_id: DidCoreId,
    ) -> Result<PasswordUser> {
        self.register_password_hash(username, hash_password(password)?, user_id)
    }

    /// Register a username/password identity with an application-supplied password hash.
    pub fn register_password_hash(
        &mut self,
        username: impl Into<String>,
        password_hash: impl Into<String>,
        user_id: DidCoreId,
    ) -> Result<PasswordUser> {
        let username = username.into();
        if self.password_users.contains_key(&username) {
            return Err(Error::Protocol("username already registered".to_owned()));
        }
        let user = PasswordUser {
            username: username.clone(),
            user_id,
            password_hash: password_hash.into(),
        };
        self.account_states
            .entry(user.user_id.clone())
            .or_insert(AccountAuthState::Active);
        self.password_users.insert(username, user.clone());
        Ok(user)
    }

    /// Login with username/password using the built-in local hash helper.
    pub fn login_password(
        &mut self,
        username: &str,
        password: &str,
        device_id: DeviceId,
    ) -> Result<AuthSession> {
        let user = self
            .password_users
            .get(username)
            .ok_or_else(|| Error::Protocol("user not found".to_owned()))?;
        if !verify_password(password, &user.password_hash) {
            return Err(Error::Protocol("invalid password".to_owned()));
        }
        self.create_session(user.user_id.clone(), device_id)
    }

    /// Create a session and enforce the concurrent session limit.
    pub fn create_session(
        &mut self,
        user_id: DidCoreId,
        device_id: DeviceId,
    ) -> Result<AuthSession> {
        self.ensure_account_active(&user_id)?;
        let now = Utc::now();
        let session = AuthSession {
            session_id: format!("sess_{}", uuid::Uuid::now_v7()),
            session_credential: format!("sc_{}", uuid::Uuid::now_v7()),
            renewal_credential: format!("rc_{}", uuid::Uuid::now_v7()),
            expires_at: now + Duration::hours(1),
            revoked: false,
            created_at: now,
            user_id: user_id.clone(),
            principal_id: user_id.clone(),
            device_id: device_id.clone(),
        };
        self.renewal_credentials.insert(
            session.session_id.clone(),
            RenewalCredentialMetadata {
                session_id: session.session_id.clone(),
                user_id: user_id.clone(),
                device_id,
                session_credential_hash: sha256_hex(session.session_credential.as_bytes()),
                renewal_credential_hash: sha256_hex(session.renewal_credential.as_bytes()),
                issued_at: now,
                expires_at: session.expires_at,
                revoked_at: None,
            },
        );
        self.sessions
            .insert(session.session_id.clone(), session.clone());
        let session_ids = self.sessions_by_user.entry(user_id).or_default();
        session_ids.push_back(session.session_id.clone());
        while session_ids.len() > self.session_limit {
            if let Some(oldest) = session_ids.pop_front()
                && let Some(session) = self.sessions.get_mut(&oldest)
            {
                session.revoked = true;
                if let Some(metadata) = self.renewal_credentials.get_mut(&oldest) {
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

    /// Current account state. Missing state fails closed.
    pub fn account_state(&self, user_id: &DidCoreId) -> AccountAuthState {
        self.account_states
            .get(user_id)
            .copied()
            .unwrap_or(AccountAuthState::Suspended)
    }

    fn ensure_account_active(&self, user_id: &DidCoreId) -> Result<()> {
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
