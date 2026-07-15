use super::helpers::{
    constant_time_eq, hash_password, recovery_proof_matches, sha256_hex, verify_password,
};
use super::*;

/// Authenticated session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_id: String,
    pub user_id: Did,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub session_credential: String,
    pub renewal_credential: String,
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
    sessions_by_user: BTreeMap<Did, VecDeque<String>>,
    account_states: BTreeMap<Did, AccountAuthState>,
    renewal_credentials: BTreeMap<String, RenewalCredentialMetadata>,
    revoked_sessions: BTreeMap<String, SessionRevocation>,
    passkey_challenges: BTreeMap<Did, PasskeyChallenge>,
    mfa_challenges: BTreeMap<Did, MfaChallenge>,
    recovery_requests: BTreeMap<String, AccountRecoveryRequestBody>,
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
            renewal_credentials: BTreeMap::new(),
            revoked_sessions: BTreeMap::new(),
            passkey_challenges: BTreeMap::new(),
            mfa_challenges: BTreeMap::new(),
            recovery_requests: BTreeMap::new(),
            rate_limit_hook: None,
            session_limit,
        }
    }

    /// Set an application-supplied rate-limit hook for login, MFA and recovery strands.
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
        self.register_password_hash(username, hash_password(password)?, user_id)
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
        self.account_states
            .entry(user.user_id.clone())
            .or_insert(AccountAuthState::Active);
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
        if !verify_password(password, &user.password_hash) {
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
        let verification = verifier.verify_password(&PasswordVerificationRequestBody {
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
    ) -> OidcAuthRequestBody {
        let issuer = issuer.into();
        let client_id = client_id.into();
        let redirect_uri = redirect_uri.into();
        let state = state.into();
        let authorization_url = format!(
            "{issuer}/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&state={state}"
        );
        OidcAuthRequestBody {
            issuer,
            client_id,
            redirect_uri,
            state,
            authorization_url,
        }
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
        request: OidcVerificationRequestBody,
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
            challenge: format!("passkey:{}", uuid::Uuid::now_v7()),
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
        response: WebAuthnPasskeyOutcome,
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
        let verified = verifier.verify_passkey(&PasskeyVerificationRequestBody {
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
        let code =
            sha256_hex(format!("{}:{}", user_id, uuid::Uuid::now_v7()).as_bytes())[..6].to_owned();
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

    /// Refresh a session credential.
    pub fn refresh_session(
        &mut self,
        session_id: &str,
        renewal_credential: &str,
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
        let supplied_hash = sha256_hex(renewal_credential.as_bytes());
        if let Some(metadata) = self.renewal_credentials.get(session_id) {
            if metadata.revoked_at.is_some() {
                return Err(Error::Protocol("session revoked".to_owned()));
            }
            if !constant_time_eq(&metadata.renewal_credential_hash, &supplied_hash) {
                return Err(Error::Protocol("invalid renewal credential".to_owned()));
            }
        } else if !constant_time_eq(&snapshot.renewal_credential, renewal_credential) {
            return Err(Error::Protocol("invalid renewal credential".to_owned()));
        }
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::Protocol("session not found".to_owned()))?;
        session.session_credential = format!("sc_{}", uuid::Uuid::now_v7());
        if session.renewal_credential == "<redacted>" {
            session.renewal_credential = renewal_credential.to_owned();
        }
        session.expires_at = Utc::now() + Duration::hours(1);
        if let Some(metadata) = self.renewal_credentials.get_mut(session_id) {
            metadata.session_credential_hash = sha256_hex(session.session_credential.as_bytes());
            metadata.renewal_credential_hash = supplied_hash;
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
        if let Some(metadata) = self.renewal_credentials.get_mut(session_id) {
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
            expires_at: session.expires_at,
        })
    }

    /// Validate access-token and device binding for an active session.
    pub fn validate_session(
        &self,
        session_id: &str,
        session_credential: &str,
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
            return Err(Error::Protocol(
                "session device binding mismatch".to_owned(),
            ));
        }
        let supplied_hash = sha256_hex(session_credential.as_bytes());
        if let Some(metadata) = self.renewal_credentials.get(session_id) {
            if !constant_time_eq(&metadata.session_credential_hash, &supplied_hash) {
                return Err(Error::Protocol("invalid session credential".to_owned()));
            }
        } else if !constant_time_eq(&session.session_credential, session_credential) {
            return Err(Error::Protocol("invalid session credential".to_owned()));
        }
        self.session_principal_binding(session_id)
    }

    /// Set an account state. Non-active states fail closed for login and refresh.
    pub fn set_account_state(&mut self, user_id: Did, state: AccountAuthState) {
        self.account_states.insert(user_id, state);
    }

    /// Current account state. Missing state fails closed.
    pub fn account_state(&self, user_id: &Did) -> AccountAuthState {
        self.account_states
            .get(user_id)
            .copied()
            .unwrap_or(AccountAuthState::Suspended)
    }

    /// Export durable auth state without raw access or renewal credential material.
    pub fn export_state(&self) -> AuthStateSnapshot {
        let sessions = self
            .sessions
            .values()
            .map(|session| {
                let metadata = self.renewal_credentials.get(&session.session_id);
                PersistedAuthSession {
                    session_id: session.session_id.clone(),
                    user_id: session.user_id.clone(),
                    principal_id: session.principal_id.clone(),
                    device_id: session.device_id.clone(),
                    expires_at: session.expires_at,
                    revoked: session.revoked,
                    created_at: session.created_at,
                    session_credential_hash: metadata
                        .map(|metadata| metadata.session_credential_hash.clone())
                        .unwrap_or_else(|| sha256_hex(session.session_credential.as_bytes())),
                    renewal_credential_hash: metadata
                        .map(|metadata| metadata.renewal_credential_hash.clone())
                        .unwrap_or_else(|| sha256_hex(session.renewal_credential.as_bytes())),
                }
            })
            .collect();
        AuthStateSnapshot {
            password_users: self.password_users.clone(),
            sessions,
            account_states: self.account_states.clone(),
            renewal_credentials: self.renewal_credentials.clone(),
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
        self.renewal_credentials = snapshot.renewal_credentials;
        self.revoked_sessions = snapshot.revoked_sessions;
        self.recovery_requests = snapshot.recovery_requests;

        for persisted in snapshot.sessions {
            let session = AuthSession {
                session_id: persisted.session_id.clone(),
                user_id: persisted.user_id.clone(),
                principal_id: persisted.principal_id,
                device_id: persisted.device_id.clone(),
                session_credential: "<redacted>".to_owned(),
                renewal_credential: "<redacted>".to_owned(),
                expires_at: persisted.expires_at,
                revoked: persisted.revoked,
                created_at: persisted.created_at,
            };
            self.renewal_credentials
                .entry(persisted.session_id.clone())
                .or_insert(RenewalCredentialMetadata {
                    session_id: persisted.session_id.clone(),
                    user_id: persisted.user_id.clone(),
                    device_id: persisted.device_id,
                    session_credential_hash: persisted.session_credential_hash,
                    renewal_credential_hash: persisted.renewal_credential_hash,
                    issued_at: persisted.created_at,
                    expires_at: persisted.expires_at,
                    revoked_at: if persisted.revoked {
                        Some(Utc::now())
                    } else {
                        None
                    },
                });
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
    ) -> Result<AccountRecoveryRequestBody> {
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::RecoveryStart,
            subject: None,
            user_id: Some(user_id.clone()),
            device_id: None,
            now: Utc::now(),
        })?;
        let request = AccountRecoveryRequestBody {
            request_id: format!("recovery_{}", uuid::Uuid::now_v7()),
            user_id,
            method,
            expires_at: Utc::now() + Duration::minutes(15),
            completed_at: None,
        };
        self.recovery_requests
            .insert(request.request_id.clone(), request.clone());
        Ok(request)
    }

    /// Complete a pending account recovery request after caller-supplied proof verification.
    pub fn complete_recovery(
        &mut self,
        request_id: &str,
        proof: &str,
    ) -> Result<AccountRecoveryRequestBody> {
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
            return Err(Error::Protocol(
                "recovery request already completed".to_owned(),
            ));
        }
        // DID-proof and passkey rebinding identifiers are PUBLIC values, so a
        // proof derived from them is no proof at all. These methods MUST be
        // completed through `complete_recovery_with_did_verifier` (or a
        // WebAuthn verifier), which checks a real signature. Fail closed here.
        if matches!(
            request.method,
            AccountRecoveryMethod::DidProof { .. }
                | AccountRecoveryMethod::PasskeyWebAuthnRebinding { .. }
        ) {
            return Err(Error::Protocol(
                "did/passkey recovery must use complete_recovery_with_did_verifier".to_owned(),
            ));
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
    ) -> Result<AccountRecoveryRequestBody>
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
            return Err(Error::Protocol(
                "recovery request already completed".to_owned(),
            ));
        }
        let AccountRecoveryMethod::DidProof {
            verification_method,
        } = &request.method
        else {
            return Err(Error::Protocol(
                "recovery method is not did proof".to_owned(),
            ));
        };
        if did_document.id != request.user_id {
            return Err(Error::Protocol("did document subject mismatch".to_owned()));
        }
        did_document.validate()?;
        let public_key = did_document
            .verification_methods
            .get(verification_method.as_str())
            .ok_or_else(|| Error::Protocol("verification method not found".to_owned()))?
            .clone();
        if proof.verification_method != verification_method.as_str() {
            return Err(Error::Protocol(
                "proof verification method mismatch".to_owned(),
            ));
        }
        let verification = verifier.verify_did_proof(&DidProofVerificationRequestBody {
            subject: request.user_id.clone(),
            did_document,
            verification_method: verification_method.clone(),
            public_key: NonEmptyString::new(public_key).map_err(|reason| {
                Error::Protocol(format!(
                    "invalid DID verification method public key: {reason}"
                ))
            })?,
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

/// One-shot DID-proof login strand that drives the single registered
/// `POST /_arkret/gate/account/session-grants`
/// (`ak.gate.account.command.issue_session_grant`) operation.
///
/// The helper is split off into its own impl block (gated on `client`
/// and `signer`) so the in-process `AuthManager` core surface stays
/// transport-free.
#[cfg(all(feature = "client", feature = "signer"))]
impl AuthManager {
    /// Maximum `expires_at - issued_at` freshness window for a
    /// `ak.did.proof` (`identity-did.md` §5.1: window upper bound MUST
    /// be ≤ 300s).
    const DID_PROOF_FRESHNESS_WINDOW_SECS: i64 = 300;

    /// One-shot DID-proof login. Builds the `ak.did.proof` signing
    /// payload (`identity-did.md` §5.1), signs it with `signer`, and
    /// submits the spec-shaped `SessionGrantRequestBody` to the single
    /// registered issuance operation. The `challenge` is the
    /// server-issued one-time challenge obtained through the
    /// deployment-local channel (the protocol HTTP binding registers
    /// no challenge sub-path under `/_arkret/`).
    pub async fn login_did_proof<S>(
        &mut self,
        client: &arkret_http_client::Client,
        principal_id: Did,
        device_id: DeviceId,
        signer: &S,
        challenge: &str,
        audience: Did,
    ) -> Result<arkret_core::SessionGrantOutcome>
    where
        S: arkret_core::MoveSigner + ?Sized,
    {
        if challenge.len() < 16 {
            return Err(Error::Protocol(
                "session grant challenge must be at least 16 characters".to_owned(),
            ));
        }

        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(Self::DID_PROOF_FRESHNESS_WINDOW_SECS);

        // Digest of the canonical request binding (request body without
        // the proof object) — bound into both the wire proof and the
        // signed payload so the proof cannot be replayed against a
        // different request body.
        let request_binding = serde_json::json!({
            "principal_id": principal_id.as_str(),
            "device_id": device_id.as_str(),
        });
        let request_canonical_digest =
            crate::Hash::new(arkret_canonical::canonical::sha256_digest(
                &arkret_canonical::canonical::canonical_json_bytes(&request_binding)?,
            ))?;

        // `ak.did.proof` structured canonical-JSON signing payload per
        // `identity-did.md` §5.1 (device_id is signed-over for
        // multi-device principals; the SDK always supplies it).
        let signing_payload = serde_json::json!({
            "kind": "ak.did.proof",
            "purpose": "ak.session.grant",
            "did": principal_id.as_str(),
            "device_id": device_id.as_str(),
            "audience": audience.as_str(),
            "challenge": challenge,
            "request_canonical_digest": request_canonical_digest.as_str(),
            "issued_at": arkret_canonical::canonical::format_timestamp_canonical(issued_at),
            "expires_at": arkret_canonical::canonical::format_timestamp_canonical(expires_at),
        });
        let payload_bytes = arkret_canonical::canonical::canonical_json_bytes(&signing_payload)?;
        let move_sig = signer.sign_payload(&payload_bytes)?;

        client
            .auth_issue_session_grant(&arkret_core::SessionGrantRequestBody {
                principal_id,
                device_id: Some(device_id),
                requested_scope: Vec::new(),
                agent_key_authorization_ref: None,
                agent_scope_request: None,
                dpop_binding_proof: None,
                applet_delegation: None,
                proof: arkret_core::SessionGrantRequestProof {
                    proof_kind: arkret_core::SessionGrantProofKind::DidBoundSignature,
                    challenge: challenge.to_owned(),
                    request_canonical_digest,
                    audience,
                    expires_at: Some(expires_at),
                    signature: move_sig.jws,
                    verification_method: None,
                    issuer: None,
                    client_id: None,
                    redirect_uri: None,
                    state: None,
                    nonce: None,
                    authorization_code: None,
                    code_verifier: None,
                },
            })
            .await
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new(8)
    }
}
