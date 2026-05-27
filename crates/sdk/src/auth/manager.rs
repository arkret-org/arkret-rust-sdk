use super::helpers::{constant_time_eq, recovery_proof_matches, sha256_hex};
use super::*;

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
    recovery_requests: BTreeMap<String, AccountRecoveryReqBody>,
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
        let verification = verifier.verify_password(&PasswordVerificationReqBody {
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
    ) -> OidcAuthReqBody {
        let issuer = issuer.into();
        let client_id = client_id.into();
        let redirect_uri = redirect_uri.into();
        let state = state.into();
        let authorization_url = format!(
            "{issuer}/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&state={state}"
        );
        OidcAuthReqBody { issuer, client_id, redirect_uri, state, authorization_url }
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
        request: OidcVerificationReqBody,
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
        response: WebAuthnPasskeyResBody,
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
        let verified = verifier.verify_passkey(&PasskeyVerificationReqBody {
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
    ) -> Result<AccountRecoveryReqBody> {
        self.check_rate_limit(AuthRateLimitContext {
            action: AuthRateLimitAction::RecoveryStart,
            subject: None,
            user_id: Some(user_id.clone()),
            device_id: None,
            now: Utc::now(),
        })?;
        let request = AccountRecoveryReqBody {
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
    ) -> Result<AccountRecoveryReqBody> {
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
    ) -> Result<AccountRecoveryReqBody>
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
        let verification = verifier.verify_did_proof(&DidProofVerificationReqBody {
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

/// S-2 (savfox SDK gap): one-shot DID-proof login flow that drives
/// `POST /auth/account/session-grants` end-to-end.
///
/// The helper is split off into its own impl block (gated on `client`
/// and `signer`) so the in-process `AuthManager` core surface stays
/// transport-free.
#[cfg(all(feature = "client", feature = "signer"))]
impl AuthManager {
    /// One-shot DID-proof login. Performs the challenge round-trip
    /// internally using the supplied signer, then maps the wire
    /// `AuthSessionWire` into the SDK's [`AuthSession`].
    ///
    /// Spec: `identity-did.md` §5.1 (`cx.did.proof` purpose
    /// `cx.session.grant`).
    pub async fn login_did_proof<S>(
        &mut self,
        client: &contrix_http_client::Client,
        principal_did: Did,
        device_id: DeviceId,
        signer: &S,
        verification_method: &str,
        audience: &str,
    ) -> Result<AuthSession>
    where
        S: contrix_core::MoveSigner + ?Sized,
    {
        // Step 1: request the challenge.
        let challenge = client
            .auth_session_grant_challenge(&crate::model::SessionGrantChallengeReq {
                principal_did: principal_did.clone(),
                device_id: device_id.clone(),
                audience: audience.to_owned(),
                origin: None,
            })
            .await?;

        // Fail-closed on expired / mismatched challenges before signing.
        if !challenge.is_session_grant_purpose() {
            return Err(Error::Protocol(format!(
                "challenge purpose must be cx.session.grant, got '{}'",
                challenge.purpose
            )));
        }
        if challenge.audience != audience {
            return Err(Error::Protocol(format!(
                "challenge audience '{}' does not match requested '{}'",
                challenge.audience, audience
            )));
        }
        if challenge.expires_at <= Utc::now() {
            return Err(Error::Protocol("session grant challenge expired".to_owned()));
        }

        // Step 2: build the cx.did.proof payload, sign it, and submit.
        let proof_payload = crate::model::SessionGrantDidProof::from_challenge(
            &challenge,
            principal_did.clone(),
            device_id.clone(),
        );
        let payload_bytes = contrix_core::canonical::canonical_json_bytes(&proof_payload)?;
        let move_sig = signer.sign_payload(&payload_bytes)?;
        let payload_digest =
            crate::Hash::new(contrix_core::canonical::sha256_digest(&payload_bytes))?;
        let proof = Proof {
            kind: contrix_core::proof_kind::DETACHED_JWS.to_owned(),
            alg: move_sig.alg,
            verification_method: verification_method.to_owned(),
            payload_digest,
            created_at: Utc::now(),
            domain: None,
            audience: Some(contrix_core::Audience::Single(audience.to_owned())),
            jws: move_sig.jws,
        };

        let wire = client
            .auth_session_grant_submit(&crate::model::SessionGrantSubmitReq {
                challenge_id: challenge.challenge_id.clone(),
                principal_did: principal_did.clone(),
                device_id: device_id.clone(),
                proof_payload,
                proof,
            })
            .await?;

        Ok(AuthSession {
            session_id: wire.session_id,
            user_id: wire.user_id,
            principal_id: wire.principal_id,
            device_id: wire.device_id,
            access_token: wire.access_token,
            refresh_token: wire.refresh_token,
            expires_at: wire.expires_at,
            revoked: wire.revoked,
            created_at: wire.created_at,
        })
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new(8)
    }
}
