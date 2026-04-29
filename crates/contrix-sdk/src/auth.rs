//! Authentication flow and session management helpers.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
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

/// Session-to-DID principal binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPrincipalBinding {
    pub session_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub created_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
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
    pub keys: serde_json::Value,
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

    /// Register a username/password identity with the legacy local hash helper.
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

    /// Login with username/password using the legacy local hash helper.
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

    /// Verify a passkey response with the legacy local challenge helper.
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
        let session = AuthSession {
            session_id: format!("sess_{}", Ulid::new()),
            access_token: format!("atk_{}", Ulid::new()),
            refresh_token: format!("rtk_{}", Ulid::new()),
            expires_at: Utc::now() + Duration::hours(1),
            revoked: false,
            created_at: Utc::now(),
            user_id: user_id.clone(),
            principal_id: user_id.clone(),
            device_id,
        };
        self.sessions.insert(session.session_id.clone(), session.clone());
        let session_ids = self.sessions_by_user.entry(user_id).or_default();
        session_ids.push_back(session.session_id.clone());
        while session_ids.len() > self.session_limit {
            if let Some(oldest) = session_ids.pop_front()
                && let Some(session) = self.sessions.get_mut(&oldest)
            {
                session.revoked = true;
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
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::Protocol("session not found".to_owned()))?;
        if session.revoked {
            return Err(Error::Protocol("session revoked".to_owned()));
        }
        if !constant_time_eq(&session.refresh_token, refresh_token) {
            return Err(Error::Protocol("invalid refresh token".to_owned()));
        }
        session.access_token = format!("atk_{}", Ulid::new());
        session.expires_at = Utc::now() + Duration::hours(1);
        Ok(session.clone())
    }

    /// Revoke a session.
    pub fn revoke_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::Protocol("session not found".to_owned()))?;
        session.revoked = true;
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
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new(8)
    }
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
