//! Authentication flow and session management helpers.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{DeviceId, Did, Error, Result};

/// Registered password user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaChallenge {
    pub user_id: Did,
    pub code: String,
    pub expires_at: DateTime<Utc>,
    pub verified: bool,
}

/// Account recovery method types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRecoveryMethod {
    DidProof { verification_method: String },
    PasswordReset { reset_token_hash: String },
    PasskeyWebAuthnRebinding { credential_id: String },
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

/// Authenticated session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Auth and session manager.
#[derive(Clone, Debug)]
pub struct AuthManager {
    password_users: BTreeMap<String, PasswordUser>,
    sessions: BTreeMap<String, AuthSession>,
    sessions_by_user: BTreeMap<Did, VecDeque<String>>,
    passkey_challenges: BTreeMap<Did, PasskeyChallenge>,
    mfa_challenges: BTreeMap<Did, MfaChallenge>,
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
            session_limit,
        }
    }

    /// Register a username/password identity.
    pub fn register_password_user(
        &mut self,
        username: impl Into<String>,
        password: &str,
        user_id: Did,
    ) -> Result<PasswordUser> {
        let username = username.into();
        if self.password_users.contains_key(&username) {
            return Err(Error::Protocol("username already registered".to_owned()));
        }
        let user = PasswordUser {
            username: username.clone(),
            user_id,
            password_hash: sha256_hex(password.as_bytes()),
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

    /// Login with username/password.
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
        if user.password_hash != sha256_hex(password.as_bytes()) {
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
        self.create_session(user_id, device_id)
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

    /// Verify a passkey response. The local test verifier expects SHA-256(challenge).
    pub fn verify_passkey(
        &mut self,
        user_id: &Did,
        response: &str,
        device_id: DeviceId,
    ) -> Result<AuthSession> {
        let challenge = self
            .passkey_challenges
            .get(user_id)
            .ok_or_else(|| Error::Protocol("passkey challenge not found".to_owned()))?;
        if challenge.expires_at <= Utc::now() {
            return Err(Error::Protocol("passkey challenge expired".to_owned()));
        }
        if response != sha256_hex(challenge.challenge.as_bytes()) {
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
        let challenge = self
            .mfa_challenges
            .get_mut(user_id)
            .ok_or_else(|| Error::Protocol("mfa challenge not found".to_owned()))?;
        if challenge.expires_at <= Utc::now() {
            return Err(Error::Protocol("mfa challenge expired".to_owned()));
        }
        if challenge.code != code {
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
        if session.refresh_token != refresh_token {
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
        &self,
        user_id: Did,
        method: AccountRecoveryMethod,
    ) -> AccountRecoveryRequest {
        AccountRecoveryRequest {
            request_id: format!("recovery_{}", Ulid::new()),
            user_id,
            method,
            expires_at: Utc::now() + Duration::minutes(15),
            completed_at: None,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn device(id: &str) -> DeviceId {
        DeviceId::new(format!("dev_{id}")).unwrap()
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
    fn auth_models_account_recovery_methods() {
        let auth = AuthManager::default();
        let request = auth.start_recovery(
            did("alice"),
            AccountRecoveryMethod::DidProof {
                verification_method: "did:web:alice.example#key-1".to_owned(),
            },
        );
        assert!(request.request_id.starts_with("recovery_"));
        assert!(request.completed_at.is_none());
    }
}
