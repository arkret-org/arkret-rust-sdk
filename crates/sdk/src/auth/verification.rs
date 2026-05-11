use super::*;

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

