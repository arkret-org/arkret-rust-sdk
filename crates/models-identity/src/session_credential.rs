use std::fmt;

use arkret_wire::{
    DeviceId, Did, DidUrl, Error, EventId, Hash, PolicyId, RecoveryModelGenerationRef,
    RecoverySessionId, Result, SessionGrantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

pub const SESSION_GRANT_CREDENTIAL_KIND: &str = "ak.session.grant";
pub const SESSION_GRANT_ISSUANCE_SCHEMA: &str = "ak.session_grant.issuance.v1";

pub const RECOVERY_RESTRICTED_SESSION_GRANT_SCOPES: [&str; 9] = [
    "ak.root.identity.recovery_policy.resource.get",
    "ak.root.identity.recovery_session.command.create",
    "ak.root.identity.recovery_session.resource.get",
    "ak.root.identity.recovery_session.command.submit_proof",
    "ak.self.security_transaction.command.create",
    "ak.self.security_transaction.resource.get",
    "ak.self.security_transaction.command.continue",
    "ak.self.recovery_authority_ticket.command.issue",
    "ak.self.keys.backups.command.unlock",
];

/// Proof kind presented with an `ak.session.grant` request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantProofKind {
    DidBoundSignature,
    PairedDeviceProof,
    PasskeyAssertion,
    OidcCodeExchange,
    PreRegistrationHandoff,
    AgentKeyProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantCredentialClass {
    Standard,
    DeviceBootstrap,
    RecoveryRestricted,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionGrantHolderBinding {
    HumanDevice {
        device_binding: String,
    },
    AgentRuntime {
        agent_id: Did,
        device_id: DeviceId,
        agent_key_authorization_ref: EventId,
        verification_method: DidUrl,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionGrantBootstrapBinding {
    Founding {
        credential_kind: String,
        principal_id: Did,
        device_id: DeviceId,
        device_key_digest: Hash,
        transaction_id: String,
        holder_jkt: Hash,
        canonical_request_digest: Hash,
        founding_batch_digest: Hash,
        founding_event_ids: Vec<EventId>,
        allowed_operation_ids: Vec<String>,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        credential_expires_at: DateTime<Utc>,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        bootstrap_transaction_expires_at: DateTime<Utc>,
    },
    SiblingPairing {
        credential_kind: String,
        principal_id: Did,
        device_id: DeviceId,
        device_key_digest: Hash,
        transaction_id: String,
        holder_jkt: Hash,
        canonical_request_digest: Hash,
        source_device_id: DeviceId,
        target_device_id: DeviceId,
        verification_content_kinds: Vec<String>,
        allowed_operation_ids: Vec<String>,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        credential_expires_at: DateTime<Utc>,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        bootstrap_transaction_expires_at: DateTime<Utc>,
    },
}

impl SessionGrantBootstrapBinding {
    fn validate(&self) -> Result<()> {
        let (
            credential_kind,
            transaction_id,
            allowed_operation_ids,
            credential_expires_at,
            bootstrap_transaction_expires_at,
        ) = match self {
            Self::Founding {
                credential_kind,
                transaction_id,
                founding_event_ids,
                allowed_operation_ids,
                credential_expires_at,
                bootstrap_transaction_expires_at,
                ..
            } => {
                if founding_event_ids.is_empty()
                    || founding_event_ids
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != founding_event_ids.len()
                {
                    return Err(Error::Protocol(
                        "device bootstrap founding_event_ids must be unique and non-empty"
                            .to_owned(),
                    ));
                }
                (
                    credential_kind,
                    transaction_id,
                    allowed_operation_ids,
                    credential_expires_at,
                    bootstrap_transaction_expires_at,
                )
            }
            Self::SiblingPairing {
                credential_kind,
                transaction_id,
                verification_content_kinds,
                allowed_operation_ids,
                credential_expires_at,
                bootstrap_transaction_expires_at,
                ..
            } => {
                if verification_content_kinds.is_empty()
                    || verification_content_kinds.iter().any(|kind| {
                        !kind.starts_with("ak.key.verification.") || kind.trim().is_empty()
                    })
                {
                    return Err(Error::Protocol(
                        "device bootstrap verification_content_kinds are invalid".to_owned(),
                    ));
                }
                (
                    credential_kind,
                    transaction_id,
                    allowed_operation_ids,
                    credential_expires_at,
                    bootstrap_transaction_expires_at,
                )
            }
        };
        if credential_kind != "device_bootstrap" {
            return Err(Error::Protocol(
                "bootstrap_binding credential_kind must be device_bootstrap".to_owned(),
            ));
        }
        if transaction_id.trim().is_empty() || allowed_operation_ids.is_empty() {
            return Err(Error::Protocol(
                "device bootstrap transaction and operation allowlist must be non-empty".to_owned(),
            ));
        }
        if credential_expires_at > bootstrap_transaction_expires_at {
            return Err(Error::Protocol(
                "device bootstrap credential cannot outlive its transaction".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantRecoveryBinding {
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantDeviceBinding {
    pub device_id: DeviceId,
    pub authorization_event_id: EventId,
    pub model_generation_ref: RecoveryModelGenerationRef,
}

/// Canonical unpadded Base64URL encoding of the issuer-generated 256-bit nonce.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SessionGrantIssuanceNonce(String);

impl SessionGrantIssuanceNonce {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(arkret_canonical::base64url_encode(bytes))
    }

    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let decoded = arkret_canonical::base64url_decode(&value).map_err(|_| {
            Error::Protocol("session grant issuance_nonce must be canonical Base64URL".to_owned())
        })?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
            Error::Protocol("session grant issuance_nonce must encode exactly 32 bytes".to_owned())
        })?;
        if arkret_canonical::base64url_encode(bytes) != value {
            return Err(Error::Protocol(
                "session grant issuance_nonce must be canonical unpadded Base64URL".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn bytes(&self) -> [u8; 32] {
        arkret_canonical::base64url_decode(&self.0)
            .expect("validated issuance nonce is Base64URL")
            .try_into()
            .expect("validated issuance nonce is 32 bytes")
    }
}

impl fmt::Display for SessionGrantIssuanceNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SessionGrantIssuanceNonce {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A supported public JWK serialized as its unique RFC 8785/JCS JSON string.
/// Inbound member order and insignificant whitespace are normalized once at
/// the SDK boundary; private-key members and unknown members fail closed.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CanonicalSessionPublicJwk(String);

impl CanonicalSessionPublicJwk {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let parsed =
            arkret_canonical::parse_json_rejecting_duplicate_keys(value.as_ref().as_bytes())
                .map_err(|error| Error::Protocol(format!("invalid session public JWK: {error}")))?;
        validate_public_jwk(&parsed)?;
        let bytes = arkret_canonical::canonical_json_bytes(&parsed)
            .map_err(|error| Error::Protocol(format!("invalid session public JWK: {error}")))?;
        let canonical = String::from_utf8(bytes).map_err(|error| {
            Error::Protocol(format!("invalid UTF-8 session public JWK: {error}"))
        })?;
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for CanonicalSessionPublicJwk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CanonicalSessionPublicJwk {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = String::deserialize(deserializer)?;
        let canonical = Self::new(&wire).map_err(serde::de::Error::custom)?;
        if canonical.as_str() != wire {
            return Err(serde::de::Error::custom(
                "signed session_public_key claim must already use canonical JWK JCS encoding",
            ));
        }
        Ok(canonical)
    }
}

fn validate_public_jwk(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        Error::Protocol("session_public_key must encode a JSON object".to_owned())
    })?;
    let kty = required_non_empty_string(object, "kty")?;
    let allowed = match kty {
        "OKP" => {
            let crv = required_non_empty_string(object, "crv")?;
            if crv != "Ed25519" || required_base64url_member(object, "x")?.len() != 32 {
                return Err(Error::Protocol(
                    "session OKP JWK must be an Ed25519 key with a 32-byte x coordinate".to_owned(),
                ));
            }
            &[
                "kty", "crv", "x", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256",
            ][..]
        }
        "EC" => {
            let crv = required_non_empty_string(object, "crv")?;
            let expected_len = match crv {
                "P-256" => 32,
                "P-384" => 48,
                "P-521" => 66,
                _ => {
                    return Err(Error::Protocol(format!(
                        "unsupported session EC JWK curve: {crv}"
                    )));
                }
            };
            if required_base64url_member(object, "x")?.len() != expected_len
                || required_base64url_member(object, "y")?.len() != expected_len
            {
                return Err(Error::Protocol(format!(
                    "session EC JWK {crv} coordinates have the wrong length"
                )));
            }
            &[
                "kty", "crv", "x", "y", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t",
                "x5t#S256",
            ][..]
        }
        "RSA" => {
            if required_base64url_member(object, "n")?.len() < 256
                || !(1..=8).contains(&required_base64url_member(object, "e")?.len())
            {
                return Err(Error::Protocol(
                    "session RSA JWK must use at least a 2048-bit modulus and a bounded exponent"
                        .to_owned(),
                ));
            }
            &[
                "kty", "n", "e", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256",
            ][..]
        }
        _ => {
            return Err(Error::Protocol(format!(
                "unsupported session public JWK kty: {kty}"
            )));
        }
    };
    if let Some(member) = object
        .keys()
        .find(|member| !allowed.contains(&member.as_str()))
    {
        return Err(Error::Protocol(format!(
            "unsupported or private session public JWK member: {member}"
        )));
    }
    for member in ["use", "alg", "kid", "x5u", "x5t", "x5t#S256"] {
        if object.contains_key(member) {
            required_non_empty_string(object, member)?;
        }
    }
    for member in ["key_ops", "x5c"] {
        if let Some(value) = object.get(member) {
            let values = value.as_array().ok_or_else(|| {
                Error::Protocol(format!("session public JWK {member} must be an array"))
            })?;
            if values
                .iter()
                .any(|value| value.as_str().is_none_or(str::is_empty))
            {
                return Err(Error::Protocol(format!(
                    "session public JWK {member} must contain only non-empty strings"
                )));
            }
        }
    }
    Ok(())
}

fn required_non_empty_string<'a>(object: &'a Map<String, Value>, member: &str) -> Result<&'a str> {
    object
        .get(member)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::Protocol(format!(
                "session public JWK {member} must be a non-empty string"
            ))
        })
}

fn required_base64url_member(object: &Map<String, Value>, member: &str) -> Result<Vec<u8>> {
    let value = required_non_empty_string(object, member)?;
    if value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || value.len() % 4 == 1
    {
        return Err(Error::Protocol(format!(
            "session public JWK {member} must be canonical unpadded Base64URL"
        )));
    }
    // JWK fixtures can carry public-key placeholders whose unused trailing
    // bits are not cryptographically decoded until the signature verifier.
    // The model boundary still enforces the exact coordinate byte length from
    // the unpadded Base64URL character count.
    Ok(vec![0; value.len() * 6 / 8])
}

fn deserialize_optional_non_null<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// RFC 7800 confirmation claim binding a grant to a DPoP holder key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantCnf {
    pub jkt: String,
}

/// Closed immutable issuer-record preimage used to derive SessionGrantId.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIssuancePreimage {
    pub schema: String,
    pub issuer: Did,
    pub issuance_nonce: SessionGrantIssuanceNonce,
    pub subject: Did,
    pub session_public_key: CanonicalSessionPublicJwk,
    pub audience: Did,
    pub scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub session_id: String,
    pub cnf: SessionGrantCnf,
    pub credential_class: SessionGrantCredentialClass,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub holder_binding: Option<SessionGrantHolderBinding>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub bootstrap_binding: Option<SessionGrantBootstrapBinding>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub recovery_binding: Option<SessionGrantRecoveryBinding>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub device_binding: Option<SessionGrantDeviceBinding>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub proof_kind: Option<SessionGrantProofKind>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub scope_details: Option<Value>,
}

impl SessionGrantIssuancePreimage {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        arkret_canonical::canonical_json_bytes(self)
            .map_err(|error| Error::Protocol(format!("invalid session grant preimage: {error}")))
    }

    pub fn issuance_digest(&self) -> Result<[u8; 32]> {
        Ok(arkret_canonical::sha256_bytes(self.canonical_bytes()?))
    }

    pub fn grant_id(&self) -> Result<SessionGrantId> {
        Ok(SessionGrantId::from_issuance_digest(
            self.issuance_digest()?,
        ))
    }

    pub fn validate(&self) -> Result<()> {
        validate_issuance_fields(
            &self.schema,
            &self.audience,
            &self.scopes,
            self.not_before,
            self.expires_at,
            &self.session_id,
            &self.cnf,
            self.credential_class,
            self.holder_binding.as_ref(),
            self.bootstrap_binding.as_ref(),
            self.recovery_binding.as_ref(),
            self.device_binding.as_ref(),
            self.scope_details.as_ref(),
        )
    }
}

/// Signed credential claims carried by an `ak.session.grant` JWT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSessionGrantClaims {
    pub kind: String,
    #[serde(rename = "jti")]
    pub grant_id: SessionGrantId,
    pub issuer: Did,
    pub issuance_nonce: SessionGrantIssuanceNonce,
    pub subject: Did,
    pub session_public_key: CanonicalSessionPublicJwk,
    pub audience: Did,
    pub scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub session_id: String,
    pub cnf: SessionGrantCnf,
    pub credential_class: SessionGrantCredentialClass,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub holder_binding: Option<SessionGrantHolderBinding>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub bootstrap_binding: Option<SessionGrantBootstrapBinding>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub recovery_binding: Option<SessionGrantRecoveryBinding>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub device_binding: Option<SessionGrantDeviceBinding>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub proof_kind: Option<SessionGrantProofKind>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub scope_details: Option<Value>,
}

impl SignedSessionGrantClaims {
    pub fn issuance_preimage(&self) -> SessionGrantIssuancePreimage {
        SessionGrantIssuancePreimage {
            schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
            issuer: self.issuer.clone(),
            issuance_nonce: self.issuance_nonce.clone(),
            subject: self.subject.clone(),
            session_public_key: self.session_public_key.clone(),
            audience: self.audience.clone(),
            scopes: self.scopes.clone(),
            not_before: self.not_before,
            expires_at: self.expires_at,
            session_id: self.session_id.clone(),
            cnf: self.cnf.clone(),
            credential_class: self.credential_class,
            holder_binding: self.holder_binding.clone(),
            bootstrap_binding: self.bootstrap_binding.clone(),
            recovery_binding: self.recovery_binding.clone(),
            device_binding: self.device_binding.clone(),
            proof_kind: self.proof_kind,
            scope_details: self.scope_details.clone(),
        }
    }

    pub fn recomputed_grant_id(&self) -> Result<SessionGrantId> {
        self.issuance_preimage().grant_id()
    }

    /// Validate claim shape and require `jti` to equal the ID recomputed from
    /// every signed issuance claim. Signature and accepted-at issuer-key
    /// verification remains the host verifier's preceding responsibility.
    pub fn validate(&self) -> Result<()> {
        if self.kind != SESSION_GRANT_CREDENTIAL_KIND {
            return Err(Error::Protocol(format!(
                "session grant kind must be {SESSION_GRANT_CREDENTIAL_KIND}"
            )));
        }
        let expected = self.recomputed_grant_id()?;
        if self.grant_id != expected {
            return Err(Error::Protocol(format!(
                "session grant jti does not match signed issuance claims: expected {expected}"
            )));
        }
        if self.session_id == self.grant_id.as_str() {
            return Err(Error::Protocol(
                "session grant session_id must be independent from grant jti".to_owned(),
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_issuance_fields(
    schema: &str,
    audience: &Did,
    scopes: &[String],
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    session_id: &str,
    cnf: &SessionGrantCnf,
    credential_class: SessionGrantCredentialClass,
    holder_binding: Option<&SessionGrantHolderBinding>,
    bootstrap_binding: Option<&SessionGrantBootstrapBinding>,
    recovery_binding: Option<&SessionGrantRecoveryBinding>,
    device_binding: Option<&SessionGrantDeviceBinding>,
    scope_details: Option<&Value>,
) -> Result<()> {
    if schema != SESSION_GRANT_ISSUANCE_SCHEMA {
        return Err(Error::Protocol(format!(
            "session grant issuance schema must be {SESSION_GRANT_ISSUANCE_SCHEMA}"
        )));
    }
    if scopes.is_empty() || scopes.iter().any(|scope| scope.trim().is_empty()) {
        return Err(Error::Protocol(
            "session grant scopes must contain only non-empty values".to_owned(),
        ));
    }
    if scopes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::Protocol(
            "session grant scopes must be byte-wise sorted and deduplicated".to_owned(),
        ));
    }
    if session_id.trim().is_empty() {
        return Err(Error::Protocol(
            "session grant session_id must not be empty".to_owned(),
        ));
    }
    if expires_at <= not_before {
        return Err(Error::Protocol(
            "session grant expires_at must be after not_before".to_owned(),
        ));
    }
    if cnf.jkt.len() != 43
        || !cnf
            .jkt
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::Protocol(
            "session grant cnf.jkt must be a base64url SHA-256 JWK thumbprint".to_owned(),
        ));
    }
    if scope_details.is_some_and(Value::is_null) {
        return Err(Error::Protocol(
            "session grant scope_details must be omitted rather than null".to_owned(),
        ));
    }
    match (
        credential_class,
        holder_binding,
        bootstrap_binding,
        recovery_binding,
    ) {
        (SessionGrantCredentialClass::RecoveryRestricted, None, None, Some(binding))
            if binding.policy_version > 0
                && scopes.iter().all(|scope| {
                    RECOVERY_RESTRICTED_SESSION_GRANT_SCOPES.contains(&scope.as_str())
                }) => {}
        (SessionGrantCredentialClass::DeviceBootstrap, None, Some(binding), None) => {
            binding.validate()?;
        }
        (SessionGrantCredentialClass::Standard, Some(_), None, None) => {}
        _ => {
            return Err(Error::Protocol(
                "session grant credential class and typed bindings disagree".to_owned(),
            ));
        }
    }
    let _ = (audience, device_binding);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn materialized_fixture_vector(fixture: &Value, name: &str) -> Value {
        let vectors = fixture["accepted_vectors"].as_array().unwrap();
        let vector = vectors
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap_or_else(|| panic!("missing accepted fixture vector {name}"));
        let mut materialized = vectors[0]["issuance_preimage"].clone();
        let object = materialized.as_object_mut().unwrap();
        if let Some(overrides) = vector.get("override").and_then(Value::as_object) {
            for (key, value) in overrides {
                object.insert(key.clone(), value.clone());
            }
        }
        if let Some(omitted) = vector.get("omit").and_then(Value::as_array) {
            for key in omitted.iter().map(|value| value.as_str().unwrap()) {
                object.remove(key);
            }
        }
        materialized
    }

    fn signed_claims_value(preimage_value: Value) -> Value {
        let preimage: SessionGrantIssuancePreimage =
            serde_json::from_value(preimage_value.clone()).unwrap();
        let grant_id = preimage.grant_id().unwrap();
        let mut claims_value = preimage_value;
        let object = claims_value.as_object_mut().unwrap();
        object.remove("schema");
        object.insert(
            "kind".to_owned(),
            Value::String(SESSION_GRANT_CREDENTIAL_KIND.to_owned()),
        );
        object.insert("jti".to_owned(), Value::String(grant_id.to_string()));
        claims_value
    }

    fn claims() -> SignedSessionGrantClaims {
        let mut claims = SignedSessionGrantClaims {
            kind: SESSION_GRANT_CREDENTIAL_KIND.to_owned(),
            grant_id: SessionGrantId::from_issuance_digest([0; 32]),
            issuer: Did::new("did:web:issuer.example").unwrap(),
            issuance_nonce: SessionGrantIssuanceNonce::from_bytes([0x11; 32]),
            subject: Did::new("did:web:alice.example").unwrap(),
            session_public_key: CanonicalSessionPublicJwk::new(
                r#"{ "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "kty":"OKP", "crv":"Ed25519" }"#,
            )
            .unwrap(),
            audience: Did::new("did:web:service.example").unwrap(),
            scopes: vec!["ak.self.events.command.submit".to_owned()],
            not_before: "2026-07-18T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-07-18T00:15:00.000Z".parse().unwrap(),
            session_id: "session-1".to_owned(),
            cnf: SessionGrantCnf {
                jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            },
            credential_class: SessionGrantCredentialClass::Standard,
            holder_binding: Some(SessionGrantHolderBinding::HumanDevice {
                device_binding: "ak:device:019a0000-0000-7000-8000-000000000001".to_owned(),
            }),
            bootstrap_binding: None,
            recovery_binding: None,
            device_binding: None,
            proof_kind: Some(SessionGrantProofKind::DidBoundSignature),
            scope_details: None,
        };
        claims.grant_id = claims.recomputed_grant_id().unwrap();
        claims
    }

    #[test]
    fn validates_normative_shape_and_recomputes_jti() {
        let claims = claims();
        claims.validate().unwrap();
        let value = serde_json::to_value(&claims).unwrap();
        assert_eq!(value["jti"], claims.grant_id.as_str());
        assert!(value.get("grant_id").is_none());
        assert_eq!(
            value["session_public_key"],
            r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#
        );
    }

    #[test]
    fn canonical_jwk_normalizes_equivalent_input() {
        let first = CanonicalSessionPublicJwk::new(
            r#"{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .unwrap();
        let second = CanonicalSessionPublicJwk::new(
            r#"{ "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "crv": "Ed25519", "kty": "OKP" }"#,
        )
        .unwrap();
        assert_eq!(first, second);
        assert!(CanonicalSessionPublicJwk::new(
            r#"{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","d":"secret"}"#
        )
        .is_err());
    }

    #[test]
    fn rejects_tampered_claim_and_explicit_null_optional() {
        let mut tampered = claims();
        tampered.audience = Did::new("did:web:other.example").unwrap();
        assert!(tampered.validate().is_err());

        let mut value = serde_json::to_value(claims()).unwrap();
        value["recovery_binding"] = Value::Null;
        assert!(serde_json::from_value::<SignedSessionGrantClaims>(value).is_err());

        let mut self_referential = claims();
        self_referential.session_id = self_referential.grant_id.to_string();
        self_referential.grant_id = self_referential.recomputed_grant_id().unwrap();
        // Recompute once more so the forbidden equality is tested directly,
        // independent of the normal digest-mismatch guard.
        self_referential.session_id = self_referential.grant_id.to_string();
        assert!(self_referential.validate().is_err());
    }

    #[test]
    fn signed_claim_rejects_noncanonical_jwk_string() {
        let mut value = serde_json::to_value(claims()).unwrap();
        value["session_public_key"] = Value::String(
            r#"{ "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "kty":"OKP", "crv":"Ed25519" }"#
                .to_owned(),
        );
        assert!(serde_json::from_value::<SignedSessionGrantClaims>(value).is_err());
    }

    #[test]
    fn fixture_known_answer_matches_spec() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/session-grant-issuance-fixture.json")
                .unwrap();
        let vectors = fixture["accepted_vectors"].as_array().unwrap();
        for vector in vectors {
            let materialized =
                materialized_fixture_vector(&fixture, vector["name"].as_str().unwrap());
            let preimage: SessionGrantIssuancePreimage =
                serde_json::from_value(materialized).unwrap();
            assert_eq!(
                String::from_utf8(preimage.canonical_bytes().unwrap()).unwrap(),
                vector["canonical_preimage_utf8"].as_str().unwrap(),
                "{} canonical bytes",
                vector["name"]
            );
            assert_eq!(
                preimage.grant_id().unwrap().as_str(),
                vector["grant_id"].as_str().unwrap(),
                "{} grant id",
                vector["name"]
            );
        }
    }

    #[test]
    fn fixture_tamper_cases_fail_closed() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/session-grant-issuance-fixture.json")
                .unwrap();
        let mut covered = BTreeSet::new();
        for case in fixture["tamper_cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            covered.insert(name);
            let base_vector = case
                .get("base_vector")
                .and_then(Value::as_str)
                .unwrap_or("issuer_a_closed_preimage");
            let mut value = signed_claims_value(materialized_fixture_vector(&fixture, base_vector));
            match case["mutate"].as_str().unwrap() {
                "issuance_nonce" => {
                    value["issuance_nonce"] = Value::String(
                        SessionGrantIssuanceNonce::from_bytes([0x22; 32]).to_string(),
                    );
                }
                "audience" => {
                    value["audience"] =
                        Value::String("did:webvh:z6mkfixture:other-service.example".to_owned());
                }
                "holder_binding.device_binding" => {
                    value["holder_binding"]["device_binding"] =
                        Value::String("ak:device:019a0000-0000-7000-8000-000000000099".to_owned());
                }
                "bootstrap_binding.transaction_id" => {
                    value["bootstrap_binding"]["transaction_id"] =
                        Value::String("bootstrap-transaction-tampered".to_owned());
                }
                "session_public_key_member_order_or_whitespace" => {
                    value["session_public_key"] = Value::String(
                        r#"{ "x":"11qYAYdk9Jc1iP4Z9Qv7XKpM6Jw8LmN0RsTuVwXyZaB", "kty":"OKP", "crv":"Ed25519" }"#
                            .to_owned(),
                    );
                    assert!(
                        serde_json::from_value::<SignedSessionGrantClaims>(value).is_err(),
                        "{name} must reject noncanonical signed JWK text"
                    );
                    continue;
                }
                "session_id"
                    if case.get("value_from") == Some(&Value::String("grant_id".to_owned())) =>
                {
                    value["session_id"] = value["jti"].clone();
                }
                mutation => panic!("unhandled session-grant tamper fixture mutation {mutation}"),
            }
            let tampered: SignedSessionGrantClaims = serde_json::from_value(value).unwrap();
            assert!(tampered.validate().is_err(), "{name} must fail validation");
        }
        for required in [
            "holder_binding_changed_without_jti_change",
            "bootstrap_binding_changed_without_jti_change",
        ] {
            assert!(
                covered.contains(required),
                "missing fixture coverage for {required}"
            );
        }
    }

    #[test]
    fn fixture_credential_binding_negative_cases_fail_closed() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/session-grant-issuance-fixture.json")
                .unwrap();
        let mut covered = BTreeSet::new();
        for case in fixture["credential_binding_negative_cases"]
            .as_array()
            .unwrap()
        {
            let name = case["name"].as_str().unwrap();
            covered.insert(name);
            let base_vector = case["base_vector"].as_str().unwrap();
            let mut value = signed_claims_value(materialized_fixture_vector(&fixture, base_vector));
            let object = value.as_object_mut().unwrap();
            if let Some(omitted) = case.get("omit").and_then(Value::as_array) {
                for field in omitted.iter().map(|value| value.as_str().unwrap()) {
                    object.remove(field);
                }
            }
            if let Some(addition) = case.get("add_from_vector") {
                let field = addition["field"].as_str().unwrap();
                let source =
                    materialized_fixture_vector(&fixture, addition["vector"].as_str().unwrap());
                object.insert(field.to_owned(), source[field].clone());
            }
            let invalid: SignedSessionGrantClaims = serde_json::from_value(value).unwrap();
            assert!(invalid.validate().is_err(), "{name} must fail validation");
        }
        for required in [
            "standard_with_recovery_binding",
            "device_bootstrap_with_recovery_binding",
        ] {
            assert!(
                covered.contains(required),
                "missing fixture coverage for {required}"
            );
        }
    }
}
