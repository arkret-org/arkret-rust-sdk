use std::fmt;

use arkret_wire::{
    AccountId, DeviceId, DeviceRevocationAdmissionInput, DeviceRevocationAdmissionResult,
    DidCoreId, DidUrl, EventId, Result, SessionGrantAdmission, SessionGrantId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

pub const SESSION_GRANT_CREDENTIAL_KIND: &str = "ak.session.grant";
pub const SESSION_GRANT_ISSUANCE_SCHEMA: &str = "ak.session_grant.issuance.v1";
/// Proof kind presented with an `ak.session.grant` request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantProofKind {
    AccountHandoff,
    AgentKeyProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantCredentialClass {
    Standard,
    RecoverySession,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionGrantHolderBinding {
    HumanDevice {
        device_binding: String,
    },
    AgentRuntime {
        agent_id: DidCoreId,
        device_id: DeviceId,
        /// Event id of the accepted `ak.agent.key.authorize`. The request body
        /// carries the same event id, so the two surfaces stay comparable.
        agent_key_authorization_ref: EventId,
        verification_method: DidUrl,
    },
    RecoveryCandidateDevice {
        device_id: DeviceId,
    },
}

/// Authorization state committed into a standard human-device grant.
///
/// The Account Authority populates it from a Station-local revocation
/// admission record, which is the only source of the origin-derived
/// authorization Event and generation. That record deliberately carries no
/// RealmCommit witness, so this binding names the authorization Event alone —
/// it is not a `CommittedEventRef` and MUST NOT be taken from client input, a
/// local cache or a private lookup.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/SessionGrantDeviceBinding.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantDeviceBinding {
    pub device_id: DeviceId,
    pub authorization_event_id: EventId,
    /// PCR-local monotonic generation; never a DID `versionId`.
    pub model_generation_ref: u64,
}

impl SessionGrantDeviceBinding {
    /// The `(expected_device_authorize_event_id, expected_device_generation_ref)`
    /// pair an admission input carries when the issuer already holds a binding.
    /// The two members appear together or not at all.
    pub fn as_expected_revocation_binding(&self) -> (Option<EventId>, Option<u64>) {
        (
            Some(self.authorization_event_id.clone()),
            Some(self.model_generation_ref),
        )
    }

    /// The only admitted construction: an `allow` record that answers this
    /// exact input and is still fresh at `now`. Every other decision, and a
    /// stale or mismatched record, yields no binding.
    pub fn from_revocation_admission(
        outcome: &DeviceRevocationAdmissionResult,
        request: &DeviceRevocationAdmissionInput,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        match outcome.session_grant_admission(request, now)? {
            SessionGrantAdmission::Authorized {
                authorization_event_id,
                device_generation_ref,
            } => Ok(Self {
                device_id: outcome.admission_record.device_id.clone(),
                authorization_event_id: authorization_event_id.clone(),
                model_generation_ref: device_generation_ref,
            }),
            SessionGrantAdmission::DeviceSetupRequired | SessionGrantAdmission::Blocked { .. } => {
                Err(WireError::Protocol(
                    "session grant device binding requires an allow revocation admission"
                        .to_owned(),
                ))
            }
        }
    }

    /// Exact origin-derived authorization Event retained in the signed grant.
    pub const fn committed_authorization(&self) -> &EventId {
        &self.authorization_event_id
    }
}

/// Canonical unpadded Base64URL encoding of the issuer_id-generated 256-bit nonce.
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
            WireError::Protocol(
                "session grant issuance_nonce must be canonical Base64URL".to_owned(),
            )
        })?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
            WireError::Protocol(
                "session grant issuance_nonce must encode exactly 32 bytes".to_owned(),
            )
        })?;
        if arkret_canonical::base64url_encode(bytes) != value {
            return Err(WireError::Protocol(
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
                .map_err(|error| {
                    WireError::Protocol(format!("invalid session public JWK: {error}"))
                })?;
        validate_public_jwk(&parsed)?;
        let bytes = arkret_canonical::canonical_json_bytes(&parsed)
            .map_err(|error| WireError::Protocol(format!("invalid session public JWK: {error}")))?;
        let canonical = String::from_utf8(bytes).map_err(|error| {
            WireError::Protocol(format!("invalid UTF-8 session public JWK: {error}"))
        })?;
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// RFC 7638 SHA-256 thumbprint of the required public-key members.
    pub fn thumbprint_sha256(&self) -> Result<String> {
        let value: Value = serde_json::from_str(&self.0)?;
        let object = value
            .as_object()
            .expect("validated canonical session JWK is an object");
        let members = match object["kty"].as_str().expect("validated kty") {
            "OKP" => serde_json::json!({
                "crv": object["crv"],
                "kty": object["kty"],
                "x": object["x"],
            }),
            "EC" => serde_json::json!({
                "crv": object["crv"],
                "kty": object["kty"],
                "x": object["x"],
                "y": object["y"],
            }),
            "RSA" => serde_json::json!({
                "e": object["e"],
                "kty": object["kty"],
                "n": object["n"],
            }),
            _ => unreachable!("validated session JWK has a supported kty"),
        };
        let bytes = arkret_canonical::canonical_json_bytes(&members)?;
        Ok(arkret_canonical::base64url_encode(
            <sha2::Sha256 as sha2::Digest>::digest(bytes),
        ))
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
        WireError::Protocol("session_public_key must encode a JSON object".to_owned())
    })?;
    let kty = required_non_empty_string(object, "kty")?;
    let allowed = match kty {
        "OKP" => {
            let crv = required_non_empty_string(object, "crv")?;
            if crv != "Ed25519" || required_base64url_member(object, "x")?.len() != 32 {
                return Err(WireError::Protocol(
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
                    return Err(WireError::Protocol(format!(
                        "unsupported session EC JWK curve: {crv}"
                    )));
                }
            };
            if required_base64url_member(object, "x")?.len() != expected_len
                || required_base64url_member(object, "y")?.len() != expected_len
            {
                return Err(WireError::Protocol(format!(
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
                return Err(WireError::Protocol(
                    "session RSA JWK must use at least a 2048-bit modulus and a bounded exponent"
                        .to_owned(),
                ));
            }
            &[
                "kty", "n", "e", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256",
            ][..]
        }
        _ => {
            return Err(WireError::Protocol(format!(
                "unsupported session public JWK kty: {kty}"
            )));
        }
    };
    if let Some(member) = object
        .keys()
        .find(|member| !allowed.contains(&member.as_str()))
    {
        return Err(WireError::Protocol(format!(
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
                WireError::Protocol(format!("session public JWK {member} must be an array"))
            })?;
            if values
                .iter()
                .any(|value| value.as_str().is_none_or(str::is_empty))
            {
                return Err(WireError::Protocol(format!(
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
            WireError::Protocol(format!(
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
        return Err(WireError::Protocol(format!(
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

/// Closed immutable issuer_id-record preimage used to derive SessionGrantId.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIssuancePreimage {
    pub schema: String,
    pub issuer_id: DidCoreId,
    pub issuance_nonce: SessionGrantIssuanceNonce,
    pub account_id: AccountId,
    pub session_public_key: CanonicalSessionPublicJwk,
    pub audience_id: DidCoreId,
    pub scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub session_id: String,
    pub credential_class: SessionGrantCredentialClass,
    pub holder_binding: SessionGrantHolderBinding,
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
    pub scope_details: Option<Map<String, Value>>,
}

impl SessionGrantIssuancePreimage {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        arkret_canonical::canonical_json_bytes(self).map_err(|error| {
            WireError::Protocol(format!("invalid session grant preimage: {error}"))
        })
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
            &self.audience_id,
            &self.scopes,
            self.not_before,
            self.expires_at,
            &self.session_id,
            self.credential_class,
            &self.holder_binding,
            self.device_binding.as_ref(),
            self.scope_details.as_ref(),
        )
    }
}

/// Signed credential claims carried by an `ak.session.grant` JWT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "RawSignedSessionGrantClaims")]
pub struct SignedSessionGrantClaims {
    pub kind: String,
    #[serde(rename = "jti")]
    pub grant_id: SessionGrantId,
    pub issuer_id: DidCoreId,
    pub issuance_nonce: SessionGrantIssuanceNonce,
    pub account_id: AccountId,
    pub session_public_key: CanonicalSessionPublicJwk,
    pub audience_id: DidCoreId,
    pub scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub session_id: String,
    pub credential_class: SessionGrantCredentialClass,
    pub holder_binding: SessionGrantHolderBinding,
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
    pub scope_details: Option<Map<String, Value>>,
}

/// Deserialization-only shape. `TryFrom` eliminates conditionally invalid
/// human/Agent combinations before they can enter the public strong type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignedSessionGrantClaims {
    kind: String,
    #[serde(rename = "jti")]
    grant_id: SessionGrantId,
    issuer_id: DidCoreId,
    issuance_nonce: SessionGrantIssuanceNonce,
    account_id: AccountId,
    session_public_key: CanonicalSessionPublicJwk,
    audience_id: DidCoreId,
    scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
    session_id: String,
    credential_class: SessionGrantCredentialClass,
    holder_binding: SessionGrantHolderBinding,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    device_binding: Option<SessionGrantDeviceBinding>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    proof_kind: Option<SessionGrantProofKind>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    scope_details: Option<Map<String, Value>>,
}

impl TryFrom<RawSignedSessionGrantClaims> for SignedSessionGrantClaims {
    type Error = WireError;

    fn try_from(raw: RawSignedSessionGrantClaims) -> Result<Self> {
        validate_issuance_fields(
            SESSION_GRANT_ISSUANCE_SCHEMA,
            &raw.audience_id,
            &raw.scopes,
            raw.not_before,
            raw.expires_at,
            &raw.session_id,
            raw.credential_class,
            &raw.holder_binding,
            raw.device_binding.as_ref(),
            raw.scope_details.as_ref(),
        )?;
        Ok(Self {
            kind: raw.kind,
            grant_id: raw.grant_id,
            issuer_id: raw.issuer_id,
            issuance_nonce: raw.issuance_nonce,
            account_id: raw.account_id,
            session_public_key: raw.session_public_key,
            audience_id: raw.audience_id,
            scopes: raw.scopes,
            not_before: raw.not_before,
            expires_at: raw.expires_at,
            session_id: raw.session_id,
            credential_class: raw.credential_class,
            holder_binding: raw.holder_binding,
            device_binding: raw.device_binding,
            proof_kind: raw.proof_kind,
            scope_details: raw.scope_details,
        })
    }
}

impl SignedSessionGrantClaims {
    pub fn issuance_preimage(&self) -> SessionGrantIssuancePreimage {
        SessionGrantIssuancePreimage {
            schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
            issuer_id: self.issuer_id.clone(),
            issuance_nonce: self.issuance_nonce.clone(),
            account_id: self.account_id.clone(),
            session_public_key: self.session_public_key.clone(),
            audience_id: self.audience_id.clone(),
            scopes: self.scopes.clone(),
            not_before: self.not_before,
            expires_at: self.expires_at,
            session_id: self.session_id.clone(),
            credential_class: self.credential_class,
            holder_binding: self.holder_binding.clone(),
            device_binding: self.device_binding.clone(),
            proof_kind: self.proof_kind,
            scope_details: self.scope_details.clone(),
        }
    }

    pub fn recomputed_grant_id(&self) -> Result<SessionGrantId> {
        self.issuance_preimage().grant_id()
    }

    /// Validate claim shape and require `jti` to equal the ID recomputed from
    /// every signed issuance claim. Signature and accepted-at issuer_id-key
    /// verification remains the host verifier's preceding responsibility.
    pub fn validate(&self) -> Result<()> {
        if self.kind != SESSION_GRANT_CREDENTIAL_KIND {
            return Err(WireError::Protocol(format!(
                "session grant kind must be {SESSION_GRANT_CREDENTIAL_KIND}"
            )));
        }
        let expected = self.recomputed_grant_id()?;
        if self.grant_id != expected {
            return Err(WireError::Protocol(format!(
                "session grant jti does not match signed issuance claims: expected {expected}"
            )));
        }
        if self.session_id == self.grant_id.as_str() {
            return Err(WireError::Protocol(
                "session grant session_id must be independent from grant jti".to_owned(),
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_issuance_fields(
    schema: &str,
    audience_id: &DidCoreId,
    scopes: &[String],
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    session_id: &str,
    credential_class: SessionGrantCredentialClass,
    holder_binding: &SessionGrantHolderBinding,
    device_binding: Option<&SessionGrantDeviceBinding>,
    scope_details: Option<&Map<String, Value>>,
) -> Result<()> {
    if schema != SESSION_GRANT_ISSUANCE_SCHEMA {
        return Err(WireError::Protocol(format!(
            "session grant issuance schema must be {SESSION_GRANT_ISSUANCE_SCHEMA}"
        )));
    }
    if scopes.is_empty() || scopes.iter().any(|scope| scope.trim().is_empty()) {
        return Err(WireError::Protocol(
            "session grant scopes must contain only non-empty values".to_owned(),
        ));
    }
    if scopes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WireError::Protocol(
            "session grant scopes must be byte-wise sorted and deduplicated".to_owned(),
        ));
    }
    if session_id.trim().is_empty() {
        return Err(WireError::Protocol(
            "session grant session_id must not be empty".to_owned(),
        ));
    }
    if expires_at <= not_before {
        return Err(WireError::Protocol(
            "session grant expires_at must be after not_before".to_owned(),
        ));
    }
    if device_binding.is_some_and(|binding| binding.model_generation_ref == 0) {
        return Err(WireError::Protocol(
            "session grant device generation must be positive".to_owned(),
        ));
    }
    match (credential_class, holder_binding) {
        (
            SessionGrantCredentialClass::Standard,
            SessionGrantHolderBinding::HumanDevice {
                device_binding: holder_device_id,
            },
        ) => {
            let binding = device_binding.ok_or_else(|| {
                WireError::Protocol(
                    "standard human session grant requires a signed device_binding".to_owned(),
                )
            })?;
            if binding.device_id.as_str() != holder_device_id {
                return Err(WireError::Protocol(
                    "human holder_binding and signed device_binding identify different devices"
                        .to_owned(),
                ));
            }
            if scope_details.is_some() {
                return Err(WireError::Protocol(
                    "human session grant must omit Agent scope_details".to_owned(),
                ));
            }
        }
        (SessionGrantCredentialClass::Standard, SessionGrantHolderBinding::AgentRuntime { .. }) => {
            if device_binding.is_some() {
                return Err(WireError::Protocol(
                    "Agent runtime session grant must omit human device_binding".to_owned(),
                ));
            }
        }
        (
            SessionGrantCredentialClass::RecoverySession,
            SessionGrantHolderBinding::RecoveryCandidateDevice { .. },
        ) => {
            if device_binding.is_some() {
                return Err(WireError::Protocol(
                    "recovery-session grant must omit accepted device_binding".to_owned(),
                ));
            }
            if scope_details.is_some() {
                return Err(WireError::Protocol(
                    "recovery-session grant must omit Agent scope_details".to_owned(),
                ));
            }
        }
        _ => {
            return Err(WireError::Protocol(
                "session grant credential_class and holder_binding are incompatible".to_owned(),
            ));
        }
    }
    let _ = (audience_id, holder_binding, device_binding, scope_details);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn device_authorization_event_id() -> EventId {
        EventId::new("ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g").unwrap()
    }

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
            issuer_id: DidCoreId::new("ak:did_core:web:issuer_id.example").unwrap(),
            issuance_nonce: SessionGrantIssuanceNonce::from_bytes([0x11; 32]),
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            ),
            session_public_key: CanonicalSessionPublicJwk::new(
                r#"{ "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "kty":"OKP", "crv":"Ed25519" }"#,
            )
            .unwrap(),
            audience_id: DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            scopes: vec!["ak.self.events.command.submit.v1".to_owned()],
            not_before: "2026-07-18T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-07-18T00:15:00.000Z".parse().unwrap(),
            session_id: "session-1".to_owned(),
            credential_class: SessionGrantCredentialClass::Standard,
            holder_binding: SessionGrantHolderBinding::HumanDevice {
                device_binding: "ak:device:019a0000-0000-7000-8000-000000000001".to_owned(),
            },
            device_binding: Some(SessionGrantDeviceBinding {
                device_id: DeviceId::new(
                    "ak:device:019a0000-0000-7000-8000-000000000001",
                )
                .unwrap(),
                authorization_event_id: device_authorization_event_id(),
                model_generation_ref: 1,
            }),
            proof_kind: Some(SessionGrantProofKind::AccountHandoff),
            scope_details: None,
        };
        claims.grant_id = claims.recomputed_grant_id().unwrap();
        claims
    }

    #[test]
    fn retired_pairwise_session_grant_members_are_rejected() {
        assert!(
            serde_json::from_str::<SessionGrantProofKind>("\"pairwise_endpoint_proof\"").is_err()
        );
        assert!(
            serde_json::from_value::<SessionGrantHolderBinding>(serde_json::json!({
                "kind": "minimal_metadata_pairwise",
                "realm_id": "ak:realm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }))
            .is_err()
        );
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
    fn recovery_claims_require_candidate_holder_without_accepted_binding() {
        let mut recovery = claims();
        recovery.credential_class = SessionGrantCredentialClass::RecoverySession;
        recovery.holder_binding = SessionGrantHolderBinding::RecoveryCandidateDevice {
            device_id: DeviceId::new("ak:device:019a0000-0000-7000-8000-000000000009").unwrap(),
        };
        recovery.device_binding = None;
        recovery.grant_id = recovery.recomputed_grant_id().unwrap();
        recovery.validate().unwrap();

        let mut accepted_binding = recovery.clone();
        accepted_binding.device_binding = claims().device_binding;
        assert!(accepted_binding.recomputed_grant_id().is_err());
        assert!(accepted_binding.validate().is_err());

        let mut wrong_class = recovery;
        wrong_class.credential_class = SessionGrantCredentialClass::Standard;
        assert!(wrong_class.recomputed_grant_id().is_err());
        assert!(wrong_class.validate().is_err());
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
        tampered.audience_id = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(tampered.validate().is_err());

        let mut value = serde_json::to_value(claims()).unwrap();
        value["unexpected_binding"] = Value::Object(Default::default());
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
    fn migrated_fixture_vectors_have_stable_canonical_grant_ids() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/session-grant-issuance-fixture.json",
        )
        .unwrap();
        let vectors = fixture["accepted_vectors"].as_array().unwrap();
        for vector in vectors {
            let materialized =
                materialized_fixture_vector(&fixture, vector["name"].as_str().unwrap());
            let preimage: SessionGrantIssuancePreimage =
                serde_json::from_value(materialized).unwrap();
            let bytes = preimage.canonical_bytes().unwrap();
            let decoded: SessionGrantIssuancePreimage = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded.grant_id().unwrap(), preimage.grant_id().unwrap());
            let canonical = String::from_utf8(bytes).unwrap();
            assert_eq!(
                canonical.contains("authorization_event_id"),
                preimage.device_binding.is_some(),
                "{} must carry the origin-derived authorization Event exactly when it has a device binding",
                vector["name"]
            );
        }
    }

    #[test]
    fn fixture_tamper_cases_fail_closed() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/session-grant-issuance-fixture.json",
        )
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
                "audience_id" => {
                    value["audience_id"] =
                        Value::String("ak:did_core:webvh:z6mkfixtureotherservice".to_owned());
                }
                "holder_binding.device_binding" => {
                    value["holder_binding"]["device_binding"] =
                        Value::String("ak:device:019a0000-0000-7000-8000-000000000099".to_owned());
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
                    if case.get("value_from")
                        == Some(&Value::String("session_grant_id".to_owned())) =>
                {
                    value["session_id"] = value["jti"].clone();
                }
                mutation => panic!("unhandled session-grant tamper fixture mutation {mutation}"),
            }
            if let Ok(tampered) = serde_json::from_value::<SignedSessionGrantClaims>(value) {
                assert!(tampered.validate().is_err(), "{name} must fail validation");
            }
        }
        let required = "holder_binding_changed_without_jti_change";
        assert!(
            covered.contains(required),
            "missing fixture coverage for {required}"
        );
    }

    #[test]
    fn fixture_credential_binding_negative_cases_fail_closed() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/session-grant-issuance-fixture.json",
        )
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
            assert!(
                serde_json::from_value::<SignedSessionGrantClaims>(value).is_err(),
                "{name} must fail decoding"
            );
        }
        let required = "standard_missing_holder_binding";
        assert!(
            covered.contains(required),
            "missing fixture coverage for {required}"
        );
    }
}
