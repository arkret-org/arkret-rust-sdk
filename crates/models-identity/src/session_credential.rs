use std::fmt;

use arkret_wire::{
    AccountDeviceRevocationAdmissionAssessment, AccountDeviceRevocationAdmissionInput, AccountId,
    DeviceId, DidCoreId, DidUrl, EventId, Result, SessionGrantAdmission, SessionGrantId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

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
        /// Event id of the accepted `ak.agent.key.authorize`. The request body
        /// carries the same event id, so the two surfaces stay comparable.
        agent_key_authorization_ref: EventId,
        verification_method: DidUrl,
    },
    RecoveryCandidateDevice {
        device_id: DeviceId,
    },
}

// Authorization state committed into a standard human-device grant.
//
// The Account Authority populates it from a Station-local revocation
// admission record, which is the only source of the origin-derived
// authorization Event and generation. That record deliberately carries no
// RealmCommit witness, so this binding names the authorization Event alone —
// it is not a `CommittedEventRef` and MUST NOT be taken from client input, a
// local cache or a private lookup.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/SessionGrantDeviceBinding.

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
        outcome: &AccountDeviceRevocationAdmissionAssessment,
        request: &AccountDeviceRevocationAdmissionInput,
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

    /// Exact origin-derived authorization Event retained in issuer-record metadata.
    pub const fn committed_authorization(&self) -> &EventId {
        &self.authorization_event_id
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
    let bytes = arkret_canonical::base64url_decode(value).map_err(|_| {
        WireError::Protocol(format!(
            "session public JWK {member} must be canonical unpadded Base64URL"
        ))
    })?;
    if arkret_canonical::base64url_encode(&bytes) != value {
        return Err(WireError::Protocol(format!(
            "session public JWK {member} has noncanonical encoding bits"
        )));
    }
    Ok(bytes)
}

/// Immutable non-secret issuer-record projection. Parsing does not authenticate its source.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "RawSessionGrantMetadata")]
pub struct SessionGrantMetadata {
    pub id: SessionGrantId,
    pub issuer_id: DidCoreId,
    pub account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub audience_id: DidCoreId,
    pub scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub session_id: String,
    pub session_public_key: CanonicalSessionPublicJwk,
    pub cnf_jkt: String,
    pub credential_class: SessionGrantCredentialClass,
    pub holder_binding: SessionGrantHolderBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_binding: Option<SessionGrantDeviceBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_kind: Option<SessionGrantProofKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_details: Option<SessionGrantScope>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSessionGrantMetadata {
    id: SessionGrantId,
    issuer_id: DidCoreId,
    account_id: AccountId,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    device_id: Option<DeviceId>,
    audience_id: DidCoreId,
    scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
    session_id: String,
    session_public_key: CanonicalSessionPublicJwk,
    cnf_jkt: String,
    credential_class: SessionGrantCredentialClass,
    holder_binding: SessionGrantHolderBinding,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    device_binding: Option<SessionGrantDeviceBinding>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    proof_kind: Option<SessionGrantProofKind>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    scope_details: Option<SessionGrantScope>,
}

impl TryFrom<RawSessionGrantMetadata> for SessionGrantMetadata {
    type Error = WireError;

    fn try_from(raw: RawSessionGrantMetadata) -> Result<Self> {
        let value = Self {
            id: raw.id,
            issuer_id: raw.issuer_id,
            account_id: raw.account_id,
            device_id: raw.device_id,
            audience_id: raw.audience_id,
            scopes: raw.scopes,
            not_before: raw.not_before,
            expires_at: raw.expires_at,
            session_id: raw.session_id,
            session_public_key: raw.session_public_key,
            cnf_jkt: raw.cnf_jkt,
            credential_class: raw.credential_class,
            holder_binding: raw.holder_binding,
            device_binding: raw.device_binding,
            proof_kind: raw.proof_kind,
            scope_details: raw.scope_details,
        };
        value.validate()?;
        Ok(value)
    }
}

impl SessionGrantMetadata {
    pub fn grant_ref(&self) -> arkret_wire::SessionGrantRef {
        arkret_wire::SessionGrantRef::new(self.issuer_id.clone(), self.id.clone())
    }

    /// Check local invariants only. The exact credential's authenticated issuer result is required.
    pub fn validate(&self) -> Result<()> {
        let invalid = |message: &str| WireError::Protocol(message.to_owned());
        if self.scopes.is_empty()
            || self.scopes.iter().any(|scope| scope.trim().is_empty())
            || self.scopes.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "session grant scopes must be nonempty, sorted and unique",
            ));
        }
        arkret_wire::validate_bounded_non_typed_identifier(&self.session_id, 256).map_err(
            |_| {
                invalid(
                    "session grant session_id must be a bounded independent non-typed coordinate",
                )
            },
        )?;
        if self.expires_at <= self.not_before {
            return Err(invalid("session grant expires_at must be after not_before"));
        }
        if self.session_public_key.thumbprint_sha256()? != self.cnf_jkt {
            return Err(invalid(
                "session grant cnf_jkt must match the exact session public key",
            ));
        }
        match (self.credential_class, &self.holder_binding) {
            (
                SessionGrantCredentialClass::Standard,
                SessionGrantHolderBinding::HumanDevice { device_binding },
            ) => {
                let accepted = self.device_binding.as_ref().ok_or_else(|| {
                    invalid("standard human grant requires accepted device_binding")
                })?;
                if self.device_id.as_ref() != Some(&accepted.device_id)
                    || accepted.device_id.as_str() != device_binding
                    || accepted.model_generation_ref == 0
                    || self.scope_details.is_some()
                    || self
                        .proof_kind
                        .is_some_and(|kind| kind != SessionGrantProofKind::AccountHandoff)
                {
                    return Err(invalid(
                        "human grant device, holder and accepted authorization bindings differ",
                    ));
                }
            }
            (
                SessionGrantCredentialClass::Standard,
                SessionGrantHolderBinding::AgentRuntime {
                    agent_id,
                    agent_key_authorization_ref,
                    ..
                },
            ) => {
                if self.device_id.is_some()
                    || self.device_binding.is_some()
                    || agent_id != &self.account_id.principal_id
                    || self
                        .proof_kind
                        .is_some_and(|kind| kind != SessionGrantProofKind::AgentKeyProof)
                {
                    return Err(invalid(
                        "Agent grant must bind its exact account and omit human device metadata",
                    ));
                }
                let scope = self
                    .scope_details
                    .as_ref()
                    .ok_or_else(|| invalid("Agent grant requires its immutable scope"))?;
                scope.validate()?;
                if &scope.agent_key_authorization_ref != agent_key_authorization_ref {
                    return Err(invalid("Agent scope and holder key authorization differ"));
                }
            }
            (
                SessionGrantCredentialClass::RecoverySession,
                SessionGrantHolderBinding::RecoveryCandidateDevice { device_id },
            ) => {
                if self.device_id.as_ref() != Some(device_id)
                    || self.device_binding.is_some()
                    || self.scope_details.is_some()
                    || self.expires_at - self.not_before > chrono::Duration::minutes(15)
                    || self
                        .proof_kind
                        .is_some_and(|kind| kind != SessionGrantProofKind::AccountHandoff)
                {
                    return Err(invalid(
                        "recovery grant requires a matching candidate, no accepted binding, and at most 15 minutes",
                    ));
                }
            }
            _ => {
                return Err(invalid(
                    "session grant credential_class and holder_binding are incompatible",
                ));
            }
        }
        Ok(())
    }

    /// Match a previously authenticated issuer projection to this exact request context.
    /// This method does not authenticate a transport, prove an exact secret, or refresh a cache.
    pub fn validate_request_binding(
        &self,
        grant_ref: &arkret_wire::SessionGrantRef,
        account_id: &AccountId,
        audience_id: &DidCoreId,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        if &self.grant_ref() != grant_ref
            || &self.account_id != account_id
            || &self.audience_id != audience_id
            || now < self.not_before
            || now >= self.expires_at
        {
            return Err(WireError::Protocol(
                "session grant issuer, account, audience or validity binding mismatch".into(),
            ));
        }
        Ok(())
    }

    pub fn human_device_authorization_selector(&self) -> Result<&SessionGrantDeviceBinding> {
        self.validate()?;
        match (&self.holder_binding, &self.device_binding) {
            (SessionGrantHolderBinding::HumanDevice { .. }, Some(binding)) => Ok(binding),
            _ => Err(WireError::Protocol(
                "accepted human device authorization is unavailable for this grant class".into(),
            )),
        }
    }
}

impl SessionGrantScope {
    pub fn validate(&self) -> Result<()> {
        let invalid = |message: &str| WireError::Protocol(message.to_owned());
        if self.resources.realm_ids != self.realm_ids
            || self.resources.strand_ids != self.strand_ids
            || !unique(&self.realm_ids)
            || !unique(&self.strand_ids)
            || !unique(&self.constraints.allowed_tracks)
            || !unique(&self.constraints.allowed_data_labels)
            || !unique(&self.constraints.allowed_endpoints)
        {
            return Err(invalid(
                "Agent scope contains duplicate or conflicting resource ceilings",
            ));
        }
        let label = |value: &str| {
            (1..=64).contains(&value.len())
                && value.as_bytes()[0].is_ascii_lowercase()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        };
        if self
            .constraints
            .allowed_tracks
            .iter()
            .chain(&self.constraints.allowed_data_labels)
            .any(|value| !label(value))
        {
            return Err(invalid(
                "Agent scope track or data label violates its canonical grammar",
            ));
        }
        if let Some(strands) = &self.constraints.allowed_strand_ids
            && (strands != &self.strand_ids || !unique(strands))
        {
            return Err(invalid(
                "Agent strand constraint differs from the resource ceiling",
            ));
        }
        if let Some(entries) = &self.participations {
            let mut scopes = std::collections::BTreeSet::new();
            for entry in entries {
                entry.validate().map_err(WireError::Protocol)?;
                if !scopes.insert(entry.target_scope.scope_key()) {
                    return Err(invalid("Agent scope has duplicate participation targets"));
                }
            }
        }
        Ok(())
    }
}

fn unique<T: Ord>(values: &[T]) -> bool {
    values
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == values.len()
}

impl SessionGrantResponseBody {
    pub fn grant_ref(&self) -> arkret_wire::SessionGrantRef {
        arkret_wire::SessionGrantRef::new(self.issuer_id.clone(), self.session_grant_id.clone())
    }

    /// Issuance response binding; caller must have authenticated its Account Authority channel.
    pub fn validate_binding(
        &self,
        issuer: &DidCoreId,
        account: &AccountId,
        audience: &DidCoreId,
        holder: &CanonicalSessionPublicJwk,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if &self.issuer_id != issuer
            || &self.account_id != account
            || &self.audience_id != audience
            || &self.session_public_key != holder
            || self.expires_at <= now
            || self.granted_scope.is_empty()
            || self
                .granted_scope
                .iter()
                .any(|scope| scope.trim().is_empty())
            || self.granted_scope.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(WireError::Protocol(
                "issued SessionGrant response binding mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Validate an authenticated refresh outcome against the client's original issuance result.
    /// The predecessor may now be expired or superseded during an exact replay; it is not reissued.
    pub fn validate_refresh_binding(&self, predecessor: &Self, now: DateTime<Utc>) -> Result<()> {
        self.validate_binding(
            &predecessor.issuer_id,
            &predecessor.account_id,
            &predecessor.audience_id,
            &predecessor.session_public_key,
            now,
        )?;
        if self.previous_session_grant_id.as_ref() != Some(&predecessor.session_grant_id)
            || self.session_grant_id == predecessor.session_grant_id
            || self.session_grant == predecessor.session_grant
            || self.device_id != predecessor.device_id
            || self.granted_scope != predecessor.granted_scope
        {
            return Err(WireError::Protocol(
                "refresh outcome changed its issuer chain, holder or scope ceiling".into(),
            ));
        }
        Ok(())
    }
}

include!("generated/session_credential_contracts.rs");

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        arkret_schema_conformance::spec_json_artifact(
            "fixtures/session-grant-issuance-fixture.json",
        )
        .unwrap()
    }

    fn vector(name: &str) -> Value {
        fixture()["accepted_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap()["metadata"]
            .clone()
    }

    fn metadata(name: &str) -> SessionGrantMetadata {
        serde_json::from_value(vector(name)).unwrap()
    }

    #[test]
    fn opaque_fixture_metadata_and_canonical_bytes_are_consumed_directly() {
        for row in fixture()["accepted_vectors"].as_array().unwrap() {
            let value: SessionGrantMetadata =
                serde_json::from_value(row["metadata"].clone()).unwrap();
            value.validate().unwrap();
            let canonical =
                String::from_utf8(arkret_canonical::canonical_json_bytes(&value).unwrap()).unwrap();
            assert_eq!(canonical, row["canonical_metadata_utf8"].as_str().unwrap());
            assert_eq!(
                serde_json::from_str::<SessionGrantMetadata>(&canonical).unwrap(),
                value
            );
        }
    }

    #[test]
    fn all_published_holder_class_and_null_negatives_remain_rejected() {
        for row in fixture()["credential_binding_negative_cases"]
            .as_array()
            .unwrap()
        {
            let mut value = vector(row["base_vector"].as_str().unwrap());
            for field in row
                .get("omit")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                value
                    .as_object_mut()
                    .unwrap()
                    .remove(field.as_str().unwrap());
            }
            for (field, replacement) in row
                .get("set")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                value[field] = replacement.clone();
            }
            assert!(
                serde_json::from_value::<SessionGrantMetadata>(value).is_err(),
                "{}",
                row["name"]
            );
        }
    }

    #[test]
    fn record_identity_is_issuer_scoped_and_not_a_metadata_hash() {
        let first = metadata("issuer_a_standard");
        let second = metadata("issuer_b_same_record_id");
        assert_eq!(first.id, second.id);
        assert_ne!(first.grant_ref(), second.grant_ref());
        assert!(
            first
                .validate_request_binding(
                    &second.grant_ref(),
                    &first.account_id,
                    &first.audience_id,
                    first.not_before
                )
                .is_err()
        );
        let mut changed = first.clone();
        changed.session_id = "another-independently-issued-chain".into();
        changed.validate().unwrap();
        assert_eq!(changed.id, first.id);
    }

    #[test]
    fn exact_request_binding_keeps_account_audience_and_expiry_boundaries() {
        let value = metadata("issuer_a_standard");
        value
            .validate_request_binding(
                &value.grant_ref(),
                &value.account_id,
                &value.audience_id,
                value.not_before,
            )
            .unwrap();
        for now in [
            value.not_before - chrono::Duration::milliseconds(1),
            value.expires_at,
        ] {
            assert!(
                value
                    .validate_request_binding(
                        &value.grant_ref(),
                        &value.account_id,
                        &value.audience_id,
                        now
                    )
                    .is_err()
            );
        }
        let mut account = value.account_id.clone();
        account.station_id = "ak:did_core:web:another.example".parse().unwrap();
        assert!(
            value
                .validate_request_binding(
                    &value.grant_ref(),
                    &account,
                    &value.audience_id,
                    value.not_before
                )
                .is_err()
        );
        assert!(
            value
                .validate_request_binding(
                    &value.grant_ref(),
                    &value.account_id,
                    &"ak:did_core:web:another.example".parse().unwrap(),
                    value.not_before
                )
                .is_err()
        );
    }

    #[test]
    fn metadata_rejects_retired_claim_fields_and_optional_nulls() {
        for field in ["jti", "issuance_nonce", "kind", "grant_jwt"] {
            let mut value = vector("issuer_a_standard");
            value[field] = Value::String("retired".into());
            assert!(serde_json::from_value::<SessionGrantMetadata>(value).is_err());
        }
        for field in ["device_id", "device_binding", "scope_details", "proof_kind"] {
            let mut value = vector("issuer_a_standard");
            value[field] = Value::Null;
            assert!(serde_json::from_value::<SessionGrantMetadata>(value).is_err());
        }
    }

    #[test]
    fn jwk_canonical_bits_and_thumbprint_are_real_not_placeholder_lengths() {
        let mut value = vector("issuer_a_standard");
        value["cnf_jkt"] = Value::String("A".repeat(43));
        assert!(serde_json::from_value::<SessionGrantMetadata>(value).is_err());
        let invalid = format!(
            r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
            "B".repeat(43)
        );
        assert!(CanonicalSessionPublicJwk::new(invalid).is_err());
        assert!(CanonicalSessionPublicJwk::new(r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","d":"secret"}"#).is_err());
        let wire = format!(
            " {}",
            metadata("issuer_a_standard").session_public_key.as_str()
        );
        assert!(serde_json::from_value::<CanonicalSessionPublicJwk>(Value::String(wire)).is_err());
    }

    #[test]
    fn recovery_lifetime_cannot_round_down_one_extra_millisecond() {
        let mut value = metadata("recovery_candidate");
        value.expires_at = value.not_before + chrono::Duration::minutes(15);
        value.validate().unwrap();
        value.expires_at += chrono::Duration::milliseconds(1);
        assert!(value.validate().is_err());
    }

    fn response(name: &str) -> SessionGrantResponseBody {
        let row = fixture()["accepted_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap()
            .clone();
        let metadata: SessionGrantMetadata =
            serde_json::from_value(row["metadata"].clone()).unwrap();
        SessionGrantResponseBody {
            account_id: metadata.account_id,
            issuer_id: metadata.issuer_id,
            device_id: metadata.device_id,
            audience_id: metadata.audience_id,
            session_grant: serde_json::from_value(row["session_grant"].clone()).unwrap(),
            session_grant_id: metadata.id,
            session_public_key: metadata.session_public_key,
            granted_scope: metadata.scopes,
            expires_at: metadata.expires_at,
            previous_session_grant_id: None,
        }
    }

    #[test]
    fn refresh_response_preserves_chain_and_cannot_expand_or_reuse_a_credential() {
        let mut previous = response("issuer_a_standard");
        let mut next = response("refresh_successor");
        next.previous_session_grant_id = Some(previous.session_grant_id.clone());
        let now = metadata("issuer_a_standard").not_before;
        previous.expires_at = now - chrono::Duration::seconds(1);
        next.validate_refresh_binding(&previous, now).unwrap();
        let mut reused = next.clone();
        reused.session_grant = previous.session_grant.clone();
        assert!(reused.validate_refresh_binding(&previous, now).is_err());
        let mut foreign = next.clone();
        foreign.issuer_id = "ak:did_core:web:another.example".parse().unwrap();
        assert!(foreign.validate_refresh_binding(&previous, now).is_err());
        let mut expanded = next;
        expanded
            .granted_scope
            .push("ak.self.future.read.expanded.v1".into());
        expanded.granted_scope.sort();
        assert!(expanded.validate_refresh_binding(&previous, now).is_err());
    }

    #[test]
    fn scope_is_typed_closed_unique_and_exactly_resource_bound() {
        let mut value = metadata("agent_runtime");
        let scope = value.scope_details.as_mut().unwrap();
        scope
            .resources
            .realm_ids
            .push(arkret_wire::RealmId::from_event_id(
                &scope.agent_key_authorization_ref,
            ));
        assert!(value.validate().is_err());
        let mut value = vector("agent_runtime");
        value["scope_details"]["unexpected"] = Value::Bool(true);
        assert!(serde_json::from_value::<SessionGrantMetadata>(value).is_err());
        let mut value = metadata("agent_runtime");
        value
            .scope_details
            .as_mut()
            .unwrap()
            .constraints
            .allowed_tracks = vec!["invalid-label".into()];
        assert!(value.validate().is_err());
    }
}
