//! Device-authorization, cross-signing, and identity-binding payloads.

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::internal_prelude::*;

pub const DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON: &str = "device_authorize_binding_one_of";

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizePayload {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub device_public_key: NonEmptyString,
    /// Device HPKE public key used for secret/key envelope sealing. Covered by
    /// `cross_signing_binding` (§5.2) or the enrollment-authority Event proof
    /// (§5.4); services MUST NOT substitute this value in projection.
    pub hpke_key: NonEmptyString,
    /// Canonical sorted (UTF-8 bytewise) unique algorithm ids supported by
    /// this device. Enters the device trust binding transcript together with
    /// `device_public_key` and `hpke_key`.
    pub algorithms: Vec<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key_algorithm: Option<NonEmptyString>,
    pub authorized_by: DeviceOrPrincipalRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<NonEmptyString>>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<SignatureMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignatureMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_signing_binding: Option<DeviceCrossSigningBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_authority_binding: Option<DeviceEnrollmentAuthorityBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_session_id: Option<RecoverySessionId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceAuthorizePayloadWire {
    principal_id: Did,
    device_id: DeviceId,
    device_public_key: NonEmptyString,
    hpke_key: NonEmptyString,
    algorithms: Vec<NonEmptyString>,
    #[serde(default)]
    device_key_algorithm: Option<NonEmptyString>,
    authorized_by: DeviceOrPrincipalRef,
    #[serde(default)]
    scopes: Option<Vec<NonEmptyString>>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    not_before: DateTime<Utc>,
    #[serde(default)]
    expires_at: Option<NullableTimestamp>,
    #[serde(default)]
    device_signature: Option<SignatureMaterial>,
    #[serde(default)]
    proof: Option<SignatureMaterial>,
    #[serde(default)]
    cross_signing_binding: Option<DeviceCrossSigningBinding>,
    #[serde(default)]
    enrollment_authority_binding: Option<DeviceEnrollmentAuthorityBinding>,
    #[serde(default)]
    recovery_session_id: Option<RecoverySessionId>,
}

impl<'de> Deserialize<'de> for DeviceAuthorizePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceAuthorizePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            principal_id: wire.principal_id,
            device_id: wire.device_id,
            device_public_key: wire.device_public_key,
            hpke_key: wire.hpke_key,
            algorithms: wire.algorithms,
            device_key_algorithm: wire.device_key_algorithm,
            authorized_by: wire.authorized_by,
            scopes: wire.scopes,
            not_before: wire.not_before,
            expires_at: wire.expires_at,
            device_signature: wire.device_signature,
            proof: wire.proof,
            cross_signing_binding: wire.cross_signing_binding,
            enrollment_authority_binding: wire.enrollment_authority_binding,
            recovery_session_id: wire.recovery_session_id,
        };
        payload
            .validate_wire_constraints()
            .map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl DeviceAuthorizePayload {
    /// Enforce the `device-lifecycle.md` §5.2 canonical-form MUST on
    /// `algorithms`: non-empty, UTF-8 bytewise ascending, no duplicates. The
    /// producer MUST write the same canonical array that enters the
    /// `ak-device-trust-bind-v1` signing input.
    pub fn validate_canonical_algorithms(&self) -> std::result::Result<(), &'static str> {
        if self.algorithms.is_empty() {
            return Err("device_authorize_algorithms_empty");
        }
        if self
            .algorithms
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err("device_authorize_algorithms_not_canonical");
        }
        Ok(())
    }

    pub fn authorization_binding_count(&self) -> usize {
        self.cross_signing_binding.is_some() as usize
            + self.enrollment_authority_binding.is_some() as usize
    }

    pub fn validate_authorization_binding_one_of(&self) -> std::result::Result<(), &'static str> {
        if self.authorization_binding_count() == 1 {
            Ok(())
        } else {
            Err(DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON)
        }
    }

    pub fn validate_wire_constraints(&self) -> std::result::Result<(), &'static str> {
        self.validate_authorization_binding_one_of()?;
        self.validate_canonical_algorithms()?;
        if self.device_signature.is_none()
            && self.proof.is_none()
            && self.enrollment_authority_binding.is_none()
        {
            return Err("device_authorize_signature_or_authority_required");
        }
        if let Some(scopes) = &self.scopes
            && (scopes.is_empty() || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len())
        {
            return Err("device_authorize_scopes_must_be_non_empty_and_unique");
        }
        Ok(())
    }

    /// Canonical signing input for
    /// `ak.device.authorize.payload.device_signature`.
    ///
    /// The signature proves possession of the private key corresponding to
    /// `device_public_key`; it is deliberately separate from the SSK-signed
    /// `cross_signing_binding`.
    pub fn device_possession_signature_input(&self) -> Result<Vec<u8>> {
        self.validate_authorization_binding_one_of()
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        self.validate_canonical_algorithms()
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        let device_key_algorithm = self.device_key_algorithm.as_deref().ok_or_else(|| {
            Error::Protocol("device_authorize_device_key_algorithm_required".to_owned())
        })?;
        if device_key_algorithm != "Ed25519" {
            return Err(Error::Protocol(
                "device_authorize_device_key_algorithm_unsupported".to_owned(),
            ));
        }
        let (authorization_binding_kind, cross_signing_generation) =
            if let Some(binding) = &self.cross_signing_binding {
                ("cross_signing", Some(binding.ssk_generation))
            } else if self.enrollment_authority_binding.is_some() {
                ("enrollment_authority", None)
            } else {
                return Err(Error::Protocol(
                    DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON.to_owned(),
                ));
            };
        let authorized_by = match &self.authorized_by {
            DeviceOrPrincipalRef::DeviceId(device_id) => device_id.as_str(),
            DeviceOrPrincipalRef::Did(did) => did.as_str(),
        };
        let mut scopes = self.scopes.clone();
        if let Some(scopes) = &mut scopes {
            scopes.sort_unstable();
            scopes.dedup();
        }
        let expires_at = self.expires_at.as_ref().and_then(|value| value.as_ref());
        let recovery_session_id = self.recovery_session_id.as_ref().map(|id| id.as_str());
        let body = serde_json::json!({
            "principal_id": self.principal_id.as_str(),
            "device_id": self.device_id.as_str(),
            "device_public_key": self.device_public_key.as_str(),
            "hpke_key": self.hpke_key.as_str(),
            "algorithms": &self.algorithms,
            "device_key_algorithm": device_key_algorithm,
            "authorized_by": authorized_by,
            "not_before": self.not_before,
            "expires_at": expires_at,
            "scopes": scopes,
            "recovery_session_id": recovery_session_id,
            "authorization_binding_kind": authorization_binding_kind,
            "cross_signing_generation": cross_signing_generation,
        });
        let mut out = binding_contexts::DEVICE_AUTHORIZE_POSSESSION_PREFIX.to_vec();
        out.extend_from_slice(&canonical::canonical_json_bytes(&body)?);
        Ok(out)
    }

    /// Validate the provenance anchor for a `service_attested`
    /// `ak.device.authorize` payload.
    ///
    /// The payload binding is not authority by itself: the accepted Event
    /// envelope must name the same service DID as `executed_by`, carry the same
    /// `authorization_ref`, and point at the DID-document delegation used for
    /// the enrollment authority signature.
    pub fn validate_service_attested_provenance(
        &self,
        executed_by: Option<&Did>,
        authorization_ref: Option<&str>,
        accepted_at: DateTime<Utc>,
    ) -> Result<()> {
        self.validate_authorization_binding_one_of()
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        let binding = self.enrollment_authority_binding.as_ref().ok_or_else(|| {
            Error::Protocol(
                "service_attested device authorize requires enrollment_authority_binding"
                    .to_owned(),
            )
        })?;
        binding.validate_against_event_anchor(executed_by, authorization_ref, accepted_at)
    }
}

/// Canonical digest of an `ak.device.authorize` payload as it appears on the
/// wire.
///
/// This is the value a B-model re-anchor commits to through
/// [`DeviceReanchorPayload::replacement_authorize_payload_digest`]. The
/// re-anchor cannot commit to the authorize Event id or envelope digest because
/// that Event's `prev_refs` names the re-anchor, and every `event_id` derives
/// from its own signed content — the two would be preimages of each other.
/// Committing to the payload keeps the binding one-directional while still
/// fixing which device is authorized.
///
/// It takes the wire `payload` object rather than [`DeviceAuthorizePayload`] on
/// purpose: the producer and the verifier must hash the same bytes, and a
/// parse-then-reserialize round trip is one normalization away from disagreeing.
pub fn device_authorize_replacement_payload_digest(
    payload: &Value,
    digest_suite: canonical::DigestSuite,
) -> Result<Hash> {
    let bytes = canonical::canonical_json_bytes(payload)?;
    Ok(Hash::new(canonical::digest(digest_suite, &bytes))?)
}

/// Closed B-model recovery payload for `ak.device.reanchor`.
///
/// The replacement binding commits to the authorize payload digest, never to
/// that Event's id or envelope digest: the authorize envelope carries this
/// Event's `event_id` in `prev_refs`, and every `event_id` is a function of its
/// own signed content, so an id or envelope binding would make the two Events
/// preimages of each other. See `key-management.md` §5.0.7.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReanchorPayload {
    pub principal_id: Did,
    pub did_version_id: NonEmptyString,
    pub previous_device_generation: NonEmptyString,
    pub new_device_generation: NonEmptyString,
    pub pre_fence_basis: Option<DeviceReanchorPreFenceBasis>,
    pub replacement_authorize_payload_digest: Hash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceReanchorPayloadWire {
    principal_id: Did,
    did_version_id: NonEmptyString,
    previous_device_generation: NonEmptyString,
    new_device_generation: NonEmptyString,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pre_fence_basis: Option<DeviceReanchorPreFenceBasis>,
    replacement_authorize_payload_digest: Hash,
}

fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl<'de> Deserialize<'de> for DeviceReanchorPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceReanchorPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            principal_id: wire.principal_id,
            did_version_id: wire.did_version_id,
            previous_device_generation: wire.previous_device_generation,
            new_device_generation: wire.new_device_generation,
            pre_fence_basis: wire.pre_fence_basis,
            replacement_authorize_payload_digest: wire.replacement_authorize_payload_digest,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl DeviceReanchorPayload {
    pub const SCHEMA: &'static str = SchemaId::DEVICE_REANCHOR_V1;
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        parse_did_webvh_version_id(self.did_version_id.as_str())?;
        parse_did_webvh_version_id(self.previous_device_generation.as_str())?;
        parse_did_webvh_version_id(self.new_device_generation.as_str())?;
        if self.new_device_generation != self.did_version_id {
            return Err("device reanchor new_device_generation must equal did_version_id");
        }
        if let Some(basis) = &self.pre_fence_basis
            && basis.validate_protocol_bounds().is_err()
        {
            return Err(
                "device reanchor pre_fence_basis leaves must be non-empty, unique, canonically \
                 ordered and at most 64",
            );
        }
        Ok(())
    }

    pub fn did_version_number(&self) -> u64 {
        parse_did_webvh_version_id(self.did_version_id.as_str())
            .expect("validated DeviceReanchorPayload has a valid did_version_id")
    }
}

/// Validate the special first Seal after a B-model recovery re-anchor when the
/// accepted pre-fence basis is explicitly null. Generic Seal validation still
/// applies; this helper requires the business delta to cover the re-anchor and
/// its replacement device authorization while permitting other pending Control
/// Moves admitted by the contextual Seal rules.
///
/// Both envelope digests are caller-supplied: the re-anchor payload binds the
/// replacement by payload digest, so the authorize envelope digest exists only
/// once both Events are formed.
pub fn validate_device_reanchor_recovery_first_seal(
    payload: &DeviceReanchorPayload,
    predecessor_refs: &[SealId],
    delta: &[Hash],
    reanchor_digest: &Hash,
    replacement_authorize_digest: &Hash,
) -> Result<()> {
    if payload.pre_fence_basis.is_some() {
        return Err(Error::Protocol(
            "device reanchor recovery-first Seal requires pre_fence_basis=null".to_owned(),
        ));
    }
    if !predecessor_refs.is_empty() {
        return Err(Error::Protocol(
            "device reanchor recovery-first Seal must have predecessor_refs=[]".to_owned(),
        ));
    }
    if delta
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(Error::Protocol(
            "device reanchor recovery-first Seal delta must be canonical sorted and duplicate-free"
                .to_owned(),
        ));
    }
    if !delta
        .iter()
        .any(|digest| digest.as_str() == reanchor_digest.as_str())
        || !delta
            .iter()
            .any(|digest| digest.as_str() == replacement_authorize_digest.as_str())
    {
        return Err(Error::Protocol(
            "device reanchor recovery-first Seal delta must cover reanchor and replacement authorize"
                .to_owned(),
        ));
    }
    Ok(())
}

fn parse_did_webvh_version_id(value: &str) -> std::result::Result<u64, &'static str> {
    let (number_text, digest) = value
        .split_once('-')
        .ok_or("did:webvh versionId must be <positive-number>-<digest>")?;
    if digest.is_empty() || digest.chars().any(char::is_whitespace) {
        return Err("did:webvh versionId digest must be non-empty and contain no whitespace");
    }
    let number = number_text
        .parse::<u64>()
        .map_err(|_| "did:webvh versionId number is invalid")?;
    if number == 0 || number_text.starts_with('0') {
        return Err("did:webvh versionId number must be positive without leading zeros");
    }
    Ok(number)
}

use arkret_models_identity::artifacts_device_identity::DeviceEnrollmentAuthorityBinding;
use arkret_wire::SchemaId;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_cross_signing_binding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCrossSigningBinding {
    pub verification_method: DidUrl,
    pub signature_algorithm: NonEmptyString,
    pub ssk_generation: NonZeroU64,
    pub signature: Base64UrlString,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_list_update_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceListUpdatePayload {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<DeviceId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<Vec<DeviceId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_list_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceListUpdatePayloadWire {
    principal_id: Did,
    #[serde(default)]
    changed: Option<Vec<DeviceId>>,
    #[serde(default)]
    left: Option<Vec<DeviceId>>,
    #[serde(default)]
    device_list_digest: Option<Hash>,
    #[serde(default)]
    stream_id: Option<NonEmptyString>,
    #[serde(default)]
    #[serde(
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    updated_at: Option<DateTime<Utc>>,
}

impl<'de> Deserialize<'de> for DeviceListUpdatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceListUpdatePayloadWire::deserialize(deserializer)?;
        if wire.changed.is_none() && wire.left.is_none() && wire.device_list_digest.is_none() {
            return Err(serde::de::Error::custom(
                "device list update requires changed, left, or device_list_digest",
            ));
        }
        for (name, devices) in [("changed", &wire.changed), ("left", &wire.left)] {
            if let Some(devices) = devices
                && (devices.is_empty()
                    || devices.iter().collect::<BTreeSet<_>>().len() != devices.len())
            {
                return Err(serde::de::Error::custom(format!(
                    "device list update {name} must be non-empty and unique"
                )));
            }
        }
        Ok(Self {
            principal_id: wire.principal_id,
            changed: wire.changed,
            left: wire.left,
            device_list_digest: wire.device_list_digest,
            stream_id: wire.stream_id,
            updated_at: wire.updated_at,
        })
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_or_principal_ref`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceOrPrincipalRef {
    DeviceId(DeviceId),
    Did(Did),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokePayload {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub revoked_by: DeviceOrPrincipalRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    pub reason: DeviceRevocationReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignatureMaterial>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DeviceRevocationReason(String);

impl DeviceRevocationReason {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, &'static str> {
        let value = value.into();
        let mut characters = value.chars();
        let Some(first) = characters.next() else {
            return Err("device revocation reason must not be empty");
        };
        if value.len() > 64
            || !first.is_ascii_lowercase()
            || !characters.all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
        {
            return Err("device revocation reason must match ^[a-z][a-z0-9_]{0,63}$");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceRevocationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DeviceRevocationReason {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The binding does not enforce uniqueness: at most one Direct Conversation Realm can exist per
/// pair because only the derived founder may author the founding unit. This payload is the
/// participant-visible endorsement of coordinates and of the first exact-pair MLS generation.
///
/// It carries no `binding_state`, no `supersedes_binding_ref` and no permanent `mls_group_id`: the
/// binding is written once and never retired, and participant authority always reads the *current*
/// active MLS generation rather than the founding group.
pub struct DirectConversationBoundPayload {
    pub pair_key: Hash,
    pub participants_unordered: Vec<Did>,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
    pub authorization_basis: DirectConversationAuthorizationBasis,
    /// `generation 1` activation Event: the first exact-pair active MLS generation.
    pub initial_exact_pair_generation_ref: EventId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl DirectConversationBoundPayload {
    pub fn validate_pair_key(&self, trust_domain: TypedTrustDomainId) -> Result<()> {
        self.authorization_basis.validate_shape()?;
        let [left, right]: [Did; 2] =
            self.participants_unordered
                .clone()
                .try_into()
                .map_err(|_| {
                    Error::Protocol("direct conversation requires two participants".to_owned())
                })?;
        let expected = direct_conversation_pair_key(
            trust_domain,
            DirectConversationPairKeyParticipant::unmapped(left),
            DirectConversationPairKeyParticipant::unmapped(right),
        )?;
        if self.pair_key != expected {
            return Err(Error::Protocol(
                "direct conversation pair_key mismatch (schema_violation)".to_owned(),
            ));
        }
        Ok(())
    }

    /// Receiver-derived semantic digest from
    /// `contact-and-direct-conversation.md` §8.3.
    ///
    /// The digest is not a wire field. It normalizes the two unordered sets,
    /// excludes `created_at` and Event envelope context, then hashes the
    /// closed binding object under the registered v1 domain separator.
    pub fn binding_digest(&self) -> Result<Hash> {
        self.authorization_basis.validate_shape()?;
        if self.participants_unordered.len() != 2 {
            return Err(Error::Protocol(
                "direct conversation requires two participants".to_owned(),
            ));
        }

        let mut participants = self
            .participants_unordered
            .iter()
            .map(Did::as_str)
            .collect::<Vec<_>>();
        participants.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut event_refs = self
            .authorization_basis
            .event_refs
            .iter()
            .map(EventId::as_str)
            .collect::<Vec<_>>();
        event_refs.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

        let binding_object = serde_json::json!({
            "pair_key": self.pair_key.as_str(),
            "participants_unordered": participants,
            "realm_id": self.realm_id.as_str(),
            "main_strand_id": self.main_strand_id.as_str(),
            "founding_unit_digest": self.founding_unit_digest.as_str(),
            "authorization_basis": {
                "kind": self.authorization_basis.kind,
                "event_refs": event_refs,
            },
            "initial_exact_pair_generation_ref": self.initial_exact_pair_generation_ref.as_str(),
        });
        let canonical = arkret_canonical::canonical_json_bytes(&binding_object)?;
        let mut preimage = b"ak.direct-conversation.binding-digest.v1\n".to_vec();
        preimage.extend_from_slice(&canonical);
        Ok(Hash::new(arkret_canonical::sha256_digest(&preimage))?)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::artifacts_device_identity::DeviceEnrollmentAuthorityBindingKind;
    use serde_json::json;

    use super::*;

    fn device_authorize_value() -> Value {
        json!({
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "device_public_key": "z6MkDeviceKey",
            "hpke_key": "z6LSHpkeKey",
            "algorithms": [
                "ak.hpke_x25519_aead_chacha20poly1305.v1",
                "ak.mls.v1"
            ],
            "device_signature": "c2ln",
            "authorized_by": "did:webvh:z6mkfixture:alice.example",
            "not_before": "2026-05-30T00:00:00.000Z",
            "enrollment_authority_binding": {
                "kind": "service_attested",
                "authority_did": "did:webvh:z6mkauthority:auth.example",
                "authorization_ref": "did:webvh:z6mkfixture:alice.example#enrollment-authority"
            }
        })
    }

    fn base_device_authorize_payload() -> DeviceAuthorizePayload {
        DeviceAuthorizePayload {
            principal_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-a11ce0000001").unwrap(),
            device_public_key: NonEmptyString::new("z6MkDeviceKey").unwrap(),
            hpke_key: NonEmptyString::new("z6LSHpkeKey").unwrap(),
            algorithms: vec![
                NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
                NonEmptyString::new("ak.mls.v1").unwrap(),
            ],
            device_key_algorithm: None,
            authorized_by: DeviceOrPrincipalRef::Did(
                Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            ),
            scopes: None,
            not_before: "2026-05-30T00:00:00.000Z".parse().unwrap(),
            expires_at: None,
            device_signature: None,
            proof: None,
            cross_signing_binding: None,
            enrollment_authority_binding: None,
            recovery_session_id: None,
        }
    }

    fn cross_signing_binding() -> DeviceCrossSigningBinding {
        DeviceCrossSigningBinding {
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#ssk").unwrap(),
            signature_algorithm: NonEmptyString::new("Ed25519").unwrap(),
            ssk_generation: NonZeroU64::new(1).unwrap(),
            signature: Base64UrlString::new("c2ln").unwrap(),
        }
    }

    #[test]
    fn device_authorize_requires_exactly_one_authorization_binding() {
        let mut payload = base_device_authorize_payload();
        assert_eq!(
            payload.validate_authorization_binding_one_of(),
            Err(DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON)
        );

        payload.cross_signing_binding = Some(cross_signing_binding());
        assert!(payload.validate_authorization_binding_one_of().is_ok());

        payload.enrollment_authority_binding = Some(DeviceEnrollmentAuthorityBinding {
            kind: DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
            authority_did: Did::new("did:webvh:z6mkauthority:auth.example").unwrap(),
            authorization_ref: NonEmptyString::new(
                "did:webvh:z6mkfixture:alice.example#enrollment-authority",
            )
            .unwrap(),
        });
        assert_eq!(
            payload.validate_authorization_binding_one_of(),
            Err(DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON)
        );

        payload.cross_signing_binding = None;
        assert!(payload.validate_authorization_binding_one_of().is_ok());
    }

    #[test]
    fn device_authorize_possession_input_binds_device_and_recovery_context() {
        let mut payload = base_device_authorize_payload();
        payload.device_key_algorithm = Some(NonEmptyString::new("Ed25519").unwrap());
        payload.cross_signing_binding = Some(cross_signing_binding());
        payload.scopes = Some(vec![
            NonEmptyString::new("write").unwrap(),
            NonEmptyString::new("read").unwrap(),
            NonEmptyString::new("read").unwrap(),
        ]);
        payload.recovery_session_id = Some(
            RecoverySessionId::new("ak:recovery_session:01904100-0000-7000-8000-000000000042")
                .unwrap(),
        );

        let input = String::from_utf8(payload.device_possession_signature_input().unwrap())
            .expect("canonical input is utf8");

        assert!(
            input
                .as_bytes()
                .starts_with(binding_contexts::DEVICE_AUTHORIZE_POSSESSION_PREFIX)
        );
        assert!(input.contains("\"authorization_binding_kind\":\"cross_signing\""));
        assert!(input.contains("\"cross_signing_generation\":1"));
        assert!(input.contains(
            "\"recovery_session_id\":\"ak:recovery_session:01904100-0000-7000-8000-000000000042\""
        ));
        assert!(input.contains("\"scopes\":[\"read\",\"write\"]"));
    }

    #[test]
    fn device_authorize_possession_input_requires_declared_device_alg() {
        let mut payload = base_device_authorize_payload();
        payload.cross_signing_binding = Some(cross_signing_binding());

        assert!(matches!(
            payload.device_possession_signature_input(),
            Err(Error::Protocol(reason))
                if reason == "device_authorize_device_key_algorithm_required"
        ));
    }

    #[test]
    fn device_authorize_deserialization_enforces_conditionals_and_canonical_lists() {
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(device_authorize_value()).is_ok());

        let mut missing_proof = device_authorize_value();
        missing_proof
            .as_object_mut()
            .unwrap()
            .remove("device_signature");
        missing_proof
            .as_object_mut()
            .unwrap()
            .remove("enrollment_authority_binding");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(missing_proof).is_err());

        let mut conflicting_binding = device_authorize_value();
        conflicting_binding["cross_signing_binding"] = json!({
            "verification_method": "did:webvh:z6mkfixture:alice.example#ssk",
            "signature_algorithm": "Ed25519",
            "ssk_generation": 1,
            "signature": "c2ln"
        });
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(conflicting_binding).is_err());

        let mut unsorted_algorithms = device_authorize_value();
        unsorted_algorithms["algorithms"] = json!(["ak.mls.v1", "ak.hpke.v1"]);
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(unsorted_algorithms).is_err());

        let mut duplicate_scopes = device_authorize_value();
        duplicate_scopes["scopes"] = json!(["read", "read"]);
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(duplicate_scopes).is_err());
    }

    #[test]
    fn device_authorize_rejects_wrong_consts_and_scalar_shapes() {
        let mut empty_key = device_authorize_value();
        empty_key["device_public_key"] = json!("");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(empty_key).is_err());

        let mut invalid_device = device_authorize_value();
        invalid_device["device_id"] = json!("device-1");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(invalid_device).is_err());
    }

    #[test]
    fn device_authorize_accepts_service_attested_did_key_authority() {
        let payload = json!({
            "principal_id": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
            "device_id": "ak:device:019eefcb-5882-7861-bc30-3033fa32dcf6",
            "device_public_key": "z6MkjHNtpwuhc2QSXzkf4DWoWp7eSMKB9PzfdnvaLB7kb3dG",
            "hpke_key": "z6LSgy7T8CEsMDMzk1e4EBFVX8CDXWWzvkFZWSXhsC97zjcM",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
            "not_before": "2026-06-22T14:45:51.000Z",
            "enrollment_authority_binding": {
                "kind": "service_attested",
                "authority_did": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
                "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
            }
        });
        let payload: DeviceAuthorizePayload = serde_json::from_value(payload).unwrap();
        assert!(payload.validate_authorization_binding_one_of().is_ok());
        assert!(
            payload
                .validate_service_attested_provenance(
                    Some(&Did::new(
                        "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw".to_owned()
                    )
                    .unwrap()),
                    Some("did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"),
                    "2026-06-22T14:45:52.000Z".parse().unwrap(),
                )
                .is_ok()
        );
    }

    #[test]
    fn service_attested_rejects_legacy_version_time_alias() {
        let binding = serde_json::from_value::<DeviceEnrollmentAuthorityBinding>(json!({
            "kind": "service_attested",
            "authority_did": "did:webvh:z6mkfixture:authority.example",
            "versionTime": "2026-06-22T14:45:51.000Z",
            "authorization_ref": "did:webvh:z6mkfixture:alice.example#enrollment-authority"
        }));
        assert!(binding.is_err());
    }

    #[test]
    fn device_or_principal_ref_rejects_unknown_string() {
        assert!(
            serde_json::from_value::<DeviceOrPrincipalRef>(json!("neither-a-device-id-nor-a-did"))
                .is_err()
        );
    }

    #[test]
    fn device_or_principal_ref_accepts_device_id_and_did_key() {
        serde_json::from_value::<DeviceOrPrincipalRef>(json!(
            "ak:device:01904100-0000-7000-8000-000000000001"
        ))
        .unwrap();
        serde_json::from_value::<DeviceOrPrincipalRef>(json!(
            "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw"
        ))
        .unwrap();
    }

    #[test]
    fn device_list_update_enforces_any_of_and_set_constraints() {
        let principal_id = "did:webvh:z6mkfixture:alice.example";
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id,
                "changed": []
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id,
                "left": [
                    "ak:device:01904100-0000-7000-8000-000000000001",
                    "ak:device:01904100-0000-7000-8000-000000000001"
                ]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id,
                "device_list_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }))
            .is_ok()
        );
    }

    #[test]
    fn device_revocation_reason_enforces_schema_slug() {
        assert!(DeviceRevocationReason::new("device_lost").is_ok());
        assert!(DeviceRevocationReason::new("").is_err());
        assert!(DeviceRevocationReason::new("DeviceLost").is_err());
        assert!(DeviceRevocationReason::new("device-lost").is_err());
        assert!(DeviceRevocationReason::new(format!("a{}", "b".repeat(64))).is_err());
    }

    #[test]
    fn device_reanchor_enforces_version_shape_generation_equality_and_basis() {
        let valid = json!({
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "did_version_id": "2-QmCurrent",
            "previous_device_generation": "1-QmPrevious",
            "new_device_generation": "2-QmCurrent",
            "pre_fence_basis": null,
            "replacement_authorize_payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        let payload: DeviceReanchorPayload = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(payload.did_version_number(), 2);
        let reanchor_digest = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let authorize_digest = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        let delta = vec![
            Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            Hash::new(reanchor_digest.as_str().to_owned()).unwrap(),
            Hash::new(authorize_digest.as_str().to_owned()).unwrap(),
        ];
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[],
                &delta,
                &reanchor_digest,
                &authorize_digest
            )
            .is_ok()
        );
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[SealId::new(format!("ak:seal:sha256:{}", "2".repeat(64))).unwrap()],
                &delta,
                &reanchor_digest,
                &authorize_digest
            )
            .is_err()
        );
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[],
                &delta[..2],
                &reanchor_digest,
                &authorize_digest
            )
            .is_err()
        );
        let missing_reanchor = vec![delta[0].clone(), delta[2].clone()];
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[],
                &missing_reanchor,
                &reanchor_digest,
                &authorize_digest
            )
            .is_err()
        );
        let duplicate = vec![delta[1].clone(), delta[1].clone(), delta[2].clone()];
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[],
                &duplicate,
                &reanchor_digest,
                &authorize_digest
            )
            .is_err()
        );

        let mut carries_event_id = valid.clone();
        carries_event_id["replacement_authorize_event_id"] =
            json!("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19");
        assert!(serde_json::from_value::<DeviceReanchorPayload>(carries_event_id).is_err());

        let mut missing_required_nullable = valid.clone();
        missing_required_nullable
            .as_object_mut()
            .unwrap()
            .remove("pre_fence_basis");
        assert!(
            serde_json::from_value::<DeviceReanchorPayload>(missing_required_nullable).is_err()
        );

        let mut mismatched = valid.clone();
        mismatched["new_device_generation"] = json!("3-QmOther");
        assert!(serde_json::from_value::<DeviceReanchorPayload>(mismatched).is_err());

        let mut leading_zero = valid;
        leading_zero["did_version_id"] = json!("02-QmCurrent");
        assert!(serde_json::from_value::<DeviceReanchorPayload>(leading_zero).is_err());
    }

    /// The non-null `pre_fence_basis` branch.
    ///
    /// It went unexercised long enough for the type to lose both roots: every
    /// fixture in this repo and in `arkret-spec` used `pre_fence_basis: null`,
    /// which is the shape a brand-new principal with no accepted Seal produces,
    /// so nothing ever round-tripped the only shape that carries them.
    #[test]
    fn device_reanchor_pre_fence_basis_round_trips_both_frontier_roots() {
        let wire = json!({
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "did_version_id": "2-QmCurrent",
            "previous_device_generation": "1-QmPrevious",
            "new_device_generation": "2-QmCurrent",
            "pre_fence_basis": {
                "leaves": [
                    format!("ak:seal:sha256:{}", "a".repeat(64)),
                    format!("ak:seal:sha256:{}", "b".repeat(64)),
                ],
                "control_event_set_root": format!("sha256:{}", "c".repeat(64)),
                "state_root": format!("sha256:{}", "d".repeat(64)),
            },
            "replacement_authorize_payload_digest": format!("sha256:{}", "e".repeat(64))
        });
        let payload: DeviceReanchorPayload = serde_json::from_value(wire.clone()).unwrap();
        let basis = payload.pre_fence_basis.as_ref().unwrap();
        assert_eq!(basis.leaves.len(), 2);
        assert_eq!(
            basis.control_event_set_root.as_str(),
            format!("sha256:{}", "c".repeat(64))
        );
        assert_eq!(
            basis.state_root.as_str(),
            format!("sha256:{}", "d".repeat(64))
        );
        assert_eq!(serde_json::to_value(&payload).unwrap(), wire);

        // Both roots are required, not optional decoration.
        for dropped in ["control_event_set_root", "state_root"] {
            let mut missing = wire.clone();
            missing["pre_fence_basis"]
                .as_object_mut()
                .unwrap()
                .remove(dropped);
            assert!(
                serde_json::from_value::<DeviceReanchorPayload>(missing).is_err(),
                "pre_fence_basis must reject a frontier missing {dropped}"
            );
        }

        // Leaf bounds still come from the one SealBasis implementation.
        let mut unsorted = wire;
        unsorted["pre_fence_basis"]["leaves"] = json!([
            format!("ak:seal:sha256:{}", "b".repeat(64)),
            format!("ak:seal:sha256:{}", "a".repeat(64)),
        ]);
        assert!(serde_json::from_value::<DeviceReanchorPayload>(unsorted).is_err());
    }

    #[test]
    fn direct_conversation_binding_digest_matches_registered_kat_and_normalizes_sets() {
        let payload = json!({
            "pair_key": "sha256:e8c24c1badc48eefa472a1700e87a6597a95aedfab8cbe3173f1622b9ad427b5",
            "participants_unordered": [
                "did:webvh:z6mkfixture:bob.example",
                "did:webvh:z6mkfixture:alice.example"
            ],
            "realm_id": "ak:realm:AVYxXzYx_KzaGx7X62doksaQR0ISkneyOwwF1k6ExHKy",
            "main_strand_id": "ak:strand:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo",
            "founding_unit_digest": format!("sha256:{}", "b".repeat(64)),
            "authorization_basis": {
                "kind": "accepted_contact",
                "event_refs": [
                    "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
                    "ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N"
                ]
            },
            "initial_exact_pair_generation_ref": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "created_at": "2026-08-07T12:34:56.000Z"
        });
        let mut parsed: DirectConversationBoundPayload = serde_json::from_value(payload).unwrap();
        let expected = "sha256:bda6045ed2af5f51dc19296b3c1f906f415a329c9d65c3da40b1d063b68773a8";
        assert_eq!(parsed.binding_digest().unwrap().as_str(), expected);

        parsed.participants_unordered.reverse();
        parsed.authorization_basis.event_refs.reverse();
        parsed.created_at = DateTime::parse_from_rfc3339("2027-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed.binding_digest().unwrap().as_str(), expected);
    }
}
