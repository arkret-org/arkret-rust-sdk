//! Arkret Seal typed model.
//!
//! A Seal is the notary-signed commitment for control-plane finality.
//! `delta[]` contains only the control-plane `event_digest` values newly
//! accepted by this Seal. Cumulative coverage is derived recursively from
//! `predecessor_ref`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{
    AuthorizationDependencyKind, CanonicalCellState, CapabilityActionId, CellRef, DidUrl, EventId,
    Hash, Hlc, NotarySignerDescriptor, RealmId, ReasonCode, Result, ScopeRef, SealId, WireError,
    canonical,
};

pub const MAX_SEAL_DELTA: usize = 4_096;
pub const MAX_SEAL_AVAILABILITY_RECEIPT_DIGESTS: usize = 65_536;
pub const MAX_SEAL_COVERED_EVENT_DIGESTS: usize = 1_048_576;

pub fn seal_canonical_bytes(seal: &Seal) -> Result<Vec<u8>> {
    seal.canonical_bytes_for_id()
}

pub fn compute_seal_id(
    canonical_bytes: &[u8],
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<SealId> {
    Seal::id_from_canonical_bytes(canonical_bytes, digest_suite)
}

/// Detached signature over the canonical bytes of a non-Event protocol object.
///
/// Seal is not an Event Envelope, so its signature uses the generic
/// `payload_digest` member rather than the Event-only `event_digest`
/// (`seal.schema.json#/$defs/signature`).
///
/// This is the single Rust implementation of
/// `seal.schema.json#/$defs/signature`; a second, incompatible copy used to
/// live in `arkret_models_collaboration::governance::agent_artifacts::Signature`
/// and was removed so the `$defs` cannot deserialize two different ways.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSignature {
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

/// Closed signature shape used only by a Seal.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealSignature {
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    pub jws: String,
}

impl From<PayloadSignature> for SealSignature {
    fn from(signature: PayloadSignature) -> Self {
        Self {
            verification_method: signature.verification_method,
            payload_digest: signature.payload_digest,
            jws: signature.jws,
        }
    }
}

impl SealSignature {
    pub fn validate_structural(&self) -> Result<()> {
        validate_seal_signature(self)
    }

    pub fn validate_descriptor_binding(&self, descriptor: &NotarySignerDescriptor) -> Result<()> {
        descriptor.validate()?;
        if self.verification_method != descriptor.verification_method {
            return Err(WireError::Protocol(
                "Seal signature verification_method does not match frozen descriptor".to_owned(),
            ));
        }
        let mut segments = self.jws.split('.');
        let protected_b64u = segments.next().unwrap_or_default();
        let payload = segments.next().unwrap_or_default();
        let signature_b64u = segments.next().unwrap_or_default();
        if segments.next().is_some() || !payload.is_empty() {
            return Err(WireError::Protocol(
                "Seal signature must use compact detached JWS".to_owned(),
            ));
        }
        let protected = crate::base64url::base64url_decode(protected_b64u)
            .map_err(|error| WireError::Protocol(format!("invalid Seal JWS header: {error}")))?;
        if crate::base64url::base64url_encode(&protected) != protected_b64u {
            return Err(WireError::Protocol(
                "Seal JWS protected header is not canonical base64url".to_owned(),
            ));
        }
        let header: Value = serde_json::from_slice(&protected)?;
        if canonical::canonical_json_bytes(&header)? != protected {
            return Err(WireError::Protocol(
                "Seal JWS protected header is not canonical JSON".to_owned(),
            ));
        }
        let Some(header) = header.as_object() else {
            return Err(WireError::Protocol(
                "Seal JWS protected header must be an object".to_owned(),
            ));
        };
        if header.get("alg").and_then(Value::as_str) != Some(descriptor.jose_algorithm.as_str())
            || header.get("kid").and_then(Value::as_str)
                != Some(descriptor.verification_method.as_str())
            || header.contains_key("crit")
        {
            return Err(WireError::Protocol(
                "Seal JWS protected header does not match frozen descriptor".to_owned(),
            ));
        }
        let signature = crate::base64url::base64url_decode(signature_b64u)
            .map_err(|error| WireError::Protocol(format!("invalid Seal JWS signature: {error}")))?;
        if signature.len() != 64 || crate::base64url::base64url_encode(&signature) != signature_b64u
        {
            return Err(WireError::Protocol(
                "Seal JWS signature is not a canonical 64-byte encoding".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Deterministic outcome of one registered atomic security command unit.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealCommandOutcome {
    pub event_digest: Hash,
    pub outcome: CommandOutcome,
    pub result_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
    pub unit_event_digests: Vec<Hash>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutcome {
    Committed,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandResultEffect {
    pub cell_id: CellRef,
    pub state: CanonicalCellState,
}

#[derive(Serialize)]
struct CommandResultDigestInput<'a> {
    event_digest: &'a Hash,
    unit_event_digests: &'a [Hash],
    outcome: CommandOutcome,
    effects: &'a [CommandResultEffect],
    reason_code: &'a Option<ReasonCode>,
}

impl SealCommandOutcome {
    pub fn committed(
        event_digest: Hash,
        unit_event_digests: Vec<Hash>,
        effects: Vec<CommandResultEffect>,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        if effects
            .windows(2)
            .any(|pair| pair[0].cell_id >= pair[1].cell_id)
        {
            return Err(WireError::Protocol(
                "command result effects must be sorted and unique by cell_id".to_owned(),
            ));
        }
        let reason_code = None;
        let result_digest = Hash::new(canonical::digest(
            digest_suite,
            &canonical::canonical_json_bytes(&CommandResultDigestInput {
                event_digest: &event_digest,
                unit_event_digests: &unit_event_digests,
                outcome: CommandOutcome::Committed,
                effects: &effects,
                reason_code: &reason_code,
            })?,
        ))?;
        let result = Self {
            event_digest,
            outcome: CommandOutcome::Committed,
            result_digest,
            reason_code,
            unit_event_digests,
        };
        result.validate_structural()?;
        Ok(result)
    }

    pub fn rejected(
        event_digest: Hash,
        unit_event_digests: Vec<Hash>,
        reason_code: ReasonCode,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        let reason_code = Some(reason_code);
        let result_digest = Hash::new(canonical::digest(
            digest_suite,
            &canonical::canonical_json_bytes(&CommandResultDigestInput {
                event_digest: &event_digest,
                unit_event_digests: &unit_event_digests,
                outcome: CommandOutcome::Rejected,
                effects: &[],
                reason_code: &reason_code,
            })?,
        ))?;
        let result = Self {
            event_digest,
            outcome: CommandOutcome::Rejected,
            result_digest,
            reason_code,
            unit_event_digests,
        };
        result.validate_structural()?;
        Ok(result)
    }

    pub fn validate_structural(&self) -> Result<()> {
        if self.unit_event_digests.is_empty() || self.unit_event_digests.len() > MAX_SEAL_DELTA {
            return Err(WireError::Protocol(
                "command result requires 1..=4096 unit_event_digests".to_owned(),
            ));
        }
        if self.unit_event_digests[0] != self.event_digest {
            return Err(WireError::Protocol(
                "command result event_digest must be the first unit member".to_owned(),
            ));
        }
        let mut members = std::collections::BTreeSet::new();
        if !self
            .unit_event_digests
            .iter()
            .all(|digest| members.insert(digest))
        {
            return Err(WireError::Protocol(
                "command result unit_event_digests must be duplicate-free".to_owned(),
            ));
        }
        match (self.outcome, self.reason_code.as_ref()) {
            (CommandOutcome::Committed, None) => Ok(()),
            (CommandOutcome::Rejected, Some(reason_code)) if reason_code.descriptor().is_some() => {
                Ok(())
            }
            (CommandOutcome::Rejected, Some(reason_code)) => Err(WireError::Protocol(format!(
                "rejected command result reason_code {} is not registered",
                reason_code.as_str()
            ))),
            (CommandOutcome::Committed, Some(_)) => Err(WireError::Protocol(
                "committed command result must omit reason_code".to_owned(),
            )),
            (CommandOutcome::Rejected, None) => Err(WireError::Protocol(
                "rejected command result requires reason_code".to_owned(),
            )),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationClosure {
    pub command_event_id: EventId,
    pub dependency_kind: AuthorizationDependencyKind,
    pub authorization_event_id: EventId,
    pub generation_event_id: EventId,
    pub scope_ref: ScopeRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<String>)))]
    pub actions: Vec<CapabilityActionId>,
    pub frontier: Vec<EventId>,
}

impl AuthorizationClosure {
    pub fn validate_structural(&self) -> Result<()> {
        if self.actions.is_empty()
            || self.frontier.len() > 4096
            || !self.dependency_kind.permits_scope(&self.scope_ref)
            || !self
                .actions
                .iter()
                .all(|action| self.dependency_kind.permits_action(*action))
        {
            return Err(WireError::Protocol(
                "authorization closure is outside protocol bounds".to_owned(),
            ));
        }
        validate_sorted_unique(
            "authorization closure actions",
            &self
                .actions
                .iter()
                .map(CapabilityActionId::as_str)
                .collect::<Vec<_>>(),
        )?;
        validate_sorted_unique("authorization closure frontier", &self.frontier)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExistenceAnchor {
    pub authorization_event_id: EventId,
    pub generation_event_id: EventId,
    pub frontier: Vec<EventId>,
}

impl ExistenceAnchor {
    pub fn validate_structural(&self) -> Result<()> {
        if self.frontier.is_empty() || self.frontier.len() > 4096 {
            return Err(WireError::Protocol(
                "existence anchor requires 1..=4096 frontier entries".to_owned(),
            ));
        }
        validate_sorted_unique("existence anchor frontier", &self.frontier)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub id: SealId,
    pub realm_id: RealmId,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub predecessor_ref: Option<SealId>,
    pub delta: Vec<Hash>,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    pub notary_seq: u64,
    pub availability_receipt_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub previous_digest_algorithm: Option<arkret_canonical::DigestSuite>,
    pub notary_signature: SealSignature,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub sealed_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub configuration_ref: EventId,
    pub command_results: Vec<SealCommandOutcome>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_closures: Vec<AuthorizationClosure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub existence_anchors: Vec<ExistenceAnchor>,
}

#[derive(Serialize)]
struct SealBody<'a> {
    realm_id: &'a RealmId,
    predecessor_ref: &'a Option<SealId>,
    delta: &'a [Hash],
    control_event_set_root: &'a Hash,
    state_root: &'a Hash,
    notary_seq: u64,
    availability_receipt_digests: &'a [Hash],
    #[serde(skip_serializing_if = "slice_is_empty")]
    covered_event_digests: &'a [Hash],
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_state_root: &'a Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_digest_algorithm: &'a Option<arkret_canonical::DigestSuite>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    sealed_at: DateTime<Utc>,
    hlc: &'a Hlc,
    configuration_ref: &'a EventId,
    command_results: &'a [SealCommandOutcome],
    #[serde(skip_serializing_if = "slice_is_empty")]
    authorization_closures: &'a [AuthorizationClosure],
    #[serde(skip_serializing_if = "slice_is_empty")]
    existence_anchors: &'a [ExistenceAnchor],
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedSeal {
    pub realm_id: RealmId,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub predecessor_ref: Option<SealId>,
    pub delta: Vec<Hash>,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    pub notary_seq: u64,
    pub availability_receipt_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub previous_digest_algorithm: Option<arkret_canonical::DigestSuite>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub sealed_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub configuration_ref: EventId,
    pub command_results: Vec<SealCommandOutcome>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_closures: Vec<AuthorizationClosure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub existence_anchors: Vec<ExistenceAnchor>,
}

impl Seal {
    /// Reconstruct a complete signed Seal from the exact canonical unsigned
    /// body retained by the durable single-writer executor.
    pub fn from_canonical_body_and_signature(
        canonical_body: &[u8],
        notary_signature: SealSignature,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        let body: UnsignedSeal = serde_json::from_slice(canonical_body)?;
        if canonical::canonical_json_bytes(&body)? != canonical_body {
            return Err(WireError::Protocol(
                "Seal body bytes are not canonical JSON".to_owned(),
            ));
        }
        let id = Self::id_from_canonical_bytes(canonical_body, digest_suite)?;
        let seal = Self {
            id,
            realm_id: body.realm_id,
            predecessor_ref: body.predecessor_ref,
            delta: body.delta,
            control_event_set_root: body.control_event_set_root,
            state_root: body.state_root,
            notary_seq: body.notary_seq,
            availability_receipt_digests: body.availability_receipt_digests,
            covered_event_digests: body.covered_event_digests,
            previous_state_root: body.previous_state_root,
            previous_digest_algorithm: body.previous_digest_algorithm,
            notary_signature,
            sealed_at: body.sealed_at,
            hlc: body.hlc,
            configuration_ref: body.configuration_ref,
            command_results: body.command_results,
            authorization_closures: body.authorization_closures,
            existence_anchors: body.existence_anchors,
        };
        seal.validate_structural()?;
        seal.validate_signature_payload_digests(|bytes| {
            Hash::new(canonical::digest(digest_suite, bytes)).map_err(Into::into)
        })?;
        Ok(seal)
    }

    pub fn is_compaction(&self) -> bool {
        !self.covered_event_digests.is_empty()
    }

    /// Mint the single-leaf Control Move basis represented by this accepted
    /// Seal. Callers must only use the result after receiver acceptance.
    pub fn seal_basis(&self) -> crate::SealBasis {
        crate::SealBasis {
            leaves: vec![self.id.clone()],
        }
    }

    pub fn canonical_bytes_for_id(&self) -> Result<Vec<u8>> {
        let body = SealBody {
            realm_id: &self.realm_id,
            predecessor_ref: &self.predecessor_ref,
            delta: &self.delta,
            control_event_set_root: &self.control_event_set_root,
            state_root: &self.state_root,
            notary_seq: self.notary_seq,
            availability_receipt_digests: &self.availability_receipt_digests,
            covered_event_digests: &self.covered_event_digests,
            previous_state_root: &self.previous_state_root,
            previous_digest_algorithm: &self.previous_digest_algorithm,
            sealed_at: self.sealed_at,
            hlc: &self.hlc,
            configuration_ref: &self.configuration_ref,
            command_results: &self.command_results,
            authorization_closures: &self.authorization_closures,
            existence_anchors: &self.existence_anchors,
        };
        Ok(canonical::canonical_json_bytes(&body)?)
    }

    /// Derive this Seal identity under the Realm's verified digest suite.
    pub fn derive_id(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<SealId> {
        Self::id_from_canonical_bytes(&self.canonical_bytes_for_id()?, digest_suite)
    }

    /// Derive a Seal identity under an explicit trusted Realm digest suite.
    pub fn id_from_canonical_bytes(
        bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<SealId> {
        let id = format!("ak:seal:{}", canonical::digest(digest_suite, bytes));
        SealId::new(id).map_err(|err| WireError::Protocol(format!("invalid Seal id: {err}")))
    }

    /// Validate the Seal identity under the Realm's verified digest suite.
    pub fn validate_id(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<()> {
        let derived = self.derive_id(digest_suite)?;
        if derived != self.id {
            return Err(WireError::Protocol(format!(
                "Seal id mismatch: declared {} but canonical bytes hash to {}",
                self.id, derived
            )));
        }
        Ok(())
    }

    pub fn validate_structural(&self) -> Result<()> {
        if self.delta.len() > MAX_SEAL_DELTA {
            return Err(WireError::Protocol(format!(
                "Seal.delta exceeds maximum item count {MAX_SEAL_DELTA}"
            )));
        }
        if self.availability_receipt_digests.len() > MAX_SEAL_AVAILABILITY_RECEIPT_DIGESTS {
            return Err(WireError::Protocol(format!(
                "Seal.availability_receipt_digests exceeds maximum item count {MAX_SEAL_AVAILABILITY_RECEIPT_DIGESTS}"
            )));
        }
        if self.covered_event_digests.len() > MAX_SEAL_COVERED_EVENT_DIGESTS {
            return Err(WireError::Protocol(format!(
                "Seal.covered_event_digests exceeds maximum item count {MAX_SEAL_COVERED_EVENT_DIGESTS}"
            )));
        }
        validate_sorted_unique("Seal.delta", &self.delta)?;
        validate_sorted_unique(
            "Seal.availability_receipt_digests",
            &self.availability_receipt_digests,
        )?;
        validate_sorted_unique("Seal.covered_event_digests", &self.covered_event_digests)?;
        if self.previous_state_root.is_some() != self.previous_digest_algorithm.is_some() {
            return Err(WireError::Protocol(
                "Seal previous_state_root and previous_digest_algorithm must be present together"
                    .to_owned(),
            ));
        }
        if self.notary_seq == 0 && self.predecessor_ref.is_some()
            || self.notary_seq > 0 && self.predecessor_ref.is_none()
        {
            return Err(WireError::Protocol(
                "Seal predecessor_ref is null exactly at genesis".to_owned(),
            ));
        }
        if self.notary_seq > 9_007_199_254_740_991 {
            return Err(WireError::Protocol(
                "Seal sequence must be a JSON-safe integer".to_owned(),
            ));
        }
        if self.command_results.len() > MAX_SEAL_DELTA
            || self.authorization_closures.len() > MAX_SEAL_DELTA
            || self.existence_anchors.len() > MAX_SEAL_DELTA
        {
            return Err(WireError::Protocol(
                "Seal command or evidence collection exceeds 4096 entries".to_owned(),
            ));
        }
        let mut command_members = std::collections::BTreeMap::new();
        for result in &self.command_results {
            result.validate_structural()?;
            for digest in &result.unit_event_digests {
                if command_members.insert(digest, result.outcome).is_some() {
                    return Err(WireError::Protocol(
                        "each Event digest must appear in exactly one command result unit"
                            .to_owned(),
                    ));
                }
            }
        }
        if self
            .delta
            .iter()
            .any(|digest| command_members.get(digest) != Some(&CommandOutcome::Committed))
        {
            return Err(WireError::Protocol(
                "Seal delta may contain only committed command unit members".to_owned(),
            ));
        }
        for closure in &self.authorization_closures {
            closure.validate_structural()?;
            if closure.scope_ref.realm_id_opt() != Some(&self.realm_id) {
                return Err(WireError::Protocol(
                    "authorization closure scope must belong to its Seal Realm".into(),
                ));
            }
        }
        for anchor in &self.existence_anchors {
            anchor.validate_structural()?;
        }
        validate_seal_signature(&self.notary_signature)?;
        Ok(())
    }

    pub fn validate_signature_payload_digests<F>(&self, digest: F) -> Result<()>
    where
        F: Fn(&[u8]) -> Result<Hash>,
    {
        let seal_digest = digest(&self.canonical_bytes_for_id()?)?;
        let transcript = canonical::canonical_json_bytes(&SealCommitTranscript {
            context: "ak.seal.commit.v1",
            seal_digest: &seal_digest,
        })?;
        let expected = digest(&transcript)?;
        let matches = self.notary_signature.payload_digest == expected;
        if !matches {
            return Err(WireError::Protocol(
                "Seal signature payload_digest does not match canonical Seal bytes".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn commit_transcript_bytes(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Vec<u8>> {
        let seal_digest = Hash::new(canonical::digest(
            digest_suite,
            &self.canonical_bytes_for_id()?,
        ))?;
        canonical::canonical_json_bytes(&SealCommitTranscript {
            context: "ak.seal.commit.v1",
            seal_digest: &seal_digest,
        })
        .map_err(Into::into)
    }
}

#[derive(Serialize)]
struct SealCommitTranscript<'a> {
    context: &'static str,
    seal_digest: &'a Hash,
}

fn validate_seal_signature(signature: &SealSignature) -> Result<()> {
    let mut segments = signature.jws.split('.');
    let valid = segments.next().is_some_and(|value| !value.is_empty())
        && segments.next().is_some()
        && segments.next().is_some_and(|value| !value.is_empty())
        && segments.next().is_none()
        && signature.jws.bytes().all(|byte| {
            byte == b'.' || byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
        });
    if !valid {
        return Err(WireError::Protocol(
            "Seal signature JWS is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sorted_unique<T>(field: &str, values: &[T]) -> Result<()>
where
    T: AsRef<str>,
{
    for pair in values.windows(2) {
        let left = pair[0].as_ref();
        let right = pair[1].as_ref();
        if left >= right {
            return Err(WireError::Protocol(format!(
                "{field} must be canonical sorted and duplicate-free"
            )));
        }
    }
    Ok(())
}

fn slice_is_empty<T>(values: &&[T]) -> bool {
    values.is_empty()
}

fn deserialize_required_option<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
