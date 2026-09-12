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
    CellRef, DidUrl, EventId, Hash, Hlc, NotarySignerDescriptor, RealmId, ReasonCode, Result,
    ScopeRef, SealId, WireError, canonical,
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
pub struct CommandResultCellState {
    pub revision_event_id: EventId,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandResultEffect {
    pub cell_id: CellRef,
    pub state: CommandResultCellState,
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
            (CommandOutcome::Committed, None) | (CommandOutcome::Rejected, Some(_)) => Ok(()),
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
    pub authorization_event_id: EventId,
    pub generation_event_id: EventId,
    pub scope_ref: ScopeRef,
    pub actions: Vec<String>,
    pub frontier: Vec<EventId>,
}

impl AuthorizationClosure {
    pub fn validate_structural(&self) -> Result<()> {
        if self.actions.is_empty()
            || self.frontier.len() > 4096
            || !self.actions.iter().all(|action| valid_action(action))
        {
            return Err(WireError::Protocol(
                "authorization closure is outside protocol bounds".to_owned(),
            ));
        }
        validate_sorted_unique("authorization closure actions", &self.actions)?;
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
pub struct TransactionParticipant {
    pub realm_id: RealmId,
    pub basis_ref: SealId,
    pub read_cell_refs: Vec<CellRef>,
    pub write_cell_refs: Vec<CellRef>,
}

impl TransactionParticipant {
    pub fn validate_structural(&self) -> Result<()> {
        if self.read_cell_refs.len() > 4096 || self.write_cell_refs.len() > 4096 {
            return Err(WireError::Protocol(
                "transaction participant cell selector limit exceeded".to_owned(),
            ));
        }
        if self.read_cell_refs.is_empty() && self.write_cell_refs.is_empty() {
            return Err(WireError::Protocol(
                "transaction participant requires a read or write Cell".to_owned(),
            ));
        }
        validate_sorted_unique(
            "transaction participant read_cell_refs",
            &self.read_cell_refs,
        )?;
        validate_sorted_unique(
            "transaction participant write_cell_refs",
            &self.write_cell_refs,
        )
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionManifest {
    pub command_event_id: EventId,
    pub participants: Vec<TransactionParticipant>,
    pub decision_realm_id: RealmId,
}

impl TransactionManifest {
    pub fn validate_structural(&self) -> Result<()> {
        if !(2..=64).contains(&self.participants.len()) {
            return Err(WireError::Protocol(
                "transaction manifest requires 2..=64 participants".to_owned(),
            ));
        }
        for participant in &self.participants {
            participant.validate_structural()?;
        }
        if self
            .participants
            .windows(2)
            .any(|pair| pair[0].realm_id >= pair[1].realm_id)
        {
            return Err(WireError::Protocol(
                "transaction participants must be sorted and unique by realm_id".to_owned(),
            ));
        }
        if self.participants[0].realm_id != self.decision_realm_id {
            return Err(WireError::Protocol(
                "transaction decision_realm_id must be the first participant".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransactionRecord {
    Prepare {
        manifest: TransactionManifest,
    },
    Commit {
        manifest: TransactionManifest,
        prepare_seal_refs: Vec<SealId>,
    },
    Abort {
        manifest: TransactionManifest,
    },
    Apply {
        manifest: TransactionManifest,
        decision_seal_ref: SealId,
    },
}

impl TransactionRecord {
    pub fn manifest(&self) -> &TransactionManifest {
        match self {
            Self::Prepare { manifest }
            | Self::Commit { manifest, .. }
            | Self::Abort { manifest }
            | Self::Apply { manifest, .. } => manifest,
        }
    }

    pub fn validate_structural(&self) -> Result<()> {
        self.manifest().validate_structural()?;
        if let Self::Commit {
            manifest,
            prepare_seal_refs,
        } = self
        {
            if prepare_seal_refs.len() != manifest.participants.len()
                || !(2..=64).contains(&prepare_seal_refs.len())
            {
                return Err(WireError::Protocol(
                    "commit prepare_seal_refs must match participant order".to_owned(),
                ));
            }
            let mut unique = std::collections::BTreeSet::new();
            if !prepare_seal_refs.iter().all(|seal| unique.insert(seal)) {
                return Err(WireError::Protocol(
                    "commit prepare_seal_refs must be duplicate-free".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// `seal.schema.json#/$defs/multi_signature` is a closed object; `kind` is the
/// discriminator that keeps this branch disjoint from the other two.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiSignature {
    pub kind: MultiSigKind,
    pub signatures: Vec<SealSignature>,
    pub view: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiSigKind {
    MultiSig,
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
    pub notary_signature: MultiSignature,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub sealed_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub configuration_ref: EventId,
    pub command_results: Vec<SealCommandOutcome>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_closures: Vec<AuthorizationClosure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub existence_anchors: Vec<ExistenceAnchor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_records: Vec<TransactionRecord>,
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
    #[serde(skip_serializing_if = "slice_is_empty")]
    transaction_records: &'a [TransactionRecord],
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_records: Vec<TransactionRecord>,
}

impl Seal {
    /// Reconstruct a complete signed Seal from the exact canonical unsigned
    /// body retained by a multi-signature aggregator.
    pub fn from_canonical_body_and_signature(
        canonical_body: &[u8],
        notary_signature: MultiSignature,
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
            transaction_records: body.transaction_records,
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
            transaction_records: &self.transaction_records,
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
        if self.notary_seq > 9_007_199_254_740_991
            || self.notary_signature.view > 9_007_199_254_740_991
        {
            return Err(WireError::Protocol(
                "Seal sequence and view must be JSON-safe integers".to_owned(),
            ));
        }
        if self.command_results.len() > MAX_SEAL_DELTA
            || self.authorization_closures.len() > MAX_SEAL_DELTA
            || self.existence_anchors.len() > MAX_SEAL_DELTA
            || self.transaction_records.len() > MAX_SEAL_DELTA
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
        }
        for anchor in &self.existence_anchors {
            anchor.validate_structural()?;
        }
        for record in &self.transaction_records {
            record.validate_structural()?;
        }
        let mut transaction_records = std::collections::BTreeSet::new();
        for record in &self.transaction_records {
            if !transaction_records.insert(canonical::canonical_json_bytes(record)?) {
                return Err(WireError::Protocol(
                    "Seal transaction_records must be duplicate-free".to_owned(),
                ));
            }
        }
        if self.notary_signature.signatures.is_empty() {
            return Err(WireError::Protocol(
                "Seal multi_sig must have at least one signature".to_owned(),
            ));
        }
        for signature in &self.notary_signature.signatures {
            validate_seal_signature(signature)?;
        }
        for pair in self.notary_signature.signatures.windows(2) {
            if pair[0].verification_method >= pair[1].verification_method {
                return Err(WireError::Protocol(
                    "Seal multi_sig signatures must be sorted and unique by verification_method"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_signature_payload_digests<F>(&self, digest: F) -> Result<()>
    where
        F: Fn(&[u8]) -> Result<Hash>,
    {
        let seal_digest = digest(&self.canonical_bytes_for_id()?)?;
        let transcript = canonical::canonical_json_bytes(&SealVoteTranscript {
            context: "ak.seal.commit.v1",
            seal_digest: &seal_digest,
            configuration_ref: &self.configuration_ref,
            notary_seq: self.notary_seq,
            view: self.notary_signature.view,
        })?;
        let expected = digest(&transcript)?;
        let matches = self
            .notary_signature
            .signatures
            .iter()
            .all(|signature| signature.payload_digest == expected);
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
        canonical::canonical_json_bytes(&SealVoteTranscript {
            context: "ak.seal.commit.v1",
            seal_digest: &seal_digest,
            configuration_ref: &self.configuration_ref,
            notary_seq: self.notary_seq,
            view: self.notary_signature.view,
        })
        .map_err(Into::into)
    }
}

#[derive(Serialize)]
struct SealVoteTranscript<'a> {
    context: &'static str,
    seal_digest: &'a Hash,
    configuration_ref: &'a EventId,
    notary_seq: u64,
    view: u64,
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

fn valid_action(action: &str) -> bool {
    let mut segments = action.split('.');
    segments.next() == Some("ak")
        && segments.clone().count() >= 2
        && segments.all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
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
