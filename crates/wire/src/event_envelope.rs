//! Event Envelope wire models.
//!
//! # Forward-compatibility policy for wire enums (per-enum, deliberate)
//!
//! The SDK intentionally uses **two different** forward-compatibility
//! strategies for enums that appear on the wire, and the split is per-enum
//! policy, not accident:
//!
//! - **`EventKind` keeps unknown values** (`EventKind::Unknown(String)`). The event-kind registry
//!   is an *open, growing* namespace: new `ak.*` kinds are added in ordinary spec revisions and
//!   vendor kinds exist by design. An older SDK deserialising a newer kind preserves the raw wire
//!   string instead of failing the whole envelope; whether an unknown *standard* kind is acceptable
//!   is the validation layer's decision (`schema_violation`), not the parser's.
//!
//! - **Closed-set wire enums hard-reject unknown values** (e.g. [`EnvelopeActorKind`],
//!   [`ScopeRef`], cursor purpose, subscribe frame kinds): no `#[serde(other)]` catch-all, so an
//!   unrecognised value fails deserialisation of the surrounding object. These enums gate
//!   authorization, scope and stream-control decisions; silently mapping an unknown value to a
//!   default could *widen* what the message is allowed to do. `conformance-profiles.md` requires
//!   implementations to reject illegal enum values — hard failure is the fail-closed behaviour, and
//!   a spec revision that extends a closed set is a coordinated upgrade, not a silent downgrade.
//!
//! Consequently: adding an event kind is a non-breaking registry evolution
//! (old SDKs keep parsing), while extending a closed-set enum intentionally
//! interrupts old parsers rather than letting them mis-authorize. The
//! affected enums additionally carry `#[non_exhaustive]` so downstream
//! `match` code is written with a fail-closed `_` arm from day one.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{
    AppletId, CircleId, Did, DidCoreId, EventId, GrantId, Hash, Hlc, RealmId, SealId, SidecarId,
    project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cba::{Precondition, SealBasis};
use crate::error::{Result, WireError};
use crate::error_codes::ReasonCode;
use crate::events::kinds::{CbaEffectPlane, EventKind};
use crate::primitives::{
    ActorId, Audience, CriticalExtension, EventProof, ProofBindingRequirements,
    SignatureBindingPayload,
};
use crate::{
    AuthorizationRef, Base64UrlString, DidUrl, FeatureRef, OpaqueLocalId, ProfileRef, SchemaId,
    canonical,
};

/// Full canonical Event Envelope bound, measured over the reducer-accepted envelope including
/// reducer-stamped top-level fields and every producer proof, excluding the read-view `unsigned`.
///
/// See `zh/conformance/scalability-constraints.md` section 2.1.1.
pub const MAX_EVENT_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Canonical body bound for `body_class=non_streaming_json` operations
/// (`scalability-constraints.md` section 2.1.2).
pub const MAX_OPERATION_CANONICAL_BODY_BYTES: usize = 8 * 1024 * 1024;

/// HTTP message content wire bound enforced before JSON parse
/// (`scalability-constraints.md` section 2.1.3).
pub const MAX_HTTP_MESSAGE_CONTENT_BYTES: usize = 16 * 1024 * 1024;

/// Bound on the service-added read-view `unsigned` object of a single Event
/// (`scalability-constraints.md` section 2.1.1). Submit paths MUST reject `unsigned` outright.
pub const MAX_READ_VIEW_UNSIGNED_CANONICAL_BYTES: usize = 16 * 1024;

pub const MAX_EVENT_SUBMIT_BATCH: usize = 1_000;
pub const MAX_EVENT_RESOLVE: usize = 100;
pub const MAX_EVENT_PREV_REFS: usize = 128;
pub const MAX_EVENT_REFS: usize = 128;
pub const MAX_AUTHORIZED_BY_REFS: usize = 64;
pub const MAX_ACTOR_SEQ_SIBLINGS: usize = 16;
pub const MAX_ACTOR_SEQ_TOTAL_SIBLINGS: usize = 64;
pub const MAX_AUTHORITY_CHAIN_DEPTH: usize = 4;
pub const MAX_AUTHORITY_CONTROL_DEPTH: u32 = 4;

pub const EVENT_REF_ROLE_AUTHORIZED_BY: &str = "authorized_by";

pub fn validate_event_envelope_byte_len(byte_len: usize) -> Result<()> {
    if byte_len > MAX_EVENT_ENVELOPE_BYTES {
        return Err(WireError::Protocol(format!(
            "event envelope exceeds v1 maximum of {MAX_EVENT_ENVELOPE_BYTES} bytes"
        )));
    }
    Ok(())
}

pub fn validate_event_submit_batch_count(count: usize) -> Result<()> {
    if count > MAX_EVENT_SUBMIT_BATCH {
        return Err(WireError::Protocol(format!(
            "event submit batch exceeds v1 maximum of {MAX_EVENT_SUBMIT_BATCH} events"
        )));
    }
    Ok(())
}

pub fn validate_event_prev_ref_count(count: usize) -> Result<()> {
    if count > MAX_EVENT_PREV_REFS {
        return Err(WireError::Protocol(format!(
            "prev_refs exceeds v1 maximum of {MAX_EVENT_PREV_REFS} entries"
        )));
    }
    Ok(())
}

pub fn validate_event_ref_count(count: usize) -> Result<()> {
    if count > MAX_EVENT_REFS {
        return Err(WireError::Protocol(format!(
            "refs exceeds v1 maximum of {MAX_EVENT_REFS} entries"
        )));
    }
    Ok(())
}

pub fn validate_authorized_by_ref_count(count: usize) -> Result<()> {
    if count > MAX_AUTHORIZED_BY_REFS {
        return Err(WireError::Protocol(format!(
            "authorized_by refs exceeds v1 maximum of {MAX_AUTHORIZED_BY_REFS} entries"
        )));
    }
    Ok(())
}

pub fn prev_frontier_digest(prev_refs: &[EventId]) -> Result<String> {
    let mut sorted = prev_refs.to_vec();
    sorted.sort();
    sorted.dedup();
    Ok(canonical::canonical_sha256(&Value::Array(
        sorted
            .into_iter()
            .map(|id| Value::String(id.into_string()))
            .collect(),
    ))?)
}

/// Reducer-stamped projection of the exact Actor Profile classification.
///
/// Event `actor_kind` and `ActorProfile.actor_kind` share one closed wire enum;
/// the field is not a runtime-origin classifier. In particular, devices are
/// endpoints rather than actors, Ghost Actor is provenance rather than an
/// actor kind, Agent is reserved for controller-provisioned Agents, and
/// Applet-managed automation uses `Bot`.
pub type EnvelopeActorKind = crate::ActorKind;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRefProof {
    pub kind: SemanticRefProofKind,
    pub leaf_digest: Hash,
    pub audit_path: Vec<Hash>,
    pub leaf_index: u64,
    pub leaf_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticRefProofKind {
    #[serde(rename = "rfc6962_merkle")]
    Rfc6962Merkle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRef {
    pub id: String,
    pub role: String,
    #[serde(default = "default_event_ref_critical")]
    pub critical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<SemanticRefProof>,
}

impl EventRef {
    pub fn new(id: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            role: role.into(),
            critical: true,
            proof: None,
        }
    }

    pub fn authorized_by_grant(grant_id: GrantId) -> Self {
        Self::new(grant_id.to_string(), EVENT_REF_ROLE_AUTHORIZED_BY)
    }
}

fn default_event_ref_critical() -> bool {
    true
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRequirements {
    #[serde(default, rename = "schema", skip_serializing_if = "Vec::is_empty")]
    pub schema_profile_refs: Vec<ProfileRef>,
    #[serde(default, rename = "features", skip_serializing_if = "Vec::is_empty")]
    pub required_features: Vec<FeatureRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub critical_extensions: Vec<CriticalExtension>,
}

/// DataEvent authorization context.
///
/// Pins the signing key identifier and key epoch a receiver verifies against
/// at `seal_ref`. The envelope `actor_id` remains the sole actor carrier. It
/// carries no capability list: effective capabilities are derived from the
/// accepted governance basis, never selected by the producer.
/// `event-and-patch.md` §75 names producer-selected
/// `auth_context.capability_refs` alongside `effects` as a field a v1 receiver
/// MUST reject with `schema_violation`, and the envelope schema closes this
/// object over `{key_id, key_epoch, credential_epoch}` — so
/// `deny_unknown_fields` here is what makes an inbound one fail rather than be
/// silently dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthContext {
    pub key_id: OpaqueLocalId,
    pub key_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_epoch: Option<u64>,
}

impl EventRequirements {
    pub fn is_empty(&self) -> bool {
        self.schema_profile_refs.is_empty()
            && self.required_features.is_empty()
            && self.critical_extensions.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(try_from = "EventWire")]
pub struct Event {
    // `Serialize` is NOT derived: `EventSer` below is the single wire-shape
    // exit, so `ak.realm.create` can omit `realm_id`
    // (`zh/models/realm-and-space.md` section 2.5.0) while it stays resolved
    // in memory here. Adding a field means adding it to `EventSer` too — the
    // compiler enforces that.
    pub event_id: EventId,
    pub kind: EventKind,
    pub realm_id: RealmId,
    /// Producer-declared and producer-signed security scope of this Event.
    ///
    /// It is part of the canonical digest transcript: rewriting it invalidates
    /// every proof. Receivers MUST additionally recompute the scope from the
    /// payload and accepted references and reject a signed-but-wrong scope
    /// (`conformance/encoding.md` §6).
    pub scope_ref: ScopeRef,
    pub actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<AuthorizationRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<EnvelopeActorKind>,
    pub actor_seq: u64,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
    pub prev_refs: Vec<EventId>,
    #[serde(default)]
    pub refs: Vec<EventRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_refs: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<Precondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<AuthContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_basis: Option<SealBasis>,
    pub payload: BTreeMap<String, Value>,
    /// Reducer/client-local extension data that is not part of the signed
    /// canonical Event Envelope transcript.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<EventProof>,
    #[serde(default, skip_serializing_if = "EventRequirements::is_empty")]
    pub requirements: EventRequirements,
}

/// Minimal accepted-Event facts needed by the registry effect projector.
///
/// This is deliberately not an authorable Event and carries no proofs,
/// requirements, or unsigned data. It preserves the accepted authorization
/// reference needed by registry effects without fabricating a new signed
/// [`Event`].
#[derive(Clone, Debug, PartialEq)]
pub struct ProjectedEventInput {
    pub kind: EventKind,
    pub event_id: EventId,
    pub actor_id: ActorId,
    pub authorization_ref: Option<AuthorizationRef>,
    pub actor_seq: u64,
    pub realm_id: RealmId,
    pub created_at: DateTime<Utc>,
    pub payload: BTreeMap<String, Value>,
    pub refs: Vec<EventRef>,
    pub preconditions: Vec<Precondition>,
    pub seal_ref: Option<SealId>,
    pub seal_basis: Option<SealBasis>,
}

impl From<&Event> for ProjectedEventInput {
    fn from(event: &Event) -> Self {
        Self {
            kind: event.kind.clone(),
            event_id: event.event_id.clone(),
            actor_id: event.actor_id.clone(),
            authorization_ref: event.authorization_ref.clone(),
            actor_seq: event.actor_seq,
            realm_id: event.realm_id.clone(),
            created_at: event.created_at,
            payload: event.payload.clone(),
            refs: event.refs.clone(),
            preconditions: event.preconditions.clone(),
            seal_ref: event.seal_ref.clone(),
            seal_basis: event.seal_basis.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DidBindingEvidenceKind {
    #[serde(rename = "ak.did.binding_evidence.v1")]
    AkDidBindingEvidenceV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DidBindingMethodProofKind {
    WebvhLog,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DidBindingWitness {
    pub witness_did: Did,
    pub controlling_organization_did: Did,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DidBindingMethodProof {
    pub kind: DidBindingMethodProofKind,
    pub history_head: String,
    pub witnesses: Vec<DidBindingWitness>,
    pub witness_proofs_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DidBindingEvidenceReceipt {
    pub kind: DidBindingEvidenceKind,
    pub method: String,
    pub document_digest: Hash,
    pub method_proofs: Vec<DidBindingMethodProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RegistrationControlSignature {
    pub verification_method: DidUrl,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: Base64UrlString,
}

const REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_DOMAIN: &str =
    "ak.registration_did_evidence_control_proof.v1\n";

/// Client-authored registration evidence before the Account Authority assigns
/// the registry acceptance time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RegistrationDidEvidenceDraft {
    pub principal_id: DidCoreId,
    pub did: Did,
    pub adapter_version: String,
    pub method_history_head: String,
    pub version_id: String,
    pub control_key_digest: Hash,
    pub method_evidence: DidBindingEvidenceReceipt,
    pub control_proof: RegistrationControlSignature,
}

impl RegistrationDidEvidenceDraft {
    pub fn validate_shape(&self) -> Result<()> {
        validate_registration_did_evidence_fields(
            &self.principal_id,
            &self.did,
            &self.adapter_version,
            &self.method_history_head,
            &self.version_id,
            &self.method_evidence,
            &self.control_proof,
        )
    }

    pub fn method_evidence_digest(&self) -> Result<Hash> {
        self.validate_shape()?;
        Hash::new(canonical::canonical_sha256(&self.method_evidence)?).map_err(Into::into)
    }

    pub fn canonical_control_proof_signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let value = serde_json::json!({
            "context": crate::ProofContextId::REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1,
            "principal_id": &self.principal_id,
            "did": &self.did,
            "adapter_version": &self.adapter_version,
            "method_history_head": &self.method_history_head,
            "version_id": &self.version_id,
            "control_key_digest": &self.control_key_digest,
            "method_evidence_digest": self.method_evidence_digest()?,
            "verification_method": &self.control_proof.verification_method,
            "created_at": canonical::format_timestamp_canonical(self.control_proof.created_at),
        });
        let mut bytes = REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_DOMAIN
            .as_bytes()
            .to_vec();
        bytes.extend(canonical::canonical_json_bytes(&value)?);
        Ok(bytes)
    }

    pub fn accept(self, accepted_at: DateTime<Utc>) -> Result<RegistrationDidEvidence> {
        self.validate_shape()?;
        if accepted_at < self.control_proof.created_at {
            return Err(WireError::Protocol(
                "registration evidence acceptance predates its control proof".to_owned(),
            ));
        }
        let evidence = RegistrationDidEvidence {
            principal_id: self.principal_id,
            did: self.did,
            adapter_version: self.adapter_version,
            accepted_at,
            method_history_head: self.method_history_head,
            version_id: self.version_id,
            control_key_digest: self.control_key_digest,
            method_evidence: self.method_evidence,
            control_proof: self.control_proof,
        };
        evidence.validate_shape()?;
        Ok(evidence)
    }
}

/// Frozen DID evidence captured when this PCR registration was accepted.
/// It is historical input: verifiers must never replace it with a current DID
/// document or current method head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RegistrationDidEvidence {
    pub principal_id: DidCoreId,
    pub did: Did,
    pub adapter_version: String,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub method_history_head: String,
    pub version_id: String,
    pub control_key_digest: Hash,
    pub method_evidence: DidBindingEvidenceReceipt,
    pub control_proof: RegistrationControlSignature,
}

impl RegistrationDidEvidence {
    pub fn validate_shape(&self) -> Result<()> {
        validate_registration_did_evidence_fields(
            &self.principal_id,
            &self.did,
            &self.adapter_version,
            &self.method_history_head,
            &self.version_id,
            &self.method_evidence,
            &self.control_proof,
        )?;
        if self.control_proof.created_at > self.accepted_at {
            return Err(WireError::Protocol(
                "registration DID evidence predates its control proof".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        self.validate_shape()?;
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }

    pub fn draft(&self) -> RegistrationDidEvidenceDraft {
        RegistrationDidEvidenceDraft {
            principal_id: self.principal_id.clone(),
            did: self.did.clone(),
            adapter_version: self.adapter_version.clone(),
            method_history_head: self.method_history_head.clone(),
            version_id: self.version_id.clone(),
            control_key_digest: self.control_key_digest.clone(),
            method_evidence: self.method_evidence.clone(),
            control_proof: self.control_proof.clone(),
        }
    }

    pub fn canonical_control_proof_signing_bytes(&self) -> Result<Vec<u8>> {
        self.draft().canonical_control_proof_signing_bytes()
    }
}

fn validate_registration_did_evidence_fields(
    principal_id: &DidCoreId,
    did: &Did,
    adapter_version: &str,
    method_history_head: &str,
    version_id: &str,
    method_evidence: &DidBindingEvidenceReceipt,
    control_proof: &RegistrationControlSignature,
) -> Result<()> {
    let controller = control_proof
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            WireError::Protocol("registration control proof has no fragment".to_owned())
        })?;
    let mut witness_ids = BTreeSet::new();
    if adapter_version.trim().is_empty()
        || method_history_head.trim().is_empty()
        || version_id.trim().is_empty()
        || project_did_to_core_id(did)? != *principal_id
        || controller != did.as_str()
        || method_evidence.method != did.method()
        || method_evidence.method_proofs.iter().any(|proof| {
            proof.history_head.is_empty()
                || proof
                    .witnesses
                    .windows(2)
                    .any(|pair| pair[0].witness_did.as_str() >= pair[1].witness_did.as_str())
                || proof
                    .witnesses
                    .iter()
                    .any(|witness| !witness_ids.insert(witness.witness_did.as_str().to_owned()))
        })
    {
        return Err(WireError::Protocol(
            "registration DID evidence shape or identity binding mismatch".to_owned(),
        ));
    }
    match did.method() {
        "webvh"
            if method_evidence.method_proofs.len() == 1
                && method_evidence.method_proofs[0].history_head == method_history_head => {}
        "web" | "key" if method_evidence.method_proofs.is_empty() => {}
        _ => {
            return Err(WireError::Protocol(
                "registration DID evidence method proof mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Derive the Realm id of an `ak.realm.create` from its own signed content.
///
/// Every Realm kind, including principal and Agent control Realms, is
/// event-derived. The high nibble of the token header is reserved and remains
/// zero; no DID-subject-derived address branch exists.
pub fn derive_genesis_realm_id(event_id: &EventId) -> RealmId {
    RealmId::from_event_id(event_id)
}

/// The Event digest preimage of `conformance/encoding.md` §6, computed from a
/// wire envelope that is already JSON.
///
/// This is the **only** implementation of the exclusion rule. It exists as a
/// `Value -> Value` function, not just as [`Event::digest_payload`], because
/// every verifier that holds an envelope it has not parsed into [`Event`] used
/// to delete the excluded fields by hand — and every hand-rolled copy drifted
/// from the rule at a different point (one forgot `event_id`, one forgot
/// `actor_kind`, one hashed the envelope itself). A drifted preimage does not
/// fail loudly: it produces bytes no other implementation can reproduce, so a
/// valid signature verifies as invalid.
///
/// The excluded set and the reason each field is in it:
///
/// * `proofs` — the signature cannot cover itself.
/// * `unsigned` — receiver-local projection context, attached after signing.
/// * `actor_kind` — the one v1 field the reducer stamps after the producer signs, so a peer
///   recomputing the digest would never see the producer's value.
/// * `event_id` — §4.0 derives the id *from this digest*, so leaving it in would put a function of
///   the digest inside the digest's own input.
///
/// Everything else, `scope_ref` included, stays inside the transcript.
pub fn event_digest_preimage(envelope: &Value) -> Result<Value> {
    let Value::Object(map) = envelope else {
        return Err(WireError::Protocol(
            "Event digest preimage input must be a JSON object envelope".to_owned(),
        ));
    };
    let mut map = map.clone();
    map.remove("proofs");
    map.remove("unsigned");
    for field in Event::REDUCER_STAMPED_TOP_LEVEL_FIELDS {
        map.remove(field);
    }
    map.remove("event_id");
    Ok(Value::Object(map))
}

/// The single wire-shape exit for [`Event`].
///
/// `Event` keeps `realm_id` resolved in memory for every kind, but the genesis
/// envelope of `ak.realm.create` MUST NOT carry it: the Realm id is derived
/// from that Event's own `event_id`, so putting it back on the wire would place
/// a function of the digest inside the digest preimage
/// (`zh/models/realm-and-space.md` section 2.5.0).
///
/// Borrowing mirror rather than a field-type change: every read site of
/// `event.realm_id` keeps working, and a new `Event` field fails to compile
/// here until it is mirrored.
#[derive(Serialize)]
struct EventSer<'a> {
    event_id: &'a EventId,
    kind: &'a EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    realm_id: Option<&'a RealmId>,
    scope_ref: &'a ScopeRef,
    actor_id: &'a ActorId,
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_by: &'a Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_ref: &'a Option<AuthorizationRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    applet_id: &'a Option<AppletId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_ref: &'a Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_kind: &'a Option<EnvelopeActorKind>,
    actor_seq: u64,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hlc: &'a Option<Hlc>,
    prev_refs: &'a Vec<EventId>,
    refs: &'a Vec<EventRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    causal_refs: &'a Vec<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    preconditions: &'a Vec<Precondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seal_ref: &'a Option<SealId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_context: &'a Option<AuthContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seal_basis: &'a Option<SealBasis>,
    payload: &'a BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    unsigned: &'a BTreeMap<String, Value>,
    proofs: &'a Vec<EventProof>,
    #[serde(skip_serializing_if = "EventRequirements::is_empty")]
    requirements: &'a EventRequirements,
}

impl<'a> From<&'a Event> for EventSer<'a> {
    fn from(event: &'a Event) -> Self {
        Self {
            event_id: &event.event_id,
            kind: &event.kind,
            realm_id: (event.kind != EventKind::RealmCreate).then_some(&event.realm_id),
            scope_ref: &event.scope_ref,
            actor_id: &event.actor_id,
            executed_by: &event.executed_by,
            authorization_ref: &event.authorization_ref,
            applet_id: &event.applet_id,
            external_ref: &event.external_ref,
            actor_kind: &event.actor_kind,
            actor_seq: event.actor_seq,
            created_at: event.created_at,
            hlc: &event.hlc,
            prev_refs: &event.prev_refs,
            refs: &event.refs,
            causal_refs: &event.causal_refs,
            preconditions: &event.preconditions,
            seal_ref: &event.seal_ref,
            auth_context: &event.auth_context,
            seal_basis: &event.seal_basis,
            payload: &event.payload,
            unsigned: &event.unsigned,
            proofs: &event.proofs,
            requirements: &event.requirements,
        }
    }
}

impl Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        EventSer::from(self).serialize(serializer)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventWire {
    pub event_id: EventId,
    pub kind: String,
    /// Absent exactly for `ak.realm.create`; see `Event::realm_id`.
    #[serde(default)]
    pub realm_id: Option<RealmId>,
    pub scope_ref: ScopeRef,
    pub actor_id: ActorId,
    #[serde(default)]
    pub executed_by: Option<ActorId>,
    #[serde(default)]
    pub authorization_ref: Option<AuthorizationRef>,
    #[serde(default)]
    pub applet_id: Option<AppletId>,
    #[serde(default)]
    pub external_ref: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    pub actor_kind: Option<EnvelopeActorKind>,
    pub actor_seq: u64,
    #[serde(deserialize_with = "crate::serde_helpers::deserialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub hlc: Option<Hlc>,
    pub prev_refs: Vec<EventId>,
    #[serde(default)]
    pub refs: Vec<EventRef>,
    #[serde(default)]
    pub causal_refs: Vec<Hash>,
    #[serde(default)]
    pub preconditions: Vec<Precondition>,
    #[serde(default)]
    pub seal_ref: Option<SealId>,
    #[serde(default)]
    pub auth_context: Option<AuthContext>,
    #[serde(default)]
    pub seal_basis: Option<SealBasis>,
    pub payload: BTreeMap<String, Value>,
    #[serde(default)]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<EventProof>,
    #[serde(default)]
    pub requirements: EventRequirements,
}

impl TryFrom<EventWire> for Event {
    type Error = String;

    fn try_from(wire: EventWire) -> std::result::Result<Self, Self::Error> {
        let kind = EventKind::from_wire(&wire.kind);
        // zh/models/realm-and-space.md section 2.5.0: the genesis envelope
        // omits realm_id and receivers derive it from the Event's own id.
        let realm_id = match wire.realm_id {
            Some(realm_id) => {
                if kind == EventKind::RealmCreate {
                    return Err(
                        "realm_id_not_event_derived: ak.realm.create MUST omit realm_id".to_owned(),
                    );
                }
                realm_id
            }
            None => {
                if kind != EventKind::RealmCreate {
                    return Err("realm_id is required".to_owned());
                }
                derive_genesis_realm_id(&wire.event_id)
            }
        };
        let event = Self {
            event_id: wire.event_id,
            kind,
            realm_id,
            scope_ref: wire.scope_ref,
            actor_id: wire.actor_id,
            executed_by: wire.executed_by,
            authorization_ref: wire.authorization_ref,
            applet_id: wire.applet_id,
            external_ref: wire.external_ref,
            actor_kind: wire.actor_kind,
            actor_seq: wire.actor_seq,
            created_at: wire.created_at,
            hlc: wire.hlc,
            prev_refs: wire.prev_refs,
            refs: wire.refs,
            causal_refs: wire.causal_refs,
            preconditions: wire.preconditions,
            seal_ref: wire.seal_ref,
            auth_context: wire.auth_context,
            seal_basis: wire.seal_basis,
            payload: wire.payload,
            unsigned: wire.unsigned,
            proofs: wire.proofs,
            requirements: wire.requirements,
        };
        if event.causal_refs.len() > 128
            || event.causal_refs.iter().collect::<BTreeSet<_>>().len() != event.causal_refs.len()
        {
            return Err("causal_refs must contain at most 128 unique hashes".to_owned());
        }
        if let Some(basis) = &event.seal_basis {
            basis
                .validate_protocol_bounds()
                .map_err(|error| error.to_string())?;
        }
        event.validate_applet_provenance_invariants()?;
        Ok(event)
    }
}

/// Security scope binding used by the protocol wherever a Realm, Circle or Sidecar
/// scope is named (`schemas/event-envelope.schema.json` `$defs.scope_ref` and
/// the byte-identical `effective_scope` definitions of the object schemas).
///
/// On an [`Event`] the value is producer-declared, producer-signed and part of
/// the canonical digest transcript. On a materialized object projection the
/// same value is reducer-written and read-only; the shape is identical, so one
/// type serves both roles and they cannot drift apart.
///
/// The wire form is an internally-tagged JSON object on `kind`:
/// - `{ "kind": "realm", "realm_id": "ak:realm:..." }`
/// - `{ "kind": "circle", "realm_id": "ak:realm:...", "circle_id": "ak:circle:..." }`
/// - `{ "kind": "sidecar", "realm_id": "ak:realm:...", "sidecar_id": "ak:sidecar:..." }`
///
/// `#[non_exhaustive]`: a future spec revision may register additional scope
/// kinds. Downstream `match` expressions MUST carry a `_` arm with
/// fail-closed semantics (treat an unrecognised scope as out-of-scope /
/// denied, never as Realm-wide). Deserialisation itself stays closed-set: an
/// unknown `kind` still fails the parse.
///
/// `#[serde(deny_unknown_fields)]` is deliberate: the schema declares
/// `additionalProperties: false` on both variants, and a signed scope that
/// silently absorbs an unrecognised member would let a producer smuggle
/// unverified routing data through the digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ScopeRef {
    /// Genesis scope for `ak.realm.create` only.
    ///
    /// It carries no `realm_id` because the receiver derives the Realm id from
    /// this Event (collaboration) or the signed actor DID (PCR), per
    /// `zh/models/realm-and-space.md` section 2.5.0. The uniform omission also
    /// prevents the collaboration digest cycle.
    RealmGenesis,
    /// Realm-default security scope.
    Realm { realm_id: RealmId },
    /// The named Circle's security scope inside `realm_id`.
    Circle {
        realm_id: RealmId,
        circle_id: CircleId,
    },
    /// The named Agent Sidecar scope inside `realm_id`.
    Sidecar {
        realm_id: RealmId,
        sidecar_id: SidecarId,
    },
}

impl ScopeRef {
    /// Byte-exact v1 MLS security-scope key.
    ///
    /// Realm and Circle identifiers are already type-separated canonical IDs.
    /// A Sidecar group additionally binds its parent Realm, separated by the
    /// ASCII Unit Separator byte. Genesis has no executable MLS scope.
    pub fn canonical_effective_scope_key_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::RealmGenesis => Err(WireError::Protocol(
                "RealmGenesis has no executable MLS security scope".to_owned(),
            )),
            Self::Realm { realm_id } => Ok(realm_id.as_str().as_bytes().to_vec()),
            Self::Circle { circle_id, .. } => Ok(circle_id.as_str().as_bytes().to_vec()),
            Self::Sidecar {
                realm_id,
                sidecar_id,
            } => {
                let mut key =
                    Vec::with_capacity(realm_id.as_str().len() + 1 + sidecar_id.as_str().len());
                key.extend_from_slice(realm_id.as_str().as_bytes());
                key.push(0x1f);
                key.extend_from_slice(sidecar_id.as_str().as_bytes());
                Ok(key)
            }
        }
    }

    /// Deterministic MLS `group_id` for this effective security scope.
    pub fn canonical_mls_group_id(&self) -> Result<String> {
        Ok(crate::base64url::base64url_encode(
            self.canonical_effective_scope_key_bytes()?,
        ))
    }

    /// The scope's own id, as selected by the registered composite
    /// `cell_subject` of the MLS component cells.
    ///
    /// `event-kind-registry.json` selects on `effective_scope.kind` and takes
    /// `realm_id` / `circle_id` / `sidecar_id` respectively - never the parent
    /// Realm id of a Circle or Sidecar. `RealmGenesis` has no MLS scope.
    pub fn cell_subject_scope_id(&self) -> Result<&str> {
        match self {
            Self::RealmGenesis => Err(WireError::Protocol(
                "RealmGenesis has no executable MLS security scope".to_owned(),
            )),
            Self::Realm { realm_id } => Ok(realm_id.as_str()),
            Self::Circle { circle_id, .. } => Ok(circle_id.as_str()),
            Self::Sidecar { sidecar_id, .. } => Ok(sidecar_id.as_str()),
        }
    }

    /// The parent Realm of this scope when the scope names one.
    ///
    /// `RealmGenesis` returns `None`: the Realm id is receiver-derived, not
    /// carried by the scope. Use [`Event::realm_id`], which resolves both.
    pub fn realm_id_opt(&self) -> Option<&RealmId> {
        match self {
            Self::RealmGenesis => None,
            Self::Realm { realm_id }
            | Self::Circle { realm_id, .. }
            | Self::Sidecar { realm_id, .. } => Some(realm_id),
        }
    }

    /// The parent Realm of this scope.
    ///
    /// # Panics
    /// Panics on `RealmGenesis`, which has no carried Realm id. Call
    /// [`Self::realm_id_opt`] when the scope may be a genesis scope.
    pub fn realm_id(&self) -> &RealmId {
        self.realm_id_opt()
            .expect("realm genesis scope carries no realm_id; use realm_id_opt")
    }

    /// The Circle id when this scope is a Circle, otherwise `None`.
    pub fn circle_id(&self) -> Option<&CircleId> {
        match self {
            Self::RealmGenesis | Self::Realm { .. } | Self::Sidecar { .. } => None,
            Self::Circle { circle_id, .. } => Some(circle_id),
        }
    }

    /// The Sidecar id when this scope is a native Sidecar, otherwise `None`.
    pub fn sidecar_id(&self) -> Option<&SidecarId> {
        match self {
            Self::Sidecar { sidecar_id, .. } => Some(sidecar_id),
            Self::RealmGenesis | Self::Realm { .. } | Self::Circle { .. } => None,
        }
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_effective_scope`.
///
/// The closed subset of [`ScopeRef`] admitted by the private history-key
/// request/response, history-only backup and organization-recovery archive
/// contracts. `RealmGenesis` has no executable MLS scope and Sidecar is
/// deliberately excluded: its profile fixes `mls_rfc9420` and defines neither
/// `history_access` nor a deliverable history secret.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryEffectiveScope {
    Realm {
        realm_id: RealmId,
    },
    Circle {
        realm_id: RealmId,
        circle_id: CircleId,
    },
}

impl HistoryEffectiveScope {
    /// The parent Realm of this scope.
    pub fn realm_id(&self) -> &RealmId {
        match self {
            Self::Realm { realm_id } | Self::Circle { realm_id, .. } => realm_id,
        }
    }

    /// The Circle id when this scope is a Circle, otherwise `None`.
    pub fn circle_id(&self) -> Option<&CircleId> {
        match self {
            Self::Realm { .. } => None,
            Self::Circle { circle_id, .. } => Some(circle_id),
        }
    }

    /// Deterministic MLS `group_id` for this effective security scope.
    pub fn canonical_mls_group_id(&self) -> Result<String> {
        ScopeRef::from(self.clone()).canonical_mls_group_id()
    }
}

impl From<HistoryEffectiveScope> for ScopeRef {
    fn from(scope: HistoryEffectiveScope) -> Self {
        match scope {
            HistoryEffectiveScope::Realm { realm_id } => Self::Realm { realm_id },
            HistoryEffectiveScope::Circle {
                realm_id,
                circle_id,
            } => Self::Circle {
                realm_id,
                circle_id,
            },
        }
    }
}

impl TryFrom<ScopeRef> for HistoryEffectiveScope {
    type Error = WireError;

    fn try_from(scope: ScopeRef) -> Result<Self> {
        match scope {
            ScopeRef::Realm { realm_id } => Ok(Self::Realm { realm_id }),
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => Ok(Self::Circle {
                realm_id,
                circle_id,
            }),
            ScopeRef::RealmGenesis | ScopeRef::Sidecar { .. } => Err(WireError::Protocol(
                "scope is not an admitted history effective scope".to_owned(),
            )),
        }
    }
}

#[cfg(test)]
mod scope_mls_group_id_tests {
    use super::*;

    #[test]
    fn effective_scope_keys_are_byte_exact_and_genesis_is_rejected() {
        let realm_id =
            RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5").unwrap();
        let circle_id =
            CircleId::new("ak:circle:AXy9G1HY-05VpUDBKqm77h_Vu7DiFOJ3sduNSXuFewp_").unwrap();
        let sidecar_id =
            SidecarId::new("ak:sidecar:Ae0kN-KHls3vjqQ9FHo4P_2uAhcMVu8dI8qHcFsqGn5d").unwrap();

        let realm = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        assert_eq!(
            realm.canonical_effective_scope_key_bytes().unwrap(),
            realm_id.as_str().as_bytes()
        );
        assert_eq!(
            realm.canonical_mls_group_id().unwrap(),
            crate::base64url::base64url_encode(realm_id.as_str().as_bytes())
        );

        let circle = ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        };
        assert_eq!(
            circle.canonical_effective_scope_key_bytes().unwrap(),
            circle_id.as_str().as_bytes()
        );

        let sidecar = ScopeRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: sidecar_id.clone(),
        };
        let expected = format!("{}\u{1f}{}", realm_id.as_str(), sidecar_id.as_str());
        assert_eq!(
            sidecar.canonical_effective_scope_key_bytes().unwrap(),
            expected.as_bytes()
        );
        assert_ne!(
            sidecar.canonical_mls_group_id().unwrap(),
            realm.canonical_mls_group_id().unwrap()
        );
        assert!(ScopeRef::RealmGenesis.canonical_mls_group_id().is_err());
    }
}

/// CBA context a structural submit check runs under.
///
/// `Standard` is the fail-closed default: every reducer-input Event must be a
/// DataEvent or a Control Move. `AnchorUnit` additionally admits the two closed
/// `seal_basis`-exempt units of `event-auth-state-resolution.md` §5 and MUST NOT
/// be used for anything else.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EventSubmitContext {
    #[default]
    Standard,
    AnchorUnit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventProofSetRequirement {
    ProducerSubmission,
    AcceptedEvent,
}

/// A canonical-shaped `event_id` that stands in while the real one is being
/// derived. It never enters a digest preimage, so its value is arbitrary — it
/// only has to parse.
const PLACEHOLDER_EVENT_ID: &str = "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

impl Event {
    pub const SCHEMA: &'static str = SchemaId::EVENT_V1;
    /// Deserialize an inbound Event Envelope after canonical JSON ingress
    /// checks (NFC strings, duplicate keys, number profile).
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }

    /// Reconstruct the unsigned Event represented by canonical digest-payload
    /// bytes returned by a protocol prepare operation.
    ///
    /// Prepare drafts intentionally omit fields outside the producer-signed
    /// transcript. This constructor is the only SDK path that restores those
    /// fields before a caller appends proofs, so downstream clients never need
    /// to patch JSON objects themselves.
    pub fn from_digest_payload_bytes(
        bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        let mut value: Value = serde_json::from_slice(bytes)?;
        let object = value.as_object_mut().ok_or_else(|| {
            WireError::Protocol("Event digest payload must be a JSON object".to_owned())
        })?;
        for forbidden in ["proofs", "unsigned", "actor_kind"] {
            if object.contains_key(forbidden) {
                return Err(WireError::Protocol(format!(
                    "Event digest payload must omit {forbidden}"
                )));
            }
        }
        object.insert("proofs".to_owned(), Value::Array(Vec::new()));
        // `event_id` is not in the preimage either — section 4.0 derives it
        // *from* this digest — so it cannot be read off these bytes. Reconstruct
        // it the only way there is: seed the parse with a placeholder, then
        // stamp the derived value. This is what makes the round-trip total.
        object.insert(
            "event_id".to_owned(),
            Value::String(PLACEHOLDER_EVENT_ID.to_owned()),
        );
        let mut event: Self = serde_json::from_value(value)?;
        event.event_id = event.derive_event_id_with_digest_suite(digest_suite)?;
        let canonical = arkret_canonical::canonical_json_bytes(&event.digest_payload()?)?;
        if canonical != bytes {
            return Err(WireError::Protocol(
                "Event digest payload bytes are not canonical".to_owned(),
            ));
        }
        Ok(event)
    }

    /// Top-level Envelope fields that are stamped by the reducer AFTER the
    /// producer signs, and therefore MUST NOT enter the signature/digest
    /// input (otherwise a federated peer independently recomputing the
    /// digest would mismatch the producer's `proof.event_digest`).
    ///
    /// Kept in lockstep with `conformance/encoding.md` §2 / §6. v1 has exactly
    /// one such field: `actor_kind`. `scope_ref` is producer-signed and MUST
    /// stay inside the transcript.
    ///
    /// Deliberately private: it is one *part* of the exclusion rule, and every
    /// caller that ever held it went on to hand-roll the rest of
    /// [`event_digest_preimage`] — and each hand-rolled copy drifted. Callers
    /// outside this module get the whole rule or nothing.
    const REDUCER_STAMPED_TOP_LEVEL_FIELDS: [&'static str; 1] = ["actor_kind"];

    pub fn digest_payload(&self) -> Result<Value> {
        event_digest_preimage(&serde_json::to_value(self)?)
    }

    /// Refresh the content-bound Event id after authoring has finished.
    ///
    /// Producers commonly have to attach actor-chain, HLC, CBA and requirement
    /// fields after constructing the initial typed payload. All of those fields
    /// are in the Event digest preimage, so the id must be derived only after
    /// they are final. A Realm genesis additionally keeps its in-memory derived
    /// Realm id in sync with the refreshed Event id.
    /// Refresh the content-bound identity under the trusted Realm digest suite.
    pub fn refresh_content_bound_identity_with_digest_suite(
        &mut self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.event_id = self.derive_event_id_with_digest_suite(digest_suite)?;
        if self.scope_ref == ScopeRef::RealmGenesis {
            self.realm_id = derive_genesis_realm_id(&self.event_id);
        }
        Ok(())
    }

    /// Derive this Event's `event_id` under the Realm's declared digest suite.
    pub fn derive_event_id_with_digest_suite(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<EventId> {
        let digest = self.event_digest_with_digest_suite(digest_suite)?;
        let hex = digest
            .split_once(':')
            .map(|(_, rest)| rest)
            .ok_or_else(|| {
                WireError::Protocol("event digest must carry a suite prefix".to_owned())
            })?;
        if hex.len() != 64 {
            return Err(WireError::Protocol(
                "Event ID format requires a 32-octet event digest".to_owned(),
            ));
        }
        let octets = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<std::result::Result<Vec<u8>, _>>()
            .map_err(|_| WireError::Protocol("event digest is not lowercase hex".to_owned()))?;
        let digest_bytes: [u8; 32] = octets.try_into().map_err(|_| {
            WireError::Protocol("Event ID format requires a 32-octet event digest".to_owned())
        })?;
        Ok(EventId::from_digest(digest_suite, digest_bytes))
    }

    /// Re-derive the id under the trusted Realm digest suite and compare it with
    /// the carried value.
    ///
    /// `encoding.md` §6 makes the *order* a security property: a receiver MUST
    /// run this before using `event_id` for deduplication, indexing, routing,
    /// idempotency or authorization. Skipping it lets a caller-chosen identity
    /// enter those paths without proving its complete digest binding.
    pub fn verify_event_id_matches_content_with_digest_suite(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        let derived = self.derive_event_id_with_digest_suite(digest_suite)?;
        if derived == self.event_id {
            Ok(())
        } else {
            Err(WireError::Protocol(
                "event_id_digest_mismatch: carried event_id does not equal the value re-derived                  from this Event's own canonical content"
                    .to_owned(),
            ))
        }
    }

    /// Compute the Event digest with the trusted Realm digest suite.
    ///
    /// The suite is supplied by the caller because the Event is not trusted
    /// until its proof has been verified; it must not be inferred from the
    /// Event payload.
    pub fn event_digest_with_digest_suite(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<String> {
        let bytes = canonical::canonical_json_bytes(&self.digest_payload()?)?;
        Ok(canonical::digest(digest_suite, &bytes))
    }

    /// Structural (payload-agnostic) submit gate.
    ///
    /// Covers every wire-level check that does not need a schema registry:
    /// reducer-stamped field rejection, applet provenance invariants, proof
    /// presence, critical-extension fail-closed flags, and CBA field shape.
    /// It deliberately does NOT run event-payload schema validation — the
    /// submit gate for callers is `arkret_schema::validate_event_for_submit`,
    /// which layers registry-backed schema validation on top of this check.
    /// Keeping schema validation out of this crate (and out of the
    /// deserialization path) is what prevents an arkret-schema dependency
    /// cycle; do not reintroduce it here.
    pub fn validate_for_submit_structural(&self) -> Result<()> {
        self.validate_for_submit_structural_in_context(EventSubmitContext::Standard)
    }

    /// Validate a retained direct-regime Event that has no Station
    /// admission proof. Its sole producer proof must carry the matching
    /// content-addressed historical signer-resolution evidence locator.
    pub fn validate_for_direct_history_structural(&self) -> Result<()> {
        self.validate_for_direct_history_structural_in_context(EventSubmitContext::Standard)
    }

    pub fn validate_for_direct_history_structural_in_context(
        &self,
        context: EventSubmitContext,
    ) -> Result<()> {
        self.validate_structural_in_context(context, EventProofSetRequirement::ProducerSubmission)?;
        let [EventProof::Producer(producer)] = self.proofs.as_slice() else {
            unreachable!("producer proof set was validated above")
        };
        producer.validate_direct_signer_resolution_evidence()
    }

    /// [`Event::validate_for_submit_structural`] under an explicit CBA context.
    ///
    /// Use [`EventSubmitContext::AnchorUnit`] only for the two closed
    /// `seal_basis`-exempt anchor units of `event-auth-state-resolution.md` §5:
    /// the `ak.realm.create` bootstrap with its closed follow-up whitelist, and
    /// the B-model `ak.device.reanchor` + replacement-authorize unit, which
    /// fixes its frontier in the payload's `pre_fence_seal_frontier` instead.
    ///
    /// Deciding whether an Event *is* one of those needs the closed kind
    /// whitelist, which lives in the registry; this crate does not hold it by
    /// layering. So the context is a claim by the caller, and the caller owes
    /// the whitelist check — `arkret_policy::validate_realm_bootstrap_unit` is
    /// the one that owns it for the ordinary Realm branch. Passing
    /// `AnchorUnit` for anything else opens a hole this crate cannot see.
    pub fn validate_for_submit_structural_in_context(
        &self,
        context: EventSubmitContext,
    ) -> Result<()> {
        self.validate_structural_in_context(context, EventProofSetRequirement::ProducerSubmission)
    }

    /// Validate the wire-level shape of an Event already admitted by its
    /// declared origin Station.
    pub fn validate_for_federation_structural_in_context(
        &self,
        context: EventSubmitContext,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.validate_structural_in_context(context, EventProofSetRequirement::AcceptedEvent)?;
        self.validate_station_admission_binding(digest_suite)
    }

    fn validate_structural_in_context(
        &self,
        context: EventSubmitContext,
        proof_requirement: EventProofSetRequirement,
    ) -> Result<()> {
        // zh/models/realm-and-space.md section 2.5.0: the genesis scope carries
        // no realm_id, so the equality check applies to every other kind and
        // the genesis branch instead pins the closed scope shape.
        if self.kind == EventKind::RealmCreate {
            if self.scope_ref != ScopeRef::RealmGenesis {
                return Err(WireError::Protocol(
                    "ak.realm.create MUST use the realm_genesis scope".to_owned(),
                ));
            }
        } else if self.scope_ref.realm_id_opt() != Some(&self.realm_id) {
            return Err(WireError::Protocol(
                "event scope_ref.realm_id must equal the envelope realm_id".to_owned(),
            ));
        }
        if self.actor_kind.is_some() {
            return Err(WireError::Protocol(
                ReasonCode::ACTOR_KIND_REDUCER_MANAGED.to_owned(),
            ));
        }
        self.validate_applet_provenance_invariants()
            .map_err(WireError::Protocol)?;
        match proof_requirement {
            EventProofSetRequirement::ProducerSubmission => match self.proofs.as_slice() {
                [EventProof::Producer(producer)] => {
                    producer.validate_signer_resolution_evidence_pair()?;
                }
                _ => {
                    return Err(WireError::Protocol(
                        "caller submission must carry exactly one producer proof and no Station admission proof"
                            .to_owned(),
                    ));
                }
            },
            EventProofSetRequirement::AcceptedEvent => match self.proofs.as_slice() {
                [
                    EventProof::Producer(producer),
                    EventProof::StationAdmission(_),
                ] => {
                    if producer.signer_resolution_evidence_ref.is_some()
                        || producer.signer_resolution_evidence_digest.is_some()
                    {
                        return Err(WireError::Protocol(
                            "admission-backed producer proof must omit direct signer resolution evidence"
                                .to_owned(),
                        ));
                    }
                }
                _ => {
                    return Err(WireError::Protocol(
                        "federated Event must carry exactly one producer proof followed by one Station admission proof"
                            .to_owned(),
                    ));
                }
            },
        }
        if self
            .requirements
            .critical_extensions
            .iter()
            .any(|extension| !extension.fail_closed)
        {
            return Err(WireError::Protocol(
                "event critical extensions must declare fail_closed=true".to_owned(),
            ));
        }
        if let Some(basis) = &self.seal_basis {
            basis.validate_protocol_bounds()?;
        }
        if self.kind.is_reducer_input() {
            let is_data_event = self.seal_ref.is_some()
                && self.auth_context.is_some()
                && self.seal_basis.is_none()
                && self.preconditions.is_empty();
            let is_control_move =
                self.seal_ref.is_none() && self.auth_context.is_none() && self.seal_basis.is_some();
            // The §5 anchor units carry no basis field at all: bootstrap has no
            // accepted Seal to point at, and the B-model re-anchor fixes its
            // frontier in the payload's `pre_fence_seal_frontier`. A bootstrap Event
            // may still carry a precondition, which is evaluated against the
            // unit's empty frozen predecessor state; only the three mutually
            // exclusive CBA basis fields participate in this shape test.
            let is_anchor_unit = context == EventSubmitContext::AnchorUnit
                && self.seal_ref.is_none()
                && self.auth_context.is_none()
                && self.seal_basis.is_none();
            match self.kind.cba_plane() {
                Some(CbaEffectPlane::Data) if is_data_event || is_anchor_unit => {}
                Some(CbaEffectPlane::Control) if is_control_move || is_anchor_unit => {}
                Some(CbaEffectPlane::Data) => {
                    return Err(WireError::Protocol(format!(
                        "data-plane Event kind {} requires seal_ref + auth_context and forbids seal_basis",
                        self.kind
                    )));
                }
                Some(CbaEffectPlane::Control) => {
                    return Err(WireError::Protocol(format!(
                        "control-plane Event kind {} requires seal_basis and forbids seal_ref + auth_context",
                        self.kind
                    )));
                }
                None => {
                    return Err(WireError::Protocol(format!(
                        "reducer-input Event kind {} has no registered CBA plane",
                        self.kind
                    )));
                }
            }
        } else if self.seal_ref.is_some()
            || self.auth_context.is_some()
            || self.seal_basis.is_some()
            || !self.preconditions.is_empty()
        {
            return Err(WireError::Protocol(
                "non-reducer events must not carry CBA reducer fields".to_owned(),
            ));
        }
        Ok(())
    }

    /// Enforce the signed-Applet-provenance invariants from
    /// `event-envelope.schema.json` (`allOf` §262): `external_ref` is only
    /// meaningful when bound to a signed `applet_id`, and any Applet-originated
    /// write (`applet_id` present) MUST cite the accepted authorization grant
    /// via `authorization_ref`.
    fn validate_applet_provenance_invariants(&self) -> std::result::Result<(), String> {
        if self.external_ref.is_some() && self.applet_id.is_none() {
            return Err(
                "event external_ref requires a signed applet_id (event-envelope allOf)".to_owned(),
            );
        }
        if self.applet_id.is_some() && self.authorization_ref.is_none() {
            return Err(
                "event applet_id requires authorization_ref (event-envelope allOf)".to_owned(),
            );
        }
        Ok(())
    }

    /// Validate proof bindings with the trusted Realm digest suite.
    pub fn validate_proof_bindings_with_digest_suite(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        let digest = self.event_digest_with_digest_suite(digest_suite)?;
        let expected_hash = Hash::new(digest)?;
        for proof in &self.proofs {
            let Some(proof) = proof.as_producer() else {
                continue;
            };
            proof.validate()?;
            if proof.event_digest != expected_hash {
                return Err(WireError::Protocol(format!(
                    "event proof event_digest '{}' does not match event digest '{}'",
                    proof.event_digest, expected_hash
                )));
            }
        }
        Ok(())
    }

    pub fn validate_proof_bindings_with_context_and_digest_suite(
        &self,
        domain: Option<String>,
        audience: Option<Audience>,
        requirements: ProofBindingRequirements,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        let expected_hash = Hash::new(self.event_digest_with_digest_suite(digest_suite)?)?;
        for proof in self.proofs.iter().filter_map(EventProof::as_producer) {
            let expected = SignatureBindingPayload {
                payload_digest: expected_hash.clone(),
                actor_id: self.actor_id.clone(),
                verification_method: proof.verification_method.clone(),
                created_at: proof.created_at,
                domain: domain.clone(),
                audience: audience.clone(),
            };
            proof.validate_binding_with_requirements(&expected, requirements)?;
        }
        Ok(())
    }

    /// Validate the closed accepted-Event proof set: exactly one producer
    /// proof followed by exactly one origin Station admission proof.
    pub fn validate_station_admission_binding(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        let expected_event_digest = Hash::new(self.event_digest_with_digest_suite(digest_suite)?)?;
        let [
            EventProof::Producer(producer),
            EventProof::StationAdmission(admission),
        ] = self.proofs.as_slice()
        else {
            return Err(WireError::Protocol(
                "accepted event must contain one producer proof followed by one Station admission proof"
                    .to_owned(),
            ));
        };
        producer.validate()?;
        if producer.event_digest != expected_event_digest {
            return Err(WireError::Protocol(
                "producer proof event digest does not match accepted event".to_owned(),
            ));
        }
        let author = self.executed_by.as_ref().unwrap_or(&self.actor_id);
        admission.validate_binding(&expected_event_digest, producer, author.route_service_id())
    }

    /// Construct an Event in the given signed security scope.
    ///
    /// `realm_id` is taken from `scope_ref` so the envelope cannot be built
    /// with a Realm that disagrees with its own signed scope.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn new(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: ActorId,
        actor_seq: u64,
        hlc: Hlc,
        payload: Value,
    ) -> Result<Self> {
        Self::new_at(
            kind,
            scope_ref,
            actor_id,
            actor_seq,
            hlc,
            payload,
            Utc::now(),
        )
    }

    /// Construct an Event at a caller-supplied instant.
    ///
    /// The instant is truncated to the fixed millisecond precision required by
    /// the Event wire profile before it is stored on the typed envelope. This
    /// is the deterministic authoring entry point for callers that need an
    /// object timestamp and its containing Event to share one exact instant.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_at(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: ActorId,
        actor_seq: u64,
        hlc: Hlc,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new_with_derived_id_at(
            kind, scope_ref, actor_id, actor_seq, hlc, payload, created_at,
        )
    }

    /// Construct an Event whose `event_id` is derived from its own content.
    ///
    /// This is the only authoring entry point for ordinary Events: the id is
    /// not a caller choice (`encoding.md` §4.0). It builds the envelope with a
    /// placeholder id, computes the digest over the preimage — which excludes
    /// `event_id` — and then stamps the derived id.
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn new_with_derived_id_at(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: ActorId,
        actor_seq: u64,
        hlc: Hlc,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        // The placeholder never enters the digest preimage, so any valid id
        // works here; it is overwritten before the Event is observable.
        let placeholder = EventId::new(PLACEHOLDER_EVENT_ID)
            .expect("placeholder id is a canonical content-bound shape");
        let mut event = Self::new_unstamped_at(
            placeholder,
            kind,
            scope_ref,
            actor_id,
            actor_seq,
            hlc,
            payload,
            created_at,
        )?;
        event.event_id =
            event.derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
        // A genesis scope names no Realm, so `realm_id` was computed from the
        // placeholder id above; recompute it now that the real id is known.
        if event.scope_ref.realm_id_opt().is_none() {
            event.realm_id = derive_genesis_realm_id(&event.event_id);
        }
        Ok(event)
    }

    /// Internal first pass used only while deriving the content-bound id.
    /// No public API may expose an Event with this placeholder identity.
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "test-support"))]
    fn new_unstamped_at(
        event_id: EventId,
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: ActorId,
        actor_seq: u64,
        hlc: Hlc,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        let Value::Object(payload) = payload else {
            return Err(WireError::Protocol(
                "event payload must be a JSON object".to_owned(),
            ));
        };
        let kind = EventKind::from_wire(&kind.into());
        // A genesis scope names no Realm; the Realm id comes from this Event.
        let realm_id = match scope_ref.realm_id_opt() {
            Some(realm_id) => realm_id.clone(),
            None => derive_genesis_realm_id(&event_id),
        };
        Ok(Self {
            event_id,
            kind,
            realm_id,
            scope_ref,
            actor_id,
            actor_seq,
            created_at: canonical::normalize_timestamp_canonical(created_at),
            hlc: Some(hlc),
            prev_refs: Vec::new(),
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            payload: payload.into_iter().collect(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        })
    }
}

#[cfg(test)]
mod event_wire_surface_tests {
    //! Guard the Event Envelope wire surface against removed non-spec fields.

    use serde_json::json;

    use super::*;
    use crate::{AccountId, ProducerEventProof};

    fn realm() -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x65; 32],
        ))
    }

    fn realm_scope() -> ScopeRef {
        ScopeRef::Realm { realm_id: realm() }
    }

    fn alice() -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
        ))
    }

    fn base_event() -> Event {
        let seed_event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0xa0; 32]);
        let strand_id = arkret_identifiers::StrandId::from_event_id(&seed_event);
        Event {
            event_id: seed_event,
            kind: "ak.message.create".into(),
            realm_id: realm(),
            scope_ref: realm_scope(),
            actor_id: alice(),
            actor_seq: 1,
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            hlc: Some(Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()),
            prev_refs: Vec::new(),
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            payload: serde_json::from_value(json!({
                "strand_id": strand_id,
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }))
            .unwrap(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        }
    }

    fn producer_proof() -> EventProof {
        EventProof::Producer(ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        })
    }

    #[test]
    fn prepared_digest_payload_reconstructs_only_the_unsigned_event() {
        // The round-trip is only total for an Event that carries its own
        // derived id — which every wire Event must (section 4.0). Stamp it, so
        // the fixture is a legal Event rather than one with a made-up id.
        let mut event = base_event();
        event.event_id = event
            .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let bytes = canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        let reconstructed =
            Event::from_digest_payload_bytes(&bytes, arkret_canonical::DigestSuite::Sha256)
                .unwrap();

        assert_eq!(reconstructed, event);
        assert!(reconstructed.proofs.is_empty());
        assert!(reconstructed.unsigned.is_empty());
        assert!(reconstructed.actor_kind.is_none());
    }

    #[test]
    fn prepared_digest_payload_rejects_out_of_transcript_fields_and_noncanonical_json() {
        let mut with_proofs = base_event().digest_payload().unwrap();
        with_proofs["proofs"] = json!([]);
        let bytes = canonical::canonical_json_bytes(&with_proofs).unwrap();
        assert!(
            Event::from_digest_payload_bytes(&bytes, arkret_canonical::DigestSuite::Sha256,)
                .is_err()
        );

        let canonical =
            canonical::canonical_json_bytes(&base_event().digest_payload().unwrap()).unwrap();
        let mut spaced = Vec::with_capacity(canonical.len() + 1);
        spaced.extend_from_slice(b" ");
        spaced.extend_from_slice(&canonical);
        assert!(
            Event::from_digest_payload_bytes(&spaced, arkret_canonical::DigestSuite::Sha256,)
                .is_err()
        );
    }

    #[test]
    fn event_new_serializes_created_at_in_canonical_utc_millisecond_form() {
        let mut event = Event::new(
            "ak.message.create",
            realm_scope(),
            alice(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"body": "hello"}),
        )
        .unwrap();
        let whole_second = "2026-06-03T12:34:56.000Z".parse().unwrap();
        event.created_at = whole_second;
        event.proofs.push(EventProof::Producer(ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at: whole_second,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }));
        let value = serde_json::to_value(&event).unwrap();
        let created_at = value["created_at"].as_str().unwrap();

        assert_eq!(created_at, "2026-06-03T12:34:56.000Z");
        assert_eq!(value["proofs"][0]["created_at"], created_at);
        canonical::validate_timestamp_canonical(created_at).unwrap();
        serde_json::from_value::<Event>(value.clone()).unwrap();

        let mut seconds = value.clone();
        seconds["created_at"] = json!("2026-06-03T12:34:56Z");
        assert!(serde_json::from_value::<Event>(seconds).is_err());

        let mut micros = value;
        micros["proofs"][0]["created_at"] = json!("2026-06-03T12:34:56.000123Z");
        assert!(serde_json::from_value::<Event>(micros).is_err());
    }

    #[test]
    fn event_new_at_normalizes_the_supplied_instant_before_serialization() {
        let created_at = "2026-06-03T12:34:56.987654Z".parse().unwrap();
        let event = Event::new_at(
            "ak.message.create",
            realm_scope(),
            alice(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"body": "hello"}),
            created_at,
        )
        .unwrap();

        assert_eq!(
            event.created_at,
            "2026-06-03T12:34:56.987Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            serde_json::to_value(event).unwrap()["created_at"],
            json!("2026-06-03T12:34:56.987Z")
        );
    }

    #[test]
    fn event_new_at_derives_and_verifies_the_identifier() {
        let event = Event::new_at(
            "ak.message.create",
            realm_scope(),
            alice(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"body": "hello"}),
            "2026-06-03T12:34:56.000Z".parse().unwrap(),
        )
        .unwrap();

        event
            .verify_event_id_matches_content_with_digest_suite(
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(event).unwrap()["created_at"],
            json!("2026-06-03T12:34:56.000Z")
        );
    }

    #[test]
    fn event_ingress_enforces_causal_ref_uniqueness_and_bound() {
        let mut duplicate = serde_json::to_value(base_event()).unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        duplicate["causal_refs"] = json!([digest.clone(), digest]);
        let error = serde_json::from_value::<Event>(duplicate).unwrap_err();
        assert!(error.to_string().contains("causal_refs"), "{error}");

        let refs = (0_u64..=128)
            .map(|index| format!("sha256:{index:064x}"))
            .collect::<Vec<_>>();
        let mut at_limit = serde_json::to_value(base_event()).unwrap();
        at_limit["causal_refs"] = json!(refs[..128]);
        serde_json::from_value::<Event>(at_limit).unwrap();

        let mut over_limit = serde_json::to_value(base_event()).unwrap();
        over_limit["causal_refs"] = json!(refs);
        let error = serde_json::from_value::<Event>(over_limit).unwrap_err();
        assert!(error.to_string().contains("causal_refs"), "{error}");
    }

    #[test]
    fn event_serialization_omits_applet_surface_when_absent() {
        let event = base_event();
        let serialized = serde_json::to_value(&event).unwrap();
        assert!(serialized.get("applet_id").is_none());
        assert!(serialized.get("external_ref").is_none());
    }

    #[test]
    fn event_accepts_top_level_applet_provenance_and_round_trips() {
        // Applet-originated write: applet_id + external_ref, with the
        // authorization_ref the schema invariant requires.
        let mut event = base_event();
        event.applet_id =
            Some(AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap());
        event.authorization_ref = Some(
            AuthorizationRef::new("ak:grant:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM").unwrap(),
        );
        event.external_ref = Some(BTreeMap::from([
            ("protocol".to_owned(), json!("slack")),
            ("external_id".to_owned(), json!("1234567890.0001")),
        ]));

        let value = serde_json::to_value(&event).unwrap();
        // Both fields serialize at the top level (so they enter canonical bytes).
        assert_eq!(
            value.get("applet_id").and_then(Value::as_str),
            Some("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb")
        );
        assert!(value.get("external_ref").unwrap().is_object());

        // Round-trips through the wire deserializer (deny_unknown_fields).
        let round_tripped: Event = serde_json::from_value(value).unwrap();
        assert_eq!(round_tripped, event);

        // Both fields enter the digest payload (proofs/unsigned removed only).
        let digest_payload = event.digest_payload().unwrap();
        assert!(digest_payload.get("applet_id").is_some());
        assert!(digest_payload.get("external_ref").is_some());
        // Mutating external_ref changes the event digest (it is covered).
        let mut mutated = event.clone();
        mutated.external_ref = Some(BTreeMap::from([
            ("protocol".to_owned(), json!("slack")),
            ("external_id".to_owned(), json!("different")),
        ]));
        assert_ne!(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            mutated
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap()
        );
    }

    #[test]
    fn actor_kind_is_the_only_field_outside_the_signed_transcript() {
        // `actor_kind` is stamped by the reducer AFTER the producer signs, so
        // it MUST NOT change the `event_digest`; a federated peer recomputing
        // the digest from the accepted envelope must reach the same value.
        // See `encoding.md` §2 / §6.
        let event = base_event();
        let baseline = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();

        let mut stamped = event;
        stamped.actor_kind = Some(EnvelopeActorKind::Agent);

        assert_eq!(
            baseline,
            stamped
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap()
        );
        let digest_payload = stamped.digest_payload().unwrap();
        assert!(digest_payload.get("actor_kind").is_none());
        assert!(digest_payload.get("proofs").is_none());
        assert!(digest_payload.get("unsigned").is_none());
    }

    #[test]
    fn signed_scope_ref_is_covered_by_the_event_digest() {
        let event = base_event();
        let baseline = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        assert!(event.digest_payload().unwrap().get("scope_ref").is_some());

        let mut rescoped = event;
        rescoped.scope_ref = ScopeRef::Circle {
            realm_id: realm(),
            circle_id: CircleId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x1c; 32],
            )),
        };

        assert_ne!(
            baseline,
            rescoped
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap()
        );
    }

    #[test]
    fn event_wire_rejects_a_missing_scope_ref() {
        let mut value = serde_json::to_value(base_event()).unwrap();
        value.as_object_mut().unwrap().remove("scope_ref");

        let err = serde_json::from_value::<Event>(value).unwrap_err();
        assert!(err.to_string().contains("scope_ref"), "{err}");
    }

    #[test]
    fn event_wire_rejects_the_deleted_producer_reducer_instruction_fields() {
        for field in ["effects", "conflict_keys_digest", "effective_scope"] {
            let mut value = serde_json::to_value(base_event()).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), json!([]));
            let err = serde_json::from_value::<Event>(value)
                .expect_err("removed wire field must fail deserialization");
            assert!(err.to_string().contains(field), "{field}: {err}");
        }
    }

    #[test]
    fn event_rejects_external_ref_without_applet_id() {
        let event = base_event();
        let mut value = serde_json::to_value(&event).unwrap();
        value.as_object_mut().unwrap().insert(
            "external_ref".to_owned(),
            json!({ "protocol": "slack", "external_id": "1234567890.0001" }),
        );
        let err = serde_json::from_value::<Event>(value).unwrap_err();
        assert!(
            err.to_string()
                .contains("external_ref requires a signed applet_id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn event_rejects_applet_id_without_authorization_ref() {
        let event = base_event();
        let mut value = serde_json::to_value(&event).unwrap();
        value.as_object_mut().unwrap().insert(
            "applet_id".to_owned(),
            json!("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"),
        );
        let err = serde_json::from_value::<Event>(value).unwrap_err();
        assert!(
            err.to_string()
                .contains("applet_id requires authorization_ref"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn submit_rejects_actor_supplied_actor_kind() {
        let mut event = base_event();
        event.actor_kind = Some(EnvelopeActorKind::Agent);

        let err = event.validate_for_submit_structural().unwrap_err();
        assert!(
            err.to_string()
                .contains(ReasonCode::ACTOR_KIND_REDUCER_MANAGED),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn submit_rejects_a_scope_ref_that_disagrees_with_the_envelope_realm() {
        let mut event = base_event();
        event.scope_ref = ScopeRef::Realm {
            realm_id: RealmId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0xff; 32],
            )),
        };

        let err = event.validate_for_submit_structural().unwrap_err();
        assert!(
            err.to_string().contains("scope_ref.realm_id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn standard_submit_uses_the_registry_plane_instead_of_the_envelope_shape() {
        let seal_id = SealId::new(format!("ak:seal:sha256:{}", "1".repeat(64))).unwrap();

        let mut data_kind_with_control_shape = base_event();
        data_kind_with_control_shape.proofs.push(producer_proof());
        data_kind_with_control_shape.seal_basis = Some(SealBasis {
            leaves: vec![seal_id.clone()],
        });
        let error = data_kind_with_control_shape
            .validate_for_submit_structural()
            .expect_err("data kind must not be reclassified by a control-shaped envelope");
        assert!(
            error.to_string().contains("data-plane Event kind"),
            "{error}"
        );

        let mut control_kind_with_data_shape = base_event();
        control_kind_with_data_shape.kind = EventKind::RealmPolicy;
        control_kind_with_data_shape.proofs.push(producer_proof());
        control_kind_with_data_shape.seal_ref = Some(seal_id);
        control_kind_with_data_shape.auth_context = Some(AuthContext {
            key_id: OpaqueLocalId::new("device").unwrap(),
            key_epoch: 0,
            credential_epoch: None,
        });
        let error = control_kind_with_data_shape
            .validate_for_submit_structural()
            .expect_err("control kind must not be reclassified by a data-shaped envelope");
        assert!(
            error.to_string().contains("control-plane Event kind"),
            "{error}"
        );
    }

    #[test]
    fn every_registered_kind_accepts_only_its_declared_cba_shape() {
        let seal_id = SealId::new(format!("ak:seal:sha256:{}", "2".repeat(64))).unwrap();
        for kind in EventKind::ALL {
            let mut matching = base_event();
            matching.kind = kind.clone();
            matching.proofs.push(producer_proof());
            matching.seal_ref = None;
            matching.auth_context = None;
            matching.seal_basis = None;
            matching.preconditions.clear();
            if *kind == EventKind::RealmCreate {
                matching.scope_ref = ScopeRef::RealmGenesis;
            }
            match kind.cba_plane() {
                Some(CbaEffectPlane::Data) => {
                    matching.seal_ref = Some(seal_id.clone());
                    matching.auth_context = Some(AuthContext {
                        key_id: OpaqueLocalId::new("device").unwrap(),
                        key_epoch: 0,
                        credential_epoch: None,
                    });
                }
                Some(CbaEffectPlane::Control) => {
                    matching.seal_basis = Some(SealBasis {
                        leaves: vec![seal_id.clone()],
                    });
                }
                None => {}
            }
            matching
                .validate_for_submit_structural()
                .unwrap_or_else(|error| panic!("matching shape rejected for {kind}: {error}"));

            let mut mismatched = matching;
            let expected_error = match kind.cba_plane() {
                Some(CbaEffectPlane::Data) => {
                    mismatched.seal_ref = None;
                    mismatched.auth_context = None;
                    mismatched.seal_basis = Some(SealBasis {
                        leaves: vec![seal_id.clone()],
                    });
                    "data-plane Event kind"
                }
                Some(CbaEffectPlane::Control) => {
                    mismatched.seal_basis = None;
                    mismatched.seal_ref = Some(seal_id.clone());
                    mismatched.auth_context = Some(AuthContext {
                        key_id: OpaqueLocalId::new("device").unwrap(),
                        key_epoch: 0,
                        credential_epoch: None,
                    });
                    "control-plane Event kind"
                }
                None => {
                    mismatched.seal_basis = Some(SealBasis {
                        leaves: vec![seal_id.clone()],
                    });
                    "non-reducer events"
                }
            };
            let error = mismatched.validate_for_submit_structural().unwrap_err();
            assert!(
                error.to_string().contains(expected_error),
                "unexpected mismatch error for {kind}: {error}"
            );
        }
    }

    #[test]
    fn anchor_unit_allows_preconditions_without_any_cba_basis_field() {
        let mut event = base_event();
        event.kind = EventKind::RealmCreate;
        // A Realm genesis carries the closed `realm_genesis` scope and no
        // `realm_id` (spec `zh/models/realm-and-space.md` section 2.5.0).
        event.scope_ref = ScopeRef::RealmGenesis;
        event.preconditions.push(Precondition {
            cell_id: crate::CellRef::new("ak:cell:ak.component.realm.create.v1:null".to_owned())
                .unwrap(),
            predicate: crate::cba::Predicate {
                op: crate::cba::PredicateOp::HeadEq,
                value: Some(Value::Null),
                values: None,
                predicate_id: None,
            },
        });
        event.proofs.push(producer_proof());

        event
            .validate_for_submit_structural_in_context(EventSubmitContext::AnchorUnit)
            .expect("anchor-unit precondition is evaluated against the frozen predecessor");
        assert!(
            event
                .validate_for_submit_structural_in_context(EventSubmitContext::Standard)
                .is_err(),
            "the same basis-less Event is not an ordinary Control Move"
        );
    }
}
