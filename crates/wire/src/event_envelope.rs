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
    AppletId, CircleId, DeviceId, Did, EventId, GrantId, Hash, Hlc, RealmId, SealId, SidecarId,
};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cba::{Precondition, SealBasis};
use crate::error::{Error, Result};
use crate::error_codes::ReasonCode;
use crate::event_receipt::EventBatchReceipt;
use crate::events::kinds::EventKind;
use crate::primitives::{
    Audience, CriticalExtension, Proof, ProofBindingRequirements, SignatureBindingPayload,
};
use crate::seal::Seal;
use crate::{
    AuthorizationRef, DidKey, DidUrl, FeatureRef, NonEmptyString, ProfileRef, SchemaId, canonical,
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
        return Err(Error::Protocol(format!(
            "event envelope exceeds v1 maximum of {MAX_EVENT_ENVELOPE_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Reject a canonical non-streaming JSON operation body that exceeds the general 8 MiB bound, or
/// the lower per-operation bound registered in `operation-registry.json`.
pub fn validate_operation_canonical_body_len(
    byte_len: usize,
    operation_max: Option<usize>,
) -> Result<()> {
    let limit = operation_max
        .unwrap_or(MAX_OPERATION_CANONICAL_BODY_BYTES)
        .min(MAX_OPERATION_CANONICAL_BODY_BYTES);
    if byte_len > limit {
        return Err(Error::Protocol(format!(
            "canonical operation body exceeds v1 maximum of {limit} bytes"
        )));
    }
    Ok(())
}

/// Reject an HTTP message content length before the body is parsed or canonicalized.
pub fn validate_http_message_content_len(byte_len: usize) -> Result<()> {
    if byte_len > MAX_HTTP_MESSAGE_CONTENT_BYTES {
        return Err(Error::Protocol(format!(
            "HTTP message content exceeds v1 maximum of {MAX_HTTP_MESSAGE_CONTENT_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Reject a service-added read-view `unsigned` object that exceeds its canonical bound.
pub fn validate_read_view_unsigned_len(byte_len: usize) -> Result<()> {
    if byte_len > MAX_READ_VIEW_UNSIGNED_CANONICAL_BYTES {
        return Err(Error::Protocol(format!(
            "read-view unsigned exceeds v1 maximum of {MAX_READ_VIEW_UNSIGNED_CANONICAL_BYTES} bytes"
        )));
    }
    Ok(())
}

pub fn validate_event_submit_batch_count(count: usize) -> Result<()> {
    if count > MAX_EVENT_SUBMIT_BATCH {
        return Err(Error::Protocol(format!(
            "event submit batch exceeds v1 maximum of {MAX_EVENT_SUBMIT_BATCH} events"
        )));
    }
    Ok(())
}

pub fn validate_event_prev_ref_count(count: usize) -> Result<()> {
    if count > MAX_EVENT_PREV_REFS {
        return Err(Error::Protocol(format!(
            "prev_refs exceeds v1 maximum of {MAX_EVENT_PREV_REFS} entries"
        )));
    }
    Ok(())
}

pub fn validate_event_ref_count(count: usize) -> Result<()> {
    if count > MAX_EVENT_REFS {
        return Err(Error::Protocol(format!(
            "refs exceeds v1 maximum of {MAX_EVENT_REFS} entries"
        )));
    }
    Ok(())
}

pub fn validate_authorized_by_ref_count(count: usize) -> Result<()> {
    if count > MAX_AUTHORIZED_BY_REFS {
        return Err(Error::Protocol(format!(
            "authorized_by refs exceeds v1 maximum of {MAX_AUTHORIZED_BY_REFS} entries"
        )));
    }
    Ok(())
}

pub fn validate_actor_seq_sibling_count(count: usize) -> Result<()> {
    if count > MAX_ACTOR_SEQ_SIBLINGS {
        return Err(Error::Protocol(format!(
            "actor_seq sibling fork count exceeds v1 maximum of {MAX_ACTOR_SEQ_SIBLINGS}"
        )));
    }
    Ok(())
}

pub fn validate_actor_seq_total_sibling_count(count: usize) -> Result<()> {
    if count > MAX_ACTOR_SEQ_TOTAL_SIBLINGS {
        return Err(Error::Protocol(format!(
            "actor_seq cumulative sibling count exceeds v1 maximum of {MAX_ACTOR_SEQ_TOTAL_SIBLINGS}"
        )));
    }
    Ok(())
}

pub fn validate_authority_chain_depth(depth: usize) -> Result<()> {
    if depth > MAX_AUTHORITY_CHAIN_DEPTH {
        return Err(Error::Protocol(format!(
            "authority chain depth exceeds v1 maximum of {MAX_AUTHORITY_CHAIN_DEPTH}"
        )));
    }
    Ok(())
}

pub fn validate_authority_control_depth(depth: u32) -> Result<()> {
    if depth > MAX_AUTHORITY_CONTROL_DEPTH {
        return Err(Error::Protocol(format!(
            "max_authority_depth exceeds v1 field maximum of {MAX_AUTHORITY_CONTROL_DEPTH}"
        )));
    }
    Ok(())
}

pub fn validate_event_prev_refs(prev_refs: &[EventId]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for prev_ref in prev_refs {
        validate_event_prev_ref_count(seen.len() + 1)?;
        if !seen.insert(prev_ref) {
            return Err(Error::Protocol(
                "prev_refs MUST NOT contain duplicate entries".to_owned(),
            ));
        }
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

/// AKP-0008 / AKP-0009 (spec head 37ce729) runtime classifier stamped by
/// the reducer on every Envelope. Distinct from the existing `ActorKind`
/// enum (which classifies `ActorProfile.actor_kind` as user/org/team/...)
/// this 4-value classifier describes the runtime origin of the
/// envelope itself: native devices, applet-bound ghost actors, service
/// principals, and personal agent runtimes.
///
/// Reducer rules:
/// - This field is reducer-stamped. Clients MUST NOT supply it; reducers MUST reject envelopes that
///   arrive with a client-supplied value (return `actor_kind_reducer_managed`).
/// - The serialized wire form on the Envelope is the field name `actor_kind`, distinct from the
///   `ActorProfile.actor_kind` slot.
///
/// `#[non_exhaustive]`: a future spec revision may register additional
/// runtime-origin classifiers. Downstream `match` expressions MUST carry a
/// `_` arm with fail-closed semantics (treat an unrecognised classifier as
/// not satisfying any privileged-origin check). Deserialisation itself stays
/// closed-set: an unknown wire value still fails the parse (fail-closed per
/// conformance-profiles.md: implementations MUST reject illegal enum values).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnvelopeActorKind {
    /// Envelope originated from a native device controlled by the principal.
    Native,
    /// Envelope originated from an applet-managed ghost actor.
    Ghost,
    /// Envelope originated from a service principal (e.g. policy server).
    Service,
    /// Envelope originated from a personal agent runtime acting on
    /// behalf of a controller.
    Agent,
}

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
/// Pins the signing DID and key epoch a receiver verifies against at
/// `seal_ref`. It carries no capability list: effective capabilities are
/// derived from the accepted governance basis, never selected by the producer.
/// `event-and-patch.md` §75 names producer-selected
/// `auth_context.capability_refs` alongside `effects` as a field a v1 receiver
/// MUST reject with `schema_violation`, and the envelope schema closes this
/// object over `{did, key_id, key_epoch, credential_epoch}` — so
/// `deny_unknown_fields` here is what makes an inbound one fail rather than be
/// silently dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthContext {
    pub did: Did,
    pub key_id: String,
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
    pub actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<Did>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<EventId>,
    /// Reducer/client-local extension data that is not part of the signed
    /// canonical Event Envelope transcript.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<Proof>,
    #[serde(default, skip_serializing_if = "EventRequirements::is_empty")]
    pub requirements: EventRequirements,
}

/// Portable PCR-anchored authorization evidence for an active device key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederatedDeviceStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederatedDeviceGenerationStatus {
    Active,
    Conflicted,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedDeviceRecord {
    pub algorithms: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signing_key: Option<DidKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hpke_key: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_algorithms: Option<Vec<NonEmptyString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_status: Option<FederatedDeviceStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_generation_ref: Option<NonEmptyString>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedDeviceGenerationState {
    pub current_device_generation_ref: NonEmptyString,
    pub device_generation_status: FederatedDeviceGenerationStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedCurrentDeviceProjection {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub device_record: FederatedDeviceRecord,
    pub generation_state: FederatedDeviceGenerationState,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedDeviceSigningKeyEvidence {
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub device_signing_key: DidKey,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub authorization_accepted_at: DateTime<Utc>,
    pub principal_genesis_receipt: EventBatchReceipt,
    pub authorization_chain: Vec<Event>,
    pub accepted_seal: Seal,
    pub current_device_projection: FederatedCurrentDeviceProjection,
    pub range_completeness_evidence: Vec<Event>,
}

impl FederatedDeviceSigningKeyEvidence {
    pub fn validate_shape(&self) -> Result<()> {
        let expected = format!("{}#{}", self.actor_id, self.device_id);
        if self.verification_method != expected {
            return Err(Error::Protocol(
                "federated device signing evidence verification_method must equal actor_id#device_id"
                    .to_owned(),
            ));
        }
        if !(2..=64).contains(&self.authorization_chain.len()) {
            return Err(Error::Protocol(
                "federated device signing evidence authorization_chain length is invalid"
                    .to_owned(),
            ));
        }
        let create = &self.authorization_chain[0];
        if create.kind.as_str() != "ak.realm.create"
            || create.actor_id != self.actor_id
            || create.proofs.len() != 1
            || !create.proofs[0].verification_method.starts_with("did:key:")
        {
            return Err(Error::Protocol(
                "federated device signing evidence must start at the root-signed PCR create"
                    .to_owned(),
            ));
        }
        let receipt_scope = self.principal_genesis_receipt.pcr_genesis_scope()?;
        if self.current_device_projection.principal_id != self.actor_id
            || self.current_device_projection.device_id != self.device_id
            || self
                .current_device_projection
                .device_record
                .device_signing_key
                .as_ref()
                != Some(&self.device_signing_key)
            || self.current_device_projection.device_record.device_status
                != Some(FederatedDeviceStatus::Active)
            || self
                .current_device_projection
                .generation_state
                .device_generation_status
                != FederatedDeviceGenerationStatus::Active
            || self
                .current_device_projection
                .device_record
                .authorized_generation_ref
                .as_ref()
                != Some(
                    &self
                        .current_device_projection
                        .generation_state
                        .current_device_generation_ref,
                )
            || self.range_completeness_evidence.is_empty()
            || self.range_completeness_evidence.iter().any(|attestation| {
                attestation.kind.as_str() != "ak.attestation.range_completeness"
                    || attestation.realm_id != create.realm_id
            })
        {
            return Err(Error::Protocol(
                "federated device signing evidence projection or range evidence is invalid"
                    .to_owned(),
            ));
        }
        let mut accepted_device_ids = BTreeSet::new();
        let mut expecting_root_authorize = true;
        let mut target_authorize = None;
        for (index, event) in self.authorization_chain.iter().enumerate().skip(1) {
            event.validate_proof_bindings()?;
            if event.actor_id != self.actor_id
                || event.realm_id != create.realm_id
                || event.proofs.len() != 1
            {
                return Err(Error::Protocol(
                    "federated device signing evidence contains an invalid control Event"
                        .to_owned(),
                ));
            }
            match event.kind.as_str() {
                "ak.device.authorize" => {
                    let device_id = event
                        .payload
                        .get("device_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            Error::Protocol("device authorization omits device_id".to_owned())
                        })?;
                    let binding_kind = event
                        .payload
                        .get("authorization_binding_kind")
                        .and_then(Value::as_str);
                    let authorized_by = event.payload.get("authorized_by").and_then(Value::as_str);
                    let proof_device_id = if expecting_root_authorize {
                        if binding_kind != Some("root_anchored")
                            || authorized_by != Some(self.actor_id.as_str())
                        {
                            return Err(Error::Protocol(
                                "root-anchored device authorization is required after an identity root anchor"
                                    .to_owned(),
                            ));
                        }
                        device_id
                    } else {
                        let authorizer = authorized_by.ok_or_else(|| {
                            Error::Protocol(
                                "accepted-device authorization omits authorized_by".to_owned(),
                            )
                        })?;
                        if binding_kind != Some("accepted_device")
                            || !accepted_device_ids.contains(authorizer)
                        {
                            return Err(Error::Protocol(
                                "device authorization authorizer is not active in the replayed prefix"
                                    .to_owned(),
                            ));
                        }
                        authorizer
                    };
                    if event.proofs[0].verification_method
                        != format!("{}#{proof_device_id}", self.actor_id)
                    {
                        return Err(Error::Protocol(
                            "device authorization Event proof signer does not match its binding"
                                .to_owned(),
                        ));
                    }
                    accepted_device_ids.insert(device_id.to_owned());
                    expecting_root_authorize = false;
                    if device_id == self.device_id.as_str() {
                        target_authorize = Some(event);
                    }
                }
                "ak.device.revoke" => {
                    let device_id = event
                        .payload
                        .get("device_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            Error::Protocol("device revoke omits device_id".to_owned())
                        })?;
                    accepted_device_ids.remove(device_id);
                }
                "ak.device.reanchor" => {
                    if !event.proofs[0].verification_method.starts_with("did:key:") {
                        return Err(Error::Protocol(
                            "device reanchor must carry an identity-root proof".to_owned(),
                        ));
                    }
                    accepted_device_ids.clear();
                    expecting_root_authorize = true;
                    target_authorize = None;
                }
                "ak.device.list.update" => {}
                _ => {
                    return Err(Error::Protocol(
                        "authorization_chain contains a non-device-control Event".to_owned(),
                    ));
                }
            }
            if index == 1 && expecting_root_authorize {
                return Err(Error::Protocol(
                    "PCR genesis must place its founding authorization second".to_owned(),
                ));
            }
        }
        let target = target_authorize.ok_or_else(|| {
            Error::Protocol("authorization chain does not authorize the target device".to_owned())
        })?;
        let create_digest = Hash::new(create.event_digest()?)?;
        let founding_authorize_digest = Hash::new(self.authorization_chain[1].event_digest()?)?;
        if !accepted_device_ids.contains(self.device_id.as_str())
            || self.authorization_accepted_at < target.created_at
            || target.payload.get("device_id").and_then(Value::as_str)
                != Some(self.device_id.as_str())
            || target
                .payload
                .get("device_public_key")
                .and_then(Value::as_str)
                != Some(self.device_signing_key.as_str())
            || self
                .current_device_projection
                .device_record
                .device_authorize_event_id
                .as_ref()
                != Some(&target.event_id)
            || self
                .current_device_projection
                .device_record
                .hpke_key
                .as_deref()
                != target.payload.get("hpke_key").and_then(Value::as_str)
            || self
                .current_device_projection
                .device_record
                .trust_algorithms
                .as_ref()
                .is_none_or(|algorithms| {
                    target
                        .payload
                        .get("algorithms")
                        .and_then(Value::as_array)
                        .is_none_or(|carried| {
                            algorithms.len() != carried.len()
                                || algorithms
                                    .iter()
                                    .zip(carried)
                                    .any(|(left, right)| right.as_str() != Some(left.as_str()))
                        })
                })
            || receipt_scope.principal_id != self.actor_id
            || receipt_scope.realm_id != create.realm_id
            || receipt_scope.create_digest != create_digest
            || receipt_scope.founding_authorize_digest != founding_authorize_digest
            || self.accepted_seal.realm_id != create.realm_id
            || self.authorization_chain.iter().any(|event| {
                event.event_digest().ok().is_none_or(|digest| {
                    !self
                        .accepted_seal
                        .covered_event_digests
                        .iter()
                        .any(|covered| covered.as_str() == digest)
                })
            })
        {
            return Err(Error::Protocol(
                "federated device signing evidence commitments do not match its authorization chain"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn matches_event_proof(&self, event: &Event, verification_method: &DidUrl) -> bool {
        self.validate_shape().is_ok()
            && self.actor_id == event.actor_id
            && &self.verification_method == verification_method
            && event
                .proofs
                .iter()
                .any(|proof| &proof.verification_method == verification_method)
    }
}

/// Derive the Realm id of an `ak.realm.create` from its own signed content.
///
/// `zh/models/realm-and-space.md` section 2.5.0 has two branches and both are
/// pure functions of the signed Event, so the id stays self-certifying either
/// way:
///
/// - **Principal Control Realm** (`payload.object.purpose == "principal_control"`) —
///   subject-derived Realm token (`0x11 || SHA-256(v1 domain || principal DID)`), so the address
///   remains computable from the DID alone.
/// - **Collaboration Realm** — event-derived: `retype(event_id)`.
pub fn derive_genesis_realm_id(
    event_id: &EventId,
    actor_id: &Did,
    payload_object: Option<&Value>,
) -> RealmId {
    let is_principal_control = payload_object
        .and_then(|object| object.get("purpose"))
        .and_then(Value::as_str)
        == Some("principal_control");
    if is_principal_control {
        crate::principal_control_realm_id(actor_id.as_str())
    } else {
        RealmId::from_event_id(event_id)
    }
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
        return Err(Error::Protocol(
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
    actor_id: &'a Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_by: &'a Option<Did>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    redacts: &'a Option<EventId>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    unsigned: &'a BTreeMap<String, Value>,
    proofs: &'a Vec<Proof>,
    #[serde(skip_serializing_if = "EventRequirements::is_empty")]
    requirements: &'a EventRequirements,
}

impl<'a> From<&'a Event> for EventSer<'a> {
    fn from(event: &'a Event) -> Self {
        Self {
            event_id: &event.event_id,
            kind: &event.kind,
            realm_id: (event.kind != EventKind::REALM_CREATE).then_some(&event.realm_id),
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
            redacts: &event.redacts,
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
    pub actor_id: Did,
    #[serde(default)]
    pub executed_by: Option<Did>,
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
    pub redacts: Option<EventId>,
    #[serde(default)]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<Proof>,
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
                if kind == EventKind::REALM_CREATE {
                    return Err(
                        "realm_id_not_event_derived: ak.realm.create MUST omit realm_id".to_owned(),
                    );
                }
                realm_id
            }
            None => {
                if kind != EventKind::REALM_CREATE {
                    return Err("realm_id is required".to_owned());
                }
                derive_genesis_realm_id(&wire.event_id, &wire.actor_id, wire.payload.get("object"))
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
            redacts: wire.redacts,
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
    /// The named native Agent Sidecar scope inside `realm_id`.
    Sidecar {
        realm_id: RealmId,
        sidecar_id: SidecarId,
    },
}

impl ScopeRef {
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
    pub fn from_digest_payload_bytes(bytes: &[u8]) -> Result<Self> {
        let mut value: Value = serde_json::from_slice(bytes)?;
        let object = value.as_object_mut().ok_or_else(|| {
            Error::Protocol("Event digest payload must be a JSON object".to_owned())
        })?;
        for forbidden in ["proofs", "unsigned", "actor_kind"] {
            if object.contains_key(forbidden) {
                return Err(Error::Protocol(format!(
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
        event.event_id = event.derive_event_id()?;
        let canonical = arkret_canonical::canonical_json_bytes(&event.digest_payload()?)?;
        if canonical != bytes {
            return Err(Error::Protocol(
                "Event digest payload bytes are not canonical".to_owned(),
            ));
        }
        Ok(event)
    }

    /// Parse the opaque event payload as `T` without checking `kind`.
    pub fn payload_as<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(Value::Object(
            self.payload
                .clone()
                .into_iter()
                .collect::<serde_json::Map<_, _>>(),
        ))
        .map_err(Into::into)
    }

    /// Assert the event kind before parsing the payload as `T`.
    pub fn typed_payload<T: DeserializeOwned>(&self, expected_kind: &str) -> Result<T> {
        self.ensure_payload_kind(expected_kind)?;
        self.payload_as()
    }

    fn ensure_payload_kind(&self, expected_kind: &str) -> Result<()> {
        if self.kind != expected_kind {
            return Err(Error::Protocol(format!(
                "event payload kind mismatch: expected {expected_kind}, got {}",
                self.kind.as_str()
            )));
        }
        Ok(())
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

    /// Derive this Event's `event_id` from its own canonical content.
    ///
    /// The id is one immutable suite-code byte plus all 256 bits of this
    /// Event's digest. It contains no explicit timestamp segment.
    pub fn derive_event_id(&self) -> Result<EventId> {
        self.derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
    }

    /// Refresh the content-bound Event id after authoring has finished.
    ///
    /// Producers commonly have to attach actor-chain, HLC, CBA and requirement
    /// fields after constructing the initial typed payload. All of those fields
    /// are in the Event digest preimage, so the id must be derived only after
    /// they are final. A Realm genesis additionally keeps its in-memory derived
    /// Realm id in sync with the refreshed Event id.
    pub fn refresh_content_bound_identity(&mut self) -> Result<()> {
        self.refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
    }

    /// [`Self::refresh_content_bound_identity`] under an explicit Realm digest
    /// suite.
    pub fn refresh_content_bound_identity_with_digest_suite(
        &mut self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.event_id = self.derive_event_id_with_digest_suite(digest_suite)?;
        if self.scope_ref == ScopeRef::RealmGenesis {
            self.realm_id =
                derive_genesis_realm_id(&self.event_id, &self.actor_id, self.payload.get("object"));
        }
        Ok(())
    }

    /// [`Event::derive_event_id`] under the Realm's declared digest suite.
    pub fn derive_event_id_with_digest_suite(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<EventId> {
        let digest = self.event_digest_with_digest_suite(digest_suite)?;
        let hex = digest
            .split_once(':')
            .map(|(_, rest)| rest)
            .ok_or_else(|| Error::Protocol("event digest must carry a suite prefix".to_owned()))?;
        if hex.len() != 64 {
            return Err(Error::Protocol(
                "Event ID format requires a 32-octet event digest".to_owned(),
            ));
        }
        let octets = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<std::result::Result<Vec<u8>, _>>()
            .map_err(|_| Error::Protocol("event digest is not lowercase hex".to_owned()))?;
        let digest_bytes: [u8; 32] = octets.try_into().map_err(|_| {
            Error::Protocol("Event ID format requires a 32-octet event digest".to_owned())
        })?;
        Ok(EventId::from_digest(digest_suite, digest_bytes))
    }

    /// Re-derive the id and compare it with the carried value.
    ///
    /// `encoding.md` §6 makes the *order* a security property: a receiver MUST
    /// run this before using `event_id` for deduplication, indexing, routing,
    /// idempotency or authorization. Skipping it lets a caller-chosen identity
    /// enter those paths without proving its complete digest binding.
    pub fn verify_event_id_matches_content(&self) -> Result<()> {
        self.verify_event_id_matches_content_with_digest_suite(
            arkret_canonical::DigestSuite::Sha256,
        )
    }

    /// [`Event::verify_event_id_matches_content`] under an explicit suite.
    pub fn verify_event_id_matches_content_with_digest_suite(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        let derived = self.derive_event_id_with_digest_suite(digest_suite)?;
        if derived == self.event_id {
            Ok(())
        } else {
            Err(Error::Protocol(
                "event_id_digest_mismatch: carried event_id does not equal the value re-derived                  from this Event's own canonical content"
                    .to_owned(),
            ))
        }
    }

    pub fn event_digest(&self) -> Result<String> {
        self.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
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

    /// [`Event::validate_for_submit_structural`] under an explicit CBA context.
    ///
    /// Use [`EventSubmitContext::AnchorUnit`] only for the two closed
    /// `seal_basis`-exempt anchor units of `event-auth-state-resolution.md` §5:
    /// the `ak.realm.create` bootstrap with its closed follow-up whitelist, and
    /// the B-model `ak.device.reanchor` + replacement-authorize unit, which
    /// fixes its frontier in the payload's `pre_fence_basis` instead.
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
        self.validate_structural_in_context(context, true)
    }

    /// Validate a producer-authored Event before proofs are appended.
    ///
    /// This applies the same CBA and envelope shape rules as submission while
    /// requiring the draft to remain unsigned. Prepare protocols use it before
    /// returning canonical digest-payload bytes to a caller.
    pub fn validate_for_authoring_structural(&self) -> Result<()> {
        self.validate_structural_in_context(EventSubmitContext::Standard, false)
    }

    fn validate_structural_in_context(
        &self,
        context: EventSubmitContext,
        require_proofs: bool,
    ) -> Result<()> {
        // zh/models/realm-and-space.md section 2.5.0: the genesis scope carries
        // no realm_id, so the equality check applies to every other kind and
        // the genesis branch instead pins the closed scope shape.
        if self.kind == EventKind::REALM_CREATE {
            if self.scope_ref != ScopeRef::RealmGenesis {
                return Err(Error::Protocol(
                    "ak.realm.create MUST use the realm_genesis scope".to_owned(),
                ));
            }
        } else if self.scope_ref.realm_id_opt() != Some(&self.realm_id) {
            return Err(Error::Protocol(
                "event scope_ref.realm_id must equal the envelope realm_id".to_owned(),
            ));
        }
        if self.actor_kind.is_some() {
            return Err(Error::Protocol(
                ReasonCode::ACTOR_KIND_REDUCER_MANAGED.to_owned(),
            ));
        }
        self.validate_applet_provenance_invariants()
            .map_err(Error::Protocol)?;
        if require_proofs && self.proofs.is_empty() {
            return Err(Error::Protocol(
                "event proofs must contain at least one proof".to_owned(),
            ));
        }
        if !require_proofs && !self.proofs.is_empty() {
            return Err(Error::Protocol(
                "Event authoring draft must not carry proofs".to_owned(),
            ));
        }
        if self
            .requirements
            .critical_extensions
            .iter()
            .any(|extension| !extension.fail_closed)
        {
            return Err(Error::Protocol(
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
            // frontier in the payload's `pre_fence_basis`. A bootstrap Event
            // may still carry a precondition, which is evaluated against the
            // unit's empty frozen predecessor state; only the three mutually
            // exclusive CBA basis fields participate in this shape test.
            let is_anchor_unit = context == EventSubmitContext::AnchorUnit
                && self.seal_ref.is_none()
                && self.auth_context.is_none()
                && self.seal_basis.is_none();
            if !is_data_event && !is_control_move && !is_anchor_unit {
                return Err(Error::Protocol(
                    "reducer-input events must be either DataEvent(seal_ref+auth_context) or Control Move(seal_basis)"
                        .to_owned(),
                ));
            }
        } else if self.seal_ref.is_some()
            || self.auth_context.is_some()
            || self.seal_basis.is_some()
            || !self.preconditions.is_empty()
        {
            return Err(Error::Protocol(
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

    /// Validate that all proofs bind to this event's digest.
    ///
    /// Checks each proof's `event_digest` matches the canonical event digest,
    /// and that each proof is structurally valid.
    pub fn validate_proof_bindings(&self) -> Result<()> {
        self.validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
    }

    /// Validate proof bindings with the trusted Realm digest suite.
    pub fn validate_proof_bindings_with_digest_suite(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        let digest = self.event_digest_with_digest_suite(digest_suite)?;
        let expected_hash = Hash::new(digest)?;
        for proof in &self.proofs {
            proof.validate()?;
            if proof.event_digest != expected_hash {
                return Err(Error::Protocol(format!(
                    "event proof event_digest '{}' does not match event digest '{}'",
                    proof.event_digest, expected_hash
                )));
            }
        }
        Ok(())
    }

    pub fn validate_proof_bindings_with_context(
        &self,
        domain: Option<String>,
        audience: Option<Audience>,
        requirements: ProofBindingRequirements,
    ) -> Result<()> {
        self.validate_proof_bindings_with_context_and_digest_suite(
            domain,
            audience,
            requirements,
            arkret_canonical::DigestSuite::Sha256,
        )
    }

    pub fn validate_proof_bindings_with_context_and_digest_suite(
        &self,
        domain: Option<String>,
        audience: Option<Audience>,
        requirements: ProofBindingRequirements,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        let expected_hash = Hash::new(self.event_digest_with_digest_suite(digest_suite)?)?;
        for proof in &self.proofs {
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

    /// Construct an Event in the given signed security scope.
    ///
    /// `realm_id` is taken from `scope_ref` so the envelope cannot be built
    /// with a Realm that disagrees with its own signed scope.
    pub fn new(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: Did,
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
    pub fn new_at(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: Did,
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
    pub fn new_with_derived_id_at(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: Did,
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
        event.event_id = event.derive_event_id()?;
        // A genesis scope names no Realm, so `realm_id` was computed from the
        // placeholder id above; recompute it now that the real id is known.
        if event.scope_ref.realm_id_opt().is_none() {
            event.realm_id = derive_genesis_realm_id(
                &event.event_id,
                &event.actor_id,
                event.payload.get("object"),
            );
        }
        Ok(event)
    }

    /// Internal first pass used only while deriving the content-bound id.
    /// No public API may expose an Event with this placeholder identity.
    #[allow(clippy::too_many_arguments)]
    fn new_unstamped_at(
        event_id: EventId,
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: Did,
        actor_seq: u64,
        hlc: Hlc,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        let Value::Object(payload) = payload else {
            return Err(Error::Protocol(
                "event payload must be a JSON object".to_owned(),
            ));
        };
        let kind = EventKind::from_wire(&kind.into());
        // A genesis scope names no Realm; the Realm id comes from this Event.
        let realm_id = match scope_ref.realm_id_opt() {
            Some(realm_id) => realm_id.clone(),
            None => derive_genesis_realm_id(&event_id, &actor_id, payload.get("object")),
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
            redacts: None,
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

    fn realm() -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x65; 32],
        ))
    }

    fn realm_scope() -> ScopeRef {
        ScopeRef::Realm { realm_id: realm() }
    }

    fn alice() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
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
            redacts: None,
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

    #[test]
    fn prepared_digest_payload_reconstructs_only_the_unsigned_event() {
        // The round-trip is only total for an Event that carries its own
        // derived id — which every wire Event must (section 4.0). Stamp it, so
        // the fixture is a legal Event rather than one with a made-up id.
        let mut event = base_event();
        event.event_id = event.derive_event_id().unwrap();
        let bytes = canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        let reconstructed = Event::from_digest_payload_bytes(&bytes).unwrap();

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
        assert!(Event::from_digest_payload_bytes(&bytes).is_err());

        let canonical =
            canonical::canonical_json_bytes(&base_event().digest_payload().unwrap()).unwrap();
        let mut spaced = Vec::with_capacity(canonical.len() + 1);
        spaced.extend_from_slice(b" ");
        spaced.extend_from_slice(&canonical);
        assert!(Event::from_digest_payload_bytes(&spaced).is_err());
    }

    #[test]
    fn authoring_validation_requires_cba_shape_before_signing() {
        let mut event = base_event();
        assert!(event.validate_for_authoring_structural().is_err());

        event.seal_basis = Some(SealBasis {
            leaves: vec![SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap()],
        });
        event.validate_for_authoring_structural().unwrap();

        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        });
        assert!(event.validate_for_authoring_structural().is_err());
        event.validate_for_submit_structural().unwrap();
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
        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            created_at: whole_second,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        });
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

        event.verify_event_id_matches_content().unwrap();
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
    fn typed_payload_rejects_kind_mismatch() {
        #[derive(Debug, Deserialize)]
        struct AnyPayload {}

        let event = base_event();
        let error = event
            .typed_payload::<AnyPayload>(EventKind::STRAND_CREATE)
            .unwrap_err();

        assert!(error.to_string().contains("kind mismatch"), "{error}");
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
            event.event_digest().unwrap(),
            mutated.event_digest().unwrap()
        );
    }

    #[test]
    fn actor_kind_is_the_only_field_outside_the_signed_transcript() {
        // `actor_kind` is stamped by the reducer AFTER the producer signs, so
        // it MUST NOT change the `event_digest`; a federated peer recomputing
        // the digest from the accepted envelope must reach the same value.
        // See `encoding.md` §2 / §6.
        let event = base_event();
        let baseline = event.event_digest().unwrap();

        let mut stamped = event;
        stamped.actor_kind = Some(EnvelopeActorKind::Agent);

        assert_eq!(baseline, stamped.event_digest().unwrap());
        let digest_payload = stamped.digest_payload().unwrap();
        assert!(digest_payload.get("actor_kind").is_none());
        assert!(digest_payload.get("proofs").is_none());
        assert!(digest_payload.get("unsigned").is_none());
    }

    #[test]
    fn signed_scope_ref_is_covered_by_the_event_digest() {
        let event = base_event();
        let baseline = event.event_digest().unwrap();
        assert!(event.digest_payload().unwrap().get("scope_ref").is_some());

        let mut rescoped = event;
        rescoped.scope_ref = ScopeRef::Circle {
            realm_id: realm(),
            circle_id: CircleId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x1c; 32],
            )),
        };

        assert_ne!(baseline, rescoped.event_digest().unwrap());
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
    fn anchor_unit_allows_preconditions_without_any_cba_basis_field() {
        let mut event = base_event();
        event.kind = EventKind::from(EventKind::REALM_CREATE);
        // A Realm genesis carries the closed `realm_genesis` scope and no
        // `realm_id` (spec `zh/models/realm-and-space.md` section 2.5.0).
        event.scope_ref = ScopeRef::RealmGenesis;
        event.preconditions.push(Precondition {
            cell: crate::CellRef::new("ak:cell:ak.component.realm.create.v1:null".to_owned())
                .unwrap(),
            predicate: crate::cba::Predicate {
                op: crate::cba::PredicateOp::HeadEq,
                value: Some(Value::Null),
                values: None,
                predicate_id: None,
            },
        });
        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        });

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
