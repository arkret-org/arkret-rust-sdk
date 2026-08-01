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
    AppletId, CircleId, DeviceId, Did, EventId, GrantId, Hash, Hlc, RealmId, SealId,
    new_prefixed_uuid7,
};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cba::{Precondition, SealBasis};
use crate::error::{Error, Result};
use crate::error_codes::ReasonCode;
use crate::events::kinds::EventKind;
use crate::primitives::{
    Audience, CriticalExtension, Proof, ProofBindingRequirements, SignatureBindingPayload,
};
use crate::{DidKey, DidUrl, SchemaId, canonical};

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

pub fn validate_event_prev_refs<I, S>(prev_refs: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = BTreeSet::new();
    let mut count = 0usize;
    for prev_ref in prev_refs {
        count += 1;
        validate_event_prev_ref_count(count)?;
        if !seen.insert(prev_ref.as_ref().to_owned()) {
            return Err(Error::Protocol(
                "prev_refs MUST NOT contain duplicate entries".to_owned(),
            ));
        }
    }
    Ok(())
}

pub fn prev_frontier_digest<I, S>(prev_refs: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut sorted = prev_refs
        .into_iter()
        .map(|prev_ref| prev_ref.as_ref().to_owned())
        .collect::<Vec<_>>();
    sorted.sort();
    sorted.dedup();
    Ok(canonical::canonical_sha256(&Value::Array(
        sorted.into_iter().map(Value::String).collect(),
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
    pub schema_profile_refs: Vec<String>,
    #[serde(default, rename = "reducer", skip_serializing_if = "Option::is_none")]
    pub reducer_profile_ref: Option<String>,
    #[serde(default, rename = "features", skip_serializing_if = "Vec::is_empty")]
    pub required_features: Vec<String>,
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
            && self.reducer_profile_ref.is_none()
            && self.required_features.is_empty()
            && self.critical_extensions.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "EventWire")]
pub struct Event {
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
    pub authorization_ref: Option<String>,
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

/// Portable authorization evidence for an active participant device signing
/// key. The original accepted `ak.device.authorize` Event anchors the key in
/// the principal's delegated enrollment authority; the authenticated source
/// service only attests current lifecycle freshness. This transport context is
/// never part of another Event's canonical bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedDeviceSigningKeyEvidence {
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub device_signing_key: DidKey,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub authorization_accepted_at: DateTime<Utc>,
    pub device_authorize_event: Box<Event>,
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
        if self.device_authorize_event.kind.as_str() != "ak.device.authorize"
            || self.device_authorize_event.actor_id != self.actor_id
            || self.authorization_accepted_at < self.device_authorize_event.created_at
            || self
                .device_authorize_event
                .payload
                .get("principal_id")
                .and_then(Value::as_str)
                != Some(self.actor_id.as_str())
            || self
                .device_authorize_event
                .payload
                .get("device_id")
                .and_then(Value::as_str)
                != Some(self.device_id.as_str())
            || self
                .device_authorize_event
                .payload
                .get("device_public_key")
                .and_then(Value::as_str)
                .is_none_or(|value| {
                    self.device_signing_key.as_str().strip_prefix("did:key:") != Some(value)
                })
            || !self
                .device_authorize_event
                .payload
                .contains_key("enrollment_authority_binding")
        {
            return Err(Error::Protocol(
                "federated device signing evidence must carry the matching service-attested ak.device.authorize Event"
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventWire {
    pub event_id: EventId,
    pub kind: String,
    pub realm_id: RealmId,
    pub scope_ref: ScopeRef,
    pub actor_id: Did,
    #[serde(default)]
    pub executed_by: Option<Did>,
    #[serde(default)]
    pub authorization_ref: Option<String>,
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
        let event = Self {
            event_id: wire.event_id,
            kind: EventKind::from_wire(&wire.kind),
            realm_id: wire.realm_id,
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
        event.validate_applet_provenance_invariants()?;
        Ok(event)
    }
}

/// Security scope binding used by the protocol wherever a Realm-or-Circle
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
    /// Realm-default security scope.
    Realm { realm_id: RealmId },
    /// The named Circle's security scope inside `realm_id`.
    Circle {
        realm_id: RealmId,
        circle_id: CircleId,
    },
}

impl ScopeRef {
    /// The parent Realm of this scope, regardless of variant.
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

impl Event {
    pub const SCHEMA: &'static str = SchemaId::EVENT_V1;
    /// Deserialize an inbound Event Envelope after canonical JSON ingress
    /// checks (NFC strings, duplicate keys, number profile).
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
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
    pub const REDUCER_STAMPED_TOP_LEVEL_FIELDS: [&'static str; 1] = ["actor_kind"];

    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
            map.remove("unsigned");
            for field in Self::REDUCER_STAMPED_TOP_LEVEL_FIELDS {
                map.remove(field);
            }
        }
        Ok(value)
    }

    pub fn event_digest(&self) -> Result<String> {
        Ok(canonical::canonical_sha256(&self.digest_payload()?)?)
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
        if self.scope_ref.realm_id() != &self.realm_id {
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
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "event proofs must contain at least one proof".to_owned(),
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
        let digest = self.event_digest()?;
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
        let expected_hash = Hash::new(self.event_digest()?)?;
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
        Self::new_with_id_at(
            EventId::new(new_prefixed_uuid7("ak:event:"))?,
            kind,
            scope_ref,
            actor_id,
            actor_seq,
            hlc,
            payload,
            created_at,
        )
    }

    /// Construct an Event with a caller-supplied identifier and instant.
    ///
    /// This deterministic variant supports protocol flows that allocate an
    /// Event identifier before authoring the envelope. It shares all envelope
    /// defaults and timestamp normalization with [`Self::new_at`].
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_id_at(
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
        Ok(Self {
            event_id,
            kind: EventKind::from_wire(&kind.into()),
            realm_id: scope_ref.realm_id().clone(),
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
        RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn realm_scope() -> ScopeRef {
        ScopeRef::Realm { realm_id: realm() }
    }

    fn alice() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn base_event() -> Event {
        Event {
            event_id: EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
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
                "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
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
            alg: "EdDSA".to_owned(),
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
    fn event_new_with_id_at_preserves_the_allocated_identifier() {
        let event_id = EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c576").unwrap();
        let event = Event::new_with_id_at(
            event_id.clone(),
            "ak.message.create",
            realm_scope(),
            alice(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"body": "hello"}),
            "2026-06-03T12:34:56.000Z".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(event.event_id, event_id);
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
        event.authorization_ref = Some("ak:grant:01904100-0000-7000-8000-cccccccccccc".to_owned());
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
            circle_id: CircleId::new("ak:circle:01904100-0000-7000-8000-1c1c1c1c1c1c").unwrap(),
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
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000ff").unwrap(),
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
            alg: "EdDSA".to_owned(),
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
