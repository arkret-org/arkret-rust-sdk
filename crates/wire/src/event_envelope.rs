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
//!   [`EffectiveScope`], cursor purpose, subscribe frame kinds): no `#[serde(other)]` catch-all, so
//!   an unrecognised value fails deserialisation of the surrounding object. These enums gate
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
    AppletId, CircleId, Did, EventId, GrantId, Hash, Hlc, RealmId, SealId, new_prefixed_uuid7,
};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical;
use crate::error::{Error, Result};
use crate::error_codes::ReasonCode;
use crate::events::kinds::EventKind;
use crate::move_event::{Effect, Precondition, SealBasis};
use crate::primitives::{
    Audience, CriticalExtension, Proof, ProofBindingRequirements, SignatureBindingPayload,
};

pub const MAX_EVENT_ENVELOPE_BYTES: usize = 1024 * 1024;
pub const MAX_EVENT_SUBMIT_BATCH: usize = 1_000;
pub const MAX_EVENT_RESOLVE: usize = 100;
pub const MAX_EVENT_PREV_REFS: usize = 128;
pub const MAX_EVENT_REFS: usize = 128;
pub const MAX_AUTHORIZED_BY_REFS: usize = 64;
pub const MAX_ACTOR_SEQ_SIBLINGS: usize = 16;
pub const MAX_DELEGATION_CHAIN_DEPTH: usize = 4;
pub const MAX_DELEGATION_CONTROL_DEPTH: u32 = 4;

pub const EVENT_REF_ROLE_AUTHORIZED_BY: &str = "authorized_by";

pub fn validate_event_envelope_byte_len(byte_len: usize) -> Result<()> {
    if byte_len > MAX_EVENT_ENVELOPE_BYTES {
        return Err(Error::Protocol(format!(
            "event envelope exceeds v1 maximum of {MAX_EVENT_ENVELOPE_BYTES} bytes"
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

pub fn validate_delegation_chain_depth(depth: usize) -> Result<()> {
    if depth > MAX_DELEGATION_CHAIN_DEPTH {
        return Err(Error::Protocol(format!(
            "delegation chain depth exceeds v1 maximum of {MAX_DELEGATION_CHAIN_DEPTH}"
        )));
    }
    Ok(())
}

pub fn validate_delegation_control_depth(depth: u32) -> Result<()> {
    if depth > MAX_DELEGATION_CONTROL_DEPTH {
        return Err(Error::Protocol(format!(
            "max_delegation_depth exceeds v1 field maximum of {MAX_DELEGATION_CONTROL_DEPTH}"
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SemanticRefProof {
    pub kind: SemanticRefProofKind,
    pub leaf_digest: Hash,
    pub audit_path: Vec<Hash>,
    pub leaf_index: u64,
    pub tree_size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub enum SemanticRefProofKind {
    #[serde(rename = "rfc6962_merkle")]
    Rfc6962Merkle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AuthContext {
    pub did: Did,
    pub key_id: String,
    pub key_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_epoch: Option<u64>,
    pub capability_refs: Vec<String>,
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(try_from = "EventWire")]
pub struct Event {
    pub event_id: EventId,
    pub kind: EventKind,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub actor_seq: u64,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub prev_refs: Vec<EventId>,
    /// AKP-0007 (spec b7d35be, schemas/event-envelope.schema.json
    /// `$defs.effective_scope`) reducer-stamped immutable scope binding.
    /// `Realm` for events emitted in Realm-default scope; `Circle` for
    /// events emitted in a Circle scope. SDK helpers that mint envelopes
    /// for a Strand / Morph / Space carrying `scope_circle_id` MUST set the
    /// `Circle` variant; envelopes for scope-unaware events MAY omit the
    /// field (deserializes as `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<EffectiveScope>,
    #[serde(default)]
    pub refs: Vec<EventRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<Precondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<Effect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<AuthContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_basis: Option<SealBasis>,
    #[serde(default, skip_serializing_if = "EventRequirements::is_empty")]
    pub requirements: EventRequirements,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<EventId>,
    pub payload: BTreeMap<String, Value>,
    /// AKP-0008 / AKP-0009 (spec head 37ce729) DID of the runtime that
    /// actually executed this envelope on behalf of `actor_id`. When
    /// present, the reducer MUST verify that the DID resolved from
    /// `proof.verification_method` equals `executed_by`. Signed; nested
    /// into the canonical signing transcript when set.
    ///
    /// The SDK model represents the accepted/read envelope. Actor-supplied
    /// submit envelopes remain a reducer validation surface: reject
    /// client-supplied `actor_kind` and verify `executed_by` against the
    /// proof verification method DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<Did>,
    /// AKP-0008 / AKP-0009 typed reference (e.g. `ak:grant:<uuidv7>` /
    /// `ak:accountability_grant:<uuidv7>`) to the authorization artifact
    /// that authorized this envelope. Conditional; when present, MUST be
    /// included in the canonical signing transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
    /// Signed Applet provenance (`event-envelope.schema.json#/$defs/applet_id`,
    /// shape `ak:applet:<uuidv7>`). Present when the Event is introduced by an
    /// Applet / Ghost Actor / bridge / delegated applet path. Enters canonical
    /// event bytes and therefore `proof.event_digest`. Invariant: when present,
    /// `authorization_ref` MUST also be present (the accepted grant that binds
    /// this applet_id + registration_epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletId>,
    /// Signed external provenance reference for Applet / bridge-originated
    /// Events (`event-envelope.schema.json#/$defs/external_ref`). Open object
    /// whose field vocabulary is defined by extension profiles (protocol,
    /// network_id, instance_id, external_id, url, ...). Covered by
    /// `event_digest`. Invariant: only meaningful when bound to a signed
    /// `applet_id` (schema `allOf`: external_ref ⇒ applet_id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<BTreeMap<String, Value>>,
    /// AKP-0008 / AKP-0009 runtime-origin classifier. Reducer-stamped
    /// projection; clients MUST NOT supply it. See
    /// [`EnvelopeActorKind`] for invariants.
    ///
    /// Actor-supplied submit envelopes MUST be rejected with
    /// `actor_kind_reducer_managed`; reducers stamp this immutable projection
    /// on accepted envelopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<EnvelopeActorKind>,
    /// Reducer/client-local extension data that is not part of the signed
    /// canonical Event Envelope transcript.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<Proof>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventWire {
    pub event_id: EventId,
    pub kind: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub actor_seq: u64,
    #[serde(deserialize_with = "crate::serde_helpers::deserialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub prev_refs: Vec<EventId>,
    #[serde(default)]
    pub effective_scope: Option<EffectiveScope>,
    #[serde(default)]
    pub refs: Vec<EventRef>,
    #[serde(default)]
    pub preconditions: Vec<Precondition>,
    #[serde(default)]
    pub effects: Vec<Effect>,
    #[serde(default)]
    pub seal_ref: Option<SealId>,
    #[serde(default)]
    pub auth_context: Option<AuthContext>,
    #[serde(default)]
    pub seal_basis: Option<SealBasis>,
    #[serde(default)]
    pub requirements: EventRequirements,
    #[serde(default)]
    pub redacts: Option<EventId>,
    pub payload: BTreeMap<String, Value>,
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
    #[serde(default)]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<Proof>,
}

impl TryFrom<EventWire> for Event {
    type Error = String;

    fn try_from(wire: EventWire) -> std::result::Result<Self, Self::Error> {
        let event = Self {
            event_id: wire.event_id,
            kind: EventKind::from_wire(&wire.kind),
            realm_id: wire.realm_id,
            actor_id: wire.actor_id,
            actor_seq: wire.actor_seq,
            created_at: wire.created_at,
            hlc: wire.hlc,
            prev_refs: wire.prev_refs,
            effective_scope: wire.effective_scope,
            refs: wire.refs,
            preconditions: wire.preconditions,
            effects: wire.effects,
            seal_ref: wire.seal_ref,
            auth_context: wire.auth_context,
            seal_basis: wire.seal_basis,
            requirements: wire.requirements,
            redacts: wire.redacts,
            payload: wire.payload,
            executed_by: wire.executed_by,
            authorization_ref: wire.authorization_ref,
            applet_id: wire.applet_id,
            external_ref: wire.external_ref,
            actor_kind: wire.actor_kind,
            unsigned: wire.unsigned,
            proofs: wire.proofs,
        };
        event.validate_applet_provenance_invariants()?;
        Ok(event)
    }
}

/// AKP-0007 (spec b7d35be, schemas/event-envelope.schema.json
/// `$defs.effective_scope`) reducer-stamped immutable scope binding on
/// an [`Event`].
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EffectiveScope {
    /// Event was emitted under Realm-default encryption scope.
    Realm { realm_id: RealmId },
    /// Event was emitted under the named Circle's encryption scope.
    Circle {
        realm_id: RealmId,
        circle_id: CircleId,
    },
}

impl EffectiveScope {
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

impl Event {
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
    /// Kept in lockstep with `conformance/encoding.md` §2 / §6 (v1 set:
    /// `effective_scope`, `actor_kind`).
    pub const REDUCER_STAMPED_TOP_LEVEL_FIELDS: [&'static str; 2] =
        ["effective_scope", "actor_kind"];

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
    /// submit gate for callers is `arkret_core`'s `validate_for_submit`,
    /// which layers registry-backed schema validation on top of this check.
    /// Keeping schema validation out of this crate (and out of the
    /// deserialization path) is what prevents an arkret-schema dependency
    /// cycle; do not reintroduce it here.
    pub fn validate_for_submit_structural(&self) -> Result<()> {
        if self.effective_scope.is_some() {
            return Err(Error::Protocol(
                ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED.to_owned(),
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
            if self.effects.is_empty() {
                return Err(Error::Protocol(
                    "reducer-input events must carry at least one effect".to_owned(),
                ));
            }
            let is_data_event = self.seal_ref.is_some()
                && self.auth_context.is_some()
                && self.seal_basis.is_none()
                && self.preconditions.is_empty();
            let is_control_move =
                self.seal_ref.is_none() && self.auth_context.is_none() && self.seal_basis.is_some();
            if !is_data_event && !is_control_move {
                return Err(Error::Protocol(
                    "reducer-input events must be either DataEvent(seal_ref+auth_context) or Control Move(seal_basis)"
                        .to_owned(),
                ));
            }
        } else if self.seal_ref.is_some()
            || self.auth_context.is_some()
            || self.seal_basis.is_some()
            || !self.preconditions.is_empty()
            || !self.effects.is_empty()
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

    pub fn new(
        kind: impl Into<String>,
        realm_id: RealmId,
        actor_id: Did,
        actor_seq: u64,
        hlc: Hlc,
        payload: Value,
    ) -> Result<Self> {
        Self::new_at(
            kind,
            realm_id,
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
        realm_id: RealmId,
        actor_id: Did,
        actor_seq: u64,
        hlc: Hlc,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new_with_id_at(
            EventId::new(new_prefixed_uuid7("ak:event:"))?,
            kind,
            realm_id,
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
        realm_id: RealmId,
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
            realm_id,
            actor_id,
            actor_seq,
            created_at: canonical::normalize_timestamp_canonical(created_at),
            hlc,
            prev_refs: Vec::new(),
            effective_scope: None,
            refs: Vec::new(),
            preconditions: Vec::new(),
            effects: Vec::new(),
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

    fn alice() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn base_event() -> Event {
        Event {
            event_id: EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
            kind: "ak.message.create".into(),
            realm_id: realm(),
            actor_id: alice(),
            actor_seq: 1,
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            prev_refs: Vec::new(),
            effective_scope: None,
            refs: Vec::new(),
            preconditions: Vec::new(),
            effects: Vec::new(),
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
            realm(),
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
            verification_method: "did:webvh:z6mkfixture:alice.example#key-1".to_owned(),
            event_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            created_at: whole_second,
            domain: None,
            audience: None,
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
            realm(),
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
            realm(),
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
    fn reducer_stamped_fields_do_not_affect_event_digest() {
        // A reducer-stamped `effective_scope` / `actor_kind` MUST NOT change
        // the `event_digest`, so a producer signature computed before stamping
        // still validates on the accepted envelope (and matches a federated
        // peer's independent recomputation). See `encoding.md` §2 / §6.
        let event = base_event();
        let baseline = event.event_digest().unwrap();

        let mut stamped = event;
        stamped.effective_scope = Some(EffectiveScope::Realm { realm_id: realm() });
        stamped.actor_kind = Some(EnvelopeActorKind::Agent);

        assert_eq!(baseline, stamped.event_digest().unwrap());
        // The stamped fields are absent from the digest payload entirely.
        let digest_payload = stamped.digest_payload().unwrap();
        assert!(digest_payload.get("effective_scope").is_none());
        assert!(digest_payload.get("actor_kind").is_none());
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
    fn submit_rejects_actor_supplied_effective_scope_with_reason() {
        let mut event = base_event();
        event.effective_scope = Some(EffectiveScope::Realm { realm_id: realm() });

        let err = event.validate_for_submit_structural().unwrap_err();
        assert!(
            err.to_string()
                .contains(ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED),
            "unexpected error: {err}"
        );
    }
}
