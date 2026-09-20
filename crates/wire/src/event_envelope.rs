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
//! - **Closed-set wire enums hard-reject unknown values** (e.g. [`ScopeRef`], cursor purpose,
//!   subscribe frame kinds): no `#[serde(other)]` catch-all, so an unrecognised value fails
//!   deserialisation of the surrounding object. These enums gate authorization, scope and
//!   stream-control decisions; silently mapping an unknown value to a default could *widen* what
//!   the message is allowed to do. `conformance-profiles.md` requires implementations to reject
//!   illegal enum values — hard failure is the fail-closed behaviour, and a spec revision that
//!   extends a closed set is a coordinated upgrade, not a silent downgrade.
//!
//! Consequently: adding an event kind is a non-breaking registry evolution
//! (old SDKs keep parsing), while extending a closed-set enum intentionally
//! interrupts old parsers rather than letting them mis-authorize. The
//! affected enums additionally carry `#[non_exhaustive]` so downstream
//! `match` code is written with a fail-closed `_` arm from day one.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{
    AppletId, CircleId, Did, DidCoreId, EventId, GrantId, Hash, RealmId, SidecarId,
    project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, WireError};
use crate::events::kinds::EventKind;
use crate::primitives::{
    ActorId, Audience, ProducerEventProof, ProofBindingRequirements, SignatureBindingPayload,
};
use crate::{AuthorizationRef, Base64UrlString, DidUrl, MlsGroupId, SchemaId, canonical};

/// Full canonical Event Envelope bound, measured over the accepted envelope including every
/// producer proof.
///
/// See `zh/conformance/scalability-constraints.md` section 2.1.1.
pub const MAX_EVENT_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Canonical body bound for `body_class=non_streaming_json` operations
/// (`scalability-constraints.md` section 2.1.2).
pub const MAX_OPERATION_CANONICAL_BODY_BYTES: usize = 8 * 1024 * 1024;

/// HTTP message content wire bound enforced before JSON parse
/// (`scalability-constraints.md` section 2.1.3).
pub const MAX_HTTP_MESSAGE_CONTENT_BYTES: usize = 16 * 1024 * 1024;

pub const MAX_EVENT_SUBMIT_BATCH: usize = 1_000;
pub const MAX_EVENT_RESOLVE: usize = 100;
pub const MAX_EVENT_REFS: usize = 128;
pub const MAX_AUTHORIZED_BY_REFS: usize = 64;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRef {
    pub id: String,
    pub role: String,
    #[serde(default = "default_event_ref_critical")]
    pub critical: bool,
}

impl EventRef {
    pub fn new(id: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            role: role.into(),
            critical: true,
        }
    }

    pub fn authorized_by_grant(grant_id: GrantId) -> Self {
        Self::new(grant_id.to_string(), EVENT_REF_ROLE_AUTHORIZED_BY)
    }
}

fn default_event_ref_critical() -> bool {
    true
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
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<EventRef>,
    pub payload: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_proof: Option<ProducerEventProof>,
}

/// Minimal accepted-Event facts needed by the registry effect projector.
///
/// This is deliberately not an authorable Event and carries no producer proof. It
/// preserves the accepted authorization
/// reference needed by registry effects without fabricating a new signed
/// [`Event`].
#[derive(Clone, Debug, PartialEq)]
pub struct ProjectedEventInput {
    pub kind: EventKind,
    pub event_id: EventId,
    pub actor_id: ActorId,
    pub authorization_ref: Option<AuthorizationRef>,
    pub realm_id: RealmId,
    pub created_at: DateTime<Utc>,
    pub payload: BTreeMap<String, Value>,
    pub refs: Vec<EventRef>,
}

impl From<&Event> for ProjectedEventInput {
    fn from(event: &Event) -> Self {
        Self {
            kind: event.kind.clone(),
            event_id: event.event_id.clone(),
            actor_id: event.actor_id.clone(),
            authorization_ref: event.authorization_ref.clone(),
            realm_id: event.realm_id.clone(),
            created_at: event.created_at,
            payload: event.payload.clone(),
            refs: event.refs.clone(),
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

    /// Attach the registry's own original acceptance time. That instant and
    /// `control_proof.created_at` come from independent Authority clocks, so
    /// their order is never compared.
    pub fn accept(self, accepted_at: DateTime<Utc>) -> Result<RegistrationDidEvidence> {
        self.validate_shape()?;
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
        )
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
    if did.method() != "webvh"
        || adapter_version != "did:webvh:1.0"
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
    if method_evidence.method_proofs.len() != 1
        || method_evidence.method_proofs[0].history_head != method_history_head
    {
        return Err(WireError::Protocol(
            "registration DID evidence requires the exact WebVH method proof".to_owned(),
        ));
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
/// from the rule at a different point (one forgot `event_id`, one hashed the
/// envelope itself). A drifted preimage does not
/// fail loudly: it produces bytes no other implementation can reproduce, so a
/// valid signature verifies as invalid.
///
/// The excluded set and the reason each field is in it:
///
/// * `producer_proof` — the signature cannot cover itself.
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
    map.remove("event_id");
    map.remove("producer_proof");
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
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    refs: &'a Vec<EventRef>,
    payload: &'a BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    producer_proof: &'a Option<ProducerEventProof>,
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
            created_at: event.created_at,
            refs: &event.refs,
            payload: &event.payload,
            producer_proof: &event.producer_proof,
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
    #[serde(deserialize_with = "crate::serde_helpers::deserialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub refs: Option<Vec<EventRef>>,
    pub payload: BTreeMap<String, Value>,
    #[serde(default)]
    pub producer_proof: Option<ProducerEventProof>,
}

impl TryFrom<EventWire> for Event {
    type Error = String;

    fn try_from(wire: EventWire) -> std::result::Result<Self, Self::Error> {
        let kind = EventKind::from_wire(&wire.kind);
        let refs = match wire.refs {
            None => Vec::new(),
            Some(refs) if refs.is_empty() => {
                return Err("refs must be omitted when empty".to_owned());
            }
            Some(refs) => refs,
        };
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
            created_at: wire.created_at,
            refs,
            payload: wire.payload,
            producer_proof: wire.producer_proof,
        };
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
    /// MLS `group_id` derivation domain separator, `zh/models/realm-and-space.md`
    /// section 2.2. The trailing `0x00` separates it from the scope key bytes,
    /// which are printable ASCII and therefore cannot contain it.
    pub const MLS_GROUP_ID_DOMAIN: &'static str = "ak.mls.group_id.v1";

    /// Byte-exact v1 MLS security-scope key.
    ///
    /// Realm and Circle identifiers are already type-separated canonical IDs:
    /// each is globally unique, self-prefixed with its own kind and fixed
    /// length, so the id alone determines the scope and a `realm_id` prefix
    /// would add no separation. A Sidecar group additionally binds its parent
    /// Realm, separated by the ASCII Unit Separator byte, because its scope key
    /// was defined that way before this derivation existed. Genesis has no
    /// executable MLS scope.
    ///
    /// The same byte string is the MLS-Exporter context in
    /// `registry/exporter-label-registry.json`, so prefixing the Circle branch,
    /// dropping the Sidecar prefix or reordering the Sidecar components is not
    /// a `group_id`-only change — it silently re-keys every exported secret.
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

    /// Raw RFC 9420 `group_id` bytes for this effective security scope.
    ///
    /// `SHA-256(UTF8("ak.mls.group_id.v1") || 0x00 || scope_key_bytes)`, always
    /// 32 bytes. This is what an MLS group is actually created with; the
    /// base64url spelling below is only how the same value is carried on the
    /// wire.
    ///
    /// The digest is one-way by design (`zh/models/realm-and-space.md` section
    /// 2.2): a `group_id` observed on the delivery path MUST NOT reveal which
    /// Realm, Circle or Sidecar it belongs to. Nothing may recover the scope
    /// from it — a consumer that needs the scope has to be told, not decode.
    /// SHA-256 is fixed here and does **not** follow the Realm
    /// `digest_algorithm`.
    pub fn canonical_mls_group_id_bytes(&self) -> Result<[u8; 32]> {
        let scope_key = self.canonical_effective_scope_key_bytes()?;
        Ok(arkret_canonical::sha256_bytes_from_slices(&[
            Self::MLS_GROUP_ID_DOMAIN.as_bytes(),
            &[0x00],
            &scope_key,
        ]))
    }

    /// Deterministic MLS `group_id` for this effective security scope, in the
    /// wire spelling: base64url without padding, therefore always exactly 43
    /// characters (`common-ids.schema.json#/$defs/mls_group_id`).
    ///
    /// This is the only accepted formula. The pre-2218 reversible encoding —
    /// base64url of the scope key bytes themselves — is not a second spelling
    /// of the same field, and a verifier MUST NOT pick between the two by
    /// string length, group epoch or local state: it recomputes this and
    /// rejects anything else.
    pub fn canonical_mls_group_id(&self) -> Result<MlsGroupId> {
        MlsGroupId::new(crate::base64url::base64url_encode(
            self.canonical_mls_group_id_bytes()?,
        ))
        .map_err(|message| WireError::Protocol(message.to_owned()))
    }

    /// Whether this scope's MLS group carries handshake messages as
    /// `PublicMessage`.
    ///
    /// Realm and Circle groups do; a Sidecar group keeps its own policy and
    /// encrypts them. Before 2218 this was read back out of the `group_id`
    /// bytes, which only worked because those bytes were the scope id in
    /// clear — exactly the leak 2218 closed. It is a property of the scope, so
    /// it is answered here and passed down, never re-derived from a
    /// `group_id`.
    pub fn requires_public_mls_handshake(&self) -> Result<bool> {
        match self {
            Self::RealmGenesis => Err(WireError::Protocol(
                "RealmGenesis has no executable MLS security scope".to_owned(),
            )),
            Self::Realm { .. } | Self::Circle { .. } => Ok(true),
            Self::Sidecar { .. } => Ok(false),
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

#[cfg(test)]
mod scope_mls_group_id_tests {
    use super::*;

    /// The three scopes of `fixtures/mls-group-id-derivation-fixture.json`.
    ///
    /// The Circle and Sidecar cases deliberately share one 44-character
    /// payload under two different kind prefixes: the typed IDs are
    /// self-describing and fixed length, so the two scopes must not collide
    /// even though only the Sidecar branch carries a `realm_id`.
    fn kat_scopes() -> (ScopeRef, ScopeRef, ScopeRef) {
        let realm_id =
            RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5").unwrap();
        let circle_id =
            CircleId::new("ak:circle:AUD2WOhX-Xh47vBHtRJPMRfXRQXGiOWQqOrJGJnE8CaI").unwrap();
        let sidecar_id =
            SidecarId::new("ak:sidecar:AUD2WOhX-Xh47vBHtRJPMRfXRQXGiOWQqOrJGJnE8CaI").unwrap();
        (
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            ScopeRef::Circle {
                realm_id: realm_id.clone(),
                circle_id,
            },
            ScopeRef::Sidecar {
                realm_id,
                sidecar_id,
            },
        )
    }

    /// `ak.vector.mls.group_id_derivation_kat.v1`, pinned to the expected
    /// values of `fixtures/mls-group-id-derivation-fixture.json` rather than to
    /// a second copy of the formula, so a drift in either direction shows up as
    /// a changed constant instead of passing silently.
    #[test]
    fn group_id_derivation_matches_the_spec_known_answer_tests() {
        let (realm, circle, sidecar) = kat_scopes();

        for (scope, scope_key_hex, group_id) in [
            (
                &realm,
                "616b3a7265616c6d3a41633161434b386151646e6b59496d7664483344466a71346a4443503139387058595743477a477556796a35",
                "QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4",
            ),
            (
                &circle,
                "616b3a636972636c653a41554432574f68582d5868343776424874524a504d52665852515847694f5751714f724a474a6e4538436149",
                "mnoZ_saVPf3fDTNZYVjrFGJxJwRL6QkkU1EzZRYPzm4",
            ),
            (
                &sidecar,
                "616b3a7265616c6d3a41633161434b386151646e6b59496d7664483344466a71346a4443503139387058595743477a477556796a351f616b3a736964656361723a41554432574f68582d5868343776424874524a504d52665852515847694f5751714f724a474a6e4538436149",
                "YCyHuyYfqfioJ1HN4_laYDdRX02bSwSKseeujcVRPgU",
            ),
        ] {
            assert_eq!(
                hex::encode(scope.canonical_effective_scope_key_bytes().unwrap()),
                scope_key_hex,
                "{scope:?}"
            );
            assert_eq!(
                scope.canonical_mls_group_id().unwrap().as_str(),
                group_id,
                "{scope:?}"
            );
            // The wire spelling is exactly the base64url of the raw bytes an
            // MLS group is created with; the two never diverge.
            assert_eq!(
                crate::base64url::base64url_encode(scope.canonical_mls_group_id_bytes().unwrap()),
                group_id
            );
            assert_eq!(scope.canonical_mls_group_id().unwrap().as_str().len(), 43);
        }

        // One 44-character payload, two kind prefixes, two distinct groups.
        assert_ne!(
            circle.canonical_mls_group_id().unwrap(),
            sidecar.canonical_mls_group_id().unwrap()
        );
    }

    /// `ak.vector.mls.group_id_reversible_formula_rejected.v1`: the pre-2218
    /// encoding decodes straight back to the scope id, and is not a second
    /// accepted spelling of the same field.
    #[test]
    fn the_reversible_pre_2218_encoding_is_not_a_second_spelling() {
        let (realm, ..) = kat_scopes();
        let offered = "YWs6cmVhbG06QWMxYUNLOGFRZG5rWUltdmRIM0RGanE0akRDUDE5OHBYWVdDR3pHdVZ5ajU";
        assert_eq!(
            offered,
            crate::base64url::base64url_encode(
                realm.canonical_effective_scope_key_bytes().unwrap()
            ),
            "the negative case must really be the old formula"
        );
        assert_ne!(realm.canonical_mls_group_id().unwrap().as_str(), offered);
        // It is not even a well-formed mls_group_id, so it fails closed at the
        // type boundary before any comparison is reached.
        assert!(MlsGroupId::new(offered).is_err());
    }

    #[test]
    fn handshake_visibility_is_a_property_of_the_scope_not_of_the_group_id() {
        let (realm, circle, sidecar) = kat_scopes();
        assert!(realm.requires_public_mls_handshake().unwrap());
        assert!(circle.requires_public_mls_handshake().unwrap());
        assert!(!sidecar.requires_public_mls_handshake().unwrap());
        assert!(
            ScopeRef::RealmGenesis
                .requires_public_mls_handshake()
                .is_err()
        );
    }

    #[test]
    fn genesis_has_no_executable_mls_scope() {
        assert!(ScopeRef::RealmGenesis.canonical_mls_group_id().is_err());
        assert!(
            ScopeRef::RealmGenesis
                .canonical_mls_group_id_bytes()
                .is_err()
        );
        assert!(
            ScopeRef::RealmGenesis
                .canonical_effective_scope_key_bytes()
                .is_err()
        );
    }
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

    /// Reconstruct the Event represented by canonical digest-payload
    /// bytes returned by a protocol prepare operation.
    ///
    /// Prepare drafts intentionally omit fields outside the producer-signed
    /// transcript. This constructor is the only SDK path that restores those
    /// fields before a caller attaches the producer proof, so downstream clients never need
    /// to patch JSON objects themselves.
    pub fn from_digest_payload_bytes(
        bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        let mut value: Value = serde_json::from_slice(bytes)?;
        let object = value.as_object_mut().ok_or_else(|| {
            WireError::Protocol("Event digest payload must be a JSON object".to_owned())
        })?;
        for forbidden in ["event_id", "producer_proof"] {
            if object.contains_key(forbidden) {
                return Err(WireError::Protocol(format!(
                    "Event digest payload must omit {forbidden}"
                )));
            }
        }
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

    pub fn digest_payload(&self) -> Result<Value> {
        event_digest_preimage(&serde_json::to_value(self)?)
    }

    /// Refresh the content-bound Event id after authoring has finished.
    ///
    /// Producers call this after the closed business payload and optional
    /// semantic references are final. Authority ordering is not part of an
    /// Event and is assigned later by the current governance Station.
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
    /// applet provenance invariants, proof
    /// presence and scope/provenance invariants.
    /// It deliberately does NOT run event-payload schema validation — the
    /// submit gate for callers is `arkret_schema::validate_event_for_submit`,
    /// which layers registry-backed schema validation on top of this check.
    /// Keeping schema validation out of this crate (and out of the
    /// deserialization path) is what prevents an arkret-schema dependency
    /// cycle; do not reintroduce it here.
    pub fn validate_for_submit_structural(&self) -> Result<()> {
        self.validate_structural()
    }

    /// Validate a retained Event using the same producer-proof shape as a new
    /// submission. Historical signer resolution is attested by RealmCommit.
    pub fn validate_for_direct_history_structural(&self) -> Result<()> {
        self.validate_structural()
    }

    /// Validate the wire-level shape of a federated Event.
    ///
    /// Federation preserves the same sole producer proof. Receiver-local
    /// admission receipts are transport state and never mutate Event bytes.
    pub fn validate_for_federation_structural(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.validate_structural()?;
        self.validate_proof_bindings_with_digest_suite(digest_suite)
    }

    /// Shape of an already-accepted Event carried as evidence rather than as a
    /// submission, without the admission-binding digest step.
    ///
    /// The container-level pass owns the exact single producer-proof shape;
    /// recomputing its binding digest belongs to the next verification step.
    pub fn validate_for_accepted_structural(&self) -> Result<()> {
        self.validate_structural()
    }

    /// Validate an original Event carried by one of the five Contact source
    /// receipts. This is only a structural gate: callers must first authenticate
    /// the source projection and must independently verify the producer JWS with
    /// its exact projected key. It grants no generic Event admission exception.
    pub fn validate_for_contact_history_structural(&self) -> Result<()> {
        if !matches!(
            self.kind,
            EventKind::ContactRequested
                | EventKind::ContactAccepted
                | EventKind::ContactRejected
                | EventKind::ContactScopeUpdate
                | EventKind::ContactTombstone
        ) {
            return Err(WireError::Protocol(
                "Contact source projection requires an original Contact Event".into(),
            ));
        }
        self.validate_structural()
    }

    fn validate_structural(&self) -> Result<()> {
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
        validate_event_ref_count(self.refs.len())?;
        self.validate_applet_provenance_invariants()
            .map_err(WireError::Protocol)?;
        let Some(producer) = self.producer_proof.as_ref() else {
            return Err(WireError::Protocol(
                "Event must carry producer_proof".to_owned(),
            ));
        };
        producer.validate()?;
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
        let proof = self
            .producer_proof
            .as_ref()
            .ok_or_else(|| WireError::Protocol("Event must carry producer_proof".to_owned()))?;
        proof.validate()?;
        if proof.event_digest != expected_hash {
            return Err(WireError::Protocol(format!(
                "event proof event_digest '{}' does not match event digest '{}'",
                proof.event_digest, expected_hash
            )));
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
        let proof = self
            .producer_proof
            .as_ref()
            .ok_or_else(|| WireError::Protocol("Event must carry producer_proof".to_owned()))?;
        let expected = SignatureBindingPayload {
            payload_digest: expected_hash,
            actor_id: self.actor_id.clone(),
            verification_method: proof.verification_method.clone(),
            created_at: proof.created_at,
            domain,
            audience,
        };
        proof.validate_binding_with_requirements(&expected, requirements)?;
        Ok(())
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
        payload: Value,
    ) -> Result<Self> {
        Self::new_at(kind, scope_ref, actor_id, payload, Utc::now())
    }

    /// Construct an Event at a caller-supplied instant.
    ///
    /// The instant is truncated to the fixed millisecond precision required by
    /// the Event wire profile before it is stored on the typed envelope. This
    /// is the deterministic authoring entry point for callers that need an
    /// object timestamp and its containing Event to share one exact instant.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn new_at(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: ActorId,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new_with_derived_id_at(kind, scope_ref, actor_id, payload, created_at)
    }

    /// Construct an Event whose `event_id` is derived from its own content.
    ///
    /// This is the only authoring entry point for ordinary Events: the id is
    /// not a caller choice (`encoding.md` §4.0). It builds the envelope with a
    /// placeholder id, computes the digest over the preimage — which excludes
    /// `event_id` — and then stamps the derived id.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn new_with_derived_id_at(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: ActorId,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        // The placeholder never enters the digest preimage, so any valid id
        // works here; it is overwritten before the Event is observable.
        let placeholder = EventId::new(PLACEHOLDER_EVENT_ID)
            .expect("placeholder id is a canonical content-bound shape");
        let mut event =
            Self::new_unstamped_at(placeholder, kind, scope_ref, actor_id, payload, created_at)?;
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
    #[cfg(any(test, feature = "test-support"))]
    fn new_unstamped_at(
        event_id: EventId,
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: ActorId,
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
            created_at: canonical::normalize_timestamp_canonical(created_at),
            refs: Vec::new(),
            payload: payload.into_iter().collect(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            producer_proof: None,
        })
    }
}

#[cfg(test)]
mod event_wire_surface_tests {
    //! Guard the compact producer Event surface. Authority ordering lives in
    //! `RealmCommit`, independently for Realm, Circle and Sidecar streams.

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

    fn producer_proof() -> ProducerEventProof {
        ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }
    }

    fn base_event() -> Event {
        Event::new_at(
            "ak.message.create",
            realm_scope(),
            alice(),
            json!({"body": "hello"}),
            "2026-04-26T00:00:00.000Z".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn digest_payload_round_trips_without_producer_proof() {
        let event = base_event();
        let bytes = canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        let reconstructed =
            Event::from_digest_payload_bytes(&bytes, arkret_canonical::DigestSuite::Sha256)
                .unwrap();

        assert_eq!(reconstructed, event);
        assert!(reconstructed.producer_proof.is_none());
    }

    #[test]
    fn digest_payload_rejects_producer_proof_and_noncanonical_json() {
        let mut with_producer_proof = base_event().digest_payload().unwrap();
        with_producer_proof["producer_proof"] = json!({});
        let bytes = canonical::canonical_json_bytes(&with_producer_proof).unwrap();
        assert!(
            Event::from_digest_payload_bytes(&bytes, arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );

        let canonical =
            canonical::canonical_json_bytes(&base_event().digest_payload().unwrap()).unwrap();
        let mut spaced = b" ".to_vec();
        spaced.extend_from_slice(&canonical);
        assert!(
            Event::from_digest_payload_bytes(&spaced, arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );
    }

    #[test]
    fn legacy_proofs_array_is_rejected() {
        let mut value = serde_json::to_value(base_event()).unwrap();
        value["proofs"] = json!([producer_proof()]);
        let error = serde_json::from_value::<Event>(value)
            .expect_err("legacy Event proofs array must be rejected");
        assert!(error.to_string().contains("proofs"), "{error}");
    }

    #[test]
    fn event_new_at_normalizes_and_binds_the_timestamp() {
        let event = Event::new_at(
            "ak.message.create",
            realm_scope(),
            alice(),
            json!({"body": "hello"}),
            "2026-06-03T12:34:56.987654Z".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(
            event.created_at,
            "2026-06-03T12:34:56.987Z".parse::<DateTime<Utc>>().unwrap()
        );
        event
            .verify_event_id_matches_content_with_digest_suite(
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
    }

    #[test]
    fn refs_are_optional_but_explicit_empty_is_rejected() {
        let value = serde_json::to_value(base_event()).unwrap();
        assert!(value.get("refs").is_none());

        let mut invalid = value;
        invalid["refs"] = json!([]);
        let err = serde_json::from_value::<Event>(invalid).unwrap_err();
        assert!(
            err.to_string().contains("must be omitted when empty"),
            "{err}"
        );
    }

    #[test]
    fn signed_scope_ref_is_covered_and_must_match_the_realm() {
        let event = base_event();
        let baseline = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
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

        rescoped.scope_ref = ScopeRef::Realm {
            realm_id: RealmId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0xff; 32],
            )),
        };
        let err = rescoped.validate_for_submit_structural().unwrap_err();
        assert!(err.to_string().contains("scope_ref.realm_id"), "{err}");
    }

    #[test]
    fn structural_validation_requires_producer_proof() {
        let mut event = base_event();
        assert!(event.validate_for_submit_structural().is_err());
        event.producer_proof = Some(producer_proof());
        event.validate_for_submit_structural().unwrap();
    }

    #[test]
    fn applet_provenance_round_trips_and_is_digest_bound() {
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
        assert_eq!(serde_json::from_value::<Event>(value).unwrap(), event);
        assert!(
            event
                .digest_payload()
                .unwrap()
                .get("external_ref")
                .is_some()
        );

        let mut invalid = serde_json::to_value(base_event()).unwrap();
        invalid["external_ref"] = json!({"protocol": "slack"});
        assert!(serde_json::from_value::<Event>(invalid).is_err());
    }
}
