use super::*;
use crate::{AnchorId, Effect, Precondition};

pub const EVENT_REF_ROLE_AUTHORIZED_BY: &str = "authorized_by";

/// CXP-0008 / CXP-0009 (spec head 37ce729) — runtime classifier stamped by
/// the reducer on every Envelope. Distinct from the existing `ActorKind`
/// enum (which classifies `ActorProfile.actor_kind` as user/org/team/...)
/// — this 4-value classifier describes the runtime origin of the
/// envelope itself: native devices, applet-bound ghost actors, service
/// principals, and personal agent runtimes.
///
/// Reducer rules:
/// - This field is reducer-stamped. Clients MUST NOT supply it; reducers
///   MUST reject envelopes that arrive with a client-supplied value
///   (return `actor_kind_self_stamped`).
/// - The serialized wire form on the Envelope is the field name
///   `actor_kind`, distinct from the `ActorProfile.actor_kind` slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventRef {
    pub id: String,
    pub role: String,
    #[serde(default = "default_event_ref_critical")]
    pub critical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl EventRef {
    pub fn new(id: impl Into<String>, role: impl Into<String>) -> Self {
        Self { id: id.into(), role: role.into(), critical: true, proof: None }
    }

    pub fn authorized_by(event_id: EventId) -> Self {
        Self::new(event_id.to_string(), EVENT_REF_ROLE_AUTHORIZED_BY)
    }
}

fn default_event_ref_critical() -> bool {
    true
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

impl EventRequirements {
    pub fn is_empty(&self) -> bool {
        self.schema_profile_refs.is_empty()
            && self.reducer_profile_ref.is_none()
            && self.required_features.is_empty()
            && self.critical_extensions.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Event {
    pub event_id: EventId,
    pub kind: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub prev_refs: Vec<EventId>,
    /// CXP-0007 (spec b7d35be, schemas/event-schema.json
    /// `$defs.effective_scope`) — reducer-stamped immutable scope binding.
    /// `Realm` for events emitted in Realm-default scope; `Circle` for
    /// events emitted in a Circle scope. SDK helpers that mint envelopes
    /// for a Flow / Morph / Space carrying `scope_circle_id` MUST set the
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
    pub anchor_ref: Option<AnchorId>,
    #[serde(default, skip_serializing_if = "EventRequirements::is_empty")]
    pub requirements: EventRequirements,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<EventId>,
    #[serde(rename = "payload")]
    pub content: Value,
    /// CXP-0008 / CXP-0009 (spec head 37ce729) — DID of the runtime that
    /// actually executed this envelope on behalf of `actor_id`. When
    /// present, the reducer MUST verify that the DID resolved from
    /// `proof.verification_method` equals `executed_by`. Signed; nested
    /// into the canonical signing transcript when set.
    ///
    // TODO(P1): reducer MUST stamp `actor_kind` and reject client-supplied;
    // reducer MUST verify `executed_by` == proof verification_method DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<Did>,
    /// CXP-0008 / CXP-0009 — typed reference (e.g. `cx:grant:<uuidv7>` /
    /// `cx:accountability_grant:<uuidv7>`) to the authorization artifact
    /// that authorized this envelope. Conditional; when present, MUST be
    /// included in the canonical signing transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
    /// CXP-0008 / CXP-0009 — runtime-origin classifier. Reducer-stamped
    /// projection; clients MUST NOT supply it. See
    /// [`EnvelopeActorKind`] for invariants.
    ///
    // TODO(P1): reducer MUST stamp this and reject client-supplied values;
    // wire-form rejection code `actor_kind_self_stamped`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<EnvelopeActorKind>,
    /// S-7 (savfox SDK gap, 2026-05-27) — when set, the typed Applet
    /// id (`cx:applet:<uuidv7>`) that produced this Envelope. First-class
    /// per `applet-integration.md` §8; included in the canonical
    /// signing transcript (folds naturally because top-level fields
    /// land in the canonical event bytes when present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<String>,
    /// S-7 (savfox SDK gap, 2026-05-27) — when set, opaque external
    /// reference for bridge-routed Envelopes (e.g. upstream message id,
    /// bridge correlation token). First-class per
    /// `applet-integration.md` §8; included in the canonical signing
    /// transcript via canonical event bytes when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<Proof>,
}

/// CXP-0007 (spec b7d35be, schemas/event-schema.json
/// `$defs.effective_scope`) — reducer-stamped immutable scope binding on
/// an [`Event`].
///
/// The wire form is an internally-tagged JSON object on `kind`:
/// - `{ "kind": "realm", "realm_id": "cx:realm:..." }`
/// - `{ "kind": "circle", "realm_id": "cx:realm:...", "circle_id": "cx:circle:..." }`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectiveScope {
    /// Event was emitted under Realm-default encryption scope.
    Realm { realm_id: RealmId },
    /// Event was emitted under the named Circle's encryption scope.
    Circle { realm_id: RealmId, circle_id: CircleId },
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
    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
            map.remove("unsigned");
        }
        Ok(value)
    }

    pub fn event_digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        self.validate_wire_schema()?;
        if self.proofs.is_empty() {
            return Err(Error::Protocol("event proofs must contain at least one proof".to_owned()));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol("event content must be a JSON object".to_owned()));
        }
        if self.requirements.critical_extensions.iter().any(|extension| !extension.fail_closed) {
            return Err(Error::Protocol(
                "event critical extensions must declare fail_closed=true".to_owned(),
            ));
        }
        if crate::events::is_reducer_input_event_kind(&self.kind) {
            if self.anchor_ref.is_none() {
                return Err(Error::Protocol(
                    "reducer-input events must carry anchor_ref".to_owned(),
                ));
            }
            if self.effects.is_empty() {
                return Err(Error::Protocol(
                    "reducer-input events must carry at least one effect".to_owned(),
                ));
            }
        } else if self.anchor_ref.is_some()
            || !self.preconditions.is_empty()
            || !self.effects.is_empty()
        {
            return Err(Error::Protocol(
                "non-reducer events must not carry preconditions, effects, or anchor_ref"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_wire_schema(&self) -> Result<()> {
        let value = serde_json::to_value(self)?;
        let registry = crate::schema::schema_registry_from_default_spec_artifacts()?
            .unwrap_or_else(ProtocolSchemaRegistry::default);
        registry.validate_value(EVENT_SCHEMA, &value)
    }

    /// Validate that all proofs bind to this event's digest.
    ///
    /// Checks each proof's `payload_digest` matches the canonical event digest,
    /// and that each proof is structurally valid.
    pub fn validate_proof_bindings(&self) -> Result<()> {
        let digest = self.event_digest()?;
        let expected_hash = Hash::new(digest)?;
        for proof in &self.proofs {
            proof.validate()?;
            if proof.payload_digest != expected_hash {
                return Err(Error::Protocol(format!(
                    "event proof payload_digest '{}' does not match event digest '{}'",
                    proof.payload_digest, expected_hash
                )));
            }
        }
        Ok(())
    }

    pub fn new(
        kind: impl Into<String>,
        realm_id: RealmId,
        actor_id: Did,
        actor_seq: u64,
        hlc: Hlc,
        content: Value,
    ) -> Result<Self> {
        Ok(Self {
            event_id: EventId::new(new_prefixed_uuid7("cx:event:"))?,
            kind: kind.into(),
            realm_id,
            actor_id,
            actor_seq,
            created_at: Utc::now(),
            hlc,
            prev_refs: Vec::new(),
            effective_scope: None,
            refs: Vec::new(),
            preconditions: Vec::new(),
            effects: Vec::new(),
            anchor_ref: None,
            requirements: EventRequirements::default(),
            redacts: None,
            content,
            executed_by: None,
            authorization_ref: None,
            actor_kind: None,
            applet_id: None,
            external_ref: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        })
    }
}

/// Canonical signed Event Envelope wire model.
pub type EventEnvelope = Event;

#[cfg(test)]
mod applet_routing_field_tests {
    //! S-7 (savfox SDK gap, 2026-05-27) — guard the `applet_id` /
    //! `external_ref` top-level slots against accidental wire drift.

    use super::*;
    use serde_json::json;

    fn realm() -> RealmId {
        RealmId::new("cx:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    fn base_event() -> Event {
        Event {
            event_id: EventId::new("cx:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
            kind: "cx.message.create".to_owned(),
            realm_id: realm(),
            actor_id: alice(),
            actor_seq: 1,
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            prev_refs: Vec::new(),
            effective_scope: None,
            refs: Vec::new(),
            preconditions: Vec::new(),
            effects: Vec::new(),
            anchor_ref: None,
            requirements: EventRequirements::default(),
            redacts: None,
            content: json!({ "body": "hello" }),
            executed_by: None,
            authorization_ref: None,
            actor_kind: None,
            applet_id: None,
            external_ref: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        }
    }

    #[test]
    fn event_digest_unchanged_when_applet_id_and_external_ref_absent() {
        let event = base_event();
        // Spec absence-symmetric: omitting both fields MUST be
        // serialization-equivalent to the legacy event.
        let serialized = serde_json::to_value(&event).unwrap();
        assert!(serialized.get("applet_id").is_none());
        assert!(serialized.get("external_ref").is_none());
    }

    #[test]
    fn event_digest_changes_when_applet_id_is_set() {
        let baseline = base_event().event_digest().unwrap();
        let mut event = base_event();
        event.applet_id = Some("cx:applet:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned());
        let with = event.event_digest().unwrap();
        assert_ne!(baseline, with, "applet_id must enter the canonical event bytes");
    }

    #[test]
    fn event_digest_changes_when_external_ref_is_set() {
        let baseline = base_event().event_digest().unwrap();
        let mut event = base_event();
        event.external_ref = Some(json!({"upstream_id": "slack:msg:12345"}));
        let with = event.event_digest().unwrap();
        assert_ne!(baseline, with, "external_ref must enter the canonical event bytes");
    }

    #[test]
    fn event_round_trips_applet_id_and_external_ref() {
        let mut event = base_event();
        event.applet_id = Some("cx:applet:01904100-0000-7000-8000-bbbbbbbbbbbb".to_owned());
        event.external_ref = Some(json!({"slack_msg_id": "1234567890.0001"}));
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["applet_id"], "cx:applet:01904100-0000-7000-8000-bbbbbbbbbbbb");
        assert_eq!(value["external_ref"]["slack_msg_id"], "1234567890.0001");
        let back: Event = serde_json::from_value(value).unwrap();
        assert_eq!(back.applet_id.as_deref(), event.applet_id.as_deref());
        assert_eq!(back.external_ref, event.external_ref);
    }
}
