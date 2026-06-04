use super::*;
use crate::{AnchorId, Effect, Precondition};

pub const EVENT_REF_ROLE_AUTHORIZED_BY: &str = "authorized_by";

/// CKP-0008 / CKP-0009 (spec head 37ce729) — runtime classifier stamped by
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
#[serde(deny_unknown_fields)]
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
#[serde(try_from = "EventWire")]
pub struct Event {
    pub event_id: EventId,
    pub kind: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub prev_refs: Vec<EventId>,
    /// CKP-0007 (spec b7d35be, schemas/event-envelope.schema.json
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
    /// CKP-0008 / CKP-0009 (spec head 37ce729) — DID of the runtime that
    /// actually executed this envelope on behalf of `actor_id`. When
    /// present, the reducer MUST verify that the DID resolved from
    /// `proof.verification_method` equals `executed_by`. Signed; nested
    /// into the canonical signing transcript when set.
    ///
    // TODO(P1): reducer MUST stamp `actor_kind` and reject client-supplied;
    // reducer MUST verify `executed_by` == proof verification_method DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<Did>,
    /// CKP-0008 / CKP-0009 — typed reference (e.g. `ck:grant:<uuidv7>` /
    /// `ck:accountability_grant:<uuidv7>`) to the authorization artifact
    /// that authorized this envelope. Conditional; when present, MUST be
    /// included in the canonical signing transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
    /// CKP-0008 / CKP-0009 — runtime-origin classifier. Reducer-stamped
    /// projection; clients MUST NOT supply it. See
    /// [`EnvelopeActorKind`] for invariants.
    ///
    // TODO(P1): reducer MUST stamp this and reject client-supplied values;
    // wire-form rejection code `actor_kind_self_stamped`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<EnvelopeActorKind>,
    /// S-7 (savfox SDK gap, 2026-05-27) — when set, the typed Applet
    /// id (`ck:applet:<uuidv7>`) that produced this Envelope. First-class
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventWire {
    pub event_id: EventId,
    pub kind: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub actor_seq: u64,
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
    pub anchor_ref: Option<AnchorId>,
    #[serde(default)]
    pub requirements: EventRequirements,
    #[serde(default)]
    pub redacts: Option<EventId>,
    #[serde(rename = "payload")]
    pub content: Value,
    #[serde(default)]
    pub executed_by: Option<Did>,
    #[serde(default)]
    pub authorization_ref: Option<String>,
    #[serde(default)]
    pub actor_kind: Option<EnvelopeActorKind>,
    #[serde(default)]
    pub applet_id: Option<String>,
    #[serde(default)]
    pub external_ref: Option<Value>,
    #[serde(default)]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<Proof>,
}

impl TryFrom<EventWire> for Event {
    type Error = String;

    fn try_from(wire: EventWire) -> std::result::Result<Self, Self::Error> {
        let event = Self {
            event_id: wire.event_id,
            kind: wire.kind,
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
            anchor_ref: wire.anchor_ref,
            requirements: wire.requirements,
            redacts: wire.redacts,
            content: wire.content,
            executed_by: wire.executed_by,
            authorization_ref: wire.authorization_ref,
            actor_kind: wire.actor_kind,
            applet_id: wire.applet_id,
            external_ref: wire.external_ref,
            unsigned: wire.unsigned,
            proofs: wire.proofs,
        };
        event.validate_forbidden_wire_surface().map_err(|err| err.to_string())?;
        Ok(event)
    }
}

/// CKP-0007 (spec b7d35be, schemas/event-envelope.schema.json
/// `$defs.effective_scope`) — reducer-stamped immutable scope binding on
/// an [`Event`].
///
/// The wire form is an internally-tagged JSON object on `kind`:
/// - `{ "kind": "realm", "realm_id": "ck:realm:..." }`
/// - `{ "kind": "circle", "realm_id": "ck:realm:...", "circle_id": "ck:circle:..." }`
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
        if self.effective_scope.is_some() {
            return Err(Error::Protocol(
                "event effective_scope is reducer-managed on actor submit".to_owned(),
            ));
        }
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
        self.validate_forbidden_wire_surface()?;
        let value = serde_json::to_value(self)?;
        let registry = crate::schema::schema_registry_from_default_spec_artifacts()?
            .unwrap_or_else(ProtocolSchemaRegistry::default);
        registry.validate_value(EVENT_SCHEMA, &value)
    }

    pub fn validate_forbidden_wire_surface(&self) -> Result<()> {
        validate_forbidden_object_keys(
            "Event.payload",
            &self.content,
            crate::WireContext::EventEnvelopeOrPayloadTopLevel,
        )?;
        if let Some(context) = payload_context_for_event_kind(&self.kind) {
            validate_forbidden_object_keys("Event.payload", &self.content, context)?;
            if let Some(object) = self.content.get("object") {
                validate_forbidden_object_keys("Event.payload.object", object, context)?;
            }
            if let Some(patch) = self.content.get("patch") {
                validate_forbidden_object_keys("Event.payload.patch", patch, context)?;
            }
        }
        validate_forbidden_id_prefixes("Event.payload", &self.content)?;
        validate_forbidden_id_prefixes(
            "Event.external_ref",
            self.external_ref.as_ref().unwrap_or(&Value::Null),
        )
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

    pub fn new(
        kind: impl Into<String>,
        realm_id: RealmId,
        actor_id: Did,
        actor_seq: u64,
        hlc: Hlc,
        content: Value,
    ) -> Result<Self> {
        Ok(Self {
            event_id: EventId::new(new_prefixed_uuid7("ck:event:"))?,
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

fn payload_context_for_event_kind(kind: &str) -> Option<crate::WireContext> {
    let suffix = kind.strip_prefix("ck.").unwrap_or(kind);
    match suffix.split('.').next()? {
        "flow" => Some(crate::WireContext::FlowPayload),
        "morph" => Some(crate::WireContext::MorphPayload),
        "space" => Some(crate::WireContext::SpacePayload),
        "relation" => Some(crate::WireContext::RelationPayload),
        "message" if suffix == "message.create" => Some(crate::WireContext::MessageCreatePayload),
        "realm" if suffix == "realm.freeze" => Some(crate::WireContext::RealmFreezePayload),
        _ => None,
    }
}

fn validate_forbidden_object_keys(
    label: &str,
    value: &Value,
    context: crate::WireContext,
) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for (key, child) in object {
        if crate::is_forbidden_in_context(key, context) {
            return Err(Error::Protocol(format!(
                "{label} contains forbidden wire field '{key}' in context {context:?}"
            )));
        }
        if let Some(fields) = child.as_object().filter(|_| key == "fields") {
            for nested_key in fields.keys() {
                let nested = format!("fields.{nested_key}");
                if crate::is_forbidden_in_context(&nested, context) {
                    return Err(Error::Protocol(format!(
                        "{label}.fields contains forbidden wire field '{nested}' in context {context:?}"
                    )));
                }
            }
        }
        if let Some(metadata) = child.as_object().filter(|_| key == "metadata")
            && let Some(fields) = metadata.get("fields").and_then(Value::as_object)
        {
            for nested_key in fields.keys() {
                let nested = format!("metadata.fields.{nested_key}");
                if crate::is_forbidden_in_context(&nested, context) {
                    return Err(Error::Protocol(format!(
                        "{label}.metadata.fields contains forbidden wire field '{nested}' in context {context:?}"
                    )));
                }
            }
        }
        if key == "kind"
            && child.as_str() == Some("room")
            && crate::is_forbidden_in_context("kind=room", context)
        {
            return Err(Error::Protocol(format!(
                "{label}.kind contains forbidden value 'room' in context {context:?}"
            )));
        }
    }
    Ok(())
}

fn validate_forbidden_id_prefixes(label: &str, value: &Value) -> Result<()> {
    match value {
        Value::String(s) if crate::is_forbidden_id_prefix(s) => Err(Error::Protocol(format!(
            "{label} contains forbidden typed-id prefix in value '{s}'"
        ))),
        Value::Array(items) => {
            for item in items {
                validate_forbidden_id_prefixes(label, item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for value in map.values() {
                validate_forbidden_id_prefixes(label, value)?;
            }
            Ok(())
        }
        _ => Ok(()),
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
        RealmId::new("ck:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    fn base_event() -> Event {
        Event {
            event_id: EventId::new("ck:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
            kind: "ck.message.create".to_owned(),
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
        event.applet_id = Some("ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned());
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
        event.applet_id = Some("ck:applet:01904100-0000-7000-8000-bbbbbbbbbbbb".to_owned());
        event.external_ref = Some(json!({"slack_msg_id": "1234567890.0001"}));
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["applet_id"], "ck:applet:01904100-0000-7000-8000-bbbbbbbbbbbb");
        assert_eq!(value["external_ref"]["slack_msg_id"], "1234567890.0001");
        let back: Event = serde_json::from_value(value).unwrap();
        assert_eq!(back.applet_id.as_deref(), event.applet_id.as_deref());
        assert_eq!(back.external_ref, event.external_ref);
    }

    #[test]
    fn event_deserialize_rejects_forbidden_payload_fields() {
        let event = base_event();
        let mut value = serde_json::to_value(&event).unwrap();
        value.as_object_mut().unwrap().insert("kind".to_owned(), json!("ck.flow.create"));
        value
            .as_object_mut()
            .unwrap()
            .insert("payload".to_owned(), json!({"discussion_space_ref": "ck:space:old"}));

        let err = serde_json::from_value::<Event>(value).unwrap_err();
        assert!(err.to_string().contains("forbidden wire field"));
    }

    #[test]
    fn event_deserialize_rejects_forbidden_typed_id_prefixes() {
        let event = base_event();
        let mut value = serde_json::to_value(&event).unwrap();
        value.as_object_mut().unwrap().insert(
            "payload".to_owned(),
            json!({"participant_identity": "ck:rtcpart:0198c2f4-0000-7000-8000-000000000000"}),
        );

        let err = serde_json::from_value::<Event>(value).unwrap_err();
        assert!(err.to_string().contains("forbidden typed-id prefix"));
    }
}
