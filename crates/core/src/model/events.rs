use super::*;
use crate::events::kinds::EventKind;
use crate::{Effect, Precondition, SealBasis, SealId};

pub const EVENT_REF_ROLE_AUTHORIZED_BY: &str = "authorized_by";

/// CKP-0008 / CKP-0009 (spec head 37ce729) â€” runtime classifier stamped by
/// the reducer on every Envelope. Distinct from the existing `ActorKind`
/// enum (which classifies `ActorProfile.actor_kind` as user/org/team/...)
/// â€” this 4-value classifier describes the runtime origin of the
/// envelope itself: native devices, applet-bound ghost actors, service
/// principals, and personal agent runtimes.
///
/// Reducer rules:
/// - This field is reducer-stamped. Clients MUST NOT supply it; reducers MUST reject envelopes that
///   arrive with a client-supplied value (return `actor_kind_reducer_managed`).
/// - The serialized wire form on the Envelope is the field name `actor_kind`, distinct from the
///   `ActorProfile.actor_kind` slot.
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(try_from = "EventWire")]
pub struct Event {
    pub event_id: EventId,
    pub kind: EventKind,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub prev_refs: Vec<EventId>,
    /// CKP-0007 (spec b7d35be, schemas/event-envelope.schema.json
    /// `$defs.effective_scope`) â€” reducer-stamped immutable scope binding.
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
    pub seal_ref: Option<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<AuthContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_basis: Option<SealBasis>,
    #[serde(default, skip_serializing_if = "EventRequirements::is_empty")]
    pub requirements: EventRequirements,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<EventId>,
    #[serde(rename = "payload")]
    pub content: Value,
    /// CKP-0008 / CKP-0009 (spec head 37ce729) â€” DID of the runtime that
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
    /// CKP-0008 / CKP-0009 â€” typed reference (e.g. `ck:grant:<uuidv7>` /
    /// `ck:accountability_grant:<uuidv7>`) to the authorization artifact
    /// that authorized this envelope. Conditional; when present, MUST be
    /// included in the canonical signing transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
    /// Signed Applet provenance (`event-envelope.schema.json#/$defs/applet_id`,
    /// shape `ck:applet:<uuidv7>`). Present when the Event is introduced by an
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
    pub external_ref: Option<Value>,
    /// CKP-0008 / CKP-0009 â€” runtime-origin classifier. Reducer-stamped
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
    #[serde(rename = "payload")]
    pub content: Value,
    #[serde(default)]
    pub executed_by: Option<Did>,
    #[serde(default)]
    pub authorization_ref: Option<String>,
    #[serde(default)]
    pub applet_id: Option<AppletId>,
    #[serde(default)]
    pub external_ref: Option<Value>,
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
            content: wire.content,
            executed_by: wire.executed_by,
            authorization_ref: wire.authorization_ref,
            applet_id: wire.applet_id,
            external_ref: wire.external_ref,
            actor_kind: wire.actor_kind,
            unsigned: wire.unsigned,
            proofs: wire.proofs,
        };
        event.validate_applet_provenance_invariants()?;
        event
            .validate_forbidden_wire_surface()
            .map_err(|err| err.to_string())?;
        Ok(event)
    }
}

/// CKP-0007 (spec b7d35be, schemas/event-envelope.schema.json
/// `$defs.effective_scope`) â€” reducer-stamped immutable scope binding on
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
        canonical::from_canonical_json_slice(bytes)
    }

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
        self.validate_applet_provenance_invariants()
            .map_err(Error::Protocol)?;
        if self.effective_scope.is_some() {
            return Err(Error::Protocol(
                "event effective_scope is reducer-managed on actor submit".to_owned(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "event proofs must contain at least one proof".to_owned(),
            ));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol(
                "event content must be a JSON object".to_owned(),
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

    pub fn validate_wire_schema(&self) -> Result<()> {
        self.validate_forbidden_wire_surface()?;
        let value = serde_json::to_value(self)?;
        let registry = crate::schema::schema_registry_from_default_spec_artifacts()?
            .unwrap_or_else(ProtocolSchemaRegistry::default);
        registry.validate_value(EVENT_SCHEMA, &value)
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

    pub fn validate_forbidden_wire_surface(&self) -> Result<()> {
        validate_forbidden_object_keys(
            "Event.payload",
            &self.content,
            crate::WireContext::EventEnvelopeOrPayloadTopLevel,
        )?;
        if let Some(context) = payload_context_for_event_kind(self.kind.as_str()) {
            validate_forbidden_object_keys("Event.payload", &self.content, context)?;
            if let Some(object) = self.content.get("object") {
                validate_forbidden_object_keys("Event.payload.object", object, context)?;
            }
            if let Some(patch) = self.content.get("patch") {
                validate_forbidden_object_keys("Event.payload.patch", patch, context)?;
            }
            if let Some(patch_context) = patch_context_for_event_kind(self.kind.as_str())
                && let Some(patch) = self.content.get("patch")
            {
                validate_forbidden_patch_paths("Event.payload.patch", patch, patch_context)?;
            }
        }
        validate_forbidden_id_prefixes("Event.payload", &self.content)
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
            kind: EventKind::from_wire(&kind.into()),
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
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            redacts: None,
            content,
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

fn patch_context_for_event_kind(kind: &str) -> Option<crate::WireContext> {
    let suffix = kind.strip_prefix("ck.").unwrap_or(kind);
    match suffix {
        "flow.update" | "flow.tracks.update" => Some(crate::WireContext::FlowPatchPath),
        "morph.update" | "morph.schema_migrate" => Some(crate::WireContext::MorphPatchPath),
        _ => None,
    }
}

fn validate_forbidden_patch_paths(
    label: &str,
    value: &Value,
    context: crate::WireContext,
) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for (key, patch_op) in object {
        if let Some(forbidden_path) = forbidden_patch_path_match(key, context) {
            return Err(Error::Protocol(format!(
                "{label} contains forbidden patch path '{key}' matching '{forbidden_path}' in context {context:?}"
            )));
        }
        validate_forbidden_patch_value(label, key, patch_op, context)?;
    }
    Ok(())
}

fn forbidden_patch_path_match<'a>(path: &'a str, context: crate::WireContext) -> Option<&'a str> {
    if let Some(entry) = forbidden_patch_path_prefixes(context)
        .iter()
        .find(|entry| path == **entry || path.starts_with(&format!("{entry}.")))
    {
        return Some(entry);
    }
    crate::is_forbidden_in_context(path, context).then_some(path)
}

fn forbidden_patch_path_prefixes(context: crate::WireContext) -> &'static [&'static str] {
    match context {
        crate::WireContext::FlowPatchPath => &[
            "stage",
            "stage_changed_at",
            "metadata.fields.assignee",
            "metadata.fields.assignees",
            "metadata.fields.assigned_to",
            "metadata.fields.assigned_actor_ids",
            "fields.assignee",
            "fields.assignees",
            "fields.assigned_to",
            "fields.assigned_actor_ids",
        ],
        crate::WireContext::MorphPatchPath => &["stage", "stage_changed_at"],
        _ => &[],
    }
}

fn validate_forbidden_patch_value(
    label: &str,
    path: &str,
    patch_op: &Value,
    context: crate::WireContext,
) -> Result<()> {
    let patch_value = patch_op
        .get("value")
        .filter(|_| patch_op.get("$op").is_some())
        .unwrap_or(patch_op);
    match context {
        crate::WireContext::FlowPatchPath => {
            validate_flow_patch_parent_value(label, path, patch_value)?;
        }
        crate::WireContext::MorphPatchPath => {
            validate_morph_patch_parent_value(label, path, patch_value)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_flow_patch_parent_value(label: &str, path: &str, value: &Value) -> Result<()> {
    match path {
        "metadata.fields" => validate_forbidden_map_value_keys(
            label,
            path,
            value,
            "metadata.fields",
            crate::WireContext::FlowPayload,
        ),
        "fields" => validate_forbidden_map_value_keys(
            label,
            path,
            value,
            "fields",
            crate::WireContext::FlowPatchPath,
        ),
        "metadata" => {
            if let Some(fields) = value.get("fields") {
                validate_forbidden_map_value_keys(
                    label,
                    "metadata.fields",
                    fields,
                    "metadata.fields",
                    crate::WireContext::FlowPayload,
                )?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_morph_patch_parent_value(label: &str, path: &str, value: &Value) -> Result<()> {
    match path {
        "fields" => validate_forbidden_map_value_keys(
            label,
            path,
            value,
            "fields",
            crate::WireContext::MorphPayload,
        ),
        _ => Ok(()),
    }
}

fn validate_forbidden_map_value_keys(
    label: &str,
    path: &str,
    value: &Value,
    key_prefix: &str,
    context: crate::WireContext,
) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for nested_key in object.keys() {
        let nested = format!("{key_prefix}.{nested_key}");
        if crate::is_forbidden_in_context(&nested, context)
            || forbidden_patch_path_match(&nested, context).is_some()
        {
            return Err(Error::Protocol(format!(
                "{label}.{path} value contains forbidden wire field '{nested}' in context {context:?}"
            )));
        }
    }
    Ok(())
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
mod event_wire_surface_tests {
    //! Guard the Event Envelope wire surface against legacy non-spec fields.

    use serde_json::json;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    fn base_event() -> Event {
        Event {
            event_id: EventId::new("ck:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
            kind: "ck.message.create".into(),
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
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            redacts: None,
            content: json!({ "body": "hello" }),
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
            Some(AppletId::new("ck:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap());
        event.authorization_ref = Some("ck:grant:01904100-0000-7000-8000-cccccccccccc".to_owned());
        event.external_ref = Some(json!({
            "protocol": "slack",
            "external_id": "1234567890.0001"
        }));

        let value = serde_json::to_value(&event).unwrap();
        // Both fields serialize at the top level (so they enter canonical bytes).
        assert_eq!(
            value.get("applet_id").and_then(Value::as_str),
            Some("ck:applet:01904100-0000-7000-8000-bbbbbbbbbbbb")
        );
        assert!(value.get("external_ref").unwrap().is_object());

        // Round-trips through the wire deserializer (deny_unknown_fields).
        let round_tripped: Event = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(round_tripped, event);

        // Both fields enter the digest payload (proofs/unsigned removed only).
        let digest_payload = event.digest_payload().unwrap();
        assert!(digest_payload.get("applet_id").is_some());
        assert!(digest_payload.get("external_ref").is_some());
        // Mutating external_ref changes the event digest (it is covered).
        let mut mutated = event.clone();
        mutated.external_ref = Some(json!({ "protocol": "slack", "external_id": "different" }));
        assert_ne!(
            event.event_digest().unwrap(),
            mutated.event_digest().unwrap()
        );
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
            json!("ck:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"),
        );
        let err = serde_json::from_value::<Event>(value).unwrap_err();
        assert!(
            err.to_string()
                .contains("applet_id requires authorization_ref"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn event_deserialize_rejects_forbidden_payload_fields() {
        let event = base_event();
        let mut value = serde_json::to_value(&event).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("kind".to_owned(), json!("ck.flow.create"));
        value.as_object_mut().unwrap().insert(
            "payload".to_owned(),
            json!({"discussion_space_ref": "ck:space:old"}),
        );

        let err = serde_json::from_value::<Event>(value).unwrap_err();
        assert!(err.to_string().contains("forbidden wire field"));
    }

    #[test]
    fn flow_update_rejects_forbidden_patch_paths() {
        for path in [
            "stage",
            "metadata.fields.assignee",
            "metadata.fields.assignee.name",
            "fields.assignee",
        ] {
            let mut event = base_event();
            event.kind = "ck.flow.update".into();
            let mut patch = serde_json::Map::new();
            patch.insert(
                path.to_owned(),
                json!({ "$op": "set", "value": "did:web:bob.example" }),
            );
            event.content = json!({
                "target_ref": "ck:flow:01904100-0000-7000-8000-000000000001",
                "patch": Value::Object(patch)
            });

            let err = event.validate_forbidden_wire_surface().unwrap_err();
            assert!(
                err.to_string().contains("forbidden patch path")
                    || err.to_string().contains("forbidden wire field"),
                "unexpected error for {path}: {err}"
            );
        }

        for (path, value) in [
            (
                "metadata.fields",
                json!({"assignee": "did:web:bob.example"}),
            ),
            (
                "metadata",
                json!({"fields": {"assignee": "did:web:bob.example"}}),
            ),
            ("fields", json!({"assignee": "did:web:bob.example"})),
        ] {
            let mut event = base_event();
            event.kind = "ck.flow.update".into();
            let mut patch = serde_json::Map::new();
            patch.insert(path.to_owned(), json!({ "$op": "set", "value": value }));
            event.content = json!({
                "target_ref": "ck:flow:01904100-0000-7000-8000-000000000001",
                "patch": Value::Object(patch)
            });

            let err = event.validate_forbidden_wire_surface().unwrap_err();
            assert!(
                err.to_string().contains("forbidden wire field")
                    || err.to_string().contains("forbidden patch path"),
                "unexpected error for {path}: {err}"
            );
        }
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
