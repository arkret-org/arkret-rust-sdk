use super::*;

/// Generic create-event payload used by Realm / Space / Flow / Morph creates.
///
/// The concrete object type is schema-specific, but the event payload envelope
/// is shared: `{ "object": ... }` plus optional initial relations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectCreatePayload<T> {
    pub object: T,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initial_relations: Vec<Value>,
}

impl<T> ObjectCreatePayload<T> {
    pub fn new(object: T) -> Self {
        Self { object, initial_relations: Vec::new() }
    }

    pub fn with_initial_relation(mut self, relation: Value) -> Self {
        self.initial_relations.push(relation);
        self
    }
}

impl<T: Serialize> ObjectCreatePayload<T> {
    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("object create payload serialize: {err}")))
    }
}

fn now_utc_seconds() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0).unwrap_or_else(Utc::now)
}

fn serialize_canonical_timestamp<S>(
    value: &DateTime<Utc>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&canonical::format_timestamp_canonical(value.to_owned()))
}

fn deserialize_canonical_timestamp<'de, D>(
    deserializer: D,
) -> std::result::Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let value = String::deserialize(deserializer)?;
    canonical::validate_timestamp_canonical(&value).map_err(serde::de::Error::custom)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(serde::de::Error::custom)
}

/// Current wire object carried by `ck.space.create`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpaceCreateObject {
    pub id: SpaceId,
    pub schema: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_scope_circle_id: Option<CircleId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_scope_policy: Option<ChildScopePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    pub kind: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<SpaceState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl SpaceCreateObject {
    pub fn new(
        id: SpaceId,
        realm_id: RealmId,
        kind: impl Into<String>,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            id,
            schema: SPACE_SCHEMA.to_owned(),
            realm_id,
            default_realm_id: None,
            scope_circle_id: None,
            default_scope_circle_id: None,
            child_scope_policy: None,
            parent_space_id: None,
            kind: kind.into(),
            title: title.into(),
            summary: None,
            rank: None,
            schema_refs: Vec::new(),
            fields: BTreeMap::new(),
            labels: Vec::new(),
            avatar_blob_ref: None,
            state: None,
            state_changed_at: None,
            created_by,
            created_at: now_utc_seconds(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }
}

/// Current wire object carried by `ck.flow.create`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowCreateObject {
    pub id: FlowId,
    pub schema: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FlowMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    #[serde(default)]
    pub tracks: BTreeMap<String, FlowTrackConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    pub stage: ObjectStage,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl FlowCreateObject {
    pub fn new(id: FlowId, realm_id: RealmId, created_by: Did) -> Self {
        Self {
            id,
            schema: FLOW_SCHEMA.to_owned(),
            realm_id,
            scope_circle_id: None,
            metadata: None,
            encrypted_metadata: None,
            content: None,
            encrypted_content: None,
            tracks: BTreeMap::new(),
            state: None,
            stage: ObjectStage::Draft,
            created_by,
            created_at: now_utc_seconds(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn with_metadata_title(mut self, title: impl Into<String>) -> Self {
        self.metadata.get_or_insert_with(FlowMetadata::default).title = Some(title.into());
        self
    }

    pub fn with_metadata_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.get_or_insert_with(FlowMetadata::default).fields.insert(key.into(), value);
        self
    }

    pub fn with_track(mut self, name: impl Into<String>, track: FlowTrackConfig) -> Self {
        self.tracks.insert(name.into(), track);
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }
}

/// Payload shared by `ck.flow.update` and `ck.flow.tracks.update`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowPatchPayload {
    pub flow_id: FlowId,
    pub patch: Patch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

impl FlowPatchPayload {
    pub fn for_flow(flow_id: FlowId, patch: Patch) -> Result<Self> {
        patch.validate()?;
        Ok(Self { flow_id, patch, expected_state_digest: None })
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("flow patch payload serialize: {err}")))
    }
}

/// Flat-form payload for `ck.relation.create`
/// (`#/$defs/relation_create_payload`).
///
/// The spec `anyOf` allows either an embedded `{relation: <object_snapshot>}`
/// or the flat `{kind, from_ref, to_ref}` triple; this strong type models the
/// flat form (the only shape yougen constructs). `additionalProperties:false`
/// — so the legacy `relation_id` / `scope_circle_id` / `fields` keys that
/// older call sites tried to emit are intentionally NOT representable here;
/// the relation id is routed via the operation `target_ref`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RelationCreatePayload {
    /// Registered `relation_kind` (e.g. `ck.relation.parent_of`).
    pub kind: String,
    /// Source endpoint `object_ref` (canonical typed id / did / digest).
    pub from_ref: ObjectRef,
    /// Target endpoint `object_ref`.
    pub to_ref: ObjectRef,
    /// Optional lexical ordering rank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
}

impl RelationCreatePayload {
    pub fn new(
        kind: impl Into<String>,
        from_ref: impl Into<ObjectRef>,
        to_ref: impl Into<ObjectRef>,
    ) -> Self {
        Self { kind: kind.into(), from_ref: from_ref.into(), to_ref: to_ref.into(), rank: None }
    }

    pub fn with_rank(mut self, rank: impl Into<String>) -> Self {
        self.rank = Some(rank.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("relation create payload serialize: {err}")))
    }
}

/// Canonical membership state for `ck.member.state` payloads
/// (`event-payload.schema.json#/$defs/membership_state`).
///
/// Distinct from [`super::MembershipState`] (the roster projection enum, which
/// only models the live `join`/`invite`/`knock` states): the FSM transition
/// payload additionally carries the terminal `leave`/`ban` states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MembershipPayloadState {
    Join,
    Invite,
    Knock,
    Leave,
    Ban,
}

/// Strong type for `ck.member.state` payloads
/// (`event-payload.schema.json#/$defs/membership_payload`).
///
/// `additionalProperties:false`: the legacy `handle` / `from` keys that older
/// yougen call sites tried to emit are intentionally NOT representable here —
/// `handle` has no spec-legal home in this payload (the member identity is
/// carried by `actor_id`; handle evidence lives in signed `HandleClaim`
/// objects on the roster, not the durable membership event), and the FSM
/// `from` precondition is expressed via the operation `preconditions`/effect
/// `transition`, not the payload body.
///
/// Conditional required fields (schema `allOf`): when `membership == join`,
/// `realm_id` + `actor_id` + `delivery_status` are required; and additionally
/// when `delivery_status == routable`, `delivery_binding` is required. These
/// are enforced by [`MembershipPayload::to_value`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MembershipPayload {
    pub membership: MembershipPayloadState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<DeliveryStatus>,
    /// `member_delivery_binding` carried opaquely as a `Value`.
    ///
    /// NOTE: we intentionally do NOT type this as the SDK
    /// [`MemberDeliveryBinding`] struct: that struct models the `*_ref`
    /// fields (e.g. `service_acceptance_ref`) as the rich `EventRef`
    /// `{id, role, …}` object, whereas the spec
    /// `member_delivery_binding.service_acceptance_ref` is a bare
    /// `event_ref` string (`^ck:event:…$`). Routing a spec-correct binding
    /// through that struct fails to deserialize. The binding wire shape is
    /// validated by soland's `validate_payload` against the canonical schema;
    /// see the "real wire divergence" note in the migration spec. Producers
    /// build the binding `Value` directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_binding: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gate_proofs: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via_service_dids: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `oneOf(event_ref | invite_id)` — both are opaque strings on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_ref: Option<String>,
}

impl MembershipPayload {
    /// Build a non-`join` transition payload (`invite`/`knock`/`leave`/`ban`).
    pub fn transition(membership: MembershipPayloadState, actor_id: Did, reason: impl Into<String>) -> Self {
        Self {
            membership,
            flow_id: None,
            realm_id: None,
            actor_id: Some(actor_id),
            delivery_status: None,
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_dids: Vec::new(),
            reason: Some(reason.into()),
            invite_ref: None,
        }
    }

    /// Build a `join` transition payload with the schema-required
    /// `realm_id` + `actor_id` + `delivery_status` fields.
    pub fn join(
        realm_id: RealmId,
        actor_id: Did,
        delivery_status: DeliveryStatus,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            membership: MembershipPayloadState::Join,
            flow_id: None,
            realm_id: Some(realm_id),
            actor_id: Some(actor_id),
            delivery_status: Some(delivery_status),
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_dids: Vec::new(),
            reason: Some(reason.into()),
            invite_ref: None,
        }
    }

    pub fn with_realm_id(mut self, realm_id: RealmId) -> Self {
        self.realm_id = Some(realm_id);
        self
    }

    pub fn with_delivery_binding(mut self, binding: Value) -> Self {
        self.delivery_binding = Some(binding);
        self
    }

    pub fn with_invite_ref(mut self, invite_ref: impl Into<String>) -> Self {
        self.invite_ref = Some(invite_ref.into());
        self
    }

    /// Validate the schema-level conditional required fields, then serialize.
    pub fn to_value(&self) -> Result<Value> {
        if self.membership == MembershipPayloadState::Join {
            if self.realm_id.is_none() || self.actor_id.is_none() || self.delivery_status.is_none() {
                return Err(Error::Protocol(
                    "membership_payload{join} requires realm_id, actor_id, delivery_status"
                        .to_owned(),
                ));
            }
            if self.delivery_status == Some(DeliveryStatus::Routable)
                && self.delivery_binding.is_none()
            {
                return Err(Error::Protocol(
                    "membership_payload{join,routable} requires delivery_binding".to_owned(),
                ));
            }
        }
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("membership payload serialize: {err}")))
    }
}

/// Directed-create form of `invite_payload`
/// (`event-payload.schema.json#/$defs/invite_payload`, anyOf branch that
/// requires `invitee + invite_delivery_target + introduction_evidence_digest
/// + expires_at`). Carried by `ck.invite.create`.
///
/// The schema allows `x_*` extension properties (patternProperties
/// `^x_[a-z][a-z0-9_]{0,63}$`) but is otherwise `additionalProperties:false`;
/// the typed `x_*` extensions (e.g. `x_role`) are carried in [`Self::extensions`]
/// and re-prefixed on serialize.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InviteCreatePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    pub invitee: Did,
    pub invite_delivery_target: InviteDeliveryTarget,
    pub introduction_evidence_digest: Hash,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `x_*` extension properties (key is stored WITHOUT the `x_` prefix; the
    /// prefix is re-applied on serialize). e.g. `role` => wire `x_role`.
    #[serde(flatten, default, with = "x_prefixed_map")]
    pub extensions: BTreeMap<String, Value>,
}

impl InviteCreatePayload {
    pub fn new(
        invite_id: InviteId,
        invitee: Did,
        invite_delivery_target: InviteDeliveryTarget,
        introduction_evidence_digest: Hash,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            invite_id: Some(invite_id),
            invitee,
            invite_delivery_target,
            introduction_evidence_digest,
            expires_at,
            reason: None,
            extensions: BTreeMap::new(),
        }
    }

    pub fn with_extension(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        self.invite_delivery_target.validate()?;
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("invite create payload serialize: {err}")))
    }
}

/// Reference-by-id form of `invite_payload` (anyOf branch requiring
/// `invite_id`). Carried by `ck.invite.accept` / `ck.invite.cancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteRefPayload {
    pub invite_id: InviteId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl InviteRefPayload {
    pub fn new(invite_id: InviteId) -> Self {
        Self { invite_id, reason: None }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("invite ref payload serialize: {err}")))
    }
}

/// serde adapter that maps a `BTreeMap<String, Value>` to/from wire keys
/// carrying the mandatory `x_` extension prefix.
mod x_prefixed_map {
    use super::*;
    use serde::{Deserializer, Serializer, ser::SerializeMap};

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<String, Value>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            let key = if k.starts_with("x_") { k.clone() } else { format!("x_{k}") };
            m.serialize_entry(&key, v)?;
        }
        m.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<String, Value>, D::Error> {
        let raw = BTreeMap::<String, Value>::deserialize(deserializer)?;
        Ok(raw
            .into_iter()
            .map(|(k, v)| (k.strip_prefix("x_").map(str::to_owned).unwrap_or(k), v))
            .collect())
    }
}

/// Current wire object carried by `ck.morph.create`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MorphCreateObject {
    pub id: MorphId,
    pub schema: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    pub schema_refs: Vec<String>,
    pub morph_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facets: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MorphMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    pub stage: ObjectStage,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl MorphCreateObject {
    pub fn new(
        id: MorphId,
        realm_id: RealmId,
        morph_type: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            id,
            schema: MORPH_SCHEMA.to_owned(),
            realm_id,
            scope_circle_id: None,
            schema_refs: vec![MORPH_SCHEMA.to_owned()],
            morph_type: morph_type.into(),
            facets: BTreeMap::new(),
            metadata: None,
            encrypted_metadata: None,
            content: None,
            encrypted_content: None,
            fields: BTreeMap::new(),
            state: None,
            stage: ObjectStage::Draft,
            created_by,
            created_at: now_utc_seconds(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.metadata.get_or_insert_with(MorphMetadata::default).title = Some(title.into());
        self
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.metadata.get_or_insert_with(MorphMetadata::default).summary = Some(summary.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.get_or_insert_with(MorphMetadata::default).extra.insert(key.into(), value);
        self
    }

    pub fn with_content(mut self, content: Value) -> Self {
        self.content = Some(content);
        self.encrypted_content = None;
        self
    }

    pub fn with_encrypted_content(mut self, encrypted_content: Value) -> Self {
        self.encrypted_content = Some(encrypted_content);
        self.content = None;
        self
    }

    pub fn with_facet(mut self, name: impl Into<String>, value: Value) -> Self {
        self.facets.insert(name.into(), value);
        self
    }

    pub fn with_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.fields.insert(key.into(), value);
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    pub fn validate_content_carrier(&self) -> Result<()> {
        if self.content.is_some() && self.encrypted_content.is_some() {
            return Err(Error::Protocol(
                "morph create object must not carry both content and encrypted_content".to_owned(),
            ));
        }
        if self.metadata.is_some() && self.encrypted_metadata.is_some() {
            return Err(Error::Protocol(
                "morph create object must not carry both metadata and encrypted_metadata"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn to_create_payload_value(&self) -> Result<Value> {
        self.validate_content_carrier()?;
        ObjectCreatePayload::new(self).to_value()
    }
}

/// Extensible ContentBlock used by message, Flow, and Morph content fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContentBlock {
    pub kind: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<ContentBlock>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ContentBlock {
    pub fn new(kind: impl Into<String>, body: impl Into<String>) -> Self {
        Self { kind: kind.into(), body: body.into(), parts: Vec::new(), extra: BTreeMap::new() }
    }

    pub fn text(body: impl Into<String>) -> Self {
        Self::new("ck.content.text", body)
    }

    pub fn with_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    pub fn with_part(mut self, part: ContentBlock) -> Self {
        self.parts.push(part);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("content block serialize: {err}")))
    }
}

/// Payload for `ck.message.create`.
///
/// Producers must choose exactly one of `content` or `encrypted_content`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageCreatePayload {
    pub flow_id: FlowId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    pub track_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

impl MessageCreatePayload {
    pub fn with_content(flow_id: FlowId, track_name: impl Into<String>, content: Value) -> Self {
        Self {
            flow_id,
            message_id: None,
            track_name: track_name.into(),
            content: Some(content),
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            blob_refs: Vec::new(),
            reply_to: None,
        }
    }

    pub fn with_encrypted_content(
        flow_id: FlowId,
        track_name: impl Into<String>,
        encrypted_content: Value,
    ) -> Self {
        Self {
            flow_id,
            message_id: None,
            track_name: track_name.into(),
            content: None,
            encrypted_content: Some(encrypted_content),
            metadata: None,
            encrypted_metadata: None,
            blob_refs: Vec::new(),
            reply_to: None,
        }
    }

    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to = Some(reply_to.into());
        self
    }

    pub fn content_mut(&mut self) -> Option<&mut Value> {
        self.content.as_mut()
    }

    pub fn to_value(&self) -> Result<Value> {
        if self.metadata.is_some() && self.encrypted_metadata.is_some() {
            return Err(Error::Protocol(
                "message create payload must not carry both metadata and encrypted_metadata"
                    .to_owned(),
            ));
        }
        match (self.content.is_some(), self.encrypted_content.is_some()) {
            (true, false) | (false, true) => serde_json::to_value(self)
                .map_err(|err| Error::Protocol(format!("message create payload serialize: {err}"))),
            (false, false) => Err(Error::Protocol(
                "message create payload requires content or encrypted_content".to_owned(),
            )),
            (true, true) => Err(Error::Protocol(
                "message create payload must not carry both content and encrypted_content"
                    .to_owned(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_create_payload_wraps_object() {
        let actor = Did::new("did:web:alice.example".to_owned()).unwrap();
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let flow_id = FlowId::new("ck:flow:01904100-0000-7000-8000-000000000002").unwrap();
        let flow = FlowCreateObject::new(flow_id, realm_id, actor)
            .with_metadata_title("Incident")
            .with_track("discussion", FlowTrackConfig::discussion_primary());
        let payload = ObjectCreatePayload::new(flow).to_value().unwrap();
        assert_eq!(payload["object"]["schema"], FLOW_SCHEMA);
        assert_eq!(payload["object"]["stage"], "draft");
        assert_eq!(payload["object"]["metadata"]["title"], "Incident");
        canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
            .unwrap();
    }

    #[test]
    fn space_create_object_uses_canonical_timestamp() {
        let actor = Did::new("did:web:alice.example".to_owned()).unwrap();
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let space_id = SpaceId::new("ck:space:01904100-0000-7000-8000-000000000002").unwrap();
        let space = SpaceCreateObject::new(space_id, realm_id, "board", "Board", actor);
        let payload = ObjectCreatePayload::new(space).to_value().unwrap();
        canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
            .unwrap();
    }

    #[test]
    fn morph_create_payload_uses_metadata_and_encrypted_content_names() {
        let actor = Did::new("did:web:alice.example".to_owned()).unwrap();
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let morph_id = MorphId::new("ck:morph:01904100-0000-7000-8000-000000000002").unwrap();
        let morph = MorphCreateObject::new(morph_id, realm_id, "document", actor)
            .with_title("Spec")
            .with_summary("Draft")
            .with_encrypted_content(json!({"version": 1}));
        let payload = ObjectCreatePayload::new(morph).to_value().unwrap();
        assert_eq!(payload["object"]["metadata"]["title"], "Spec");
        assert_eq!(payload["object"]["metadata"]["summary"], "Draft");
        assert_eq!(payload["object"]["encrypted_content"]["version"], 1);
        canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
            .unwrap();
        assert!(payload["object"].get("title").is_none());
        assert!(payload["object"].get("summary").is_none());
        assert!(payload["object"].get("encrypted_payload").is_none());
    }

    #[test]
    fn message_create_payload_requires_exactly_one_content_carrier() {
        let flow_id = FlowId::new("ck:flow:01904100-0000-7000-8000-000000000002").unwrap();
        let payload = MessageCreatePayload::with_content(
            flow_id,
            "discussion",
            ContentBlock::text("hello").to_value().unwrap(),
        )
        .to_value()
        .unwrap();
        assert_eq!(payload["content"]["kind"], "ck.content.text");
        assert!(payload.get("encrypted_content").is_none());
    }

    #[test]
    fn morph_create_object_rejects_both_content_carriers() {
        let actor = Did::new("did:web:alice.example".to_owned()).unwrap();
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let morph_id = MorphId::new("ck:morph:01904100-0000-7000-8000-000000000003").unwrap();
        let mut morph = MorphCreateObject::new(morph_id, realm_id, "document", actor);
        morph.content = Some(json!({"kind": "ck.content.text", "body": "hello"}));
        morph.encrypted_content = Some(json!({"schema": ENCRYPTED_ENVELOPE_SCHEMA}));

        let err = morph.to_create_payload_value().unwrap_err();
        assert!(err.to_string().contains("content and encrypted_content"));
    }
}
