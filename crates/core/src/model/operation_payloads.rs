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
