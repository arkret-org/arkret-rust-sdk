//! Flow model and shared object metadata.

use super::*;

/// Shared `metadata` shape for materialised objects that carry
/// `metadata.title` / `metadata.summary` (Flow, Morph). Field set matches
/// `flow.schema.json#/$defs/metadata` (common-fields §3): `title`, `summary`,
/// `fields`, plus a `#[serde(flatten)]` `extra` catch-all. Empty `fields` is
/// omitted from the wire (`skip_serializing_if`), so objects that do not use
/// `metadata.fields` (e.g. Morph, which carries top-level `fields`) serialise
/// identically to a metadata object without a `fields` member.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ObjectMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ObjectMetadata {
    pub fn with_title(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            ..Self::default()
        }
    }
}

/// Flow `metadata` shape — see [`ObjectMetadata`].
pub type FlowMetadata = ObjectMetadata;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MessageMetadata {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Flow {
    pub id: FlowId,
    pub schema: String,
    pub realm_id: RealmId,
    /// CKP-0007 (spec b7d35be) — optional Circle scope binding. When set, all
    /// Flow tracks share the referenced Circle's MLS group, membership and
    /// history visibility; when unset the Flow lives in the Realm-default
    /// scope. Rebinding `scope_circle_id` is forbidden by default (reducer
    /// reason `scope_rebind_forbidden`). The Circle's parent Realm MUST
    /// equal the Flow's Realm.
    ///
    /// Declaration order mirrors `spec/v1/artifacts/schemas/flow.schema.json`
    /// (common-fields §3.2): `id, schema, realm_id, scope_circle_id, …`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FlowMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<Value>,
    #[serde(rename = "content", skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    /// Active Flow tracks keyed by canonical track name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tracks: BTreeMap<String, FlowTrackConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// Business-progression stage (spec `flow.schema.json` required `stage`).
    /// Orthogonal to lifecycle `state`. Mutated only via `ck.flow.stage.set`;
    /// constructors default to [`ObjectStage::Draft`], consistent with Morph.
    pub stage: ObjectStage,
    /// Reducer-derived timestamp of the most recent `stage` transition;
    /// preserved on deserialize, omitted by producers (servers populate it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage_changed_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Flow {
    pub fn new(id: FlowId, realm_id: RealmId, title: impl Into<String>, created_by: Did) -> Self {
        let mut tracks = BTreeMap::new();
        tracks.insert(
            FLOW_TRACK_NAME_SYNTHESIS.to_owned(),
            FlowTrackConfig::synthesis(),
        );
        Self {
            id,
            schema: FLOW_SCHEMA.to_owned(),
            realm_id,
            scope_circle_id: None,
            metadata: Some(FlowMetadata::with_title(title)),
            encrypted_metadata: None,
            body: None,
            encrypted_content: None,
            tracks,
            state: Some(ObjectState::Active),
            state_changed_at: None,
            stage: ObjectStage::Draft,
            stage_changed_at: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn with_metadata_title(mut self, title: impl Into<String>) -> Self {
        self.metadata
            .get_or_insert_with(FlowMetadata::default)
            .title = Some(title.into());
        self
    }

    pub fn metadata_title(&self) -> Option<&str> {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.title.as_deref())
    }

    pub fn metadata_summary(&self) -> Option<&str> {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.summary.as_deref())
    }

    pub fn metadata_fields(&self) -> Option<&BTreeMap<String, Value>> {
        self.metadata.as_ref().map(|metadata| &metadata.fields)
    }

    /// Construct a Flow whose primary entry point is the `discussion` track.
    pub fn discussion(
        id: FlowId,
        realm_id: RealmId,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        let mut flow = Self::new(id, realm_id, title, created_by);
        let mut tracks = BTreeMap::new();
        tracks.insert(
            FLOW_TRACK_NAME_SYNTHESIS.to_owned(),
            FlowTrackConfig::synthesis(),
        );
        tracks.insert(
            FLOW_TRACK_NAME_DISCUSSION.to_owned(),
            FlowTrackConfig::discussion_primary(),
        );
        flow.tracks = tracks;
        flow
    }

    pub fn is_conversational(&self) -> bool {
        resolve_primary_track(&self.tracks, None)
            .ok()
            .flatten()
            .is_some_and(|(name, _)| name == FLOW_TRACK_NAME_DISCUSSION)
    }

    pub fn validate_title(&self) -> Result<()> {
        if self
            .metadata_title()
            .is_none_or(|title| title.trim().is_empty())
        {
            return Err(Error::Protocol("flow title must not be empty".to_owned()));
        }
        if self.tracks.is_empty() {
            return Err(Error::Protocol("flow tracks must not be empty".to_owned()));
        }
        for track_name in self.tracks.keys() {
            validate_flow_track_name(track_name)?;
        }
        Ok(())
    }
}
