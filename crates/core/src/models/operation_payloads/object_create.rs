use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::canonical::now_utc_seconds;
use crate::*;

/// Generic create-event payload used by Realm / Space / Strand / Morph creates.
///
/// The concrete object type is schema-specific, but the event payload envelope
/// is shared: `{ "object": ... }` plus optional initial relations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectCreatePayload<T> {
    pub object: T,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initial_relations: Vec<BTreeMap<String, Value>>,
}

impl<T> ObjectCreatePayload<T> {
    pub fn new(object: T) -> Self {
        Self {
            object,
            initial_relations: Vec::new(),
        }
    }

    pub fn with_initial_relation(mut self, relation: BTreeMap<String, Value>) -> Self {
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

/// Current wire object carried by `ak.space.create`.
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

/// Current wire object carried by `ak.strand.create`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrandCreateObject {
    pub id: StrandId,
    pub schema: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<StrandMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    #[serde(default)]
    pub tracks: BTreeMap<String, StrandTrackConfig>,
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

impl StrandCreateObject {
    pub fn new(id: StrandId, realm_id: RealmId, created_by: Did) -> Self {
        Self {
            id,
            schema: STRAND_SCHEMA.to_owned(),
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
        self.metadata
            .get_or_insert_with(StrandMetadata::default)
            .title = Some(title.into());
        self
    }

    pub fn with_metadata_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata
            .get_or_insert_with(StrandMetadata::default)
            .fields
            .insert(key.into(), value);
        self
    }

    pub fn with_track(mut self, name: impl Into<String>, track: StrandTrackConfig) -> Self {
        self.tracks.insert(name.into(), track);
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }
}

/// Payload for `ak.strand.update`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrandPatchPayload {
    pub target_ref: StrandId,
    pub patch: Patch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

impl StrandPatchPayload {
    pub fn for_strand(strand_id: StrandId, patch: Patch) -> Result<Self> {
        patch.validate()?;
        Ok(Self {
            target_ref: strand_id,
            patch,
            expected_state_digest: None,
        })
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("strand patch payload serialize: {err}")))
    }
}
