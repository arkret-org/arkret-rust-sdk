//! Strand create payload builder for event drafts.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::ContentBlock;
use arkret_models_collaboration::governance::agent_participation::AgentParticipationPolicy;
use arkret_models_collaboration::objects::profiles::StrandTrack;
use arkret_models_collaboration::objects::strand::StrandMetadata;
use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
use arkret_wire::{CircleId, DidCoreId, ObjectStage, ObjectState, RealmId, SchemaId, StrandId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn now_utc_canonical() -> DateTime<Utc> {
    arkret_canonical::normalize_timestamp_canonical(Utc::now())
}

/// Current wire object carried by `ak.strand.create`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandCreateObject {
    /// Absent by contract: `ak.strand.create` is an `event_derived` kind, so
    /// the Strand id is `StrandId::from_event_id(&event_id)` and the payload
    /// MUST omit it (spec `zh/models/common-fields.md` section 6.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<StrandId>,
    pub schema: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<StrandMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default)]
    pub tracks: BTreeMap<String, StrandTrack>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    pub stage: ObjectStage,
    pub created_by: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl arkret_models_collaboration::events_payloads::ProtocolCreateObject for StrandCreateObject {}

impl StrandCreateObject {
    /// Build a create input. There is no id parameter — see [`Self::id`].
    pub fn new(realm_id: RealmId, created_by: DidCoreId) -> Self {
        Self {
            id: None,
            schema: SchemaId::STRAND_V1.to_owned(),
            realm_id,
            scope_circle_id: None,
            agent_participation: None,
            metadata: None,
            encrypted_metadata: None,
            content: None,
            encrypted_content: None,
            tracks: BTreeMap::new(),
            state: None,
            stage: ObjectStage::Draft,
            created_by,
            created_at: now_utc_canonical(),
            updated_by: None,
            updated_at: None,
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

    pub fn with_track(mut self, name: impl Into<String>, track: StrandTrack) -> Self {
        self.tracks.insert(name.into(), track);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strand_create_object_omitted_updated_at_round_trip() {
        let object = StrandCreateObject::new(
            RealmId::new("ak:realm:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
        );

        let serialized = serde_json::to_value(&object).unwrap();
        assert!(!serialized.as_object().unwrap().contains_key("updated_at"));

        let restored: StrandCreateObject = serde_json::from_value(serialized).unwrap();
        assert!(restored.updated_at.is_none());
        assert_eq!(restored.realm_id, object.realm_id);
    }
}
