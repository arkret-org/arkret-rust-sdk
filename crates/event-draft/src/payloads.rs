//! Strand create / tracks-update payload builders for event drafts.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::morph_message::ContentBlock;
use arkret_models_collaboration::governance::agent_participation::AgentParticipationPolicy;
use arkret_models_collaboration::objects::profiles::{
    StrandTrackConfig, validate_strand_track_name,
};
use arkret_models_collaboration::objects::strand::StrandMetadata;
use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
use arkret_wire::{
    CircleId, Did, ObjectStage, ObjectState, Patch, RealmId, STRAND_SCHEMA, StrandId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EventDraftError, Result};

fn now_utc_canonical() -> DateTime<Utc> {
    arkret_canonical::normalize_timestamp_canonical(Utc::now())
}

/// Current wire object carried by `ak.strand.create`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandCreateObject {
    pub id: StrandId,
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
    pub tracks: BTreeMap<String, StrandTrackConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    pub stage: ObjectStage,
    pub created_by: Did,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl StrandCreateObject {
    pub fn new(id: StrandId, realm_id: RealmId, created_by: Did) -> Self {
        Self {
            id,
            schema: STRAND_SCHEMA.to_owned(),
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

    pub fn with_track(mut self, name: impl Into<String>, track: StrandTrackConfig) -> Self {
        self.tracks.insert(name.into(), track);
        self
    }
}

/// Strong type for `ak.strand.tracks.update` payloads
/// (`event-payload.schema.json#/$defs/strand_tracks_update_payload`).
///
/// Track changes target a Strand through `strand_id`, not the generic
/// object-patch `target_ref`. Writers MUST carry either an atomic `patch` or a
/// full replacement `tracks` map; constructors enforce the non-empty branch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandTracksUpdatePayload {
    pub strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracks: Option<BTreeMap<String, StrandTrackConfig>>,
}

impl StrandTracksUpdatePayload {
    pub fn with_patch(strand_id: StrandId, patch: Patch) -> Result<Self> {
        patch.validate()?;
        Ok(Self {
            strand_id,
            patch: Some(patch),
            tracks: None,
        })
    }

    pub fn with_tracks(
        strand_id: StrandId,
        tracks: BTreeMap<String, StrandTrackConfig>,
    ) -> Result<Self> {
        if tracks.is_empty() {
            return Err(EventDraftError::Protocol(
                "strand tracks update requires non-empty tracks".to_owned(),
            ));
        }
        for track_name in tracks.keys() {
            validate_strand_track_name(track_name)?;
        }
        Ok(Self {
            strand_id,
            patch: None,
            tracks: Some(tracks),
        })
    }

    pub fn to_value(&self) -> Result<Value> {
        if self.patch.is_none() && self.tracks.is_none() {
            return Err(EventDraftError::Protocol(
                "strand tracks update requires patch or tracks".to_owned(),
            ));
        }
        if let Some(patch) = &self.patch {
            patch.validate()?;
        }
        if let Some(tracks) = &self.tracks {
            if tracks.is_empty() {
                return Err(EventDraftError::Protocol(
                    "strand tracks update requires non-empty tracks".to_owned(),
                ));
            }
            for track_name in tracks.keys() {
                validate_strand_track_name(track_name)?;
            }
        }
        serde_json::to_value(self).map_err(EventDraftError::from)
    }
}
