//! Strand tracks-update payload retained by `arkret-core`.
//!
//! The strand move / reorder / watch payloads migrated to
//! `arkret-models-collaboration` (re-exported below).
//! [`StrandTracksUpdatePayload`] stays because it embeds the (not yet
//! migrated) `StrandTrackConfig` strand type.

use std::collections::BTreeMap;

pub use arkret_models_collaboration::events_payloads::strand_ops::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

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
            return Err(Error::Protocol(
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
            return Err(Error::Protocol(
                "strand tracks update requires patch or tracks".to_owned(),
            ));
        }
        if let Some(patch) = &self.patch {
            patch.validate()?;
        }
        if let Some(tracks) = &self.tracks {
            if tracks.is_empty() {
                return Err(Error::Protocol(
                    "strand tracks update requires non-empty tracks".to_owned(),
                ));
            }
            for track_name in tracks.keys() {
                validate_strand_track_name(track_name)?;
            }
        }
        serde_json::to_value(self).map_err(Error::from)
    }
}
