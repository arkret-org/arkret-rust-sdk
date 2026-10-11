//! MIMI interop event payloads.

use arkret_wire::{
    CurrentRevision, CurrentSelector, DidCoreId, EventId, RealmCommitId, Result, WireError,
};

use crate::internal_prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimiLocalProviderRole {
    Hub,
    Follower,
    Observer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimiRoomBindingStatus {
    Proposed,
    Accepted,
    Revoked,
    Migrating,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimiRoomBindingMigrationOutcome {
    Completed,
    RolledBack,
}

/// Accepted Event/RealmCommit lineage supplied by a migration resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingMigrationProof {
    pub previous_accepted_event_id: EventId,
    pub previous_accepted_commit_id: RealmCommitId,
    pub migrating_event_id: EventId,
    pub migrating_commit_id: RealmCommitId,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mimi_room_binding_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingPayloadBindingScope {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingPayload {
    pub profile: MimiInteropProfileId,
    pub mimi_room_uri: MimiRoomUri,
    pub binding_scope: MimiRoomBindingPayloadBindingScope,
    pub hub_provider_id: DidCoreId,
    pub local_provider_role: MimiLocalProviderRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follower_provider_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<MlsGroupId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_profile: Option<ContentProfileId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    pub status: MimiRoomBindingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_outcome: Option<MimiRoomBindingMigrationOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_proof: Option<MimiRoomBindingMigrationProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
}

impl MimiRoomBindingPayload {
    pub fn validate_shape(&self) -> Result<()> {
        if self.migration_outcome.is_some() != self.migration_proof.is_some() {
            return Err(WireError::Protocol(
                "MIMI binding migration_outcome and migration_proof must appear together"
                    .to_owned(),
            ));
        }
        if self.migration_outcome.is_some() && self.status != MimiRoomBindingStatus::Accepted {
            return Err(WireError::Protocol(
                "MIMI binding migration resolution must have accepted status".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Typed current result for the URI-keyed MIMI room binding projection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingCurrentRow {
    pub selector: CurrentSelector,
    pub revision: CurrentRevision,
    pub value: MimiRoomBindingPayload,
}

impl MimiRoomBindingCurrentRow {
    pub fn validate(&self) -> Result<()> {
        self.value.validate_shape()?;
        match &self.selector {
            CurrentSelector::MimiRoomBinding { mimi_room_uri }
                if mimi_room_uri == &self.value.mimi_room_uri =>
            {
                Ok(())
            }
            _ => Err(WireError::Protocol(
                "MIMI room binding current result selector must name its payload URI".to_owned(),
            )),
        }
    }
}
