//! MIMI interop event payloads.

use arkret_wire::{
    CommitStreamRef, CurrentRevision, DidCoreId, EventId, MimiRoomUri, RealmCommitId, Result,
    WireError,
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

/// Closed selector for
/// `current-state.schema.json#/$defs/current_mimi_room_binding/properties/selector`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimiRoomBindingSelectorKind {
    MimiRoomBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingSelector {
    pub kind: MimiRoomBindingSelectorKind,
    pub mimi_room_uri: MimiRoomUri,
}

/// Complete authority current state, not the facade's payload-only projection.
/// `current-state.schema.json#/$defs/current_mimi_room_binding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentMimiRoomBinding {
    pub selector: MimiRoomBindingSelector,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: MimiRoomBindingPayload,
}

impl CurrentMimiRoomBinding {
    pub fn validate(&self) -> Result<()> {
        self.value.validate_shape()?;
        if self.selector.mimi_room_uri != self.value.mimi_room_uri {
            return Err(WireError::Protocol(
                "MIMI current selector must name its payload URI".to_owned(),
            ));
        }
        if self.source_stream_ref.realm_id() != &self.value.binding_scope.realm_id {
            return Err(WireError::Protocol(
                "MIMI current source must belong to its binding Realm".to_owned(),
            ));
        }
        Ok(())
    }
}

include!("generated/mimi_contracts.rs");

#[cfg(test)]
mod current_binding_tests {
    use serde_json::{Value, json};

    use super::*;

    fn specimen() -> Value {
        let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x41; 32]);
        let realm = RealmId::from_event_id(&event);
        let strand = StrandId::from_event_id(&event);
        json!({
            "selector": {"kind": "mimi_room_binding", "mimi_room_uri": "mimi://binding.example/rooms/one"},
            "source_stream_ref": {"kind": "realm", "realm_id": realm},
            "revision": {"commit_id": RealmCommitId::from_digest([0x42; 32]), "stream_position": 7},
            "value": {"profile": "ak.profile.mimi_interop.v1", "mimi_room_uri": "mimi://binding.example/rooms/one",
                "binding_scope": {"realm_id": realm, "strand_id": strand},
                "hub_provider_id": "ak:did_core:web:binding.example", "local_provider_role": "hub", "status": "accepted"}
        })
    }

    #[test]
    fn complete_current_round_trips_and_rejects_partial_or_foreign_selectors() {
        let original = specimen();
        let current: CurrentMimiRoomBinding = serde_json::from_value(original.clone()).unwrap();
        current.validate().unwrap();
        assert_eq!(serde_json::to_value(current).unwrap(), original);
        for mutation in [
            "missing_source",
            "foreign_kind",
            "extra_selector_field",
            "extra_current_field",
        ] {
            let mut value = original.clone();
            match mutation {
                "missing_source" => {
                    value.as_object_mut().unwrap().remove("source_stream_ref");
                }
                "foreign_kind" => value["selector"]["kind"] = json!("agent_status"),
                "extra_selector_field" => value["selector"]["agent_id"] = json!("unrelated"),
                _ => value["legacy"] = json!(true),
            }
            assert!(
                serde_json::from_value::<CurrentMimiRoomBinding>(value).is_err(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn current_validation_binds_room_identity_and_source_realm() {
        for mutation in ["room", "realm"] {
            let mut value = specimen();
            if mutation == "room" {
                value["selector"]["mimi_room_uri"] = json!("mimi://binding.example/rooms/two");
            } else {
                let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x43; 32]);
                value["source_stream_ref"]["realm_id"] = json!(RealmId::from_event_id(&event));
            }
            let current: CurrentMimiRoomBinding = serde_json::from_value(value).unwrap();
            assert!(current.validate().is_err(), "{mutation}");
        }
    }
}
