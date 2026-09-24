//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-23.1;
//! sha256=6f43b967676819bc1e9c91e4d25e66225b6ebdbd62e781521c1b4689d6603c19 Input: reachable event
//! schema closure; version=aggregate;
//! sha256=5e036cab38103bfd3fdfc1702ce4bfa56ba3acbb4fde2c312fe96d2ec917d1b9
//! Entries: preimage_commitments=36

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreimageCommitment {
    EnvelopeOmission,
    FixedEvent,
    LaterSubmission,
    NoEventIdentity,
    SameUnitSibling,
    SelfIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreimageCommitmentField {
    pub schema_file: &'static str,
    pub json_pointer: &'static str,
    pub commitment: PreimageCommitment,
}

pub const PREIMAGE_COMMITMENT_FIELDS: &[PreimageCommitmentField] = &[
    PreimageCommitmentField {
        schema_file: "schemas/agent-membership-cascade.schema.json",
        json_pointer: "/$defs/agent_controller_membership_binding/properties/controller_terminal_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/agent-provision.schema.json",
        json_pointer: "/properties/principal_control_realm_id",
        commitment: PreimageCommitment::LaterSubmission,
    },
    PreimageCommitmentField {
        schema_file: "schemas/call-recording-artifact.schema.json",
        json_pointer: "/$defs/call_recording_deletion_audit/properties/trigger_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/call-recording-artifact.schema.json",
        json_pointer: "/$defs/recording_encryption/properties/context/properties/recording_start_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/call-recording-artifact.schema.json",
        json_pointer: "/properties/recording_start_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/capability-grant.schema.json",
        json_pointer: "/properties/issuer_authority_refs/items/oneOf/1/properties/authority_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/contact-operations.schema.json",
        json_pointer: "/$defs/contact_scope_update_payload/properties/predecessor_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/erasure-verification-stub.schema.json",
        json_pointer: "/$defs/trigger/oneOf/0/properties/event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-envelope.schema.json",
        json_pointer: "/$defs/external_ref/properties/event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-envelope.schema.json",
        json_pointer: "/properties/event_id",
        commitment: PreimageCommitment::EnvelopeOmission,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/account_data_set_payload/properties/source_pending_event_id",
        commitment: PreimageCommitment::LaterSubmission,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/agent_action_approve_payload/properties/approved_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/agent_key_authorize_payload/properties/supersedes/items/properties/authorized_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/audit_accessed_payload/properties/late_recovery_original_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/audit_accessed_payload/properties/paired_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/call_state_payload/properties/recording_transition/properties/result/properties/recording_start_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/call_state_payload/properties/recording_transition/properties/result/properties/recording_stop_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/call_state_payload/properties/transcript_transition/properties/result/properties/transcript_start_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/call_state_payload/properties/transcript_transition/properties/result/properties/transcript_stop_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/contact_accepted_payload/properties/request_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/contact_rejected_payload/properties/request_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/contact_tombstoned_payload/properties/predecessor_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/member_identity_update_payload/properties/replaces/items/properties/event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/mimi_room_binding_migration_proof/properties/migrating_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/mimi_room_binding_migration_proof/properties/previous_accepted_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/poll_response_head/properties/poll_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/poll_response_head/properties/response_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/realm_link_payload/properties/counterpart_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/realm_tombstone_payload/properties/replacement_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/sidecar_context_attach_payload/properties/predecessor_event_ref",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/event-payload.schema.json",
        json_pointer: "/$defs/space_object_tombstone_payload/properties/replacement_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/key-backup-active-series.schema.json",
        json_pointer: "/properties/auth_data/properties/device_authorize_event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/moderation-evidence.schema.json",
        json_pointer: "/$defs/franking_proof/properties/event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/read-cursor.schema.json",
        json_pointer: "/$defs/position/properties/event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
    PreimageCommitmentField {
        schema_file: "schemas/realm-genesis.schema.json",
        json_pointer: "/properties/genesis_salt",
        commitment: PreimageCommitment::NoEventIdentity,
    },
    PreimageCommitmentField {
        schema_file: "schemas/resource-selector.schema.json",
        json_pointer: "/properties/event_id",
        commitment: PreimageCommitment::FixedEvent,
    },
];

pub fn preimage_commitment_at(schema_file: &str, json_pointer: &str) -> Option<PreimageCommitment> {
    PREIMAGE_COMMITMENT_FIELDS
        .iter()
        .find(|field| field.schema_file == schema_file && field.json_pointer == json_pointer)
        .map(|field| field.commitment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_commitments_are_unique_and_queryable_by_exact_pointer() {
        for (index, field) in PREIMAGE_COMMITMENT_FIELDS.iter().enumerate() {
            assert_eq!(
                preimage_commitment_at(field.schema_file, field.json_pointer),
                Some(field.commitment)
            );
            assert!(!PREIMAGE_COMMITMENT_FIELDS[..index].iter().any(|earlier| {
                earlier.schema_file == field.schema_file
                    && earlier.json_pointer == field.json_pointer
            }));
        }
        assert_eq!(
            preimage_commitment_at("schemas/event-envelope.schema.json", "/properties/event_id"),
            Some(PreimageCommitment::EnvelopeOmission)
        );
        assert_eq!(
            preimage_commitment_at(
                "schemas/agent-provision.schema.json",
                "/properties/principal_control_realm_id"
            ),
            Some(PreimageCommitment::LaterSubmission)
        );
    }
}
