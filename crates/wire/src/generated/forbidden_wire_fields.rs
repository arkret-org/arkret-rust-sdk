//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/forbidden-wire-fields.json; version=unversioned;
//! sha256=6dfec255c5af491a11cb84cb7f7ed7ee2c61a788618c41ed2b435fbbb715cf6b
//! Entries: forbidden_wire_fields=261

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForbiddenWireFieldDescriptor {
    pub id: &'static str,
    pub context: &'static str,
    pub rejection_level: &'static str,
}

/// Canonical projection of `registry/forbidden-wire-fields.json`: field
/// names that MUST NOT appear on the current v1 wire in the listed context.
/// Patch-context entries carry the registry's `patch:` prefix on their id
/// (for example `patch:stage`). Consumers query this table through
/// `arkret_wire::forbidden_wire` and never spell their own list.
pub const FORBIDDEN_WIRE_FIELDS: &[ForbiddenWireFieldDescriptor] = &[
    ForbiddenWireFieldDescriptor {
        id: "events",
        context: "account_subscribe_device_message_container",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "space_entry",
        context: "account_subscribe_frame_schema_def",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "accountable_to",
        context: "actor_profile",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "actor_kind=agent_ghost",
        context: "actor_profile.actor_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "actor_kind=agent_native",
        context: "actor_profile.actor_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "actor_kind=device",
        context: "actor_profile.actor_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "actor_kind=ghost",
        context: "actor_profile.actor_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "actor",
        context: "agent.audit_binding",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "evidence_ref",
        context: "agent_key_authorize_runtime_attestation",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "accountable_actor",
        context: "agent_key_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "agent_did",
        context: "agent_key_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "changed_at",
        context: "agent_lifecycle_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "account_data_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "account_data_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allowed_data_classes",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allowed_morph_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allowed_object_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allowed_target_classes",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "artifact DSL type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "backup_class",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "by_tier_and_class",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "capability_tiers",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "claim_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "constraint_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "content_class",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "data_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "denied_morph_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "denied_object_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "destination_service_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "device_key_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "did_service_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "expected_classes",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "field_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "field_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "from_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "item_object_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "item_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "item_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "lattice_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "link_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "morph_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "morph_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "notary.type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "notary_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "notification_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "object_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "object_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "op_target_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "policy_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "profile_tiers",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "proposal_morph_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "purpose_class",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "purpose_classes",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "range_request_same_error_class",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "receipt_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "recipient_service_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "recovery transcript type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "rejected_input_classes",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "requested_source_class",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "required_constraint_subtypes",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "required_constraint_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "resource_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "resource_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "risk_class",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "same_timing_class",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "serviceType",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "service_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "service_types",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "share_class",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "signal_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "subtype",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "surface group tier",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "to_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "type_restriction",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "verified_principal_type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "webhook_auth.type",
        context: "all_arkret_owned_wire_canonical_json_and_executable_artifact_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_binding_sources",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_delegated_native_actors",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_e2ee_join",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_ghost_actors",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_if_visibility_allows",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_ipv6",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_last_resort",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_mls_join",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_plaintext_fallback",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_plaintext_realms",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_redact_after_window",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_scope_expansion",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_t0_visible_with_current_policy",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_tcp",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_udp",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allow_widget",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "allowed_introduction_kinds",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "batch_size",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "deny_redacted_history",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "failure_code",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "forbidden_introduction_kinds",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "force_turn",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "from_tree_size",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "override_requires_organization_approval",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "permitted_introduction_kinds",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "quorum_size",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "rejection_code",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "require_audit_trail",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "require_consent",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "require_key_backup",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "require_parent_reference",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "requires_claims",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "requires_consent",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "requires_franking_proof_verification",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "requires_fresh_authentication",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "requires_human_review",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "requires_mls_join",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "root_hash",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "segment_size",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "to_tree_size",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "tree_size",
        context: "all_arkret_owned_wire_contexts",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "icon_blob",
        context: "applet_protocol_metadata",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "audit_agent_did",
        context: "attestation_evidence",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "evidence_id",
        context: "audit_release_attestation",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "stage",
        context: "audit_session_contract",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "sha256",
        context: "blob_metadata",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "thumbnail_ref",
        context: "blob_metadata",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "size",
        context: "blob_upload_metadata",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "source_capability",
        context: "capability_grant_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "require_scope_ref",
        context: "child_scope_policy.kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "blocks",
        context: "content_block_composite",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "encrypted_payload",
        context: "content_carrier_with_content_counterpart",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "cas-register",
        context: "crdt_lattice_enum",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "mv-register",
        context: "crdt_lattice_enum",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "or-set",
        context: "crdt_lattice_enum",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ordered-log",
        context: "crdt_lattice_enum",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "device_key_alg",
        context: "device_authorize_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "avatar",
        context: "directory_projection",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "name",
        context: "directory_projection",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "official_organizations",
        context: "directory_projection",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "blocked_principal_services",
        context: "directory_query_policy",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "blocked_subjects",
        context: "directory_query_policy",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "parent_realm_id",
        context: "directory_search_request",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "cleartext_commitment",
        context: "encrypted_envelope",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "frank_unavailable",
        context: "error_code",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "room_kind",
        context: "event_envelope_or_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak.agent.key.authorized",
        context: "event_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak.agent.key.revoked",
        context: "event_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak.agent.key.rotate",
        context: "event_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak.agent.key.rotated",
        context: "event_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak.device.authorized",
        context: "event_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak.device.revoked",
        context: "event_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak.relation.delete",
        context: "event_kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak.read.marker",
        context: "event_kind_or_capability_action",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "sender",
        context: "event_payload_or_projection",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "payload_hash",
        context: "event_proof",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "signed_payload_hash",
        context: "federation_verification_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "cleartext_sha256",
        context: "file_transfer_payload_or_account_data_value",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "space_frontier",
        context: "frontier_object_property",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "payload_hash",
        context: "generic_proof",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "grant_constraint_single_kind_refs_to_ids",
        context: "grant_constraint",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "claim_kind",
        context: "handle_claim_top_level",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ok",
        context: "http_response_body",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "blocked_handle_domains",
        context: "invite_receive_policy_constraints",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "parent_space_refs",
        context: "join_policy_component",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "hash#key_backup_kdf_params",
        context: "key_backup.encryption.kdf.params",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "signature_alg",
        context: "key_backup_recovery_auth_data",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "endpoint_signature",
        context: "keypackage_upload_entry",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "available_count",
        context: "keypackages_upload_outcome",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "space_bound",
        context: "media_metadata.visibility",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "participant_identity",
        context: "media_response_backend_token_roster_binding_sfu_answer_exporter_context_error_code_or_vector_id",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "avatar_ref",
        context: "member_identity.display_profile",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "via",
        context: "membership_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "via_ids",
        context: "membership_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "track_name",
        context: "message",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "message_id",
        context: "message_create_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "revision_root",
        context: "message_create_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "requester",
        context: "mimi_request_consent_request_body",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "actor",
        context: "mimi_update_consent_request_body",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "endpoint_signature",
        context: "mls_keypackage_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "queue_item_id",
        context: "moderation_queue_item",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "requires_frank_verification",
        context: "moderation_queue_item.evidence_policy",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "retention_until",
        context: "moderation_queue_item.evidence_policy",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "frank_only",
        context: "moderation_queue_item.visibility",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "frank",
        context: "moderation_report_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "fields.lifecycle",
        context: "morph_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "fields.progress_state",
        context: "morph_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "fields.stage",
        context: "morph_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "fields.stage_changed_at",
        context: "morph_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "fields.stage_note",
        context: "morph_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "fields.stage_reason",
        context: "morph_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:morph_kind",
        context: "morph_update_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:stage",
        context: "morph_update_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "notification.space_name",
        context: "notification_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "sender_display_name",
        context: "notification_projection",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "object_ref",
        context: "object_lifecycle_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "object_ref",
        context: "object_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "stage",
        context: "pending_sidecar_access_reconciliation_item",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "sidecar_exchange_binding",
        context: "plaintext_metadata_or_shared_scope_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "signed_by",
        context: "proof_or_cross_signing_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "actor_did",
        context: "protocol_subject_field",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "principal_did",
        context: "protocol_subject_field",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "subject_did",
        context: "protocol_subject_field",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "alias",
        context: "realm_object_or_realm_lifecycle_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "cowrite_policy",
        context: "realm_object_or_realm_lifecycle_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "realm_alias",
        context: "realm_object_or_realm_lifecycle_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "retention_policy",
        context: "realm_object_or_realm_lifecycle_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "commitment_b64",
        context: "recovery_policy.share_commitment",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "fields.rank",
        context: "relation_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "bootstrap_binding",
        context: "retired_device_identity_wire",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "cross_signing_binding",
        context: "retired_device_identity_wire",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "enrollment_authority_binding",
        context: "retired_device_identity_wire",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "recovery_authority_ticket",
        context: "retired_device_identity_wire",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ssk_generation",
        context: "retired_device_identity_wire",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "of",
        context: "reviewer_quorum",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak.schema.read_marker.v1",
        context: "schema_id",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "notary_sig",
        context: "seal",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "cotest_issuer_did",
        context: "service_describe_verified_profiles",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "cotest_run_id",
        context: "service_describe_verified_profiles",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "identifier_suffix_ref_to_id_batch",
        context: "single_kind_identifier_fields",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "sha256",
        context: "snapshot.chunks[]",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "fields.rank",
        context: "space_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "history_access",
        context: "space_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "join_rule",
        context: "space_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "security_class",
        context: "space_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "fields",
        context: "strand_or_message_payload_top_level",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "summary",
        context: "strand_or_morph_payload_top_level",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "title",
        context: "strand_or_morph_payload_top_level",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:fields.assigned_actor_ids",
        context: "strand_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:fields.assigned_to",
        context: "strand_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:fields.assignee",
        context: "strand_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:fields.assignees",
        context: "strand_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:metadata.fields.assigned_actor_ids",
        context: "strand_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:metadata.fields.assigned_to",
        context: "strand_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:metadata.fields.assignee",
        context: "strand_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:metadata.fields.assignees",
        context: "strand_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "patch:stage",
        context: "strand_patch_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "discussion_space_ref",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.assigned_actor_ids",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.assigned_to",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.assignee",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.assignees",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.lifecycle",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.progress_state",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.stage",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.stage_changed_at",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.stage_note",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.stage_reason",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "metadata.fields.status",
        context: "strand_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "kind=room",
        context: "strand_payload.kind",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "track",
        context: "strand_track_key_field",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "branch",
        context: "timeline_event_top_level",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak:devmsg:",
        context: "typed_id_prefix",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak:keyevt:",
        context: "typed_id_prefix",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak:modq:",
        context: "typed_id_prefix",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak:notif:",
        context: "typed_id_prefix",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak:req:",
        context: "typed_id_prefix",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak:rtcpart:",
        context: "typed_id_prefix",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "ak:txn:",
        context: "typed_id_prefix",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "duration_compact_mini_dsl",
        context: "wire_duration_string",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "cache_until",
        context: "wire_schema_or_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "cache_valid_until",
        context: "wire_schema_or_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "not_after",
        context: "wire_schema_or_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "valid_from",
        context: "wire_schema_or_payload",
        rejection_level: "hard_reject",
    },
    ForbiddenWireFieldDescriptor {
        id: "valid_until",
        context: "wire_schema_or_payload",
        rejection_level: "hard_reject",
    },
];
