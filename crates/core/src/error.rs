use thiserror::Error;

use crate::model::ErrorEnvelope;

pub type Result<T> = std::result::Result<T, Error>;

// ── Canonical error codes (mirror of `error-code-registry.json` v2026-05-09) ─
//
// Use these constants when populating `ErrorEnvelope.code` so the wire form
// stays in sync with the canonical registry. `error_code_http_status` returns
// the registered HTTP status binding for HTTP/JSON deployments.
pub const ERROR_CODE_BAD_JSON: &str = "bad_json";
pub const ERROR_CODE_BAD_QUERY: &str = "bad_query";
pub const ERROR_CODE_SCHEMA_VIOLATION: &str = "schema_violation";
pub const ERROR_CODE_MISSING_PARAM: &str = "missing_param";
pub const ERROR_CODE_INVALID_PARAM: &str = "invalid_param";
pub const ERROR_CODE_UNAUTHENTICATED: &str = "unauthenticated";
pub const ERROR_CODE_AUTH_EXPIRED: &str = "auth_expired";
pub const ERROR_CODE_SOFT_LOGGED_OUT: &str = "soft_logged_out";
pub const ERROR_CODE_INVALID_SIGNATURE: &str = "invalid_signature";
pub const ERROR_CODE_CAPABILITY_DENIED: &str = "capability_denied";
pub const ERROR_CODE_SPACE_FROZEN: &str = "space_frozen";
pub const ERROR_CODE_CLAIM_REQUIRED: &str = "claim_required";
pub const ERROR_CODE_NOT_FOUND: &str = "not_found";
pub const ERROR_CODE_UNRECOGNIZED_ENDPOINT: &str = "unrecognized_endpoint";
pub const ERROR_CODE_METHOD_NOT_ALLOWED: &str = "method_not_allowed";
pub const ERROR_CODE_CONFLICT: &str = "conflict";
pub const ERROR_CODE_CAS_CONFLICT: &str = "cas_conflict";
pub const ERROR_CODE_CAUSAL_CONFLICT: &str = "causal_conflict";
pub const ERROR_CODE_DEPENDENCY_MISSING: &str = "dependency_missing";
pub const ERROR_CODE_DISCUSSION_TRACK_DISABLED: &str = "discussion_track_disabled";
/// C14 / read-receipts §2.5: Sync Service drops `cx.receipt.read` events
/// when the effective Space `disclosure="disabled"` policy is in force, and
/// returns this code with `retry_after_ms=null` so the client knows it's a
/// hard policy refusal (not a transient back-off).
pub const ERROR_CODE_POLICY_VIOLATION: &str = "policy_violation";
pub const ERROR_CODE_EPOCH_MISMATCH: &str = "epoch_mismatch";
pub const ERROR_CODE_DUPLICATE_CONFLICT: &str = "duplicate_conflict";
pub const ERROR_CODE_RANK_EXHAUSTED: &str = "rank_exhausted";
pub const ERROR_CODE_HLC_LOGICAL_OVERFLOW: &str = "hlc_logical_overflow";
pub const ERROR_CODE_PAYLOAD_TOO_LARGE: &str = "payload_too_large";
pub const ERROR_CODE_DIGEST_MISMATCH: &str = "digest_mismatch";
pub const ERROR_CODE_AAD_DIGEST_MISMATCH: &str = "aad_digest_mismatch";
pub const ERROR_CODE_PAYLOAD_DIGEST_MISMATCH: &str = "payload_digest_mismatch";
pub const ERROR_CODE_KEY_UNAVAILABLE: &str = "key_unavailable";
pub const ERROR_CODE_STATE_MISMATCH: &str = "state_mismatch";
pub const ERROR_CODE_AUDIT_RECEIPT_INVALIDATED: &str = "audit_receipt_invalidated";
pub const ERROR_CODE_UNKNOWN_DID: &str = "unknown_did";
pub const ERROR_CODE_QUOTA_EXCEEDED: &str = "quota_exceeded";
pub const ERROR_CODE_RATE_LIMITED: &str = "rate_limited";
pub const ERROR_CODE_TIMEOUT: &str = "timeout";
pub const ERROR_CODE_STALE_FRONTIER: &str = "stale_frontier";
pub const ERROR_CODE_CURSOR_EXPIRED: &str = "cursor_expired";
pub const ERROR_CODE_SYNC_TOKEN_EXPIRED: &str = ERROR_CODE_CURSOR_EXPIRED;
pub const ERROR_CODE_UNSUPPORTED_FEATURE: &str = "unsupported_feature";
pub const ERROR_CODE_UNSUPPORTED_EVENT_KIND: &str = "unsupported_event_kind";
pub const ERROR_CODE_PROJECTION_INCOMPLETE: &str = "projection_incomplete";
pub const ERROR_CODE_INTERNAL_ERROR: &str = "internal_error";
pub const ERROR_CODE_TEMPORARILY_UNAVAILABLE: &str = "temporarily_unavailable";
pub const ERROR_CODE_POLICY_COMBINATION_INVALID: &str = "policy_combination_invalid";
pub const ERROR_CODE_ANCHORER_RECOVERY_MISSING: &str = "anchorer_recovery_missing";
pub const ERROR_CODE_UNSUPPORTED_LATTICE_TYPE: &str = "unsupported_lattice_type";
/// Round C44 (2026-05-18) — registry add: peer or ServiceDescribe advertises a
/// `cx.profile.*` ID this implementation does not support. Wire-level top
/// error code (not a `failed_precondition` sub-reason). Spec
/// `error-code-registry.json` v2026-05-18.
pub const ERROR_CODE_PROFILE_UNSUPPORTED: &str = "profile_unsupported";

// ── Round C45 (2026-05-18 main) — registry add (6 wire-level codes).
//
// Spec: `error-code-registry.json` (dc01ad7..5ed365c).
// `failed_precondition` carries the round-C45 state-machine reason families
// (flow_not_active, place_not_archived, morph_already_terminal, ...). See the
// `REASON_*` constants further below.
pub const ERROR_CODE_CURSOR_INTEGRITY_INVALID: &str = "cursor_integrity_invalid";
pub const ERROR_CODE_FAILED_PRECONDITION: &str = "failed_precondition";
pub const ERROR_CODE_UNSUPPORTED_HASH: &str = "unsupported_hash";
pub const ERROR_CODE_ANCHOR_INCOMPLETE: &str = "anchor_incomplete";
pub const ERROR_CODE_FRANK_UNAVAILABLE: &str = "frank_unavailable";
pub const ERROR_CODE_TURN_CREDENTIAL_EXPIRED: &str = "turn_credential_expired";

// ── Round C47 (2026-05-18 main, spec e10b6ad) — registry add (1 wire-level code).
//
// `stale_peer` is returned (409, service_call scope) when a federation
// high-assurance peer has missed proactive frontier probes or produced
// invalid/divergent frontier evidence and is quarantined for the affected
// Space until fork resolution succeeds. See zh/sync/federation.md §4.5.3.
pub const ERROR_CODE_STALE_PEER: &str = "stale_peer";

/// All canonical error codes recognised by the registry. The order matches
/// `error-code-registry.json`. Use [`is_known_error_code`] before populating
/// `ErrorEnvelope.code` from arbitrary input.
pub const KNOWN_ERROR_CODES: &[&str] = &[
    ERROR_CODE_BAD_JSON,
    ERROR_CODE_BAD_QUERY,
    ERROR_CODE_SCHEMA_VIOLATION,
    ERROR_CODE_MISSING_PARAM,
    ERROR_CODE_INVALID_PARAM,
    ERROR_CODE_UNAUTHENTICATED,
    ERROR_CODE_AUTH_EXPIRED,
    ERROR_CODE_SOFT_LOGGED_OUT,
    ERROR_CODE_INVALID_SIGNATURE,
    ERROR_CODE_CAPABILITY_DENIED,
    ERROR_CODE_SPACE_FROZEN,
    ERROR_CODE_CLAIM_REQUIRED,
    ERROR_CODE_NOT_FOUND,
    ERROR_CODE_UNRECOGNIZED_ENDPOINT,
    ERROR_CODE_METHOD_NOT_ALLOWED,
    ERROR_CODE_CONFLICT,
    ERROR_CODE_CAS_CONFLICT,
    ERROR_CODE_CAUSAL_CONFLICT,
    ERROR_CODE_DEPENDENCY_MISSING,
    ERROR_CODE_DISCUSSION_TRACK_DISABLED,
    ERROR_CODE_POLICY_VIOLATION,
    ERROR_CODE_EPOCH_MISMATCH,
    ERROR_CODE_DUPLICATE_CONFLICT,
    ERROR_CODE_RANK_EXHAUSTED,
    ERROR_CODE_HLC_LOGICAL_OVERFLOW,
    ERROR_CODE_PAYLOAD_TOO_LARGE,
    ERROR_CODE_DIGEST_MISMATCH,
    ERROR_CODE_AAD_DIGEST_MISMATCH,
    ERROR_CODE_PAYLOAD_DIGEST_MISMATCH,
    ERROR_CODE_KEY_UNAVAILABLE,
    ERROR_CODE_STATE_MISMATCH,
    ERROR_CODE_AUDIT_RECEIPT_INVALIDATED,
    ERROR_CODE_UNKNOWN_DID,
    ERROR_CODE_QUOTA_EXCEEDED,
    ERROR_CODE_RATE_LIMITED,
    ERROR_CODE_TIMEOUT,
    ERROR_CODE_STALE_FRONTIER,
    ERROR_CODE_CURSOR_EXPIRED,
    ERROR_CODE_UNSUPPORTED_FEATURE,
    ERROR_CODE_UNSUPPORTED_EVENT_KIND,
    ERROR_CODE_PROJECTION_INCOMPLETE,
    ERROR_CODE_INTERNAL_ERROR,
    ERROR_CODE_TEMPORARILY_UNAVAILABLE,
    ERROR_CODE_POLICY_COMBINATION_INVALID,
    ERROR_CODE_ANCHORER_RECOVERY_MISSING,
    ERROR_CODE_UNSUPPORTED_LATTICE_TYPE,
    ERROR_CODE_PROFILE_UNSUPPORTED,
    ERROR_CODE_CURSOR_INTEGRITY_INVALID,
    ERROR_CODE_FAILED_PRECONDITION,
    ERROR_CODE_UNSUPPORTED_HASH,
    ERROR_CODE_ANCHOR_INCOMPLETE,
    ERROR_CODE_FRANK_UNAVAILABLE,
    ERROR_CODE_TURN_CREDENTIAL_EXPIRED,
    ERROR_CODE_STALE_PEER,
];

// ── Failed-precondition reason codes (sub-codes inside `failed_precondition`)
//
// These are NOT top-level wire error codes; they go in the
// `failed_precondition` envelope's `reason` field. Round C44 (2026-05-18)
// added a batch of reasons for Tier-0 security (S3/S4/S5/S6),
// agent_workspace profile interactions, and source-export attestation.
// Spec: `error-code-registry.json#reason_codes`.

// Tier-0 S3 — `did:web` → `did:webvh` upgrade evidence (5 reasons).
pub const REASON_INCEPTION_UPGRADE_FINGERPRINT_MISMATCH: &str =
    "inception_upgrade_fingerprint_mismatch";
pub const REASON_INCEPTION_UPGRADE_SIGNATURE_CHAIN_INVALID: &str =
    "inception_upgrade_signature_chain_invalid";
pub const REASON_INCEPTION_UPGRADE_OLD_DOCUMENT_HASH_MISMATCH: &str =
    "inception_upgrade_old_document_hash_mismatch";
pub const REASON_INCEPTION_UPGRADE_EVIDENCE_INSUFFICIENT: &str =
    "inception_upgrade_evidence_insufficient";

// Tier-0 S6 — `attested_hardware` Audit Agent removal must be paired with
// `cx.audit.epoch_key_destruction` (round C45 drops the `.v1` kind suffix;
// wire schema versioning now flows through `requirements.features`).
pub const REASON_AUDIT_AGENT_KEY_DESTRUCTION_ATTESTATION_MISSING: &str =
    "audit_agent_key_destruction_attestation_missing";
pub const REASON_AUDIT_AGENT_REMOVE_REQUIRES_PAIRED_DESTRUCTION_ATTESTATION: &str =
    "audit_agent_remove_requires_paired_destruction_attestation";
pub const REASON_AUDIT_AGENT_DESTRUCTION_NOT_PAIRED_WITH_REMOVE: &str =
    "audit_agent_destruction_not_paired_with_remove";
pub const REASON_AUDIT_AGENT_DESTRUCTION_PROOF_NOT_ENCLAVE_SIGNED: &str =
    "audit_agent_destruction_proof_not_enclave_signed";
pub const REASON_AUDIT_AGENT_EPOCH_RANGE_INCOMPLETE: &str = "audit_agent_epoch_range_incomplete";
pub const REASON_AUDIT_AGENT_ATTESTATION_MISMATCH: &str = "audit_agent_attestation_mismatch";

// P-D4 — `cx.profile.e2ee_relaxed.v1` profile interactions.
pub const REASON_MLS_SEND_PAUSE_ADVISORY_REQUIRES_E2EE_RELAXED_PROFILE: &str =
    "mls_send_pause_advisory_requires_e2ee_relaxed_profile";
pub const REASON_CONFLICTING_E2EE_PROFILES: &str = "conflicting_e2ee_profiles";

// P-D13 — `cx.profile.agent_workspace.lite.v1` profile interactions.
pub const REASON_CONFLICTING_AGENT_WORKSPACE_PROFILES: &str =
    "conflicting_agent_workspace_profiles";
pub const REASON_LITE_PROFILE_WRITES_DISALLOWED_EVENT_KIND: &str =
    "lite_profile_writes_disallowed_event_kind";

// Agent Workspace reservation cell & source-export attestation.
pub const REASON_RESERVATION_CELL_ALREADY_SET: &str = "reservation_cell_already_set";
pub const REASON_SOURCE_EXPORT_ATTESTATION_MISSING: &str = "source_export_attestation_required";
pub const REASON_SOURCE_EXPORT_ATTESTATION_INVALID: &str = "source_export_attestation_invalid";
pub const REASON_SOURCE_EXPORT_ATTESTATION_EXPIRED: &str = "source_export_attestation_expired";
pub const REASON_SOURCE_EXPORT_ATTESTATION_DENIED: &str = "source_export_attestation_denied";
pub const REASON_SOURCE_EXPORT_AUTHORITY_UNAUTHORIZED: &str =
    "source_export_authority_unauthorized";
pub const REASON_SOURCE_EXPORT_CONTENT_HASH_MISMATCH: &str = "source_export_content_hash_mismatch";
pub const REASON_SOURCE_EXPORT_DESTINATION_MISMATCH: &str = "source_export_destination_mismatch";

// Misc.
pub const REASON_CARDINALITY_VIOLATION: &str = "cardinality_violation";
pub const REASON_CLAIM_FAILED: &str = "claim_failed";

// ── Round C45 (2026-05-18 main) — reason codes.
//
// `failed_precondition` sub-codes for lifecycle state machines, patch grammar,
// AEAD nonce derivation, accountability_grant verification, delegation, fork
// recovery witness, sender commitment, range completeness, and deprecation
// timeline. Spec: `error-code-registry.json#reason_codes`.

// Lifecycle state-machine guards (Flow / Place / Morph / Message / Relation).
pub const REASON_FLOW_NOT_ACTIVE: &str = "flow_not_active";
pub const REASON_FLOW_NOT_ARCHIVED: &str = "flow_not_archived";
pub const REASON_FLOW_ALREADY_TERMINAL: &str = "flow_already_terminal";
pub const REASON_PLACE_NOT_ACTIVE: &str = "place_not_active";
pub const REASON_PLACE_NOT_ARCHIVED: &str = "place_not_archived";
pub const REASON_PLACE_ALREADY_TERMINAL: &str = "place_already_terminal";
pub const REASON_PLACE_PARENT_CYCLE: &str = "place_parent_cycle";
pub const REASON_PLACE_HAS_LIVE_DEPENDENTS: &str = "place_has_live_dependents";
pub const REASON_MORPH_NOT_ACTIVE: &str = "morph_not_active";
pub const REASON_MORPH_NOT_ARCHIVED: &str = "morph_not_archived";
pub const REASON_MORPH_ALREADY_TERMINAL: &str = "morph_already_terminal";
pub const REASON_MESSAGE_ALREADY_TERMINAL: &str = "message_already_terminal";
pub const REASON_RELATION_ALREADY_TERMINAL: &str = "relation_already_terminal";

// Moderation report standard categories (alongside C44's spam/harassment).
pub const REASON_HATE_SPEECH: &str = "hate_speech";
pub const REASON_NSFW: &str = "nsfw";
pub const REASON_ILLEGAL: &str = "illegal";
pub const REASON_MISINFORMATION: &str = "misinformation";
pub const REASON_OTHER: &str = "other";

// Cursor integrity (paired with ERROR_CODE_CURSOR_INTEGRITY_INVALID).
pub const REASON_CURSOR_INTEGRITY_INVALID: &str = "cursor_integrity_invalid";

// Claim / KeyPackage rate-limit (per-target tuple).
pub const REASON_CLAIM_RATE_LIMITED: &str = "claim_rate_limited";

// Registry hygiene (lint warning, not wire reject).
pub const REASON_NAMING_CONVENTION_VIOLATION: &str = "naming_convention_violation";

// Approval signature replay protection (zh/authz/constraint-schema.md §9.3).
pub const REASON_APPROVAL_NONCE_REUSED: &str = "approval_nonce_reused";

// Applet / delegated envelope missing executed_by.
pub const REASON_EXECUTED_BY_MISSING: &str = "executed_by_missing";

// 3PID invite token transport (zh/sync/third-party-invites.md §3.2).
pub const REASON_THIRD_PARTY_INVITE_TOKEN_IN_QUERY: &str = "third_party_invite_token_in_query";

// Patch grammar / safety (zh/models/event-and-patch.md §4).
pub const REASON_PATCH_PATH_INVALID: &str = "patch_path_invalid";
pub const REASON_PATCH_PATH_REDUCER_MANAGED: &str = "patch_path_reducer_managed";
pub const REASON_PATCH_UNSET_REDACTABLE_FIELD: &str = "patch_unset_redactable_field";
pub const REASON_PATCH_SELECTOR_NO_MATCH: &str = "patch_selector_no_match";
pub const REASON_PATCH_SELECTOR_AMBIGUOUS: &str = "patch_selector_ambiguous";

// AEAD nonce derivation invariants.
pub const REASON_AEAD_NONCE_COUNTER_REPLAY: &str = "aead_nonce_counter_replay";
pub const REASON_AEAD_NONCE_DERIVATION_INVALID: &str = "aead_nonce_derivation_invalid";

// Accountability grant verification (zh/models/actor.md §3.3.1).
pub const REASON_ACCOUNTABILITY_GRANT_MISSING: &str = "accountability_grant_missing";

// MLS Welcome envelope replay binding (zh/crypto-media/encryption-and-audit.md §2.6).
pub const REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH: &str =
    "keypackage_welcome_envelope_mismatch";

// Capability delegation safety (zh/authz/capabilities.md §10).
pub const REASON_DELEGATION_CYCLE: &str = "delegation_cycle";
pub const REASON_DELEGATION_EXPIRY_WIDENING: &str = "delegation_expiry_widening";

// Fork-conflict recovery witness (zh/authz/event-auth-state-resolution.md §8.1).
pub const REASON_RECOVERY_WITNESS_MISSING: &str = "recovery_witness_missing";
pub const REASON_RECOVERY_WITNESS_INVALID: &str = "recovery_witness_invalid";
pub const REASON_RECOVERY_WITNESS_POST_CONFLICT: &str = "recovery_witness_post_conflict";
pub const REASON_RECOVERY_CAPABILITY_NOT_ANCHORED: &str = "recovery_capability_not_anchored";

// Policy server runtime challenge (zh/authz/policy-server.md §4).
pub const REASON_CHALLENGE_PROOF_INVALID: &str = "challenge_proof_invalid";

// Agent task FSM.
pub const REASON_INVALID_TASK_FSM_TRANSITION: &str = "invalid_task_fsm_transition";

// Watch state capabilities (zh/models/flow-and-message.md §8.4–8.5).
//
// `mixed_secret_storage_disallowed_by_profile` was dropped from the registry
// in round C47 (spec e10b6ad). The mixed-secret-storage check is no longer
// a wire-level reason — schema-level validation in `key-management.md §7.1`
// now rejects mixed storage at envelope decode, surfacing as a plain
// `schema_violation`. Cross-actor watch writes gained three new reasons.
pub const REASON_AUDIT_CAPABILITY_INCOMPLETE: &str = "audit_capability_incomplete";
pub const REASON_WATCH_MUST_BE_SELF: &str = "watch_must_be_self";
pub const REASON_WATCH_MUTED_MUST_BE_SELF: &str = "watch_muted_must_be_self";
pub const REASON_WATCH_LEVEL_PUBLIC_MUST_BE_SELF: &str = "watch_level_public_must_be_self";
pub const REASON_MANAGE_OTHERS_AUDIT_MISSING: &str = "manage_others_audit_missing";

// Cross-space structural relation guard (zh/models/relation.md §4).
pub const REASON_CROSS_SPACE_STRUCTURAL_RELATION: &str = "cross_space_structural_relation";

// Join policy (zh/governance/join-policy.md §4 / §6).
pub const REASON_JOIN_AUTHORISATION_INVALID: &str = "join_authorisation_invalid";
pub const REASON_JOIN_RULE_POLICY_MISMATCH: &str = "join_rule_policy_mismatch";

// Cross-signing reset (zh/crypto-media/device-lifecycle.md §14).
pub const REASON_CROSS_SIGNING_RESET: &str = "cross_signing_reset";

// Bounded-lifetime / provisioning generic reasons.
pub const REASON_TTL_EXPIRED: &str = "ttl_expired";
pub const REASON_NOT_PROVISIONED: &str = "not_provisioned";

// Morph schema evolution (zh/models/morph.md §4.1).
pub const REASON_MORPH_SCHEMA_REFS_EVOLUTION_UNAUTHORIZED: &str =
    "morph_schema_refs_evolution_unauthorized";
pub const REASON_MORPH_SCHEMA_REFS_TRANSFORMATION_UNSUPPORTED: &str =
    "morph_schema_refs_transformation_unsupported";
pub const REASON_MORPH_SCHEMA_VERSION_BINDING_MISSING: &str =
    "morph_schema_version_binding_missing";

// Sender commitment opt-in profile (zh/governance/content-moderation.md §3.4.2).
pub const REASON_SENDER_COMMITMENT_INVALID: &str = "sender_commitment_invalid";
pub const REASON_SENDER_COMMITMENT_MISSING: &str = "sender_commitment_missing";
pub const REASON_SENDER_COMMITMENT_SEQ_REPLAY: &str = "sender_commitment_seq_replay";
pub const REASON_SENDER_COMMITMENT_CIPHERTEXT_MISMATCH: &str =
    "sender_commitment_ciphertext_mismatch";
pub const REASON_SENDER_COMMITMENT_EPOCH_MISMATCH: &str = "sender_commitment_epoch_mismatch";

// Range-completeness attestation (zh/sync/operations-sync.md §4.2.4).
pub const REASON_RANGE_COMPLETENESS_ROOT_MISMATCH: &str = "range_completeness_root_mismatch";
pub const REASON_RANGE_COMPLETENESS_ACTOR_SEQ_GAP: &str = "range_completeness_actor_seq_gap";

/// Known `failed_precondition` reason codes registered in round C45.
pub const KNOWN_REASON_CODES_ROUND_C45: &[&str] = &[
    REASON_FLOW_NOT_ACTIVE,
    REASON_FLOW_NOT_ARCHIVED,
    REASON_FLOW_ALREADY_TERMINAL,
    REASON_PLACE_NOT_ACTIVE,
    REASON_PLACE_NOT_ARCHIVED,
    REASON_PLACE_ALREADY_TERMINAL,
    REASON_PLACE_PARENT_CYCLE,
    REASON_PLACE_HAS_LIVE_DEPENDENTS,
    REASON_MORPH_NOT_ACTIVE,
    REASON_MORPH_NOT_ARCHIVED,
    REASON_MORPH_ALREADY_TERMINAL,
    REASON_MESSAGE_ALREADY_TERMINAL,
    REASON_RELATION_ALREADY_TERMINAL,
    REASON_HATE_SPEECH,
    REASON_NSFW,
    REASON_ILLEGAL,
    REASON_MISINFORMATION,
    REASON_OTHER,
    REASON_CURSOR_INTEGRITY_INVALID,
    REASON_CLAIM_RATE_LIMITED,
    REASON_NAMING_CONVENTION_VIOLATION,
    REASON_APPROVAL_NONCE_REUSED,
    REASON_EXECUTED_BY_MISSING,
    REASON_THIRD_PARTY_INVITE_TOKEN_IN_QUERY,
    REASON_PATCH_PATH_INVALID,
    REASON_PATCH_PATH_REDUCER_MANAGED,
    REASON_PATCH_UNSET_REDACTABLE_FIELD,
    REASON_PATCH_SELECTOR_NO_MATCH,
    REASON_PATCH_SELECTOR_AMBIGUOUS,
    REASON_AEAD_NONCE_COUNTER_REPLAY,
    REASON_AEAD_NONCE_DERIVATION_INVALID,
    REASON_ACCOUNTABILITY_GRANT_MISSING,
    REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH,
    REASON_DELEGATION_CYCLE,
    REASON_DELEGATION_EXPIRY_WIDENING,
    REASON_RECOVERY_WITNESS_MISSING,
    REASON_RECOVERY_WITNESS_INVALID,
    REASON_RECOVERY_WITNESS_POST_CONFLICT,
    REASON_RECOVERY_CAPABILITY_NOT_ANCHORED,
    REASON_CHALLENGE_PROOF_INVALID,
    REASON_INVALID_TASK_FSM_TRANSITION,
    REASON_AUDIT_CAPABILITY_INCOMPLETE,
    REASON_WATCH_MUST_BE_SELF,
    REASON_WATCH_MUTED_MUST_BE_SELF,
    REASON_WATCH_LEVEL_PUBLIC_MUST_BE_SELF,
    REASON_MANAGE_OTHERS_AUDIT_MISSING,
    REASON_CROSS_SPACE_STRUCTURAL_RELATION,
    REASON_JOIN_AUTHORISATION_INVALID,
    REASON_JOIN_RULE_POLICY_MISMATCH,
    REASON_CROSS_SIGNING_RESET,
    REASON_TTL_EXPIRED,
    REASON_NOT_PROVISIONED,
    REASON_MORPH_SCHEMA_REFS_EVOLUTION_UNAUTHORIZED,
    REASON_MORPH_SCHEMA_REFS_TRANSFORMATION_UNSUPPORTED,
    REASON_MORPH_SCHEMA_VERSION_BINDING_MISSING,
    REASON_SENDER_COMMITMENT_INVALID,
    REASON_SENDER_COMMITMENT_MISSING,
    REASON_SENDER_COMMITMENT_SEQ_REPLAY,
    REASON_SENDER_COMMITMENT_CIPHERTEXT_MISMATCH,
    REASON_SENDER_COMMITMENT_EPOCH_MISMATCH,
    REASON_RANGE_COMPLETENESS_ROOT_MISMATCH,
    REASON_RANGE_COMPLETENESS_ACTOR_SEQ_GAP,
];

/// Known `failed_precondition` reason codes registered in round C44.
pub const KNOWN_REASON_CODES_ROUND_C44: &[&str] = &[
    REASON_INCEPTION_UPGRADE_FINGERPRINT_MISMATCH,
    REASON_INCEPTION_UPGRADE_SIGNATURE_CHAIN_INVALID,
    REASON_INCEPTION_UPGRADE_OLD_DOCUMENT_HASH_MISMATCH,
    REASON_INCEPTION_UPGRADE_EVIDENCE_INSUFFICIENT,
    REASON_AUDIT_AGENT_KEY_DESTRUCTION_ATTESTATION_MISSING,
    REASON_AUDIT_AGENT_REMOVE_REQUIRES_PAIRED_DESTRUCTION_ATTESTATION,
    REASON_AUDIT_AGENT_DESTRUCTION_NOT_PAIRED_WITH_REMOVE,
    REASON_AUDIT_AGENT_DESTRUCTION_PROOF_NOT_ENCLAVE_SIGNED,
    REASON_AUDIT_AGENT_EPOCH_RANGE_INCOMPLETE,
    REASON_AUDIT_AGENT_ATTESTATION_MISMATCH,
    REASON_MLS_SEND_PAUSE_ADVISORY_REQUIRES_E2EE_RELAXED_PROFILE,
    REASON_CONFLICTING_E2EE_PROFILES,
    REASON_CONFLICTING_AGENT_WORKSPACE_PROFILES,
    REASON_LITE_PROFILE_WRITES_DISALLOWED_EVENT_KIND,
    REASON_RESERVATION_CELL_ALREADY_SET,
    REASON_SOURCE_EXPORT_ATTESTATION_MISSING,
    REASON_SOURCE_EXPORT_ATTESTATION_INVALID,
    REASON_SOURCE_EXPORT_ATTESTATION_EXPIRED,
    REASON_SOURCE_EXPORT_ATTESTATION_DENIED,
    REASON_SOURCE_EXPORT_AUTHORITY_UNAUTHORIZED,
    REASON_SOURCE_EXPORT_CONTENT_HASH_MISMATCH,
    REASON_SOURCE_EXPORT_DESTINATION_MISMATCH,
    REASON_CARDINALITY_VIOLATION,
    REASON_CLAIM_FAILED,
];

/// Return `true` when `code` is a registered canonical error code.
pub fn is_known_error_code(code: &str) -> bool {
    KNOWN_ERROR_CODES.contains(&code)
}

/// Return the HTTP status binding for `code` per `error-code-registry.json`.
/// `None` when `code` is not registered (callers SHOULD reject the response).
pub fn error_code_http_status(code: &str) -> Option<u16> {
    Some(match code {
        ERROR_CODE_BAD_JSON
        | ERROR_CODE_BAD_QUERY
        | ERROR_CODE_MISSING_PARAM
        | ERROR_CODE_INVALID_PARAM
        | ERROR_CODE_CURSOR_INTEGRITY_INVALID => 400,
        ERROR_CODE_UNAUTHENTICATED
        | ERROR_CODE_AUTH_EXPIRED
        | ERROR_CODE_SOFT_LOGGED_OUT
        | ERROR_CODE_INVALID_SIGNATURE
        | ERROR_CODE_TURN_CREDENTIAL_EXPIRED => 401,
        ERROR_CODE_CAPABILITY_DENIED
        | ERROR_CODE_SPACE_FROZEN
        | ERROR_CODE_CLAIM_REQUIRED
        | ERROR_CODE_POLICY_VIOLATION
        | ERROR_CODE_QUOTA_EXCEEDED => 403,
        ERROR_CODE_NOT_FOUND | ERROR_CODE_UNRECOGNIZED_ENDPOINT => 404,
        ERROR_CODE_METHOD_NOT_ALLOWED => 405,
        ERROR_CODE_CONFLICT
        | ERROR_CODE_CAS_CONFLICT
        | ERROR_CODE_CAUSAL_CONFLICT
        | ERROR_CODE_DEPENDENCY_MISSING
        | ERROR_CODE_DISCUSSION_TRACK_DISABLED
        | ERROR_CODE_EPOCH_MISMATCH
        | ERROR_CODE_DUPLICATE_CONFLICT
        | ERROR_CODE_RANK_EXHAUSTED
        | ERROR_CODE_KEY_UNAVAILABLE
        | ERROR_CODE_STATE_MISMATCH
        | ERROR_CODE_AUDIT_RECEIPT_INVALIDATED
        | ERROR_CODE_STALE_FRONTIER
        | ERROR_CODE_PROJECTION_INCOMPLETE
        | ERROR_CODE_FAILED_PRECONDITION
        | ERROR_CODE_ANCHOR_INCOMPLETE
        | ERROR_CODE_STALE_PEER => 409,
        ERROR_CODE_CURSOR_EXPIRED => 410,
        ERROR_CODE_PAYLOAD_TOO_LARGE => 413,
        ERROR_CODE_SCHEMA_VIOLATION
        | ERROR_CODE_DIGEST_MISMATCH
        | ERROR_CODE_AAD_DIGEST_MISMATCH
        | ERROR_CODE_PAYLOAD_DIGEST_MISMATCH
        | ERROR_CODE_UNKNOWN_DID
        | ERROR_CODE_POLICY_COMBINATION_INVALID
        | ERROR_CODE_ANCHORER_RECOVERY_MISSING
        | ERROR_CODE_UNSUPPORTED_LATTICE_TYPE
        | ERROR_CODE_UNSUPPORTED_HASH => 422,
        ERROR_CODE_RATE_LIMITED => 429,
        ERROR_CODE_INTERNAL_ERROR => 500,
        ERROR_CODE_HLC_LOGICAL_OVERFLOW
        | ERROR_CODE_TEMPORARILY_UNAVAILABLE
        | ERROR_CODE_FRANK_UNAVAILABLE => 503,
        ERROR_CODE_TIMEOUT => 504,
        ERROR_CODE_UNSUPPORTED_FEATURE
        | ERROR_CODE_UNSUPPORTED_EVENT_KIND
        | ERROR_CODE_PROFILE_UNSUPPORTED => 501,
        _ => return None,
    })
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid Contrix identifier: {0}")]
    InvalidId(String),

    #[error("conflicting bytes for idempotent object {0}")]
    IdempotencyConflict(String),

    #[error(
        "canonical JSON does not allow floating point or ambiguous numbers (encoding.md \
         §3.2: only integer-typed values may appear in signing inputs)"
    )]
    NonCanonicalNumber,

    #[error("canonical JSON serialization failed: {0}")]
    CanonicalJson(#[from] serde_json::Error),

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[cfg(feature = "client")]
    #[error("invalid service URL: {0}")]
    Url(#[from] url::ParseError),

    #[cfg(feature = "client")]
    #[error("insecure service URL is not allowed by default: {0}")]
    InsecureUrl(String),

    #[cfg(feature = "client")]
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[cfg(feature = "mls")]
    #[error("MLS operation failed: {0}")]
    Mls(String),

    #[error("Contrix API returned {status}: {error}")]
    Api { status: u16, error: ErrorEnvelope },

    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<contrix_identifiers::IdentifierError> for Error {
    fn from(error: contrix_identifiers::IdentifierError) -> Self {
        match error {
            contrix_identifiers::IdentifierError::InvalidId(value) => Self::InvalidId(value),
            contrix_identifiers::IdentifierError::Random(error) => Self::Crypto(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn known_error_codes_match_current_registry_shape() {
        let codes = KNOWN_ERROR_CODES.iter().copied().collect::<BTreeSet<_>>();

        assert_eq!(codes.len(), KNOWN_ERROR_CODES.len(), "duplicate error code");
        // Registry v2026-05-18 main (round C47, spec e10b6ad): C44's 47 + 6 C45
        // wire codes (cursor_integrity_invalid / failed_precondition /
        // unsupported_hash / anchor_incomplete / frank_unavailable /
        // turn_credential_expired) + 1 C47 wire code (stale_peer).
        assert_eq!(KNOWN_ERROR_CODES.len(), 54);
        assert!(codes.contains(ERROR_CODE_CURSOR_EXPIRED));
        assert!(codes.contains(ERROR_CODE_POLICY_COMBINATION_INVALID));
        assert!(codes.contains(ERROR_CODE_ANCHORER_RECOVERY_MISSING));
        assert!(codes.contains(ERROR_CODE_UNSUPPORTED_LATTICE_TYPE));
        assert!(codes.contains(ERROR_CODE_PROFILE_UNSUPPORTED));
        assert!(codes.contains(ERROR_CODE_CURSOR_INTEGRITY_INVALID));
        assert!(codes.contains(ERROR_CODE_FAILED_PRECONDITION));
        assert!(codes.contains(ERROR_CODE_UNSUPPORTED_HASH));
        assert!(codes.contains(ERROR_CODE_ANCHOR_INCOMPLETE));
        assert!(codes.contains(ERROR_CODE_FRANK_UNAVAILABLE));
        assert!(codes.contains(ERROR_CODE_TURN_CREDENTIAL_EXPIRED));
        assert!(!codes.contains("sync_token_expired"));
    }

    #[test]
    fn round_c45_reason_codes_are_unique() {
        let set: BTreeSet<&str> = KNOWN_REASON_CODES_ROUND_C45.iter().copied().collect();
        assert_eq!(
            set.len(),
            KNOWN_REASON_CODES_ROUND_C45.len(),
            "duplicate reason code in KNOWN_REASON_CODES_ROUND_C45",
        );
    }

    #[test]
    fn sync_token_expired_aliases_cursor_expired() {
        assert_eq!(ERROR_CODE_SYNC_TOKEN_EXPIRED, ERROR_CODE_CURSOR_EXPIRED);
        assert_eq!(error_code_http_status(ERROR_CODE_SYNC_TOKEN_EXPIRED), Some(410));
        assert!(is_known_error_code(ERROR_CODE_SYNC_TOKEN_EXPIRED));
    }
}
