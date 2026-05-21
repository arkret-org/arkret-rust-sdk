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
pub const ERROR_CODE_INVALID_RESPONSE: &str = "invalid_response";
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

// ── Round R2/R3 (2026-05-20, spec 8b7978d) — registry add (15 wire-level codes).
//
// Round-23 wire breakers spanning the e2ee_relaxed window ceiling, the
// cross-domain replay guard on cross-signing reset, the moderation appeal
// flow, the audit-agent attestation pipeline, realm-terminal lifecycle,
// legal hold / blob redaction, MLS governance, invite token expiry, and
// late-recovery membership rejection.
pub const ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING: &str = "relaxed_window_exceeds_ceiling";
pub const ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE: &str =
    "e2ee_relaxed_disallowed_in_compliance_profile";
pub const ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED: &str = "cross_domain_replay_rejected";
pub const ERROR_CODE_RESET_EVENT_ID_MISMATCH: &str = "reset_event_id_mismatch";
pub const ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT: &str = "appeal_overturn_missing_lift";
pub const ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN: &str = "appeal_self_review_forbidden";
pub const ERROR_CODE_REALM_TERMINAL_STATE: &str = "realm_terminal_state";
pub const ERROR_CODE_AUDIT_AGENT_ATTESTATION_MISMATCH: &str = "audit_agent_attestation_mismatch";
pub const ERROR_CODE_AUDIT_PURPOSE_MISMATCH: &str = "audit_purpose_mismatch";
pub const ERROR_CODE_LEGAL_HOLD_ACTIVE: &str = "legal_hold_active";
pub const ERROR_CODE_BLOB_REDACTED: &str = "blob_redacted";
pub const ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED: &str =
    "media_plaintext_service_not_authorised";
pub const ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE: &str = "mls_governance_binding_stale";
pub const ERROR_CODE_EXPIRED_INVITE_TOKEN: &str = "expired_invite_token";
pub const ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP: &str = "late_recovery_rejected_membership";

// ── Round 4 (2026-05-20, spec a77b995) — registry add (3 wire-level codes).
//
// `delivery_binding_stale` (409): federation sender used an obsolete member
// delivery binding frontier; response carries `new_recipient_service_did` and
// `handover_frontier` so the sender can retry at the current service.
// `delivery_binding_handed_over` (409): sender continued using a previous
// `recipient_service_did` after the handover grace window expired; sender
// MUST resolve current binding and retry there.
// `historical_only` (200, diagnostic): idempotency cache replay served only
// as a historical diagnostic after key or binding state changed; receivers
// MUST NOT perform new reducer side effects.
pub const ERROR_CODE_DELIVERY_BINDING_STALE: &str = "delivery_binding_stale";
pub const ERROR_CODE_DELIVERY_BINDING_HANDED_OVER: &str = "delivery_binding_handed_over";
pub const ERROR_CODE_HISTORICAL_ONLY: &str = "historical_only";

// ── Directory ingest registry additions (2026-05-22).
//
// Teabay is the reference directory service implementation. These codes are
// normative for directory announce / withdraw validation and are exposed here
// so services do not maintain local wire-code enums.
pub const ERROR_CODE_DIRECTORY_NOT_AUTHORIZED: &str = "directory_not_authorized";
pub const ERROR_CODE_ACCEPT_POLICY_DENIED: &str = "accept_policy_denied";
pub const ERROR_CODE_SIGNATURE_INVALID: &str = "signature_invalid";
pub const ERROR_CODE_SIGNATURE_STALE: &str = "signature_stale";
pub const ERROR_CODE_SOURCE_REFS_UNVERIFIABLE: &str = "source_refs_unverifiable";
pub const ERROR_CODE_GOVERNANCE_KEY_INVALID: &str = "governance_key_invalid";
pub const ERROR_CODE_TTL_OUT_OF_RANGE: &str = "ttl_out_of_range";
pub const ERROR_CODE_TAKEDOWN_IN_FORCE: &str = "takedown_in_force";
pub const ERROR_CODE_POLICY_REVISION_ROLLBACK: &str = "policy_revision_rollback";

/// All canonical error codes recognised by the registry. The order matches
/// `error-code-registry.json`. Use [`is_known_error_code`] before populating
/// `ErrorEnvelope.code` from arbitrary input.
pub const KNOWN_ERROR_CODES: &[&str] = &[
    ERROR_CODE_BAD_JSON,
    ERROR_CODE_BAD_QUERY,
    ERROR_CODE_SCHEMA_VIOLATION,
    ERROR_CODE_MISSING_PARAM,
    ERROR_CODE_INVALID_PARAM,
    ERROR_CODE_INVALID_RESPONSE,
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
    // Round R2/R3 (2026-05-20).
    ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING,
    ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE,
    ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED,
    ERROR_CODE_RESET_EVENT_ID_MISMATCH,
    ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT,
    ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN,
    ERROR_CODE_REALM_TERMINAL_STATE,
    ERROR_CODE_AUDIT_AGENT_ATTESTATION_MISMATCH,
    ERROR_CODE_AUDIT_PURPOSE_MISMATCH,
    ERROR_CODE_LEGAL_HOLD_ACTIVE,
    ERROR_CODE_BLOB_REDACTED,
    ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED,
    ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE,
    ERROR_CODE_EXPIRED_INVITE_TOKEN,
    ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP,
    // Round 4 (2026-05-20).
    ERROR_CODE_DELIVERY_BINDING_STALE,
    ERROR_CODE_DELIVERY_BINDING_HANDED_OVER,
    ERROR_CODE_HISTORICAL_ONLY,
    // Directory ingest (2026-05-22).
    ERROR_CODE_DIRECTORY_NOT_AUTHORIZED,
    ERROR_CODE_ACCEPT_POLICY_DENIED,
    ERROR_CODE_SIGNATURE_INVALID,
    ERROR_CODE_SIGNATURE_STALE,
    ERROR_CODE_SOURCE_REFS_UNVERIFIABLE,
    ERROR_CODE_GOVERNANCE_KEY_INVALID,
    ERROR_CODE_TTL_OUT_OF_RANGE,
    ERROR_CODE_TAKEDOWN_IN_FORCE,
    ERROR_CODE_POLICY_REVISION_ROLLBACK,
];

// ── Failed-precondition reason codes (sub-codes inside `failed_precondition`)
//
// These are NOT top-level wire error codes; they go in the
// `failed_precondition` envelope's `reason` field. Round C44 (2026-05-18)
// added a batch of reasons for Tier-0 security (S3/S4/S5/S6) and profile
// interactions.
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

pub const REASON_LITE_PROFILE_WRITES_DISALLOWED_EVENT_KIND: &str =
    "lite_profile_writes_disallowed_event_kind";

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
    REASON_LITE_PROFILE_WRITES_DISALLOWED_EVENT_KIND,
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
        | ERROR_CODE_INVALID_RESPONSE
        | ERROR_CODE_CURSOR_INTEGRITY_INVALID
        | ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING
        | ERROR_CODE_RESET_EVENT_ID_MISMATCH
        | ERROR_CODE_EXPIRED_INVITE_TOKEN
        | ERROR_CODE_SIGNATURE_INVALID
        | ERROR_CODE_SIGNATURE_STALE
        | ERROR_CODE_SOURCE_REFS_UNVERIFIABLE
        | ERROR_CODE_GOVERNANCE_KEY_INVALID
        | ERROR_CODE_TTL_OUT_OF_RANGE => 400,
        ERROR_CODE_UNAUTHENTICATED
        | ERROR_CODE_AUTH_EXPIRED
        | ERROR_CODE_SOFT_LOGGED_OUT
        | ERROR_CODE_INVALID_SIGNATURE
        | ERROR_CODE_TURN_CREDENTIAL_EXPIRED => 401,
        ERROR_CODE_CAPABILITY_DENIED
        | ERROR_CODE_DIRECTORY_NOT_AUTHORIZED
        | ERROR_CODE_ACCEPT_POLICY_DENIED
        | ERROR_CODE_SPACE_FROZEN
        | ERROR_CODE_CLAIM_REQUIRED
        | ERROR_CODE_POLICY_VIOLATION
        | ERROR_CODE_QUOTA_EXCEEDED
        | ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE
        | ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN
        | ERROR_CODE_LEGAL_HOLD_ACTIVE
        | ERROR_CODE_BLOB_REDACTED
        | ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED
        | ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP => 403,
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
        | ERROR_CODE_STALE_PEER
        | ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED
        | ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT
        | ERROR_CODE_REALM_TERMINAL_STATE
        | ERROR_CODE_AUDIT_AGENT_ATTESTATION_MISMATCH
        | ERROR_CODE_AUDIT_PURPOSE_MISMATCH
        | ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE
        | ERROR_CODE_DELIVERY_BINDING_STALE
        | ERROR_CODE_DELIVERY_BINDING_HANDED_OVER
        | ERROR_CODE_TAKEDOWN_IN_FORCE
        | ERROR_CODE_POLICY_REVISION_ROLLBACK => 409,
        ERROR_CODE_HISTORICAL_ONLY => 200,
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

// ── Typed `ErrorCode` enum ────────────────────────────────────────────────
//
// Strongly-typed view over [`KNOWN_ERROR_CODES`]. Mirrors the wire-form
// snake_case strings exactly through [`ErrorCode::as_str`] / [`ErrorCode::from_wire`].
//
// Adding a new error code to the registry MUST be paired with a new
// [`ErrorCode`] variant + an entry in [`ErrorCode::ALL`]. The
// `error_code_enum_matches_registry` test in this module catches drift
// in either direction.

/// Strongly-typed view over the canonical Contrix error code registry.
///
/// Every variant corresponds to one entry in [`KNOWN_ERROR_CODES`].
/// Round-trip helpers:
///
/// - [`ErrorCode::as_str`] → wire-form snake_case string (same value as
///   the matching `ERROR_CODE_*` constant).
/// - [`ErrorCode::from_wire`] → parse a wire string back into the typed
///   variant. Returns `None` for any code not in the registry.
/// - [`ErrorCode::http_status`] → registered HTTP status, identical to
///   what [`error_code_http_status`] returns for the same wire string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    BadJson,
    BadQuery,
    SchemaViolation,
    MissingParam,
    InvalidParam,
    InvalidResponse,
    Unauthenticated,
    AuthExpired,
    SoftLoggedOut,
    InvalidSignature,
    CapabilityDenied,
    SpaceFrozen,
    ClaimRequired,
    NotFound,
    UnrecognizedEndpoint,
    MethodNotAllowed,
    Conflict,
    CasConflict,
    CausalConflict,
    DependencyMissing,
    DiscussionTrackDisabled,
    /// C14 / read-receipts §2.5: Sync Service drops `cx.receipt.read` when
    /// the effective Space `disclosure="disabled"` policy is in force.
    PolicyViolation,
    EpochMismatch,
    DuplicateConflict,
    RankExhausted,
    HlcLogicalOverflow,
    PayloadTooLarge,
    DigestMismatch,
    AadDigestMismatch,
    PayloadDigestMismatch,
    KeyUnavailable,
    StateMismatch,
    AuditReceiptInvalidated,
    UnknownDid,
    QuotaExceeded,
    RateLimited,
    Timeout,
    StaleFrontier,
    CursorExpired,
    UnsupportedFeature,
    UnsupportedEventKind,
    ProjectionIncomplete,
    InternalError,
    TemporarilyUnavailable,
    PolicyCombinationInvalid,
    AnchorerRecoveryMissing,
    UnsupportedLatticeType,
    ProfileUnsupported,
    CursorIntegrityInvalid,
    FailedPrecondition,
    UnsupportedHash,
    AnchorIncomplete,
    FrankUnavailable,
    TurnCredentialExpired,
    StalePeer,
    // ── Round R2/R3 (2026-05-20).
    RelaxedWindowExceedsCeiling,
    E2eeRelaxedDisallowedInComplianceProfile,
    CrossDomainReplayRejected,
    ResetEventIdMismatch,
    AppealOverturnMissingLift,
    AppealSelfReviewForbidden,
    RealmTerminalState,
    AuditAgentAttestationMismatch,
    AuditPurposeMismatch,
    LegalHoldActive,
    BlobRedacted,
    MediaPlaintextServiceNotAuthorised,
    MlsGovernanceBindingStale,
    ExpiredInviteToken,
    LateRecoveryRejectedMembership,
    // ── Round 4 (2026-05-20).
    DeliveryBindingStale,
    DeliveryBindingHandedOver,
    HistoricalOnly,
    // ── Directory ingest (2026-05-22).
    DirectoryNotAuthorized,
    AcceptPolicyDenied,
    SignatureInvalid,
    SignatureStale,
    SourceRefsUnverifiable,
    GovernanceKeyInvalid,
    TtlOutOfRange,
    TakedownInForce,
    PolicyRevisionRollback,
}

impl ErrorCode {
    /// All variants in registry order.
    pub const ALL: &'static [Self] = &[
        Self::BadJson,
        Self::BadQuery,
        Self::SchemaViolation,
        Self::MissingParam,
        Self::InvalidParam,
        Self::InvalidResponse,
        Self::Unauthenticated,
        Self::AuthExpired,
        Self::SoftLoggedOut,
        Self::InvalidSignature,
        Self::CapabilityDenied,
        Self::SpaceFrozen,
        Self::ClaimRequired,
        Self::NotFound,
        Self::UnrecognizedEndpoint,
        Self::MethodNotAllowed,
        Self::Conflict,
        Self::CasConflict,
        Self::CausalConflict,
        Self::DependencyMissing,
        Self::DiscussionTrackDisabled,
        Self::PolicyViolation,
        Self::EpochMismatch,
        Self::DuplicateConflict,
        Self::RankExhausted,
        Self::HlcLogicalOverflow,
        Self::PayloadTooLarge,
        Self::DigestMismatch,
        Self::AadDigestMismatch,
        Self::PayloadDigestMismatch,
        Self::KeyUnavailable,
        Self::StateMismatch,
        Self::AuditReceiptInvalidated,
        Self::UnknownDid,
        Self::QuotaExceeded,
        Self::RateLimited,
        Self::Timeout,
        Self::StaleFrontier,
        Self::CursorExpired,
        Self::UnsupportedFeature,
        Self::UnsupportedEventKind,
        Self::ProjectionIncomplete,
        Self::InternalError,
        Self::TemporarilyUnavailable,
        Self::PolicyCombinationInvalid,
        Self::AnchorerRecoveryMissing,
        Self::UnsupportedLatticeType,
        Self::ProfileUnsupported,
        Self::CursorIntegrityInvalid,
        Self::FailedPrecondition,
        Self::UnsupportedHash,
        Self::AnchorIncomplete,
        Self::FrankUnavailable,
        Self::TurnCredentialExpired,
        Self::StalePeer,
        Self::RelaxedWindowExceedsCeiling,
        Self::E2eeRelaxedDisallowedInComplianceProfile,
        Self::CrossDomainReplayRejected,
        Self::ResetEventIdMismatch,
        Self::AppealOverturnMissingLift,
        Self::AppealSelfReviewForbidden,
        Self::RealmTerminalState,
        Self::AuditAgentAttestationMismatch,
        Self::AuditPurposeMismatch,
        Self::LegalHoldActive,
        Self::BlobRedacted,
        Self::MediaPlaintextServiceNotAuthorised,
        Self::MlsGovernanceBindingStale,
        Self::ExpiredInviteToken,
        Self::LateRecoveryRejectedMembership,
        Self::DeliveryBindingStale,
        Self::DeliveryBindingHandedOver,
        Self::HistoricalOnly,
        Self::DirectoryNotAuthorized,
        Self::AcceptPolicyDenied,
        Self::SignatureInvalid,
        Self::SignatureStale,
        Self::SourceRefsUnverifiable,
        Self::GovernanceKeyInvalid,
        Self::TtlOutOfRange,
        Self::TakedownInForce,
        Self::PolicyRevisionRollback,
    ];

    /// Canonical wire-form code (snake_case string).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadJson => ERROR_CODE_BAD_JSON,
            Self::BadQuery => ERROR_CODE_BAD_QUERY,
            Self::SchemaViolation => ERROR_CODE_SCHEMA_VIOLATION,
            Self::MissingParam => ERROR_CODE_MISSING_PARAM,
            Self::InvalidParam => ERROR_CODE_INVALID_PARAM,
            Self::InvalidResponse => ERROR_CODE_INVALID_RESPONSE,
            Self::Unauthenticated => ERROR_CODE_UNAUTHENTICATED,
            Self::AuthExpired => ERROR_CODE_AUTH_EXPIRED,
            Self::SoftLoggedOut => ERROR_CODE_SOFT_LOGGED_OUT,
            Self::InvalidSignature => ERROR_CODE_INVALID_SIGNATURE,
            Self::CapabilityDenied => ERROR_CODE_CAPABILITY_DENIED,
            Self::SpaceFrozen => ERROR_CODE_SPACE_FROZEN,
            Self::ClaimRequired => ERROR_CODE_CLAIM_REQUIRED,
            Self::NotFound => ERROR_CODE_NOT_FOUND,
            Self::UnrecognizedEndpoint => ERROR_CODE_UNRECOGNIZED_ENDPOINT,
            Self::MethodNotAllowed => ERROR_CODE_METHOD_NOT_ALLOWED,
            Self::Conflict => ERROR_CODE_CONFLICT,
            Self::CasConflict => ERROR_CODE_CAS_CONFLICT,
            Self::CausalConflict => ERROR_CODE_CAUSAL_CONFLICT,
            Self::DependencyMissing => ERROR_CODE_DEPENDENCY_MISSING,
            Self::DiscussionTrackDisabled => ERROR_CODE_DISCUSSION_TRACK_DISABLED,
            Self::PolicyViolation => ERROR_CODE_POLICY_VIOLATION,
            Self::EpochMismatch => ERROR_CODE_EPOCH_MISMATCH,
            Self::DuplicateConflict => ERROR_CODE_DUPLICATE_CONFLICT,
            Self::RankExhausted => ERROR_CODE_RANK_EXHAUSTED,
            Self::HlcLogicalOverflow => ERROR_CODE_HLC_LOGICAL_OVERFLOW,
            Self::PayloadTooLarge => ERROR_CODE_PAYLOAD_TOO_LARGE,
            Self::DigestMismatch => ERROR_CODE_DIGEST_MISMATCH,
            Self::AadDigestMismatch => ERROR_CODE_AAD_DIGEST_MISMATCH,
            Self::PayloadDigestMismatch => ERROR_CODE_PAYLOAD_DIGEST_MISMATCH,
            Self::KeyUnavailable => ERROR_CODE_KEY_UNAVAILABLE,
            Self::StateMismatch => ERROR_CODE_STATE_MISMATCH,
            Self::AuditReceiptInvalidated => ERROR_CODE_AUDIT_RECEIPT_INVALIDATED,
            Self::UnknownDid => ERROR_CODE_UNKNOWN_DID,
            Self::QuotaExceeded => ERROR_CODE_QUOTA_EXCEEDED,
            Self::RateLimited => ERROR_CODE_RATE_LIMITED,
            Self::Timeout => ERROR_CODE_TIMEOUT,
            Self::StaleFrontier => ERROR_CODE_STALE_FRONTIER,
            Self::CursorExpired => ERROR_CODE_CURSOR_EXPIRED,
            Self::UnsupportedFeature => ERROR_CODE_UNSUPPORTED_FEATURE,
            Self::UnsupportedEventKind => ERROR_CODE_UNSUPPORTED_EVENT_KIND,
            Self::ProjectionIncomplete => ERROR_CODE_PROJECTION_INCOMPLETE,
            Self::InternalError => ERROR_CODE_INTERNAL_ERROR,
            Self::TemporarilyUnavailable => ERROR_CODE_TEMPORARILY_UNAVAILABLE,
            Self::PolicyCombinationInvalid => ERROR_CODE_POLICY_COMBINATION_INVALID,
            Self::AnchorerRecoveryMissing => ERROR_CODE_ANCHORER_RECOVERY_MISSING,
            Self::UnsupportedLatticeType => ERROR_CODE_UNSUPPORTED_LATTICE_TYPE,
            Self::ProfileUnsupported => ERROR_CODE_PROFILE_UNSUPPORTED,
            Self::CursorIntegrityInvalid => ERROR_CODE_CURSOR_INTEGRITY_INVALID,
            Self::FailedPrecondition => ERROR_CODE_FAILED_PRECONDITION,
            Self::UnsupportedHash => ERROR_CODE_UNSUPPORTED_HASH,
            Self::AnchorIncomplete => ERROR_CODE_ANCHOR_INCOMPLETE,
            Self::FrankUnavailable => ERROR_CODE_FRANK_UNAVAILABLE,
            Self::TurnCredentialExpired => ERROR_CODE_TURN_CREDENTIAL_EXPIRED,
            Self::StalePeer => ERROR_CODE_STALE_PEER,
            Self::RelaxedWindowExceedsCeiling => ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING,
            Self::E2eeRelaxedDisallowedInComplianceProfile => {
                ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE
            }
            Self::CrossDomainReplayRejected => ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED,
            Self::ResetEventIdMismatch => ERROR_CODE_RESET_EVENT_ID_MISMATCH,
            Self::AppealOverturnMissingLift => ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT,
            Self::AppealSelfReviewForbidden => ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN,
            Self::RealmTerminalState => ERROR_CODE_REALM_TERMINAL_STATE,
            Self::AuditAgentAttestationMismatch => ERROR_CODE_AUDIT_AGENT_ATTESTATION_MISMATCH,
            Self::AuditPurposeMismatch => ERROR_CODE_AUDIT_PURPOSE_MISMATCH,
            Self::LegalHoldActive => ERROR_CODE_LEGAL_HOLD_ACTIVE,
            Self::BlobRedacted => ERROR_CODE_BLOB_REDACTED,
            Self::MediaPlaintextServiceNotAuthorised => {
                ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED
            }
            Self::MlsGovernanceBindingStale => ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE,
            Self::ExpiredInviteToken => ERROR_CODE_EXPIRED_INVITE_TOKEN,
            Self::LateRecoveryRejectedMembership => ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP,
            Self::DeliveryBindingStale => ERROR_CODE_DELIVERY_BINDING_STALE,
            Self::DeliveryBindingHandedOver => ERROR_CODE_DELIVERY_BINDING_HANDED_OVER,
            Self::HistoricalOnly => ERROR_CODE_HISTORICAL_ONLY,
            Self::DirectoryNotAuthorized => ERROR_CODE_DIRECTORY_NOT_AUTHORIZED,
            Self::AcceptPolicyDenied => ERROR_CODE_ACCEPT_POLICY_DENIED,
            Self::SignatureInvalid => ERROR_CODE_SIGNATURE_INVALID,
            Self::SignatureStale => ERROR_CODE_SIGNATURE_STALE,
            Self::SourceRefsUnverifiable => ERROR_CODE_SOURCE_REFS_UNVERIFIABLE,
            Self::GovernanceKeyInvalid => ERROR_CODE_GOVERNANCE_KEY_INVALID,
            Self::TtlOutOfRange => ERROR_CODE_TTL_OUT_OF_RANGE,
            Self::TakedownInForce => ERROR_CODE_TAKEDOWN_IN_FORCE,
            Self::PolicyRevisionRollback => ERROR_CODE_POLICY_REVISION_ROLLBACK,
        }
    }

    /// Registered HTTP status, identical to what
    /// [`error_code_http_status`] returns for the same wire string.
    /// Panics only if the constant table and the HTTP-status mapping
    /// drift; the `every_variant_has_http_status` test catches this.
    pub fn http_status(self) -> u16 {
        error_code_http_status(self.as_str())
            .expect("every ErrorCode variant has a registered HTTP status")
    }

    /// Parse a wire-form code back into its typed variant.
    pub fn from_wire(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == code)
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
        // turn_credential_expired) + 1 C47 wire code (stale_peer) +
        // 15 Round R2/R3 wire codes (relaxed_window_exceeds_ceiling, ...) +
        // 3 Round 4 wire codes (delivery_binding_stale, delivery_binding_handed_over,
        // historical_only) + 10 directory ingest wire codes.
        assert_eq!(KNOWN_ERROR_CODES.len(), 82);
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
        assert!(codes.contains(ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING));
        assert!(codes.contains(ERROR_CODE_RESET_EVENT_ID_MISMATCH));
        assert!(codes.contains(ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT));
        assert!(codes.contains(ERROR_CODE_BLOB_REDACTED));
        assert!(codes.contains(ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP));
        assert!(codes.contains(ERROR_CODE_DIRECTORY_NOT_AUTHORIZED));
        assert!(codes.contains(ERROR_CODE_POLICY_REVISION_ROLLBACK));
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

    /// `ErrorCode::ALL` MUST contain one variant per entry in
    /// `KNOWN_ERROR_CODES`.
    #[test]
    fn error_code_enum_matches_registry() {
        assert_eq!(ErrorCode::ALL.len(), KNOWN_ERROR_CODES.len());
        for code in ErrorCode::ALL {
            let wire = code.as_str();
            assert!(
                is_known_error_code(wire),
                "ErrorCode::{:?} → {wire:?} missing from KNOWN_ERROR_CODES",
                code
            );
            assert_eq!(
                ErrorCode::from_wire(wire),
                Some(*code),
                "round-trip mismatch for ErrorCode::{:?}",
                code,
            );
        }
        for wire in KNOWN_ERROR_CODES {
            assert!(
                ErrorCode::from_wire(wire).is_some(),
                "registry wire {wire:?} has no ErrorCode variant",
            );
        }
    }

    /// Every variant MUST resolve to an HTTP status via
    /// `error_code_http_status`. Catches drift between the registry
    /// table and the HTTP-status `match` arm.
    #[test]
    fn every_variant_has_http_status() {
        for code in ErrorCode::ALL {
            let status = code.http_status();
            assert!(
                (100..=599).contains(&status),
                "ErrorCode::{:?} returned status {status}",
                code,
            );
        }
    }
}
