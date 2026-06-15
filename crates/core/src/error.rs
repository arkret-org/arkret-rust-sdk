use thiserror::Error;

use crate::models::ErrorEnvelope;

pub type Result<T> = std::result::Result<T, Error>;

// ── Canonical error codes (mirror of `error-code-registry.json` v2026-05-23) ─
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
pub const ERROR_CODE_REALM_FROZEN: &str = "realm_frozen";
pub const ERROR_CODE_SPACE_FROZEN: &str = ERROR_CODE_REALM_FROZEN;
pub const ERROR_CODE_CLAIM_REQUIRED: &str = "claim_required";
pub const ERROR_CODE_NOT_FOUND: &str = "not_found";
pub const ERROR_CODE_UNRECOGNIZED_ENDPOINT: &str = "unrecognized_endpoint";
pub const ERROR_CODE_METHOD_NOT_ALLOWED: &str = "method_not_allowed";
pub const ERROR_CODE_CONFLICT: &str = "conflict";
pub const ERROR_CODE_CAS_CONFLICT: &str = "cas_conflict";
pub const ERROR_CODE_CAUSAL_CONFLICT: &str = "causal_conflict";
pub const ERROR_CODE_DEPENDENCY_MISSING: &str = "dependency_missing";
pub const ERROR_CODE_DISCUSSION_TRACK_DISABLED: &str = "discussion_track_disabled";
/// C14 / read-receipts §2.5: Sync Service drops `ck.receipt.read` events
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
pub const ERROR_CODE_LIMIT_EXCEEDED: &str = "limit_exceeded";
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
pub const ERROR_CODE_HISTORY_SHARING_POLICY_MISSING: &str = "history_sharing_policy_missing";
pub const ERROR_CODE_HISTORY_NOT_VISIBLE: &str = "history_not_visible";
pub const ERROR_CODE_PREVIEW_POLICY_DENIED: &str = "preview_policy_denied";
pub const ERROR_CODE_NOTARY_RECOVERY_MISSING: &str = "notary_recovery_missing";
pub const ERROR_CODE_UNSUPPORTED_LATTICE_TYPE: &str = "unsupported_lattice_type";
/// Round C44 (2026-05-18) — registry add: peer or ServiceDescribe advertises a
/// `ck.profile.*` ID this implementation does not support. Wire-level top
/// error code (not a `failed_precondition` sub-reason). Spec
/// `error-code-registry.json` v2026-05-18.
pub const ERROR_CODE_PROFILE_UNSUPPORTED: &str = "profile_unsupported";

// ── Round C45 (2026-05-18 main) — registry add (6 wire-level codes).
//
// Spec: `error-code-registry.json` (dc01ad7..5ed365c).
// `failed_precondition` carries the round-C45 state-machine reason families
// (strand_not_active, space_not_archived, morph_already_terminal, ...). See the
// `REASON_*` constants further below.
pub const ERROR_CODE_CURSOR_INTEGRITY_INVALID: &str = "cursor_integrity_invalid";
pub const ERROR_CODE_FAILED_PRECONDITION: &str = "failed_precondition";
pub const ERROR_CODE_UNSUPPORTED_HASH: &str = "unsupported_digest_algorithm";
pub const ERROR_CODE_SEAL_INCOMPLETE: &str = "seal_incomplete";
pub const ERROR_CODE_FRANKING_PROOF_UNAVAILABLE: &str = "franking_proof_unavailable";
pub const ERROR_CODE_FRANK_UNAVAILABLE: &str = ERROR_CODE_FRANKING_PROOF_UNAVAILABLE;
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
// strand, the audit-agent attestation pipeline, realm-terminal lifecycle,
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

// ── Spec main (2026-05-23) registry additions.
pub const ERROR_CODE_DID_PROOF_REQUIRED: &str = "did_proof_required";
pub const ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED: &str =
    "read_receipt_compliance_floor_violated";
pub const ERROR_CODE_EPHEMERAL_KIND_NOT_PERMITTED: &str = "ephemeral_kind_not_permitted";
pub const ERROR_CODE_EPHEMERAL_TTL_OUT_OF_RANGE: &str = "ephemeral_ttl_out_of_range";
pub const ERROR_CODE_EPHEMERAL_CHANNEL_UNAVAILABLE: &str = "ephemeral_channel_unavailable";
pub const ERROR_CODE_AUTHORIZED_GRANT_REVOKED: &str = "authorized_grant_revoked";
pub const ERROR_CODE_DEVICE_RECOVERY_SSK_GENERATION_MISMATCH: &str =
    "device_recovery_ssk_generation_mismatch";
pub const ERROR_CODE_CURSOR_REVOKED: &str = "cursor_revoked";
pub const ERROR_CODE_MEMBER_IDENTITY_STATE_MISMATCH: &str = "member_identity_state_mismatch";
pub const ERROR_CODE_MEMBER_IDENTITY_PROOF_INVALID: &str = "member_identity_proof_invalid";
pub const ERROR_CODE_MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH: &str =
    "member_identity_replacement_digest_mismatch";
pub const ERROR_CODE_MEMBER_IDENTITY_UNKNOWN_SEGMENT: &str = "member_identity_unknown_segment";

// ── Key-backup hardening (B-C, spec head 37ce729) — 11 new wire-level error
// codes covering the key-backup series chain, recovery-policy alignment,
// share commitment, frontier staleness, removed secret_storage rejection,
// recovery evidence binding, AEAD profile gating, and attestation presence.
pub const ERROR_CODE_SERIES_CHAIN_BROKEN: &str = "series_chain_broken";
pub const ERROR_CODE_SERIES_SEQ_NOT_MONOTONIC: &str = "series_seq_not_monotonic";
pub const ERROR_CODE_SERIES_PREDECESSOR_NOT_FOUND: &str = "series_predecessor_not_found";
pub const ERROR_CODE_RECOVERY_POLICY_MISMATCH: &str = "recovery_policy_mismatch";
pub const ERROR_CODE_SHARE_COMMITMENT_MISMATCH: &str = "share_commitment_mismatch";
pub const ERROR_CODE_BACKUP_FRONTIER_STALE: &str = "backup_frontier_stale";
pub const ERROR_CODE_BACKUP_POST_RESET_STALE: &str = "backup_post_reset_stale";
pub const ERROR_CODE_RECOVERY_EVIDENCE_UNBOUND: &str = "recovery_evidence_unbound";
pub const ERROR_CODE_UNSUPPORTED_AEAD_PROFILE: &str = "unsupported_aead_profile";
pub const ERROR_CODE_ATTESTATION_MISSING: &str = "attestation_missing";

// ── R3 spec-sync (2026-05-27, cokret-spec b47ff6ec) — 20 new wire-level
// error codes spanning CKP-0008/0009 (personal-agent / pairing / sidecar),
// CKP-0010 (call media token exchange / focus / e2ee / recording artifact
// pipeline), recovery witness revoke lag, and the wire-level handle
// homograph guard. Spec `error-code-registry.json` v2026-05-27.
pub const ERROR_CODE_PAIRING_REQUEST_EXPIRED: &str = "pairing_request_expired";
pub const ERROR_CODE_PROOF_INVALID: &str = "proof_invalid";
pub const ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH: &str =
    "verification_method_principal_mismatch";
pub const ERROR_CODE_AGENT_PAUSED: &str = "agent_paused";
pub const ERROR_CODE_AGENT_DEACTIVATED: &str = "agent_deactivated";
pub const ERROR_CODE_APPROVAL_ALREADY_CONSUMED: &str = "approval_already_consumed";
pub const ERROR_CODE_SIDECAR_CREATE_DENIED: &str = "sidecar_create_denied";
pub const ERROR_CODE_ACTOR_KIND_REDUCER_MANAGED: &str = "actor_kind_reducer_managed";
pub const ERROR_CODE_FOCUS_MISMATCH: &str = "focus_mismatch";
pub const ERROR_CODE_UNKNOWN_FOCUS_TYPE: &str = "unknown_focus_type";
pub const ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED: &str = "token_issuer_unauthorised";
pub const ERROR_CODE_PARTICIPANT_BINDING_INVALID: &str = "participant_binding_invalid";
pub const ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED: &str = "participant_identity_unrecognised";
pub const ERROR_CODE_SESSION_FOCUS_ALREADY_COMMITTED: &str = "session_focus_already_committed";
pub const ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED: &str = "e2ee_key_source_unauthorised";
pub const ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED: &str =
    "recording_artifact_pipeline_bypassed";
pub const ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT: &str = "focus_unavailable_for_client";
pub const ERROR_CODE_RECOVERY_WITNESS_REVOKE_LAGGING: &str = "recovery_witness_revoke_lagging";
pub const ERROR_CODE_HANDLE_HOMOGRAPH_FORBIDDEN: &str = "handle_homograph_forbidden";

// ── Registry backfill (2026-06-08) — top-level wire codes present in
// `error-code-registry.json` with HTTP bindings, previously missing from the
// SDK mirror.
pub const ERROR_CODE_POLICY_DENIED: &str = "policy_denied";
pub const ERROR_CODE_CURSOR_UNRECOGNIZED: &str = "cursor_unrecognized";
pub const ERROR_CODE_ACTOR_SEQ_INVALID: &str = "actor_seq_invalid";
pub const ERROR_CODE_STALE_SEAL_REF: &str = "stale_seal_ref";
pub const ERROR_CODE_SEAL_REF_UNKNOWN: &str = "seal_ref_unknown";
pub const ERROR_CODE_AUDIENCE_UNKNOWN: &str = "audience_unknown";
pub const ERROR_CODE_BLOB_DIGEST_MISMATCH: &str = "blob_digest_mismatch";
pub const ERROR_CODE_BLOB_EXPIRED: &str = "blob_expired";
pub const ERROR_CODE_BLOB_PRESIGN_INVALID: &str = "blob_presign_invalid";
pub const ERROR_CODE_BLOB_QUOTA_EXCEEDED: &str = "blob_quota_exceeded";
pub const ERROR_CODE_CURSOR_INVALID: &str = "cursor_invalid";
pub const ERROR_CODE_DEVICE_UNKNOWN: &str = "device_unknown";
pub const ERROR_CODE_DID_ALREADY_EXISTS: &str = "did_already_exists";
pub const ERROR_CODE_DID_NOT_FOUND: &str = "did_not_found";
pub const ERROR_CODE_DID_REVOKED: &str = "did_revoked";
pub const ERROR_CODE_FRONTIER_UNAVAILABLE: &str = "frontier_unavailable";
pub const ERROR_CODE_HANDLE_UNVERIFIED: &str = "handle_unverified";
pub const ERROR_CODE_KEY_REPLAY: &str = "key_replay";
pub const ERROR_CODE_KEYPACKAGE_ALREADY_CONSUMED: &str = "keypackage_already_consumed";
pub const ERROR_CODE_KEYPACKAGE_UNKNOWN: &str = "keypackage_unknown";
pub const ERROR_CODE_ONE_TIME_KEYS_EXHAUSTED: &str = "one_time_keys_exhausted";
pub const ERROR_CODE_POLICY_STALE: &str = "policy_stale";
pub const ERROR_CODE_POLICY_UNAVAILABLE: &str = "policy_unavailable";
pub const ERROR_CODE_PRINCIPAL_UNKNOWN: &str = "principal_unknown";
pub const ERROR_CODE_PUSH_GATEWAY_UNREACHABLE: &str = "push_gateway_unreachable";
pub const ERROR_CODE_PUSH_PAYLOAD_TOO_LARGE: &str = "push_payload_too_large";
pub const ERROR_CODE_PUSH_TARGET_UNKNOWN: &str = "push_target_unknown";
pub const ERROR_CODE_PUSH_TOKEN_INVALID: &str = "push_token_invalid";
pub const ERROR_CODE_PUSH_TOKEN_UNKNOWN: &str = "push_token_unknown";
pub const ERROR_CODE_QUARANTINE: &str = "quarantine";
pub const ERROR_CODE_SNAPSHOT_AUTHORITY_UNVERIFIED: &str = "snapshot_authority_unverified";
pub const ERROR_CODE_REDUCER_PROFILE_MISMATCH: &str = "reducer_profile_mismatch";
pub const ERROR_CODE_SNAPSHOT_UNAVAILABLE: &str = "snapshot_unavailable";
pub const ERROR_CODE_STREAM_DROPPED: &str = "stream_dropped";
pub const ERROR_CODE_STREAM_RESYNC_REQUIRED: &str = "stream_resync_required";
pub const ERROR_CODE_TOO_LARGE: &str = "too_large";
pub const ERROR_CODE_UNSUPPORTED_DID_METHOD: &str = "unsupported_did_method";
pub const ERROR_CODE_UNSUPPORTED_MEDIA_POLICY: &str = "unsupported_media_policy";
pub const ERROR_CODE_NOT_IMPLEMENTED: &str = "not_implemented";
pub const ERROR_CODE_SERVICE_UNAVAILABLE: &str = "service_unavailable";
pub const ERROR_CODE_UNSUPPORTED_JOIN_RULE: &str = "unsupported_join_rule";
pub const ERROR_CODE_CONTACT_NOT_ACCEPTED: &str = "contact_not_accepted";
pub const ERROR_CODE_CONTACT_CONSENT_MISSING: &str = "contact_consent_missing";
pub const ERROR_CODE_CONTACT_REQUEST_NOT_PENDING: &str = "contact_request_not_pending";
pub const ERROR_CODE_CONTACT_REQUEST_EXPIRED: &str = "contact_request_expired";
pub const ERROR_CODE_DELIVERY_BINDING_UNRESOLVABLE: &str = "delivery_binding_unresolvable";
pub const ERROR_CODE_APPLET_REGISTRATION_UNAUTHORIZED: &str = "applet_registration_unauthorized";
pub const ERROR_CODE_APPLET_INSTALL_PLAN_MISMATCH: &str = "applet_install_plan_mismatch";
pub const ERROR_CODE_APPLET_E2EE_JOIN_UNAUTHORIZED: &str = "applet_e2ee_join_unauthorized";
pub const ERROR_CODE_APPLET_REVOKED: &str = "applet_revoked";
pub const ERROR_CODE_INVALID_AVATAR_BLOB_REF: &str = "invalid_avatar_blob_ref";
pub const ERROR_CODE_UNSUPPORTED_PROFILE_PATCH_PATH: &str = "unsupported_profile_patch_path";
pub const ERROR_CODE_SESSION_GRANT_NOT_FOUND: &str = "session_grant_not_found";
pub const ERROR_CODE_SESSION_REVOKE_SELECTOR_CONFLICT: &str = "session_revoke_selector_conflict";
pub const ERROR_CODE_REVIEWER_CAPABILITY_REVOKED: &str = "reviewer_capability_revoked";
pub const ERROR_CODE_NOT_MEMBER: &str = "not_member";
pub const ERROR_CODE_CALL_NOT_FOUND: &str = "call_not_found";
pub const ERROR_CODE_CALL_EXPIRED: &str = "call_expired";
pub const ERROR_CODE_CALL_ALREADY_ANSWERED: &str = "call_already_answered";
pub const ERROR_CODE_MEDIA_PERMISSION_DENIED: &str = "media_permission_denied";
pub const ERROR_CODE_ICE_CONFIG_DENIED: &str = "ice_config_denied";
pub const ERROR_CODE_SFU_NOT_ALLOWED: &str = "sfu_not_allowed";
pub const ERROR_CODE_E2EE_REQUIRED: &str = "e2ee_required";
pub const ERROR_CODE_RECORDING_DENIED: &str = "recording_denied";
pub const ERROR_CODE_MORPH_PROFILE_WIDENS_SCHEMA_REF: &str = "morph_profile_widens_schema_ref";
pub const ERROR_CODE_MORPH_TYPE_IMMUTABLE: &str = "morph_type_immutable";

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
    ERROR_CODE_REALM_FROZEN,
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
    ERROR_CODE_LIMIT_EXCEEDED,
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
    ERROR_CODE_HISTORY_SHARING_POLICY_MISSING,
    ERROR_CODE_HISTORY_NOT_VISIBLE,
    ERROR_CODE_PREVIEW_POLICY_DENIED,
    ERROR_CODE_NOTARY_RECOVERY_MISSING,
    ERROR_CODE_UNSUPPORTED_LATTICE_TYPE,
    ERROR_CODE_PROFILE_UNSUPPORTED,
    ERROR_CODE_CURSOR_INTEGRITY_INVALID,
    ERROR_CODE_FAILED_PRECONDITION,
    ERROR_CODE_UNSUPPORTED_HASH,
    ERROR_CODE_SEAL_INCOMPLETE,
    ERROR_CODE_FRANKING_PROOF_UNAVAILABLE,
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
    // Spec main (2026-05-23).
    ERROR_CODE_DID_PROOF_REQUIRED,
    ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED,
    ERROR_CODE_EPHEMERAL_KIND_NOT_PERMITTED,
    ERROR_CODE_EPHEMERAL_TTL_OUT_OF_RANGE,
    ERROR_CODE_EPHEMERAL_CHANNEL_UNAVAILABLE,
    ERROR_CODE_AUTHORIZED_GRANT_REVOKED,
    ERROR_CODE_DEVICE_RECOVERY_SSK_GENERATION_MISMATCH,
    ERROR_CODE_CURSOR_REVOKED,
    // Key-backup hardening (B-C, spec head 37ce729) — 11 codes.
    ERROR_CODE_SERIES_CHAIN_BROKEN,
    ERROR_CODE_SERIES_SEQ_NOT_MONOTONIC,
    ERROR_CODE_SERIES_PREDECESSOR_NOT_FOUND,
    ERROR_CODE_RECOVERY_POLICY_MISMATCH,
    ERROR_CODE_SHARE_COMMITMENT_MISMATCH,
    ERROR_CODE_BACKUP_FRONTIER_STALE,
    ERROR_CODE_BACKUP_POST_RESET_STALE,
    ERROR_CODE_RECOVERY_EVIDENCE_UNBOUND,
    ERROR_CODE_UNSUPPORTED_AEAD_PROFILE,
    ERROR_CODE_ATTESTATION_MISSING,
    // R3 spec-sync (2026-05-27) — 20 new codes.
    ERROR_CODE_PAIRING_REQUEST_EXPIRED,
    ERROR_CODE_PROOF_INVALID,
    ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
    ERROR_CODE_AGENT_PAUSED,
    ERROR_CODE_AGENT_DEACTIVATED,
    ERROR_CODE_APPROVAL_ALREADY_CONSUMED,
    ERROR_CODE_SIDECAR_CREATE_DENIED,
    ERROR_CODE_ACTOR_KIND_REDUCER_MANAGED,
    ERROR_CODE_FOCUS_MISMATCH,
    ERROR_CODE_UNKNOWN_FOCUS_TYPE,
    ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED,
    ERROR_CODE_PARTICIPANT_BINDING_INVALID,
    ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED,
    ERROR_CODE_SESSION_FOCUS_ALREADY_COMMITTED,
    ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED,
    ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED,
    ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT,
    ERROR_CODE_RECOVERY_WITNESS_REVOKE_LAGGING,
    ERROR_CODE_HANDLE_HOMOGRAPH_FORBIDDEN,
    // Registry backfill (2026-06-08).
    ERROR_CODE_POLICY_DENIED,
    ERROR_CODE_CURSOR_UNRECOGNIZED,
    ERROR_CODE_ACTOR_SEQ_INVALID,
    ERROR_CODE_STALE_SEAL_REF,
    ERROR_CODE_SEAL_REF_UNKNOWN,
    ERROR_CODE_AUDIENCE_UNKNOWN,
    ERROR_CODE_BLOB_DIGEST_MISMATCH,
    ERROR_CODE_BLOB_EXPIRED,
    ERROR_CODE_BLOB_PRESIGN_INVALID,
    ERROR_CODE_BLOB_QUOTA_EXCEEDED,
    ERROR_CODE_CURSOR_INVALID,
    ERROR_CODE_DEVICE_UNKNOWN,
    ERROR_CODE_DID_ALREADY_EXISTS,
    ERROR_CODE_DID_NOT_FOUND,
    ERROR_CODE_DID_REVOKED,
    ERROR_CODE_FRONTIER_UNAVAILABLE,
    ERROR_CODE_HANDLE_UNVERIFIED,
    ERROR_CODE_KEY_REPLAY,
    ERROR_CODE_KEYPACKAGE_ALREADY_CONSUMED,
    ERROR_CODE_KEYPACKAGE_UNKNOWN,
    ERROR_CODE_ONE_TIME_KEYS_EXHAUSTED,
    ERROR_CODE_POLICY_STALE,
    ERROR_CODE_POLICY_UNAVAILABLE,
    ERROR_CODE_PRINCIPAL_UNKNOWN,
    ERROR_CODE_PUSH_GATEWAY_UNREACHABLE,
    ERROR_CODE_PUSH_PAYLOAD_TOO_LARGE,
    ERROR_CODE_PUSH_TARGET_UNKNOWN,
    ERROR_CODE_PUSH_TOKEN_INVALID,
    ERROR_CODE_PUSH_TOKEN_UNKNOWN,
    ERROR_CODE_QUARANTINE,
    ERROR_CODE_SNAPSHOT_AUTHORITY_UNVERIFIED,
    ERROR_CODE_REDUCER_PROFILE_MISMATCH,
    ERROR_CODE_SNAPSHOT_UNAVAILABLE,
    ERROR_CODE_STREAM_DROPPED,
    ERROR_CODE_STREAM_RESYNC_REQUIRED,
    ERROR_CODE_TOO_LARGE,
    ERROR_CODE_UNSUPPORTED_DID_METHOD,
    ERROR_CODE_UNSUPPORTED_MEDIA_POLICY,
    ERROR_CODE_NOT_IMPLEMENTED,
    ERROR_CODE_SERVICE_UNAVAILABLE,
    ERROR_CODE_UNSUPPORTED_JOIN_RULE,
    ERROR_CODE_CONTACT_NOT_ACCEPTED,
    ERROR_CODE_CONTACT_CONSENT_MISSING,
    ERROR_CODE_CONTACT_REQUEST_NOT_PENDING,
    ERROR_CODE_CONTACT_REQUEST_EXPIRED,
    ERROR_CODE_DELIVERY_BINDING_UNRESOLVABLE,
    ERROR_CODE_APPLET_REGISTRATION_UNAUTHORIZED,
    ERROR_CODE_APPLET_INSTALL_PLAN_MISMATCH,
    ERROR_CODE_APPLET_E2EE_JOIN_UNAUTHORIZED,
    ERROR_CODE_APPLET_REVOKED,
    ERROR_CODE_INVALID_AVATAR_BLOB_REF,
    ERROR_CODE_UNSUPPORTED_PROFILE_PATCH_PATH,
    ERROR_CODE_SESSION_GRANT_NOT_FOUND,
    ERROR_CODE_SESSION_REVOKE_SELECTOR_CONFLICT,
    ERROR_CODE_REVIEWER_CAPABILITY_REVOKED,
    ERROR_CODE_NOT_MEMBER,
    ERROR_CODE_CALL_NOT_FOUND,
    ERROR_CODE_CALL_EXPIRED,
    ERROR_CODE_CALL_ALREADY_ANSWERED,
    ERROR_CODE_MEDIA_PERMISSION_DENIED,
    ERROR_CODE_ICE_CONFIG_DENIED,
    ERROR_CODE_SFU_NOT_ALLOWED,
    ERROR_CODE_E2EE_REQUIRED,
    ERROR_CODE_RECORDING_DENIED,
    ERROR_CODE_MORPH_PROFILE_WIDENS_SCHEMA_REF,
    ERROR_CODE_MORPH_TYPE_IMMUTABLE,
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
/// Inception key age (computed independently by the receiver / Auth Server from
/// the verifiable `did:webvh` bootstrap timestamp against the local clock)
/// exceeds the 24h protocol hard cap. The receiver MUST reject the
/// `ck.device.authorize` / `ck.session.grant` / long-lived capability / ordinary
/// DID update signed by that inception key regardless of any longer
/// `inception_key_max_online_window` self-reported by deployment policy
/// (key-management.md §5). `applies_to`: event_envelope / auth_decision.
pub const REASON_INCEPTION_KEY_WINDOW_EXCEEDED: &str = "inception_key_window_exceeded";

// P-D4 — `ck.profile.e2ee_relaxed.v1` profile interactions.
pub const REASON_MLS_SEND_PAUSE_ADVISORY_REQUIRES_E2EE_RELAXED_PROFILE: &str =
    "mls_send_pause_advisory_requires_e2ee_relaxed_profile";
pub const REASON_CONFLICTING_E2EE_PROFILES: &str = "conflicting_e2ee_profiles";

// Misc.
pub const REASON_CARDINALITY_VIOLATION: &str = "cardinality_violation";
pub const REASON_CLAIM_FAILED: &str = "claim_failed";

// ── Round C45 (2026-05-18 main) — reason codes.
//
// `failed_precondition` sub-codes for lifecycle state machines, patch grammar,
// AEAD nonce derivation, accountability_grant verification, delegation, fork
// recovery witness, range completeness, and deprecation timeline. Spec:
// `error-code-registry.json#reason_codes`.

// Lifecycle state-machine guards (Strand / Space / Morph / Message / Relation).
pub const REASON_STRAND_NOT_ACTIVE: &str = "strand_not_active";
pub const REASON_STRAND_NOT_ARCHIVED: &str = "strand_not_archived";
pub const REASON_STRAND_ALREADY_TERMINAL: &str = "strand_already_terminal";
pub const REASON_SPACE_NOT_ACTIVE: &str = "space_not_active";
pub const REASON_SPACE_NOT_ARCHIVED: &str = "space_not_archived";
pub const REASON_SPACE_ALREADY_TERMINAL: &str = "space_already_terminal";
pub const REASON_SPACE_PARENT_CYCLE: &str = "space_parent_cycle";
pub const REASON_SPACE_HAS_LIVE_DEPENDENTS: &str = "space_has_live_dependents";
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
pub const REASON_RECOVERY_CAPABILITY_NOT_SEALED: &str = "recovery_capability_not_sealed";

// Policy server runtime challenge (zh/authz/policy-server.md §4).
pub const REASON_CHALLENGE_PROOF_INVALID: &str = "challenge_proof_invalid";
pub const REASON_INVALID_TASK_FSM_TRANSITION: &str = "invalid_task_fsm_transition";

// Audit-agent destruction pairing and attestations.
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

// Profile and structural relation policy reasons.
pub const REASON_LITE_PROFILE_WRITES_DISALLOWED_EVENT_KIND: &str =
    "lite_profile_writes_disallowed_event_kind";
pub const REASON_CROSS_SPACE_STRUCTURAL_RELATION: &str = "cross_space_structural_relation";

// Watch state capabilities (zh/models/strand-and-message.md §8.4–8.5).
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
pub const REASON_WATCH_SET_OTHERS_AUDIT_MISSING: &str = "watch_set_others_audit_missing";
pub const REASON_MANAGE_OTHERS_AUDIT_MISSING: &str = "manage_others_audit_missing";

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

// Range-completeness attestation (zh/sync/operations-sync.md §4.2.4).
pub const REASON_RANGE_COMPLETENESS_ROOT_MISMATCH: &str = "range_completeness_root_mismatch";
pub const REASON_RANGE_COMPLETENESS_ACTOR_SEQ_GAP: &str = "range_completeness_actor_seq_gap";
pub const REASON_WITNESS_DISAGREEMENT: &str = "witness_disagreement";

/// Known `failed_precondition` reason codes registered in round C45.
pub const KNOWN_REASON_CODES_ROUND_C45: &[&str] = &[
    REASON_STRAND_NOT_ACTIVE,
    REASON_STRAND_NOT_ARCHIVED,
    REASON_STRAND_ALREADY_TERMINAL,
    REASON_SPACE_NOT_ACTIVE,
    REASON_SPACE_NOT_ARCHIVED,
    REASON_SPACE_ALREADY_TERMINAL,
    REASON_SPACE_PARENT_CYCLE,
    REASON_SPACE_HAS_LIVE_DEPENDENTS,
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
    REASON_RECOVERY_CAPABILITY_NOT_SEALED,
    REASON_CHALLENGE_PROOF_INVALID,
    REASON_AUDIT_CAPABILITY_INCOMPLETE,
    REASON_WATCH_MUST_BE_SELF,
    REASON_WATCH_MUTED_MUST_BE_SELF,
    REASON_WATCH_LEVEL_PUBLIC_MUST_BE_SELF,
    REASON_WATCH_SET_OTHERS_AUDIT_MISSING,
    REASON_JOIN_AUTHORISATION_INVALID,
    REASON_JOIN_RULE_POLICY_MISMATCH,
    REASON_CROSS_SIGNING_RESET,
    REASON_TTL_EXPIRED,
    REASON_NOT_PROVISIONED,
    REASON_MORPH_SCHEMA_REFS_EVOLUTION_UNAUTHORIZED,
    REASON_MORPH_SCHEMA_REFS_TRANSFORMATION_UNSUPPORTED,
    REASON_MORPH_SCHEMA_VERSION_BINDING_MISSING,
    REASON_RANGE_COMPLETENESS_ROOT_MISMATCH,
    REASON_RANGE_COMPLETENESS_ACTOR_SEQ_GAP,
    REASON_WITNESS_DISAGREEMENT,
];

// ── CKP-0007 (spec b7d35be) — Circle primitive reason codes.
//
// `failed_precondition` / `schema_violation` sub-codes for the Circle
// invariants in zh/models/circle.md. Spec `error-code-registry.json`
// reason_codes section.
/// `schema_violation` sub-reason: object's `scope_circle_id` references a
/// Circle whose `realm_id` does not match the object's `realm_id`.
pub const REASON_CIRCLE_REALM_MISMATCH: &str = "circle_realm_mismatch";
/// `failed_precondition` sub-reason: `scope_circle_id` points at a Circle
/// whose state is `archived` or `tombstoned`.
pub const REASON_CIRCLE_NOT_ACTIVE: &str = "circle_not_active";
/// `failed_precondition` sub-reason on `ck.circle.member.state → active`
/// when the target actor is not yet an active member of the parent Realm.
/// Reflects the strict-subset invariant
/// `Circle.members ⊆ Realm.members`.
pub const REASON_CIRCLE_MEMBER_MUST_BE_REALM_MEMBER: &str = "circle_member_must_be_realm_member";
/// `failed_precondition` sub-reason: Circle encryption profile would be
/// weaker than the parent Realm encryption profile or content encryption
/// floor.
pub const REASON_CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR: &str = "circle_encryption_below_realm_floor";
/// `failed_precondition` sub-reason: content write would land in a
/// non-MLS-backed effective scope while the Realm content floor requires E2EE.
pub const REASON_CONTENT_ENCRYPTION_FLOOR_VIOLATION: &str = "content_encryption_floor_violation";
/// `failed_precondition` sub-reason: attempted `scope_circle_id` rebind
/// without an explicitly profile-permitted audited-high-risk path.
pub const REASON_SCOPE_REBIND_FORBIDDEN: &str = "scope_rebind_forbidden";
/// `schema_violation` sub-reason: actor-side submit payload supplied the
/// reducer-managed `effective_scope` field directly.
pub const REASON_EFFECTIVE_SCOPE_REDUCER_MANAGED: &str = "effective_scope_reducer_managed";
/// `failed_precondition` sub-reason: a write would expose metadata below
/// the effective `metadata_encryption_floor` floor (max of parent
/// Realm, Circle, Space child-scope-policy, and object profile floors).
pub const REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION: &str = "metadata_encryption_floor_violation";
/// `failed_precondition` sub-reason: a `ck.realm.policy_components` /
/// `ck.circle.update` would lower a scope's effective
/// `content_encryption_floor` from `e2ee_required` back to `allow_plaintext`.
/// The effective content floor is a one-way ratchet (monotonically
/// non-decreasing); tightening is allowed, lowering is rejected.
pub const REASON_CONTENT_ENCRYPTION_FLOOR_DOWNGRADE: &str = "content_encryption_floor_downgrade";
/// `failed_precondition` sub-reason: a `ck.realm.policy_components` /
/// `ck.circle.update` would lower a scope's effective metadata encryption
/// floor to a lower level (`allow_plaintext < e2ee_required`).
/// The effective metadata floor is a one-way ratchet.
pub const REASON_METADATA_ENCRYPTION_FLOOR_DOWNGRADE: &str = "metadata_encryption_floor_downgrade";

/// CKP-0007 (spec b7d35be) — Circle reason codes registered under the
/// `failed_precondition` / `schema_violation` wire-code families. The
/// 6th CKP-0007 code is the top-level
/// [`ERROR_CODE_DELIVERY_BINDING_HANDED_OVER`] already registered in
/// round 4 (CKP-0006).
pub const KNOWN_REASON_CODES_CKP_0007: &[&str] = &[
    REASON_CIRCLE_REALM_MISMATCH,
    REASON_CIRCLE_NOT_ACTIVE,
    REASON_CIRCLE_MEMBER_MUST_BE_REALM_MEMBER,
    REASON_CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR,
    REASON_CONTENT_ENCRYPTION_FLOOR_VIOLATION,
    REASON_SCOPE_REBIND_FORBIDDEN,
    REASON_EFFECTIVE_SCOPE_REDUCER_MANAGED,
    REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION,
    REASON_CONTENT_ENCRYPTION_FLOOR_DOWNGRADE,
    REASON_METADATA_ENCRYPTION_FLOOR_DOWNGRADE,
];

/// Known `failed_precondition` reason codes registered in round C44.
pub const KNOWN_REASON_CODES_ROUND_C44: &[&str] = &[
    REASON_INCEPTION_UPGRADE_FINGERPRINT_MISMATCH,
    REASON_INCEPTION_UPGRADE_SIGNATURE_CHAIN_INVALID,
    REASON_INCEPTION_UPGRADE_OLD_DOCUMENT_HASH_MISMATCH,
    REASON_INCEPTION_UPGRADE_EVIDENCE_INSUFFICIENT,
    REASON_INCEPTION_KEY_WINDOW_EXCEEDED,
    REASON_MLS_SEND_PAUSE_ADVISORY_REQUIRES_E2EE_RELAXED_PROFILE,
    REASON_CONFLICTING_E2EE_PROFILES,
    REASON_CARDINALITY_VIOLATION,
    REASON_CLAIM_FAILED,
];

// ── Reaction model (spec strand-and-message.md §9.8) reason codes.
//
// Sub-reasons registered against `schema_violation` / `failed_precondition`
// for the v1 Reaction target-scope invariants.
// Spec: `error-code-registry.json#reason_codes` (commit 4d9438f).

/// `schema_violation` sub-reason: a `ck.reaction.add` / `ck.reaction.remove`
/// `target_ref` points at an object kind that the deployment does not allow
/// reactions on. v1 core only allows `ck:message:` targets; profiles MAY
/// register additional target kinds. See zh/models/strand-and-message.md §9.8.2.
pub const REASON_REACTION_TARGET_UNSUPPORTED: &str = "reaction_target_unsupported";
/// `failed_precondition` sub-reason: a `ck.reaction.*` `target_ref` resolves
/// to an object outside the reaction event's stamped effective scope.
/// Reactions MUST target an object within their own effective scope. See
/// zh/models/strand-and-message.md §9.8.2.
pub const REASON_REACTION_SCOPE_MISMATCH: &str = "reaction_scope_mismatch";

/// Reaction reason codes registered for the §9.8 Reaction model.
pub const KNOWN_REASON_CODES_REACTION: &[&str] = &[
    REASON_REACTION_TARGET_UNSUPPORTED,
    REASON_REACTION_SCOPE_MISMATCH,
];

pub const REASON_CONTACT_NOT_ACCEPTED: &str = "contact_not_accepted";
pub const REASON_CONTACT_CONSENT_MISSING: &str = "contact_consent_missing";
pub const KNOWN_REASON_CODES_CONTACT_DIRECT_CONVERSATION: &[&str] =
    &[REASON_CONTACT_NOT_ACCEPTED, REASON_CONTACT_CONSENT_MISSING];

// ── Federation / to-device reason codes (error-code-registry.json#reason_codes).

/// `federation_transaction` / `service_call` audit-only reason:
/// `Destination-Trust-Domain` does not equal the receiver deployment's
/// `ServiceDescribe.trust_domain`, or does not match the receiving Realm's
/// `trust_domain` (zh/sync/federation.md §3.2). The wire response MUST be the
/// unified minimal-disclosure authentication failure envelope.
pub const REASON_FEDERATION_TRUST_DOMAIN_MISMATCH: &str = "federation_trust_domain_mismatch";
/// `service_call` reason carried under `invalid_param`: a to-device message
/// ack carried an ack token that does not correspond to a delivered to-device
/// cursor (unknown, malformed, or already-superseded). See
/// zh/sync/client-sync.md §10.1 and zh/sync/service-http-binding.md
/// device_messages/ack.
pub const REASON_INVALID_ACK_TOKEN: &str = "invalid_ack_token";

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
        | ERROR_CODE_TTL_OUT_OF_RANGE
        | ERROR_CODE_EPHEMERAL_TTL_OUT_OF_RANGE
        | ERROR_CODE_CURSOR_UNRECOGNIZED
        | ERROR_CODE_BLOB_PRESIGN_INVALID
        | ERROR_CODE_CURSOR_INVALID
        | ERROR_CODE_PUSH_TOKEN_INVALID => 400,
        ERROR_CODE_UNAUTHENTICATED
        | ERROR_CODE_AUTH_EXPIRED
        | ERROR_CODE_SOFT_LOGGED_OUT
        | ERROR_CODE_INVALID_SIGNATURE
        | ERROR_CODE_TURN_CREDENTIAL_EXPIRED
        | ERROR_CODE_ATTESTATION_MISSING
        | ERROR_CODE_DID_PROOF_REQUIRED
        | ERROR_CODE_PROOF_INVALID
        | ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH
        | ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED => 401,
        ERROR_CODE_CAPABILITY_DENIED
        | ERROR_CODE_DIRECTORY_NOT_AUTHORIZED
        | ERROR_CODE_ACCEPT_POLICY_DENIED
        | ERROR_CODE_REALM_FROZEN
        | ERROR_CODE_CLAIM_REQUIRED
        | ERROR_CODE_POLICY_VIOLATION
        | ERROR_CODE_QUOTA_EXCEEDED
        | ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE
        | ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN
        | ERROR_CODE_LEGAL_HOLD_ACTIVE
        | ERROR_CODE_BLOB_REDACTED
        | ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED
        | ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP
        | ERROR_CODE_EPHEMERAL_KIND_NOT_PERMITTED
        | ERROR_CODE_AGENT_PAUSED
        | ERROR_CODE_AGENT_DEACTIVATED
        | ERROR_CODE_SIDECAR_CREATE_DENIED
        | ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED
        | ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED
        | ERROR_CODE_HISTORY_NOT_VISIBLE
        | ERROR_CODE_PREVIEW_POLICY_DENIED
        | ERROR_CODE_HANDLE_HOMOGRAPH_FORBIDDEN
        | ERROR_CODE_POLICY_DENIED
        | ERROR_CODE_BLOB_QUOTA_EXCEEDED
        | ERROR_CODE_HANDLE_UNVERIFIED
        | ERROR_CODE_SNAPSHOT_AUTHORITY_UNVERIFIED
        | ERROR_CODE_APPLET_REGISTRATION_UNAUTHORIZED
        | ERROR_CODE_APPLET_E2EE_JOIN_UNAUTHORIZED
        | ERROR_CODE_APPLET_REVOKED
        | ERROR_CODE_REVIEWER_CAPABILITY_REVOKED
        | ERROR_CODE_NOT_MEMBER
        | ERROR_CODE_MEDIA_PERMISSION_DENIED
        | ERROR_CODE_ICE_CONFIG_DENIED
        | ERROR_CODE_SFU_NOT_ALLOWED
        | ERROR_CODE_E2EE_REQUIRED
        | ERROR_CODE_RECORDING_DENIED => 403,
        ERROR_CODE_NOT_FOUND
        | ERROR_CODE_UNRECOGNIZED_ENDPOINT
        | ERROR_CODE_SEAL_REF_UNKNOWN
        | ERROR_CODE_AUDIENCE_UNKNOWN
        | ERROR_CODE_DEVICE_UNKNOWN
        | ERROR_CODE_DID_NOT_FOUND
        | ERROR_CODE_KEYPACKAGE_UNKNOWN
        | ERROR_CODE_PRINCIPAL_UNKNOWN
        | ERROR_CODE_PUSH_TARGET_UNKNOWN
        | ERROR_CODE_PUSH_TOKEN_UNKNOWN
        | ERROR_CODE_SESSION_GRANT_NOT_FOUND
        | ERROR_CODE_CALL_NOT_FOUND => 404,
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
        | ERROR_CODE_SEAL_INCOMPLETE
        | ERROR_CODE_STALE_PEER
        | ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED
        | ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT
        | ERROR_CODE_REALM_TERMINAL_STATE
        | ERROR_CODE_AUDIT_PURPOSE_MISMATCH
        | ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE
        | ERROR_CODE_DELIVERY_BINDING_STALE
        | ERROR_CODE_DELIVERY_BINDING_HANDED_OVER
        | ERROR_CODE_TAKEDOWN_IN_FORCE
        | ERROR_CODE_POLICY_REVISION_ROLLBACK
        | ERROR_CODE_AUTHORIZED_GRANT_REVOKED
        | ERROR_CODE_DEVICE_RECOVERY_SSK_GENERATION_MISMATCH
        | ERROR_CODE_SERIES_CHAIN_BROKEN
        | ERROR_CODE_SERIES_SEQ_NOT_MONOTONIC
        | ERROR_CODE_SERIES_PREDECESSOR_NOT_FOUND
        | ERROR_CODE_RECOVERY_POLICY_MISMATCH
        | ERROR_CODE_BACKUP_FRONTIER_STALE
        | ERROR_CODE_BACKUP_POST_RESET_STALE
        | ERROR_CODE_APPROVAL_ALREADY_CONSUMED
        | ERROR_CODE_ACTOR_KIND_REDUCER_MANAGED
        | ERROR_CODE_FOCUS_MISMATCH
        | ERROR_CODE_SESSION_FOCUS_ALREADY_COMMITTED
        | ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT
        | ERROR_CODE_RECOVERY_WITNESS_REVOKE_LAGGING
        | ERROR_CODE_ACTOR_SEQ_INVALID
        | ERROR_CODE_STALE_SEAL_REF
        | ERROR_CODE_DID_ALREADY_EXISTS
        | ERROR_CODE_KEY_REPLAY
        | ERROR_CODE_KEYPACKAGE_ALREADY_CONSUMED
        | ERROR_CODE_ONE_TIME_KEYS_EXHAUSTED
        | ERROR_CODE_POLICY_STALE
        | ERROR_CODE_QUARANTINE
        | ERROR_CODE_REDUCER_PROFILE_MISMATCH
        | ERROR_CODE_STREAM_DROPPED
        | ERROR_CODE_STREAM_RESYNC_REQUIRED
        | ERROR_CODE_CONTACT_NOT_ACCEPTED
        | ERROR_CODE_CONTACT_CONSENT_MISSING
        | ERROR_CODE_CONTACT_REQUEST_NOT_PENDING
        | ERROR_CODE_CONTACT_REQUEST_EXPIRED
        | ERROR_CODE_DELIVERY_BINDING_UNRESOLVABLE
        | ERROR_CODE_APPLET_INSTALL_PLAN_MISMATCH
        | ERROR_CODE_CALL_ALREADY_ANSWERED => 409,
        ERROR_CODE_HISTORICAL_ONLY => 200,
        ERROR_CODE_CURSOR_EXPIRED
        | ERROR_CODE_CURSOR_REVOKED
        | ERROR_CODE_BLOB_EXPIRED
        | ERROR_CODE_DID_REVOKED
        | ERROR_CODE_CALL_EXPIRED => 410,
        ERROR_CODE_PAYLOAD_TOO_LARGE
        | ERROR_CODE_PUSH_PAYLOAD_TOO_LARGE
        | ERROR_CODE_TOO_LARGE
        | ERROR_CODE_LIMIT_EXCEEDED => 413,
        ERROR_CODE_SCHEMA_VIOLATION
        | ERROR_CODE_DIGEST_MISMATCH
        | ERROR_CODE_AAD_DIGEST_MISMATCH
        | ERROR_CODE_PAYLOAD_DIGEST_MISMATCH
        | ERROR_CODE_UNKNOWN_DID
        | ERROR_CODE_POLICY_COMBINATION_INVALID
        | ERROR_CODE_HISTORY_SHARING_POLICY_MISSING
        | ERROR_CODE_NOTARY_RECOVERY_MISSING
        | ERROR_CODE_UNSUPPORTED_LATTICE_TYPE
        | ERROR_CODE_UNSUPPORTED_HASH
        | ERROR_CODE_SHARE_COMMITMENT_MISMATCH
        | ERROR_CODE_RECOVERY_EVIDENCE_UNBOUND
        | ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED
        | ERROR_CODE_PAIRING_REQUEST_EXPIRED
        | ERROR_CODE_UNKNOWN_FOCUS_TYPE
        | ERROR_CODE_PARTICIPANT_BINDING_INVALID
        | ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED
        | ERROR_CODE_PROFILE_UNSUPPORTED
        | ERROR_CODE_BLOB_DIGEST_MISMATCH
        | ERROR_CODE_UNSUPPORTED_DID_METHOD
        | ERROR_CODE_UNSUPPORTED_MEDIA_POLICY
        | ERROR_CODE_UNSUPPORTED_JOIN_RULE
        | ERROR_CODE_INVALID_AVATAR_BLOB_REF
        | ERROR_CODE_UNSUPPORTED_PROFILE_PATCH_PATH
        | ERROR_CODE_SESSION_REVOKE_SELECTOR_CONFLICT
        | ERROR_CODE_MORPH_PROFILE_WIDENS_SCHEMA_REF
        | ERROR_CODE_MORPH_TYPE_IMMUTABLE => 422,
        ERROR_CODE_RATE_LIMITED => 429,
        ERROR_CODE_INTERNAL_ERROR => 500,
        ERROR_CODE_HLC_LOGICAL_OVERFLOW
        | ERROR_CODE_TEMPORARILY_UNAVAILABLE
        | ERROR_CODE_FRANKING_PROOF_UNAVAILABLE
        | ERROR_CODE_EPHEMERAL_CHANNEL_UNAVAILABLE
        | ERROR_CODE_FRONTIER_UNAVAILABLE
        | ERROR_CODE_POLICY_UNAVAILABLE
        | ERROR_CODE_PUSH_GATEWAY_UNREACHABLE
        | ERROR_CODE_SNAPSHOT_UNAVAILABLE
        | ERROR_CODE_SERVICE_UNAVAILABLE => 503,
        ERROR_CODE_TIMEOUT => 504,
        ERROR_CODE_UNSUPPORTED_FEATURE
        | ERROR_CODE_UNSUPPORTED_EVENT_KIND
        | ERROR_CODE_UNSUPPORTED_AEAD_PROFILE
        | ERROR_CODE_NOT_IMPLEMENTED => 501,
        _ => return None,
    })
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid Cokret identifier: {0}")]
    InvalidId(String),

    #[error("conflicting bytes for idempotent object {0}")]
    IdempotencyConflict(String),

    #[error(
        "canonical JSON does not allow floating point or ambiguous numbers (encoding.md \
         §3.2: only integer-typed values may appear in signing inputs)"
    )]
    NonCanonicalNumber,

    #[error(
        "canonical JSON integer is outside the JSON safe-integer range \
         [-9007199254740991, 9007199254740991] (encoding.md §2): values beyond this range \
         MUST be encoded as an explicitly-formatted string, not a JSON number"
    )]
    NumberOutOfSafeRange,

    #[error(
        "canonical JSON object contains duplicate key {0:?} (encoding.md §2: duplicate keys MUST be rejected)"
    )]
    DuplicateObjectKey(String),

    #[error(
        "canonical JSON contains a forbidden U+FEFF / UTF-8 BOM (encoding.md §2: any U+FEFF, \
         at stream start or inside a string value, MUST be rejected as schema_violation): {0}"
    )]
    NonCanonicalString(String),

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

    // Transport-agnostic HTTP failure. cokret-core is the wire-model /
    // canonical layer and deliberately has no dependency on a concrete HTTP
    // stack; transport adapters (cokret-http-client and any alternative
    // binding) wrap their stack-specific errors into this variant at the
    // boundary.
    #[cfg(feature = "client")]
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[cfg(feature = "mls")]
    #[error("MLS operation failed: {0}")]
    Mls(String),

    #[error("Cokret API returned {status}: {error}")]
    Api {
        status: u16,
        error: Box<ErrorEnvelope>,
    },

    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<cokret_identifiers::IdentifierError> for Error {
    fn from(error: cokret_identifiers::IdentifierError) -> Self {
        match error {
            cokret_identifiers::IdentifierError::InvalidId(value) => Self::InvalidId(value),
            cokret_identifiers::IdentifierError::Random(error) => Self::Crypto(error),
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

/// Strongly-typed view over the canonical Cokret error code registry.
///
/// Every variant corresponds to one entry in [`KNOWN_ERROR_CODES`].
/// Round-trip helpers:
///
/// - [`ErrorCode::as_str`] → wire-form snake_case string (same value as the matching `ERROR_CODE_*`
///   constant).
/// - [`ErrorCode::from_wire`] → parse a wire string back into the typed variant. Returns `None` for
///   any code not in the registry.
/// - [`ErrorCode::http_status`] → registered HTTP status, identical to what
///   [`error_code_http_status`] returns for the same wire string.
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
    RealmFrozen,
    ClaimRequired,
    NotFound,
    UnrecognizedEndpoint,
    MethodNotAllowed,
    Conflict,
    CasConflict,
    CausalConflict,
    DependencyMissing,
    DiscussionTrackDisabled,
    /// C14 / read-receipts §2.5: Sync Service drops `ck.receipt.read` when
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
    LimitExceeded,
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
    HistorySharingPolicyMissing,
    HistoryNotVisible,
    PreviewPolicyDenied,
    NotaryRecoveryMissing,
    UnsupportedLatticeType,
    ProfileUnsupported,
    CursorIntegrityInvalid,
    FailedPrecondition,
    UnsupportedHash,
    SealIncomplete,
    FrankingProofUnavailable,
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
    // ── Spec main (2026-05-23).
    DidProofRequired,
    ReadReceiptComplianceFloorViolated,
    EphemeralKindNotPermitted,
    EphemeralTtlOutOfRange,
    EphemeralChannelUnavailable,
    AuthorizedGrantRevoked,
    DeviceRecoverySskGenerationMismatch,
    CursorRevoked,
    // ── Key-backup hardening (B-C, spec head 37ce729).
    SeriesChainBroken,
    SeriesSeqNotMonotonic,
    SeriesPredecessorNotFound,
    RecoveryPolicyMismatch,
    ShareCommitmentMismatch,
    BackupFrontierStale,
    BackupPostResetStale,
    RecoveryEvidenceUnbound,
    UnsupportedAeadProfile,
    AttestationMissing,
    // ── R3 spec-sync (2026-05-27, cokret-spec b47ff6ec).
    PairingRequestExpired,
    ProofInvalid,
    VerificationMethodPrincipalMismatch,
    AgentPaused,
    AgentDeactivated,
    ApprovalAlreadyConsumed,
    SidecarCreateDenied,
    ActorKindReducerManaged,
    FocusMismatch,
    UnknownFocusType,
    TokenIssuerUnauthorised,
    ParticipantBindingInvalid,
    ParticipantIdentityUnrecognised,
    SessionFocusAlreadyCommitted,
    E2eeKeySourceUnauthorised,
    RecordingArtifactPipelineBypassed,
    FocusUnavailableForClient,
    RecoveryWitnessRevokeLagging,
    HandleHomographForbidden,
    // ── Registry backfill (2026-06-08).
    PolicyDenied,
    CursorUnrecognized,
    ActorSeqInvalid,
    StaleSealRef,
    SealRefUnknown,
    AudienceUnknown,
    BlobDigestMismatch,
    BlobExpired,
    BlobPresignInvalid,
    BlobQuotaExceeded,
    CursorInvalid,
    DeviceUnknown,
    DidAlreadyExists,
    DidNotFound,
    DidRevoked,
    FrontierUnavailable,
    HandleUnverified,
    KeyReplay,
    KeypackageAlreadyConsumed,
    KeypackageUnknown,
    OneTimeKeysExhausted,
    PolicyStale,
    PolicyUnavailable,
    PrincipalUnknown,
    PushGatewayUnreachable,
    PushPayloadTooLarge,
    PushTargetUnknown,
    PushTokenInvalid,
    PushTokenUnknown,
    Quarantine,
    SnapshotAuthorityUnverified,
    ReducerProfileMismatch,
    SnapshotUnavailable,
    StreamDropped,
    StreamResyncRequired,
    TooLarge,
    UnsupportedDidMethod,
    UnsupportedMediaPolicy,
    NotImplemented,
    ServiceUnavailable,
    UnsupportedJoinRule,
    ContactNotAccepted,
    ContactConsentMissing,
    ContactRequestNotPending,
    ContactRequestExpired,
    DeliveryBindingUnresolvable,
    AppletRegistrationUnauthorized,
    AppletInstallPlanMismatch,
    AppletE2eeJoinUnauthorized,
    AppletRevoked,
    InvalidAvatarBlobRef,
    UnsupportedProfilePatchPath,
    SessionGrantNotFound,
    SessionRevokeSelectorConflict,
    ReviewerCapabilityRevoked,
    NotMember,
    CallNotFound,
    CallExpired,
    CallAlreadyAnswered,
    MediaPermissionDenied,
    IceConfigDenied,
    SfuNotAllowed,
    E2eeRequired,
    RecordingDenied,
    MorphProfileWidensSchemaRef,
    MorphTypeImmutable,
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
        Self::RealmFrozen,
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
        Self::LimitExceeded,
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
        Self::HistorySharingPolicyMissing,
        Self::HistoryNotVisible,
        Self::PreviewPolicyDenied,
        Self::NotaryRecoveryMissing,
        Self::UnsupportedLatticeType,
        Self::ProfileUnsupported,
        Self::CursorIntegrityInvalid,
        Self::FailedPrecondition,
        Self::UnsupportedHash,
        Self::SealIncomplete,
        Self::FrankingProofUnavailable,
        Self::TurnCredentialExpired,
        Self::StalePeer,
        Self::RelaxedWindowExceedsCeiling,
        Self::E2eeRelaxedDisallowedInComplianceProfile,
        Self::CrossDomainReplayRejected,
        Self::ResetEventIdMismatch,
        Self::AppealOverturnMissingLift,
        Self::AppealSelfReviewForbidden,
        Self::RealmTerminalState,
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
        Self::DidProofRequired,
        Self::ReadReceiptComplianceFloorViolated,
        Self::EphemeralKindNotPermitted,
        Self::EphemeralTtlOutOfRange,
        Self::EphemeralChannelUnavailable,
        Self::AuthorizedGrantRevoked,
        Self::DeviceRecoverySskGenerationMismatch,
        Self::CursorRevoked,
        Self::SeriesChainBroken,
        Self::SeriesSeqNotMonotonic,
        Self::SeriesPredecessorNotFound,
        Self::RecoveryPolicyMismatch,
        Self::ShareCommitmentMismatch,
        Self::BackupFrontierStale,
        Self::BackupPostResetStale,
        Self::RecoveryEvidenceUnbound,
        Self::UnsupportedAeadProfile,
        Self::AttestationMissing,
        // ── R3 spec-sync (2026-05-27).
        Self::PairingRequestExpired,
        Self::ProofInvalid,
        Self::VerificationMethodPrincipalMismatch,
        Self::AgentPaused,
        Self::AgentDeactivated,
        Self::ApprovalAlreadyConsumed,
        Self::SidecarCreateDenied,
        Self::ActorKindReducerManaged,
        Self::FocusMismatch,
        Self::UnknownFocusType,
        Self::TokenIssuerUnauthorised,
        Self::ParticipantBindingInvalid,
        Self::ParticipantIdentityUnrecognised,
        Self::SessionFocusAlreadyCommitted,
        Self::E2eeKeySourceUnauthorised,
        Self::RecordingArtifactPipelineBypassed,
        Self::FocusUnavailableForClient,
        Self::RecoveryWitnessRevokeLagging,
        Self::HandleHomographForbidden,
        // ── Registry backfill (2026-06-08).
        Self::PolicyDenied,
        Self::CursorUnrecognized,
        Self::ActorSeqInvalid,
        Self::StaleSealRef,
        Self::SealRefUnknown,
        Self::AudienceUnknown,
        Self::BlobDigestMismatch,
        Self::BlobExpired,
        Self::BlobPresignInvalid,
        Self::BlobQuotaExceeded,
        Self::CursorInvalid,
        Self::DeviceUnknown,
        Self::DidAlreadyExists,
        Self::DidNotFound,
        Self::DidRevoked,
        Self::FrontierUnavailable,
        Self::HandleUnverified,
        Self::KeyReplay,
        Self::KeypackageAlreadyConsumed,
        Self::KeypackageUnknown,
        Self::OneTimeKeysExhausted,
        Self::PolicyStale,
        Self::PolicyUnavailable,
        Self::PrincipalUnknown,
        Self::PushGatewayUnreachable,
        Self::PushPayloadTooLarge,
        Self::PushTargetUnknown,
        Self::PushTokenInvalid,
        Self::PushTokenUnknown,
        Self::Quarantine,
        Self::SnapshotAuthorityUnverified,
        Self::ReducerProfileMismatch,
        Self::SnapshotUnavailable,
        Self::StreamDropped,
        Self::StreamResyncRequired,
        Self::TooLarge,
        Self::UnsupportedDidMethod,
        Self::UnsupportedMediaPolicy,
        Self::NotImplemented,
        Self::ServiceUnavailable,
        Self::UnsupportedJoinRule,
        Self::ContactNotAccepted,
        Self::ContactConsentMissing,
        Self::ContactRequestNotPending,
        Self::ContactRequestExpired,
        Self::DeliveryBindingUnresolvable,
        Self::AppletRegistrationUnauthorized,
        Self::AppletInstallPlanMismatch,
        Self::AppletE2eeJoinUnauthorized,
        Self::AppletRevoked,
        Self::InvalidAvatarBlobRef,
        Self::UnsupportedProfilePatchPath,
        Self::SessionGrantNotFound,
        Self::SessionRevokeSelectorConflict,
        Self::ReviewerCapabilityRevoked,
        Self::NotMember,
        Self::CallNotFound,
        Self::CallExpired,
        Self::CallAlreadyAnswered,
        Self::MediaPermissionDenied,
        Self::IceConfigDenied,
        Self::SfuNotAllowed,
        Self::E2eeRequired,
        Self::RecordingDenied,
        Self::MorphProfileWidensSchemaRef,
        Self::MorphTypeImmutable,
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
            Self::RealmFrozen => ERROR_CODE_REALM_FROZEN,
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
            Self::LimitExceeded => ERROR_CODE_LIMIT_EXCEEDED,
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
            Self::HistorySharingPolicyMissing => ERROR_CODE_HISTORY_SHARING_POLICY_MISSING,
            Self::HistoryNotVisible => ERROR_CODE_HISTORY_NOT_VISIBLE,
            Self::PreviewPolicyDenied => ERROR_CODE_PREVIEW_POLICY_DENIED,
            Self::NotaryRecoveryMissing => ERROR_CODE_NOTARY_RECOVERY_MISSING,
            Self::UnsupportedLatticeType => ERROR_CODE_UNSUPPORTED_LATTICE_TYPE,
            Self::ProfileUnsupported => ERROR_CODE_PROFILE_UNSUPPORTED,
            Self::CursorIntegrityInvalid => ERROR_CODE_CURSOR_INTEGRITY_INVALID,
            Self::FailedPrecondition => ERROR_CODE_FAILED_PRECONDITION,
            Self::UnsupportedHash => ERROR_CODE_UNSUPPORTED_HASH,
            Self::SealIncomplete => ERROR_CODE_SEAL_INCOMPLETE,
            Self::FrankingProofUnavailable => ERROR_CODE_FRANKING_PROOF_UNAVAILABLE,
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
            Self::DidProofRequired => ERROR_CODE_DID_PROOF_REQUIRED,
            Self::ReadReceiptComplianceFloorViolated => {
                ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED
            }
            Self::EphemeralKindNotPermitted => ERROR_CODE_EPHEMERAL_KIND_NOT_PERMITTED,
            Self::EphemeralTtlOutOfRange => ERROR_CODE_EPHEMERAL_TTL_OUT_OF_RANGE,
            Self::EphemeralChannelUnavailable => ERROR_CODE_EPHEMERAL_CHANNEL_UNAVAILABLE,
            Self::AuthorizedGrantRevoked => ERROR_CODE_AUTHORIZED_GRANT_REVOKED,
            Self::DeviceRecoverySskGenerationMismatch => {
                ERROR_CODE_DEVICE_RECOVERY_SSK_GENERATION_MISMATCH
            }
            Self::CursorRevoked => ERROR_CODE_CURSOR_REVOKED,
            Self::SeriesChainBroken => ERROR_CODE_SERIES_CHAIN_BROKEN,
            Self::SeriesSeqNotMonotonic => ERROR_CODE_SERIES_SEQ_NOT_MONOTONIC,
            Self::SeriesPredecessorNotFound => ERROR_CODE_SERIES_PREDECESSOR_NOT_FOUND,
            Self::RecoveryPolicyMismatch => ERROR_CODE_RECOVERY_POLICY_MISMATCH,
            Self::ShareCommitmentMismatch => ERROR_CODE_SHARE_COMMITMENT_MISMATCH,
            Self::BackupFrontierStale => ERROR_CODE_BACKUP_FRONTIER_STALE,
            Self::BackupPostResetStale => ERROR_CODE_BACKUP_POST_RESET_STALE,
            Self::RecoveryEvidenceUnbound => ERROR_CODE_RECOVERY_EVIDENCE_UNBOUND,
            Self::UnsupportedAeadProfile => ERROR_CODE_UNSUPPORTED_AEAD_PROFILE,
            Self::AttestationMissing => ERROR_CODE_ATTESTATION_MISSING,
            // ── R3 spec-sync (2026-05-27).
            Self::PairingRequestExpired => ERROR_CODE_PAIRING_REQUEST_EXPIRED,
            Self::ProofInvalid => ERROR_CODE_PROOF_INVALID,
            Self::VerificationMethodPrincipalMismatch => {
                ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH
            }
            Self::AgentPaused => ERROR_CODE_AGENT_PAUSED,
            Self::AgentDeactivated => ERROR_CODE_AGENT_DEACTIVATED,
            Self::ApprovalAlreadyConsumed => ERROR_CODE_APPROVAL_ALREADY_CONSUMED,
            Self::SidecarCreateDenied => ERROR_CODE_SIDECAR_CREATE_DENIED,
            Self::ActorKindReducerManaged => ERROR_CODE_ACTOR_KIND_REDUCER_MANAGED,
            Self::FocusMismatch => ERROR_CODE_FOCUS_MISMATCH,
            Self::UnknownFocusType => ERROR_CODE_UNKNOWN_FOCUS_TYPE,
            Self::TokenIssuerUnauthorised => ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED,
            Self::ParticipantBindingInvalid => ERROR_CODE_PARTICIPANT_BINDING_INVALID,
            Self::ParticipantIdentityUnrecognised => ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED,
            Self::SessionFocusAlreadyCommitted => ERROR_CODE_SESSION_FOCUS_ALREADY_COMMITTED,
            Self::E2eeKeySourceUnauthorised => ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED,
            Self::RecordingArtifactPipelineBypassed => {
                ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED
            }
            Self::FocusUnavailableForClient => ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT,
            Self::RecoveryWitnessRevokeLagging => ERROR_CODE_RECOVERY_WITNESS_REVOKE_LAGGING,
            Self::HandleHomographForbidden => ERROR_CODE_HANDLE_HOMOGRAPH_FORBIDDEN,
            // ── Registry backfill (2026-06-08).
            Self::PolicyDenied => ERROR_CODE_POLICY_DENIED,
            Self::CursorUnrecognized => ERROR_CODE_CURSOR_UNRECOGNIZED,
            Self::ActorSeqInvalid => ERROR_CODE_ACTOR_SEQ_INVALID,
            Self::StaleSealRef => ERROR_CODE_STALE_SEAL_REF,
            Self::SealRefUnknown => ERROR_CODE_SEAL_REF_UNKNOWN,
            Self::AudienceUnknown => ERROR_CODE_AUDIENCE_UNKNOWN,
            Self::BlobDigestMismatch => ERROR_CODE_BLOB_DIGEST_MISMATCH,
            Self::BlobExpired => ERROR_CODE_BLOB_EXPIRED,
            Self::BlobPresignInvalid => ERROR_CODE_BLOB_PRESIGN_INVALID,
            Self::BlobQuotaExceeded => ERROR_CODE_BLOB_QUOTA_EXCEEDED,
            Self::CursorInvalid => ERROR_CODE_CURSOR_INVALID,
            Self::DeviceUnknown => ERROR_CODE_DEVICE_UNKNOWN,
            Self::DidAlreadyExists => ERROR_CODE_DID_ALREADY_EXISTS,
            Self::DidNotFound => ERROR_CODE_DID_NOT_FOUND,
            Self::DidRevoked => ERROR_CODE_DID_REVOKED,
            Self::FrontierUnavailable => ERROR_CODE_FRONTIER_UNAVAILABLE,
            Self::HandleUnverified => ERROR_CODE_HANDLE_UNVERIFIED,
            Self::KeyReplay => ERROR_CODE_KEY_REPLAY,
            Self::KeypackageAlreadyConsumed => ERROR_CODE_KEYPACKAGE_ALREADY_CONSUMED,
            Self::KeypackageUnknown => ERROR_CODE_KEYPACKAGE_UNKNOWN,
            Self::OneTimeKeysExhausted => ERROR_CODE_ONE_TIME_KEYS_EXHAUSTED,
            Self::PolicyStale => ERROR_CODE_POLICY_STALE,
            Self::PolicyUnavailable => ERROR_CODE_POLICY_UNAVAILABLE,
            Self::PrincipalUnknown => ERROR_CODE_PRINCIPAL_UNKNOWN,
            Self::PushGatewayUnreachable => ERROR_CODE_PUSH_GATEWAY_UNREACHABLE,
            Self::PushPayloadTooLarge => ERROR_CODE_PUSH_PAYLOAD_TOO_LARGE,
            Self::PushTargetUnknown => ERROR_CODE_PUSH_TARGET_UNKNOWN,
            Self::PushTokenInvalid => ERROR_CODE_PUSH_TOKEN_INVALID,
            Self::PushTokenUnknown => ERROR_CODE_PUSH_TOKEN_UNKNOWN,
            Self::Quarantine => ERROR_CODE_QUARANTINE,
            Self::SnapshotAuthorityUnverified => ERROR_CODE_SNAPSHOT_AUTHORITY_UNVERIFIED,
            Self::ReducerProfileMismatch => ERROR_CODE_REDUCER_PROFILE_MISMATCH,
            Self::SnapshotUnavailable => ERROR_CODE_SNAPSHOT_UNAVAILABLE,
            Self::StreamDropped => ERROR_CODE_STREAM_DROPPED,
            Self::StreamResyncRequired => ERROR_CODE_STREAM_RESYNC_REQUIRED,
            Self::TooLarge => ERROR_CODE_TOO_LARGE,
            Self::UnsupportedDidMethod => ERROR_CODE_UNSUPPORTED_DID_METHOD,
            Self::UnsupportedMediaPolicy => ERROR_CODE_UNSUPPORTED_MEDIA_POLICY,
            Self::NotImplemented => ERROR_CODE_NOT_IMPLEMENTED,
            Self::ServiceUnavailable => ERROR_CODE_SERVICE_UNAVAILABLE,
            Self::UnsupportedJoinRule => ERROR_CODE_UNSUPPORTED_JOIN_RULE,
            Self::ContactNotAccepted => ERROR_CODE_CONTACT_NOT_ACCEPTED,
            Self::ContactConsentMissing => ERROR_CODE_CONTACT_CONSENT_MISSING,
            Self::ContactRequestNotPending => ERROR_CODE_CONTACT_REQUEST_NOT_PENDING,
            Self::ContactRequestExpired => ERROR_CODE_CONTACT_REQUEST_EXPIRED,
            Self::DeliveryBindingUnresolvable => ERROR_CODE_DELIVERY_BINDING_UNRESOLVABLE,
            Self::AppletRegistrationUnauthorized => ERROR_CODE_APPLET_REGISTRATION_UNAUTHORIZED,
            Self::AppletInstallPlanMismatch => ERROR_CODE_APPLET_INSTALL_PLAN_MISMATCH,
            Self::AppletE2eeJoinUnauthorized => ERROR_CODE_APPLET_E2EE_JOIN_UNAUTHORIZED,
            Self::AppletRevoked => ERROR_CODE_APPLET_REVOKED,
            Self::InvalidAvatarBlobRef => ERROR_CODE_INVALID_AVATAR_BLOB_REF,
            Self::UnsupportedProfilePatchPath => ERROR_CODE_UNSUPPORTED_PROFILE_PATCH_PATH,
            Self::SessionGrantNotFound => ERROR_CODE_SESSION_GRANT_NOT_FOUND,
            Self::SessionRevokeSelectorConflict => ERROR_CODE_SESSION_REVOKE_SELECTOR_CONFLICT,
            Self::ReviewerCapabilityRevoked => ERROR_CODE_REVIEWER_CAPABILITY_REVOKED,
            Self::NotMember => ERROR_CODE_NOT_MEMBER,
            Self::CallNotFound => ERROR_CODE_CALL_NOT_FOUND,
            Self::CallExpired => ERROR_CODE_CALL_EXPIRED,
            Self::CallAlreadyAnswered => ERROR_CODE_CALL_ALREADY_ANSWERED,
            Self::MediaPermissionDenied => ERROR_CODE_MEDIA_PERMISSION_DENIED,
            Self::IceConfigDenied => ERROR_CODE_ICE_CONFIG_DENIED,
            Self::SfuNotAllowed => ERROR_CODE_SFU_NOT_ALLOWED,
            Self::E2eeRequired => ERROR_CODE_E2EE_REQUIRED,
            Self::RecordingDenied => ERROR_CODE_RECORDING_DENIED,
            Self::MorphProfileWidensSchemaRef => ERROR_CODE_MORPH_PROFILE_WIDENS_SCHEMA_REF,
            Self::MorphTypeImmutable => ERROR_CODE_MORPH_TYPE_IMMUTABLE,
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

    #[test]
    fn every_known_error_code_has_http_status() {
        for code in KNOWN_ERROR_CODES {
            assert!(
                error_code_http_status(code).is_some(),
                "known error code {code:?} has no HTTP status mapping",
            );
        }
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

    /// Guard against the manual-mirror drift fixed in SDK-01-001: every
    /// hand-maintained `REASON_*` constant MUST exist as a declared identifier
    /// in the embedded `error-code-registry.json` snapshot. This pins the
    /// previously-missing `federation_trust_domain_mismatch` /
    /// `invalid_ack_token` and catches any future reason code added as a
    /// constant without a matching registry entry (or vice versa).
    ///
    /// The spec registry files identifiers across two arrays: canonical error
    /// codes under `codes` and finer sub-reasons under `reason_codes`. Several
    /// curated constants (the Reaction and direct-conversation sub-reasons) are
    /// registered by the spec under `codes`, so the cross-check resolves
    /// against the union of both arrays rather than `reason_codes` alone.
    #[test]
    fn reason_constants_are_declared_in_embedded_registry() {
        let registry = crate::schema::embedded_error_code_identifiers()
            .expect("embedded error-code-registry identifiers must load");

        // The two reason codes restored in SDK-01-001 must be present.
        assert!(
            registry.contains(REASON_FEDERATION_TRUST_DOMAIN_MISMATCH),
            "federation_trust_domain_mismatch missing from embedded registry",
        );
        assert!(
            registry.contains(REASON_INVALID_ACK_TOKEN),
            "invalid_ack_token missing from embedded registry",
        );

        // Every curated reason-code set MUST be a registry subset; a constant
        // absent from the snapshot signals manual-mirror drift.
        let curated = [
            KNOWN_REASON_CODES_ROUND_C45,
            KNOWN_REASON_CODES_CKP_0007,
            KNOWN_REASON_CODES_ROUND_C44,
            KNOWN_REASON_CODES_REACTION,
            KNOWN_REASON_CODES_CONTACT_DIRECT_CONVERSATION,
        ];
        for reason in curated.iter().flat_map(|set| set.iter()) {
            assert!(
                registry.contains(*reason),
                "REASON constant {reason:?} not present in embedded \
                 error-code-registry.json (codes or reason_codes)",
            );
        }
    }
}
