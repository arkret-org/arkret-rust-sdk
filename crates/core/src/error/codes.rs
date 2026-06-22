// This file is generated from cokret-spec/spec/v1/artifacts/registry/error-code-registry.json.
// Keep the top-level code set exact; reason_codes live in reasons.rs.

pub const ERROR_CODE_BAD_JSON: &str = "bad_json";
pub const ERROR_CODE_BAD_QUERY: &str = "bad_query";
pub const ERROR_CODE_SCHEMA_VIOLATION: &str = "schema_violation";
pub const ERROR_CODE_MISSING_PARAM: &str = "missing_param";
pub const ERROR_CODE_INVALID_PARAM: &str = "invalid_param";
pub const ERROR_CODE_INVALID_RESPONSE: &str = "invalid_response";
pub const ERROR_CODE_UNAUTHENTICATED: &str = "unauthenticated";
pub const ERROR_CODE_AUTH_EXPIRED: &str = "auth_expired";
pub const ERROR_CODE_GRANT_ALREADY_CONSUMED: &str = "grant_already_consumed";
pub const ERROR_CODE_SESSION_LOGGED_OUT: &str = "session_logged_out";
pub const ERROR_CODE_AUDIENCE_MISMATCH: &str = "audience_mismatch";
pub const ERROR_CODE_SOFT_LOGGED_OUT: &str = "soft_logged_out";
pub const ERROR_CODE_DID_PROOF_REQUIRED: &str = "did_proof_required";
pub const ERROR_CODE_INVALID_SIGNATURE: &str = "invalid_signature";
pub const ERROR_CODE_HTTP_SIGNATURE_REQUIRED: &str = "http_signature_required";
pub const ERROR_CODE_HTTP_SIGNATURE_INVALID: &str = "http_signature_invalid";
pub const ERROR_CODE_SIGNATURE_WINDOW_INVALID: &str = "signature_window_invalid";
pub const ERROR_CODE_DIRECTORY_NOT_AUTHORIZED: &str = "directory_not_authorized";
pub const ERROR_CODE_ACCEPT_POLICY_DENIED: &str = "accept_policy_denied";
pub const ERROR_CODE_SIGNATURE_INVALID: &str = "signature_invalid";
pub const ERROR_CODE_SIGNATURE_STALE: &str = "signature_stale";
pub const ERROR_CODE_SOURCE_REFS_UNVERIFIABLE: &str = "source_refs_unverifiable";
pub const ERROR_CODE_GOVERNANCE_KEY_INVALID: &str = "governance_key_invalid";
pub const ERROR_CODE_TTL_OUT_OF_RANGE: &str = "ttl_out_of_range";
pub const ERROR_CODE_TAKEDOWN_IN_FORCE: &str = "takedown_in_force";
pub const ERROR_CODE_POLICY_REVISION_ROLLBACK: &str = "policy_revision_rollback";
pub const ERROR_CODE_CAPABILITY_DENIED: &str = "capability_denied";
pub const ERROR_CODE_REALM_FROZEN: &str = "realm_frozen";
pub const ERROR_CODE_CLAIM_REQUIRED: &str = "claim_required";
pub const ERROR_CODE_POLICY_VIOLATION: &str = "policy_violation";
pub const ERROR_CODE_POLICY_DENIED: &str = "policy_denied";
pub const ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED: &str =
    "read_receipt_compliance_floor_violated";
pub const ERROR_CODE_EPHEMERAL_KIND_NOT_PERMITTED: &str = "ephemeral_kind_not_permitted";
pub const ERROR_CODE_EPHEMERAL_TTL_OUT_OF_RANGE: &str = "ephemeral_ttl_out_of_range";
pub const ERROR_CODE_EPHEMERAL_CHANNEL_UNAVAILABLE: &str = "ephemeral_channel_unavailable";
pub const ERROR_CODE_NOT_FOUND: &str = "not_found";
pub const ERROR_CODE_UNRECOGNIZED_ENDPOINT: &str = "unrecognized_endpoint";
pub const ERROR_CODE_METHOD_NOT_ALLOWED: &str = "method_not_allowed";
pub const ERROR_CODE_CONFLICT: &str = "conflict";
pub const ERROR_CODE_CAS_CONFLICT: &str = "cas_conflict";
pub const ERROR_CODE_CAUSAL_CONFLICT: &str = "causal_conflict";
pub const ERROR_CODE_DEPENDENCY_MISSING: &str = "dependency_missing";
pub const ERROR_CODE_DISCUSSION_TRACK_DISABLED: &str = "discussion_track_disabled";
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
pub const ERROR_CODE_STALE_PEER: &str = "stale_peer";
pub const ERROR_CODE_AUTHORIZED_GRANT_REVOKED: &str = "authorized_grant_revoked";
pub const ERROR_CODE_DEVICE_RECOVERY_SSK_GENERATION_MISMATCH: &str =
    "device_recovery_ssk_generation_mismatch";
pub const ERROR_CODE_CURSOR_EXPIRED: &str = "cursor_expired";
pub const ERROR_CODE_CURSOR_INTEGRITY_INVALID: &str = "cursor_integrity_invalid";
pub const ERROR_CODE_CURSOR_REVOKED: &str = "cursor_revoked";
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
pub const ERROR_CODE_DEVICE_ENROLLMENT_AUTHORITY_NOT_DESIGNATED: &str =
    "device_enrollment_authority_not_designated";
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
pub const ERROR_CODE_SNAPSHOT_UNAVAILABLE: &str = "snapshot_unavailable";
pub const ERROR_CODE_STREAM_DROPPED: &str = "stream_dropped";
pub const ERROR_CODE_STREAM_RESYNC_REQUIRED: &str = "stream_resync_required";
pub const ERROR_CODE_TOO_LARGE: &str = "too_large";
pub const ERROR_CODE_UNSUPPORTED_DID_METHOD: &str = "unsupported_did_method";
pub const ERROR_CODE_UNSUPPORTED_MEDIA_POLICY: &str = "unsupported_media_policy";
pub const ERROR_CODE_UNSUPPORTED_FEATURE: &str = "unsupported_feature";
pub const ERROR_CODE_UNSUPPORTED_EVENT_KIND: &str = "unsupported_event_kind";
pub const ERROR_CODE_NOT_IMPLEMENTED: &str = "not_implemented";
pub const ERROR_CODE_PROJECTION_INCOMPLETE: &str = "projection_incomplete";
pub const ERROR_CODE_INTERNAL_ERROR: &str = "internal_error";
pub const ERROR_CODE_TEMPORARILY_UNAVAILABLE: &str = "temporarily_unavailable";
pub const ERROR_CODE_SERVICE_UNAVAILABLE: &str = "service_unavailable";
pub const ERROR_CODE_POLICY_COMBINATION_INVALID: &str = "policy_combination_invalid";
pub const ERROR_CODE_HISTORY_SHARING_POLICY_MISSING: &str = "history_sharing_policy_missing";
pub const ERROR_CODE_HISTORY_NOT_VISIBLE: &str = "history_not_visible";
pub const ERROR_CODE_PREVIEW_POLICY_DENIED: &str = "preview_policy_denied";
pub const ERROR_CODE_NOTARY_RECOVERY_MISSING: &str = "notary_recovery_missing";
pub const ERROR_CODE_UNSUPPORTED_LATTICE_TYPE: &str = "unsupported_lattice_type";
pub const ERROR_CODE_PROFILE_UNSUPPORTED: &str = "profile_unsupported";
pub const ERROR_CODE_UNSUPPORTED_JOIN_RULE: &str = "unsupported_join_rule";
pub const ERROR_CODE_FAILED_PRECONDITION: &str = "failed_precondition";
pub const ERROR_CODE_CONTACT_NOT_ACCEPTED: &str = "contact_not_accepted";
pub const ERROR_CODE_CONTACT_CONSENT_MISSING: &str = "contact_consent_missing";
pub const ERROR_CODE_PEER_UNRESOLVABLE: &str = "peer_unresolvable";
pub const ERROR_CODE_CONTACT_REQUEST_NOT_PENDING: &str = "contact_request_not_pending";
pub const ERROR_CODE_CONTACT_REQUEST_EXPIRED: &str = "contact_request_expired";
pub const ERROR_CODE_UNSUPPORTED_DIGEST_ALGORITHM: &str = "unsupported_digest_algorithm";
pub const ERROR_CODE_UNSUPPORTED_SIGNATURE_ALG: &str = "unsupported_signature_alg";
pub const ERROR_CODE_UNSUPPORTED_HPKE_SUITE: &str = "unsupported_hpke_suite";
pub const ERROR_CODE_SEAL_INCOMPLETE: &str = "seal_incomplete";
pub const ERROR_CODE_FRANKING_PROOF_UNAVAILABLE: &str = "franking_proof_unavailable";
pub const ERROR_CODE_TURN_CREDENTIAL_EXPIRED: &str = "turn_credential_expired";
pub const ERROR_CODE_DELIVERY_BINDING_STALE: &str = "delivery_binding_stale";
pub const ERROR_CODE_DELIVERY_BINDING_HANDED_OVER: &str = "delivery_binding_handed_over";
pub const ERROR_CODE_DELIVERY_BINDING_UNRESOLVABLE: &str = "delivery_binding_unresolvable";
pub const ERROR_CODE_HISTORICAL_ONLY: &str = "historical_only";
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
pub const ERROR_CODE_APPROVAL_ALREADY_CONSUMED: &str = "approval_already_consumed";
pub const ERROR_CODE_FOCUS_MISMATCH: &str = "focus_mismatch";
pub const ERROR_CODE_UNKNOWN_FOCUS_TYPE: &str = "unknown_focus_type";
pub const ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED: &str = "token_issuer_unauthorised";
pub const ERROR_CODE_PARTICIPANT_BINDING_INVALID: &str = "participant_binding_invalid";
pub const ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED: &str = "participant_identity_unrecognised";
pub const ERROR_CODE_SESSION_FOCUS_ALREADY_COMMITTED: &str = "session_focus_already_committed";
pub const ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED: &str = "e2ee_key_source_unauthorised";
pub const ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED: &str =
    "recording_artifact_pipeline_bypassed";
pub const ERROR_CODE_TRANSCRIPTION_DENIED: &str = "transcription_denied";
pub const ERROR_CODE_TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED: &str =
    "transcription_artifact_pipeline_bypassed";
pub const ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT: &str = "focus_unavailable_for_client";
pub const ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH: &str =
    "verification_method_principal_mismatch";
pub const ERROR_CODE_PAIRING_REQUEST_EXPIRED: &str = "pairing_request_expired";
pub const ERROR_CODE_PROOF_INVALID: &str = "proof_invalid";
pub const ERROR_CODE_AGENT_PAUSED: &str = "agent_paused";
pub const ERROR_CODE_AGENT_DEACTIVATED: &str = "agent_deactivated";
pub const ERROR_CODE_SIDECAR_CREATE_DENIED: &str = "sidecar_create_denied";
pub const ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING: &str = "relaxed_window_exceeds_ceiling";
pub const ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE: &str =
    "e2ee_relaxed_disallowed_in_compliance_profile";
pub const ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED: &str = "cross_domain_replay_rejected";
pub const ERROR_CODE_RESET_EVENT_ID_MISMATCH: &str = "reset_event_id_mismatch";
pub const ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT: &str = "appeal_overturn_missing_lift";
pub const ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN: &str = "appeal_self_review_forbidden";
pub const ERROR_CODE_LEGAL_HOLD_ACTIVE: &str = "legal_hold_active";
pub const ERROR_CODE_BLOB_REDACTED: &str = "blob_redacted";
pub const ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED: &str =
    "media_plaintext_service_not_authorised";
pub const ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE: &str = "mls_governance_binding_stale";
pub const ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP: &str = "late_recovery_rejected_membership";
pub const ERROR_CODE_SERIES_CHAIN_BROKEN: &str = "series_chain_broken";
pub const ERROR_CODE_SERIES_SEQ_NOT_MONOTONIC: &str = "series_seq_not_monotonic";
pub const ERROR_CODE_SERIES_PREDECESSOR_NOT_FOUND: &str = "series_predecessor_not_found";
pub const ERROR_CODE_BACKUP_POST_RESET_STALE: &str = "backup_post_reset_stale";
pub const ERROR_CODE_RECOVERY_EVIDENCE_UNBOUND: &str = "recovery_evidence_unbound";
pub const ERROR_CODE_MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH: &str =
    "member_identity_replacement_digest_mismatch";
pub const ERROR_CODE_MEMBER_IDENTITY_STATE_MISMATCH: &str = "member_identity_state_mismatch";
pub const ERROR_CODE_MEMBER_IDENTITY_PROOF_INVALID: &str = "member_identity_proof_invalid";
pub const ERROR_CODE_MEMBER_IDENTITY_UNKNOWN_SEGMENT: &str = "member_identity_unknown_segment";

/// Canonical top-level error codes from error-code-registry.json, in registry order.
pub const KNOWN_ERROR_CODES: &[&str] = &[
    ERROR_CODE_BAD_JSON,
    ERROR_CODE_BAD_QUERY,
    ERROR_CODE_SCHEMA_VIOLATION,
    ERROR_CODE_MISSING_PARAM,
    ERROR_CODE_INVALID_PARAM,
    ERROR_CODE_INVALID_RESPONSE,
    ERROR_CODE_UNAUTHENTICATED,
    ERROR_CODE_AUTH_EXPIRED,
    ERROR_CODE_GRANT_ALREADY_CONSUMED,
    ERROR_CODE_SESSION_LOGGED_OUT,
    ERROR_CODE_AUDIENCE_MISMATCH,
    ERROR_CODE_SOFT_LOGGED_OUT,
    ERROR_CODE_DID_PROOF_REQUIRED,
    ERROR_CODE_INVALID_SIGNATURE,
    ERROR_CODE_HTTP_SIGNATURE_REQUIRED,
    ERROR_CODE_HTTP_SIGNATURE_INVALID,
    ERROR_CODE_SIGNATURE_WINDOW_INVALID,
    ERROR_CODE_DIRECTORY_NOT_AUTHORIZED,
    ERROR_CODE_ACCEPT_POLICY_DENIED,
    ERROR_CODE_SIGNATURE_INVALID,
    ERROR_CODE_SIGNATURE_STALE,
    ERROR_CODE_SOURCE_REFS_UNVERIFIABLE,
    ERROR_CODE_GOVERNANCE_KEY_INVALID,
    ERROR_CODE_TTL_OUT_OF_RANGE,
    ERROR_CODE_TAKEDOWN_IN_FORCE,
    ERROR_CODE_POLICY_REVISION_ROLLBACK,
    ERROR_CODE_CAPABILITY_DENIED,
    ERROR_CODE_REALM_FROZEN,
    ERROR_CODE_CLAIM_REQUIRED,
    ERROR_CODE_POLICY_VIOLATION,
    ERROR_CODE_POLICY_DENIED,
    ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED,
    ERROR_CODE_EPHEMERAL_KIND_NOT_PERMITTED,
    ERROR_CODE_EPHEMERAL_TTL_OUT_OF_RANGE,
    ERROR_CODE_EPHEMERAL_CHANNEL_UNAVAILABLE,
    ERROR_CODE_NOT_FOUND,
    ERROR_CODE_UNRECOGNIZED_ENDPOINT,
    ERROR_CODE_METHOD_NOT_ALLOWED,
    ERROR_CODE_CONFLICT,
    ERROR_CODE_CAS_CONFLICT,
    ERROR_CODE_CAUSAL_CONFLICT,
    ERROR_CODE_DEPENDENCY_MISSING,
    ERROR_CODE_DISCUSSION_TRACK_DISABLED,
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
    ERROR_CODE_STALE_PEER,
    ERROR_CODE_AUTHORIZED_GRANT_REVOKED,
    ERROR_CODE_DEVICE_RECOVERY_SSK_GENERATION_MISMATCH,
    ERROR_CODE_CURSOR_EXPIRED,
    ERROR_CODE_CURSOR_INTEGRITY_INVALID,
    ERROR_CODE_CURSOR_REVOKED,
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
    ERROR_CODE_DEVICE_ENROLLMENT_AUTHORITY_NOT_DESIGNATED,
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
    ERROR_CODE_SNAPSHOT_UNAVAILABLE,
    ERROR_CODE_STREAM_DROPPED,
    ERROR_CODE_STREAM_RESYNC_REQUIRED,
    ERROR_CODE_TOO_LARGE,
    ERROR_CODE_UNSUPPORTED_DID_METHOD,
    ERROR_CODE_UNSUPPORTED_MEDIA_POLICY,
    ERROR_CODE_UNSUPPORTED_FEATURE,
    ERROR_CODE_UNSUPPORTED_EVENT_KIND,
    ERROR_CODE_NOT_IMPLEMENTED,
    ERROR_CODE_PROJECTION_INCOMPLETE,
    ERROR_CODE_INTERNAL_ERROR,
    ERROR_CODE_TEMPORARILY_UNAVAILABLE,
    ERROR_CODE_SERVICE_UNAVAILABLE,
    ERROR_CODE_POLICY_COMBINATION_INVALID,
    ERROR_CODE_HISTORY_SHARING_POLICY_MISSING,
    ERROR_CODE_HISTORY_NOT_VISIBLE,
    ERROR_CODE_PREVIEW_POLICY_DENIED,
    ERROR_CODE_NOTARY_RECOVERY_MISSING,
    ERROR_CODE_UNSUPPORTED_LATTICE_TYPE,
    ERROR_CODE_PROFILE_UNSUPPORTED,
    ERROR_CODE_UNSUPPORTED_JOIN_RULE,
    ERROR_CODE_FAILED_PRECONDITION,
    ERROR_CODE_CONTACT_NOT_ACCEPTED,
    ERROR_CODE_CONTACT_CONSENT_MISSING,
    ERROR_CODE_PEER_UNRESOLVABLE,
    ERROR_CODE_CONTACT_REQUEST_NOT_PENDING,
    ERROR_CODE_CONTACT_REQUEST_EXPIRED,
    ERROR_CODE_UNSUPPORTED_DIGEST_ALGORITHM,
    ERROR_CODE_UNSUPPORTED_SIGNATURE_ALG,
    ERROR_CODE_UNSUPPORTED_HPKE_SUITE,
    ERROR_CODE_SEAL_INCOMPLETE,
    ERROR_CODE_FRANKING_PROOF_UNAVAILABLE,
    ERROR_CODE_TURN_CREDENTIAL_EXPIRED,
    ERROR_CODE_DELIVERY_BINDING_STALE,
    ERROR_CODE_DELIVERY_BINDING_HANDED_OVER,
    ERROR_CODE_DELIVERY_BINDING_UNRESOLVABLE,
    ERROR_CODE_HISTORICAL_ONLY,
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
