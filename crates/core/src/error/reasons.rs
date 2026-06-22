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
pub const REASON_PROOF_BINDING_MISSING: &str = "proof_binding_missing";
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
pub const REASON_ERASURE_PENDING_IS_TERMINAL: &str = "erasure_pending_is_terminal";
pub const REASON_ACCOUNT_STATUS_TRANSITION_INVALID: &str = "account_status_transition_invalid";
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
pub const REASON_RELATION_CONFLICT_FANOUT_EXCEEDED: &str = "relation_conflict_fanout_exceeded";
pub const REASON_RELATION_KIND_WATCHES_DERIVED: &str = "relation_kind_watches_derived";
pub const REASON_RELATION_KIND_CONTAINS_DERIVED: &str = "relation_kind_contains_derived";
pub const REASON_CROSS_REALM_STRUCTURAL_RELATION: &str = "cross_realm_structural_relation";

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
pub const REASON_AEAD_NONCE_SENDER_DOMAIN_COLLISION: &str = "aead_nonce_sender_domain_collision";

// Accountability grant verification (zh/models/actor.md §3.3.1).
pub const REASON_ACCOUNTABILITY_GRANT_MISSING: &str = "accountability_grant_missing";

// MLS Welcome envelope replay binding (zh/crypto-media/encryption-and-audit.md §2.6).
pub const REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH: &str =
    "keypackage_welcome_envelope_mismatch";

// Capability delegation safety (zh/authz/capabilities.md §10).
pub const REASON_GRANT_EXCEEDS_ISSUER_AUTHORITY: &str = "grant_exceeds_issuer_authority";
pub const REASON_GRANT_REVOKED_UPSTREAM: &str = "grant_revoked_upstream";
pub const REASON_DELEGATION_CYCLE: &str = "delegation_cycle";
pub const REASON_DELEGATION_EXPIRY_WIDENING: &str = "delegation_expiry_widening";

// Event-auth / governance fail-closed reasons.
pub const REASON_PLANE_CROSS_WRITE: &str = "plane_cross_write";
pub const REASON_MODERATION_STATE_CONFLICT: &str = "moderation_state_conflict";
pub const REASON_DELIVERY_BINDING_INVALID: &str = "delivery_binding_invalid";

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
    REASON_ERASURE_PENDING_IS_TERMINAL,
    REASON_ACCOUNT_STATUS_TRANSITION_INVALID,
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
    REASON_PROOF_BINDING_MISSING,
    REASON_APPROVAL_NONCE_REUSED,
    REASON_EXECUTED_BY_MISSING,
    REASON_ACTOR_KIND_REDUCER_MANAGED,
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

/// Authz / governance reason codes mirrored from the registry snapshot.
pub const KNOWN_REASON_CODES_AUTHZ_GOVERNANCE: &[&str] = &[
    REASON_GRANT_EXCEEDS_ISSUER_AUTHORITY,
    REASON_GRANT_REVOKED_UPSTREAM,
    REASON_MODERATION_STATE_CONFLICT,
    REASON_DELIVERY_BINDING_INVALID,
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
/// `schema_violation` sub-reason: actor-side submit payload supplied the
/// reducer-managed Envelope runtime classifier directly.
pub const REASON_ACTOR_KIND_REDUCER_MANAGED: &str = "actor_kind_reducer_managed";
/// `failed_precondition` sub-reason: an inner Realm / Circle / Strand
/// agent-participation ceiling would enable a bit disabled by its parent.
pub const REASON_AGENT_PARTICIPATION_CEILING_WIDEN: &str = "agent_participation_ceiling_widen";
/// `failed_precondition` sub-reason: a controller selection enables a
/// participation bit disabled by the effective governance ceiling.
pub const REASON_AGENT_PARTICIPATION_EXCEEDS_CEILING: &str = "agent_participation_exceeds_ceiling";
/// `failed_precondition` / authorization sub-reason: a native personal
/// agent action is denied by effective participation policy.
pub const REASON_AGENT_PARTICIPATION_DENIED: &str = "agent_participation_denied";
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

/// Reason codes for the agent participation policy profile.
pub const KNOWN_REASON_CODES_AGENT_PARTICIPATION: &[&str] = &[
    REASON_AGENT_PARTICIPATION_CEILING_WIDEN,
    REASON_AGENT_PARTICIPATION_EXCEEDS_CEILING,
    REASON_AGENT_PARTICIPATION_DENIED,
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
pub const REASON_PEER_UNRESOLVABLE: &str = "peer_unresolvable";
pub const REASON_KEYPACKAGE_UNKNOWN: &str = "keypackage_unknown";
pub const KNOWN_REASON_CODES_CONTACT_DIRECT_CONVERSATION: &[&str] = &[
    REASON_CONTACT_NOT_ACCEPTED,
    REASON_CONTACT_CONSENT_MISSING,
    REASON_PEER_UNRESOLVABLE,
    REASON_KEYPACKAGE_UNKNOWN,
];

// MLS / media reason codes from error-code-registry.json#reason_codes.
pub const REASON_REDUCER_PROFILE_MISMATCH: &str = "reducer_profile_mismatch";
pub const REASON_MLS_GOVERNANCE_BINDING_STALE: &str = "mls_governance_binding_stale";
pub const REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED: &str =
    "recording_artifact_pipeline_bypassed";
pub const REASON_RECORDING_CONSENT_REQUIRED: &str = "recording_consent_required";
pub const REASON_RELAXED_WINDOW_EXCEEDS_CEILING: &str = "relaxed_window_exceeds_ceiling";
pub const REASON_LEGAL_HOLD_ACTIVE: &str = "legal_hold_active";
pub const REASON_TOKEN_ISSUER_UNAUTHORISED: &str = "token_issuer_unauthorised";
pub const REASON_E2EE_KEY_SOURCE_UNAUTHORISED: &str = "e2ee_key_source_unauthorised";

// Late key recovery transition guards.
pub const REASON_LATE_RECOVERY_REJECTED_MEMBERSHIP: &str = "late_recovery_rejected_membership";
pub const REASON_LATE_RECOVERY_SHARE_NOT_AUTHORIZED: &str = "late_recovery_share_not_authorized";
pub const REASON_LATE_RECOVERY_REJECTED_EXPIRED: &str = "late_recovery_rejected_expired";
pub const KNOWN_REASON_CODES_LATE_RECOVERY: &[&str] = &[
    REASON_LATE_RECOVERY_REJECTED_MEMBERSHIP,
    REASON_LATE_RECOVERY_SHARE_NOT_AUTHORIZED,
    REASON_LATE_RECOVERY_REJECTED_EXPIRED,
];

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
