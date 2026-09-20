//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/error-code-registry.json; version=2026-09-21.3;
//! sha256=be9eb43fcecb7fe103c3a383eaada503c90aa8b31a415d02f42611ba091f2103
//! Entries: reason_codes=308, reserved_not_emitted=73

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReasonCode {
    AccountBindingPrincipalMismatch,
    AccountStatusBindingRollback,
    AccountStatusRecordFork,
    AccountStatusRecordStale,
    AccountStatusTransitionInvalid,
    AccountabilityGrantMissing,
    AeadNonceCounterReplay,
    AeadNonceDerivationInvalid,
    AgentDeactivated,
    AgentGrantExceedsRequestedScope,
    AgentKeyAuthorizationExpired,
    AgentKeyScopeReauthorizationRequired,
    AgentParticipationCeilingUnresolved,
    AgentParticipationCeilingWiden,
    AgentPaused,
    AgentPcrGenesisDeclarationConflict,
    AgentPcrGenesisDeclarationMissing,
    AgentProvisionScopeMigrationRequired,
    AgentProvisioningAlreadyDeclared,
    AgentReplyNotPermitted,
    AgentRequestedScopeCommitmentInvalid,
    AgentRuntimeRequestConflict,
    AgentSessionScopeRefreshRequired,
    AppletManagedActorProvisionInvalid,
    AppletManagedPcrGenesisInvalid,
    AppletManagedPcrGenesisRequiresClosedAggregate,
    AppletNamespaceMismatch,
    ApprovalAlreadyConsumed,
    ApprovalNonceReused,
    ApprovalRequired,
    AudienceMismatch,
    AuthorityCycle,
    AuthorityExpiryWidening,
    BackendUnavailable,
    BackupRevisionStale,
    BlobRedacted,
    CalendarActivationMismatch,
    CalendarEventCancelled,
    CalendarScheduleUnavailable,
    CalendarTzdbMismatch,
    CallModerationUnauthorised,
    CallParticipantRemoved,
    CallStateTerminal,
    CallStateTransitionInvalid,
    CallSummaryInvalid,
    CborBoundsInvalid,
    CborNotDeterministic,
    ChallengeExpired,
    ChallengeFailed,
    ChallengeProofInvalid,
    CircleCountExceeded,
    CircleMemberMustBeRealmMember,
    CircleNotActive,
    CircleRealmMismatch,
    ClaimInvalid,
    ConsentRevoked,
    ConsentWithdrawn,
    CrossDomainReplayRejected,
    CrossRealmStructuralRelation,
    CursorExpired,
    CursorIntegrityInvalid,
    CursorRevoked,
    CursorUnrecognized,
    DecryptionPending,
    DependencyMissing,
    DeviceDirectoryUnavailable,
    DeviceGenerationFenced,
    DeviceMessageIdConflict,
    DeviceReanchorAuthorizeMismatch,
    DeviceResultUnavailable,
    DirectConversationBindingInvalid,
    DirectConversationFoundingUnitInvalid,
    DirectConversationInviteForbidden,
    DirectConversationMemberCountInvalid,
    DirectConversationPairMaterializationConflict,
    DirectConversationParticipantAuthorityDenied,
    DirectConversationRootMaskViolation,
    DirectConversationSlotAlreadyCommitted,
    DirectConversationSpaceForbidden,
    DirectConversationTerminalForbidden,
    DirectConversationThirdPartyMemberForbidden,
    DirectDownloadDisallowedPresignForbidden,
    DuplicateConflict,
    E2eeKeySourceUnauthorised,
    EffectiveScopeReducerManaged,
    EgressPolicyDenied,
    EpochUpdateRequired,
    ErasurePendingIsTerminal,
    ErasureReceiptAuthorityInvalid,
    ErasureReceiptProofInvalid,
    ErasureReceiptStubBindingMismatch,
    ErasureReceiptStubDigestMismatch,
    ErasureRequestAlreadyPending,
    EventIdDigestMismatch,
    EvidenceRecipientMismatch,
    ExpiredInviteToken,
    ExternalRateLimited,
    FocusMismatch,
    FocusUnavailableForClient,
    FoundingDeviceCommitmentMismatch,
    GateCheckFailed,
    GovernanceBindingMismatch,
    GrantExceedsIssuerAuthority,
    GrantRelinquishNotSubject,
    GrantValidityWindowEmpty,
    HandleHomographForbidden,
    Harassment,
    HateSpeech,
    HumanApprovalRequired,
    IdentityCreationAlreadyAccepted,
    IdentityCreationChallengeAlreadyConsumed,
    IdentityCreationChallengeExpired,
    IdentityCreationLeaseFenced,
    IdentityLinkNoLongerVisible,
    IdentityLinkPolicyTightened,
    IdentityMethodEvidenceInvalid,
    Illegal,
    InitialSessionRequestMismatch,
    IntegrityFailed,
    InternalError,
    InvalidAckToken,
    InvalidCanonicalJson,
    InvalidCursor,
    InvalidEncoding,
    InvalidatedByRateLimit,
    InviteAlreadyTerminal,
    InviteDirectedInviteeMismatch,
    InviteKindRequiresRevoke,
    InviteLiveTargetOccupied,
    InviteOobEntropyTooLow,
    JoinPolicyDuplicateGateId,
    JoinRulePolicyMismatch,
    KeyBackupWireSchemaRequired,
    KeypackageClaimRateLimited,
    KeypackageExpired,
    KeypackageRotated,
    KeypackageWelcomeEnvelopeMismatch,
    LastResortNotSupported,
    LastResortRealmAffinityViolation,
    LastResortRotationRequired,
    LegalHoldActive,
    MediaNegotiationTimeout,
    MediaPlaintextServiceNotAuthorised,
    MediaPlaintextWarningRequired,
    MediaServiceBindingUncovered,
    MediaServiceFociRequired,
    MediaSourceUnavailable,
    MemberIdentityProofInvalid,
    MemberIdentityReplacementDigestMismatch,
    MemberIdentityStateMismatch,
    MemberIdentityUnknownSegment,
    MimiGovernanceBindingMismatch,
    MimiGovernanceBindingMissing,
    MimiPolicyRevisionMismatch,
    MimiRoomBindingStatusTransitionInvalid,
    MimiRoomStateIncompatible,
    MinimalDisclosureViolation,
    Misinformation,
    MlsActivationIrreversible,
    MlsActivationRequired,
    MlsGovernanceBindingStale,
    ModerationControlSplit,
    ModerationStateConflict,
    MorphAlreadyTerminal,
    MorphNotActive,
    MorphNotArchived,
    Nsfw,
    ObjectIdNotEventDerived,
    Ok,
    OperatorRejected,
    Other,
    PairingExpired,
    PairingRequestExpired,
    ParticipantBindingInvalid,
    ParticipantIdUnrecognised,
    PatchPathInvalid,
    PatchPathReducerManaged,
    PatchUnsetRedactableField,
    PcrGenesisConflict,
    PcrGenesisUnitInvalid,
    PermissionDenied,
    PolicyDenied,
    PolicyRevisionGap,
    PolicyRevoked,
    PresignExpired,
    PresignInvalid,
    PresignScopeMismatch,
    PrincipalControlEventKindForbidden,
    PrincipalDeactivated,
    PrivateAttachment,
    PrivateViewRequiresAccountData,
    ProfileUnavailable,
    ProjectionIncomplete,
    ProofFailed,
    ProofInvalid,
    PushGatewayUnreachable,
    PushPayloadTooLarge,
    PushRouteLimitExceeded,
    PushTargetUnknown,
    PushTokenInvalid,
    PushTokenUnknown,
    Quarantined,
    QueueFull,
    RateLimited,
    RealmAliasAuthorityMismatch,
    RealmAuthorityRootConflict,
    RealmIdNotEventDerived,
    RealmLinkInvalidTransition,
    RealmLinkSelfReference,
    RealmOrganizationAuthorizationInvalid,
    RealmOrganizationDelegationMissing,
    RealmOrganizationExpired,
    RealmOrganizationRealmAcceptanceMissing,
    RealmOrganizationScopeMissing,
    RecordingArtifactPipelineBypassed,
    RecordingConsentRequired,
    RecordingStateTransitionInvalid,
    RecoveryEvidenceUnbound,
    RecoveryPolicyGenesisNotV1,
    RecoveryPolicyMismatch,
    RecoveryPolicySupersedesInvalid,
    RecoveryPolicyVersionNotMonotonic,
    RecoveryPrincipalIsolation,
    RecoveryProofKindUnknown,
    RecoveryReceiptCompletedAtAfterCommit,
    RecoverySessionChallengeMismatch,
    ReducerProjectionFailed,
    RelationKindContainsDerived,
    RelationKindWatchesDerived,
    ResolutionHistoryAncestorUnknown,
    RevocationFreshnessUnknown,
    RiskPolicy,
    RoutingUnlinkabilityPresignForbidden,
    RsvpBasisMalformed,
    RsvpOccurrenceNotCanonical,
    RuntimeKeyMissing,
    ScopeRebindForbidden,
    ScopeRefMismatch,
    SegmentBoundsInvalid,
    SegmentReplay,
    SegmentSequenceInvalid,
    SegmentStreamTruncated,
    SelectorActorWildcardForbidden,
    SendFailed,
    SeriesChainBroken,
    SeriesPredecessorNotFound,
    SeriesSeqNotMonotonic,
    ServiceKeyRevoked,
    ServiceNotPlaintextVisible,
    ServicePrerotationInvalid,
    ServiceRouteFork,
    SessionFocusAlreadyCommitted,
    SessionFocusNoSplitBrain,
    SessionMissing,
    SidecarCreateDenied,
    SignalPlaintextForbidden,
    SpaceAlreadyTerminal,
    SpaceHasLiveDependents,
    SpaceNotActive,
    SpaceNotArchived,
    SpaceParentMismatch,
    SpaceParentUnreadable,
    SpaceRealmMismatch,
    Spam,
    StateMismatch,
    StorageFailed,
    StrandAlreadyTerminal,
    StrandNotActive,
    StrandNotArchived,
    StreamTailMissing,
    StructureDepthExceeded,
    Superseded,
    SupersededByRepairing,
    TestSigningMaterialDenied,
    ThirdPartyInviteAcceptanceMissing,
    ThirdPartyInviteAcceptanceStale,
    ThirdPartyInviteMaterialMismatch,
    ThirdPartyInviteProvisioningAlreadyBound,
    ThirdPartyInviteProvisioningExpired,
    ThirdPartyInviteTokenInQuery,
    TokenIssuerUnauthorised,
    TranscriptionArtifactPipelineBypassed,
    TranscriptionDenied,
    UnknownEventKind,
    UnknownField,
    UnknownFocusType,
    UnresolvedBasis,
    UnsupportedAeadProfile,
    UnsupportedAttachmentScheme,
    UnsupportedCiphersuite,
    UnsupportedDigestAlgorithm,
    UnsupportedEventKind,
    UnsupportedFeature,
    UnsupportedHpkeSuite,
    UnsupportedProfile,
    UnsupportedProtocolVersion,
    UnsupportedSignatureAlg,
    UntrustedBackupSignature,
    VerificationMethodPrincipalMismatch,
    ViewAlreadyTerminal,
    WebvhWitnessControllingOrganizationUnverified,
    WebvhWitnessEvidenceStale,
    WebvhWitnessParameterMalformed,
    WebvhWitnessProofInvalid,
    WebvhWitnessProofsUnavailable,
    WebvhWitnessThresholdNotMet,
    WelcomeCapabilityMismatch,
    WitnessDisagreement,
    Unknown(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReasonCodeDescriptor {
    pub code: &'static str,
    pub applies_to: &'static [&'static str],
    pub description: &'static str,
}

impl ReasonCode {
    pub const ACCOUNT_BINDING_PRINCIPAL_MISMATCH: &'static str =
        "account_binding_principal_mismatch";
    pub const ACCOUNT_STATUS_BINDING_ROLLBACK: &'static str = "account_status_binding_rollback";
    pub const ACCOUNT_STATUS_RECORD_FORK: &'static str = "account_status_record_fork";
    pub const ACCOUNT_STATUS_RECORD_STALE: &'static str = "account_status_record_stale";
    pub const ACCOUNT_STATUS_TRANSITION_INVALID: &'static str = "account_status_transition_invalid";
    pub const ACCOUNTABILITY_GRANT_MISSING: &'static str = "accountability_grant_missing";
    pub const AEAD_NONCE_COUNTER_REPLAY: &'static str = "aead_nonce_counter_replay";
    pub const AEAD_NONCE_DERIVATION_INVALID: &'static str = "aead_nonce_derivation_invalid";
    pub const AGENT_DEACTIVATED: &'static str = "agent_deactivated";
    pub const AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE: &'static str =
        "agent_grant_exceeds_requested_scope";
    pub const AGENT_KEY_AUTHORIZATION_EXPIRED: &'static str = "agent_key_authorization_expired";
    pub const AGENT_KEY_SCOPE_REAUTHORIZATION_REQUIRED: &'static str =
        "agent_key_scope_reauthorization_required";
    pub const AGENT_PARTICIPATION_CEILING_UNRESOLVED: &'static str =
        "agent_participation_ceiling_unresolved";
    pub const AGENT_PARTICIPATION_CEILING_WIDEN: &'static str = "agent_participation_ceiling_widen";
    pub const AGENT_PAUSED: &'static str = "agent_paused";
    pub const AGENT_PCR_GENESIS_DECLARATION_CONFLICT: &'static str =
        "agent_pcr_genesis_declaration_conflict";
    pub const AGENT_PCR_GENESIS_DECLARATION_MISSING: &'static str =
        "agent_pcr_genesis_declaration_missing";
    pub const AGENT_PROVISION_SCOPE_MIGRATION_REQUIRED: &'static str =
        "agent_provision_scope_migration_required";
    pub const AGENT_PROVISIONING_ALREADY_DECLARED: &'static str =
        "agent_provisioning_already_declared";
    pub const AGENT_REPLY_NOT_PERMITTED: &'static str = "agent_reply_not_permitted";
    pub const AGENT_REQUESTED_SCOPE_COMMITMENT_INVALID: &'static str =
        "agent_requested_scope_commitment_invalid";
    pub const AGENT_RUNTIME_REQUEST_CONFLICT: &'static str = "agent_runtime_request_conflict";
    pub const AGENT_SESSION_SCOPE_REFRESH_REQUIRED: &'static str =
        "agent_session_scope_refresh_required";
    pub const APPLET_MANAGED_ACTOR_PROVISION_INVALID: &'static str =
        "applet_managed_actor_provision_invalid";
    pub const APPLET_MANAGED_PCR_GENESIS_INVALID: &'static str =
        "applet_managed_pcr_genesis_invalid";
    pub const APPLET_MANAGED_PCR_GENESIS_REQUIRES_CLOSED_AGGREGATE: &'static str =
        "applet_managed_pcr_genesis_requires_closed_aggregate";
    pub const APPLET_NAMESPACE_MISMATCH: &'static str = "applet_namespace_mismatch";
    pub const APPROVAL_ALREADY_CONSUMED: &'static str = "approval_already_consumed";
    pub const APPROVAL_NONCE_REUSED: &'static str = "approval_nonce_reused";
    pub const APPROVAL_REQUIRED: &'static str = "approval_required";
    pub const AUDIENCE_MISMATCH: &'static str = "audience_mismatch";
    pub const AUTHORITY_CYCLE: &'static str = "authority_cycle";
    pub const AUTHORITY_EXPIRY_WIDENING: &'static str = "authority_expiry_widening";
    pub const BACKEND_UNAVAILABLE: &'static str = "backend_unavailable";
    pub const BACKUP_REVISION_STALE: &'static str = "backup_revision_stale";
    pub const BLOB_REDACTED: &'static str = "blob_redacted";
    pub const CALENDAR_ACTIVATION_MISMATCH: &'static str = "calendar_activation_mismatch";
    pub const CALENDAR_EVENT_CANCELLED: &'static str = "calendar_event_cancelled";
    pub const CALENDAR_SCHEDULE_UNAVAILABLE: &'static str = "calendar_schedule_unavailable";
    pub const CALENDAR_TZDB_MISMATCH: &'static str = "calendar_tzdb_mismatch";
    pub const CALL_MODERATION_UNAUTHORISED: &'static str = "call_moderation_unauthorised";
    pub const CALL_PARTICIPANT_REMOVED: &'static str = "call_participant_removed";
    pub const CALL_STATE_TERMINAL: &'static str = "call_state_terminal";
    pub const CALL_STATE_TRANSITION_INVALID: &'static str = "call_state_transition_invalid";
    pub const CALL_SUMMARY_INVALID: &'static str = "call_summary_invalid";
    pub const CBOR_BOUNDS_INVALID: &'static str = "cbor_bounds_invalid";
    pub const CBOR_NOT_DETERMINISTIC: &'static str = "cbor_not_deterministic";
    pub const CHALLENGE_EXPIRED: &'static str = "challenge_expired";
    pub const CHALLENGE_FAILED: &'static str = "challenge_failed";
    pub const CHALLENGE_PROOF_INVALID: &'static str = "challenge_proof_invalid";
    pub const CIRCLE_COUNT_EXCEEDED: &'static str = "circle_count_exceeded";
    pub const CIRCLE_MEMBER_MUST_BE_REALM_MEMBER: &'static str =
        "circle_member_must_be_realm_member";
    pub const CIRCLE_NOT_ACTIVE: &'static str = "circle_not_active";
    pub const CIRCLE_REALM_MISMATCH: &'static str = "circle_realm_mismatch";
    pub const CLAIM_INVALID: &'static str = "claim_invalid";
    pub const CONSENT_REVOKED: &'static str = "consent_revoked";
    pub const CONSENT_WITHDRAWN: &'static str = "consent_withdrawn";
    pub const CROSS_DOMAIN_REPLAY_REJECTED: &'static str = "cross_domain_replay_rejected";
    pub const CROSS_REALM_STRUCTURAL_RELATION: &'static str = "cross_realm_structural_relation";
    pub const CURSOR_EXPIRED: &'static str = "cursor_expired";
    pub const CURSOR_INTEGRITY_INVALID: &'static str = "cursor_integrity_invalid";
    pub const CURSOR_REVOKED: &'static str = "cursor_revoked";
    pub const CURSOR_UNRECOGNIZED: &'static str = "cursor_unrecognized";
    pub const DECRYPTION_PENDING: &'static str = "decryption_pending";
    pub const DEPENDENCY_MISSING: &'static str = "dependency_missing";
    pub const DEVICE_DIRECTORY_UNAVAILABLE: &'static str = "device_directory_unavailable";
    pub const DEVICE_GENERATION_FENCED: &'static str = "device_generation_fenced";
    pub const DEVICE_MESSAGE_ID_CONFLICT: &'static str = "device_message_id_conflict";
    pub const DEVICE_REANCHOR_AUTHORIZE_MISMATCH: &'static str =
        "device_reanchor_authorize_mismatch";
    pub const DEVICE_RESULT_UNAVAILABLE: &'static str = "device_result_unavailable";
    pub const DIRECT_CONVERSATION_BINDING_INVALID: &'static str =
        "direct_conversation_binding_invalid";
    pub const DIRECT_CONVERSATION_FOUNDING_UNIT_INVALID: &'static str =
        "direct_conversation_founding_unit_invalid";
    pub const DIRECT_CONVERSATION_INVITE_FORBIDDEN: &'static str =
        "direct_conversation_invite_forbidden";
    pub const DIRECT_CONVERSATION_MEMBER_COUNT_INVALID: &'static str =
        "direct_conversation_member_count_invalid";
    pub const DIRECT_CONVERSATION_PAIR_MATERIALIZATION_CONFLICT: &'static str =
        "direct_conversation_pair_materialization_conflict";
    pub const DIRECT_CONVERSATION_PARTICIPANT_AUTHORITY_DENIED: &'static str =
        "direct_conversation_participant_authority_denied";
    pub const DIRECT_CONVERSATION_ROOT_MASK_VIOLATION: &'static str =
        "direct_conversation_root_mask_violation";
    pub const DIRECT_CONVERSATION_SLOT_ALREADY_COMMITTED: &'static str =
        "direct_conversation_slot_already_committed";
    pub const DIRECT_CONVERSATION_SPACE_FORBIDDEN: &'static str =
        "direct_conversation_space_forbidden";
    pub const DIRECT_CONVERSATION_TERMINAL_FORBIDDEN: &'static str =
        "direct_conversation_terminal_forbidden";
    pub const DIRECT_CONVERSATION_THIRD_PARTY_MEMBER_FORBIDDEN: &'static str =
        "direct_conversation_third_party_member_forbidden";
    pub const DIRECT_DOWNLOAD_DISALLOWED_PRESIGN_FORBIDDEN: &'static str =
        "direct_download_disallowed_presign_forbidden";
    pub const DUPLICATE_CONFLICT: &'static str = "duplicate_conflict";
    pub const E2EE_KEY_SOURCE_UNAUTHORISED: &'static str = "e2ee_key_source_unauthorised";
    pub const EFFECTIVE_SCOPE_REDUCER_MANAGED: &'static str = "effective_scope_reducer_managed";
    pub const EGRESS_POLICY_DENIED: &'static str = "egress_policy_denied";
    pub const EPOCH_UPDATE_REQUIRED: &'static str = "epoch_update_required";
    pub const ERASURE_PENDING_IS_TERMINAL: &'static str = "erasure_pending_is_terminal";
    pub const ERASURE_RECEIPT_AUTHORITY_INVALID: &'static str = "erasure_receipt_authority_invalid";
    pub const ERASURE_RECEIPT_PROOF_INVALID: &'static str = "erasure_receipt_proof_invalid";
    pub const ERASURE_RECEIPT_STUB_BINDING_MISMATCH: &'static str =
        "erasure_receipt_stub_binding_mismatch";
    pub const ERASURE_RECEIPT_STUB_DIGEST_MISMATCH: &'static str =
        "erasure_receipt_stub_digest_mismatch";
    pub const ERASURE_REQUEST_ALREADY_PENDING: &'static str = "erasure_request_already_pending";
    pub const EVENT_ID_DIGEST_MISMATCH: &'static str = "event_id_digest_mismatch";
    pub const EVIDENCE_RECIPIENT_MISMATCH: &'static str = "evidence_recipient_mismatch";
    pub const EXPIRED_INVITE_TOKEN: &'static str = "expired_invite_token";
    pub const EXTERNAL_RATE_LIMITED: &'static str = "external_rate_limited";
    pub const FOCUS_MISMATCH: &'static str = "focus_mismatch";
    pub const FOCUS_UNAVAILABLE_FOR_CLIENT: &'static str = "focus_unavailable_for_client";
    pub const FOUNDING_DEVICE_COMMITMENT_MISMATCH: &'static str =
        "founding_device_commitment_mismatch";
    pub const GATE_CHECK_FAILED: &'static str = "gate_check_failed";
    pub const GOVERNANCE_BINDING_MISMATCH: &'static str = "governance_binding_mismatch";
    pub const GRANT_EXCEEDS_ISSUER_AUTHORITY: &'static str = "grant_exceeds_issuer_authority";
    pub const GRANT_RELINQUISH_NOT_SUBJECT: &'static str = "grant_relinquish_not_subject";
    pub const GRANT_VALIDITY_WINDOW_EMPTY: &'static str = "grant_validity_window_empty";
    pub const HANDLE_HOMOGRAPH_FORBIDDEN: &'static str = "handle_homograph_forbidden";
    pub const HARASSMENT: &'static str = "harassment";
    pub const HATE_SPEECH: &'static str = "hate_speech";
    pub const HUMAN_APPROVAL_REQUIRED: &'static str = "human_approval_required";
    pub const IDENTITY_CREATION_ALREADY_ACCEPTED: &'static str =
        "identity_creation_already_accepted";
    pub const IDENTITY_CREATION_CHALLENGE_ALREADY_CONSUMED: &'static str =
        "identity_creation_challenge_already_consumed";
    pub const IDENTITY_CREATION_CHALLENGE_EXPIRED: &'static str =
        "identity_creation_challenge_expired";
    pub const IDENTITY_CREATION_LEASE_FENCED: &'static str = "identity_creation_lease_fenced";
    pub const IDENTITY_LINK_NO_LONGER_VISIBLE: &'static str = "identity_link_no_longer_visible";
    pub const IDENTITY_LINK_POLICY_TIGHTENED: &'static str = "identity_link_policy_tightened";
    pub const IDENTITY_METHOD_EVIDENCE_INVALID: &'static str = "identity_method_evidence_invalid";
    pub const ILLEGAL: &'static str = "illegal";
    pub const INITIAL_SESSION_REQUEST_MISMATCH: &'static str = "initial_session_request_mismatch";
    pub const INTEGRITY_FAILED: &'static str = "integrity_failed";
    pub const INTERNAL_ERROR: &'static str = "internal_error";
    pub const INVALID_ACK_TOKEN: &'static str = "invalid_ack_token";
    pub const INVALID_CANONICAL_JSON: &'static str = "invalid_canonical_json";
    pub const INVALID_CURSOR: &'static str = "invalid_cursor";
    pub const INVALID_ENCODING: &'static str = "invalid_encoding";
    pub const INVALIDATED_BY_RATE_LIMIT: &'static str = "invalidated_by_rate_limit";
    pub const INVITE_ALREADY_TERMINAL: &'static str = "invite_already_terminal";
    pub const INVITE_DIRECTED_INVITEE_MISMATCH: &'static str = "invite_directed_invitee_mismatch";
    pub const INVITE_KIND_REQUIRES_REVOKE: &'static str = "invite_kind_requires_revoke";
    pub const INVITE_LIVE_TARGET_OCCUPIED: &'static str = "invite_live_target_occupied";
    pub const INVITE_OOB_ENTROPY_TOO_LOW: &'static str = "invite_oob_entropy_too_low";
    pub const JOIN_POLICY_DUPLICATE_GATE_ID: &'static str = "join_policy_duplicate_gate_id";
    pub const JOIN_RULE_POLICY_MISMATCH: &'static str = "join_rule_policy_mismatch";
    pub const KEY_BACKUP_WIRE_SCHEMA_REQUIRED: &'static str = "key_backup_wire_schema_required";
    pub const KEYPACKAGE_CLAIM_RATE_LIMITED: &'static str = "keypackage_claim_rate_limited";
    pub const KEYPACKAGE_EXPIRED: &'static str = "keypackage_expired";
    pub const KEYPACKAGE_ROTATED: &'static str = "keypackage_rotated";
    pub const KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH: &'static str =
        "keypackage_welcome_envelope_mismatch";
    pub const LAST_RESORT_NOT_SUPPORTED: &'static str = "last_resort_not_supported";
    pub const LAST_RESORT_REALM_AFFINITY_VIOLATION: &'static str =
        "last_resort_realm_affinity_violation";
    pub const LAST_RESORT_ROTATION_REQUIRED: &'static str = "last_resort_rotation_required";
    pub const LEGAL_HOLD_ACTIVE: &'static str = "legal_hold_active";
    pub const MEDIA_NEGOTIATION_TIMEOUT: &'static str = "media_negotiation_timeout";
    pub const MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED: &'static str =
        "media_plaintext_service_not_authorised";
    pub const MEDIA_PLAINTEXT_WARNING_REQUIRED: &'static str = "media_plaintext_warning_required";
    pub const MEDIA_SERVICE_BINDING_UNCOVERED: &'static str = "media_service_binding_uncovered";
    pub const MEDIA_SERVICE_FOCI_REQUIRED: &'static str = "media_service_foci_required";
    pub const MEDIA_SOURCE_UNAVAILABLE: &'static str = "media_source_unavailable";
    pub const MEMBER_IDENTITY_PROOF_INVALID: &'static str = "member_identity_proof_invalid";
    pub const MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH: &'static str =
        "member_identity_replacement_digest_mismatch";
    pub const MEMBER_IDENTITY_STATE_MISMATCH: &'static str = "member_identity_state_mismatch";
    pub const MEMBER_IDENTITY_UNKNOWN_SEGMENT: &'static str = "member_identity_unknown_segment";
    pub const MIMI_GOVERNANCE_BINDING_MISMATCH: &'static str = "mimi_governance_binding_mismatch";
    pub const MIMI_GOVERNANCE_BINDING_MISSING: &'static str = "mimi_governance_binding_missing";
    pub const MIMI_POLICY_REVISION_MISMATCH: &'static str = "mimi_policy_revision_mismatch";
    pub const MIMI_ROOM_BINDING_STATUS_TRANSITION_INVALID: &'static str =
        "mimi_room_binding_status_transition_invalid";
    pub const MIMI_ROOM_STATE_INCOMPATIBLE: &'static str = "mimi_room_state_incompatible";
    pub const MINIMAL_DISCLOSURE_VIOLATION: &'static str = "minimal_disclosure_violation";
    pub const MISINFORMATION: &'static str = "misinformation";
    pub const MLS_ACTIVATION_IRREVERSIBLE: &'static str = "mls_activation_irreversible";
    pub const MLS_ACTIVATION_REQUIRED: &'static str = "mls_activation_required";
    pub const MLS_GOVERNANCE_BINDING_STALE: &'static str = "mls_governance_binding_stale";
    pub const MODERATION_CONTROL_SPLIT: &'static str = "moderation_control_split";
    pub const MODERATION_STATE_CONFLICT: &'static str = "moderation_state_conflict";
    pub const MORPH_ALREADY_TERMINAL: &'static str = "morph_already_terminal";
    pub const MORPH_NOT_ACTIVE: &'static str = "morph_not_active";
    pub const MORPH_NOT_ARCHIVED: &'static str = "morph_not_archived";
    pub const NSFW: &'static str = "nsfw";
    pub const OBJECT_ID_NOT_EVENT_DERIVED: &'static str = "object_id_not_event_derived";
    pub const OK: &'static str = "ok";
    pub const OPERATOR_REJECTED: &'static str = "operator_rejected";
    pub const OTHER: &'static str = "other";
    pub const PAIRING_EXPIRED: &'static str = "pairing_expired";
    pub const PAIRING_REQUEST_EXPIRED: &'static str = "pairing_request_expired";
    pub const PARTICIPANT_BINDING_INVALID: &'static str = "participant_binding_invalid";
    pub const PARTICIPANT_ID_UNRECOGNISED: &'static str = "participant_id_unrecognised";
    pub const PATCH_PATH_INVALID: &'static str = "patch_path_invalid";
    pub const PATCH_PATH_REDUCER_MANAGED: &'static str = "patch_path_reducer_managed";
    pub const PATCH_UNSET_REDACTABLE_FIELD: &'static str = "patch_unset_redactable_field";
    pub const PCR_GENESIS_CONFLICT: &'static str = "pcr_genesis_conflict";
    pub const PCR_GENESIS_UNIT_INVALID: &'static str = "pcr_genesis_unit_invalid";
    pub const PERMISSION_DENIED: &'static str = "permission_denied";
    pub const POLICY_DENIED: &'static str = "policy_denied";
    pub const POLICY_REVISION_GAP: &'static str = "policy_revision_gap";
    pub const POLICY_REVOKED: &'static str = "policy_revoked";
    pub const PRESIGN_EXPIRED: &'static str = "presign_expired";
    pub const PRESIGN_INVALID: &'static str = "presign_invalid";
    pub const PRESIGN_SCOPE_MISMATCH: &'static str = "presign_scope_mismatch";
    pub const PRINCIPAL_CONTROL_EVENT_KIND_FORBIDDEN: &'static str =
        "principal_control_event_kind_forbidden";
    pub const PRINCIPAL_DEACTIVATED: &'static str = "principal_deactivated";
    pub const PRIVATE_ATTACHMENT: &'static str = "private_attachment";
    pub const PRIVATE_VIEW_REQUIRES_ACCOUNT_DATA: &'static str =
        "private_view_requires_account_data";
    pub const PROFILE_UNAVAILABLE: &'static str = "profile_unavailable";
    pub const PROJECTION_INCOMPLETE: &'static str = "projection_incomplete";
    pub const PROOF_FAILED: &'static str = "proof_failed";
    pub const PROOF_INVALID: &'static str = "proof_invalid";
    pub const PUSH_GATEWAY_UNREACHABLE: &'static str = "push_gateway_unreachable";
    pub const PUSH_PAYLOAD_TOO_LARGE: &'static str = "push_payload_too_large";
    pub const PUSH_ROUTE_LIMIT_EXCEEDED: &'static str = "push_route_limit_exceeded";
    pub const PUSH_TARGET_UNKNOWN: &'static str = "push_target_unknown";
    pub const PUSH_TOKEN_INVALID: &'static str = "push_token_invalid";
    pub const PUSH_TOKEN_UNKNOWN: &'static str = "push_token_unknown";
    pub const QUARANTINED: &'static str = "quarantined";
    pub const QUEUE_FULL: &'static str = "queue_full";
    pub const RATE_LIMITED: &'static str = "rate_limited";
    pub const REALM_ALIAS_AUTHORITY_MISMATCH: &'static str = "realm_alias_authority_mismatch";
    pub const REALM_AUTHORITY_ROOT_CONFLICT: &'static str = "realm_authority_root_conflict";
    pub const REALM_ID_NOT_EVENT_DERIVED: &'static str = "realm_id_not_event_derived";
    pub const REALM_LINK_INVALID_TRANSITION: &'static str = "realm_link_invalid_transition";
    pub const REALM_LINK_SELF_REFERENCE: &'static str = "realm_link_self_reference";
    pub const REALM_ORGANIZATION_AUTHORIZATION_INVALID: &'static str =
        "realm_organization_authorization_invalid";
    pub const REALM_ORGANIZATION_DELEGATION_MISSING: &'static str =
        "realm_organization_delegation_missing";
    pub const REALM_ORGANIZATION_EXPIRED: &'static str = "realm_organization_expired";
    pub const REALM_ORGANIZATION_REALM_ACCEPTANCE_MISSING: &'static str =
        "realm_organization_realm_acceptance_missing";
    pub const REALM_ORGANIZATION_SCOPE_MISSING: &'static str = "realm_organization_scope_missing";
    pub const RECORDING_ARTIFACT_PIPELINE_BYPASSED: &'static str =
        "recording_artifact_pipeline_bypassed";
    pub const RECORDING_CONSENT_REQUIRED: &'static str = "recording_consent_required";
    pub const RECORDING_STATE_TRANSITION_INVALID: &'static str =
        "recording_state_transition_invalid";
    pub const RECOVERY_EVIDENCE_UNBOUND: &'static str = "recovery_evidence_unbound";
    pub const RECOVERY_POLICY_GENESIS_NOT_V1: &'static str = "recovery_policy_genesis_not_v1";
    pub const RECOVERY_POLICY_MISMATCH: &'static str = "recovery_policy_mismatch";
    pub const RECOVERY_POLICY_SUPERSEDES_INVALID: &'static str =
        "recovery_policy_supersedes_invalid";
    pub const RECOVERY_POLICY_VERSION_NOT_MONOTONIC: &'static str =
        "recovery_policy_version_not_monotonic";
    pub const RECOVERY_PRINCIPAL_ISOLATION: &'static str = "recovery_principal_isolation";
    pub const RECOVERY_PROOF_KIND_UNKNOWN: &'static str = "recovery_proof_kind_unknown";
    pub const RECOVERY_RECEIPT_COMPLETED_AT_AFTER_COMMIT: &'static str =
        "recovery_receipt_completed_at_after_commit";
    pub const RECOVERY_SESSION_CHALLENGE_MISMATCH: &'static str =
        "recovery_session_challenge_mismatch";
    pub const REDUCER_PROJECTION_FAILED: &'static str = "reducer_projection_failed";
    pub const RELATION_KIND_CONTAINS_DERIVED: &'static str = "relation_kind_contains_derived";
    pub const RELATION_KIND_WATCHES_DERIVED: &'static str = "relation_kind_watches_derived";
    pub const RESOLUTION_HISTORY_ANCESTOR_UNKNOWN: &'static str =
        "resolution_history_ancestor_unknown";
    pub const REVOCATION_FRESHNESS_UNKNOWN: &'static str = "revocation_freshness_unknown";
    pub const RISK_POLICY: &'static str = "risk_policy";
    pub const ROUTING_UNLINKABILITY_PRESIGN_FORBIDDEN: &'static str =
        "routing_unlinkability_presign_forbidden";
    pub const RSVP_BASIS_MALFORMED: &'static str = "rsvp_basis_malformed";
    pub const RSVP_OCCURRENCE_NOT_CANONICAL: &'static str = "rsvp_occurrence_not_canonical";
    pub const RUNTIME_KEY_MISSING: &'static str = "runtime_key_missing";
    pub const SCOPE_REBIND_FORBIDDEN: &'static str = "scope_rebind_forbidden";
    pub const SCOPE_REF_MISMATCH: &'static str = "scope_ref_mismatch";
    pub const SEGMENT_BOUNDS_INVALID: &'static str = "segment_bounds_invalid";
    pub const SEGMENT_REPLAY: &'static str = "segment_replay";
    pub const SEGMENT_SEQUENCE_INVALID: &'static str = "segment_sequence_invalid";
    pub const SEGMENT_STREAM_TRUNCATED: &'static str = "segment_stream_truncated";
    pub const SELECTOR_ACTOR_WILDCARD_FORBIDDEN: &'static str = "selector_actor_wildcard_forbidden";
    pub const SEND_FAILED: &'static str = "send_failed";
    pub const SERIES_CHAIN_BROKEN: &'static str = "series_chain_broken";
    pub const SERIES_PREDECESSOR_NOT_FOUND: &'static str = "series_predecessor_not_found";
    pub const SERIES_SEQ_NOT_MONOTONIC: &'static str = "series_seq_not_monotonic";
    pub const SERVICE_KEY_REVOKED: &'static str = "service_key_revoked";
    pub const SERVICE_NOT_PLAINTEXT_VISIBLE: &'static str = "service_not_plaintext_visible";
    pub const SERVICE_PREROTATION_INVALID: &'static str = "service_prerotation_invalid";
    pub const SERVICE_ROUTE_FORK: &'static str = "service_route_fork";
    pub const SESSION_FOCUS_ALREADY_COMMITTED: &'static str = "session_focus_already_committed";
    pub const SESSION_FOCUS_NO_SPLIT_BRAIN: &'static str = "session_focus_no_split_brain";
    pub const SESSION_MISSING: &'static str = "session_missing";
    pub const SIDECAR_CREATE_DENIED: &'static str = "sidecar_create_denied";
    pub const SIGNAL_PLAINTEXT_FORBIDDEN: &'static str = "signal_plaintext_forbidden";
    pub const SPACE_ALREADY_TERMINAL: &'static str = "space_already_terminal";
    pub const SPACE_HAS_LIVE_DEPENDENTS: &'static str = "space_has_live_dependents";
    pub const SPACE_NOT_ACTIVE: &'static str = "space_not_active";
    pub const SPACE_NOT_ARCHIVED: &'static str = "space_not_archived";
    pub const SPACE_PARENT_MISMATCH: &'static str = "space_parent_mismatch";
    pub const SPACE_PARENT_UNREADABLE: &'static str = "space_parent_unreadable";
    pub const SPACE_REALM_MISMATCH: &'static str = "space_realm_mismatch";
    pub const SPAM: &'static str = "spam";
    pub const STATE_MISMATCH: &'static str = "state_mismatch";
    pub const STORAGE_FAILED: &'static str = "storage_failed";
    pub const STRAND_ALREADY_TERMINAL: &'static str = "strand_already_terminal";
    pub const STRAND_NOT_ACTIVE: &'static str = "strand_not_active";
    pub const STRAND_NOT_ARCHIVED: &'static str = "strand_not_archived";
    pub const STREAM_TAIL_MISSING: &'static str = "stream_tail_missing";
    pub const STRUCTURE_DEPTH_EXCEEDED: &'static str = "structure_depth_exceeded";
    pub const SUPERSEDED: &'static str = "superseded";
    pub const SUPERSEDED_BY_REPAIRING: &'static str = "superseded_by_repairing";
    pub const TEST_SIGNING_MATERIAL_DENIED: &'static str = "test_signing_material_denied";
    pub const THIRD_PARTY_INVITE_ACCEPTANCE_MISSING: &'static str =
        "third_party_invite_acceptance_missing";
    pub const THIRD_PARTY_INVITE_ACCEPTANCE_STALE: &'static str =
        "third_party_invite_acceptance_stale";
    pub const THIRD_PARTY_INVITE_MATERIAL_MISMATCH: &'static str =
        "third_party_invite_material_mismatch";
    pub const THIRD_PARTY_INVITE_PROVISIONING_ALREADY_BOUND: &'static str =
        "third_party_invite_provisioning_already_bound";
    pub const THIRD_PARTY_INVITE_PROVISIONING_EXPIRED: &'static str =
        "third_party_invite_provisioning_expired";
    pub const THIRD_PARTY_INVITE_TOKEN_IN_QUERY: &'static str = "third_party_invite_token_in_query";
    pub const TOKEN_ISSUER_UNAUTHORISED: &'static str = "token_issuer_unauthorised";
    pub const TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED: &'static str =
        "transcription_artifact_pipeline_bypassed";
    pub const TRANSCRIPTION_DENIED: &'static str = "transcription_denied";
    pub const UNKNOWN_EVENT_KIND: &'static str = "unknown_event_kind";
    pub const UNKNOWN_FIELD: &'static str = "unknown_field";
    pub const UNKNOWN_FOCUS_TYPE: &'static str = "unknown_focus_type";
    pub const UNRESOLVED_BASIS: &'static str = "unresolved_basis";
    pub const UNSUPPORTED_AEAD_PROFILE: &'static str = "unsupported_aead_profile";
    pub const UNSUPPORTED_ATTACHMENT_SCHEME: &'static str = "unsupported_attachment_scheme";
    pub const UNSUPPORTED_CIPHERSUITE: &'static str = "unsupported_ciphersuite";
    pub const UNSUPPORTED_DIGEST_ALGORITHM: &'static str = "unsupported_digest_algorithm";
    pub const UNSUPPORTED_EVENT_KIND: &'static str = "unsupported_event_kind";
    pub const UNSUPPORTED_FEATURE: &'static str = "unsupported_feature";
    pub const UNSUPPORTED_HPKE_SUITE: &'static str = "unsupported_hpke_suite";
    pub const UNSUPPORTED_PROFILE: &'static str = "unsupported_profile";
    pub const UNSUPPORTED_PROTOCOL_VERSION: &'static str = "unsupported_protocol_version";
    pub const UNSUPPORTED_SIGNATURE_ALG: &'static str = "unsupported_signature_alg";
    pub const UNTRUSTED_BACKUP_SIGNATURE: &'static str = "untrusted_backup_signature";
    pub const VERIFICATION_METHOD_PRINCIPAL_MISMATCH: &'static str =
        "verification_method_principal_mismatch";
    pub const VIEW_ALREADY_TERMINAL: &'static str = "view_already_terminal";
    pub const WEBVH_WITNESS_CONTROLLING_ORGANIZATION_UNVERIFIED: &'static str =
        "webvh_witness_controlling_organization_unverified";
    pub const WEBVH_WITNESS_EVIDENCE_STALE: &'static str = "webvh_witness_evidence_stale";
    pub const WEBVH_WITNESS_PARAMETER_MALFORMED: &'static str = "webvh_witness_parameter_malformed";
    pub const WEBVH_WITNESS_PROOF_INVALID: &'static str = "webvh_witness_proof_invalid";
    pub const WEBVH_WITNESS_PROOFS_UNAVAILABLE: &'static str = "webvh_witness_proofs_unavailable";
    pub const WEBVH_WITNESS_THRESHOLD_NOT_MET: &'static str = "webvh_witness_threshold_not_met";
    pub const WELCOME_CAPABILITY_MISMATCH: &'static str = "welcome_capability_mismatch";
    pub const WITNESS_DISAGREEMENT: &'static str = "witness_disagreement";

    pub fn as_str(&self) -> &str {
        match self {
            Self::AccountBindingPrincipalMismatch => Self::ACCOUNT_BINDING_PRINCIPAL_MISMATCH,
            Self::AccountStatusBindingRollback => Self::ACCOUNT_STATUS_BINDING_ROLLBACK,
            Self::AccountStatusRecordFork => Self::ACCOUNT_STATUS_RECORD_FORK,
            Self::AccountStatusRecordStale => Self::ACCOUNT_STATUS_RECORD_STALE,
            Self::AccountStatusTransitionInvalid => Self::ACCOUNT_STATUS_TRANSITION_INVALID,
            Self::AccountabilityGrantMissing => Self::ACCOUNTABILITY_GRANT_MISSING,
            Self::AeadNonceCounterReplay => Self::AEAD_NONCE_COUNTER_REPLAY,
            Self::AeadNonceDerivationInvalid => Self::AEAD_NONCE_DERIVATION_INVALID,
            Self::AgentDeactivated => Self::AGENT_DEACTIVATED,
            Self::AgentGrantExceedsRequestedScope => Self::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE,
            Self::AgentKeyAuthorizationExpired => Self::AGENT_KEY_AUTHORIZATION_EXPIRED,
            Self::AgentKeyScopeReauthorizationRequired => {
                Self::AGENT_KEY_SCOPE_REAUTHORIZATION_REQUIRED
            }
            Self::AgentParticipationCeilingUnresolved => {
                Self::AGENT_PARTICIPATION_CEILING_UNRESOLVED
            }
            Self::AgentParticipationCeilingWiden => Self::AGENT_PARTICIPATION_CEILING_WIDEN,
            Self::AgentPaused => Self::AGENT_PAUSED,
            Self::AgentPcrGenesisDeclarationConflict => {
                Self::AGENT_PCR_GENESIS_DECLARATION_CONFLICT
            }
            Self::AgentPcrGenesisDeclarationMissing => Self::AGENT_PCR_GENESIS_DECLARATION_MISSING,
            Self::AgentProvisionScopeMigrationRequired => {
                Self::AGENT_PROVISION_SCOPE_MIGRATION_REQUIRED
            }
            Self::AgentProvisioningAlreadyDeclared => Self::AGENT_PROVISIONING_ALREADY_DECLARED,
            Self::AgentReplyNotPermitted => Self::AGENT_REPLY_NOT_PERMITTED,
            Self::AgentRequestedScopeCommitmentInvalid => {
                Self::AGENT_REQUESTED_SCOPE_COMMITMENT_INVALID
            }
            Self::AgentRuntimeRequestConflict => Self::AGENT_RUNTIME_REQUEST_CONFLICT,
            Self::AgentSessionScopeRefreshRequired => Self::AGENT_SESSION_SCOPE_REFRESH_REQUIRED,
            Self::AppletManagedActorProvisionInvalid => {
                Self::APPLET_MANAGED_ACTOR_PROVISION_INVALID
            }
            Self::AppletManagedPcrGenesisInvalid => Self::APPLET_MANAGED_PCR_GENESIS_INVALID,
            Self::AppletManagedPcrGenesisRequiresClosedAggregate => {
                Self::APPLET_MANAGED_PCR_GENESIS_REQUIRES_CLOSED_AGGREGATE
            }
            Self::AppletNamespaceMismatch => Self::APPLET_NAMESPACE_MISMATCH,
            Self::ApprovalAlreadyConsumed => Self::APPROVAL_ALREADY_CONSUMED,
            Self::ApprovalNonceReused => Self::APPROVAL_NONCE_REUSED,
            Self::ApprovalRequired => Self::APPROVAL_REQUIRED,
            Self::AudienceMismatch => Self::AUDIENCE_MISMATCH,
            Self::AuthorityCycle => Self::AUTHORITY_CYCLE,
            Self::AuthorityExpiryWidening => Self::AUTHORITY_EXPIRY_WIDENING,
            Self::BackendUnavailable => Self::BACKEND_UNAVAILABLE,
            Self::BackupRevisionStale => Self::BACKUP_REVISION_STALE,
            Self::BlobRedacted => Self::BLOB_REDACTED,
            Self::CalendarActivationMismatch => Self::CALENDAR_ACTIVATION_MISMATCH,
            Self::CalendarEventCancelled => Self::CALENDAR_EVENT_CANCELLED,
            Self::CalendarScheduleUnavailable => Self::CALENDAR_SCHEDULE_UNAVAILABLE,
            Self::CalendarTzdbMismatch => Self::CALENDAR_TZDB_MISMATCH,
            Self::CallModerationUnauthorised => Self::CALL_MODERATION_UNAUTHORISED,
            Self::CallParticipantRemoved => Self::CALL_PARTICIPANT_REMOVED,
            Self::CallStateTerminal => Self::CALL_STATE_TERMINAL,
            Self::CallStateTransitionInvalid => Self::CALL_STATE_TRANSITION_INVALID,
            Self::CallSummaryInvalid => Self::CALL_SUMMARY_INVALID,
            Self::CborBoundsInvalid => Self::CBOR_BOUNDS_INVALID,
            Self::CborNotDeterministic => Self::CBOR_NOT_DETERMINISTIC,
            Self::ChallengeExpired => Self::CHALLENGE_EXPIRED,
            Self::ChallengeFailed => Self::CHALLENGE_FAILED,
            Self::ChallengeProofInvalid => Self::CHALLENGE_PROOF_INVALID,
            Self::CircleCountExceeded => Self::CIRCLE_COUNT_EXCEEDED,
            Self::CircleMemberMustBeRealmMember => Self::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER,
            Self::CircleNotActive => Self::CIRCLE_NOT_ACTIVE,
            Self::CircleRealmMismatch => Self::CIRCLE_REALM_MISMATCH,
            Self::ClaimInvalid => Self::CLAIM_INVALID,
            Self::ConsentRevoked => Self::CONSENT_REVOKED,
            Self::ConsentWithdrawn => Self::CONSENT_WITHDRAWN,
            Self::CrossDomainReplayRejected => Self::CROSS_DOMAIN_REPLAY_REJECTED,
            Self::CrossRealmStructuralRelation => Self::CROSS_REALM_STRUCTURAL_RELATION,
            Self::CursorExpired => Self::CURSOR_EXPIRED,
            Self::CursorIntegrityInvalid => Self::CURSOR_INTEGRITY_INVALID,
            Self::CursorRevoked => Self::CURSOR_REVOKED,
            Self::CursorUnrecognized => Self::CURSOR_UNRECOGNIZED,
            Self::DecryptionPending => Self::DECRYPTION_PENDING,
            Self::DependencyMissing => Self::DEPENDENCY_MISSING,
            Self::DeviceDirectoryUnavailable => Self::DEVICE_DIRECTORY_UNAVAILABLE,
            Self::DeviceGenerationFenced => Self::DEVICE_GENERATION_FENCED,
            Self::DeviceMessageIdConflict => Self::DEVICE_MESSAGE_ID_CONFLICT,
            Self::DeviceReanchorAuthorizeMismatch => Self::DEVICE_REANCHOR_AUTHORIZE_MISMATCH,
            Self::DeviceResultUnavailable => Self::DEVICE_RESULT_UNAVAILABLE,
            Self::DirectConversationBindingInvalid => Self::DIRECT_CONVERSATION_BINDING_INVALID,
            Self::DirectConversationFoundingUnitInvalid => {
                Self::DIRECT_CONVERSATION_FOUNDING_UNIT_INVALID
            }
            Self::DirectConversationInviteForbidden => Self::DIRECT_CONVERSATION_INVITE_FORBIDDEN,
            Self::DirectConversationMemberCountInvalid => {
                Self::DIRECT_CONVERSATION_MEMBER_COUNT_INVALID
            }
            Self::DirectConversationPairMaterializationConflict => {
                Self::DIRECT_CONVERSATION_PAIR_MATERIALIZATION_CONFLICT
            }
            Self::DirectConversationParticipantAuthorityDenied => {
                Self::DIRECT_CONVERSATION_PARTICIPANT_AUTHORITY_DENIED
            }
            Self::DirectConversationRootMaskViolation => {
                Self::DIRECT_CONVERSATION_ROOT_MASK_VIOLATION
            }
            Self::DirectConversationSlotAlreadyCommitted => {
                Self::DIRECT_CONVERSATION_SLOT_ALREADY_COMMITTED
            }
            Self::DirectConversationSpaceForbidden => Self::DIRECT_CONVERSATION_SPACE_FORBIDDEN,
            Self::DirectConversationTerminalForbidden => {
                Self::DIRECT_CONVERSATION_TERMINAL_FORBIDDEN
            }
            Self::DirectConversationThirdPartyMemberForbidden => {
                Self::DIRECT_CONVERSATION_THIRD_PARTY_MEMBER_FORBIDDEN
            }
            Self::DirectDownloadDisallowedPresignForbidden => {
                Self::DIRECT_DOWNLOAD_DISALLOWED_PRESIGN_FORBIDDEN
            }
            Self::DuplicateConflict => Self::DUPLICATE_CONFLICT,
            Self::E2eeKeySourceUnauthorised => Self::E2EE_KEY_SOURCE_UNAUTHORISED,
            Self::EffectiveScopeReducerManaged => Self::EFFECTIVE_SCOPE_REDUCER_MANAGED,
            Self::EgressPolicyDenied => Self::EGRESS_POLICY_DENIED,
            Self::EpochUpdateRequired => Self::EPOCH_UPDATE_REQUIRED,
            Self::ErasurePendingIsTerminal => Self::ERASURE_PENDING_IS_TERMINAL,
            Self::ErasureReceiptAuthorityInvalid => Self::ERASURE_RECEIPT_AUTHORITY_INVALID,
            Self::ErasureReceiptProofInvalid => Self::ERASURE_RECEIPT_PROOF_INVALID,
            Self::ErasureReceiptStubBindingMismatch => Self::ERASURE_RECEIPT_STUB_BINDING_MISMATCH,
            Self::ErasureReceiptStubDigestMismatch => Self::ERASURE_RECEIPT_STUB_DIGEST_MISMATCH,
            Self::ErasureRequestAlreadyPending => Self::ERASURE_REQUEST_ALREADY_PENDING,
            Self::EventIdDigestMismatch => Self::EVENT_ID_DIGEST_MISMATCH,
            Self::EvidenceRecipientMismatch => Self::EVIDENCE_RECIPIENT_MISMATCH,
            Self::ExpiredInviteToken => Self::EXPIRED_INVITE_TOKEN,
            Self::ExternalRateLimited => Self::EXTERNAL_RATE_LIMITED,
            Self::FocusMismatch => Self::FOCUS_MISMATCH,
            Self::FocusUnavailableForClient => Self::FOCUS_UNAVAILABLE_FOR_CLIENT,
            Self::FoundingDeviceCommitmentMismatch => Self::FOUNDING_DEVICE_COMMITMENT_MISMATCH,
            Self::GateCheckFailed => Self::GATE_CHECK_FAILED,
            Self::GovernanceBindingMismatch => Self::GOVERNANCE_BINDING_MISMATCH,
            Self::GrantExceedsIssuerAuthority => Self::GRANT_EXCEEDS_ISSUER_AUTHORITY,
            Self::GrantRelinquishNotSubject => Self::GRANT_RELINQUISH_NOT_SUBJECT,
            Self::GrantValidityWindowEmpty => Self::GRANT_VALIDITY_WINDOW_EMPTY,
            Self::HandleHomographForbidden => Self::HANDLE_HOMOGRAPH_FORBIDDEN,
            Self::Harassment => Self::HARASSMENT,
            Self::HateSpeech => Self::HATE_SPEECH,
            Self::HumanApprovalRequired => Self::HUMAN_APPROVAL_REQUIRED,
            Self::IdentityCreationAlreadyAccepted => Self::IDENTITY_CREATION_ALREADY_ACCEPTED,
            Self::IdentityCreationChallengeAlreadyConsumed => {
                Self::IDENTITY_CREATION_CHALLENGE_ALREADY_CONSUMED
            }
            Self::IdentityCreationChallengeExpired => Self::IDENTITY_CREATION_CHALLENGE_EXPIRED,
            Self::IdentityCreationLeaseFenced => Self::IDENTITY_CREATION_LEASE_FENCED,
            Self::IdentityLinkNoLongerVisible => Self::IDENTITY_LINK_NO_LONGER_VISIBLE,
            Self::IdentityLinkPolicyTightened => Self::IDENTITY_LINK_POLICY_TIGHTENED,
            Self::IdentityMethodEvidenceInvalid => Self::IDENTITY_METHOD_EVIDENCE_INVALID,
            Self::Illegal => Self::ILLEGAL,
            Self::InitialSessionRequestMismatch => Self::INITIAL_SESSION_REQUEST_MISMATCH,
            Self::IntegrityFailed => Self::INTEGRITY_FAILED,
            Self::InternalError => Self::INTERNAL_ERROR,
            Self::InvalidAckToken => Self::INVALID_ACK_TOKEN,
            Self::InvalidCanonicalJson => Self::INVALID_CANONICAL_JSON,
            Self::InvalidCursor => Self::INVALID_CURSOR,
            Self::InvalidEncoding => Self::INVALID_ENCODING,
            Self::InvalidatedByRateLimit => Self::INVALIDATED_BY_RATE_LIMIT,
            Self::InviteAlreadyTerminal => Self::INVITE_ALREADY_TERMINAL,
            Self::InviteDirectedInviteeMismatch => Self::INVITE_DIRECTED_INVITEE_MISMATCH,
            Self::InviteKindRequiresRevoke => Self::INVITE_KIND_REQUIRES_REVOKE,
            Self::InviteLiveTargetOccupied => Self::INVITE_LIVE_TARGET_OCCUPIED,
            Self::InviteOobEntropyTooLow => Self::INVITE_OOB_ENTROPY_TOO_LOW,
            Self::JoinPolicyDuplicateGateId => Self::JOIN_POLICY_DUPLICATE_GATE_ID,
            Self::JoinRulePolicyMismatch => Self::JOIN_RULE_POLICY_MISMATCH,
            Self::KeyBackupWireSchemaRequired => Self::KEY_BACKUP_WIRE_SCHEMA_REQUIRED,
            Self::KeypackageClaimRateLimited => Self::KEYPACKAGE_CLAIM_RATE_LIMITED,
            Self::KeypackageExpired => Self::KEYPACKAGE_EXPIRED,
            Self::KeypackageRotated => Self::KEYPACKAGE_ROTATED,
            Self::KeypackageWelcomeEnvelopeMismatch => Self::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH,
            Self::LastResortNotSupported => Self::LAST_RESORT_NOT_SUPPORTED,
            Self::LastResortRealmAffinityViolation => Self::LAST_RESORT_REALM_AFFINITY_VIOLATION,
            Self::LastResortRotationRequired => Self::LAST_RESORT_ROTATION_REQUIRED,
            Self::LegalHoldActive => Self::LEGAL_HOLD_ACTIVE,
            Self::MediaNegotiationTimeout => Self::MEDIA_NEGOTIATION_TIMEOUT,
            Self::MediaPlaintextServiceNotAuthorised => {
                Self::MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED
            }
            Self::MediaPlaintextWarningRequired => Self::MEDIA_PLAINTEXT_WARNING_REQUIRED,
            Self::MediaServiceBindingUncovered => Self::MEDIA_SERVICE_BINDING_UNCOVERED,
            Self::MediaServiceFociRequired => Self::MEDIA_SERVICE_FOCI_REQUIRED,
            Self::MediaSourceUnavailable => Self::MEDIA_SOURCE_UNAVAILABLE,
            Self::MemberIdentityProofInvalid => Self::MEMBER_IDENTITY_PROOF_INVALID,
            Self::MemberIdentityReplacementDigestMismatch => {
                Self::MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH
            }
            Self::MemberIdentityStateMismatch => Self::MEMBER_IDENTITY_STATE_MISMATCH,
            Self::MemberIdentityUnknownSegment => Self::MEMBER_IDENTITY_UNKNOWN_SEGMENT,
            Self::MimiGovernanceBindingMismatch => Self::MIMI_GOVERNANCE_BINDING_MISMATCH,
            Self::MimiGovernanceBindingMissing => Self::MIMI_GOVERNANCE_BINDING_MISSING,
            Self::MimiPolicyRevisionMismatch => Self::MIMI_POLICY_REVISION_MISMATCH,
            Self::MimiRoomBindingStatusTransitionInvalid => {
                Self::MIMI_ROOM_BINDING_STATUS_TRANSITION_INVALID
            }
            Self::MimiRoomStateIncompatible => Self::MIMI_ROOM_STATE_INCOMPATIBLE,
            Self::MinimalDisclosureViolation => Self::MINIMAL_DISCLOSURE_VIOLATION,
            Self::Misinformation => Self::MISINFORMATION,
            Self::MlsActivationIrreversible => Self::MLS_ACTIVATION_IRREVERSIBLE,
            Self::MlsActivationRequired => Self::MLS_ACTIVATION_REQUIRED,
            Self::MlsGovernanceBindingStale => Self::MLS_GOVERNANCE_BINDING_STALE,
            Self::ModerationControlSplit => Self::MODERATION_CONTROL_SPLIT,
            Self::ModerationStateConflict => Self::MODERATION_STATE_CONFLICT,
            Self::MorphAlreadyTerminal => Self::MORPH_ALREADY_TERMINAL,
            Self::MorphNotActive => Self::MORPH_NOT_ACTIVE,
            Self::MorphNotArchived => Self::MORPH_NOT_ARCHIVED,
            Self::Nsfw => Self::NSFW,
            Self::ObjectIdNotEventDerived => Self::OBJECT_ID_NOT_EVENT_DERIVED,
            Self::Ok => Self::OK,
            Self::OperatorRejected => Self::OPERATOR_REJECTED,
            Self::Other => Self::OTHER,
            Self::PairingExpired => Self::PAIRING_EXPIRED,
            Self::PairingRequestExpired => Self::PAIRING_REQUEST_EXPIRED,
            Self::ParticipantBindingInvalid => Self::PARTICIPANT_BINDING_INVALID,
            Self::ParticipantIdUnrecognised => Self::PARTICIPANT_ID_UNRECOGNISED,
            Self::PatchPathInvalid => Self::PATCH_PATH_INVALID,
            Self::PatchPathReducerManaged => Self::PATCH_PATH_REDUCER_MANAGED,
            Self::PatchUnsetRedactableField => Self::PATCH_UNSET_REDACTABLE_FIELD,
            Self::PcrGenesisConflict => Self::PCR_GENESIS_CONFLICT,
            Self::PcrGenesisUnitInvalid => Self::PCR_GENESIS_UNIT_INVALID,
            Self::PermissionDenied => Self::PERMISSION_DENIED,
            Self::PolicyDenied => Self::POLICY_DENIED,
            Self::PolicyRevisionGap => Self::POLICY_REVISION_GAP,
            Self::PolicyRevoked => Self::POLICY_REVOKED,
            Self::PresignExpired => Self::PRESIGN_EXPIRED,
            Self::PresignInvalid => Self::PRESIGN_INVALID,
            Self::PresignScopeMismatch => Self::PRESIGN_SCOPE_MISMATCH,
            Self::PrincipalControlEventKindForbidden => {
                Self::PRINCIPAL_CONTROL_EVENT_KIND_FORBIDDEN
            }
            Self::PrincipalDeactivated => Self::PRINCIPAL_DEACTIVATED,
            Self::PrivateAttachment => Self::PRIVATE_ATTACHMENT,
            Self::PrivateViewRequiresAccountData => Self::PRIVATE_VIEW_REQUIRES_ACCOUNT_DATA,
            Self::ProfileUnavailable => Self::PROFILE_UNAVAILABLE,
            Self::ProjectionIncomplete => Self::PROJECTION_INCOMPLETE,
            Self::ProofFailed => Self::PROOF_FAILED,
            Self::ProofInvalid => Self::PROOF_INVALID,
            Self::PushGatewayUnreachable => Self::PUSH_GATEWAY_UNREACHABLE,
            Self::PushPayloadTooLarge => Self::PUSH_PAYLOAD_TOO_LARGE,
            Self::PushRouteLimitExceeded => Self::PUSH_ROUTE_LIMIT_EXCEEDED,
            Self::PushTargetUnknown => Self::PUSH_TARGET_UNKNOWN,
            Self::PushTokenInvalid => Self::PUSH_TOKEN_INVALID,
            Self::PushTokenUnknown => Self::PUSH_TOKEN_UNKNOWN,
            Self::Quarantined => Self::QUARANTINED,
            Self::QueueFull => Self::QUEUE_FULL,
            Self::RateLimited => Self::RATE_LIMITED,
            Self::RealmAliasAuthorityMismatch => Self::REALM_ALIAS_AUTHORITY_MISMATCH,
            Self::RealmAuthorityRootConflict => Self::REALM_AUTHORITY_ROOT_CONFLICT,
            Self::RealmIdNotEventDerived => Self::REALM_ID_NOT_EVENT_DERIVED,
            Self::RealmLinkInvalidTransition => Self::REALM_LINK_INVALID_TRANSITION,
            Self::RealmLinkSelfReference => Self::REALM_LINK_SELF_REFERENCE,
            Self::RealmOrganizationAuthorizationInvalid => {
                Self::REALM_ORGANIZATION_AUTHORIZATION_INVALID
            }
            Self::RealmOrganizationDelegationMissing => Self::REALM_ORGANIZATION_DELEGATION_MISSING,
            Self::RealmOrganizationExpired => Self::REALM_ORGANIZATION_EXPIRED,
            Self::RealmOrganizationRealmAcceptanceMissing => {
                Self::REALM_ORGANIZATION_REALM_ACCEPTANCE_MISSING
            }
            Self::RealmOrganizationScopeMissing => Self::REALM_ORGANIZATION_SCOPE_MISSING,
            Self::RecordingArtifactPipelineBypassed => Self::RECORDING_ARTIFACT_PIPELINE_BYPASSED,
            Self::RecordingConsentRequired => Self::RECORDING_CONSENT_REQUIRED,
            Self::RecordingStateTransitionInvalid => Self::RECORDING_STATE_TRANSITION_INVALID,
            Self::RecoveryEvidenceUnbound => Self::RECOVERY_EVIDENCE_UNBOUND,
            Self::RecoveryPolicyGenesisNotV1 => Self::RECOVERY_POLICY_GENESIS_NOT_V1,
            Self::RecoveryPolicyMismatch => Self::RECOVERY_POLICY_MISMATCH,
            Self::RecoveryPolicySupersedesInvalid => Self::RECOVERY_POLICY_SUPERSEDES_INVALID,
            Self::RecoveryPolicyVersionNotMonotonic => Self::RECOVERY_POLICY_VERSION_NOT_MONOTONIC,
            Self::RecoveryPrincipalIsolation => Self::RECOVERY_PRINCIPAL_ISOLATION,
            Self::RecoveryProofKindUnknown => Self::RECOVERY_PROOF_KIND_UNKNOWN,
            Self::RecoveryReceiptCompletedAtAfterCommit => {
                Self::RECOVERY_RECEIPT_COMPLETED_AT_AFTER_COMMIT
            }
            Self::RecoverySessionChallengeMismatch => Self::RECOVERY_SESSION_CHALLENGE_MISMATCH,
            Self::ReducerProjectionFailed => Self::REDUCER_PROJECTION_FAILED,
            Self::RelationKindContainsDerived => Self::RELATION_KIND_CONTAINS_DERIVED,
            Self::RelationKindWatchesDerived => Self::RELATION_KIND_WATCHES_DERIVED,
            Self::ResolutionHistoryAncestorUnknown => Self::RESOLUTION_HISTORY_ANCESTOR_UNKNOWN,
            Self::RevocationFreshnessUnknown => Self::REVOCATION_FRESHNESS_UNKNOWN,
            Self::RiskPolicy => Self::RISK_POLICY,
            Self::RoutingUnlinkabilityPresignForbidden => {
                Self::ROUTING_UNLINKABILITY_PRESIGN_FORBIDDEN
            }
            Self::RsvpBasisMalformed => Self::RSVP_BASIS_MALFORMED,
            Self::RsvpOccurrenceNotCanonical => Self::RSVP_OCCURRENCE_NOT_CANONICAL,
            Self::RuntimeKeyMissing => Self::RUNTIME_KEY_MISSING,
            Self::ScopeRebindForbidden => Self::SCOPE_REBIND_FORBIDDEN,
            Self::ScopeRefMismatch => Self::SCOPE_REF_MISMATCH,
            Self::SegmentBoundsInvalid => Self::SEGMENT_BOUNDS_INVALID,
            Self::SegmentReplay => Self::SEGMENT_REPLAY,
            Self::SegmentSequenceInvalid => Self::SEGMENT_SEQUENCE_INVALID,
            Self::SegmentStreamTruncated => Self::SEGMENT_STREAM_TRUNCATED,
            Self::SelectorActorWildcardForbidden => Self::SELECTOR_ACTOR_WILDCARD_FORBIDDEN,
            Self::SendFailed => Self::SEND_FAILED,
            Self::SeriesChainBroken => Self::SERIES_CHAIN_BROKEN,
            Self::SeriesPredecessorNotFound => Self::SERIES_PREDECESSOR_NOT_FOUND,
            Self::SeriesSeqNotMonotonic => Self::SERIES_SEQ_NOT_MONOTONIC,
            Self::ServiceKeyRevoked => Self::SERVICE_KEY_REVOKED,
            Self::ServiceNotPlaintextVisible => Self::SERVICE_NOT_PLAINTEXT_VISIBLE,
            Self::ServicePrerotationInvalid => Self::SERVICE_PREROTATION_INVALID,
            Self::ServiceRouteFork => Self::SERVICE_ROUTE_FORK,
            Self::SessionFocusAlreadyCommitted => Self::SESSION_FOCUS_ALREADY_COMMITTED,
            Self::SessionFocusNoSplitBrain => Self::SESSION_FOCUS_NO_SPLIT_BRAIN,
            Self::SessionMissing => Self::SESSION_MISSING,
            Self::SidecarCreateDenied => Self::SIDECAR_CREATE_DENIED,
            Self::SignalPlaintextForbidden => Self::SIGNAL_PLAINTEXT_FORBIDDEN,
            Self::SpaceAlreadyTerminal => Self::SPACE_ALREADY_TERMINAL,
            Self::SpaceHasLiveDependents => Self::SPACE_HAS_LIVE_DEPENDENTS,
            Self::SpaceNotActive => Self::SPACE_NOT_ACTIVE,
            Self::SpaceNotArchived => Self::SPACE_NOT_ARCHIVED,
            Self::SpaceParentMismatch => Self::SPACE_PARENT_MISMATCH,
            Self::SpaceParentUnreadable => Self::SPACE_PARENT_UNREADABLE,
            Self::SpaceRealmMismatch => Self::SPACE_REALM_MISMATCH,
            Self::Spam => Self::SPAM,
            Self::StateMismatch => Self::STATE_MISMATCH,
            Self::StorageFailed => Self::STORAGE_FAILED,
            Self::StrandAlreadyTerminal => Self::STRAND_ALREADY_TERMINAL,
            Self::StrandNotActive => Self::STRAND_NOT_ACTIVE,
            Self::StrandNotArchived => Self::STRAND_NOT_ARCHIVED,
            Self::StreamTailMissing => Self::STREAM_TAIL_MISSING,
            Self::StructureDepthExceeded => Self::STRUCTURE_DEPTH_EXCEEDED,
            Self::Superseded => Self::SUPERSEDED,
            Self::SupersededByRepairing => Self::SUPERSEDED_BY_REPAIRING,
            Self::TestSigningMaterialDenied => Self::TEST_SIGNING_MATERIAL_DENIED,
            Self::ThirdPartyInviteAcceptanceMissing => Self::THIRD_PARTY_INVITE_ACCEPTANCE_MISSING,
            Self::ThirdPartyInviteAcceptanceStale => Self::THIRD_PARTY_INVITE_ACCEPTANCE_STALE,
            Self::ThirdPartyInviteMaterialMismatch => Self::THIRD_PARTY_INVITE_MATERIAL_MISMATCH,
            Self::ThirdPartyInviteProvisioningAlreadyBound => {
                Self::THIRD_PARTY_INVITE_PROVISIONING_ALREADY_BOUND
            }
            Self::ThirdPartyInviteProvisioningExpired => {
                Self::THIRD_PARTY_INVITE_PROVISIONING_EXPIRED
            }
            Self::ThirdPartyInviteTokenInQuery => Self::THIRD_PARTY_INVITE_TOKEN_IN_QUERY,
            Self::TokenIssuerUnauthorised => Self::TOKEN_ISSUER_UNAUTHORISED,
            Self::TranscriptionArtifactPipelineBypassed => {
                Self::TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED
            }
            Self::TranscriptionDenied => Self::TRANSCRIPTION_DENIED,
            Self::UnknownEventKind => Self::UNKNOWN_EVENT_KIND,
            Self::UnknownField => Self::UNKNOWN_FIELD,
            Self::UnknownFocusType => Self::UNKNOWN_FOCUS_TYPE,
            Self::UnresolvedBasis => Self::UNRESOLVED_BASIS,
            Self::UnsupportedAeadProfile => Self::UNSUPPORTED_AEAD_PROFILE,
            Self::UnsupportedAttachmentScheme => Self::UNSUPPORTED_ATTACHMENT_SCHEME,
            Self::UnsupportedCiphersuite => Self::UNSUPPORTED_CIPHERSUITE,
            Self::UnsupportedDigestAlgorithm => Self::UNSUPPORTED_DIGEST_ALGORITHM,
            Self::UnsupportedEventKind => Self::UNSUPPORTED_EVENT_KIND,
            Self::UnsupportedFeature => Self::UNSUPPORTED_FEATURE,
            Self::UnsupportedHpkeSuite => Self::UNSUPPORTED_HPKE_SUITE,
            Self::UnsupportedProfile => Self::UNSUPPORTED_PROFILE,
            Self::UnsupportedProtocolVersion => Self::UNSUPPORTED_PROTOCOL_VERSION,
            Self::UnsupportedSignatureAlg => Self::UNSUPPORTED_SIGNATURE_ALG,
            Self::UntrustedBackupSignature => Self::UNTRUSTED_BACKUP_SIGNATURE,
            Self::VerificationMethodPrincipalMismatch => {
                Self::VERIFICATION_METHOD_PRINCIPAL_MISMATCH
            }
            Self::ViewAlreadyTerminal => Self::VIEW_ALREADY_TERMINAL,
            Self::WebvhWitnessControllingOrganizationUnverified => {
                Self::WEBVH_WITNESS_CONTROLLING_ORGANIZATION_UNVERIFIED
            }
            Self::WebvhWitnessEvidenceStale => Self::WEBVH_WITNESS_EVIDENCE_STALE,
            Self::WebvhWitnessParameterMalformed => Self::WEBVH_WITNESS_PARAMETER_MALFORMED,
            Self::WebvhWitnessProofInvalid => Self::WEBVH_WITNESS_PROOF_INVALID,
            Self::WebvhWitnessProofsUnavailable => Self::WEBVH_WITNESS_PROOFS_UNAVAILABLE,
            Self::WebvhWitnessThresholdNotMet => Self::WEBVH_WITNESS_THRESHOLD_NOT_MET,
            Self::WelcomeCapabilityMismatch => Self::WELCOME_CAPABILITY_MISMATCH,
            Self::WitnessDisagreement => Self::WITNESS_DISAGREEMENT,
            Self::Unknown(value) => value,
        }
    }

    pub fn from_wire(value: &str) -> Self {
        match value {
            Self::ACCOUNT_BINDING_PRINCIPAL_MISMATCH => Self::AccountBindingPrincipalMismatch,
            Self::ACCOUNT_STATUS_BINDING_ROLLBACK => Self::AccountStatusBindingRollback,
            Self::ACCOUNT_STATUS_RECORD_FORK => Self::AccountStatusRecordFork,
            Self::ACCOUNT_STATUS_RECORD_STALE => Self::AccountStatusRecordStale,
            Self::ACCOUNT_STATUS_TRANSITION_INVALID => Self::AccountStatusTransitionInvalid,
            Self::ACCOUNTABILITY_GRANT_MISSING => Self::AccountabilityGrantMissing,
            Self::AEAD_NONCE_COUNTER_REPLAY => Self::AeadNonceCounterReplay,
            Self::AEAD_NONCE_DERIVATION_INVALID => Self::AeadNonceDerivationInvalid,
            Self::AGENT_DEACTIVATED => Self::AgentDeactivated,
            Self::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE => Self::AgentGrantExceedsRequestedScope,
            Self::AGENT_KEY_AUTHORIZATION_EXPIRED => Self::AgentKeyAuthorizationExpired,
            Self::AGENT_KEY_SCOPE_REAUTHORIZATION_REQUIRED => {
                Self::AgentKeyScopeReauthorizationRequired
            }
            Self::AGENT_PARTICIPATION_CEILING_UNRESOLVED => {
                Self::AgentParticipationCeilingUnresolved
            }
            Self::AGENT_PARTICIPATION_CEILING_WIDEN => Self::AgentParticipationCeilingWiden,
            Self::AGENT_PAUSED => Self::AgentPaused,
            Self::AGENT_PCR_GENESIS_DECLARATION_CONFLICT => {
                Self::AgentPcrGenesisDeclarationConflict
            }
            Self::AGENT_PCR_GENESIS_DECLARATION_MISSING => Self::AgentPcrGenesisDeclarationMissing,
            Self::AGENT_PROVISION_SCOPE_MIGRATION_REQUIRED => {
                Self::AgentProvisionScopeMigrationRequired
            }
            Self::AGENT_PROVISIONING_ALREADY_DECLARED => Self::AgentProvisioningAlreadyDeclared,
            Self::AGENT_REPLY_NOT_PERMITTED => Self::AgentReplyNotPermitted,
            Self::AGENT_REQUESTED_SCOPE_COMMITMENT_INVALID => {
                Self::AgentRequestedScopeCommitmentInvalid
            }
            Self::AGENT_RUNTIME_REQUEST_CONFLICT => Self::AgentRuntimeRequestConflict,
            Self::AGENT_SESSION_SCOPE_REFRESH_REQUIRED => Self::AgentSessionScopeRefreshRequired,
            Self::APPLET_MANAGED_ACTOR_PROVISION_INVALID => {
                Self::AppletManagedActorProvisionInvalid
            }
            Self::APPLET_MANAGED_PCR_GENESIS_INVALID => Self::AppletManagedPcrGenesisInvalid,
            Self::APPLET_MANAGED_PCR_GENESIS_REQUIRES_CLOSED_AGGREGATE => {
                Self::AppletManagedPcrGenesisRequiresClosedAggregate
            }
            Self::APPLET_NAMESPACE_MISMATCH => Self::AppletNamespaceMismatch,
            Self::APPROVAL_ALREADY_CONSUMED => Self::ApprovalAlreadyConsumed,
            Self::APPROVAL_NONCE_REUSED => Self::ApprovalNonceReused,
            Self::APPROVAL_REQUIRED => Self::ApprovalRequired,
            Self::AUDIENCE_MISMATCH => Self::AudienceMismatch,
            Self::AUTHORITY_CYCLE => Self::AuthorityCycle,
            Self::AUTHORITY_EXPIRY_WIDENING => Self::AuthorityExpiryWidening,
            Self::BACKEND_UNAVAILABLE => Self::BackendUnavailable,
            Self::BACKUP_REVISION_STALE => Self::BackupRevisionStale,
            Self::BLOB_REDACTED => Self::BlobRedacted,
            Self::CALENDAR_ACTIVATION_MISMATCH => Self::CalendarActivationMismatch,
            Self::CALENDAR_EVENT_CANCELLED => Self::CalendarEventCancelled,
            Self::CALENDAR_SCHEDULE_UNAVAILABLE => Self::CalendarScheduleUnavailable,
            Self::CALENDAR_TZDB_MISMATCH => Self::CalendarTzdbMismatch,
            Self::CALL_MODERATION_UNAUTHORISED => Self::CallModerationUnauthorised,
            Self::CALL_PARTICIPANT_REMOVED => Self::CallParticipantRemoved,
            Self::CALL_STATE_TERMINAL => Self::CallStateTerminal,
            Self::CALL_STATE_TRANSITION_INVALID => Self::CallStateTransitionInvalid,
            Self::CALL_SUMMARY_INVALID => Self::CallSummaryInvalid,
            Self::CBOR_BOUNDS_INVALID => Self::CborBoundsInvalid,
            Self::CBOR_NOT_DETERMINISTIC => Self::CborNotDeterministic,
            Self::CHALLENGE_EXPIRED => Self::ChallengeExpired,
            Self::CHALLENGE_FAILED => Self::ChallengeFailed,
            Self::CHALLENGE_PROOF_INVALID => Self::ChallengeProofInvalid,
            Self::CIRCLE_COUNT_EXCEEDED => Self::CircleCountExceeded,
            Self::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER => Self::CircleMemberMustBeRealmMember,
            Self::CIRCLE_NOT_ACTIVE => Self::CircleNotActive,
            Self::CIRCLE_REALM_MISMATCH => Self::CircleRealmMismatch,
            Self::CLAIM_INVALID => Self::ClaimInvalid,
            Self::CONSENT_REVOKED => Self::ConsentRevoked,
            Self::CONSENT_WITHDRAWN => Self::ConsentWithdrawn,
            Self::CROSS_DOMAIN_REPLAY_REJECTED => Self::CrossDomainReplayRejected,
            Self::CROSS_REALM_STRUCTURAL_RELATION => Self::CrossRealmStructuralRelation,
            Self::CURSOR_EXPIRED => Self::CursorExpired,
            Self::CURSOR_INTEGRITY_INVALID => Self::CursorIntegrityInvalid,
            Self::CURSOR_REVOKED => Self::CursorRevoked,
            Self::CURSOR_UNRECOGNIZED => Self::CursorUnrecognized,
            Self::DECRYPTION_PENDING => Self::DecryptionPending,
            Self::DEPENDENCY_MISSING => Self::DependencyMissing,
            Self::DEVICE_DIRECTORY_UNAVAILABLE => Self::DeviceDirectoryUnavailable,
            Self::DEVICE_GENERATION_FENCED => Self::DeviceGenerationFenced,
            Self::DEVICE_MESSAGE_ID_CONFLICT => Self::DeviceMessageIdConflict,
            Self::DEVICE_REANCHOR_AUTHORIZE_MISMATCH => Self::DeviceReanchorAuthorizeMismatch,
            Self::DEVICE_RESULT_UNAVAILABLE => Self::DeviceResultUnavailable,
            Self::DIRECT_CONVERSATION_BINDING_INVALID => Self::DirectConversationBindingInvalid,
            Self::DIRECT_CONVERSATION_FOUNDING_UNIT_INVALID => {
                Self::DirectConversationFoundingUnitInvalid
            }
            Self::DIRECT_CONVERSATION_INVITE_FORBIDDEN => Self::DirectConversationInviteForbidden,
            Self::DIRECT_CONVERSATION_MEMBER_COUNT_INVALID => {
                Self::DirectConversationMemberCountInvalid
            }
            Self::DIRECT_CONVERSATION_PAIR_MATERIALIZATION_CONFLICT => {
                Self::DirectConversationPairMaterializationConflict
            }
            Self::DIRECT_CONVERSATION_PARTICIPANT_AUTHORITY_DENIED => {
                Self::DirectConversationParticipantAuthorityDenied
            }
            Self::DIRECT_CONVERSATION_ROOT_MASK_VIOLATION => {
                Self::DirectConversationRootMaskViolation
            }
            Self::DIRECT_CONVERSATION_SLOT_ALREADY_COMMITTED => {
                Self::DirectConversationSlotAlreadyCommitted
            }
            Self::DIRECT_CONVERSATION_SPACE_FORBIDDEN => Self::DirectConversationSpaceForbidden,
            Self::DIRECT_CONVERSATION_TERMINAL_FORBIDDEN => {
                Self::DirectConversationTerminalForbidden
            }
            Self::DIRECT_CONVERSATION_THIRD_PARTY_MEMBER_FORBIDDEN => {
                Self::DirectConversationThirdPartyMemberForbidden
            }
            Self::DIRECT_DOWNLOAD_DISALLOWED_PRESIGN_FORBIDDEN => {
                Self::DirectDownloadDisallowedPresignForbidden
            }
            Self::DUPLICATE_CONFLICT => Self::DuplicateConflict,
            Self::E2EE_KEY_SOURCE_UNAUTHORISED => Self::E2eeKeySourceUnauthorised,
            Self::EFFECTIVE_SCOPE_REDUCER_MANAGED => Self::EffectiveScopeReducerManaged,
            Self::EGRESS_POLICY_DENIED => Self::EgressPolicyDenied,
            Self::EPOCH_UPDATE_REQUIRED => Self::EpochUpdateRequired,
            Self::ERASURE_PENDING_IS_TERMINAL => Self::ErasurePendingIsTerminal,
            Self::ERASURE_RECEIPT_AUTHORITY_INVALID => Self::ErasureReceiptAuthorityInvalid,
            Self::ERASURE_RECEIPT_PROOF_INVALID => Self::ErasureReceiptProofInvalid,
            Self::ERASURE_RECEIPT_STUB_BINDING_MISMATCH => Self::ErasureReceiptStubBindingMismatch,
            Self::ERASURE_RECEIPT_STUB_DIGEST_MISMATCH => Self::ErasureReceiptStubDigestMismatch,
            Self::ERASURE_REQUEST_ALREADY_PENDING => Self::ErasureRequestAlreadyPending,
            Self::EVENT_ID_DIGEST_MISMATCH => Self::EventIdDigestMismatch,
            Self::EVIDENCE_RECIPIENT_MISMATCH => Self::EvidenceRecipientMismatch,
            Self::EXPIRED_INVITE_TOKEN => Self::ExpiredInviteToken,
            Self::EXTERNAL_RATE_LIMITED => Self::ExternalRateLimited,
            Self::FOCUS_MISMATCH => Self::FocusMismatch,
            Self::FOCUS_UNAVAILABLE_FOR_CLIENT => Self::FocusUnavailableForClient,
            Self::FOUNDING_DEVICE_COMMITMENT_MISMATCH => Self::FoundingDeviceCommitmentMismatch,
            Self::GATE_CHECK_FAILED => Self::GateCheckFailed,
            Self::GOVERNANCE_BINDING_MISMATCH => Self::GovernanceBindingMismatch,
            Self::GRANT_EXCEEDS_ISSUER_AUTHORITY => Self::GrantExceedsIssuerAuthority,
            Self::GRANT_RELINQUISH_NOT_SUBJECT => Self::GrantRelinquishNotSubject,
            Self::GRANT_VALIDITY_WINDOW_EMPTY => Self::GrantValidityWindowEmpty,
            Self::HANDLE_HOMOGRAPH_FORBIDDEN => Self::HandleHomographForbidden,
            Self::HARASSMENT => Self::Harassment,
            Self::HATE_SPEECH => Self::HateSpeech,
            Self::HUMAN_APPROVAL_REQUIRED => Self::HumanApprovalRequired,
            Self::IDENTITY_CREATION_ALREADY_ACCEPTED => Self::IdentityCreationAlreadyAccepted,
            Self::IDENTITY_CREATION_CHALLENGE_ALREADY_CONSUMED => {
                Self::IdentityCreationChallengeAlreadyConsumed
            }
            Self::IDENTITY_CREATION_CHALLENGE_EXPIRED => Self::IdentityCreationChallengeExpired,
            Self::IDENTITY_CREATION_LEASE_FENCED => Self::IdentityCreationLeaseFenced,
            Self::IDENTITY_LINK_NO_LONGER_VISIBLE => Self::IdentityLinkNoLongerVisible,
            Self::IDENTITY_LINK_POLICY_TIGHTENED => Self::IdentityLinkPolicyTightened,
            Self::IDENTITY_METHOD_EVIDENCE_INVALID => Self::IdentityMethodEvidenceInvalid,
            Self::ILLEGAL => Self::Illegal,
            Self::INITIAL_SESSION_REQUEST_MISMATCH => Self::InitialSessionRequestMismatch,
            Self::INTEGRITY_FAILED => Self::IntegrityFailed,
            Self::INTERNAL_ERROR => Self::InternalError,
            Self::INVALID_ACK_TOKEN => Self::InvalidAckToken,
            Self::INVALID_CANONICAL_JSON => Self::InvalidCanonicalJson,
            Self::INVALID_CURSOR => Self::InvalidCursor,
            Self::INVALID_ENCODING => Self::InvalidEncoding,
            Self::INVALIDATED_BY_RATE_LIMIT => Self::InvalidatedByRateLimit,
            Self::INVITE_ALREADY_TERMINAL => Self::InviteAlreadyTerminal,
            Self::INVITE_DIRECTED_INVITEE_MISMATCH => Self::InviteDirectedInviteeMismatch,
            Self::INVITE_KIND_REQUIRES_REVOKE => Self::InviteKindRequiresRevoke,
            Self::INVITE_LIVE_TARGET_OCCUPIED => Self::InviteLiveTargetOccupied,
            Self::INVITE_OOB_ENTROPY_TOO_LOW => Self::InviteOobEntropyTooLow,
            Self::JOIN_POLICY_DUPLICATE_GATE_ID => Self::JoinPolicyDuplicateGateId,
            Self::JOIN_RULE_POLICY_MISMATCH => Self::JoinRulePolicyMismatch,
            Self::KEY_BACKUP_WIRE_SCHEMA_REQUIRED => Self::KeyBackupWireSchemaRequired,
            Self::KEYPACKAGE_CLAIM_RATE_LIMITED => Self::KeypackageClaimRateLimited,
            Self::KEYPACKAGE_EXPIRED => Self::KeypackageExpired,
            Self::KEYPACKAGE_ROTATED => Self::KeypackageRotated,
            Self::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH => Self::KeypackageWelcomeEnvelopeMismatch,
            Self::LAST_RESORT_NOT_SUPPORTED => Self::LastResortNotSupported,
            Self::LAST_RESORT_REALM_AFFINITY_VIOLATION => Self::LastResortRealmAffinityViolation,
            Self::LAST_RESORT_ROTATION_REQUIRED => Self::LastResortRotationRequired,
            Self::LEGAL_HOLD_ACTIVE => Self::LegalHoldActive,
            Self::MEDIA_NEGOTIATION_TIMEOUT => Self::MediaNegotiationTimeout,
            Self::MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED => {
                Self::MediaPlaintextServiceNotAuthorised
            }
            Self::MEDIA_PLAINTEXT_WARNING_REQUIRED => Self::MediaPlaintextWarningRequired,
            Self::MEDIA_SERVICE_BINDING_UNCOVERED => Self::MediaServiceBindingUncovered,
            Self::MEDIA_SERVICE_FOCI_REQUIRED => Self::MediaServiceFociRequired,
            Self::MEDIA_SOURCE_UNAVAILABLE => Self::MediaSourceUnavailable,
            Self::MEMBER_IDENTITY_PROOF_INVALID => Self::MemberIdentityProofInvalid,
            Self::MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH => {
                Self::MemberIdentityReplacementDigestMismatch
            }
            Self::MEMBER_IDENTITY_STATE_MISMATCH => Self::MemberIdentityStateMismatch,
            Self::MEMBER_IDENTITY_UNKNOWN_SEGMENT => Self::MemberIdentityUnknownSegment,
            Self::MIMI_GOVERNANCE_BINDING_MISMATCH => Self::MimiGovernanceBindingMismatch,
            Self::MIMI_GOVERNANCE_BINDING_MISSING => Self::MimiGovernanceBindingMissing,
            Self::MIMI_POLICY_REVISION_MISMATCH => Self::MimiPolicyRevisionMismatch,
            Self::MIMI_ROOM_BINDING_STATUS_TRANSITION_INVALID => {
                Self::MimiRoomBindingStatusTransitionInvalid
            }
            Self::MIMI_ROOM_STATE_INCOMPATIBLE => Self::MimiRoomStateIncompatible,
            Self::MINIMAL_DISCLOSURE_VIOLATION => Self::MinimalDisclosureViolation,
            Self::MISINFORMATION => Self::Misinformation,
            Self::MLS_ACTIVATION_IRREVERSIBLE => Self::MlsActivationIrreversible,
            Self::MLS_ACTIVATION_REQUIRED => Self::MlsActivationRequired,
            Self::MLS_GOVERNANCE_BINDING_STALE => Self::MlsGovernanceBindingStale,
            Self::MODERATION_CONTROL_SPLIT => Self::ModerationControlSplit,
            Self::MODERATION_STATE_CONFLICT => Self::ModerationStateConflict,
            Self::MORPH_ALREADY_TERMINAL => Self::MorphAlreadyTerminal,
            Self::MORPH_NOT_ACTIVE => Self::MorphNotActive,
            Self::MORPH_NOT_ARCHIVED => Self::MorphNotArchived,
            Self::NSFW => Self::Nsfw,
            Self::OBJECT_ID_NOT_EVENT_DERIVED => Self::ObjectIdNotEventDerived,
            Self::OK => Self::Ok,
            Self::OPERATOR_REJECTED => Self::OperatorRejected,
            Self::OTHER => Self::Other,
            Self::PAIRING_EXPIRED => Self::PairingExpired,
            Self::PAIRING_REQUEST_EXPIRED => Self::PairingRequestExpired,
            Self::PARTICIPANT_BINDING_INVALID => Self::ParticipantBindingInvalid,
            Self::PARTICIPANT_ID_UNRECOGNISED => Self::ParticipantIdUnrecognised,
            Self::PATCH_PATH_INVALID => Self::PatchPathInvalid,
            Self::PATCH_PATH_REDUCER_MANAGED => Self::PatchPathReducerManaged,
            Self::PATCH_UNSET_REDACTABLE_FIELD => Self::PatchUnsetRedactableField,
            Self::PCR_GENESIS_CONFLICT => Self::PcrGenesisConflict,
            Self::PCR_GENESIS_UNIT_INVALID => Self::PcrGenesisUnitInvalid,
            Self::PERMISSION_DENIED => Self::PermissionDenied,
            Self::POLICY_DENIED => Self::PolicyDenied,
            Self::POLICY_REVISION_GAP => Self::PolicyRevisionGap,
            Self::POLICY_REVOKED => Self::PolicyRevoked,
            Self::PRESIGN_EXPIRED => Self::PresignExpired,
            Self::PRESIGN_INVALID => Self::PresignInvalid,
            Self::PRESIGN_SCOPE_MISMATCH => Self::PresignScopeMismatch,
            Self::PRINCIPAL_CONTROL_EVENT_KIND_FORBIDDEN => {
                Self::PrincipalControlEventKindForbidden
            }
            Self::PRINCIPAL_DEACTIVATED => Self::PrincipalDeactivated,
            Self::PRIVATE_ATTACHMENT => Self::PrivateAttachment,
            Self::PRIVATE_VIEW_REQUIRES_ACCOUNT_DATA => Self::PrivateViewRequiresAccountData,
            Self::PROFILE_UNAVAILABLE => Self::ProfileUnavailable,
            Self::PROJECTION_INCOMPLETE => Self::ProjectionIncomplete,
            Self::PROOF_FAILED => Self::ProofFailed,
            Self::PROOF_INVALID => Self::ProofInvalid,
            Self::PUSH_GATEWAY_UNREACHABLE => Self::PushGatewayUnreachable,
            Self::PUSH_PAYLOAD_TOO_LARGE => Self::PushPayloadTooLarge,
            Self::PUSH_ROUTE_LIMIT_EXCEEDED => Self::PushRouteLimitExceeded,
            Self::PUSH_TARGET_UNKNOWN => Self::PushTargetUnknown,
            Self::PUSH_TOKEN_INVALID => Self::PushTokenInvalid,
            Self::PUSH_TOKEN_UNKNOWN => Self::PushTokenUnknown,
            Self::QUARANTINED => Self::Quarantined,
            Self::QUEUE_FULL => Self::QueueFull,
            Self::RATE_LIMITED => Self::RateLimited,
            Self::REALM_ALIAS_AUTHORITY_MISMATCH => Self::RealmAliasAuthorityMismatch,
            Self::REALM_AUTHORITY_ROOT_CONFLICT => Self::RealmAuthorityRootConflict,
            Self::REALM_ID_NOT_EVENT_DERIVED => Self::RealmIdNotEventDerived,
            Self::REALM_LINK_INVALID_TRANSITION => Self::RealmLinkInvalidTransition,
            Self::REALM_LINK_SELF_REFERENCE => Self::RealmLinkSelfReference,
            Self::REALM_ORGANIZATION_AUTHORIZATION_INVALID => {
                Self::RealmOrganizationAuthorizationInvalid
            }
            Self::REALM_ORGANIZATION_DELEGATION_MISSING => Self::RealmOrganizationDelegationMissing,
            Self::REALM_ORGANIZATION_EXPIRED => Self::RealmOrganizationExpired,
            Self::REALM_ORGANIZATION_REALM_ACCEPTANCE_MISSING => {
                Self::RealmOrganizationRealmAcceptanceMissing
            }
            Self::REALM_ORGANIZATION_SCOPE_MISSING => Self::RealmOrganizationScopeMissing,
            Self::RECORDING_ARTIFACT_PIPELINE_BYPASSED => Self::RecordingArtifactPipelineBypassed,
            Self::RECORDING_CONSENT_REQUIRED => Self::RecordingConsentRequired,
            Self::RECORDING_STATE_TRANSITION_INVALID => Self::RecordingStateTransitionInvalid,
            Self::RECOVERY_EVIDENCE_UNBOUND => Self::RecoveryEvidenceUnbound,
            Self::RECOVERY_POLICY_GENESIS_NOT_V1 => Self::RecoveryPolicyGenesisNotV1,
            Self::RECOVERY_POLICY_MISMATCH => Self::RecoveryPolicyMismatch,
            Self::RECOVERY_POLICY_SUPERSEDES_INVALID => Self::RecoveryPolicySupersedesInvalid,
            Self::RECOVERY_POLICY_VERSION_NOT_MONOTONIC => Self::RecoveryPolicyVersionNotMonotonic,
            Self::RECOVERY_PRINCIPAL_ISOLATION => Self::RecoveryPrincipalIsolation,
            Self::RECOVERY_PROOF_KIND_UNKNOWN => Self::RecoveryProofKindUnknown,
            Self::RECOVERY_RECEIPT_COMPLETED_AT_AFTER_COMMIT => {
                Self::RecoveryReceiptCompletedAtAfterCommit
            }
            Self::RECOVERY_SESSION_CHALLENGE_MISMATCH => Self::RecoverySessionChallengeMismatch,
            Self::REDUCER_PROJECTION_FAILED => Self::ReducerProjectionFailed,
            Self::RELATION_KIND_CONTAINS_DERIVED => Self::RelationKindContainsDerived,
            Self::RELATION_KIND_WATCHES_DERIVED => Self::RelationKindWatchesDerived,
            Self::RESOLUTION_HISTORY_ANCESTOR_UNKNOWN => Self::ResolutionHistoryAncestorUnknown,
            Self::REVOCATION_FRESHNESS_UNKNOWN => Self::RevocationFreshnessUnknown,
            Self::RISK_POLICY => Self::RiskPolicy,
            Self::ROUTING_UNLINKABILITY_PRESIGN_FORBIDDEN => {
                Self::RoutingUnlinkabilityPresignForbidden
            }
            Self::RSVP_BASIS_MALFORMED => Self::RsvpBasisMalformed,
            Self::RSVP_OCCURRENCE_NOT_CANONICAL => Self::RsvpOccurrenceNotCanonical,
            Self::RUNTIME_KEY_MISSING => Self::RuntimeKeyMissing,
            Self::SCOPE_REBIND_FORBIDDEN => Self::ScopeRebindForbidden,
            Self::SCOPE_REF_MISMATCH => Self::ScopeRefMismatch,
            Self::SEGMENT_BOUNDS_INVALID => Self::SegmentBoundsInvalid,
            Self::SEGMENT_REPLAY => Self::SegmentReplay,
            Self::SEGMENT_SEQUENCE_INVALID => Self::SegmentSequenceInvalid,
            Self::SEGMENT_STREAM_TRUNCATED => Self::SegmentStreamTruncated,
            Self::SELECTOR_ACTOR_WILDCARD_FORBIDDEN => Self::SelectorActorWildcardForbidden,
            Self::SEND_FAILED => Self::SendFailed,
            Self::SERIES_CHAIN_BROKEN => Self::SeriesChainBroken,
            Self::SERIES_PREDECESSOR_NOT_FOUND => Self::SeriesPredecessorNotFound,
            Self::SERIES_SEQ_NOT_MONOTONIC => Self::SeriesSeqNotMonotonic,
            Self::SERVICE_KEY_REVOKED => Self::ServiceKeyRevoked,
            Self::SERVICE_NOT_PLAINTEXT_VISIBLE => Self::ServiceNotPlaintextVisible,
            Self::SERVICE_PREROTATION_INVALID => Self::ServicePrerotationInvalid,
            Self::SERVICE_ROUTE_FORK => Self::ServiceRouteFork,
            Self::SESSION_FOCUS_ALREADY_COMMITTED => Self::SessionFocusAlreadyCommitted,
            Self::SESSION_FOCUS_NO_SPLIT_BRAIN => Self::SessionFocusNoSplitBrain,
            Self::SESSION_MISSING => Self::SessionMissing,
            Self::SIDECAR_CREATE_DENIED => Self::SidecarCreateDenied,
            Self::SIGNAL_PLAINTEXT_FORBIDDEN => Self::SignalPlaintextForbidden,
            Self::SPACE_ALREADY_TERMINAL => Self::SpaceAlreadyTerminal,
            Self::SPACE_HAS_LIVE_DEPENDENTS => Self::SpaceHasLiveDependents,
            Self::SPACE_NOT_ACTIVE => Self::SpaceNotActive,
            Self::SPACE_NOT_ARCHIVED => Self::SpaceNotArchived,
            Self::SPACE_PARENT_MISMATCH => Self::SpaceParentMismatch,
            Self::SPACE_PARENT_UNREADABLE => Self::SpaceParentUnreadable,
            Self::SPACE_REALM_MISMATCH => Self::SpaceRealmMismatch,
            Self::SPAM => Self::Spam,
            Self::STATE_MISMATCH => Self::StateMismatch,
            Self::STORAGE_FAILED => Self::StorageFailed,
            Self::STRAND_ALREADY_TERMINAL => Self::StrandAlreadyTerminal,
            Self::STRAND_NOT_ACTIVE => Self::StrandNotActive,
            Self::STRAND_NOT_ARCHIVED => Self::StrandNotArchived,
            Self::STREAM_TAIL_MISSING => Self::StreamTailMissing,
            Self::STRUCTURE_DEPTH_EXCEEDED => Self::StructureDepthExceeded,
            Self::SUPERSEDED => Self::Superseded,
            Self::SUPERSEDED_BY_REPAIRING => Self::SupersededByRepairing,
            Self::TEST_SIGNING_MATERIAL_DENIED => Self::TestSigningMaterialDenied,
            Self::THIRD_PARTY_INVITE_ACCEPTANCE_MISSING => Self::ThirdPartyInviteAcceptanceMissing,
            Self::THIRD_PARTY_INVITE_ACCEPTANCE_STALE => Self::ThirdPartyInviteAcceptanceStale,
            Self::THIRD_PARTY_INVITE_MATERIAL_MISMATCH => Self::ThirdPartyInviteMaterialMismatch,
            Self::THIRD_PARTY_INVITE_PROVISIONING_ALREADY_BOUND => {
                Self::ThirdPartyInviteProvisioningAlreadyBound
            }
            Self::THIRD_PARTY_INVITE_PROVISIONING_EXPIRED => {
                Self::ThirdPartyInviteProvisioningExpired
            }
            Self::THIRD_PARTY_INVITE_TOKEN_IN_QUERY => Self::ThirdPartyInviteTokenInQuery,
            Self::TOKEN_ISSUER_UNAUTHORISED => Self::TokenIssuerUnauthorised,
            Self::TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED => {
                Self::TranscriptionArtifactPipelineBypassed
            }
            Self::TRANSCRIPTION_DENIED => Self::TranscriptionDenied,
            Self::UNKNOWN_EVENT_KIND => Self::UnknownEventKind,
            Self::UNKNOWN_FIELD => Self::UnknownField,
            Self::UNKNOWN_FOCUS_TYPE => Self::UnknownFocusType,
            Self::UNRESOLVED_BASIS => Self::UnresolvedBasis,
            Self::UNSUPPORTED_AEAD_PROFILE => Self::UnsupportedAeadProfile,
            Self::UNSUPPORTED_ATTACHMENT_SCHEME => Self::UnsupportedAttachmentScheme,
            Self::UNSUPPORTED_CIPHERSUITE => Self::UnsupportedCiphersuite,
            Self::UNSUPPORTED_DIGEST_ALGORITHM => Self::UnsupportedDigestAlgorithm,
            Self::UNSUPPORTED_EVENT_KIND => Self::UnsupportedEventKind,
            Self::UNSUPPORTED_FEATURE => Self::UnsupportedFeature,
            Self::UNSUPPORTED_HPKE_SUITE => Self::UnsupportedHpkeSuite,
            Self::UNSUPPORTED_PROFILE => Self::UnsupportedProfile,
            Self::UNSUPPORTED_PROTOCOL_VERSION => Self::UnsupportedProtocolVersion,
            Self::UNSUPPORTED_SIGNATURE_ALG => Self::UnsupportedSignatureAlg,
            Self::UNTRUSTED_BACKUP_SIGNATURE => Self::UntrustedBackupSignature,
            Self::VERIFICATION_METHOD_PRINCIPAL_MISMATCH => {
                Self::VerificationMethodPrincipalMismatch
            }
            Self::VIEW_ALREADY_TERMINAL => Self::ViewAlreadyTerminal,
            Self::WEBVH_WITNESS_CONTROLLING_ORGANIZATION_UNVERIFIED => {
                Self::WebvhWitnessControllingOrganizationUnverified
            }
            Self::WEBVH_WITNESS_EVIDENCE_STALE => Self::WebvhWitnessEvidenceStale,
            Self::WEBVH_WITNESS_PARAMETER_MALFORMED => Self::WebvhWitnessParameterMalformed,
            Self::WEBVH_WITNESS_PROOF_INVALID => Self::WebvhWitnessProofInvalid,
            Self::WEBVH_WITNESS_PROOFS_UNAVAILABLE => Self::WebvhWitnessProofsUnavailable,
            Self::WEBVH_WITNESS_THRESHOLD_NOT_MET => Self::WebvhWitnessThresholdNotMet,
            Self::WELCOME_CAPABILITY_MISMATCH => Self::WelcomeCapabilityMismatch,
            Self::WITNESS_DISAGREEMENT => Self::WitnessDisagreement,
            _ => Self::Unknown(value.to_owned()),
        }
    }

    /// Whether `value` is a reason code registered in
    /// `registry/error-code-registry.json` (as opposed to merely well-formed,
    /// which [`Self::is_valid_wire`] checks).
    pub fn is_registered(value: &str) -> bool {
        !matches!(Self::from_wire(value), Self::Unknown(_))
    }

    pub fn is_valid_wire(value: &str) -> bool {
        let mut characters = value.chars();
        matches!(characters.next(), Some('a'..='z'))
            && value.len() <= 64
            && characters.all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
    }

    pub fn descriptor(&self) -> Option<&'static ReasonCodeDescriptor> {
        REASON_CODE_DESCRIPTORS
            .iter()
            .find(|row| row.code == self.as_str())
    }
}

impl Serialize for ReasonCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !Self::is_valid_wire(self.as_str()) {
            return Err(serde::ser::Error::custom("invalid reason code"));
        }
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ReasonCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if !Self::is_valid_wire(&value) {
            return Err(serde::de::Error::custom("invalid reason code"));
        }
        Ok(Self::from_wire(&value))
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ToSchema for ReasonCode {
    fn to_schema(
        _components: &mut salvo_oapi::Components,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        salvo_oapi::schema::Object::new()
            .schema_type(salvo_oapi::schema::BasicType::String)
            .pattern("^[a-z][a-z0-9_]{0,63}$")
            .max_length(64)
            .into()
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ComposeSchema for ReasonCode {
    fn compose(
        components: &mut salvo_oapi::Components,
        generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        let _ = generics;
        <Self as salvo_oapi::ToSchema>::to_schema(components)
    }
}

pub const REASON_CODE_DESCRIPTORS: &[ReasonCodeDescriptor] = &[
    ReasonCodeDescriptor {
        code: ReasonCode::ACCOUNT_BINDING_PRINCIPAL_MISMATCH,
        applies_to: &["identity_creation", "client_validation"],
        description: "The authenticated service account is already bound to a principal_id different from the DID locally derived from the frozen identity-creation draft. The client MUST fail closed, visibly disclose the conflict, and MUST NOT adopt the returned principal or silently regenerate a replacement identity.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ACCOUNT_STATUS_BINDING_ROLLBACK,
        applies_to: &["account_status", "service_call", "state_resolution"],
        description: "A Station received an otherwise valid AccountStatusRecord whose binding_version is lower than the durable floor for the same Account Authority and account. The receiver MUST return failed_precondition with this reason, perform zero replica/outbox/erasure-intent writes, and MUST NOT retry the same record. See zh/identity/account-lifecycle.md §3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ACCOUNT_STATUS_RECORD_FORK,
        applies_to: &["account_status", "service_call", "state_resolution"],
        description: "A Station received an AccountStatusRecord that conflicts with the issuer-ledger chain: either the durable status_seq already names a different record, or the next status_seq does not name the durable head as previous_account_status_record_id. The receiver MUST return failed_precondition with this reason, perform zero writes, stop automatic retry or gap recovery for the conflicting record, and quarantine/alert for operator investigation. It MUST NOT reuse duplicate_conflict, which is reserved by this operation for Idempotency-Key reuse with different canonical request bytes. See zh/identity/account-lifecycle.md §3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ACCOUNT_STATUS_RECORD_STALE,
        applies_to: &["account_status", "service_call", "state_resolution"],
        description: "A Station received an otherwise valid AccountStatusRecord whose status_seq is lower than its durable replica head. The durable head is the only comparison baseline, so this reason applies even when the submitted record is byte-identical to a history row the receiver still stores for that status_seq; a retained history row MUST NOT downgrade the outcome to duplicate. The receiver MUST return failed_precondition with this reason, perform zero writes, and treat the exact record as terminal/non-retryable. duplicate is reserved for a submission whose status_seq and record identity both equal the durable head. The full ordered classification is registry/account-status-replica-decision-table.json. See zh/identity/account-lifecycle.md §3.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ACCOUNT_STATUS_TRANSITION_INVALID,
        applies_to: &["account_status", "event_envelope", "state_resolution"],
        description: "An Account Authority issuer-ledger mutation requested a `from â†’ to` status transition not permitted by the account-status legal-transition table â€” e.g. reactivating a `deactivated` account. The current-head transaction MUST fail with zero account-row/ledger/audit/outbox writes. A successor after `erasure_pending` uses the more specific `erasure_pending_is_terminal`. See zh/identity/account-lifecycle.md §3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "Returned in three surfaces. (1) `event_envelope` / `auth_decision`: an Actor Profile update declares an `accountable_principal_ids[]` entry without a corresponding active `ak.identity.accountability_grant` (issuer=that DID, subject=profile.principal_id, grant_status=active, within validity window). Reducer MUST reject the entire Event with this reason and MUST NOT accept a field-stripped projection. See zh/models/actor.md §3.3.1. (2) `service_call`: returned by orchestrator HTTP operations that fan-out an accountability grant â€” `ak.self.agent.command.provision.v1` rejects when the controller cannot present an issuable accountability grant for the new agent principal, and `ak.self.agent.command.resume.v1` rejects when the controller's accountability grant over the agent has been revoked or has lapsed its freshness window since `ak.self.agent.command.pause.v1`. HTTP callers MUST treat this as a precondition-class failure, not transient.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AEAD_NONCE_COUNTER_REPLAY,
        applies_to: &["event_envelope", "encoding"],
        description: "An AEAD-encrypted payload (encrypted_payload, blob attachment, to_device, etc.) repeated a per-(key_ref, epoch, device_id) counter already seen by the receiver. The receiver MUST reject the payload before AEAD decryption to prevent attempted nonce reuse against a valid sender device. See zh/crypto-media/media-and-blob.md §3.1 and zh/conformance/encoding.md §10.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
        applies_to: &["event_envelope", "encoding"],
        description: "An AEAD nonce on the wire does not match the deterministic derivation from MLS-Exporter context {key_ref, epoch, purpose} plus (device_id, monotonic counter) mandated by zh/crypto-media/media-and-blob.md §3.1. Producers MUST NOT emit naive random nonces under shared MLS application keys; receivers MUST reject such payloads to enforce the cross-implementation nonce-uniqueness contract.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_DEACTIVATED,
        applies_to: &["auth_decision", "service_call", "event_envelope"],
        description: "A request targeted an Agent principal whose current `agent_status` typed current result is `deactivated` (terminal). The endpoint MUST fail closed and no resume path exists. The accepted parent lifecycle witness is sufficient to make all subordinate authorization ineffective; asynchronous cleanup need not synthesize key/grant revoke Events and cannot restore authority. Callers MUST NOT treat this as transient. See zh/identity/key-management.md §3.6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE,
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "A Agent Realm grant contains an action or resource not covered by the Agent's immutable provision requested_scope, or attempts to omit or relax a mandatory provision constraint. Grant attach and reducer admission MUST fail closed with failed_precondition; Realm membership, policy, participation, pairing or key authorization cannot restore authority omitted at provision time. See zh/authz/capabilities.md section 9.1 and zh/identity/key-management.md section 3.6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_KEY_AUTHORIZATION_EXPIRED,
        applies_to: &["auth_decision"],
        description: "Agent session issuance rejected because the referenced ak.agent.key.authorize declared an expires_at that has elapsed. Distinct from proof_invalid (malformed / unverifiable proof): the runtime should prompt the controller to re-authorize the same key (same-key re-authorization, zh/identity/key-management.md §3.6) rather than rebuild the proof. Never returned for non-expiring (absent expires_at) authorizations.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_KEY_SCOPE_REAUTHORIZATION_REQUIRED,
        applies_to: &["auth_decision", "service_call"],
        description: "The immutable provision ceiling contains every operation required by the selected runtime capability, but the accepted Agent key authorization omits one or more of them. The operation fails with failed_precondition; the controller may re-authorize or rotate the key only within the immutable provision ceiling. See zh/identity/key-management.md §3.6.1 and agent-runtime-scope-registry.json.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_PARTICIPATION_CEILING_UNRESOLVED,
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "An Agent action or mention fanout requires the current target-local deployment/Realm/Circle/Strand participation policy, but one or more required layers are stale, unavailable, or unverifiable. The action-time gate treats the unresolved policy as all false. The controller's private selection remains stored unchanged. See zh/authz/capabilities.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_PARTICIPATION_CEILING_WIDEN,
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a Realm/Circle/Strand agent_participation ceiling write would widen (enable a bit disabled by) its parent ceiling. The deployment âŠ‡ Realm âŠ‡ Circle âŠ‡ Strand ceiling chain is tighten-only (monotone). See zh/models/realm-and-space.md, zh/models/circle.md, zh/authz/capabilities.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_PAUSED,
        applies_to: &["auth_decision", "service_call", "event_envelope"],
        description: "A request targeted an agent principal whose current `agent_status` typed current result is `paused`. Auth Server MUST reject new agent session grants, and any submit / sidecar / grant-management call by or for the paused agent MUST fail closed until `ak.self.agent.command.resume.v1` lands. Distinct from `capability_denied` so callers can surface the recoverable lifecycle state. See zh/identity/key-management.md §3.6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_PCR_GENESIS_DECLARATION_CONFLICT,
        applies_to: &["service_call", "event_envelope"],
        description: "A second ak.agent.provision declared a principal_control_realm_id that another accepted provision already claims. Inside one controller PCR the commit-ordered projection claim typed current result rejects it; across controllers the Station's local uniqueness index rejects it. Either way the write set is empty and the earlier claim is untouched. See zh/identity/key-management.md §3.6.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_PCR_GENESIS_DECLARATION_MISSING,
        applies_to: &["pcr_genesis", "event_envelope"],
        description: "A agent_control ak.realm.create was submitted without an already accepted ak.agent.provision in the controller PCR whose payload.principal_control_realm_id equals retype(this genesis event_id). The genesis carries no ref to its provision, so this reverse look-up is the whole binding: no match MUST fail closed with zero writes, and the receiver MUST NOT materialize the Realm, the agent-status transition or any partial projection. See zh/identity/key-management.md §3.6.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_PROVISION_SCOPE_MIGRATION_REQUIRED,
        applies_to: &["auth_decision", "service_call"],
        description: "The Agent's immutable provision requested_scope omits an operation mandatory for the selected runtime capability. The operation fails with failed_precondition and recovery requires provisioning a new Agent principal; key re-pairing, Realm grants and session issuance MUST NOT widen this ceiling. See zh/identity/key-management.md §3.6.1 and agent-runtime-scope-registry.json.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_PROVISIONING_ALREADY_DECLARED,
        applies_to: &["event_envelope", "service_call"],
        description: "A second ak.agent.provision declared an agent_id that an accepted provision in this controller PCR already carries in the agent_provisioning family. The write set is empty and the earlier fact is untouched. The realm-id claim cannot catch this case: a second provision freezes a different genesis create, so it declares a different principal_control_realm_id and conflicts with nothing. Re-declaring one agent_id is how the immutable requested_scope ceiling would be widened, which zh/identity/key-management.md section 3.6.1 answers with provisioning a new Agent principal instead. See zh/identity/key-management.md section 3.6.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_REPLY_NOT_PERMITTED,
        applies_to: &["state_resolution"],
        description: "An Agent attempted to author ak.message.create in a scope where current controller selection and current target policy do not both enable reply_message. See zh/authz/capabilities.md §5.4 and zh/models/private-objects.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_REQUESTED_SCOPE_COMMITMENT_INVALID,
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "The complete immutable Agent requested_scope commitment is missing from accepted-at Agent DID history, differs from the service projection, or its domain-separated digest does not verify. Pairing, Realm grant admission and agent session issuance MUST fail closed and MUST NOT treat a service-local Agent row as the authority source. See zh/identity/key-management.md section 3.6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_RUNTIME_REQUEST_CONFLICT,
        applies_to: &["service_call"],
        description: "A different stable runtime key binding was submitted while the same open pairing_request_id already has a pending runtime request. The service MUST return HTTP 409 and MUST NOT replace the current pending request, approval_request_id, or notification id. A retry with the same ak.agent.runtime_key_binding.v1 digest is idempotent and does not use this error. See zh/identity/key-management.md §3.6.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AGENT_SESSION_SCOPE_REFRESH_REQUIRED,
        applies_to: &["auth_decision", "service_call"],
        description: "The immutable provision ceiling and accepted Agent key authorization both contain every operation required by the selected runtime capability, but the requested or current session scope omits one or more. The operation fails with failed_precondition and recovery is a new session constrained by both upper ceilings. See zh/identity/key-management.md §3.6.1 and agent-runtime-scope-registry.json.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::APPLET_MANAGED_ACTOR_PROVISION_INVALID,
        applies_to: &["event_envelope", "auth_decision"],
        description: "An ak.applet.managed_actor.provision Event in the closed Applet managed-actor creation aggregate does not satisfy its binding rules: actor_id.account_id.station_id is not the receiving Station, the actor collides with the service or controller principal, or the provisioned actor is not the registration's declared bot_actor_id. See zh/extensions/applet-integration.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::APPLET_MANAGED_PCR_GENESIS_INVALID,
        applies_to: &["pcr_genesis", "event_envelope"],
        description: "The purpose=applet_managed_control PCR genesis Event in the Applet managed-actor creation aggregate does not cross-bind its provision Event, initial_resolution, Applet, grant and service verbatim. See zh/extensions/applet-integration.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::APPLET_MANAGED_PCR_GENESIS_REQUIRES_CLOSED_AGGREGATE,
        applies_to: &["pcr_genesis", "federation_transaction"],
        description: "A purpose=applet_managed_control PCR genesis arrived outside the closed Applet install / Ghost provisioning aggregate - an ordinary submit, a Realm bootstrap batch, or ak.peer.events.command.submit.v1. Transport and proof validity do not make it an AppletFormal admission. See zh/extensions/applet-integration.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::APPLET_NAMESPACE_MISMATCH,
        applies_to: &["state_resolution", "auth_decision"],
        description: "Sub-reason for a delegated-handoff Event rejection when auth_data.executed_by is not within the applet_id registration's declared service / bot DID set or namespaces.actors pattern. Prevents a grant scoped to one applet from being exercised under an unrelated applet_id. See zh/extensions/applet-integration.md §11.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::APPROVAL_ALREADY_CONSUMED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "An agent draft/action approval has already been consumed by a successful publish attempt. Replaying the same approval MUST fail closed instead of publishing twice. See zh/conformance/conformance-vectors.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::APPROVAL_NONCE_REUSED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "An approval signature whose (approval_context, approver_did, nonce) triple was already consumed by a successfully accepted target was presented for a different target. The nonce namespace is (approval_context, approver_did) and the nonce is consumed only when the target is accepted, in that same transaction: an exact replay of the already accepted target returns the original outcome, and a failed verification or an unmet quorum MUST NOT consume it early, so normal retries that collect the remaining votes still work. See zh/authz/constraint-schema.md section 9.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::APPROVAL_REQUIRED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "An eligible execution was rejected because approval evidence is required and what was supplied through its registered carrier does not meet the requirement. Two independent layers can raise that requirement and both are evaluated: an approval constraint on a matched capability grant (zh/authz/capabilities.md §6 / §8, zh/authz/constraint-schema.md §9), and the Realm governance approval configuration registered as the policy_action typed current result (zh/models/governance-objects.md §3.5), which hangs off an (action token, scope) pair rather than off one grant. Either layer alone is enough to produce this reason code, and a layer writing approval_required=false only withdraws its own demand -- it never cancels the other's. The top-level error is claim_required. This is a require_review-class outcome, not a deny: supplying the missing approval signatures through the carrier named by capability-action-registry.json and retrying is the defined path. Requirements for actions without a registered carrier are instead rejected at configuration write time with approval_carrier_unregistered.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AUDIENCE_MISMATCH,
        applies_to: &["auth_decision", "event_envelope", "service_call"],
        description: "A proof, token, Auth Server verification result, invite claim, KeyPackage claim, or signed handoff was presented to a Realm / service / audience different from the one bound into the signed material. Receivers MUST reject rather than reinterpret the audience. See zh/conformance/conformance-vectors.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AUTHORITY_CYCLE,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A ak.capability.grant would close a cycle in the authority graph, traversed as a DFS over grant_id edges taken from issuer_authority_refs entries with kind=grant. realm_root refs are rooted terminals and contribute no edge. Reducer MUST reject the grant; evaluation MUST NOT recurse without terminating. See zh/authz/capabilities.md §10.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::AUTHORITY_EXPIRY_WIDENING,
        applies_to: &["event_envelope", "auth_decision"],
        description: "For some action this grant claims, its effective window is wider than the refs that cover that action allow: it starts before the earliest effective_not_before among them, or ends after the latest effective_expires_at. The bound is evaluated per action, because a global min/max would let an action covered only by a late-window ref borrow an early one. See zh/authz/capabilities.md §10.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::BACKEND_UNAVAILABLE,
        applies_to: &["event_envelope", "service_call"],
        description: "The selected recording or transcription backend was unavailable.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::BACKUP_REVISION_STALE,
        applies_to: &["device_recovery", "state_resolution"],
        description: "`ak.schema.key_backup.v1.source_commit_ref.realm_commit_id` does not resolve to an accepted RealmCommit on the principal control stream, or `device_generation_ref` does not equal the active `current_device_generation_ref`. A later RealmCommit on the same stream does not by itself make the envelope stale. Receivers MUST refuse to use the envelope as the primary recovery source. See zh/identity/key-management.md §7.6.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::BLOB_REDACTED,
        applies_to: &["state_resolution"],
        description: "Blob has been redacted (ak.redaction accepted) or hard-erased (ak.audit.erasure_receipt published) and is no longer fetchable. Both new presign requests and in-flight (not-yet-expired) presign URLs MUST be rejected with this code. See zh/crypto-media/media-and-blob.md §5.4.4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CALENDAR_ACTIVATION_MISMATCH,
        applies_to: &["event_envelope", "schema_validation"],
        description: "Sub-reason for schema_violation when Strand.schema_refs and the matching metadata.fields profile subtree do not co-occur on the post-patch object, in either direction. Applies to ak.schema.calendar_event.v1 with metadata.fields.calendar. See zh/models/calendar-event.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CALENDAR_EVENT_CANCELLED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A new RSVP targets a Calendar Strand whose schedule status is cancelled. Historical RSVP projection is retained; new responses are refused. The generic Strand stage axis MUST NOT be reinterpreted as calendar status. See zh/models/calendar-event.md. This is an authoring-side and projection-side code for the same reason as calendar_schedule_unavailable: the cancelled status lives in the Calendar subtree plaintext.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CALENDAR_SCHEDULE_UNAVAILABLE,
        applies_to: &["event_envelope", "state_resolution"],
        description: "An RSVP or occurrence expansion was attempted while the deterministic Calendar schedule winner is encrypted_unresolved rather than available. See zh/models/calendar-event.md. This is an authoring-side and projection-side code, never a server admission gate: deciding readability requires the Calendar subtree plaintext, so gating admission on it would fork the accepted set between e2ee and plaintext Realms.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CALENDAR_TZDB_MISMATCH,
        applies_to: &["event_envelope", "service_call", "projection"],
        description: "The signed schedule tzdb_version is outside the receiver's executable release set declared in ServiceDescribe.calendar_tzdb_versions. The receiver MUST fail closed or mark instant projection unresolved and MUST NOT substitute a nearby or newer release. See zh/models/calendar-event.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CALL_MODERATION_UNAUTHORISED,
        applies_to: &["service_call", "event_envelope"],
        description: "A moderator action (kick / ban / force-mute / end-for-all, via `ak.call.signal{moderation}` or a `ak.call.state` moderation field) was attempted by an actor lacking `ak.call.moderate`. Reducer / receiver MUST reject. See zh/crypto-media/webrtc-signaling.md §3a (kick / ban / end-for-all) and §6.1 (force-mute via `mute_state{by=moderator}`).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CALL_PARTICIPANT_REMOVED,
        applies_to: &["service_call"],
        description: "A participant whose `(actor_id, device_id)` has an effective kick in `call_moderation`, or whose actor has an effective ban there, attempted to re-establish a media leg or re-issue a join token. Token issuer / SFU MUST refuse; a banned actor MUST NOT rejoin until the ban is lifted. See zh/crypto-media/webrtc-signaling.md §3a.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CALL_STATE_TERMINAL,
        applies_to: &["event_envelope"],
        description: "An `ak.call.state` event attempted to transition `state_transition.from` out of a terminal value (`ended` / `missed` / `failed` / `cancelled`). Call lifecycle is monotonic; the reducer MUST `failed_precondition`. Capture lifecycles use orthogonal per-segment transition typed results. See zh/crypto-media/call-state.md §4.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CALL_STATE_TRANSITION_INVALID,
        applies_to: &["event_envelope"],
        description: "A `ak.call.state` event requested a `state` transition from a non-terminal state that is not listed in the legal-successor table (transitions out of a terminal state use `call_state_terminal` instead). The reducer MUST `failed_precondition`. See zh/crypto-media/call-state.md §4.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CALL_SUMMARY_INVALID,
        applies_to: &["event_envelope"],
        description: "A `ak.call.summary` event was rejected because its `final_state` is not a terminal call state, the referenced `call_id` has no terminal `ak.call.state` head, or a divergent summary already exists for the call (the summary typed current result is write-once). Reducer MUST `failed_precondition`. See zh/crypto-media/call-state.md §7.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CBOR_BOUNDS_INVALID,
        applies_to: &["encoding", "schema_validation"],
        description: "A hand-written deterministic CBOR structure (e.g. the mls_governance_binding GroupContext extension) violates v1 decode bounds: a single array/map declares or contains more than 65536 items, or a string / byte string / array / map header declares a length or item count exceeding the remaining input bytes (capacity bomb). Decoder MUST reject (top-level schema_violation) before allocating buffers sized from the declared length. See zh/conformance/scalability-constraints.md section 2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CBOR_NOT_DETERMINISTIC,
        applies_to: &["encoding", "schema_validation"],
        description: "A hand-written CBOR structure violates RFC 8949 section 4.2 deterministic encoding requirements: indefinite-length items (map 0xbf, array 0x9f, string 0x5f/0x7f), non-minimal length encoding, or unsorted map keys. Receiver MUST reject (top-level schema_violation) instead of normalising. See zh/conformance/scalability-constraints.md section 2 and zh/crypto-media/encryption-and-audit.md section 2.5.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CHALLENGE_EXPIRED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A challenge proof was submitted whose issuance is older than `max_proof_age`. The reducer MUST reject with failed_precondition and MUST NOT auto-renew; the applicant must obtain a fresh challenge_id. See zh/governance/join-policy.md §3.1 and §4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CHALLENGE_FAILED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A join-policy challenge gate answer (e.g. CAPTCHA / proof-of-work / knowledge challenge) carried by a membership admission request failed verification.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CHALLENGE_PROOF_INVALID,
        applies_to: &["auth_decision", "service_call"],
        description: "A runtime challenge proof attached to `ak.member.state{join}.gate_proofs[]` fails verification (signature / freshness / verifier domain). Freshness here is the replay/binding freshness carried by the proof itself; a proof issued beyond max_proof_age is challenge_expired instead, and the two reasons are mutually exclusive. See zh/governance/join-policy.md §4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CIRCLE_COUNT_EXCEEDED,
        applies_to: &["event_envelope", "state_resolution"],
        description: "Reducer rejected a `ak.circle.create` exceeding the per-Realm active Circle cap, or a `ak.circle.member.state -> join` that would exceed the per-actor active MLS-backed Circle cap. Caps bound cascade/delivery fanout and the M+R MLS-rotation amplification of a single membership change (zh/conformance/scalability-constraints.md §5, zh/models/circle.md §10).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER,
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition on ak.circle.member.state -> join when target actor is not yet a `join` member of the parent Realm. Circle.members âŠ† Realm.members is a hard invariant. See zh/models/circle.md §9.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CIRCLE_NOT_ACTIVE,
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when scope_circle_id points at a Circle whose state is archived or tombstoned. See zh/models/circle.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CIRCLE_REALM_MISMATCH,
        applies_to: &["schema_validation", "state_resolution"],
        description: "Sub-reason for schema_violation when an object's scope_circle_id references a Circle whose realm_id does not match the object's realm_id. See zh/models/circle.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CLAIM_INVALID,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A claim, attestation, or invite / binding proof submitted for membership or invitation admission is malformed, unverifiable, or fails policy checks.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CONSENT_REVOKED,
        applies_to: &["auth_decision"],
        description: "Authorization outcome when a cached consent decision is re-evaluated and the underlying consent has been revoked; the stale cache entry MUST NOT authorize the action. See zh/conformance/conformance-vectors.md §3.5 (ak.vector.consent.cache_invalidation.v1).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CONSENT_WITHDRAWN,
        applies_to: &["event_envelope", "state_resolution"],
        description: "Required recording or transcription consent was withdrawn.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED,
        applies_to: &["identity_creation", "proof_verification"],
        description: "The signed proof audience, origin or trust_domain does not match the current request context; the verifier rejects it before any state transition.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CROSS_REALM_STRUCTURAL_RELATION,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A structural `contains` Relation was submitted that would cross Realm boundaries. Structural containment (Board â†’ List â†’ Strand / Space hierarchy) MUST stay within a single Realm; cross-Realm links use the dedicated `ak.relation.*` non-structural kinds. See zh/models/relation.md §4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CURSOR_EXPIRED,
        applies_to: &["client_sync"],
        description: "Cursor's `x` expiry is in the past; caller MUST request a fresh cursor.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CURSOR_INTEGRITY_INVALID,
        applies_to: &["client_sync", "encoding"],
        description: "Cursor failed the §8.3.1 integrity check: the stateful `h` handle is unknown / revoked / expired / cross-bound, or its stored binding (principal / device / service / filter_digest / purpose) does not match the authenticated request. Distinct from cursor_expired (TTL) and cursor_unrecognized (cross-service portability miss). Triggered before any server-side state advancement (/account/subscribe after= resume, X-Arkret-Wait-For release, dropped/resync_required recovery; to-device queue deletion is decoupled from cursors per client-sync.md §10.1). Client MUST clear local cursor cache and restart from initial /account/subscribe.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CURSOR_REVOKED,
        applies_to: &["client_sync", "encoding"],
        description: "Cursor passed syntax and integrity validation but is present in the issuing service's revocation set. Treated as an authority revocation, not tamper; endpoint MUST NOT advance server-side state.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::CURSOR_UNRECOGNIZED,
        applies_to: &["client_sync"],
        description: "Cursor decoded successfully but cannot be used by this service because it is a stateful handle issued by another service. This is a cross-service portability miss, not TTL expiry and not local integrity failure; caller MUST restart sync from a fresh cursor.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DECRYPTION_PENDING,
        applies_to: &["client_sync"],
        description: "Recipient cannot decrypt the targeted MLS epoch yet; client MUST surface a placeholder and continue retrying within the configured window.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DEPENDENCY_MISSING,
        applies_to: &["batch_item", "federation_transaction"],
        description: "The item cannot yet be verified because an exact Event, RealmCommit, predecessor, proof, or other signed dependency is absent. Federation submit items MUST include at least one non-empty typed missing set; independent complete items remain eligible for acceptance. Dual-registered with the top-level service code.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DEVICE_DIRECTORY_UNAVAILABLE,
        applies_to: &["service_call"],
        description: "The requester's own Station could not obtain or verify a current attested device projection for an exact (account_id, device_id) on this call. It reports only the fetching Station's result, never target state, and MUST NOT be rendered as an omitted row or an empty device list. See zh/crypto-media/device-lifecycle.md section 8.2.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DEVICE_GENERATION_FENCED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "The receiver knows an authenticated device-generation revocation or the security command fails the current generation revision check. New affected live submissions are fenced; ordinary historical eligibility is recomputed from the signed authority context and authenticated closures, not the receiver arrival time.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DEVICE_MESSAGE_ID_CONFLICT,
        applies_to: &["event_envelope", "client_sync"],
        description: "A to-device retry reused the same device_message_id with different canonical target content. The queue service MUST return duplicate_conflict with this reason_code and MUST NOT enqueue a replacement message. Scheduled-send plan convergence is keyed independently by scheduled_send_id and account-data CAS; durable ak.message.create identity conflicts are keyed only by the content-bound Event.event_id.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DEVICE_REANCHOR_AUTHORIZE_MISMATCH,
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "The atomic replacement ak.device.authorize payload digest, principal, device, session, or enrollment-authority proof does not exactly match the binding in ak.device.reanchor. Dual-registered as a reason_code and a top-level service code (see codes[]).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DEVICE_RESULT_UNAVAILABLE,
        applies_to: &["service_call"],
        description: "Single non-enumerating device directory failure. Absent, invisible, unrelated, revoked, fenced and policy-denied targets MUST all use this one value so a caller cannot probe device existence or revocation state. See zh/crypto-media/device-lifecycle.md section 8.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_BINDING_INVALID,
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "The ak.self.events.command.submit.v1 Direct Conversation binding-integrity stage rejected an ak.direct_conversation.bound Event because its issuer, pair key, authorization basis, Realm role, exact two-member set, main Strand, founding unit digest, or founding MLS references did not match accepted authoritative facts. The rejection occurs before result application, is atomic, and writes nothing; see contract-registry.json operation_registry.direct_conversation_admission_mappings.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_FOUNDING_UNIT_INVALID,
        applies_to: &["event_envelope", "service_call", "federation_transaction"],
        description: "A Direct Conversation founding unit is not the closed caller-authored four-Event unit. Causes include a count other than four, wrong wire order, a missing peer or founder ak.member.state{join}, a missing ak.strand.create, a fifth Event, a mixed actor/pair/profile/Realm, any envelope field naming a predecessor Event inside the unit, a missing founder-member expected_revision null genesis guard, an envelope realm_id that is not retype(events[0] event_id), a main_strand_id that is not retype(events[3] event_id), a founding_unit_digest that does not match the recomputed value, or any request field asserting a service-allocated identifier, reservation handle or materialization draft. The whole unit is rejected with zero writes. See zh/identity/contact-and-direct-conversation.md sections 5.5 and 6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_INVITE_FORBIDDEN,
        applies_to: &["event_envelope", "auth_decision"],
        description: "The ak.self.events.command.submit.v1 active-profile invite guard rejected an ak.invite.create or ak.invite.third_party Event targeting a Direct Conversation. A pair-external candidate is classified earlier as direct_conversation_third_party_member_forbidden; the atomic founding peer join is not an invite. The rejection writes nothing; see contract-registry.json operation_registry.direct_conversation_admission_mappings.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_MEMBER_COUNT_INVALID,
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "The ak.self.events.command.submit.v1 exact-two profile gate rejected a new write because the Direct Conversation binding or authoritative membership projection did not resolve to exactly two distinct principal participants. Existing stable conversations are returned read-only by ak.self.direct_conversation.read.resolve.v1 as suspended with blocker member_count_invalid, never as a write rejection. The rejection writes nothing; see contract-registry.json operation_registry.direct_conversation_admission_mappings.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_PAIR_MATERIALIZATION_CONFLICT,
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "A second accepted Direct Conversation Realm was observed for the same pair_key while both carried apparently valid founder admission, four exact Events, four consecutive source RealmCommits and founding-authority evidence, indicating slot, cutover-fence or signature equivocation by a trusted current Station. Both Realms freeze new Message, membership, policy, MLS and binding writes and all evidence is retained; implementations MUST NOT pick a winner by Realm-token lexical order or arrival order, tombstone either Realm, or migrate history. See zh/identity/contact-and-direct-conversation.md §5.7.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_PARTICIPANT_AUTHORITY_DENIED,
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "The current governance Station's active ak.authority.direct_conversation_participant.v1 evaluator rejected an Event-mapped allowlisted action because it could not establish every required immutable binding, exact participant, active membership, Realm/Strand/current scope-derived MLS group-and-epoch cross-binding, lifecycle, resource, directional Contact, device, or Agent input. The ak.self.events.command.submit.v1 rejection exposes only this non-enumerating reason and writes nothing. Encrypted Signal product actions use their own outer admission carrier and recipient policy, never this Event reason. Consent, created_by, a local projection row, Realm owner aggregation, or an arbitrary Event/current result cannot substitute; see contract-registry.json operation_registry.direct_conversation_admission_mappings.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_ROOT_MASK_VIOLATION,
        applies_to: &["event_envelope", "auth_decision"],
        description: "The ak.self.events.command.submit.v1 technical-root phase-mask stage rejected an operational, grant, member-governance, policy, or terminal action outside the exact active Direct Conversation founding/materialization mask. Root owner aggregation cannot bypass participant authority or target the other participant. The rejection writes nothing; see contract-registry.json operation_registry.direct_conversation_admission_mappings.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_SLOT_ALREADY_COMMITTED,
        applies_to: &["service_call", "federation_transaction"],
        description: "The founder's current Station already closed its local (founder_id, trust_domain_id, pair_key) founding slot with a different unit, so this unit is refused with zero writes. Carried under conflict. The caller MUST re-resolve the existing coordinates through ak.self.direct_conversation.read.resolve.v1 instead of authoring another unit; the service MUST NOT accept a second unit, degrade it to a partial acceptance or quarantine it. A byte-identical replay of the committed unit is not this code: it returns the same four byte-identical source RealmCommits without changing the fourth committed_at. See zh/identity/contact-and-direct-conversation.md section 5.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_SPACE_FORBIDDEN,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A Space create/update/parent/archive/restore/tombstone operation targeted a Realm carrying ak.profile.direct_conversation_realm.v1. Space containers are not permitted in this constrained Realm role.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_TERMINAL_FORBIDDEN,
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "The ak.self.events.command.submit.v1 profile terminal guard rejected ak.realm.destroy or ak.realm.tombstone against the canonical Direct Conversation Realm. DM coordinates are permanent and successor-free. Reversible archive/freeze and their reverse transitions remain subject to ordinary authority and do not match this reason. The rejection writes nothing; see zh/identity/contact-and-direct-conversation.md §8.1 and contract-registry.json operation_registry.direct_conversation_admission_mappings.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_CONVERSATION_THIRD_PARTY_MEMBER_FORBIDDEN,
        applies_to: &["event_envelope", "auth_decision"],
        description: "The ak.self.events.command.submit.v1 candidate-pair membership stage rejected an invite or join whose candidate ActorId was not one of the immutable Direct Conversation binding's two exact ActorIds. This reason has precedence over direct_conversation_invite_forbidden when both predicates match. Group expansion requires a new ordinary Collaboration Realm. The rejection writes nothing; see contract-registry.json operation_registry.direct_conversation_admission_mappings.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DIRECT_DOWNLOAD_DISALLOWED_PRESIGN_FORBIDDEN,
        applies_to: &["authz", "service_call"],
        description: "A presigned blob URL was requested for a Realm-owned blob whose current effective asset policy does not explicitly set direct_download_allowed=true. Missing, unverifiable, non-effective, omitted, or false policy state all fail closed. The service MUST deny presign and require authenticated fetch or an authorized proxy path.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::DUPLICATE_CONFLICT,
        applies_to: &["client_sync"],
        description: "An idempotency key or non-Event stable identifier was reused with different canonical content. For to-device device_message_id the send operation rejects the conflicting enqueue with reason device_message_id_conflict. Event Envelope carried-ID mismatches use event_id_digest_mismatch; confirmed full-hash collision evidence uses witness_disagreement and whole-group quarantine per zh/sync/operations-sync.md §12.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED,
        applies_to: &["service_call"],
        description: "A backend media SDK supplied an SFrame / frame encryption key from a source other than the Arkret MLS exporter (label `ak.rtc-frame-key/v1`). Clients MUST reject and refuse to publish / subscribe media. Closes the attack where backend cloud key escrow could intercept ostensibly-E2EE media. See zh/crypto-media/media-service-binding.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED,
        applies_to: &["schema_validation"],
        description: "Sub-reason for schema_violation when an actor-supplied payload illegally carries `effective_scope` where the object schema reserves that name for a read-only materialized projection. Both surfaces are decided by schema: the create shape bans the member (event-payload.schema.json#/$defs/relation_create_object), and the update shape bans the `effective_scope` / `effective_scope.*` patch paths (#/$defs/relation_update_payload), registered in registry/reducer-managed-path-registry.json. The Event envelope instead requires producer-signed `scope_ref`; the receiver derives the scope from payload and frozen pre-state, verifies exact equality, and only then may copy it into the object's effective_scope projection. See zh/models/circle.md §6.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::EGRESS_POLICY_DENIED,
        applies_to: &["authz", "federation_transaction", "service_call"],
        description: "An outbound Applet, MIMI, or federation transfer would emit plaintext or derived content without the egress grant, data-class allowance, or destination policy required for that transfer. It also covers SSRF address-class denial: a server-side fetch whose resolved target (after redirect / Alt-Svc) hits a forbidden address class such as cloud metadata, internal, or loopback is rejected with this reason, for example MIMI proxy_download. The sender MUST reject the transfer before releasing content. See zh/sync/api-conventions.md §11.2 and zh/extensions/mimi-interop.md §11.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::EPOCH_UPDATE_REQUIRED,
        applies_to: &["crypto", "service_call", "state_resolution"],
        description: "Membership, policy, or governance checkpoint changed and the current MLS epoch does not yet have a winning ak.mls.commit whose governance_binding covers that checkpoint. Clients MUST pause new application messages for the scope until the effective epoch catches up. See zh/crypto-media/encryption-and-audit.md §2.4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ERASURE_PENDING_IS_TERMINAL,
        applies_to: &["account_status", "event_envelope", "state_resolution"],
        description: "An Account Authority issuer-ledger mutation attempted to create a successor after `erasure_pending`. The state is terminal because erasure physically destroys data; the current-head transaction and every receiver MUST reject the successor and retain the terminal record. See zh/identity/account-lifecycle.md §3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ERASURE_RECEIPT_AUTHORITY_INVALID,
        applies_to: &["account_status", "identity_resolution", "service_call"],
        description: "The erasure receipt issuer, signing verification method, service transport identity or accepted-at authority chain does not establish authority for the claimed erasure scope. The receiver MUST reject before deletion or durable acknowledgement.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ERASURE_RECEIPT_PROOF_INVALID,
        applies_to: &["account_status", "identity_resolution", "service_call"],
        description: "One or more required erasure receipt proofs fail canonical transcript, signature, threshold or validity-window verification. The receiver MUST reject before deletion or durable acknowledgement.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ERASURE_RECEIPT_STUB_BINDING_MISMATCH,
        applies_to: &["account_status", "identity_resolution", "service_call"],
        description: "The retained stub carried with an erasure receipt does not bind the receipt scope, subject, terminal status or required verification coordinates. The receiver MUST reject before deletion or durable acknowledgement.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ERASURE_RECEIPT_STUB_DIGEST_MISMATCH,
        applies_to: &["account_status", "identity_resolution"],
        description: "Retained erasure stub bytes do not match retained_stub_digest in the erasure receipt. Verifier MUST reject the receipt and treat the erasure as not completed (fail closed).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ERASURE_REQUEST_ALREADY_PENDING,
        applies_to: &["account_status"],
        description: "Sub-reason for failed_precondition on ak.gate.account.command.request_erasure.v1: the account already holds a live self-initiated erasure intent whose erasure_pending AccountStatusRecord has not yet been signed. The client MUST NOT submit a second distinct request; it either awaits the recorded intent or withdraws it inside the deployment-granted withdrawal window. Once the record is signed, requests fail at authentication with account_erased instead. See zh/identity/account-lifecycle.md section 8.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::EVENT_ID_DIGEST_MISMATCH,
        applies_to: &["event_envelope"],
        description: "Sub-reason for schema_violation when the carried event_id does not equal the value re-derived from the Event's own canonical content per zh/conformance/encoding.md section 4.0. Receivers MUST re-derive and compare before using event_id for deduplication, indexing, routing, idempotency or authorization, and MUST NOT report this as proof_invalid: the distinct code is what localises cross-implementation canonical-JSON divergence and what prevents a forged event_id from entering the duplicate_conflict quarantine path.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::EVIDENCE_RECIPIENT_MISMATCH,
        applies_to: &["moderation_decision", "moderation_report"],
        description: "A moderation evidence package's encrypted_to recipient does not match the declared recipient_public_key_ref binding. The submission MUST reject. See governance/content-moderation.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::EXPIRED_INVITE_TOKEN,
        applies_to: &["state_resolution"],
        description: "Invite token's expires_at has passed when claim is attempted. Internal-only reason code; the wire response MUST be the unified non-enumerable `not_found` per zh/sync/third-party-invites.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::EXTERNAL_RATE_LIMITED,
        applies_to: &["service_call"],
        description: "Bridge / applet transaction failed because the external upstream service rate-limited the request, distinct from the local `rate_limited` (this service's own limit). Carried as a bridge_error error_code with error_class=rate_limit; the caller MAY retry after retry_after_ms. See zh/extensions/applet-schema.md §7.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::FOCUS_MISMATCH,
        applies_to: &["service_call", "auth_decision"],
        description: "Media token exchange (ak.self.call.media.exchange.issue_token.v1) requested a `focus_id` different from the already-committed `ak.call.state.session_focus`. Token issuer MUST reject; clients MUST re-target the established focus rather than retrying with the original preference. See zh/crypto-media/media-service-binding.md §3 and §5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::FOCUS_UNAVAILABLE_FOR_CLIENT,
        applies_to: &["service_call"],
        description: "Client cannot use the committed `session_focus` (e.g. focus not in local `foci_preferred[]`, region restricted, capability mismatch). Client MAY fail closed without joining the call rather than silently degrading; clients MUST NOT pick a different focus to bypass `session_focus_no_split_brain`. See zh/crypto-media/media-service-binding.md §5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::FOUNDING_DEVICE_COMMITMENT_MISMATCH,
        applies_to: &["pcr_genesis"],
        description: "The FoundingDeviceDescriptor, authorize payload, device/HPKE digests, algorithms or root creation transcript are not byte-for-byte consistent.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::GATE_CHECK_FAILED,
        applies_to: &["auth_decision", "state_resolution"],
        description: "External applicant-facing generic join gate failure. Wire response MUST NOT reveal whether a claim was absent, revoked, issuer-unreachable, parent-membership-missing, or challenge-invalid; detailed diagnostics are audit/reviewer-only. See zh/governance/join-policy.md §5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::GOVERNANCE_BINDING_MISMATCH,
        applies_to: &[
            "event_envelope",
            "state_resolution",
            "federation_transaction",
        ],
        description: "An MLS Commit's mls_governance_binding GroupContext extension does not match the accepted key-access state, Event payload or active epoch chain: scope/base/epoch fields disagree, the unsigned monotonic key_access_revision counter differs from the Station's accepted key-access revision, or extension bytes differ from the Event payload. The receiver MUST reject the Commit - and, on a federation push, the batch - rather than advance an epoch under a forged or stale binding. See zh/crypto-media/encryption-and-audit.md §2.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY,
        applies_to: &["event_envelope", "auth_decision"],
        description: "An `ak.capability.grant` attempts to grant actions[] / resources[] that exceed the union of its `issuer_authority_refs[]` at the issuing authority commit basis. Holding the `ak.capability.grant` action alone does not permit minting authority the issuer does not itself hold; reducers MUST fail closed (schema_violation for actions/resources over-scope, failed_precondition when the issuer does not hold the required upper bound at that basis). See zh/authz/capabilities.md §3.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::GRANT_RELINQUISH_NOT_SUBJECT,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A ak.capability.relinquish named a grant whose subject is not the actor. Relinquish is subject-only precisely so it needs no revoke capability; allowing any other actor would turn it into an unauthorized revocation. The authority-root typed current result is not a grant and can never be a relinquish target. The rejection MUST NOT disclose whether the target exists.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::GRANT_VALIDITY_WINDOW_EMPTY,
        applies_to: &["auth_decision", "event_envelope"],
        description: "A capability grant's normalized effective validity window is empty: effective_not_before >= effective_expires_at after intersecting its temporal constraints. Reducer MUST reject the grant. See zh/authz/capabilities.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::HANDLE_HOMOGRAPH_FORBIDDEN,
        applies_to: &["schema_validation", "service_call"],
        description: "Handle registration collided with the same authority-local handle-namespace UTS #39 skeleton index or failed the authority's declared Highly Restrictive registration policy. This is registration policy, not canonical equality; the skeleton never enters wire or proof bytes. See zh/identity/identity-handles.md §17.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::HARASSMENT,
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: harassment.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::HATE_SPEECH,
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: hate speech / targeted attacks against a protected group.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::HUMAN_APPROVAL_REQUIRED,
        applies_to: &["auth_decision", "service_call"],
        description: "An agent runtime requested a high-risk session scope that requires out-of-band controller approval. The top-level service error is claim_required; error.details carries this reason_code and an opaque approval_request_id. The runtime MUST NOT receive a CAPTCHA, OTP, or browser challenge. See zh/identity/key-management.md §3.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::IDENTITY_CREATION_ALREADY_ACCEPTED,
        applies_to: &["identity_creation", "service_call"],
        description: "The exact Principal Control Realm genesis for this provisional identity has already been accepted and MUST NOT be abandoned. The Account Authority checks the frozen identity creation operation and durable PCR submission/result evidence. An uncertain dispatch is not evidence of non-acceptance. Return the stable terminal result without creating an orphan anchor tombstone, suppressing the checkpoint or releasing the lease. Established identities use the account deletion / erasure path. See zh/identity/key-management.md §5.0.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::IDENTITY_CREATION_CHALLENGE_ALREADY_CONSUMED,
        applies_to: &["identity_creation", "service_call"],
        description: "The identity-binding challenge was already consumed and the request is not a byte-identical replay whose canonical request digest matches the stored successful outcome. The Account Authority MUST reject it before any state transition; an exact replay returns the recorded outcome instead of this code.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::IDENTITY_CREATION_CHALLENGE_EXPIRED,
        applies_to: &["identity_creation", "service_call"],
        description: "The persisted identity-binding challenge expired before first successful consumption. The Account Authority MUST reject before publishing the DID operation or relaying PCR genesis, and the client must obtain a fresh challenge for the same frozen draft.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::IDENTITY_CREATION_LEASE_FENCED,
        applies_to: &["identity_creation"],
        description: "The identity-creation lease fence is no longer current. A stale holder cannot publish or complete the frozen account/principal registration.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::IDENTITY_LINK_NO_LONGER_VISIBLE,
        applies_to: &["identity_resolution"],
        description: "An identity-link resolution was invalidated because the linked identity is no longer visible to the requester after a membership transition or capability revoke; directory / sync / invite caches MUST drop the stale link. See zh/conformance/conformance-vectors.md §3.5 (ak.vector.identity_link.eager_invalidation.v1).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::IDENTITY_LINK_POLICY_TIGHTENED,
        applies_to: &["identity_resolution"],
        description: "An identity-link resolution was invalidated because the governing visibility / link policy was tightened after the link was cached. See zh/conformance/conformance-vectors.md §3.5 (ak.vector.identity_link.policy_tightening_invalidation.v1).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::IDENTITY_METHOD_EVIDENCE_INVALID,
        applies_to: &["identity_resolution", "auth_decision"],
        description: "Submitted method_history_evidence fails independent verification: broken inception/current hash chain, SCID mismatch, invalid controller proof, unmet witness threshold, or stale evidence. An Applet-managed principal MUST carry a complete webvh_log; did:web snapshots, did:key expansion and service attestation are not substitutes. See zh/extensions/applet-integration.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ILLEGAL,
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: content alleged to violate applicable law (CSAM, threats, IP infringement, etc.).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INITIAL_SESSION_REQUEST_MISMATCH,
        applies_to: &["identity_creation"],
        description: "The InitialSessionGrantRequest digest, device id, audience, scope ceiling, or RFC 7638 thumbprint does not match the frozen registration and handoff holder binding.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INTEGRITY_FAILED,
        applies_to: &["event_envelope", "service_call"],
        description: "A recording or transcription artifact failed digest, encryption-context, or integrity verification.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INTERNAL_ERROR,
        applies_to: &["batch_item"],
        description: "Per-event rejection reason in an Applet edge transaction response (rejected[].reason_code) when the receiving applet hit an internal failure while processing that item; mirrors the top-level internal_error endpoint code at batch-item granularity. See zh/extensions/applet-integration.md §7.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVALID_ACK_TOKEN,
        applies_to: &["service_call"],
        description: "A to-device message ack carried an ack token that does not correspond to a delivered to-device cursor (unknown, malformed, or already-superseded). Carried under param_invalid. See zh/sync/client-sync.md §10.1 and zh/sync/service-http-binding.md device_messages/ack.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVALID_CANONICAL_JSON,
        applies_to: &["encoding"],
        description: "Bytes are not valid Arkret canonical JSON (sorted keys, integer-only numbers, escape rules per encoding.md §1).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVALID_CURSOR,
        applies_to: &["client_sync", "encoding"],
        description: "Cursor payload fails the §8.2 / §8.3 cursor syntax or schema before integrity verification. HTTP endpoints surface this as top-level `param_invalid` with reason_code `invalid_cursor`. Expiry uses `cursor_expired`; handle lookup or cross-binding failures use `cursor_integrity_invalid`; cross-service portability misses use `cursor_unrecognized`.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVALID_ENCODING,
        applies_to: &["encoding"],
        description: "Generic encoding violation (HLC format, UUIDv7 format, base64url alphabet, etc.) not otherwise classified.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVALIDATED_BY_RATE_LIMIT,
        applies_to: &["auth_decision"],
        description: "An out-of-band invite code attempt was invalidated because the per-code attempt rate limit was exceeded. See zh/conformance/conformance-vectors.md §3.11 (ak.vector.invite.oob_code_entropy.v1).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVITE_ALREADY_TERMINAL,
        applies_to: &["event_envelope", "auth_decision"],
        description: "An Invite state transition is rejected because the target Invite is already in a terminal flow state (`accepted` / `rejected` / `revoked` / `revoked_by_capability_loss` / `revoked_by_inviter_left` / `expired` / `invalidated_by_rate_limit`). Note the Invite `state` is the invite flow axis (not the generic object lifecycle axis); see zh/models/governance-objects.md §5.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVITE_DIRECTED_INVITEE_MISMATCH,
        applies_to: &["event_envelope", "state_resolution"],
        description: "The invitee account carried by an ak.invite.accept / cancel / revoke payload and the invite_directed_invitee record stored for that InviteId are not both absent and not both present and byte-equal. It closes both directions of zh/models/governance-objects.md section 5.3: a third-party Invite cannot release another account's directed slot with a forged invitee, and a directed Invite cannot hold its slot forever by omitting the field.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVITE_KIND_REQUIRES_REVOKE,
        applies_to: &["event_envelope", "auth_decision"],
        description: "ak.invite.cancel targeted a token/3PID Invite without a stored direct invitee binding. Only ak.invite.revoke may terminate that Invite class.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVITE_LIVE_TARGET_OCCUPIED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "Sub-reason for failed_precondition when ak.invite.create targets an account whose Realm live-target slot invite_live_target is already claimed by another live directed Invite. The Event is not accepted, enters no canonical history and derives no typed current result write; the closed error.details is InviteLiveTargetOccupiedProblem carrying the occupying invite_id and create_event_id. See zh/models/governance-objects.md section 5.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::INVITE_OOB_ENTROPY_TOO_LOW,
        applies_to: &["auth_decision"],
        description: "An out-of-band invite code was rejected because its entropy is below the required floor. See zh/conformance/conformance-vectors.md §3.11 (ak.vector.invite.oob_code_entropy.v1).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::JOIN_POLICY_DUPLICATE_GATE_ID,
        applies_to: &["schema_validation", "state_resolution"],
        description: "Sub-reason for a schema_violation on ak.realm.join_policy where gates[] contains duplicate gate_id values. gate_id MUST be stable and unique within the policy so that audit refs in ak.member.state{gate_proofs[gate_id=â€¦]} are unambiguous. Wire response uses code=schema_violation with reason_code=join_policy_duplicate_gate_id. See zh/governance/join-policy.md §3.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::JOIN_RULE_POLICY_MISMATCH,
        applies_to: &["event_envelope", "auth_decision"],
        description: "Realm `ak.realm.join_rule` and `ak.realm.policy_bundle` declare conflicting join modes (e.g., `restricted` with no gate configuration, or `knock_restricted` with all-auto gates degrading to `restricted`). See zh/governance/join-policy.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::KEY_BACKUP_WIRE_SCHEMA_REQUIRED,
        applies_to: &["schema_validation"],
        description: "Station device/key surface received a `ak.keys.backups.*` request body that does not validate as `ak.schema.key_backup.v1`. Wire backups MUST carry the dedicated key-backup envelope with `series_id` and `series_seq`; client-local secret-storage envelopes are not accepted on wire endpoints. See zh/crypto-media/device-lifecycle.md §11.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::KEYPACKAGE_CLAIM_RATE_LIMITED,
        applies_to: &["service_call"],
        description: "Internal server-side audit reason recorded when an MLS KeyPackage claim exceeds the per-(requester_id, target_principal_id) rate limit. The outward response MUST stay anti-enumeration (generic `claim_failed` or rate-limited envelope) and MUST NOT leak target existence; this reason is the canonical audit-log token only. See zh/conformance/scalability-constraints.md §6 and zh/identity/key-management.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::KEYPACKAGE_EXPIRED,
        applies_to: &["keypackage_lifecycle"],
        description: "A reusable last-resort KeyPackage was revoked because its expires_at deadline elapsed. It MUST NOT be returned by a later claim. This is a revocation reason, not a KeyPackage lifecycle state. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::KEYPACKAGE_ROTATED,
        applies_to: &["keypackage_lifecycle"],
        description: "A reusable last-resort KeyPackage was revoked because its holder came online and rotated it to fresh init / encryption key material. This is a revocation reason, not a KeyPackage lifecycle state. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH,
        applies_to: &["event_envelope", "auth_decision"],
        description: "An MLS Welcome arrived with a `claim_envelope` whose canonical signing input does not match the Welcome's actual intended_realm_id / claim_id / requester_actor_id, or the envelope signature does not chain to the requester's PCR current accepted device signing key and authorization Event. See zh/crypto-media/encryption-and-audit.md §2.6.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::LAST_RESORT_NOT_SUPPORTED,
        applies_to: &["service_call", "feature_discovery"],
        description: "A KeyPackage claim requested a last-resort fallback from a server that does not advertise `ak.feature.mls_last_resort_keypackage.v1`. The server MUST continue to fail closed on an empty single-use pool and MUST NOT return a `last_resort=true` package. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::LAST_RESORT_REALM_AFFINITY_VIOLATION,
        applies_to: &["service_call", "auth_decision"],
        description: "An attempt to reuse a last-resort KeyPackage outside its `intended_realm_id` Realm-scoped last-resort pool. Servers MUST reject. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::LAST_RESORT_ROTATION_REQUIRED,
        applies_to: &["service_call", "crypto"],
        description: "A holder that joined groups via a last-resort KeyPackage came online but has not rotated the package and performed the required group self-updates. Those updates do not retroactively restore old Welcome confidentiality. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::LEGAL_HOLD_ACTIVE,
        applies_to: &["auth_decision"],
        description: "Requested operation targets a blob / object currently under legal hold. ak.self.blob.command.presign.v1 / ak.blob.delete / redaction-equivalent operations MUST be rejected with this code; legal hold takes precedence over capability and TTL. See zh/crypto-media/media-and-blob.md §5.4.4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEDIA_NEGOTIATION_TIMEOUT,
        applies_to: &["event_envelope", "state_resolution"],
        description: "Call connection or capture media negotiation exceeded the registered timeout.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED,
        applies_to: &["auth_decision"],
        description: "An SFU / MCU attempted to negotiate plaintext-decrypting media role without a matching Realm policy plaintext_visible_services[] entry whose data_classes[] contains media_plaintext, OR without the active media key-access revision covering media_service_decrypts=true. Free-text purposes do not grant authority. MUST be rejected; the SFU may still act as opaque RTP relay. See zh/crypto-media/media-service-binding.md §8.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEDIA_PLAINTEXT_WARNING_REQUIRED,
        applies_to: &["auth_decision"],
        description: "A client attempted to join a call where media_service_decrypts=true without first displaying the required prominent plaintext-service warning and obtaining explicit second confirmation. The client MUST reject the join before releasing a token or media key. See zh/crypto-media/media-service-binding.md §8.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEDIA_SERVICE_BINDING_UNCOVERED,
        applies_to: &["service_call", "state_resolution"],
        description: "A media token / focus join was presented but the current MLS epoch governance binding does not cover the `ak.realm.media_service` binding the token relies on (token issuer trust-root sealing is unverifiable). The verifier MUST fail closed instead of trusting an uncovered media binding. See zh/crypto-media/media-service-binding.md §2.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEDIA_SERVICE_FOCI_REQUIRED,
        applies_to: &["service_call", "schema_validation"],
        description: "`ak.realm.media_service` is missing the required non-empty `foci[]` list. Services MUST reject payloads that do not declare explicit media foci and MUST NOT infer a focus from unrelated endpoint fields. See zh/crypto-media/media-service-binding.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEDIA_SOURCE_UNAVAILABLE,
        applies_to: &["event_envelope", "service_call"],
        description: "The source media required for recording or transcription was unavailable.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEMBER_IDENTITY_PROOF_INVALID,
        applies_to: &["event_envelope", "state_resolution"],
        description: "The MemberIdentity object carried by ak.member.identity.update failed proof validation: proof.payload_digest does not equal the sha256 of the proof-less MemberIdentity RFC 8785 JCS canonical bytes, the signature does not verify under proof.verification_method, or the method is not controlled by the disclosed subject_actor_id. The event MUST NOT be promoted to a verified display identity. See zh/sync/client-sync.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH,
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.member.identity.update replaces[] entry references an event whose payload.identity_payload carrier digest does not equal the declared payload_digest, or references an event under a different (realm_id, member_id, segment). The replacement edge is invalid; receivers MUST NOT remove the referenced event from the effective set on its basis. See zh/sync/client-sync.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEMBER_IDENTITY_STATE_MISMATCH,
        applies_to: &["event_envelope", "state_resolution"],
        description: "The optional expected_state_digest optimistic-concurrency guard on ak.member.identity.update does not equal the current effective-set digest for the same (realm_id, member_id, segment). The server / reducer MUST reject or quarantine the event instead of applying it as a valid replacement. See zh/sync/client-sync.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MEMBER_IDENTITY_UNKNOWN_SEGMENT,
        applies_to: &["event_envelope", "schema_validation"],
        description: "A ak.member.identity.update declared a segment value outside the v1 core enum (member_identity). Receivers MUST reject unknown segment values until a schema / profile revision extends the enum. See zh/sync/client-sync.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH,
        applies_to: &["service_call", "state_resolution"],
        description: "A MIMI facade found a governance binding, but its realm_id, strand_id, mls_group_id, provider DID, or endpoint digest does not match the incoming MIMI room state. Receiver MUST quarantine or reject fail-closed. See zh/extensions/mimi-interop.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING,
        applies_to: &["service_call", "state_resolution"],
        description: "A MIMI facade attempted to project room state, groupInfo, key material, or message data into a Arkret Realm without a verifiable Arkret MLS governance binding. Receiver MUST quarantine or reject fail-closed instead of accepting unauthenticated MIMI state as Realm authority. See zh/extensions/mimi-interop.md §4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MIMI_POLICY_REVISION_MISMATCH,
        applies_to: &["service_call", "state_resolution"],
        description: "A MIMI room policy component does not match the accepted Arkret ak.realm.policy_bundle revision. Facade MUST reject the update until a fresh policy projection is available. See zh/extensions/mimi-interop.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MIMI_ROOM_BINDING_STATUS_TRANSITION_INVALID,
        applies_to: &["state_resolution"],
        description: "A ak.mimi.room_binding Event declared a payload.status value that is not a legal transition from the binding's current status (including an illegal initial status or any write after the terminal revoked state). Reducer MUST reject; the room binding status lifecycle is defined in zh/extensions/mimi-interop.md §4.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE,
        applies_to: &["service_call", "schema_validation"],
        description: "Incoming MIMI room state uses lifecycle, membership, policy, or extension shape not supported by the declared Arkret MIMI interop profile. Facade MUST reject or require a newer profile. See zh/extensions/mimi-interop.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MINIMAL_DISCLOSURE_VIOLATION,
        applies_to: &["moderation_decision", "moderation_report"],
        description: "A moderation evidence package discloses material beyond the minimal-disclosure obligation (for example unrelated plaintext message bodies or MLS private state). The evidence submission MUST reject. See governance/content-moderation.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MISINFORMATION,
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: misleading / false information posing harm.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MLS_ACTIVATION_IRREVERSIBLE,
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when an Event would deactivate, replace or re-run the accepted ak.mls.genesis of an already activated Realm, Circle or Sidecar scope. Activation is a one-way transition with no protocol path back to plaintext. See zh/models/realm-and-space.md section 2.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MLS_ACTIVATION_REQUIRED,
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a Strand / Message / Morph / Blob content or metadata write carries plaintext into a scope whose ak.mls.genesis is already accepted. An activated scope accepts only RFC 9420 application ciphertext. See zh/models/circle.md section 7.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MLS_GOVERNANCE_BINDING_STALE,
        applies_to: &["state_resolution", "auth_decision"],
        description: "Current MLS epoch's key_access_revision does not cover key-access policy components the client wants to act on (for example media_service_decrypts and plaintext_visible_services for a decrypting media service). Receivers MUST refuse to act until a fresh Commit covers the rederived checkpoint. See zh/crypto-media/media-service-binding.md §8.2 and zh/crypto-media/encryption-and-audit.md §2.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MODERATION_CONTROL_SPLIT,
        applies_to: &["policy_decision", "state_resolution"],
        description: "Committed moderation control evidence is internally inconsistent or cannot be verified; downstream decisions depending on it fail closed until a complete valid state is available.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MODERATION_STATE_CONFLICT,
        applies_to: &["auth_decision", "state_resolution"],
        description: "The referenced moderation state cannot be verified as a complete valid projection. Read, write, and distribute paths MUST fail closed. See zh/governance/content-moderation.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MORPH_ALREADY_TERMINAL,
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.redaction` targeting a Morph is rejected because the target Morph is already in terminal state `redacted`.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MORPH_NOT_ACTIVE,
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.morph.archive` / `ak.morph.update` rejected because the target Morph is not in `active` state.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::MORPH_NOT_ARCHIVED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.morph.restore` rejected because the target Morph is not in `archived` state.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::NSFW,
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: not-safe-for-work / explicit adult content posted outside permitted contexts.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::OBJECT_ID_NOT_EVENT_DERIVED,
        applies_to: &["event_envelope"],
        description: "Sub-reason for schema_violation when a create Event carries an object identifier in its payload for an object kind whose id MUST be derived from the create Event's event_id. Create payloads MUST omit the id; the reducer materialises it by retyping the complete event-derived EventId token. See zh/models/common-fields.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::OK,
        applies_to: &["batch_item", "auth_decision", "policy_decision"],
        description: "Sentinel value indicating an item or decision succeeded with no further reason.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::OPERATOR_REJECTED,
        applies_to: &["device_recovery"],
        description: "Recovery-session `rejection_reason_code` value: an operator / admin surface explicitly rejected the session. Closed value set defined in artifacts/schemas/recovery-session.schema.json; completion ownership is defined in zh/identity/security-transactions.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::OTHER,
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: catch-all for reports that do not fit the named categories. MUST be accompanied by a free-text `description` field. See zh/governance/content-moderation.md §3.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PAIRING_EXPIRED,
        applies_to: &["auth_decision", "event_envelope"],
        description: "Agent bootstrap pairing window elapsed before the first runtime key authorization completed. Generic list/get views close the open handle and report readiness not_ready with runtime_key_missing; only the pairing poll may return its operation-local runtime_state=pairing_expired diagnostic. Pairing expiry does not create, revoke or rewrite Realm grants. It never applies to previously keyed Agents: an expired replacement handle only clears open fields and pairing_open readiness.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PAIRING_REQUEST_EXPIRED,
        applies_to: &["auth_decision", "service_call"],
        description: "A `ak.gate.account.command.pair_agent_key.v1` pairing request was presented after its `pairing_expires_at` (or the runtime key-pairing session id has been closed). The endpoint MUST fail closed; the controller MUST initiate a fresh pairing strand. See zh/identity/key-management.md §3.6.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PARTICIPANT_BINDING_INVALID,
        applies_to: &["event_envelope", "service_call"],
        description: "A `ak.call.state` participant's `participant_binding` failed one of: (a) issuer_kid resolution against current `ak.realm.media_service.service_id`; (b) field consistency with the participant entry (`realm_id` / `call_id` / `focus_id` / `actor_id` / `device_id` / `participant_id`); (c) `expires_at` freshness vs event `created_at`; (d) signature verification. Reducer MUST `failed_precondition`. See zh/crypto-media/call-state.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PARTICIPANT_ID_UNRECOGNISED,
        applies_to: &["service_call"],
        description: "Backend (LiveKit / SFU / etc.) signalled `ParticipantConnected` with a `participant_id` that has no matching value in the accepted call roster effective authority-ordered keyed set (or matches a value whose `participant_binding` fails verification). Client MUST refuse to establish media streams for that participant â€” this closes the attack where a compromised backend tries to inject unauthorized participants into the conference. See zh/crypto-media/media-service-binding.md §7.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PATCH_PATH_INVALID,
        applies_to: &["event_envelope"],
        description: "An `ak.schema.patch.v1` patch path violates the ABNF grammar in zh/models/event-and-patch.md §4.2.1 (malformed identifier, quoted identifier, selector or numeric-index form, path > 1024 bytes, or nesting > 16 segments). Parser MUST NOT attempt fallback recovery; reducer rejects with this reason.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PATCH_PATH_REDUCER_MANAGED,
        applies_to: &["event_envelope"],
        description: "An `ak.schema.patch.v1` patch path addresses a field the generic update surface does not own. The normative per-object path set is registry/reducer-managed-path-registry.json (universal minimum set plus per-object-kind additions, minus the named View `state` exemption); the description here is not the criterion and MUST NOT be read as one. The forbidden path and every dotted descendant of it are rejected together. See zh/models/event-and-patch.md §4.2.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PATCH_UNSET_REDACTABLE_FIELD,
        applies_to: &["event_envelope"],
        description: "An `ak.schema.patch.v1` `$op=\"unset\"` addressed a redactable content-carrier slot. The normative path set is registry/redactable-field-registry.json (Message / Morph content pairs; Strand Description and synthesis content pairs) plus any Realm-schema field marked `redactable: true`; the description here is not the criterion. Absence of a content slot on the materialized object is reserved for `never authored` and `cleared by redaction`, so an ordinary update MUST NOT remove it. This is a slot-existence rule, not a capability boundary: `$op=\"set\"` on the same path is ordinary authoring and MUST be accepted even when the new value carries an empty body, and no patch op can reproduce the whole-object, terminal, audit-committed effect of redaction. `metadata`, `encrypted_metadata`, `metadata.title`, `metadata.summary` and paths under `metadata.fields` are NOT covered and MUST accept `$op=\"unset\"`. See zh/models/event-and-patch.md §4.2.4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PCR_GENESIS_CONFLICT,
        applies_to: &["pcr_genesis"],
        description: "The deterministic Principal Control Realm already has a different authoritative genesis unit. The receiver MUST perform zero writes and MUST NOT replace the accepted founding device.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PCR_GENESIS_UNIT_INVALID,
        applies_to: &["pcr_genesis"],
        description: "The closed ordered pair is not exactly one root-signed ak.realm.create followed by one founding-device-signed ak.device.authorize, or atomic validation failed. No partial write is permitted.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PERMISSION_DENIED,
        applies_to: &["event_envelope", "service_call"],
        description: "A recording or transcription backend could not obtain the required media permission.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::POLICY_DENIED,
        applies_to: &["auth_decision", "service_call"],
        description: "A Realm, organization, account, holder-disclosure, agent, or deployment policy explicitly denied the requested operation after syntactic validation and authentication succeeded. Use a narrower code when a more specific registry entry applies. See zh/crypto-media/device-lifecycle.md and zh/identity/identity-handles.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::POLICY_REVISION_GAP,
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.policy_bundle update skipped one or more monotonic policy_revision values. Reducer MUST reject instead of accepting a discontinuous realm_policy revision.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::POLICY_REVOKED,
        applies_to: &["event_envelope", "state_resolution"],
        description: "The Realm policy authorizing capture was revoked while the capture lifecycle was active.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PRESIGN_EXPIRED,
        applies_to: &["service_call", "auth_decision"],
        description: "A ak.self.blob.command.presign.v1 bearer URL was presented outside its nbf / exp window or after its nonce was revoked. Wire response remains non-enumerating not_found where required; audit logs may record this reason. See zh/crypto-media/media-and-blob.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PRESIGN_INVALID,
        applies_to: &["service_call", "auth_decision"],
        description: "A ak.self.blob.command.presign.v1 bearer envelope is syntactically invalid, has an unrecognised scheme, fails signature verification, mixes with Authorization header auth, or otherwise cannot be validated. Wire response remains non-enumerating not_found where required; audit logs may record this reason. See zh/crypto-media/media-and-blob.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PRESIGN_SCOPE_MISMATCH,
        applies_to: &["service_call", "auth_decision"],
        description: "A ak.self.blob.command.presign.v1 envelope scope does not match the requested blob_ref, method, byte range, purpose, Realm, issuer trust state, or current blob visibility. Wire response remains non-enumerating not_found where required; audit logs may record this reason. See zh/crypto-media/media-and-blob.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PRINCIPAL_CONTROL_EVENT_KIND_FORBIDDEN,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A Realm claiming ak.profile.principal_control_realm.v1 received a collaboration / media / content event kind outside its allowlist-only control-plane event policy. Reducers MUST reject instead of treating the Realm as ordinary collaboration history. See zh/models/realm-and-space.md §2.8.1 and artifacts/profiles/conformance-profiles.json#profile_requirements.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PRINCIPAL_DEACTIVATED,
        applies_to: &[
            "auth_decision",
            "event_envelope",
            "service_call",
            "state_resolution",
        ],
        description: "The account status checkpoint contains a deactivation for the exact AccountId acting as actor, subject, issuer, recipient, or device owner. New device/session grants, KeyPackage operations, capability delegation, membership writes targeting that account, push routes, and to-device enqueue MUST fail closed. See zh/identity/account-lifecycle.md §7.1 and the federation propagation rules of zh/identity/account-lifecycle.md §7.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PRIVATE_ATTACHMENT,
        applies_to: &["service_call", "auth_decision"],
        description: "The target blob is actor_private / private attachment material and MUST NOT be exposed through a bearer presign URL. It remains fetchable only through header-authenticated actor-bound access. See zh/crypto-media/media-and-blob.md §5.4.4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PRIVATE_VIEW_REQUIRES_ACCOUNT_DATA,
        applies_to: &["event_envelope", "schema_validation"],
        description: "A shared Realm View Event attempted to persist visibility=private. Private Views are encrypted holder account data under ak.views.private.<view_id> and MUST NOT enter the shared reducer. Carried under schema_violation. See zh/models/views.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PROFILE_UNAVAILABLE,
        applies_to: &["service_call"],
        description: "Per-actor outcome of ak.self.actor_profile.read.resolve.v1. Unknown actor, actor without an accepted global profile, actor that is not an effective joined member of the request realm_id, and a caller not authorized for that actor MUST all report this single value, so the only outward carrier for PCR-resident ak.profile.create / ak.profile.update cannot be used to probe membership or account existence. See zh/discovery/profiles-presence.md §2.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PROJECTION_INCOMPLETE,
        applies_to: &["client_sync", "view_projection"],
        description: "Projection cannot be materialized because of missing reducer inputs, decryption_pending epochs, or out-of-window backfill.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PROOF_FAILED,
        applies_to: &["device_recovery"],
        description: "Recovery-session `rejection_reason_code` value: proof verification failures reached the server-side policy limit, so the session transitioned to `rejected`. Closed value set defined in artifacts/schemas/recovery-session.schema.json; completion ownership is defined in zh/identity/security-transactions.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PROOF_INVALID,
        applies_to: &["auth_decision", "service_call"],
        description: "A runtime key-pairing or session-grant proof (DID `assertionMethod` signature, agent_key_proof transcript, etc.) failed signature verification, transcript binding, or `proof_kind` check. Distinct from `signature_invalid` in that the wire shape was syntactically valid but the proof semantics did not bind to the expected principal / nonce / audience. See zh/identity/key-management.md §3.6.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PUSH_GATEWAY_UNREACHABLE,
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify.v1: the gateway could not durably take the route over. One of exactly two caller-retryable notify reasons; it MAY carry retry_after_ms, and its presence is the wire signal that the caller â€” not the gateway â€” owns the next attempt. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PUSH_PAYLOAD_TOO_LARGE,
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify.v1: the notification exceeds the push profile, provider, or deployment size limit. Target-level, so the gateway MUST expand it into one same-reason rejected outcome per input device. Terminal until the caller shrinks the payload; MUST NOT carry retry_after_ms. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PUSH_ROUTE_LIMIT_EXCEEDED,
        applies_to: &["event_envelope", "service_call"],
        description: "A `ak.device.push_route` registration would exceed the v1 wire limit of 16 active push_route entries per `(recipient_id, principal_id, device_id)`. The server MUST reject the new registration. See zh/crypto-media/device-lifecycle.md §5.6.2 and zh/conformance/scalability-constraints.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PUSH_TARGET_UNKNOWN,
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify.v1: the push target is unknown or no longer visible. Target-level, so the gateway MUST expand it into one same-reason rejected outcome per input device. Terminal; not caller-retryable and MUST NOT carry retry_after_ms. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PUSH_TOKEN_INVALID,
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify.v1: the registered route failed provider validation or is no longer bound to this device. Terminal; the caller SHOULD drop the device registration. Cleanup is addressed by the composite identity â€” the response never returns the raw push_key. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::PUSH_TOKEN_UNKNOWN,
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify.v1: no active push registration exists for this (push_target_id, device_id). Terminal; the caller SHOULD drop the device registration. Cleanup is addressed by the composite identity â€” the response never returns the raw push_key. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::QUARANTINED,
        applies_to: &["state_resolution", "federation_transaction"],
        description: "Item was placed in quarantine pending operator decision (state_conflict_resolution); not finalized.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::QUEUE_FULL,
        applies_to: &["batch_item"],
        description: "Per-event rejection reason in an Applet edge transaction response (rejected[].reason_code) when the receiving side's inbound processing queue is saturated (backpressure) -- the Applet for node-to-Applet pushes, the Arkret edge for Applet-to-node pushes. The push sender MAY re-deliver the rejected events later under the same idempotency identity. See zh/extensions/applet-integration.md §7.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RATE_LIMITED,
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify.v1: gateway-side admission limiting refused durable takeover of this route. One of exactly two caller-retryable notify reasons; it MAY carry retry_after_ms. A route the gateway already accepted is retried by the gateway and never surfaces this reason. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_ALIAS_AUTHORITY_MISMATCH,
        applies_to: &["state_resolution", "service_call"],
        description: "An ak.realm.alias declaration carried an alias whose <domain> is not an authority domain of this Realm's trust_domain, so the RealmCommit signature from the governance Station is not evidence that the domain's alias issuer authorized the claim. Domain reducers and directories MUST fail closed instead of registering a foreign-domain alias. See zh/discovery/object-addressing.md §3.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_AUTHORITY_ROOT_CONFLICT,
        applies_to: &["event_envelope", "state_resolution"],
        description: "The authority-root typed current result value was author-supplied or otherwise diverges from the registered value_projection: controller_actor_id not equal to the create envelope actor_id, a non-zero controller_epoch or authority_generation at genesis, or members beyond the closed three-field shape. Reducer MUST reject the whole unit. See zh/models/realm-and-space.md section 2.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_ID_NOT_EVENT_DERIVED,
        applies_to: &["event_envelope"],
        description: "Sub-reason for schema_violation when ak.realm.create carries a forbidden envelope realm_id instead of the realm_genesis shape, when a Collaboration Realm does not retype the full 33-byte create Event token, when a Principal Control Realm does not match the 0x11 subject transcript, or when payload.object still carries an id field. See zh/models/realm-and-space.md section 2.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_LINK_INVALID_TRANSITION,
        applies_to: &["state_resolution"],
        description: "An ak.realm.link status transition is absent from the canonical domain-transition contract, including any non-byte-identical attempt to leave terminal tombstoned state. The reducer MUST reject with top-level failed_precondition. See zh/models/realm-links.md §4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_LINK_SELF_REFERENCE,
        applies_to: &["schema_validation", "state_resolution"],
        description: "An ak.realm.link targets its own enclosing Realm. Self-links have no cross-boundary meaning and MUST be rejected with top-level schema_violation. General directed cycles remain valid. See zh/models/realm-links.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_ORGANIZATION_AUTHORIZATION_INVALID,
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement failed organization-side authorization: payload.authorization.proof did not verify against the organization DID control state, threshold governance quorum, or the verification_method, or issuer_role is not allowed for the relationship. This is the generic organization-consent failure used when no more specific realm_organization_* reason applies. Downstream implementations MUST emit this exact code rather than inventing a bare string.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_ORGANIZATION_DELEGATION_MISSING,
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement whose authorization.issuer_role is governance_service or account_authority omitted authorization.delegation_ref, or the referenced delegation does not resolve to a live organization DID delegation whose purpose covers ak.realm.organization and the requested relationship/control_scopes.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_ORGANIZATION_EXPIRED,
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement is outside its validity window: the evaluation time is before payload.not_before, after payload.expires_at, or outside the referenced delegation's validity period. Schema validation passes; the reducer MUST reject the statement as expired or not-yet-valid.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_ORGANIZATION_REALM_ACCEPTANCE_MISSING,
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement lacks the Realm-side acceptance layer: the writing principal does not hold ak.realm.admin and the event is not part of an allowed create-bootstrap initial-configuration batch. Realm-side acceptance is independent of the organization-side proof.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REALM_ORGANIZATION_SCOPE_MISSING,
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement asserts a control_scope (or relationship) that the verified organization-side authorization or its delegation does not cover. The endorsement boundary in payload.control_scopes exceeds what the proof/delegation grants.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED,
        applies_to: &["service_call"],
        description: "A backend (LiveKit Egress / Janus recording plugin / etc.) attempted to deliver a recording artifact outside the Arkret-side blob pipeline â€” e.g. an Egress destination pointing to LiveKit Cloud / S3 / GCS direct, instead of the Arkret media service authenticated upload endpoint. Clients MUST fail closed. See zh/crypto-media/call-state.md §5 and zh/crypto-media/media-service-binding.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECORDING_CONSENT_REQUIRED,
        applies_to: &["service_call", "event_envelope"],
        description: "A capture attempted to enter or stay in recording/transcribing without the consent evidence its Realm requires. The reachable trigger is the per-participant consent acknowledgment profile of zh/crypto-media/call-state.md §5.2: a recorded party has no current device-signed acknowledgment, or membership, device or capture epoch changed and the acknowledgment was not re-acquired. This code is NOT how a producer-declared consent value is refused: `call_recording_start_payload.result.retention.consent_confirmed` is `const: true`, so any other value is `schema_violation` before the reducer runs, and the capture-kind start-event ref is stamped by the reducer because the payload MUST NOT carry it. Reducer MUST reject before either capture FSM or result typed current result is written.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECORDING_STATE_TRANSITION_INVALID,
        applies_to: &["event_envelope"],
        description: "An `ak.call.state` event requested a `recording_transition` or `transcript_transition` not listed in the per-capture controlled state machine (e.g. transitioning out of terminal `ready` / `failed`, `stopped â†’ failed`, or attempting to enter a capturing state without a new `ak.call.recording.start`). The reducer MUST `failed_precondition`. The same code covers both orthogonal capture dimensions. See zh/crypto-media/call-state.md §4.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECOVERY_EVIDENCE_UNBOUND,
        applies_to: &["recovery_transaction"],
        description: "Recovery evidence does not bind the current transaction, recovery session, principal, replacement device or prepared-plan digest.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECOVERY_POLICY_GENESIS_NOT_V1,
        applies_to: &["schema_validation", "state_resolution"],
        description: "A recovery policy publish is the first accepted policy for the principal but does not use `version=1`. Genesis recovery policies MUST start at version 1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECOVERY_POLICY_MISMATCH,
        applies_to: &["device_recovery", "state_resolution"],
        description: "A key-backup envelope or recovery proof references a `recovery_policy.policy_id` / `policy_version` that is not the currently accepted policy for the principal. Recovery strands MUST surface this to the user as 'update recovery policy' rather than silently continuing. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/identity/key-management.md §7.5.4 / §7.7 / §8 and zh/identity/security-transactions.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECOVERY_POLICY_SUPERSEDES_INVALID,
        applies_to: &["schema_validation", "state_resolution"],
        description: "A non-genesis recovery policy rotation omits `supersedes` or names a predecessor other than the currently accepted policy_id for the principal. Servers MUST reject with 409 Conflict.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECOVERY_POLICY_VERSION_NOT_MONOTONIC,
        applies_to: &["schema_validation", "state_resolution"],
        description: "A recovery policy publish or rotation uses a `version` that is not strictly greater than the currently accepted policy version for the principal. Servers MUST reject with 409 Conflict.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECOVERY_PRINCIPAL_ISOLATION,
        applies_to: &["authz", "device_recovery"],
        description: "A recovery policy or recovery session request targets an AccountId different from the exact account bound to the authenticated SessionGrant. Servers MUST compare both principal_id and station_id and reject without revealing the target account's recovery state.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECOVERY_PROOF_KIND_UNKNOWN,
        applies_to: &["schema_validation", "device_recovery"],
        description: "A recovery policy, receipt, or proof names a proof kind outside the ak.schema.recovery_policy.v1 methods kind union. Producers MUST use one of did_root, recovery_unlock, device_quorum, or trusted_recovery_service.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECOVERY_RECEIPT_COMPLETED_AT_AFTER_COMMIT,
        applies_to: &["recovery_transaction"],
        description: "A RecoveryTerminalCommit carries a recovery_receipt whose completed_at is later than the Station's own linearized commit time for commit_recovery_unit. The receipt's completed_at is the replacement device's authoring time for \"completed if every check passes\", so it can never be later than the commit that would make it true. The Station MUST reject the whole submission with this deterministic reason and perform zero authoritative writes: no accepted step, no terminal result, no accepted Event, no committed RealmCommit, no generation advance, no activated device and no consumed recovery session. v1 defines no skew allowance, the Station MUST NOT sign a future-dated completion attestation and MUST NOT block waiting for the client clock. The rejected request was never accepted, so a corrected submission MUST use a new receipt; bytes already frozen as a step outcome still return duplicate_conflict. See zh/identity/security-transactions.md section 2.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RECOVERY_SESSION_CHALLENGE_MISMATCH,
        applies_to: &["device_recovery", "schema_validation"],
        description: "A recovery proof echoes a challenge value that does not exactly match the server-issued challenge for the referenced recovery_session_id. Servers MUST reject the proof before completing device recovery. See artifacts/schemas/recovery-session.schema.json and zh/identity/security-transactions.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REDUCER_PROJECTION_FAILED,
        applies_to: &["event_envelope", "state_resolution"],
        description: "The reducer projection required by the registered contract cannot be derived uniquely from `kind`, signed envelope fields, schema-validated payload, and frozen pre-state. Receiver MUST reject the entire Event; projected writes are reducer output and never producer-selected Event fields. See zh/models/event-and-patch.md §4.3.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RELATION_KIND_CONTAINS_DERIVED,
        applies_to: &["event_envelope", "schema_validation"],
        description: "Sub-reason for schema_violation when a direct ak.relation.create / update / delete targets a derived-projection contains shape (Space(board) -> Space(list) or Space(list) -> Strand). Truth sources are the space_parent and strand_position typed results written via ak.space.parent / ak.strand.move / ak.strand.reorder Events; only the non-derived object-composition contains form is directly writable. See zh/models/relation.md §3.2 and zh/models/realm-and-space.md §3.5-§3.6.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RELATION_KIND_WATCHES_DERIVED,
        applies_to: &["event_envelope", "schema_validation"],
        description: "Sub-reason for schema_violation when a direct ak.relation.create / update / delete targets relation_kind=watches. The watches Relation is a derived projection only: its truth source is the strand_watch typed current result written via the ak.strand.watch.set durable event, never a direct Relation write. See zh/models/relation.md §3.2 and zh/models/strand-and-message.md §8.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RESOLUTION_HISTORY_ANCESTOR_UNKNOWN,
        applies_to: &["service_call"],
        description: "Sub-reason for param_invalid when ak.self.identity.read.resolution_audit.v1 receives an after_resolution_event_ref that is neither the genesis Event nor an accepted ak.identity.resolution.update in this account's current resolution lineage. The audit surface is already exact-current-holder authorized, so a stale or foreign cursor is reported as an invalid parameter rather than folded into the anti-enumeration outcome. See zh/identity/identity-did.md §4.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::REVOCATION_FRESHNESS_UNKNOWN,
        applies_to: &[
            "auth_decision",
            "federation_transaction",
            "state_resolution",
        ],
        description: "Revocation / grant freshness cannot be established for a high-risk, cross-domain, or delegated action. Receiver MUST fail closed and return freshness diagnostics instead of treating missing revoke evidence as allow.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RISK_POLICY,
        applies_to: &["device_recovery"],
        description: "Recovery-session `rejection_reason_code` value: a server-side risk policy rejected the session. Closed value set defined in artifacts/schemas/recovery-session.schema.json; completion ownership is defined in zh/identity/security-transactions.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::ROUTING_UNLINKABILITY_PRESIGN_FORBIDDEN,
        applies_to: &["authz", "service_call"],
        description: "A presigned blob URL was requested for a Realm whose asset policy declares routing_unlinkability_required=true. The service MUST deny presign and require an authenticated proxy, OHTTP relay, or equivalent non-bearer direct download path.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RSVP_BASIS_MALFORMED,
        applies_to: &["event_envelope", "schema_validation"],
        description: "entry.schedule_basis_refs does not carry exactly one well-formed ak:event: typed id: it is empty, holds more than one item, repeats an item, or the item is not a valid typed Event id. This shape admission is decidable from the payload field alone, without resolving the referenced Event, and MUST reject rather than pend. See zh/models/calendar-event.md section 8.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RSVP_OCCURRENCE_NOT_CANONICAL,
        applies_to: &["event_envelope", "schema_validation"],
        description: "payload.occurrence is neither JSON null nor a canonical instance key (YYYY-MM-DD for all-day, YYYY-MM-DDTHH:MM:SS[Zone] for timed), including when its date component is not a real proleptic-Gregorian date. Receivers MUST reject instead of rewriting the key, since the typed current result subject derives from the signed value. See zh/models/calendar-event.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::RUNTIME_KEY_MISSING,
        applies_to: &["agent_readiness"],
        description: "Closed generic Agent readiness blocker: no active accepted runtime key exists. It is durable subject-level readiness state and MUST NOT be inferred from a missing session or target-Realm grant.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SCOPE_REBIND_FORBIDDEN,
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when scope_circle_id rebind is attempted without an explicitly profile-permitted audited-high-risk path. Default reducer rejects rebinds to prevent silent historical-discussion migration. See zh/models/circle.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SCOPE_REF_MISMATCH,
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "The signed Event `scope_ref` does not equal the security scope deterministically resolved from the target or referenced accepted object state. Receiver MUST reject the Event and MUST NOT rewrite or reducer-stamp the signed scope. See zh/models/circle.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SEGMENT_BOUNDS_INVALID,
        applies_to: &["schema_validation", "service_call"],
        description: "Streaming-chunked AEAD attachment: a segment index is out of range, a segment length violates `segment_bytes`, or `segment_count` disagrees with the observed stream. Receivers MUST reject. See zh/crypto-media/media-and-blob.md §3.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SEGMENT_REPLAY,
        applies_to: &["crypto", "service_call"],
        description: "Streaming-chunked AEAD attachment: a segment index appears more than once in the stream. Receivers MUST reject. See zh/crypto-media/media-and-blob.md §3.3.6.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SEGMENT_SEQUENCE_INVALID,
        applies_to: &["crypto", "service_call"],
        description: "Streaming-chunked AEAD attachment (`ak.blob.stream_aead.v1`): segment indices arrive out of order, skip a value, or leave a gap. Receivers MUST reject. See zh/crypto-media/media-and-blob.md §3.3.6.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SEGMENT_STREAM_TRUNCATED,
        applies_to: &["crypto", "service_call"],
        description: "Streaming-chunked AEAD attachment: the stream ended without a valid final segment (last_segment_flag never observed, or fewer segments than `segment_count`). Receivers MUST reject to resist truncation. See zh/crypto-media/media-and-blob.md §3.3.6.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SELECTOR_ACTOR_WILDCARD_FORBIDDEN,
        applies_to: &["auth_decision", "schema_validation"],
        description: "The resource selector attempted to use actor:*. v1 actor selectors MUST name a concrete DID; universal subject grants are not accepted.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SEND_FAILED,
        applies_to: &["state_resolution"],
        description: "Invite delivery to the private target failed after the delivery service exhausted the retry budget. Used as a stable invite transition reason for ak.invite state projections; see zh/models/governance-objects.md and zh/sync/third-party-invites.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SERIES_CHAIN_BROKEN,
        applies_to: &["schema_validation", "state_resolution", "device_recovery"],
        description: "ak.schema.key_backup.v1 envelope chain failed verification: a `supersedes_digest` does not match the canonical_json digest of its predecessor, or a non-genesis envelope is missing a predecessor accessible to the caller. See zh/identity/key-management.md §7.6 and zh/crypto-media/device-lifecycle.md §12 / §12.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SERIES_PREDECESSOR_NOT_FOUND,
        applies_to: &["schema_validation", "state_resolution"],
        description: "`ak.schema.key_backup.v1.supersedes` references a backup_id that is unknown to the server, deleted, or owned by a different actor / series. Wire endpoint returns 409 Conflict; receivers MUST treat the chain as broken. See zh/crypto-media/device-lifecycle.md §12.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SERIES_SEQ_NOT_MONOTONIC,
        applies_to: &["schema_validation", "state_resolution"],
        description: "A PUT /_arkret/self/keys/backups/{backup_id} request whose `series_seq` is not strictly greater than the current maximum sequence within the same (actor_id, series_id), or whose genesis envelope sets series_seq != 0. See zh/crypto-media/device-lifecycle.md §12.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SERVICE_KEY_REVOKED,
        applies_to: &["federation_transaction", "auth_decision"],
        description: "Federation idempotency replay outcome: a cached federated request was re-evaluated and the origin service's signing key is now revoked, so the cache hit is treated as historical_only and MUST NOT bypass current key-state verification. See zh/conformance/conformance-vectors.md §3.9 (ak.vector.federation.idempotency_after_key_revoke.v1).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SERVICE_NOT_PLAINTEXT_VISIBLE,
        applies_to: &["service_call", "auth_decision"],
        description: "Service is not in the Realm's plaintext_visible_services policy; plaintext-bound operation refused.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SERVICE_PREROTATION_INVALID,
        applies_to: &["identity_resolution", "service_call"],
        description: "A service did:webvh inception or rotation omitted the sole next-key commitment, supplied more than one update/next key, or failed to open the previous nextKeyHashes commitment. Providers and resolvers MUST fail closed as service_registration_denied.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SERVICE_ROUTE_FORK,
        applies_to: &["identity_resolution", "federation_transaction"],
        description: "The method-native service evidence conflicts with the durable accepted DID history prefix.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED,
        applies_to: &["event_envelope"],
        description: "A subsequent `ak.call.state` event attempted to write a `session_focus` value different from the already-committed one. The reducer MUST `failed_precondition` â€” `session_focus` is write-once per call lifecycle; in-session focus migration is not supported in v1. See zh/crypto-media/call-state.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SESSION_FOCUS_NO_SPLIT_BRAIN,
        applies_to: &["service_call"],
        description: "The committed `ak.call.state.session_focus` is authoritative and write-once: once it exists, a connect / token-exchange failure against that focus MUST be surfaced as focus-unavailable (`focus_unavailable_for_client`) and clients MUST NOT silently fall back to a different focus to keep the media path up. Naming the invariant explicitly closes the split-brain attack where two subsets of a conference converge on different SFUs. See zh/crypto-media/media-service-binding.md §5 and §2 (`foci[].health_endpoint`).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SESSION_MISSING,
        applies_to: &["direct_conversation_readiness"],
        description: "Closed target-specific Direct Conversation readiness blocker: the otherwise authorized Agent has no current session for the requested send path. It MUST NOT appear in generic Agent readiness.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SIDECAR_CREATE_DENIED,
        applies_to: &["auth_decision", "state_resolution", "service_call"],
        description: "Agent Sidecar ensure was denied without revealing whether the controller's native Sidecar or requested source-context mapping already exists. Returned as a generic failed_precondition sub-reason to avoid existence side channels. See zh/models/sidecar.md §3 and §7.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SIGNAL_PLAINTEXT_FORBIDDEN,
        applies_to: &["service_call", "client_sync"],
        description: "Sub-reason for failed_precondition when any plaintext broadcast envelope is submitted or received. Signal is encrypted-only in every scope; implementations MUST fail closed and MUST NOT advertise Signal for a scope unless they can verify its MLS basis, AAD, and proof. See zh/sync/signal.md §1 and §3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SPACE_ALREADY_TERMINAL,
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.space.tombstone` rejected because the target Space is already `tombstoned`.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SPACE_HAS_LIVE_DEPENDENTS,
        applies_to: &["event_envelope", "auth_decision"],
        description: "Space tombstone is blocked by a non-tombstoned child Space or an effective canonical placement of a non-redacted Strand. Archived dependents still count. See zh/models/realm-and-space.md section 3.4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SPACE_NOT_ACTIVE,
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.space.archive` rejected because the target Space is not in `active` state (per zh/models/realm-and-space.md §3.3).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SPACE_NOT_ARCHIVED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.space.restore` rejected because the target Space is not in `archived` state; `tombstoned` is a terminal state and MUST NOT be restored.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SPACE_PARENT_MISMATCH,
        applies_to: &["event_envelope", "state_resolution"],
        description: "The expected_parent_space_id declared by an ak.space.parent payload and the parent_space_id stored in that Space's space_parent register are not byte-equal. Both are always present -- the payload member is required and the register is written for every Space by the ak.space.create genesis write -- so this is a two-valued equality, not the three-valued stored_field_matches_payload the directed-invite slot needs. Reducer MUST reject with zero writes (zh/models/realm-and-space.md section 3.5).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SPACE_PARENT_UNREADABLE,
        applies_to: &["event_envelope", "auth_decision", "projection"],
        description: "Canonical parent or placement structural facts cannot be read or verified at the operation basis. Structural validation and subtree authorization MUST fail closed, without disclosing hidden target Realm identity.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SPACE_REALM_MISMATCH,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A verified canonical Space parent or Board/List/Strand placement crosses actual Realm identities. Reject with failed_precondition after target readability and evidence checks; no profile exception or automatic Realm rewrite.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SPAM,
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: spam content.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::STATE_MISMATCH,
        applies_to: &["client_sync", "state_resolution"],
        description: "Local state does not match the authoritative checkpoint; client SHOULD reconcile via backfill or snapshot before continuing.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::STORAGE_FAILED,
        applies_to: &["event_envelope", "service_call"],
        description: "Capture artifact persistence or deletion failed in the Arkret blob pipeline.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::STRAND_ALREADY_TERMINAL,
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `ak.redaction` event targeting a Strand is rejected because the target Strand is already in terminal state `redacted`. Strand terminal state is reached via ak.redaction.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::STRAND_NOT_ACTIVE,
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.strand.archive` / `ak.strand.update` rejected because the target Strand is not in `active` state (per zh/models/common-fields.md §5.1).",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::STRAND_NOT_ARCHIVED,
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.strand.restore` rejected because the target Strand is not in `archived` state.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::STREAM_TAIL_MISSING,
        applies_to: &["client_sync"],
        description: "One authorized commit stream cannot be continued from the caller's durable cursor: the tail range between that cursor and the stream's current head is unavailable to this service (retention or history floor reached, or the durable range is otherwise not servable). It is per-stream and scoped to exactly one stream_ref, so the client re-acquires the snapshot and tail for that stream alone and MUST NOT reset other Realm / Circle / Sidecar streams, the account baseline or to-device ACKs. It is NOT the same as an empty tail: an authorized stream that is simply at its head returns zero items and `accepted`. emitting this code for a stream the caller may not read, or for one that does not exist, would turn that anti-enumeration bucket into an oracle. Only a stream the caller is currently authorized to read may be reported with it. See zh/sync/client-sync.md section 3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::STRUCTURE_DEPTH_EXCEEDED,
        applies_to: &["encoding", "schema_validation"],
        description: "A canonical JSON or deterministic CBOR structure exceeds the v1 maximum nesting depth of 64 (objects and arrays combined, top-level container = depth 1). Receiver MUST reject (top-level schema_violation) before recursive descent can exhaust the stack, and MUST NOT truncate or partially parse. See zh/conformance/scalability-constraints.md section 2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SUPERSEDED,
        applies_to: &["device_recovery"],
        description: "Recovery-session `rejection_reason_code` value: the session was superseded by a newer recovery session for the same principal / device. Closed value set defined in artifacts/schemas/recovery-session.schema.json; completion ownership is defined in zh/identity/security-transactions.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::SUPERSEDED_BY_REPAIRING,
        applies_to: &["event_envelope", "auth_decision"],
        description: "Reducer audit reason stamped when one controller-signed ak.agent.key.authorize runtime-replacement Event atomically observe-removes every prior active authorization dot named by its exact supersedes[] set and adds the new authorization. No synthetic ak.agent.key.revoke Event is authored. Sessions issued from superseded keys MUST fail closed within the revocation freshness window. See zh/identity/key-management.md §3.6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::TEST_SIGNING_MATERIAL_DENIED,
        applies_to: &[
            "auth_decision",
            "identity_resolution",
            "proof_verification",
            "crypto",
        ],
        description: "The presented signing material or identifier is registered in artifacts/registry/test-material-registry.json as published test material or as a reserved test identifier, so it MUST NOT be admitted on a formal verification, authorization or trust-admission path even when the signature verifies: its private key ships with the specification. The refusal is fail-closed and MUST NOT leave a verified binding, a resolution cache entry or accepted auth state behind, MUST NOT degrade to a weaker evidence class, a limited_trust pin or a retryable unavailable, and MUST NOT be reachable through a configuration switch on the formal API. See zh/identity/did-usage-and-verification.md §8.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::THIRD_PARTY_INVITE_ACCEPTANCE_MISSING,
        applies_to: &["service_call", "auth_decision"],
        description: "Sub-reason for failed_precondition when ak.open.third_party_invite.command.activate.v1 has no usable Station acceptance attestation for the named invite: the attestation signature does not verify against the attesting Station service identity, its audience or verification_id is not this service, or it does not attest a pending ak.invite.third_party on an accepted basis. A caller-reported invite id, a caller-computed invite digest, an Event signature or an HTTP success MUST NOT be accepted in its place. See zh/sync/third-party-invites.md section 7.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::THIRD_PARTY_INVITE_ACCEPTANCE_STALE,
        applies_to: &["service_call", "auth_decision"],
        description: "Sub-reason for failed_precondition when a Station acceptance attestation is structurally valid but its signed expires_at has passed, observed_at is later than expires_at, or expires_at exceeds invite_expires_at. The verification service MUST fail closed rather than bind private invite material with an invalid or expired attestation. See zh/sync/third-party-invites.md section 7.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::THIRD_PARTY_INVITE_MATERIAL_MISMATCH,
        applies_to: &["service_call", "auth_decision"],
        description: "Sub-reason for failed_precondition when the accepted ak.invite.third_party attested for activation differs from the frozen provisioning record in author, Realm, expiry or any member of the public third_party_invite object. The verification service MUST refuse rather than adopt the accepted typed current result values, because its private token, salt or pepper and ephemeral key were generated for the frozen material. See zh/sync/third-party-invites.md section 7.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::THIRD_PARTY_INVITE_PROVISIONING_ALREADY_BOUND,
        applies_to: &["service_call", "auth_decision"],
        description: "Sub-reason for duplicate_conflict when an activation attempt would bind an already bound provisioning record to a different invite, Realm or author. One provisioning record binds to exactly one invite for its whole life; the service MUST NOT rebind, rotate the ephemeral key or reissue the token. See zh/sync/third-party-invites.md section 7.5.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::THIRD_PARTY_INVITE_PROVISIONING_EXPIRED,
        applies_to: &["service_call", "auth_decision"],
        description: "Sub-reason for failed_precondition when activation is attempted after the provisioning record activation_expires_at. The record is cleaned up on the zh/sync/third-party-invites.md section 6.1 schedule and MUST NOT be revived; the inviter provisions fresh material and authors a new invite.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::THIRD_PARTY_INVITE_TOKEN_IN_QUERY,
        applies_to: &["service_call", "auth_decision"],
        description: "A 3PID invite claim arrived with the invite_token sourced from a URL query string or path segment instead of from a URL fragment or out-of-band code, in violation of zh/sync/third-party-invites.md §3.2. The verification service MUST reject and SHOULD invalidate the token to prevent referer / log replay.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::TOKEN_ISSUER_UNAUTHORISED,
        applies_to: &["service_call", "auth_decision"],
        description: "A media token's `service_signature.kid` or `participant_binding.issuer_kid` resolves to a service DID that does NOT appear in the current epoch `ak.realm.media_service.service_id` (or the foci[]-aligned token endpoint authority commit). Clients MUST reject â€” this closes the attack where any service can forge a focus join token. See zh/crypto-media/media-service-binding.md §3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED,
        applies_to: &["service_call"],
        description: "A backend attempted to deliver a transcription artifact outside the Arkret-side blob pipeline, or used a key not derived from the MLS-Exporter label `ak.rtc-transcript-key/v1` (e.g. reused the SFrame / recording label or an empty Context). Clients MUST fail closed. See zh/crypto-media/call-state.md §5.1 and zh/crypto-media/media-service-binding.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::TRANSCRIPTION_DENIED,
        applies_to: &["service_call", "auth_decision"],
        description: "Call transcription was requested without `ak.call.transcribe` capability, or the Realm policy forbids transcription. Issuer / reducer MUST reject; parallels `recording_denied` for the transcribe dimension. See zh/crypto-media/call-state.md §5.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNKNOWN_EVENT_KIND,
        applies_to: &["event_envelope"],
        description: "Event kind does not appear in the current registry. Fail closed; an unknown kind is not a non-critical extension and current-v1 has no generic critical_extensions carrier that can make it admissible.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNKNOWN_FIELD,
        applies_to: &["event_envelope"],
        description: "Current parser rejected an Event carrying a top-level or payload field not declared by the closed schema for its kind (including removed / renamed fields in artifacts/registry/forbidden-wire-fields.json). Distinct from `schema_violation` in that it pinpoints an unrecognized field rather than a constraint violation on a known field. See zh/overview/current-contract.md §1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNKNOWN_FOCUS_TYPE,
        applies_to: &["service_call", "schema_validation"],
        description: "A `ak.realm.media_service.foci[].focus_kind` value is not in the v1 registered set (`livekit` / `mediasoup` / `janus` / `arkret_native` / `moq_relay`) or is registered but not supported by this client / issuer. Clients MUST fail closed instead of forwarding the token to an arbitrary SDK. See zh/crypto-media/media-service-binding.md §2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNRESOLVED_BASIS,
        applies_to: &["state_resolution", "projection"],
        description: "A projected RSVP head references a schedule basis that cannot be resolved, is invisible, or is not on the target Strand's schedule revision DAG. The head is retained for audit, excluded from the effective response, and MUST NOT be guessed into currency. See zh/models/calendar-event.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_AEAD_PROFILE,
        applies_to: &["crypto", "schema_validation"],
        description: "Receiver does not recognise `encryption.aead.aead_profile` (or sees a reserved-but-unpublished profile such as `ak.aead.hybrid_kem.*`). Receivers MUST fail closed; inferring parameters from `aead.name` alone is forbidden. See zh/identity/key-management.md §7.9.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_ATTACHMENT_SCHEME,
        applies_to: &["schema_validation", "service_call"],
        description: "An encrypted-attachment envelope carries a `scheme` value the receiver does not recognise. Receivers MUST fail closed rather than guess a decryption form. See zh/crypto-media/media-and-blob.md §3.2/§3.3.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_CIPHERSUITE,
        applies_to: &["service_call", "auth_decision", "keypackage_lifecycle"],
        description: "An MLS ciphersuite selector is not an active row of artifacts/registry/mls-ciphersuite-registry.json (unknown, inactive, or reserved-but-not-activated) during KeyPackage publish, claim or Commit submission. Receivers MUST fail closed even if the underlying MLS library supports the suite. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/crypto-media/encryption-and-audit.md §2.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_DIGEST_ALGORITHM,
        applies_to: &["schema_validation", "batch_item", "event_envelope"],
        description: "Per-item algorithm-agility failure: a critical digest prefix is not an active digest-suite registry row. Receiver MUST fail closed. Dual-registered with the top-level service code.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_EVENT_KIND,
        applies_to: &["event_envelope"],
        description: "Event kind is not active in the receiver's profile or registry; receiver MUST NOT silently drop, MUST report this code.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_FEATURE,
        applies_to: &["service_call", "feature_discovery", "event_envelope"],
        description: "Implementation does not advertise the feature requested; caller SHOULD downgrade or pick another peer. At event_envelope scope it is the per-item reason_code for a structurally valid Event whose wire feature or producer class has no admissible v1 form, including an rfc9420.proposal whose decoded RFC 9420 sender class or Proposal type is a status=unsupported row of mls-proposal-admission-registry.json. Dual-registered with the top-level service code.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_HPKE_SUITE,
        applies_to: &["service_call", "auth_decision"],
        description: "HPKE suite id on an application-layer committed surface (key-backup recipient_method=recovery_public_key, ak.secret.send, member-application encryption_envelope, file-transfer key_envelope) is not an active row in artifacts/registry/hpke-suite-registry.json (unknown, inactive, or reserved-but-not-activated). Receivers MUST fail closed rather than infer suite parameters from the AEAD name. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/identity/key-management.md §7.5.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_PROFILE,
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify.v1: the device has not opted in to the requested notification profile (for example a visible notification sent to a device without visible_notification_opt_in). Terminal; the caller falls back to the blind_wakeup form and MUST NOT resend the same shape. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_PROTOCOL_VERSION,
        applies_to: &["feature_discovery", "service_call"],
        description: "The peer's protocol-family bootstrap discriminator is well formed but unsupported. The consumer rejects the complete service before reading version-specific capability claims or caching its route. Missing or non-string values remain schema_violation. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/overview/current-contract.md §1 and §4.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNSUPPORTED_SIGNATURE_ALG,
        applies_to: &["event_envelope", "auth_decision"],
        description: "Proof / event signature `alg` is not in the conformance signature-algorithm allowlist. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/conformance/encoding.md.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::UNTRUSTED_BACKUP_SIGNATURE,
        applies_to: &["crypto", "device_recovery", "state_resolution"],
        description: "A key-backup envelope signature verifies cryptographically but the signer is not an active accepted device in the current generation, or is revoked, unauthorized, or generation-mismatched. Receivers MUST reject it even if the series chain and ciphertext_digest are self-consistent. See zh/identity/key-management.md §7.4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
        applies_to: &["auth_decision", "service_call"],
        description: "A request supplied a `verification_method` whose DID component does not bit-identically match the target principal id after stripping fragment/query. Surfaces in two places. (1) `ak.gate.account.command.pair_agent_key.v1`: `verification_method` vs `agent_id`. (2) `ak.gate.account.command.issue_session_grant.v1` agent branch (`proof.proof_kind=\"agent_key_proof\"`): `proof.verification_method` vs request `principal_id`. Endpoints MUST fail closed before invoking the proof validator so that mismatch is reported as this code rather than as a generic signature failure. See zh/identity/key-management.md §3.6.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::VIEW_ALREADY_TERMINAL,
        applies_to: &["event_envelope", "state_resolution"],
        description: "An ak.view.update or ak.view.reconcile targeted a View whose accepted lifecycle state is tombstoned, or attempted to restore that View to active. Tombstoned shared Views are terminal. See zh/models/views.md §3.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::WEBVH_WITNESS_CONTROLLING_ORGANIZATION_UNVERIFIED,
        applies_to: &["identity_resolution", "auth_decision"],
        description: "A deployment profile requires witnesses from distinct controlling organizations, but the controlling organization of at least one witness cannot be verified, or two witnesses resolve to the same organization. Counting unverifiable or colliding organizations would let one operator running several witness keys satisfy a distinct-organization requirement alone; the verifier MUST fail closed on high-risk paths. See zh/identity/identity-did.md §3.4.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::WEBVH_WITNESS_EVIDENCE_STALE,
        applies_to: &["identity_resolution", "auth_decision"],
        description: "Witness evidence is older than the effective max age set by deployment / Realm policy, measured from when the proof was observed rather than from when any Arkret receipt was signed. Re-signing an old observation does not refresh it. See zh/identity/identity-did.md §3.4.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::WEBVH_WITNESS_PARAMETER_MALFORMED,
        applies_to: &["identity_resolution", "auth_decision"],
        description: "parameters.witness is present but is not the did:webvh 1.0 shape {threshold, witnesses:[{id}]}: threshold outside 1..witnesses.length, a duplicated witness id, a witness id that is not a did:key, a did:key whose multibase/multicodec payload does not decode to a well-formed public key compatible with the log's Data Integrity cryptosuite, or an unregistered extension key. Key decoding happens during parameter validation, not at signature time; accepting a witness id on string shape alone would let an unverifiable key occupy a threshold slot and hollow out the threshold. Also raised when parameters carries a look-alike key such as witnesses, witness_threshold or witnessThreshold, because that shape is evidence the log was produced against a non-standard dialect and the true policy is therefore unknown. A verifier MUST fail closed and MUST NOT fall back to treating the DID as unwitnessed: silently reading a malformed or aliased declaration as threshold 0 turns a DID that declares witnesses into one that requires none. See zh/identity/identity-did.md §3.4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::WEBVH_WITNESS_PROOF_INVALID,
        applies_to: &["identity_resolution", "auth_decision"],
        description: "A witness proof in did-witness.json fails signature verification, is signed by a key outside the witness listed in parameters.witness, or does not bind the versionId it is offered for. The proof does not count toward threshold and the entry MUST be treated as under-witnessed. See zh/identity/identity-did.md §3.4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::WEBVH_WITNESS_PROOFS_UNAVAILABLE,
        applies_to: &["identity_resolution", "auth_decision"],
        description: "parameters.witness declares a witness policy but the did-witness.json proofs file is unreachable, unparseable, or contains no entry for the versionId under evaluation. Unavailable evidence is not absent policy; the verifier MUST fail closed on high-risk paths rather than proceed as if no witnessing were required. See zh/identity/identity-did.md §3.4.1.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::WEBVH_WITNESS_THRESHOLD_NOT_MET,
        applies_to: &["identity_resolution", "auth_decision"],
        description: "Valid distinct witness proofs for the versionId are fewer than the effective threshold, which is the strictest intersection of the method-native parameters.witness.threshold and the deployment / Realm policy minimum. A holder-declared policy can raise this bar but MUST NOT lower it. See zh/identity/identity-did.md §3.4.1 and §3.4.2.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::WELCOME_CAPABILITY_MISMATCH,
        applies_to: &["event_envelope", "crypto"],
        description: "An MlsWelcomeDelivery claim reference does not match the claimed KeyPackage capabilities. The recipient MUST reject the delivery before decrypting it.",
    },
    ReasonCodeDescriptor {
        code: ReasonCode::WITNESS_DISAGREEMENT,
        applies_to: &["state_resolution", "federation_transaction"],
        description: "Confirmed fork evidence: two byte-distinct canonical Event preimages pass structure, suite and proof prerequisites and independently recompute to the same complete suite-tagged event_id (full-hash collision evidence); two byte-distinct signed RealmCommit objects name the same (stream_ref, stream_position); or a profile declares the observed combination non-joinable. A carried event_id whose recomputed digest differs is only event_id_digest_mismatch and MUST be rejected before quarantine. Two different accepted Events by one actor are not by themselves disagreement: an actor may author any number of Events and event-and-patch.md section 2.6 gives ordering precedence to the RealmCommit alone, so only one stream position carrying two distinct commits is equivocation. Raw stream head differences observed across different replication or disclosure scopes also are not disagreement: a consumer only ever observes the heads of the streams it is granted. The verifier MUST quarantine only the affected evidence scope and fail closed; recovery requires raw replay plus an accepted operator-approved fork resolution. See zh/sync/operations-sync.md §12 and zh/sync/federation.md §4.5.1.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_and_wire_tables_are_bijective() {
        for (index, descriptor) in REASON_CODE_DESCRIPTORS.iter().enumerate() {
            assert!(index == 0 || REASON_CODE_DESCRIPTORS[index - 1].code < descriptor.code);
            let parsed = ReasonCode::from_wire(descriptor.code);
            assert_eq!(parsed.as_str(), descriptor.code);
            assert!(ReasonCode::is_registered(descriptor.code));
            assert_eq!(parsed.descriptor(), Some(descriptor));
        }
        let unknown = ReasonCode::from_wire("reserved_or_unknown");
        assert_eq!(
            unknown,
            ReasonCode::Unknown("reserved_or_unknown".to_owned())
        );
        assert!(!ReasonCode::is_registered(unknown.as_str()));
        assert_eq!(unknown.descriptor(), None);
    }
}
