//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/error-code-registry.json; version=2026-07-30.1;
//! sha256=69916b7548766bb811e5a22987a60ea669f7b668e6a8d167e3b89dcc7f5f5bc0
//! Entries: reason_codes=446

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReasonCode {
    AbuseCluster,
    AbuseNetwork,
    AbuseReview,
    AccountStatusTransitionInvalid,
    AccountabilityGrantMissing,
    ActorKindReducerManaged,
    ActorSignatureRevoked,
    AeadNonceCounterReplay,
    AeadNonceDerivationInvalid,
    AeadNonceSenderDomainCollision,
    AgentDeactivated,
    AgentDeactivationRevocationsIncomplete,
    AgentGrantConstraintMissing,
    AgentGrantExceedsRequestedScope,
    AgentGrantExpiryRequired,
    AgentKeyAuthorizationExpired,
    AgentParticipationCeilingUnresolved,
    AgentParticipationCeilingWiden,
    AgentParticipationExceedsCeiling,
    AgentPaused,
    AgentPcrRecoveryNotReady,
    AgentReplyNotPermitted,
    AgentRequestedScopeCommitmentInvalid,
    AgentRuntimeRequestConflict,
    AppealModifyMissingLift,
    AppealOverturnMissingLift,
    AppealSelfReviewForbidden,
    AppletNamespaceMismatch,
    ApprovalAlreadyConsumed,
    ApprovalNonceReused,
    ApprovalRequired,
    AttestationMissing,
    AudienceMismatch,
    AuditAgentAttestationMismatch,
    AuditAgentDestructionNotPairedWithRemove,
    AuditAgentDestructionProofNotEnclaveSigned,
    AuditAgentEpochRangeIncomplete,
    AuditAgentKeyDestructionAttestationMissing,
    AuditAgentRemoveRequiresPairedDestructionAttestation,
    AuditCapabilityIncomplete,
    AuditPurposeMismatch,
    AuditReceiptInvalidated,
    AuditReleaseAttestationInvalid,
    AuditReleaseAttestationMismatch,
    AuditReleaseBindingInactive,
    AuditReleaseBindingMissing,
    AuditReleaseCurrentEpochForbidden,
    AuditReleaseManifestInvalid,
    AuditReleaseNoticeMissing,
    AuditReleaseRetroactiveScopeForbidden,
    AuditReleaseScopeMismatch,
    AuthIncomplete,
    AuthorizedGrantRevoked,
    BackendUnavailable,
    BackupFrontierStale,
    BackupPostResetStale,
    BlobRedacted,
    CalendarActivationMismatch,
    CalendarEventCancelled,
    CalendarScheduleUnsettled,
    CalendarTzdbMismatch,
    CallModerationUnauthorised,
    CallParticipantRemoved,
    CallStateTerminal,
    CallStateTransitionInvalid,
    CallSummaryInvalid,
    CapabilityRegistryBasisUnavailable,
    CardinalityViolation,
    CausalRefsTooLarge,
    CborBoundsInvalid,
    CborNotDeterministic,
    CellInBottomState,
    ChallengeExpired,
    ChallengeFailed,
    ChallengeProofInvalid,
    CircleAlreadyTerminal,
    CircleCountExceeded,
    CircleEncryptionBelowRealmFloor,
    CircleMemberMustBeRealmMember,
    CircleNotActive,
    CircleNotArchived,
    CircleRealmMismatch,
    CircleShortNameTaken,
    ClaimGenerationMismatch,
    ClaimInvalid,
    ClaimRateLimited,
    ConflictingE2eeProfiles,
    ConsentRevoked,
    ConsentWithdrawn,
    ContentEncryptionFloorDowngrade,
    ContentEncryptionFloorViolation,
    ControlProposalDecisionOverdue,
    ControllerMembershipEnded,
    CounterBoundExceeded,
    CoveredSetMismatch,
    CrossDomainReplayRejected,
    CrossRealmStructuralRelation,
    CrossSigningReset,
    CrossSigningResetAttestationMissing,
    CrossSigningResetClockSkewExceeded,
    CrossSigningResetGenerationMismatch,
    CrossSigningResetProofAuthorityInvalid,
    CrossSigningResetQuorumBelowPolicy,
    CrossSigningResetQuorumInsufficient,
    CrossSigningResetRecoveryRefUnknown,
    CrossSigningResetRecoveryServiceAttestationDomainMismatch,
    CrossSigningResetRecoveryServiceUnknown,
    CrossSigningResetReplayed,
    CrossSigningResetSignatureInvalid,
    CrossSigningResetUnlockCommitmentMismatch,
    CrossSpaceStructuralRelation,
    CursorExpired,
    CursorIntegrityInvalid,
    CursorRevoked,
    CursorUnrecognized,
    DeactivationFederationIncomplete,
    DecryptionFailed,
    DecryptionPending,
    DelegationCycle,
    DelegationExpiryWidening,
    DelegationRevoked,
    DelegationScopeCustomUnsupported,
    DelegationScopeMismatch,
    DeliveryBindingHandoverProofInvalid,
    DeliveryBindingHandoverRateLimited,
    DeliveryBindingInvalid,
    DeliveryBindingPolicyMismatch,
    DeliveryBindingStale,
    DeltaContainsDataEvent,
    DependencyMissing,
    DeviceAuthorizedPrincipalControlRealmMismatch,
    DeviceEnrollmentAuthoritySnapshotMissing,
    DeviceGenerationFenced,
    DeviceReanchorAuthorizeMismatch,
    DeviceReanchorConflict,
    DeviceReanchorEntryNotHead,
    DeviceReanchorFrontierMismatch,
    DeviceRecoverySskGenerationMismatch,
    DidProofReplayWindowExceeded,
    DirectConversationBindingInvalid,
    DirectConversationInviteForbidden,
    DirectConversationMemberCountInvalid,
    DirectConversationSpaceForbidden,
    DirectConversationThirdPartyMemberForbidden,
    DirectDownloadDisallowedPresignForbidden,
    DuplicateConflict,
    DurabilityRecoveryRecipientUnverified,
    DurabilitySchemeIncompatible,
    DurabilitySealMissingBeforeGc,
    E2eeKeySourceUnauthorised,
    E2eeRelaxedDisallowedInComplianceProfile,
    E2eeRelaxedFederationPolicyUnsupported,
    EffectiveScopeReducerManaged,
    EgressPolicyDenied,
    EpochUpdateRequired,
    ErasurePendingIsTerminal,
    ErasureReceiptStubDigestMismatch,
    EvidenceRecipientMismatch,
    ExecutedByMissing,
    ExpiredInviteToken,
    ExternalRateLimited,
    FederationAuthorityMismatch,
    FederationTrustDomainMismatch,
    FocusMismatch,
    FocusUnavailableForClient,
    ForensicAttributionMismatch,
    GateCheckFailed,
    GovernanceBindingMismatch,
    GrantExceedsIssuerAuthority,
    GrantRevokedBeforeEventFrontier,
    GrantRevokedUpstream,
    GrantValidityWindowEmpty,
    HandleHolderAcceptanceMissing,
    HandleHomographForbidden,
    HandleSubjectMismatch,
    Harassment,
    HateSpeech,
    HistoryVisibilityRequiresHistoryCapableScheme,
    HumanApprovalRequired,
    IdentityLinkNoLongerVisible,
    IdentityLinkPolicyTightened,
    Illegal,
    InceptionUpgradeEvidenceInsufficient,
    InceptionUpgradeEvidenceStale,
    InceptionUpgradeFingerprintMismatch,
    InceptionUpgradeOldDocumentHashMismatch,
    InceptionUpgradeSignatureChainInvalid,
    InclusionListViolation,
    InclusionProofFailed,
    InsufficientChallengeSamples,
    IntegrityFailed,
    InternalError,
    InvalidAckToken,
    InvalidAppealFsmTransition,
    InvalidCanonicalJson,
    InvalidCursor,
    InvalidEncoding,
    InvalidGenesisSeal,
    InvalidMembershipTransition,
    InvalidRealmFoundingGrant,
    InvalidTaskFsmTransition,
    InvalidatedByRateLimit,
    InviteAlreadyTerminal,
    InviteOobEntropyTooLow,
    JoinAuthorisationInvalid,
    JoinPolicyDuplicateGateId,
    JoinRulePolicyMismatch,
    JoinRuleTightened,
    KeyBackupWireSchemaRequired,
    KeypackageClaimRateLimited,
    KeypackageExpired,
    KeypackageRefreshRequired,
    KeypackageRotated,
    KeypackageWelcomeEnvelopeMismatch,
    LastResortNotSupported,
    LastResortRealmAffinityViolation,
    LastResortRotationRequired,
    LateRecoveryRejectedExpired,
    LateRecoveryRejectedMembership,
    LateRecoveryShareNotAuthorized,
    LegalHoldActive,
    LiteProfileWritesDisallowedEventKind,
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
    MessageAlreadyTerminal,
    MessageIdConflict,
    MetadataEncryptionFloorDowngrade,
    MetadataEncryptionFloorViolation,
    MimiDraftUnsupported,
    MimiGovernanceBindingMismatch,
    MimiGovernanceBindingMissing,
    MimiObserverWriteForbidden,
    MimiPolicyRootMismatch,
    MimiProviderUnreachable,
    MimiRoomBindingStatusTransitionInvalid,
    MimiRoomStateIncompatible,
    MinimalDisclosureViolation,
    MinimalMetadataAuthorCredentialInvalid,
    MinimalMetadataPresignForbidden,
    Misinformation,
    MissingParentReference,
    MlsGovernanceBindingStale,
    MlsSendPauseAdvisoryRequiresE2eeRelaxedProfile,
    ModerationControlLifted,
    ModerationControlPending,
    ModerationControlSplit,
    ModerationStateConflict,
    MorphAlreadyTerminal,
    MorphNotActive,
    MorphNotArchived,
    MorphSchemaRefsEvolutionUnauthorized,
    MorphSchemaRefsPreconditionMismatch,
    MorphSchemaRefsTransformationUnsupported,
    MorphSchemaVersionBindingMissing,
    NamingConventionViolation,
    NoStrandTrackMessageGrant,
    NotProvisioned,
    Nsfw,
    Ok,
    OperatorRejected,
    Other,
    OutOfOrderBootstrap,
    PairingExpired,
    PairingRequestExpired,
    PartialAuthState,
    ParticipantBindingInvalid,
    ParticipantIdentityUnrecognised,
    PatchAtomicConflict,
    PatchPathInvalid,
    PatchPathReducerManaged,
    PatchUnsetRedactableField,
    PermissionDenied,
    PlaneCrossWrite,
    PolicyDenied,
    PolicyRecall,
    PolicyRevisionGap,
    PolicyRevoked,
    PresignExpired,
    PresignInvalid,
    PresignScopeMismatch,
    PrevRefsTooLarge,
    PrincipalControlEventKindForbidden,
    PrincipalDeactivated,
    PrivateAttachment,
    ProfileUnsupported,
    ProjectionIncomplete,
    ProofBindingMissing,
    ProofFailed,
    ProofInvalid,
    PushGatewayUnreachable,
    PushPayloadTooLarge,
    PushRouteLimitExceeded,
    PushRouteRegistrationRateLimited,
    PushTargetUnknown,
    PushTokenInvalid,
    PushTokenUnknown,
    Quarantined,
    QueueFull,
    QuorumUnreachable,
    RangeCompletenessActorSeqGap,
    RangeCompletenessRootMismatch,
    RateLimited,
    ReactionScopeMismatch,
    ReactionTargetUnsupported,
    ReadReceiptForcedPublicWorldReadableForbidden,
    ReadReceiptVisibilityCombinationInvalid,
    RealmAliasHomographForbidden,
    RealmAlreadyExists,
    RealmFoundingGrantMissing,
    RealmLinkInvalidTransition,
    RealmLinkSelfReference,
    RealmOrganizationAuthorizationInvalid,
    RealmOrganizationDelegationMissing,
    RealmOrganizationExpired,
    RealmOrganizationRealmAcceptanceMissing,
    RealmOrganizationScopeMissing,
    RealmTerminalState,
    RealmUnavailable,
    RecipientUnavailable,
    RecordingArtifactPipelineBypassed,
    RecordingConsentRequired,
    RecordingStateTransitionInvalid,
    RecoveryCapabilityNotSealed,
    RecoveryEvidenceUnbound,
    RecoveryPolicyGenesisNotV1,
    RecoveryPolicyMismatch,
    RecoveryPolicySupersedesInvalid,
    RecoveryPolicyVersionNotMonotonic,
    RecoveryPrincipalIsolation,
    RecoveryProofKindUnknown,
    RecoverySessionChallengeMismatch,
    RecoverySessionTerminal,
    RecoveryTargetNotInBottom,
    RecoveryWitnessInvalid,
    RecoveryWitnessMissing,
    RecoveryWitnessPostConflict,
    RecoveryWitnessRevokeLagging,
    ReducerProfileMismatch,
    ReducerProjectionFailed,
    RefsTooLarge,
    RelationAlreadyTerminal,
    RelationConflictFanoutExceeded,
    RelationKindContainsDerived,
    RelationKindWatchesDerived,
    RelationProfileCardinalityConflict,
    RelationScopeUnresolved,
    RelaxedWindowExceedsCeiling,
    RequiresOrganizationApproval,
    ReservedCircleShortName,
    ResetEventIdMismatch,
    RevocationFreshnessUnknown,
    RevokeOrderUnknownRequiresBackfillOrReview,
    RevokeUndoInvalidSignature,
    RiskPolicy,
    RsvpBasisNotCausal,
    RsvpOccurrenceNotCanonical,
    ScheduleFrontierTooLarge,
    ScopeExpansionForbidden,
    ScopeIncomparable,
    ScopeRebindForbidden,
    ScopeRefMismatch,
    ScopeUnavailable,
    SegmentAeadFailed,
    SegmentBoundsInvalid,
    SegmentReplay,
    SegmentSequenceInvalid,
    SegmentStreamTruncated,
    SelectorActorWildcardForbidden,
    SelectorGovernanceWildcardForbidden,
    SelectorTooComplex,
    SendFailed,
    SeriesChainBroken,
    SeriesPredecessorNotFound,
    SeriesSeqNotMonotonic,
    ServiceKeyRevoked,
    ServiceNotPlaintextVisible,
    ServicePrerotationInvalid,
    SessionFocusAlreadyCommitted,
    SessionFocusNoSplitBrain,
    ShareCommitmentMismatch,
    SidecarCreateDenied,
    SidecarExposureAckRequired,
    SignalPlaintextForbidden,
    SnapshotIssuerRevoked,
    SoftFailed,
    SpaceAlreadyTerminal,
    SpaceHasLiveDependents,
    SpaceNotActive,
    SpaceNotArchived,
    SpaceParentChainInBottomState,
    SpaceParentCycle,
    SpaceParentUnreadable,
    Spam,
    StaleBackupTrustGeneration,
    StateMismatch,
    StorageFailed,
    StrandAlreadyTerminal,
    StrandNotActive,
    StrandNotArchived,
    StructureDepthExceeded,
    SubdelegationProhibited,
    Superseded,
    SupersededByRepairing,
    ThirdPartyInviteTokenInQuery,
    TokenExpired,
    TokenIssuerUnauthorised,
    TranscriptionArtifactPipelineBypassed,
    TranscriptionDenied,
    TtlExpired,
    UnknownEventKind,
    UnknownField,
    UnknownFocusType,
    UnknownKind,
    UnresolvedBasis,
    UnsupportedAeadProfile,
    UnsupportedAttachmentScheme,
    UnsupportedDigestAlgorithm,
    UnsupportedEventKind,
    UnsupportedFeature,
    UnsupportedHpkeSuite,
    UnsupportedSignatureAlg,
    UntrustedBackupSignature,
    VerificationMethodPrincipalMismatch,
    ViewAlreadyTerminal,
    WatchLevelPublicMustBeSelf,
    WatchMustBeSelf,
    WatchMutedMustBeSelf,
    WatchSetOthersAuditMissing,
    WebvhCacheTooStale,
    WebvhCacheUnavailable,
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
    pub const ABUSE_CLUSTER: &'static str = "abuse_cluster";
    pub const ABUSE_NETWORK: &'static str = "abuse_network";
    pub const ABUSE_REVIEW: &'static str = "abuse_review";
    pub const ACCOUNT_STATUS_TRANSITION_INVALID: &'static str = "account_status_transition_invalid";
    pub const ACCOUNTABILITY_GRANT_MISSING: &'static str = "accountability_grant_missing";
    pub const ACTOR_KIND_REDUCER_MANAGED: &'static str = "actor_kind_reducer_managed";
    pub const ACTOR_SIGNATURE_REVOKED: &'static str = "actor_signature_revoked";
    pub const AEAD_NONCE_COUNTER_REPLAY: &'static str = "aead_nonce_counter_replay";
    pub const AEAD_NONCE_DERIVATION_INVALID: &'static str = "aead_nonce_derivation_invalid";
    pub const AEAD_NONCE_SENDER_DOMAIN_COLLISION: &'static str =
        "aead_nonce_sender_domain_collision";
    pub const AGENT_DEACTIVATED: &'static str = "agent_deactivated";
    pub const AGENT_DEACTIVATION_REVOCATIONS_INCOMPLETE: &'static str =
        "agent_deactivation_revocations_incomplete";
    pub const AGENT_GRANT_CONSTRAINT_MISSING: &'static str = "agent_grant_constraint_missing";
    pub const AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE: &'static str =
        "agent_grant_exceeds_requested_scope";
    pub const AGENT_GRANT_EXPIRY_REQUIRED: &'static str = "agent_grant_expiry_required";
    pub const AGENT_KEY_AUTHORIZATION_EXPIRED: &'static str = "agent_key_authorization_expired";
    pub const AGENT_PARTICIPATION_CEILING_UNRESOLVED: &'static str =
        "agent_participation_ceiling_unresolved";
    pub const AGENT_PARTICIPATION_CEILING_WIDEN: &'static str = "agent_participation_ceiling_widen";
    pub const AGENT_PARTICIPATION_EXCEEDS_CEILING: &'static str =
        "agent_participation_exceeds_ceiling";
    pub const AGENT_PAUSED: &'static str = "agent_paused";
    pub const AGENT_PCR_RECOVERY_NOT_READY: &'static str = "agent_pcr_recovery_not_ready";
    pub const AGENT_REPLY_NOT_PERMITTED: &'static str = "agent_reply_not_permitted";
    pub const AGENT_REQUESTED_SCOPE_COMMITMENT_INVALID: &'static str =
        "agent_requested_scope_commitment_invalid";
    pub const AGENT_RUNTIME_REQUEST_CONFLICT: &'static str = "agent_runtime_request_conflict";
    pub const APPEAL_MODIFY_MISSING_LIFT: &'static str = "appeal_modify_missing_lift";
    pub const APPEAL_OVERTURN_MISSING_LIFT: &'static str = "appeal_overturn_missing_lift";
    pub const APPEAL_SELF_REVIEW_FORBIDDEN: &'static str = "appeal_self_review_forbidden";
    pub const APPLET_NAMESPACE_MISMATCH: &'static str = "applet_namespace_mismatch";
    pub const APPROVAL_ALREADY_CONSUMED: &'static str = "approval_already_consumed";
    pub const APPROVAL_NONCE_REUSED: &'static str = "approval_nonce_reused";
    pub const APPROVAL_REQUIRED: &'static str = "approval_required";
    pub const ATTESTATION_MISSING: &'static str = "attestation_missing";
    pub const AUDIENCE_MISMATCH: &'static str = "audience_mismatch";
    pub const AUDIT_AGENT_ATTESTATION_MISMATCH: &'static str = "audit_agent_attestation_mismatch";
    pub const AUDIT_AGENT_DESTRUCTION_NOT_PAIRED_WITH_REMOVE: &'static str =
        "audit_agent_destruction_not_paired_with_remove";
    pub const AUDIT_AGENT_DESTRUCTION_PROOF_NOT_ENCLAVE_SIGNED: &'static str =
        "audit_agent_destruction_proof_not_enclave_signed";
    pub const AUDIT_AGENT_EPOCH_RANGE_INCOMPLETE: &'static str =
        "audit_agent_epoch_range_incomplete";
    pub const AUDIT_AGENT_KEY_DESTRUCTION_ATTESTATION_MISSING: &'static str =
        "audit_agent_key_destruction_attestation_missing";
    pub const AUDIT_AGENT_REMOVE_REQUIRES_PAIRED_DESTRUCTION_ATTESTATION: &'static str =
        "audit_agent_remove_requires_paired_destruction_attestation";
    pub const AUDIT_CAPABILITY_INCOMPLETE: &'static str = "audit_capability_incomplete";
    pub const AUDIT_PURPOSE_MISMATCH: &'static str = "audit_purpose_mismatch";
    pub const AUDIT_RECEIPT_INVALIDATED: &'static str = "audit_receipt_invalidated";
    pub const AUDIT_RELEASE_ATTESTATION_INVALID: &'static str = "audit_release_attestation_invalid";
    pub const AUDIT_RELEASE_ATTESTATION_MISMATCH: &'static str =
        "audit_release_attestation_mismatch";
    pub const AUDIT_RELEASE_BINDING_INACTIVE: &'static str = "audit_release_binding_inactive";
    pub const AUDIT_RELEASE_BINDING_MISSING: &'static str = "audit_release_binding_missing";
    pub const AUDIT_RELEASE_CURRENT_EPOCH_FORBIDDEN: &'static str =
        "audit_release_current_epoch_forbidden";
    pub const AUDIT_RELEASE_MANIFEST_INVALID: &'static str = "audit_release_manifest_invalid";
    pub const AUDIT_RELEASE_NOTICE_MISSING: &'static str = "audit_release_notice_missing";
    pub const AUDIT_RELEASE_RETROACTIVE_SCOPE_FORBIDDEN: &'static str =
        "audit_release_retroactive_scope_forbidden";
    pub const AUDIT_RELEASE_SCOPE_MISMATCH: &'static str = "audit_release_scope_mismatch";
    pub const AUTH_INCOMPLETE: &'static str = "auth_incomplete";
    pub const AUTHORIZED_GRANT_REVOKED: &'static str = "authorized_grant_revoked";
    pub const BACKEND_UNAVAILABLE: &'static str = "backend_unavailable";
    pub const BACKUP_FRONTIER_STALE: &'static str = "backup_frontier_stale";
    pub const BACKUP_POST_RESET_STALE: &'static str = "backup_post_reset_stale";
    pub const BLOB_REDACTED: &'static str = "blob_redacted";
    pub const CALENDAR_ACTIVATION_MISMATCH: &'static str = "calendar_activation_mismatch";
    pub const CALENDAR_EVENT_CANCELLED: &'static str = "calendar_event_cancelled";
    pub const CALENDAR_SCHEDULE_UNSETTLED: &'static str = "calendar_schedule_unsettled";
    pub const CALENDAR_TZDB_MISMATCH: &'static str = "calendar_tzdb_mismatch";
    pub const CALL_MODERATION_UNAUTHORISED: &'static str = "call_moderation_unauthorised";
    pub const CALL_PARTICIPANT_REMOVED: &'static str = "call_participant_removed";
    pub const CALL_STATE_TERMINAL: &'static str = "call_state_terminal";
    pub const CALL_STATE_TRANSITION_INVALID: &'static str = "call_state_transition_invalid";
    pub const CALL_SUMMARY_INVALID: &'static str = "call_summary_invalid";
    pub const CAPABILITY_REGISTRY_BASIS_UNAVAILABLE: &'static str =
        "capability_registry_basis_unavailable";
    pub const CARDINALITY_VIOLATION: &'static str = "cardinality_violation";
    pub const CAUSAL_REFS_TOO_LARGE: &'static str = "causal_refs_too_large";
    pub const CBOR_BOUNDS_INVALID: &'static str = "cbor_bounds_invalid";
    pub const CBOR_NOT_DETERMINISTIC: &'static str = "cbor_not_deterministic";
    pub const CELL_IN_BOTTOM_STATE: &'static str = "cell_in_bottom_state";
    pub const CHALLENGE_EXPIRED: &'static str = "challenge_expired";
    pub const CHALLENGE_FAILED: &'static str = "challenge_failed";
    pub const CHALLENGE_PROOF_INVALID: &'static str = "challenge_proof_invalid";
    pub const CIRCLE_ALREADY_TERMINAL: &'static str = "circle_already_terminal";
    pub const CIRCLE_COUNT_EXCEEDED: &'static str = "circle_count_exceeded";
    pub const CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR: &'static str =
        "circle_encryption_below_realm_floor";
    pub const CIRCLE_MEMBER_MUST_BE_REALM_MEMBER: &'static str =
        "circle_member_must_be_realm_member";
    pub const CIRCLE_NOT_ACTIVE: &'static str = "circle_not_active";
    pub const CIRCLE_NOT_ARCHIVED: &'static str = "circle_not_archived";
    pub const CIRCLE_REALM_MISMATCH: &'static str = "circle_realm_mismatch";
    pub const CIRCLE_SHORT_NAME_TAKEN: &'static str = "circle_short_name_taken";
    pub const CLAIM_GENERATION_MISMATCH: &'static str = "claim_generation_mismatch";
    pub const CLAIM_INVALID: &'static str = "claim_invalid";
    pub const CLAIM_RATE_LIMITED: &'static str = "claim_rate_limited";
    pub const CONFLICTING_E2EE_PROFILES: &'static str = "conflicting_e2ee_profiles";
    pub const CONSENT_REVOKED: &'static str = "consent_revoked";
    pub const CONSENT_WITHDRAWN: &'static str = "consent_withdrawn";
    pub const CONTENT_ENCRYPTION_FLOOR_DOWNGRADE: &'static str =
        "content_encryption_floor_downgrade";
    pub const CONTENT_ENCRYPTION_FLOOR_VIOLATION: &'static str =
        "content_encryption_floor_violation";
    pub const CONTROL_PROPOSAL_DECISION_OVERDUE: &'static str = "control_proposal_decision_overdue";
    pub const CONTROLLER_MEMBERSHIP_ENDED: &'static str = "controller_membership_ended";
    pub const COUNTER_BOUND_EXCEEDED: &'static str = "counter_bound_exceeded";
    pub const COVERED_SET_MISMATCH: &'static str = "covered_set_mismatch";
    pub const CROSS_DOMAIN_REPLAY_REJECTED: &'static str = "cross_domain_replay_rejected";
    pub const CROSS_REALM_STRUCTURAL_RELATION: &'static str = "cross_realm_structural_relation";
    pub const CROSS_SIGNING_RESET: &'static str = "cross_signing_reset";
    pub const CROSS_SIGNING_RESET_ATTESTATION_MISSING: &'static str =
        "cross_signing_reset_attestation_missing";
    pub const CROSS_SIGNING_RESET_CLOCK_SKEW_EXCEEDED: &'static str =
        "cross_signing_reset_clock_skew_exceeded";
    pub const CROSS_SIGNING_RESET_GENERATION_MISMATCH: &'static str =
        "cross_signing_reset_generation_mismatch";
    pub const CROSS_SIGNING_RESET_PROOF_AUTHORITY_INVALID: &'static str =
        "cross_signing_reset_proof_authority_invalid";
    pub const CROSS_SIGNING_RESET_QUORUM_BELOW_POLICY: &'static str =
        "cross_signing_reset_quorum_below_policy";
    pub const CROSS_SIGNING_RESET_QUORUM_INSUFFICIENT: &'static str =
        "cross_signing_reset_quorum_insufficient";
    pub const CROSS_SIGNING_RESET_RECOVERY_REF_UNKNOWN: &'static str =
        "cross_signing_reset_recovery_ref_unknown";
    pub const CROSS_SIGNING_RESET_RECOVERY_SERVICE_ATTESTATION_DOMAIN_MISMATCH: &'static str =
        "cross_signing_reset_recovery_service_attestation_domain_mismatch";
    pub const CROSS_SIGNING_RESET_RECOVERY_SERVICE_UNKNOWN: &'static str =
        "cross_signing_reset_recovery_service_unknown";
    pub const CROSS_SIGNING_RESET_REPLAYED: &'static str = "cross_signing_reset_replayed";
    pub const CROSS_SIGNING_RESET_SIGNATURE_INVALID: &'static str =
        "cross_signing_reset_signature_invalid";
    pub const CROSS_SIGNING_RESET_UNLOCK_COMMITMENT_MISMATCH: &'static str =
        "cross_signing_reset_unlock_commitment_mismatch";
    pub const CROSS_SPACE_STRUCTURAL_RELATION: &'static str = "cross_space_structural_relation";
    pub const CURSOR_EXPIRED: &'static str = "cursor_expired";
    pub const CURSOR_INTEGRITY_INVALID: &'static str = "cursor_integrity_invalid";
    pub const CURSOR_REVOKED: &'static str = "cursor_revoked";
    pub const CURSOR_UNRECOGNIZED: &'static str = "cursor_unrecognized";
    pub const DEACTIVATION_FEDERATION_INCOMPLETE: &'static str =
        "deactivation_federation_incomplete";
    pub const DECRYPTION_FAILED: &'static str = "decryption_failed";
    pub const DECRYPTION_PENDING: &'static str = "decryption_pending";
    pub const DELEGATION_CYCLE: &'static str = "delegation_cycle";
    pub const DELEGATION_EXPIRY_WIDENING: &'static str = "delegation_expiry_widening";
    pub const DELEGATION_REVOKED: &'static str = "delegation_revoked";
    pub const DELEGATION_SCOPE_CUSTOM_UNSUPPORTED: &'static str =
        "delegation_scope_custom_unsupported";
    pub const DELEGATION_SCOPE_MISMATCH: &'static str = "delegation_scope_mismatch";
    pub const DELIVERY_BINDING_HANDOVER_PROOF_INVALID: &'static str =
        "delivery_binding_handover_proof_invalid";
    pub const DELIVERY_BINDING_HANDOVER_RATE_LIMITED: &'static str =
        "delivery_binding_handover_rate_limited";
    pub const DELIVERY_BINDING_INVALID: &'static str = "delivery_binding_invalid";
    pub const DELIVERY_BINDING_POLICY_MISMATCH: &'static str = "delivery_binding_policy_mismatch";
    pub const DELIVERY_BINDING_STALE: &'static str = "delivery_binding_stale";
    pub const DELTA_CONTAINS_DATA_EVENT: &'static str = "delta_contains_data_event";
    pub const DEPENDENCY_MISSING: &'static str = "dependency_missing";
    pub const DEVICE_AUTHORIZED_PRINCIPAL_CONTROL_REALM_MISMATCH: &'static str =
        "device_authorized_principal_control_realm_mismatch";
    pub const DEVICE_ENROLLMENT_AUTHORITY_SNAPSHOT_MISSING: &'static str =
        "device_enrollment_authority_snapshot_missing";
    pub const DEVICE_GENERATION_FENCED: &'static str = "device_generation_fenced";
    pub const DEVICE_REANCHOR_AUTHORIZE_MISMATCH: &'static str =
        "device_reanchor_authorize_mismatch";
    pub const DEVICE_REANCHOR_CONFLICT: &'static str = "device_reanchor_conflict";
    pub const DEVICE_REANCHOR_ENTRY_NOT_HEAD: &'static str = "device_reanchor_entry_not_head";
    pub const DEVICE_REANCHOR_FRONTIER_MISMATCH: &'static str = "device_reanchor_frontier_mismatch";
    pub const DEVICE_RECOVERY_SSK_GENERATION_MISMATCH: &'static str =
        "device_recovery_ssk_generation_mismatch";
    pub const DID_PROOF_REPLAY_WINDOW_EXCEEDED: &'static str = "did_proof_replay_window_exceeded";
    pub const DIRECT_CONVERSATION_BINDING_INVALID: &'static str =
        "direct_conversation_binding_invalid";
    pub const DIRECT_CONVERSATION_INVITE_FORBIDDEN: &'static str =
        "direct_conversation_invite_forbidden";
    pub const DIRECT_CONVERSATION_MEMBER_COUNT_INVALID: &'static str =
        "direct_conversation_member_count_invalid";
    pub const DIRECT_CONVERSATION_SPACE_FORBIDDEN: &'static str =
        "direct_conversation_space_forbidden";
    pub const DIRECT_CONVERSATION_THIRD_PARTY_MEMBER_FORBIDDEN: &'static str =
        "direct_conversation_third_party_member_forbidden";
    pub const DIRECT_DOWNLOAD_DISALLOWED_PRESIGN_FORBIDDEN: &'static str =
        "direct_download_disallowed_presign_forbidden";
    pub const DUPLICATE_CONFLICT: &'static str = "duplicate_conflict";
    pub const DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED: &'static str =
        "durability_recovery_recipient_unverified";
    pub const DURABILITY_SCHEME_INCOMPATIBLE: &'static str = "durability_scheme_incompatible";
    pub const DURABILITY_SEAL_MISSING_BEFORE_GC: &'static str = "durability_seal_missing_before_gc";
    pub const E2EE_KEY_SOURCE_UNAUTHORISED: &'static str = "e2ee_key_source_unauthorised";
    pub const E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE: &'static str =
        "e2ee_relaxed_disallowed_in_compliance_profile";
    pub const E2EE_RELAXED_FEDERATION_POLICY_UNSUPPORTED: &'static str =
        "e2ee_relaxed_federation_policy_unsupported";
    pub const EFFECTIVE_SCOPE_REDUCER_MANAGED: &'static str = "effective_scope_reducer_managed";
    pub const EGRESS_POLICY_DENIED: &'static str = "egress_policy_denied";
    pub const EPOCH_UPDATE_REQUIRED: &'static str = "epoch_update_required";
    pub const ERASURE_PENDING_IS_TERMINAL: &'static str = "erasure_pending_is_terminal";
    pub const ERASURE_RECEIPT_STUB_DIGEST_MISMATCH: &'static str =
        "erasure_receipt_stub_digest_mismatch";
    pub const EVIDENCE_RECIPIENT_MISMATCH: &'static str = "evidence_recipient_mismatch";
    pub const EXECUTED_BY_MISSING: &'static str = "executed_by_missing";
    pub const EXPIRED_INVITE_TOKEN: &'static str = "expired_invite_token";
    pub const EXTERNAL_RATE_LIMITED: &'static str = "external_rate_limited";
    pub const FEDERATION_AUTHORITY_MISMATCH: &'static str = "federation_authority_mismatch";
    pub const FEDERATION_TRUST_DOMAIN_MISMATCH: &'static str = "federation_trust_domain_mismatch";
    pub const FOCUS_MISMATCH: &'static str = "focus_mismatch";
    pub const FOCUS_UNAVAILABLE_FOR_CLIENT: &'static str = "focus_unavailable_for_client";
    pub const FORENSIC_ATTRIBUTION_MISMATCH: &'static str = "forensic_attribution_mismatch";
    pub const GATE_CHECK_FAILED: &'static str = "gate_check_failed";
    pub const GOVERNANCE_BINDING_MISMATCH: &'static str = "governance_binding_mismatch";
    pub const GRANT_EXCEEDS_ISSUER_AUTHORITY: &'static str = "grant_exceeds_issuer_authority";
    pub const GRANT_REVOKED_BEFORE_EVENT_FRONTIER: &'static str =
        "grant_revoked_before_event_frontier";
    pub const GRANT_REVOKED_UPSTREAM: &'static str = "grant_revoked_upstream";
    pub const GRANT_VALIDITY_WINDOW_EMPTY: &'static str = "grant_validity_window_empty";
    pub const HANDLE_HOLDER_ACCEPTANCE_MISSING: &'static str = "handle_holder_acceptance_missing";
    pub const HANDLE_HOMOGRAPH_FORBIDDEN: &'static str = "handle_homograph_forbidden";
    pub const HANDLE_SUBJECT_MISMATCH: &'static str = "handle_subject_mismatch";
    pub const HARASSMENT: &'static str = "harassment";
    pub const HATE_SPEECH: &'static str = "hate_speech";
    pub const HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME: &'static str =
        "history_visibility_requires_history_capable_scheme";
    pub const HUMAN_APPROVAL_REQUIRED: &'static str = "human_approval_required";
    pub const IDENTITY_LINK_NO_LONGER_VISIBLE: &'static str = "identity_link_no_longer_visible";
    pub const IDENTITY_LINK_POLICY_TIGHTENED: &'static str = "identity_link_policy_tightened";
    pub const ILLEGAL: &'static str = "illegal";
    pub const INCEPTION_UPGRADE_EVIDENCE_INSUFFICIENT: &'static str =
        "inception_upgrade_evidence_insufficient";
    pub const INCEPTION_UPGRADE_EVIDENCE_STALE: &'static str = "inception_upgrade_evidence_stale";
    pub const INCEPTION_UPGRADE_FINGERPRINT_MISMATCH: &'static str =
        "inception_upgrade_fingerprint_mismatch";
    pub const INCEPTION_UPGRADE_OLD_DOCUMENT_HASH_MISMATCH: &'static str =
        "inception_upgrade_old_document_hash_mismatch";
    pub const INCEPTION_UPGRADE_SIGNATURE_CHAIN_INVALID: &'static str =
        "inception_upgrade_signature_chain_invalid";
    pub const INCLUSION_LIST_VIOLATION: &'static str = "inclusion_list_violation";
    pub const INCLUSION_PROOF_FAILED: &'static str = "inclusion_proof_failed";
    pub const INSUFFICIENT_CHALLENGE_SAMPLES: &'static str = "insufficient_challenge_samples";
    pub const INTEGRITY_FAILED: &'static str = "integrity_failed";
    pub const INTERNAL_ERROR: &'static str = "internal_error";
    pub const INVALID_ACK_TOKEN: &'static str = "invalid_ack_token";
    pub const INVALID_APPEAL_FSM_TRANSITION: &'static str = "invalid_appeal_fsm_transition";
    pub const INVALID_CANONICAL_JSON: &'static str = "invalid_canonical_json";
    pub const INVALID_CURSOR: &'static str = "invalid_cursor";
    pub const INVALID_ENCODING: &'static str = "invalid_encoding";
    pub const INVALID_GENESIS_SEAL: &'static str = "invalid_genesis_seal";
    pub const INVALID_MEMBERSHIP_TRANSITION: &'static str = "invalid_membership_transition";
    pub const INVALID_REALM_FOUNDING_GRANT: &'static str = "invalid_realm_founding_grant";
    pub const INVALID_TASK_FSM_TRANSITION: &'static str = "invalid_task_fsm_transition";
    pub const INVALIDATED_BY_RATE_LIMIT: &'static str = "invalidated_by_rate_limit";
    pub const INVITE_ALREADY_TERMINAL: &'static str = "invite_already_terminal";
    pub const INVITE_OOB_ENTROPY_TOO_LOW: &'static str = "invite_oob_entropy_too_low";
    pub const JOIN_AUTHORISATION_INVALID: &'static str = "join_authorisation_invalid";
    pub const JOIN_POLICY_DUPLICATE_GATE_ID: &'static str = "join_policy_duplicate_gate_id";
    pub const JOIN_RULE_POLICY_MISMATCH: &'static str = "join_rule_policy_mismatch";
    pub const JOIN_RULE_TIGHTENED: &'static str = "join_rule_tightened";
    pub const KEY_BACKUP_WIRE_SCHEMA_REQUIRED: &'static str = "key_backup_wire_schema_required";
    pub const KEYPACKAGE_CLAIM_RATE_LIMITED: &'static str = "keypackage_claim_rate_limited";
    pub const KEYPACKAGE_EXPIRED: &'static str = "keypackage_expired";
    pub const KEYPACKAGE_REFRESH_REQUIRED: &'static str = "keypackage_refresh_required";
    pub const KEYPACKAGE_ROTATED: &'static str = "keypackage_rotated";
    pub const KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH: &'static str =
        "keypackage_welcome_envelope_mismatch";
    pub const LAST_RESORT_NOT_SUPPORTED: &'static str = "last_resort_not_supported";
    pub const LAST_RESORT_REALM_AFFINITY_VIOLATION: &'static str =
        "last_resort_realm_affinity_violation";
    pub const LAST_RESORT_ROTATION_REQUIRED: &'static str = "last_resort_rotation_required";
    pub const LATE_RECOVERY_REJECTED_EXPIRED: &'static str = "late_recovery_rejected_expired";
    pub const LATE_RECOVERY_REJECTED_MEMBERSHIP: &'static str = "late_recovery_rejected_membership";
    pub const LATE_RECOVERY_SHARE_NOT_AUTHORIZED: &'static str =
        "late_recovery_share_not_authorized";
    pub const LEGAL_HOLD_ACTIVE: &'static str = "legal_hold_active";
    pub const LITE_PROFILE_WRITES_DISALLOWED_EVENT_KIND: &'static str =
        "lite_profile_writes_disallowed_event_kind";
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
    pub const MESSAGE_ALREADY_TERMINAL: &'static str = "message_already_terminal";
    pub const MESSAGE_ID_CONFLICT: &'static str = "message_id_conflict";
    pub const METADATA_ENCRYPTION_FLOOR_DOWNGRADE: &'static str =
        "metadata_encryption_floor_downgrade";
    pub const METADATA_ENCRYPTION_FLOOR_VIOLATION: &'static str =
        "metadata_encryption_floor_violation";
    pub const MIMI_DRAFT_UNSUPPORTED: &'static str = "mimi_draft_unsupported";
    pub const MIMI_GOVERNANCE_BINDING_MISMATCH: &'static str = "mimi_governance_binding_mismatch";
    pub const MIMI_GOVERNANCE_BINDING_MISSING: &'static str = "mimi_governance_binding_missing";
    pub const MIMI_OBSERVER_WRITE_FORBIDDEN: &'static str = "mimi_observer_write_forbidden";
    pub const MIMI_POLICY_ROOT_MISMATCH: &'static str = "mimi_policy_root_mismatch";
    pub const MIMI_PROVIDER_UNREACHABLE: &'static str = "mimi_provider_unreachable";
    pub const MIMI_ROOM_BINDING_STATUS_TRANSITION_INVALID: &'static str =
        "mimi_room_binding_status_transition_invalid";
    pub const MIMI_ROOM_STATE_INCOMPATIBLE: &'static str = "mimi_room_state_incompatible";
    pub const MINIMAL_DISCLOSURE_VIOLATION: &'static str = "minimal_disclosure_violation";
    pub const MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID: &'static str =
        "minimal_metadata_author_credential_invalid";
    pub const MINIMAL_METADATA_PRESIGN_FORBIDDEN: &'static str =
        "minimal_metadata_presign_forbidden";
    pub const MISINFORMATION: &'static str = "misinformation";
    pub const MISSING_PARENT_REFERENCE: &'static str = "missing_parent_reference";
    pub const MLS_GOVERNANCE_BINDING_STALE: &'static str = "mls_governance_binding_stale";
    pub const MLS_SEND_PAUSE_ADVISORY_REQUIRES_E2EE_RELAXED_PROFILE: &'static str =
        "mls_send_pause_advisory_requires_e2ee_relaxed_profile";
    pub const MODERATION_CONTROL_LIFTED: &'static str = "moderation_control_lifted";
    pub const MODERATION_CONTROL_PENDING: &'static str = "moderation_control_pending";
    pub const MODERATION_CONTROL_SPLIT: &'static str = "moderation_control_split";
    pub const MODERATION_STATE_CONFLICT: &'static str = "moderation_state_conflict";
    pub const MORPH_ALREADY_TERMINAL: &'static str = "morph_already_terminal";
    pub const MORPH_NOT_ACTIVE: &'static str = "morph_not_active";
    pub const MORPH_NOT_ARCHIVED: &'static str = "morph_not_archived";
    pub const MORPH_SCHEMA_REFS_EVOLUTION_UNAUTHORIZED: &'static str =
        "morph_schema_refs_evolution_unauthorized";
    pub const MORPH_SCHEMA_REFS_PRECONDITION_MISMATCH: &'static str =
        "morph_schema_refs_precondition_mismatch";
    pub const MORPH_SCHEMA_REFS_TRANSFORMATION_UNSUPPORTED: &'static str =
        "morph_schema_refs_transformation_unsupported";
    pub const MORPH_SCHEMA_VERSION_BINDING_MISSING: &'static str =
        "morph_schema_version_binding_missing";
    pub const NAMING_CONVENTION_VIOLATION: &'static str = "naming_convention_violation";
    pub const NO_STRAND_TRACK_MESSAGE_GRANT: &'static str = "no_strand_track_message_grant";
    pub const NOT_PROVISIONED: &'static str = "not_provisioned";
    pub const NSFW: &'static str = "nsfw";
    pub const OK: &'static str = "ok";
    pub const OPERATOR_REJECTED: &'static str = "operator_rejected";
    pub const OTHER: &'static str = "other";
    pub const OUT_OF_ORDER_BOOTSTRAP: &'static str = "out_of_order_bootstrap";
    pub const PAIRING_EXPIRED: &'static str = "pairing_expired";
    pub const PAIRING_REQUEST_EXPIRED: &'static str = "pairing_request_expired";
    pub const PARTIAL_AUTH_STATE: &'static str = "partial_auth_state";
    pub const PARTICIPANT_BINDING_INVALID: &'static str = "participant_binding_invalid";
    pub const PARTICIPANT_IDENTITY_UNRECOGNISED: &'static str = "participant_identity_unrecognised";
    pub const PATCH_ATOMIC_CONFLICT: &'static str = "patch_atomic_conflict";
    pub const PATCH_PATH_INVALID: &'static str = "patch_path_invalid";
    pub const PATCH_PATH_REDUCER_MANAGED: &'static str = "patch_path_reducer_managed";
    pub const PATCH_UNSET_REDACTABLE_FIELD: &'static str = "patch_unset_redactable_field";
    pub const PERMISSION_DENIED: &'static str = "permission_denied";
    pub const PLANE_CROSS_WRITE: &'static str = "plane_cross_write";
    pub const POLICY_DENIED: &'static str = "policy_denied";
    pub const POLICY_RECALL: &'static str = "policy_recall";
    pub const POLICY_REVISION_GAP: &'static str = "policy_revision_gap";
    pub const POLICY_REVOKED: &'static str = "policy_revoked";
    pub const PRESIGN_EXPIRED: &'static str = "presign_expired";
    pub const PRESIGN_INVALID: &'static str = "presign_invalid";
    pub const PRESIGN_SCOPE_MISMATCH: &'static str = "presign_scope_mismatch";
    pub const PREV_REFS_TOO_LARGE: &'static str = "prev_refs_too_large";
    pub const PRINCIPAL_CONTROL_EVENT_KIND_FORBIDDEN: &'static str =
        "principal_control_event_kind_forbidden";
    pub const PRINCIPAL_DEACTIVATED: &'static str = "principal_deactivated";
    pub const PRIVATE_ATTACHMENT: &'static str = "private_attachment";
    pub const PROFILE_UNSUPPORTED: &'static str = "profile_unsupported";
    pub const PROJECTION_INCOMPLETE: &'static str = "projection_incomplete";
    pub const PROOF_BINDING_MISSING: &'static str = "proof_binding_missing";
    pub const PROOF_FAILED: &'static str = "proof_failed";
    pub const PROOF_INVALID: &'static str = "proof_invalid";
    pub const PUSH_GATEWAY_UNREACHABLE: &'static str = "push_gateway_unreachable";
    pub const PUSH_PAYLOAD_TOO_LARGE: &'static str = "push_payload_too_large";
    pub const PUSH_ROUTE_LIMIT_EXCEEDED: &'static str = "push_route_limit_exceeded";
    pub const PUSH_ROUTE_REGISTRATION_RATE_LIMITED: &'static str =
        "push_route_registration_rate_limited";
    pub const PUSH_TARGET_UNKNOWN: &'static str = "push_target_unknown";
    pub const PUSH_TOKEN_INVALID: &'static str = "push_token_invalid";
    pub const PUSH_TOKEN_UNKNOWN: &'static str = "push_token_unknown";
    pub const QUARANTINED: &'static str = "quarantined";
    pub const QUEUE_FULL: &'static str = "queue_full";
    pub const QUORUM_UNREACHABLE: &'static str = "quorum_unreachable";
    pub const RANGE_COMPLETENESS_ACTOR_SEQ_GAP: &'static str = "range_completeness_actor_seq_gap";
    pub const RANGE_COMPLETENESS_ROOT_MISMATCH: &'static str = "range_completeness_root_mismatch";
    pub const RATE_LIMITED: &'static str = "rate_limited";
    pub const REACTION_SCOPE_MISMATCH: &'static str = "reaction_scope_mismatch";
    pub const REACTION_TARGET_UNSUPPORTED: &'static str = "reaction_target_unsupported";
    pub const READ_RECEIPT_FORCED_PUBLIC_WORLD_READABLE_FORBIDDEN: &'static str =
        "read_receipt_forced_public_world_readable_forbidden";
    pub const READ_RECEIPT_VISIBILITY_COMBINATION_INVALID: &'static str =
        "read_receipt_visibility_combination_invalid";
    pub const REALM_ALIAS_HOMOGRAPH_FORBIDDEN: &'static str = "realm_alias_homograph_forbidden";
    pub const REALM_ALREADY_EXISTS: &'static str = "realm_already_exists";
    pub const REALM_FOUNDING_GRANT_MISSING: &'static str = "realm_founding_grant_missing";
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
    pub const REALM_TERMINAL_STATE: &'static str = "realm_terminal_state";
    pub const REALM_UNAVAILABLE: &'static str = "realm_unavailable";
    pub const RECIPIENT_UNAVAILABLE: &'static str = "recipient_unavailable";
    pub const RECORDING_ARTIFACT_PIPELINE_BYPASSED: &'static str =
        "recording_artifact_pipeline_bypassed";
    pub const RECORDING_CONSENT_REQUIRED: &'static str = "recording_consent_required";
    pub const RECORDING_STATE_TRANSITION_INVALID: &'static str =
        "recording_state_transition_invalid";
    pub const RECOVERY_CAPABILITY_NOT_SEALED: &'static str = "recovery_capability_not_sealed";
    pub const RECOVERY_EVIDENCE_UNBOUND: &'static str = "recovery_evidence_unbound";
    pub const RECOVERY_POLICY_GENESIS_NOT_V1: &'static str = "recovery_policy_genesis_not_v1";
    pub const RECOVERY_POLICY_MISMATCH: &'static str = "recovery_policy_mismatch";
    pub const RECOVERY_POLICY_SUPERSEDES_INVALID: &'static str =
        "recovery_policy_supersedes_invalid";
    pub const RECOVERY_POLICY_VERSION_NOT_MONOTONIC: &'static str =
        "recovery_policy_version_not_monotonic";
    pub const RECOVERY_PRINCIPAL_ISOLATION: &'static str = "recovery_principal_isolation";
    pub const RECOVERY_PROOF_KIND_UNKNOWN: &'static str = "recovery_proof_kind_unknown";
    pub const RECOVERY_SESSION_CHALLENGE_MISMATCH: &'static str =
        "recovery_session_challenge_mismatch";
    pub const RECOVERY_SESSION_TERMINAL: &'static str = "recovery_session_terminal";
    pub const RECOVERY_TARGET_NOT_IN_BOTTOM: &'static str = "recovery_target_not_in_bottom";
    pub const RECOVERY_WITNESS_INVALID: &'static str = "recovery_witness_invalid";
    pub const RECOVERY_WITNESS_MISSING: &'static str = "recovery_witness_missing";
    pub const RECOVERY_WITNESS_POST_CONFLICT: &'static str = "recovery_witness_post_conflict";
    pub const RECOVERY_WITNESS_REVOKE_LAGGING: &'static str = "recovery_witness_revoke_lagging";
    pub const REDUCER_PROFILE_MISMATCH: &'static str = "reducer_profile_mismatch";
    pub const REDUCER_PROJECTION_FAILED: &'static str = "reducer_projection_failed";
    pub const REFS_TOO_LARGE: &'static str = "refs_too_large";
    pub const RELATION_ALREADY_TERMINAL: &'static str = "relation_already_terminal";
    pub const RELATION_CONFLICT_FANOUT_EXCEEDED: &'static str = "relation_conflict_fanout_exceeded";
    pub const RELATION_KIND_CONTAINS_DERIVED: &'static str = "relation_kind_contains_derived";
    pub const RELATION_KIND_WATCHES_DERIVED: &'static str = "relation_kind_watches_derived";
    pub const RELATION_PROFILE_CARDINALITY_CONFLICT: &'static str =
        "relation_profile_cardinality_conflict";
    pub const RELATION_SCOPE_UNRESOLVED: &'static str = "relation_scope_unresolved";
    pub const RELAXED_WINDOW_EXCEEDS_CEILING: &'static str = "relaxed_window_exceeds_ceiling";
    pub const REQUIRES_ORGANIZATION_APPROVAL: &'static str = "requires_organization_approval";
    pub const RESERVED_CIRCLE_SHORT_NAME: &'static str = "reserved_circle_short_name";
    pub const RESET_EVENT_ID_MISMATCH: &'static str = "reset_event_id_mismatch";
    pub const REVOCATION_FRESHNESS_UNKNOWN: &'static str = "revocation_freshness_unknown";
    pub const REVOKE_ORDER_UNKNOWN_REQUIRES_BACKFILL_OR_REVIEW: &'static str =
        "revoke_order_unknown_requires_backfill_or_review";
    pub const REVOKE_UNDO_INVALID_SIGNATURE: &'static str = "revoke_undo_invalid_signature";
    pub const RISK_POLICY: &'static str = "risk_policy";
    pub const RSVP_BASIS_NOT_CAUSAL: &'static str = "rsvp_basis_not_causal";
    pub const RSVP_OCCURRENCE_NOT_CANONICAL: &'static str = "rsvp_occurrence_not_canonical";
    pub const SCHEDULE_FRONTIER_TOO_LARGE: &'static str = "schedule_frontier_too_large";
    pub const SCOPE_EXPANSION_FORBIDDEN: &'static str = "scope_expansion_forbidden";
    pub const SCOPE_INCOMPARABLE: &'static str = "scope_incomparable";
    pub const SCOPE_REBIND_FORBIDDEN: &'static str = "scope_rebind_forbidden";
    pub const SCOPE_REF_MISMATCH: &'static str = "scope_ref_mismatch";
    pub const SCOPE_UNAVAILABLE: &'static str = "scope_unavailable";
    pub const SEGMENT_AEAD_FAILED: &'static str = "segment_aead_failed";
    pub const SEGMENT_BOUNDS_INVALID: &'static str = "segment_bounds_invalid";
    pub const SEGMENT_REPLAY: &'static str = "segment_replay";
    pub const SEGMENT_SEQUENCE_INVALID: &'static str = "segment_sequence_invalid";
    pub const SEGMENT_STREAM_TRUNCATED: &'static str = "segment_stream_truncated";
    pub const SELECTOR_ACTOR_WILDCARD_FORBIDDEN: &'static str = "selector_actor_wildcard_forbidden";
    pub const SELECTOR_GOVERNANCE_WILDCARD_FORBIDDEN: &'static str =
        "selector_governance_wildcard_forbidden";
    pub const SELECTOR_TOO_COMPLEX: &'static str = "selector_too_complex";
    pub const SEND_FAILED: &'static str = "send_failed";
    pub const SERIES_CHAIN_BROKEN: &'static str = "series_chain_broken";
    pub const SERIES_PREDECESSOR_NOT_FOUND: &'static str = "series_predecessor_not_found";
    pub const SERIES_SEQ_NOT_MONOTONIC: &'static str = "series_seq_not_monotonic";
    pub const SERVICE_KEY_REVOKED: &'static str = "service_key_revoked";
    pub const SERVICE_NOT_PLAINTEXT_VISIBLE: &'static str = "service_not_plaintext_visible";
    pub const SERVICE_PREROTATION_INVALID: &'static str = "service_prerotation_invalid";
    pub const SESSION_FOCUS_ALREADY_COMMITTED: &'static str = "session_focus_already_committed";
    pub const SESSION_FOCUS_NO_SPLIT_BRAIN: &'static str = "session_focus_no_split_brain";
    pub const SHARE_COMMITMENT_MISMATCH: &'static str = "share_commitment_mismatch";
    pub const SIDECAR_CREATE_DENIED: &'static str = "sidecar_create_denied";
    pub const SIDECAR_EXPOSURE_ACK_REQUIRED: &'static str = "sidecar_exposure_ack_required";
    pub const SIGNAL_PLAINTEXT_FORBIDDEN: &'static str = "signal_plaintext_forbidden";
    pub const SNAPSHOT_ISSUER_REVOKED: &'static str = "snapshot_issuer_revoked";
    pub const SOFT_FAILED: &'static str = "soft_failed";
    pub const SPACE_ALREADY_TERMINAL: &'static str = "space_already_terminal";
    pub const SPACE_HAS_LIVE_DEPENDENTS: &'static str = "space_has_live_dependents";
    pub const SPACE_NOT_ACTIVE: &'static str = "space_not_active";
    pub const SPACE_NOT_ARCHIVED: &'static str = "space_not_archived";
    pub const SPACE_PARENT_CHAIN_IN_BOTTOM_STATE: &'static str =
        "space_parent_chain_in_bottom_state";
    pub const SPACE_PARENT_CYCLE: &'static str = "space_parent_cycle";
    pub const SPACE_PARENT_UNREADABLE: &'static str = "space_parent_unreadable";
    pub const SPAM: &'static str = "spam";
    pub const STALE_BACKUP_TRUST_GENERATION: &'static str = "stale_backup_trust_generation";
    pub const STATE_MISMATCH: &'static str = "state_mismatch";
    pub const STORAGE_FAILED: &'static str = "storage_failed";
    pub const STRAND_ALREADY_TERMINAL: &'static str = "strand_already_terminal";
    pub const STRAND_NOT_ACTIVE: &'static str = "strand_not_active";
    pub const STRAND_NOT_ARCHIVED: &'static str = "strand_not_archived";
    pub const STRUCTURE_DEPTH_EXCEEDED: &'static str = "structure_depth_exceeded";
    pub const SUBDELEGATION_PROHIBITED: &'static str = "subdelegation_prohibited";
    pub const SUPERSEDED: &'static str = "superseded";
    pub const SUPERSEDED_BY_REPAIRING: &'static str = "superseded_by_repairing";
    pub const THIRD_PARTY_INVITE_TOKEN_IN_QUERY: &'static str = "third_party_invite_token_in_query";
    pub const TOKEN_EXPIRED: &'static str = "token_expired";
    pub const TOKEN_ISSUER_UNAUTHORISED: &'static str = "token_issuer_unauthorised";
    pub const TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED: &'static str =
        "transcription_artifact_pipeline_bypassed";
    pub const TRANSCRIPTION_DENIED: &'static str = "transcription_denied";
    pub const TTL_EXPIRED: &'static str = "ttl_expired";
    pub const UNKNOWN_EVENT_KIND: &'static str = "unknown_event_kind";
    pub const UNKNOWN_FIELD: &'static str = "unknown_field";
    pub const UNKNOWN_FOCUS_TYPE: &'static str = "unknown_focus_type";
    pub const UNKNOWN_KIND: &'static str = "unknown_kind";
    pub const UNRESOLVED_BASIS: &'static str = "unresolved_basis";
    pub const UNSUPPORTED_AEAD_PROFILE: &'static str = "unsupported_aead_profile";
    pub const UNSUPPORTED_ATTACHMENT_SCHEME: &'static str = "unsupported_attachment_scheme";
    pub const UNSUPPORTED_DIGEST_ALGORITHM: &'static str = "unsupported_digest_algorithm";
    pub const UNSUPPORTED_EVENT_KIND: &'static str = "unsupported_event_kind";
    pub const UNSUPPORTED_FEATURE: &'static str = "unsupported_feature";
    pub const UNSUPPORTED_HPKE_SUITE: &'static str = "unsupported_hpke_suite";
    pub const UNSUPPORTED_SIGNATURE_ALG: &'static str = "unsupported_signature_alg";
    pub const UNTRUSTED_BACKUP_SIGNATURE: &'static str = "untrusted_backup_signature";
    pub const VERIFICATION_METHOD_PRINCIPAL_MISMATCH: &'static str =
        "verification_method_principal_mismatch";
    pub const VIEW_ALREADY_TERMINAL: &'static str = "view_already_terminal";
    pub const WATCH_LEVEL_PUBLIC_MUST_BE_SELF: &'static str = "watch_level_public_must_be_self";
    pub const WATCH_MUST_BE_SELF: &'static str = "watch_must_be_self";
    pub const WATCH_MUTED_MUST_BE_SELF: &'static str = "watch_muted_must_be_self";
    pub const WATCH_SET_OTHERS_AUDIT_MISSING: &'static str = "watch_set_others_audit_missing";
    pub const WEBVH_CACHE_TOO_STALE: &'static str = "webvh_cache_too_stale";
    pub const WEBVH_CACHE_UNAVAILABLE: &'static str = "webvh_cache_unavailable";
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
            Self::AbuseCluster => "abuse_cluster",
            Self::AbuseNetwork => "abuse_network",
            Self::AbuseReview => "abuse_review",
            Self::AccountStatusTransitionInvalid => "account_status_transition_invalid",
            Self::AccountabilityGrantMissing => "accountability_grant_missing",
            Self::ActorKindReducerManaged => "actor_kind_reducer_managed",
            Self::ActorSignatureRevoked => "actor_signature_revoked",
            Self::AeadNonceCounterReplay => "aead_nonce_counter_replay",
            Self::AeadNonceDerivationInvalid => "aead_nonce_derivation_invalid",
            Self::AeadNonceSenderDomainCollision => "aead_nonce_sender_domain_collision",
            Self::AgentDeactivated => "agent_deactivated",
            Self::AgentDeactivationRevocationsIncomplete => {
                "agent_deactivation_revocations_incomplete"
            }
            Self::AgentGrantConstraintMissing => "agent_grant_constraint_missing",
            Self::AgentGrantExceedsRequestedScope => "agent_grant_exceeds_requested_scope",
            Self::AgentGrantExpiryRequired => "agent_grant_expiry_required",
            Self::AgentKeyAuthorizationExpired => "agent_key_authorization_expired",
            Self::AgentParticipationCeilingUnresolved => "agent_participation_ceiling_unresolved",
            Self::AgentParticipationCeilingWiden => "agent_participation_ceiling_widen",
            Self::AgentParticipationExceedsCeiling => "agent_participation_exceeds_ceiling",
            Self::AgentPaused => "agent_paused",
            Self::AgentPcrRecoveryNotReady => "agent_pcr_recovery_not_ready",
            Self::AgentReplyNotPermitted => "agent_reply_not_permitted",
            Self::AgentRequestedScopeCommitmentInvalid => {
                "agent_requested_scope_commitment_invalid"
            }
            Self::AgentRuntimeRequestConflict => "agent_runtime_request_conflict",
            Self::AppealModifyMissingLift => "appeal_modify_missing_lift",
            Self::AppealOverturnMissingLift => "appeal_overturn_missing_lift",
            Self::AppealSelfReviewForbidden => "appeal_self_review_forbidden",
            Self::AppletNamespaceMismatch => "applet_namespace_mismatch",
            Self::ApprovalAlreadyConsumed => "approval_already_consumed",
            Self::ApprovalNonceReused => "approval_nonce_reused",
            Self::ApprovalRequired => "approval_required",
            Self::AttestationMissing => "attestation_missing",
            Self::AudienceMismatch => "audience_mismatch",
            Self::AuditAgentAttestationMismatch => "audit_agent_attestation_mismatch",
            Self::AuditAgentDestructionNotPairedWithRemove => {
                "audit_agent_destruction_not_paired_with_remove"
            }
            Self::AuditAgentDestructionProofNotEnclaveSigned => {
                "audit_agent_destruction_proof_not_enclave_signed"
            }
            Self::AuditAgentEpochRangeIncomplete => "audit_agent_epoch_range_incomplete",
            Self::AuditAgentKeyDestructionAttestationMissing => {
                "audit_agent_key_destruction_attestation_missing"
            }
            Self::AuditAgentRemoveRequiresPairedDestructionAttestation => {
                "audit_agent_remove_requires_paired_destruction_attestation"
            }
            Self::AuditCapabilityIncomplete => "audit_capability_incomplete",
            Self::AuditPurposeMismatch => "audit_purpose_mismatch",
            Self::AuditReceiptInvalidated => "audit_receipt_invalidated",
            Self::AuditReleaseAttestationInvalid => "audit_release_attestation_invalid",
            Self::AuditReleaseAttestationMismatch => "audit_release_attestation_mismatch",
            Self::AuditReleaseBindingInactive => "audit_release_binding_inactive",
            Self::AuditReleaseBindingMissing => "audit_release_binding_missing",
            Self::AuditReleaseCurrentEpochForbidden => "audit_release_current_epoch_forbidden",
            Self::AuditReleaseManifestInvalid => "audit_release_manifest_invalid",
            Self::AuditReleaseNoticeMissing => "audit_release_notice_missing",
            Self::AuditReleaseRetroactiveScopeForbidden => {
                "audit_release_retroactive_scope_forbidden"
            }
            Self::AuditReleaseScopeMismatch => "audit_release_scope_mismatch",
            Self::AuthIncomplete => "auth_incomplete",
            Self::AuthorizedGrantRevoked => "authorized_grant_revoked",
            Self::BackendUnavailable => "backend_unavailable",
            Self::BackupFrontierStale => "backup_frontier_stale",
            Self::BackupPostResetStale => "backup_post_reset_stale",
            Self::BlobRedacted => "blob_redacted",
            Self::CalendarActivationMismatch => "calendar_activation_mismatch",
            Self::CalendarEventCancelled => "calendar_event_cancelled",
            Self::CalendarScheduleUnsettled => "calendar_schedule_unsettled",
            Self::CalendarTzdbMismatch => "calendar_tzdb_mismatch",
            Self::CallModerationUnauthorised => "call_moderation_unauthorised",
            Self::CallParticipantRemoved => "call_participant_removed",
            Self::CallStateTerminal => "call_state_terminal",
            Self::CallStateTransitionInvalid => "call_state_transition_invalid",
            Self::CallSummaryInvalid => "call_summary_invalid",
            Self::CapabilityRegistryBasisUnavailable => "capability_registry_basis_unavailable",
            Self::CardinalityViolation => "cardinality_violation",
            Self::CausalRefsTooLarge => "causal_refs_too_large",
            Self::CborBoundsInvalid => "cbor_bounds_invalid",
            Self::CborNotDeterministic => "cbor_not_deterministic",
            Self::CellInBottomState => "cell_in_bottom_state",
            Self::ChallengeExpired => "challenge_expired",
            Self::ChallengeFailed => "challenge_failed",
            Self::ChallengeProofInvalid => "challenge_proof_invalid",
            Self::CircleAlreadyTerminal => "circle_already_terminal",
            Self::CircleCountExceeded => "circle_count_exceeded",
            Self::CircleEncryptionBelowRealmFloor => "circle_encryption_below_realm_floor",
            Self::CircleMemberMustBeRealmMember => "circle_member_must_be_realm_member",
            Self::CircleNotActive => "circle_not_active",
            Self::CircleNotArchived => "circle_not_archived",
            Self::CircleRealmMismatch => "circle_realm_mismatch",
            Self::CircleShortNameTaken => "circle_short_name_taken",
            Self::ClaimGenerationMismatch => "claim_generation_mismatch",
            Self::ClaimInvalid => "claim_invalid",
            Self::ClaimRateLimited => "claim_rate_limited",
            Self::ConflictingE2eeProfiles => "conflicting_e2ee_profiles",
            Self::ConsentRevoked => "consent_revoked",
            Self::ConsentWithdrawn => "consent_withdrawn",
            Self::ContentEncryptionFloorDowngrade => "content_encryption_floor_downgrade",
            Self::ContentEncryptionFloorViolation => "content_encryption_floor_violation",
            Self::ControlProposalDecisionOverdue => "control_proposal_decision_overdue",
            Self::ControllerMembershipEnded => "controller_membership_ended",
            Self::CounterBoundExceeded => "counter_bound_exceeded",
            Self::CoveredSetMismatch => "covered_set_mismatch",
            Self::CrossDomainReplayRejected => "cross_domain_replay_rejected",
            Self::CrossRealmStructuralRelation => "cross_realm_structural_relation",
            Self::CrossSigningReset => "cross_signing_reset",
            Self::CrossSigningResetAttestationMissing => "cross_signing_reset_attestation_missing",
            Self::CrossSigningResetClockSkewExceeded => "cross_signing_reset_clock_skew_exceeded",
            Self::CrossSigningResetGenerationMismatch => "cross_signing_reset_generation_mismatch",
            Self::CrossSigningResetProofAuthorityInvalid => {
                "cross_signing_reset_proof_authority_invalid"
            }
            Self::CrossSigningResetQuorumBelowPolicy => "cross_signing_reset_quorum_below_policy",
            Self::CrossSigningResetQuorumInsufficient => "cross_signing_reset_quorum_insufficient",
            Self::CrossSigningResetRecoveryRefUnknown => "cross_signing_reset_recovery_ref_unknown",
            Self::CrossSigningResetRecoveryServiceAttestationDomainMismatch => {
                "cross_signing_reset_recovery_service_attestation_domain_mismatch"
            }
            Self::CrossSigningResetRecoveryServiceUnknown => {
                "cross_signing_reset_recovery_service_unknown"
            }
            Self::CrossSigningResetReplayed => "cross_signing_reset_replayed",
            Self::CrossSigningResetSignatureInvalid => "cross_signing_reset_signature_invalid",
            Self::CrossSigningResetUnlockCommitmentMismatch => {
                "cross_signing_reset_unlock_commitment_mismatch"
            }
            Self::CrossSpaceStructuralRelation => "cross_space_structural_relation",
            Self::CursorExpired => "cursor_expired",
            Self::CursorIntegrityInvalid => "cursor_integrity_invalid",
            Self::CursorRevoked => "cursor_revoked",
            Self::CursorUnrecognized => "cursor_unrecognized",
            Self::DeactivationFederationIncomplete => "deactivation_federation_incomplete",
            Self::DecryptionFailed => "decryption_failed",
            Self::DecryptionPending => "decryption_pending",
            Self::DelegationCycle => "delegation_cycle",
            Self::DelegationExpiryWidening => "delegation_expiry_widening",
            Self::DelegationRevoked => "delegation_revoked",
            Self::DelegationScopeCustomUnsupported => "delegation_scope_custom_unsupported",
            Self::DelegationScopeMismatch => "delegation_scope_mismatch",
            Self::DeliveryBindingHandoverProofInvalid => "delivery_binding_handover_proof_invalid",
            Self::DeliveryBindingHandoverRateLimited => "delivery_binding_handover_rate_limited",
            Self::DeliveryBindingInvalid => "delivery_binding_invalid",
            Self::DeliveryBindingPolicyMismatch => "delivery_binding_policy_mismatch",
            Self::DeliveryBindingStale => "delivery_binding_stale",
            Self::DeltaContainsDataEvent => "delta_contains_data_event",
            Self::DependencyMissing => "dependency_missing",
            Self::DeviceAuthorizedPrincipalControlRealmMismatch => {
                "device_authorized_principal_control_realm_mismatch"
            }
            Self::DeviceEnrollmentAuthoritySnapshotMissing => {
                "device_enrollment_authority_snapshot_missing"
            }
            Self::DeviceGenerationFenced => "device_generation_fenced",
            Self::DeviceReanchorAuthorizeMismatch => "device_reanchor_authorize_mismatch",
            Self::DeviceReanchorConflict => "device_reanchor_conflict",
            Self::DeviceReanchorEntryNotHead => "device_reanchor_entry_not_head",
            Self::DeviceReanchorFrontierMismatch => "device_reanchor_frontier_mismatch",
            Self::DeviceRecoverySskGenerationMismatch => "device_recovery_ssk_generation_mismatch",
            Self::DidProofReplayWindowExceeded => "did_proof_replay_window_exceeded",
            Self::DirectConversationBindingInvalid => "direct_conversation_binding_invalid",
            Self::DirectConversationInviteForbidden => "direct_conversation_invite_forbidden",
            Self::DirectConversationMemberCountInvalid => {
                "direct_conversation_member_count_invalid"
            }
            Self::DirectConversationSpaceForbidden => "direct_conversation_space_forbidden",
            Self::DirectConversationThirdPartyMemberForbidden => {
                "direct_conversation_third_party_member_forbidden"
            }
            Self::DirectDownloadDisallowedPresignForbidden => {
                "direct_download_disallowed_presign_forbidden"
            }
            Self::DuplicateConflict => "duplicate_conflict",
            Self::DurabilityRecoveryRecipientUnverified => {
                "durability_recovery_recipient_unverified"
            }
            Self::DurabilitySchemeIncompatible => "durability_scheme_incompatible",
            Self::DurabilitySealMissingBeforeGc => "durability_seal_missing_before_gc",
            Self::E2eeKeySourceUnauthorised => "e2ee_key_source_unauthorised",
            Self::E2eeRelaxedDisallowedInComplianceProfile => {
                "e2ee_relaxed_disallowed_in_compliance_profile"
            }
            Self::E2eeRelaxedFederationPolicyUnsupported => {
                "e2ee_relaxed_federation_policy_unsupported"
            }
            Self::EffectiveScopeReducerManaged => "effective_scope_reducer_managed",
            Self::EgressPolicyDenied => "egress_policy_denied",
            Self::EpochUpdateRequired => "epoch_update_required",
            Self::ErasurePendingIsTerminal => "erasure_pending_is_terminal",
            Self::ErasureReceiptStubDigestMismatch => "erasure_receipt_stub_digest_mismatch",
            Self::EvidenceRecipientMismatch => "evidence_recipient_mismatch",
            Self::ExecutedByMissing => "executed_by_missing",
            Self::ExpiredInviteToken => "expired_invite_token",
            Self::ExternalRateLimited => "external_rate_limited",
            Self::FederationAuthorityMismatch => "federation_authority_mismatch",
            Self::FederationTrustDomainMismatch => "federation_trust_domain_mismatch",
            Self::FocusMismatch => "focus_mismatch",
            Self::FocusUnavailableForClient => "focus_unavailable_for_client",
            Self::ForensicAttributionMismatch => "forensic_attribution_mismatch",
            Self::GateCheckFailed => "gate_check_failed",
            Self::GovernanceBindingMismatch => "governance_binding_mismatch",
            Self::GrantExceedsIssuerAuthority => "grant_exceeds_issuer_authority",
            Self::GrantRevokedBeforeEventFrontier => "grant_revoked_before_event_frontier",
            Self::GrantRevokedUpstream => "grant_revoked_upstream",
            Self::GrantValidityWindowEmpty => "grant_validity_window_empty",
            Self::HandleHolderAcceptanceMissing => "handle_holder_acceptance_missing",
            Self::HandleHomographForbidden => "handle_homograph_forbidden",
            Self::HandleSubjectMismatch => "handle_subject_mismatch",
            Self::Harassment => "harassment",
            Self::HateSpeech => "hate_speech",
            Self::HistoryVisibilityRequiresHistoryCapableScheme => {
                "history_visibility_requires_history_capable_scheme"
            }
            Self::HumanApprovalRequired => "human_approval_required",
            Self::IdentityLinkNoLongerVisible => "identity_link_no_longer_visible",
            Self::IdentityLinkPolicyTightened => "identity_link_policy_tightened",
            Self::Illegal => "illegal",
            Self::InceptionUpgradeEvidenceInsufficient => "inception_upgrade_evidence_insufficient",
            Self::InceptionUpgradeEvidenceStale => "inception_upgrade_evidence_stale",
            Self::InceptionUpgradeFingerprintMismatch => "inception_upgrade_fingerprint_mismatch",
            Self::InceptionUpgradeOldDocumentHashMismatch => {
                "inception_upgrade_old_document_hash_mismatch"
            }
            Self::InceptionUpgradeSignatureChainInvalid => {
                "inception_upgrade_signature_chain_invalid"
            }
            Self::InclusionListViolation => "inclusion_list_violation",
            Self::InclusionProofFailed => "inclusion_proof_failed",
            Self::InsufficientChallengeSamples => "insufficient_challenge_samples",
            Self::IntegrityFailed => "integrity_failed",
            Self::InternalError => "internal_error",
            Self::InvalidAckToken => "invalid_ack_token",
            Self::InvalidAppealFsmTransition => "invalid_appeal_fsm_transition",
            Self::InvalidCanonicalJson => "invalid_canonical_json",
            Self::InvalidCursor => "invalid_cursor",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InvalidGenesisSeal => "invalid_genesis_seal",
            Self::InvalidMembershipTransition => "invalid_membership_transition",
            Self::InvalidRealmFoundingGrant => "invalid_realm_founding_grant",
            Self::InvalidTaskFsmTransition => "invalid_task_fsm_transition",
            Self::InvalidatedByRateLimit => "invalidated_by_rate_limit",
            Self::InviteAlreadyTerminal => "invite_already_terminal",
            Self::InviteOobEntropyTooLow => "invite_oob_entropy_too_low",
            Self::JoinAuthorisationInvalid => "join_authorisation_invalid",
            Self::JoinPolicyDuplicateGateId => "join_policy_duplicate_gate_id",
            Self::JoinRulePolicyMismatch => "join_rule_policy_mismatch",
            Self::JoinRuleTightened => "join_rule_tightened",
            Self::KeyBackupWireSchemaRequired => "key_backup_wire_schema_required",
            Self::KeypackageClaimRateLimited => "keypackage_claim_rate_limited",
            Self::KeypackageExpired => "keypackage_expired",
            Self::KeypackageRefreshRequired => "keypackage_refresh_required",
            Self::KeypackageRotated => "keypackage_rotated",
            Self::KeypackageWelcomeEnvelopeMismatch => "keypackage_welcome_envelope_mismatch",
            Self::LastResortNotSupported => "last_resort_not_supported",
            Self::LastResortRealmAffinityViolation => "last_resort_realm_affinity_violation",
            Self::LastResortRotationRequired => "last_resort_rotation_required",
            Self::LateRecoveryRejectedExpired => "late_recovery_rejected_expired",
            Self::LateRecoveryRejectedMembership => "late_recovery_rejected_membership",
            Self::LateRecoveryShareNotAuthorized => "late_recovery_share_not_authorized",
            Self::LegalHoldActive => "legal_hold_active",
            Self::LiteProfileWritesDisallowedEventKind => {
                "lite_profile_writes_disallowed_event_kind"
            }
            Self::MediaNegotiationTimeout => "media_negotiation_timeout",
            Self::MediaPlaintextServiceNotAuthorised => "media_plaintext_service_not_authorised",
            Self::MediaPlaintextWarningRequired => "media_plaintext_warning_required",
            Self::MediaServiceBindingUncovered => "media_service_binding_uncovered",
            Self::MediaServiceFociRequired => "media_service_foci_required",
            Self::MediaSourceUnavailable => "media_source_unavailable",
            Self::MemberIdentityProofInvalid => "member_identity_proof_invalid",
            Self::MemberIdentityReplacementDigestMismatch => {
                "member_identity_replacement_digest_mismatch"
            }
            Self::MemberIdentityStateMismatch => "member_identity_state_mismatch",
            Self::MemberIdentityUnknownSegment => "member_identity_unknown_segment",
            Self::MessageAlreadyTerminal => "message_already_terminal",
            Self::MessageIdConflict => "message_id_conflict",
            Self::MetadataEncryptionFloorDowngrade => "metadata_encryption_floor_downgrade",
            Self::MetadataEncryptionFloorViolation => "metadata_encryption_floor_violation",
            Self::MimiDraftUnsupported => "mimi_draft_unsupported",
            Self::MimiGovernanceBindingMismatch => "mimi_governance_binding_mismatch",
            Self::MimiGovernanceBindingMissing => "mimi_governance_binding_missing",
            Self::MimiObserverWriteForbidden => "mimi_observer_write_forbidden",
            Self::MimiPolicyRootMismatch => "mimi_policy_root_mismatch",
            Self::MimiProviderUnreachable => "mimi_provider_unreachable",
            Self::MimiRoomBindingStatusTransitionInvalid => {
                "mimi_room_binding_status_transition_invalid"
            }
            Self::MimiRoomStateIncompatible => "mimi_room_state_incompatible",
            Self::MinimalDisclosureViolation => "minimal_disclosure_violation",
            Self::MinimalMetadataAuthorCredentialInvalid => {
                "minimal_metadata_author_credential_invalid"
            }
            Self::MinimalMetadataPresignForbidden => "minimal_metadata_presign_forbidden",
            Self::Misinformation => "misinformation",
            Self::MissingParentReference => "missing_parent_reference",
            Self::MlsGovernanceBindingStale => "mls_governance_binding_stale",
            Self::MlsSendPauseAdvisoryRequiresE2eeRelaxedProfile => {
                "mls_send_pause_advisory_requires_e2ee_relaxed_profile"
            }
            Self::ModerationControlLifted => "moderation_control_lifted",
            Self::ModerationControlPending => "moderation_control_pending",
            Self::ModerationControlSplit => "moderation_control_split",
            Self::ModerationStateConflict => "moderation_state_conflict",
            Self::MorphAlreadyTerminal => "morph_already_terminal",
            Self::MorphNotActive => "morph_not_active",
            Self::MorphNotArchived => "morph_not_archived",
            Self::MorphSchemaRefsEvolutionUnauthorized => {
                "morph_schema_refs_evolution_unauthorized"
            }
            Self::MorphSchemaRefsPreconditionMismatch => "morph_schema_refs_precondition_mismatch",
            Self::MorphSchemaRefsTransformationUnsupported => {
                "morph_schema_refs_transformation_unsupported"
            }
            Self::MorphSchemaVersionBindingMissing => "morph_schema_version_binding_missing",
            Self::NamingConventionViolation => "naming_convention_violation",
            Self::NoStrandTrackMessageGrant => "no_strand_track_message_grant",
            Self::NotProvisioned => "not_provisioned",
            Self::Nsfw => "nsfw",
            Self::Ok => "ok",
            Self::OperatorRejected => "operator_rejected",
            Self::Other => "other",
            Self::OutOfOrderBootstrap => "out_of_order_bootstrap",
            Self::PairingExpired => "pairing_expired",
            Self::PairingRequestExpired => "pairing_request_expired",
            Self::PartialAuthState => "partial_auth_state",
            Self::ParticipantBindingInvalid => "participant_binding_invalid",
            Self::ParticipantIdentityUnrecognised => "participant_identity_unrecognised",
            Self::PatchAtomicConflict => "patch_atomic_conflict",
            Self::PatchPathInvalid => "patch_path_invalid",
            Self::PatchPathReducerManaged => "patch_path_reducer_managed",
            Self::PatchUnsetRedactableField => "patch_unset_redactable_field",
            Self::PermissionDenied => "permission_denied",
            Self::PlaneCrossWrite => "plane_cross_write",
            Self::PolicyDenied => "policy_denied",
            Self::PolicyRecall => "policy_recall",
            Self::PolicyRevisionGap => "policy_revision_gap",
            Self::PolicyRevoked => "policy_revoked",
            Self::PresignExpired => "presign_expired",
            Self::PresignInvalid => "presign_invalid",
            Self::PresignScopeMismatch => "presign_scope_mismatch",
            Self::PrevRefsTooLarge => "prev_refs_too_large",
            Self::PrincipalControlEventKindForbidden => "principal_control_event_kind_forbidden",
            Self::PrincipalDeactivated => "principal_deactivated",
            Self::PrivateAttachment => "private_attachment",
            Self::ProfileUnsupported => "profile_unsupported",
            Self::ProjectionIncomplete => "projection_incomplete",
            Self::ProofBindingMissing => "proof_binding_missing",
            Self::ProofFailed => "proof_failed",
            Self::ProofInvalid => "proof_invalid",
            Self::PushGatewayUnreachable => "push_gateway_unreachable",
            Self::PushPayloadTooLarge => "push_payload_too_large",
            Self::PushRouteLimitExceeded => "push_route_limit_exceeded",
            Self::PushRouteRegistrationRateLimited => "push_route_registration_rate_limited",
            Self::PushTargetUnknown => "push_target_unknown",
            Self::PushTokenInvalid => "push_token_invalid",
            Self::PushTokenUnknown => "push_token_unknown",
            Self::Quarantined => "quarantined",
            Self::QueueFull => "queue_full",
            Self::QuorumUnreachable => "quorum_unreachable",
            Self::RangeCompletenessActorSeqGap => "range_completeness_actor_seq_gap",
            Self::RangeCompletenessRootMismatch => "range_completeness_root_mismatch",
            Self::RateLimited => "rate_limited",
            Self::ReactionScopeMismatch => "reaction_scope_mismatch",
            Self::ReactionTargetUnsupported => "reaction_target_unsupported",
            Self::ReadReceiptForcedPublicWorldReadableForbidden => {
                "read_receipt_forced_public_world_readable_forbidden"
            }
            Self::ReadReceiptVisibilityCombinationInvalid => {
                "read_receipt_visibility_combination_invalid"
            }
            Self::RealmAliasHomographForbidden => "realm_alias_homograph_forbidden",
            Self::RealmAlreadyExists => "realm_already_exists",
            Self::RealmFoundingGrantMissing => "realm_founding_grant_missing",
            Self::RealmLinkInvalidTransition => "realm_link_invalid_transition",
            Self::RealmLinkSelfReference => "realm_link_self_reference",
            Self::RealmOrganizationAuthorizationInvalid => {
                "realm_organization_authorization_invalid"
            }
            Self::RealmOrganizationDelegationMissing => "realm_organization_delegation_missing",
            Self::RealmOrganizationExpired => "realm_organization_expired",
            Self::RealmOrganizationRealmAcceptanceMissing => {
                "realm_organization_realm_acceptance_missing"
            }
            Self::RealmOrganizationScopeMissing => "realm_organization_scope_missing",
            Self::RealmTerminalState => "realm_terminal_state",
            Self::RealmUnavailable => "realm_unavailable",
            Self::RecipientUnavailable => "recipient_unavailable",
            Self::RecordingArtifactPipelineBypassed => "recording_artifact_pipeline_bypassed",
            Self::RecordingConsentRequired => "recording_consent_required",
            Self::RecordingStateTransitionInvalid => "recording_state_transition_invalid",
            Self::RecoveryCapabilityNotSealed => "recovery_capability_not_sealed",
            Self::RecoveryEvidenceUnbound => "recovery_evidence_unbound",
            Self::RecoveryPolicyGenesisNotV1 => "recovery_policy_genesis_not_v1",
            Self::RecoveryPolicyMismatch => "recovery_policy_mismatch",
            Self::RecoveryPolicySupersedesInvalid => "recovery_policy_supersedes_invalid",
            Self::RecoveryPolicyVersionNotMonotonic => "recovery_policy_version_not_monotonic",
            Self::RecoveryPrincipalIsolation => "recovery_principal_isolation",
            Self::RecoveryProofKindUnknown => "recovery_proof_kind_unknown",
            Self::RecoverySessionChallengeMismatch => "recovery_session_challenge_mismatch",
            Self::RecoverySessionTerminal => "recovery_session_terminal",
            Self::RecoveryTargetNotInBottom => "recovery_target_not_in_bottom",
            Self::RecoveryWitnessInvalid => "recovery_witness_invalid",
            Self::RecoveryWitnessMissing => "recovery_witness_missing",
            Self::RecoveryWitnessPostConflict => "recovery_witness_post_conflict",
            Self::RecoveryWitnessRevokeLagging => "recovery_witness_revoke_lagging",
            Self::ReducerProfileMismatch => "reducer_profile_mismatch",
            Self::ReducerProjectionFailed => "reducer_projection_failed",
            Self::RefsTooLarge => "refs_too_large",
            Self::RelationAlreadyTerminal => "relation_already_terminal",
            Self::RelationConflictFanoutExceeded => "relation_conflict_fanout_exceeded",
            Self::RelationKindContainsDerived => "relation_kind_contains_derived",
            Self::RelationKindWatchesDerived => "relation_kind_watches_derived",
            Self::RelationProfileCardinalityConflict => "relation_profile_cardinality_conflict",
            Self::RelationScopeUnresolved => "relation_scope_unresolved",
            Self::RelaxedWindowExceedsCeiling => "relaxed_window_exceeds_ceiling",
            Self::RequiresOrganizationApproval => "requires_organization_approval",
            Self::ReservedCircleShortName => "reserved_circle_short_name",
            Self::ResetEventIdMismatch => "reset_event_id_mismatch",
            Self::RevocationFreshnessUnknown => "revocation_freshness_unknown",
            Self::RevokeOrderUnknownRequiresBackfillOrReview => {
                "revoke_order_unknown_requires_backfill_or_review"
            }
            Self::RevokeUndoInvalidSignature => "revoke_undo_invalid_signature",
            Self::RiskPolicy => "risk_policy",
            Self::RsvpBasisNotCausal => "rsvp_basis_not_causal",
            Self::RsvpOccurrenceNotCanonical => "rsvp_occurrence_not_canonical",
            Self::ScheduleFrontierTooLarge => "schedule_frontier_too_large",
            Self::ScopeExpansionForbidden => "scope_expansion_forbidden",
            Self::ScopeIncomparable => "scope_incomparable",
            Self::ScopeRebindForbidden => "scope_rebind_forbidden",
            Self::ScopeRefMismatch => "scope_ref_mismatch",
            Self::ScopeUnavailable => "scope_unavailable",
            Self::SegmentAeadFailed => "segment_aead_failed",
            Self::SegmentBoundsInvalid => "segment_bounds_invalid",
            Self::SegmentReplay => "segment_replay",
            Self::SegmentSequenceInvalid => "segment_sequence_invalid",
            Self::SegmentStreamTruncated => "segment_stream_truncated",
            Self::SelectorActorWildcardForbidden => "selector_actor_wildcard_forbidden",
            Self::SelectorGovernanceWildcardForbidden => "selector_governance_wildcard_forbidden",
            Self::SelectorTooComplex => "selector_too_complex",
            Self::SendFailed => "send_failed",
            Self::SeriesChainBroken => "series_chain_broken",
            Self::SeriesPredecessorNotFound => "series_predecessor_not_found",
            Self::SeriesSeqNotMonotonic => "series_seq_not_monotonic",
            Self::ServiceKeyRevoked => "service_key_revoked",
            Self::ServiceNotPlaintextVisible => "service_not_plaintext_visible",
            Self::ServicePrerotationInvalid => "service_prerotation_invalid",
            Self::SessionFocusAlreadyCommitted => "session_focus_already_committed",
            Self::SessionFocusNoSplitBrain => "session_focus_no_split_brain",
            Self::ShareCommitmentMismatch => "share_commitment_mismatch",
            Self::SidecarCreateDenied => "sidecar_create_denied",
            Self::SidecarExposureAckRequired => "sidecar_exposure_ack_required",
            Self::SignalPlaintextForbidden => "signal_plaintext_forbidden",
            Self::SnapshotIssuerRevoked => "snapshot_issuer_revoked",
            Self::SoftFailed => "soft_failed",
            Self::SpaceAlreadyTerminal => "space_already_terminal",
            Self::SpaceHasLiveDependents => "space_has_live_dependents",
            Self::SpaceNotActive => "space_not_active",
            Self::SpaceNotArchived => "space_not_archived",
            Self::SpaceParentChainInBottomState => "space_parent_chain_in_bottom_state",
            Self::SpaceParentCycle => "space_parent_cycle",
            Self::SpaceParentUnreadable => "space_parent_unreadable",
            Self::Spam => "spam",
            Self::StaleBackupTrustGeneration => "stale_backup_trust_generation",
            Self::StateMismatch => "state_mismatch",
            Self::StorageFailed => "storage_failed",
            Self::StrandAlreadyTerminal => "strand_already_terminal",
            Self::StrandNotActive => "strand_not_active",
            Self::StrandNotArchived => "strand_not_archived",
            Self::StructureDepthExceeded => "structure_depth_exceeded",
            Self::SubdelegationProhibited => "subdelegation_prohibited",
            Self::Superseded => "superseded",
            Self::SupersededByRepairing => "superseded_by_repairing",
            Self::ThirdPartyInviteTokenInQuery => "third_party_invite_token_in_query",
            Self::TokenExpired => "token_expired",
            Self::TokenIssuerUnauthorised => "token_issuer_unauthorised",
            Self::TranscriptionArtifactPipelineBypassed => {
                "transcription_artifact_pipeline_bypassed"
            }
            Self::TranscriptionDenied => "transcription_denied",
            Self::TtlExpired => "ttl_expired",
            Self::UnknownEventKind => "unknown_event_kind",
            Self::UnknownField => "unknown_field",
            Self::UnknownFocusType => "unknown_focus_type",
            Self::UnknownKind => "unknown_kind",
            Self::UnresolvedBasis => "unresolved_basis",
            Self::UnsupportedAeadProfile => "unsupported_aead_profile",
            Self::UnsupportedAttachmentScheme => "unsupported_attachment_scheme",
            Self::UnsupportedDigestAlgorithm => "unsupported_digest_algorithm",
            Self::UnsupportedEventKind => "unsupported_event_kind",
            Self::UnsupportedFeature => "unsupported_feature",
            Self::UnsupportedHpkeSuite => "unsupported_hpke_suite",
            Self::UnsupportedSignatureAlg => "unsupported_signature_alg",
            Self::UntrustedBackupSignature => "untrusted_backup_signature",
            Self::VerificationMethodPrincipalMismatch => "verification_method_principal_mismatch",
            Self::ViewAlreadyTerminal => "view_already_terminal",
            Self::WatchLevelPublicMustBeSelf => "watch_level_public_must_be_self",
            Self::WatchMustBeSelf => "watch_must_be_self",
            Self::WatchMutedMustBeSelf => "watch_muted_must_be_self",
            Self::WatchSetOthersAuditMissing => "watch_set_others_audit_missing",
            Self::WebvhCacheTooStale => "webvh_cache_too_stale",
            Self::WebvhCacheUnavailable => "webvh_cache_unavailable",
            Self::WebvhWitnessControllingOrganizationUnverified => {
                "webvh_witness_controlling_organization_unverified"
            }
            Self::WebvhWitnessEvidenceStale => "webvh_witness_evidence_stale",
            Self::WebvhWitnessParameterMalformed => "webvh_witness_parameter_malformed",
            Self::WebvhWitnessProofInvalid => "webvh_witness_proof_invalid",
            Self::WebvhWitnessProofsUnavailable => "webvh_witness_proofs_unavailable",
            Self::WebvhWitnessThresholdNotMet => "webvh_witness_threshold_not_met",
            Self::WelcomeCapabilityMismatch => "welcome_capability_mismatch",
            Self::WitnessDisagreement => "witness_disagreement",
            Self::Unknown(value) => value,
        }
    }

    pub fn from_wire(value: &str) -> Self {
        match value {
            "abuse_cluster" => Self::AbuseCluster,
            "abuse_network" => Self::AbuseNetwork,
            "abuse_review" => Self::AbuseReview,
            "account_status_transition_invalid" => Self::AccountStatusTransitionInvalid,
            "accountability_grant_missing" => Self::AccountabilityGrantMissing,
            "actor_kind_reducer_managed" => Self::ActorKindReducerManaged,
            "actor_signature_revoked" => Self::ActorSignatureRevoked,
            "aead_nonce_counter_replay" => Self::AeadNonceCounterReplay,
            "aead_nonce_derivation_invalid" => Self::AeadNonceDerivationInvalid,
            "aead_nonce_sender_domain_collision" => Self::AeadNonceSenderDomainCollision,
            "agent_deactivated" => Self::AgentDeactivated,
            "agent_deactivation_revocations_incomplete" => {
                Self::AgentDeactivationRevocationsIncomplete
            }
            "agent_grant_constraint_missing" => Self::AgentGrantConstraintMissing,
            "agent_grant_exceeds_requested_scope" => Self::AgentGrantExceedsRequestedScope,
            "agent_grant_expiry_required" => Self::AgentGrantExpiryRequired,
            "agent_key_authorization_expired" => Self::AgentKeyAuthorizationExpired,
            "agent_participation_ceiling_unresolved" => Self::AgentParticipationCeilingUnresolved,
            "agent_participation_ceiling_widen" => Self::AgentParticipationCeilingWiden,
            "agent_participation_exceeds_ceiling" => Self::AgentParticipationExceedsCeiling,
            "agent_paused" => Self::AgentPaused,
            "agent_pcr_recovery_not_ready" => Self::AgentPcrRecoveryNotReady,
            "agent_reply_not_permitted" => Self::AgentReplyNotPermitted,
            "agent_requested_scope_commitment_invalid" => {
                Self::AgentRequestedScopeCommitmentInvalid
            }
            "agent_runtime_request_conflict" => Self::AgentRuntimeRequestConflict,
            "appeal_modify_missing_lift" => Self::AppealModifyMissingLift,
            "appeal_overturn_missing_lift" => Self::AppealOverturnMissingLift,
            "appeal_self_review_forbidden" => Self::AppealSelfReviewForbidden,
            "applet_namespace_mismatch" => Self::AppletNamespaceMismatch,
            "approval_already_consumed" => Self::ApprovalAlreadyConsumed,
            "approval_nonce_reused" => Self::ApprovalNonceReused,
            "approval_required" => Self::ApprovalRequired,
            "attestation_missing" => Self::AttestationMissing,
            "audience_mismatch" => Self::AudienceMismatch,
            "audit_agent_attestation_mismatch" => Self::AuditAgentAttestationMismatch,
            "audit_agent_destruction_not_paired_with_remove" => {
                Self::AuditAgentDestructionNotPairedWithRemove
            }
            "audit_agent_destruction_proof_not_enclave_signed" => {
                Self::AuditAgentDestructionProofNotEnclaveSigned
            }
            "audit_agent_epoch_range_incomplete" => Self::AuditAgentEpochRangeIncomplete,
            "audit_agent_key_destruction_attestation_missing" => {
                Self::AuditAgentKeyDestructionAttestationMissing
            }
            "audit_agent_remove_requires_paired_destruction_attestation" => {
                Self::AuditAgentRemoveRequiresPairedDestructionAttestation
            }
            "audit_capability_incomplete" => Self::AuditCapabilityIncomplete,
            "audit_purpose_mismatch" => Self::AuditPurposeMismatch,
            "audit_receipt_invalidated" => Self::AuditReceiptInvalidated,
            "audit_release_attestation_invalid" => Self::AuditReleaseAttestationInvalid,
            "audit_release_attestation_mismatch" => Self::AuditReleaseAttestationMismatch,
            "audit_release_binding_inactive" => Self::AuditReleaseBindingInactive,
            "audit_release_binding_missing" => Self::AuditReleaseBindingMissing,
            "audit_release_current_epoch_forbidden" => Self::AuditReleaseCurrentEpochForbidden,
            "audit_release_manifest_invalid" => Self::AuditReleaseManifestInvalid,
            "audit_release_notice_missing" => Self::AuditReleaseNoticeMissing,
            "audit_release_retroactive_scope_forbidden" => {
                Self::AuditReleaseRetroactiveScopeForbidden
            }
            "audit_release_scope_mismatch" => Self::AuditReleaseScopeMismatch,
            "auth_incomplete" => Self::AuthIncomplete,
            "authorized_grant_revoked" => Self::AuthorizedGrantRevoked,
            "backend_unavailable" => Self::BackendUnavailable,
            "backup_frontier_stale" => Self::BackupFrontierStale,
            "backup_post_reset_stale" => Self::BackupPostResetStale,
            "blob_redacted" => Self::BlobRedacted,
            "calendar_activation_mismatch" => Self::CalendarActivationMismatch,
            "calendar_event_cancelled" => Self::CalendarEventCancelled,
            "calendar_schedule_unsettled" => Self::CalendarScheduleUnsettled,
            "calendar_tzdb_mismatch" => Self::CalendarTzdbMismatch,
            "call_moderation_unauthorised" => Self::CallModerationUnauthorised,
            "call_participant_removed" => Self::CallParticipantRemoved,
            "call_state_terminal" => Self::CallStateTerminal,
            "call_state_transition_invalid" => Self::CallStateTransitionInvalid,
            "call_summary_invalid" => Self::CallSummaryInvalid,
            "capability_registry_basis_unavailable" => Self::CapabilityRegistryBasisUnavailable,
            "cardinality_violation" => Self::CardinalityViolation,
            "causal_refs_too_large" => Self::CausalRefsTooLarge,
            "cbor_bounds_invalid" => Self::CborBoundsInvalid,
            "cbor_not_deterministic" => Self::CborNotDeterministic,
            "cell_in_bottom_state" => Self::CellInBottomState,
            "challenge_expired" => Self::ChallengeExpired,
            "challenge_failed" => Self::ChallengeFailed,
            "challenge_proof_invalid" => Self::ChallengeProofInvalid,
            "circle_already_terminal" => Self::CircleAlreadyTerminal,
            "circle_count_exceeded" => Self::CircleCountExceeded,
            "circle_encryption_below_realm_floor" => Self::CircleEncryptionBelowRealmFloor,
            "circle_member_must_be_realm_member" => Self::CircleMemberMustBeRealmMember,
            "circle_not_active" => Self::CircleNotActive,
            "circle_not_archived" => Self::CircleNotArchived,
            "circle_realm_mismatch" => Self::CircleRealmMismatch,
            "circle_short_name_taken" => Self::CircleShortNameTaken,
            "claim_generation_mismatch" => Self::ClaimGenerationMismatch,
            "claim_invalid" => Self::ClaimInvalid,
            "claim_rate_limited" => Self::ClaimRateLimited,
            "conflicting_e2ee_profiles" => Self::ConflictingE2eeProfiles,
            "consent_revoked" => Self::ConsentRevoked,
            "consent_withdrawn" => Self::ConsentWithdrawn,
            "content_encryption_floor_downgrade" => Self::ContentEncryptionFloorDowngrade,
            "content_encryption_floor_violation" => Self::ContentEncryptionFloorViolation,
            "control_proposal_decision_overdue" => Self::ControlProposalDecisionOverdue,
            "controller_membership_ended" => Self::ControllerMembershipEnded,
            "counter_bound_exceeded" => Self::CounterBoundExceeded,
            "covered_set_mismatch" => Self::CoveredSetMismatch,
            "cross_domain_replay_rejected" => Self::CrossDomainReplayRejected,
            "cross_realm_structural_relation" => Self::CrossRealmStructuralRelation,
            "cross_signing_reset" => Self::CrossSigningReset,
            "cross_signing_reset_attestation_missing" => Self::CrossSigningResetAttestationMissing,
            "cross_signing_reset_clock_skew_exceeded" => Self::CrossSigningResetClockSkewExceeded,
            "cross_signing_reset_generation_mismatch" => Self::CrossSigningResetGenerationMismatch,
            "cross_signing_reset_proof_authority_invalid" => {
                Self::CrossSigningResetProofAuthorityInvalid
            }
            "cross_signing_reset_quorum_below_policy" => Self::CrossSigningResetQuorumBelowPolicy,
            "cross_signing_reset_quorum_insufficient" => Self::CrossSigningResetQuorumInsufficient,
            "cross_signing_reset_recovery_ref_unknown" => Self::CrossSigningResetRecoveryRefUnknown,
            "cross_signing_reset_recovery_service_attestation_domain_mismatch" => {
                Self::CrossSigningResetRecoveryServiceAttestationDomainMismatch
            }
            "cross_signing_reset_recovery_service_unknown" => {
                Self::CrossSigningResetRecoveryServiceUnknown
            }
            "cross_signing_reset_replayed" => Self::CrossSigningResetReplayed,
            "cross_signing_reset_signature_invalid" => Self::CrossSigningResetSignatureInvalid,
            "cross_signing_reset_unlock_commitment_mismatch" => {
                Self::CrossSigningResetUnlockCommitmentMismatch
            }
            "cross_space_structural_relation" => Self::CrossSpaceStructuralRelation,
            "cursor_expired" => Self::CursorExpired,
            "cursor_integrity_invalid" => Self::CursorIntegrityInvalid,
            "cursor_revoked" => Self::CursorRevoked,
            "cursor_unrecognized" => Self::CursorUnrecognized,
            "deactivation_federation_incomplete" => Self::DeactivationFederationIncomplete,
            "decryption_failed" => Self::DecryptionFailed,
            "decryption_pending" => Self::DecryptionPending,
            "delegation_cycle" => Self::DelegationCycle,
            "delegation_expiry_widening" => Self::DelegationExpiryWidening,
            "delegation_revoked" => Self::DelegationRevoked,
            "delegation_scope_custom_unsupported" => Self::DelegationScopeCustomUnsupported,
            "delegation_scope_mismatch" => Self::DelegationScopeMismatch,
            "delivery_binding_handover_proof_invalid" => Self::DeliveryBindingHandoverProofInvalid,
            "delivery_binding_handover_rate_limited" => Self::DeliveryBindingHandoverRateLimited,
            "delivery_binding_invalid" => Self::DeliveryBindingInvalid,
            "delivery_binding_policy_mismatch" => Self::DeliveryBindingPolicyMismatch,
            "delivery_binding_stale" => Self::DeliveryBindingStale,
            "delta_contains_data_event" => Self::DeltaContainsDataEvent,
            "dependency_missing" => Self::DependencyMissing,
            "device_authorized_principal_control_realm_mismatch" => {
                Self::DeviceAuthorizedPrincipalControlRealmMismatch
            }
            "device_enrollment_authority_snapshot_missing" => {
                Self::DeviceEnrollmentAuthoritySnapshotMissing
            }
            "device_generation_fenced" => Self::DeviceGenerationFenced,
            "device_reanchor_authorize_mismatch" => Self::DeviceReanchorAuthorizeMismatch,
            "device_reanchor_conflict" => Self::DeviceReanchorConflict,
            "device_reanchor_entry_not_head" => Self::DeviceReanchorEntryNotHead,
            "device_reanchor_frontier_mismatch" => Self::DeviceReanchorFrontierMismatch,
            "device_recovery_ssk_generation_mismatch" => Self::DeviceRecoverySskGenerationMismatch,
            "did_proof_replay_window_exceeded" => Self::DidProofReplayWindowExceeded,
            "direct_conversation_binding_invalid" => Self::DirectConversationBindingInvalid,
            "direct_conversation_invite_forbidden" => Self::DirectConversationInviteForbidden,
            "direct_conversation_member_count_invalid" => {
                Self::DirectConversationMemberCountInvalid
            }
            "direct_conversation_space_forbidden" => Self::DirectConversationSpaceForbidden,
            "direct_conversation_third_party_member_forbidden" => {
                Self::DirectConversationThirdPartyMemberForbidden
            }
            "direct_download_disallowed_presign_forbidden" => {
                Self::DirectDownloadDisallowedPresignForbidden
            }
            "duplicate_conflict" => Self::DuplicateConflict,
            "durability_recovery_recipient_unverified" => {
                Self::DurabilityRecoveryRecipientUnverified
            }
            "durability_scheme_incompatible" => Self::DurabilitySchemeIncompatible,
            "durability_seal_missing_before_gc" => Self::DurabilitySealMissingBeforeGc,
            "e2ee_key_source_unauthorised" => Self::E2eeKeySourceUnauthorised,
            "e2ee_relaxed_disallowed_in_compliance_profile" => {
                Self::E2eeRelaxedDisallowedInComplianceProfile
            }
            "e2ee_relaxed_federation_policy_unsupported" => {
                Self::E2eeRelaxedFederationPolicyUnsupported
            }
            "effective_scope_reducer_managed" => Self::EffectiveScopeReducerManaged,
            "egress_policy_denied" => Self::EgressPolicyDenied,
            "epoch_update_required" => Self::EpochUpdateRequired,
            "erasure_pending_is_terminal" => Self::ErasurePendingIsTerminal,
            "erasure_receipt_stub_digest_mismatch" => Self::ErasureReceiptStubDigestMismatch,
            "evidence_recipient_mismatch" => Self::EvidenceRecipientMismatch,
            "executed_by_missing" => Self::ExecutedByMissing,
            "expired_invite_token" => Self::ExpiredInviteToken,
            "external_rate_limited" => Self::ExternalRateLimited,
            "federation_authority_mismatch" => Self::FederationAuthorityMismatch,
            "federation_trust_domain_mismatch" => Self::FederationTrustDomainMismatch,
            "focus_mismatch" => Self::FocusMismatch,
            "focus_unavailable_for_client" => Self::FocusUnavailableForClient,
            "forensic_attribution_mismatch" => Self::ForensicAttributionMismatch,
            "gate_check_failed" => Self::GateCheckFailed,
            "governance_binding_mismatch" => Self::GovernanceBindingMismatch,
            "grant_exceeds_issuer_authority" => Self::GrantExceedsIssuerAuthority,
            "grant_revoked_before_event_frontier" => Self::GrantRevokedBeforeEventFrontier,
            "grant_revoked_upstream" => Self::GrantRevokedUpstream,
            "grant_validity_window_empty" => Self::GrantValidityWindowEmpty,
            "handle_holder_acceptance_missing" => Self::HandleHolderAcceptanceMissing,
            "handle_homograph_forbidden" => Self::HandleHomographForbidden,
            "handle_subject_mismatch" => Self::HandleSubjectMismatch,
            "harassment" => Self::Harassment,
            "hate_speech" => Self::HateSpeech,
            "history_visibility_requires_history_capable_scheme" => {
                Self::HistoryVisibilityRequiresHistoryCapableScheme
            }
            "human_approval_required" => Self::HumanApprovalRequired,
            "identity_link_no_longer_visible" => Self::IdentityLinkNoLongerVisible,
            "identity_link_policy_tightened" => Self::IdentityLinkPolicyTightened,
            "illegal" => Self::Illegal,
            "inception_upgrade_evidence_insufficient" => Self::InceptionUpgradeEvidenceInsufficient,
            "inception_upgrade_evidence_stale" => Self::InceptionUpgradeEvidenceStale,
            "inception_upgrade_fingerprint_mismatch" => Self::InceptionUpgradeFingerprintMismatch,
            "inception_upgrade_old_document_hash_mismatch" => {
                Self::InceptionUpgradeOldDocumentHashMismatch
            }
            "inception_upgrade_signature_chain_invalid" => {
                Self::InceptionUpgradeSignatureChainInvalid
            }
            "inclusion_list_violation" => Self::InclusionListViolation,
            "inclusion_proof_failed" => Self::InclusionProofFailed,
            "insufficient_challenge_samples" => Self::InsufficientChallengeSamples,
            "integrity_failed" => Self::IntegrityFailed,
            "internal_error" => Self::InternalError,
            "invalid_ack_token" => Self::InvalidAckToken,
            "invalid_appeal_fsm_transition" => Self::InvalidAppealFsmTransition,
            "invalid_canonical_json" => Self::InvalidCanonicalJson,
            "invalid_cursor" => Self::InvalidCursor,
            "invalid_encoding" => Self::InvalidEncoding,
            "invalid_genesis_seal" => Self::InvalidGenesisSeal,
            "invalid_membership_transition" => Self::InvalidMembershipTransition,
            "invalid_realm_founding_grant" => Self::InvalidRealmFoundingGrant,
            "invalid_task_fsm_transition" => Self::InvalidTaskFsmTransition,
            "invalidated_by_rate_limit" => Self::InvalidatedByRateLimit,
            "invite_already_terminal" => Self::InviteAlreadyTerminal,
            "invite_oob_entropy_too_low" => Self::InviteOobEntropyTooLow,
            "join_authorisation_invalid" => Self::JoinAuthorisationInvalid,
            "join_policy_duplicate_gate_id" => Self::JoinPolicyDuplicateGateId,
            "join_rule_policy_mismatch" => Self::JoinRulePolicyMismatch,
            "join_rule_tightened" => Self::JoinRuleTightened,
            "key_backup_wire_schema_required" => Self::KeyBackupWireSchemaRequired,
            "keypackage_claim_rate_limited" => Self::KeypackageClaimRateLimited,
            "keypackage_expired" => Self::KeypackageExpired,
            "keypackage_refresh_required" => Self::KeypackageRefreshRequired,
            "keypackage_rotated" => Self::KeypackageRotated,
            "keypackage_welcome_envelope_mismatch" => Self::KeypackageWelcomeEnvelopeMismatch,
            "last_resort_not_supported" => Self::LastResortNotSupported,
            "last_resort_realm_affinity_violation" => Self::LastResortRealmAffinityViolation,
            "last_resort_rotation_required" => Self::LastResortRotationRequired,
            "late_recovery_rejected_expired" => Self::LateRecoveryRejectedExpired,
            "late_recovery_rejected_membership" => Self::LateRecoveryRejectedMembership,
            "late_recovery_share_not_authorized" => Self::LateRecoveryShareNotAuthorized,
            "legal_hold_active" => Self::LegalHoldActive,
            "lite_profile_writes_disallowed_event_kind" => {
                Self::LiteProfileWritesDisallowedEventKind
            }
            "media_negotiation_timeout" => Self::MediaNegotiationTimeout,
            "media_plaintext_service_not_authorised" => Self::MediaPlaintextServiceNotAuthorised,
            "media_plaintext_warning_required" => Self::MediaPlaintextWarningRequired,
            "media_service_binding_uncovered" => Self::MediaServiceBindingUncovered,
            "media_service_foci_required" => Self::MediaServiceFociRequired,
            "media_source_unavailable" => Self::MediaSourceUnavailable,
            "member_identity_proof_invalid" => Self::MemberIdentityProofInvalid,
            "member_identity_replacement_digest_mismatch" => {
                Self::MemberIdentityReplacementDigestMismatch
            }
            "member_identity_state_mismatch" => Self::MemberIdentityStateMismatch,
            "member_identity_unknown_segment" => Self::MemberIdentityUnknownSegment,
            "message_already_terminal" => Self::MessageAlreadyTerminal,
            "message_id_conflict" => Self::MessageIdConflict,
            "metadata_encryption_floor_downgrade" => Self::MetadataEncryptionFloorDowngrade,
            "metadata_encryption_floor_violation" => Self::MetadataEncryptionFloorViolation,
            "mimi_draft_unsupported" => Self::MimiDraftUnsupported,
            "mimi_governance_binding_mismatch" => Self::MimiGovernanceBindingMismatch,
            "mimi_governance_binding_missing" => Self::MimiGovernanceBindingMissing,
            "mimi_observer_write_forbidden" => Self::MimiObserverWriteForbidden,
            "mimi_policy_root_mismatch" => Self::MimiPolicyRootMismatch,
            "mimi_provider_unreachable" => Self::MimiProviderUnreachable,
            "mimi_room_binding_status_transition_invalid" => {
                Self::MimiRoomBindingStatusTransitionInvalid
            }
            "mimi_room_state_incompatible" => Self::MimiRoomStateIncompatible,
            "minimal_disclosure_violation" => Self::MinimalDisclosureViolation,
            "minimal_metadata_author_credential_invalid" => {
                Self::MinimalMetadataAuthorCredentialInvalid
            }
            "minimal_metadata_presign_forbidden" => Self::MinimalMetadataPresignForbidden,
            "misinformation" => Self::Misinformation,
            "missing_parent_reference" => Self::MissingParentReference,
            "mls_governance_binding_stale" => Self::MlsGovernanceBindingStale,
            "mls_send_pause_advisory_requires_e2ee_relaxed_profile" => {
                Self::MlsSendPauseAdvisoryRequiresE2eeRelaxedProfile
            }
            "moderation_control_lifted" => Self::ModerationControlLifted,
            "moderation_control_pending" => Self::ModerationControlPending,
            "moderation_control_split" => Self::ModerationControlSplit,
            "moderation_state_conflict" => Self::ModerationStateConflict,
            "morph_already_terminal" => Self::MorphAlreadyTerminal,
            "morph_not_active" => Self::MorphNotActive,
            "morph_not_archived" => Self::MorphNotArchived,
            "morph_schema_refs_evolution_unauthorized" => {
                Self::MorphSchemaRefsEvolutionUnauthorized
            }
            "morph_schema_refs_precondition_mismatch" => Self::MorphSchemaRefsPreconditionMismatch,
            "morph_schema_refs_transformation_unsupported" => {
                Self::MorphSchemaRefsTransformationUnsupported
            }
            "morph_schema_version_binding_missing" => Self::MorphSchemaVersionBindingMissing,
            "naming_convention_violation" => Self::NamingConventionViolation,
            "no_strand_track_message_grant" => Self::NoStrandTrackMessageGrant,
            "not_provisioned" => Self::NotProvisioned,
            "nsfw" => Self::Nsfw,
            "ok" => Self::Ok,
            "operator_rejected" => Self::OperatorRejected,
            "other" => Self::Other,
            "out_of_order_bootstrap" => Self::OutOfOrderBootstrap,
            "pairing_expired" => Self::PairingExpired,
            "pairing_request_expired" => Self::PairingRequestExpired,
            "partial_auth_state" => Self::PartialAuthState,
            "participant_binding_invalid" => Self::ParticipantBindingInvalid,
            "participant_identity_unrecognised" => Self::ParticipantIdentityUnrecognised,
            "patch_atomic_conflict" => Self::PatchAtomicConflict,
            "patch_path_invalid" => Self::PatchPathInvalid,
            "patch_path_reducer_managed" => Self::PatchPathReducerManaged,
            "patch_unset_redactable_field" => Self::PatchUnsetRedactableField,
            "permission_denied" => Self::PermissionDenied,
            "plane_cross_write" => Self::PlaneCrossWrite,
            "policy_denied" => Self::PolicyDenied,
            "policy_recall" => Self::PolicyRecall,
            "policy_revision_gap" => Self::PolicyRevisionGap,
            "policy_revoked" => Self::PolicyRevoked,
            "presign_expired" => Self::PresignExpired,
            "presign_invalid" => Self::PresignInvalid,
            "presign_scope_mismatch" => Self::PresignScopeMismatch,
            "prev_refs_too_large" => Self::PrevRefsTooLarge,
            "principal_control_event_kind_forbidden" => Self::PrincipalControlEventKindForbidden,
            "principal_deactivated" => Self::PrincipalDeactivated,
            "private_attachment" => Self::PrivateAttachment,
            "profile_unsupported" => Self::ProfileUnsupported,
            "projection_incomplete" => Self::ProjectionIncomplete,
            "proof_binding_missing" => Self::ProofBindingMissing,
            "proof_failed" => Self::ProofFailed,
            "proof_invalid" => Self::ProofInvalid,
            "push_gateway_unreachable" => Self::PushGatewayUnreachable,
            "push_payload_too_large" => Self::PushPayloadTooLarge,
            "push_route_limit_exceeded" => Self::PushRouteLimitExceeded,
            "push_route_registration_rate_limited" => Self::PushRouteRegistrationRateLimited,
            "push_target_unknown" => Self::PushTargetUnknown,
            "push_token_invalid" => Self::PushTokenInvalid,
            "push_token_unknown" => Self::PushTokenUnknown,
            "quarantined" => Self::Quarantined,
            "queue_full" => Self::QueueFull,
            "quorum_unreachable" => Self::QuorumUnreachable,
            "range_completeness_actor_seq_gap" => Self::RangeCompletenessActorSeqGap,
            "range_completeness_root_mismatch" => Self::RangeCompletenessRootMismatch,
            "rate_limited" => Self::RateLimited,
            "reaction_scope_mismatch" => Self::ReactionScopeMismatch,
            "reaction_target_unsupported" => Self::ReactionTargetUnsupported,
            "read_receipt_forced_public_world_readable_forbidden" => {
                Self::ReadReceiptForcedPublicWorldReadableForbidden
            }
            "read_receipt_visibility_combination_invalid" => {
                Self::ReadReceiptVisibilityCombinationInvalid
            }
            "realm_alias_homograph_forbidden" => Self::RealmAliasHomographForbidden,
            "realm_already_exists" => Self::RealmAlreadyExists,
            "realm_founding_grant_missing" => Self::RealmFoundingGrantMissing,
            "realm_link_invalid_transition" => Self::RealmLinkInvalidTransition,
            "realm_link_self_reference" => Self::RealmLinkSelfReference,
            "realm_organization_authorization_invalid" => {
                Self::RealmOrganizationAuthorizationInvalid
            }
            "realm_organization_delegation_missing" => Self::RealmOrganizationDelegationMissing,
            "realm_organization_expired" => Self::RealmOrganizationExpired,
            "realm_organization_realm_acceptance_missing" => {
                Self::RealmOrganizationRealmAcceptanceMissing
            }
            "realm_organization_scope_missing" => Self::RealmOrganizationScopeMissing,
            "realm_terminal_state" => Self::RealmTerminalState,
            "realm_unavailable" => Self::RealmUnavailable,
            "recipient_unavailable" => Self::RecipientUnavailable,
            "recording_artifact_pipeline_bypassed" => Self::RecordingArtifactPipelineBypassed,
            "recording_consent_required" => Self::RecordingConsentRequired,
            "recording_state_transition_invalid" => Self::RecordingStateTransitionInvalid,
            "recovery_capability_not_sealed" => Self::RecoveryCapabilityNotSealed,
            "recovery_evidence_unbound" => Self::RecoveryEvidenceUnbound,
            "recovery_policy_genesis_not_v1" => Self::RecoveryPolicyGenesisNotV1,
            "recovery_policy_mismatch" => Self::RecoveryPolicyMismatch,
            "recovery_policy_supersedes_invalid" => Self::RecoveryPolicySupersedesInvalid,
            "recovery_policy_version_not_monotonic" => Self::RecoveryPolicyVersionNotMonotonic,
            "recovery_principal_isolation" => Self::RecoveryPrincipalIsolation,
            "recovery_proof_kind_unknown" => Self::RecoveryProofKindUnknown,
            "recovery_session_challenge_mismatch" => Self::RecoverySessionChallengeMismatch,
            "recovery_session_terminal" => Self::RecoverySessionTerminal,
            "recovery_target_not_in_bottom" => Self::RecoveryTargetNotInBottom,
            "recovery_witness_invalid" => Self::RecoveryWitnessInvalid,
            "recovery_witness_missing" => Self::RecoveryWitnessMissing,
            "recovery_witness_post_conflict" => Self::RecoveryWitnessPostConflict,
            "recovery_witness_revoke_lagging" => Self::RecoveryWitnessRevokeLagging,
            "reducer_profile_mismatch" => Self::ReducerProfileMismatch,
            "reducer_projection_failed" => Self::ReducerProjectionFailed,
            "refs_too_large" => Self::RefsTooLarge,
            "relation_already_terminal" => Self::RelationAlreadyTerminal,
            "relation_conflict_fanout_exceeded" => Self::RelationConflictFanoutExceeded,
            "relation_kind_contains_derived" => Self::RelationKindContainsDerived,
            "relation_kind_watches_derived" => Self::RelationKindWatchesDerived,
            "relation_profile_cardinality_conflict" => Self::RelationProfileCardinalityConflict,
            "relation_scope_unresolved" => Self::RelationScopeUnresolved,
            "relaxed_window_exceeds_ceiling" => Self::RelaxedWindowExceedsCeiling,
            "requires_organization_approval" => Self::RequiresOrganizationApproval,
            "reserved_circle_short_name" => Self::ReservedCircleShortName,
            "reset_event_id_mismatch" => Self::ResetEventIdMismatch,
            "revocation_freshness_unknown" => Self::RevocationFreshnessUnknown,
            "revoke_order_unknown_requires_backfill_or_review" => {
                Self::RevokeOrderUnknownRequiresBackfillOrReview
            }
            "revoke_undo_invalid_signature" => Self::RevokeUndoInvalidSignature,
            "risk_policy" => Self::RiskPolicy,
            "rsvp_basis_not_causal" => Self::RsvpBasisNotCausal,
            "rsvp_occurrence_not_canonical" => Self::RsvpOccurrenceNotCanonical,
            "schedule_frontier_too_large" => Self::ScheduleFrontierTooLarge,
            "scope_expansion_forbidden" => Self::ScopeExpansionForbidden,
            "scope_incomparable" => Self::ScopeIncomparable,
            "scope_rebind_forbidden" => Self::ScopeRebindForbidden,
            "scope_ref_mismatch" => Self::ScopeRefMismatch,
            "scope_unavailable" => Self::ScopeUnavailable,
            "segment_aead_failed" => Self::SegmentAeadFailed,
            "segment_bounds_invalid" => Self::SegmentBoundsInvalid,
            "segment_replay" => Self::SegmentReplay,
            "segment_sequence_invalid" => Self::SegmentSequenceInvalid,
            "segment_stream_truncated" => Self::SegmentStreamTruncated,
            "selector_actor_wildcard_forbidden" => Self::SelectorActorWildcardForbidden,
            "selector_governance_wildcard_forbidden" => Self::SelectorGovernanceWildcardForbidden,
            "selector_too_complex" => Self::SelectorTooComplex,
            "send_failed" => Self::SendFailed,
            "series_chain_broken" => Self::SeriesChainBroken,
            "series_predecessor_not_found" => Self::SeriesPredecessorNotFound,
            "series_seq_not_monotonic" => Self::SeriesSeqNotMonotonic,
            "service_key_revoked" => Self::ServiceKeyRevoked,
            "service_not_plaintext_visible" => Self::ServiceNotPlaintextVisible,
            "service_prerotation_invalid" => Self::ServicePrerotationInvalid,
            "session_focus_already_committed" => Self::SessionFocusAlreadyCommitted,
            "session_focus_no_split_brain" => Self::SessionFocusNoSplitBrain,
            "share_commitment_mismatch" => Self::ShareCommitmentMismatch,
            "sidecar_create_denied" => Self::SidecarCreateDenied,
            "sidecar_exposure_ack_required" => Self::SidecarExposureAckRequired,
            "signal_plaintext_forbidden" => Self::SignalPlaintextForbidden,
            "snapshot_issuer_revoked" => Self::SnapshotIssuerRevoked,
            "soft_failed" => Self::SoftFailed,
            "space_already_terminal" => Self::SpaceAlreadyTerminal,
            "space_has_live_dependents" => Self::SpaceHasLiveDependents,
            "space_not_active" => Self::SpaceNotActive,
            "space_not_archived" => Self::SpaceNotArchived,
            "space_parent_chain_in_bottom_state" => Self::SpaceParentChainInBottomState,
            "space_parent_cycle" => Self::SpaceParentCycle,
            "space_parent_unreadable" => Self::SpaceParentUnreadable,
            "spam" => Self::Spam,
            "stale_backup_trust_generation" => Self::StaleBackupTrustGeneration,
            "state_mismatch" => Self::StateMismatch,
            "storage_failed" => Self::StorageFailed,
            "strand_already_terminal" => Self::StrandAlreadyTerminal,
            "strand_not_active" => Self::StrandNotActive,
            "strand_not_archived" => Self::StrandNotArchived,
            "structure_depth_exceeded" => Self::StructureDepthExceeded,
            "subdelegation_prohibited" => Self::SubdelegationProhibited,
            "superseded" => Self::Superseded,
            "superseded_by_repairing" => Self::SupersededByRepairing,
            "third_party_invite_token_in_query" => Self::ThirdPartyInviteTokenInQuery,
            "token_expired" => Self::TokenExpired,
            "token_issuer_unauthorised" => Self::TokenIssuerUnauthorised,
            "transcription_artifact_pipeline_bypassed" => {
                Self::TranscriptionArtifactPipelineBypassed
            }
            "transcription_denied" => Self::TranscriptionDenied,
            "ttl_expired" => Self::TtlExpired,
            "unknown_event_kind" => Self::UnknownEventKind,
            "unknown_field" => Self::UnknownField,
            "unknown_focus_type" => Self::UnknownFocusType,
            "unknown_kind" => Self::UnknownKind,
            "unresolved_basis" => Self::UnresolvedBasis,
            "unsupported_aead_profile" => Self::UnsupportedAeadProfile,
            "unsupported_attachment_scheme" => Self::UnsupportedAttachmentScheme,
            "unsupported_digest_algorithm" => Self::UnsupportedDigestAlgorithm,
            "unsupported_event_kind" => Self::UnsupportedEventKind,
            "unsupported_feature" => Self::UnsupportedFeature,
            "unsupported_hpke_suite" => Self::UnsupportedHpkeSuite,
            "unsupported_signature_alg" => Self::UnsupportedSignatureAlg,
            "untrusted_backup_signature" => Self::UntrustedBackupSignature,
            "verification_method_principal_mismatch" => Self::VerificationMethodPrincipalMismatch,
            "view_already_terminal" => Self::ViewAlreadyTerminal,
            "watch_level_public_must_be_self" => Self::WatchLevelPublicMustBeSelf,
            "watch_must_be_self" => Self::WatchMustBeSelf,
            "watch_muted_must_be_self" => Self::WatchMutedMustBeSelf,
            "watch_set_others_audit_missing" => Self::WatchSetOthersAuditMissing,
            "webvh_cache_too_stale" => Self::WebvhCacheTooStale,
            "webvh_cache_unavailable" => Self::WebvhCacheUnavailable,
            "webvh_witness_controlling_organization_unverified" => {
                Self::WebvhWitnessControllingOrganizationUnverified
            }
            "webvh_witness_evidence_stale" => Self::WebvhWitnessEvidenceStale,
            "webvh_witness_parameter_malformed" => Self::WebvhWitnessParameterMalformed,
            "webvh_witness_proof_invalid" => Self::WebvhWitnessProofInvalid,
            "webvh_witness_proofs_unavailable" => Self::WebvhWitnessProofsUnavailable,
            "webvh_witness_threshold_not_met" => Self::WebvhWitnessThresholdNotMet,
            "welcome_capability_mismatch" => Self::WelcomeCapabilityMismatch,
            "witness_disagreement" => Self::WitnessDisagreement,
            _ => Self::Unknown(value.to_owned()),
        }
    }

    pub fn descriptor(&self) -> Option<&'static ReasonCodeDescriptor> {
        REASON_CODE_DESCRIPTORS
            .iter()
            .find(|row| row.code == self.as_str())
    }
}

impl Serialize for ReasonCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ReasonCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_wire(&String::deserialize(deserializer)?))
    }
}

pub const REASON_CODE_DESCRIPTORS: &[ReasonCodeDescriptor] = &[
    ReasonCodeDescriptor {
        code: "abuse_cluster",
        applies_to: &["moderation_decision"],
        description: "Multiple reports clustered together for triage; not finalized.",
    },
    ReasonCodeDescriptor {
        code: "abuse_network",
        applies_to: &["moderation_decision"],
        description: "Cross-Realm abuse network signal aggregated by moderation server.",
    },
    ReasonCodeDescriptor {
        code: "abuse_review",
        applies_to: &["moderation_decision"],
        description: "Awaiting moderator review.",
    },
    ReasonCodeDescriptor {
        code: "account_status_transition_invalid",
        applies_to: &["account_status", "event_envelope", "state_resolution"],
        description: "A `ak.account.status` event requested a `from → to` status transition not permitted by the account-status legal-transition table — e.g. reactivating a `deactivated` account (`deactivated → active`/any lower-severity), which v1 does not define because the §7.1 deactivation fanout (device revoked / KeyPackage retired / session revoked) is irreversible. The reducer / projection MUST `failed_precondition`. (Superseding `erasure_pending` uses the more specific `erasure_pending_is_terminal`.) See zh/identity/account-lifecycle.md §3.",
    },
    ReasonCodeDescriptor {
        code: "accountability_grant_missing",
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "Returned in three surfaces. (1) `event_envelope` / `auth_decision`: an Actor Profile update declares an `accountable_principal_ids[]` entry without a corresponding active `ak.identity.accountability_grant` (issuer=that DID, subject=profile.principal_id, grant_status=active, within validity window). Reducer MUST reject the entire Event with this reason and MUST NOT accept a field-stripped projection. See zh/models/actor.md §3.3.1. (2) `service_call`: returned by orchestrator HTTP operations that fan-out an accountability grant — `ak.self.agent.command.provision` rejects when the controller cannot present an issuable accountability grant for the new agent principal, and `ak.self.agent.command.resume` rejects when the controller's accountability grant over the agent has been revoked or has lapsed its freshness window since `ak.self.agent.command.pause`. HTTP callers MUST treat this as a precondition-class failure, not transient.",
    },
    ReasonCodeDescriptor {
        code: "actor_kind_reducer_managed",
        applies_to: &["schema_validation", "event_envelope"],
        description: "Sub-reason for schema_violation when actor-side submit payload carries `actor_kind`. The reducer derives actor_kind immutably from actor_id's Actor Profile after acceptance; submitters MUST NOT supply it. See zh/models/event-and-patch.md §2.1.",
    },
    ReasonCodeDescriptor {
        code: "actor_signature_revoked",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An event was signed with a device key that the deactivation/lock fanout has marked revoked. Subsequent ak.self.events.command.submit signed by that device MUST be rejected. See zh/identity/account-lifecycle.md §7.1.",
    },
    ReasonCodeDescriptor {
        code: "aead_nonce_counter_replay",
        applies_to: &["event_envelope", "encoding"],
        description: "An AEAD-encrypted payload (encrypted_payload, blob attachment, to_device, etc.) repeated a per-(key_ref, epoch, device_id) counter already seen by the receiver. The receiver MUST reject the payload before AEAD decryption to prevent attempted nonce reuse against a valid sender device. See zh/crypto-media/media-and-blob.md §3.1 and zh/conformance/encoding.md §10.1.",
    },
    ReasonCodeDescriptor {
        code: "aead_nonce_derivation_invalid",
        applies_to: &["event_envelope", "encoding"],
        description: "An AEAD nonce on the wire does not match the deterministic derivation from MLS-Exporter context {key_ref, epoch, purpose} plus (device_id, monotonic counter) mandated by zh/crypto-media/media-and-blob.md §3.1. Producers MUST NOT emit naive random nonces under shared MLS application keys; receivers MUST reject such payloads to enforce the cross-implementation nonce-uniqueness contract.",
    },
    ReasonCodeDescriptor {
        code: "aead_nonce_sender_domain_collision",
        applies_to: &["event_envelope", "encoding"],
        description: "Two active senders share an AEAD nonce sender-domain prefix (device_id-derived), so their derived nonces can collide under the same (key_ref, epoch). The receiver MUST fail closed before AEAD decryption to prevent nonce reuse compromising the epoch key. See zh/crypto-media/media-and-blob.md §3.1.",
    },
    ReasonCodeDescriptor {
        code: "agent_deactivated",
        applies_to: &["auth_decision", "service_call", "event_envelope"],
        description: "A request targeted an agent principal whose current `ak.component.agent.status.v1` cell is `deactivated` (terminal). The endpoint MUST fail closed; no resume path exists, and `ak.agent.key.revoke` / `ak.capability.revoke` fan-out is expected to be complete or in progress. Callers MUST NOT treat this as a transient error. See zh/identity/key-management.md §3.6 §4.11.",
    },
    ReasonCodeDescriptor {
        code: "agent_deactivation_revocations_incomplete",
        applies_to: &["service_call"],
        description: "Sub-reason for failed_precondition when ak.self.agent.command.deactivate does not supply revocation Events covering every authoritative active Agent key and unrevoked Agent grant, or when accepted revoke Events have not yet left both authoritative projections empty. The lifecycle Event MUST remain unaccepted and the Agent MUST remain non-terminal; after refreshing the authoritative projection, callers may replay every still-applicable signed Event id and add signed Events for newly observed residual facts. See zh/identity/key-management.md §3.6.1 Lifecycle.",
    },
    ReasonCodeDescriptor {
        code: "agent_grant_constraint_missing",
        applies_to: &["event_envelope"],
        description: "A capability grant whose subject is an agent/service principal is missing a typed constraint listed in the action's capability-action-registry required_constraints (for example allowed_strand_ids on ak.agent.sidecar.write). The reducer rejects with failed_precondition.",
    },
    ReasonCodeDescriptor {
        code: "agent_grant_exceeds_requested_scope",
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "A personal Agent Realm grant contains an action or resource not covered by the Agent's immutable provision requested_scope, or attempts to omit or relax a mandatory provision constraint. Grant attach and reducer admission MUST fail closed with failed_precondition; Realm membership, policy, participation, pairing or key authorization cannot restore authority omitted at provision time. See zh/authz/capabilities.md section 9.1 and zh/identity/key-management.md section 3.6.1.",
    },
    ReasonCodeDescriptor {
        code: "agent_grant_expiry_required",
        applies_to: &["event_envelope"],
        description: "A capability grant whose subject is an agent/service principal carries a risk_tier=high action (or an action whose registry required_constraints demand expires_at) without a finite effective expiry. capabilities.md §8: low/medium-risk agent grants may be non-expiring (revocation-governed), high-risk agent grants MUST carry a finite expires_at; the reducer rejects with failed_precondition.",
    },
    ReasonCodeDescriptor {
        code: "agent_key_authorization_expired",
        applies_to: &["auth_decision"],
        description: "Agent session issuance rejected because the referenced ak.agent.key.authorize declared an expires_at that has elapsed. Distinct from proof_invalid (malformed / unverifiable proof): the runtime should prompt the controller to re-authorize the same key (same-key re-authorization, zh/identity/key-management.md §3.6) rather than rebuild the proof. Never returned for non-expiring (absent expires_at) authorizations.",
    },
    ReasonCodeDescriptor {
        code: "agent_participation_ceiling_unresolved",
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "Evaluating `ak.self.agent.participation.resource.replace` required folding the immutable provision-derived ceiling with the deployment⊇Realm⊇Circle⊇Strand agent-participation ceiling, but one or more layers were in a bottom (⊥) / unresolvable state at the operation's basis. The fold MUST treat any unresolved layer as the most restrictive (empty selection / full deny) and the replace MUST `failed_precondition`; an unresolved layer MUST NOT be read as 'no declaration = no tightening'. See zh/authz/capabilities.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: "agent_participation_ceiling_widen",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a Realm/Circle/Strand agent_participation ceiling write would widen (enable a bit disabled by) its parent ceiling. The deployment ⊇ Realm ⊇ Circle ⊇ Strand ceiling chain is tighten-only (monotone). See zh/models/realm-and-space.md, zh/models/circle.md, zh/authz/capabilities.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: "agent_participation_exceeds_ceiling",
        applies_to: &["state_resolution", "service_call"],
        description: "Sub-reason for failed_precondition when a controller's ak.self.agent.participation.resource.replace selection enables a bit disabled by either the immutable provision-derived ceiling or the effective deployment/Realm/Circle/Strand governance ceiling. Effective participation = provision-derived ceiling ∩ governance ceiling ∩ selection. See zh/authz/capabilities.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: "agent_paused",
        applies_to: &["auth_decision", "service_call", "event_envelope"],
        description: "A request targeted an agent principal whose current `ak.component.agent.status.v1` cell is `paused`. Auth Server MUST reject new agent session grants, and any submit / sidecar / grant-management call by or for the paused agent MUST fail closed until `ak.self.agent.command.resume` lands. Distinct from `capability_denied` so callers can surface the recoverable lifecycle state. See zh/identity/key-management.md §3.6 §4.11.",
    },
    ReasonCodeDescriptor {
        code: "agent_pcr_recovery_not_ready",
        applies_to: &["service_call", "auth_decision"],
        description: "A Native Personal Agent runtime pairing commit was attempted while its controller-owned managed-PCR recovery projection was pending, stale, missing, or unverifiable. The endpoint MUST leave the pairing handle and every existing key/grant unchanged. The controller E2EE client must publish a current recovery_public_key mls_history series tail whose managed binding covers the Agent PCR accepted Seal frontier and MLS epoch, then retry the identical pairing request. See zh/identity/key-management.md §3.6.1 / §7.5.6.",
    },
    ReasonCodeDescriptor {
        code: "agent_reply_not_permitted",
        applies_to: &["state_resolution"],
        description: "A native personal agent attempted to author ak.message.create / ak.reaction.add in a scope where its effective participation reply bit is false (no reply-enabled selection ∩ ceiling covering the scope). See zh/authz/capabilities.md §5.4 and zh/models/private-objects.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "agent_requested_scope_commitment_invalid",
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "The complete immutable Agent requested_scope commitment is missing from accepted-at Agent DID history, differs from the service projection, or its domain-separated digest does not verify. Pairing, Realm grant admission, participation and agent session issuance MUST fail closed and MUST NOT treat a service-local Agent row as the authority source. See zh/identity/key-management.md section 3.6.1.",
    },
    ReasonCodeDescriptor {
        code: "agent_runtime_request_conflict",
        applies_to: &["service_call"],
        description: "A different stable runtime key binding was submitted while the same open pairing_request_id already has a pending runtime request. The service MUST return HTTP 409 and MUST NOT replace the current pending request, approval_request_id, or notification id. A retry with the same ak.agent.runtime_key_binding.v1 digest is idempotent and does not use this error. See zh/identity/key-management.md §3.6.2.",
    },
    ReasonCodeDescriptor {
        code: "appeal_modify_missing_lift",
        applies_to: &["schema_violation", "state_resolution"],
        description: "A ak.moderation.appeal.decision event with verdict=modify did not atomically include both a ak.moderation.decision.lift for the original decision_ref and the replacement decision named by modify_decision_ref. Reducer MUST reject the whole batch so the old and replacement decisions cannot remain active together. See zh/governance/content-moderation.md §5.5.2.",
    },
    ReasonCodeDescriptor {
        code: "appeal_overturn_missing_lift",
        applies_to: &["schema_violation", "state_resolution"],
        description: "A ak.moderation.appeal.decision event with verdict=overturn was accepted without a paired ak.moderation.decision.lift event in the same ordered submit batch or equivalent control transaction (targeting the original decision_ref). Reducer MUST reject; appeal overturn is only complete when the lift is observed atomically. See zh/governance/content-moderation.md §5.5.2.",
    },
    ReasonCodeDescriptor {
        code: "appeal_self_review_forbidden",
        applies_to: &["auth_decision"],
        description: "The reviewer in ak.moderation.appeal.review / ak.moderation.appeal.decision is the same actor who issued the original ak.moderation.decision being appealed. Separation of duties forbids self-review; reducer MUST reject. See zh/governance/content-moderation.md §5.5.",
    },
    ReasonCodeDescriptor {
        code: "applet_namespace_mismatch",
        applies_to: &["state_resolution", "auth_decision"],
        description: "Sub-reason for a delegated-handoff Event rejection when auth_data.executed_by is not within the applet_id registration's declared service / bot DID set or namespaces.actors pattern. Prevents a grant scoped to one applet from being exercised under an unrelated applet_id. See zh/extensions/applet-integration.md §11.",
    },
    ReasonCodeDescriptor {
        code: "approval_already_consumed",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An agent draft/action approval has already been consumed by a successful publish attempt. Replaying the same approval MUST fail closed instead of publishing twice. See zh/conformance/conformance-vectors.md.",
    },
    ReasonCodeDescriptor {
        code: "approval_nonce_reused",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An approval signature carrying a (approver_did, nonce) tuple that was already consumed for the same grant_id / proposal_id was resubmitted. Approval signatures are single-use per-grant; reusing them is a cross-grant replay attempt. See zh/authz/constraint-schema.md §9.3.",
    },
    ReasonCodeDescriptor {
        code: "approval_required",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Event was rejected because the active capability constraint requires approval evidence (per zh/authz/capabilities.md §6 / §8) and none was supplied.",
    },
    ReasonCodeDescriptor {
        code: "attestation_missing",
        applies_to: &["crypto", "device_recovery", "schema_validation"],
        description: "A `recipient_method=hardware_wrapped_key` key-backup envelope, or any recovery / cross-signing proof requiring hardware attestation, lacks an `attestation` chain that the receiver can verify against the active recovery policy's `trusted_recovery_services[]`. See zh/identity/key-management.md §7.5.5.",
    },
    ReasonCodeDescriptor {
        code: "audience_mismatch",
        applies_to: &["auth_decision", "event_envelope", "service_call"],
        description: "A proof, token, Auth Server verification result, invite claim, KeyPackage claim, or signed handoff was presented to a Realm / service / audience different from the one bound into the signed material. Receivers MUST reject rather than reinterpret the audience. See zh/conformance/conformance-vectors.md.",
    },
    ReasonCodeDescriptor {
        code: "audit_agent_attestation_mismatch",
        applies_to: &["event_envelope", "audit_decision"],
        description: "Audit Agent attestation evidence does not match the expected binding: realm_id, service_id, audit_service_actor_id, measurement, audit_purpose, policy digest, validity, or operator DID diverge from the registered audit binding. Join and release paths MUST fail closed. See zh/crypto-media/audited-e2ee.md §6 and artifacts/schemas/audit-release-attestation.schema.json.",
    },
    ReasonCodeDescriptor {
        code: "audit_agent_destruction_not_paired_with_remove",
        applies_to: &["event_envelope", "audit_decision"],
        description: "A key-destruction attestation for an Audit Agent was submitted standalone, without the paired remove (membership end) it must accompany. Destruction evidence MUST be bound to the corresponding remove; receivers MUST reject the unpaired attestation. See zh/crypto-media/audited-e2ee.md.",
    },
    ReasonCodeDescriptor {
        code: "audit_agent_destruction_proof_not_enclave_signed",
        applies_to: &["event_envelope", "audit_decision"],
        description: "The key-destruction proof for an Audit Agent was not signed by the attested enclave (TEE / HSM) key bound in the agent's attestation evidence. Software- or operator-signed destruction claims MUST be rejected under attested_hardware profiles. See zh/crypto-media/audited-e2ee.md §2 and artifacts/schemas/audit-release-attestation.schema.json.",
    },
    ReasonCodeDescriptor {
        code: "audit_agent_epoch_range_incomplete",
        applies_to: &["event_envelope", "audit_decision"],
        description: "The epoch range covered by an Audit Agent key-destruction attestation does not cover every sealed epoch the agent had access to. Gaps MUST cause rejection of the attestation (and any paired remove) instead of partial acceptance. See zh/crypto-media/audited-e2ee.md.",
    },
    ReasonCodeDescriptor {
        code: "audit_agent_key_destruction_attestation_missing",
        applies_to: &["event_envelope", "audit_decision"],
        description: "An Audit Agent lifecycle transition that ends its access to sealed epoch key material lacks the required key-destruction attestation for the epoch secrets the agent held. Receivers MUST fail closed rather than treat missing destruction evidence as destroyed. See zh/crypto-media/audited-e2ee.md and artifacts/schemas/audit-release-attestation.schema.json.",
    },
    ReasonCodeDescriptor {
        code: "audit_agent_remove_requires_paired_destruction_attestation",
        applies_to: &["event_envelope", "audit_decision"],
        description: "A remove ending an Audit Agent's membership in an audited group / Realm was submitted without the paired key-destruction attestation covering the epoch secrets the agent held. The remove MUST be rejected until the paired destruction attestation is presented. See zh/crypto-media/audited-e2ee.md.",
    },
    ReasonCodeDescriptor {
        code: "audit_capability_incomplete",
        applies_to: &["auth_decision"],
        description: "Reading the full per-Strand watch state (including `muted` entries) requires both `ak.realm.notification.audit` and `ak.audit.accessed` capabilities; one was missing. See zh/models/strand-and-message.md §8.5.",
    },
    ReasonCodeDescriptor {
        code: "audit_purpose_mismatch",
        applies_to: &["auth_decision"],
        description: "Audit release service attestation_evidence.audit_purpose does not match the active binding/session purpose. Verifier MUST reject the release evidence; the service MAY re-attest with the correct purpose. See zh/crypto-media/audited-e2ee.md §6.",
    },
    ReasonCodeDescriptor {
        code: "audit_receipt_invalidated",
        applies_to: &["audit_decision"],
        description: "A previously valid Read-Your-Writes receipt has been invalidated by subsequent backfill, witness disagreement, or audit_assurance_class / Audit Applet Binding mismatch (see zh/crypto-media/audited-e2ee.md §6).",
    },
    ReasonCodeDescriptor {
        code: "audit_release_attestation_invalid",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Attested audit release evidence does not validate against the active binding/release policy, service DID, measurement, validity window, or attestation trust root.",
    },
    ReasonCodeDescriptor {
        code: "audit_release_attestation_mismatch",
        applies_to: &["schema_violation", "event_envelope", "auth_decision"],
        description: "Audit release service attestation evidence (ak.schema.audit_release_attestation.v1) does not match the active ak.audit.applet_binding, ak.audit.release service_id, measurement, or policy digest. Reducer / verifier MUST reject. See zh/crypto-media/audited-e2ee.md §6.",
    },
    ReasonCodeDescriptor {
        code: "audit_release_binding_inactive",
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "ak.audit.release was evaluated after the referenced ak.audit.applet_binding became suspended or revoked. Reducer and release service MUST recheck binding status at release time and fail closed unless it is still active.",
    },
    ReasonCodeDescriptor {
        code: "audit_release_binding_missing",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A ak.audit.session.* or ak.audit.release event referenced no active ak.audit.applet_binding for the target Realm/Circle effective_scope. Audit release MUST fail closed without an active binding.",
    },
    ReasonCodeDescriptor {
        code: "audit_release_current_epoch_forbidden",
        applies_to: &["event_envelope", "auth_decision"],
        description: "ak.audit.release attempted to release the current active MLS epoch. Releases may cover only sealed historical epochs and MUST reference sealed_by_commit_ref when epoch material is involved.",
    },
    ReasonCodeDescriptor {
        code: "audit_release_manifest_invalid",
        applies_to: &["event_envelope", "auth_decision"],
        description: "ak.audit.release manifest is inconsistent with the authorized session, binding policy, release mode, target_refs, sealed_epoch_range, recipient key, or wrapped_material_digest set.",
    },
    ReasonCodeDescriptor {
        code: "audit_release_notice_missing",
        applies_to: &["event_envelope", "auth_decision"],
        description: "ak.audit.release lacks a valid prior ak.audit.session.notice for the same session, binding, scope, purpose, and approved range.",
    },
    ReasonCodeDescriptor {
        code: "audit_release_retroactive_scope_forbidden",
        applies_to: &["event_envelope", "auth_decision"],
        description: "ak.audit.session.* or ak.audit.release attempted to cover messages, targets, or epochs before the binding activation frontier / first_auditable_epoch, or attempted to apply a later-expanded release_window_policy to already encrypted messages. Audit Applet Binding is non-retroactive; reducers MUST fail closed.",
    },
    ReasonCodeDescriptor {
        code: "audit_release_scope_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "The audit request / authorization / notice / release effective_scope does not match the active binding or attempts to cover a Circle without a Circle-scoped binding.",
    },
    ReasonCodeDescriptor {
        code: "auth_incomplete",
        applies_to: &["auth_decision"],
        description: "Required refs[role=authorized_by] are not yet accepted at the local frontier; the event MUST be parked until the missing refs converge.",
    },
    ReasonCodeDescriptor {
        code: "authorized_grant_revoked",
        applies_to: &["authz", "event_auth_state"],
        description: "The grant referenced by refs[role=authorized_by] or an ancestor grant in its delegation chain has been revoked, superseded, expired, or tombstoned.",
    },
    ReasonCodeDescriptor {
        code: "backend_unavailable",
        applies_to: &["event_envelope", "service_call"],
        description: "The selected recording or transcription backend was unavailable.",
    },
    ReasonCodeDescriptor {
        code: "backup_frontier_stale",
        applies_to: &["device_recovery", "state_resolution"],
        description: "`ak.schema.key_backup.v1.frontier_ref.frontier_digest` does not match the current principal control stream frontier; in A model `ssk_generation` is below the current accepted generation; or in B model `device_generation_ref` does not equal the active `current_device_generation_ref` / the generation is not active. Receivers MUST refuse to use the envelope as the primary recovery source. See zh/identity/key-management.md §7.6.",
    },
    ReasonCodeDescriptor {
        code: "backup_post_reset_stale",
        applies_to: &["device_recovery", "cross_signing"],
        description: "A `secret_storage` backup envelope references a `self_signing_key` / `user_signing_key` whose generation was retired by a cross-signing reset, and the publish-recovery window elapsed without a successor envelope. Receivers MUST refuse it as the primary recovery source. See zh/crypto-media/device-lifecycle.md §14.2 step 7.",
    },
    ReasonCodeDescriptor {
        code: "blob_redacted",
        applies_to: &["state_resolution"],
        description: "Blob has been redacted (ak.redaction accepted) or hard-erased (ak.audit.erasure_receipt published) and is no longer fetchable. Both new presign requests and in-flight (not-yet-expired) presign URLs MUST be rejected with this code. See zh/crypto-media/media-and-blob.md §5.4.4.1.",
    },
    ReasonCodeDescriptor {
        code: "calendar_activation_mismatch",
        applies_to: &["event_envelope", "schema_validation"],
        description: "Sub-reason for schema_violation when Strand.schema_refs and the matching metadata.fields profile subtree do not co-occur on the post-patch object, in either direction. Applies to ak.schema.calendar_event.v1 with metadata.fields.calendar. See zh/models/calendar-event.md.",
    },
    ReasonCodeDescriptor {
        code: "calendar_event_cancelled",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A new RSVP targets a Calendar Strand whose schedule status is cancelled. Historical RSVP projection is retained; new responses are refused. The generic Strand stage axis MUST NOT be reinterpreted as calendar status. See zh/models/calendar-event.md. This is an authoring-side and projection-side code for the same reason as calendar_schedule_unsettled: the cancelled status lives in the Calendar subtree plaintext.",
    },
    ReasonCodeDescriptor {
        code: "calendar_schedule_unsettled",
        applies_to: &["event_envelope", "state_resolution"],
        description: "An RSVP or occurrence expansion was attempted while the Calendar schedule projection is conflict or encrypted_unresolved rather than settled. Concurrent schedule heads MUST be resolved by a schedule resolution Event first; no HLC, arrival order, or private last-writer rule may pick a winner. See zh/models/calendar-event.md. This is an authoring-side and projection-side code, never a server admission gate: deciding settledness requires the Calendar subtree plaintext, so gating admission on it would fork the accepted set between e2ee and plaintext Realms.",
    },
    ReasonCodeDescriptor {
        code: "calendar_tzdb_mismatch",
        applies_to: &["event_envelope", "service_call", "projection"],
        description: "The signed schedule tzdb_version is outside the receiver's executable release set declared in ServiceDescribe.calendar_tzdb_versions. The receiver MUST fail closed or mark instant projection unresolved and MUST NOT substitute a nearby or newer release. See zh/models/calendar-event.md.",
    },
    ReasonCodeDescriptor {
        code: "call_moderation_unauthorised",
        applies_to: &["service_call", "event_envelope"],
        description: "A moderator action (kick / ban / force-mute / end-for-all, via `ak.call.signal{moderation}` or a `ak.call.state` moderation field) was attempted by an actor lacking `ak.call.moderate`. Reducer / receiver MUST reject. See zh/crypto-media/webrtc-signaling.md §3a (kick / ban / end-for-all) and §6.1 (force-mute via `mute_state{by=moderator}`).",
    },
    ReasonCodeDescriptor {
        code: "call_participant_removed",
        applies_to: &["service_call"],
        description: "A participant whose `(actor_id, device_id)` has an effective kick in `ak.component.call.moderation.v1`, or whose actor has an effective ban there, attempted to re-establish a media leg or re-issue a join token. Token issuer / SFU MUST refuse; a banned actor MUST NOT rejoin until the ban is lifted. See zh/crypto-media/webrtc-signaling.md §3a.",
    },
    ReasonCodeDescriptor {
        code: "call_state_terminal",
        applies_to: &["event_envelope"],
        description: "An `ak.call.state` event attempted to transition `state_transition.from` out of a terminal value (`ended` / `missed` / `failed` / `cancelled`). Call lifecycle is monotonic; the reducer MUST `failed_precondition`. Capture lifecycles use orthogonal per-segment transition cells. See zh/crypto-media/call-state.md §4.2.",
    },
    ReasonCodeDescriptor {
        code: "call_state_transition_invalid",
        applies_to: &["event_envelope"],
        description: "A `ak.call.state` event requested a `state` transition from a non-terminal state that is not listed in the legal-successor table (transitions out of a terminal state use `call_state_terminal` instead). The reducer MUST `failed_precondition`. See zh/crypto-media/call-state.md §4.2.",
    },
    ReasonCodeDescriptor {
        code: "call_summary_invalid",
        applies_to: &["event_envelope"],
        description: "A `ak.call.summary` event was rejected because its `final_state` is not a terminal call state, the referenced `call_id` has no terminal `ak.call.state` head, or a divergent summary already exists for the call (the summary cell is write-once). Reducer MUST `failed_precondition`. See zh/crypto-media/call-state.md §7.",
    },
    ReasonCodeDescriptor {
        code: "capability_registry_basis_unavailable",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An aggregate capability grant pins a capability-action registry digest whose canonical snapshot is unavailable or whose JCS digest does not match. Receiver MUST fail closed and MUST NOT expand the grant against the current registry.",
    },
    ReasonCodeDescriptor {
        code: "cardinality_violation",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An event violates a declared relation / cell cardinality constraint.",
    },
    ReasonCodeDescriptor {
        code: "causal_refs_too_large",
        applies_to: &["schema_validation", "event_envelope"],
        description: "Event Envelope causal_refs exceeds the v1 maximum of 128 entries or contains duplicates. Receiver MUST reject with schema_violation and MUST NOT truncate the causal frontier. See zh/conformance/scalability-constraints.md.",
    },
    ReasonCodeDescriptor {
        code: "cbor_bounds_invalid",
        applies_to: &["encoding", "schema_validation"],
        description: "A hand-written deterministic CBOR structure (e.g. the mls_governance_binding GroupContext extension) violates v1 decode bounds: a single array/map declares or contains more than 65536 items, or a string / byte string / array / map header declares a length or item count exceeding the remaining input bytes (capacity bomb). Decoder MUST reject (top-level schema_violation) before allocating buffers sized from the declared length. See zh/conformance/scalability-constraints.md section 2.",
    },
    ReasonCodeDescriptor {
        code: "cbor_not_deterministic",
        applies_to: &["encoding", "schema_validation"],
        description: "A hand-written CBOR structure violates RFC 8949 section 4.2 deterministic encoding requirements: indefinite-length items (map 0xbf, array 0x9f, string 0x5f/0x7f), non-minimal length encoding, or unsorted map keys. Receiver MUST reject (top-level schema_violation) instead of normalising. See zh/conformance/scalability-constraints.md section 2 and zh/crypto-media/encryption-and-audit.md section 2.5.3.",
    },
    ReasonCodeDescriptor {
        code: "cell_in_bottom_state",
        applies_to: &["state_resolution", "auth_decision"],
        description: "A Move attempted to read or write a bottom=reject cell while the effective value is ⊥. Ordinary CAS writes MUST fail; recovery requires the conflict-recovery witness path. See zh/authz/event-auth-state-resolution.md §5.1 and §8.",
    },
    ReasonCodeDescriptor {
        code: "challenge_expired",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A Policy Server challenge obligation was not satisfied within `max_proof_age`, or a challenge_proof was submitted whose issuance is older than `max_proof_age`. The reducer / Policy Server MUST reject with failed_precondition and MUST NOT auto-renew; the applicant must re-run ak.self.policy.query.check to obtain a fresh challenge_id. See zh/governance/join-policy.md §11.",
    },
    ReasonCodeDescriptor {
        code: "challenge_failed",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A join-policy challenge gate answer (e.g. CAPTCHA / proof-of-work / knowledge challenge) submitted with a member application failed verification. Used as a `reason_code` in member.application.review reject decisions. See zh/governance/join-policy.md §7.3.",
    },
    ReasonCodeDescriptor {
        code: "challenge_proof_invalid",
        applies_to: &["auth_decision", "service_call"],
        description: "A runtime challenge proof attached to `ak.member.state{join}.gate_proofs[]` or `member.application.gate_proofs[]` (candidate kind, no `ak.*` prefix) fails verification (signature / freshness / verifier domain). See zh/authz/policy-server.md §4.",
    },
    ReasonCodeDescriptor {
        code: "circle_already_terminal",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a Circle lifecycle write targets a Circle that is already tombstoned or otherwise terminal. See zh/models/common-fields.md §5.1 and zh/models/circle.md §9.",
    },
    ReasonCodeDescriptor {
        code: "circle_count_exceeded",
        applies_to: &["event_envelope", "state_resolution"],
        description: "Reducer rejected a `ak.circle.create` exceeding the per-Realm active Circle cap, or a `ak.circle.member.state -> join` that would exceed the per-actor active MLS-backed Circle cap. Caps bound cascade/delivery fanout and the M+R MLS-rotation amplification of a single membership change (zh/conformance/scalability-constraints.md §5, zh/models/circle.md §10.3).",
    },
    ReasonCodeDescriptor {
        code: "circle_encryption_below_realm_floor",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when ak.circle.create / ak.circle.update would set a Circle encryption setting below the parent Realm floor: either Circle.encryption_profile below the parent Realm encryption_profile / effective content_encryption_floor (E2EE Realm / e2ee_required floor requires an MLS-backed Circle), or Circle.content_encryption_floor below the effective floor max(parent Realm content_encryption_floor, Circle), or a Circle with encryption_profile=none declaring content_encryption_floor=e2ee_required (no MLS-backed effective_scope to carry ciphertext). See zh/models/circle.md §7.",
    },
    ReasonCodeDescriptor {
        code: "circle_member_must_be_realm_member",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition on ak.circle.member.state -> join when target actor is not yet a `join` member of the parent Realm. Circle.members ⊆ Realm.members is a hard invariant. See zh/models/circle.md §9.1.",
    },
    ReasonCodeDescriptor {
        code: "circle_not_active",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when scope_circle_id points at a Circle whose state is archived or tombstoned. See zh/models/circle.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "circle_not_archived",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when ak.circle.restore targets a Circle whose current lifecycle state is not archived. See zh/models/common-fields.md §5.1 and zh/models/circle.md §9.",
    },
    ReasonCodeDescriptor {
        code: "circle_realm_mismatch",
        applies_to: &["schema_validation", "state_resolution"],
        description: "Sub-reason for schema_violation when an object's scope_circle_id references a Circle whose realm_id does not match the object's realm_id. See zh/models/circle.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "circle_short_name_taken",
        applies_to: &["schema_validation", "state_resolution", "service_call"],
        description: "Ordinary Circle creation or display update failed the reducer-enforced case-insensitive uniqueness of display.short_name within (realm_id, short_name). Sidecar backing Circle names are reducer-derived and any collision is hidden behind sidecar_create_denied. See zh/models/circle.md §4.",
    },
    ReasonCodeDescriptor {
        code: "claim_generation_mismatch",
        applies_to: &["crypto", "auth_decision"],
        description: "An MLS Welcome / KeyPackage claim binds a cross-signing or self-signing generation that does not equal the receiver's current accepted generation. Receivers MUST reject before admitting the Welcome or key material. See zh/crypto-media/encryption-and-audit.md §2.6 and zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "claim_invalid",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A claim, attestation, or invite / binding proof submitted with a member application is malformed, unverifiable, or fails policy checks. Used as a `reason_code` in member.application.review reject decisions. See zh/governance/join-policy.md §7.3.",
    },
    ReasonCodeDescriptor {
        code: "claim_rate_limited",
        applies_to: &["service_call", "auth_decision"],
        description: "Per-(requester, target, intended_realm_id) KeyPackage / one-time-key claim rate limit hit; caller MUST back off before retrying. Distinct from the global `rate_limited` HTTP code because the limit is keyed on the (target, intended use) tuple, not the caller alone.",
    },
    ReasonCodeDescriptor {
        code: "conflicting_e2ee_profiles",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Realm declares both ak.profile.e2ee_relaxed.v1 and ak.profile.mls_governance_binding.full.v1; these are mutually exclusive (encryption-and-audit.md §2.4.2).",
    },
    ReasonCodeDescriptor {
        code: "consent_revoked",
        applies_to: &["auth_decision"],
        description: "Authorization outcome when a cached consent decision is re-evaluated and the underlying consent has been revoked; the stale cache entry MUST NOT authorize the action. See zh/conformance/conformance-vectors.md §9 (ak.vector.consent.cache_invalidation.v1).",
    },
    ReasonCodeDescriptor {
        code: "consent_withdrawn",
        applies_to: &["event_envelope", "state_resolution"],
        description: "Required recording or transcription consent was withdrawn.",
    },
    ReasonCodeDescriptor {
        code: "content_encryption_floor_downgrade",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a ak.realm.policy_bundle or ak.circle.update would lower a scope's effective content_encryption_floor from e2ee_required back to allow_plaintext. The effective content encryption floor is a one-way ratchet (monotonically non-decreasing); tightening is allowed, lowering is rejected. See zh/models/realm-and-space.md §2.5 and zh/models/circle.md §7.",
    },
    ReasonCodeDescriptor {
        code: "content_encryption_floor_violation",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a Realm declares content_encryption_floor=e2ee_required but a Strand / Message / Morph / Blob content write would land in a non-MLS-backed effective_scope (plaintext). The content effective_scope MUST be Realm-default MLS or Circle MLS. See zh/models/circle.md §7 (Realm.content_encryption_floor).",
    },
    ReasonCodeDescriptor {
        code: "control_proposal_decision_overdue",
        applies_to: &["state_resolution", "auth_decision"],
        description: "A receipted Control Move proposal reached its signed decision_due_at without include, signed-reject, or a valid bounded signed-defer, or exhausted its immutable absolute_due_at / maximum defer count without include or signed-reject. This is a governance health and censorship-evidence fault, not an acceptance or Seal-finality result: a later cryptographically valid Seal remains acceptable and the fault stays auditable. See zh/authz/event-auth-state-resolution.md section 7.2.",
    },
    ReasonCodeDescriptor {
        code: "controller_membership_ended",
        applies_to: &["event_envelope", "state_resolution"],
        description: "Canonical reason written on reducer-generated ak.member.state transitions that move an active Native Personal Agent from join to leave because its verified controller left or was banned from the same Realm. The cascade MUST also drive Circle membership, delivery, and MLS removal convergence and MUST NOT automatically rejoin the agent if the controller later rejoins. See zh/models/actor.md §3.2 and zh/models/realm-and-space.md §2.7.",
    },
    ReasonCodeDescriptor {
        code: "counter_bound_exceeded",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A counter-lattice inc / dec op would move the cell's cumulative value past `parameters.max` (or below `parameters.min`) declared in the cell schema. The op MUST be rejected at validate_op / verify_move time with top-level `failed_precondition` carrying this reason_code; it never enters the join. See zh/authz/event-auth-state-resolution.md §9.3.",
    },
    ReasonCodeDescriptor {
        code: "covered_set_mismatch",
        applies_to: &["event_auth_state", "state_resolution"],
        description: "A compaction Seal's covered set does not match the deterministic control view of the interval it claims to compact. Mismatched coverage MUST reject; only full-coverage compaction within seal_compaction_max_interval_ms enables bootstrap. See authz/event-auth-state-resolution.md and fixtures/cba-lattice-fixture.json.",
    },
    ReasonCodeDescriptor {
        code: "cross_domain_replay_rejected",
        applies_to: &["auth_decision"],
        description: "A ak.cross_signing.reset payload declared a trust_domain that does not match the receiver's own trust_domain (or the receiver is unable to validate that the declared trust_domain belongs to this deployment). Rejected before signature verification to prevent replay of reset proofs across deployments / sovereign trust domains. See zh/crypto-media/device-lifecycle.md §14.1.",
    },
    ReasonCodeDescriptor {
        code: "cross_realm_structural_relation",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A structural `contains` Relation was submitted that would cross Realm boundaries. Structural containment (Board → List → Strand / Space hierarchy) MUST stay within a single Realm; cross-Realm links use the dedicated `ak.relation.*` non-structural kinds. See zh/models/relation.md §4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A previously trusted cross-signing key set was reset; verifications against the old `ssk_generation` MUST fail until the user re-verifies under the new generation. See zh/crypto-media/device-lifecycle.md §14.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_attestation_missing",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `trusted_recovery_service` declaration requires an `attestation_ref` but the proof omits it, or the ref does not resolve to a verifiable attestation event. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_clock_skew_exceeded",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.cross_signing.reset.issued_at` deviates from receiver local clock by more than `ak.profile.cross_signing.reset.v1.max_clock_skew_seconds`. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_generation_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.cross_signing.reset.previous_generation` does not equal the receiver's currently accepted publish generation, or `new_generation != previous_generation + 1`. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_proof_authority_invalid",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `ak.cross_signing.reset` proof was signed by a key class that does not have authority for that proof.kind: `principal_signing.verification_method` is not a principal-grade DID control key (or is the self/user signing key being retired), `recovery_unlock` is signed by a key that is not the declared recovery key, `trusted_recovery_service` is signed by a non-published verification method, or `device_quorum.signatures[i].verification_method` is not the named device's authorized key. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_quorum_below_policy",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`device_quorum.threshold` is below the principal's currently published `recovery_policy.device_quorum.threshold`; receivers MUST reject so issuers cannot weaken the quorum unilaterally. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_quorum_insufficient",
        applies_to: &["event_envelope", "auth_decision"],
        description: "After deduplication by `device_id` and signature verification, `device_quorum.signatures[]` contains fewer than `threshold` valid signatures. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_recovery_ref_unknown",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`recovery_unlock.recovery_secret_ref` does not resolve to an active recovery_keys[] signing entry in the recovery session's snapshotted accepted recovery_policy at `issued_at`. DID Document-only keys are not authoritative. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_recovery_service_attestation_domain_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `ak.cross_signing.reset` `trusted_recovery_service` proof referenced an `attestation_ref` whose trust domain does not equal the reset payload `trust_domain`. Cross-trust-domain attestations MUST NOT serve as recovery-service authorization. See zh/crypto-media/device-lifecycle.md §14.4 and cross-signing-reset.schema.json.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_recovery_service_unknown",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`trusted_recovery_service.service_id` is not declared in the recovery session's snapshotted accepted `recovery_policy.trusted_recovery_services[]`, or is outside its validity window. A DID Document-only service declaration is not sufficient. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_replayed",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Another `ak.cross_signing.reset` already consumed the same `(principal_id, previous_generation)` tuple; receivers MUST reject duplicates until the corresponding successor `ak.cross_signing.publish` is accepted + 24h. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_signature_invalid",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `ak.cross_signing.reset` proof signature failed verification: `principal_signing.signature` does not verify under the resolved principal-grade DID control key, `recovery_unlock` / `trusted_recovery_service` signature does not verify under the bound key, or any `device_quorum.signatures[i]` does not verify under the named device key. Key-class or authority failures use `cross_signing_reset_proof_authority_invalid`. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_signing_reset_unlock_commitment_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`recovery_unlock.unlock_commitment` does not equal the receiver-recomputed `SHA-256(utf8('ak.cross-signing-reset-unlock-binding-v1\\n') || recovery_secret_ref || unlock_binding_input_bytes)`, where `unlock_binding_input_bytes` is the §14.1 canonical input with `proof_body` excluding both signature fields and `unlock_commitment`. This is a wire-integrity binding (not a secret-knowledge proof) preventing the same recovery-key signature from being shelled into a different reset envelope. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "cross_space_structural_relation",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A structural containment write would span incompatible Space container hierarchies - e.g. adding a Strand positioned under one Board to a List belonging to a different Board / Space tree. Structural containment MUST stay within a single container hierarchy; the reducer MUST reject failed_precondition. (Crossing a Realm boundary uses the more specific cross_realm_structural_relation.) See zh/models/relation.md §4.4 and zh/models/realm-and-space.md §3.6.",
    },
    ReasonCodeDescriptor {
        code: "cursor_expired",
        applies_to: &["client_sync"],
        description: "Cursor's `x` expiry is in the past; caller MUST request a fresh cursor.",
    },
    ReasonCodeDescriptor {
        code: "cursor_integrity_invalid",
        applies_to: &["client_sync", "encoding"],
        description: "Cursor failed the §8.3.1 integrity check: the stateful `h` handle is unknown / revoked / expired / cross-bound, or its stored binding (principal / device / service / filter_digest / purpose) does not match the authenticated request. Distinct from cursor_expired (TTL) and cursor_unrecognized (cross-service portability miss). Triggered before any server-side state advancement (/account/subscribe after= resume, X-Arkret-Wait-For release, dropped/resync_required recovery; to-device queue deletion is decoupled from cursors per client-sync.md §10.1). Client MUST clear local cursor cache and restart from initial /account/subscribe.",
    },
    ReasonCodeDescriptor {
        code: "cursor_revoked",
        applies_to: &["client_sync", "encoding"],
        description: "Cursor passed syntax and integrity validation but is present in the issuing service's revocation set. Treated as an authority revocation, not tamper; endpoint MUST NOT advance server-side state.",
    },
    ReasonCodeDescriptor {
        code: "cursor_unrecognized",
        applies_to: &["client_sync"],
        description: "Cursor decoded successfully but cannot be used by this service because it is a stateful handle issued by another service. This is a cross-service portability miss, not TTL expiry and not local integrity failure; caller MUST restart sync from a fresh cursor.",
    },
    ReasonCodeDescriptor {
        code: "deactivation_federation_incomplete",
        applies_to: &[
            "account_status",
            "federation_transaction",
            "state_resolution",
        ],
        description: "Account deactivation could not be acknowledged by every peer Principal Server inside deactivation_propagation_window_ms. Source services MUST keep deactivation fanout retrying and pause new Realm onboard, session/device grant, and KeyPackage publication for the principal.",
    },
    ReasonCodeDescriptor {
        code: "decryption_failed",
        applies_to: &["client_sync"],
        description: "Recipient permanently cannot decrypt; epoch is unrecoverable on this device under current keys.",
    },
    ReasonCodeDescriptor {
        code: "decryption_pending",
        applies_to: &["client_sync"],
        description: "Recipient cannot decrypt the targeted MLS epoch yet; client MUST surface a placeholder and continue retrying within the configured window.",
    },
    ReasonCodeDescriptor {
        code: "delegation_cycle",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `ak.capability.delegate` would close a cycle in the delegation graph (when traversed by grant_id node DFS). Reducer MUST reject the entire delegation chain to prevent circular authority. See zh/authz/capabilities.md §10.",
    },
    ReasonCodeDescriptor {
        code: "delegation_expiry_widening",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A delegated grant's `expires_at` is later than the parent grant's `expires_at`, or `not_before` is earlier than the parent's `not_before`. Delegation MUST NOT widen the parent's validity window. See zh/authz/capabilities.md §10.",
    },
    ReasonCodeDescriptor {
        code: "delegation_revoked",
        applies_to: &["auth_decision", "service_call"],
        description: "An applet/service call used a delegated device session that the deactivation/lock fanout revoked (ak.applet.registration delegated devices). The call MUST fail closed. See zh/identity/account-lifecycle.md §7.1.",
    },
    ReasonCodeDescriptor {
        code: "delegation_scope_custom_unsupported",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A grant declared `delegation_scope=custom`, which v1 does not define an evaluable semantics for. The reducer MUST reject (schema_violation) until a future profile assigns custom-scope evaluation rules. See zh/authz/constraint-schema.md §7.",
    },
    ReasonCodeDescriptor {
        code: "delegation_scope_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A delegated grant violated its parent's `delegation_scope`: `narrowing_only` requires the child resources/actions to be a strict-or-equal subset that narrows at least one axis, and `same_scope` requires the child to match the parent's scope exactly. The reducer MUST reject a child that exceeds or fails to satisfy the declared narrowing discipline. See zh/authz/constraint-schema.md §7.",
    },
    ReasonCodeDescriptor {
        code: "delivery_binding_handover_proof_invalid",
        applies_to: &["service_call", "auth_decision"],
        description: "A federation delivery-binding handover response carried a proof that does not verify against the Realm Event graph, handover_frontier, actor_id, new_recipient_service_id, or effective delivery binding policy. Sender MUST stop redirection and MUST NOT fall back to DID Document routing. See zh/sync/federation.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "delivery_binding_handover_rate_limited",
        applies_to: &["service_call"],
        description: "Sender has already accepted the maximum number of successful delivery-binding handovers for the same target principal and Realm in the configured rolling window. It MUST enter operator diagnostic instead of following another handover. See zh/sync/federation.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "delivery_binding_invalid",
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "A member join / invite / delivery-binding candidate passed schema validation but failed cryptographic or semantic evidence validation before membership acceptance: signature invalid, subject / service DID mismatch, expired candidate, unresolved issuer, missing or invalid referenced service-acceptance / policy evidence, or evidence whose scope does not cover the Realm. Pure schema-level omissions and shape failures, including missing delivery_binding for a routable member, missing source-conditional binding fields, or missing / empty delivery_modes, remain schema_violation and MUST be rejected before reducer policy validation. Reducers MUST reject the Move fail-closed rather than partially accepting membership. Realm policy allowlist, source-priority, endorsement, or allow_unroutable failures use delivery_binding_policy_mismatch instead. See zh/governance/member-delivery-binding.md §2 and zh/identity/identity-handles.md §3.7.",
    },
    ReasonCodeDescriptor {
        code: "delivery_binding_policy_mismatch",
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "The resolved member delivery binding source, recipient_service_id, endorsement set, unroutable-membership status, or selected source priority conflicts with the Realm delivery_binding_policy allowlist / priority rules. Reducers MUST NOT fall through to a lower-priority binding source after this mismatch. See zh/governance/member-delivery-binding.md §2 and §3.1.",
    },
    ReasonCodeDescriptor {
        code: "delivery_binding_stale",
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify: the receiver's delivery-binding frontier has advanced past the route this notify was built against. Terminal for this attempt; the caller MUST re-resolve the route rather than retry the same one. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: "delta_contains_data_event",
        applies_to: &["event_auth_state", "state_resolution"],
        description: "A Seal delta contained a data-plane (DataEvent) digest. A Seal delta MUST carry newly sealed control-plane event digests only; including a DataEvent digest is a Seal validation failure and receivers MUST reject the Seal (rejected_seal). See models/event-and-patch.md and fixtures/cba-lattice-fixture.json.",
    },
    ReasonCodeDescriptor {
        code: "dependency_missing",
        applies_to: &["batch_item", "federation_transaction"],
        description: "The item cannot yet be verified because an exact Event, Seal, predecessor, proof, or other signed dependency is absent. Federation submit items MUST include at least one non-empty typed missing set; independent complete items remain eligible for acceptance. Dual-registered with the top-level service code.",
    },
    ReasonCodeDescriptor {
        code: "device_authorized_principal_control_realm_mismatch",
        applies_to: &["auth_decision", "state_resolution"],
        description: "A non-bootstrap ak.device.authorize event was submitted outside the principal's bound principal_control Realm, or the Realm purpose/profile/created_by does not match the device owner and issuer principal. Reducer MUST fail closed. See zh/identity/key-management.md §5.0.3.",
    },
    ReasonCodeDescriptor {
        code: "device_enrollment_authority_snapshot_missing",
        applies_to: &["auth_decision", "state_resolution"],
        description: "A service_attested ak.device.authorize was signed by an enrollment authority whose DID has no history-resolution method (e.g. did:web), but its enrollment_authority_binding omits the inline issuance-time verification method snapshot and/or controller proof required for point-in-time historical re-verification. Without these, the authorization cannot be re-verified at its signing time and a rotated/hijacked current document could forge re-verification, so the receiver MUST reject. See zh/identity/key-management.md §5.0.6 and zh/identity/identity-did.md §3.2.",
    },
    ReasonCodeDescriptor {
        code: "device_generation_fenced",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A normal Event or Seal was signed by a device whose authorized_generation_ref does not equal the active current_device_generation_ref, or the principal generation state is conflicted. Dual-registered as a reason_code and a top-level service code (see codes[]).",
    },
    ReasonCodeDescriptor {
        code: "device_reanchor_authorize_mismatch",
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "The atomic replacement ak.device.authorize id/digest, prev_refs, principal, device, session, or enrollment-authority proof does not exactly match the binding in ak.device.reanchor. Dual-registered as a reason_code and a top-level service code (see codes[]).",
    },
    ReasonCodeDescriptor {
        code: "device_reanchor_conflict",
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "More than one non-identical re-anchor unit occupies the same (principal_id, did_version_number) slot. Every candidate and successor generation is quarantined; first-seen selection is forbidden. Dual-registered as a reason_code and a top-level service code (see codes[]).",
    },
    ReasonCodeDescriptor {
        code: "device_reanchor_entry_not_head",
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "Live B-model re-anchor references a verified DID entry that is not the registry head at admission time. Historical replay uses the accepted batch receipt instead of this live-head check. Dual-registered as a reason_code and a top-level service code (see codes[]).",
    },
    ReasonCodeDescriptor {
        code: "device_reanchor_frontier_mismatch",
        applies_to: &["event_envelope", "auth_decision", "service_call"],
        description: "The re-anchor pre_fence_basis is null despite an accepted Seal, omits or adds frontier leaves, has unreconstructable roots, or lost the admission-time frontier compare-and-swap race. Dual-registered as a reason_code and a top-level service code (see codes[]).",
    },
    ReasonCodeDescriptor {
        code: "device_recovery_ssk_generation_mismatch",
        applies_to: &["device_recovery", "cross_signing"],
        description: "Recovery request or device authorization references a stale or future cross-signing generation.",
    },
    ReasonCodeDescriptor {
        code: "did_proof_replay_window_exceeded",
        applies_to: &["account_status", "auth_decision"],
        description: "A soft-logout recovery DID proof was rejected because expires_at is missing or its freshness window exceeded the bound (expires_at - issued_at > 300s, or issued_at skew beyond tolerance); see account-lifecycle.md §4 and identity-did.md §5.1.",
    },
    ReasonCodeDescriptor {
        code: "direct_conversation_binding_invalid",
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "An authored Direct Conversation binding fact has an invalid issuer, pair key, referenced contact facts, Realm role, membership set, main Strand, retirement target, or other canonical verification input.",
    },
    ReasonCodeDescriptor {
        code: "direct_conversation_invite_forbidden",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An invite operation targeted a Realm carrying ak.profile.direct_conversation_realm.v1. Direct Conversation membership is established only by the resolver's verified two-participant bootstrap; all invite flows fail closed.",
    },
    ReasonCodeDescriptor {
        code: "direct_conversation_member_count_invalid",
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "A Direct Conversation binding or membership projection does not resolve to exactly two distinct active principal participants. The Realm cannot be returned as an active canonical DM and policy evaluation fails closed.",
    },
    ReasonCodeDescriptor {
        code: "direct_conversation_space_forbidden",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A Space create/update/parent/archive/restore/tombstone operation targeted a Realm carrying ak.profile.direct_conversation_realm.v1. Space containers are not permitted in this constrained Realm role.",
    },
    ReasonCodeDescriptor {
        code: "direct_conversation_third_party_member_forbidden",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An invite or join attempted to add a principal that is not one of the two stable subject DIDs in the active canonical Direct Conversation binding. Group-chat expansion requires a new ordinary Collaboration Realm.",
    },
    ReasonCodeDescriptor {
        code: "direct_download_disallowed_presign_forbidden",
        applies_to: &["authz", "service_call"],
        description: "A presigned blob URL was requested for a Realm-owned blob whose current effective asset policy does not explicitly set direct_download_allowed=true. Missing, unverifiable, non-effective, omitted, or false policy state all fail closed. The service MUST deny presign and require authenticated fetch or an authorized proxy path.",
    },
    ReasonCodeDescriptor {
        code: "duplicate_conflict",
        applies_to: &["event_envelope", "client_sync"],
        description: "A stable protocol identity was reused with different canonical content. For Event Envelope event_id this is quarantined per event-auth-state-resolution.md §11; for to-device message_id the send operation rejects the conflicting enqueue with reason message_id_conflict.",
    },
    ReasonCodeDescriptor {
        code: "durability_recovery_recipient_unverified",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition on an unverifiable RRK durability recovery recipient, on either side. Sealer side: the sealer cannot resolve a durability_policy.recovery_recipients[].verification_method to a verification method designated by an active ArkretRealmHistoryRecoveryKey service entry published by the named principal_id; it MUST fail closed and MUST NOT fall back to any other key. Receiver side: replaying a historical RRK ak.realm_key.share, either the accepted-at point-in-time DID resolution does not yield that verification method as active, or the payload triple (recovery_recipient_id, recipient_principal_id, recipient_verification_method) has no unique field-for-field match in the durability_policy.recovery_recipients[] effective on the CBA/policy basis pinned by the Event seal_ref. Receivers MUST NOT substitute the receive-time DID document or the receive-time policy. See zh/crypto-media/encryption-and-audit.md §2.10.8 and zh/identity/identity-did.md §8.3.",
    },
    ReasonCodeDescriptor {
        code: "durability_scheme_incompatible",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a ak.realm.policy_bundle write declares durability_policy.mode != none on a Realm whose content_scheme is not mls_exporter_aead_v1. mls_rfc9420 Realms have no deliverable history_secret, so Realm Recovery Key (RRK) durability is structurally unavailable. See zh/models/realm-and-space.md §2.3.1 and zh/crypto-media/encryption-and-audit.md §2.10.8.",
    },
    ReasonCodeDescriptor {
        code: "durability_seal_missing_before_gc",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition raised when a member would GC an epoch's history_secret before the RRK durability ak.realm_key.share for every durability_policy.recovery_recipients[] is accepted (read-your-writes), i.e. the eager-seal precondition is unmet. The member MUST retain history_secret[N] until the durability seal is accepted or the policy no longer requires it. See zh/crypto-media/encryption-and-audit.md §2.10.8 and §2.10.5.",
    },
    ReasonCodeDescriptor {
        code: "e2ee_key_source_unauthorised",
        applies_to: &["service_call"],
        description: "A backend media SDK supplied an SFrame / frame encryption key from a source other than the Arkret MLS exporter (label `ak.rtc-frame-key/v1`). Clients MUST reject and refuse to publish / subscribe media. Closes the attack where backend cloud key escrow could intercept ostensibly-E2EE media. See zh/crypto-media/media-service-binding.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: "e2ee_relaxed_disallowed_in_compliance_profile",
        applies_to: &["schema_violation", "state_resolution"],
        description: "A deployment attempted to enable ak.profile.e2ee_relaxed.v1 alongside a compliance-tier profile (ak.profile.attested_audit.e2ee.v1 / ak.profile.disclosed_audit.e2ee.v1 / any active Audit Applet Binding). The relaxed window contradicts the compliance presumption that kick-out is cryptographically immediate; the combination MUST be rejected by the reducer. See artifacts/profiles/conformance-profiles.json#ak.profile.e2ee_relaxed.v1.downgrade_window_constraint.compliance_profile_disabled.",
    },
    ReasonCodeDescriptor {
        code: "e2ee_relaxed_federation_policy_unsupported",
        applies_to: &["schema_validation", "state_resolution"],
        description: "A Realm attempted to combine ak.profile.e2ee_relaxed.v1 with an open or quarantine federation policy, or with restricted federation that lacks a bounded fanout SLA within the relaxed E2EE window.",
    },
    ReasonCodeDescriptor {
        code: "effective_scope_reducer_managed",
        applies_to: &["schema_validation"],
        description: "Sub-reason for schema_violation when an object content payload illegally carries `effective_scope` where its schema reserves that name for a read-only materialized projection. The Event envelope instead requires producer-signed `scope_ref`; the receiver derives the scope from payload and frozen pre-state, verifies exact equality, and only then may copy it into the object's effective_scope projection. See zh/models/circle.md §6.2.",
    },
    ReasonCodeDescriptor {
        code: "egress_policy_denied",
        applies_to: &["authz", "federation_transaction", "service_call"],
        description: "An outbound Applet, MIMI, or federation transfer would emit plaintext or derived content without the egress grant, data-class allowance, or destination policy required for that transfer. The sender MUST reject the transfer before releasing content.",
    },
    ReasonCodeDescriptor {
        code: "epoch_update_required",
        applies_to: &["crypto", "service_call", "state_resolution"],
        description: "Membership, policy, or governance frontier changed and the current MLS epoch does not yet have a winning ak.mls.commit whose governance_binding covers that frontier. Clients MUST pause new application messages for the scope until the effective epoch catches up. See zh/crypto-media/encryption-and-audit.md §2.4.1.",
    },
    ReasonCodeDescriptor {
        code: "erasure_pending_is_terminal",
        applies_to: &["account_status", "event_envelope", "state_resolution"],
        description: "A `ak.account.status` event attempted to supersede an `erasure_pending` status (via `supersedes_status_event_id`) down to a lower-severity status. `erasure_pending` is terminal: erasure physically destroys data, so reducers / projections MUST reject the downgrade and keep `erasure_pending` as the current status. See zh/identity/account-lifecycle.md §3.",
    },
    ReasonCodeDescriptor {
        code: "erasure_receipt_stub_digest_mismatch",
        applies_to: &["account_status", "identity_resolution"],
        description: "Retained erasure stub bytes do not match retained_stub_digest in the erasure receipt. Verifier MUST reject the receipt and treat the erasure as not completed (fail closed).",
    },
    ReasonCodeDescriptor {
        code: "evidence_recipient_mismatch",
        applies_to: &["moderation_decision", "moderation_report"],
        description: "A moderation evidence package's encrypted_to recipient does not match the declared recipient_public_key_ref binding. The submission MUST reject. See governance/content-moderation.md.",
    },
    ReasonCodeDescriptor {
        code: "executed_by_missing",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An Event whose envelope signature was produced by an applet / delegated agent key but whose `actor_id` points to a different (native) principal DID is missing the mandatory `executed_by` / `authorization_ref` / `applet_id` fields. Reducer MUST schema_violation per zh/extensions/applet-integration.md §11.",
    },
    ReasonCodeDescriptor {
        code: "expired_invite_token",
        applies_to: &["state_resolution"],
        description: "Invite token's expires_at has passed when claim is attempted. Internal-only reason code; the wire response MUST be the unified non-enumerable `not_found` per zh/sync/third-party-invites.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "external_rate_limited",
        applies_to: &["service_call"],
        description: "Bridge / applet transaction failed because the external upstream service rate-limited the request, distinct from the local `rate_limited` (this service's own limit). Carried as a bridge_error error_code with error_class=rate_limit; the caller MAY retry after retry_after_ms. See zh/extensions/applet-schema.md §7.",
    },
    ReasonCodeDescriptor {
        code: "federation_authority_mismatch",
        applies_to: &["federation_transaction", "service_call"],
        description: "HTTP Message Signature @authority / target URI host does not match the resolved service endpoint for Destination-Service-ID, or the Destination-Service-ID is not authorized by Realm policy for the requested federation operation. Receiver MUST reject before processing events.",
    },
    ReasonCodeDescriptor {
        code: "federation_trust_domain_mismatch",
        applies_to: &["federation_transaction", "service_call"],
        description: "Destination-Trust-Domain does not equal the receiver deployment's ServiceDescribe.trust_domain, or does not match the receiving Realm's trust_domain (zh/sync/federation.md §3.2). Internal audit-only reason; the wire response MUST be the unified minimal-disclosure authentication failure envelope.",
    },
    ReasonCodeDescriptor {
        code: "focus_mismatch",
        applies_to: &["service_call", "auth_decision"],
        description: "Media token exchange (ak.self.call.media.exchange.issue_token) requested a `focus_id` different from the already-committed `ak.call.state.session_focus`. Token issuer MUST reject; clients MUST re-target the established focus rather than retrying with the original preference. See zh/crypto-media/media-service-binding.md §3 and §5.",
    },
    ReasonCodeDescriptor {
        code: "focus_unavailable_for_client",
        applies_to: &["service_call"],
        description: "Client cannot use the committed `session_focus` (e.g. focus not in local `foci_preferred[]`, region restricted, capability mismatch). Client MAY fail closed without joining the call rather than silently degrading; clients MUST NOT pick a different focus to bypass `session_focus_no_split_brain`. See zh/crypto-media/media-service-binding.md §5.",
    },
    ReasonCodeDescriptor {
        code: "forensic_attribution_mismatch",
        applies_to: &["event_auth_state", "state_resolution"],
        description: "A threshold-notary Seal's declared forensic_attribution mode (e.g. waived or quorum_intersection) does not satisfy the Realm's forensic-attribution obligation for the signer set. The Seal MUST reject. See fixtures/cba-lattice-fixture.json.",
    },
    ReasonCodeDescriptor {
        code: "gate_check_failed",
        applies_to: &["auth_decision", "state_resolution"],
        description: "External applicant-facing generic join gate failure. Wire response MUST NOT reveal whether a claim was absent, revoked, issuer-unreachable, parent-membership-missing, or challenge-invalid; detailed diagnostics are audit/reviewer-only. See zh/governance/join-policy.md §5.",
    },
    ReasonCodeDescriptor {
        code: "governance_binding_mismatch",
        applies_to: &[
            "event_envelope",
            "state_resolution",
            "federation_transaction",
        ],
        description: "An MLS commit's mls_governance_binding GroupContext extension declares a policy_root (or realm policy digest) that does not match the policy root the group's epoch chain is genesis-bound to. The receiver MUST reject the commit - and, on a federation push, the batch - rather than advance an epoch under a forged or stale governance binding. See zh/crypto-media/encryption-and-audit.md §2.5.1.",
    },
    ReasonCodeDescriptor {
        code: "grant_exceeds_issuer_authority",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A first-issue `ak.capability.grant` (no parent_grant_id) attempts to grant actions[] / resources[] that exceed the issuer's own effective capability at the issuing seal basis. Holding the `ak.capability.grant` action alone does not permit minting authority the issuer does not itself hold; reducers MUST fail closed (schema_violation for actions/resources over-scope, failed_precondition when the issuer does not hold the required upper bound at that basis), symmetric to the delegation narrowing rule. See zh/authz/capabilities.md §3.2.",
    },
    ReasonCodeDescriptor {
        code: "grant_revoked_before_event_frontier",
        applies_to: &["auth_decision"],
        description: "The capability grant cited as authority was revoked at a frontier causally preceding this event; reducer rejects.",
    },
    ReasonCodeDescriptor {
        code: "grant_revoked_upstream",
        applies_to: &["auth_decision", "state_resolution"],
        description: "A child grant or Move depends on a parent grant that is locally known to be revoked, superseded, expired, or tombstoned. Reducers MUST fail closed without waiting for the child causal frontier to include the revoke. See zh/authz/capabilities.md §10.3.",
    },
    ReasonCodeDescriptor {
        code: "grant_validity_window_empty",
        applies_to: &["auth_decision", "event_envelope"],
        description: "A capability grant's normalized effective validity window is empty: effective_not_before >= effective_expires_at after combining top-level not_before/expires_at with temporal not_before/expires_at constraints. Reducer MUST reject the grant. See zh/authz/capabilities.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "handle_holder_acceptance_missing",
        applies_to: &["auth_decision", "service_call"],
        description: "A restricted handle whose subject DID is NOT controlled by the issuer was presented as binding_state=verified without a holder-acceptance proof (a proof in proofs[] signed by a verification method of the subject DID covering (handle, subject, audience, claim_scope)). Verifiers MUST treat it as at most issuer-attested (below verified): it MUST NOT enter the verified candidate set, be displayed as verified, or drive grant conditions / roster strong attribution / delivery binding. This closes issuer-unilateral impersonation within the issuer's audience. See zh/identity/identity-handles.md §6.",
    },
    ReasonCodeDescriptor {
        code: "handle_homograph_forbidden",
        applies_to: &["schema_validation", "service_call"],
        description: "Handle registration collided with the same authority-local handle-namespace UTS #39 skeleton index or failed the authority's declared Highly Restrictive registration policy. This is registration policy, not canonical equality; the skeleton never enters wire or proof bytes. See zh/identity/identity-handles.md §17.",
    },
    ReasonCodeDescriptor {
        code: "handle_subject_mismatch",
        applies_to: &["auth_decision", "service_call"],
        description: "Handle resolution returned a subject DID that does not match the expected applicant / member / invite subject. Clients and reducers MUST reject the candidate before building delivery_binding or join material. See zh/identity/identity-handles.md §3.7 and zh/conformance/conformance-vectors.md §8.",
    },
    ReasonCodeDescriptor {
        code: "harassment",
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: harassment.",
    },
    ReasonCodeDescriptor {
        code: "hate_speech",
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: hate speech / targeted attacks against a protected group.",
    },
    ReasonCodeDescriptor {
        code: "history_visibility_requires_history_capable_scheme",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when an MLS-backed Realm sets history_visibility=world_readable/shared/invited while the effective content_scheme is not mls_exporter_aead_v1. mls_rfc9420 has per-message forward secrecy and no deliverable history_secret for later joiners; reducers MUST reject create/bootstrap or policy writes that would produce the invalid combination. See zh/models/realm-and-space.md §2.3 and zh/crypto-media/encryption-and-audit.md §2.10.",
    },
    ReasonCodeDescriptor {
        code: "human_approval_required",
        applies_to: &["auth_decision", "service_call"],
        description: "An agent runtime requested a high-risk session scope that requires out-of-band controller approval. The top-level service error is claim_required; error.details carries this reason_code and an opaque approval_request_id. The runtime MUST NOT receive a CAPTCHA, OTP, or browser challenge. See zh/identity/key-management.md §3.2.",
    },
    ReasonCodeDescriptor {
        code: "identity_link_no_longer_visible",
        applies_to: &["identity_resolution"],
        description: "An identity-link resolution was invalidated because the linked identity is no longer visible to the requester after a membership transition or capability revoke; directory / sync / invite caches MUST drop the stale link. See zh/conformance/conformance-vectors.md §9 (ak.vector.identity_link.eager_invalidation.v1).",
    },
    ReasonCodeDescriptor {
        code: "identity_link_policy_tightened",
        applies_to: &["identity_resolution"],
        description: "An identity-link resolution was invalidated because the governing visibility / link policy was tightened after the link was cached. See zh/conformance/conformance-vectors.md §9 (ak.vector.identity_link.policy_tightening_invalidation.v1).",
    },
    ReasonCodeDescriptor {
        code: "illegal",
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: content alleged to violate applicable law (CSAM, threats, IP infringement, etc.).",
    },
    ReasonCodeDescriptor {
        code: "inception_upgrade_evidence_insufficient",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Cross-method principal upgrade (e.g. personal_node `did:web` -> small_team `did:webvh`) is missing the OOB fingerprint confirmation evidence or any of the required `transfer_proof` fields (key-management.md §5.0.5).",
    },
    ReasonCodeDescriptor {
        code: "inception_upgrade_evidence_stale",
        applies_to: &["auth_decision", "identity_resolution"],
        description: "Cross-method principal upgrade transfer_proof.old_did_document_fetched_at is older than the maximum 168h evidence window. Receiver MUST reject instead of accepting stale did:web evidence. See zh/identity/key-management.md §5.0.5.",
    },
    ReasonCodeDescriptor {
        code: "inception_upgrade_fingerprint_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Cross-method principal upgrade evidence `inception_public_key_fingerprint` does not match the cold root key bound by the old method continuity evidence and verified in key-management.md §5.0.5.",
    },
    ReasonCodeDescriptor {
        code: "inception_upgrade_old_document_hash_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Cross-method principal upgrade evidence `old_did_document_canonical_digest` does not match the receiver's canonicalised view of the current `old_did` DID Document. Indicates the hosting domain has been substituted after the upgrade was signed (key-management.md §5.0.5).",
    },
    ReasonCodeDescriptor {
        code: "inception_upgrade_signature_chain_invalid",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Cross-method principal upgrade `ak.did.proof.continuity` `signature_chain` is missing one of the two mandated signatures (the old method's continuity-evidence-bound cold root + the new method's entry-0 active cold root), uses a DID Document-only inception/verification key instead of the bound cold-root evidence key, or one of the signatures fails to verify (key-management.md §5.0.5).",
    },
    ReasonCodeDescriptor {
        code: "inclusion_list_violation",
        applies_to: &["event_auth_state", "state_resolution"],
        description: "A Seal failed to discharge a FOCIL-style inclusion-list obligation: a listed, receipt-backed Control Move digest was neither included nor signed-rejected nor proven to fail batch pre-state verification within expiry_seal_count. Receivers MUST reject the entire Seal (rejected_seal). See authz/event-auth-state-resolution.md section 7.3 and schemas/inclusion-list.schema.json.",
    },
    ReasonCodeDescriptor {
        code: "inclusion_proof_failed",
        applies_to: &["client_sync", "snapshot_verification"],
        description: "Snapshot inclusion / omission challenge failed: issuer could not produce a valid Merkle branch or ordered-set slice for a sampled Event ID / actor sequence range against the manifest's event_set_commitment.root, OR the proof's root differs, OR an actor sequence gap is not reflected in soft_failed/quarantined digests. Client MUST quarantine or reject the snapshot and fall back to raw Event replay.",
    },
    ReasonCodeDescriptor {
        code: "insufficient_challenge_samples",
        applies_to: &["client_sync", "snapshot_verification"],
        description: "A high-assurance range/challenge attestation does not carry the required minimum number of event_id (or equivalent) samples. The challenge MUST reject. See sync/client-sync.md and fixtures/sync-fixture.json.",
    },
    ReasonCodeDescriptor {
        code: "integrity_failed",
        applies_to: &["event_envelope", "service_call"],
        description: "A recording or transcription artifact failed digest, encryption-context, or integrity verification.",
    },
    ReasonCodeDescriptor {
        code: "internal_error",
        applies_to: &["batch_item"],
        description: "Per-event rejection reason in an Applet edge transaction response (rejected[].reason_code) when the receiving applet hit an internal failure while processing that item; mirrors the top-level internal_error endpoint code at batch-item granularity. See zh/extensions/applet-integration.md §7.3.",
    },
    ReasonCodeDescriptor {
        code: "invalid_ack_token",
        applies_to: &["service_call"],
        description: "A to-device message ack carried an ack token that does not correspond to a delivered to-device cursor (unknown, malformed, or already-superseded). Carried under invalid_param. See zh/sync/client-sync.md §10.1 and zh/sync/service-http-binding.md device_messages/ack.",
    },
    ReasonCodeDescriptor {
        code: "invalid_appeal_fsm_transition",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A moderation appeal Move requested an unlisted, out-of-order, from-state-mismatched, or post-closed transition. The reducer MUST reject it with failed_precondition. See zh/governance/content-moderation.md §5.5.2.",
    },
    ReasonCodeDescriptor {
        code: "invalid_canonical_json",
        applies_to: &["encoding"],
        description: "Bytes are not valid Arkret canonical JSON (sorted keys, integer-only numbers, escape rules per encoding.md §1).",
    },
    ReasonCodeDescriptor {
        code: "invalid_cursor",
        applies_to: &["client_sync", "encoding"],
        description: "Cursor payload fails the §8.2 / §8.3 cursor syntax or schema before integrity verification. HTTP endpoints surface this as top-level `invalid_param` with reason_code `invalid_cursor`. Expiry uses `cursor_expired`; handle lookup or cross-binding failures use `cursor_integrity_invalid`; cross-service portability misses use `cursor_unrecognized`.",
    },
    ReasonCodeDescriptor {
        code: "invalid_encoding",
        applies_to: &["encoding"],
        description: "Generic encoding violation (HLC format, UUIDv7 format, base64url alphabet, etc.) not otherwise classified.",
    },
    ReasonCodeDescriptor {
        code: "invalid_genesis_seal",
        applies_to: &["seal", "state_resolution"],
        description: "The first Seal of a Realm did not atomically cover the complete founding anchor unit (Realm metadata, creator joined membership, founding authority/notary, founding grant, base policy, and for an MLS-backed scope the epoch-0 governance binding), or used an empty covered set or empty control_event_set_root. See zh/authz/cba-profiles.md section 3.",
    },
    ReasonCodeDescriptor {
        code: "invalid_membership_transition",
        applies_to: &["authz", "state_resolution"],
        description: "A ak.member.state Move requests a membership FSM transition that is not listed as legal for the member's current state. Reducers MUST reject the Move with failed_precondition. See zh/models/realm-and-space.md §2.7.",
    },
    ReasonCodeDescriptor {
        code: "invalid_realm_founding_grant",
        applies_to: &["event_envelope", "state_resolution", "auth_decision"],
        description: "The purported Realm founding grant was outside the ak.realm.create atomic bootstrap unit, did not target created_by, or widened the closed actions/resources/constraints shape. Reducer MUST reject it and, during bootstrap, roll back the entire unit. See zh/models/realm-and-space.md section 2.5 and zh/authz/capabilities.md section 3.2.",
    },
    ReasonCodeDescriptor {
        code: "invalid_task_fsm_transition",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A transition effect on a profile-declared task/workflow fsm lattice cell declared a from -> to pair that is not a legal transition of that profile-declared state machine, or whose from does not match the cell's current state. v1 core defines no task object; the task/workflow FSM is declared by a Realm profile (e.g. a Jira-style issue-workflow profile) and evaluated by the generic fsm lattice type. The reducer MUST reject the Move instead of coercing the state machine. See zh/authz/event-auth-state-resolution.md §9.",
    },
    ReasonCodeDescriptor {
        code: "invalidated_by_rate_limit",
        applies_to: &["auth_decision"],
        description: "An out-of-band invite code attempt was invalidated because the per-code attempt rate limit was exceeded. See zh/conformance/conformance-vectors.md §9 (ak.vector.invite.oob_code_entropy.v1).",
    },
    ReasonCodeDescriptor {
        code: "invite_already_terminal",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An Invite state transition is rejected because the target Invite is already in a terminal flow state (`accepted` / `rejected` / `revoked` / `revoked_by_capability_loss` / `revoked_by_inviter_left` / `expired` / `invalidated_by_rate_limit`). Note the Invite `state` is the invite flow axis (not the generic object lifecycle axis); see zh/models/governance-objects.md §5.3.",
    },
    ReasonCodeDescriptor {
        code: "invite_oob_entropy_too_low",
        applies_to: &["auth_decision"],
        description: "An out-of-band invite code was rejected because its entropy is below the required floor. See zh/conformance/conformance-vectors.md §9 (ak.vector.invite.oob_code_entropy.v1).",
    },
    ReasonCodeDescriptor {
        code: "join_authorisation_invalid",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `ak.member.state{membership=join}` event's `join_authorisation` proof (the equivalent of Matrix `join_authorised_via_users_server`) does not verify against the cited reviewer's capability state at the citing frontier. See zh/governance/join-policy.md §6.",
    },
    ReasonCodeDescriptor {
        code: "join_policy_duplicate_gate_id",
        applies_to: &["schema_validation", "state_resolution"],
        description: "Sub-reason for a schema_violation on ak.realm.join_policy where gates[] contains duplicate gate_id values. gate_id MUST be stable and unique within the policy so that audit refs in ak.member.state{gate_proofs[gate_id=…]} are unambiguous. Wire response uses code=schema_violation with reason_code=join_policy_duplicate_gate_id. See zh/governance/join-policy.md §3.1.",
    },
    ReasonCodeDescriptor {
        code: "join_rule_policy_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Realm `ak.realm.join_rule` and `ak.realm.policy_bundle` declare conflicting join modes (e.g., `restricted` with no gate configuration, or `knock_restricted` with all-auto gates degrading to `restricted`). See zh/governance/join-policy.md §4.",
    },
    ReasonCodeDescriptor {
        code: "join_rule_tightened",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An in-flight pending member application (knock / awaiting_review / changes_requested) was terminated to a terminal leave because the Realm `default_join_rule` was tightened to `closed` or `invite`, which no longer accepts the knock / application path. Does not count toward cooldown. Applications already accepted with a committed ak.invite.create are unaffected. See zh/governance/join-policy.md §4.",
    },
    ReasonCodeDescriptor {
        code: "key_backup_wire_schema_required",
        applies_to: &["schema_validation"],
        description: "Device / Key Server received a `ak.keys.backups.*` request body that does not validate as `ak.schema.key_backup.v1`. Wire backups MUST carry the dedicated key-backup envelope with `series_id` and `series_seq`; client-local secret-storage envelopes are not accepted on wire endpoints. See zh/crypto-media/device-lifecycle.md §11.",
    },
    ReasonCodeDescriptor {
        code: "keypackage_claim_rate_limited",
        applies_to: &["service_call"],
        description: "Internal server-side audit reason recorded when an MLS KeyPackage claim exceeds the per-(requester_service_id, target_principal_id) rate limit. The outward response MUST stay anti-enumeration (generic `claim_failed` or rate-limited envelope) and MUST NOT leak target existence; this reason is the canonical audit-log token only. See zh/conformance/scalability-constraints.md §6 and zh/identity/key-management.md.",
    },
    ReasonCodeDescriptor {
        code: "keypackage_expired",
        applies_to: &["keypackage_lifecycle"],
        description: "A reusable last-resort KeyPackage was revoked because its expires_at deadline elapsed. It MUST NOT be returned by a later claim. This is a revocation reason, not a KeyPackage lifecycle state. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: "keypackage_refresh_required",
        applies_to: &["crypto", "service_call"],
        description: "Available one-time KeyPackage count is below the Realm or service low-watermark after claim attempts. Senders MAY delay Welcome generation and the target device SHOULD publish fresh KeyPackages. See zh/crypto-media/device-lifecycle.md §14.4.",
    },
    ReasonCodeDescriptor {
        code: "keypackage_rotated",
        applies_to: &["keypackage_lifecycle"],
        description: "A reusable last-resort KeyPackage was revoked because its holder came online and rotated it to fresh init / encryption key material. This is a revocation reason, not a KeyPackage lifecycle state. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: "keypackage_welcome_envelope_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "An MLS Welcome arrived with a `claim_envelope` whose canonical signing input does not match the Welcome's actual intended_realm_id / claim_id / requester_did, or the envelope signature does not chain to the requester's current accepted self-signing key or requester device authorization. See zh/crypto-media/encryption-and-audit.md §2.6.",
    },
    ReasonCodeDescriptor {
        code: "last_resort_not_supported",
        applies_to: &["service_call", "feature_discovery"],
        description: "A KeyPackage claim requested a last-resort fallback from a server that does not advertise `ak.feature.mls_last_resort_keypackage.v1`. The server MUST continue to fail closed on an empty single-use pool and MUST NOT return a `last_resort=true` package. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: "last_resort_realm_affinity_violation",
        applies_to: &["service_call", "auth_decision"],
        description: "An attempt to reuse a last-resort KeyPackage outside its `intended_realm_id` Realm-scoped last-resort pool. Servers MUST reject. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: "last_resort_rotation_required",
        applies_to: &["service_call", "crypto"],
        description: "A holder that joined groups via a last-resort KeyPackage came online but has not rotated the package and closed the forward-secrecy weakening window as required. See zh/crypto-media/encryption-and-audit.md §2.6.2.",
    },
    ReasonCodeDescriptor {
        code: "late_recovery_rejected_expired",
        applies_to: &["audit_decision"],
        description: "A late-arriving key tried to recover plaintext for an event whose disappearing expiry plus grace has elapsed, or whose retention policy requires content-key destruction. Client MUST keep the expiry stub / metadata-only state. See zh/crypto-media/encryption-and-audit.md §2.3.5 and zh/crypto-media/disappearing-messages.md §4.",
    },
    ReasonCodeDescriptor {
        code: "late_recovery_rejected_membership",
        applies_to: &["audit_decision"],
        description: "A late-arriving key tried to upgrade a decryption_failed event to late_recovered, but the receiver was not a member of the Realm at the original causal time T₀ (or has since been banned/removed). Client MUST NOT admit the recovered plaintext to verified timeline; audit log records this code. See zh/crypto-media/encryption-and-audit.md §2.3.5.",
    },
    ReasonCodeDescriptor {
        code: "late_recovery_share_not_authorized",
        applies_to: &["audit_decision"],
        description: "A key share or withheld decision is not covered by a verifiable source authorization. Covers three fail-closed cases. (a) A key backup / archive node / peer refused to deliver late key material because, on re-running the T₀ membership + policy check before sending, the current share policy no longer permits delivery to the requesting device (distinct from late_recovery_rejected_membership, which is the receiver-side T₀ non-membership case). (b) An ak.realm_key.share whose source_authorization_ref is missing or does not cover (source principal/device, recipient principal/device, key_scope, share_kind) at the Event CBA basis; this includes an RRK-holder re-share whose source principal is not the active RecoveryRecipient, whose signer is not a real accepted undertaken device of that principal, or whose reference does not satisfy the effective history-sharing policy for the recovery_service key source. (c) An ak.realm_key.withheld whose required source_authorization_ref is missing or does not cover the refusal decision; an unauthorized withheld MUST NOT be projected as a terminal state. See zh/crypto-media/encryption-and-audit.md §2.3.5 / §2.10.8 and zh/crypto-media/device-lifecycle.md §13.",
    },
    ReasonCodeDescriptor {
        code: "legal_hold_active",
        applies_to: &["auth_decision"],
        description: "Requested operation targets a blob / object currently under legal hold. ak.self.blob.command.presign / ak.blob.delete / redaction-equivalent operations MUST be rejected with this code; legal hold takes precedence over capability and TTL. See zh/crypto-media/media-and-blob.md §5.4.4.1.",
    },
    ReasonCodeDescriptor {
        code: "lite_profile_writes_disallowed_event_kind",
        applies_to: &["event_envelope", "policy_decision"],
        description: "A writer operating under a lite / reduced-surface conformance profile submitted an event kind outside the write surface its declared profile covers. Undeclared profile surface MUST be rejected (unsupported_feature / policy-denied semantics), not silently accepted. See zh/conformance/conformance-profiles.md.",
    },
    ReasonCodeDescriptor {
        code: "media_negotiation_timeout",
        applies_to: &["event_envelope", "state_resolution"],
        description: "Call connection or capture media negotiation exceeded the registered timeout.",
    },
    ReasonCodeDescriptor {
        code: "media_plaintext_service_not_authorised",
        applies_to: &["auth_decision"],
        description: "An SFU / MCU attempted to negotiate plaintext-decrypting media role without a matching Realm policy plaintext_visible_services[] entry whose data_classes[] contains media_plaintext, OR without policy_root covering media_service_decrypts=true. Free-text purposes do not grant authority. MUST be rejected; the SFU may still act as opaque RTP relay. See zh/crypto-media/media-service-binding.md §8.2.",
    },
    ReasonCodeDescriptor {
        code: "media_plaintext_warning_required",
        applies_to: &["auth_decision"],
        description: "A client attempted to join a call where media_service_decrypts=true without first displaying the required prominent plaintext-service warning and obtaining explicit second confirmation. The client MUST reject the join before releasing a token or media key. See zh/crypto-media/media-service-binding.md §8.2.",
    },
    ReasonCodeDescriptor {
        code: "media_service_binding_uncovered",
        applies_to: &["service_call", "state_resolution"],
        description: "A media token / focus join was presented but the current MLS epoch governance binding does not cover the `ak.realm.media_service` binding the token relies on (token issuer trust-root sealing is unverifiable). The verifier MUST fail closed instead of trusting an uncovered media binding. See zh/crypto-media/media-service-binding.md §2.1.",
    },
    ReasonCodeDescriptor {
        code: "media_service_foci_required",
        applies_to: &["service_call", "schema_validation"],
        description: "`ak.realm.media_service` is missing the required non-empty `foci[]` list. Services MUST reject payloads that do not declare explicit media foci and MUST NOT infer a focus from unrelated endpoint fields. See zh/crypto-media/media-service-binding.md §2.",
    },
    ReasonCodeDescriptor {
        code: "media_source_unavailable",
        applies_to: &["event_envelope", "service_call"],
        description: "The source media required for recording or transcription was unavailable.",
    },
    ReasonCodeDescriptor {
        code: "member_identity_proof_invalid",
        applies_to: &["event_envelope", "state_resolution"],
        description: "The MemberIdentity object carried by ak.member.identity.update failed proof validation: proof.payload_digest does not equal the sha256 of the proof-less MemberIdentity RFC 8785 JCS canonical bytes, the signature does not verify under proof.verification_method, or the method is not controlled by the disclosed subject_id. The event MUST NOT be promoted to a verified display identity. See zh/sync/client-sync.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: "member_identity_replacement_digest_mismatch",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.member.identity.update replaces[] entry references an event whose payload.identity_payload carrier digest does not equal the declared payload_digest, or references an event under a different (realm_id, actor_id, segment). The replacement edge is invalid; receivers MUST NOT remove the referenced event from the effective set on its basis. See zh/sync/client-sync.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: "member_identity_state_mismatch",
        applies_to: &["event_envelope", "state_resolution"],
        description: "The optional expected_state_digest optimistic-concurrency guard on ak.member.identity.update does not equal the current effective-set digest for the same (realm_id, actor_id, segment). The server / reducer MUST reject or quarantine the event instead of applying it as a valid replacement. See zh/sync/client-sync.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: "member_identity_unknown_segment",
        applies_to: &["event_envelope", "schema_validation"],
        description: "A ak.member.identity.update declared a segment value outside the v1 core enum (member_identity). Receivers MUST reject unknown segment values until a schema / profile revision extends the enum. See zh/sync/client-sync.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: "message_already_terminal",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.message.redact` / `ak.message.revise` / equivalent Message write rejected because the target Message is already in a terminal state (`redacted` or `deleted`). In particular, `ak.message.revise` targeting a terminal Message MUST be rejected with this reason_code.",
    },
    ReasonCodeDescriptor {
        code: "message_id_conflict",
        applies_to: &["event_envelope", "scheduled_send", "client_sync"],
        description: "A scheduled-send plan reused the same planned_message_id with different canonical plan content, or a to-device retry reused the same message_id with different canonical target content. The plan store or queue service MUST return duplicate_conflict with this reason_code and MUST NOT emit or enqueue a replacement message. Durable ak.message.create identity conflicts are keyed only by Event.event_id.",
    },
    ReasonCodeDescriptor {
        code: "metadata_encryption_floor_downgrade",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a ak.realm.policy_bundle or ak.circle.update would lower a scope's effective metadata encryption floor to a lower level (comparison order allow_plaintext < e2ee_required). The effective metadata encryption floor is a one-way ratchet (monotonically non-decreasing). See zh/models/realm-and-space.md §2.5 and zh/models/circle.md §7.",
    },
    ReasonCodeDescriptor {
        code: "metadata_encryption_floor_violation",
        applies_to: &["schema_validation", "state_resolution"],
        description: "Sub-reason for failed_precondition when a write would expose metadata below the effective metadata_encryption_floor floor (max of parent Realm floor, Circle metadata_encryption_floor and object profile requirement). See zh/models/circle.md §7.",
    },
    ReasonCodeDescriptor {
        code: "mimi_draft_unsupported",
        applies_to: &["service_call", "schema_validation"],
        description: "Counterparty declared a MIMI Internet-Draft version not supported by this interop profile. Facade MUST reject instead of guessing a nearby draft shape. See zh/extensions/mimi-interop.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "mimi_governance_binding_mismatch",
        applies_to: &["service_call", "state_resolution"],
        description: "A MIMI facade found a governance binding, but its realm_id, strand_id, mls_group_id, provider DID, or endpoint digest does not match the incoming MIMI room state. Receiver MUST quarantine or reject fail-closed. See zh/extensions/mimi-interop.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "mimi_governance_binding_missing",
        applies_to: &["service_call", "state_resolution"],
        description: "A MIMI facade attempted to project room state, groupInfo, key material, or message data into a Arkret Realm without a verifiable Arkret MLS governance binding. Receiver MUST quarantine or reject fail-closed instead of accepting unauthenticated MIMI state as Realm authority. See zh/extensions/mimi-interop.md §4.",
    },
    ReasonCodeDescriptor {
        code: "mimi_observer_write_forbidden",
        applies_to: &["service_call", "authz"],
        description: "A MIMI submit_message was attempted over a provider binding whose local_provider_role is observer, which MUST NOT submit writes on behalf of local participants. The submission MUST be rejected. See zh/extensions/mimi-interop.md section 7.",
    },
    ReasonCodeDescriptor {
        code: "mimi_policy_root_mismatch",
        applies_to: &["service_call", "state_resolution"],
        description: "A MIMI room policy component does not match the Arkret Realm policy_root or ak.realm.policy_bundle state. Facade MUST reject the update until a fresh policy projection is available. See zh/extensions/mimi-interop.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "mimi_provider_unreachable",
        applies_to: &["service_call"],
        description: "Required MIMI provider directory, key material, or groupInfo dependency is temporarily unreachable. Facade MAY retry with bounded backoff but MUST NOT accept fallback state without governance binding. See zh/extensions/mimi-interop.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "mimi_room_binding_status_transition_invalid",
        applies_to: &["state_resolution"],
        description: "A ak.mimi.room_binding Control Move declared a payload.status value that is not a legal transition from the binding's current status (including an illegal initial status or any write after the terminal revoked state). Reducer MUST reject; the room binding status lifecycle is defined in zh/extensions/mimi-interop.md §4.2.",
    },
    ReasonCodeDescriptor {
        code: "mimi_room_state_incompatible",
        applies_to: &["service_call", "schema_validation"],
        description: "Incoming MIMI room state uses lifecycle, membership, policy, or extension shape not supported by the declared Arkret MIMI interop profile. Facade MUST reject or require a newer profile. See zh/extensions/mimi-interop.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "minimal_disclosure_violation",
        applies_to: &["moderation_decision", "moderation_report"],
        description: "A moderation evidence package discloses material beyond the minimal-disclosure obligation (for example unrelated plaintext message bodies, MLS epoch or history secrets). The evidence submission MUST reject. See governance/content-moderation.md.",
    },
    ReasonCodeDescriptor {
        code: "minimal_metadata_author_credential_invalid",
        applies_to: &["event_envelope", "identity_resolution"],
        description: "A minimal-metadata content Event proof could not be bound to exactly one active MLS LeafNode whose basic credential identity equals Event.actor_id and whose signature_key matches proof.verification_method at the encrypted envelope epoch/group-state reference. The receiver MUST fail closed without querying a principal-scoped device directory. See zh/crypto-media/encryption-and-audit.md §2.10.3.",
    },
    ReasonCodeDescriptor {
        code: "minimal_metadata_presign_forbidden",
        applies_to: &["authz", "service_call"],
        description: "A presigned blob URL was requested for a Realm that requires minimal metadata or routing unlinkability. The service MUST deny presign and require an authenticated proxy, OHTTP relay, or equivalent non-bearer direct download path.",
    },
    ReasonCodeDescriptor {
        code: "misinformation",
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: misleading / false information posing harm.",
    },
    ReasonCodeDescriptor {
        code: "missing_parent_reference",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A delegated grant whose parent carries `parent_reference_required=true` omitted the explicit `parent_grant_id` / `refs[role=authorized_by]` linkage back to the parent grant. The reducer MUST reject so the delegation chain stays explicitly anchored. See zh/authz/constraint-schema.md §7 / zh/authz/capabilities.md §10.",
    },
    ReasonCodeDescriptor {
        code: "mls_governance_binding_stale",
        applies_to: &["state_resolution", "auth_decision"],
        description: "Current MLS epoch's governance binding policy_root does not cover the Realm policy components the client wants to act on (e.g. media_service_decrypts toggle, plaintext_visible_services). Receivers MUST refuse to act until a fresh commit updates policy_root. See zh/crypto-media/media-service-binding.md §8.2 and zh/crypto-media/encryption-and-audit.md §3.2.",
    },
    ReasonCodeDescriptor {
        code: "mls_send_pause_advisory_requires_e2ee_relaxed_profile",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Realm attempts to set mls_send_pause='advisory' without declaring ak.profile.e2ee_relaxed.v1; default profile MUST treat mls_send_pause as a MUST gate.",
    },
    ReasonCodeDescriptor {
        code: "moderation_control_lifted",
        applies_to: &["client_sync", "policy_decision"],
        description: "An sealed moderation quarantine or fast-path quarantine was lifted, and clients viewing the Realm should surface that affected content became visible again.",
    },
    ReasonCodeDescriptor {
        code: "moderation_control_pending",
        applies_to: &["client_sync", "policy_decision"],
        description: "A fast-path moderation quarantine signal was recorded but its sealed Control Move has not yet arrived; clients MAY temporarily hide the target and MUST switch display once the sealed decision lands (policy-server.md §7.2).",
    },
    ReasonCodeDescriptor {
        code: "moderation_control_split",
        applies_to: &["policy_decision", "state_resolution"],
        description: "A moderation control cell resolved to bottom under conflicting sealed Control Moves; downstream decisions depending on the cell fail closed until the split is resolved (policy-server.md §7.2).",
    },
    ReasonCodeDescriptor {
        code: "moderation_state_conflict",
        applies_to: &["auth_decision", "state_resolution"],
        description: "The referenced moderation state cell is in bottom / exposed multi-head conflict. Read, write, distribute, and policy-check paths MUST fail closed rather than selecting a temporary winner. See zh/authz/policy-server.md §7.2.",
    },
    ReasonCodeDescriptor {
        code: "morph_already_terminal",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.redaction` targeting a Morph is rejected because the target Morph is already in terminal state `redacted`.",
    },
    ReasonCodeDescriptor {
        code: "morph_not_active",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.morph.archive` / `ak.morph.update` rejected because the target Morph is not in `active` state.",
    },
    ReasonCodeDescriptor {
        code: "morph_not_archived",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.morph.restore` rejected because the target Morph is not in `archived` state.",
    },
    ReasonCodeDescriptor {
        code: "morph_schema_refs_evolution_unauthorized",
        applies_to: &["event_envelope", "auth_decision"],
        description: "ak.morph.update attempted to modify schema_refs[] without going through the Realm's declared schema-evolution policy (high-tier capability such as ak.morph.schema_migrate, or equivalent) and an explicit audit-grade authorization_ref. See zh/models/morph.md §4.1 S2.",
    },
    ReasonCodeDescriptor {
        code: "morph_schema_refs_precondition_mismatch",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Sub-reason for failed_precondition when a `ak.morph.schema_migrate` / `ak.morph.update` declares `from_schema_refs[]` (or the writer's expected current `schema_refs[]`) that is not set-equal to the Morph's actual current state — an optimistic-concurrency (CAS) miss distinct from the other morph_schema_* authorization/transformation failures. See zh/models/morph.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "morph_schema_refs_transformation_unsupported",
        applies_to: &["event_envelope"],
        description: "ak.morph.update attempted a non-additive schema_refs[] transformation (breaking or transformation-class change). Such transformations MUST be expressed as a ak.morph.schema_migrate event and require the Realm to declare the ak.profile.morph.schema_migration_transformations.v1 opt-in profile. See zh/models/morph.md §4.1 S3.",
    },
    ReasonCodeDescriptor {
        code: "morph_schema_version_binding_missing",
        applies_to: &["event_envelope"],
        description: "A reducer-input event targeting an evolvable-schema object (typically a Morph) did not include the active schema profile id(s) in requirements.schema[]. Reader cannot resolve which schema version to validate the event against. See zh/models/morph.md §4.1 S1 and zh/models/event-and-patch.md §2.7.",
    },
    ReasonCodeDescriptor {
        code: "naming_convention_violation",
        applies_to: &["event_envelope"],
        description: "A registry entry (event_kind / schema_id / typed-id) violates the canonical naming convention (e.g. embedding a `.v<n>` version suffix in the kind name instead of carrying the version via `requirements.features`). Surface as lint output, not as a wire-time reject.",
    },
    ReasonCodeDescriptor {
        code: "no_strand_track_message_grant",
        applies_to: &["auth_decision"],
        description: "No active capability grant authorises ak.message.create on the targeted Strand track for the actor.",
    },
    ReasonCodeDescriptor {
        code: "not_provisioned",
        applies_to: &["service_call"],
        description: "The requested principal / service / Realm is recognised by the registry but no provisioning exists at this endpoint — caller should bootstrap or pick another host. See zh/sync/service-http-binding.md.",
    },
    ReasonCodeDescriptor {
        code: "nsfw",
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: not-safe-for-work / explicit adult content posted outside permitted contexts.",
    },
    ReasonCodeDescriptor {
        code: "ok",
        applies_to: &["batch_item", "auth_decision", "policy_decision"],
        description: "Sentinel value indicating an item or decision succeeded with no further reason.",
    },
    ReasonCodeDescriptor {
        code: "operator_rejected",
        applies_to: &["device_recovery"],
        description: "Recovery-session `rejection_reason_code` value: an operator / admin surface explicitly rejected the session. Closed value set defined in artifacts/schemas/recovery-session.schema.json and zh/crypto-media/device-lifecycle.md §15.",
    },
    ReasonCodeDescriptor {
        code: "other",
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: catch-all for reports that do not fit the named categories. MUST be accompanied by a free-text `description` field. See zh/governance/content-moderation.md §3.2.",
    },
    ReasonCodeDescriptor {
        code: "out_of_order_bootstrap",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A Realm bootstrap batch placed a facet event before the ak.realm.create event that establishes the creator membership and Realm create cell.",
    },
    ReasonCodeDescriptor {
        code: "pairing_expired",
        applies_to: &["auth_decision", "event_envelope"],
        description: "Agent bootstrap pairing window elapsed before the first runtime key authorization completed, so the derived agent runtime_state projection reports pairing_expired (the controller lifecycle intent axis is unaffected). Pairing expiry does not create, revoke, or rewrite Realm grants. Never applies to previously keyed agents: an expired runtime replacement re-pairing handle has no side effects and returns runtime_state to ready. See zh/identity/account-lifecycle.md §9.1 and zh/identity/key-management.md §3.6.1.",
    },
    ReasonCodeDescriptor {
        code: "pairing_request_expired",
        applies_to: &["auth_decision", "service_call"],
        description: "A `ak.gate.account.command.pair_agent_key` pairing request was presented after its `pairing_expires_at` (or the runtime key-pairing session id has been retired). The endpoint MUST fail closed; the controller MUST initiate a fresh pairing strand. See zh/identity/key-management.md §3.6 §4.5.",
    },
    ReasonCodeDescriptor {
        code: "partial_auth_state",
        applies_to: &["state_resolution"],
        description: "Auth state for the event could not be fully resolved within the implementation's auth_chain backfill bound; treat as soft-fail per scalability-constraints.md.",
    },
    ReasonCodeDescriptor {
        code: "participant_binding_invalid",
        applies_to: &["event_envelope", "service_call"],
        description: "A `ak.call.state` participant's `participant_binding` failed one of: (a) issuer_kid resolution against current `ak.realm.media_service.service_id`; (b) field consistency with the participant entry (`realm_id` / `call_id` / `focus_id` / `actor_id` / `device_id` / `participant_identity`); (c) `expires_at` freshness vs event `created_at`; (d) signature verification. Reducer MUST `failed_precondition`. See zh/crypto-media/call-state.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "participant_identity_unrecognised",
        applies_to: &["service_call"],
        description: "Backend (LiveKit / SFU / etc.) signalled `ParticipantConnected` with a `participant_identity` that has no matching value in the accepted call roster effective OR-Set (or matches a value whose `participant_binding` fails verification). Client MUST refuse to establish media streams for that participant — this closes the attack where a compromised backend tries to inject unauthorized participants into the conference. See zh/crypto-media/media-service-binding.md §7.",
    },
    ReasonCodeDescriptor {
        code: "patch_atomic_conflict",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A single payload.patch contains parent/child writes, duplicate target paths, selector-affecting writes, or another multi-path combination that cannot be applied as one deterministic atomic Move. Reducer MUST reject the whole patch rather than partially applying paths. See zh/models/event-and-patch.md §4.4.",
    },
    ReasonCodeDescriptor {
        code: "patch_path_invalid",
        applies_to: &["event_envelope"],
        description: "An `ak.schema.patch.v1` patch path violates the ABNF grammar in zh/models/event-and-patch.md §4.2.1 (malformed identifier, quoted identifier, selector or numeric-index form, path > 1024 bytes, or nesting > 16 segments). Parser MUST NOT attempt fallback recovery; reducer rejects with this reason.",
    },
    ReasonCodeDescriptor {
        code: "patch_path_reducer_managed",
        applies_to: &["event_envelope"],
        description: "An `ak.schema.patch.v1` patch path attempts to modify a reducer-managed field (`id` / `schema` / `realm_id` / `created_by` / `created_at` / `state` / `state_changed_at`). These fields are owned by their corresponding lifecycle events; patch MUST NOT touch them. See zh/models/event-and-patch.md §4.2.5.",
    },
    ReasonCodeDescriptor {
        code: "patch_unset_redactable_field",
        applies_to: &["event_envelope"],
        description: "An `ak.schema.patch.v1` `$op=\"unset\"` was used on a redactable content field (e.g. message.content, strand.metadata.summary, encrypted_content / encrypted_metadata). Redaction MUST go through `ak.<kind>.redact` or `ak.redaction` events to enforce redaction-specific capability checks and audit. See zh/models/event-and-patch.md §4.2.4.",
    },
    ReasonCodeDescriptor {
        code: "permission_denied",
        applies_to: &["event_envelope", "service_call"],
        description: "A recording or transcription backend could not obtain the required media permission.",
    },
    ReasonCodeDescriptor {
        code: "plane_cross_write",
        applies_to: &["event_envelope", "schema_validation"],
        description: "Sub-reason for schema_violation when a DataEvent's registered reducer projection targets a control-plane cell. Data-plane events MUST only project writes to data-plane cell families; the receiver MUST reject the envelope instead of applying a cross-plane write. See zh/authz/event-auth-state-resolution.md §4.",
    },
    ReasonCodeDescriptor {
        code: "policy_denied",
        applies_to: &["auth_decision", "service_call"],
        description: "A Realm, organization, account, holder-disclosure, agent, or deployment policy explicitly denied the requested operation after syntactic validation and authentication succeeded. Use a narrower code when a more specific registry entry applies. See zh/authz/policy-server.md, zh/crypto-media/device-lifecycle.md, and zh/identity/identity-handles.md.",
    },
    ReasonCodeDescriptor {
        code: "policy_recall",
        applies_to: &["moderation_decision", "auth_decision"],
        description: "A policy-server-issued recall of a previous allow decision; corresponding action MUST be reversed if still reversible.",
    },
    ReasonCodeDescriptor {
        code: "policy_revision_gap",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.policy_bundle update skipped one or more monotonic policy_revision values. Reducer MUST reject instead of accepting a discontinuous policy frontier.",
    },
    ReasonCodeDescriptor {
        code: "policy_revoked",
        applies_to: &["event_envelope", "state_resolution"],
        description: "The Realm policy authorizing capture was revoked while the capture lifecycle was active.",
    },
    ReasonCodeDescriptor {
        code: "presign_expired",
        applies_to: &["service_call", "auth_decision"],
        description: "A ak.self.blob.command.presign bearer URL was presented outside its nbf / exp window or after its nonce was revoked. Wire response remains non-enumerating not_found where required; audit logs may record this reason. See zh/crypto-media/media-and-blob.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: "presign_invalid",
        applies_to: &["service_call", "auth_decision"],
        description: "A ak.self.blob.command.presign bearer envelope is syntactically invalid, has an unrecognised scheme, fails signature verification, mixes with Authorization header auth, or otherwise cannot be validated. Wire response remains non-enumerating not_found where required; audit logs may record this reason. See zh/crypto-media/media-and-blob.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: "presign_scope_mismatch",
        applies_to: &["service_call", "auth_decision"],
        description: "A ak.self.blob.command.presign envelope scope does not match the requested blob_ref, method, byte range, purpose, Realm, issuer trust state, or current blob visibility. Wire response remains non-enumerating not_found where required; audit logs may record this reason. See zh/crypto-media/media-and-blob.md §5.4.",
    },
    ReasonCodeDescriptor {
        code: "prev_refs_too_large",
        applies_to: &["schema_validation", "event_envelope"],
        description: "Event Envelope prev_refs exceeds the v1 maximum of 128 entries, or duplicates entries where uniqueness is required. Receiver MUST reject with schema_violation. See zh/conformance/scalability-constraints.md.",
    },
    ReasonCodeDescriptor {
        code: "principal_control_event_kind_forbidden",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A Realm claiming ak.profile.principal_control_realm.v1 received a collaboration / media / content event kind outside its allowlist-only control-plane event policy. Reducers MUST reject instead of treating the Realm as ordinary collaboration history. See zh/identity/key-management.md §4.2 and artifacts/profiles/conformance-profiles.json#profile_requirements.",
    },
    ReasonCodeDescriptor {
        code: "principal_deactivated",
        applies_to: &[
            "auth_decision",
            "event_envelope",
            "service_call",
            "state_resolution",
        ],
        description: "The account status frontier contains a deactivation for the principal acting as actor, subject, issuer, recipient, or device owner. New device/session grants, KeyPackage operations, capability delegation, delivery binding writes, push routes, and to-device enqueue MUST fail closed. See zh/identity/account-lifecycle.md §7.1 and zh/sync/federation.md §4.4.1.",
    },
    ReasonCodeDescriptor {
        code: "private_attachment",
        applies_to: &["service_call", "auth_decision"],
        description: "The target blob is actor_private / private attachment material and MUST NOT be exposed through a bearer presign URL. It remains fetchable only through header-authenticated actor-bound access. See zh/crypto-media/media-and-blob.md §5.4.4.1.",
    },
    ReasonCodeDescriptor {
        code: "profile_unsupported",
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify: the device has not opted in to the requested notification profile (for example a visible notification sent to a device without visible_notification_opt_in). Terminal; the caller falls back to the blind_wakeup form and MUST NOT resend the same shape. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: "projection_incomplete",
        applies_to: &["client_sync", "view_projection"],
        description: "Projection cannot be materialized because of missing reducer inputs, decryption_pending epochs, or out-of-window backfill.",
    },
    ReasonCodeDescriptor {
        code: "proof_binding_missing",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Proof lacks a required `domain` or `audience` binding on a cross-service, cross-trust-domain, federation, or multi-audience call. Receivers MUST fail closed rather than accept a single-audience proof across services. A profile MAY define a more specific reason. See zh/models/event-and-patch.md §3.",
    },
    ReasonCodeDescriptor {
        code: "proof_failed",
        applies_to: &["device_recovery"],
        description: "Recovery-session `rejection_reason_code` value: proof verification failures reached the server-side policy limit, so the session transitioned to `rejected`. Closed value set defined in artifacts/schemas/recovery-session.schema.json and zh/crypto-media/device-lifecycle.md §15.",
    },
    ReasonCodeDescriptor {
        code: "proof_invalid",
        applies_to: &["auth_decision", "service_call"],
        description: "A runtime key-pairing or session-grant proof (DID `assertionMethod` signature, agent_key_proof transcript, etc.) failed signature verification, transcript binding, or `proof_kind` check. Distinct from `invalid_signature` in that the wire shape was syntactically valid but the proof semantics did not bind to the expected principal / nonce / audience. See zh/identity/key-management.md §3.6 §4.5.",
    },
    ReasonCodeDescriptor {
        code: "push_gateway_unreachable",
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify: the gateway could not durably take the route over. One of exactly two caller-retryable notify reasons; it MAY carry retry_after_ms, and its presence is the wire signal that the caller — not the gateway — owns the next attempt. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: "push_payload_too_large",
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify: the notification exceeds the push profile, provider, or deployment size limit. Target-level, so the gateway MUST expand it into one same-reason rejected outcome per input device. Terminal until the caller shrinks the payload; MUST NOT carry retry_after_ms. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: "push_route_limit_exceeded",
        applies_to: &["event_envelope", "service_call"],
        description: "A `ak.device.push_route` registration would exceed the v1 wire limit of 16 active push_route entries per `(recipient_service_id, principal_id, device_id)`. The server MUST reject the new registration. See zh/crypto-media/device-lifecycle.md §5a.2 and zh/conformance/scalability-constraints.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "push_route_registration_rate_limited",
        applies_to: &["service_call"],
        description: "Internal audit reason recorded when push-route registration / rotation writes for a `(recipient_service_id, principal_id, device_id)` exceed the default rate (8 writes per 60s). The outward response uses a generic rate-limited envelope; this reason is for server-side abuse detection only. See zh/crypto-media/device-lifecycle.md §5a.2 and zh/conformance/scalability-constraints.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "push_target_unknown",
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify: the push target is unknown or no longer visible. Target-level, so the gateway MUST expand it into one same-reason rejected outcome per input device. Terminal; not caller-retryable and MUST NOT carry retry_after_ms. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: "push_token_invalid",
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify: the registered route failed provider validation or is no longer bound to this device. Terminal; the caller SHOULD drop the device registration. Cleanup is addressed by the composite identity — the response never returns the raw push_key. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: "push_token_unknown",
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify: no active push registration exists for this (push_target_id, device_id). Terminal; the caller SHOULD drop the device registration. Cleanup is addressed by the composite identity — the response never returns the raw push_key. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: "quarantined",
        applies_to: &["state_resolution", "federation_transaction"],
        description: "Item was placed in quarantine pending operator decision (state_conflict_resolution); not finalized.",
    },
    ReasonCodeDescriptor {
        code: "queue_full",
        applies_to: &["batch_item"],
        description: "Per-event rejection reason in an Applet edge transaction response (rejected[].reason_code) when the receiving applet's inbound processing queue is saturated (backpressure). The push sender MAY re-deliver the rejected events later under the same idempotency identity. See zh/extensions/applet-integration.md §7.3.",
    },
    ReasonCodeDescriptor {
        code: "quorum_unreachable",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A member application under an object-form `reviewer_quorum` {threshold, reviewers} can no longer reach `threshold`: the count of reviewers still holding `review_capability` at the evaluation frontier dropped below `threshold`. The reducer / review service MUST terminate the application as a reject with reason_code=quorum_unreachable rather than letting it hang until application_ttl, and SHOULD trigger join-policy re-evaluation. See zh/governance/join-policy.md §3.",
    },
    ReasonCodeDescriptor {
        code: "range_completeness_actor_seq_gap",
        applies_to: &["audit_decision", "state_resolution"],
        description: "Verifier's local actor view contains a per-actor seq gap inside an interval that a ak.attestation.range_completeness attestation (payload schema ak.schema.range_completeness_attestation.v1) declared complete. Most likely indicator of silent fork or partial replication divergence beyond the attestation's stated scope. See zh/sync/operations-sync.md §6.4.4 step 6.",
    },
    ReasonCodeDescriptor {
        code: "range_completeness_root_mismatch",
        applies_to: &["audit_decision", "state_resolution"],
        description: "A ak.attestation.range_completeness attestation's root (payload schema ak.schema.range_completeness_attestation.v1) does not match the locally-recomputed Merkle root over the scope's reducer-input events. Indicates either silent omission by the issuer or scope/canonicalization drift. See zh/sync/operations-sync.md §6.4.4 step 4.",
    },
    ReasonCodeDescriptor {
        code: "rate_limited",
        applies_to: &["push_notify_outcome"],
        description: "Per-device rejection reason in ak.edge.push.command.notify: gateway-side admission limiting refused durable takeover of this route. One of exactly two caller-retryable notify reasons; it MAY carry retry_after_ms. A route the gateway already accepted is retried by the gateway and never surfaces this reason. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/discovery/push-notifications.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: "reaction_scope_mismatch",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a ak.reaction.* target_ref resolves to an object outside the reaction event's stamped effective scope. Reactions MUST target an object within their own effective scope. See zh/models/strand-and-message.md §9.8.2.",
    },
    ReasonCodeDescriptor {
        code: "reaction_target_unsupported",
        applies_to: &["schema_validation", "state_resolution"],
        description: "Sub-reason for schema_violation when a ak.reaction.add / ak.reaction.remove target_ref points at an object kind that the deployment does not allow reactions on. v1 core only allows ak:message: targets; profiles MAY register additional target kinds. See zh/models/strand-and-message.md §9.8.2.",
    },
    ReasonCodeDescriptor {
        code: "read_receipt_forced_public_world_readable_forbidden",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Reducer rejected a read-receipt policy whose effective combination is `disclosure='required'` AND `visibility='public'` on a `world_readable` scope — forced emission of publicly-pullable read positions with no member opt-out (forced de-anonymized activity tracking) — unless the policy payload also sets the second explicit opt-in `receipt_compliance_opt_in.forced_public_world_readable_receipts=true`. See zh/discovery/read-receipts.md §2.5.1.",
    },
    ReasonCodeDescriptor {
        code: "read_receipt_visibility_combination_invalid",
        applies_to: &["schema_violation", "state_resolution"],
        description: "Read receipt visibility=public was combined with history_visibility=world_readable without an explicit opt-in marker. Reducer MUST reject the combination to avoid leaking actor read positions to anonymous observers.",
    },
    ReasonCodeDescriptor {
        code: "realm_alias_homograph_forbidden",
        applies_to: &["schema_validation", "service_call"],
        description: "Realm alias registration collided with the same authority-local realm-alias-namespace UTS #39 skeleton index or failed its declared Highly Restrictive registration policy. Skeletons do not define canonical equality; cross-namespace handle/realm-alias homographs are disambiguated by sigil and type context. See zh/discovery/object-addressing.md §3.3.",
    },
    ReasonCodeDescriptor {
        code: "realm_already_exists",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.create event attempted to create a Realm id whose genesis cell is already set. Reducer MUST reject the duplicate create without rewriting create-locked fields.",
    },
    ReasonCodeDescriptor {
        code: "realm_founding_grant_missing",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.create bootstrap batch did not place the required closed-form creator self founding grant immediately after the create event. Reducer MUST reject the entire bootstrap unit atomically without leaving Realm metadata or creator membership. See zh/models/realm-and-space.md section 2.5.",
    },
    ReasonCodeDescriptor {
        code: "realm_link_invalid_transition",
        applies_to: &["state_resolution"],
        description: "An ak.realm.link status transition is absent from the canonical FSM transition matrix, including any non-byte-identical attempt to leave terminal tombstoned state. The reducer MUST reject with top-level failed_precondition. See zh/models/realm-links.md §4.",
    },
    ReasonCodeDescriptor {
        code: "realm_link_self_reference",
        applies_to: &["schema_validation", "state_resolution"],
        description: "An ak.realm.link targets its own enclosing Realm. Self-links have no cross-boundary meaning and MUST be rejected with top-level schema_violation. General directed cycles remain valid. See zh/models/realm-links.md §2.",
    },
    ReasonCodeDescriptor {
        code: "realm_organization_authorization_invalid",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement failed organization-side authorization: payload.authorization.proof did not verify against the organization DID control state, threshold governance quorum, or the verification_method, or issuer_role is not allowed for the relationship. This is the generic organization-consent failure used when no more specific realm_organization_* reason applies. Downstream implementations MUST emit this exact code rather than inventing a bare string.",
    },
    ReasonCodeDescriptor {
        code: "realm_organization_delegation_missing",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement whose authorization.issuer_role is governance_service or account_authority omitted authorization.delegation_ref, or the referenced delegation does not resolve to a live organization DID delegation whose purpose covers ak.realm.organization and the requested relationship/control_scopes.",
    },
    ReasonCodeDescriptor {
        code: "realm_organization_expired",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement is outside its validity window: the evaluation time is before payload.not_before, after payload.expires_at, or outside the referenced delegation's validity period. Schema validation passes; the reducer MUST reject the statement as expired or not-yet-valid.",
    },
    ReasonCodeDescriptor {
        code: "realm_organization_realm_acceptance_missing",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement lacks the Realm-side acceptance layer: the writing principal does not hold ak.realm.admin and the event is not part of an allowed create-bootstrap initial-configuration batch. Realm-side acceptance is independent of the organization-side proof.",
    },
    ReasonCodeDescriptor {
        code: "realm_organization_scope_missing",
        applies_to: &["event_envelope", "state_resolution"],
        description: "A ak.realm.organization statement asserts a control_scope (or relationship) that the verified organization-side authorization or its delegation does not cover. The endorsement boundary in payload.control_scopes exceeds what the proof/delegation grants.",
    },
    ReasonCodeDescriptor {
        code: "realm_terminal_state",
        applies_to: &["state_resolution", "auth_decision"],
        description: "Realm has accepted ak.realm.tombstone or ak.realm.destroy and cannot accept new ordinary writes. Only audit-class events (ak.audit.*, ak.audit.erasure_receipt) are still acceptable. Receivers MUST reject ak.self.events.command.submit for any other kind targeting this Realm. See zh/models/realm-and-space.md §2.6.",
    },
    ReasonCodeDescriptor {
        code: "realm_unavailable",
        applies_to: &["auth_decision", "state_resolution"],
        description: "The effective target Realm is tombstoned, destroyed, unreachable, or not writable by the actor; default Realm resolution MUST fail closed instead of following Realm links or falling back implicitly. See zh/models/space-hierarchy.md §4.",
    },
    ReasonCodeDescriptor {
        code: "recipient_unavailable",
        applies_to: &["service_call"],
        description: "A to-device delivery targeted a deactivated principal whose pending queue was dropped by the deactivation fanout; further delivery MUST fail closed rather than enqueue. See zh/identity/account-lifecycle.md §7.1.",
    },
    ReasonCodeDescriptor {
        code: "recording_artifact_pipeline_bypassed",
        applies_to: &["service_call"],
        description: "A backend (LiveKit Egress / Janus recording plugin / etc.) attempted to deliver a recording artifact outside the Arkret-side blob pipeline — e.g. an Egress destination pointing to LiveKit Cloud / S3 / GCS direct, instead of the Arkret media service authenticated upload endpoint. Clients MUST fail closed. See zh/crypto-media/call-state.md §5 and zh/crypto-media/media-service-binding.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: "recording_consent_required",
        applies_to: &["service_call", "event_envelope"],
        description: "An `ak.call.recording.start` event attempted to enter recording/transcribing without `payload.result.retention.consent_confirmed=true` and a capture-kind-specific start-event ref equal to the Event `event_id`. Reducer MUST reject before either capture FSM or result cell is written. See zh/crypto-media/call-state.md §5.2.",
    },
    ReasonCodeDescriptor {
        code: "recording_state_transition_invalid",
        applies_to: &["event_envelope"],
        description: "An `ak.call.state` event requested a `recording_transition` or `transcript_transition` not listed in the per-capture controlled state machine (e.g. transitioning out of terminal `ready` / `failed`, `stopped → failed`, or attempting to enter a capturing state without a new `ak.call.recording.start`). The reducer MUST `failed_precondition`. The same code covers both orthogonal capture dimensions. See zh/crypto-media/call-state.md §4.2.",
    },
    ReasonCodeDescriptor {
        code: "recovery_capability_not_sealed",
        applies_to: &["event_envelope", "state_resolution"],
        description: "Conflict-recovery witness's state_root does not contain (or contains a divergent value for) the recovery_capability cell referenced by the grant. See zh/authz/event-auth-state-resolution.md §9.5.",
    },
    ReasonCodeDescriptor {
        code: "recovery_evidence_unbound",
        applies_to: &["device_recovery", "cross_signing"],
        description: "A proof transcript for recovery, cross-signing reset, device authorization, or recovery-policy rotation is not bound to `(policy_id, version, recovery_session_id)`. Receivers MUST reject. See zh/identity/key-management.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: "recovery_policy_genesis_not_v1",
        applies_to: &["schema_validation", "state_resolution"],
        description: "A recovery policy publish is the first accepted policy for the principal but does not use `version=1`. Genesis recovery policies MUST start at version 1.",
    },
    ReasonCodeDescriptor {
        code: "recovery_policy_mismatch",
        applies_to: &["device_recovery", "state_resolution"],
        description: "A key-backup envelope or recovery proof references a `recovery_policy.policy_id` / `policy_version` that is not the currently accepted policy for the principal. Recovery strands MUST surface this to the user as 'update recovery policy' rather than silently continuing. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/identity/key-management.md §7.5.4 / §7.7 and zh/crypto-media/device-lifecycle.md §15.",
    },
    ReasonCodeDescriptor {
        code: "recovery_policy_supersedes_invalid",
        applies_to: &["schema_validation", "state_resolution"],
        description: "A non-genesis recovery policy rotation omits `supersedes` or names a predecessor other than the currently accepted policy_id for the principal. Servers MUST reject with 409 Conflict.",
    },
    ReasonCodeDescriptor {
        code: "recovery_policy_version_not_monotonic",
        applies_to: &["schema_validation", "state_resolution"],
        description: "A recovery policy publish or rotation uses a `version` that is not strictly greater than the currently accepted policy version for the principal. Servers MUST reject with 409 Conflict.",
    },
    ReasonCodeDescriptor {
        code: "recovery_principal_isolation",
        applies_to: &["authz", "device_recovery"],
        description: "A recovery policy or recovery session request targets a principal_id different from the authenticated principal or authorized recovery coordinator scope. Servers MUST reject without revealing the target principal's recovery state.",
    },
    ReasonCodeDescriptor {
        code: "recovery_proof_kind_unknown",
        applies_to: &["schema_validation", "device_recovery"],
        description: "A recovery policy, receipt, or proof names a proof kind outside the ak.schema.recovery_policy.v1 allowed_proof_kinds enum. Producers MUST use one of principal_signing, recovery_unlock, device_quorum, trusted_recovery_service, or threshold_recovery.",
    },
    ReasonCodeDescriptor {
        code: "recovery_session_challenge_mismatch",
        applies_to: &["device_recovery", "schema_validation"],
        description: "A recovery proof echoes a challenge value that does not exactly match the server-issued challenge for the referenced recovery_session_id. Servers MUST reject the proof before completing device recovery. See zh/crypto-media/device-lifecycle.md §15 and artifacts/schemas/recovery-session.schema.json.",
    },
    ReasonCodeDescriptor {
        code: "recovery_session_terminal",
        applies_to: &["device_recovery", "service_call"],
        description: "A recovery-session submit_proof or a new RecoveryTransaction binding targeted a recovery session that is already in a terminal state (`completed` / `rejected` / `expired`). Terminal recovery sessions are immutable; servers MUST reject with top-level `failed_precondition` carrying this reason_code. Recovery sessions have no public complete operation. See zh/crypto-media/device-lifecycle.md §15 and artifacts/schemas/recovery-session.schema.json.",
    },
    ReasonCodeDescriptor {
        code: "recovery_target_not_in_bottom",
        applies_to: &["state_resolution", "auth_decision"],
        description: "An ak.state.conflict_recovery reset named a target_cell that is not in ⊥. The reset replaces a cell rather than joining into it, so allowing it on a live cell would make recovery a general overwrite channel that bypasses every lattice and every precondition. This is the converse of cell_in_bottom_state, which rejects an ordinary write against a cell that is in ⊥. See zh/authz/event-auth-state-resolution.md §9.5.",
    },
    ReasonCodeDescriptor {
        code: "recovery_witness_invalid",
        applies_to: &["event_envelope", "state_resolution"],
        description: "Conflict-recovery Move's inclusion proof cannot reconstruct the witness's `state_root`. See zh/authz/event-auth-state-resolution.md §9.5.",
    },
    ReasonCodeDescriptor {
        code: "recovery_witness_missing",
        applies_to: &["event_envelope", "state_resolution"],
        description: "Conflict-recovery Move is missing the required `refs[role=state_witness]` reference. See zh/authz/event-auth-state-resolution.md §9.5.",
    },
    ReasonCodeDescriptor {
        code: "recovery_witness_post_conflict",
        applies_to: &["event_envelope", "state_resolution"],
        description: "Conflict-recovery witness frontier has a causal path from one of the sibling Moves that triggered the bottom — i.e., the witness is not strictly pre-conflict. See zh/authz/event-auth-state-resolution.md §9.5.",
    },
    ReasonCodeDescriptor {
        code: "recovery_witness_revoke_lagging",
        applies_to: &["event_envelope", "state_resolution"],
        description: "Conflict-recovery witness is older than the permitted freshness window, or local frontier has observed a revoke / supersede for the referenced recovery_capability after the witness frontier. Receivers MUST reject stale witness replay. See zh/authz/event-auth-state-resolution.md §9.5.",
    },
    ReasonCodeDescriptor {
        code: "reducer_profile_mismatch",
        applies_to: &["federation_transaction", "service_call"],
        description: "Federation push / pull body's service_binding_ref.reducer_profile_digest differs from the receiver's reducer profile for the target Realm. Receiver MUST reject the entire batch (not partial-accept) because the same Event under different reducer profiles would produce divergent cell state, state_root and covered_seals_cell state — silently accepting would corrupt audit. Sender SHOULD reconcile reducer profile via Realm policy update or terminate federation for this Realm.",
    },
    ReasonCodeDescriptor {
        code: "reducer_projection_failed",
        applies_to: &["event_envelope", "state_resolution"],
        description: "The reducer projection required by the registered contract cannot be derived uniquely from `kind`, signed envelope fields, schema-validated payload, and frozen pre-state. Receiver MUST reject the entire Event; projected writes are reducer output and never producer-selected Event fields. See zh/models/event-and-patch.md §4.3.1.",
    },
    ReasonCodeDescriptor {
        code: "refs_too_large",
        applies_to: &["schema_validation", "event_envelope"],
        description: "Event Envelope refs[] exceeds the v1 maximum of 128 semantic refs. Receiver MUST reject with schema_violation. See zh/conformance/scalability-constraints.md.",
    },
    ReasonCodeDescriptor {
        code: "relation_already_terminal",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.relation.tombstone` / `ak.relation.update` / equivalent Relation write rejected because the target Relation is already in the terminal state `tombstone`. In particular, `ak.relation.update` targeting a tombstoned Relation MUST be rejected with this reason_code.",
    },
    ReasonCodeDescriptor {
        code: "relation_conflict_fanout_exceeded",
        applies_to: &["state_resolution"],
        description: "The number of concurrent candidates (winner + losers) under a single Relation dedupe key exceeded the conflict fanout limit (v1 public profile: 16, aligned with the sibling fork limit in zh/models/event-and-patch.md §2.6). The reducer rejects the whole candidate group rather than retaining unbounded loser records; reconvergence requires a repair Event/Control Move on the latest CBA query basis. See zh/models/relation.md §6.",
    },
    ReasonCodeDescriptor {
        code: "relation_kind_contains_derived",
        applies_to: &["event_envelope", "schema_validation"],
        description: "Sub-reason for schema_violation when a direct ak.relation.create / update / delete targets a derived-projection contains shape (Space(board) -> Space(list) or Space(list) -> Strand). Truth sources are the ak.component.space.parent.v1 and ak.component.strand.position.v1 cells written via ak.space.parent / ak.strand.move / ak.strand.reorder Moves; only the non-derived object-composition contains form is directly writable. See zh/models/relation.md §3.2 and zh/models/realm-and-space.md §3.5-§3.6.",
    },
    ReasonCodeDescriptor {
        code: "relation_kind_watches_derived",
        applies_to: &["event_envelope", "schema_validation"],
        description: "Sub-reason for schema_violation when a direct ak.relation.create / update / delete targets relation_kind=watches. The watches Relation is a derived projection only: its truth source is the ak.component.strand.watch.v1 cell written via the ak.strand.watch.set durable event, never a direct Relation write. See zh/models/relation.md §3.2 and zh/models/strand-and-message.md §8.",
    },
    ReasonCodeDescriptor {
        code: "relation_profile_cardinality_conflict",
        applies_to: &["schema_validation", "state_resolution"],
        description: "RelationProfile registration/update was rejected because its `cardinality` and `max_to_per_from` / `max_from_per_to` express contradictory bounds (e.g. one_to_one with max_to_per_from > 1, or many_to_one with max_to_per_from > 1), or a `max_*` value is <= 0. `max_*` may only tighten within the direction implied by `cardinality`. See zh/models/relation.md §5.",
    },
    ReasonCodeDescriptor {
        code: "relation_scope_unresolved",
        applies_to: &["state_resolution", "service_call"],
        description: "A Relation write with `relation_scope` in {space, board} was rejected because the reducer could not resolve the participating endpoints' owning board/space (`board_space_id`) used as the dedupe/cardinality key — the endpoint belongs to no board/space, or the owning board/space is tombstoned. The reducer MUST NOT silently downgrade to realm-scope dedupe. See zh/models/relation.md §5.",
    },
    ReasonCodeDescriptor {
        code: "relaxed_window_exceeds_ceiling",
        applies_to: &["schema_violation", "state_resolution"],
        description: "A ak.realm.policy_bundle write under ak.profile.e2ee_relaxed.v1 declared relaxed_window_max_ms greater than the spec hard ceiling (300000 ms / 5 min). Reducer MUST reject the policy update and receivers MUST NOT silently clamp; otherwise visible policy state splits across implementations. See artifacts/profiles/conformance-profiles.json#ak.profile.e2ee_relaxed.v1.downgrade_window_constraint.",
    },
    ReasonCodeDescriptor {
        code: "requires_organization_approval",
        applies_to: &["auth_decision", "service_call"],
        description: "Sub-reason for failed_precondition when a Realm moderation-policy override would relax an action forbidden by inherited organization policy without embedding a valid organization approval. See zh/sync/service-http-binding.md §2.3.",
    },
    ReasonCodeDescriptor {
        code: "reserved_circle_short_name",
        applies_to: &["schema_validation", "state_resolution", "service_call"],
        description: "Ordinary Circle create/update attempted to use the SC- short-name prefix reserved for reducer-managed Agent Sidecar backing Circles. The write is rejected as schema_violation. See zh/models/circle.md §4 and zh/models/sidecar.md §5.",
    },
    ReasonCodeDescriptor {
        code: "reset_event_id_mismatch",
        applies_to: &["schema_violation"],
        description: "ak.cross_signing.reset payload's reset_event_id does not match the enclosing Event Envelope's event_id. Binding reset_event_id into proof transcript prevents wrapping the same proof bytes into a different Event shell; receivers MUST reject the reset on any mismatch. See zh/crypto-media/device-lifecycle.md §14.1.",
    },
    ReasonCodeDescriptor {
        code: "revocation_freshness_unknown",
        applies_to: &[
            "auth_decision",
            "federation_transaction",
            "state_resolution",
        ],
        description: "Revocation / grant freshness cannot be established for a high-risk, cross-domain, or delegated action. Receiver MUST fail closed and return freshness diagnostics instead of treating missing revoke evidence as allow.",
    },
    ReasonCodeDescriptor {
        code: "revoke_order_unknown_requires_backfill_or_review",
        applies_to: &["state_resolution"],
        description: "Concurrent grant/revoke ordering cannot be deterministically resolved with currently available history; recipient SHOULD backfill or escalate to manual review rather than picking a winner.",
    },
    ReasonCodeDescriptor {
        code: "revoke_undo_invalid_signature",
        applies_to: &["authz", "auth_decision"],
        description: "A capability revoke-undo (rollback) references a revoke whose signature does not verify. The undo MUST fail closed and the original revoke stays in effect. See authz/capabilities.md and fixtures/capability-fixture.json.",
    },
    ReasonCodeDescriptor {
        code: "risk_policy",
        applies_to: &["device_recovery"],
        description: "Recovery-session `rejection_reason_code` value: a server-side risk policy rejected the session. Closed value set defined in artifacts/schemas/recovery-session.schema.json and zh/crypto-media/device-lifecycle.md §15.",
    },
    ReasonCodeDescriptor {
        code: "rsvp_basis_not_causal",
        applies_to: &["event_envelope", "schema_validation"],
        description: "entry.schedule_basis_refs is not a subset of the envelope causal_refs[], or is empty, duplicated, or not sorted in ascending canonical byte order. This shape admission is decidable without resolving the referenced Events and MUST reject rather than pend. See zh/models/calendar-event.md.",
    },
    ReasonCodeDescriptor {
        code: "rsvp_occurrence_not_canonical",
        applies_to: &["event_envelope", "schema_validation"],
        description: "payload.occurrence is neither JSON null nor a canonical instance key (YYYY-MM-DD for all-day, YYYY-MM-DDTHH:MM:SS[Zone] for timed), including when its date component is not a real proleptic-Gregorian date. Receivers MUST reject instead of rewriting the key, since the cell subject derives from the signed value. See zh/models/calendar-event.md.",
    },
    ReasonCodeDescriptor {
        code: "schedule_frontier_too_large",
        applies_to: &["event_envelope", "schema_validation"],
        description: "The observed Calendar schedule revision frontier exceeds the 128-entry bound shared with causal_refs, so entry.schedule_basis_refs cannot express it. The producer MUST converge the schedule before responding and MUST NOT truncate the basis. See zh/conformance/scalability-constraints.md. It is raised by the authoring client when the observed frontier itself exceeds the bound; a wire Event that actually carries more than 128 refs is instead rejected by schema maxItems as schema_violation.",
    },
    ReasonCodeDescriptor {
        code: "scope_expansion_forbidden",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A grant or delegation set `scope_expansion_allowed=true`. v1 does not permit a child to expand beyond the parent's resources/actions; the reducer MUST reject (schema_violation) because the field directly conflicts with the §10.1 `resources MUST ⊆ parent` invariant. See zh/authz/constraint-schema.md §7 / zh/authz/capabilities.md §10.1.",
    },
    ReasonCodeDescriptor {
        code: "scope_incomparable",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when a structural relation, parent, position, cascade, or reverse-projected fact would need to span two sibling Circle scopes in the same Realm. v1 reducers MUST NOT choose either Circle, union them, or promote the fact to Realm-default. See zh/models/circle.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "scope_rebind_forbidden",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when scope_circle_id rebind is attempted without an explicitly profile-permitted audited-high-risk path. Default reducer rejects rebinds to prevent silent historical-discussion migration. See zh/models/circle.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "scope_ref_mismatch",
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "The signed Event `scope_ref` does not equal the security scope deterministically resolved from the target or referenced accepted object state. Receiver MUST reject the Event and MUST NOT rewrite or reducer-stamp the signed scope. See zh/models/circle.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "scope_unavailable",
        applies_to: &["state_resolution"],
        description: "Sub-reason for failed_precondition when an object write references an effective scope whose Circle or parent Realm has been tombstoned/destroyed and cannot accept new writes. Projections may surface the same string as a non-error status marker. See zh/models/realm-and-space.md §2.6.1 and zh/models/circle.md §9.2.",
    },
    ReasonCodeDescriptor {
        code: "segment_aead_failed",
        applies_to: &["crypto", "service_call"],
        description: "Streaming-chunked AEAD attachment: a per-segment AEAD tag fails to verify. Receivers MUST reject the segment and abort the stream. See zh/crypto-media/media-and-blob.md §3.3.6.",
    },
    ReasonCodeDescriptor {
        code: "segment_bounds_invalid",
        applies_to: &["schema_validation", "service_call"],
        description: "Streaming-chunked AEAD attachment: a segment index is out of range, a segment length violates `segment_bytes`, or `segment_count` disagrees with the observed stream. Receivers MUST reject. See zh/crypto-media/media-and-blob.md §3.3.",
    },
    ReasonCodeDescriptor {
        code: "segment_replay",
        applies_to: &["crypto", "service_call"],
        description: "Streaming-chunked AEAD attachment: a segment index appears more than once in the stream. Receivers MUST reject. See zh/crypto-media/media-and-blob.md §3.3.6.",
    },
    ReasonCodeDescriptor {
        code: "segment_sequence_invalid",
        applies_to: &["crypto", "service_call"],
        description: "Streaming-chunked AEAD attachment (`ak.blob.stream_aead.v1`): segment indices arrive out of order, skip a value, or leave a gap. Receivers MUST reject. See zh/crypto-media/media-and-blob.md §3.3.6.",
    },
    ReasonCodeDescriptor {
        code: "segment_stream_truncated",
        applies_to: &["crypto", "service_call"],
        description: "Streaming-chunked AEAD attachment: the stream ended without a valid final segment (last_segment_flag never observed, or fewer segments than `segment_count`). Receivers MUST reject to resist truncation. See zh/crypto-media/media-and-blob.md §3.3.6.",
    },
    ReasonCodeDescriptor {
        code: "selector_actor_wildcard_forbidden",
        applies_to: &["auth_decision", "schema_validation"],
        description: "The resource selector attempted to use actor:*. v1 actor selectors MUST name a concrete DID; universal subject grants are not accepted.",
    },
    ReasonCodeDescriptor {
        code: "selector_governance_wildcard_forbidden",
        applies_to: &["authz", "schema_violation"],
        description: "Governance-plane resource selector wildcard (e.g. policy:*, schema:*, or a governance object:* selector) was used without the required mitigation (denied by deployment policy, or constrained with max_delegation_depth=0 plus bounded expiry plus admin approval). Receiver MUST reject.",
    },
    ReasonCodeDescriptor {
        code: "selector_too_complex",
        applies_to: &["auth_decision", "service_call"],
        description: "Resource selector or constraint exceeds parser hard limits defined in resource-selector-grammar.md §3.3 (string length, resources[] length, token count, nesting depth, single-field length, required_claims item count, constraint nesting). Distinct from invalid_param so audit / abuse-detection can separate suspected parser-DoS attempts from ordinary format errors. Dual-registered as a reason_code and a top-level service code (see codes[]).",
    },
    ReasonCodeDescriptor {
        code: "send_failed",
        applies_to: &["state_resolution"],
        description: "Invite delivery to the private target failed after the delivery service exhausted the retry budget. Used as a stable invite transition reason for ak.invite state projections; see zh/models/governance-objects.md and zh/sync/third-party-invites.md §6.1.",
    },
    ReasonCodeDescriptor {
        code: "series_chain_broken",
        applies_to: &["schema_validation", "state_resolution", "device_recovery"],
        description: "ak.schema.key_backup.v1 envelope chain failed verification: a `supersedes_digest` does not match the canonical_json digest of its predecessor, or a non-genesis envelope is missing a predecessor accessible to the caller. See zh/identity/key-management.md §7.6 and zh/crypto-media/device-lifecycle.md §12 / §12.1.",
    },
    ReasonCodeDescriptor {
        code: "series_predecessor_not_found",
        applies_to: &["schema_validation", "state_resolution"],
        description: "`ak.schema.key_backup.v1.supersedes` references a backup_id that is unknown to the server, deleted, or owned by a different actor / series. Wire endpoint returns 409 Conflict; receivers MUST treat the chain as broken. See zh/crypto-media/device-lifecycle.md §12.1.",
    },
    ReasonCodeDescriptor {
        code: "series_seq_not_monotonic",
        applies_to: &["schema_validation", "state_resolution"],
        description: "A PUT /_arkret/self/keys/backups/{backup_id} request whose `series_seq` is not strictly greater than the current maximum sequence within the same (actor_id, series_id), or whose genesis envelope sets series_seq != 0. See zh/crypto-media/device-lifecycle.md §12.1.",
    },
    ReasonCodeDescriptor {
        code: "service_key_revoked",
        applies_to: &["federation_transaction", "auth_decision"],
        description: "Federation idempotency replay outcome: a cached federated request was re-evaluated and the origin service's signing key is now revoked, so the cache hit is treated as historical_only and MUST NOT bypass current key-state verification. See zh/conformance/conformance-vectors.md §9 (ak.vector.federation.idempotency_after_key_revoke.v1).",
    },
    ReasonCodeDescriptor {
        code: "service_not_plaintext_visible",
        applies_to: &["service_call", "auth_decision"],
        description: "Service is not in the Realm's plaintext_visible_services policy; plaintext-bound operation refused.",
    },
    ReasonCodeDescriptor {
        code: "service_prerotation_invalid",
        applies_to: &["identity_resolution", "service_call"],
        description: "A service did:webvh inception or rotation omitted the sole next-key commitment, supplied more than one update/next key, or failed to open the previous nextKeyHashes commitment. Providers and resolvers MUST fail closed as service_registration_rejected.",
    },
    ReasonCodeDescriptor {
        code: "session_focus_already_committed",
        applies_to: &["event_envelope"],
        description: "A subsequent `ak.call.state` event attempted to write a `session_focus` value different from the already-committed one. The reducer MUST `failed_precondition` — `session_focus` is write-once per call lifecycle; in-session focus migration is not supported in v1. See zh/crypto-media/call-state.md §4.1.",
    },
    ReasonCodeDescriptor {
        code: "session_focus_no_split_brain",
        applies_to: &["service_call"],
        description: "The committed `ak.call.state.session_focus` is authoritative and write-once: once it exists, a connect / token-exchange failure against that focus MUST be surfaced as focus-unavailable (`focus_unavailable_for_client`) and clients MUST NOT silently fall back to a different focus to keep the media path up. Naming the invariant explicitly closes the split-brain attack where two subsets of a conference converge on different SFUs. See zh/crypto-media/media-service-binding.md §5 and §2 (`foci[].health_endpoint`).",
    },
    ReasonCodeDescriptor {
        code: "share_commitment_mismatch",
        applies_to: &["crypto", "device_recovery"],
        description: "A threshold-recovery share submitted during reconstruction does not match the `share_commitment{algorithm, commitment_b64u}` declared in the active recovery policy. Coordinator MUST notify the user which holder submitted an invalid share. See zh/identity/key-management.md §7.5.4 / §8.",
    },
    ReasonCodeDescriptor {
        code: "sidecar_create_denied",
        applies_to: &["auth_decision", "state_resolution", "service_call"],
        description: "Agent Sidecar ensure was denied without revealing whether the Sidecar, backing scope, context-private Strand, or a derived internal name already exists. Returned as a generic failed_precondition sub-reason to avoid existence side channels. See zh/models/sidecar.md §3 and §7.",
    },
    ReasonCodeDescriptor {
        code: "sidecar_exposure_ack_required",
        applies_to: &["auth_decision", "state_resolution", "service_call"],
        description: "ak.self.agent.command.resume was rejected because the Agent entered the desired-exposure set of one or more Agent Sidecar objects while paused, and the controller has not supplied the matching sidecar_exposure_ack re-disclosure. The controller MUST re-read the disclosure and resubmit; effective access still waits for backing-scope and MLS reconciliation. See zh/identity/key-management.md §3.6.1.",
    },
    ReasonCodeDescriptor {
        code: "signal_plaintext_forbidden",
        applies_to: &["service_call", "client_sync"],
        description: "Sub-reason for failed_precondition when any legacy plaintext broadcast envelope is submitted or received. Signal is encrypted-only in every scope; implementations MUST fail closed and MUST NOT advertise Signal for a scope unless they can verify its MLS basis, AAD, and proof. See zh/crypto-media/encryption-and-audit.md section 2.9.1.",
    },
    ReasonCodeDescriptor {
        code: "snapshot_issuer_revoked",
        applies_to: &["client_sync", "snapshot_verification"],
        description: "Snapshot signer's authority (Realm owner / admin / trusted snapshot issuer / witness quorum membership) was revoked at or before the manifest's `created_at`, or revoke freshness cannot be sealed within the verifier's revocation_freshness_window_ms. Client MUST quarantine or reject the snapshot. A revoke that takes effect strictly after `created_at` does not retroactively invalidate a previously valid snapshot.",
    },
    ReasonCodeDescriptor {
        code: "soft_failed",
        applies_to: &["state_resolution", "service_call"],
        description: "An Event or reducer input is held in a reversible soft-failed state pending causal backfill, authorization material, policy evidence, or asynchronous verification. It may later upgrade to accepted or roll back to rejected, but accepted MUST NOT degrade to rejected without a new governance event. See zh/sync/operations-sync.md §4.4.",
    },
    ReasonCodeDescriptor {
        code: "space_already_terminal",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.space.tombstone` rejected because the target Space is already `tombstoned`.",
    },
    ReasonCodeDescriptor {
        code: "space_has_live_dependents",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.space.tombstone` cannot proceed because the target Space still has active `contains` Relations or non-tombstoned child Spaces. See zh/models/realm-and-space.md §3.4.",
    },
    ReasonCodeDescriptor {
        code: "space_not_active",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.space.archive` rejected because the target Space is not in `active` state (per zh/models/realm-and-space.md §3.3).",
    },
    ReasonCodeDescriptor {
        code: "space_not_archived",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.space.restore` rejected because the target Space is not in `archived` state; `tombstoned` is a terminal state and MUST NOT be restored.",
    },
    ReasonCodeDescriptor {
        code: "space_parent_chain_in_bottom_state",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `match_scope=subtree` / `children` selector required resolving the target Space's ancestor chain under the authorizing operation's CBA basis, but the `ak.space.parent` cell was in a multi-head / bottom (⊥) state. The subtree authorization branch MUST fail closed rather than pick an arbitrary head, otherwise the same grant could authorize divergently across receivers (split authz). See zh/authz/resource-selector-grammar.md §6.",
    },
    ReasonCodeDescriptor {
        code: "space_parent_cycle",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.space.parent` would create a cycle in the Space ancestor chain (self-loop or chain loop). Reducer MUST reject (zh/models/realm-and-space.md §3.5).",
    },
    ReasonCodeDescriptor {
        code: "space_parent_unreadable",
        applies_to: &["event_envelope", "auth_decision", "projection"],
        description: "The effective Space parent chain cannot be read or verified at the operation basis. Parent-dependent placement, default-Realm resolution, and subtree authorization MUST fail closed rather than treating the Space as a root. See zh/models/space-hierarchy.md section 4.",
    },
    ReasonCodeDescriptor {
        code: "spam",
        applies_to: &["moderation_report"],
        description: "Standard moderation reason: spam content.",
    },
    ReasonCodeDescriptor {
        code: "stale_backup_trust_generation",
        applies_to: &["device_recovery", "cross_signing", "state_resolution"],
        description: "A key-backup envelope's auth_data verification method is bound to a self-signing generation older than the current accepted generation and outside the rotation grace window. Receivers MUST reject the envelope for recovery or read paths. See zh/identity/key-management.md §7.4.1.",
    },
    ReasonCodeDescriptor {
        code: "state_mismatch",
        applies_to: &["client_sync", "state_resolution"],
        description: "Local state does not match the authoritative frontier; client SHOULD reconcile via backfill or snapshot before continuing.",
    },
    ReasonCodeDescriptor {
        code: "storage_failed",
        applies_to: &["event_envelope", "service_call"],
        description: "Capture artifact persistence or deletion failed in the Arkret blob pipeline.",
    },
    ReasonCodeDescriptor {
        code: "strand_already_terminal",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `ak.redaction` event targeting a Strand is rejected because the target Strand is already in terminal state `redacted`. Strand terminal state is reached via ak.redaction.",
    },
    ReasonCodeDescriptor {
        code: "strand_not_active",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.strand.archive` / `ak.strand.update` rejected because the target Strand is not in `active` state (per zh/models/common-fields.md §5.1).",
    },
    ReasonCodeDescriptor {
        code: "strand_not_archived",
        applies_to: &["event_envelope", "auth_decision"],
        description: "`ak.strand.restore` rejected because the target Strand is not in `archived` state.",
    },
    ReasonCodeDescriptor {
        code: "structure_depth_exceeded",
        applies_to: &["encoding", "schema_validation"],
        description: "A canonical JSON or deterministic CBOR structure exceeds the v1 maximum nesting depth of 64 (objects and arrays combined, top-level container = depth 1). Receiver MUST reject (top-level schema_violation) before recursive descent can exhaust the stack, and MUST NOT truncate or partially parse. See zh/conformance/scalability-constraints.md section 2.",
    },
    ReasonCodeDescriptor {
        code: "subdelegation_prohibited",
        applies_to: &["event_envelope", "auth_decision"],
        description: "A `ak.capability.delegate` was issued from a parent grant carrying `prohibit_subdelegation=true`, or attempts to set the child's `max_delegation_depth` above 0 when the parent prohibits sub-delegation. When `prohibit_subdelegation=true` the child's `max_delegation_depth` MUST be 0; reducers MUST reject any further delegation. See zh/authz/capabilities.md §6 / §10.",
    },
    ReasonCodeDescriptor {
        code: "superseded",
        applies_to: &["device_recovery"],
        description: "Recovery-session `rejection_reason_code` value: the session was superseded by a newer recovery session for the same principal / device. Closed value set defined in artifacts/schemas/recovery-session.schema.json and zh/crypto-media/device-lifecycle.md §15.",
    },
    ReasonCodeDescriptor {
        code: "superseded_by_repairing",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Reducer audit reason stamped when one controller-signed ak.agent.key.authorize runtime-replacement Event atomically observe-removes every prior active authorization dot named by its exact supersedes[] set and adds the new authorization. No synthetic ak.agent.key.revoke Event is authored. Sessions issued from superseded keys MUST fail closed within the revocation freshness window. See zh/identity/key-management.md §3.6.1.",
    },
    ReasonCodeDescriptor {
        code: "third_party_invite_token_in_query",
        applies_to: &["service_call", "auth_decision"],
        description: "A 3PID invite claim arrived with the invite_token sourced from a URL query string or path segment instead of from a URL fragment or out-of-band code, in violation of zh/sync/third-party-invites.md §3.2. The verification service MUST reject and SHOULD invalidate the token to prevent referer / log replay.",
    },
    ReasonCodeDescriptor {
        code: "token_expired",
        applies_to: &["service_call", "auth_decision"],
        description: "A media backend join token presented at connect time is past its `expires_at` (e.g. a LiveKit JWT whose `exp` has elapsed, distinct from `proof_invalid` which covers a structurally bad / wrong-issuer signature). The client MUST re-run the media-service-binding §3 token exchange instead of reusing the stale token; clients MUST NOT extend or replay an expired backend token. See zh/crypto-media/bindings/livekit.md §8 and zh/crypto-media/bindings/arkret-native.md.",
    },
    ReasonCodeDescriptor {
        code: "token_issuer_unauthorised",
        applies_to: &["service_call", "auth_decision"],
        description: "A media token's `service_signature.kid` or `participant_binding.issuer_kid` resolves to a service DID that does NOT appear in the current epoch `ak.realm.media_service.service_id` (or the foci[]-aligned token endpoint seal). Clients MUST reject — this closes the attack where any service can forge a focus join token. See zh/crypto-media/media-service-binding.md §3.",
    },
    ReasonCodeDescriptor {
        code: "transcription_artifact_pipeline_bypassed",
        applies_to: &["service_call"],
        description: "A backend attempted to deliver a transcription artifact outside the Arkret-side blob pipeline, or used a key not derived from the MLS-Exporter label `ak.rtc-transcript-key/v1` (e.g. reused the SFrame / recording label or an empty Context). Clients MUST fail closed. See zh/crypto-media/call-state.md §5.1 and zh/crypto-media/media-service-binding.md §8.1.",
    },
    ReasonCodeDescriptor {
        code: "transcription_denied",
        applies_to: &["service_call", "auth_decision"],
        description: "Call transcription was requested without `ak.call.transcribe` capability, or the Realm policy forbids transcription. Issuer / reducer MUST reject; parallels `recording_denied` for the transcribe dimension. See zh/crypto-media/call-state.md §5.1.",
    },
    ReasonCodeDescriptor {
        code: "ttl_expired",
        applies_to: &["event_envelope", "auth_decision", "state_resolution"],
        description: "A bounded-lifetime artefact (member application, reservation cell, presign envelope, runtime gate proof, etc.) is past its declared `expires_at` / TTL window. See per-feature spec sections.",
    },
    ReasonCodeDescriptor {
        code: "unknown_event_kind",
        applies_to: &["event_envelope"],
        description: "Event kind does not appear in any known registry entry; treat per non_critical_extension_rule (preserve canonical bytes, ignore in reducer) unless declared in critical_extensions.",
    },
    ReasonCodeDescriptor {
        code: "unknown_field",
        applies_to: &["event_envelope"],
        description: "Current parser rejected an Event carrying a top-level or payload field not declared by the closed schema for its kind (including removed / renamed fields in artifacts/registry/forbidden-wire-fields.json). Distinct from `schema_violation` in that it pinpoints an unrecognized field rather than a constraint violation on a known field. See zh/spec-map.md §1.2.1.",
    },
    ReasonCodeDescriptor {
        code: "unknown_focus_type",
        applies_to: &["service_call", "schema_validation"],
        description: "A `ak.realm.media_service.foci[].type` value is not in the v1 registered set (`livekit` / `mediasoup` / `janus` / `arkret_native` / `moq_relay`) or is registered but not supported by this client / issuer. Clients MUST fail closed instead of forwarding the token to an arbitrary SDK. See zh/crypto-media/media-service-binding.md §2.",
    },
    ReasonCodeDescriptor {
        code: "unknown_kind",
        applies_to: &["event_envelope"],
        description: "Current parser rejected an Event whose `kind` is not an active registered v1 kind. Sync, federation, snapshot, SDK, and conformance paths MUST fail closed and MUST NOT perform payload-shape disambiguation or alias lookup. See zh/spec-map.md §1.2.1 and zh/overview/evolution-and-compatibility.md.",
    },
    ReasonCodeDescriptor {
        code: "unresolved_basis",
        applies_to: &["state_resolution", "projection"],
        description: "A projected RSVP head references a schedule basis that cannot be resolved, is invisible, or is not on the target Strand's schedule revision DAG. The head is retained for audit, excluded from the effective response, and MUST NOT be guessed into currency. See zh/models/calendar-event.md.",
    },
    ReasonCodeDescriptor {
        code: "unsupported_aead_profile",
        applies_to: &["crypto", "schema_validation"],
        description: "Receiver does not recognise `encryption.aead.aead_profile` (or sees a reserved-but-unpublished profile such as `ak.aead.hybrid_kem.*`). Receivers MUST fail closed; inferring parameters from `aead.name` alone is forbidden. See zh/identity/key-management.md §7.9.",
    },
    ReasonCodeDescriptor {
        code: "unsupported_attachment_scheme",
        applies_to: &["schema_validation", "service_call"],
        description: "An encrypted-attachment envelope carries a `scheme` value the receiver does not recognise. Receivers MUST fail closed rather than guess a decryption form. See zh/crypto-media/media-and-blob.md §3.2/§3.3.",
    },
    ReasonCodeDescriptor {
        code: "unsupported_digest_algorithm",
        applies_to: &["schema_validation", "batch_item", "event_envelope"],
        description: "Per-item algorithm-agility failure: a critical digest prefix is not an active digest-suite registry row. Receiver MUST fail closed. Dual-registered with the top-level service code.",
    },
    ReasonCodeDescriptor {
        code: "unsupported_event_kind",
        applies_to: &["event_envelope"],
        description: "Event kind is not active in the receiver's profile or registry; receiver MUST NOT silently drop, MUST report this code.",
    },
    ReasonCodeDescriptor {
        code: "unsupported_feature",
        applies_to: &["service_call", "feature_discovery"],
        description: "Implementation does not advertise the feature requested; caller SHOULD downgrade or pick another peer.",
    },
    ReasonCodeDescriptor {
        code: "unsupported_hpke_suite",
        applies_to: &["service_call", "auth_decision"],
        description: "HPKE suite id on an application-layer sealed surface (key-backup recipient_method=recovery_public_key, ak.secret.send, member-application encryption_envelope, file-transfer key_envelope) is not an active row in artifacts/registry/hpke-suite-registry.json (unknown, inactive, or reserved-but-not-activated). Receivers MUST fail closed rather than infer suite parameters from the AEAD name. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/identity/key-management.md §7.5.2.",
    },
    ReasonCodeDescriptor {
        code: "unsupported_signature_alg",
        applies_to: &["event_envelope", "auth_decision"],
        description: "Proof / event signature `alg` is not in the conformance signature-algorithm allowlist. Dual-registered as a reason_code and a top-level service code (see codes[]). See zh/conformance/encoding.md.",
    },
    ReasonCodeDescriptor {
        code: "untrusted_backup_signature",
        applies_to: &["crypto", "device_recovery", "state_resolution"],
        description: "A key-backup envelope signature verifies cryptographically but the signer device key cannot be linked to the current actor cross-signing trust root, or the signer is revoked, unauthorized, or generation-mismatched. Receivers MUST reject it even if the series chain and ciphertext_digest are self-consistent. See zh/identity/key-management.md §7.4.1.",
    },
    ReasonCodeDescriptor {
        code: "verification_method_principal_mismatch",
        applies_to: &["auth_decision", "service_call"],
        description: "A request supplied a `verification_method` whose DID component does not bit-identically match the target principal id after stripping fragment/query. Surfaces in two places. (1) `ak.gate.account.command.pair_agent_key`: `verification_method` vs `agent_id`. (2) `ak.gate.account.command.issue_session_grant` agent branch (`proof.proof_kind=\"agent_key_proof\"`): `proof.verification_method` vs request `principal_id`. Endpoints MUST fail closed before invoking the proof validator so that mismatch is reported as this code rather than as a generic signature failure. See zh/identity/key-management.md §3.6.1.",
    },
    ReasonCodeDescriptor {
        code: "view_already_terminal",
        applies_to: &["event_envelope", "state_resolution"],
        description: "An ak.view.update or ak.view.reconcile targeted a View whose accepted lifecycle state is tombstoned, or attempted to restore that View to active. Tombstoned shared Views are terminal. See zh/models/views.md §3.1.",
    },
    ReasonCodeDescriptor {
        code: "watch_level_public_must_be_self",
        applies_to: &["auth_decision"],
        description: "`ak.strand.watch.set` writing `level_public=true` for another actor is rejected — publishing one's own subscription level is an opt-in personal disclosure and MUST be written by the target actor themself. `ak.strand.watch.set.others` writes MUST omit `level_public` or set it to `false`. See zh/models/strand-and-message.md §8.4.",
    },
    ReasonCodeDescriptor {
        code: "watch_must_be_self",
        applies_to: &["auth_decision"],
        description: "`ak.strand.watch.set` may only set the watch state of the submitting actor; cross-actor writes require `ak.strand.watch.set.others` (audit / accessibility scope). See zh/models/strand-and-message.md §8.4.",
    },
    ReasonCodeDescriptor {
        code: "watch_muted_must_be_self",
        applies_to: &["auth_decision"],
        description: "`ak.strand.watch.set` writing `level=\"muted\"` for another actor is rejected — `muted` suppresses mention / moderation / workflow notifications and MUST be opt-in by the target actor themself. `ak.strand.watch.set.others` only authorizes writing `level ∈ {mentions_only, participating, all}` for other actors. See zh/models/strand-and-message.md §8.4.",
    },
    ReasonCodeDescriptor {
        code: "watch_set_others_audit_missing",
        applies_to: &["auth_decision"],
        description: "A `ak.strand.watch.set` write that uses `ak.strand.watch.set.others` to set another actor's watch state was rejected because it lacked refs[role=audit_pair] to a same-batch `ak.audit.accessed` event, or the paired audit payload did not identify the same writer DID, target actor DID, cell id, paired event id/digest, and before/after heads. See zh/models/strand-and-message.md §8.4.",
    },
    ReasonCodeDescriptor {
        code: "webvh_cache_too_stale",
        applies_to: &["auth_decision", "service_call"],
        description: "A did:webvh resolver cache entry exceeded the per-entry maximum evidence age, even if the global cache-only outage window has not expired. High-risk writes, service delegation, capability reconstruction, and snapshot witness acceptance MUST fail closed. See zh/identity/identity-did.md §5.",
    },
    ReasonCodeDescriptor {
        code: "webvh_cache_unavailable",
        applies_to: &["identity_resolution"],
        description: "did:webvh resolution is in cache-only degraded mode and either the requested operation is outside the closed low-risk read-only set, or no sealed, controller-proof-verified cache evidence is available. Resolver MUST fail closed rather than treat unresolvable as valid.",
    },
    ReasonCodeDescriptor {
        code: "webvh_witness_controlling_organization_unverified",
        applies_to: &["identity_resolution", "auth_decision"],
        description: "A deployment profile requires witnesses from distinct controlling organizations, but the controlling organization of at least one witness cannot be verified, or two witnesses resolve to the same organization. Counting unverifiable or colliding organizations would let one operator running several witness keys satisfy a distinct-organization requirement alone; the verifier MUST fail closed on high-risk paths. See zh/identity/identity-did.md §3.4.2.",
    },
    ReasonCodeDescriptor {
        code: "webvh_witness_evidence_stale",
        applies_to: &["identity_resolution", "auth_decision"],
        description: "Witness evidence is older than the effective max age set by deployment / Realm policy, measured from when the proof was observed rather than from when any Arkret receipt was signed. Re-signing an old observation does not refresh it. See zh/identity/identity-did.md §3.4.2.",
    },
    ReasonCodeDescriptor {
        code: "webvh_witness_parameter_malformed",
        applies_to: &["identity_resolution", "auth_decision"],
        description: "parameters.witness is present but is not the did:webvh 1.0 shape {threshold, witnesses:[{id}]}: threshold outside 1..witnesses.length, a duplicated witness id, a witness id that is not a did:key, a did:key whose multibase/multicodec payload does not decode to a well-formed public key compatible with the log's Data Integrity cryptosuite, or an unregistered extension key. Key decoding happens during parameter validation, not at signature time; accepting a witness id on string shape alone would let an unverifiable key occupy a threshold slot and hollow out the threshold. Also raised when parameters carries a look-alike key such as witnesses, witness_threshold or witnessThreshold, because that shape is evidence the log was produced against a non-standard dialect and the true policy is therefore unknown. A verifier MUST fail closed and MUST NOT fall back to treating the DID as unwitnessed: silently reading a malformed or aliased declaration as threshold 0 turns a DID that declares witnesses into one that requires none. See zh/identity/identity-did.md §3.4.1.",
    },
    ReasonCodeDescriptor {
        code: "webvh_witness_proof_invalid",
        applies_to: &["identity_resolution", "auth_decision"],
        description: "A witness proof in did-witness.json fails signature verification, is signed by a key outside the witness listed in parameters.witness, or does not bind the versionId it is offered for. The proof does not count toward threshold and the entry MUST be treated as under-witnessed. See zh/identity/identity-did.md §3.4.1.",
    },
    ReasonCodeDescriptor {
        code: "webvh_witness_proofs_unavailable",
        applies_to: &["identity_resolution", "auth_decision"],
        description: "parameters.witness declares a witness policy but the did-witness.json proofs file is unreachable, unparseable, or contains no entry for the versionId under evaluation. Unavailable evidence is not absent policy; the verifier MUST fail closed on high-risk paths rather than proceed as if no witnessing were required. See zh/identity/identity-did.md §3.4.1.",
    },
    ReasonCodeDescriptor {
        code: "webvh_witness_threshold_not_met",
        applies_to: &["identity_resolution", "auth_decision"],
        description: "Valid distinct witness proofs for the versionId are fewer than the effective threshold, which is the strictest intersection of the method-native parameters.witness.threshold and the deployment / Realm policy minimum. A holder-declared policy can raise this bar but MUST NOT lower it. See zh/identity/identity-did.md §3.4.1 and §3.4.2.",
    },
    ReasonCodeDescriptor {
        code: "welcome_capability_mismatch",
        applies_to: &["event_envelope", "crypto"],
        description: "`ak.mls.welcome.payload.claim_ref.capabilities_digest` does not match the claimed KeyPackage capabilities, or the Welcome requires capabilities outside the claimed subset. Receivers MUST reject before decrypting the Welcome. See zh/crypto-media/encryption-and-audit.md §2.6.",
    },
    ReasonCodeDescriptor {
        code: "witness_disagreement",
        applies_to: &["state_resolution", "federation_transaction"],
        description: "Confirmed fork/witness evidence: the same event_id resolves to different event_digest values; a validated per-actor sibling set exceeds the registered single-bucket or per-position limit; a profile declares the observed sibling combination non-joinable; or witnesses required to sign the same complete (realm_id, from_frontier, to_frontier, actor_seq_ranges, root, count) attestation payload return inconsistent values. Different event_id/hash values at the same (realm_id, actor_id, actor_seq) are not by themselves disagreement: event-and-patch.md §2.6 permits a bounded legal sibling set, which peers MUST reconcile by validated set union. Raw frontier_root / heads / range-root differences across different replication, disclosure, or attestation scopes also are not disagreement. The verifier MUST quarantine only the affected evidence scope and fail closed; recovery requires raw replay, an aligned same-scope quorum, or operator-approved fork resolution. See zh/sync/operations-sync.md §6.4.2 / §6.4.4 step 7 and zh/sync/federation.md §4.5.1.",
    },
];
