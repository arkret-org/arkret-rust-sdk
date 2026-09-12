//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/agent-runtime-scope-registry.json; version=2026-08-31.2;
//! sha256=4423e87f24e4c8b5967a2851163f446a33858f45fcdce9eaf52f41126c68d23c Input: registry/
//! contract-registry.json; version=2026-09-12.18;
//! sha256=f39f56e1e3f787ec5766a744ca745efa40bcb0c61c0329c09174c512de85feee Input: registry/
//! operation-registry.json; version=2026-09-12.16;
//! sha256=ee5f17d876d77c0d4c6d5f5bf9489fc9d769e882216bdf5ef4ca524ec1904895 Input: registry/
//! event-kind-registry.json; version=2026-09-12.13;
//! sha256=4e4e8c58ce5f20e4b0e424b8825af201b11382818acd53762eb4cf684712606b Input: registry/
//! schema-registry.json; version=2026-09-12.12;
//! sha256=59cdd1ff7620d3d800f9052caa1c18728d160be728607f716ac1433944f9d994 Input: registry/
//! id-kind-registry.json; version=2026-09-08.4;
//! sha256=c5670a4aac6d12bb30ab214dcac0da63d291c804157286e52d6d743952bd6886
//! Input: deployment-probes.json; version=2026-06-19;
//! sha256=3aaf7d76d6618e2ea0dcc211195cfc9ffe21b6233faeafd5c7df4aac0ac3054d
//! Entries: capability_sets=2, layers=3, feature_additions=2, bootstrap_profiles=2,
//! operation_surface_groups=33

use arkret_wire::{ServiceOperationId, event_kind_str};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AgentRuntimeCapability {
    E2ee,
    InteractiveChat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRuntimeCapabilitySelectionRule {
    AnyActivationOperationPresentInImmutableProvisionActions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentRuntimeCapabilityDescriptor {
    pub capability: AgentRuntimeCapability,
    pub selection_rule: AgentRuntimeCapabilitySelectionRule,
    pub activation_operations: &'static [ServiceOperationId],
    pub mandatory_operations: &'static [ServiceOperationId],
}

pub const AGENT_RUNTIME_CAPABILITIES: &[AgentRuntimeCapabilityDescriptor] = &[
    AgentRuntimeCapabilityDescriptor { capability: AgentRuntimeCapability::E2ee, selection_rule: AgentRuntimeCapabilitySelectionRule::AnyActivationOperationPresentInImmutableProvisionActions, activation_operations: &[ServiceOperationId::SelfKeysKeypackagesUploadCreateV1, ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1, ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1], mandatory_operations: &[ServiceOperationId::SelfKeysKeypackagesUploadCreateV1] },
    AgentRuntimeCapabilityDescriptor { capability: AgentRuntimeCapability::InteractiveChat, selection_rule: AgentRuntimeCapabilitySelectionRule::AnyActivationOperationPresentInImmutableProvisionActions, activation_operations: &[ServiceOperationId::SelfEventsStreamSubscribeV1, ServiceOperationId::SelfEventsReadScanV1, ServiceOperationId::SelfEventsReadFrontierV1, ServiceOperationId::SelfSealsReadFrontierV1, ServiceOperationId::SelfEventsCommandSubmitV1], mandatory_operations: &[ServiceOperationId::SelfEventsStreamSubscribeV1, ServiceOperationId::SelfEventsReadScanV1, ServiceOperationId::SelfEventsReadFrontierV1, ServiceOperationId::SelfSealsReadFrontierV1, ServiceOperationId::SelfEventsCommandSubmitV1] },
];

pub const fn agent_runtime_capability_descriptor(
    capability: AgentRuntimeCapability,
) -> &'static AgentRuntimeCapabilityDescriptor {
    match capability {
        AgentRuntimeCapability::E2ee => &AGENT_RUNTIME_CAPABILITIES[0],
        AgentRuntimeCapability::InteractiveChat => &AGENT_RUNTIME_CAPABILITIES[1],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AgentRuntimeScopeLayer {
    Provision,
    KeyAuthorization,
    Session,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentRuntimeScopeLayerDescriptor {
    pub layer: AgentRuntimeScopeLayer,
    pub missing_reason: &'static str,
    pub recovery: &'static str,
}

pub const AGENT_RUNTIME_SCOPE_LAYERS: &[AgentRuntimeScopeLayerDescriptor] = &[
    AgentRuntimeScopeLayerDescriptor {
        layer: AgentRuntimeScopeLayer::Provision,
        missing_reason: "agent_provision_scope_migration_required",
        recovery: "provision_new_agent",
    },
    AgentRuntimeScopeLayerDescriptor {
        layer: AgentRuntimeScopeLayer::KeyAuthorization,
        missing_reason: "agent_key_scope_reauthorization_required",
        recovery: "reauthorize_key_within_provision_ceiling",
    },
    AgentRuntimeScopeLayerDescriptor {
        layer: AgentRuntimeScopeLayer::Session,
        missing_reason: "agent_session_scope_refresh_required",
        recovery: "issue_session_within_provision_and_key_ceilings",
    },
];

pub const fn agent_runtime_scope_layer_descriptor(
    layer: AgentRuntimeScopeLayer,
) -> &'static AgentRuntimeScopeLayerDescriptor {
    match layer {
        AgentRuntimeScopeLayer::Provision => &AGENT_RUNTIME_SCOPE_LAYERS[0],
        AgentRuntimeScopeLayer::KeyAuthorization => &AGENT_RUNTIME_SCOPE_LAYERS[1],
        AgentRuntimeScopeLayer::Session => &AGENT_RUNTIME_SCOPE_LAYERS[2],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AgentRuntimeFeature {
    DelayedOrOfflinePublish,
    OnlinePresence,
}

pub const AGENT_RUNTIME_FEATURE_OPERATIONS: &[&[ServiceOperationId]] = &[
    &[ServiceOperationId::SelfAuthorizationLeasesCommandIssueV1],
    &[ServiceOperationId::SelfSignalCommandSendV1],
];

pub const fn agent_runtime_feature_operations(
    feature: AgentRuntimeFeature,
) -> &'static [ServiceOperationId] {
    match feature {
        AgentRuntimeFeature::DelayedOrOfflinePublish => AGENT_RUNTIME_FEATURE_OPERATIONS[0],
        AgentRuntimeFeature::OnlinePresence => AGENT_RUNTIME_FEATURE_OPERATIONS[1],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapProfile {
    OrdinaryCollaboration,
    DirectConversation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapPresence {
    Required,
    Optional,
    Conditional,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapIdSource {
    EventDerived,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapCondition {
    DeclaredPlaintextServiceVisibility,
    MainStrandAndScopeCircleIdIsNull,
    SubjectIsGenesisActorAndMembershipIsJoin,
    SubjectIsPeerParticipantAndMembershipIsJoin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapHeadEq {
    Null,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealmBootstrapSlotDescriptor {
    pub event_kind: &'static str,
    pub presence: RealmBootstrapPresence,
    pub id_source: Option<RealmBootstrapIdSource>,
    pub condition: Option<RealmBootstrapCondition>,
    pub head_eq: Option<RealmBootstrapHeadEq>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealmBootstrapProfileDescriptor {
    pub profile: RealmBootstrapProfile,
    pub atomic: bool,
    pub all_or_nothing: bool,
    pub genesis_confirms_complete_unit: bool,
    pub ordered_slots: &'static [RealmBootstrapSlotDescriptor],
}

const ORDINARY_COLLABORATION_BOOTSTRAP_SLOTS: &[RealmBootstrapSlotDescriptor] = &[
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::REALM_CREATE,
        presence: RealmBootstrapPresence::Required,
        id_source: Some(RealmBootstrapIdSource::EventDerived),
        condition: None,
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::REALM_PROFILE,
        presence: RealmBootstrapPresence::Required,
        id_source: None,
        condition: None,
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::REALM_POLICY_BUNDLE,
        presence: RealmBootstrapPresence::Required,
        id_source: None,
        condition: None,
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::REALM_JOIN_RULE,
        presence: RealmBootstrapPresence::Required,
        id_source: None,
        condition: None,
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::REALM_HISTORY_ACCESS,
        presence: RealmBootstrapPresence::Required,
        id_source: None,
        condition: None,
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::REALM_DISCOVERY,
        presence: RealmBootstrapPresence::Required,
        id_source: None,
        condition: None,
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::REALM_ALIAS,
        presence: RealmBootstrapPresence::Optional,
        id_source: None,
        condition: None,
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::REALM_PLAINTEXT_VISIBLE_SERVICES,
        presence: RealmBootstrapPresence::Conditional,
        id_source: None,
        condition: Some(RealmBootstrapCondition::DeclaredPlaintextServiceVisibility),
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::MEMBER_STATE,
        presence: RealmBootstrapPresence::Required,
        id_source: None,
        condition: Some(RealmBootstrapCondition::SubjectIsGenesisActorAndMembershipIsJoin),
        head_eq: Some(RealmBootstrapHeadEq::Null),
    },
];

const DIRECT_CONVERSATION_BOOTSTRAP_SLOTS: &[RealmBootstrapSlotDescriptor] = &[
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::REALM_CREATE,
        presence: RealmBootstrapPresence::Required,
        id_source: Some(RealmBootstrapIdSource::EventDerived),
        condition: None,
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::MEMBER_STATE,
        presence: RealmBootstrapPresence::Required,
        id_source: None,
        condition: Some(RealmBootstrapCondition::SubjectIsPeerParticipantAndMembershipIsJoin),
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::STRAND_CREATE,
        presence: RealmBootstrapPresence::Required,
        id_source: Some(RealmBootstrapIdSource::EventDerived),
        condition: Some(RealmBootstrapCondition::MainStrandAndScopeCircleIdIsNull),
        head_eq: None,
    },
    RealmBootstrapSlotDescriptor {
        event_kind: event_kind_str::MEMBER_STATE,
        presence: RealmBootstrapPresence::Required,
        id_source: None,
        condition: Some(RealmBootstrapCondition::SubjectIsGenesisActorAndMembershipIsJoin),
        head_eq: Some(RealmBootstrapHeadEq::Null),
    },
];

pub const REALM_BOOTSTRAP_PROFILES: &[RealmBootstrapProfileDescriptor] = &[
    RealmBootstrapProfileDescriptor {
        profile: RealmBootstrapProfile::OrdinaryCollaboration,
        atomic: true,
        all_or_nothing: true,
        genesis_confirms_complete_unit: true,
        ordered_slots: ORDINARY_COLLABORATION_BOOTSTRAP_SLOTS,
    },
    RealmBootstrapProfileDescriptor {
        profile: RealmBootstrapProfile::DirectConversation,
        atomic: true,
        all_or_nothing: true,
        genesis_confirms_complete_unit: true,
        ordered_slots: DIRECT_CONVERSATION_BOOTSTRAP_SLOTS,
    },
];

pub const fn realm_bootstrap_profile_descriptor(
    profile: RealmBootstrapProfile,
) -> &'static RealmBootstrapProfileDescriptor {
    match profile {
        RealmBootstrapProfile::OrdinaryCollaboration => &REALM_BOOTSTRAP_PROFILES[0],
        RealmBootstrapProfile::DirectConversation => &REALM_BOOTSTRAP_PROFILES[1],
    }
}

pub fn realm_bootstrap_slot_for_condition(
    profile: RealmBootstrapProfile,
    condition: RealmBootstrapCondition,
) -> Option<&'static RealmBootstrapSlotDescriptor> {
    realm_bootstrap_profile_descriptor(profile)
        .ordered_slots
        .iter()
        .find(|slot| slot.condition == Some(condition))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealmBootstrapFirstContactDescriptor {
    pub require_create_derived_realm_id: bool,
    pub require_complete_genesis_state_commitment: bool,
    pub fail_closed_until_complete: bool,
}

pub const REALM_BOOTSTRAP_FIRST_CONTACT: RealmBootstrapFirstContactDescriptor =
    RealmBootstrapFirstContactDescriptor {
        require_create_derived_realm_id: true,
        require_complete_genesis_state_commitment: true,
        fail_closed_until_complete: true,
    };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationSurfaceGroupDescriptor {
    pub surface: &'static str,
    pub surface_class: &'static str,
    pub profile: Option<&'static str>,
    pub operations: &'static [ServiceOperationId],
}

pub const REGISTERED_OPERATION_SURFACE_GROUPS: &[OperationSurfaceGroupDescriptor] = &[
    OperationSurfaceGroupDescriptor {
        surface: "service_discovery",
        surface_class: "core",
        profile: None,
        operations: &[ServiceOperationId::ServerReadDescribeV1],
    },
    OperationSurfaceGroupDescriptor {
        surface: "identity_registry",
        surface_class: "core",
        profile: None,
        operations: &[
            ServiceOperationId::RootIdentityRegistryReadDescribeV1,
            ServiceOperationId::RootIdentityReadResolveV1,
            ServiceOperationId::RootIdentityDocumentResourceGetV1,
            ServiceOperationId::RootIdentityLogReadListV1,
            ServiceOperationId::RootIdentityReceiptsReadListV1,
            ServiceOperationId::RootIdentityCommandSubmitDidOperationV1,
            ServiceOperationId::RootIdentityServiceRegistrationCommandEnsureV1,
            ServiceOperationId::RootIdentityServiceRegistrationResourceGetV1,
            ServiceOperationId::RootIdentityOrganizationRegistrationCommandPrepareV1,
            ServiceOperationId::RootIdentityOrganizationRegistrationCommandEnsureV1,
            ServiceOperationId::RootIdentityOrganizationRegistrationResourceGetV1,
            ServiceOperationId::RootIdentityOrganizationRegistrationCommandRefreshV1,
            ServiceOperationId::RootIdentityOrganizationRegistrationCommandRevokeV1,
            ServiceOperationId::RootIdentityRecoveryPolicyResourceGetV1,
            ServiceOperationId::RootIdentityRecoveryPolicyCommandPublishV1,
            ServiceOperationId::RootIdentityRecoverySessionCommandCreateV1,
            ServiceOperationId::RootIdentityRecoverySessionResourceGetV1,
            ServiceOperationId::RootIdentityRecoverySessionCommandSubmitProofV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "security_transactions",
        surface_class: "core",
        profile: None,
        operations: &[
            ServiceOperationId::SelfSecurityTransactionCommandCreateV1,
            ServiceOperationId::SelfSecurityTransactionResourceGetV1,
            ServiceOperationId::SelfSecurityTransactionCommandContinueV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "events_sync",
        surface_class: "core",
        profile: None,
        operations: &[
            ServiceOperationId::SelfControlProposalAcksCommandIssueV1,
            ServiceOperationId::SelfControlProposalDecisionsCommandSubmitV1,
            ServiceOperationId::SelfControlProposalDecisionsReadGetV1,
            ServiceOperationId::SelfAuthorizationLeasesCommandIssueV1,
            ServiceOperationId::SelfEventsReadDescribeV1,
            ServiceOperationId::SelfEventsReadDeliveryStatusV1,
            ServiceOperationId::SelfEventsCommandSubmitV1,
            ServiceOperationId::SelfSealsCommandPrepareV1,
            ServiceOperationId::SelfSealsCommandSubmitV1,
            ServiceOperationId::SelfEventsResourceGetV1,
            ServiceOperationId::SelfEventsReadResolveV1,
            ServiceOperationId::SelfEventsReadScanV1,
            ServiceOperationId::SelfEventsStreamSubscribeV1,
            ServiceOperationId::SelfEventsReadFrontierV1,
            ServiceOperationId::SelfSealsReadFrontierV1,
            ServiceOperationId::SelfSealsReadResolveV1,
            ServiceOperationId::SelfSealsReadMlsGovernanceProofV1,
            ServiceOperationId::SelfSealsReadMlsAcceptedArtifactV1,
            ServiceOperationId::SelfSealsReadMlsWelcomeRefsV1,
            ServiceOperationId::SelfSealsReadMembershipAuthorityV1,
            ServiceOperationId::SelfSealsReadMlsMembershipRemovalV1,
            ServiceOperationId::SelfSealsReadHistoryAuthorityV1,
            ServiceOperationId::SelfSealsReadGovernanceDependenciesV1,
            ServiceOperationId::SelfAccountReadDescribeV1,
            ServiceOperationId::SelfAccountReadViewerV1,
            ServiceOperationId::SelfAccountCommandUpdateProfileV1,
            ServiceOperationId::SelfActorProfileReadResolveV1,
            ServiceOperationId::SelfAccountStreamSubscribeV1,
            ServiceOperationId::SelfAccountCommandRevokeCursorV1,
            ServiceOperationId::SelfRealmStateSnapshotReadManifestHeadV1,
            ServiceOperationId::SelfSealsReadPendingControlV1,
            ServiceOperationId::SelfCurrentPrincipalReadResolveV1,
            ServiceOperationId::SelfGenesisNotaryReadResolveV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "history_key_recovery",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfHistoryKeyRequestsCommandCreateV1,
            ServiceOperationId::SelfHistoryKeyRequestsReadListV1,
            ServiceOperationId::SelfHistoryKeyResponsesCommandSendV1,
            ServiceOperationId::SelfHistoryKeyResponsesReadListV1,
            ServiceOperationId::SelfHistoryKeyResponsesCommandAckV1,
            ServiceOperationId::SelfOrganizationRecoveryArchivesReadListV1,
            ServiceOperationId::PeerHistoryKeyRequestsCommandReplicateV1,
            ServiceOperationId::PeerHistoryKeyResponsesCommandRelayV1,
            ServiceOperationId::PeerSealsReadMlsGovernanceProofV1,
            ServiceOperationId::PeerSealsReadGovernanceDependenciesV1,
            ServiceOperationId::PeerOrganizationRecoveryArchivesCommandReplicateV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "peer_federation",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::PeerDeviceRevocationsCommandCheckV1,
            ServiceOperationId::PeerEventsCommandSubmitV1,
            ServiceOperationId::PeerAccountStatusReadResolveV1,
            ServiceOperationId::PeerAccountStatusCommandSubmitV1,
            ServiceOperationId::PeerErasureReceiptCommandSubmitV1,
            ServiceOperationId::PeerErasureReceiptResourceGetV1,
            ServiceOperationId::PeerMlsReadGroupStateMaterialV1,
            ServiceOperationId::PeerEventsReadResolveV1,
            ServiceOperationId::PeerEventsReadScanV1,
            ServiceOperationId::PeerEventsReadSiblingPositionsV1,
            ServiceOperationId::PeerEventsReadFrontierV1,
            ServiceOperationId::PeerSealsReadFrontierV1,
            ServiceOperationId::PeerSealsReadResolveV1,
            ServiceOperationId::PeerInvitesCommandSubmitV1,
            ServiceOperationId::PeerContactsCommandSubmitV1,
            ServiceOperationId::PeerCurrentSignerEvidenceReadResolveV1,
            ServiceOperationId::PeerKeysKeypackagesCommandClaimV1,
            ServiceOperationId::PeerKeysKeypackagesReadClaimV1,
            ServiceOperationId::PeerKeysReadLookupV1,
            ServiceOperationId::PeerSignalCommandRelayV1,
            ServiceOperationId::PeerPrincipalGenesisCommandSubmitV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "realm_join_intake",
        surface_class: "core",
        profile: None,
        operations: &[
            ServiceOperationId::PeerRealmJoinReadApplicationStatusV1,
            ServiceOperationId::PeerRealmJoinReadBootstrapV1,
            ServiceOperationId::PeerRealmJoinReadPreviewV1,
            ServiceOperationId::SelfMessagesCommandPrepareV1,
            ServiceOperationId::SelfRealmJoinCommandPrepareV1,
            ServiceOperationId::SelfRealmJoinReadApplicationStatusV1,
            ServiceOperationId::SelfRealmJoinReadPreviewV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "directory_discovery",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::FindDirectoryReadDescribeV1,
            ServiceOperationId::FindDirectoryReadSearchRealmsV1,
            ServiceOperationId::FindDirectoryReadResolveRealmV1,
            ServiceOperationId::FindDirectoryReadResolveTargetV1,
            ServiceOperationId::FindDirectoryReadSearchOrganizationsV1,
            ServiceOperationId::FindDirectoryReadResolveOrganizationV1,
            ServiceOperationId::FindDirectoryReadSearchActorsV1,
            ServiceOperationId::FindDirectoryReadSearchUsersV1,
            ServiceOperationId::FindDirectoryReadResolveHandleV1,
            ServiceOperationId::FindDirectoryReadResolveAgentSelectorV1,
            ServiceOperationId::FindDirectoryReadListHandlesForSubjectV1,
            ServiceOperationId::FindDirectoryReadPrivateContactDiscoveryV1,
            ServiceOperationId::FindDirectoryCommandAnnounceV1,
            ServiceOperationId::FindDirectoryCommandWithdrawV1,
            ServiceOperationId::FindDirectoryPushCommandRegisterV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "contact_lifecycle",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfContactCommandRequestV1,
            ServiceOperationId::SelfContactCommandCheckpointV1,
            ServiceOperationId::SelfContactCommandRespondV1,
            ServiceOperationId::SelfContactCommandRejectV1,
            ServiceOperationId::SelfContactCommandScopeUpdateV1,
            ServiceOperationId::SelfContactReadListV1,
            ServiceOperationId::SelfContactCommandTombstoneV1,
            ServiceOperationId::SelfInvitesCommandDispatchV1,
            ServiceOperationId::SelfInviteReceivePolicyResourceGetV1,
            ServiceOperationId::SelfInviteReceivePolicyResourceReplaceV1,
            ServiceOperationId::SelfInviteLocatorCommandIssueV1,
            ServiceOperationId::SelfInviteLocatorCommandRotateV1,
            ServiceOperationId::SelfInviteLocatorCommandRevokeV1,
            ServiceOperationId::SelfDirectConversationReadResolveV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "circle_management",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfCircleCommandCreateV1,
            ServiceOperationId::SelfCircleReadListV1,
            ServiceOperationId::SelfCircleResourceGetV1,
            ServiceOperationId::SelfCircleMemberCommandAddV1,
            ServiceOperationId::SelfCircleMemberResourceDeleteV1,
            ServiceOperationId::SelfCircleCommandRotateScopeV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "realm_governance_links",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfRealmLinkReadListV1,
            ServiceOperationId::SelfRealmLinkReadEffectivePolicyV1,
            ServiceOperationId::SelfRealmOrganizationReadListV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "realm_read",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfRealmResourceGetV1,
            ServiceOperationId::SelfRealmReadExportV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "consent_management",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfConsentReadListV1,
            ServiceOperationId::SelfConsentResourceGetV1,
            ServiceOperationId::SelfConsentCommandGrantV1,
            ServiceOperationId::SelfConsentCommandRevokeV1,
            ServiceOperationId::SelfConsentCommandRequestV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "account_data",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfAccountDataReadListV1,
            ServiceOperationId::SelfAccountDataResourceGetV1,
            ServiceOperationId::SelfAccountDataResourceReplaceV1,
            ServiceOperationId::SelfAccountDataResourceDeleteV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "read_cursor",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfReadCursorCommandAdvanceV1,
            ServiceOperationId::SelfReadCursorReadListV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "blob_storage",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfBlobUploadCreateV1,
            ServiceOperationId::SelfBlobResourceHeadV1,
            ServiceOperationId::SelfBlobResourceGetV1,
            ServiceOperationId::SelfBlobCommandPresignV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "realtime_media",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfMediaReadIceConfigV1,
            ServiceOperationId::SelfSignalCommandSendV1,
            ServiceOperationId::SelfSignalStreamSubscribeV1,
            ServiceOperationId::SelfCallMediaExchangeIssueTokenV1,
            ServiceOperationId::SelfMediaServiceBindingReadResolveV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "authz_policy",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfAuthzReadCheckV1,
            ServiceOperationId::SelfAuthzGrantsReadEffectiveV1,
            ServiceOperationId::SelfAuthzInvitesReadListV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "moderation_reports",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfModerationCommandReportV1,
            ServiceOperationId::SelfModerationReadFrankingSealObservationV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "device_and_keys",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfDeviceMessagesCommandSendV1,
            ServiceOperationId::SelfDeviceMessagesReadListV1,
            ServiceOperationId::SelfDeviceMessagesCommandAckV1,
            ServiceOperationId::SelfKeysUploadCreateV1,
            ServiceOperationId::SelfKeysReadLookupV1,
            ServiceOperationId::SelfSignerKeysReadResolveV1,
            ServiceOperationId::SelfKeysCommandClaimV1,
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
            ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1,
            ServiceOperationId::SelfKeysBackupsResourceReplaceV1,
            ServiceOperationId::SelfKeysBackupsReadListV1,
            ServiceOperationId::SelfKeysBackupsCommandUnlockV1,
            ServiceOperationId::SelfKeysBackupsCommandIssueDeleteChallengeV1,
            ServiceOperationId::SelfKeysBackupsCommandIssueUnlockChallengeV1,
            ServiceOperationId::SelfKeysBackupsResourceDeleteV1,
            ServiceOperationId::SelfKeysBackupSeriesCommandEraseV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "push",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::EdgePushCommandRegisterDeviceV1,
            ServiceOperationId::EdgePushCommandUnregisterDeviceV1,
            ServiceOperationId::EdgePushCommandNotifyV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "realm_object_read",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfSpaceReadListV1,
            ServiceOperationId::SelfStrandReadListV1,
            ServiceOperationId::SelfMorphReadListV1,
            ServiceOperationId::SelfMorphResourceGetV1,
            ServiceOperationId::SelfRelationConflictsReadCandidatesV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "applet",
        surface_class: "interop_bridge",
        profile: None,
        operations: &[
            ServiceOperationId::EdgeAppletReadPingV1,
            ServiceOperationId::EdgeAppletReadDescribeV1,
            ServiceOperationId::EdgeAppletCommandTransactionV1,
            ServiceOperationId::EdgeAppletActorReadResolveV1,
            ServiceOperationId::EdgeAppletRealmReadResolveV1,
            ServiceOperationId::EdgeAppletReadProtocolMetadataV1,
            ServiceOperationId::EdgeAppletManagedActorCommandAuthorV1,
            ServiceOperationId::EdgeAppletThirdPartyUsersReadListV1,
            ServiceOperationId::EdgeAppletThirdPartyLocationsReadListV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "applet_install",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::SelfAppletInstallCommandPreviewV1,
            ServiceOperationId::SelfAppletCommandInstallV1,
            ServiceOperationId::SelfAppletRevokeCommandPreviewV1,
            ServiceOperationId::SelfAppletCommandRevokeV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "applet_ghost",
        surface_class: "interop_bridge",
        profile: None,
        operations: &[
            ServiceOperationId::SelfAppletGhostCommandPreviewV1,
            ServiceOperationId::SelfAppletGhostCommandProvisionV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "mimi_interop",
        surface_class: "interop_bridge",
        profile: None,
        operations: &[
            ServiceOperationId::OpenMimiReadProviderDirectoryV1,
            ServiceOperationId::OpenMimiExchangeRequestKeyMaterialV1,
            ServiceOperationId::OpenMimiCommandSubmitMessageV1,
            ServiceOperationId::OpenMimiCommandUpdateRoomV1,
            ServiceOperationId::OpenMimiCommandRequestConsentV1,
            ServiceOperationId::OpenMimiCommandUpdateConsentV1,
            ServiceOperationId::OpenMimiReadIdentifiersV1,
            ServiceOperationId::OpenMimiCommandNotifyV1,
            ServiceOperationId::OpenMimiCommandReportAbuseV1,
            ServiceOperationId::OpenMimiCommandProxyDownloadV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "agent_pairing_handoff",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::OpenAgentPairingReadResolveV1,
            ServiceOperationId::OpenAgentPairingCommandSubmitRuntimeKeyRequestV1,
            ServiceOperationId::OpenAgentPairingReadRuntimeKeyRequestStatusV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "device_pairing_handoff",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::OpenDevicePairingCommandStageV1,
            ServiceOperationId::OpenDevicePairingReadResolveV1,
            ServiceOperationId::OpenDevicePairingReadStatusV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "invite_locator_handoff",
        surface_class: "extension",
        profile: None,
        operations: &[ServiceOperationId::OpenInviteLocatorReadResolveV1],
    },
    OperationSurfaceGroupDescriptor {
        surface: "third_party_invite_handoff",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::OpenThirdPartyInviteCommandActivateV1,
            ServiceOperationId::OpenThirdPartyInviteCommandPresentTokenV1,
            ServiceOperationId::OpenThirdPartyInviteCommandProvisionV1,
            ServiceOperationId::OpenThirdPartyInviteReadProvisioningStatusV1,
            ServiceOperationId::SelfThirdPartyInviteReadAcceptanceAttestationV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "identity_resolution",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::OpenIdentityReadResolutionV1,
            ServiceOperationId::SelfIdentityReadResolutionAuditV1,
            ServiceOperationId::OpenServiceReadResolutionV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "account_auth",
        surface_class: "deployment_local",
        profile: None,
        operations: &[
            ServiceOperationId::GateAccountExchangeCreateHandoffV1,
            ServiceOperationId::GateAccountReadOnboardingV1,
            ServiceOperationId::GateAccountCommandIssueControllerGateAttestationV1,
            ServiceOperationId::GateAccountCommandIssueIdentityBindingChallengeV1,
            ServiceOperationId::GateAccountCommandIssueDidBindingChallengeV1,
            ServiceOperationId::GateAccountCommandIssueIdentityAbandonmentChallengeV1,
            ServiceOperationId::GateAccountCommandAbandonIdentityCreationV1,
            ServiceOperationId::GateAccountCommandRegisterV1,
            ServiceOperationId::GateAccountCommandPairDeviceV1,
            ServiceOperationId::GateAccountCommandIssueSessionGrantV1,
            ServiceOperationId::GateAccountCommandRefreshSessionGrantV1,
            ServiceOperationId::GateAccountCommandIssueRecoveryCompletionGrantV1,
            ServiceOperationId::GateAccountCommandLogoutAuthSessionV1,
            ServiceOperationId::GateAccountCommandIntrospectSessionGrantV1,
            ServiceOperationId::GateAccountCommandLogoutV1,
            ServiceOperationId::GateAccountCommandRequestErasureV1,
            ServiceOperationId::GateAccountCommandRevokeSessionV1,
        ],
    },
    OperationSurfaceGroupDescriptor {
        surface: "agent_runtime",
        surface_class: "extension",
        profile: None,
        operations: &[
            ServiceOperationId::GateAccountCommandPairAgentKeyV1,
            ServiceOperationId::SelfAgentCommandProvisionV1,
            ServiceOperationId::SelfAgentCommandRenewPairingV1,
            ServiceOperationId::SelfAgentReadListV1,
            ServiceOperationId::SelfAgentResourceGetV1,
            ServiceOperationId::SelfAgentCommandPauseV1,
            ServiceOperationId::SelfAgentCommandResumeV1,
            ServiceOperationId::SelfAgentCommandDeactivateV1,
            ServiceOperationId::SelfAgentSidecarCommandEnsureV1,
            ServiceOperationId::SelfAgentSidecarResourceGetV1,
            ServiceOperationId::SelfAgentSidecarReadListV1,
            ServiceOperationId::SelfAgentParticipationResourceReplaceV1,
            ServiceOperationId::SelfAgentParticipationResourceGetV1,
        ],
    },
];

pub const HIGH_SECURITY_SESSION_OPERATION_PREFIX: &str = "ak.self.";
pub const UNAUTHENTICATED_PUBLIC_PROJECTION_OPERATIONS: &[ServiceOperationId] = &[
    ServiceOperationId::SelfEventsReadDescribeV1,
    ServiceOperationId::SelfAccountReadDescribeV1,
];

pub const EVENT_KIND_REGISTRY_VERSION: &str = "2026-09-12.13";
pub const SCHEMA_REGISTRY_VERSION: &str = "2026-09-12.12";
pub const OPERATION_REGISTRY_VERSION: &str = "2026-09-12.16";
pub const ID_KIND_REGISTRY_VERSION: &str = "2026-09-08.4";
pub const PQ_HYBRID_TLS_REQUIRED_GROUP: &str = "X25519MLKEM768";
