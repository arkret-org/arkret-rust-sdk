//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: profiles/conformance-profiles.json; version=2026-08-02.4;
//! sha256=17d11e0ea544547180a1cf750a0d11d7384c5b96048f48da3138cb920219c6ae Entries: profile_ids=98

use serde::{Deserialize, Serialize};

/// Declared conformance profile identifiers. Every `ak.profile.*` literal
/// the SDK ships is spelled exactly once, here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ProfileId {
    AgentAuthV1,
    AgentDelegationPolicyV1,
    AgentParticipationPolicyV1,
    AgentRuntimeV1,
    AgentSidecarV1,
    AgentSignerEvidenceV1,
    AppletBridgeV1,
    AppletDelegatedV1,
    AppletE2eeJoinV1,
    AppletServiceV1,
    AppletWidgetV1,
    AttestedAuditE2eeV1,
    AuthServerV1,
    BindingWebsocketV1,
    BlobNodeV1,
    CalendarEventV1,
    CalendarNotificationDispatchV1,
    CandidateJoinPolicyV1,
    ChatMvpV1,
    CircleConformanceV1,
    CircleSealCadenceFixed5mV1,
    ConstraintApprovalWorkflowV1,
    ConstraintClaimBasedV1,
    ConstraintEncryptionRequirementV1,
    ConstraintResourceLimitV1,
    ConstraintVisibilityControlV1,
    CoreEventStoreV1,
    CrdtTextV1,
    CrossSigningResetV1,
    DirectConversationRealmV1,
    DirectoryServiceV1,
    DisappearingV1,
    DisclosedAuditE2eeV1,
    DraftSyncV1,
    E2eeClientV1,
    E2eeRelaxedV1,
    EncodingCborV1,
    EncodingMultihashV1,
    EnterpriseClientV1,
    FederationHighAssuranceV1,
    FederationRbsrNegentropyV1,
    FederationMinimalV1,
    FileTransferV1,
    FrankingV1,
    FullClientV1,
    HashBlake3V1,
    HashTransitionV1,
    HighSecurityOrganizationV1,
    HpkeP256V1,
    IdentityRegistryV1,
    IsolatedSovereignNetworkV1,
    KanbanMvpV1,
    KemHybridXwingV1,
    KeyBackupMemoryHardV1,
    KeyTransparencyV1,
    MatrixCompatV1,
    MediaServiceBindingArkretNativeV1,
    MediaServiceBindingLivekitV1,
    MediaServiceBindingV1,
    MimiInteropV1,
    MinimalClientV1,
    MlsMinimalMetadataRealmV1,
    MlsCiphersuiteChacha20poly1305V1,
    MlsCiphersuitePqAuthV1,
    MlsGovernanceBindingFullV1,
    MorphSchemaMigrationTransformationsV1,
    NotaryMixedRecoveryV1,
    NotaryOpenSetV1,
    NotarySingleDidV1,
    NotaryThresholdV1,
    OrgHighAssuranceIdentityV1,
    OrganizationV1,
    PersonalAgentProvisioningV1,
    PersonalNodeV1,
    PersonalProductivityV1,
    PinnedItemsV1,
    PrincipalControlRealmV1,
    PrincipalServerV1,
    PrincipalServerEventsApiV1,
    PublicNetworkIdentityV1,
    PushGatewayBlindWakeupV1,
    PushGatewayMatrixPassthroughV1,
    PushGatewayV1,
    PushGatewayVisibleNotificationV1,
    SearchBlindIndexV1,
    SearchClientIndexV1,
    SearchForwardPrivateV1,
    SignalMessageStreamV1,
    SignalPeerRelayV1,
    SignatureEcdsaP256V1,
    SignaturePqcV1,
    SmallTeamV1,
    SovereignClientV1,
    SovereignDeploymentV1,
    SovereignEnclaveV1,
    TrafficMetadataHardenedV1,
    UcanInteropV1,
    WebrtcMediaV1,
}

impl ProfileId {
    pub const ALL: &'static [Self] = &[
        Self::AgentAuthV1,
        Self::AgentDelegationPolicyV1,
        Self::AgentParticipationPolicyV1,
        Self::AgentRuntimeV1,
        Self::AgentSidecarV1,
        Self::AgentSignerEvidenceV1,
        Self::AppletBridgeV1,
        Self::AppletDelegatedV1,
        Self::AppletE2eeJoinV1,
        Self::AppletServiceV1,
        Self::AppletWidgetV1,
        Self::AttestedAuditE2eeV1,
        Self::AuthServerV1,
        Self::BindingWebsocketV1,
        Self::BlobNodeV1,
        Self::CalendarEventV1,
        Self::CalendarNotificationDispatchV1,
        Self::CandidateJoinPolicyV1,
        Self::ChatMvpV1,
        Self::CircleConformanceV1,
        Self::CircleSealCadenceFixed5mV1,
        Self::ConstraintApprovalWorkflowV1,
        Self::ConstraintClaimBasedV1,
        Self::ConstraintEncryptionRequirementV1,
        Self::ConstraintResourceLimitV1,
        Self::ConstraintVisibilityControlV1,
        Self::CoreEventStoreV1,
        Self::CrdtTextV1,
        Self::CrossSigningResetV1,
        Self::DirectConversationRealmV1,
        Self::DirectoryServiceV1,
        Self::DisappearingV1,
        Self::DisclosedAuditE2eeV1,
        Self::DraftSyncV1,
        Self::E2eeClientV1,
        Self::E2eeRelaxedV1,
        Self::EncodingCborV1,
        Self::EncodingMultihashV1,
        Self::EnterpriseClientV1,
        Self::FederationHighAssuranceV1,
        Self::FederationRbsrNegentropyV1,
        Self::FederationMinimalV1,
        Self::FileTransferV1,
        Self::FrankingV1,
        Self::FullClientV1,
        Self::HashBlake3V1,
        Self::HashTransitionV1,
        Self::HighSecurityOrganizationV1,
        Self::HpkeP256V1,
        Self::IdentityRegistryV1,
        Self::IsolatedSovereignNetworkV1,
        Self::KanbanMvpV1,
        Self::KemHybridXwingV1,
        Self::KeyBackupMemoryHardV1,
        Self::KeyTransparencyV1,
        Self::MatrixCompatV1,
        Self::MediaServiceBindingArkretNativeV1,
        Self::MediaServiceBindingLivekitV1,
        Self::MediaServiceBindingV1,
        Self::MimiInteropV1,
        Self::MinimalClientV1,
        Self::MlsMinimalMetadataRealmV1,
        Self::MlsCiphersuiteChacha20poly1305V1,
        Self::MlsCiphersuitePqAuthV1,
        Self::MlsGovernanceBindingFullV1,
        Self::MorphSchemaMigrationTransformationsV1,
        Self::NotaryMixedRecoveryV1,
        Self::NotaryOpenSetV1,
        Self::NotarySingleDidV1,
        Self::NotaryThresholdV1,
        Self::OrgHighAssuranceIdentityV1,
        Self::OrganizationV1,
        Self::PersonalAgentProvisioningV1,
        Self::PersonalNodeV1,
        Self::PersonalProductivityV1,
        Self::PinnedItemsV1,
        Self::PrincipalControlRealmV1,
        Self::PrincipalServerV1,
        Self::PrincipalServerEventsApiV1,
        Self::PublicNetworkIdentityV1,
        Self::PushGatewayBlindWakeupV1,
        Self::PushGatewayMatrixPassthroughV1,
        Self::PushGatewayV1,
        Self::PushGatewayVisibleNotificationV1,
        Self::SearchBlindIndexV1,
        Self::SearchClientIndexV1,
        Self::SearchForwardPrivateV1,
        Self::SignalMessageStreamV1,
        Self::SignalPeerRelayV1,
        Self::SignatureEcdsaP256V1,
        Self::SignaturePqcV1,
        Self::SmallTeamV1,
        Self::SovereignClientV1,
        Self::SovereignDeploymentV1,
        Self::SovereignEnclaveV1,
        Self::TrafficMetadataHardenedV1,
        Self::UcanInteropV1,
        Self::WebrtcMediaV1,
    ];

    pub const AGENT_AUTH_V1: &'static str = "ak.profile.agent_auth.v1";
    pub const AGENT_DELEGATION_POLICY_V1: &'static str = "ak.profile.agent_delegation_policy.v1";
    pub const AGENT_PARTICIPATION_POLICY_V1: &'static str =
        "ak.profile.agent_participation_policy.v1";
    pub const AGENT_RUNTIME_V1: &'static str = "ak.profile.agent_runtime.v1";
    pub const AGENT_SIDECAR_V1: &'static str = "ak.profile.agent_sidecar.v1";
    pub const AGENT_SIGNER_EVIDENCE_V1: &'static str = "ak.profile.agent_signer_evidence.v1";
    pub const APPLET_BRIDGE_V1: &'static str = "ak.profile.applet_bridge.v1";
    pub const APPLET_DELEGATED_V1: &'static str = "ak.profile.applet_delegated.v1";
    pub const APPLET_E2EE_JOIN_V1: &'static str = "ak.profile.applet_e2ee_join.v1";
    pub const APPLET_SERVICE_V1: &'static str = "ak.profile.applet_service.v1";
    pub const APPLET_WIDGET_V1: &'static str = "ak.profile.applet_widget.v1";
    pub const ATTESTED_AUDIT_E2EE_V1: &'static str = "ak.profile.attested_audit.e2ee.v1";
    pub const AUTH_SERVER_V1: &'static str = "ak.profile.auth_server.v1";
    pub const BINDING_WEBSOCKET_V1: &'static str = "ak.profile.binding.websocket.v1";
    pub const BLOB_NODE_V1: &'static str = "ak.profile.blob_node.v1";
    pub const CALENDAR_EVENT_V1: &'static str = "ak.profile.calendar_event.v1";
    pub const CALENDAR_NOTIFICATION_DISPATCH_V1: &'static str =
        "ak.profile.calendar_notification_dispatch.v1";
    pub const CANDIDATE_JOIN_POLICY_V1: &'static str = "ak.profile.candidate.join_policy.v1";
    pub const CHAT_MVP_V1: &'static str = "ak.profile.chat_mvp.v1";
    pub const CIRCLE_CONFORMANCE_V1: &'static str = "ak.profile.circle_conformance.v1";
    pub const CIRCLE_SEAL_CADENCE_FIXED_5M_V1: &'static str =
        "ak.profile.circle_seal_cadence.fixed_5m.v1";
    pub const CONSTRAINT_APPROVAL_WORKFLOW_V1: &'static str =
        "ak.profile.constraint.approval_workflow.v1";
    pub const CONSTRAINT_CLAIM_BASED_V1: &'static str = "ak.profile.constraint.claim_based.v1";
    pub const CONSTRAINT_ENCRYPTION_REQUIREMENT_V1: &'static str =
        "ak.profile.constraint.encryption_requirement.v1";
    pub const CONSTRAINT_RESOURCE_LIMIT_V1: &'static str =
        "ak.profile.constraint.resource_limit.v1";
    pub const CONSTRAINT_VISIBILITY_CONTROL_V1: &'static str =
        "ak.profile.constraint.visibility_control.v1";
    pub const CORE_EVENT_STORE_V1: &'static str = "ak.profile.core_event_store.v1";
    pub const CRDT_TEXT_V1: &'static str = "ak.profile.crdt.text.v1";
    pub const CROSS_SIGNING_RESET_V1: &'static str = "ak.profile.cross_signing.reset.v1";
    pub const DIRECT_CONVERSATION_REALM_V1: &'static str =
        "ak.profile.direct_conversation_realm.v1";
    pub const DIRECTORY_SERVICE_V1: &'static str = "ak.profile.directory_service.v1";
    pub const DISAPPEARING_V1: &'static str = "ak.profile.disappearing.v1";
    pub const DISCLOSED_AUDIT_E2EE_V1: &'static str = "ak.profile.disclosed_audit.e2ee.v1";
    pub const DRAFT_SYNC_V1: &'static str = "ak.profile.draft_sync.v1";
    pub const E2EE_CLIENT_V1: &'static str = "ak.profile.e2ee_client.v1";
    pub const E2EE_RELAXED_V1: &'static str = "ak.profile.e2ee_relaxed.v1";
    pub const ENCODING_CBOR_V1: &'static str = "ak.profile.encoding.cbor.v1";
    pub const ENCODING_MULTIHASH_V1: &'static str = "ak.profile.encoding.multihash.v1";
    pub const ENTERPRISE_CLIENT_V1: &'static str = "ak.profile.enterprise_client.v1";
    pub const FEDERATION_HIGH_ASSURANCE_V1: &'static str =
        "ak.profile.federation.high_assurance.v1";
    pub const FEDERATION_RBSR_NEGENTROPY_V1: &'static str =
        "ak.profile.federation.rbsr.negentropy.v1";
    pub const FEDERATION_MINIMAL_V1: &'static str = "ak.profile.federation_minimal.v1";
    pub const FILE_TRANSFER_V1: &'static str = "ak.profile.file_transfer.v1";
    pub const FRANKING_V1: &'static str = "ak.profile.franking.v1";
    pub const FULL_CLIENT_V1: &'static str = "ak.profile.full_client.v1";
    pub const HASH_BLAKE3_V1: &'static str = "ak.profile.hash.blake3.v1";
    pub const HASH_TRANSITION_V1: &'static str = "ak.profile.hash_transition.v1";
    pub const HIGH_SECURITY_ORGANIZATION_V1: &'static str =
        "ak.profile.high_security_organization.v1";
    pub const HPKE_P256_V1: &'static str = "ak.profile.hpke.p256.v1";
    pub const IDENTITY_REGISTRY_V1: &'static str = "ak.profile.identity_registry.v1";
    pub const ISOLATED_SOVEREIGN_NETWORK_V1: &'static str =
        "ak.profile.isolated_sovereign_network.v1";
    pub const KANBAN_MVP_V1: &'static str = "ak.profile.kanban_mvp.v1";
    pub const KEM_HYBRID_XWING_V1: &'static str = "ak.profile.kem.hybrid_xwing.v1";
    pub const KEY_BACKUP_MEMORY_HARD_V1: &'static str = "ak.profile.key_backup.memory_hard.v1";
    pub const KEY_TRANSPARENCY_V1: &'static str = "ak.profile.key_transparency.v1";
    pub const MATRIX_COMPAT_V1: &'static str = "ak.profile.matrix_compat.v1";
    pub const MEDIA_SERVICE_BINDING_ARKRET_NATIVE_V1: &'static str =
        "ak.profile.media_service_binding.arkret_native.v1";
    pub const MEDIA_SERVICE_BINDING_LIVEKIT_V1: &'static str =
        "ak.profile.media_service_binding.livekit.v1";
    pub const MEDIA_SERVICE_BINDING_V1: &'static str = "ak.profile.media_service_binding.v1";
    pub const MIMI_INTEROP_V1: &'static str = "ak.profile.mimi_interop.v1";
    pub const MINIMAL_CLIENT_V1: &'static str = "ak.profile.minimal_client.v1";
    pub const MLS_MINIMAL_METADATA_REALM_V1: &'static str =
        "ak.profile.mls.minimal_metadata_realm.v1";
    pub const MLS_CIPHERSUITE_CHACHA20POLY1305_V1: &'static str =
        "ak.profile.mls_ciphersuite.chacha20poly1305.v1";
    pub const MLS_CIPHERSUITE_PQ_AUTH_V1: &'static str = "ak.profile.mls_ciphersuite.pq_auth.v1";
    pub const MLS_GOVERNANCE_BINDING_FULL_V1: &'static str =
        "ak.profile.mls_governance_binding.full.v1";
    pub const MORPH_SCHEMA_MIGRATION_TRANSFORMATIONS_V1: &'static str =
        "ak.profile.morph.schema_migration_transformations.v1";
    pub const NOTARY_MIXED_RECOVERY_V1: &'static str = "ak.profile.notary.mixed_recovery.v1";
    pub const NOTARY_OPEN_SET_V1: &'static str = "ak.profile.notary.open_set.v1";
    pub const NOTARY_SINGLE_DID_V1: &'static str = "ak.profile.notary.single_did.v1";
    pub const NOTARY_THRESHOLD_V1: &'static str = "ak.profile.notary.threshold.v1";
    pub const ORG_HIGH_ASSURANCE_IDENTITY_V1: &'static str =
        "ak.profile.org_high_assurance_identity.v1";
    pub const ORGANIZATION_V1: &'static str = "ak.profile.organization.v1";
    pub const PERSONAL_AGENT_PROVISIONING_V1: &'static str =
        "ak.profile.personal_agent_provisioning.v1";
    pub const PERSONAL_NODE_V1: &'static str = "ak.profile.personal_node.v1";
    pub const PERSONAL_PRODUCTIVITY_V1: &'static str = "ak.profile.personal_productivity.v1";
    pub const PINNED_ITEMS_V1: &'static str = "ak.profile.pinned_items.v1";
    pub const PRINCIPAL_CONTROL_REALM_V1: &'static str = "ak.profile.principal_control_realm.v1";
    pub const PRINCIPAL_SERVER_V1: &'static str = "ak.profile.principal_server.v1";
    pub const PRINCIPAL_SERVER_EVENTS_API_V1: &'static str =
        "ak.profile.principal_server_events_api.v1";
    pub const PUBLIC_NETWORK_IDENTITY_V1: &'static str = "ak.profile.public_network_identity.v1";
    pub const PUSH_GATEWAY_BLIND_WAKEUP_V1: &'static str =
        "ak.profile.push_gateway.blind_wakeup.v1";
    pub const PUSH_GATEWAY_MATRIX_PASSTHROUGH_V1: &'static str =
        "ak.profile.push_gateway.matrix_passthrough.v1";
    pub const PUSH_GATEWAY_V1: &'static str = "ak.profile.push_gateway.v1";
    pub const PUSH_GATEWAY_VISIBLE_NOTIFICATION_V1: &'static str =
        "ak.profile.push_gateway.visible_notification.v1";
    pub const SEARCH_BLIND_INDEX_V1: &'static str = "ak.profile.search.blind_index.v1";
    pub const SEARCH_CLIENT_INDEX_V1: &'static str = "ak.profile.search.client_index.v1";
    pub const SEARCH_FORWARD_PRIVATE_V1: &'static str = "ak.profile.search.forward_private.v1";
    pub const SIGNAL_MESSAGE_STREAM_V1: &'static str = "ak.profile.signal_message_stream.v1";
    pub const SIGNAL_PEER_RELAY_V1: &'static str = "ak.profile.signal_peer_relay.v1";
    pub const SIGNATURE_ECDSA_P256_V1: &'static str = "ak.profile.signature.ecdsa_p256.v1";
    pub const SIGNATURE_PQC_V1: &'static str = "ak.profile.signature.pqc.v1";
    pub const SMALL_TEAM_V1: &'static str = "ak.profile.small_team.v1";
    pub const SOVEREIGN_CLIENT_V1: &'static str = "ak.profile.sovereign_client.v1";
    pub const SOVEREIGN_DEPLOYMENT_V1: &'static str = "ak.profile.sovereign_deployment.v1";
    pub const SOVEREIGN_ENCLAVE_V1: &'static str = "ak.profile.sovereign_enclave.v1";
    pub const TRAFFIC_METADATA_HARDENED_V1: &'static str =
        "ak.profile.traffic_metadata_hardened.v1";
    pub const UCAN_INTEROP_V1: &'static str = "ak.profile.ucan_interop.v1";
    pub const WEBRTC_MEDIA_V1: &'static str = "ak.profile.webrtc_media.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentAuthV1 => Self::AGENT_AUTH_V1,
            Self::AgentDelegationPolicyV1 => Self::AGENT_DELEGATION_POLICY_V1,
            Self::AgentParticipationPolicyV1 => Self::AGENT_PARTICIPATION_POLICY_V1,
            Self::AgentRuntimeV1 => Self::AGENT_RUNTIME_V1,
            Self::AgentSidecarV1 => Self::AGENT_SIDECAR_V1,
            Self::AgentSignerEvidenceV1 => Self::AGENT_SIGNER_EVIDENCE_V1,
            Self::AppletBridgeV1 => Self::APPLET_BRIDGE_V1,
            Self::AppletDelegatedV1 => Self::APPLET_DELEGATED_V1,
            Self::AppletE2eeJoinV1 => Self::APPLET_E2EE_JOIN_V1,
            Self::AppletServiceV1 => Self::APPLET_SERVICE_V1,
            Self::AppletWidgetV1 => Self::APPLET_WIDGET_V1,
            Self::AttestedAuditE2eeV1 => Self::ATTESTED_AUDIT_E2EE_V1,
            Self::AuthServerV1 => Self::AUTH_SERVER_V1,
            Self::BindingWebsocketV1 => Self::BINDING_WEBSOCKET_V1,
            Self::BlobNodeV1 => Self::BLOB_NODE_V1,
            Self::CalendarEventV1 => Self::CALENDAR_EVENT_V1,
            Self::CalendarNotificationDispatchV1 => Self::CALENDAR_NOTIFICATION_DISPATCH_V1,
            Self::CandidateJoinPolicyV1 => Self::CANDIDATE_JOIN_POLICY_V1,
            Self::ChatMvpV1 => Self::CHAT_MVP_V1,
            Self::CircleConformanceV1 => Self::CIRCLE_CONFORMANCE_V1,
            Self::CircleSealCadenceFixed5mV1 => Self::CIRCLE_SEAL_CADENCE_FIXED_5M_V1,
            Self::ConstraintApprovalWorkflowV1 => Self::CONSTRAINT_APPROVAL_WORKFLOW_V1,
            Self::ConstraintClaimBasedV1 => Self::CONSTRAINT_CLAIM_BASED_V1,
            Self::ConstraintEncryptionRequirementV1 => Self::CONSTRAINT_ENCRYPTION_REQUIREMENT_V1,
            Self::ConstraintResourceLimitV1 => Self::CONSTRAINT_RESOURCE_LIMIT_V1,
            Self::ConstraintVisibilityControlV1 => Self::CONSTRAINT_VISIBILITY_CONTROL_V1,
            Self::CoreEventStoreV1 => Self::CORE_EVENT_STORE_V1,
            Self::CrdtTextV1 => Self::CRDT_TEXT_V1,
            Self::CrossSigningResetV1 => Self::CROSS_SIGNING_RESET_V1,
            Self::DirectConversationRealmV1 => Self::DIRECT_CONVERSATION_REALM_V1,
            Self::DirectoryServiceV1 => Self::DIRECTORY_SERVICE_V1,
            Self::DisappearingV1 => Self::DISAPPEARING_V1,
            Self::DisclosedAuditE2eeV1 => Self::DISCLOSED_AUDIT_E2EE_V1,
            Self::DraftSyncV1 => Self::DRAFT_SYNC_V1,
            Self::E2eeClientV1 => Self::E2EE_CLIENT_V1,
            Self::E2eeRelaxedV1 => Self::E2EE_RELAXED_V1,
            Self::EncodingCborV1 => Self::ENCODING_CBOR_V1,
            Self::EncodingMultihashV1 => Self::ENCODING_MULTIHASH_V1,
            Self::EnterpriseClientV1 => Self::ENTERPRISE_CLIENT_V1,
            Self::FederationHighAssuranceV1 => Self::FEDERATION_HIGH_ASSURANCE_V1,
            Self::FederationRbsrNegentropyV1 => Self::FEDERATION_RBSR_NEGENTROPY_V1,
            Self::FederationMinimalV1 => Self::FEDERATION_MINIMAL_V1,
            Self::FileTransferV1 => Self::FILE_TRANSFER_V1,
            Self::FrankingV1 => Self::FRANKING_V1,
            Self::FullClientV1 => Self::FULL_CLIENT_V1,
            Self::HashBlake3V1 => Self::HASH_BLAKE3_V1,
            Self::HashTransitionV1 => Self::HASH_TRANSITION_V1,
            Self::HighSecurityOrganizationV1 => Self::HIGH_SECURITY_ORGANIZATION_V1,
            Self::HpkeP256V1 => Self::HPKE_P256_V1,
            Self::IdentityRegistryV1 => Self::IDENTITY_REGISTRY_V1,
            Self::IsolatedSovereignNetworkV1 => Self::ISOLATED_SOVEREIGN_NETWORK_V1,
            Self::KanbanMvpV1 => Self::KANBAN_MVP_V1,
            Self::KemHybridXwingV1 => Self::KEM_HYBRID_XWING_V1,
            Self::KeyBackupMemoryHardV1 => Self::KEY_BACKUP_MEMORY_HARD_V1,
            Self::KeyTransparencyV1 => Self::KEY_TRANSPARENCY_V1,
            Self::MatrixCompatV1 => Self::MATRIX_COMPAT_V1,
            Self::MediaServiceBindingArkretNativeV1 => Self::MEDIA_SERVICE_BINDING_ARKRET_NATIVE_V1,
            Self::MediaServiceBindingLivekitV1 => Self::MEDIA_SERVICE_BINDING_LIVEKIT_V1,
            Self::MediaServiceBindingV1 => Self::MEDIA_SERVICE_BINDING_V1,
            Self::MimiInteropV1 => Self::MIMI_INTEROP_V1,
            Self::MinimalClientV1 => Self::MINIMAL_CLIENT_V1,
            Self::MlsMinimalMetadataRealmV1 => Self::MLS_MINIMAL_METADATA_REALM_V1,
            Self::MlsCiphersuiteChacha20poly1305V1 => Self::MLS_CIPHERSUITE_CHACHA20POLY1305_V1,
            Self::MlsCiphersuitePqAuthV1 => Self::MLS_CIPHERSUITE_PQ_AUTH_V1,
            Self::MlsGovernanceBindingFullV1 => Self::MLS_GOVERNANCE_BINDING_FULL_V1,
            Self::MorphSchemaMigrationTransformationsV1 => {
                Self::MORPH_SCHEMA_MIGRATION_TRANSFORMATIONS_V1
            }
            Self::NotaryMixedRecoveryV1 => Self::NOTARY_MIXED_RECOVERY_V1,
            Self::NotaryOpenSetV1 => Self::NOTARY_OPEN_SET_V1,
            Self::NotarySingleDidV1 => Self::NOTARY_SINGLE_DID_V1,
            Self::NotaryThresholdV1 => Self::NOTARY_THRESHOLD_V1,
            Self::OrgHighAssuranceIdentityV1 => Self::ORG_HIGH_ASSURANCE_IDENTITY_V1,
            Self::OrganizationV1 => Self::ORGANIZATION_V1,
            Self::PersonalAgentProvisioningV1 => Self::PERSONAL_AGENT_PROVISIONING_V1,
            Self::PersonalNodeV1 => Self::PERSONAL_NODE_V1,
            Self::PersonalProductivityV1 => Self::PERSONAL_PRODUCTIVITY_V1,
            Self::PinnedItemsV1 => Self::PINNED_ITEMS_V1,
            Self::PrincipalControlRealmV1 => Self::PRINCIPAL_CONTROL_REALM_V1,
            Self::PrincipalServerV1 => Self::PRINCIPAL_SERVER_V1,
            Self::PrincipalServerEventsApiV1 => Self::PRINCIPAL_SERVER_EVENTS_API_V1,
            Self::PublicNetworkIdentityV1 => Self::PUBLIC_NETWORK_IDENTITY_V1,
            Self::PushGatewayBlindWakeupV1 => Self::PUSH_GATEWAY_BLIND_WAKEUP_V1,
            Self::PushGatewayMatrixPassthroughV1 => Self::PUSH_GATEWAY_MATRIX_PASSTHROUGH_V1,
            Self::PushGatewayV1 => Self::PUSH_GATEWAY_V1,
            Self::PushGatewayVisibleNotificationV1 => Self::PUSH_GATEWAY_VISIBLE_NOTIFICATION_V1,
            Self::SearchBlindIndexV1 => Self::SEARCH_BLIND_INDEX_V1,
            Self::SearchClientIndexV1 => Self::SEARCH_CLIENT_INDEX_V1,
            Self::SearchForwardPrivateV1 => Self::SEARCH_FORWARD_PRIVATE_V1,
            Self::SignalMessageStreamV1 => Self::SIGNAL_MESSAGE_STREAM_V1,
            Self::SignalPeerRelayV1 => Self::SIGNAL_PEER_RELAY_V1,
            Self::SignatureEcdsaP256V1 => Self::SIGNATURE_ECDSA_P256_V1,
            Self::SignaturePqcV1 => Self::SIGNATURE_PQC_V1,
            Self::SmallTeamV1 => Self::SMALL_TEAM_V1,
            Self::SovereignClientV1 => Self::SOVEREIGN_CLIENT_V1,
            Self::SovereignDeploymentV1 => Self::SOVEREIGN_DEPLOYMENT_V1,
            Self::SovereignEnclaveV1 => Self::SOVEREIGN_ENCLAVE_V1,
            Self::TrafficMetadataHardenedV1 => Self::TRAFFIC_METADATA_HARDENED_V1,
            Self::UcanInteropV1 => Self::UCAN_INTEROP_V1,
            Self::WebrtcMediaV1 => Self::WEBRTC_MEDIA_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::AGENT_AUTH_V1 => Some(Self::AgentAuthV1),
            Self::AGENT_DELEGATION_POLICY_V1 => Some(Self::AgentDelegationPolicyV1),
            Self::AGENT_PARTICIPATION_POLICY_V1 => Some(Self::AgentParticipationPolicyV1),
            Self::AGENT_RUNTIME_V1 => Some(Self::AgentRuntimeV1),
            Self::AGENT_SIDECAR_V1 => Some(Self::AgentSidecarV1),
            Self::AGENT_SIGNER_EVIDENCE_V1 => Some(Self::AgentSignerEvidenceV1),
            Self::APPLET_BRIDGE_V1 => Some(Self::AppletBridgeV1),
            Self::APPLET_DELEGATED_V1 => Some(Self::AppletDelegatedV1),
            Self::APPLET_E2EE_JOIN_V1 => Some(Self::AppletE2eeJoinV1),
            Self::APPLET_SERVICE_V1 => Some(Self::AppletServiceV1),
            Self::APPLET_WIDGET_V1 => Some(Self::AppletWidgetV1),
            Self::ATTESTED_AUDIT_E2EE_V1 => Some(Self::AttestedAuditE2eeV1),
            Self::AUTH_SERVER_V1 => Some(Self::AuthServerV1),
            Self::BINDING_WEBSOCKET_V1 => Some(Self::BindingWebsocketV1),
            Self::BLOB_NODE_V1 => Some(Self::BlobNodeV1),
            Self::CALENDAR_EVENT_V1 => Some(Self::CalendarEventV1),
            Self::CALENDAR_NOTIFICATION_DISPATCH_V1 => Some(Self::CalendarNotificationDispatchV1),
            Self::CANDIDATE_JOIN_POLICY_V1 => Some(Self::CandidateJoinPolicyV1),
            Self::CHAT_MVP_V1 => Some(Self::ChatMvpV1),
            Self::CIRCLE_CONFORMANCE_V1 => Some(Self::CircleConformanceV1),
            Self::CIRCLE_SEAL_CADENCE_FIXED_5M_V1 => Some(Self::CircleSealCadenceFixed5mV1),
            Self::CONSTRAINT_APPROVAL_WORKFLOW_V1 => Some(Self::ConstraintApprovalWorkflowV1),
            Self::CONSTRAINT_CLAIM_BASED_V1 => Some(Self::ConstraintClaimBasedV1),
            Self::CONSTRAINT_ENCRYPTION_REQUIREMENT_V1 => {
                Some(Self::ConstraintEncryptionRequirementV1)
            }
            Self::CONSTRAINT_RESOURCE_LIMIT_V1 => Some(Self::ConstraintResourceLimitV1),
            Self::CONSTRAINT_VISIBILITY_CONTROL_V1 => Some(Self::ConstraintVisibilityControlV1),
            Self::CORE_EVENT_STORE_V1 => Some(Self::CoreEventStoreV1),
            Self::CRDT_TEXT_V1 => Some(Self::CrdtTextV1),
            Self::CROSS_SIGNING_RESET_V1 => Some(Self::CrossSigningResetV1),
            Self::DIRECT_CONVERSATION_REALM_V1 => Some(Self::DirectConversationRealmV1),
            Self::DIRECTORY_SERVICE_V1 => Some(Self::DirectoryServiceV1),
            Self::DISAPPEARING_V1 => Some(Self::DisappearingV1),
            Self::DISCLOSED_AUDIT_E2EE_V1 => Some(Self::DisclosedAuditE2eeV1),
            Self::DRAFT_SYNC_V1 => Some(Self::DraftSyncV1),
            Self::E2EE_CLIENT_V1 => Some(Self::E2eeClientV1),
            Self::E2EE_RELAXED_V1 => Some(Self::E2eeRelaxedV1),
            Self::ENCODING_CBOR_V1 => Some(Self::EncodingCborV1),
            Self::ENCODING_MULTIHASH_V1 => Some(Self::EncodingMultihashV1),
            Self::ENTERPRISE_CLIENT_V1 => Some(Self::EnterpriseClientV1),
            Self::FEDERATION_HIGH_ASSURANCE_V1 => Some(Self::FederationHighAssuranceV1),
            Self::FEDERATION_RBSR_NEGENTROPY_V1 => Some(Self::FederationRbsrNegentropyV1),
            Self::FEDERATION_MINIMAL_V1 => Some(Self::FederationMinimalV1),
            Self::FILE_TRANSFER_V1 => Some(Self::FileTransferV1),
            Self::FRANKING_V1 => Some(Self::FrankingV1),
            Self::FULL_CLIENT_V1 => Some(Self::FullClientV1),
            Self::HASH_BLAKE3_V1 => Some(Self::HashBlake3V1),
            Self::HASH_TRANSITION_V1 => Some(Self::HashTransitionV1),
            Self::HIGH_SECURITY_ORGANIZATION_V1 => Some(Self::HighSecurityOrganizationV1),
            Self::HPKE_P256_V1 => Some(Self::HpkeP256V1),
            Self::IDENTITY_REGISTRY_V1 => Some(Self::IdentityRegistryV1),
            Self::ISOLATED_SOVEREIGN_NETWORK_V1 => Some(Self::IsolatedSovereignNetworkV1),
            Self::KANBAN_MVP_V1 => Some(Self::KanbanMvpV1),
            Self::KEM_HYBRID_XWING_V1 => Some(Self::KemHybridXwingV1),
            Self::KEY_BACKUP_MEMORY_HARD_V1 => Some(Self::KeyBackupMemoryHardV1),
            Self::KEY_TRANSPARENCY_V1 => Some(Self::KeyTransparencyV1),
            Self::MATRIX_COMPAT_V1 => Some(Self::MatrixCompatV1),
            Self::MEDIA_SERVICE_BINDING_ARKRET_NATIVE_V1 => {
                Some(Self::MediaServiceBindingArkretNativeV1)
            }
            Self::MEDIA_SERVICE_BINDING_LIVEKIT_V1 => Some(Self::MediaServiceBindingLivekitV1),
            Self::MEDIA_SERVICE_BINDING_V1 => Some(Self::MediaServiceBindingV1),
            Self::MIMI_INTEROP_V1 => Some(Self::MimiInteropV1),
            Self::MINIMAL_CLIENT_V1 => Some(Self::MinimalClientV1),
            Self::MLS_MINIMAL_METADATA_REALM_V1 => Some(Self::MlsMinimalMetadataRealmV1),
            Self::MLS_CIPHERSUITE_CHACHA20POLY1305_V1 => {
                Some(Self::MlsCiphersuiteChacha20poly1305V1)
            }
            Self::MLS_CIPHERSUITE_PQ_AUTH_V1 => Some(Self::MlsCiphersuitePqAuthV1),
            Self::MLS_GOVERNANCE_BINDING_FULL_V1 => Some(Self::MlsGovernanceBindingFullV1),
            Self::MORPH_SCHEMA_MIGRATION_TRANSFORMATIONS_V1 => {
                Some(Self::MorphSchemaMigrationTransformationsV1)
            }
            Self::NOTARY_MIXED_RECOVERY_V1 => Some(Self::NotaryMixedRecoveryV1),
            Self::NOTARY_OPEN_SET_V1 => Some(Self::NotaryOpenSetV1),
            Self::NOTARY_SINGLE_DID_V1 => Some(Self::NotarySingleDidV1),
            Self::NOTARY_THRESHOLD_V1 => Some(Self::NotaryThresholdV1),
            Self::ORG_HIGH_ASSURANCE_IDENTITY_V1 => Some(Self::OrgHighAssuranceIdentityV1),
            Self::ORGANIZATION_V1 => Some(Self::OrganizationV1),
            Self::PERSONAL_AGENT_PROVISIONING_V1 => Some(Self::PersonalAgentProvisioningV1),
            Self::PERSONAL_NODE_V1 => Some(Self::PersonalNodeV1),
            Self::PERSONAL_PRODUCTIVITY_V1 => Some(Self::PersonalProductivityV1),
            Self::PINNED_ITEMS_V1 => Some(Self::PinnedItemsV1),
            Self::PRINCIPAL_CONTROL_REALM_V1 => Some(Self::PrincipalControlRealmV1),
            Self::PRINCIPAL_SERVER_V1 => Some(Self::PrincipalServerV1),
            Self::PRINCIPAL_SERVER_EVENTS_API_V1 => Some(Self::PrincipalServerEventsApiV1),
            Self::PUBLIC_NETWORK_IDENTITY_V1 => Some(Self::PublicNetworkIdentityV1),
            Self::PUSH_GATEWAY_BLIND_WAKEUP_V1 => Some(Self::PushGatewayBlindWakeupV1),
            Self::PUSH_GATEWAY_MATRIX_PASSTHROUGH_V1 => Some(Self::PushGatewayMatrixPassthroughV1),
            Self::PUSH_GATEWAY_V1 => Some(Self::PushGatewayV1),
            Self::PUSH_GATEWAY_VISIBLE_NOTIFICATION_V1 => {
                Some(Self::PushGatewayVisibleNotificationV1)
            }
            Self::SEARCH_BLIND_INDEX_V1 => Some(Self::SearchBlindIndexV1),
            Self::SEARCH_CLIENT_INDEX_V1 => Some(Self::SearchClientIndexV1),
            Self::SEARCH_FORWARD_PRIVATE_V1 => Some(Self::SearchForwardPrivateV1),
            Self::SIGNAL_MESSAGE_STREAM_V1 => Some(Self::SignalMessageStreamV1),
            Self::SIGNAL_PEER_RELAY_V1 => Some(Self::SignalPeerRelayV1),
            Self::SIGNATURE_ECDSA_P256_V1 => Some(Self::SignatureEcdsaP256V1),
            Self::SIGNATURE_PQC_V1 => Some(Self::SignaturePqcV1),
            Self::SMALL_TEAM_V1 => Some(Self::SmallTeamV1),
            Self::SOVEREIGN_CLIENT_V1 => Some(Self::SovereignClientV1),
            Self::SOVEREIGN_DEPLOYMENT_V1 => Some(Self::SovereignDeploymentV1),
            Self::SOVEREIGN_ENCLAVE_V1 => Some(Self::SovereignEnclaveV1),
            Self::TRAFFIC_METADATA_HARDENED_V1 => Some(Self::TrafficMetadataHardenedV1),
            Self::UCAN_INTEROP_V1 => Some(Self::UcanInteropV1),
            Self::WEBRTC_MEDIA_V1 => Some(Self::WebrtcMediaV1),
            _ => None,
        }
    }
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ProfileId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProfileId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown profile id: {raw}")))
    }
}
