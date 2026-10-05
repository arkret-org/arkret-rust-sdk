//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: profiles/conformance-profiles.json; version=2026-10-05.1;
//! sha256=158b719c773a6bfd2f233eacc3f940a4e71164fca6083cb34fcdadf553c0ef5b Entries: profile_ids=78

use serde::{Deserialize, Serialize};

/// Declared conformance profile identifiers. Every `ak.profile.*` literal
/// the SDK ships is spelled exactly once, here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ProfileId {
    AgentAuthV1,
    AgentDelegationPolicyV1,
    AgentParticipationPolicyV1,
    AgentProvisioningV1,
    AgentRuntimeV1,
    AgentSidecarV1,
    AgentSignerEvidenceV1,
    AppletBridgeV1,
    AppletDelegatedV1,
    AppletE2eeJoinV1,
    AppletServiceV1,
    AppletWidgetV1,
    BindingWebsocketV1,
    BlobNodeV1,
    CalendarEventV1,
    CalendarNotificationDispatchV1,
    ChatMvpV1,
    CircleConformanceV1,
    ConstraintApprovalWorkflowV1,
    ConstraintClaimBasedV1,
    ConstraintEncryptionRequirementV1,
    ConstraintResourceLimitV1,
    ConstraintVisibilityControlV1,
    CoreEventStoreV1,
    DirectConversationRealmV1,
    DirectConversationRepairV1,
    DirectoryServiceV1,
    DraftSyncV1,
    E2eeClientV1,
    EncodingCborV1,
    EnterpriseClientV1,
    FederationMinimalV1,
    FileTransferV1,
    FrankingV1,
    FullClientV1,
    HashBlake3V1,
    HighSecurityOrganizationV1,
    HpkeP256V1,
    IdentityRegistryV1,
    IsolatedSovereignNetworkV1,
    KanbanMvpV1,
    KemHybridXwingV1,
    KeyBackupMemoryHardV1,
    KeyTransparencyV1,
    MediaServiceBindingArkretNativeV1,
    MediaServiceBindingLivekitV1,
    MediaServiceBindingV1,
    MembershipJoinCompensationV1,
    MimiInteropV1,
    MinimalClientV1,
    MlsCiphersuiteChacha20poly1305V1,
    MlsCiphersuitePqAuthV1,
    OrganizationV1,
    OrganizationHighAssuranceIdentityV1,
    PersonalNodeV1,
    PersonalProductivityV1,
    PinnedItemsV1,
    PrincipalControlRealmV1,
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
    StationV1,
    StationEventsApiV1,
    TrafficMetadataHardenedV1,
    WebrtcMediaV1,
}

/// Spec-layer `profile_roles` partition: every declared profile id
/// belongs to exactly one of these roles. SDK manifests, client-side
/// feature negotiation, and conformance loaders MUST consult
/// [`ProfileId::role`] before claiming a profile as locally implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileRole {
    Client,
    Server,
    Gateway,
    Directory,
    Admin,
    Interop,
}

impl ProfileRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Gateway => "gateway",
            Self::Directory => "directory",
            Self::Admin => "admin",
            Self::Interop => "interop",
        }
    }
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "client" => Some(Self::Client),
            "server" => Some(Self::Server),
            "gateway" => Some(Self::Gateway),
            "directory" => Some(Self::Directory),
            "admin" => Some(Self::Admin),
            "interop" => Some(Self::Interop),
            _ => None,
        }
    }
}

impl ProfileId {
    pub const ALL: &'static [Self] = &[
        Self::AgentAuthV1,
        Self::AgentDelegationPolicyV1,
        Self::AgentParticipationPolicyV1,
        Self::AgentProvisioningV1,
        Self::AgentRuntimeV1,
        Self::AgentSidecarV1,
        Self::AgentSignerEvidenceV1,
        Self::AppletBridgeV1,
        Self::AppletDelegatedV1,
        Self::AppletE2eeJoinV1,
        Self::AppletServiceV1,
        Self::AppletWidgetV1,
        Self::BindingWebsocketV1,
        Self::BlobNodeV1,
        Self::CalendarEventV1,
        Self::CalendarNotificationDispatchV1,
        Self::ChatMvpV1,
        Self::CircleConformanceV1,
        Self::ConstraintApprovalWorkflowV1,
        Self::ConstraintClaimBasedV1,
        Self::ConstraintEncryptionRequirementV1,
        Self::ConstraintResourceLimitV1,
        Self::ConstraintVisibilityControlV1,
        Self::CoreEventStoreV1,
        Self::DirectConversationRealmV1,
        Self::DirectConversationRepairV1,
        Self::DirectoryServiceV1,
        Self::DraftSyncV1,
        Self::E2eeClientV1,
        Self::EncodingCborV1,
        Self::EnterpriseClientV1,
        Self::FederationMinimalV1,
        Self::FileTransferV1,
        Self::FrankingV1,
        Self::FullClientV1,
        Self::HashBlake3V1,
        Self::HighSecurityOrganizationV1,
        Self::HpkeP256V1,
        Self::IdentityRegistryV1,
        Self::IsolatedSovereignNetworkV1,
        Self::KanbanMvpV1,
        Self::KemHybridXwingV1,
        Self::KeyBackupMemoryHardV1,
        Self::KeyTransparencyV1,
        Self::MediaServiceBindingArkretNativeV1,
        Self::MediaServiceBindingLivekitV1,
        Self::MediaServiceBindingV1,
        Self::MembershipJoinCompensationV1,
        Self::MimiInteropV1,
        Self::MinimalClientV1,
        Self::MlsCiphersuiteChacha20poly1305V1,
        Self::MlsCiphersuitePqAuthV1,
        Self::OrganizationV1,
        Self::OrganizationHighAssuranceIdentityV1,
        Self::PersonalNodeV1,
        Self::PersonalProductivityV1,
        Self::PinnedItemsV1,
        Self::PrincipalControlRealmV1,
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
        Self::StationV1,
        Self::StationEventsApiV1,
        Self::TrafficMetadataHardenedV1,
        Self::WebrtcMediaV1,
    ];

    pub const AGENT_AUTH_V1: &'static str = "ak.profile.agent_auth.v1";
    pub const AGENT_DELEGATION_POLICY_V1: &'static str = "ak.profile.agent_delegation_policy.v1";
    pub const AGENT_PARTICIPATION_POLICY_V1: &'static str =
        "ak.profile.agent_participation_policy.v1";
    pub const AGENT_PROVISIONING_V1: &'static str = "ak.profile.agent_provisioning.v1";
    pub const AGENT_RUNTIME_V1: &'static str = "ak.profile.agent_runtime.v1";
    pub const AGENT_SIDECAR_V1: &'static str = "ak.profile.agent_sidecar.v1";
    pub const AGENT_SIGNER_EVIDENCE_V1: &'static str = "ak.profile.agent_signer_evidence.v1";
    pub const APPLET_BRIDGE_V1: &'static str = "ak.profile.applet_bridge.v1";
    pub const APPLET_DELEGATED_V1: &'static str = "ak.profile.applet_delegated.v1";
    pub const APPLET_E2EE_JOIN_V1: &'static str = "ak.profile.applet_e2ee_join.v1";
    pub const APPLET_SERVICE_V1: &'static str = "ak.profile.applet_service.v1";
    pub const APPLET_WIDGET_V1: &'static str = "ak.profile.applet_widget.v1";
    pub const BINDING_WEBSOCKET_V1: &'static str = "ak.profile.binding.websocket.v1";
    pub const BLOB_NODE_V1: &'static str = "ak.profile.blob_node.v1";
    pub const CALENDAR_EVENT_V1: &'static str = "ak.profile.calendar_event.v1";
    pub const CALENDAR_NOTIFICATION_DISPATCH_V1: &'static str =
        "ak.profile.calendar_notification_dispatch.v1";
    pub const CHAT_MVP_V1: &'static str = "ak.profile.chat_mvp.v1";
    pub const CIRCLE_CONFORMANCE_V1: &'static str = "ak.profile.circle_conformance.v1";
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
    pub const DIRECT_CONVERSATION_REALM_V1: &'static str =
        "ak.profile.direct_conversation_realm.v1";
    pub const DIRECT_CONVERSATION_REPAIR_V1: &'static str =
        "ak.profile.direct_conversation_repair.v1";
    pub const DIRECTORY_SERVICE_V1: &'static str = "ak.profile.directory_service.v1";
    pub const DRAFT_SYNC_V1: &'static str = "ak.profile.draft_sync.v1";
    pub const E2EE_CLIENT_V1: &'static str = "ak.profile.e2ee_client.v1";
    pub const ENCODING_CBOR_V1: &'static str = "ak.profile.encoding.cbor.v1";
    pub const ENTERPRISE_CLIENT_V1: &'static str = "ak.profile.enterprise_client.v1";
    pub const FEDERATION_MINIMAL_V1: &'static str = "ak.profile.federation_minimal.v1";
    pub const FILE_TRANSFER_V1: &'static str = "ak.profile.file_transfer.v1";
    pub const FRANKING_V1: &'static str = "ak.profile.franking.v1";
    pub const FULL_CLIENT_V1: &'static str = "ak.profile.full_client.v1";
    pub const HASH_BLAKE3_V1: &'static str = "ak.profile.hash.blake3.v1";
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
    pub const MEDIA_SERVICE_BINDING_ARKRET_NATIVE_V1: &'static str =
        "ak.profile.media_service_binding.arkret_native.v1";
    pub const MEDIA_SERVICE_BINDING_LIVEKIT_V1: &'static str =
        "ak.profile.media_service_binding.livekit.v1";
    pub const MEDIA_SERVICE_BINDING_V1: &'static str = "ak.profile.media_service_binding.v1";
    pub const MEMBERSHIP_JOIN_COMPENSATION_V1: &'static str =
        "ak.profile.membership_join_compensation.v1";
    pub const MIMI_INTEROP_V1: &'static str = "ak.profile.mimi_interop.v1";
    pub const MINIMAL_CLIENT_V1: &'static str = "ak.profile.minimal_client.v1";
    pub const MLS_CIPHERSUITE_CHACHA20POLY1305_V1: &'static str =
        "ak.profile.mls_ciphersuite.chacha20poly1305.v1";
    pub const MLS_CIPHERSUITE_PQ_AUTH_V1: &'static str = "ak.profile.mls_ciphersuite.pq_auth.v1";
    pub const ORGANIZATION_V1: &'static str = "ak.profile.organization.v1";
    pub const ORGANIZATION_HIGH_ASSURANCE_IDENTITY_V1: &'static str =
        "ak.profile.organization_high_assurance_identity.v1";
    pub const PERSONAL_NODE_V1: &'static str = "ak.profile.personal_node.v1";
    pub const PERSONAL_PRODUCTIVITY_V1: &'static str = "ak.profile.personal_productivity.v1";
    pub const PINNED_ITEMS_V1: &'static str = "ak.profile.pinned_items.v1";
    pub const PRINCIPAL_CONTROL_REALM_V1: &'static str = "ak.profile.principal_control_realm.v1";
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
    pub const STATION_V1: &'static str = "ak.profile.station.v1";
    pub const STATION_EVENTS_API_V1: &'static str = "ak.profile.station_events_api.v1";
    pub const TRAFFIC_METADATA_HARDENED_V1: &'static str =
        "ak.profile.traffic_metadata_hardened.v1";
    pub const WEBRTC_MEDIA_V1: &'static str = "ak.profile.webrtc_media.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentAuthV1 => Self::AGENT_AUTH_V1,
            Self::AgentDelegationPolicyV1 => Self::AGENT_DELEGATION_POLICY_V1,
            Self::AgentParticipationPolicyV1 => Self::AGENT_PARTICIPATION_POLICY_V1,
            Self::AgentProvisioningV1 => Self::AGENT_PROVISIONING_V1,
            Self::AgentRuntimeV1 => Self::AGENT_RUNTIME_V1,
            Self::AgentSidecarV1 => Self::AGENT_SIDECAR_V1,
            Self::AgentSignerEvidenceV1 => Self::AGENT_SIGNER_EVIDENCE_V1,
            Self::AppletBridgeV1 => Self::APPLET_BRIDGE_V1,
            Self::AppletDelegatedV1 => Self::APPLET_DELEGATED_V1,
            Self::AppletE2eeJoinV1 => Self::APPLET_E2EE_JOIN_V1,
            Self::AppletServiceV1 => Self::APPLET_SERVICE_V1,
            Self::AppletWidgetV1 => Self::APPLET_WIDGET_V1,
            Self::BindingWebsocketV1 => Self::BINDING_WEBSOCKET_V1,
            Self::BlobNodeV1 => Self::BLOB_NODE_V1,
            Self::CalendarEventV1 => Self::CALENDAR_EVENT_V1,
            Self::CalendarNotificationDispatchV1 => Self::CALENDAR_NOTIFICATION_DISPATCH_V1,
            Self::ChatMvpV1 => Self::CHAT_MVP_V1,
            Self::CircleConformanceV1 => Self::CIRCLE_CONFORMANCE_V1,
            Self::ConstraintApprovalWorkflowV1 => Self::CONSTRAINT_APPROVAL_WORKFLOW_V1,
            Self::ConstraintClaimBasedV1 => Self::CONSTRAINT_CLAIM_BASED_V1,
            Self::ConstraintEncryptionRequirementV1 => Self::CONSTRAINT_ENCRYPTION_REQUIREMENT_V1,
            Self::ConstraintResourceLimitV1 => Self::CONSTRAINT_RESOURCE_LIMIT_V1,
            Self::ConstraintVisibilityControlV1 => Self::CONSTRAINT_VISIBILITY_CONTROL_V1,
            Self::CoreEventStoreV1 => Self::CORE_EVENT_STORE_V1,
            Self::DirectConversationRealmV1 => Self::DIRECT_CONVERSATION_REALM_V1,
            Self::DirectConversationRepairV1 => Self::DIRECT_CONVERSATION_REPAIR_V1,
            Self::DirectoryServiceV1 => Self::DIRECTORY_SERVICE_V1,
            Self::DraftSyncV1 => Self::DRAFT_SYNC_V1,
            Self::E2eeClientV1 => Self::E2EE_CLIENT_V1,
            Self::EncodingCborV1 => Self::ENCODING_CBOR_V1,
            Self::EnterpriseClientV1 => Self::ENTERPRISE_CLIENT_V1,
            Self::FederationMinimalV1 => Self::FEDERATION_MINIMAL_V1,
            Self::FileTransferV1 => Self::FILE_TRANSFER_V1,
            Self::FrankingV1 => Self::FRANKING_V1,
            Self::FullClientV1 => Self::FULL_CLIENT_V1,
            Self::HashBlake3V1 => Self::HASH_BLAKE3_V1,
            Self::HighSecurityOrganizationV1 => Self::HIGH_SECURITY_ORGANIZATION_V1,
            Self::HpkeP256V1 => Self::HPKE_P256_V1,
            Self::IdentityRegistryV1 => Self::IDENTITY_REGISTRY_V1,
            Self::IsolatedSovereignNetworkV1 => Self::ISOLATED_SOVEREIGN_NETWORK_V1,
            Self::KanbanMvpV1 => Self::KANBAN_MVP_V1,
            Self::KemHybridXwingV1 => Self::KEM_HYBRID_XWING_V1,
            Self::KeyBackupMemoryHardV1 => Self::KEY_BACKUP_MEMORY_HARD_V1,
            Self::KeyTransparencyV1 => Self::KEY_TRANSPARENCY_V1,
            Self::MediaServiceBindingArkretNativeV1 => Self::MEDIA_SERVICE_BINDING_ARKRET_NATIVE_V1,
            Self::MediaServiceBindingLivekitV1 => Self::MEDIA_SERVICE_BINDING_LIVEKIT_V1,
            Self::MediaServiceBindingV1 => Self::MEDIA_SERVICE_BINDING_V1,
            Self::MembershipJoinCompensationV1 => Self::MEMBERSHIP_JOIN_COMPENSATION_V1,
            Self::MimiInteropV1 => Self::MIMI_INTEROP_V1,
            Self::MinimalClientV1 => Self::MINIMAL_CLIENT_V1,
            Self::MlsCiphersuiteChacha20poly1305V1 => Self::MLS_CIPHERSUITE_CHACHA20POLY1305_V1,
            Self::MlsCiphersuitePqAuthV1 => Self::MLS_CIPHERSUITE_PQ_AUTH_V1,
            Self::OrganizationV1 => Self::ORGANIZATION_V1,
            Self::OrganizationHighAssuranceIdentityV1 => {
                Self::ORGANIZATION_HIGH_ASSURANCE_IDENTITY_V1
            }
            Self::PersonalNodeV1 => Self::PERSONAL_NODE_V1,
            Self::PersonalProductivityV1 => Self::PERSONAL_PRODUCTIVITY_V1,
            Self::PinnedItemsV1 => Self::PINNED_ITEMS_V1,
            Self::PrincipalControlRealmV1 => Self::PRINCIPAL_CONTROL_REALM_V1,
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
            Self::StationV1 => Self::STATION_V1,
            Self::StationEventsApiV1 => Self::STATION_EVENTS_API_V1,
            Self::TrafficMetadataHardenedV1 => Self::TRAFFIC_METADATA_HARDENED_V1,
            Self::WebrtcMediaV1 => Self::WEBRTC_MEDIA_V1,
        }
    }

    pub const fn role(self) -> ProfileRole {
        match self {
            Self::AgentAuthV1 => ProfileRole::Server,
            Self::AgentDelegationPolicyV1 => ProfileRole::Server,
            Self::AgentParticipationPolicyV1 => ProfileRole::Server,
            Self::AgentProvisioningV1 => ProfileRole::Server,
            Self::AgentRuntimeV1 => ProfileRole::Server,
            Self::AgentSidecarV1 => ProfileRole::Server,
            Self::AgentSignerEvidenceV1 => ProfileRole::Interop,
            Self::AppletBridgeV1 => ProfileRole::Server,
            Self::AppletDelegatedV1 => ProfileRole::Server,
            Self::AppletE2eeJoinV1 => ProfileRole::Server,
            Self::AppletServiceV1 => ProfileRole::Server,
            Self::AppletWidgetV1 => ProfileRole::Server,
            Self::BindingWebsocketV1 => ProfileRole::Interop,
            Self::BlobNodeV1 => ProfileRole::Gateway,
            Self::CalendarEventV1 => ProfileRole::Client,
            Self::CalendarNotificationDispatchV1 => ProfileRole::Server,
            Self::ChatMvpV1 => ProfileRole::Client,
            Self::CircleConformanceV1 => ProfileRole::Interop,
            Self::ConstraintApprovalWorkflowV1 => ProfileRole::Admin,
            Self::ConstraintClaimBasedV1 => ProfileRole::Admin,
            Self::ConstraintEncryptionRequirementV1 => ProfileRole::Admin,
            Self::ConstraintResourceLimitV1 => ProfileRole::Admin,
            Self::ConstraintVisibilityControlV1 => ProfileRole::Admin,
            Self::CoreEventStoreV1 => ProfileRole::Server,
            Self::DirectConversationRealmV1 => ProfileRole::Admin,
            Self::DirectConversationRepairV1 => ProfileRole::Server,
            Self::DirectoryServiceV1 => ProfileRole::Directory,
            Self::DraftSyncV1 => ProfileRole::Client,
            Self::E2eeClientV1 => ProfileRole::Client,
            Self::EncodingCborV1 => ProfileRole::Interop,
            Self::EnterpriseClientV1 => ProfileRole::Client,
            Self::FederationMinimalV1 => ProfileRole::Server,
            Self::FileTransferV1 => ProfileRole::Client,
            Self::FrankingV1 => ProfileRole::Server,
            Self::FullClientV1 => ProfileRole::Client,
            Self::HashBlake3V1 => ProfileRole::Interop,
            Self::HighSecurityOrganizationV1 => ProfileRole::Admin,
            Self::HpkeP256V1 => ProfileRole::Admin,
            Self::IdentityRegistryV1 => ProfileRole::Directory,
            Self::IsolatedSovereignNetworkV1 => ProfileRole::Admin,
            Self::KanbanMvpV1 => ProfileRole::Client,
            Self::KemHybridXwingV1 => ProfileRole::Admin,
            Self::KeyBackupMemoryHardV1 => ProfileRole::Admin,
            Self::KeyTransparencyV1 => ProfileRole::Directory,
            Self::MediaServiceBindingArkretNativeV1 => ProfileRole::Server,
            Self::MediaServiceBindingLivekitV1 => ProfileRole::Server,
            Self::MediaServiceBindingV1 => ProfileRole::Server,
            Self::MembershipJoinCompensationV1 => ProfileRole::Server,
            Self::MimiInteropV1 => ProfileRole::Interop,
            Self::MinimalClientV1 => ProfileRole::Client,
            Self::MlsCiphersuiteChacha20poly1305V1 => ProfileRole::Interop,
            Self::MlsCiphersuitePqAuthV1 => ProfileRole::Interop,
            Self::OrganizationV1 => ProfileRole::Admin,
            Self::OrganizationHighAssuranceIdentityV1 => ProfileRole::Directory,
            Self::PersonalNodeV1 => ProfileRole::Admin,
            Self::PersonalProductivityV1 => ProfileRole::Client,
            Self::PinnedItemsV1 => ProfileRole::Client,
            Self::PrincipalControlRealmV1 => ProfileRole::Admin,
            Self::PublicNetworkIdentityV1 => ProfileRole::Directory,
            Self::PushGatewayBlindWakeupV1 => ProfileRole::Gateway,
            Self::PushGatewayMatrixPassthroughV1 => ProfileRole::Interop,
            Self::PushGatewayV1 => ProfileRole::Gateway,
            Self::PushGatewayVisibleNotificationV1 => ProfileRole::Gateway,
            Self::SearchBlindIndexV1 => ProfileRole::Server,
            Self::SearchClientIndexV1 => ProfileRole::Client,
            Self::SearchForwardPrivateV1 => ProfileRole::Server,
            Self::SignalMessageStreamV1 => ProfileRole::Client,
            Self::SignalPeerRelayV1 => ProfileRole::Server,
            Self::SignatureEcdsaP256V1 => ProfileRole::Admin,
            Self::SignaturePqcV1 => ProfileRole::Admin,
            Self::SmallTeamV1 => ProfileRole::Admin,
            Self::SovereignClientV1 => ProfileRole::Client,
            Self::SovereignDeploymentV1 => ProfileRole::Admin,
            Self::SovereignEnclaveV1 => ProfileRole::Admin,
            Self::StationV1 => ProfileRole::Server,
            Self::StationEventsApiV1 => ProfileRole::Server,
            Self::TrafficMetadataHardenedV1 => ProfileRole::Admin,
            Self::WebrtcMediaV1 => ProfileRole::Gateway,
        }
    }

    pub fn with_role(role: ProfileRole) -> impl Iterator<Item = Self> {
        Self::ALL
            .iter()
            .copied()
            .filter(move |id| id.role() == role)
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::AGENT_AUTH_V1 => Some(Self::AgentAuthV1),
            Self::AGENT_DELEGATION_POLICY_V1 => Some(Self::AgentDelegationPolicyV1),
            Self::AGENT_PARTICIPATION_POLICY_V1 => Some(Self::AgentParticipationPolicyV1),
            Self::AGENT_PROVISIONING_V1 => Some(Self::AgentProvisioningV1),
            Self::AGENT_RUNTIME_V1 => Some(Self::AgentRuntimeV1),
            Self::AGENT_SIDECAR_V1 => Some(Self::AgentSidecarV1),
            Self::AGENT_SIGNER_EVIDENCE_V1 => Some(Self::AgentSignerEvidenceV1),
            Self::APPLET_BRIDGE_V1 => Some(Self::AppletBridgeV1),
            Self::APPLET_DELEGATED_V1 => Some(Self::AppletDelegatedV1),
            Self::APPLET_E2EE_JOIN_V1 => Some(Self::AppletE2eeJoinV1),
            Self::APPLET_SERVICE_V1 => Some(Self::AppletServiceV1),
            Self::APPLET_WIDGET_V1 => Some(Self::AppletWidgetV1),
            Self::BINDING_WEBSOCKET_V1 => Some(Self::BindingWebsocketV1),
            Self::BLOB_NODE_V1 => Some(Self::BlobNodeV1),
            Self::CALENDAR_EVENT_V1 => Some(Self::CalendarEventV1),
            Self::CALENDAR_NOTIFICATION_DISPATCH_V1 => Some(Self::CalendarNotificationDispatchV1),
            Self::CHAT_MVP_V1 => Some(Self::ChatMvpV1),
            Self::CIRCLE_CONFORMANCE_V1 => Some(Self::CircleConformanceV1),
            Self::CONSTRAINT_APPROVAL_WORKFLOW_V1 => Some(Self::ConstraintApprovalWorkflowV1),
            Self::CONSTRAINT_CLAIM_BASED_V1 => Some(Self::ConstraintClaimBasedV1),
            Self::CONSTRAINT_ENCRYPTION_REQUIREMENT_V1 => {
                Some(Self::ConstraintEncryptionRequirementV1)
            }
            Self::CONSTRAINT_RESOURCE_LIMIT_V1 => Some(Self::ConstraintResourceLimitV1),
            Self::CONSTRAINT_VISIBILITY_CONTROL_V1 => Some(Self::ConstraintVisibilityControlV1),
            Self::CORE_EVENT_STORE_V1 => Some(Self::CoreEventStoreV1),
            Self::DIRECT_CONVERSATION_REALM_V1 => Some(Self::DirectConversationRealmV1),
            Self::DIRECT_CONVERSATION_REPAIR_V1 => Some(Self::DirectConversationRepairV1),
            Self::DIRECTORY_SERVICE_V1 => Some(Self::DirectoryServiceV1),
            Self::DRAFT_SYNC_V1 => Some(Self::DraftSyncV1),
            Self::E2EE_CLIENT_V1 => Some(Self::E2eeClientV1),
            Self::ENCODING_CBOR_V1 => Some(Self::EncodingCborV1),
            Self::ENTERPRISE_CLIENT_V1 => Some(Self::EnterpriseClientV1),
            Self::FEDERATION_MINIMAL_V1 => Some(Self::FederationMinimalV1),
            Self::FILE_TRANSFER_V1 => Some(Self::FileTransferV1),
            Self::FRANKING_V1 => Some(Self::FrankingV1),
            Self::FULL_CLIENT_V1 => Some(Self::FullClientV1),
            Self::HASH_BLAKE3_V1 => Some(Self::HashBlake3V1),
            Self::HIGH_SECURITY_ORGANIZATION_V1 => Some(Self::HighSecurityOrganizationV1),
            Self::HPKE_P256_V1 => Some(Self::HpkeP256V1),
            Self::IDENTITY_REGISTRY_V1 => Some(Self::IdentityRegistryV1),
            Self::ISOLATED_SOVEREIGN_NETWORK_V1 => Some(Self::IsolatedSovereignNetworkV1),
            Self::KANBAN_MVP_V1 => Some(Self::KanbanMvpV1),
            Self::KEM_HYBRID_XWING_V1 => Some(Self::KemHybridXwingV1),
            Self::KEY_BACKUP_MEMORY_HARD_V1 => Some(Self::KeyBackupMemoryHardV1),
            Self::KEY_TRANSPARENCY_V1 => Some(Self::KeyTransparencyV1),
            Self::MEDIA_SERVICE_BINDING_ARKRET_NATIVE_V1 => {
                Some(Self::MediaServiceBindingArkretNativeV1)
            }
            Self::MEDIA_SERVICE_BINDING_LIVEKIT_V1 => Some(Self::MediaServiceBindingLivekitV1),
            Self::MEDIA_SERVICE_BINDING_V1 => Some(Self::MediaServiceBindingV1),
            Self::MEMBERSHIP_JOIN_COMPENSATION_V1 => Some(Self::MembershipJoinCompensationV1),
            Self::MIMI_INTEROP_V1 => Some(Self::MimiInteropV1),
            Self::MINIMAL_CLIENT_V1 => Some(Self::MinimalClientV1),
            Self::MLS_CIPHERSUITE_CHACHA20POLY1305_V1 => {
                Some(Self::MlsCiphersuiteChacha20poly1305V1)
            }
            Self::MLS_CIPHERSUITE_PQ_AUTH_V1 => Some(Self::MlsCiphersuitePqAuthV1),
            Self::ORGANIZATION_V1 => Some(Self::OrganizationV1),
            Self::ORGANIZATION_HIGH_ASSURANCE_IDENTITY_V1 => {
                Some(Self::OrganizationHighAssuranceIdentityV1)
            }
            Self::PERSONAL_NODE_V1 => Some(Self::PersonalNodeV1),
            Self::PERSONAL_PRODUCTIVITY_V1 => Some(Self::PersonalProductivityV1),
            Self::PINNED_ITEMS_V1 => Some(Self::PinnedItemsV1),
            Self::PRINCIPAL_CONTROL_REALM_V1 => Some(Self::PrincipalControlRealmV1),
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
            Self::STATION_V1 => Some(Self::StationV1),
            Self::STATION_EVENTS_API_V1 => Some(Self::StationEventsApiV1),
            Self::TRAFFIC_METADATA_HARDENED_V1 => Some(Self::TrafficMetadataHardenedV1),
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
