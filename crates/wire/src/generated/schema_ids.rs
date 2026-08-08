//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/schema-registry.json; version=2026-08-08.9;
//! sha256=7cd8e07f52d701e436a6c2df2a67f5565e6e704f73fd297be061f40985a4b6d4 Entries: schema_ids=183,
//! active=183

use serde::{Deserialize, Serialize};

/// Registered `ak.schema.*` identifiers. Every schema-id literal the
/// SDK ships is spelled exactly once, here; owning wire types alias the
/// associated const as `Type::SCHEMA`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum SchemaId {
    AccountDataEncryptedValueV1,
    AccountDataOperationsV1,
    AccountOperationsV1,
    AccountSubscribeFrameV1,
    AccountabilityGrantV1,
    ActorProfileV1,
    AgentOperationsV1,
    AgentPairingBootstrapV1,
    AgentProvisionV1,
    AgentRequestedScopeDisclosureV1,
    AgentSelectorClaimV1,
    AgentSidecarV1,
    AgentSidecarEventExchangeBindingV1,
    AgentSidecarExchangeControlV1,
    AgentSidecarExchangeProjectionV1,
    AgentSidecarViewStateV1,
    AgentSignerAdmissionReceiptV1,
    AgentSignerEvidenceV1,
    AgentSignerEvidenceBundleV1,
    AgentSignerEvidenceQueryOutcomeV1,
    AgentSignerEvidenceQueryRequestV1,
    AgentSigningKeyBindingV1,
    AppletV1,
    AppletEdgeOperationsV1,
    AppletGhostOperationsV1,
    AppletInstallOperationsV1,
    AppletInstallPlanV1,
    AppletPackageV1,
    AppletRegistrationEpochTranscriptV1,
    AppletWidgetDeclarationV1,
    AuditReleaseAttestationV1,
    AuditRywReceiptV1,
    AuthoritySetPolicyV1,
    AuthzOperationsV1,
    AvailabilityReceiptV1,
    BackupSeriesEraseConfirmationV1,
    BlobV1,
    BlobOperationsV1,
    BottomV1,
    CalendarEventV1,
    CallRecordingArtifactV1,
    CallSignalPlaintextV1,
    CapabilityV1,
    CbaProofBundleV1,
    CircleV1,
    CircleOperationsV1,
    CommonIdsV1,
    ConsentOperationsV1,
    ContactOperationsV1,
    ContactScopeUpdateV1,
    ContentBlockPollV1,
    ControllerAccountGateAttestationV1,
    CrossSigningPublishV1,
    CrossSigningResetV1,
    CursorV1,
    DeliveryBindingStaleV1,
    DeviceMessageV1,
    DevicePairingBootstrapV1,
    DevicePairingOperationsV1,
    DeviceReanchorV1,
    DidBindingContractsV1,
    DidContinuityProofV1,
    DidKeyLogEntryV1,
    DidWebvhWitnessReceiptV1,
    DirectConversationOperationsV1,
    DirectoryOperationsV1,
    DisappearingMessagesV1,
    DraftSyncV1,
    EncryptedEnvelopeV1,
    ErasureReceiptV1,
    ErasureVerificationStubV1,
    EventV1,
    EventBatchReceiptV1,
    EventPayloadV1,
    EventsSubscribeFrameV1,
    ExtensionManifestV1,
    FederatedDeviceSigningKeyEvidenceV1,
    FileTransferV1,
    GrantConstraintV1,
    HandleClaimV1,
    HighRiskAuthorityProofV1,
    IceConfigResponseV1,
    IdentityLinkV1,
    IdentityReceiptV1,
    InclusionListV1,
    InviteV1,
    InviteDeliveryRequestV1,
    InviteReceivePolicyV1,
    JoinPolicyOperationsV1,
    KeyBackupV1,
    KeyBackupActiveSeriesV1,
    KeyBackupPlaintextV1,
    KeyBackupUnlockProofV1,
    KeyTransparencyV1,
    KeypackageOperationsV1,
    KeysOperationsV1,
    ListHandlesForSubjectResponseV1,
    MediaMetadataV1,
    MediaOperationsV1,
    MemberDeliveryBindingCandidateV1,
    MemberIdentityV1,
    MessageV1,
    MimiInteropV1,
    MimiOperationsV1,
    MlsGovernanceProofBundleV1,
    ModerationAppealV1,
    ModerationQueueItemV1,
    ModerationReportV1,
    MorphCustomerRiskExtV1,
    MorphCustomerRiskV1,
    MorphV1,
    NotificationV1,
    ObjectAddressingV1,
    OfflinePublicationV1,
    PatchV1,
    PersonalProductivityV1,
    PinV1,
    PolicyV1,
    PrincipalLocatorV1,
    PrincipalOperationsV1,
    PublicKeyV1,
    PushOperationsV1,
    QueryV1,
    RangeCompletenessAttestationV1,
    ReadCursorV1,
    ReadCursorOperationsV1,
    ReadReceiptV1,
    RealmV1,
    RealmGenesisV1,
    RealmJoinCandidateV1,
    RealmLinkOperationsV1,
    RealmOrganizationOperationsV1,
    RealmPolicyServerOperationsV1,
    RealmProfileV1,
    RealmReadOperationsV1,
    RecoveryAuthorityTicketV1,
    RecoveryCompletionAttestationV1,
    RecoveryPolicyV1,
    RecoveryReceiptV1,
    RecoverySessionV1,
    RelationV1,
    ResourceSelectorV1,
    RsvpV1,
    SdkConformanceClaimV1,
    SealV1,
    SealTransparencyV1,
    SearchServiceV1,
    SecurityRotationLocalCommitV1,
    SecurityTransactionV1,
    ServiceDescribeV1,
    ServiceOperationDtosV1,
    SignalEnvelopeV1,
    SignalMessageStreamV1,
    SignalPresenceV1,
    SignalRelayV1,
    SignalStreamFrameV1,
    SignalTypingV1,
    SnapshotV1,
    SpaceV1,
    StrandV1,
    StringProfilesV1,
    TimeV1,
    TransportBindingV1,
    ViewV1,
    WebsocketAuthenticateFrameV1,
    WebsocketChallengeFrameV1,
    WebsocketClientFrameV1,
    WebsocketCloseFrameV1,
    WebsocketClosedFrameV1,
    WebsocketControlFrameV1,
    WebsocketDataFrameV1,
    WebsocketDpopClaimsV1,
    WebsocketDpopProofV1,
    WebsocketDpopProtectedHeaderV1,
    WebsocketErrorFrameV1,
    WebsocketFrameV1,
    WebsocketOpenFrameV1,
    WebsocketOpenedFrameV1,
    WebsocketPingFrameV1,
    WebsocketPongFrameV1,
    WebsocketReauthRequiredFrameV1,
    WebsocketServerFrameV1,
    WebsocketWelcomeFrameV1,
}

impl SchemaId {
    pub const ALL: &'static [Self] = &[
        Self::AccountDataEncryptedValueV1,
        Self::AccountDataOperationsV1,
        Self::AccountOperationsV1,
        Self::AccountSubscribeFrameV1,
        Self::AccountabilityGrantV1,
        Self::ActorProfileV1,
        Self::AgentOperationsV1,
        Self::AgentPairingBootstrapV1,
        Self::AgentProvisionV1,
        Self::AgentRequestedScopeDisclosureV1,
        Self::AgentSelectorClaimV1,
        Self::AgentSidecarV1,
        Self::AgentSidecarEventExchangeBindingV1,
        Self::AgentSidecarExchangeControlV1,
        Self::AgentSidecarExchangeProjectionV1,
        Self::AgentSidecarViewStateV1,
        Self::AgentSignerAdmissionReceiptV1,
        Self::AgentSignerEvidenceV1,
        Self::AgentSignerEvidenceBundleV1,
        Self::AgentSignerEvidenceQueryOutcomeV1,
        Self::AgentSignerEvidenceQueryRequestV1,
        Self::AgentSigningKeyBindingV1,
        Self::AppletV1,
        Self::AppletEdgeOperationsV1,
        Self::AppletGhostOperationsV1,
        Self::AppletInstallOperationsV1,
        Self::AppletInstallPlanV1,
        Self::AppletPackageV1,
        Self::AppletRegistrationEpochTranscriptV1,
        Self::AppletWidgetDeclarationV1,
        Self::AuditReleaseAttestationV1,
        Self::AuditRywReceiptV1,
        Self::AuthoritySetPolicyV1,
        Self::AuthzOperationsV1,
        Self::AvailabilityReceiptV1,
        Self::BackupSeriesEraseConfirmationV1,
        Self::BlobV1,
        Self::BlobOperationsV1,
        Self::BottomV1,
        Self::CalendarEventV1,
        Self::CallRecordingArtifactV1,
        Self::CallSignalPlaintextV1,
        Self::CapabilityV1,
        Self::CbaProofBundleV1,
        Self::CircleV1,
        Self::CircleOperationsV1,
        Self::CommonIdsV1,
        Self::ConsentOperationsV1,
        Self::ContactOperationsV1,
        Self::ContactScopeUpdateV1,
        Self::ContentBlockPollV1,
        Self::ControllerAccountGateAttestationV1,
        Self::CrossSigningPublishV1,
        Self::CrossSigningResetV1,
        Self::CursorV1,
        Self::DeliveryBindingStaleV1,
        Self::DeviceMessageV1,
        Self::DevicePairingBootstrapV1,
        Self::DevicePairingOperationsV1,
        Self::DeviceReanchorV1,
        Self::DidBindingContractsV1,
        Self::DidContinuityProofV1,
        Self::DidKeyLogEntryV1,
        Self::DidWebvhWitnessReceiptV1,
        Self::DirectConversationOperationsV1,
        Self::DirectoryOperationsV1,
        Self::DisappearingMessagesV1,
        Self::DraftSyncV1,
        Self::EncryptedEnvelopeV1,
        Self::ErasureReceiptV1,
        Self::ErasureVerificationStubV1,
        Self::EventV1,
        Self::EventBatchReceiptV1,
        Self::EventPayloadV1,
        Self::EventsSubscribeFrameV1,
        Self::ExtensionManifestV1,
        Self::FederatedDeviceSigningKeyEvidenceV1,
        Self::FileTransferV1,
        Self::GrantConstraintV1,
        Self::HandleClaimV1,
        Self::HighRiskAuthorityProofV1,
        Self::IceConfigResponseV1,
        Self::IdentityLinkV1,
        Self::IdentityReceiptV1,
        Self::InclusionListV1,
        Self::InviteV1,
        Self::InviteDeliveryRequestV1,
        Self::InviteReceivePolicyV1,
        Self::JoinPolicyOperationsV1,
        Self::KeyBackupV1,
        Self::KeyBackupActiveSeriesV1,
        Self::KeyBackupPlaintextV1,
        Self::KeyBackupUnlockProofV1,
        Self::KeyTransparencyV1,
        Self::KeypackageOperationsV1,
        Self::KeysOperationsV1,
        Self::ListHandlesForSubjectResponseV1,
        Self::MediaMetadataV1,
        Self::MediaOperationsV1,
        Self::MemberDeliveryBindingCandidateV1,
        Self::MemberIdentityV1,
        Self::MessageV1,
        Self::MimiInteropV1,
        Self::MimiOperationsV1,
        Self::MlsGovernanceProofBundleV1,
        Self::ModerationAppealV1,
        Self::ModerationQueueItemV1,
        Self::ModerationReportV1,
        Self::MorphCustomerRiskExtV1,
        Self::MorphCustomerRiskV1,
        Self::MorphV1,
        Self::NotificationV1,
        Self::ObjectAddressingV1,
        Self::OfflinePublicationV1,
        Self::PatchV1,
        Self::PersonalProductivityV1,
        Self::PinV1,
        Self::PolicyV1,
        Self::PrincipalLocatorV1,
        Self::PrincipalOperationsV1,
        Self::PublicKeyV1,
        Self::PushOperationsV1,
        Self::QueryV1,
        Self::RangeCompletenessAttestationV1,
        Self::ReadCursorV1,
        Self::ReadCursorOperationsV1,
        Self::ReadReceiptV1,
        Self::RealmV1,
        Self::RealmGenesisV1,
        Self::RealmJoinCandidateV1,
        Self::RealmLinkOperationsV1,
        Self::RealmOrganizationOperationsV1,
        Self::RealmPolicyServerOperationsV1,
        Self::RealmProfileV1,
        Self::RealmReadOperationsV1,
        Self::RecoveryAuthorityTicketV1,
        Self::RecoveryCompletionAttestationV1,
        Self::RecoveryPolicyV1,
        Self::RecoveryReceiptV1,
        Self::RecoverySessionV1,
        Self::RelationV1,
        Self::ResourceSelectorV1,
        Self::RsvpV1,
        Self::SdkConformanceClaimV1,
        Self::SealV1,
        Self::SealTransparencyV1,
        Self::SearchServiceV1,
        Self::SecurityRotationLocalCommitV1,
        Self::SecurityTransactionV1,
        Self::ServiceDescribeV1,
        Self::ServiceOperationDtosV1,
        Self::SignalEnvelopeV1,
        Self::SignalMessageStreamV1,
        Self::SignalPresenceV1,
        Self::SignalRelayV1,
        Self::SignalStreamFrameV1,
        Self::SignalTypingV1,
        Self::SnapshotV1,
        Self::SpaceV1,
        Self::StrandV1,
        Self::StringProfilesV1,
        Self::TimeV1,
        Self::TransportBindingV1,
        Self::ViewV1,
        Self::WebsocketAuthenticateFrameV1,
        Self::WebsocketChallengeFrameV1,
        Self::WebsocketClientFrameV1,
        Self::WebsocketCloseFrameV1,
        Self::WebsocketClosedFrameV1,
        Self::WebsocketControlFrameV1,
        Self::WebsocketDataFrameV1,
        Self::WebsocketDpopClaimsV1,
        Self::WebsocketDpopProofV1,
        Self::WebsocketDpopProtectedHeaderV1,
        Self::WebsocketErrorFrameV1,
        Self::WebsocketFrameV1,
        Self::WebsocketOpenFrameV1,
        Self::WebsocketOpenedFrameV1,
        Self::WebsocketPingFrameV1,
        Self::WebsocketPongFrameV1,
        Self::WebsocketReauthRequiredFrameV1,
        Self::WebsocketServerFrameV1,
        Self::WebsocketWelcomeFrameV1,
    ];

    /// Rows the registry declares `active`; excludes `candidate` rows.
    pub const ACTIVE: &'static [Self] = &[
        Self::AccountDataEncryptedValueV1,
        Self::AccountDataOperationsV1,
        Self::AccountOperationsV1,
        Self::AccountSubscribeFrameV1,
        Self::AccountabilityGrantV1,
        Self::ActorProfileV1,
        Self::AgentOperationsV1,
        Self::AgentPairingBootstrapV1,
        Self::AgentProvisionV1,
        Self::AgentRequestedScopeDisclosureV1,
        Self::AgentSelectorClaimV1,
        Self::AgentSidecarV1,
        Self::AgentSidecarEventExchangeBindingV1,
        Self::AgentSidecarExchangeControlV1,
        Self::AgentSidecarExchangeProjectionV1,
        Self::AgentSidecarViewStateV1,
        Self::AgentSignerAdmissionReceiptV1,
        Self::AgentSignerEvidenceV1,
        Self::AgentSignerEvidenceBundleV1,
        Self::AgentSignerEvidenceQueryOutcomeV1,
        Self::AgentSignerEvidenceQueryRequestV1,
        Self::AgentSigningKeyBindingV1,
        Self::AppletV1,
        Self::AppletEdgeOperationsV1,
        Self::AppletGhostOperationsV1,
        Self::AppletInstallOperationsV1,
        Self::AppletInstallPlanV1,
        Self::AppletPackageV1,
        Self::AppletRegistrationEpochTranscriptV1,
        Self::AppletWidgetDeclarationV1,
        Self::AuditReleaseAttestationV1,
        Self::AuditRywReceiptV1,
        Self::AuthoritySetPolicyV1,
        Self::AuthzOperationsV1,
        Self::AvailabilityReceiptV1,
        Self::BackupSeriesEraseConfirmationV1,
        Self::BlobV1,
        Self::BlobOperationsV1,
        Self::BottomV1,
        Self::CalendarEventV1,
        Self::CallRecordingArtifactV1,
        Self::CallSignalPlaintextV1,
        Self::CapabilityV1,
        Self::CbaProofBundleV1,
        Self::CircleV1,
        Self::CircleOperationsV1,
        Self::CommonIdsV1,
        Self::ConsentOperationsV1,
        Self::ContactOperationsV1,
        Self::ContactScopeUpdateV1,
        Self::ContentBlockPollV1,
        Self::ControllerAccountGateAttestationV1,
        Self::CrossSigningPublishV1,
        Self::CrossSigningResetV1,
        Self::CursorV1,
        Self::DeliveryBindingStaleV1,
        Self::DeviceMessageV1,
        Self::DevicePairingBootstrapV1,
        Self::DevicePairingOperationsV1,
        Self::DeviceReanchorV1,
        Self::DidBindingContractsV1,
        Self::DidContinuityProofV1,
        Self::DidKeyLogEntryV1,
        Self::DidWebvhWitnessReceiptV1,
        Self::DirectConversationOperationsV1,
        Self::DirectoryOperationsV1,
        Self::DisappearingMessagesV1,
        Self::DraftSyncV1,
        Self::EncryptedEnvelopeV1,
        Self::ErasureReceiptV1,
        Self::ErasureVerificationStubV1,
        Self::EventV1,
        Self::EventBatchReceiptV1,
        Self::EventPayloadV1,
        Self::EventsSubscribeFrameV1,
        Self::ExtensionManifestV1,
        Self::FederatedDeviceSigningKeyEvidenceV1,
        Self::FileTransferV1,
        Self::GrantConstraintV1,
        Self::HandleClaimV1,
        Self::HighRiskAuthorityProofV1,
        Self::IceConfigResponseV1,
        Self::IdentityLinkV1,
        Self::IdentityReceiptV1,
        Self::InclusionListV1,
        Self::InviteV1,
        Self::InviteDeliveryRequestV1,
        Self::InviteReceivePolicyV1,
        Self::JoinPolicyOperationsV1,
        Self::KeyBackupV1,
        Self::KeyBackupActiveSeriesV1,
        Self::KeyBackupPlaintextV1,
        Self::KeyBackupUnlockProofV1,
        Self::KeyTransparencyV1,
        Self::KeypackageOperationsV1,
        Self::KeysOperationsV1,
        Self::ListHandlesForSubjectResponseV1,
        Self::MediaMetadataV1,
        Self::MediaOperationsV1,
        Self::MemberDeliveryBindingCandidateV1,
        Self::MemberIdentityV1,
        Self::MessageV1,
        Self::MimiInteropV1,
        Self::MimiOperationsV1,
        Self::MlsGovernanceProofBundleV1,
        Self::ModerationAppealV1,
        Self::ModerationQueueItemV1,
        Self::ModerationReportV1,
        Self::MorphCustomerRiskExtV1,
        Self::MorphCustomerRiskV1,
        Self::MorphV1,
        Self::NotificationV1,
        Self::ObjectAddressingV1,
        Self::OfflinePublicationV1,
        Self::PatchV1,
        Self::PersonalProductivityV1,
        Self::PinV1,
        Self::PolicyV1,
        Self::PrincipalLocatorV1,
        Self::PrincipalOperationsV1,
        Self::PublicKeyV1,
        Self::PushOperationsV1,
        Self::QueryV1,
        Self::RangeCompletenessAttestationV1,
        Self::ReadCursorV1,
        Self::ReadCursorOperationsV1,
        Self::ReadReceiptV1,
        Self::RealmV1,
        Self::RealmGenesisV1,
        Self::RealmJoinCandidateV1,
        Self::RealmLinkOperationsV1,
        Self::RealmOrganizationOperationsV1,
        Self::RealmPolicyServerOperationsV1,
        Self::RealmProfileV1,
        Self::RealmReadOperationsV1,
        Self::RecoveryAuthorityTicketV1,
        Self::RecoveryCompletionAttestationV1,
        Self::RecoveryPolicyV1,
        Self::RecoveryReceiptV1,
        Self::RecoverySessionV1,
        Self::RelationV1,
        Self::ResourceSelectorV1,
        Self::RsvpV1,
        Self::SdkConformanceClaimV1,
        Self::SealV1,
        Self::SealTransparencyV1,
        Self::SearchServiceV1,
        Self::SecurityRotationLocalCommitV1,
        Self::SecurityTransactionV1,
        Self::ServiceDescribeV1,
        Self::ServiceOperationDtosV1,
        Self::SignalEnvelopeV1,
        Self::SignalMessageStreamV1,
        Self::SignalPresenceV1,
        Self::SignalRelayV1,
        Self::SignalStreamFrameV1,
        Self::SignalTypingV1,
        Self::SnapshotV1,
        Self::SpaceV1,
        Self::StrandV1,
        Self::StringProfilesV1,
        Self::TimeV1,
        Self::TransportBindingV1,
        Self::ViewV1,
        Self::WebsocketAuthenticateFrameV1,
        Self::WebsocketChallengeFrameV1,
        Self::WebsocketClientFrameV1,
        Self::WebsocketCloseFrameV1,
        Self::WebsocketClosedFrameV1,
        Self::WebsocketControlFrameV1,
        Self::WebsocketDataFrameV1,
        Self::WebsocketDpopClaimsV1,
        Self::WebsocketDpopProofV1,
        Self::WebsocketDpopProtectedHeaderV1,
        Self::WebsocketErrorFrameV1,
        Self::WebsocketFrameV1,
        Self::WebsocketOpenFrameV1,
        Self::WebsocketOpenedFrameV1,
        Self::WebsocketPingFrameV1,
        Self::WebsocketPongFrameV1,
        Self::WebsocketReauthRequiredFrameV1,
        Self::WebsocketServerFrameV1,
        Self::WebsocketWelcomeFrameV1,
    ];

    /// Closed XChaCha20-Poly1305 envelope for principal-private encrypted Account Data values.
    pub const ACCOUNT_DATA_ENCRYPTED_VALUE_V1: &'static str =
        "ak.schema.account_data_encrypted_value.v1";
    /// Closed request/response DTO bundle for self-surface actor-private account_data operations
    /// (ak.self.account_data.*); see zh/discovery/client-preferences.md.
    pub const ACCOUNT_DATA_OPERATIONS_V1: &'static str = "ak.schema.account_data_operations.v1";
    /// Closed request/response DTO bundle for account self-service operations: viewer, register,
    /// profile update, and session revocation.
    pub const ACCOUNT_OPERATIONS_V1: &'static str = "ak.schema.account_operations.v1";
    pub const ACCOUNT_SUBSCRIBE_FRAME_V1: &'static str = "ak.schema.account_subscribe_frame.v1";
    /// Issuer-signed accountability endorsement for Actor Profile accountable_principal_ids
    /// verification.
    pub const ACCOUNTABILITY_GRANT_V1: &'static str = "ak.schema.accountability_grant.v1";
    pub const ACTOR_PROFILE_V1: &'static str = "ak.schema.actor_profile.v1";
    /// Closed request/response DTO bundle for account pairing and native personal agent management
    /// operations.
    pub const AGENT_OPERATIONS_V1: &'static str = "ak.schema.agent_operations.v1";
    /// One-time bootstrap DTO for personal agent runtime pairing. Resolves to the sub-schema at
    /// file + fragment (agent-operations.schema.json#/$defs/agent_pairing_bootstrap), not the
    /// top-level oneOf DTO bundle that ak.schema.agent_operations.v1 maps to.
    pub const AGENT_PAIRING_BOOTSTRAP_V1: &'static str = "ak.schema.agent_pairing_bootstrap.v1";
    /// Single controller-authored native personal Agent provisioning payload with atomic
    /// accountability and selector projections.
    pub const AGENT_PROVISION_V1: &'static str = "ak.schema.agent_provision.v1";
    /// Controller-signed, verifier-bound private disclosure of a managed Agent's immutable
    /// requested_scope; the public Agent DID carries only its commitment digest.
    pub const AGENT_REQUESTED_SCOPE_DISCLOSURE_V1: &'static str =
        "ak.schema.agent_requested_scope_disclosure.v1";
    /// Signed controller-scoped native personal agent selector claim for
    /// @&lt;controller-handle&gt;/&lt;agent_slug&gt; resolution.
    pub const AGENT_SELECTOR_CLAIM_V1: &'static str = "ak.schema.agent_selector_claim.v1";
    /// Controller-owned private AI workspace with native Sidecar scope and ownership-derived Agent
    /// access. It is not a Circle profile and has no backing Circle or editable membership. See
    /// zh/models/sidecar.md.
    pub const AGENT_SIDECAR_V1: &'static str = "ak.schema.agent_sidecar.v1";
    /// Closed exchange binding inside the encrypted metadata plaintext of Sidecar-scoped Message
    /// events. Sole normative declaration of explicit user-facing/internal response disposition.
    /// Never legal in plaintext metadata or shared Realm/Circle events. See zh/models/sidecar.md
    /// section 7.2.1.
    pub const AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1: &'static str =
        "ak.schema.agent_sidecar_event_exchange_binding.v1";
    /// Closed plaintext encrypted by ak.agent.sidecar.exchange.control. Sole durable source of
    /// Sidecar exchange coordinator reassignment and terminal state.
    pub const AGENT_SIDECAR_EXCHANGE_CONTROL_V1: &'static str =
        "ak.schema.agent_sidecar_exchange_control.v1";
    /// Disposable controller-device-local Event-fold cache for one source-routed Sidecar exchange.
    /// Not Account Data or wire truth.
    pub const AGENT_SIDECAR_EXCHANGE_PROJECTION_V1: &'static str =
        "ak.schema.agent_sidecar_exchange_projection.v1";
    /// Controller-private encrypted account-data plaintext for per-context Sidecar display mode and
    /// hosted-view state.
    pub const AGENT_SIDECAR_VIEW_STATE_V1: &'static str = "ak.schema.agent_sidecar_view_state.v1";
    /// Destination-signed immutable receipt for the exact Native Agent signer evidence used when
    /// one Event was accepted.
    pub const AGENT_SIGNER_ADMISSION_RECEIPT_V1: &'static str =
        "ak.schema.agent_signer_admission_receipt.v1";
    /// Portable Native Agent signer authorization, state-witness, and freshness evidence used
    /// outside the ordinary device directory.
    pub const AGENT_SIGNER_EVIDENCE_V1: &'static str = "ak.schema.agent_signer_evidence.v1";
    /// Deduplicated transport-level Agent signer evidence bundle shared by sync, backfill, and
    /// federation.
    pub const AGENT_SIGNER_EVIDENCE_BUNDLE_V1: &'static str =
        "ak.schema.agent_signer_evidence_bundle.v1";
    /// Closed outcome carrying portable Agent signer evidence or non-enumerating per-selector
    /// failures.
    pub const AGENT_SIGNER_EVIDENCE_QUERY_OUTCOME_V1: &'static str =
        "ak.schema.agent_signer_evidence_query_outcome.v1";
    /// Authenticated shared-context Agent signer evidence query request.
    pub const AGENT_SIGNER_EVIDENCE_QUERY_REQUEST_V1: &'static str =
        "ak.schema.agent_signer_evidence_query_request.v1";
    /// Controller-signed minimal public binding from a Native Agent verification method to raw
    /// Ed25519 key material and one accepted Agent key authorization.
    pub const AGENT_SIGNING_KEY_BINDING_V1: &'static str = "ak.schema.agent_signing_key_binding.v1";
    /// Schema-registry object for applet protocol metadata snapshots. Event payloads for
    /// ak.applet.* use typed payload definitions in event-payload.schema.json.
    pub const APPLET_V1: &'static str = "ak.schema.applet.v1";
    /// Closed request/response DTO bundle for Applet edge and bridge operations.
    pub const APPLET_EDGE_OPERATIONS_V1: &'static str = "ak.schema.applet_edge_operations.v1";
    /// Closed request/response DTO bundle for ak.self.applet.ghost.command.provision
    /// (Applet-managed Ghost Actor provisioning by an installed bridge Applet).
    pub const APPLET_GHOST_OPERATIONS_V1: &'static str = "ak.schema.applet_ghost_operations.v1";
    /// Closed request/response DTO bundle for ak.self.applet.install.command.preview and
    /// ak.applet.install.
    pub const APPLET_INSTALL_OPERATIONS_V1: &'static str = "ak.schema.applet_install_operations.v1";
    /// Canonical Applet InstallPlan returned by ak.self.applet.install.command.preview and
    /// recomputed by ak.self.applet.command.install before commit. plan_digest is calculated over
    /// this object with plan_digest omitted.
    pub const APPLET_INSTALL_PLAN_V1: &'static str = "ak.schema.applet_install_plan.v1";
    /// Controller-signed package used by ak.self.applet.command.install preview/commit to derive
    /// ak.applet.registration and capability grants. Distribution object only; not Realm history
    /// truth and not authorization.
    pub const APPLET_PACKAGE_V1: &'static str = "ak.schema.applet_package.v1";
    /// Closed normalized transcript for deterministic recomputation of Applet registration_epoch
    /// from derived registration, DID document/version, signing-key, endpoint/auth, and
    /// security-policy evidence.
    pub const APPLET_REGISTRATION_EPOCH_TRANSCRIPT_V1: &'static str =
        "ak.schema.applet_registration_epoch_transcript.v1";
    /// Closed declaration for Applet UI widget origin, CSP, scoped token capability scope, and
    /// consent gate.
    pub const APPLET_WIDGET_DECLARATION_V1: &'static str = "ak.schema.applet_widget_declaration.v1";
    pub const AUDIT_RELEASE_ATTESTATION_V1: &'static str = "ak.schema.audit_release_attestation.v1";
    pub const AUDIT_RYW_RECEIPT_V1: &'static str = "ak.schema.audit_ryw_receipt.v1";
    /// Canonical concrete authority policy rederived from accepted CBA control state and bound by
    /// AuthoritySetRef.
    pub const AUTHORITY_SET_POLICY_V1: &'static str = "ak.schema.authority_set_policy.v1";
    /// Closed response DTO bundle for authorization query operations.
    pub const AUTHZ_OPERATIONS_V1: &'static str = "ak.schema.authz_operations.v1";
    /// Signed holder commitment that Event bytes are available until retention_expires_at; used by
    /// CBA Seal availability_root.
    pub const AVAILABILITY_RECEIPT_V1: &'static str = "ak.schema.availability_receipt.v1";
    /// Immutable transaction-bound completion artifact proving all planned old secret_storage and
    /// mls_history backup objects were erased after authoritative pointer switch.
    pub const BACKUP_SERIES_ERASE_CONFIRMATION_V1: &'static str =
        "ak.schema.backup_series_erase_confirmation.v1";
    pub const BLOB_V1: &'static str = "ak.schema.blob.v1";
    /// Closed request/response DTO bundle for Blob service operations.
    pub const BLOB_OPERATIONS_V1: &'static str = "ak.schema.blob_operations.v1";
    /// Structured Bottom (⊥) diagnostic surfaced on /account/subscribe, /events, and state query
    /// responses when a cell's effective Lattice value is undefined
    pub const BOTTOM_V1: &'static str = "ak.schema.bottom.v1";
    /// Profile fields for calendar-event Strands.
    pub const CALENDAR_EVENT_V1: &'static str = "ak.schema.calendar_event.v1";
    /// Canonical metadata for call recording artifacts after Arkret blob pipeline ingestion,
    /// including recording exporter context, retention policy and deletion audit binding.
    pub const CALL_RECORDING_ARTIFACT_V1: &'static str = "ak.schema.call_recording_artifact.v1";
    /// Closed top-level E2EE plaintext for ak.call.signal, with signal_kind-specific data
    /// validation defined by the WebRTC signaling profile.
    pub const CALL_SIGNAL_PLAINTEXT_V1: &'static str = "ak.schema.call_signal_plaintext.v1";
    pub const CAPABILITY_V1: &'static str = "ak.schema.capability.v1";
    /// Unsigned, independently verified CBA dependency bundle.
    pub const CBA_PROOF_BUNDLE_V1: &'static str = "ak.schema.cba_proof_bundle.v1";
    /// Circle — intra-Realm scoped event/message boundary. Subset membership, independent history
    /// visibility, delivery/query/projection boundary, and optional independent MLS group. Does NOT
    /// carry federation identity or policy server. see zh/models/circle.md.
    pub const CIRCLE_V1: &'static str = "ak.schema.circle.v1";
    /// Closed request/response DTO bundle for self-surface Circle administration operations
    /// (ak.self.circle.*); see zh/models/circle.md.
    pub const CIRCLE_OPERATIONS_V1: &'static str = "ak.schema.circle_operations.v1";
    /// Defs-only shared typed-ID patterns (e.g. circle_id) referenced cross-file by morph and
    /// relation schemas so a single id-form change propagates without inline drift. Not an
    /// object/event schema. See zh/models/common-fields.md §6.
    pub const COMMON_IDS_V1: &'static str = "ak.schema.common_ids.v1";
    /// Closed request/response DTO bundle for self-surface holder-private consent cell operations
    /// (ak.self.consent.*); see zh/identity/consent-model.md.
    pub const CONSENT_OPERATIONS_V1: &'static str = "ak.schema.consent_operations.v1";
    /// Closed request/response DTO bundle for the Contact lifecycle: request, respond, reject,
    /// scope replacement, tombstone, the portable basis evidence bundle, acceptance receipts and
    /// the peer Contact carrier, plus the contact-list projection.
    pub const CONTACT_OPERATIONS_V1: &'static str = "ak.schema.contact_operations.v1";
    /// Closed holder-signed Contact scope replacement payload, including the peer XOR, stable
    /// basis, version, predecessor and full granted-scope set.
    pub const CONTACT_SCOPE_UPDATE_V1: &'static str = "ak.schema.contact_scope_update.v1";
    /// Canonical content-block schema for ak.content.poll and ak.content.poll.response.
    pub const CONTENT_BLOCK_POLL_V1: &'static str = "ak.schema.content_block_poll.v1";
    /// Privacy-minimal Account Authority attestation of the controller principal lifecycle gate;
    /// never carries service-local account identity or a raw account cell.
    pub const CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1: &'static str =
        "ak.schema.controller_account_gate_attestation.v1";
    /// Wire payload schema for ak.cross_signing.publish — establishes the PSK→{SSK, USK} binding on
    /// the principal control stream. See device-lifecycle.md §5.1.
    pub const CROSS_SIGNING_PUBLISH_V1: &'static str = "ak.schema.cross_signing_publish.v1";
    /// Wire payload schema for ak.cross_signing.reset — retires the current (SSK, USK) generation
    /// under one of four kinds of high-risk proof. See device-lifecycle.md §14.1.
    pub const CROSS_SIGNING_RESET_V1: &'static str = "ak.schema.cross_signing_reset.v1";
    pub const CURSOR_V1: &'static str = "ak.schema.cursor.v1";
    /// Canonical response body for the delivery_binding_stale federation signal (member
    /// delivery-binding rebind handover): new_recipient_service_id, handover_frontier, and the
    /// verifiable handover_proof. See zh/sync/federation.md §4.1 and error-code-registry.json
    /// (delivery_binding_stale / delivery_binding_handover_proof_invalid).
    pub const DELIVERY_BINDING_STALE_V1: &'static str = "ak.schema.delivery_binding_stale.v1";
    pub const DEVICE_MESSAGE_V1: &'static str = "ak.schema.device_message.v1";
    /// Pairing material DTO handed to an already-authorized device after resolving a device-pairing
    /// short link. Resolves to the sub-schema at file + fragment
    /// (device-pairing.schema.json#/$defs/device_pairing_bootstrap), not the top-level oneOf DTO
    /// bundle that ak.schema.device_pairing_operations.v1 maps to.
    pub const DEVICE_PAIRING_BOOTSTRAP_V1: &'static str = "ak.schema.device_pairing_bootstrap.v1";
    /// Closed request/response DTO bundle for the server-mediated device-pairing short-link handoff
    /// (stage / resolve / status). See device-lifecycle.md §2.1.1.
    pub const DEVICE_PAIRING_OPERATIONS_V1: &'static str = "ak.schema.device_pairing_operations.v1";
    /// Closed B-model recovery re-anchor payload binding one verified DID version, the complete
    /// pre-fence Seal frontier, and the exact replacement device authorization event id/digest.
    pub const DEVICE_REANCHOR_V1: &'static str = "ak.schema.device_reanchor.v1";
    /// Verified DID binding contracts behind identity/did-usage-and-verification.md §5: canonical
    /// evidence receipt (evidence_digest), canonical resolver policy snapshot (policy_digest),
    /// mechanically extracted evidence dependency record, per-pin limited-trust record, and the
    /// freshness profile row every authority call site references.
    pub const DID_BINDING_CONTRACTS_V1: &'static str = "ak.schema.did_binding_contracts.v1";
    /// Signed DID continuity / migration proof payload
    pub const DID_CONTINUITY_PROOF_V1: &'static str = "ak.schema.did_continuity_proof.v1";
    pub const DID_KEY_LOG_ENTRY_V1: &'static str = "ak.schema.did_key_log_entry.v1";
    /// Arkret-layer record that a named did:webvh witness was observed attesting a specific log
    /// versionId. Separate object family from ak.schema.identity_receipt.v1, whose witness_role
    /// describes a DID registry consensus role rather than a method-native witness; both are
    /// returned by ak.root.identity.receipts.read.list as a tagged union discriminated on schema.
    /// Never substitutes for verifying the standard did-witness.json proofs.
    pub const DID_WEBVH_WITNESS_RECEIPT_V1: &'static str = "ak.schema.did_webvh_witness_receipt.v1";
    /// Closed carriers for the Direct Conversation resolver and single-sided founding: the
    /// query-only resolve request and tagged outcome, permanent coordinates, the resolver blocker
    /// set and the source founding acceptance receipt.
    pub const DIRECT_CONVERSATION_OPERATIONS_V1: &'static str =
        "ak.schema.direct_conversation_operations.v1";
    /// Closed request/response DTO bundle for Directory discovery search, resolve, private contact
    /// discovery, handle lookup, agent selector lookup, and push webhook registration operations.
    pub const DIRECTORY_OPERATIONS_V1: &'static str = "ak.schema.directory_operations.v1";
    /// Message expiry and Realm disappearing-message policy shape.
    pub const DISAPPEARING_MESSAGES_V1: &'static str = "ak.schema.disappearing_messages.v1";
    /// Encrypted account-data plaintext shape for cross-device draft sync.
    pub const DRAFT_SYNC_V1: &'static str = "ak.schema.draft_sync.v1";
    pub const ENCRYPTED_ENVELOPE_V1: &'static str = "ak.schema.encrypted_envelope.v1";
    /// Signed hard-erasure receipt payload for ak.audit.erasure_receipt
    pub const ERASURE_RECEIPT_V1: &'static str = "ak.schema.erasure_receipt.v1";
    /// Minimal retained verification stub bound by erasure-receipt.retained_stub_digest
    pub const ERASURE_VERIFICATION_STUB_V1: &'static str = "ak.schema.erasure_verification_stub.v1";
    pub const EVENT_V1: &'static str = "ak.schema.event.v1";
    pub const EVENT_BATCH_RECEIPT_V1: &'static str = "ak.schema.event_batch_receipt.v1";
    pub const EVENT_PAYLOAD_V1: &'static str = "ak.schema.event_payload.v1";
    /// Closed data/control frame union for ak.self.events.stream.subscribe.
    pub const EVENTS_SUBSCRIBE_FRAME_V1: &'static str = "ak.schema.events_subscribe_frame.v1";
    /// Declarative extension loading and conformance manifest.
    pub const EXTENSION_MANIFEST_V1: &'static str = "ak.schema.extension_manifest.v1";
    /// Portable service-attested device authorization evidence reused by peer Event, contact fact,
    /// and KeyPackage claim transports. The original ak.device.authorize Event anchors the key in
    /// the DID-designated enrollment authority; the source Principal Server attests current
    /// lifecycle freshness.
    pub const FEDERATED_DEVICE_SIGNING_KEY_EVIDENCE_V1: &'static str =
        "ak.schema.federated_device_signing_key_evidence.v1";
    /// Encrypted account-data plaintext shape and to-device key message content for
    /// principal-private cross-device file transfer.
    pub const FILE_TRANSFER_V1: &'static str = "ak.schema.file_transfer.v1";
    pub const GRANT_CONSTRAINT_V1: &'static str = "ak.schema.grant_constraint.v1";
    pub const HANDLE_CLAIM_V1: &'static str = "ak.schema.handle_claim.v1";
    /// Shared high-risk authority proof family (principal_signing / device_quorum /
    /// trusted_recovery_service) over an operation's canonical transcript, each branch reusing the
    /// common detached-JWS leaf. First consumer: active-series key backup tail deletion
    /// (key-management.md §7.8).
    pub const HIGH_RISK_AUTHORITY_PROOF_V1: &'static str = "ak.schema.high_risk_authority_proof.v1";
    pub const ICE_CONFIG_RESPONSE_V1: &'static str = "ak.schema.ice_config_response.v1";
    /// Encrypted minimal-metadata binding from Realm-scoped pairwise DID to principal DID, scoped
    /// by realm_id and trust_domain.
    pub const IDENTITY_LINK_V1: &'static str = "ak.schema.identity_link.v1";
    pub const IDENTITY_RECEIPT_V1: &'static str = "ak.schema.identity_receipt.v1";
    /// FOCIL-style control-plane inclusion list signed by a non-proposer notary signer; the next
    /// Seal MUST include, signed-reject, or prove verification failure for every listed digest
    pub const INCLUSION_LIST_V1: &'static str = "ak.schema.inclusion_list.v1";
    pub const INVITE_V1: &'static str = "ak.schema.invite.v1";
    /// Private service-to-service invite delivery request carrying invite_address and
    /// introduction_evidence.
    pub const INVITE_DELIVERY_REQUEST_V1: &'static str = "ak.schema.invite_delivery_request.v1";
    /// Subject-private invite receive policy controlling which introduction evidence kinds may
    /// notify the holder.
    pub const INVITE_RECEIVE_POLICY_V1: &'static str = "ak.schema.invite_receive_policy.v1";
    /// Closed profile-private request/response and signed receipt DTO bundle for
    /// ak.profile.candidate.join_policy.v1. Candidate receipts never become Event.kind values or
    /// shared Realm history.
    pub const JOIN_POLICY_OPERATIONS_V1: &'static str = "ak.schema.join_policy_operations.v1";
    pub const KEY_BACKUP_V1: &'static str = "ak.schema.key_backup.v1";
    /// Signed principal-control record selecting the active backup series for one (actor_id,
    /// backup_kind).
    pub const KEY_BACKUP_ACTIVE_SERIES_V1: &'static str = "ak.schema.key_backup_active_series.v1";
    /// Canonical plaintext keybag opened from a ak.schema.key_backup.v1 envelope.
    pub const KEY_BACKUP_PLAINTEXT_V1: &'static str = "ak.schema.key_backup_plaintext.v1";
    /// Proof binding a key-backup read/decrypt action to one recovery session, requesting device,
    /// backup object, selected series, ciphertext digest, and accepted proof transcript.
    pub const KEY_BACKUP_UNLOCK_PROOF_V1: &'static str = "ak.schema.key_backup_unlock_proof.v1";
    /// Canonical log head, inclusion proof, consistency proof and witness evidence for
    /// ak.profile.key_transparency.v1 and high-security log-backed identity checks.
    pub const KEY_TRANSPARENCY_V1: &'static str = "ak.schema.key_transparency.v1";
    /// Closed request/response DTO bundle for self KeyPackage upload/claim/consume/revoke and
    /// atomic peer claim/outcome-query operations.
    pub const KEYPACKAGE_OPERATIONS_V1: &'static str = "ak.schema.keypackage_operations.v1";
    /// Closed request/response DTO bundle for ak.self.keys.upload.create, query, claim, and key
    /// backup put/list/delete responses.
    pub const KEYS_OPERATIONS_V1: &'static str = "ak.schema.keys_operations.v1";
    /// Directory response listing currently visible handle claims for a disclosed subject DID.
    pub const LIST_HANDLES_FOR_SUBJECT_RESPONSE_V1: &'static str =
        "ak.schema.list_handles_for_subject_response.v1";
    pub const MEDIA_METADATA_V1: &'static str = "ak.schema.media_metadata.v1";
    /// Closed request DTO bundle for realtime media service operations.
    pub const MEDIA_OPERATIONS_V1: &'static str = "ak.schema.media_operations.v1";
    /// Builder-side candidate object for Handle resolution intent=member_add | invite
    /// (identity-handles.md §3.7); produces a Realm-scoped member_delivery_binding only after Join
    /// Policy re-validation.
    pub const MEMBER_DELIVERY_BINDING_CANDIDATE_V1: &'static str =
        "ak.schema.member_delivery_binding_candidate.v1";
    /// Realm-scoped member display/subject projection carried by ak.member.identity.update; handle
    /// lifecycle is carried by ak.schema.handle_claim.v1.
    pub const MEMBER_IDENTITY_V1: &'static str = "ak.schema.member_identity.v1";
    pub const MESSAGE_V1: &'static str = "ak.schema.message.v1";
    pub const MIMI_INTEROP_V1: &'static str = "ak.schema.mimi_interop.v1";
    /// Closed request/response DTO bundle for MIMI provider interop operations.
    pub const MIMI_OPERATIONS_V1: &'static str = "ak.schema.mimi_operations.v1";
    /// Complete-materialization accepted-Seal proof bundle for independently verifying full-profile
    /// MLS governance bindings
    pub const MLS_GOVERNANCE_PROOF_BUNDLE_V1: &'static str =
        "ak.schema.mls_governance_proof_bundle.v1";
    pub const MODERATION_APPEAL_V1: &'static str = "ak.schema.moderation_appeal.v1";
    pub const MODERATION_QUEUE_ITEM_V1: &'static str = "ak.schema.moderation_queue_item.v1";
    pub const MODERATION_REPORT_V1: &'static str = "ak.schema.moderation_report.v1";
    /// Reference additive extension business-field schema for the customer_risk example, used by
    /// the ak.morph.schema_migrate transformation conformance vectors
    /// (ak.vector.morph.transformation_*). Declares the optional renamed score / backfilled
    /// priority fields a transformation migration introduces on top of
    /// ak.schema.morph.customer_risk.v1.
    pub const MORPH_CUSTOMER_RISK_EXT_V1: &'static str = "ak.schema.morph.customer_risk.ext.v1";
    /// Reference business-field schema used by the Morph type-system example. It validates the
    /// customer_risk fields.status / fields.severity payload carried inside ak.schema.morph.v1
    /// containers.
    pub const MORPH_CUSTOMER_RISK_V1: &'static str = "ak.schema.morph.customer_risk.v1";
    pub const MORPH_V1: &'static str = "ak.schema.morph.v1";
    pub const NOTIFICATION_V1: &'static str = "ak.schema.notification.v1";
    /// Canonical address-link target descriptor and signed token claims.
    pub const OBJECT_ADDRESSING_V1: &'static str = "ak.schema.object_addressing.v1";
    /// AuthorizationLease and IngressReceipt proof objects.
    pub const OFFLINE_PUBLICATION_V1: &'static str = "ak.schema.offline_publication.v1";
    /// Registered schema for the canonical Arkret field-patch wire format.
    pub const PATCH_V1: &'static str = "ak.schema.patch.v1";
    /// Encrypted account-data value shapes for reminders, scheduled send, snooze, and saved items.
    pub const PERSONAL_PRODUCTIVITY_V1: &'static str = "ak.schema.personal_productivity.v1";
    /// Payload schemas for shared pin events.
    pub const PIN_V1: &'static str = "ak.schema.pin.v1";
    pub const POLICY_V1: &'static str = "ak.schema.policy.v1";
    /// Signed online invite locator asserting subject_id and recipient_service_id for private
    /// invite delivery.
    pub const PRINCIPAL_LOCATOR_V1: &'static str = "ak.schema.principal_locator.v1";
    /// Closed wire carriers scoped to a single principal: device bootstrap, participation
    /// replacement, history ingress contracts, KeyPackage terminal handling, Sidecar staging and
    /// the shared identifier, signature and receipt primitives those carriers reuse.
    pub const PRINCIPAL_OPERATIONS_V1: &'static str = "ak.schema.principal_operations.v1";
    /// Defs-only canonical PublicKey DTO (kty/kid/algorithm/key, optional key_digest). Owned by its
    /// own document so device, agent, account and to-device surfaces reference one shared
    /// definition instead of reverse-referencing each other's bundles. The {kid, alg, public_key}
    /// spelling is not canonical wire and MUST be rejected.
    pub const PUBLIC_KEY_V1: &'static str = "ak.schema.public_key.v1";
    /// Closed request/response DTO bundle for push device registration and push wakeup delivery.
    pub const PUSH_OPERATIONS_V1: &'static str = "ak.schema.push_operations.v1";
    /// Canonical wire schema for client query / projection (query_request) and search
    /// (search_request) request bodies plus reusable filter / sort / relation-query $defs. The
    /// OpenAPI QueryRequestBody / SearchRequestBody / QueryFilter / FieldFilter / BooleanFilter /
    /// SortSpec / RelationQuery components $ref this file so there is a single source of truth.
    /// Human-readable semantics: zh/conformance/query-schema.md.
    pub const QUERY_V1: &'static str = "ak.schema.query.v1";
    pub const RANGE_COMPLETENESS_ATTESTATION_V1: &'static str =
        "ak.schema.range_completeness_attestation.v1";
    pub const READ_CURSOR_V1: &'static str = "ak.schema.read_cursor.v1";
    /// Closed request/response DTO bundle for self-surface read cursor operations
    /// (ak.self.read_cursor.*); see zh/discovery/read-receipts.md.
    pub const READ_CURSOR_OPERATIONS_V1: &'static str = "ak.schema.read_cursor_operations.v1";
    /// Closed decrypted Signal payload profile for ak.receipt.read timeline read hints.
    pub const READ_RECEIPT_V1: &'static str = "ak.schema.read_receipt.v1";
    pub const REALM_V1: &'static str = "ak.schema.realm.v1";
    pub const REALM_GENESIS_V1: &'static str = "ak.schema.realm_genesis.v1";
    /// Time-bounded routing hint returned by Realm discovery / resolve paths for selecting a
    /// qualified service to receive join, invite-accept, knock, or restricted-join submissions. Not
    /// an authorization grant and not a member_delivery_binding.
    pub const REALM_JOIN_CANDIDATE_V1: &'static str = "ak.schema.realm_join_candidate.v1";
    /// Closed request/response DTO bundle for self-surface cross-Realm link operations
    /// (ak.self.realm_link.*); see zh/models/realm-links.md.
    pub const REALM_LINK_OPERATIONS_V1: &'static str = "ak.schema.realm_link_operations.v1";
    /// Closed response DTO bundle for self-surface Realm organization relationship reads
    /// (ak.self.realm_organization.*); see zh/models/realm-and-space.md.
    pub const REALM_ORGANIZATION_OPERATIONS_V1: &'static str =
        "ak.schema.realm_organization_operations.v1";
    /// Closed request/response DTO bundle for self-surface Realm policy-server config operations
    /// (ak.self.realm_policy_server.*); see zh/authz/policy-server.md.
    pub const REALM_POLICY_SERVER_OPERATIONS_V1: &'static str =
        "ak.schema.realm_policy_server_operations.v1";
    pub const REALM_PROFILE_V1: &'static str = "ak.schema.realm_profile.v1";
    /// Closed request/response DTO bundle for self-surface Realm read and moderation-policy
    /// operations (ak.self.realm.*); see zh/models/realm-and-space.md and
    /// zh/governance/content-moderation.md.
    pub const REALM_READ_OPERATIONS_V1: &'static str = "ak.schema.realm_read_operations.v1";
    /// Transaction-bound recovery authority ticket plus ticket issuance, recovery device
    /// authorization and recovery grant promotion DTOs.
    pub const RECOVERY_AUTHORITY_TICKET_V1: &'static str = "ak.schema.recovery_authority_ticket.v1";
    /// Coordinator-signed proof of a durably completed RecoveryTransaction for recovery grant
    /// promotion.
    pub const RECOVERY_COMPLETION_ATTESTATION_V1: &'static str =
        "ak.schema.recovery_completion_attestation.v1";
    /// Wire payload schema for the principal recovery policy. Bound to the Principal Control Realm
    /// via signed publish / rotate / share-revoke; receivers MUST reject recovery / rotate /
    /// ak.device.authorize and cross-signing-reset evidence whose proof family is not allowed by
    /// the currently accepted recovery policy. See identity/key-management.md §3.3 / §7 / §8.
    pub const RECOVERY_POLICY_V1: &'static str = "ak.schema.recovery_policy.v1";
    /// Signed completion receipt for a principal recovery strand. Bound to recovery_session_id used
    /// by every proof, backup unlock, and MLS Welcome replay during the recovery. See
    /// crypto-media/device-lifecycle.md §15 step 7.
    pub const RECOVERY_RECEIPT_V1: &'static str = "ak.schema.recovery_receipt.v1";
    /// Wire contract for the device recovery session state machine, including create/get session
    /// shape, proof submit request and response helpers, the closed publication-authority snapshot,
    /// and principal_signing recovery proof transcript. Session completion is owned exclusively by
    /// the bound RecoveryTransaction terminal commit. See crypto-media/device-lifecycle.md §15.
    pub const RECOVERY_SESSION_V1: &'static str = "ak.schema.recovery_session.v1";
    pub const RELATION_V1: &'static str = "ak.schema.relation.v1";
    pub const RESOURCE_SELECTOR_V1: &'static str = "ak.schema.resource_selector.v1";
    /// Payload schema for ak.rsvp.set.
    pub const RSVP_V1: &'static str = "ak.schema.rsvp.v1";
    /// Machine-verifiable SDK release claim against the canonical sdk_conformance_contract.
    pub const SDK_CONFORMANCE_CLAIM_V1: &'static str = "ak.schema.sdk_conformance_claim.v1";
    /// Seal control-plane finality commitment schema
    pub const SEAL_V1: &'static str = "ak.schema.seal.v1";
    /// Seal transparency append-only log entry and independent auditor attestation wire schema
    pub const SEAL_TRANSPARENCY_V1: &'static str = "ak.schema.seal_transparency.v1";
    /// Privacy-preserving search index manifest, blind index query, and policy shapes.
    pub const SEARCH_SERVICE_V1: &'static str = "ak.schema.search_service.v1";
    /// Typed local-device commit artifact for the terminal SecurityRotationTransaction step.
    pub const SECURITY_ROTATION_LOCAL_COMMIT_V1: &'static str =
        "ak.schema.security_rotation_local_commit.v1";
    /// Closed RecoveryTransaction and SecurityRotationTransaction resource.
    pub const SECURITY_TRANSACTION_V1: &'static str = "ak.schema.security_transaction.v1";
    /// Canonical ServiceDescribe response for ak.server.read.describe and per-surface describe
    /// operations: base service metadata plus claim-level partitions (supported_operations /
    /// implemented_features / claimed_profiles / verified_profiles / experimental_features /
    /// compat_surfaces) and the registered directory_service overlay fields used by
    /// ak.find.directory.read.describe. Enforces development_mode=true =&gt; verified_profiles=[].
    /// compat_surfaces is limited to external interop surfaces. See service-surface.md §3.0 and
    /// discovery-directory.md §8.9.
    pub const SERVICE_DESCRIBE_V1: &'static str = "ak.schema.service_describe.v1";
    /// Canonical DTO bundle for service operation request/response shapes migrated out of OpenAPI
    /// inline components.
    pub const SERVICE_OPERATION_DTOS_V1: &'static str = "ak.schema.service_operation_dtos.v1";
    /// Encrypted-only Signal Extension envelope; product payload types remain inside ciphertext.
    pub const SIGNAL_ENVELOPE_V1: &'static str = "ak.schema.signal_envelope.v1";
    /// Closed decrypted Signal payload profile for transient Message generation keyframe, delta,
    /// and abort frames.
    pub const SIGNAL_MESSAGE_STREAM_V1: &'static str = "ak.schema.signal_message_stream.v1";
    /// Closed decrypted Signal payload profile for ak.presence state, status message and activity
    /// bucket.
    pub const SIGNAL_PRESENCE_V1: &'static str = "ak.schema.signal_presence.v1";
    /// Bounded single-hop peer relay request and opaque outcome for encrypted SignalEnvelope
    /// values.
    pub const SIGNAL_RELAY_V1: &'static str = "ak.schema.signal_relay.v1";
    /// Closed data/control frame union for ak.self.signal.stream.subscribe.
    pub const SIGNAL_STREAM_FRAME_V1: &'static str = "ak.schema.signal_stream_frame.v1";
    /// Closed decrypted Signal payload profile for ak.typing Strand composition indicators.
    pub const SIGNAL_TYPING_V1: &'static str = "ak.schema.signal_typing.v1";
    pub const SNAPSHOT_V1: &'static str = "ak.schema.snapshot.v1";
    pub const SPACE_V1: &'static str = "ak.schema.space.v1";
    pub const STRAND_V1: &'static str = "ak.schema.strand.v1";
    /// Shared coarse JSON Schema shapes for Arkret human identifiers, IDNA domains, handles, acct
    /// URIs, and human-readable text profiles.
    pub const STRING_PROFILES_V1: &'static str = "ak.schema.string_profiles.v1";
    /// Defs-only shared canonical Arkret timestamp profile. Arkret-owned absolute instants use
    /// fixed UTC milliseconds (YYYY-MM-DDTHH:MM:SS.sssZ); external protocol time, local wall time,
    /// durations, and algorithm-internal epochs remain separate semantic types.
    pub const TIME_V1: &'static str = "ak.schema.time.v1";
    /// Closed ServiceDescribe supported_bindings union for registered HTTP companion and extension
    /// transports.
    pub const TRANSPORT_BINDING_V1: &'static str = "ak.schema.transport_binding.v1";
    pub const VIEW_V1: &'static str = "ak.schema.view.v1";
    /// Client authentication and reauthentication response frame.
    pub const WEBSOCKET_AUTHENTICATE_FRAME_V1: &'static str =
        "ak.schema.websocket_authenticate_frame.v1";
    /// Server challenge frame with connection-bound one-time nonce.
    pub const WEBSOCKET_CHALLENGE_FRAME_V1: &'static str = "ak.schema.websocket_challenge_frame.v1";
    /// Closed client-to-server WebSocket frame union.
    pub const WEBSOCKET_CLIENT_FRAME_V1: &'static str = "ak.schema.websocket_client_frame.v1";
    /// Client channel-close request.
    pub const WEBSOCKET_CLOSE_FRAME_V1: &'static str = "ak.schema.websocket_close_frame.v1";
    /// Server channel-termination frame.
    pub const WEBSOCKET_CLOSED_FRAME_V1: &'static str = "ak.schema.websocket_closed_frame.v1";
    /// Server connection- or channel-scoped control frame.
    pub const WEBSOCKET_CONTROL_FRAME_V1: &'static str = "ak.schema.websocket_control_frame.v1";
    /// Server channel data wrapper over a canonical account, events, or signal payload.
    pub const WEBSOCKET_DATA_FRAME_V1: &'static str = "ak.schema.websocket_data_frame.v1";
    /// Closed htm, wss htu, ath, nonce, iat and jti claim set for a WebSocket authentication proof.
    pub const WEBSOCKET_DPOP_CLAIMS_V1: &'static str = "ak.schema.websocket_dpop_claims.v1";
    /// Decoded protected header and claim set for the application-level challenge_dpop_session_v1
    /// proof.
    pub const WEBSOCKET_DPOP_PROOF_V1: &'static str = "ak.schema.websocket_dpop_proof.v1";
    /// Closed Ed25519 JOSE protected header for a WebSocket authentication proof.
    pub const WEBSOCKET_DPOP_PROTECTED_HEADER_V1: &'static str =
        "ak.schema.websocket_dpop_protected_header.v1";
    /// Server connection- or channel-scoped error frame.
    pub const WEBSOCKET_ERROR_FRAME_V1: &'static str = "ak.schema.websocket_error_frame.v1";
    /// Closed bidirectional application-frame union for ak.profile.binding.websocket.v1.
    pub const WEBSOCKET_FRAME_V1: &'static str = "ak.schema.websocket_frame.v1";
    /// Client channel-open union with operation-specific closed parameters.
    pub const WEBSOCKET_OPEN_FRAME_V1: &'static str = "ak.schema.websocket_open_frame.v1";
    /// Server channel-open acknowledgement.
    pub const WEBSOCKET_OPENED_FRAME_V1: &'static str = "ak.schema.websocket_opened_frame.v1";
    /// Server application heartbeat probe.
    pub const WEBSOCKET_PING_FRAME_V1: &'static str = "ak.schema.websocket_ping_frame.v1";
    /// Client application heartbeat response.
    pub const WEBSOCKET_PONG_FRAME_V1: &'static str = "ak.schema.websocket_pong_frame.v1";
    /// Server reauthentication challenge frame.
    pub const WEBSOCKET_REAUTH_REQUIRED_FRAME_V1: &'static str =
        "ak.schema.websocket_reauth_required_frame.v1";
    /// Closed server-to-client WebSocket frame union.
    pub const WEBSOCKET_SERVER_FRAME_V1: &'static str = "ak.schema.websocket_server_frame.v1";
    /// Server authentication-success frame carrying effective connection and channel limits.
    pub const WEBSOCKET_WELCOME_FRAME_V1: &'static str = "ak.schema.websocket_welcome_frame.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountDataEncryptedValueV1 => Self::ACCOUNT_DATA_ENCRYPTED_VALUE_V1,
            Self::AccountDataOperationsV1 => Self::ACCOUNT_DATA_OPERATIONS_V1,
            Self::AccountOperationsV1 => Self::ACCOUNT_OPERATIONS_V1,
            Self::AccountSubscribeFrameV1 => Self::ACCOUNT_SUBSCRIBE_FRAME_V1,
            Self::AccountabilityGrantV1 => Self::ACCOUNTABILITY_GRANT_V1,
            Self::ActorProfileV1 => Self::ACTOR_PROFILE_V1,
            Self::AgentOperationsV1 => Self::AGENT_OPERATIONS_V1,
            Self::AgentPairingBootstrapV1 => Self::AGENT_PAIRING_BOOTSTRAP_V1,
            Self::AgentProvisionV1 => Self::AGENT_PROVISION_V1,
            Self::AgentRequestedScopeDisclosureV1 => Self::AGENT_REQUESTED_SCOPE_DISCLOSURE_V1,
            Self::AgentSelectorClaimV1 => Self::AGENT_SELECTOR_CLAIM_V1,
            Self::AgentSidecarV1 => Self::AGENT_SIDECAR_V1,
            Self::AgentSidecarEventExchangeBindingV1 => {
                Self::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1
            }
            Self::AgentSidecarExchangeControlV1 => Self::AGENT_SIDECAR_EXCHANGE_CONTROL_V1,
            Self::AgentSidecarExchangeProjectionV1 => Self::AGENT_SIDECAR_EXCHANGE_PROJECTION_V1,
            Self::AgentSidecarViewStateV1 => Self::AGENT_SIDECAR_VIEW_STATE_V1,
            Self::AgentSignerAdmissionReceiptV1 => Self::AGENT_SIGNER_ADMISSION_RECEIPT_V1,
            Self::AgentSignerEvidenceV1 => Self::AGENT_SIGNER_EVIDENCE_V1,
            Self::AgentSignerEvidenceBundleV1 => Self::AGENT_SIGNER_EVIDENCE_BUNDLE_V1,
            Self::AgentSignerEvidenceQueryOutcomeV1 => Self::AGENT_SIGNER_EVIDENCE_QUERY_OUTCOME_V1,
            Self::AgentSignerEvidenceQueryRequestV1 => Self::AGENT_SIGNER_EVIDENCE_QUERY_REQUEST_V1,
            Self::AgentSigningKeyBindingV1 => Self::AGENT_SIGNING_KEY_BINDING_V1,
            Self::AppletV1 => Self::APPLET_V1,
            Self::AppletEdgeOperationsV1 => Self::APPLET_EDGE_OPERATIONS_V1,
            Self::AppletGhostOperationsV1 => Self::APPLET_GHOST_OPERATIONS_V1,
            Self::AppletInstallOperationsV1 => Self::APPLET_INSTALL_OPERATIONS_V1,
            Self::AppletInstallPlanV1 => Self::APPLET_INSTALL_PLAN_V1,
            Self::AppletPackageV1 => Self::APPLET_PACKAGE_V1,
            Self::AppletRegistrationEpochTranscriptV1 => {
                Self::APPLET_REGISTRATION_EPOCH_TRANSCRIPT_V1
            }
            Self::AppletWidgetDeclarationV1 => Self::APPLET_WIDGET_DECLARATION_V1,
            Self::AuditReleaseAttestationV1 => Self::AUDIT_RELEASE_ATTESTATION_V1,
            Self::AuditRywReceiptV1 => Self::AUDIT_RYW_RECEIPT_V1,
            Self::AuthoritySetPolicyV1 => Self::AUTHORITY_SET_POLICY_V1,
            Self::AuthzOperationsV1 => Self::AUTHZ_OPERATIONS_V1,
            Self::AvailabilityReceiptV1 => Self::AVAILABILITY_RECEIPT_V1,
            Self::BackupSeriesEraseConfirmationV1 => Self::BACKUP_SERIES_ERASE_CONFIRMATION_V1,
            Self::BlobV1 => Self::BLOB_V1,
            Self::BlobOperationsV1 => Self::BLOB_OPERATIONS_V1,
            Self::BottomV1 => Self::BOTTOM_V1,
            Self::CalendarEventV1 => Self::CALENDAR_EVENT_V1,
            Self::CallRecordingArtifactV1 => Self::CALL_RECORDING_ARTIFACT_V1,
            Self::CallSignalPlaintextV1 => Self::CALL_SIGNAL_PLAINTEXT_V1,
            Self::CapabilityV1 => Self::CAPABILITY_V1,
            Self::CbaProofBundleV1 => Self::CBA_PROOF_BUNDLE_V1,
            Self::CircleV1 => Self::CIRCLE_V1,
            Self::CircleOperationsV1 => Self::CIRCLE_OPERATIONS_V1,
            Self::CommonIdsV1 => Self::COMMON_IDS_V1,
            Self::ConsentOperationsV1 => Self::CONSENT_OPERATIONS_V1,
            Self::ContactOperationsV1 => Self::CONTACT_OPERATIONS_V1,
            Self::ContactScopeUpdateV1 => Self::CONTACT_SCOPE_UPDATE_V1,
            Self::ContentBlockPollV1 => Self::CONTENT_BLOCK_POLL_V1,
            Self::ControllerAccountGateAttestationV1 => {
                Self::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1
            }
            Self::CrossSigningPublishV1 => Self::CROSS_SIGNING_PUBLISH_V1,
            Self::CrossSigningResetV1 => Self::CROSS_SIGNING_RESET_V1,
            Self::CursorV1 => Self::CURSOR_V1,
            Self::DeliveryBindingStaleV1 => Self::DELIVERY_BINDING_STALE_V1,
            Self::DeviceMessageV1 => Self::DEVICE_MESSAGE_V1,
            Self::DevicePairingBootstrapV1 => Self::DEVICE_PAIRING_BOOTSTRAP_V1,
            Self::DevicePairingOperationsV1 => Self::DEVICE_PAIRING_OPERATIONS_V1,
            Self::DeviceReanchorV1 => Self::DEVICE_REANCHOR_V1,
            Self::DidBindingContractsV1 => Self::DID_BINDING_CONTRACTS_V1,
            Self::DidContinuityProofV1 => Self::DID_CONTINUITY_PROOF_V1,
            Self::DidKeyLogEntryV1 => Self::DID_KEY_LOG_ENTRY_V1,
            Self::DidWebvhWitnessReceiptV1 => Self::DID_WEBVH_WITNESS_RECEIPT_V1,
            Self::DirectConversationOperationsV1 => Self::DIRECT_CONVERSATION_OPERATIONS_V1,
            Self::DirectoryOperationsV1 => Self::DIRECTORY_OPERATIONS_V1,
            Self::DisappearingMessagesV1 => Self::DISAPPEARING_MESSAGES_V1,
            Self::DraftSyncV1 => Self::DRAFT_SYNC_V1,
            Self::EncryptedEnvelopeV1 => Self::ENCRYPTED_ENVELOPE_V1,
            Self::ErasureReceiptV1 => Self::ERASURE_RECEIPT_V1,
            Self::ErasureVerificationStubV1 => Self::ERASURE_VERIFICATION_STUB_V1,
            Self::EventV1 => Self::EVENT_V1,
            Self::EventBatchReceiptV1 => Self::EVENT_BATCH_RECEIPT_V1,
            Self::EventPayloadV1 => Self::EVENT_PAYLOAD_V1,
            Self::EventsSubscribeFrameV1 => Self::EVENTS_SUBSCRIBE_FRAME_V1,
            Self::ExtensionManifestV1 => Self::EXTENSION_MANIFEST_V1,
            Self::FederatedDeviceSigningKeyEvidenceV1 => {
                Self::FEDERATED_DEVICE_SIGNING_KEY_EVIDENCE_V1
            }
            Self::FileTransferV1 => Self::FILE_TRANSFER_V1,
            Self::GrantConstraintV1 => Self::GRANT_CONSTRAINT_V1,
            Self::HandleClaimV1 => Self::HANDLE_CLAIM_V1,
            Self::HighRiskAuthorityProofV1 => Self::HIGH_RISK_AUTHORITY_PROOF_V1,
            Self::IceConfigResponseV1 => Self::ICE_CONFIG_RESPONSE_V1,
            Self::IdentityLinkV1 => Self::IDENTITY_LINK_V1,
            Self::IdentityReceiptV1 => Self::IDENTITY_RECEIPT_V1,
            Self::InclusionListV1 => Self::INCLUSION_LIST_V1,
            Self::InviteV1 => Self::INVITE_V1,
            Self::InviteDeliveryRequestV1 => Self::INVITE_DELIVERY_REQUEST_V1,
            Self::InviteReceivePolicyV1 => Self::INVITE_RECEIVE_POLICY_V1,
            Self::JoinPolicyOperationsV1 => Self::JOIN_POLICY_OPERATIONS_V1,
            Self::KeyBackupV1 => Self::KEY_BACKUP_V1,
            Self::KeyBackupActiveSeriesV1 => Self::KEY_BACKUP_ACTIVE_SERIES_V1,
            Self::KeyBackupPlaintextV1 => Self::KEY_BACKUP_PLAINTEXT_V1,
            Self::KeyBackupUnlockProofV1 => Self::KEY_BACKUP_UNLOCK_PROOF_V1,
            Self::KeyTransparencyV1 => Self::KEY_TRANSPARENCY_V1,
            Self::KeypackageOperationsV1 => Self::KEYPACKAGE_OPERATIONS_V1,
            Self::KeysOperationsV1 => Self::KEYS_OPERATIONS_V1,
            Self::ListHandlesForSubjectResponseV1 => Self::LIST_HANDLES_FOR_SUBJECT_RESPONSE_V1,
            Self::MediaMetadataV1 => Self::MEDIA_METADATA_V1,
            Self::MediaOperationsV1 => Self::MEDIA_OPERATIONS_V1,
            Self::MemberDeliveryBindingCandidateV1 => Self::MEMBER_DELIVERY_BINDING_CANDIDATE_V1,
            Self::MemberIdentityV1 => Self::MEMBER_IDENTITY_V1,
            Self::MessageV1 => Self::MESSAGE_V1,
            Self::MimiInteropV1 => Self::MIMI_INTEROP_V1,
            Self::MimiOperationsV1 => Self::MIMI_OPERATIONS_V1,
            Self::MlsGovernanceProofBundleV1 => Self::MLS_GOVERNANCE_PROOF_BUNDLE_V1,
            Self::ModerationAppealV1 => Self::MODERATION_APPEAL_V1,
            Self::ModerationQueueItemV1 => Self::MODERATION_QUEUE_ITEM_V1,
            Self::ModerationReportV1 => Self::MODERATION_REPORT_V1,
            Self::MorphCustomerRiskExtV1 => Self::MORPH_CUSTOMER_RISK_EXT_V1,
            Self::MorphCustomerRiskV1 => Self::MORPH_CUSTOMER_RISK_V1,
            Self::MorphV1 => Self::MORPH_V1,
            Self::NotificationV1 => Self::NOTIFICATION_V1,
            Self::ObjectAddressingV1 => Self::OBJECT_ADDRESSING_V1,
            Self::OfflinePublicationV1 => Self::OFFLINE_PUBLICATION_V1,
            Self::PatchV1 => Self::PATCH_V1,
            Self::PersonalProductivityV1 => Self::PERSONAL_PRODUCTIVITY_V1,
            Self::PinV1 => Self::PIN_V1,
            Self::PolicyV1 => Self::POLICY_V1,
            Self::PrincipalLocatorV1 => Self::PRINCIPAL_LOCATOR_V1,
            Self::PrincipalOperationsV1 => Self::PRINCIPAL_OPERATIONS_V1,
            Self::PublicKeyV1 => Self::PUBLIC_KEY_V1,
            Self::PushOperationsV1 => Self::PUSH_OPERATIONS_V1,
            Self::QueryV1 => Self::QUERY_V1,
            Self::RangeCompletenessAttestationV1 => Self::RANGE_COMPLETENESS_ATTESTATION_V1,
            Self::ReadCursorV1 => Self::READ_CURSOR_V1,
            Self::ReadCursorOperationsV1 => Self::READ_CURSOR_OPERATIONS_V1,
            Self::ReadReceiptV1 => Self::READ_RECEIPT_V1,
            Self::RealmV1 => Self::REALM_V1,
            Self::RealmGenesisV1 => Self::REALM_GENESIS_V1,
            Self::RealmJoinCandidateV1 => Self::REALM_JOIN_CANDIDATE_V1,
            Self::RealmLinkOperationsV1 => Self::REALM_LINK_OPERATIONS_V1,
            Self::RealmOrganizationOperationsV1 => Self::REALM_ORGANIZATION_OPERATIONS_V1,
            Self::RealmPolicyServerOperationsV1 => Self::REALM_POLICY_SERVER_OPERATIONS_V1,
            Self::RealmProfileV1 => Self::REALM_PROFILE_V1,
            Self::RealmReadOperationsV1 => Self::REALM_READ_OPERATIONS_V1,
            Self::RecoveryAuthorityTicketV1 => Self::RECOVERY_AUTHORITY_TICKET_V1,
            Self::RecoveryCompletionAttestationV1 => Self::RECOVERY_COMPLETION_ATTESTATION_V1,
            Self::RecoveryPolicyV1 => Self::RECOVERY_POLICY_V1,
            Self::RecoveryReceiptV1 => Self::RECOVERY_RECEIPT_V1,
            Self::RecoverySessionV1 => Self::RECOVERY_SESSION_V1,
            Self::RelationV1 => Self::RELATION_V1,
            Self::ResourceSelectorV1 => Self::RESOURCE_SELECTOR_V1,
            Self::RsvpV1 => Self::RSVP_V1,
            Self::SdkConformanceClaimV1 => Self::SDK_CONFORMANCE_CLAIM_V1,
            Self::SealV1 => Self::SEAL_V1,
            Self::SealTransparencyV1 => Self::SEAL_TRANSPARENCY_V1,
            Self::SearchServiceV1 => Self::SEARCH_SERVICE_V1,
            Self::SecurityRotationLocalCommitV1 => Self::SECURITY_ROTATION_LOCAL_COMMIT_V1,
            Self::SecurityTransactionV1 => Self::SECURITY_TRANSACTION_V1,
            Self::ServiceDescribeV1 => Self::SERVICE_DESCRIBE_V1,
            Self::ServiceOperationDtosV1 => Self::SERVICE_OPERATION_DTOS_V1,
            Self::SignalEnvelopeV1 => Self::SIGNAL_ENVELOPE_V1,
            Self::SignalMessageStreamV1 => Self::SIGNAL_MESSAGE_STREAM_V1,
            Self::SignalPresenceV1 => Self::SIGNAL_PRESENCE_V1,
            Self::SignalRelayV1 => Self::SIGNAL_RELAY_V1,
            Self::SignalStreamFrameV1 => Self::SIGNAL_STREAM_FRAME_V1,
            Self::SignalTypingV1 => Self::SIGNAL_TYPING_V1,
            Self::SnapshotV1 => Self::SNAPSHOT_V1,
            Self::SpaceV1 => Self::SPACE_V1,
            Self::StrandV1 => Self::STRAND_V1,
            Self::StringProfilesV1 => Self::STRING_PROFILES_V1,
            Self::TimeV1 => Self::TIME_V1,
            Self::TransportBindingV1 => Self::TRANSPORT_BINDING_V1,
            Self::ViewV1 => Self::VIEW_V1,
            Self::WebsocketAuthenticateFrameV1 => Self::WEBSOCKET_AUTHENTICATE_FRAME_V1,
            Self::WebsocketChallengeFrameV1 => Self::WEBSOCKET_CHALLENGE_FRAME_V1,
            Self::WebsocketClientFrameV1 => Self::WEBSOCKET_CLIENT_FRAME_V1,
            Self::WebsocketCloseFrameV1 => Self::WEBSOCKET_CLOSE_FRAME_V1,
            Self::WebsocketClosedFrameV1 => Self::WEBSOCKET_CLOSED_FRAME_V1,
            Self::WebsocketControlFrameV1 => Self::WEBSOCKET_CONTROL_FRAME_V1,
            Self::WebsocketDataFrameV1 => Self::WEBSOCKET_DATA_FRAME_V1,
            Self::WebsocketDpopClaimsV1 => Self::WEBSOCKET_DPOP_CLAIMS_V1,
            Self::WebsocketDpopProofV1 => Self::WEBSOCKET_DPOP_PROOF_V1,
            Self::WebsocketDpopProtectedHeaderV1 => Self::WEBSOCKET_DPOP_PROTECTED_HEADER_V1,
            Self::WebsocketErrorFrameV1 => Self::WEBSOCKET_ERROR_FRAME_V1,
            Self::WebsocketFrameV1 => Self::WEBSOCKET_FRAME_V1,
            Self::WebsocketOpenFrameV1 => Self::WEBSOCKET_OPEN_FRAME_V1,
            Self::WebsocketOpenedFrameV1 => Self::WEBSOCKET_OPENED_FRAME_V1,
            Self::WebsocketPingFrameV1 => Self::WEBSOCKET_PING_FRAME_V1,
            Self::WebsocketPongFrameV1 => Self::WEBSOCKET_PONG_FRAME_V1,
            Self::WebsocketReauthRequiredFrameV1 => Self::WEBSOCKET_REAUTH_REQUIRED_FRAME_V1,
            Self::WebsocketServerFrameV1 => Self::WEBSOCKET_SERVER_FRAME_V1,
            Self::WebsocketWelcomeFrameV1 => Self::WEBSOCKET_WELCOME_FRAME_V1,
        }
    }

    /// Path of the JSON Schema document backing this id, relative to
    /// `spec/v1/artifacts/`.
    pub const fn file(self) -> &'static str {
        match self {
            Self::AccountDataEncryptedValueV1 => "schemas/account-data-encrypted-value.schema.json",
            Self::AccountDataOperationsV1 => "schemas/account-data-operations.schema.json",
            Self::AccountOperationsV1 => "schemas/account-operations.schema.json",
            Self::AccountSubscribeFrameV1 => "schemas/account-subscribe-frame.schema.json",
            Self::AccountabilityGrantV1 => "schemas/accountability-grant.schema.json",
            Self::ActorProfileV1 => "schemas/actor-profile.schema.json",
            Self::AgentOperationsV1 => "schemas/agent-operations.schema.json",
            Self::AgentPairingBootstrapV1 => "schemas/agent-operations.schema.json",
            Self::AgentProvisionV1 => "schemas/agent-provision.schema.json",
            Self::AgentRequestedScopeDisclosureV1 => {
                "schemas/agent-requested-scope-disclosure.schema.json"
            }
            Self::AgentSelectorClaimV1 => "schemas/agent-selector-claim.schema.json",
            Self::AgentSidecarV1 => "schemas/agent-sidecar.schema.json",
            Self::AgentSidecarEventExchangeBindingV1 => {
                "schemas/agent-sidecar-event-exchange-binding.schema.json"
            }
            Self::AgentSidecarExchangeControlV1 => {
                "schemas/agent-sidecar-exchange-control.schema.json"
            }
            Self::AgentSidecarExchangeProjectionV1 => {
                "schemas/agent-sidecar-exchange-projection.schema.json"
            }
            Self::AgentSidecarViewStateV1 => "schemas/agent-sidecar-view-state.schema.json",
            Self::AgentSignerAdmissionReceiptV1 => "schemas/agent-signer-evidence.schema.json",
            Self::AgentSignerEvidenceV1 => "schemas/agent-signer-evidence.schema.json",
            Self::AgentSignerEvidenceBundleV1 => {
                "schemas/agent-signer-evidence-operations.schema.json"
            }
            Self::AgentSignerEvidenceQueryOutcomeV1 => {
                "schemas/agent-signer-evidence-operations.schema.json"
            }
            Self::AgentSignerEvidenceQueryRequestV1 => {
                "schemas/agent-signer-evidence-operations.schema.json"
            }
            Self::AgentSigningKeyBindingV1 => "schemas/agent-signing-key-binding.schema.json",
            Self::AppletV1 => "schemas/applet.schema.json",
            Self::AppletEdgeOperationsV1 => "schemas/applet-edge-operations.schema.json",
            Self::AppletGhostOperationsV1 => "schemas/applet-ghost-operations.schema.json",
            Self::AppletInstallOperationsV1 => "schemas/applet-install-operations.schema.json",
            Self::AppletInstallPlanV1 => "schemas/applet-install-plan.schema.json",
            Self::AppletPackageV1 => "schemas/applet-package.schema.json",
            Self::AppletRegistrationEpochTranscriptV1 => {
                "schemas/applet-registration-epoch-transcript.schema.json"
            }
            Self::AppletWidgetDeclarationV1 => "schemas/applet-widget-declaration.schema.json",
            Self::AuditReleaseAttestationV1 => "schemas/audit-release-attestation.schema.json",
            Self::AuditRywReceiptV1 => "schemas/audit-ryw-receipt.schema.json",
            Self::AuthoritySetPolicyV1 => "schemas/authority-set-policy.schema.json",
            Self::AuthzOperationsV1 => "schemas/authz-operations.schema.json",
            Self::AvailabilityReceiptV1 => "schemas/availability-receipt.schema.json",
            Self::BackupSeriesEraseConfirmationV1 => "schemas/keys-operations.schema.json",
            Self::BlobV1 => "schemas/blob.schema.json",
            Self::BlobOperationsV1 => "schemas/blob-operations.schema.json",
            Self::BottomV1 => "schemas/bottom.schema.json",
            Self::CalendarEventV1 => "schemas/calendar-event.schema.json",
            Self::CallRecordingArtifactV1 => "schemas/call-recording-artifact.schema.json",
            Self::CallSignalPlaintextV1 => "schemas/call-signal-plaintext.schema.json",
            Self::CapabilityV1 => "schemas/capability-grant.schema.json",
            Self::CbaProofBundleV1 => "schemas/cba-proof-bundle.schema.json",
            Self::CircleV1 => "schemas/circle.schema.json",
            Self::CircleOperationsV1 => "schemas/circle-operations.schema.json",
            Self::CommonIdsV1 => "schemas/common-ids.schema.json",
            Self::ConsentOperationsV1 => "schemas/consent-operations.schema.json",
            Self::ContactOperationsV1 => "schemas/contact-operations.schema.json",
            Self::ContactScopeUpdateV1 => "schemas/contact-operations.schema.json",
            Self::ContentBlockPollV1 => "schemas/content-block-poll.schema.json",
            Self::ControllerAccountGateAttestationV1 => "schemas/agent-signer-evidence.schema.json",
            Self::CrossSigningPublishV1 => "schemas/cross-signing-publish.schema.json",
            Self::CrossSigningResetV1 => "schemas/cross-signing-reset.schema.json",
            Self::CursorV1 => "schemas/cursor.schema.json",
            Self::DeliveryBindingStaleV1 => "schemas/delivery-binding-stale.schema.json",
            Self::DeviceMessageV1 => "schemas/device-message.schema.json",
            Self::DevicePairingBootstrapV1 => "schemas/device-pairing.schema.json",
            Self::DevicePairingOperationsV1 => "schemas/device-pairing.schema.json",
            Self::DeviceReanchorV1 => "schemas/device-reanchor.schema.json",
            Self::DidBindingContractsV1 => "schemas/did-binding-contracts.schema.json",
            Self::DidContinuityProofV1 => "schemas/did-continuity-proof.schema.json",
            Self::DidKeyLogEntryV1 => "schemas/did-key-log-entry.schema.json",
            Self::DidWebvhWitnessReceiptV1 => "schemas/did-webvh-witness-receipt.schema.json",
            Self::DirectConversationOperationsV1 => {
                "schemas/direct-conversation-operations.schema.json"
            }
            Self::DirectoryOperationsV1 => "schemas/directory-operations.schema.json",
            Self::DisappearingMessagesV1 => "schemas/disappearing-messages.schema.json",
            Self::DraftSyncV1 => "schemas/draft-sync.schema.json",
            Self::EncryptedEnvelopeV1 => "schemas/encrypted-envelope.schema.json",
            Self::ErasureReceiptV1 => "schemas/erasure-receipt.schema.json",
            Self::ErasureVerificationStubV1 => "schemas/erasure-verification-stub.schema.json",
            Self::EventV1 => "schemas/event-envelope.schema.json",
            Self::EventBatchReceiptV1 => "schemas/event-batch-receipt.schema.json",
            Self::EventPayloadV1 => "schemas/event-payload.schema.json",
            Self::EventsSubscribeFrameV1 => "schemas/events-subscribe-frame.schema.json",
            Self::ExtensionManifestV1 => "schemas/extension-manifest.schema.json",
            Self::FederatedDeviceSigningKeyEvidenceV1 => {
                "schemas/federated-device-signing-key-evidence.schema.json"
            }
            Self::FileTransferV1 => "schemas/file-transfer.schema.json",
            Self::GrantConstraintV1 => "schemas/grant-constraint.schema.json",
            Self::HandleClaimV1 => "schemas/handle-claim.schema.json",
            Self::HighRiskAuthorityProofV1 => "schemas/high-risk-authority-proof.schema.json",
            Self::IceConfigResponseV1 => "schemas/ice-config-response.schema.json",
            Self::IdentityLinkV1 => "schemas/identity-link.schema.json",
            Self::IdentityReceiptV1 => "schemas/identity-receipt.schema.json",
            Self::InclusionListV1 => "schemas/inclusion-list.schema.json",
            Self::InviteV1 => "schemas/invite.schema.json",
            Self::InviteDeliveryRequestV1 => "schemas/invite-delivery-request.schema.json",
            Self::InviteReceivePolicyV1 => "schemas/invite-receive-policy.schema.json",
            Self::JoinPolicyOperationsV1 => "schemas/join-policy-operations.schema.json",
            Self::KeyBackupV1 => "schemas/key-backup.schema.json",
            Self::KeyBackupActiveSeriesV1 => "schemas/key-backup-active-series.schema.json",
            Self::KeyBackupPlaintextV1 => "schemas/key-backup-plaintext.schema.json",
            Self::KeyBackupUnlockProofV1 => "schemas/key-backup-unlock-proof.schema.json",
            Self::KeyTransparencyV1 => "schemas/key-transparency.schema.json",
            Self::KeypackageOperationsV1 => "schemas/keypackage-operations.schema.json",
            Self::KeysOperationsV1 => "schemas/keys-operations.schema.json",
            Self::ListHandlesForSubjectResponseV1 => {
                "schemas/list-handles-for-subject-response.schema.json"
            }
            Self::MediaMetadataV1 => "schemas/media-metadata.schema.json",
            Self::MediaOperationsV1 => "schemas/media-operations.schema.json",
            Self::MemberDeliveryBindingCandidateV1 => {
                "schemas/member-delivery-binding-candidate.schema.json"
            }
            Self::MemberIdentityV1 => "schemas/member-identity.schema.json",
            Self::MessageV1 => "schemas/message.schema.json",
            Self::MimiInteropV1 => "schemas/mimi-interop.schema.json",
            Self::MimiOperationsV1 => "schemas/mimi-operations.schema.json",
            Self::MlsGovernanceProofBundleV1 => "schemas/mls-governance-proof-bundle.schema.json",
            Self::ModerationAppealV1 => "schemas/moderation-appeal.schema.json",
            Self::ModerationQueueItemV1 => "schemas/moderation-queue-item.schema.json",
            Self::ModerationReportV1 => "schemas/moderation-report.schema.json",
            Self::MorphCustomerRiskExtV1 => "schemas/morph-customer-risk-ext.schema.json",
            Self::MorphCustomerRiskV1 => "schemas/morph-customer-risk.schema.json",
            Self::MorphV1 => "schemas/morph.schema.json",
            Self::NotificationV1 => "schemas/notification.schema.json",
            Self::ObjectAddressingV1 => "schemas/object-addressing.schema.json",
            Self::OfflinePublicationV1 => "schemas/offline-publication.schema.json",
            Self::PatchV1 => "schemas/patch.schema.json",
            Self::PersonalProductivityV1 => "schemas/personal-productivity.schema.json",
            Self::PinV1 => "schemas/pin.schema.json",
            Self::PolicyV1 => "schemas/policy.schema.json",
            Self::PrincipalLocatorV1 => "schemas/principal-locator.schema.json",
            Self::PrincipalOperationsV1 => "schemas/principal-operations.schema.json",
            Self::PublicKeyV1 => "schemas/public-key.schema.json",
            Self::PushOperationsV1 => "schemas/push-operations.schema.json",
            Self::QueryV1 => "schemas/query.schema.json",
            Self::RangeCompletenessAttestationV1 => {
                "schemas/range-completeness-attestation.schema.json"
            }
            Self::ReadCursorV1 => "schemas/read-cursor.schema.json",
            Self::ReadCursorOperationsV1 => "schemas/read-cursor-operations.schema.json",
            Self::ReadReceiptV1 => "schemas/read-receipt.schema.json",
            Self::RealmV1 => "schemas/realm.schema.json",
            Self::RealmGenesisV1 => "schemas/realm-genesis.schema.json",
            Self::RealmJoinCandidateV1 => "schemas/realm-join-candidate.schema.json",
            Self::RealmLinkOperationsV1 => "schemas/realm-link-operations.schema.json",
            Self::RealmOrganizationOperationsV1 => {
                "schemas/realm-organization-operations.schema.json"
            }
            Self::RealmPolicyServerOperationsV1 => {
                "schemas/realm-policy-server-operations.schema.json"
            }
            Self::RealmProfileV1 => "schemas/realm-profile.schema.json",
            Self::RealmReadOperationsV1 => "schemas/realm-read-operations.schema.json",
            Self::RecoveryAuthorityTicketV1 => "schemas/recovery-authority.schema.json",
            Self::RecoveryCompletionAttestationV1 => "schemas/recovery-authority.schema.json",
            Self::RecoveryPolicyV1 => "schemas/recovery-policy.schema.json",
            Self::RecoveryReceiptV1 => "schemas/recovery-receipt.schema.json",
            Self::RecoverySessionV1 => "schemas/recovery-session.schema.json",
            Self::RelationV1 => "schemas/relation.schema.json",
            Self::ResourceSelectorV1 => "schemas/resource-selector.schema.json",
            Self::RsvpV1 => "schemas/rsvp.schema.json",
            Self::SdkConformanceClaimV1 => "schemas/sdk-conformance-claim.schema.json",
            Self::SealV1 => "schemas/seal.schema.json",
            Self::SealTransparencyV1 => "schemas/seal-transparency.schema.json",
            Self::SearchServiceV1 => "schemas/search-service.schema.json",
            Self::SecurityRotationLocalCommitV1 => "schemas/security-transaction.schema.json",
            Self::SecurityTransactionV1 => "schemas/security-transaction.schema.json",
            Self::ServiceDescribeV1 => "schemas/service-describe.schema.json",
            Self::ServiceOperationDtosV1 => "schemas/service-operation-dtos.schema.json",
            Self::SignalEnvelopeV1 => "schemas/signal-envelope.schema.json",
            Self::SignalMessageStreamV1 => "schemas/signal-message-stream.schema.json",
            Self::SignalPresenceV1 => "schemas/signal-presence.schema.json",
            Self::SignalRelayV1 => "schemas/signal-relay.schema.json",
            Self::SignalStreamFrameV1 => "schemas/signal-stream-frame.schema.json",
            Self::SignalTypingV1 => "schemas/signal-typing.schema.json",
            Self::SnapshotV1 => "schemas/snapshot.schema.json",
            Self::SpaceV1 => "schemas/space.schema.json",
            Self::StrandV1 => "schemas/strand.schema.json",
            Self::StringProfilesV1 => "schemas/string-profiles.schema.json",
            Self::TimeV1 => "schemas/time.schema.json",
            Self::TransportBindingV1 => "schemas/transport-binding.schema.json",
            Self::ViewV1 => "schemas/view.schema.json",
            Self::WebsocketAuthenticateFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketChallengeFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketClientFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketCloseFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketClosedFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketControlFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketDataFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketDpopClaimsV1 => "schemas/websocket-dpop-proof.schema.json",
            Self::WebsocketDpopProofV1 => "schemas/websocket-dpop-proof.schema.json",
            Self::WebsocketDpopProtectedHeaderV1 => "schemas/websocket-dpop-proof.schema.json",
            Self::WebsocketErrorFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketOpenFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketOpenedFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketPingFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketPongFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketReauthRequiredFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketServerFrameV1 => "schemas/websocket-frame.schema.json",
            Self::WebsocketWelcomeFrameV1 => "schemas/websocket-frame.schema.json",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ACCOUNT_DATA_ENCRYPTED_VALUE_V1 => Some(Self::AccountDataEncryptedValueV1),
            Self::ACCOUNT_DATA_OPERATIONS_V1 => Some(Self::AccountDataOperationsV1),
            Self::ACCOUNT_OPERATIONS_V1 => Some(Self::AccountOperationsV1),
            Self::ACCOUNT_SUBSCRIBE_FRAME_V1 => Some(Self::AccountSubscribeFrameV1),
            Self::ACCOUNTABILITY_GRANT_V1 => Some(Self::AccountabilityGrantV1),
            Self::ACTOR_PROFILE_V1 => Some(Self::ActorProfileV1),
            Self::AGENT_OPERATIONS_V1 => Some(Self::AgentOperationsV1),
            Self::AGENT_PAIRING_BOOTSTRAP_V1 => Some(Self::AgentPairingBootstrapV1),
            Self::AGENT_PROVISION_V1 => Some(Self::AgentProvisionV1),
            Self::AGENT_REQUESTED_SCOPE_DISCLOSURE_V1 => {
                Some(Self::AgentRequestedScopeDisclosureV1)
            }
            Self::AGENT_SELECTOR_CLAIM_V1 => Some(Self::AgentSelectorClaimV1),
            Self::AGENT_SIDECAR_V1 => Some(Self::AgentSidecarV1),
            Self::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1 => {
                Some(Self::AgentSidecarEventExchangeBindingV1)
            }
            Self::AGENT_SIDECAR_EXCHANGE_CONTROL_V1 => Some(Self::AgentSidecarExchangeControlV1),
            Self::AGENT_SIDECAR_EXCHANGE_PROJECTION_V1 => {
                Some(Self::AgentSidecarExchangeProjectionV1)
            }
            Self::AGENT_SIDECAR_VIEW_STATE_V1 => Some(Self::AgentSidecarViewStateV1),
            Self::AGENT_SIGNER_ADMISSION_RECEIPT_V1 => Some(Self::AgentSignerAdmissionReceiptV1),
            Self::AGENT_SIGNER_EVIDENCE_V1 => Some(Self::AgentSignerEvidenceV1),
            Self::AGENT_SIGNER_EVIDENCE_BUNDLE_V1 => Some(Self::AgentSignerEvidenceBundleV1),
            Self::AGENT_SIGNER_EVIDENCE_QUERY_OUTCOME_V1 => {
                Some(Self::AgentSignerEvidenceQueryOutcomeV1)
            }
            Self::AGENT_SIGNER_EVIDENCE_QUERY_REQUEST_V1 => {
                Some(Self::AgentSignerEvidenceQueryRequestV1)
            }
            Self::AGENT_SIGNING_KEY_BINDING_V1 => Some(Self::AgentSigningKeyBindingV1),
            Self::APPLET_V1 => Some(Self::AppletV1),
            Self::APPLET_EDGE_OPERATIONS_V1 => Some(Self::AppletEdgeOperationsV1),
            Self::APPLET_GHOST_OPERATIONS_V1 => Some(Self::AppletGhostOperationsV1),
            Self::APPLET_INSTALL_OPERATIONS_V1 => Some(Self::AppletInstallOperationsV1),
            Self::APPLET_INSTALL_PLAN_V1 => Some(Self::AppletInstallPlanV1),
            Self::APPLET_PACKAGE_V1 => Some(Self::AppletPackageV1),
            Self::APPLET_REGISTRATION_EPOCH_TRANSCRIPT_V1 => {
                Some(Self::AppletRegistrationEpochTranscriptV1)
            }
            Self::APPLET_WIDGET_DECLARATION_V1 => Some(Self::AppletWidgetDeclarationV1),
            Self::AUDIT_RELEASE_ATTESTATION_V1 => Some(Self::AuditReleaseAttestationV1),
            Self::AUDIT_RYW_RECEIPT_V1 => Some(Self::AuditRywReceiptV1),
            Self::AUTHORITY_SET_POLICY_V1 => Some(Self::AuthoritySetPolicyV1),
            Self::AUTHZ_OPERATIONS_V1 => Some(Self::AuthzOperationsV1),
            Self::AVAILABILITY_RECEIPT_V1 => Some(Self::AvailabilityReceiptV1),
            Self::BACKUP_SERIES_ERASE_CONFIRMATION_V1 => {
                Some(Self::BackupSeriesEraseConfirmationV1)
            }
            Self::BLOB_V1 => Some(Self::BlobV1),
            Self::BLOB_OPERATIONS_V1 => Some(Self::BlobOperationsV1),
            Self::BOTTOM_V1 => Some(Self::BottomV1),
            Self::CALENDAR_EVENT_V1 => Some(Self::CalendarEventV1),
            Self::CALL_RECORDING_ARTIFACT_V1 => Some(Self::CallRecordingArtifactV1),
            Self::CALL_SIGNAL_PLAINTEXT_V1 => Some(Self::CallSignalPlaintextV1),
            Self::CAPABILITY_V1 => Some(Self::CapabilityV1),
            Self::CBA_PROOF_BUNDLE_V1 => Some(Self::CbaProofBundleV1),
            Self::CIRCLE_V1 => Some(Self::CircleV1),
            Self::CIRCLE_OPERATIONS_V1 => Some(Self::CircleOperationsV1),
            Self::COMMON_IDS_V1 => Some(Self::CommonIdsV1),
            Self::CONSENT_OPERATIONS_V1 => Some(Self::ConsentOperationsV1),
            Self::CONTACT_OPERATIONS_V1 => Some(Self::ContactOperationsV1),
            Self::CONTACT_SCOPE_UPDATE_V1 => Some(Self::ContactScopeUpdateV1),
            Self::CONTENT_BLOCK_POLL_V1 => Some(Self::ContentBlockPollV1),
            Self::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1 => {
                Some(Self::ControllerAccountGateAttestationV1)
            }
            Self::CROSS_SIGNING_PUBLISH_V1 => Some(Self::CrossSigningPublishV1),
            Self::CROSS_SIGNING_RESET_V1 => Some(Self::CrossSigningResetV1),
            Self::CURSOR_V1 => Some(Self::CursorV1),
            Self::DELIVERY_BINDING_STALE_V1 => Some(Self::DeliveryBindingStaleV1),
            Self::DEVICE_MESSAGE_V1 => Some(Self::DeviceMessageV1),
            Self::DEVICE_PAIRING_BOOTSTRAP_V1 => Some(Self::DevicePairingBootstrapV1),
            Self::DEVICE_PAIRING_OPERATIONS_V1 => Some(Self::DevicePairingOperationsV1),
            Self::DEVICE_REANCHOR_V1 => Some(Self::DeviceReanchorV1),
            Self::DID_BINDING_CONTRACTS_V1 => Some(Self::DidBindingContractsV1),
            Self::DID_CONTINUITY_PROOF_V1 => Some(Self::DidContinuityProofV1),
            Self::DID_KEY_LOG_ENTRY_V1 => Some(Self::DidKeyLogEntryV1),
            Self::DID_WEBVH_WITNESS_RECEIPT_V1 => Some(Self::DidWebvhWitnessReceiptV1),
            Self::DIRECT_CONVERSATION_OPERATIONS_V1 => Some(Self::DirectConversationOperationsV1),
            Self::DIRECTORY_OPERATIONS_V1 => Some(Self::DirectoryOperationsV1),
            Self::DISAPPEARING_MESSAGES_V1 => Some(Self::DisappearingMessagesV1),
            Self::DRAFT_SYNC_V1 => Some(Self::DraftSyncV1),
            Self::ENCRYPTED_ENVELOPE_V1 => Some(Self::EncryptedEnvelopeV1),
            Self::ERASURE_RECEIPT_V1 => Some(Self::ErasureReceiptV1),
            Self::ERASURE_VERIFICATION_STUB_V1 => Some(Self::ErasureVerificationStubV1),
            Self::EVENT_V1 => Some(Self::EventV1),
            Self::EVENT_BATCH_RECEIPT_V1 => Some(Self::EventBatchReceiptV1),
            Self::EVENT_PAYLOAD_V1 => Some(Self::EventPayloadV1),
            Self::EVENTS_SUBSCRIBE_FRAME_V1 => Some(Self::EventsSubscribeFrameV1),
            Self::EXTENSION_MANIFEST_V1 => Some(Self::ExtensionManifestV1),
            Self::FEDERATED_DEVICE_SIGNING_KEY_EVIDENCE_V1 => {
                Some(Self::FederatedDeviceSigningKeyEvidenceV1)
            }
            Self::FILE_TRANSFER_V1 => Some(Self::FileTransferV1),
            Self::GRANT_CONSTRAINT_V1 => Some(Self::GrantConstraintV1),
            Self::HANDLE_CLAIM_V1 => Some(Self::HandleClaimV1),
            Self::HIGH_RISK_AUTHORITY_PROOF_V1 => Some(Self::HighRiskAuthorityProofV1),
            Self::ICE_CONFIG_RESPONSE_V1 => Some(Self::IceConfigResponseV1),
            Self::IDENTITY_LINK_V1 => Some(Self::IdentityLinkV1),
            Self::IDENTITY_RECEIPT_V1 => Some(Self::IdentityReceiptV1),
            Self::INCLUSION_LIST_V1 => Some(Self::InclusionListV1),
            Self::INVITE_V1 => Some(Self::InviteV1),
            Self::INVITE_DELIVERY_REQUEST_V1 => Some(Self::InviteDeliveryRequestV1),
            Self::INVITE_RECEIVE_POLICY_V1 => Some(Self::InviteReceivePolicyV1),
            Self::JOIN_POLICY_OPERATIONS_V1 => Some(Self::JoinPolicyOperationsV1),
            Self::KEY_BACKUP_V1 => Some(Self::KeyBackupV1),
            Self::KEY_BACKUP_ACTIVE_SERIES_V1 => Some(Self::KeyBackupActiveSeriesV1),
            Self::KEY_BACKUP_PLAINTEXT_V1 => Some(Self::KeyBackupPlaintextV1),
            Self::KEY_BACKUP_UNLOCK_PROOF_V1 => Some(Self::KeyBackupUnlockProofV1),
            Self::KEY_TRANSPARENCY_V1 => Some(Self::KeyTransparencyV1),
            Self::KEYPACKAGE_OPERATIONS_V1 => Some(Self::KeypackageOperationsV1),
            Self::KEYS_OPERATIONS_V1 => Some(Self::KeysOperationsV1),
            Self::LIST_HANDLES_FOR_SUBJECT_RESPONSE_V1 => {
                Some(Self::ListHandlesForSubjectResponseV1)
            }
            Self::MEDIA_METADATA_V1 => Some(Self::MediaMetadataV1),
            Self::MEDIA_OPERATIONS_V1 => Some(Self::MediaOperationsV1),
            Self::MEMBER_DELIVERY_BINDING_CANDIDATE_V1 => {
                Some(Self::MemberDeliveryBindingCandidateV1)
            }
            Self::MEMBER_IDENTITY_V1 => Some(Self::MemberIdentityV1),
            Self::MESSAGE_V1 => Some(Self::MessageV1),
            Self::MIMI_INTEROP_V1 => Some(Self::MimiInteropV1),
            Self::MIMI_OPERATIONS_V1 => Some(Self::MimiOperationsV1),
            Self::MLS_GOVERNANCE_PROOF_BUNDLE_V1 => Some(Self::MlsGovernanceProofBundleV1),
            Self::MODERATION_APPEAL_V1 => Some(Self::ModerationAppealV1),
            Self::MODERATION_QUEUE_ITEM_V1 => Some(Self::ModerationQueueItemV1),
            Self::MODERATION_REPORT_V1 => Some(Self::ModerationReportV1),
            Self::MORPH_CUSTOMER_RISK_EXT_V1 => Some(Self::MorphCustomerRiskExtV1),
            Self::MORPH_CUSTOMER_RISK_V1 => Some(Self::MorphCustomerRiskV1),
            Self::MORPH_V1 => Some(Self::MorphV1),
            Self::NOTIFICATION_V1 => Some(Self::NotificationV1),
            Self::OBJECT_ADDRESSING_V1 => Some(Self::ObjectAddressingV1),
            Self::OFFLINE_PUBLICATION_V1 => Some(Self::OfflinePublicationV1),
            Self::PATCH_V1 => Some(Self::PatchV1),
            Self::PERSONAL_PRODUCTIVITY_V1 => Some(Self::PersonalProductivityV1),
            Self::PIN_V1 => Some(Self::PinV1),
            Self::POLICY_V1 => Some(Self::PolicyV1),
            Self::PRINCIPAL_LOCATOR_V1 => Some(Self::PrincipalLocatorV1),
            Self::PRINCIPAL_OPERATIONS_V1 => Some(Self::PrincipalOperationsV1),
            Self::PUBLIC_KEY_V1 => Some(Self::PublicKeyV1),
            Self::PUSH_OPERATIONS_V1 => Some(Self::PushOperationsV1),
            Self::QUERY_V1 => Some(Self::QueryV1),
            Self::RANGE_COMPLETENESS_ATTESTATION_V1 => Some(Self::RangeCompletenessAttestationV1),
            Self::READ_CURSOR_V1 => Some(Self::ReadCursorV1),
            Self::READ_CURSOR_OPERATIONS_V1 => Some(Self::ReadCursorOperationsV1),
            Self::READ_RECEIPT_V1 => Some(Self::ReadReceiptV1),
            Self::REALM_V1 => Some(Self::RealmV1),
            Self::REALM_GENESIS_V1 => Some(Self::RealmGenesisV1),
            Self::REALM_JOIN_CANDIDATE_V1 => Some(Self::RealmJoinCandidateV1),
            Self::REALM_LINK_OPERATIONS_V1 => Some(Self::RealmLinkOperationsV1),
            Self::REALM_ORGANIZATION_OPERATIONS_V1 => Some(Self::RealmOrganizationOperationsV1),
            Self::REALM_POLICY_SERVER_OPERATIONS_V1 => Some(Self::RealmPolicyServerOperationsV1),
            Self::REALM_PROFILE_V1 => Some(Self::RealmProfileV1),
            Self::REALM_READ_OPERATIONS_V1 => Some(Self::RealmReadOperationsV1),
            Self::RECOVERY_AUTHORITY_TICKET_V1 => Some(Self::RecoveryAuthorityTicketV1),
            Self::RECOVERY_COMPLETION_ATTESTATION_V1 => Some(Self::RecoveryCompletionAttestationV1),
            Self::RECOVERY_POLICY_V1 => Some(Self::RecoveryPolicyV1),
            Self::RECOVERY_RECEIPT_V1 => Some(Self::RecoveryReceiptV1),
            Self::RECOVERY_SESSION_V1 => Some(Self::RecoverySessionV1),
            Self::RELATION_V1 => Some(Self::RelationV1),
            Self::RESOURCE_SELECTOR_V1 => Some(Self::ResourceSelectorV1),
            Self::RSVP_V1 => Some(Self::RsvpV1),
            Self::SDK_CONFORMANCE_CLAIM_V1 => Some(Self::SdkConformanceClaimV1),
            Self::SEAL_V1 => Some(Self::SealV1),
            Self::SEAL_TRANSPARENCY_V1 => Some(Self::SealTransparencyV1),
            Self::SEARCH_SERVICE_V1 => Some(Self::SearchServiceV1),
            Self::SECURITY_ROTATION_LOCAL_COMMIT_V1 => Some(Self::SecurityRotationLocalCommitV1),
            Self::SECURITY_TRANSACTION_V1 => Some(Self::SecurityTransactionV1),
            Self::SERVICE_DESCRIBE_V1 => Some(Self::ServiceDescribeV1),
            Self::SERVICE_OPERATION_DTOS_V1 => Some(Self::ServiceOperationDtosV1),
            Self::SIGNAL_ENVELOPE_V1 => Some(Self::SignalEnvelopeV1),
            Self::SIGNAL_MESSAGE_STREAM_V1 => Some(Self::SignalMessageStreamV1),
            Self::SIGNAL_PRESENCE_V1 => Some(Self::SignalPresenceV1),
            Self::SIGNAL_RELAY_V1 => Some(Self::SignalRelayV1),
            Self::SIGNAL_STREAM_FRAME_V1 => Some(Self::SignalStreamFrameV1),
            Self::SIGNAL_TYPING_V1 => Some(Self::SignalTypingV1),
            Self::SNAPSHOT_V1 => Some(Self::SnapshotV1),
            Self::SPACE_V1 => Some(Self::SpaceV1),
            Self::STRAND_V1 => Some(Self::StrandV1),
            Self::STRING_PROFILES_V1 => Some(Self::StringProfilesV1),
            Self::TIME_V1 => Some(Self::TimeV1),
            Self::TRANSPORT_BINDING_V1 => Some(Self::TransportBindingV1),
            Self::VIEW_V1 => Some(Self::ViewV1),
            Self::WEBSOCKET_AUTHENTICATE_FRAME_V1 => Some(Self::WebsocketAuthenticateFrameV1),
            Self::WEBSOCKET_CHALLENGE_FRAME_V1 => Some(Self::WebsocketChallengeFrameV1),
            Self::WEBSOCKET_CLIENT_FRAME_V1 => Some(Self::WebsocketClientFrameV1),
            Self::WEBSOCKET_CLOSE_FRAME_V1 => Some(Self::WebsocketCloseFrameV1),
            Self::WEBSOCKET_CLOSED_FRAME_V1 => Some(Self::WebsocketClosedFrameV1),
            Self::WEBSOCKET_CONTROL_FRAME_V1 => Some(Self::WebsocketControlFrameV1),
            Self::WEBSOCKET_DATA_FRAME_V1 => Some(Self::WebsocketDataFrameV1),
            Self::WEBSOCKET_DPOP_CLAIMS_V1 => Some(Self::WebsocketDpopClaimsV1),
            Self::WEBSOCKET_DPOP_PROOF_V1 => Some(Self::WebsocketDpopProofV1),
            Self::WEBSOCKET_DPOP_PROTECTED_HEADER_V1 => Some(Self::WebsocketDpopProtectedHeaderV1),
            Self::WEBSOCKET_ERROR_FRAME_V1 => Some(Self::WebsocketErrorFrameV1),
            Self::WEBSOCKET_FRAME_V1 => Some(Self::WebsocketFrameV1),
            Self::WEBSOCKET_OPEN_FRAME_V1 => Some(Self::WebsocketOpenFrameV1),
            Self::WEBSOCKET_OPENED_FRAME_V1 => Some(Self::WebsocketOpenedFrameV1),
            Self::WEBSOCKET_PING_FRAME_V1 => Some(Self::WebsocketPingFrameV1),
            Self::WEBSOCKET_PONG_FRAME_V1 => Some(Self::WebsocketPongFrameV1),
            Self::WEBSOCKET_REAUTH_REQUIRED_FRAME_V1 => Some(Self::WebsocketReauthRequiredFrameV1),
            Self::WEBSOCKET_SERVER_FRAME_V1 => Some(Self::WebsocketServerFrameV1),
            Self::WEBSOCKET_WELCOME_FRAME_V1 => Some(Self::WebsocketWelcomeFrameV1),
            _ => None,
        }
    }
}

impl std::fmt::Display for SchemaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for SchemaId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SchemaId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown schema id: {raw}")))
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ToSchema for SchemaId {
    fn to_schema(
        _components: &mut salvo_oapi::Components,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        salvo_oapi::schema::Object::new()
            .schema_type(salvo_oapi::schema::BasicType::String)
            .enum_values(Self::ALL.iter().map(|value| value.as_str()))
            .into()
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ComposeSchema for SchemaId {
    fn compose(
        components: &mut salvo_oapi::Components,
        generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        let _ = generics;
        <Self as salvo_oapi::ToSchema>::to_schema(components)
    }
}
