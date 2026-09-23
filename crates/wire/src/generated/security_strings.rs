//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/proof-context-registry.json; version=2026-09-23.1;
//! sha256=0cece6481d59f18f33fa1255f45999bb2ce70316aba9ef034f0d3179e2367502 Input: registry/
//! exporter-label-registry.json; version=2026-09-19.1;
//! sha256=30b6f19c7a78d8f53f222ceb33867fc2216db73c3f9113d03ab89235ddffe68d Input: registry/
//! digest-suite-registry.json; version=2026-09-19.1;
//! sha256=5beb1a9c98f49df7b091ef2b8798be8f22aa0206452de2e112d833dc4f6e152f Input: registry/
//! signature-alg-registry.json; version=2026-09-20.1;
//! sha256=ef58f25cd4bdcc0101dd841d4271b0454f22bef3bb8b3636cb383d10c0b15009 Input: registry/
//! hpke-suite-registry.json; version=2026-09-23.1;
//! sha256=a1740d80a9fe630e2d3f32a75f3cd4a270fed17dfb573d119c71365f22e1aafd Input: registry/
//! mls-ciphersuite-registry.json; version=2026-09-19.1;
//! sha256=537db5f0e28f156755dfe617a235812eb236e938e9e7d7739e22ab675a63a0ae Input: registry/
//! mls-extension-registry.json; version=2026-09-19.1;
//! sha256=b365def7af189e665ea8631f9ce218658cc5a08b1e0f9c4d634fbbc04736c544 Input: registry/
//! aead-profile-registry.json; version=2026-08-16.1;
//! sha256=5cab256353caa112d59f4ba10390715eaa27a3c3b530ee1766f01d35a4ea72de
//! Entries: proof_contexts=39, exporter_labels=7, digest_suites=3, signature_algorithms=4,
//! hpke_suites=4, mls_ciphersuites=4, mls_extensions=2, domain_separations=35, aead_profiles=2

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ProofContextId {
    AccountBindingReceiptProofV1,
    AccountHandoffAuthenticationProofV1,
    AccountRegistrationControlProofV1,
    AccountStatusRecordProofV1,
    AccountStatusReplicationReceiptProofV1,
    AccountabilityGrantProofV1,
    AgentRequestedScopeDisclosureProofV1,
    AgentRuntimeKeyPossessionProofV1,
    AgentSelectorClaimProofV1,
    AgentSessionRefreshProofV1,
    AppletPackageProofV1,
    DeviceProjectionAttestationProofV1,
    DidWebvhWitnessReceiptProofV1,
    EventProofV1,
    ExtensionManifestProofV1,
    HandleClaimProofV1,
    HandleClaimRevocationV1,
    HandleClaimStatusV1,
    IdentityReceiptProofV1,
    JoinGateProofV1,
    KeyBackupDeleteProofV1,
    MimiIdentifierQueryOutcomeProofV1,
    MimiIdentifierQueryRequestProofV1,
    MimiKeyMaterialOutcomeProofV1,
    MimiKeyMaterialRequestProofV1,
    MimiProviderDirectoryProofV1,
    MimiRequestConsentRequestProofV1,
    MimiUpdateConsentRequestProofV1,
    OrganizationRegistrationControlProofV1,
    OrganizationRegistrationReceiptProofV1,
    PrincipalLocatorProofV1,
    PrincipalResolutionProjectionAttestationProofV1,
    PushRegistrationInstallationReceiptProofV1,
    RegistrationDidEvidenceControlProofV1,
    ServiceRegistrationReceiptProofV1,
    SessionGrantAcceptedDevicePossessionProofV1,
    SignalProofV1,
    ThirdPartyInviteAcceptanceAttestationProofV1,
    ThirdPartyInviteProvisionRequestProofV1,
}

impl ProofContextId {
    pub const ALL: &'static [Self] = &[
        Self::AccountBindingReceiptProofV1,
        Self::AccountHandoffAuthenticationProofV1,
        Self::AccountRegistrationControlProofV1,
        Self::AccountStatusRecordProofV1,
        Self::AccountStatusReplicationReceiptProofV1,
        Self::AccountabilityGrantProofV1,
        Self::AgentRequestedScopeDisclosureProofV1,
        Self::AgentRuntimeKeyPossessionProofV1,
        Self::AgentSelectorClaimProofV1,
        Self::AgentSessionRefreshProofV1,
        Self::AppletPackageProofV1,
        Self::DeviceProjectionAttestationProofV1,
        Self::DidWebvhWitnessReceiptProofV1,
        Self::EventProofV1,
        Self::ExtensionManifestProofV1,
        Self::HandleClaimProofV1,
        Self::HandleClaimRevocationV1,
        Self::HandleClaimStatusV1,
        Self::IdentityReceiptProofV1,
        Self::JoinGateProofV1,
        Self::KeyBackupDeleteProofV1,
        Self::MimiIdentifierQueryOutcomeProofV1,
        Self::MimiIdentifierQueryRequestProofV1,
        Self::MimiKeyMaterialOutcomeProofV1,
        Self::MimiKeyMaterialRequestProofV1,
        Self::MimiProviderDirectoryProofV1,
        Self::MimiRequestConsentRequestProofV1,
        Self::MimiUpdateConsentRequestProofV1,
        Self::OrganizationRegistrationControlProofV1,
        Self::OrganizationRegistrationReceiptProofV1,
        Self::PrincipalLocatorProofV1,
        Self::PrincipalResolutionProjectionAttestationProofV1,
        Self::PushRegistrationInstallationReceiptProofV1,
        Self::RegistrationDidEvidenceControlProofV1,
        Self::ServiceRegistrationReceiptProofV1,
        Self::SessionGrantAcceptedDevicePossessionProofV1,
        Self::SignalProofV1,
        Self::ThirdPartyInviteAcceptanceAttestationProofV1,
        Self::ThirdPartyInviteProvisionRequestProofV1,
    ];

    pub const ACCOUNT_BINDING_RECEIPT_PROOF_V1: &'static str =
        "ak.account_binding_receipt_proof.v1";
    pub const ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_V1: &'static str =
        "ak.account_handoff_authentication_proof.v1";
    pub const ACCOUNT_REGISTRATION_CONTROL_PROOF_V1: &'static str =
        "ak.account_registration_control_proof.v1";
    pub const ACCOUNT_STATUS_RECORD_PROOF_V1: &'static str = "ak.account_status_record_proof.v1";
    pub const ACCOUNT_STATUS_REPLICATION_RECEIPT_PROOF_V1: &'static str =
        "ak.account_status_replication_receipt_proof.v1";
    pub const ACCOUNTABILITY_GRANT_PROOF_V1: &'static str = "ak.accountability_grant_proof.v1";
    pub const AGENT_REQUESTED_SCOPE_DISCLOSURE_PROOF_V1: &'static str =
        "ak.agent_requested_scope_disclosure_proof.v1";
    pub const AGENT_RUNTIME_KEY_POSSESSION_PROOF_V1: &'static str =
        "ak.agent_runtime_key_possession_proof.v1";
    pub const AGENT_SELECTOR_CLAIM_PROOF_V1: &'static str = "ak.agent_selector_claim_proof.v1";
    pub const AGENT_SESSION_REFRESH_PROOF_V1: &'static str = "ak.agent_session_refresh_proof.v1";
    pub const APPLET_PACKAGE_PROOF_V1: &'static str = "ak.applet_package_proof.v1";
    pub const DEVICE_PROJECTION_ATTESTATION_PROOF_V1: &'static str =
        "ak.device_projection_attestation_proof.v1";
    pub const DID_WEBVH_WITNESS_RECEIPT_PROOF_V1: &'static str =
        "ak.did_webvh_witness_receipt_proof.v1";
    pub const EVENT_PROOF_V1: &'static str = "ak.event_proof.v1";
    pub const EXTENSION_MANIFEST_PROOF_V1: &'static str = "ak.extension_manifest_proof.v1";
    pub const HANDLE_CLAIM_PROOF_V1: &'static str = "ak.handle_claim_proof.v1";
    pub const HANDLE_CLAIM_REVOCATION_V1: &'static str = "ak.handle_claim_revocation.v1";
    pub const HANDLE_CLAIM_STATUS_V1: &'static str = "ak.handle_claim_status.v1";
    pub const IDENTITY_RECEIPT_PROOF_V1: &'static str = "ak.identity_receipt_proof.v1";
    pub const JOIN_GATE_PROOF_V1: &'static str = "ak.join_gate_proof.v1";
    pub const KEY_BACKUP_DELETE_PROOF_V1: &'static str = "ak.key_backup_delete_proof.v1";
    pub const MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1: &'static str =
        "ak.mimi_identifier_query_outcome_proof.v1";
    pub const MIMI_IDENTIFIER_QUERY_REQUEST_PROOF_V1: &'static str =
        "ak.mimi_identifier_query_request_proof.v1";
    pub const MIMI_KEY_MATERIAL_OUTCOME_PROOF_V1: &'static str =
        "ak.mimi_key_material_outcome_proof.v1";
    pub const MIMI_KEY_MATERIAL_REQUEST_PROOF_V1: &'static str =
        "ak.mimi_key_material_request_proof.v1";
    pub const MIMI_PROVIDER_DIRECTORY_PROOF_V1: &'static str =
        "ak.mimi_provider_directory_proof.v1";
    pub const MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1: &'static str =
        "ak.mimi_request_consent_request_proof.v1";
    pub const MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1: &'static str =
        "ak.mimi_update_consent_request_proof.v1";
    pub const ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1: &'static str =
        "ak.organization_registration_control_proof.v1";
    pub const ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1: &'static str =
        "ak.organization_registration_receipt_proof.v1";
    pub const PRINCIPAL_LOCATOR_PROOF_V1: &'static str = "ak.principal_locator_proof.v1";
    pub const PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_PROOF_V1: &'static str =
        "ak.principal_resolution_projection_attestation_proof.v1";
    pub const PUSH_REGISTRATION_INSTALLATION_RECEIPT_PROOF_V1: &'static str =
        "ak.push_registration_installation_receipt_proof.v1";
    pub const REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1: &'static str =
        "ak.registration_did_evidence_control_proof.v1";
    pub const SERVICE_REGISTRATION_RECEIPT_PROOF_V1: &'static str =
        "ak.service_registration_receipt_proof.v1";
    pub const SESSION_GRANT_ACCEPTED_DEVICE_POSSESSION_PROOF_V1: &'static str =
        "ak.session_grant_accepted_device_possession_proof.v1";
    pub const SIGNAL_PROOF_V1: &'static str = "ak.signal_proof.v1";
    pub const THIRD_PARTY_INVITE_ACCEPTANCE_ATTESTATION_PROOF_V1: &'static str =
        "ak.third_party_invite_acceptance_attestation_proof.v1";
    pub const THIRD_PARTY_INVITE_PROVISION_REQUEST_PROOF_V1: &'static str =
        "ak.third_party_invite_provision_request_proof.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountBindingReceiptProofV1 => Self::ACCOUNT_BINDING_RECEIPT_PROOF_V1,
            Self::AccountHandoffAuthenticationProofV1 => {
                Self::ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_V1
            }
            Self::AccountRegistrationControlProofV1 => Self::ACCOUNT_REGISTRATION_CONTROL_PROOF_V1,
            Self::AccountStatusRecordProofV1 => Self::ACCOUNT_STATUS_RECORD_PROOF_V1,
            Self::AccountStatusReplicationReceiptProofV1 => {
                Self::ACCOUNT_STATUS_REPLICATION_RECEIPT_PROOF_V1
            }
            Self::AccountabilityGrantProofV1 => Self::ACCOUNTABILITY_GRANT_PROOF_V1,
            Self::AgentRequestedScopeDisclosureProofV1 => {
                Self::AGENT_REQUESTED_SCOPE_DISCLOSURE_PROOF_V1
            }
            Self::AgentRuntimeKeyPossessionProofV1 => Self::AGENT_RUNTIME_KEY_POSSESSION_PROOF_V1,
            Self::AgentSelectorClaimProofV1 => Self::AGENT_SELECTOR_CLAIM_PROOF_V1,
            Self::AgentSessionRefreshProofV1 => Self::AGENT_SESSION_REFRESH_PROOF_V1,
            Self::AppletPackageProofV1 => Self::APPLET_PACKAGE_PROOF_V1,
            Self::DeviceProjectionAttestationProofV1 => {
                Self::DEVICE_PROJECTION_ATTESTATION_PROOF_V1
            }
            Self::DidWebvhWitnessReceiptProofV1 => Self::DID_WEBVH_WITNESS_RECEIPT_PROOF_V1,
            Self::EventProofV1 => Self::EVENT_PROOF_V1,
            Self::ExtensionManifestProofV1 => Self::EXTENSION_MANIFEST_PROOF_V1,
            Self::HandleClaimProofV1 => Self::HANDLE_CLAIM_PROOF_V1,
            Self::HandleClaimRevocationV1 => Self::HANDLE_CLAIM_REVOCATION_V1,
            Self::HandleClaimStatusV1 => Self::HANDLE_CLAIM_STATUS_V1,
            Self::IdentityReceiptProofV1 => Self::IDENTITY_RECEIPT_PROOF_V1,
            Self::JoinGateProofV1 => Self::JOIN_GATE_PROOF_V1,
            Self::KeyBackupDeleteProofV1 => Self::KEY_BACKUP_DELETE_PROOF_V1,
            Self::MimiIdentifierQueryOutcomeProofV1 => Self::MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1,
            Self::MimiIdentifierQueryRequestProofV1 => Self::MIMI_IDENTIFIER_QUERY_REQUEST_PROOF_V1,
            Self::MimiKeyMaterialOutcomeProofV1 => Self::MIMI_KEY_MATERIAL_OUTCOME_PROOF_V1,
            Self::MimiKeyMaterialRequestProofV1 => Self::MIMI_KEY_MATERIAL_REQUEST_PROOF_V1,
            Self::MimiProviderDirectoryProofV1 => Self::MIMI_PROVIDER_DIRECTORY_PROOF_V1,
            Self::MimiRequestConsentRequestProofV1 => Self::MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1,
            Self::MimiUpdateConsentRequestProofV1 => Self::MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1,
            Self::OrganizationRegistrationControlProofV1 => {
                Self::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1
            }
            Self::OrganizationRegistrationReceiptProofV1 => {
                Self::ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1
            }
            Self::PrincipalLocatorProofV1 => Self::PRINCIPAL_LOCATOR_PROOF_V1,
            Self::PrincipalResolutionProjectionAttestationProofV1 => {
                Self::PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_PROOF_V1
            }
            Self::PushRegistrationInstallationReceiptProofV1 => {
                Self::PUSH_REGISTRATION_INSTALLATION_RECEIPT_PROOF_V1
            }
            Self::RegistrationDidEvidenceControlProofV1 => {
                Self::REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1
            }
            Self::ServiceRegistrationReceiptProofV1 => Self::SERVICE_REGISTRATION_RECEIPT_PROOF_V1,
            Self::SessionGrantAcceptedDevicePossessionProofV1 => {
                Self::SESSION_GRANT_ACCEPTED_DEVICE_POSSESSION_PROOF_V1
            }
            Self::SignalProofV1 => Self::SIGNAL_PROOF_V1,
            Self::ThirdPartyInviteAcceptanceAttestationProofV1 => {
                Self::THIRD_PARTY_INVITE_ACCEPTANCE_ATTESTATION_PROOF_V1
            }
            Self::ThirdPartyInviteProvisionRequestProofV1 => {
                Self::THIRD_PARTY_INVITE_PROVISION_REQUEST_PROOF_V1
            }
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ACCOUNT_BINDING_RECEIPT_PROOF_V1 => Some(Self::AccountBindingReceiptProofV1),
            Self::ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_V1 => {
                Some(Self::AccountHandoffAuthenticationProofV1)
            }
            Self::ACCOUNT_REGISTRATION_CONTROL_PROOF_V1 => {
                Some(Self::AccountRegistrationControlProofV1)
            }
            Self::ACCOUNT_STATUS_RECORD_PROOF_V1 => Some(Self::AccountStatusRecordProofV1),
            Self::ACCOUNT_STATUS_REPLICATION_RECEIPT_PROOF_V1 => {
                Some(Self::AccountStatusReplicationReceiptProofV1)
            }
            Self::ACCOUNTABILITY_GRANT_PROOF_V1 => Some(Self::AccountabilityGrantProofV1),
            Self::AGENT_REQUESTED_SCOPE_DISCLOSURE_PROOF_V1 => {
                Some(Self::AgentRequestedScopeDisclosureProofV1)
            }
            Self::AGENT_RUNTIME_KEY_POSSESSION_PROOF_V1 => {
                Some(Self::AgentRuntimeKeyPossessionProofV1)
            }
            Self::AGENT_SELECTOR_CLAIM_PROOF_V1 => Some(Self::AgentSelectorClaimProofV1),
            Self::AGENT_SESSION_REFRESH_PROOF_V1 => Some(Self::AgentSessionRefreshProofV1),
            Self::APPLET_PACKAGE_PROOF_V1 => Some(Self::AppletPackageProofV1),
            Self::DEVICE_PROJECTION_ATTESTATION_PROOF_V1 => {
                Some(Self::DeviceProjectionAttestationProofV1)
            }
            Self::DID_WEBVH_WITNESS_RECEIPT_PROOF_V1 => Some(Self::DidWebvhWitnessReceiptProofV1),
            Self::EVENT_PROOF_V1 => Some(Self::EventProofV1),
            Self::EXTENSION_MANIFEST_PROOF_V1 => Some(Self::ExtensionManifestProofV1),
            Self::HANDLE_CLAIM_PROOF_V1 => Some(Self::HandleClaimProofV1),
            Self::HANDLE_CLAIM_REVOCATION_V1 => Some(Self::HandleClaimRevocationV1),
            Self::HANDLE_CLAIM_STATUS_V1 => Some(Self::HandleClaimStatusV1),
            Self::IDENTITY_RECEIPT_PROOF_V1 => Some(Self::IdentityReceiptProofV1),
            Self::JOIN_GATE_PROOF_V1 => Some(Self::JoinGateProofV1),
            Self::KEY_BACKUP_DELETE_PROOF_V1 => Some(Self::KeyBackupDeleteProofV1),
            Self::MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1 => {
                Some(Self::MimiIdentifierQueryOutcomeProofV1)
            }
            Self::MIMI_IDENTIFIER_QUERY_REQUEST_PROOF_V1 => {
                Some(Self::MimiIdentifierQueryRequestProofV1)
            }
            Self::MIMI_KEY_MATERIAL_OUTCOME_PROOF_V1 => Some(Self::MimiKeyMaterialOutcomeProofV1),
            Self::MIMI_KEY_MATERIAL_REQUEST_PROOF_V1 => Some(Self::MimiKeyMaterialRequestProofV1),
            Self::MIMI_PROVIDER_DIRECTORY_PROOF_V1 => Some(Self::MimiProviderDirectoryProofV1),
            Self::MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1 => {
                Some(Self::MimiRequestConsentRequestProofV1)
            }
            Self::MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1 => {
                Some(Self::MimiUpdateConsentRequestProofV1)
            }
            Self::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1 => {
                Some(Self::OrganizationRegistrationControlProofV1)
            }
            Self::ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1 => {
                Some(Self::OrganizationRegistrationReceiptProofV1)
            }
            Self::PRINCIPAL_LOCATOR_PROOF_V1 => Some(Self::PrincipalLocatorProofV1),
            Self::PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_PROOF_V1 => {
                Some(Self::PrincipalResolutionProjectionAttestationProofV1)
            }
            Self::PUSH_REGISTRATION_INSTALLATION_RECEIPT_PROOF_V1 => {
                Some(Self::PushRegistrationInstallationReceiptProofV1)
            }
            Self::REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1 => {
                Some(Self::RegistrationDidEvidenceControlProofV1)
            }
            Self::SERVICE_REGISTRATION_RECEIPT_PROOF_V1 => {
                Some(Self::ServiceRegistrationReceiptProofV1)
            }
            Self::SESSION_GRANT_ACCEPTED_DEVICE_POSSESSION_PROOF_V1 => {
                Some(Self::SessionGrantAcceptedDevicePossessionProofV1)
            }
            Self::SIGNAL_PROOF_V1 => Some(Self::SignalProofV1),
            Self::THIRD_PARTY_INVITE_ACCEPTANCE_ATTESTATION_PROOF_V1 => {
                Some(Self::ThirdPartyInviteAcceptanceAttestationProofV1)
            }
            Self::THIRD_PARTY_INVITE_PROVISION_REQUEST_PROOF_V1 => {
                Some(Self::ThirdPartyInviteProvisionRequestProofV1)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum DomainSeparationId {
    AccountabilityScopeSetV1,
    AgentAuthorityStateEvidenceV1,
    AppletManagedActorAuthoringRequestProofV1,
    AppletManagedActorBundleProofV1,
    ApprovalSignatureV1,
    ContactGlareUnconsumedSlotV1,
    ContactNoOutgoingSlotV1,
    ContactRequestAcceptanceCoreV1,
    ContactRequestSourceCheckpointV1,
    ControllerAccountGateV1,
    DeviceAuthorizeAcceptedDevicePossessionProofV1,
    DeviceAuthorizeAppletManagedPossessionProofV1,
    DeviceAuthorizePossessionProofV1,
    DeviceAuthorizeRecoveryPossessionProofV1,
    FrankingProofSignatureV1,
    HttpMessageSignatureV1,
    IdentityRecoveryDevicePossessionV1,
    IdentityRecoveryPolicySignatureV1,
    IdentityRecoveryProofV1,
    IdentityRecoveryReceiptSignatureV1,
    IdentityCreationControlProofV1,
    KeypackageClaimTerminalReceiptV1,
    KeypackageConsumeReceiptV1,
    MimiReporterAuthorityProofV1,
    MlsRecipientDurableReceiptV1,
    MlsWelcomeDeliverySignatureV1,
    PeerContactControlReceiptV1,
    PeerContactMirrorReceiptV1,
    RealmOrganizationStatementV1,
    RealmAuthorityCurrentAssertionSignatureV1,
    RealmAuthorityHandoffNewAcceptanceSignatureV1,
    RealmAuthorityHandoffOldSignatureV1,
    RealmCommitSignatureV1,
    RealmSnapshotSignatureV1,
    WebsocketAuthV1,
}

impl DomainSeparationId {
    pub const ALL: &'static [Self] = &[
        Self::AccountabilityScopeSetV1,
        Self::AgentAuthorityStateEvidenceV1,
        Self::AppletManagedActorAuthoringRequestProofV1,
        Self::AppletManagedActorBundleProofV1,
        Self::ApprovalSignatureV1,
        Self::ContactGlareUnconsumedSlotV1,
        Self::ContactNoOutgoingSlotV1,
        Self::ContactRequestAcceptanceCoreV1,
        Self::ContactRequestSourceCheckpointV1,
        Self::ControllerAccountGateV1,
        Self::DeviceAuthorizeAcceptedDevicePossessionProofV1,
        Self::DeviceAuthorizeAppletManagedPossessionProofV1,
        Self::DeviceAuthorizePossessionProofV1,
        Self::DeviceAuthorizeRecoveryPossessionProofV1,
        Self::FrankingProofSignatureV1,
        Self::HttpMessageSignatureV1,
        Self::IdentityRecoveryDevicePossessionV1,
        Self::IdentityRecoveryPolicySignatureV1,
        Self::IdentityRecoveryProofV1,
        Self::IdentityRecoveryReceiptSignatureV1,
        Self::IdentityCreationControlProofV1,
        Self::KeypackageClaimTerminalReceiptV1,
        Self::KeypackageConsumeReceiptV1,
        Self::MimiReporterAuthorityProofV1,
        Self::MlsRecipientDurableReceiptV1,
        Self::MlsWelcomeDeliverySignatureV1,
        Self::PeerContactControlReceiptV1,
        Self::PeerContactMirrorReceiptV1,
        Self::RealmOrganizationStatementV1,
        Self::RealmAuthorityCurrentAssertionSignatureV1,
        Self::RealmAuthorityHandoffNewAcceptanceSignatureV1,
        Self::RealmAuthorityHandoffOldSignatureV1,
        Self::RealmCommitSignatureV1,
        Self::RealmSnapshotSignatureV1,
        Self::WebsocketAuthV1,
    ];

    pub const ACCOUNTABILITY_SCOPE_SET_V1: &'static str = "ak.accountability_scope_set.v1";
    pub const AGENT_AUTHORITY_STATE_EVIDENCE_V1: &'static str =
        "ak.agent_authority_state_evidence.v1";
    pub const APPLET_MANAGED_ACTOR_AUTHORING_REQUEST_PROOF_V1: &'static str =
        "ak.applet_managed_actor_authoring_request_proof.v1";
    pub const APPLET_MANAGED_ACTOR_BUNDLE_PROOF_V1: &'static str =
        "ak.applet_managed_actor_bundle_proof.v1";
    pub const APPROVAL_SIGNATURE_V1: &'static str = "ak.approval.signature.v1";
    pub const CONTACT_GLARE_UNCONSUMED_SLOT_V1: &'static str =
        "ak.contact.glare_unconsumed_slot.v1";
    pub const CONTACT_NO_OUTGOING_SLOT_V1: &'static str = "ak.contact.no_outgoing_slot.v1";
    pub const CONTACT_REQUEST_ACCEPTANCE_CORE_V1: &'static str =
        "ak.contact.request_acceptance_core.v1";
    pub const CONTACT_REQUEST_SOURCE_CHECKPOINT_V1: &'static str =
        "ak.contact.request_source_checkpoint.v1";
    pub const CONTROLLER_ACCOUNT_GATE_V1: &'static str = "ak.controller_account_gate.v1";
    pub const DEVICE_AUTHORIZE_ACCEPTED_DEVICE_POSSESSION_PROOF_V1: &'static str =
        "ak.device_authorize_accepted_device_possession_proof.v1";
    pub const DEVICE_AUTHORIZE_APPLET_MANAGED_POSSESSION_PROOF_V1: &'static str =
        "ak.device_authorize_applet_managed_possession_proof.v1";
    pub const DEVICE_AUTHORIZE_POSSESSION_PROOF_V1: &'static str =
        "ak.device_authorize_possession_proof.v1";
    pub const DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PROOF_V1: &'static str =
        "ak.device_authorize_recovery_possession_proof.v1";
    pub const FRANKING_PROOF_SIGNATURE_V1: &'static str = "ak.franking_proof.signature.v1";
    pub const HTTP_MESSAGE_SIGNATURE_V1: &'static str = "ak.http_message_signature.v1";
    pub const IDENTITY_RECOVERY_DEVICE_POSSESSION_V1: &'static str =
        "ak.identity.recovery_device_possession.v1";
    pub const IDENTITY_RECOVERY_POLICY_SIGNATURE_V1: &'static str =
        "ak.identity.recovery_policy.signature.v1";
    pub const IDENTITY_RECOVERY_PROOF_V1: &'static str = "ak.identity.recovery_proof.v1";
    pub const IDENTITY_RECOVERY_RECEIPT_SIGNATURE_V1: &'static str =
        "ak.identity.recovery_receipt.signature.v1";
    pub const IDENTITY_CREATION_CONTROL_PROOF_V1: &'static str =
        "ak.identity_creation_control_proof.v1";
    pub const KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1: &'static str =
        "ak.keypackage.claim_terminal_receipt.v1";
    pub const KEYPACKAGE_CONSUME_RECEIPT_V1: &'static str = "ak.keypackage.consume_receipt.v1";
    pub const MIMI_REPORTER_AUTHORITY_PROOF_V1: &'static str =
        "ak.mimi_reporter_authority_proof.v1";
    pub const MLS_RECIPIENT_DURABLE_RECEIPT_V1: &'static str =
        "ak.mls.recipient_durable_receipt.v1";
    pub const MLS_WELCOME_DELIVERY_SIGNATURE_V1: &'static str =
        "ak.mls_welcome_delivery_signature.v1";
    pub const PEER_CONTACT_CONTROL_RECEIPT_V1: &'static str = "ak.peer_contact.control_receipt.v1";
    pub const PEER_CONTACT_MIRROR_RECEIPT_V1: &'static str = "ak.peer_contact.mirror_receipt.v1";
    pub const REALM_ORGANIZATION_STATEMENT_V1: &'static str = "ak.realm.organization.statement.v1";
    pub const REALM_AUTHORITY_CURRENT_ASSERTION_SIGNATURE_V1: &'static str =
        "ak.realm_authority_current_assertion_signature.v1";
    pub const REALM_AUTHORITY_HANDOFF_NEW_ACCEPTANCE_SIGNATURE_V1: &'static str =
        "ak.realm_authority_handoff_new_acceptance_signature.v1";
    pub const REALM_AUTHORITY_HANDOFF_OLD_SIGNATURE_V1: &'static str =
        "ak.realm_authority_handoff_old_signature.v1";
    pub const REALM_COMMIT_SIGNATURE_V1: &'static str = "ak.realm_commit_signature.v1";
    pub const REALM_SNAPSHOT_SIGNATURE_V1: &'static str = "ak.realm_snapshot_signature.v1";
    pub const WEBSOCKET_AUTH_V1: &'static str = "ak.websocket_auth.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountabilityScopeSetV1 => Self::ACCOUNTABILITY_SCOPE_SET_V1,
            Self::AgentAuthorityStateEvidenceV1 => Self::AGENT_AUTHORITY_STATE_EVIDENCE_V1,
            Self::AppletManagedActorAuthoringRequestProofV1 => {
                Self::APPLET_MANAGED_ACTOR_AUTHORING_REQUEST_PROOF_V1
            }
            Self::AppletManagedActorBundleProofV1 => Self::APPLET_MANAGED_ACTOR_BUNDLE_PROOF_V1,
            Self::ApprovalSignatureV1 => Self::APPROVAL_SIGNATURE_V1,
            Self::ContactGlareUnconsumedSlotV1 => Self::CONTACT_GLARE_UNCONSUMED_SLOT_V1,
            Self::ContactNoOutgoingSlotV1 => Self::CONTACT_NO_OUTGOING_SLOT_V1,
            Self::ContactRequestAcceptanceCoreV1 => Self::CONTACT_REQUEST_ACCEPTANCE_CORE_V1,
            Self::ContactRequestSourceCheckpointV1 => Self::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,
            Self::ControllerAccountGateV1 => Self::CONTROLLER_ACCOUNT_GATE_V1,
            Self::DeviceAuthorizeAcceptedDevicePossessionProofV1 => {
                Self::DEVICE_AUTHORIZE_ACCEPTED_DEVICE_POSSESSION_PROOF_V1
            }
            Self::DeviceAuthorizeAppletManagedPossessionProofV1 => {
                Self::DEVICE_AUTHORIZE_APPLET_MANAGED_POSSESSION_PROOF_V1
            }
            Self::DeviceAuthorizePossessionProofV1 => Self::DEVICE_AUTHORIZE_POSSESSION_PROOF_V1,
            Self::DeviceAuthorizeRecoveryPossessionProofV1 => {
                Self::DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PROOF_V1
            }
            Self::FrankingProofSignatureV1 => Self::FRANKING_PROOF_SIGNATURE_V1,
            Self::HttpMessageSignatureV1 => Self::HTTP_MESSAGE_SIGNATURE_V1,
            Self::IdentityRecoveryDevicePossessionV1 => {
                Self::IDENTITY_RECOVERY_DEVICE_POSSESSION_V1
            }
            Self::IdentityRecoveryPolicySignatureV1 => Self::IDENTITY_RECOVERY_POLICY_SIGNATURE_V1,
            Self::IdentityRecoveryProofV1 => Self::IDENTITY_RECOVERY_PROOF_V1,
            Self::IdentityRecoveryReceiptSignatureV1 => {
                Self::IDENTITY_RECOVERY_RECEIPT_SIGNATURE_V1
            }
            Self::IdentityCreationControlProofV1 => Self::IDENTITY_CREATION_CONTROL_PROOF_V1,
            Self::KeypackageClaimTerminalReceiptV1 => Self::KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1,
            Self::KeypackageConsumeReceiptV1 => Self::KEYPACKAGE_CONSUME_RECEIPT_V1,
            Self::MimiReporterAuthorityProofV1 => Self::MIMI_REPORTER_AUTHORITY_PROOF_V1,
            Self::MlsRecipientDurableReceiptV1 => Self::MLS_RECIPIENT_DURABLE_RECEIPT_V1,
            Self::MlsWelcomeDeliverySignatureV1 => Self::MLS_WELCOME_DELIVERY_SIGNATURE_V1,
            Self::PeerContactControlReceiptV1 => Self::PEER_CONTACT_CONTROL_RECEIPT_V1,
            Self::PeerContactMirrorReceiptV1 => Self::PEER_CONTACT_MIRROR_RECEIPT_V1,
            Self::RealmOrganizationStatementV1 => Self::REALM_ORGANIZATION_STATEMENT_V1,
            Self::RealmAuthorityCurrentAssertionSignatureV1 => {
                Self::REALM_AUTHORITY_CURRENT_ASSERTION_SIGNATURE_V1
            }
            Self::RealmAuthorityHandoffNewAcceptanceSignatureV1 => {
                Self::REALM_AUTHORITY_HANDOFF_NEW_ACCEPTANCE_SIGNATURE_V1
            }
            Self::RealmAuthorityHandoffOldSignatureV1 => {
                Self::REALM_AUTHORITY_HANDOFF_OLD_SIGNATURE_V1
            }
            Self::RealmCommitSignatureV1 => Self::REALM_COMMIT_SIGNATURE_V1,
            Self::RealmSnapshotSignatureV1 => Self::REALM_SNAPSHOT_SIGNATURE_V1,
            Self::WebsocketAuthV1 => Self::WEBSOCKET_AUTH_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ACCOUNTABILITY_SCOPE_SET_V1 => Some(Self::AccountabilityScopeSetV1),
            Self::AGENT_AUTHORITY_STATE_EVIDENCE_V1 => Some(Self::AgentAuthorityStateEvidenceV1),
            Self::APPLET_MANAGED_ACTOR_AUTHORING_REQUEST_PROOF_V1 => {
                Some(Self::AppletManagedActorAuthoringRequestProofV1)
            }
            Self::APPLET_MANAGED_ACTOR_BUNDLE_PROOF_V1 => {
                Some(Self::AppletManagedActorBundleProofV1)
            }
            Self::APPROVAL_SIGNATURE_V1 => Some(Self::ApprovalSignatureV1),
            Self::CONTACT_GLARE_UNCONSUMED_SLOT_V1 => Some(Self::ContactGlareUnconsumedSlotV1),
            Self::CONTACT_NO_OUTGOING_SLOT_V1 => Some(Self::ContactNoOutgoingSlotV1),
            Self::CONTACT_REQUEST_ACCEPTANCE_CORE_V1 => Some(Self::ContactRequestAcceptanceCoreV1),
            Self::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1 => {
                Some(Self::ContactRequestSourceCheckpointV1)
            }
            Self::CONTROLLER_ACCOUNT_GATE_V1 => Some(Self::ControllerAccountGateV1),
            Self::DEVICE_AUTHORIZE_ACCEPTED_DEVICE_POSSESSION_PROOF_V1 => {
                Some(Self::DeviceAuthorizeAcceptedDevicePossessionProofV1)
            }
            Self::DEVICE_AUTHORIZE_APPLET_MANAGED_POSSESSION_PROOF_V1 => {
                Some(Self::DeviceAuthorizeAppletManagedPossessionProofV1)
            }
            Self::DEVICE_AUTHORIZE_POSSESSION_PROOF_V1 => {
                Some(Self::DeviceAuthorizePossessionProofV1)
            }
            Self::DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PROOF_V1 => {
                Some(Self::DeviceAuthorizeRecoveryPossessionProofV1)
            }
            Self::FRANKING_PROOF_SIGNATURE_V1 => Some(Self::FrankingProofSignatureV1),
            Self::HTTP_MESSAGE_SIGNATURE_V1 => Some(Self::HttpMessageSignatureV1),
            Self::IDENTITY_RECOVERY_DEVICE_POSSESSION_V1 => {
                Some(Self::IdentityRecoveryDevicePossessionV1)
            }
            Self::IDENTITY_RECOVERY_POLICY_SIGNATURE_V1 => {
                Some(Self::IdentityRecoveryPolicySignatureV1)
            }
            Self::IDENTITY_RECOVERY_PROOF_V1 => Some(Self::IdentityRecoveryProofV1),
            Self::IDENTITY_RECOVERY_RECEIPT_SIGNATURE_V1 => {
                Some(Self::IdentityRecoveryReceiptSignatureV1)
            }
            Self::IDENTITY_CREATION_CONTROL_PROOF_V1 => Some(Self::IdentityCreationControlProofV1),
            Self::KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1 => {
                Some(Self::KeypackageClaimTerminalReceiptV1)
            }
            Self::KEYPACKAGE_CONSUME_RECEIPT_V1 => Some(Self::KeypackageConsumeReceiptV1),
            Self::MIMI_REPORTER_AUTHORITY_PROOF_V1 => Some(Self::MimiReporterAuthorityProofV1),
            Self::MLS_RECIPIENT_DURABLE_RECEIPT_V1 => Some(Self::MlsRecipientDurableReceiptV1),
            Self::MLS_WELCOME_DELIVERY_SIGNATURE_V1 => Some(Self::MlsWelcomeDeliverySignatureV1),
            Self::PEER_CONTACT_CONTROL_RECEIPT_V1 => Some(Self::PeerContactControlReceiptV1),
            Self::PEER_CONTACT_MIRROR_RECEIPT_V1 => Some(Self::PeerContactMirrorReceiptV1),
            Self::REALM_ORGANIZATION_STATEMENT_V1 => Some(Self::RealmOrganizationStatementV1),
            Self::REALM_AUTHORITY_CURRENT_ASSERTION_SIGNATURE_V1 => {
                Some(Self::RealmAuthorityCurrentAssertionSignatureV1)
            }
            Self::REALM_AUTHORITY_HANDOFF_NEW_ACCEPTANCE_SIGNATURE_V1 => {
                Some(Self::RealmAuthorityHandoffNewAcceptanceSignatureV1)
            }
            Self::REALM_AUTHORITY_HANDOFF_OLD_SIGNATURE_V1 => {
                Some(Self::RealmAuthorityHandoffOldSignatureV1)
            }
            Self::REALM_COMMIT_SIGNATURE_V1 => Some(Self::RealmCommitSignatureV1),
            Self::REALM_SNAPSHOT_SIGNATURE_V1 => Some(Self::RealmSnapshotSignatureV1),
            Self::WEBSOCKET_AUTH_V1 => Some(Self::WebsocketAuthV1),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum AeadProfileId {
    Chacha20Poly1305V1,
    Xchacha20Poly1305V1,
}

impl AeadProfileId {
    pub const ALL: &'static [Self] = &[Self::Chacha20Poly1305V1, Self::Xchacha20Poly1305V1];

    pub const CHACHA20_POLY1305_V1: &'static str = "ak.aead.chacha20_poly1305.v1";
    pub const XCHACHA20_POLY1305_V1: &'static str = "ak.aead.xchacha20_poly1305.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chacha20Poly1305V1 => Self::CHACHA20_POLY1305_V1,
            Self::Xchacha20Poly1305V1 => Self::XCHACHA20_POLY1305_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::CHACHA20_POLY1305_V1 => Some(Self::Chacha20Poly1305V1),
            Self::XCHACHA20_POLY1305_V1 => Some(Self::Xchacha20Poly1305V1),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum HpkeSuiteId {
    P256AeadAes256gcmV1,
    X25519AeadAes256gcmV1,
    X25519AeadChacha20poly1305V1,
    XwingAeadChacha20poly1305V1,
}

impl HpkeSuiteId {
    pub const ALL: &'static [Self] = &[
        Self::P256AeadAes256gcmV1,
        Self::X25519AeadAes256gcmV1,
        Self::X25519AeadChacha20poly1305V1,
        Self::XwingAeadChacha20poly1305V1,
    ];

    pub const P256_AEAD_AES256GCM_V1: &'static str = "ak.hpke_p256_aead_aes256gcm.v1";
    pub const X25519_AEAD_AES256GCM_V1: &'static str = "ak.hpke_x25519_aead_aes256gcm.v1";
    pub const X25519_AEAD_CHACHA20POLY1305_V1: &'static str =
        "ak.hpke_x25519_aead_chacha20poly1305.v1";
    pub const XWING_AEAD_CHACHA20POLY1305_V1: &'static str =
        "ak.hpke_xwing_aead_chacha20poly1305.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P256AeadAes256gcmV1 => Self::P256_AEAD_AES256GCM_V1,
            Self::X25519AeadAes256gcmV1 => Self::X25519_AEAD_AES256GCM_V1,
            Self::X25519AeadChacha20poly1305V1 => Self::X25519_AEAD_CHACHA20POLY1305_V1,
            Self::XwingAeadChacha20poly1305V1 => Self::XWING_AEAD_CHACHA20POLY1305_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::P256_AEAD_AES256GCM_V1 => Some(Self::P256AeadAes256gcmV1),
            Self::X25519_AEAD_AES256GCM_V1 => Some(Self::X25519AeadAes256gcmV1),
            Self::X25519_AEAD_CHACHA20POLY1305_V1 => Some(Self::X25519AeadChacha20poly1305V1),
            Self::XWING_AEAD_CHACHA20POLY1305_V1 => Some(Self::XwingAeadChacha20poly1305V1),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ExporterLabelId {
    ReactionRoutingRootV1,
    ReactionRoutingV1,
    RtcFrameKeyV1,
    RtcRecordingKeyV1,
    RtcTranscriptKeyV1,
    SignalRootV1,
    SignalV1,
}

impl ExporterLabelId {
    pub const ALL: &'static [Self] = &[
        Self::ReactionRoutingRootV1,
        Self::ReactionRoutingV1,
        Self::RtcFrameKeyV1,
        Self::RtcRecordingKeyV1,
        Self::RtcTranscriptKeyV1,
        Self::SignalRootV1,
        Self::SignalV1,
    ];

    pub const REACTION_ROUTING_ROOT_V1: &'static str = "ak.reaction-routing-root-v1";
    pub const REACTION_ROUTING_V1: &'static str = "ak.reaction-routing-v1";
    pub const RTC_FRAME_KEY_V1: &'static str = "ak.rtc-frame-key/v1";
    pub const RTC_RECORDING_KEY_V1: &'static str = "ak.rtc-recording-key/v1";
    pub const RTC_TRANSCRIPT_KEY_V1: &'static str = "ak.rtc-transcript-key/v1";
    pub const SIGNAL_ROOT_V1: &'static str = "ak.signal-root-v1";
    pub const SIGNAL_V1: &'static str = "ak.signal-v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReactionRoutingRootV1 => Self::REACTION_ROUTING_ROOT_V1,
            Self::ReactionRoutingV1 => Self::REACTION_ROUTING_V1,
            Self::RtcFrameKeyV1 => Self::RTC_FRAME_KEY_V1,
            Self::RtcRecordingKeyV1 => Self::RTC_RECORDING_KEY_V1,
            Self::RtcTranscriptKeyV1 => Self::RTC_TRANSCRIPT_KEY_V1,
            Self::SignalRootV1 => Self::SIGNAL_ROOT_V1,
            Self::SignalV1 => Self::SIGNAL_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::REACTION_ROUTING_ROOT_V1 => Some(Self::ReactionRoutingRootV1),
            Self::REACTION_ROUTING_V1 => Some(Self::ReactionRoutingV1),
            Self::RTC_FRAME_KEY_V1 => Some(Self::RtcFrameKeyV1),
            Self::RTC_RECORDING_KEY_V1 => Some(Self::RtcRecordingKeyV1),
            Self::RTC_TRANSCRIPT_KEY_V1 => Some(Self::RtcTranscriptKeyV1),
            Self::SIGNAL_ROOT_V1 => Some(Self::SignalRootV1),
            Self::SIGNAL_V1 => Some(Self::SignalV1),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofContextDescriptor {
    pub id: ProofContextId,
    pub context: &'static str,
    pub object_family: &'static str,
    pub consumer_operation: Option<&'static str>,
    pub binding_fields: &'static [&'static str],
    pub schema_ref: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExporterLabelDescriptor {
    pub id: ExporterLabelId,
    pub label: &'static str,
    pub primitive: Option<&'static str>,
    pub context_fields: &'static [&'static str],
    pub output_bytes: &'static str,
    pub empty_context_forbidden: bool,
    pub forbid_reuse_with: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgorithmSuiteDescriptor {
    pub canonical_id: &'static str,
    pub status: &'static str,
    pub role: &'static str,
    pub profile_gate: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsExtensionDescriptor {
    pub name: &'static str,
    pub codepoint: &'static str,
    pub status: &'static str,
    pub profile_id: Option<&'static str>,
    pub rejection_error: Option<&'static str>,
}

pub const PROOF_CONTEXTS: &[ProofContextDescriptor] = &[
    ProofContextDescriptor {
        id: ProofContextId::AccountBindingReceiptProofV1,
        context: "ak.account_binding_receipt_proof.v1",
        object_family: "account_binding_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "account_authority_id",
            "account_subject",
            "principal_id",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/account-operations.schema.json#/$defs/account_binding_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::AccountHandoffAuthenticationProofV1,
        context: "ak.account_handoff_authentication_proof.v1",
        object_family: "account_handoff_authentication",
        consumer_operation: None,
        binding_fields: &[
            "proof_kind",
            "challenge",
            "request_canonical_digest",
            "audience_id",
            "issuer_uri",
            "client_id",
            "redirect_uri",
            "state",
            "nonce",
            "authorization_code",
            "code_verifier",
        ],
        schema_ref: "schemas/account-operations.schema.json#/$defs/account_handoff_authentication_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::AccountRegistrationControlProofV1,
        context: "ak.account_registration_control_proof.v1",
        object_family: "account_registration_control_proof",
        consumer_operation: None,
        binding_fields: &[
            "proof_kind",
            "challenge_id",
            "challenge",
            "purpose",
            "request_canonical_digest",
            "account_subject",
            "principal_id",
            "did",
            "did_version_id",
            "log_head_digest",
            "control_key_digest",
            "dpop_jkt",
            "audience_id",
            "origin",
            "trust_domain",
            "issued_at",
            "expires_at",
            "verification_method",
            "witness_evidence?",
        ],
        schema_ref: "schemas/account-operations.schema.json#/$defs/account_registration_control_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::AccountStatusRecordProofV1,
        context: "ak.account_status_record_proof.v1",
        object_family: "account_status_record",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/account-operations.schema.json#/$defs/account_status_record",
    },
    ProofContextDescriptor {
        id: ProofContextId::AccountStatusReplicationReceiptProofV1,
        context: "ak.account_status_replication_receipt_proof.v1",
        object_family: "account_status_replication_receipt",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/account-operations.schema.json#/$defs/account_status_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::AccountabilityGrantProofV1,
        context: "ak.accountability_grant_proof.v1",
        object_family: "accountability_grant",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer_id",
            "subject_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/accountability-grant.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AgentRequestedScopeDisclosureProofV1,
        context: "ak.agent_requested_scope_disclosure_proof.v1",
        object_family: "agent_requested_scope_disclosure",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "controller_principal_id",
            "agent_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/agent-requested-scope-disclosure.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AgentRuntimeKeyPossessionProofV1,
        context: "ak.agent_runtime_key_possession_proof.v1",
        object_family: "agent_runtime_key_possession",
        consumer_operation: None,
        binding_fields: &[
            "kind",
            "verification_method",
            "signature_algorithm",
            "challenge",
            "audience_id",
            "created_at",
            "expires_at",
            "pairing_code",
            "runtime_key_binding_digest",
        ],
        schema_ref: "schemas/agent-operations.schema.json#/$defs/agent_runtime_key_possession_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::AgentSelectorClaimProofV1,
        context: "ak.agent_selector_claim_proof.v1",
        object_family: "agent_selector_claim",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "controller_subject_id",
            "subject_account_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/agent-selector-claim.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AgentSessionRefreshProofV1,
        context: "ak.agent_session_refresh_proof.v1",
        object_family: "agent_session_refresh_proof",
        consumer_operation: None,
        binding_fields: &[
            "request_canonical_digest",
            "audience_id",
            "issued_at",
            "expires_at",
            "verification_method",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/AgentSessionRefreshProof",
    },
    ProofContextDescriptor {
        id: ProofContextId::AppletPackageProofV1,
        context: "ak.applet_package_proof.v1",
        object_family: "applet_package",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "applet_id",
            "controller_principal_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/applet-package.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::DeviceProjectionAttestationProofV1,
        context: "ak.device_projection_attestation_proof.v1",
        object_family: "device_projection_attestation",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "account_id",
            "device_id",
            "device_signing_key_did",
            "hpke_key",
            "device_authorize_event_id",
            "authorized_generation_ref",
            "device_status",
            "attested_at",
            "expires_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/keys-operations.schema.json#/$defs/device_projection_attestation",
    },
    ProofContextDescriptor {
        id: ProofContextId::DidWebvhWitnessReceiptProofV1,
        context: "ak.did_webvh_witness_receipt_proof.v1",
        object_family: "did_webvh_witness_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer_id",
            "subject_did",
            "version_id",
            "witness_did",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/did-webvh-witness-receipt.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::EventProofV1,
        context: "ak.event_proof.v1",
        object_family: "event_envelope",
        consumer_operation: None,
        binding_fields: &[
            "event_digest",
            "actor_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/event-envelope.schema.json#/$defs/event_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::ExtensionManifestProofV1,
        context: "ak.extension_manifest_proof.v1",
        object_family: "extension_manifest",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "extension_id",
            "publisher_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/extension-manifest.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::HandleClaimProofV1,
        context: "ak.handle_claim_proof.v1",
        object_family: "handle_claim",
        consumer_operation: None,
        binding_fields: &[
            "kind",
            "verification_method",
            "payload_digest",
            "created_at",
            "domain",
            "audience",
            "proof_purpose",
        ],
        schema_ref: "schemas/handle-claim.schema.json#/$defs/handle_claim_core",
    },
    ProofContextDescriptor {
        id: ProofContextId::HandleClaimRevocationV1,
        context: "ak.handle_claim_revocation.v1",
        object_family: "handle_claim_revocation",
        consumer_operation: None,
        binding_fields: &[
            "kind",
            "verification_method",
            "payload_digest",
            "created_at",
            "domain",
            "audience",
            "proof_purpose",
        ],
        schema_ref: "schemas/handle-claim.schema.json#/$defs/handle_claim_revocation",
    },
    ProofContextDescriptor {
        id: ProofContextId::HandleClaimStatusV1,
        context: "ak.handle_claim_status.v1",
        object_family: "handle_claim_status",
        consumer_operation: None,
        binding_fields: &[
            "kind",
            "verification_method",
            "payload_digest",
            "created_at",
            "domain",
            "audience",
            "proof_purpose",
        ],
        schema_ref: "schemas/handle-claim.schema.json#/$defs/handle_claim_status_view",
    },
    ProofContextDescriptor {
        id: ProofContextId::IdentityReceiptProofV1,
        context: "ak.identity_receipt_proof.v1",
        object_family: "identity_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "registry_id",
            "subject_did",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/identity-receipt.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::JoinGateProofV1,
        context: "ak.join_gate_proof.v1",
        object_family: "join_gate_proof",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "gate_id",
            "realm_id",
            "applicant_actor_id",
            "policy_digest",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/event-payload.schema.json#/$defs/join_gate_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::KeyBackupDeleteProofV1,
        context: "ak.key_backup_delete_proof.v1",
        object_family: "key_backup_delete_authority",
        consumer_operation: Some("ak.self.keys.backups.resource.delete.v1"),
        binding_fields: &[
            "payload_digest",
            "operation",
            "request_id",
            "account_id",
            "backup_id",
            "reason",
            "challenge_id",
            "challenge",
            "nonce",
            "audience",
            "service_id",
            "issued_at",
            "expires_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/high-risk-authority-proof.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::MimiIdentifierQueryOutcomeProofV1,
        context: "ak.mimi_identifier_query_outcome_proof.v1",
        object_family: "mimi_identifier_query_outcome",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "operation_id",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/mimi-operations.schema.json#/$defs/mimi_identifier_query_outcome",
    },
    ProofContextDescriptor {
        id: ProofContextId::MimiIdentifierQueryRequestProofV1,
        context: "ak.mimi_identifier_query_request_proof.v1",
        object_family: "mimi_identifier_query_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer?",
            "operation_id",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/mimi-operations.schema.json#/$defs/mimi_identifier_query_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::MimiKeyMaterialOutcomeProofV1,
        context: "ak.mimi_key_material_outcome_proof.v1",
        object_family: "mimi_key_material_outcome",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "operation_id",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/mimi-operations.schema.json#/$defs/mimi_key_material_outcome",
    },
    ProofContextDescriptor {
        id: ProofContextId::MimiKeyMaterialRequestProofV1,
        context: "ak.mimi_key_material_request_proof.v1",
        object_family: "mimi_key_material_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "strand_id",
            "device_id",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/mimi-operations.schema.json#/$defs/mimi_key_material_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::MimiProviderDirectoryProofV1,
        context: "ak.mimi_provider_directory_proof.v1",
        object_family: "mimi_provider_directory",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "schema",
            "service_id",
            "service_kind",
            "supported_profiles",
            "mimi",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/mimi-interop.schema.json#/$defs/provider_directory",
    },
    ProofContextDescriptor {
        id: ProofContextId::MimiRequestConsentRequestProofV1,
        context: "ak.mimi_request_consent_request_proof.v1",
        object_family: "mimi_request_consent_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "holder_account_id",
            "purpose",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/mimi-operations.schema.json#/$defs/mimi_request_consent_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::MimiUpdateConsentRequestProofV1,
        context: "ak.mimi_update_consent_request_proof.v1",
        object_family: "mimi_update_consent_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "consent_id",
            "decision",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/mimi-operations.schema.json#/$defs/mimi_update_consent_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::OrganizationRegistrationControlProofV1,
        context: "ak.organization_registration_control_proof.v1",
        object_family: "organization_registration_control_proof",
        consumer_operation: None,
        binding_fields: &[
            "challenge_id",
            "organization_id",
            "organization_did",
            "local_admin_subject_id",
            "version_id",
            "log_head_digest",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/OrganizationControlProof",
    },
    ProofContextDescriptor {
        id: ProofContextId::OrganizationRegistrationReceiptProofV1,
        context: "ak.organization_registration_receipt_proof.v1",
        object_family: "organization_registration_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer_id",
            "registration_receipt_id",
            "organization_id",
            "organization_did",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationReceipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::PrincipalLocatorProofV1,
        context: "ak.principal_locator_proof.v1",
        object_family: "principal_locator",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "account_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/principal-locator.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::PrincipalResolutionProjectionAttestationProofV1,
        context: "ak.principal_resolution_projection_attestation_proof.v1",
        object_family: "principal_resolution_projection_attestation",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "account_id",
            "resolution_projection",
            "method_history_evidence_digest",
            "issued_at",
            "expires_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/identity-resolution.schema.json#/$defs/principal_resolution_projection_attestation",
    },
    ProofContextDescriptor {
        id: ProofContextId::PushRegistrationInstallationReceiptProofV1,
        context: "ak.push_registration_installation_receipt_proof.v1",
        object_family: "push_registration_installation_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "registration_id",
            "push_target_id",
            "device_id",
            "state",
            "request_digest",
            "source_station_id",
            "destination_gateway_id",
            "verification_method",
            "created_at",
            "audience",
        ],
        schema_ref: "schemas/push-operations.schema.json#/$defs/push_registration_installation_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::RegistrationDidEvidenceControlProofV1,
        context: "ak.registration_did_evidence_control_proof.v1",
        object_family: "registration_did_evidence_control",
        consumer_operation: None,
        binding_fields: &[
            "principal_id",
            "did",
            "adapter_version",
            "method_history_head",
            "version_id",
            "control_key_digest",
            "method_evidence_digest",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/registration-did-evidence.schema.json#/$defs/registration_did_evidence_draft",
    },
    ProofContextDescriptor {
        id: ProofContextId::ServiceRegistrationReceiptProofV1,
        context: "ak.service_registration_receipt_proof.v1",
        object_family: "service_registration_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "provider_id",
            "registration_receipt_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/ServiceRegistrationReceipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::SessionGrantAcceptedDevicePossessionProofV1,
        context: "ak.session_grant_accepted_device_possession_proof.v1",
        object_family: "session_grant_accepted_device_possession",
        consumer_operation: None,
        binding_fields: &[
            "purpose",
            "request_id?",
            "account_subject?",
            "account_handoff_grant_digest?",
            "predecessor_session_grant_id?",
            "account_id",
            "device_id",
            "audience_id",
            "holder_jkt",
            "session_intent_digest",
            "issued_at",
            "expires_at",
            "verification_method",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/AcceptedDevicePossessionProof",
    },
    ProofContextDescriptor {
        id: ProofContextId::SignalProofV1,
        context: "ak.signal_proof.v1",
        object_family: "signal_envelope",
        consumer_operation: None,
        binding_fields: &[
            "envelope_digest",
            "sender_actor_id",
            "sender_device_id?",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/signal-envelope.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::ThirdPartyInviteAcceptanceAttestationProofV1,
        context: "ak.third_party_invite_acceptance_attestation_proof.v1",
        object_family: "third_party_invite_acceptance_attestation",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/invite.schema.json#/$defs/third_party_invite_acceptance_attestation",
    },
    ProofContextDescriptor {
        id: ProofContextId::ThirdPartyInviteProvisionRequestProofV1,
        context: "ak.third_party_invite_provision_request_proof.v1",
        object_family: "third_party_invite_provision_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/invite.schema.json#/$defs/third_party_invite_provision_request_body",
    },
];

pub const EXPORTER_LABELS: &[ExporterLabelDescriptor] = &[
    ExporterLabelDescriptor {
        id: ExporterLabelId::ReactionRoutingRootV1,
        label: "ak.reaction-routing-root-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["effective_scope"],
        output_bytes: "KDF.Nh",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.signal-root-v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::ReactionRoutingV1,
        label: "ak.reaction-routing-v1",
        primitive: Some("ExpandWithLabel"),
        context_fields: &["effective_scope", "target_ref", "routing_window"],
        output_bytes: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.signal-v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::RtcFrameKeyV1,
        label: "ak.rtc-frame-key/v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &[
            "realm_id",
            "call_id",
            "focus_id",
            "epoch_id",
            "participant_id",
            "device_id",
        ],
        output_bytes: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.rtc-recording-key/v1", "ak.rtc-transcript-key/v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::RtcRecordingKeyV1,
        label: "ak.rtc-recording-key/v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &[
            "realm_id",
            "call_id",
            "focus_id",
            "recording_id",
            "media_service_id",
            "recording_start_event_id",
        ],
        output_bytes: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.rtc-frame-key/v1", "ak.rtc-transcript-key/v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::RtcTranscriptKeyV1,
        label: "ak.rtc-transcript-key/v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &[
            "realm_id",
            "call_id",
            "focus_id",
            "recording_id",
            "media_service_id",
            "transcript_start_event_id",
        ],
        output_bytes: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.rtc-frame-key/v1", "ak.rtc-recording-key/v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::SignalRootV1,
        label: "ak.signal-root-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["effective_scope"],
        output_bytes: "KDF.Nh",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.reaction-routing-root-v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::SignalV1,
        label: "ak.signal-v1",
        primitive: Some("ExpandWithLabel"),
        context_fields: &["sender_domain"],
        output_bytes: "AEAD.Nk",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.reaction-routing-v1"],
    },
];

pub const DIGEST_SUITES: &[AlgorithmSuiteDescriptor] = &[
    AlgorithmSuiteDescriptor {
        canonical_id: "blake3",
        status: "active",
        role: "v1_optional_interop",
        profile_gate: Some("ak.profile.hash.blake3.v1"),
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "cbor.sha256",
        status: "reserved",
        role: "reserved_encoding_extension",
        profile_gate: Some("ak.profile.encoding.cbor.v1"),
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "sha256",
        status: "active",
        role: "v1_content_address_must",
        profile_gate: None,
    },
];

pub const SIGNATURE_ALGORITHMS: &[AlgorithmSuiteDescriptor] = &[
    AlgorithmSuiteDescriptor {
        canonical_id: "ECDSA-P256-SHA256",
        status: "active",
        role: "v1_optional_interop",
        profile_gate: Some("ak.profile.signature.ecdsa_p256.v1"),
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "Ed25519",
        status: "active",
        role: "v1_default_must",
        profile_gate: None,
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "Ed25519+ML-DSA-65",
        status: "reserved",
        role: "reserved_hybrid_signature_policy",
        profile_gate: Some("ak.profile.signature.pqc.v1"),
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "ML-DSA-65",
        status: "reserved",
        role: "reserved_pqc_signature",
        profile_gate: Some("ak.profile.signature.pqc.v1"),
    },
];

pub const HPKE_SUITES: &[AlgorithmSuiteDescriptor] = &[
    AlgorithmSuiteDescriptor {
        canonical_id: "ak.hpke_p256_aead_aes256gcm.v1",
        status: "active",
        role: "v1_profile_gated_interop",
        profile_gate: Some("ak.profile.hpke.p256.v1"),
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "ak.hpke_x25519_aead_aes256gcm.v1",
        status: "active",
        role: "v1_optional_interop",
        profile_gate: None,
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "ak.hpke_x25519_aead_chacha20poly1305.v1",
        status: "active",
        role: "v1_default_must",
        profile_gate: None,
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "ak.hpke_xwing_aead_chacha20poly1305.v1",
        status: "reserved",
        role: "reserved_pqc_hybrid",
        profile_gate: Some("ak.profile.kem.hybrid_xwing.v1"),
    },
];

pub const MLS_CIPHERSUITES: &[AlgorithmSuiteDescriptor] = &[
    AlgorithmSuiteDescriptor {
        canonical_id: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        status: "active",
        role: "v1_default_must",
        profile_gate: None,
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
        status: "reserved",
        role: "reserved_software_friendly_interop",
        profile_gate: Some("ak.profile.mls_ciphersuite.chacha20poly1305.v1"),
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519",
        status: "reserved",
        role: "reserved_pqc_hybrid",
        profile_gate: Some("ak.profile.kem.hybrid_xwing.v1"),
    },
    AlgorithmSuiteDescriptor {
        canonical_id: "MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44",
        status: "reserved",
        role: "reserved_pqc_hybrid_authentication",
        profile_gate: Some("ak.profile.mls_ciphersuite.pq_auth.v1"),
    },
];

pub const MLS_EXTENSIONS: &[MlsExtensionDescriptor] = &[
    MlsExtensionDescriptor {
        name: "mls_governance_binding",
        codepoint: "0xF1C0",
        status: "active",
        profile_id: None,
        rejection_error: None,
    },
    MlsExtensionDescriptor {
        name: "required_capabilities",
        codepoint: "0x0003",
        status: "active",
        profile_id: None,
        rejection_error: None,
    },
];

pub fn proof_context(value: &str) -> Option<&'static ProofContextDescriptor> {
    ProofContextId::from_wire(value).map(proof_context_descriptor)
}

pub const fn proof_context_descriptor(id: ProofContextId) -> &'static ProofContextDescriptor {
    &PROOF_CONTEXTS[id as usize]
}

pub fn exporter_label(value: &str) -> Option<&'static ExporterLabelDescriptor> {
    ExporterLabelId::from_wire(value).map(exporter_label_descriptor)
}

pub const fn exporter_label_descriptor(id: ExporterLabelId) -> &'static ExporterLabelDescriptor {
    &EXPORTER_LABELS[id as usize]
}
