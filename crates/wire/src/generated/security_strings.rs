//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/proof-context-registry.json; version=2026-08-18.1;
//! sha256=1c75280f5aa5247c867dc66e4a8a82d5824f5013be77d0f37ff2e9792cd1c7d7 Input: registry/
//! exporter-label-registry.json; version=2026-08-13.2;
//! sha256=d34969b38e82214fab7eda88928c1ee2c250b29be58d0c5968666ebb5ea54533 Input: registry/
//! digest-suite-registry.json; version=2026-08-18;
//! sha256=7b9f5368e30cebd43c509db7815b9a01681f8cf11147600f6be16bddcc74657f Input: registry/
//! signature-alg-registry.json; version=2026-08-18.1;
//! sha256=2bd41f0302e641c5a9eac6297b0e500c9d7100bb925c1f395d7198a7b4ac3e3c Input: registry/
//! hpke-suite-registry.json; version=2026-08-18;
//! sha256=00564ec5d5f123c750c1db89e342e037d7bc8b12b42fb1f94eadd34fb3c5df41 Input: registry/
//! mls-ciphersuite-registry.json; version=2026-08-18;
//! sha256=8a270bf4fb05fa17f1594d61252f573fff6eca36e2da7afa910fc44c7d334dad Input: registry/
//! mls-extension-registry.json; version=2026-06-03;
//! sha256=4f759c4fe77917be80bb0b46b561daf1b7205288bc32f6b7a80d0d3be80242b8 Input: registry/
//! aead-profile-registry.json; version=2026-08-16.1;
//! sha256=5cab256353caa112d59f4ba10390715eaa27a3c3b530ee1766f01d35a4ea72de
//! Entries: proof_contexts=63, exporter_labels=9, digest_suites=3, signature_algorithms=4,
//! hpke_suites=4, mls_ciphersuites=4, mls_extensions=1, domain_separations=23, aead_profiles=2

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
    AppletPackageProofV1,
    AuditReleaseAttestationProofV1,
    AuditRywReceiptProofV1,
    AuthorizationLeaseProofV1,
    ControlProposalAuthorityAckProofV1,
    ControlProposalDecisionProofV1,
    DeviceAuthorizeAcceptedDevicePossessionProofV1,
    DeviceAuthorizePossessionProofV1,
    DeviceAuthorizeRecoveryPossessionProofV1,
    DeviceProjectionAttestationProofV1,
    DeviceRevocationGateDecisionProofV1,
    DidWebvhWitnessReceiptProofV1,
    DirectoryGovernanceRequestProofV1,
    DirectoryListHandlesForSubjectRequestProofV1,
    DirectoryResolveAgentSelectorRequestProofV1,
    DirectoryResolveHandleRequestProofV1,
    DirectoryResolveOrganizationRequestProofV1,
    DirectoryResolveTargetRequestProofV1,
    EventProofV1,
    ExtensionManifestProofV1,
    HandleClaimProofV1,
    IdentityCreationControlProofV1,
    IdentityReceiptProofV1,
    IngressReceiptProofV1,
    JoinApplicationCancelReceiptProofV1,
    JoinApplicationReceiptProofV1,
    JoinApplicationReviewReceiptProofV1,
    KeyBackupDeleteProofV1,
    MemberDeliveryBindingCandidateProofV1,
    MimiGroupInfoOutcomeProofV1,
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
    PrincipalServerAdmissionProofV1,
    RangeCompletenessAttestationProofV1,
    RealmJoinCandidateProofV1,
    RealmKeyShareSenderProofV1,
    ReceiptProofV1,
    RegistrationDidEvidenceControlProofV1,
    ServiceRegistrationReceiptProofV1,
    ServiceResolutionPublishAckProofV1,
    ServiceResolutionRecordProofV1,
    ServiceRouteHandoverNoticeProofV1,
    SignalProofV1,
    SnapshotProofV1,
    SnapshotWitnessAttestationProofV1,
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
        Self::AppletPackageProofV1,
        Self::AuditReleaseAttestationProofV1,
        Self::AuditRywReceiptProofV1,
        Self::AuthorizationLeaseProofV1,
        Self::ControlProposalAuthorityAckProofV1,
        Self::ControlProposalDecisionProofV1,
        Self::DeviceAuthorizeAcceptedDevicePossessionProofV1,
        Self::DeviceAuthorizePossessionProofV1,
        Self::DeviceAuthorizeRecoveryPossessionProofV1,
        Self::DeviceProjectionAttestationProofV1,
        Self::DeviceRevocationGateDecisionProofV1,
        Self::DidWebvhWitnessReceiptProofV1,
        Self::DirectoryGovernanceRequestProofV1,
        Self::DirectoryListHandlesForSubjectRequestProofV1,
        Self::DirectoryResolveAgentSelectorRequestProofV1,
        Self::DirectoryResolveHandleRequestProofV1,
        Self::DirectoryResolveOrganizationRequestProofV1,
        Self::DirectoryResolveTargetRequestProofV1,
        Self::EventProofV1,
        Self::ExtensionManifestProofV1,
        Self::HandleClaimProofV1,
        Self::IdentityCreationControlProofV1,
        Self::IdentityReceiptProofV1,
        Self::IngressReceiptProofV1,
        Self::JoinApplicationCancelReceiptProofV1,
        Self::JoinApplicationReceiptProofV1,
        Self::JoinApplicationReviewReceiptProofV1,
        Self::KeyBackupDeleteProofV1,
        Self::MemberDeliveryBindingCandidateProofV1,
        Self::MimiGroupInfoOutcomeProofV1,
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
        Self::PrincipalServerAdmissionProofV1,
        Self::RangeCompletenessAttestationProofV1,
        Self::RealmJoinCandidateProofV1,
        Self::RealmKeyShareSenderProofV1,
        Self::ReceiptProofV1,
        Self::RegistrationDidEvidenceControlProofV1,
        Self::ServiceRegistrationReceiptProofV1,
        Self::ServiceResolutionPublishAckProofV1,
        Self::ServiceResolutionRecordProofV1,
        Self::ServiceRouteHandoverNoticeProofV1,
        Self::SignalProofV1,
        Self::SnapshotProofV1,
        Self::SnapshotWitnessAttestationProofV1,
    ];

    pub const ACCOUNT_BINDING_RECEIPT_PROOF_V1: &'static str =
        "ak.account-binding-receipt-proof-v1";
    pub const ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_V1: &'static str =
        "ak.account-handoff-authentication-proof-v1";
    pub const ACCOUNT_REGISTRATION_CONTROL_PROOF_V1: &'static str =
        "ak.account-registration-control-proof-v1";
    pub const ACCOUNT_STATUS_RECORD_PROOF_V1: &'static str = "ak.account-status-record-proof-v1";
    pub const ACCOUNT_STATUS_REPLICATION_RECEIPT_PROOF_V1: &'static str =
        "ak.account-status-replication-receipt-proof-v1";
    pub const ACCOUNTABILITY_GRANT_PROOF_V1: &'static str = "ak.accountability-grant-proof-v1";
    pub const AGENT_REQUESTED_SCOPE_DISCLOSURE_PROOF_V1: &'static str =
        "ak.agent-requested-scope-disclosure-proof-v1";
    pub const AGENT_RUNTIME_KEY_POSSESSION_PROOF_V1: &'static str =
        "ak.agent-runtime-key-possession-proof-v1";
    pub const AGENT_SELECTOR_CLAIM_PROOF_V1: &'static str = "ak.agent-selector-claim-proof-v1";
    pub const APPLET_PACKAGE_PROOF_V1: &'static str = "ak.applet-package-proof-v1";
    pub const AUDIT_RELEASE_ATTESTATION_PROOF_V1: &'static str =
        "ak.audit-release-attestation-proof-v1";
    pub const AUDIT_RYW_RECEIPT_PROOF_V1: &'static str = "ak.audit-ryw-receipt-proof-v1";
    pub const AUTHORIZATION_LEASE_PROOF_V1: &'static str = "ak.authorization-lease-proof-v1";
    pub const CONTROL_PROPOSAL_AUTHORITY_ACK_PROOF_V1: &'static str =
        "ak.control-proposal-authority-ack-proof-v1";
    pub const CONTROL_PROPOSAL_DECISION_PROOF_V1: &'static str =
        "ak.control-proposal-decision-proof-v1";
    pub const DEVICE_AUTHORIZE_ACCEPTED_DEVICE_POSSESSION_PROOF_V1: &'static str =
        "ak.device-authorize-accepted-device-possession-proof-v1";
    pub const DEVICE_AUTHORIZE_POSSESSION_PROOF_V1: &'static str =
        "ak.device-authorize-possession-proof-v1";
    pub const DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PROOF_V1: &'static str =
        "ak.device-authorize-recovery-possession-proof-v1";
    pub const DEVICE_PROJECTION_ATTESTATION_PROOF_V1: &'static str =
        "ak.device-projection-attestation-proof-v1";
    pub const DEVICE_REVOCATION_GATE_DECISION_PROOF_V1: &'static str =
        "ak.device-revocation-gate-decision-proof-v1";
    pub const DID_WEBVH_WITNESS_RECEIPT_PROOF_V1: &'static str =
        "ak.did-webvh-witness-receipt-proof-v1";
    pub const DIRECTORY_GOVERNANCE_REQUEST_PROOF_V1: &'static str =
        "ak.directory-governance-request-proof-v1";
    pub const DIRECTORY_LIST_HANDLES_FOR_SUBJECT_REQUEST_PROOF_V1: &'static str =
        "ak.directory-list-handles-for-subject-request-proof-v1";
    pub const DIRECTORY_RESOLVE_AGENT_SELECTOR_REQUEST_PROOF_V1: &'static str =
        "ak.directory-resolve-agent-selector-request-proof-v1";
    pub const DIRECTORY_RESOLVE_HANDLE_REQUEST_PROOF_V1: &'static str =
        "ak.directory-resolve-handle-request-proof-v1";
    pub const DIRECTORY_RESOLVE_ORGANIZATION_REQUEST_PROOF_V1: &'static str =
        "ak.directory-resolve-organization-request-proof-v1";
    pub const DIRECTORY_RESOLVE_TARGET_REQUEST_PROOF_V1: &'static str =
        "ak.directory-resolve-target-request-proof-v1";
    pub const EVENT_PROOF_V1: &'static str = "ak.event-proof-v1";
    pub const EXTENSION_MANIFEST_PROOF_V1: &'static str = "ak.extension-manifest-proof-v1";
    pub const HANDLE_CLAIM_PROOF_V1: &'static str = "ak.handle-claim-proof-v1";
    pub const IDENTITY_CREATION_CONTROL_PROOF_V1: &'static str =
        "ak.identity-creation-control-proof-v1";
    pub const IDENTITY_RECEIPT_PROOF_V1: &'static str = "ak.identity-receipt-proof-v1";
    pub const INGRESS_RECEIPT_PROOF_V1: &'static str = "ak.ingress-receipt-proof-v1";
    pub const JOIN_APPLICATION_CANCEL_RECEIPT_PROOF_V1: &'static str =
        "ak.join-application-cancel-receipt-proof-v1";
    pub const JOIN_APPLICATION_RECEIPT_PROOF_V1: &'static str =
        "ak.join-application-receipt-proof-v1";
    pub const JOIN_APPLICATION_REVIEW_RECEIPT_PROOF_V1: &'static str =
        "ak.join-application-review-receipt-proof-v1";
    pub const KEY_BACKUP_DELETE_PROOF_V1: &'static str = "ak.key-backup-delete-proof-v1";
    pub const MEMBER_DELIVERY_BINDING_CANDIDATE_PROOF_V1: &'static str =
        "ak.member-delivery-binding-candidate-proof-v1";
    pub const MIMI_GROUP_INFO_OUTCOME_PROOF_V1: &'static str =
        "ak.mimi-group-info-outcome-proof-v1";
    pub const MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1: &'static str =
        "ak.mimi-identifier-query-outcome-proof-v1";
    pub const MIMI_IDENTIFIER_QUERY_REQUEST_PROOF_V1: &'static str =
        "ak.mimi-identifier-query-request-proof-v1";
    pub const MIMI_KEY_MATERIAL_OUTCOME_PROOF_V1: &'static str =
        "ak.mimi-key-material-outcome-proof-v1";
    pub const MIMI_KEY_MATERIAL_REQUEST_PROOF_V1: &'static str =
        "ak.mimi-key-material-request-proof-v1";
    pub const MIMI_PROVIDER_DIRECTORY_PROOF_V1: &'static str =
        "ak.mimi-provider-directory-proof-v1";
    pub const MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1: &'static str =
        "ak.mimi-request-consent-request-proof-v1";
    pub const MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1: &'static str =
        "ak.mimi-update-consent-request-proof-v1";
    pub const ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1: &'static str =
        "ak.organization-registration-control-proof-v1";
    pub const ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1: &'static str =
        "ak.organization-registration-receipt-proof-v1";
    pub const PRINCIPAL_LOCATOR_PROOF_V1: &'static str = "ak.principal-locator-proof-v1";
    pub const PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_PROOF_V1: &'static str =
        "ak.principal-resolution-projection-attestation-proof-v1";
    pub const PRINCIPAL_SERVER_ADMISSION_PROOF_V1: &'static str =
        "ak.principal-server-admission-proof-v1";
    pub const RANGE_COMPLETENESS_ATTESTATION_PROOF_V1: &'static str =
        "ak.range-completeness-attestation-proof-v1";
    pub const REALM_JOIN_CANDIDATE_PROOF_V1: &'static str = "ak.realm-join-candidate-proof-v1";
    pub const REALM_KEY_SHARE_SENDER_PROOF_V1: &'static str = "ak.realm-key-share-sender-proof-v1";
    pub const RECEIPT_PROOF_V1: &'static str = "ak.receipt-proof-v1";
    pub const REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1: &'static str =
        "ak.registration-did-evidence-control-proof-v1";
    pub const SERVICE_REGISTRATION_RECEIPT_PROOF_V1: &'static str =
        "ak.service-registration-receipt-proof-v1";
    pub const SERVICE_RESOLUTION_PUBLISH_ACK_PROOF_V1: &'static str =
        "ak.service-resolution-publish-ack-proof-v1";
    pub const SERVICE_RESOLUTION_RECORD_PROOF_V1: &'static str =
        "ak.service-resolution-record-proof-v1";
    pub const SERVICE_ROUTE_HANDOVER_NOTICE_PROOF_V1: &'static str =
        "ak.service-route-handover-notice-proof-v1";
    pub const SIGNAL_PROOF_V1: &'static str = "ak.signal-proof-v1";
    pub const SNAPSHOT_PROOF_V1: &'static str = "ak.snapshot-proof-v1";
    pub const SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1: &'static str =
        "ak.snapshot-witness-attestation-proof-v1";

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
            Self::AppletPackageProofV1 => Self::APPLET_PACKAGE_PROOF_V1,
            Self::AuditReleaseAttestationProofV1 => Self::AUDIT_RELEASE_ATTESTATION_PROOF_V1,
            Self::AuditRywReceiptProofV1 => Self::AUDIT_RYW_RECEIPT_PROOF_V1,
            Self::AuthorizationLeaseProofV1 => Self::AUTHORIZATION_LEASE_PROOF_V1,
            Self::ControlProposalAuthorityAckProofV1 => {
                Self::CONTROL_PROPOSAL_AUTHORITY_ACK_PROOF_V1
            }
            Self::ControlProposalDecisionProofV1 => Self::CONTROL_PROPOSAL_DECISION_PROOF_V1,
            Self::DeviceAuthorizeAcceptedDevicePossessionProofV1 => {
                Self::DEVICE_AUTHORIZE_ACCEPTED_DEVICE_POSSESSION_PROOF_V1
            }
            Self::DeviceAuthorizePossessionProofV1 => Self::DEVICE_AUTHORIZE_POSSESSION_PROOF_V1,
            Self::DeviceAuthorizeRecoveryPossessionProofV1 => {
                Self::DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PROOF_V1
            }
            Self::DeviceProjectionAttestationProofV1 => {
                Self::DEVICE_PROJECTION_ATTESTATION_PROOF_V1
            }
            Self::DeviceRevocationGateDecisionProofV1 => {
                Self::DEVICE_REVOCATION_GATE_DECISION_PROOF_V1
            }
            Self::DidWebvhWitnessReceiptProofV1 => Self::DID_WEBVH_WITNESS_RECEIPT_PROOF_V1,
            Self::DirectoryGovernanceRequestProofV1 => Self::DIRECTORY_GOVERNANCE_REQUEST_PROOF_V1,
            Self::DirectoryListHandlesForSubjectRequestProofV1 => {
                Self::DIRECTORY_LIST_HANDLES_FOR_SUBJECT_REQUEST_PROOF_V1
            }
            Self::DirectoryResolveAgentSelectorRequestProofV1 => {
                Self::DIRECTORY_RESOLVE_AGENT_SELECTOR_REQUEST_PROOF_V1
            }
            Self::DirectoryResolveHandleRequestProofV1 => {
                Self::DIRECTORY_RESOLVE_HANDLE_REQUEST_PROOF_V1
            }
            Self::DirectoryResolveOrganizationRequestProofV1 => {
                Self::DIRECTORY_RESOLVE_ORGANIZATION_REQUEST_PROOF_V1
            }
            Self::DirectoryResolveTargetRequestProofV1 => {
                Self::DIRECTORY_RESOLVE_TARGET_REQUEST_PROOF_V1
            }
            Self::EventProofV1 => Self::EVENT_PROOF_V1,
            Self::ExtensionManifestProofV1 => Self::EXTENSION_MANIFEST_PROOF_V1,
            Self::HandleClaimProofV1 => Self::HANDLE_CLAIM_PROOF_V1,
            Self::IdentityCreationControlProofV1 => Self::IDENTITY_CREATION_CONTROL_PROOF_V1,
            Self::IdentityReceiptProofV1 => Self::IDENTITY_RECEIPT_PROOF_V1,
            Self::IngressReceiptProofV1 => Self::INGRESS_RECEIPT_PROOF_V1,
            Self::JoinApplicationCancelReceiptProofV1 => {
                Self::JOIN_APPLICATION_CANCEL_RECEIPT_PROOF_V1
            }
            Self::JoinApplicationReceiptProofV1 => Self::JOIN_APPLICATION_RECEIPT_PROOF_V1,
            Self::JoinApplicationReviewReceiptProofV1 => {
                Self::JOIN_APPLICATION_REVIEW_RECEIPT_PROOF_V1
            }
            Self::KeyBackupDeleteProofV1 => Self::KEY_BACKUP_DELETE_PROOF_V1,
            Self::MemberDeliveryBindingCandidateProofV1 => {
                Self::MEMBER_DELIVERY_BINDING_CANDIDATE_PROOF_V1
            }
            Self::MimiGroupInfoOutcomeProofV1 => Self::MIMI_GROUP_INFO_OUTCOME_PROOF_V1,
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
            Self::PrincipalServerAdmissionProofV1 => Self::PRINCIPAL_SERVER_ADMISSION_PROOF_V1,
            Self::RangeCompletenessAttestationProofV1 => {
                Self::RANGE_COMPLETENESS_ATTESTATION_PROOF_V1
            }
            Self::RealmJoinCandidateProofV1 => Self::REALM_JOIN_CANDIDATE_PROOF_V1,
            Self::RealmKeyShareSenderProofV1 => Self::REALM_KEY_SHARE_SENDER_PROOF_V1,
            Self::ReceiptProofV1 => Self::RECEIPT_PROOF_V1,
            Self::RegistrationDidEvidenceControlProofV1 => {
                Self::REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1
            }
            Self::ServiceRegistrationReceiptProofV1 => Self::SERVICE_REGISTRATION_RECEIPT_PROOF_V1,
            Self::ServiceResolutionPublishAckProofV1 => {
                Self::SERVICE_RESOLUTION_PUBLISH_ACK_PROOF_V1
            }
            Self::ServiceResolutionRecordProofV1 => Self::SERVICE_RESOLUTION_RECORD_PROOF_V1,
            Self::ServiceRouteHandoverNoticeProofV1 => Self::SERVICE_ROUTE_HANDOVER_NOTICE_PROOF_V1,
            Self::SignalProofV1 => Self::SIGNAL_PROOF_V1,
            Self::SnapshotProofV1 => Self::SNAPSHOT_PROOF_V1,
            Self::SnapshotWitnessAttestationProofV1 => Self::SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1,
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
            Self::APPLET_PACKAGE_PROOF_V1 => Some(Self::AppletPackageProofV1),
            Self::AUDIT_RELEASE_ATTESTATION_PROOF_V1 => Some(Self::AuditReleaseAttestationProofV1),
            Self::AUDIT_RYW_RECEIPT_PROOF_V1 => Some(Self::AuditRywReceiptProofV1),
            Self::AUTHORIZATION_LEASE_PROOF_V1 => Some(Self::AuthorizationLeaseProofV1),
            Self::CONTROL_PROPOSAL_AUTHORITY_ACK_PROOF_V1 => {
                Some(Self::ControlProposalAuthorityAckProofV1)
            }
            Self::CONTROL_PROPOSAL_DECISION_PROOF_V1 => Some(Self::ControlProposalDecisionProofV1),
            Self::DEVICE_AUTHORIZE_ACCEPTED_DEVICE_POSSESSION_PROOF_V1 => {
                Some(Self::DeviceAuthorizeAcceptedDevicePossessionProofV1)
            }
            Self::DEVICE_AUTHORIZE_POSSESSION_PROOF_V1 => {
                Some(Self::DeviceAuthorizePossessionProofV1)
            }
            Self::DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PROOF_V1 => {
                Some(Self::DeviceAuthorizeRecoveryPossessionProofV1)
            }
            Self::DEVICE_PROJECTION_ATTESTATION_PROOF_V1 => {
                Some(Self::DeviceProjectionAttestationProofV1)
            }
            Self::DEVICE_REVOCATION_GATE_DECISION_PROOF_V1 => {
                Some(Self::DeviceRevocationGateDecisionProofV1)
            }
            Self::DID_WEBVH_WITNESS_RECEIPT_PROOF_V1 => Some(Self::DidWebvhWitnessReceiptProofV1),
            Self::DIRECTORY_GOVERNANCE_REQUEST_PROOF_V1 => {
                Some(Self::DirectoryGovernanceRequestProofV1)
            }
            Self::DIRECTORY_LIST_HANDLES_FOR_SUBJECT_REQUEST_PROOF_V1 => {
                Some(Self::DirectoryListHandlesForSubjectRequestProofV1)
            }
            Self::DIRECTORY_RESOLVE_AGENT_SELECTOR_REQUEST_PROOF_V1 => {
                Some(Self::DirectoryResolveAgentSelectorRequestProofV1)
            }
            Self::DIRECTORY_RESOLVE_HANDLE_REQUEST_PROOF_V1 => {
                Some(Self::DirectoryResolveHandleRequestProofV1)
            }
            Self::DIRECTORY_RESOLVE_ORGANIZATION_REQUEST_PROOF_V1 => {
                Some(Self::DirectoryResolveOrganizationRequestProofV1)
            }
            Self::DIRECTORY_RESOLVE_TARGET_REQUEST_PROOF_V1 => {
                Some(Self::DirectoryResolveTargetRequestProofV1)
            }
            Self::EVENT_PROOF_V1 => Some(Self::EventProofV1),
            Self::EXTENSION_MANIFEST_PROOF_V1 => Some(Self::ExtensionManifestProofV1),
            Self::HANDLE_CLAIM_PROOF_V1 => Some(Self::HandleClaimProofV1),
            Self::IDENTITY_CREATION_CONTROL_PROOF_V1 => Some(Self::IdentityCreationControlProofV1),
            Self::IDENTITY_RECEIPT_PROOF_V1 => Some(Self::IdentityReceiptProofV1),
            Self::INGRESS_RECEIPT_PROOF_V1 => Some(Self::IngressReceiptProofV1),
            Self::JOIN_APPLICATION_CANCEL_RECEIPT_PROOF_V1 => {
                Some(Self::JoinApplicationCancelReceiptProofV1)
            }
            Self::JOIN_APPLICATION_RECEIPT_PROOF_V1 => Some(Self::JoinApplicationReceiptProofV1),
            Self::JOIN_APPLICATION_REVIEW_RECEIPT_PROOF_V1 => {
                Some(Self::JoinApplicationReviewReceiptProofV1)
            }
            Self::KEY_BACKUP_DELETE_PROOF_V1 => Some(Self::KeyBackupDeleteProofV1),
            Self::MEMBER_DELIVERY_BINDING_CANDIDATE_PROOF_V1 => {
                Some(Self::MemberDeliveryBindingCandidateProofV1)
            }
            Self::MIMI_GROUP_INFO_OUTCOME_PROOF_V1 => Some(Self::MimiGroupInfoOutcomeProofV1),
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
            Self::PRINCIPAL_SERVER_ADMISSION_PROOF_V1 => {
                Some(Self::PrincipalServerAdmissionProofV1)
            }
            Self::RANGE_COMPLETENESS_ATTESTATION_PROOF_V1 => {
                Some(Self::RangeCompletenessAttestationProofV1)
            }
            Self::REALM_JOIN_CANDIDATE_PROOF_V1 => Some(Self::RealmJoinCandidateProofV1),
            Self::REALM_KEY_SHARE_SENDER_PROOF_V1 => Some(Self::RealmKeyShareSenderProofV1),
            Self::RECEIPT_PROOF_V1 => Some(Self::ReceiptProofV1),
            Self::REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1 => {
                Some(Self::RegistrationDidEvidenceControlProofV1)
            }
            Self::SERVICE_REGISTRATION_RECEIPT_PROOF_V1 => {
                Some(Self::ServiceRegistrationReceiptProofV1)
            }
            Self::SERVICE_RESOLUTION_PUBLISH_ACK_PROOF_V1 => {
                Some(Self::ServiceResolutionPublishAckProofV1)
            }
            Self::SERVICE_RESOLUTION_RECORD_PROOF_V1 => Some(Self::ServiceResolutionRecordProofV1),
            Self::SERVICE_ROUTE_HANDOVER_NOTICE_PROOF_V1 => {
                Some(Self::ServiceRouteHandoverNoticeProofV1)
            }
            Self::SIGNAL_PROOF_V1 => Some(Self::SignalProofV1),
            Self::SNAPSHOT_PROOF_V1 => Some(Self::SnapshotProofV1),
            Self::SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1 => {
                Some(Self::SnapshotWitnessAttestationProofV1)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum DomainSeparationId {
    AccountabilityScopeSetV1,
    AppletDeliveryAuthenticationRecordDigestV1,
    ContactGlareUnconsumedSlotV1,
    ContactNoOutgoingSlotV1,
    ContactRequestAcceptanceCoreV1,
    ContactRequestSourceCheckpointV1,
    EventsFrontierLeafV1,
    EventsFrontierNodeV1,
    EventsFrontierRootV1,
    EventsFrontierSignatureV1,
    FederationVerifyActorSignatureV1,
    HttpMessageSignatureV1,
    IdentityRecoveryPolicySignatureV1,
    IdentityRecoveryReceiptSignatureV1,
    JoinedControlViewDigestV1,
    MembershipCompensationSingleUseCasV1,
    MembershipCompensationTerminalCertificateV1,
    PeerEventsCommandSubmitServiceBindingV1,
    PolicyCheckTranscriptV1,
    RealmHistorySecretShareV1,
    RealmOrganizationStatementV1,
    SnapshotAuthStateIssuerLocalV1,
    WebsocketAuthV1,
}

impl DomainSeparationId {
    pub const ALL: &'static [Self] = &[
        Self::AccountabilityScopeSetV1,
        Self::AppletDeliveryAuthenticationRecordDigestV1,
        Self::ContactGlareUnconsumedSlotV1,
        Self::ContactNoOutgoingSlotV1,
        Self::ContactRequestAcceptanceCoreV1,
        Self::ContactRequestSourceCheckpointV1,
        Self::EventsFrontierLeafV1,
        Self::EventsFrontierNodeV1,
        Self::EventsFrontierRootV1,
        Self::EventsFrontierSignatureV1,
        Self::FederationVerifyActorSignatureV1,
        Self::HttpMessageSignatureV1,
        Self::IdentityRecoveryPolicySignatureV1,
        Self::IdentityRecoveryReceiptSignatureV1,
        Self::JoinedControlViewDigestV1,
        Self::MembershipCompensationSingleUseCasV1,
        Self::MembershipCompensationTerminalCertificateV1,
        Self::PeerEventsCommandSubmitServiceBindingV1,
        Self::PolicyCheckTranscriptV1,
        Self::RealmHistorySecretShareV1,
        Self::RealmOrganizationStatementV1,
        Self::SnapshotAuthStateIssuerLocalV1,
        Self::WebsocketAuthV1,
    ];

    pub const ACCOUNTABILITY_SCOPE_SET_V1: &'static str = "ak.accountability-scope-set-v1";
    pub const APPLET_DELIVERY_AUTHENTICATION_RECORD_DIGEST_V1: &'static str =
        "ak.applet.delivery_authentication_record_digest.v1";
    pub const CONTACT_GLARE_UNCONSUMED_SLOT_V1: &'static str =
        "ak.contact.glare-unconsumed-slot.v1";
    pub const CONTACT_NO_OUTGOING_SLOT_V1: &'static str = "ak.contact.no-outgoing-slot.v1";
    pub const CONTACT_REQUEST_ACCEPTANCE_CORE_V1: &'static str =
        "ak.contact.request-acceptance-core.v1";
    pub const CONTACT_REQUEST_SOURCE_CHECKPOINT_V1: &'static str =
        "ak.contact.request-source-checkpoint.v1";
    pub const EVENTS_FRONTIER_LEAF_V1: &'static str = "ak.events.frontier.leaf.v1";
    pub const EVENTS_FRONTIER_NODE_V1: &'static str = "ak.events.frontier.node.v1";
    pub const EVENTS_FRONTIER_ROOT_V1: &'static str = "ak.events.frontier.root.v1";
    pub const EVENTS_FRONTIER_SIGNATURE_V1: &'static str = "ak.events.frontier.signature.v1";
    pub const FEDERATION_VERIFY_ACTOR_SIGNATURE_V1: &'static str =
        "ak.federation.verify_actor.signature.v1";
    pub const HTTP_MESSAGE_SIGNATURE_V1: &'static str = "ak.http-message-signature.v1";
    pub const IDENTITY_RECOVERY_POLICY_SIGNATURE_V1: &'static str =
        "ak.identity.recovery_policy.signature.v1";
    pub const IDENTITY_RECOVERY_RECEIPT_SIGNATURE_V1: &'static str =
        "ak.identity.recovery_receipt.signature.v1";
    pub const JOINED_CONTROL_VIEW_DIGEST_V1: &'static str = "ak.joined-control-view-digest-v1";
    pub const MEMBERSHIP_COMPENSATION_SINGLE_USE_CAS_V1: &'static str =
        "ak.membership-compensation.single-use-cas.v1";
    pub const MEMBERSHIP_COMPENSATION_TERMINAL_CERTIFICATE_V1: &'static str =
        "ak.membership-compensation.terminal-certificate.v1";
    pub const PEER_EVENTS_COMMAND_SUBMIT_SERVICE_BINDING_V1: &'static str =
        "ak.peer.events.command.submit.service_binding.v1";
    pub const POLICY_CHECK_TRANSCRIPT_V1: &'static str = "ak.policy.check.transcript.v1";
    pub const REALM_HISTORY_SECRET_SHARE_V1: &'static str = "ak.realm-history-secret-share-v1";
    pub const REALM_ORGANIZATION_STATEMENT_V1: &'static str = "ak.realm.organization.statement.v1";
    pub const SNAPSHOT_AUTH_STATE_ISSUER_LOCAL_V1: &'static str =
        "ak.snapshot.auth_state.issuer_local.v1";
    pub const WEBSOCKET_AUTH_V1: &'static str = "ak.websocket-auth.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountabilityScopeSetV1 => Self::ACCOUNTABILITY_SCOPE_SET_V1,
            Self::AppletDeliveryAuthenticationRecordDigestV1 => {
                Self::APPLET_DELIVERY_AUTHENTICATION_RECORD_DIGEST_V1
            }
            Self::ContactGlareUnconsumedSlotV1 => Self::CONTACT_GLARE_UNCONSUMED_SLOT_V1,
            Self::ContactNoOutgoingSlotV1 => Self::CONTACT_NO_OUTGOING_SLOT_V1,
            Self::ContactRequestAcceptanceCoreV1 => Self::CONTACT_REQUEST_ACCEPTANCE_CORE_V1,
            Self::ContactRequestSourceCheckpointV1 => Self::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,
            Self::EventsFrontierLeafV1 => Self::EVENTS_FRONTIER_LEAF_V1,
            Self::EventsFrontierNodeV1 => Self::EVENTS_FRONTIER_NODE_V1,
            Self::EventsFrontierRootV1 => Self::EVENTS_FRONTIER_ROOT_V1,
            Self::EventsFrontierSignatureV1 => Self::EVENTS_FRONTIER_SIGNATURE_V1,
            Self::FederationVerifyActorSignatureV1 => Self::FEDERATION_VERIFY_ACTOR_SIGNATURE_V1,
            Self::HttpMessageSignatureV1 => Self::HTTP_MESSAGE_SIGNATURE_V1,
            Self::IdentityRecoveryPolicySignatureV1 => Self::IDENTITY_RECOVERY_POLICY_SIGNATURE_V1,
            Self::IdentityRecoveryReceiptSignatureV1 => {
                Self::IDENTITY_RECOVERY_RECEIPT_SIGNATURE_V1
            }
            Self::JoinedControlViewDigestV1 => Self::JOINED_CONTROL_VIEW_DIGEST_V1,
            Self::MembershipCompensationSingleUseCasV1 => {
                Self::MEMBERSHIP_COMPENSATION_SINGLE_USE_CAS_V1
            }
            Self::MembershipCompensationTerminalCertificateV1 => {
                Self::MEMBERSHIP_COMPENSATION_TERMINAL_CERTIFICATE_V1
            }
            Self::PeerEventsCommandSubmitServiceBindingV1 => {
                Self::PEER_EVENTS_COMMAND_SUBMIT_SERVICE_BINDING_V1
            }
            Self::PolicyCheckTranscriptV1 => Self::POLICY_CHECK_TRANSCRIPT_V1,
            Self::RealmHistorySecretShareV1 => Self::REALM_HISTORY_SECRET_SHARE_V1,
            Self::RealmOrganizationStatementV1 => Self::REALM_ORGANIZATION_STATEMENT_V1,
            Self::SnapshotAuthStateIssuerLocalV1 => Self::SNAPSHOT_AUTH_STATE_ISSUER_LOCAL_V1,
            Self::WebsocketAuthV1 => Self::WEBSOCKET_AUTH_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ACCOUNTABILITY_SCOPE_SET_V1 => Some(Self::AccountabilityScopeSetV1),
            Self::APPLET_DELIVERY_AUTHENTICATION_RECORD_DIGEST_V1 => {
                Some(Self::AppletDeliveryAuthenticationRecordDigestV1)
            }
            Self::CONTACT_GLARE_UNCONSUMED_SLOT_V1 => Some(Self::ContactGlareUnconsumedSlotV1),
            Self::CONTACT_NO_OUTGOING_SLOT_V1 => Some(Self::ContactNoOutgoingSlotV1),
            Self::CONTACT_REQUEST_ACCEPTANCE_CORE_V1 => Some(Self::ContactRequestAcceptanceCoreV1),
            Self::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1 => {
                Some(Self::ContactRequestSourceCheckpointV1)
            }
            Self::EVENTS_FRONTIER_LEAF_V1 => Some(Self::EventsFrontierLeafV1),
            Self::EVENTS_FRONTIER_NODE_V1 => Some(Self::EventsFrontierNodeV1),
            Self::EVENTS_FRONTIER_ROOT_V1 => Some(Self::EventsFrontierRootV1),
            Self::EVENTS_FRONTIER_SIGNATURE_V1 => Some(Self::EventsFrontierSignatureV1),
            Self::FEDERATION_VERIFY_ACTOR_SIGNATURE_V1 => {
                Some(Self::FederationVerifyActorSignatureV1)
            }
            Self::HTTP_MESSAGE_SIGNATURE_V1 => Some(Self::HttpMessageSignatureV1),
            Self::IDENTITY_RECOVERY_POLICY_SIGNATURE_V1 => {
                Some(Self::IdentityRecoveryPolicySignatureV1)
            }
            Self::IDENTITY_RECOVERY_RECEIPT_SIGNATURE_V1 => {
                Some(Self::IdentityRecoveryReceiptSignatureV1)
            }
            Self::JOINED_CONTROL_VIEW_DIGEST_V1 => Some(Self::JoinedControlViewDigestV1),
            Self::MEMBERSHIP_COMPENSATION_SINGLE_USE_CAS_V1 => {
                Some(Self::MembershipCompensationSingleUseCasV1)
            }
            Self::MEMBERSHIP_COMPENSATION_TERMINAL_CERTIFICATE_V1 => {
                Some(Self::MembershipCompensationTerminalCertificateV1)
            }
            Self::PEER_EVENTS_COMMAND_SUBMIT_SERVICE_BINDING_V1 => {
                Some(Self::PeerEventsCommandSubmitServiceBindingV1)
            }
            Self::POLICY_CHECK_TRANSCRIPT_V1 => Some(Self::PolicyCheckTranscriptV1),
            Self::REALM_HISTORY_SECRET_SHARE_V1 => Some(Self::RealmHistorySecretShareV1),
            Self::REALM_ORGANIZATION_STATEMENT_V1 => Some(Self::RealmOrganizationStatementV1),
            Self::SNAPSHOT_AUTH_STATE_ISSUER_LOCAL_V1 => Some(Self::SnapshotAuthStateIssuerLocalV1),
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
    ContentV1,
    HistoryV1,
    RtcFrameKeyV1,
    RtcRecordingKeyV1,
    RtcTranscriptKeyV1,
    SignalV1,
    AeadSenderNoncePrefixV1,
    MentionRoutingV1,
    ReactionRoutingV1,
}

impl ExporterLabelId {
    pub const ALL: &'static [Self] = &[
        Self::ContentV1,
        Self::HistoryV1,
        Self::RtcFrameKeyV1,
        Self::RtcRecordingKeyV1,
        Self::RtcTranscriptKeyV1,
        Self::SignalV1,
        Self::AeadSenderNoncePrefixV1,
        Self::MentionRoutingV1,
        Self::ReactionRoutingV1,
    ];

    pub const CONTENT_V1: &'static str = "ak.content-v1";
    pub const HISTORY_V1: &'static str = "ak.history-v1";
    pub const RTC_FRAME_KEY_V1: &'static str = "ak.rtc-frame-key/v1";
    pub const RTC_RECORDING_KEY_V1: &'static str = "ak.rtc-recording-key/v1";
    pub const RTC_TRANSCRIPT_KEY_V1: &'static str = "ak.rtc-transcript-key/v1";
    pub const SIGNAL_V1: &'static str = "ak.signal-v1";
    pub const AEAD_SENDER_NONCE_PREFIX_V1: &'static str = "arkret-aead-sender-nonce-prefix-v1";
    pub const MENTION_ROUTING_V1: &'static str = "arkret-mention-routing-v1";
    pub const REACTION_ROUTING_V1: &'static str = "arkret-reaction-routing-v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContentV1 => Self::CONTENT_V1,
            Self::HistoryV1 => Self::HISTORY_V1,
            Self::RtcFrameKeyV1 => Self::RTC_FRAME_KEY_V1,
            Self::RtcRecordingKeyV1 => Self::RTC_RECORDING_KEY_V1,
            Self::RtcTranscriptKeyV1 => Self::RTC_TRANSCRIPT_KEY_V1,
            Self::SignalV1 => Self::SIGNAL_V1,
            Self::AeadSenderNoncePrefixV1 => Self::AEAD_SENDER_NONCE_PREFIX_V1,
            Self::MentionRoutingV1 => Self::MENTION_ROUTING_V1,
            Self::ReactionRoutingV1 => Self::REACTION_ROUTING_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::CONTENT_V1 => Some(Self::ContentV1),
            Self::HISTORY_V1 => Some(Self::HistoryV1),
            Self::RTC_FRAME_KEY_V1 => Some(Self::RtcFrameKeyV1),
            Self::RTC_RECORDING_KEY_V1 => Some(Self::RtcRecordingKeyV1),
            Self::RTC_TRANSCRIPT_KEY_V1 => Some(Self::RtcTranscriptKeyV1),
            Self::SIGNAL_V1 => Some(Self::SignalV1),
            Self::AEAD_SENDER_NONCE_PREFIX_V1 => Some(Self::AeadSenderNoncePrefixV1),
            Self::MENTION_ROUTING_V1 => Some(Self::MentionRoutingV1),
            Self::REACTION_ROUTING_V1 => Some(Self::ReactionRoutingV1),
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
    pub profile_id: &'static str,
}

pub const PROOF_CONTEXTS: &[ProofContextDescriptor] = &[
    ProofContextDescriptor {
        id: ProofContextId::AccountBindingReceiptProofV1,
        context: "ak.account-binding-receipt-proof-v1",
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
        context: "ak.account-handoff-authentication-proof-v1",
        object_family: "account_handoff_authentication",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "account_id",
            "principal_id",
            "verification_method",
            "created_at",
            "audience",
        ],
        schema_ref: "schemas/account-operations.schema.json#/$defs/account_handoff_authentication_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::AccountRegistrationControlProofV1,
        context: "ak.account-registration-control-proof-v1",
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
            "full_id",
            "did_version_id",
            "log_head_digest",
            "control_key_digest",
            "dpop_jkt",
            "audience",
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
        context: "ak.account-status-record-proof-v1",
        object_family: "account_status_record",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/account-operations.schema.json#/$defs/account_status_record",
    },
    ProofContextDescriptor {
        id: ProofContextId::AccountStatusReplicationReceiptProofV1,
        context: "ak.account-status-replication-receipt-proof-v1",
        object_family: "account_status_replication_receipt",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/account-operations.schema.json#/$defs/account_status_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::AccountabilityGrantProofV1,
        context: "ak.accountability-grant-proof-v1",
        object_family: "accountability_grant",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "subject",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/accountability-grant.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AgentRequestedScopeDisclosureProofV1,
        context: "ak.agent-requested-scope-disclosure-proof-v1",
        object_family: "agent_requested_scope_disclosure",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "controller_id",
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
        context: "ak.agent-runtime-key-possession-proof-v1",
        object_family: "agent_runtime_key_possession",
        consumer_operation: None,
        binding_fields: &[
            "kind",
            "verification_method",
            "signature_algorithm",
            "challenge",
            "audience",
            "created_at",
            "expires_at",
            "pairing_code",
            "runtime_key_binding_digest",
        ],
        schema_ref: "schemas/agent-operations.schema.json#/$defs/agent_runtime_key_possession_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::AgentSelectorClaimProofV1,
        context: "ak.agent-selector-claim-proof-v1",
        object_family: "agent_selector_claim",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "controller_id",
            "agent_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/agent-selector-claim.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AppletPackageProofV1,
        context: "ak.applet-package-proof-v1",
        object_family: "applet_package",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "applet_id",
            "publisher_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/applet-package.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AuditReleaseAttestationProofV1,
        context: "ak.audit-release-attestation-proof-v1",
        object_family: "attestation_evidence",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "subject",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/audit-release-attestation.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AuditRywReceiptProofV1,
        context: "ak.audit-ryw-receipt-proof-v1",
        object_family: "audit_ryw_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "scope",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/audit-ryw-receipt.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AuthorizationLeaseProofV1,
        context: "ak.authorization-lease-proof-v1",
        object_family: "authorization_lease",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "authority_set_ref",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/offline-publication.schema.json#/$defs/authorization_lease",
    },
    ProofContextDescriptor {
        id: ProofContextId::ControlProposalAuthorityAckProofV1,
        context: "ak.control-proposal-authority-ack-proof-v1",
        object_family: "control_proposal_authority_ack",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/control-proposal-decision.schema.json#/$defs/control_proposal_authority_ack",
    },
    ProofContextDescriptor {
        id: ProofContextId::ControlProposalDecisionProofV1,
        context: "ak.control-proposal-decision-proof-v1",
        object_family: "control_proposal_decision",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/control-proposal-decision.schema.json#/$defs/proposal_decision",
    },
    ProofContextDescriptor {
        id: ProofContextId::DeviceAuthorizeAcceptedDevicePossessionProofV1,
        context: "ak.device-authorize-accepted-device-possession-proof-v1",
        object_family: "device_authorize_accepted_device_possession",
        consumer_operation: None,
        binding_fields: &[
            "device_id",
            "device_public_key",
            "hpke_key",
            "algorithms",
            "device_key_algorithm",
            "authorization_binding_kind",
            "pairing_challenge_transcript_digest",
        ],
        schema_ref: "schemas/device-pairing.schema.json#/$defs/device_pairing_target_attestation",
    },
    ProofContextDescriptor {
        id: ProofContextId::DeviceAuthorizePossessionProofV1,
        context: "ak.device-authorize-possession-proof-v1",
        object_family: "device_authorize_possession",
        consumer_operation: None,
        binding_fields: &[
            "principal_id",
            "device_id",
            "device_public_key",
            "hpke_key",
            "algorithms",
            "device_key_algorithm",
            "authorized_by",
            "not_before",
            "expires_at?",
            "scopes?",
            "recovery_session_id?",
            "authorization_binding_kind",
        ],
        schema_ref: "schemas/event-payload.schema.json#/$defs/device_authorize_payload",
    },
    ProofContextDescriptor {
        id: ProofContextId::DeviceAuthorizeRecoveryPossessionProofV1,
        context: "ak.device-authorize-recovery-possession-proof-v1",
        object_family: "device_authorize_recovery_possession",
        consumer_operation: None,
        binding_fields: &[
            "principal_id",
            "device_id",
            "device_public_key",
            "hpke_key",
            "algorithms",
            "device_key_algorithm",
            "authorized_by",
            "recovery_session_id",
            "authorization_binding_kind",
        ],
        schema_ref: "schemas/event-payload.schema.json#/$defs/device_authorize_payload",
    },
    ProofContextDescriptor {
        id: ProofContextId::DeviceProjectionAttestationProofV1,
        context: "ak.device-projection-attestation-proof-v1",
        object_family: "device_projection_attestation",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "principal_id",
            "principal_server_id",
            "device_id",
            "device_signing_key",
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
        id: ProofContextId::DeviceRevocationGateDecisionProofV1,
        context: "ak.device-revocation-gate-decision-proof-v1",
        object_family: "device_revocation_gate_decision_receipt",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/device-revocation-state.schema.json#/$defs/device_revocation_gate_decision_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::DidWebvhWitnessReceiptProofV1,
        context: "ak.did-webvh-witness-receipt-proof-v1",
        object_family: "did_webvh_witness_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer_service_id",
            "did",
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
        id: ProofContextId::DirectoryGovernanceRequestProofV1,
        context: "ak.directory-governance-request-proof-v1",
        object_family: "directory_governance_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "operation_id",
            "resource_id",
            "verification_method",
            "created_at",
            "proof_purpose",
            "audience",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/DirectoryGovernanceProof",
    },
    ProofContextDescriptor {
        id: ProofContextId::DirectoryListHandlesForSubjectRequestProofV1,
        context: "ak.directory-list-handles-for-subject-request-proof-v1",
        object_family: "directory_list_handles_for_subject_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "subject",
            "verification_method",
            "created_at",
            "audience",
        ],
        schema_ref: "schemas/directory-operations.schema.json#/$defs/directory_list_handles_for_subject_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::DirectoryResolveAgentSelectorRequestProofV1,
        context: "ak.directory-resolve-agent-selector-request-proof-v1",
        object_family: "directory_resolve_agent_selector_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "controller_handle",
            "agent_slug",
            "verification_method",
            "created_at",
            "audience",
        ],
        schema_ref: "schemas/directory-operations.schema.json#/$defs/directory_resolve_agent_selector_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::DirectoryResolveHandleRequestProofV1,
        context: "ak.directory-resolve-handle-request-proof-v1",
        object_family: "directory_resolve_handle_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "handle",
            "verification_method",
            "created_at",
            "audience",
        ],
        schema_ref: "schemas/directory-operations.schema.json#/$defs/directory_resolve_handle_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::DirectoryResolveOrganizationRequestProofV1,
        context: "ak.directory-resolve-organization-request-proof-v1",
        object_family: "directory_resolve_organization_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "operation_id",
            "verification_method",
            "created_at",
            "audience",
        ],
        schema_ref: "schemas/directory-operations.schema.json#/$defs/directory_resolve_organization_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::DirectoryResolveTargetRequestProofV1,
        context: "ak.directory-resolve-target-request-proof-v1",
        object_family: "directory_resolve_target_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "address",
            "verification_method",
            "created_at",
            "audience",
        ],
        schema_ref: "schemas/directory-operations.schema.json#/$defs/directory_resolve_target_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::EventProofV1,
        context: "ak.event-proof-v1",
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
        context: "ak.extension-manifest-proof-v1",
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
        context: "ak.handle-claim-proof-v1",
        object_family: "handle_claim",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "handle",
            "subject_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/handle-claim.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::IdentityCreationControlProofV1,
        context: "ak.identity-creation-control-proof-v1",
        object_family: "identity_creation_control",
        consumer_operation: None,
        binding_fields: &[
            "proof_kind",
            "challenge_id",
            "challenge",
            "purpose",
            "principal_id",
            "operation_digest",
            "pcr_realm_id",
            "realm_create_payload_digest",
            "founding_authorize_payload_digest",
            "initial_session_request_digest",
            "genesis_unit_kinds",
            "identity_creation_lease_id",
            "lease_fence",
            "dpop_jkt",
            "audience",
            "origin",
            "trust_domain",
            "issued_at",
            "expires_at",
            "verification_key_multibase",
        ],
        schema_ref: "schemas/account-operations.schema.json#/$defs/identity_creation_control_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::IdentityReceiptProofV1,
        context: "ak.identity-receipt-proof-v1",
        object_family: "identity_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "registry_service_id",
            "did",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/identity-receipt.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::IngressReceiptProofV1,
        context: "ak.ingress-receipt-proof-v1",
        object_family: "ingress_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "authority_set_ref",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/offline-publication.schema.json#/$defs/ingress_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::JoinApplicationCancelReceiptProofV1,
        context: "ak.join-application-cancel-receipt-proof-v1",
        object_family: "join_application_cancel_receipt",
        consumer_operation: None,
        binding_fields: &[
            "receipt_digest",
            "realm_id",
            "application_ref",
            "actor_id",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/join-policy-operations.schema.json#/$defs/cancel_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::JoinApplicationReceiptProofV1,
        context: "ak.join-application-receipt-proof-v1",
        object_family: "join_application_receipt",
        consumer_operation: None,
        binding_fields: &[
            "receipt_digest",
            "realm_id",
            "actor_id",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/join-policy-operations.schema.json#/$defs/application_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::JoinApplicationReviewReceiptProofV1,
        context: "ak.join-application-review-receipt-proof-v1",
        object_family: "join_application_review_receipt",
        consumer_operation: None,
        binding_fields: &[
            "receipt_digest",
            "realm_id",
            "application_ref",
            "application_revision_digest",
            "actor_id",
            "principal_server_id",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/join-policy-operations.schema.json#/$defs/review_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::KeyBackupDeleteProofV1,
        context: "ak.key-backup-delete-proof-v1",
        object_family: "key_backup_delete_authority",
        consumer_operation: Some("ak.self.keys.backups.resource.delete"),
        binding_fields: &[
            "payload_digest",
            "operation",
            "request_id",
            "principal_id",
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
        id: ProofContextId::MemberDeliveryBindingCandidateProofV1,
        context: "ak.member-delivery-binding-candidate-proof-v1",
        object_family: "member_delivery_binding_candidate",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "subject_id",
            "recipient_service_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/member-delivery-binding-candidate.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::MimiGroupInfoOutcomeProofV1,
        context: "ak.mimi-group-info-outcome-proof-v1",
        object_family: "mimi_group_info_outcome",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "operation_id",
            "room_binding_ref?",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/mimi-operations.schema.json#/$defs/mimi_group_info_outcome",
    },
    ProofContextDescriptor {
        id: ProofContextId::MimiIdentifierQueryOutcomeProofV1,
        context: "ak.mimi-identifier-query-outcome-proof-v1",
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
        context: "ak.mimi-identifier-query-request-proof-v1",
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
        context: "ak.mimi-key-material-outcome-proof-v1",
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
        context: "ak.mimi-key-material-request-proof-v1",
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
        context: "ak.mimi-provider-directory-proof-v1",
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
        context: "ak.mimi-request-consent-request-proof-v1",
        object_family: "mimi_request_consent_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "target",
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
        context: "ak.mimi-update-consent-request-proof-v1",
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
        context: "ak.organization-registration-control-proof-v1",
        object_family: "organization_registration_control_proof",
        consumer_operation: None,
        binding_fields: &[
            "challenge_id",
            "organization_id",
            "local_admin_subject",
            "version_id",
            "log_head_digest",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/OrganizationControlProof",
    },
    ProofContextDescriptor {
        id: ProofContextId::OrganizationRegistrationReceiptProofV1,
        context: "ak.organization-registration-receipt-proof-v1",
        object_family: "organization_registration_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer_service_id",
            "registration_receipt_id",
            "organization_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/OrganizationRegistrationReceipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::PrincipalLocatorProofV1,
        context: "ak.principal-locator-proof-v1",
        object_family: "principal_locator",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "subject_id",
            "recipient_service_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/principal-locator.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::PrincipalResolutionProjectionAttestationProofV1,
        context: "ak.principal-resolution-projection-attestation-proof-v1",
        object_family: "principal_resolution_projection_attestation",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "principal_id",
            "principal_server_id",
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
        id: ProofContextId::PrincipalServerAdmissionProofV1,
        context: "ak.principal-server-admission-proof-v1",
        object_family: "principal_server_event_admission",
        consumer_operation: None,
        binding_fields: &[
            "event_digest",
            "producer_proof_digest",
            "producer_verification_method",
            "producer_signing_key",
            "accepted_at",
            "verification_method",
        ],
        schema_ref: "schemas/event-envelope.schema.json#/$defs/principal_server_admission_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::RangeCompletenessAttestationProofV1,
        context: "ak.range-completeness-attestation-proof-v1",
        object_family: "range_completeness_attestation",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "scope",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/range-completeness-attestation.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::RealmJoinCandidateProofV1,
        context: "ak.realm-join-candidate-proof-v1",
        object_family: "realm_join_candidate",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "realm_id",
            "subject_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/realm-join-candidate.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::RealmKeyShareSenderProofV1,
        context: "ak.realm-key-share-sender-proof-v1",
        object_family: "realm_key_share_sender_transcript",
        consumer_operation: None,
        binding_fields: &[
            "share_kind",
            "sender_device_id",
            "source_authorization_ref",
            "recipient_principal_id",
            "recipient_device_id?",
            "recipient_verification_method?",
            "recovery_recipient_id?",
            "key_scope",
            "ciphertext?",
            "encrypted_key_ref?",
            "aad_digest?",
            "expires_at?",
            "created_at",
        ],
        schema_ref: "schemas/event-payload.schema.json#/$defs/realm_key_share_payload",
    },
    ProofContextDescriptor {
        id: ProofContextId::ReceiptProofV1,
        context: "ak.receipt-proof-v1",
        object_family: "event_batch_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/event-batch-receipt.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::RegistrationDidEvidenceControlProofV1,
        context: "ak.registration-did-evidence-control-proof-v1",
        object_family: "registration_did_evidence_control",
        consumer_operation: None,
        binding_fields: &[
            "principal_id",
            "full_id",
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
        context: "ak.service-registration-receipt-proof-v1",
        object_family: "service_registration_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "provider_service_id",
            "registration_receipt_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/ServiceRegistrationReceipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::ServiceResolutionPublishAckProofV1,
        context: "ak.service-resolution-publish-ack-proof-v1",
        object_family: "service_resolution_publish_ack",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "request_id",
            "source_service_id",
            "receiver_service_id",
            "realm_id",
            "request_digest",
            "artifact_key",
            "artifact_digest",
            "accepted_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/identity-resolution.schema.json#/$defs/service_resolution_publish_ack",
    },
    ProofContextDescriptor {
        id: ProofContextId::ServiceResolutionRecordProofV1,
        context: "ak.service-resolution-record-proof-v1",
        object_family: "service_resolution_record",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "service_id",
            "service_kind",
            "full_id",
            "method_history_head",
            "version_id",
            "resolution_event_ref",
            "record_sequence",
            "previous_record_digest",
            "current_record_url",
            "base_url",
            "describe_digest",
            "issued_at",
            "refresh_after",
            "expires_at",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/identity-resolution.schema.json#/$defs/service_resolution_record",
    },
    ProofContextDescriptor {
        id: ProofContextId::ServiceRouteHandoverNoticeProofV1,
        context: "ak.service-route-handover-notice-proof-v1",
        object_family: "service_route_handover_notice",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "service_id",
            "service_kind",
            "handover_id",
            "notice_revision",
            "state",
            "from_record_sequence",
            "from_record_digest",
            "candidate_base_url?",
            "candidate_record_url?",
            "not_before?",
            "cutover_at?",
            "grace_until?",
            "previous_notice_digest",
            "issued_at",
            "expires_at",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/identity-resolution.schema.json#/$defs/service_route_handover_notice",
    },
    ProofContextDescriptor {
        id: ProofContextId::SignalProofV1,
        context: "ak.signal-proof-v1",
        object_family: "signal_envelope",
        consumer_operation: None,
        binding_fields: &[
            "envelope_digest",
            "sender_actor_id",
            "sender_device_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/signal-envelope.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::SnapshotProofV1,
        context: "ak.snapshot-proof-v1",
        object_family: "snapshot",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "snapshot_id",
            "realm_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/snapshot.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::SnapshotWitnessAttestationProofV1,
        context: "ak.snapshot-witness-attestation-proof-v1",
        object_family: "snapshot_witness_attestation",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "witness_id",
            "snapshot_id",
            "realm_id",
            "reducer_profile",
            "schema_profile_refs",
            "security_class",
            "state_digest",
            "frontier",
            "event_set_commitment",
            "issuer",
            "authority_kind",
            "auth_state_digest",
            "auth_frontier",
            "snapshot_created_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/snapshot.schema.json#/$defs/snapshot_witness_attestation",
    },
];

pub const EXPORTER_LABELS: &[ExporterLabelDescriptor] = &[
    ExporterLabelDescriptor {
        id: ExporterLabelId::ContentV1,
        label: "ak.content-v1",
        primitive: Some("ExpandWithLabel"),
        context_fields: &[],
        output_bytes: "AEAD.Nk for the active MLS ciphersuite",
        empty_context_forbidden: false,
        forbid_reuse_with: &[
            "ak.history-v1",
            "arkret-aead-sender-nonce-prefix-v1",
            "arkret-reaction-routing-v1",
            "arkret-mention-routing-v1",
        ],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::HistoryV1,
        label: "ak.history-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["realm_id"],
        output_bytes: "KDF.Nh for the active MLS ciphersuite",
        empty_context_forbidden: true,
        forbid_reuse_with: &[
            "ak.content-v1",
            "arkret-aead-sender-nonce-prefix-v1",
            "arkret-reaction-routing-v1",
            "arkret-mention-routing-v1",
        ],
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
            "participant_identity",
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
        id: ExporterLabelId::SignalV1,
        label: "ak.signal-v1",
        primitive: Some("ExpandWithLabel"),
        context_fields: &["sender_device_id"],
        output_bytes: "AEAD.Nk for the active MLS ciphersuite",
        empty_context_forbidden: true,
        forbid_reuse_with: &[
            "ak.history-v1",
            "arkret-aead-sender-nonce-prefix-v1",
            "arkret-reaction-routing-v1",
            "arkret-mention-routing-v1",
        ],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::AeadSenderNoncePrefixV1,
        label: "arkret-aead-sender-nonce-prefix-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["key_ref", "epoch", "device_id", "purpose", "aead_profile"],
        output_bytes: "N_AEAD - 8 (16 for XChaCha20-Poly1305, 4 for AES-GCM)",
        empty_context_forbidden: true,
        forbid_reuse_with: &[],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::MentionRoutingV1,
        label: "arkret-mention-routing-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["realm_id"],
        output_bytes: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["arkret-reaction-routing-v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::ReactionRoutingV1,
        label: "arkret-reaction-routing-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["realm_id"],
        output_bytes: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["arkret-mention-routing-v1"],
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
        role: "v1_default_must",
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
        status: "active",
        role: "v1_profile_gated_pqc",
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

pub const MLS_EXTENSIONS: &[MlsExtensionDescriptor] = &[MlsExtensionDescriptor {
    name: "mls_governance_binding",
    codepoint: "0xF1C0",
    status: "active",
    profile_id: "ak.profile.mls_governance_binding.full.v1",
}];

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
