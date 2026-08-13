//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/proof-context-registry.json; version=2026-08-13.2;
//! sha256=2fbe405bbf52d5c5761fc0793ef587ab2b23e540b5cf3e23138126e4fdc52f0d Input: registry/
//! exporter-label-registry.json; version=2026-08-13.2;
//! sha256=d34969b38e82214fab7eda88928c1ee2c250b29be58d0c5968666ebb5ea54533 Input: registry/
//! digest-suite-registry.json; version=2026-08-10.1;
//! sha256=e51b58edc46ab7e1ab337883dc9fa36ccebb7536bb06eafb1b4771f844078151 Input: registry/
//! signature-alg-registry.json; version=2026-08-04.2;
//! sha256=d8f6166e45bd37f01be18d48b7ef1d83397d3912c9ebbf4bd713f7b9059d2621 Input: registry/
//! hpke-suite-registry.json; version=2026-08-09;
//! sha256=a96497d01ad2f5bc3221f9cf5990cdc78e5c16d9dd12b99ade6673833fc33627 Input: registry/
//! mls-ciphersuite-registry.json; version=2026-07-29;
//! sha256=9c2bfe1e1e6f9df9c798323ff5156b2e0b6531cd7715a9a1a7da0ddb30feeade Input: registry/
//! mls-extension-registry.json; version=2026-06-03;
//! sha256=0fbcc85e00b58715c360aa0ed37acf11d858fd6b1a7d0ceb9b0c82bda99f1614
//! Entries: proof_contexts=46, exporter_labels=9, digest_suites=3, signature_algorithms=4,
//! hpke_suites=4, mls_ciphersuites=4, mls_extensions=1

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ProofContextId {
    AccountBindingReceiptProofV1,
    AccountHandoffAuthenticationProofV1,
    AccountRegistrationControlProofV1,
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
    DidWebvhWitnessReceiptProofV1,
    DirectoryGovernanceRequestProofV1,
    DirectoryOperationProofV1,
    EventProofV1,
    ExtensionManifestProofV1,
    HandleClaimProofV1,
    IdentityCreationControlProofV1,
    IdentityReceiptProofV1,
    IngressReceiptProofV1,
    JoinApplicationCancelReceiptProofV1,
    JoinApplicationReceiptProofV1,
    JoinApplicationReviewReceiptProofV1,
    KeypackageClaimRequestProofV1,
    MemberDeliveryBindingCandidateProofV1,
    MimiOperationProofV1,
    OrganizationRegistrationControlProofV1,
    OrganizationRegistrationReceiptProofV1,
    PrincipalLocatorProofV1,
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
}

impl ProofContextId {
    pub const ALL: &'static [Self] = &[
        Self::AccountBindingReceiptProofV1,
        Self::AccountHandoffAuthenticationProofV1,
        Self::AccountRegistrationControlProofV1,
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
        Self::DidWebvhWitnessReceiptProofV1,
        Self::DirectoryGovernanceRequestProofV1,
        Self::DirectoryOperationProofV1,
        Self::EventProofV1,
        Self::ExtensionManifestProofV1,
        Self::HandleClaimProofV1,
        Self::IdentityCreationControlProofV1,
        Self::IdentityReceiptProofV1,
        Self::IngressReceiptProofV1,
        Self::JoinApplicationCancelReceiptProofV1,
        Self::JoinApplicationReceiptProofV1,
        Self::JoinApplicationReviewReceiptProofV1,
        Self::KeypackageClaimRequestProofV1,
        Self::MemberDeliveryBindingCandidateProofV1,
        Self::MimiOperationProofV1,
        Self::OrganizationRegistrationControlProofV1,
        Self::OrganizationRegistrationReceiptProofV1,
        Self::PrincipalLocatorProofV1,
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
    ];

    pub const ACCOUNT_BINDING_RECEIPT_PROOF_V1: &'static str =
        "ak.account-binding-receipt-proof-v1";
    pub const ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_V1: &'static str =
        "ak.account-handoff-authentication-proof-v1";
    pub const ACCOUNT_REGISTRATION_CONTROL_PROOF_V1: &'static str =
        "ak.account-registration-control-proof-v1";
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
    pub const DID_WEBVH_WITNESS_RECEIPT_PROOF_V1: &'static str =
        "ak.did-webvh-witness-receipt-proof-v1";
    pub const DIRECTORY_GOVERNANCE_REQUEST_PROOF_V1: &'static str =
        "ak.directory-governance-request-proof-v1";
    pub const DIRECTORY_OPERATION_PROOF_V1: &'static str = "ak.directory-operation-proof-v1";
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
    pub const KEYPACKAGE_CLAIM_REQUEST_PROOF_V1: &'static str =
        "ak.keypackage-claim-request-proof-v1";
    pub const MEMBER_DELIVERY_BINDING_CANDIDATE_PROOF_V1: &'static str =
        "ak.member-delivery-binding-candidate-proof-v1";
    pub const MIMI_OPERATION_PROOF_V1: &'static str = "ak.mimi-operation-proof-v1";
    pub const ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1: &'static str =
        "ak.organization-registration-control-proof-v1";
    pub const ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1: &'static str =
        "ak.organization-registration-receipt-proof-v1";
    pub const PRINCIPAL_LOCATOR_PROOF_V1: &'static str = "ak.principal-locator-proof-v1";
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

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountBindingReceiptProofV1 => Self::ACCOUNT_BINDING_RECEIPT_PROOF_V1,
            Self::AccountHandoffAuthenticationProofV1 => {
                Self::ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_V1
            }
            Self::AccountRegistrationControlProofV1 => Self::ACCOUNT_REGISTRATION_CONTROL_PROOF_V1,
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
            Self::DidWebvhWitnessReceiptProofV1 => Self::DID_WEBVH_WITNESS_RECEIPT_PROOF_V1,
            Self::DirectoryGovernanceRequestProofV1 => Self::DIRECTORY_GOVERNANCE_REQUEST_PROOF_V1,
            Self::DirectoryOperationProofV1 => Self::DIRECTORY_OPERATION_PROOF_V1,
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
            Self::KeypackageClaimRequestProofV1 => Self::KEYPACKAGE_CLAIM_REQUEST_PROOF_V1,
            Self::MemberDeliveryBindingCandidateProofV1 => {
                Self::MEMBER_DELIVERY_BINDING_CANDIDATE_PROOF_V1
            }
            Self::MimiOperationProofV1 => Self::MIMI_OPERATION_PROOF_V1,
            Self::OrganizationRegistrationControlProofV1 => {
                Self::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1
            }
            Self::OrganizationRegistrationReceiptProofV1 => {
                Self::ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1
            }
            Self::PrincipalLocatorProofV1 => Self::PRINCIPAL_LOCATOR_PROOF_V1,
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
            Self::DID_WEBVH_WITNESS_RECEIPT_PROOF_V1 => Some(Self::DidWebvhWitnessReceiptProofV1),
            Self::DIRECTORY_GOVERNANCE_REQUEST_PROOF_V1 => {
                Some(Self::DirectoryGovernanceRequestProofV1)
            }
            Self::DIRECTORY_OPERATION_PROOF_V1 => Some(Self::DirectoryOperationProofV1),
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
            Self::KEYPACKAGE_CLAIM_REQUEST_PROOF_V1 => Some(Self::KeypackageClaimRequestProofV1),
            Self::MEMBER_DELIVERY_BINDING_CANDIDATE_PROOF_V1 => {
                Some(Self::MemberDeliveryBindingCandidateProofV1)
            }
            Self::MIMI_OPERATION_PROOF_V1 => Some(Self::MimiOperationProofV1),
            Self::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1 => {
                Some(Self::OrganizationRegistrationControlProofV1)
            }
            Self::ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1 => {
                Some(Self::OrganizationRegistrationReceiptProofV1)
            }
            Self::PRINCIPAL_LOCATOR_PROOF_V1 => Some(Self::PrincipalLocatorProofV1),
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
        binding_fields: &[
            "payload_digest",
            "account_id",
            "principal_id",
            "verification_method",
            "created_at",
            "audience",
        ],
        schema_ref: "schemas/account-operations.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AccountRegistrationControlProofV1,
        context: "ak.account-registration-control-proof-v1",
        object_family: "account_registration_control_proof",
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
        id: ProofContextId::AccountabilityGrantProofV1,
        context: "ak.accountability-grant-proof-v1",
        object_family: "accountability_grant",
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
        binding_fields: &[
            "kind",
            "verification_method",
            "alg",
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
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/control-proposal-decision.schema.json#/$defs/control_proposal_authority_ack",
    },
    ProofContextDescriptor {
        id: ProofContextId::ControlProposalDecisionProofV1,
        context: "ak.control-proposal-decision-proof-v1",
        object_family: "control_proposal_decision",
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/control-proposal-decision.schema.json#/$defs/proposal_decision",
    },
    ProofContextDescriptor {
        id: ProofContextId::DeviceAuthorizeAcceptedDevicePossessionProofV1,
        context: "ak.device-authorize-accepted-device-possession-proof-v1",
        object_family: "device_authorize_accepted_device_possession",
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
        id: ProofContextId::DidWebvhWitnessReceiptProofV1,
        context: "ak.did-webvh-witness-receipt-proof-v1",
        object_family: "did_webvh_witness_receipt",
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
        id: ProofContextId::DirectoryOperationProofV1,
        context: "ak.directory-operation-proof-v1",
        object_family: "directory_operation",
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/directory-operations.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::EventProofV1,
        context: "ak.event-proof-v1",
        object_family: "event_envelope",
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
        binding_fields: &[
            "receipt_digest",
            "realm_id",
            "application_ref",
            "application_revision_digest",
            "actor_id",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/join-policy-operations.schema.json#/$defs/review_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::KeypackageClaimRequestProofV1,
        context: "ak.keypackage-claim-request-proof-v1",
        object_family: "keypackage_claim_request",
        binding_fields: &[
            "payload_digest",
            "requester",
            "target_principal_id",
            "intended_realm_id",
            "claim_nonce",
            "verification_method",
            "created_at",
            "proof_purpose",
            "audience",
        ],
        schema_ref: "schemas/keypackage-operations.schema.json#/$defs/keypackage_claim_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::MemberDeliveryBindingCandidateProofV1,
        context: "ak.member-delivery-binding-candidate-proof-v1",
        object_family: "member_delivery_binding_candidate",
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
        id: ProofContextId::MimiOperationProofV1,
        context: "ak.mimi-operation-proof-v1",
        object_family: "mimi_operation",
        binding_fields: &[
            "payload_digest",
            "issuer",
            "operation_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/mimi-operations.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::OrganizationRegistrationControlProofV1,
        context: "ak.organization-registration-control-proof-v1",
        object_family: "organization_registration_control_proof",
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
        id: ProofContextId::PrincipalServerAdmissionProofV1,
        context: "ak.principal-server-admission-proof-v1",
        object_family: "principal_server_event_admission",
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
