//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/proof-context-registry.json; version=2026-09-10.17;
//! sha256=acad38dab5c932b41fc89c686cf992e2ea685778aca074f318bd2e0fc16159bf Input: registry/
//! exporter-label-registry.json; version=2026-09-01.1;
//! sha256=1bba5f530b6d6ce8d64c20b4418163bd3eebe8c44cef8a246d14b846c7d1b333 Input: registry/
//! digest-suite-registry.json; version=2026-08-31;
//! sha256=d75d7fd0feb27c7a29db2255ce503f6137f31a9102086cb05be4b84ce03f297b Input: registry/
//! signature-alg-registry.json; version=2026-08-18.1;
//! sha256=2bd41f0302e641c5a9eac6297b0e500c9d7100bb925c1f395d7198a7b4ac3e3c Input: registry/
//! hpke-suite-registry.json; version=2026-09-08.3;
//! sha256=b5395c8e30fcc650e128567631d3c2a4d46fa6b5d80cf29ab83c0e4b3477b4d1 Input: registry/
//! mls-ciphersuite-registry.json; version=2026-08-25;
//! sha256=68619d8db1de222c9d032fdc96e92be32e85fdc0a3a0befdf4b21d135a57075d Input: registry/
//! mls-extension-registry.json; version=2026-09-10;
//! sha256=81e22df857af450c7544257a0e6b5256a245501b45de0748ba4e3649dda8238e Input: registry/
//! aead-profile-registry.json; version=2026-08-16.1;
//! sha256=5cab256353caa112d59f4ba10390715eaa27a3c3b530ee1766f01d35a4ea72de
//! Entries: proof_contexts=72, exporter_labels=9, digest_suites=3, signature_algorithms=4,
//! hpke_suites=4, mls_ciphersuites=4, mls_extensions=5, domain_separations=40, aead_profiles=2

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
    AuditReleaseAttestationProofV1,
    AuditRywReceiptProofV1,
    AuthorizationLeaseProofV1,
    AvailabilityReceiptProofV1,
    CollisionVariantRecordProofV1,
    ControlProposalAuthorityAckProofV1,
    ControlProposalDecisionProofV1,
    DeviceAuthorizeAcceptedDevicePossessionProofV1,
    DeviceAuthorizePossessionProofV1,
    DeviceAuthorizeRecoveryPossessionProofV1,
    DeviceProjectionAttestationProofV1,
    DeviceRevocationGateDecisionProofV1,
    DidWebvhWitnessReceiptProofV1,
    DirectoryGovernanceRequestProofV1,
    DirectorySourceRefAccessProofV1,
    EventProofV1,
    ExtensionManifestProofV1,
    HandleClaimProofV1,
    HandleClaimRevocationV1,
    HandleClaimStatusV1,
    HistoryKeyRequestProofV1,
    HistoryKeyRequestReceiptProofV1,
    HistoryKeyRequestReplicaProofV1,
    HistoryKeyRequestReplicaReceiptProofV1,
    HistoryKeyResponseLostRecordProofV1,
    HistoryKeyResponseProofV1,
    HistoryKeyResponseRecordProofV1,
    HistoryKeyResponseSendReceiptProofV1,
    HistoryKeySourceRelayAttestationProofV1,
    IdentityCreationControlProofV1,
    IdentityReceiptProofV1,
    IngressReceiptProofV1,
    JoinGateProofV1,
    KeyBackupDeleteProofV1,
    MimiIdentifierQueryOutcomeProofV1,
    MimiIdentifierQueryRequestProofV1,
    MimiKeyMaterialOutcomeProofV1,
    MimiKeyMaterialRequestProofV1,
    MimiProviderDirectoryProofV1,
    MimiRequestConsentRequestProofV1,
    MimiUpdateConsentRequestProofV1,
    OrganizationRecoveryArchiveReplicaProofV1,
    OrganizationRecoveryArchiveReplicaReceiptProofV1,
    OrganizationRecoveryKeyHolderAcceptanceProofV1,
    OrganizationRegistrationControlProofV1,
    OrganizationRegistrationReceiptProofV1,
    PeerSealFrontierProofV1,
    PrincipalLocatorProofV1,
    PrincipalResolutionProjectionAttestationProofV1,
    RealmJoinCandidateProofV1,
    RealmStateSnapshotProofV1,
    RealmStateSnapshotWitnessAttestationProofV1,
    ReceiptProofV1,
    RegistrationDidEvidenceControlProofV1,
    ServiceRegistrationReceiptProofV1,
    SessionGrantAcceptedDevicePossessionProofV1,
    SessionGrantPairwiseEndpointPossessionProofV1,
    SignalProofV1,
    StationAdmissionProofV1,
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
        Self::AuditReleaseAttestationProofV1,
        Self::AuditRywReceiptProofV1,
        Self::AuthorizationLeaseProofV1,
        Self::AvailabilityReceiptProofV1,
        Self::CollisionVariantRecordProofV1,
        Self::ControlProposalAuthorityAckProofV1,
        Self::ControlProposalDecisionProofV1,
        Self::DeviceAuthorizeAcceptedDevicePossessionProofV1,
        Self::DeviceAuthorizePossessionProofV1,
        Self::DeviceAuthorizeRecoveryPossessionProofV1,
        Self::DeviceProjectionAttestationProofV1,
        Self::DeviceRevocationGateDecisionProofV1,
        Self::DidWebvhWitnessReceiptProofV1,
        Self::DirectoryGovernanceRequestProofV1,
        Self::DirectorySourceRefAccessProofV1,
        Self::EventProofV1,
        Self::ExtensionManifestProofV1,
        Self::HandleClaimProofV1,
        Self::HandleClaimRevocationV1,
        Self::HandleClaimStatusV1,
        Self::HistoryKeyRequestProofV1,
        Self::HistoryKeyRequestReceiptProofV1,
        Self::HistoryKeyRequestReplicaProofV1,
        Self::HistoryKeyRequestReplicaReceiptProofV1,
        Self::HistoryKeyResponseLostRecordProofV1,
        Self::HistoryKeyResponseProofV1,
        Self::HistoryKeyResponseRecordProofV1,
        Self::HistoryKeyResponseSendReceiptProofV1,
        Self::HistoryKeySourceRelayAttestationProofV1,
        Self::IdentityCreationControlProofV1,
        Self::IdentityReceiptProofV1,
        Self::IngressReceiptProofV1,
        Self::JoinGateProofV1,
        Self::KeyBackupDeleteProofV1,
        Self::MimiIdentifierQueryOutcomeProofV1,
        Self::MimiIdentifierQueryRequestProofV1,
        Self::MimiKeyMaterialOutcomeProofV1,
        Self::MimiKeyMaterialRequestProofV1,
        Self::MimiProviderDirectoryProofV1,
        Self::MimiRequestConsentRequestProofV1,
        Self::MimiUpdateConsentRequestProofV1,
        Self::OrganizationRecoveryArchiveReplicaProofV1,
        Self::OrganizationRecoveryArchiveReplicaReceiptProofV1,
        Self::OrganizationRecoveryKeyHolderAcceptanceProofV1,
        Self::OrganizationRegistrationControlProofV1,
        Self::OrganizationRegistrationReceiptProofV1,
        Self::PeerSealFrontierProofV1,
        Self::PrincipalLocatorProofV1,
        Self::PrincipalResolutionProjectionAttestationProofV1,
        Self::RealmJoinCandidateProofV1,
        Self::RealmStateSnapshotProofV1,
        Self::RealmStateSnapshotWitnessAttestationProofV1,
        Self::ReceiptProofV1,
        Self::RegistrationDidEvidenceControlProofV1,
        Self::ServiceRegistrationReceiptProofV1,
        Self::SessionGrantAcceptedDevicePossessionProofV1,
        Self::SessionGrantPairwiseEndpointPossessionProofV1,
        Self::SignalProofV1,
        Self::StationAdmissionProofV1,
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
    pub const AUDIT_RELEASE_ATTESTATION_PROOF_V1: &'static str =
        "ak.audit_release_attestation_proof.v1";
    pub const AUDIT_RYW_RECEIPT_PROOF_V1: &'static str = "ak.audit_ryw_receipt_proof.v1";
    pub const AUTHORIZATION_LEASE_PROOF_V1: &'static str = "ak.authorization_lease_proof.v1";
    pub const AVAILABILITY_RECEIPT_PROOF_V1: &'static str = "ak.availability_receipt_proof.v1";
    pub const COLLISION_VARIANT_RECORD_PROOF_V1: &'static str =
        "ak.collision_variant_record_proof.v1";
    pub const CONTROL_PROPOSAL_AUTHORITY_ACK_PROOF_V1: &'static str =
        "ak.control_proposal_authority_ack_proof.v1";
    pub const CONTROL_PROPOSAL_DECISION_PROOF_V1: &'static str =
        "ak.control_proposal_decision_proof.v1";
    pub const DEVICE_AUTHORIZE_ACCEPTED_DEVICE_POSSESSION_PROOF_V1: &'static str =
        "ak.device_authorize_accepted_device_possession_proof.v1";
    pub const DEVICE_AUTHORIZE_POSSESSION_PROOF_V1: &'static str =
        "ak.device_authorize_possession_proof.v1";
    pub const DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PROOF_V1: &'static str =
        "ak.device_authorize_recovery_possession_proof.v1";
    pub const DEVICE_PROJECTION_ATTESTATION_PROOF_V1: &'static str =
        "ak.device_projection_attestation_proof.v1";
    pub const DEVICE_REVOCATION_GATE_DECISION_PROOF_V1: &'static str =
        "ak.device_revocation_gate_decision_proof.v1";
    pub const DID_WEBVH_WITNESS_RECEIPT_PROOF_V1: &'static str =
        "ak.did_webvh_witness_receipt_proof.v1";
    pub const DIRECTORY_GOVERNANCE_REQUEST_PROOF_V1: &'static str =
        "ak.directory_governance_request_proof.v1";
    pub const DIRECTORY_SOURCE_REF_ACCESS_PROOF_V1: &'static str =
        "ak.directory_source_ref_access_proof.v1";
    pub const EVENT_PROOF_V1: &'static str = "ak.event_proof.v1";
    pub const EXTENSION_MANIFEST_PROOF_V1: &'static str = "ak.extension_manifest_proof.v1";
    pub const HANDLE_CLAIM_PROOF_V1: &'static str = "ak.handle_claim_proof.v1";
    pub const HANDLE_CLAIM_REVOCATION_V1: &'static str = "ak.handle_claim_revocation.v1";
    pub const HANDLE_CLAIM_STATUS_V1: &'static str = "ak.handle_claim_status.v1";
    pub const HISTORY_KEY_REQUEST_PROOF_V1: &'static str = "ak.history_key_request_proof.v1";
    pub const HISTORY_KEY_REQUEST_RECEIPT_PROOF_V1: &'static str =
        "ak.history_key_request_receipt_proof.v1";
    pub const HISTORY_KEY_REQUEST_REPLICA_PROOF_V1: &'static str =
        "ak.history_key_request_replica_proof.v1";
    pub const HISTORY_KEY_REQUEST_REPLICA_RECEIPT_PROOF_V1: &'static str =
        "ak.history_key_request_replica_receipt_proof.v1";
    pub const HISTORY_KEY_RESPONSE_LOST_RECORD_PROOF_V1: &'static str =
        "ak.history_key_response_lost_record_proof.v1";
    pub const HISTORY_KEY_RESPONSE_PROOF_V1: &'static str = "ak.history_key_response_proof.v1";
    pub const HISTORY_KEY_RESPONSE_RECORD_PROOF_V1: &'static str =
        "ak.history_key_response_record_proof.v1";
    pub const HISTORY_KEY_RESPONSE_SEND_RECEIPT_PROOF_V1: &'static str =
        "ak.history_key_response_send_receipt_proof.v1";
    pub const HISTORY_KEY_SOURCE_RELAY_ATTESTATION_PROOF_V1: &'static str =
        "ak.history_key_source_relay_attestation_proof.v1";
    pub const IDENTITY_CREATION_CONTROL_PROOF_V1: &'static str =
        "ak.identity_creation_control_proof.v1";
    pub const IDENTITY_RECEIPT_PROOF_V1: &'static str = "ak.identity_receipt_proof.v1";
    pub const INGRESS_RECEIPT_PROOF_V1: &'static str = "ak.ingress_receipt_proof.v1";
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
    pub const ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_PROOF_V1: &'static str =
        "ak.organization_recovery_archive_replica_proof.v1";
    pub const ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_RECEIPT_PROOF_V1: &'static str =
        "ak.organization_recovery_archive_replica_receipt_proof.v1";
    pub const ORGANIZATION_RECOVERY_KEY_HOLDER_ACCEPTANCE_PROOF_V1: &'static str =
        "ak.organization_recovery_key_holder_acceptance_proof.v1";
    pub const ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1: &'static str =
        "ak.organization_registration_control_proof.v1";
    pub const ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1: &'static str =
        "ak.organization_registration_receipt_proof.v1";
    pub const PEER_SEAL_FRONTIER_PROOF_V1: &'static str = "ak.peer_seal_frontier_proof.v1";
    pub const PRINCIPAL_LOCATOR_PROOF_V1: &'static str = "ak.principal_locator_proof.v1";
    pub const PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_PROOF_V1: &'static str =
        "ak.principal_resolution_projection_attestation_proof.v1";
    pub const REALM_JOIN_CANDIDATE_PROOF_V1: &'static str = "ak.realm_join_candidate_proof.v1";
    pub const REALM_STATE_SNAPSHOT_PROOF_V1: &'static str = "ak.realm_state_snapshot_proof.v1";
    pub const REALM_STATE_SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1: &'static str =
        "ak.realm_state_snapshot_witness_attestation_proof.v1";
    pub const RECEIPT_PROOF_V1: &'static str = "ak.receipt_proof.v1";
    pub const REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1: &'static str =
        "ak.registration_did_evidence_control_proof.v1";
    pub const SERVICE_REGISTRATION_RECEIPT_PROOF_V1: &'static str =
        "ak.service_registration_receipt_proof.v1";
    pub const SESSION_GRANT_ACCEPTED_DEVICE_POSSESSION_PROOF_V1: &'static str =
        "ak.session_grant_accepted_device_possession_proof.v1";
    pub const SESSION_GRANT_PAIRWISE_ENDPOINT_POSSESSION_PROOF_V1: &'static str =
        "ak.session_grant_pairwise_endpoint_possession_proof.v1";
    pub const SIGNAL_PROOF_V1: &'static str = "ak.signal_proof.v1";
    pub const STATION_ADMISSION_PROOF_V1: &'static str = "ak.station_admission_proof.v1";
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
            Self::AuditReleaseAttestationProofV1 => Self::AUDIT_RELEASE_ATTESTATION_PROOF_V1,
            Self::AuditRywReceiptProofV1 => Self::AUDIT_RYW_RECEIPT_PROOF_V1,
            Self::AuthorizationLeaseProofV1 => Self::AUTHORIZATION_LEASE_PROOF_V1,
            Self::AvailabilityReceiptProofV1 => Self::AVAILABILITY_RECEIPT_PROOF_V1,
            Self::CollisionVariantRecordProofV1 => Self::COLLISION_VARIANT_RECORD_PROOF_V1,
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
            Self::DirectorySourceRefAccessProofV1 => Self::DIRECTORY_SOURCE_REF_ACCESS_PROOF_V1,
            Self::EventProofV1 => Self::EVENT_PROOF_V1,
            Self::ExtensionManifestProofV1 => Self::EXTENSION_MANIFEST_PROOF_V1,
            Self::HandleClaimProofV1 => Self::HANDLE_CLAIM_PROOF_V1,
            Self::HandleClaimRevocationV1 => Self::HANDLE_CLAIM_REVOCATION_V1,
            Self::HandleClaimStatusV1 => Self::HANDLE_CLAIM_STATUS_V1,
            Self::HistoryKeyRequestProofV1 => Self::HISTORY_KEY_REQUEST_PROOF_V1,
            Self::HistoryKeyRequestReceiptProofV1 => Self::HISTORY_KEY_REQUEST_RECEIPT_PROOF_V1,
            Self::HistoryKeyRequestReplicaProofV1 => Self::HISTORY_KEY_REQUEST_REPLICA_PROOF_V1,
            Self::HistoryKeyRequestReplicaReceiptProofV1 => {
                Self::HISTORY_KEY_REQUEST_REPLICA_RECEIPT_PROOF_V1
            }
            Self::HistoryKeyResponseLostRecordProofV1 => {
                Self::HISTORY_KEY_RESPONSE_LOST_RECORD_PROOF_V1
            }
            Self::HistoryKeyResponseProofV1 => Self::HISTORY_KEY_RESPONSE_PROOF_V1,
            Self::HistoryKeyResponseRecordProofV1 => Self::HISTORY_KEY_RESPONSE_RECORD_PROOF_V1,
            Self::HistoryKeyResponseSendReceiptProofV1 => {
                Self::HISTORY_KEY_RESPONSE_SEND_RECEIPT_PROOF_V1
            }
            Self::HistoryKeySourceRelayAttestationProofV1 => {
                Self::HISTORY_KEY_SOURCE_RELAY_ATTESTATION_PROOF_V1
            }
            Self::IdentityCreationControlProofV1 => Self::IDENTITY_CREATION_CONTROL_PROOF_V1,
            Self::IdentityReceiptProofV1 => Self::IDENTITY_RECEIPT_PROOF_V1,
            Self::IngressReceiptProofV1 => Self::INGRESS_RECEIPT_PROOF_V1,
            Self::JoinGateProofV1 => Self::JOIN_GATE_PROOF_V1,
            Self::KeyBackupDeleteProofV1 => Self::KEY_BACKUP_DELETE_PROOF_V1,
            Self::MimiIdentifierQueryOutcomeProofV1 => Self::MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1,
            Self::MimiIdentifierQueryRequestProofV1 => Self::MIMI_IDENTIFIER_QUERY_REQUEST_PROOF_V1,
            Self::MimiKeyMaterialOutcomeProofV1 => Self::MIMI_KEY_MATERIAL_OUTCOME_PROOF_V1,
            Self::MimiKeyMaterialRequestProofV1 => Self::MIMI_KEY_MATERIAL_REQUEST_PROOF_V1,
            Self::MimiProviderDirectoryProofV1 => Self::MIMI_PROVIDER_DIRECTORY_PROOF_V1,
            Self::MimiRequestConsentRequestProofV1 => Self::MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1,
            Self::MimiUpdateConsentRequestProofV1 => Self::MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1,
            Self::OrganizationRecoveryArchiveReplicaProofV1 => {
                Self::ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_PROOF_V1
            }
            Self::OrganizationRecoveryArchiveReplicaReceiptProofV1 => {
                Self::ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_RECEIPT_PROOF_V1
            }
            Self::OrganizationRecoveryKeyHolderAcceptanceProofV1 => {
                Self::ORGANIZATION_RECOVERY_KEY_HOLDER_ACCEPTANCE_PROOF_V1
            }
            Self::OrganizationRegistrationControlProofV1 => {
                Self::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1
            }
            Self::OrganizationRegistrationReceiptProofV1 => {
                Self::ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1
            }
            Self::PeerSealFrontierProofV1 => Self::PEER_SEAL_FRONTIER_PROOF_V1,
            Self::PrincipalLocatorProofV1 => Self::PRINCIPAL_LOCATOR_PROOF_V1,
            Self::PrincipalResolutionProjectionAttestationProofV1 => {
                Self::PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_PROOF_V1
            }
            Self::RealmJoinCandidateProofV1 => Self::REALM_JOIN_CANDIDATE_PROOF_V1,
            Self::RealmStateSnapshotProofV1 => Self::REALM_STATE_SNAPSHOT_PROOF_V1,
            Self::RealmStateSnapshotWitnessAttestationProofV1 => {
                Self::REALM_STATE_SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1
            }
            Self::ReceiptProofV1 => Self::RECEIPT_PROOF_V1,
            Self::RegistrationDidEvidenceControlProofV1 => {
                Self::REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1
            }
            Self::ServiceRegistrationReceiptProofV1 => Self::SERVICE_REGISTRATION_RECEIPT_PROOF_V1,
            Self::SessionGrantAcceptedDevicePossessionProofV1 => {
                Self::SESSION_GRANT_ACCEPTED_DEVICE_POSSESSION_PROOF_V1
            }
            Self::SessionGrantPairwiseEndpointPossessionProofV1 => {
                Self::SESSION_GRANT_PAIRWISE_ENDPOINT_POSSESSION_PROOF_V1
            }
            Self::SignalProofV1 => Self::SIGNAL_PROOF_V1,
            Self::StationAdmissionProofV1 => Self::STATION_ADMISSION_PROOF_V1,
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
            Self::AUDIT_RELEASE_ATTESTATION_PROOF_V1 => Some(Self::AuditReleaseAttestationProofV1),
            Self::AUDIT_RYW_RECEIPT_PROOF_V1 => Some(Self::AuditRywReceiptProofV1),
            Self::AUTHORIZATION_LEASE_PROOF_V1 => Some(Self::AuthorizationLeaseProofV1),
            Self::AVAILABILITY_RECEIPT_PROOF_V1 => Some(Self::AvailabilityReceiptProofV1),
            Self::COLLISION_VARIANT_RECORD_PROOF_V1 => Some(Self::CollisionVariantRecordProofV1),
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
            Self::DIRECTORY_SOURCE_REF_ACCESS_PROOF_V1 => {
                Some(Self::DirectorySourceRefAccessProofV1)
            }
            Self::EVENT_PROOF_V1 => Some(Self::EventProofV1),
            Self::EXTENSION_MANIFEST_PROOF_V1 => Some(Self::ExtensionManifestProofV1),
            Self::HANDLE_CLAIM_PROOF_V1 => Some(Self::HandleClaimProofV1),
            Self::HANDLE_CLAIM_REVOCATION_V1 => Some(Self::HandleClaimRevocationV1),
            Self::HANDLE_CLAIM_STATUS_V1 => Some(Self::HandleClaimStatusV1),
            Self::HISTORY_KEY_REQUEST_PROOF_V1 => Some(Self::HistoryKeyRequestProofV1),
            Self::HISTORY_KEY_REQUEST_RECEIPT_PROOF_V1 => {
                Some(Self::HistoryKeyRequestReceiptProofV1)
            }
            Self::HISTORY_KEY_REQUEST_REPLICA_PROOF_V1 => {
                Some(Self::HistoryKeyRequestReplicaProofV1)
            }
            Self::HISTORY_KEY_REQUEST_REPLICA_RECEIPT_PROOF_V1 => {
                Some(Self::HistoryKeyRequestReplicaReceiptProofV1)
            }
            Self::HISTORY_KEY_RESPONSE_LOST_RECORD_PROOF_V1 => {
                Some(Self::HistoryKeyResponseLostRecordProofV1)
            }
            Self::HISTORY_KEY_RESPONSE_PROOF_V1 => Some(Self::HistoryKeyResponseProofV1),
            Self::HISTORY_KEY_RESPONSE_RECORD_PROOF_V1 => {
                Some(Self::HistoryKeyResponseRecordProofV1)
            }
            Self::HISTORY_KEY_RESPONSE_SEND_RECEIPT_PROOF_V1 => {
                Some(Self::HistoryKeyResponseSendReceiptProofV1)
            }
            Self::HISTORY_KEY_SOURCE_RELAY_ATTESTATION_PROOF_V1 => {
                Some(Self::HistoryKeySourceRelayAttestationProofV1)
            }
            Self::IDENTITY_CREATION_CONTROL_PROOF_V1 => Some(Self::IdentityCreationControlProofV1),
            Self::IDENTITY_RECEIPT_PROOF_V1 => Some(Self::IdentityReceiptProofV1),
            Self::INGRESS_RECEIPT_PROOF_V1 => Some(Self::IngressReceiptProofV1),
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
            Self::ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_PROOF_V1 => {
                Some(Self::OrganizationRecoveryArchiveReplicaProofV1)
            }
            Self::ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_RECEIPT_PROOF_V1 => {
                Some(Self::OrganizationRecoveryArchiveReplicaReceiptProofV1)
            }
            Self::ORGANIZATION_RECOVERY_KEY_HOLDER_ACCEPTANCE_PROOF_V1 => {
                Some(Self::OrganizationRecoveryKeyHolderAcceptanceProofV1)
            }
            Self::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1 => {
                Some(Self::OrganizationRegistrationControlProofV1)
            }
            Self::ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1 => {
                Some(Self::OrganizationRegistrationReceiptProofV1)
            }
            Self::PEER_SEAL_FRONTIER_PROOF_V1 => Some(Self::PeerSealFrontierProofV1),
            Self::PRINCIPAL_LOCATOR_PROOF_V1 => Some(Self::PrincipalLocatorProofV1),
            Self::PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_PROOF_V1 => {
                Some(Self::PrincipalResolutionProjectionAttestationProofV1)
            }
            Self::REALM_JOIN_CANDIDATE_PROOF_V1 => Some(Self::RealmJoinCandidateProofV1),
            Self::REALM_STATE_SNAPSHOT_PROOF_V1 => Some(Self::RealmStateSnapshotProofV1),
            Self::REALM_STATE_SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1 => {
                Some(Self::RealmStateSnapshotWitnessAttestationProofV1)
            }
            Self::RECEIPT_PROOF_V1 => Some(Self::ReceiptProofV1),
            Self::REGISTRATION_DID_EVIDENCE_CONTROL_PROOF_V1 => {
                Some(Self::RegistrationDidEvidenceControlProofV1)
            }
            Self::SERVICE_REGISTRATION_RECEIPT_PROOF_V1 => {
                Some(Self::ServiceRegistrationReceiptProofV1)
            }
            Self::SESSION_GRANT_ACCEPTED_DEVICE_POSSESSION_PROOF_V1 => {
                Some(Self::SessionGrantAcceptedDevicePossessionProofV1)
            }
            Self::SESSION_GRANT_PAIRWISE_ENDPOINT_POSSESSION_PROOF_V1 => {
                Some(Self::SessionGrantPairwiseEndpointPossessionProofV1)
            }
            Self::SIGNAL_PROOF_V1 => Some(Self::SignalProofV1),
            Self::STATION_ADMISSION_PROOF_V1 => Some(Self::StationAdmissionProofV1),
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
    AgentSignerAdmissionReceiptV1,
    AppletDeliveryAuthenticationRecordDigestV1,
    AppletManagedActorAuthoringRequestProofV1,
    AppletManagedActorBundleProofV1,
    ContactGlareUnconsumedSlotV1,
    ContactNoOutgoingSlotV1,
    ContactRequestAcceptanceCoreV1,
    ContactRequestSourceCheckpointV1,
    ControllerAccountGateV1,
    DirectoryListHandlesForSubjectRequestProofV1,
    DirectoryResolveAgentSelectorRequestProofV1,
    DirectoryResolveHandleRequestProofV1,
    DirectoryResolveOrganizationRequestProofV1,
    DirectoryResolveTargetRequestProofV1,
    EventsFrontierLeafV1,
    EventsFrontierNodeV1,
    EventsFrontierRootV1,
    EventsFrontierSignatureV1,
    FederationVerifyActorSignatureV1,
    FrankingProofSignatureV1,
    HttpMessageSignatureV1,
    IdentityRecoveryDevicePossessionV1,
    IdentityRecoveryPolicySignatureV1,
    IdentityRecoveryProofV1,
    IdentityRecoveryReceiptSignatureV1,
    JoinedControlViewDigestV1,
    KeypackageClaimTerminalReceiptV1,
    KeypackageConsumeReceiptV1,
    MembershipCompensationSingleUseCasV1,
    MembershipCompensationTerminalCertificateV1,
    MimiReporterAuthorityProofV1,
    MlsRecipientDurableReceiptV1,
    PeerEventsCommandSubmitV1ServiceBindingV1,
    PeerContactControlReceiptV1,
    PeerContactMirrorReceiptV1,
    RealmOrganizationStatementV1,
    RealmStateSnapshotAuthStateIssuerLocalV1,
    WebsocketAuthV1,
}

impl DomainSeparationId {
    pub const ALL: &'static [Self] = &[
        Self::AccountabilityScopeSetV1,
        Self::AgentAuthorityStateEvidenceV1,
        Self::AgentSignerAdmissionReceiptV1,
        Self::AppletDeliveryAuthenticationRecordDigestV1,
        Self::AppletManagedActorAuthoringRequestProofV1,
        Self::AppletManagedActorBundleProofV1,
        Self::ContactGlareUnconsumedSlotV1,
        Self::ContactNoOutgoingSlotV1,
        Self::ContactRequestAcceptanceCoreV1,
        Self::ContactRequestSourceCheckpointV1,
        Self::ControllerAccountGateV1,
        Self::DirectoryListHandlesForSubjectRequestProofV1,
        Self::DirectoryResolveAgentSelectorRequestProofV1,
        Self::DirectoryResolveHandleRequestProofV1,
        Self::DirectoryResolveOrganizationRequestProofV1,
        Self::DirectoryResolveTargetRequestProofV1,
        Self::EventsFrontierLeafV1,
        Self::EventsFrontierNodeV1,
        Self::EventsFrontierRootV1,
        Self::EventsFrontierSignatureV1,
        Self::FederationVerifyActorSignatureV1,
        Self::FrankingProofSignatureV1,
        Self::HttpMessageSignatureV1,
        Self::IdentityRecoveryDevicePossessionV1,
        Self::IdentityRecoveryPolicySignatureV1,
        Self::IdentityRecoveryProofV1,
        Self::IdentityRecoveryReceiptSignatureV1,
        Self::JoinedControlViewDigestV1,
        Self::KeypackageClaimTerminalReceiptV1,
        Self::KeypackageConsumeReceiptV1,
        Self::MembershipCompensationSingleUseCasV1,
        Self::MembershipCompensationTerminalCertificateV1,
        Self::MimiReporterAuthorityProofV1,
        Self::MlsRecipientDurableReceiptV1,
        Self::PeerEventsCommandSubmitV1ServiceBindingV1,
        Self::PeerContactControlReceiptV1,
        Self::PeerContactMirrorReceiptV1,
        Self::RealmOrganizationStatementV1,
        Self::RealmStateSnapshotAuthStateIssuerLocalV1,
        Self::WebsocketAuthV1,
    ];

    pub const ACCOUNTABILITY_SCOPE_SET_V1: &'static str = "ak.accountability_scope_set.v1";
    pub const AGENT_AUTHORITY_STATE_EVIDENCE_V1: &'static str =
        "ak.agent_authority_state_evidence.v1";
    pub const AGENT_SIGNER_ADMISSION_RECEIPT_V1: &'static str =
        "ak.agent_signer_admission_receipt.v1";
    pub const APPLET_DELIVERY_AUTHENTICATION_RECORD_DIGEST_V1: &'static str =
        "ak.applet.delivery_authentication_record_digest.v1";
    pub const APPLET_MANAGED_ACTOR_AUTHORING_REQUEST_PROOF_V1: &'static str =
        "ak.applet_managed_actor_authoring_request_proof.v1";
    pub const APPLET_MANAGED_ACTOR_BUNDLE_PROOF_V1: &'static str =
        "ak.applet_managed_actor_bundle_proof.v1";
    pub const CONTACT_GLARE_UNCONSUMED_SLOT_V1: &'static str =
        "ak.contact.glare_unconsumed_slot.v1";
    pub const CONTACT_NO_OUTGOING_SLOT_V1: &'static str = "ak.contact.no_outgoing_slot.v1";
    pub const CONTACT_REQUEST_ACCEPTANCE_CORE_V1: &'static str =
        "ak.contact.request_acceptance_core.v1";
    pub const CONTACT_REQUEST_SOURCE_CHECKPOINT_V1: &'static str =
        "ak.contact.request_source_checkpoint.v1";
    pub const CONTROLLER_ACCOUNT_GATE_V1: &'static str = "ak.controller_account_gate.v1";
    pub const DIRECTORY_LIST_HANDLES_FOR_SUBJECT_REQUEST_PROOF_V1: &'static str =
        "ak.directory_list_handles_for_subject_request_proof.v1";
    pub const DIRECTORY_RESOLVE_AGENT_SELECTOR_REQUEST_PROOF_V1: &'static str =
        "ak.directory_resolve_agent_selector_request_proof.v1";
    pub const DIRECTORY_RESOLVE_HANDLE_REQUEST_PROOF_V1: &'static str =
        "ak.directory_resolve_handle_request_proof.v1";
    pub const DIRECTORY_RESOLVE_ORGANIZATION_REQUEST_PROOF_V1: &'static str =
        "ak.directory_resolve_organization_request_proof.v1";
    pub const DIRECTORY_RESOLVE_TARGET_REQUEST_PROOF_V1: &'static str =
        "ak.directory_resolve_target_request_proof.v1";
    pub const EVENTS_FRONTIER_LEAF_V1: &'static str = "ak.events.frontier.leaf.v1";
    pub const EVENTS_FRONTIER_NODE_V1: &'static str = "ak.events.frontier.node.v1";
    pub const EVENTS_FRONTIER_ROOT_V1: &'static str = "ak.events.frontier.root.v1";
    pub const EVENTS_FRONTIER_SIGNATURE_V1: &'static str = "ak.events.frontier.signature.v1";
    pub const FEDERATION_VERIFY_ACTOR_SIGNATURE_V1: &'static str =
        "ak.federation.verify_actor.signature.v1";
    pub const FRANKING_PROOF_SIGNATURE_V1: &'static str = "ak.franking_proof.signature.v1";
    pub const HTTP_MESSAGE_SIGNATURE_V1: &'static str = "ak.http_message_signature.v1";
    pub const IDENTITY_RECOVERY_DEVICE_POSSESSION_V1: &'static str =
        "ak.identity.recovery_device_possession.v1";
    pub const IDENTITY_RECOVERY_POLICY_SIGNATURE_V1: &'static str =
        "ak.identity.recovery_policy.signature.v1";
    pub const IDENTITY_RECOVERY_PROOF_V1: &'static str = "ak.identity.recovery_proof.v1";
    pub const IDENTITY_RECOVERY_RECEIPT_SIGNATURE_V1: &'static str =
        "ak.identity.recovery_receipt.signature.v1";
    pub const JOINED_CONTROL_VIEW_DIGEST_V1: &'static str = "ak.joined_control_view_digest.v1";
    pub const KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1: &'static str =
        "ak.keypackage.claim_terminal_receipt.v1";
    pub const KEYPACKAGE_CONSUME_RECEIPT_V1: &'static str = "ak.keypackage.consume_receipt.v1";
    pub const MEMBERSHIP_COMPENSATION_SINGLE_USE_CAS_V1: &'static str =
        "ak.membership_compensation.single_use_cas.v1";
    pub const MEMBERSHIP_COMPENSATION_TERMINAL_CERTIFICATE_V1: &'static str =
        "ak.membership_compensation.terminal_certificate.v1";
    pub const MIMI_REPORTER_AUTHORITY_PROOF_V1: &'static str =
        "ak.mimi_reporter_authority_proof.v1";
    pub const MLS_RECIPIENT_DURABLE_RECEIPT_V1: &'static str =
        "ak.mls.recipient_durable_receipt.v1";
    pub const PEER_EVENTS_COMMAND_SUBMIT_V1_SERVICE_BINDING_V1: &'static str =
        "ak.peer.events.command.submit.v1.service_binding.v1";
    pub const PEER_CONTACT_CONTROL_RECEIPT_V1: &'static str = "ak.peer_contact.control_receipt.v1";
    pub const PEER_CONTACT_MIRROR_RECEIPT_V1: &'static str = "ak.peer_contact.mirror_receipt.v1";
    pub const REALM_ORGANIZATION_STATEMENT_V1: &'static str = "ak.realm.organization.statement.v1";
    pub const REALM_STATE_SNAPSHOT_AUTH_STATE_ISSUER_LOCAL_V1: &'static str =
        "ak.realm_state_snapshot.auth_state.issuer_local.v1";
    pub const WEBSOCKET_AUTH_V1: &'static str = "ak.websocket_auth.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountabilityScopeSetV1 => Self::ACCOUNTABILITY_SCOPE_SET_V1,
            Self::AgentAuthorityStateEvidenceV1 => Self::AGENT_AUTHORITY_STATE_EVIDENCE_V1,
            Self::AgentSignerAdmissionReceiptV1 => Self::AGENT_SIGNER_ADMISSION_RECEIPT_V1,
            Self::AppletDeliveryAuthenticationRecordDigestV1 => {
                Self::APPLET_DELIVERY_AUTHENTICATION_RECORD_DIGEST_V1
            }
            Self::AppletManagedActorAuthoringRequestProofV1 => {
                Self::APPLET_MANAGED_ACTOR_AUTHORING_REQUEST_PROOF_V1
            }
            Self::AppletManagedActorBundleProofV1 => Self::APPLET_MANAGED_ACTOR_BUNDLE_PROOF_V1,
            Self::ContactGlareUnconsumedSlotV1 => Self::CONTACT_GLARE_UNCONSUMED_SLOT_V1,
            Self::ContactNoOutgoingSlotV1 => Self::CONTACT_NO_OUTGOING_SLOT_V1,
            Self::ContactRequestAcceptanceCoreV1 => Self::CONTACT_REQUEST_ACCEPTANCE_CORE_V1,
            Self::ContactRequestSourceCheckpointV1 => Self::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,
            Self::ControllerAccountGateV1 => Self::CONTROLLER_ACCOUNT_GATE_V1,
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
            Self::EventsFrontierLeafV1 => Self::EVENTS_FRONTIER_LEAF_V1,
            Self::EventsFrontierNodeV1 => Self::EVENTS_FRONTIER_NODE_V1,
            Self::EventsFrontierRootV1 => Self::EVENTS_FRONTIER_ROOT_V1,
            Self::EventsFrontierSignatureV1 => Self::EVENTS_FRONTIER_SIGNATURE_V1,
            Self::FederationVerifyActorSignatureV1 => Self::FEDERATION_VERIFY_ACTOR_SIGNATURE_V1,
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
            Self::JoinedControlViewDigestV1 => Self::JOINED_CONTROL_VIEW_DIGEST_V1,
            Self::KeypackageClaimTerminalReceiptV1 => Self::KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1,
            Self::KeypackageConsumeReceiptV1 => Self::KEYPACKAGE_CONSUME_RECEIPT_V1,
            Self::MembershipCompensationSingleUseCasV1 => {
                Self::MEMBERSHIP_COMPENSATION_SINGLE_USE_CAS_V1
            }
            Self::MembershipCompensationTerminalCertificateV1 => {
                Self::MEMBERSHIP_COMPENSATION_TERMINAL_CERTIFICATE_V1
            }
            Self::MimiReporterAuthorityProofV1 => Self::MIMI_REPORTER_AUTHORITY_PROOF_V1,
            Self::MlsRecipientDurableReceiptV1 => Self::MLS_RECIPIENT_DURABLE_RECEIPT_V1,
            Self::PeerEventsCommandSubmitV1ServiceBindingV1 => {
                Self::PEER_EVENTS_COMMAND_SUBMIT_V1_SERVICE_BINDING_V1
            }
            Self::PeerContactControlReceiptV1 => Self::PEER_CONTACT_CONTROL_RECEIPT_V1,
            Self::PeerContactMirrorReceiptV1 => Self::PEER_CONTACT_MIRROR_RECEIPT_V1,
            Self::RealmOrganizationStatementV1 => Self::REALM_ORGANIZATION_STATEMENT_V1,
            Self::RealmStateSnapshotAuthStateIssuerLocalV1 => {
                Self::REALM_STATE_SNAPSHOT_AUTH_STATE_ISSUER_LOCAL_V1
            }
            Self::WebsocketAuthV1 => Self::WEBSOCKET_AUTH_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ACCOUNTABILITY_SCOPE_SET_V1 => Some(Self::AccountabilityScopeSetV1),
            Self::AGENT_AUTHORITY_STATE_EVIDENCE_V1 => Some(Self::AgentAuthorityStateEvidenceV1),
            Self::AGENT_SIGNER_ADMISSION_RECEIPT_V1 => Some(Self::AgentSignerAdmissionReceiptV1),
            Self::APPLET_DELIVERY_AUTHENTICATION_RECORD_DIGEST_V1 => {
                Some(Self::AppletDeliveryAuthenticationRecordDigestV1)
            }
            Self::APPLET_MANAGED_ACTOR_AUTHORING_REQUEST_PROOF_V1 => {
                Some(Self::AppletManagedActorAuthoringRequestProofV1)
            }
            Self::APPLET_MANAGED_ACTOR_BUNDLE_PROOF_V1 => {
                Some(Self::AppletManagedActorBundleProofV1)
            }
            Self::CONTACT_GLARE_UNCONSUMED_SLOT_V1 => Some(Self::ContactGlareUnconsumedSlotV1),
            Self::CONTACT_NO_OUTGOING_SLOT_V1 => Some(Self::ContactNoOutgoingSlotV1),
            Self::CONTACT_REQUEST_ACCEPTANCE_CORE_V1 => Some(Self::ContactRequestAcceptanceCoreV1),
            Self::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1 => {
                Some(Self::ContactRequestSourceCheckpointV1)
            }
            Self::CONTROLLER_ACCOUNT_GATE_V1 => Some(Self::ControllerAccountGateV1),
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
            Self::EVENTS_FRONTIER_LEAF_V1 => Some(Self::EventsFrontierLeafV1),
            Self::EVENTS_FRONTIER_NODE_V1 => Some(Self::EventsFrontierNodeV1),
            Self::EVENTS_FRONTIER_ROOT_V1 => Some(Self::EventsFrontierRootV1),
            Self::EVENTS_FRONTIER_SIGNATURE_V1 => Some(Self::EventsFrontierSignatureV1),
            Self::FEDERATION_VERIFY_ACTOR_SIGNATURE_V1 => {
                Some(Self::FederationVerifyActorSignatureV1)
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
            Self::JOINED_CONTROL_VIEW_DIGEST_V1 => Some(Self::JoinedControlViewDigestV1),
            Self::KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1 => {
                Some(Self::KeypackageClaimTerminalReceiptV1)
            }
            Self::KEYPACKAGE_CONSUME_RECEIPT_V1 => Some(Self::KeypackageConsumeReceiptV1),
            Self::MEMBERSHIP_COMPENSATION_SINGLE_USE_CAS_V1 => {
                Some(Self::MembershipCompensationSingleUseCasV1)
            }
            Self::MEMBERSHIP_COMPENSATION_TERMINAL_CERTIFICATE_V1 => {
                Some(Self::MembershipCompensationTerminalCertificateV1)
            }
            Self::MIMI_REPORTER_AUTHORITY_PROOF_V1 => Some(Self::MimiReporterAuthorityProofV1),
            Self::MLS_RECIPIENT_DURABLE_RECEIPT_V1 => Some(Self::MlsRecipientDurableReceiptV1),
            Self::PEER_EVENTS_COMMAND_SUBMIT_V1_SERVICE_BINDING_V1 => {
                Some(Self::PeerEventsCommandSubmitV1ServiceBindingV1)
            }
            Self::PEER_CONTACT_CONTROL_RECEIPT_V1 => Some(Self::PeerContactControlReceiptV1),
            Self::PEER_CONTACT_MIRROR_RECEIPT_V1 => Some(Self::PeerContactMirrorReceiptV1),
            Self::REALM_ORGANIZATION_STATEMENT_V1 => Some(Self::RealmOrganizationStatementV1),
            Self::REALM_STATE_SNAPSHOT_AUTH_STATE_ISSUER_LOCAL_V1 => {
                Some(Self::RealmStateSnapshotAuthStateIssuerLocalV1)
            }
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
        Self::ContentV1,
        Self::HistoryV1,
        Self::ReactionRoutingRootV1,
        Self::ReactionRoutingV1,
        Self::RtcFrameKeyV1,
        Self::RtcRecordingKeyV1,
        Self::RtcTranscriptKeyV1,
        Self::SignalRootV1,
        Self::SignalV1,
    ];

    pub const CONTENT_V1: &'static str = "ak.content-v1";
    pub const HISTORY_V1: &'static str = "ak.history-v1";
    pub const REACTION_ROUTING_ROOT_V1: &'static str = "ak.reaction-routing-root-v1";
    pub const REACTION_ROUTING_V1: &'static str = "ak.reaction-routing-v1";
    pub const RTC_FRAME_KEY_V1: &'static str = "ak.rtc-frame-key/v1";
    pub const RTC_RECORDING_KEY_V1: &'static str = "ak.rtc-recording-key/v1";
    pub const RTC_TRANSCRIPT_KEY_V1: &'static str = "ak.rtc-transcript-key/v1";
    pub const SIGNAL_ROOT_V1: &'static str = "ak.signal-root-v1";
    pub const SIGNAL_V1: &'static str = "ak.signal-v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContentV1 => Self::CONTENT_V1,
            Self::HistoryV1 => Self::HISTORY_V1,
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
            Self::CONTENT_V1 => Some(Self::ContentV1),
            Self::HISTORY_V1 => Some(Self::HistoryV1),
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
        id: ProofContextId::AuditReleaseAttestationProofV1,
        context: "ak.audit_release_attestation_proof.v1",
        object_family: "attestation_evidence",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "operator_id",
            "audit_actor_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/audit-release-attestation.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AuditRywReceiptProofV1,
        context: "ak.audit_ryw_receipt_proof.v1",
        object_family: "audit_ryw_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer_id",
            "realm_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/audit-ryw-receipt.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::AuthorizationLeaseProofV1,
        context: "ak.authorization_lease_proof.v1",
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
        id: ProofContextId::AvailabilityReceiptProofV1,
        context: "ak.availability_receipt_proof.v1",
        object_family: "availability_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "realm_id",
            "event_id",
            "bytes_digest",
            "holder_service_id",
            "retention_expires_at",
            "holder_signer_evidence_ref",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/availability-receipt.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::CollisionVariantRecordProofV1,
        context: "ak.collision_variant_record_proof.v1",
        object_family: "collision_variant_record",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/collision-variant-record.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::ControlProposalAuthorityAckProofV1,
        context: "ak.control_proposal_authority_ack_proof.v1",
        object_family: "control_proposal_authority_ack",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/control-proposal-decision.schema.json#/$defs/control_proposal_authority_ack",
    },
    ProofContextDescriptor {
        id: ProofContextId::ControlProposalDecisionProofV1,
        context: "ak.control_proposal_decision_proof.v1",
        object_family: "control_proposal_decision",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/control-proposal-decision.schema.json#/$defs/proposal_decision",
    },
    ProofContextDescriptor {
        id: ProofContextId::DeviceAuthorizeAcceptedDevicePossessionProofV1,
        context: "ak.device_authorize_accepted_device_possession_proof.v1",
        object_family: "device_authorize_accepted_device_possession",
        consumer_operation: None,
        binding_fields: &[
            "device_id",
            "device_public_key_did",
            "hpke_key",
            "algorithms",
            "device_key_algorithm",
            "authorization_binding_kind",
            "pairing_challenge_transcript_digest",
        ],
        schema_ref: "schemas/device-pairing.schema.json#/$defs/device_pairing_target_proof",
    },
    ProofContextDescriptor {
        id: ProofContextId::DeviceAuthorizePossessionProofV1,
        context: "ak.device_authorize_possession_proof.v1",
        object_family: "device_authorize_possession",
        consumer_operation: None,
        binding_fields: &[
            "account_id",
            "device_id",
            "device_public_key_did",
            "hpke_key",
            "algorithms",
            "device_key_algorithm",
            "authorized_by",
            "not_before",
            "expires_at",
            "scopes",
            "recovery_session_id",
            "authorization_binding_kind",
        ],
        schema_ref: "schemas/event-payload.schema.json#/$defs/device_authorize_payload",
    },
    ProofContextDescriptor {
        id: ProofContextId::DeviceAuthorizeRecoveryPossessionProofV1,
        context: "ak.device_authorize_recovery_possession_proof.v1",
        object_family: "device_authorize_recovery_possession",
        consumer_operation: None,
        binding_fields: &[
            "account_id",
            "device_id",
            "device_public_key_did",
            "hpke_key",
            "algorithms",
            "device_key_algorithm",
            "authorized_by",
            "not_before",
            "expires_at",
            "scopes",
            "recovery_session_id",
            "authorization_binding_kind",
        ],
        schema_ref: "schemas/event-payload.schema.json#/$defs/device_authorize_payload",
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
        id: ProofContextId::DeviceRevocationGateDecisionProofV1,
        context: "ak.device_revocation_gate_decision_proof.v1",
        object_family: "device_revocation_gate_decision_receipt",
        consumer_operation: None,
        binding_fields: &["payload_digest", "verification_method", "created_at"],
        schema_ref: "schemas/device-revocation-state.schema.json#/$defs/device_revocation_gate_decision_receipt",
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
        id: ProofContextId::DirectoryGovernanceRequestProofV1,
        context: "ak.directory_governance_request_proof.v1",
        object_family: "directory_governance_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "operation_id",
            "resource_id",
            "verification_method",
            "created_at",
            "proof_purpose",
            "audience_id",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/DirectoryGovernanceProof",
    },
    ProofContextDescriptor {
        id: ProofContextId::DirectorySourceRefAccessProofV1,
        context: "ak.directory_source_ref_access_proof.v1",
        object_family: "directory_source_ref_access",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "source_id",
            "directory_id",
            "realm_id",
            "discovery_event_id",
            "source_refs",
            "as_of",
            "expires_at",
            "verification_method",
            "created_at",
            "domain",
            "audience",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/DirectorySourceRefAccess",
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
            "signer_resolution_evidence_ref?",
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
        id: ProofContextId::HistoryKeyRequestProofV1,
        context: "ak.history_key_request_proof.v1",
        object_family: "history_key_request",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "request_id",
            "kind",
            "effective_scope",
            "requester_actor_id",
            "requester_sender_domain",
            "requester_author_profile",
            "requester_endpoint_authorization",
            "requester_authorization_incarnation",
            "requested_ranges",
            "recipient_hpke_public_key",
            "expires_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/history_key_request",
    },
    ProofContextDescriptor {
        id: ProofContextId::HistoryKeyRequestReceiptProofV1,
        context: "ak.history_key_request_receipt_proof.v1",
        object_family: "history_key_request_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "request_digest",
            "response_capability_commitment",
            "sealed_response_capability_digest",
            "effective_scope",
            "requester_sender_domain",
            "requester_authorization_incarnation",
            "release_id",
            "release_service_binding_ref",
            "release_service_resolution_ref",
            "release_service_resolution_digest",
            "release_service_route_digest",
            "history_traversal_retention",
            "accepted_at",
            "expires_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/history_key_request_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::HistoryKeyRequestReplicaProofV1,
        context: "ak.history_key_request_replica_proof.v1",
        object_family: "history_key_request_replica",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "kind",
            "request",
            "request_receipt",
            "destination_id",
            "destination_authorization",
            "replicated_at",
            "expires_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/history_key_request_replica",
    },
    ProofContextDescriptor {
        id: ProofContextId::HistoryKeyRequestReplicaReceiptProofV1,
        context: "ak.history_key_request_replica_receipt_proof.v1",
        object_family: "history_key_request_replica_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "request_digest",
            "destination_id",
            "accepted_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/history_key_request_replica_outcome",
    },
    ProofContextDescriptor {
        id: ProofContextId::HistoryKeyResponseLostRecordProofV1,
        context: "ak.history_key_response_lost_record_proof.v1",
        object_family: "history_key_response_lost_record",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "sequence",
            "cursor",
            "response_id",
            "record_digest",
            "lost_at",
            "release_service_signer_evidence_ref",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/history_key_response_lost_record",
    },
    ProofContextDescriptor {
        id: ProofContextId::HistoryKeyResponseProofV1,
        context: "ak.history_key_response_proof.v1",
        object_family: "history_key_response",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "response_id",
            "effective_scope",
            "source_actor_id",
            "source_sender_domain",
            "source_signer_evidence_ref",
            "request_digest",
            "request_receipt_digest",
            "expires_at",
            "content",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/history_key_response_send_request_body",
    },
    ProofContextDescriptor {
        id: ProofContextId::HistoryKeyResponseRecordProofV1,
        context: "ak.history_key_response_record_proof.v1",
        object_family: "history_key_response_record",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "sequence",
            "cursor",
            "record_digest",
            "source_record",
            "sent_at",
            "release_service_signer_evidence_ref",
            "manifest_admission?",
            "release_attestation?",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/history_key_response_record",
    },
    ProofContextDescriptor {
        id: ProofContextId::HistoryKeyResponseSendReceiptProofV1,
        context: "ak.history_key_response_send_receipt_proof.v1",
        object_family: "history_key_response_send_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "response_id",
            "source_record_digest",
            "record_digest",
            "sequence",
            "accepted_at",
            "manifest_admission_digest",
            "release_attestation_digest",
            "receipt_digest",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/history_key_response_send_receipt",
    },
    ProofContextDescriptor {
        id: ProofContextId::HistoryKeySourceRelayAttestationProofV1,
        context: "ak.history_key_source_relay_attestation_proof.v1",
        object_family: "history_key_source_relay_attestation",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "kind",
            "source_record_digest",
            "request_digest",
            "request_receipt_digest",
            "effective_scope",
            "source_actor_id",
            "source_sender_domain",
            "source_kind",
            "source_author_profile?",
            "source_authorization_incarnation?",
            "source_id",
            "source_authority_locator",
            "destination_release_id",
            "relayed_at",
            "expires_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/source_relay_attestation",
    },
    ProofContextDescriptor {
        id: ProofContextId::IdentityCreationControlProofV1,
        context: "ak.identity_creation_control_proof.v1",
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
            "audience_id",
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
        id: ProofContextId::IngressReceiptProofV1,
        context: "ak.ingress_receipt_proof.v1",
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
        id: ProofContextId::OrganizationRecoveryArchiveReplicaProofV1,
        context: "ak.organization_recovery_archive_replica_proof.v1",
        object_family: "organization_recovery_archive_replica",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "kind",
            "archive",
            "container_event_ref",
            "history_traversal_retention",
            "source_id",
            "holder_service_id",
            "replicated_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/organization_recovery_archive_replica",
    },
    ProofContextDescriptor {
        id: ProofContextId::OrganizationRecoveryArchiveReplicaReceiptProofV1,
        context: "ak.organization_recovery_archive_replica_receipt_proof.v1",
        object_family: "organization_recovery_archive_replica_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "archive_replica_digest",
            "holder_service_id",
            "archive_sequence",
            "accepted_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/history-key.schema.json#/$defs/organization_recovery_archive_replica_outcome",
    },
    ProofContextDescriptor {
        id: ProofContextId::OrganizationRecoveryKeyHolderAcceptanceProofV1,
        context: "ak.organization_recovery_key_holder_acceptance_proof.v1",
        object_family: "organization_recovery_key_holder_acceptance",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "realm_id",
            "new_key_tuple",
            "holder_trusted_basis",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/event-payload.schema.json#/$defs/organization_recovery_holder_acceptance",
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
        id: ProofContextId::PeerSealFrontierProofV1,
        context: "ak.peer_seal_frontier_proof.v1",
        object_family: "peer_seal_frontier",
        consumer_operation: None,
        binding_fields: &["frontier", "verification_method", "created_at"],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/PeerSealFrontierState/properties/service_proof",
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
        id: ProofContextId::RealmJoinCandidateProofV1,
        context: "ak.realm_join_candidate_proof.v1",
        object_family: "realm_join_candidate",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "realm_id",
            "service_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/realm-join-candidate.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::RealmStateSnapshotProofV1,
        context: "ak.realm_state_snapshot_proof.v1",
        object_family: "realm_state_snapshot",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "realm_state_snapshot_id",
            "realm_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/realm-state-snapshot.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::RealmStateSnapshotWitnessAttestationProofV1,
        context: "ak.realm_state_snapshot_witness_attestation_proof.v1",
        object_family: "realm_state_snapshot_witness_attestation",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "witness_id",
            "realm_state_snapshot_id",
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
            "realm_state_snapshot_created_at",
            "verification_method",
            "created_at",
        ],
        schema_ref: "schemas/realm-state-snapshot.schema.json#/$defs/realm_state_snapshot_witness_attestation",
    },
    ProofContextDescriptor {
        id: ProofContextId::ReceiptProofV1,
        context: "ak.receipt_proof.v1",
        object_family: "event_batch_receipt",
        consumer_operation: None,
        binding_fields: &[
            "payload_digest",
            "issuer_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/event-batch-receipt.schema.json",
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
        id: ProofContextId::SessionGrantPairwiseEndpointPossessionProofV1,
        context: "ak.session_grant_pairwise_endpoint_possession_proof.v1",
        object_family: "session_grant_pairwise_endpoint_possession",
        consumer_operation: None,
        binding_fields: &[
            "request_id",
            "account_id",
            "realm_id",
            "actor_id",
            "audience_id",
            "holder_jkt",
            "session_intent_digest",
            "issued_at",
            "expires_at",
            "verification_method",
        ],
        schema_ref: "schemas/service-operation-dtos.schema.json#/$defs/PairwiseEndpointPossessionProof",
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
        id: ProofContextId::StationAdmissionProofV1,
        context: "ak.station_admission_proof.v1",
        object_family: "station_event_admission",
        consumer_operation: None,
        binding_fields: &[
            "event_digest",
            "producer_proof_digest",
            "producer_verification_method",
            "producer_signing_key_did",
            "producer_signer_resolution_evidence_ref?",
            "signer_resolution_evidence_ref",
            "applet_installation_digest?",
            "accepted_at",
            "verification_method",
        ],
        schema_ref: "schemas/event-envelope.schema.json#/$defs/station_admission_proof",
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
        id: ExporterLabelId::ContentV1,
        label: "ak.content-v1",
        primitive: Some("ExpandWithLabel"),
        context_fields: &["sender_domain"],
        output_bytes: "AEAD.Nk",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.reaction-routing-v1", "ak.signal-v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::HistoryV1,
        label: "ak.history-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["effective_scope"],
        output_bytes: "KDF.Nh",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.reaction-routing-root-v1", "ak.signal-root-v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::ReactionRoutingRootV1,
        label: "ak.reaction-routing-root-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["effective_scope"],
        output_bytes: "KDF.Nh",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.history-v1", "ak.signal-root-v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::ReactionRoutingV1,
        label: "ak.reaction-routing-v1",
        primitive: Some("ExpandWithLabel"),
        context_fields: &["effective_scope", "target_ref", "routing_window"],
        output_bytes: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.content-v1", "ak.signal-v1"],
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
        forbid_reuse_with: &["ak.history-v1", "ak.reaction-routing-root-v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::SignalV1,
        label: "ak.signal-v1",
        primitive: Some("ExpandWithLabel"),
        context_fields: &["sender_domain"],
        output_bytes: "AEAD.Nk",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.content-v1", "ak.reaction-routing-v1"],
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

pub const MLS_EXTENSIONS: &[MlsExtensionDescriptor] = &[
    MlsExtensionDescriptor {
        name: "external_senders",
        codepoint: "0x0004",
        status: "unsupported",
        profile_id: None,
        rejection_error: Some("unsupported_feature"),
    },
    MlsExtensionDescriptor {
        name: "keypackage_capabilities",
        codepoint: "0xF1C1",
        status: "active",
        profile_id: Some("ak.profile.mls_governance_binding.full.v1"),
        rejection_error: None,
    },
    MlsExtensionDescriptor {
        name: "mls_governance_binding",
        codepoint: "0xF1C0",
        status: "active",
        profile_id: Some("ak.profile.mls_governance_binding.full.v1"),
        rejection_error: None,
    },
    MlsExtensionDescriptor {
        name: "required_capabilities",
        codepoint: "0x0003",
        status: "active",
        profile_id: Some("ak.profile.mls_governance_binding.full.v1"),
        rejection_error: None,
    },
    MlsExtensionDescriptor {
        name: "required_keypackage_capabilities",
        codepoint: "0xF1C2",
        status: "active",
        profile_id: Some("ak.profile.mls_governance_binding.full.v1"),
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
