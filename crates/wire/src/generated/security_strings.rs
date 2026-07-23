//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/proof-context-registry.json; version=2026-07-16;
//! sha256=2dfe74804a47e3904c3e339472227b4524c60bd57992b41e6612af632dd071cc Input: registry/
//! exporter-label-registry.json; version=2026-06-10;
//! sha256=7d67b5d14ab81711347af19f9f1759d9ee35dd1f15d96c92ed02fd6b27847d76 Input: registry/
//! digest-suite-registry.json; version=2026-06-10;
//! sha256=a2ec09df95e7115ea2feba454b121cb9095f21e42313422ac6d9b9c9cd5f7573 Input: registry/
//! signature-alg-registry.json; version=2026-07-13;
//! sha256=5ccd1caf0e223f267b782a5d8bd61310597031f76f71cc49d60eea261b73061f Input: registry/
//! hpke-suite-registry.json; version=2026-07-13;
//! sha256=bbb4b335c9d8e33b7c3b378932dedaa7aff019c5dec21225576632d88374a5d2 Input: registry/
//! mls-ciphersuite-registry.json; version=2026-07-13;
//! sha256=0fa9193fba7c2b4d1f7e36cc92c669f3dca251272897ac20cdbc70d5d160613b Input: registry/
//! mls-extension-registry.json; version=2026-06-03;
//! sha256=0fbcc85e00b58715c360aa0ed37acf11d858fd6b1a7d0ceb9b0c82bda99f1614
//! Entries: proof_contexts=24, exporter_labels=8, digest_suites=3, signature_algorithms=4,
//! hpke_suites=4, mls_ciphersuites=3, mls_extensions=1

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ProofContextId {
    AccountHandoffAuthenticationProofV1,
    AccountabilityGrantProofV1,
    AgentRequestedScopeDisclosureProofV1,
    AgentSelectorClaimProofV1,
    AppletPackageProofV1,
    AttestationEvidenceProofV1,
    AuditRywReceiptProofV1,
    CapabilityGrantProofV1,
    DidContinuityProofV1,
    DidKeyLogEntryProofV1,
    DirectoryOperationProofV1,
    EphemeralProofV1,
    EventProofV1,
    HandleClaimProofV1,
    IdentityCreationControlProofV1,
    IdentityReceiptProofV1,
    MemberDeliveryBindingCandidateProofV1,
    MimiOperationProofV1,
    PrincipalLocatorProofV1,
    RangeCompletenessAttestationProofV1,
    RealmJoinCandidateProofV1,
    ReceiptProofV1,
    ServiceRegistrationReceiptProofV1,
    SnapshotProofV1,
}

impl ProofContextId {
    pub const ALL: &'static [Self] = &[
        Self::AccountHandoffAuthenticationProofV1,
        Self::AccountabilityGrantProofV1,
        Self::AgentRequestedScopeDisclosureProofV1,
        Self::AgentSelectorClaimProofV1,
        Self::AppletPackageProofV1,
        Self::AttestationEvidenceProofV1,
        Self::AuditRywReceiptProofV1,
        Self::CapabilityGrantProofV1,
        Self::DidContinuityProofV1,
        Self::DidKeyLogEntryProofV1,
        Self::DirectoryOperationProofV1,
        Self::EphemeralProofV1,
        Self::EventProofV1,
        Self::HandleClaimProofV1,
        Self::IdentityCreationControlProofV1,
        Self::IdentityReceiptProofV1,
        Self::MemberDeliveryBindingCandidateProofV1,
        Self::MimiOperationProofV1,
        Self::PrincipalLocatorProofV1,
        Self::RangeCompletenessAttestationProofV1,
        Self::RealmJoinCandidateProofV1,
        Self::ReceiptProofV1,
        Self::ServiceRegistrationReceiptProofV1,
        Self::SnapshotProofV1,
    ];

    pub const ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_V1: &'static str =
        "ak.account-handoff-authentication-proof-v1";
    pub const ACCOUNTABILITY_GRANT_PROOF_V1: &'static str = "ak.accountability-grant-proof-v1";
    pub const AGENT_REQUESTED_SCOPE_DISCLOSURE_PROOF_V1: &'static str =
        "ak.agent-requested-scope-disclosure-proof-v1";
    pub const AGENT_SELECTOR_CLAIM_PROOF_V1: &'static str = "ak.agent-selector-claim-proof-v1";
    pub const APPLET_PACKAGE_PROOF_V1: &'static str = "ak.applet-package-proof-v1";
    pub const ATTESTATION_EVIDENCE_PROOF_V1: &'static str = "ak.attestation-evidence-proof-v1";
    pub const AUDIT_RYW_RECEIPT_PROOF_V1: &'static str = "ak.audit-ryw-receipt-proof-v1";
    pub const CAPABILITY_GRANT_PROOF_V1: &'static str = "ak.capability-grant-proof-v1";
    pub const DID_CONTINUITY_PROOF_V1: &'static str = "ak.did-continuity-proof-v1";
    pub const DID_KEY_LOG_ENTRY_PROOF_V1: &'static str = "ak.did-key-log-entry-proof-v1";
    pub const DIRECTORY_OPERATION_PROOF_V1: &'static str = "ak.directory-operation-proof-v1";
    pub const EPHEMERAL_PROOF_V1: &'static str = "ak.ephemeral-proof-v1";
    pub const EVENT_PROOF_V1: &'static str = "ak.event-proof-v1";
    pub const HANDLE_CLAIM_PROOF_V1: &'static str = "ak.handle-claim-proof-v1";
    pub const IDENTITY_CREATION_CONTROL_PROOF_V1: &'static str =
        "ak.identity-creation-control-proof-v1";
    pub const IDENTITY_RECEIPT_PROOF_V1: &'static str = "ak.identity-receipt-proof-v1";
    pub const MEMBER_DELIVERY_BINDING_CANDIDATE_PROOF_V1: &'static str =
        "ak.member-delivery-binding-candidate-proof-v1";
    pub const MIMI_OPERATION_PROOF_V1: &'static str = "ak.mimi-operation-proof-v1";
    pub const PRINCIPAL_LOCATOR_PROOF_V1: &'static str = "ak.principal-locator-proof-v1";
    pub const RANGE_COMPLETENESS_ATTESTATION_PROOF_V1: &'static str =
        "ak.range-completeness-attestation-proof-v1";
    pub const REALM_JOIN_CANDIDATE_PROOF_V1: &'static str = "ak.realm-join-candidate-proof-v1";
    pub const RECEIPT_PROOF_V1: &'static str = "ak.receipt-proof-v1";
    pub const SERVICE_REGISTRATION_RECEIPT_PROOF_V1: &'static str =
        "ak.service-registration-receipt-proof-v1";
    pub const SNAPSHOT_PROOF_V1: &'static str = "ak.snapshot-proof-v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountHandoffAuthenticationProofV1 => {
                "ak.account-handoff-authentication-proof-v1"
            }
            Self::AccountabilityGrantProofV1 => "ak.accountability-grant-proof-v1",
            Self::AgentRequestedScopeDisclosureProofV1 => {
                "ak.agent-requested-scope-disclosure-proof-v1"
            }
            Self::AgentSelectorClaimProofV1 => "ak.agent-selector-claim-proof-v1",
            Self::AppletPackageProofV1 => "ak.applet-package-proof-v1",
            Self::AttestationEvidenceProofV1 => "ak.attestation-evidence-proof-v1",
            Self::AuditRywReceiptProofV1 => "ak.audit-ryw-receipt-proof-v1",
            Self::CapabilityGrantProofV1 => "ak.capability-grant-proof-v1",
            Self::DidContinuityProofV1 => "ak.did-continuity-proof-v1",
            Self::DidKeyLogEntryProofV1 => "ak.did-key-log-entry-proof-v1",
            Self::DirectoryOperationProofV1 => "ak.directory-operation-proof-v1",
            Self::EphemeralProofV1 => "ak.ephemeral-proof-v1",
            Self::EventProofV1 => "ak.event-proof-v1",
            Self::HandleClaimProofV1 => "ak.handle-claim-proof-v1",
            Self::IdentityCreationControlProofV1 => "ak.identity-creation-control-proof-v1",
            Self::IdentityReceiptProofV1 => "ak.identity-receipt-proof-v1",
            Self::MemberDeliveryBindingCandidateProofV1 => {
                "ak.member-delivery-binding-candidate-proof-v1"
            }
            Self::MimiOperationProofV1 => "ak.mimi-operation-proof-v1",
            Self::PrincipalLocatorProofV1 => "ak.principal-locator-proof-v1",
            Self::RangeCompletenessAttestationProofV1 => {
                "ak.range-completeness-attestation-proof-v1"
            }
            Self::RealmJoinCandidateProofV1 => "ak.realm-join-candidate-proof-v1",
            Self::ReceiptProofV1 => "ak.receipt-proof-v1",
            Self::ServiceRegistrationReceiptProofV1 => "ak.service-registration-receipt-proof-v1",
            Self::SnapshotProofV1 => "ak.snapshot-proof-v1",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "ak.account-handoff-authentication-proof-v1" => {
                Some(Self::AccountHandoffAuthenticationProofV1)
            }
            "ak.accountability-grant-proof-v1" => Some(Self::AccountabilityGrantProofV1),
            "ak.agent-requested-scope-disclosure-proof-v1" => {
                Some(Self::AgentRequestedScopeDisclosureProofV1)
            }
            "ak.agent-selector-claim-proof-v1" => Some(Self::AgentSelectorClaimProofV1),
            "ak.applet-package-proof-v1" => Some(Self::AppletPackageProofV1),
            "ak.attestation-evidence-proof-v1" => Some(Self::AttestationEvidenceProofV1),
            "ak.audit-ryw-receipt-proof-v1" => Some(Self::AuditRywReceiptProofV1),
            "ak.capability-grant-proof-v1" => Some(Self::CapabilityGrantProofV1),
            "ak.did-continuity-proof-v1" => Some(Self::DidContinuityProofV1),
            "ak.did-key-log-entry-proof-v1" => Some(Self::DidKeyLogEntryProofV1),
            "ak.directory-operation-proof-v1" => Some(Self::DirectoryOperationProofV1),
            "ak.ephemeral-proof-v1" => Some(Self::EphemeralProofV1),
            "ak.event-proof-v1" => Some(Self::EventProofV1),
            "ak.handle-claim-proof-v1" => Some(Self::HandleClaimProofV1),
            "ak.identity-creation-control-proof-v1" => Some(Self::IdentityCreationControlProofV1),
            "ak.identity-receipt-proof-v1" => Some(Self::IdentityReceiptProofV1),
            "ak.member-delivery-binding-candidate-proof-v1" => {
                Some(Self::MemberDeliveryBindingCandidateProofV1)
            }
            "ak.mimi-operation-proof-v1" => Some(Self::MimiOperationProofV1),
            "ak.principal-locator-proof-v1" => Some(Self::PrincipalLocatorProofV1),
            "ak.range-completeness-attestation-proof-v1" => {
                Some(Self::RangeCompletenessAttestationProofV1)
            }
            "ak.realm-join-candidate-proof-v1" => Some(Self::RealmJoinCandidateProofV1),
            "ak.receipt-proof-v1" => Some(Self::ReceiptProofV1),
            "ak.service-registration-receipt-proof-v1" => {
                Some(Self::ServiceRegistrationReceiptProofV1)
            }
            "ak.snapshot-proof-v1" => Some(Self::SnapshotProofV1),
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
        Self::AeadSenderNoncePrefixV1,
        Self::MentionRoutingV1,
        Self::ReactionRoutingV1,
    ];

    pub const CONTENT_V1: &'static str = "ak.content-v1";
    pub const HISTORY_V1: &'static str = "ak.history-v1";
    pub const RTC_FRAME_KEY_V1: &'static str = "ak.rtc-frame-key/v1";
    pub const RTC_RECORDING_KEY_V1: &'static str = "ak.rtc-recording-key/v1";
    pub const RTC_TRANSCRIPT_KEY_V1: &'static str = "ak.rtc-transcript-key/v1";
    pub const AEAD_SENDER_NONCE_PREFIX_V1: &'static str = "arkret-aead-sender-nonce-prefix-v1";
    pub const MENTION_ROUTING_V1: &'static str = "arkret-mention-routing-v1";
    pub const REACTION_ROUTING_V1: &'static str = "arkret-reaction-routing-v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContentV1 => "ak.content-v1",
            Self::HistoryV1 => "ak.history-v1",
            Self::RtcFrameKeyV1 => "ak.rtc-frame-key/v1",
            Self::RtcRecordingKeyV1 => "ak.rtc-recording-key/v1",
            Self::RtcTranscriptKeyV1 => "ak.rtc-transcript-key/v1",
            Self::AeadSenderNoncePrefixV1 => "arkret-aead-sender-nonce-prefix-v1",
            Self::MentionRoutingV1 => "arkret-mention-routing-v1",
            Self::ReactionRoutingV1 => "arkret-reaction-routing-v1",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "ak.content-v1" => Some(Self::ContentV1),
            "ak.history-v1" => Some(Self::HistoryV1),
            "ak.rtc-frame-key/v1" => Some(Self::RtcFrameKeyV1),
            "ak.rtc-recording-key/v1" => Some(Self::RtcRecordingKeyV1),
            "ak.rtc-transcript-key/v1" => Some(Self::RtcTranscriptKeyV1),
            "arkret-aead-sender-nonce-prefix-v1" => Some(Self::AeadSenderNoncePrefixV1),
            "arkret-mention-routing-v1" => Some(Self::MentionRoutingV1),
            "arkret-reaction-routing-v1" => Some(Self::ReactionRoutingV1),
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
    pub output_length: &'static str,
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
        id: ProofContextId::AttestationEvidenceProofV1,
        context: "ak.attestation-evidence-proof-v1",
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
        schema_ref: "schemas/attestation-evidence.schema.json",
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
        id: ProofContextId::CapabilityGrantProofV1,
        context: "ak.capability-grant-proof-v1",
        object_family: "capability_grant",
        binding_fields: &[
            "payload_digest",
            "issuer",
            "subject",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/capability-grant.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::DidContinuityProofV1,
        context: "ak.did-continuity-proof-v1",
        object_family: "did_continuity",
        binding_fields: &[
            "payload_digest",
            "old_did",
            "new_did",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/did-continuity-proof.schema.json",
    },
    ProofContextDescriptor {
        id: ProofContextId::DidKeyLogEntryProofV1,
        context: "ak.did-key-log-entry-proof-v1",
        object_family: "did_key_log_entry",
        binding_fields: &[
            "payload_digest",
            "did",
            "seq",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/did-key-log-entry.schema.json",
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
        id: ProofContextId::EphemeralProofV1,
        context: "ak.ephemeral-proof-v1",
        object_family: "ephemeral_envelope",
        binding_fields: &[
            "payload_digest",
            "actor_id",
            "device_id",
            "verification_method",
            "created_at",
            "domain?",
            "audience?",
        ],
        schema_ref: "schemas/ephemeral-envelope.schema.json",
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
            "payload_digest",
            "principal_id",
            "verification_method",
            "created_at",
            "audience",
        ],
        schema_ref: "schemas/account-operations.schema.json",
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
        output_length: "AEAD.Nk for the active MLS ciphersuite",
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
        output_length: "KDF.Nh for the active MLS ciphersuite",
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
        output_length: "32",
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
        output_length: "32",
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
        output_length: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["ak.rtc-frame-key/v1", "ak.rtc-recording-key/v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::AeadSenderNoncePrefixV1,
        label: "arkret-aead-sender-nonce-prefix-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["key_ref", "epoch", "device_id", "purpose", "aead_profile"],
        output_length: "N_AEAD - 8 (16 for XChaCha20-Poly1305, 4 for AES-GCM)",
        empty_context_forbidden: true,
        forbid_reuse_with: &[],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::MentionRoutingV1,
        label: "arkret-mention-routing-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["realm_id"],
        output_length: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["arkret-reaction-routing-v1"],
    },
    ExporterLabelDescriptor {
        id: ExporterLabelId::ReactionRoutingV1,
        label: "arkret-reaction-routing-v1",
        primitive: Some("MLS-Exporter"),
        context_fields: &["realm_id"],
        output_length: "32",
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
