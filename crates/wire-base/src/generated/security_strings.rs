//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/proof-context-registry.json; version=2026-07-16;
//! sha256=2dfe74804a47e3904c3e339472227b4524c60bd57992b41e6612af632dd071cc Input: registry/
//! exporter-label-registry.json; version=2026-06-10;
//! sha256=e119ced0d8bff290880df1e6ecaa31946d6a2a6ffc005d144e60db26a4a01ecd Input: registry/
//! digest-suite-registry.json; version=2026-06-10;
//! sha256=a2ec09df95e7115ea2feba454b121cb9095f21e42313422ac6d9b9c9cd5f7573 Input: registry/
//! signature-alg-registry.json; version=2026-07-13;
//! sha256=717b8de6fb0a51e0d1ab8c9e12ebfbd4c8418be1b86bc52a000429076d299e41 Input: registry/
//! hpke-suite-registry.json; version=2026-07-13;
//! sha256=bbb4b335c9d8e33b7c3b378932dedaa7aff019c5dec21225576632d88374a5d2 Input: registry/
//! mls-ciphersuite-registry.json; version=2026-07-13;
//! sha256=25cd19e74d91c18a3c1f837c04c8f3d7ad165e52f87421d85c5e778ef8f8a588 Input: registry/
//! mls-extension-registry.json; version=2026-06-03;
//! sha256=0fbcc85e00b58715c360aa0ed37acf11d858fd6b1a7d0ceb9b0c82bda99f1614
//! Entries: proof_contexts=24, exporter_labels=8, digest_suites=3, signature_algorithms=3,
//! hpke_suites=4, mls_ciphersuites=2, mls_extensions=1

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofContextDescriptor {
    pub context: &'static str,
    pub object_family: &'static str,
    pub binding_fields: &'static [&'static str],
    pub schema_ref: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExporterLabelDescriptor {
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
        label: "ak.rtc-frame-key/v1",
        primitive: None,
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
        label: "ak.rtc-recording-key/v1",
        primitive: None,
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
        label: "ak.rtc-transcript-key/v1",
        primitive: None,
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
        label: "arkret-aead-sender-nonce-prefix-v1",
        primitive: None,
        context_fields: &["key_ref", "epoch", "device_id", "purpose", "aead_profile"],
        output_length: "N_AEAD - 8 (16 for XChaCha20-Poly1305, 4 for AES-GCM)",
        empty_context_forbidden: true,
        forbid_reuse_with: &[],
    },
    ExporterLabelDescriptor {
        label: "arkret-mention-routing-v1",
        primitive: None,
        context_fields: &["realm_id"],
        output_length: "32",
        empty_context_forbidden: true,
        forbid_reuse_with: &["arkret-reaction-routing-v1"],
    },
    ExporterLabelDescriptor {
        label: "arkret-reaction-routing-v1",
        primitive: None,
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
    PROOF_CONTEXTS.iter().find(|row| row.context == value)
}

pub fn exporter_label(value: &str) -> Option<&'static ExporterLabelDescriptor> {
    EXPORTER_LABELS.iter().find(|row| row.label == value)
}
