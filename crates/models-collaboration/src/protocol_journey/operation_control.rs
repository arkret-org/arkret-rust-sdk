use std::collections::BTreeSet;

use arkret_models_crypto::{
    KeyPackageClaimTerminalReceipt, KeyPackageConsumeReceipt, PeerKeyPackageClaimReceipt,
    PeerKeyPackagesClaimAuthorizationDraft, PeerKeyPackagesClaimRequestBody,
};
use arkret_wire::{
    Base64UrlString, DeviceId, Did, DidUrl, Event, EventId, Hash, RealmId, StrandId,
    TypedTrustDomainId,
};
pub use arkret_wire::{
    MembershipCompensationAction, MembershipCompensationCasToken,
    MembershipCompensationDelegationCore, MembershipCompensationDelegationRef,
    MembershipCompensationExecutorDelegation, MembershipCompensationSubmissionEvidence,
    MembershipCompensationTerminalCertificate, MembershipJoinAcceptedProof,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{ContactPeer, ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature, string_marker};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<String>)))]
pub struct NonEmptyDigestList(Vec<Hash>);

impl NonEmptyDigestList {
    pub fn new(values: Vec<Hash>) -> arkret_wire::Result<Self> {
        if values.is_empty() {
            return Err(arkret_wire::Error::Protocol(
                "digest list must not be empty".to_owned(),
            ));
        }
        Ok(Self(values))
    }
    pub fn as_slice(&self) -> &[Hash] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NonEmptyDigestList {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = Vec::<Hash>::deserialize(deserializer)?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AttemptCleanupFailedStage {
    KeypackageClaim,
    FoundingUnit,
    MainStrand,
    MlsEpoch,
    WelcomeAdmission,
    BindingFinalize,
}

string_marker!(
    PeerKeyPackagesClaimOperationId,
    V1,
    "ak.peer.keys.keypackages.command.claim"
);
string_marker!(
    PeerEventsSubmitOperationId,
    V1,
    "ak.peer.events.command.submit"
);
string_marker!(
    PeerKeyPackagesClaimRequestSchemaRef,
    V1,
    "schemas/keypackage-operations.schema.json#/$defs/peer_key_packages_claim_request_body"
);
string_marker!(
    EventsSubmitFederationRequestSchemaRef,
    V1,
    "schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitFederationRequestBody"
);

macro_rules! fixed_event_kinds {
    ($name:ident, [$($wire:literal),+ $(,)?]) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        pub struct $name;

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                [$($wire),+].serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let actual = Vec::<String>::deserialize(deserializer)?;
                let expected = vec![$($wire.to_owned()),+];
                if actual != expected {
                    return Err(serde::de::Error::custom(format!(
                        "event kinds must be exactly {:?}", expected
                    )));
                }
                Ok(Self)
            }
        }
    };
}

fixed_event_kinds!(
    FoundingUnitEventKinds,
    ["ak.realm.create", "ak.member.state"]
);
fixed_event_kinds!(MainStrandEventKinds, ["ak.strand.create"]);
fixed_event_kinds!(MlsEpochEventKinds, ["ak.mls.genesis", "ak.mls.commit"]);
fixed_event_kinds!(WelcomeAdmissionEventKinds, ["ak.mls.welcome"]);
fixed_event_kinds!(BindingFinalizeEventKinds, ["ak.direct_conversation.bound"]);
fixed_event_kinds!(MembershipCompensationEventKinds, ["ak.member.state"]);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "materialization_step",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum OrdinaryExternalEffect {
    KeypackageClaim {
        target_operation_id: PeerKeyPackagesClaimOperationId,
        request_schema_ref: PeerKeyPackagesClaimRequestSchemaRef,
        request_digest: Hash,
        authorization_digest: Hash,
    },
    FoundingUnit {
        target_operation_id: PeerEventsSubmitOperationId,
        request_schema_ref: EventsSubmitFederationRequestSchemaRef,
        request_digest: Hash,
        authorization_digest: Hash,
        admitted_event_kinds: FoundingUnitEventKinds,
        claim_receipt_digest: Hash,
    },
    MainStrand {
        target_operation_id: PeerEventsSubmitOperationId,
        request_schema_ref: EventsSubmitFederationRequestSchemaRef,
        request_digest: Hash,
        authorization_digest: Hash,
        admitted_event_kinds: MainStrandEventKinds,
        founding_effect_commitment_digest: Hash,
        founding_delivery_receipt_digest: Hash,
    },
    MlsEpoch {
        target_operation_id: PeerEventsSubmitOperationId,
        request_schema_ref: EventsSubmitFederationRequestSchemaRef,
        request_digest: Hash,
        authorization_digest: Hash,
        admitted_event_kinds: MlsEpochEventKinds,
        strand_effect_commitment_digest: Hash,
        strand_delivery_receipt_digest: Hash,
        claim_receipt_digest: Hash,
    },
    WelcomeAdmission {
        target_operation_id: PeerEventsSubmitOperationId,
        request_schema_ref: EventsSubmitFederationRequestSchemaRef,
        request_digest: Hash,
        authorization_digest: Hash,
        admitted_event_kinds: WelcomeAdmissionEventKinds,
        claim_receipt_digest: Hash,
        mls_effect_commitment_digest: Hash,
        mls_delivery_receipt_digest: Hash,
    },
    BindingFinalize {
        target_operation_id: PeerEventsSubmitOperationId,
        request_schema_ref: EventsSubmitFederationRequestSchemaRef,
        request_digest: Hash,
        authorization_digest: Hash,
        admitted_event_kinds: BindingFinalizeEventKinds,
        welcome_effect_commitment_digest: Hash,
        welcome_delivery_receipt_digest: Hash,
        recipient_durable_receipt_digest: Hash,
        consume_receipt_digest: Hash,
    },
    MembershipCompensation {
        target_operation_id: PeerEventsSubmitOperationId,
        request_schema_ref: EventsSubmitFederationRequestSchemaRef,
        request_digest: Hash,
        authorization_digest: Hash,
        admitted_event_kinds: MembershipCompensationEventKinds,
        founding_effect_commitment_digest: Hash,
        founding_delivery_receipt_digest: Hash,
        compensation_evidence_digest: Hash,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AttemptCleanupValue {
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub failed_stage: AttemptCleanupFailedStage,
    pub cleanup_manifest_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AttemptAdvanceValue {
    pub operation_id: ProtocolOperationId,
    pub from_attempt: u64,
    pub to_attempt: u64,
    pub cleanup_effect_commitment_digest: Hash,
    pub cleanup_effect_head_digest: Hash,
    pub fresh_target_authorization_digest: Hash,
    pub claim_request_digest: Hash,
}

impl AttemptAdvanceValue {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.from_attempt == 0 || self.from_attempt.checked_add(1) != Some(self.to_attempt) {
            return Err(arkret_wire::Error::Protocol(
                "attempt advance must increment exactly once".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HostTransferPrepareValue {
    pub transfer_id: ProtocolOpaqueId,
    pub from_host_service_id: Did,
    pub from_host_epoch: u64,
    pub to_host_service_id: Did,
    pub to_host_epoch: u64,
    pub manifest_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HostTransferValue {
    pub transfer_id: ProtocolOpaqueId,
    pub from_host_service_id: Did,
    pub from_host_epoch: u64,
    pub to_host_service_id: Did,
    pub to_host_epoch: u64,
    pub manifest_digest: Hash,
    pub prepare_effect_commitment_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "effect_kind",
    content = "effect_details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum OperationControlEffect {
    OrdinaryExternal(OrdinaryExternalEffect),
    AttemptCleanup(AttemptCleanupValue),
    AttemptAdvance(AttemptAdvanceValue),
    HostTransferPrepare(HostTransferPrepareValue),
    HostTransfer(HostTransferValue),
}

impl OperationControlEffect {
    pub fn semantic_digest(&self) -> arkret_wire::Result<Hash> {
        domain_hash("ak.direct-conversation.effect.v1", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct EffectValueCore {
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub effect_id: ProtocolOpaqueId,
    pub effect: OperationControlEffect,
    pub effect_digest: Hash,
    pub payload_digest: Hash,
    pub destination: Did,
    pub expected_host_service_id: Did,
    pub expected_host_epoch: u64,
    pub resulting_host_service_id: Did,
    pub resulting_host_epoch: u64,
    pub predecessor_head_digest: Hash,
    pub journal_root: Hash,
    pub journal_validation_receipt_digest: Hash,
}

impl EffectValueCore {
    pub fn value_digest(&self) -> arkret_wire::Result<Hash> {
        domain_hash("ak.direct-conversation.value.v1", self)
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.effect.semantic_digest()? != self.effect_digest {
            return Err(arkret_wire::Error::Protocol(
                "effect_digest does not match the exact operation-control effect".to_owned(),
            ));
        }
        let host_unchanged = self.expected_host_service_id == self.resulting_host_service_id
            && self.expected_host_epoch == self.resulting_host_epoch;
        let shape_is_valid = match &self.effect {
            OperationControlEffect::OrdinaryExternal(_) => host_unchanged,
            OperationControlEffect::AttemptCleanup(cleanup) => {
                cleanup.operation_id == self.operation_id
                    && cleanup.attempt_sequence == self.attempt_sequence
                    && host_unchanged
                    && self.destination == self.expected_host_service_id
            }
            OperationControlEffect::AttemptAdvance(advance) => {
                advance.validate()?;
                advance.operation_id == self.operation_id
                    && advance.from_attempt == self.attempt_sequence
                    && advance.cleanup_effect_head_digest == self.predecessor_head_digest
                    && host_unchanged
                    && self.destination == self.expected_host_service_id
            }
            OperationControlEffect::HostTransferPrepare(transfer) => {
                transfer.from_host_epoch.checked_add(1) == Some(transfer.to_host_epoch)
                    && self.expected_host_service_id == transfer.from_host_service_id
                    && self.expected_host_epoch == transfer.from_host_epoch
                    && self.resulting_host_service_id == transfer.from_host_service_id
                    && self.resulting_host_epoch == transfer.from_host_epoch
                    && self.destination == transfer.to_host_service_id
            }
            OperationControlEffect::HostTransfer(transfer) => {
                transfer.from_host_epoch.checked_add(1) == Some(transfer.to_host_epoch)
                    && self.expected_host_service_id == transfer.from_host_service_id
                    && self.expected_host_epoch == transfer.from_host_epoch
                    && self.resulting_host_service_id == transfer.to_host_service_id
                    && self.resulting_host_epoch == transfer.to_host_epoch
                    && self.destination == transfer.to_host_service_id
            }
        };
        if !shape_is_valid {
            return Err(arkret_wire::Error::Protocol(
                "operation-control effect details do not match outer value coordinates".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn journal_validation_core(&self) -> JournalValidationCore {
        JournalValidationCore {
            registry_digest: self.registry_digest.clone(),
            pair_registry_id: self.pair_registry_id.clone(),
            pair_key: self.pair_key.clone(),
            operation_id: self.operation_id.clone(),
            attempt_sequence: self.attempt_sequence,
            effect_id: self.effect_id.clone(),
            effect: self.effect.clone(),
            effect_digest: self.effect_digest.clone(),
            payload_digest: self.payload_digest.clone(),
            destination: self.destination.clone(),
            expected_host_service_id: self.expected_host_service_id.clone(),
            expected_host_epoch: self.expected_host_epoch,
            resulting_host_service_id: self.resulting_host_service_id.clone(),
            resulting_host_epoch: self.resulting_host_epoch,
            predecessor_head_digest: self.predecessor_head_digest.clone(),
            journal_root: self.journal_root.clone(),
        }
    }
}

string_marker!(
    AuthenticatedEncryptedJournalDomain,
    V1,
    "ak.direct-conversation.authenticated-journal.v1"
);
string_marker!(
    AuthenticatedEncryptedJournalScheme,
    V1,
    "ak.hpke_x25519_aead_chacha20poly1305.v1"
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum JournalPlaintextSchemaRef {
    #[serde(
        rename = "schemas/keypackage-operations.schema.json#/$defs/peer_key_packages_claim_request_body"
    )]
    PeerKeyPackagesClaimRequest,
    #[serde(
        rename = "schemas/protocol-journey-wire.schema.json#/$defs/direct_conversation_event_admission_journal"
    )]
    DirectConversationEventAdmission,
    #[serde(
        rename = "schemas/protocol-journey-wire.schema.json#/$defs/direct_conversation_compensation_journal"
    )]
    DirectConversationCompensation,
    #[serde(
        rename = "schemas/protocol-journey-wire.schema.json#/$defs/attempt_cleanup_journal_plaintext"
    )]
    AttemptCleanup,
    #[serde(
        rename = "schemas/protocol-journey-wire.schema.json#/$defs/attempt_advance_journal_plaintext"
    )]
    AttemptAdvance,
    #[serde(
        rename = "schemas/protocol-journey-wire.schema.json#/$defs/host_transfer_prepare_journal_plaintext"
    )]
    HostTransferPrepare,
    #[serde(
        rename = "schemas/protocol-journey-wire.schema.json#/$defs/host_transfer_finalize_journal_plaintext"
    )]
    HostTransferFinalize,
}

string_marker!(
    OperationControlJournalAadDomain,
    V1,
    "ak.direct-conversation.authenticated-journal-aad.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlJournalAadCore {
    pub domain: OperationControlJournalAadDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub effect_id: ProtocolOpaqueId,
    pub effect_digest: Hash,
    pub payload_digest: Hash,
    pub destination: Did,
    pub expected_host_service_id: Did,
    pub expected_host_epoch: u64,
    pub resulting_host_service_id: Did,
    pub resulting_host_epoch: u64,
    pub predecessor_head_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AuthenticatedEncryptedJournal {
    pub domain: AuthenticatedEncryptedJournalDomain,
    pub scheme: AuthenticatedEncryptedJournalScheme,
    pub recipient_service_id: Did,
    pub recipient_key_ref: DidUrl,
    pub enc: Base64UrlString,
    pub plaintext_schema_ref: JournalPlaintextSchemaRef,
    pub plaintext_digest: Hash,
    pub aad_core: OperationControlJournalAadCore,
    pub aad_digest: Hash,
    pub ciphertext: Base64UrlString,
}

string_marker!(
    JournalValidationReceiptDomain,
    V1,
    "ak.direct-conversation.journal-validation-receipt.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct JournalValidationReceipt {
    pub domain: JournalValidationReceiptDomain,
    pub validation_request_id: ProtocolOpaqueId,
    pub validation_core_digest: Hash,
    pub journal_root: Hash,
    pub effect_digest: Hash,
    pub payload_digest: Hash,
    pub destination: Did,
    pub recipient_key_ref: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub validated_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct JournalValidationCore {
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub effect_id: ProtocolOpaqueId,
    pub effect: OperationControlEffect,
    pub effect_digest: Hash,
    pub payload_digest: Hash,
    pub destination: Did,
    pub expected_host_service_id: Did,
    pub expected_host_epoch: u64,
    pub resulting_host_service_id: Did,
    pub resulting_host_epoch: u64,
    pub predecessor_head_digest: Hash,
    pub journal_root: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct JournalValidationRequest {
    pub validation_request_id: ProtocolOpaqueId,
    pub registry_authorization: OperationControlAuthorization,
    pub validation_core: JournalValidationCore,
    pub authenticated_encrypted_journal: AuthenticatedEncryptedJournal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum JournalValidationOutcome {
    Accepted { receipt: JournalValidationReceipt },
    Duplicate { receipt: JournalValidationReceipt },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ExecutionBundleDeliveryRequest {
    pub registry_digest: Hash,
    pub submitted_bundle_digest: Hash,
    pub effect_commitment_digest: Hash,
    pub bundle: ExecutionBundle,
}

string_marker!(
    AttemptCleanupManifestDomain,
    V1,
    "ak.direct-conversation.attempt-cleanup-manifest.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AttemptCleanupManifest {
    pub domain: AttemptCleanupManifestDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub failed_stage: AttemptCleanupFailedStage,
    pub claim_terminal_receipt: KeyPackageClaimTerminalReceipt,
    pub effect_delivery_receipts: Vec<ExecutionBundleDeliveryReceipt>,
    pub membership_compensation_delivery_receipts: Vec<ExecutionBundleDeliveryReceipt>,
    pub current_host_service_id: Did,
    pub current_host_epoch: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AttemptCleanupCertificateBundle {
    pub value_core: EffectValueCore,
    pub journal_validation_receipt: JournalValidationReceipt,
    pub qda_certificate: QdaCertificate,
    pub qcommit_certificate: QcommitCertificate,
    pub cleanup_manifest: AttemptCleanupManifest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HostTransferJournalEntry {
    pub journal_index: u64,
    pub attempt_sequence: u64,
    pub effect_id: ProtocolOpaqueId,
    pub value_digest: Hash,
    pub effect_commitment_digest: Hash,
    pub effect_head_digest: Hash,
    pub qcommit_certificate_digest: Hash,
    pub submitted_bundle_digest: Hash,
}

string_marker!(
    HostTransferJournalManifestDomain,
    V1,
    "ak.direct-conversation.host-transfer-journal-manifest.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HostTransferJournalManifest {
    pub domain: HostTransferJournalManifestDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub transfer_id: ProtocolOpaqueId,
    pub from_host_service_id: Did,
    pub from_host_epoch: u64,
    pub to_host_service_id: Did,
    pub to_host_epoch: u64,
    pub completed_effect_head_digest: Hash,
    pub entries: Vec<HostTransferJournalEntry>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
}

string_marker!(
    HostTransferFailoverVoteDomain,
    V1,
    "ak.direct-conversation.host-transfer-failover-vote.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HostTransferFailoverVote {
    pub domain: HostTransferFailoverVoteDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub transfer_id: ProtocolOpaqueId,
    pub manifest_digest: Hash,
    pub from_host_service_id: Did,
    pub from_host_epoch: u64,
    pub to_host_service_id: Did,
    pub to_host_epoch: u64,
    pub read_certificate_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub unavailable_since: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    pub replica_id: Did,
    pub signature: ProtocolSignature,
}

string_marker!(
    HostTransferFailoverCertificateDomain,
    V1,
    "ak.direct-conversation.host-transfer-failover-certificate.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HostTransferFailoverCertificate {
    pub domain: HostTransferFailoverCertificateDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub transfer_id: ProtocolOpaqueId,
    pub manifest_digest: Hash,
    pub from_host_service_id: Did,
    pub from_host_epoch: u64,
    pub to_host_service_id: Did,
    pub to_host_epoch: u64,
    pub read_certificate: OperationControlReadCertificate,
    pub host_epoch_policy_digest: Hash,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub votes: Vec<HostTransferFailoverVote>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "authorization_kind",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum HostTransferAuthorization {
    Graceful {
        from_host_verification_method: DidUrl,
        from_host_signature: ProtocolSignature,
    },
    QuorumFailover {
        failover_certificate: HostTransferFailoverCertificate,
    },
}

string_marker!(
    HostTransferPrepareJournalDomain,
    V1,
    "ak.direct-conversation.host-transfer-prepare-journal.v1"
);
string_marker!(
    HostTransferFinalizeJournalDomain,
    V1,
    "ak.direct-conversation.host-transfer-finalize-journal.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HostTransferPrepareJournalPlaintext {
    pub domain: HostTransferPrepareJournalDomain,
    pub manifest: HostTransferJournalManifest,
    pub manifest_digest: Hash,
    pub transfer_authorization: HostTransferAuthorization,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HostTransferFinalizeJournalPlaintext {
    pub domain: HostTransferFinalizeJournalDomain,
    pub manifest: HostTransferJournalManifest,
    pub manifest_digest: Hash,
    pub transfer_authorization: HostTransferAuthorization,
    pub prepare_effect_commitment_digest: Hash,
    pub prepare_delivery_receipt: ExecutionBundleDeliveryReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "head_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum OperationControlHead {
    Genesis {
        registry_digest: Hash,
        pair_registry_id: Hash,
        pair_key: Hash,
        genesis_head_digest: Hash,
        host_service_id: Did,
        host_epoch: u64,
    },
    Committed {
        registry_digest: Hash,
        pair_registry_id: Hash,
        pair_key: Hash,
        effect_id: ProtocolOpaqueId,
        effect_commitment_digest: Hash,
        effect_head_digest: Hash,
        predecessor_head_digest: Hash,
        operation_id: ProtocolOperationId,
        attempt_sequence: u64,
        value_digest: Hash,
        qda_certificate_digest: Hash,
        qcommit_certificate_digest: Hash,
        host_service_id: Did,
        host_epoch: u64,
    },
}

string_marker!(
    OperationControlReadRequestDomain,
    V1,
    "ak.direct-conversation.operation-control-read-request.v1"
);
string_marker!(
    OperationControlReadReceiptDomain,
    V1,
    "ak.direct-conversation.operation-control-read-receipt.v1"
);
string_marker!(
    OperationControlReadCertificateDomain,
    V1,
    "ak.direct-conversation.operation-control-read-certificate.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlReadRequest {
    pub domain: OperationControlReadRequestDomain,
    pub registry_digest: Hash,
    pub read_request_id: ProtocolOpaqueId,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub requester_service_id: Did,
    pub audience: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_host_service_id: Option<Did>,
    pub minimum_host_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_head_digest: Option<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlReadReceipt {
    pub domain: OperationControlReadReceiptDomain,
    pub request_digest: Hash,
    pub head: OperationControlHead,
    pub replica_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlReadCertificate {
    pub domain: OperationControlReadCertificateDomain,
    pub read_request: OperationControlReadRequest,
    pub request_digest: Hash,
    pub head: OperationControlHead,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub receipts: Vec<OperationControlReadReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsensusPhase {
    PrePrepare,
    Prepare,
    Commit,
}

string_marker!(
    ConsensusEnvelopeDomain,
    V1,
    "ak.direct-conversation.pbft-envelope.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsensusEnvelope {
    PrePrepare {
        domain: ConsensusEnvelopeDomain,
        registry_digest: Hash,
        pair_registry_id: Hash,
        pair_key: Hash,
        instance_predecessor_head_digest: Hash,
        operation_id: ProtocolOperationId,
        attempt_sequence: u64,
        view: u64,
        value_digest: Hash,
        qda_certificate_digest: Hash,
        replica_id: Did,
        signature: ProtocolSignature,
    },
    Prepare {
        domain: ConsensusEnvelopeDomain,
        registry_digest: Hash,
        pair_registry_id: Hash,
        pair_key: Hash,
        instance_predecessor_head_digest: Hash,
        operation_id: ProtocolOperationId,
        attempt_sequence: u64,
        view: u64,
        value_digest: Hash,
        qda_certificate_digest: Hash,
        pre_prepare_digest: Hash,
        replica_id: Did,
        signature: ProtocolSignature,
    },
    Commit {
        domain: ConsensusEnvelopeDomain,
        registry_digest: Hash,
        pair_registry_id: Hash,
        pair_key: Hash,
        instance_predecessor_head_digest: Hash,
        operation_id: ProtocolOperationId,
        attempt_sequence: u64,
        view: u64,
        value_digest: Hash,
        qda_certificate_digest: Hash,
        prepared_certificate_digest: Hash,
        replica_id: Did,
        signature: ProtocolSignature,
    },
}

impl ConsensusEnvelope {
    fn phase(&self) -> ConsensusPhase {
        match self {
            Self::PrePrepare { .. } => ConsensusPhase::PrePrepare,
            Self::Prepare { .. } => ConsensusPhase::Prepare,
            Self::Commit { .. } => ConsensusPhase::Commit,
        }
    }
    fn pair_registry_id(&self) -> &Hash {
        match self {
            Self::PrePrepare {
                pair_registry_id, ..
            }
            | Self::Prepare {
                pair_registry_id, ..
            }
            | Self::Commit {
                pair_registry_id, ..
            } => pair_registry_id,
        }
    }
    fn registry_digest(&self) -> &Hash {
        match self {
            Self::PrePrepare {
                registry_digest, ..
            }
            | Self::Prepare {
                registry_digest, ..
            }
            | Self::Commit {
                registry_digest, ..
            } => registry_digest,
        }
    }
    fn predecessor_head_digest(&self) -> &Hash {
        match self {
            Self::PrePrepare {
                instance_predecessor_head_digest,
                ..
            }
            | Self::Prepare {
                instance_predecessor_head_digest,
                ..
            }
            | Self::Commit {
                instance_predecessor_head_digest,
                ..
            } => instance_predecessor_head_digest,
        }
    }
    fn pair_key(&self) -> &Hash {
        match self {
            Self::PrePrepare { pair_key, .. }
            | Self::Prepare { pair_key, .. }
            | Self::Commit { pair_key, .. } => pair_key,
        }
    }
    fn operation_id(&self) -> &ProtocolOperationId {
        match self {
            Self::PrePrepare { operation_id, .. }
            | Self::Prepare { operation_id, .. }
            | Self::Commit { operation_id, .. } => operation_id,
        }
    }
    fn attempt_sequence(&self) -> u64 {
        match self {
            Self::PrePrepare {
                attempt_sequence, ..
            }
            | Self::Prepare {
                attempt_sequence, ..
            }
            | Self::Commit {
                attempt_sequence, ..
            } => *attempt_sequence,
        }
    }
    fn view(&self) -> u64 {
        match self {
            Self::PrePrepare { view, .. }
            | Self::Prepare { view, .. }
            | Self::Commit { view, .. } => *view,
        }
    }
    fn value_digest(&self) -> &Hash {
        match self {
            Self::PrePrepare { value_digest, .. }
            | Self::Prepare { value_digest, .. }
            | Self::Commit { value_digest, .. } => value_digest,
        }
    }
    fn qda_certificate_digest(&self) -> &Hash {
        match self {
            Self::PrePrepare {
                qda_certificate_digest,
                ..
            }
            | Self::Prepare {
                qda_certificate_digest,
                ..
            }
            | Self::Commit {
                qda_certificate_digest,
                ..
            } => qda_certificate_digest,
        }
    }
    fn replica_id(&self) -> &Did {
        match self {
            Self::PrePrepare { replica_id, .. }
            | Self::Prepare { replica_id, .. }
            | Self::Commit { replica_id, .. } => replica_id,
        }
    }

    fn pre_prepare_digest(&self) -> Option<&Hash> {
        match self {
            Self::Prepare {
                pre_prepare_digest, ..
            } => Some(pre_prepare_digest),
            _ => None,
        }
    }

    fn prepared_certificate_digest(&self) -> Option<&Hash> {
        match self {
            Self::Commit {
                prepared_certificate_digest,
                ..
            } => Some(prepared_certificate_digest),
            _ => None,
        }
    }
}

string_marker!(PreparedCertificateKind, Prepared, "prepared");
string_marker!(
    PreparedCertificateDomain,
    V1,
    "ak.direct-conversation.prepared-certificate.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PreparedCertificate {
    pub certificate_kind: PreparedCertificateKind,
    pub domain: PreparedCertificateDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub instance_predecessor_head_digest: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub view: u64,
    pub value_digest: Hash,
    pub qda_certificate_digest: Hash,
    pub certificate_digest: Hash,
    pub pre_prepare: ConsensusEnvelope,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub prepares: Vec<ConsensusEnvelope>,
}

impl PreparedCertificate {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_pbft_shape(self.n, self.f, self.quorum, self.prepares.len())?;
        if self.pre_prepare.phase() != ConsensusPhase::PrePrepare {
            return Err(arkret_wire::Error::Protocol(
                "prepared certificate requires PRE-PREPARE envelope".to_owned(),
            ));
        }
        validate_envelope_coordinates(
            &self.pre_prepare,
            &self.registry_digest,
            &self.pair_registry_id,
            &self.pair_key,
            &self.instance_predecessor_head_digest,
            &self.operation_id,
            self.attempt_sequence,
            self.view,
            &self.value_digest,
            &self.qda_certificate_digest,
        )?;
        let pre_prepare_digest =
            domain_hash("ak.direct-conversation.pre-prepare.v1", &self.pre_prepare)?;
        validate_envelopes(
            &self.prepares,
            ConsensusPhase::Prepare,
            &self.registry_digest,
            &self.pair_registry_id,
            &self.pair_key,
            &self.instance_predecessor_head_digest,
            &self.operation_id,
            self.attempt_sequence,
            self.view,
            &self.value_digest,
            &self.qda_certificate_digest,
        )?;
        if self
            .prepares
            .iter()
            .any(|prepare| prepare.pre_prepare_digest() != Some(&pre_prepare_digest))
            || self.semantic_digest()? != self.certificate_digest
        {
            return Err(arkret_wire::Error::Protocol(
                "prepared certificate digest binding is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn semantic_digest(&self) -> arkret_wire::Result<Hash> {
        #[derive(Serialize)]
        struct Core<'a> {
            certificate_kind: &'a PreparedCertificateKind,
            domain: &'a PreparedCertificateDomain,
            registry_digest: &'a Hash,
            pair_registry_id: &'a Hash,
            pair_key: &'a Hash,
            instance_predecessor_head_digest: &'a Hash,
            operation_id: &'a ProtocolOperationId,
            attempt_sequence: u64,
            view: u64,
            value_digest: &'a Hash,
            qda_certificate_digest: &'a Hash,
            n: u64,
            f: u64,
            quorum: u64,
        }
        domain_hash(
            "ak.direct-conversation.prepared-certificate.v1",
            &Core {
                certificate_kind: &self.certificate_kind,
                domain: &self.domain,
                registry_digest: &self.registry_digest,
                pair_registry_id: &self.pair_registry_id,
                pair_key: &self.pair_key,
                instance_predecessor_head_digest: &self.instance_predecessor_head_digest,
                operation_id: &self.operation_id,
                attempt_sequence: self.attempt_sequence,
                view: self.view,
                value_digest: &self.value_digest,
                qda_certificate_digest: &self.qda_certificate_digest,
                n: self.n,
                f: self.f,
                quorum: self.quorum,
            },
        )
    }
}

string_marker!(
    ViewChangeDomain,
    V1,
    "ak.direct-conversation.view-change.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "prepared_state", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ViewChangeMessage {
    None {
        domain: ViewChangeDomain,
        registry_digest: Hash,
        pair_registry_id: Hash,
        pair_key: Hash,
        instance_predecessor_head_digest: Hash,
        operation_id: ProtocolOperationId,
        attempt_sequence: u64,
        from_view: u64,
        target_view: u64,
        replica_id: Did,
        signature: ProtocolSignature,
    },
    Prepared {
        domain: ViewChangeDomain,
        registry_digest: Hash,
        pair_registry_id: Hash,
        pair_key: Hash,
        instance_predecessor_head_digest: Hash,
        operation_id: ProtocolOperationId,
        attempt_sequence: u64,
        from_view: u64,
        target_view: u64,
        highest_prepared: PreparedCertificate,
        replica_id: Did,
        signature: ProtocolSignature,
    },
}

impl ViewChangeMessage {
    fn replica_id(&self) -> &Did {
        match self {
            Self::None { replica_id, .. } | Self::Prepared { replica_id, .. } => replica_id,
        }
    }

    fn matches_certificate(&self, certificate: &ViewChangeCertificate) -> bool {
        let (
            registry_digest,
            pair_registry_id,
            pair_key,
            predecessor,
            operation_id,
            attempt_sequence,
            from_view,
            target_view,
        ) = match self {
            Self::None {
                registry_digest,
                pair_registry_id,
                pair_key,
                instance_predecessor_head_digest,
                operation_id,
                attempt_sequence,
                from_view,
                target_view,
                ..
            }
            | Self::Prepared {
                registry_digest,
                pair_registry_id,
                pair_key,
                instance_predecessor_head_digest,
                operation_id,
                attempt_sequence,
                from_view,
                target_view,
                ..
            } => (
                registry_digest,
                pair_registry_id,
                pair_key,
                instance_predecessor_head_digest,
                operation_id,
                *attempt_sequence,
                *from_view,
                *target_view,
            ),
        };
        registry_digest == &certificate.registry_digest
            && pair_registry_id == &certificate.pair_registry_id
            && pair_key == &certificate.pair_key
            && predecessor == &certificate.instance_predecessor_head_digest
            && operation_id == &certificate.operation_id
            && attempt_sequence == certificate.attempt_sequence
            && from_view < target_view
            && target_view == certificate.target_view
    }
}

string_marker!(ViewChangeCertificateKind, ViewChange, "view_change");
string_marker!(
    ViewChangeCertificateDomain,
    V1,
    "ak.direct-conversation.view-change-certificate.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ViewChangeCertificate {
    pub certificate_kind: ViewChangeCertificateKind,
    pub domain: ViewChangeCertificateDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub instance_predecessor_head_digest: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub target_view: u64,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub messages: Vec<ViewChangeMessage>,
}

impl ViewChangeCertificate {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_pbft_shape(self.n, self.f, self.quorum, self.messages.len())?;
        require_unique(
            self.messages.iter().map(ViewChangeMessage::replica_id),
            "view-change",
        )?;
        if self.target_view == 0
            || self
                .messages
                .iter()
                .any(|message| !message.matches_certificate(self))
        {
            return Err(arkret_wire::Error::Protocol(
                "view-change message coordinates do not match certificate".to_owned(),
            ));
        }
        for message in &self.messages {
            if let ViewChangeMessage::Prepared {
                highest_prepared,
                from_view,
                ..
            } = message
            {
                highest_prepared.validate()?;
                if highest_prepared.registry_digest != self.registry_digest
                    || highest_prepared.pair_registry_id != self.pair_registry_id
                    || highest_prepared.pair_key != self.pair_key
                    || highest_prepared.instance_predecessor_head_digest
                        != self.instance_predecessor_head_digest
                    || highest_prepared.operation_id != self.operation_id
                    || highest_prepared.attempt_sequence != self.attempt_sequence
                    || highest_prepared.view > *from_view
                {
                    return Err(arkret_wire::Error::Protocol(
                        "view-change prepared certificate is from another instance".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

string_marker!(NewViewCertificateKind, NewView, "new_view");
string_marker!(
    NewViewCertificateDomain,
    V1,
    "ak.direct-conversation.new-view-certificate.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct NewViewCertificate {
    pub certificate_kind: NewViewCertificateKind,
    pub domain: NewViewCertificateDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub instance_predecessor_head_digest: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub view: u64,
    pub selected_value_digest: Hash,
    pub qda_certificate_digest: Hash,
    pub view_change_certificate: ViewChangeCertificate,
    pub proposal: ConsensusEnvelope,
    pub proposer_id: Did,
    pub signature: ProtocolSignature,
}

impl NewViewCertificate {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.view_change_certificate.validate()?;
        if self.view == 0
            || self.view_change_certificate.registry_digest != self.registry_digest
            || self.view_change_certificate.pair_registry_id != self.pair_registry_id
            || self.view_change_certificate.pair_key != self.pair_key
            || self
                .view_change_certificate
                .instance_predecessor_head_digest
                != self.instance_predecessor_head_digest
            || self.view_change_certificate.operation_id != self.operation_id
            || self.view_change_certificate.attempt_sequence != self.attempt_sequence
            || self.view_change_certificate.target_view != self.view
            || self.proposal.phase() != ConsensusPhase::PrePrepare
            || self.proposal.registry_digest() != &self.registry_digest
            || self.proposal.pair_registry_id() != &self.pair_registry_id
            || self.proposal.pair_key() != &self.pair_key
            || self.proposal.predecessor_head_digest() != &self.instance_predecessor_head_digest
            || self.proposal.operation_id() != &self.operation_id
            || self.proposal.attempt_sequence() != self.attempt_sequence
            || self.proposal.view() != self.view
            || self.proposal.replica_id() != &self.proposer_id
            || self.proposal.value_digest() != &self.selected_value_digest
            || self.proposal.qda_certificate_digest() != &self.qda_certificate_digest
        {
            return Err(arkret_wire::Error::Protocol(
                "invalid NEW-VIEW proposal binding".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PerViewCertificate {
    Prepared(PreparedCertificate),
    ViewChange(ViewChangeCertificate),
    NewView(NewViewCertificate),
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InitialViewPrePrepare(pub ConsensusEnvelope);

impl Serialize for InitialViewPrePrepare {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !matches!(&self.0, ConsensusEnvelope::PrePrepare { view: 0, .. }) {
            return Err(serde::ser::Error::custom(
                "initial proposal requires a view-0 PRE-PREPARE",
            ));
        }
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InitialViewPrePrepare {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = ConsensusEnvelope::deserialize(deserializer)?;
        if !matches!(&envelope, ConsensusEnvelope::PrePrepare { view: 0, .. }) {
            return Err(serde::de::Error::custom(
                "initial proposal requires a view-0 PRE-PREPARE",
            ));
        }
        Ok(Self(envelope))
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SuccessorViewPrePrepare(pub ConsensusEnvelope);

impl Serialize for SuccessorViewPrePrepare {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !matches!(&self.0, ConsensusEnvelope::PrePrepare { view, .. } if *view > 0) {
            return Err(serde::ser::Error::custom(
                "successor proposal requires a view>0 PRE-PREPARE",
            ));
        }
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SuccessorViewPrePrepare {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = ConsensusEnvelope::deserialize(deserializer)?;
        if !matches!(&envelope, ConsensusEnvelope::PrePrepare { view, .. } if *view > 0) {
            return Err(serde::de::Error::custom(
                "successor proposal requires a view>0 PRE-PREPARE",
            ));
        }
        Ok(Self(envelope))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InitialOperationControlProposal {
    pub value_core: EffectValueCore,
    pub journal_validation_receipt: JournalValidationReceipt,
    pub qda_certificate: QdaCertificate,
    pub authenticated_encrypted_journal: AuthenticatedEncryptedJournal,
    pub pre_prepare: InitialViewPrePrepare,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SuccessorOperationControlProposal {
    pub value_core: EffectValueCore,
    pub journal_validation_receipt: JournalValidationReceipt,
    pub qda_certificate: QdaCertificate,
    pub authenticated_encrypted_journal: AuthenticatedEncryptedJournal,
    pub pre_prepare: SuccessorViewPrePrepare,
    pub new_view_certificate: NewViewCertificate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum OperationControlProposal {
    Initial(InitialOperationControlProposal),
    Successor(SuccessorOperationControlProposal),
}

impl OperationControlProposal {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        match self {
            Self::Initial(proposal) => validate_operation_control_proposal(
                &proposal.value_core,
                &proposal.journal_validation_receipt,
                &proposal.qda_certificate,
                &proposal.authenticated_encrypted_journal,
                &proposal.pre_prepare.0,
                None,
            ),
            Self::Successor(proposal) => validate_operation_control_proposal(
                &proposal.value_core,
                &proposal.journal_validation_receipt,
                &proposal.qda_certificate,
                &proposal.authenticated_encrypted_journal,
                &proposal.pre_prepare.0,
                Some(&proposal.new_view_certificate),
            ),
        }
    }
}

string_marker!(
    QdaReceiptDomain,
    V1,
    "ak.direct-conversation.qda-receipt.v1"
);
string_marker!(
    QdaCertificateDomain,
    V1,
    "ak.direct-conversation.qda-certificate.v1"
);
string_marker!(
    QcommitCertificateDomain,
    V1,
    "ak.direct-conversation.qcommit-certificate.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct QdaReceipt {
    pub domain: QdaReceiptDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub effect_id: ProtocolOpaqueId,
    pub value_digest: Hash,
    pub journal_root: Hash,
    pub destination: Did,
    pub expected_host_service_id: Did,
    pub expected_host_epoch: u64,
    pub resulting_host_service_id: Did,
    pub resulting_host_epoch: u64,
    pub replica_id: Did,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct QdaCertificate {
    pub domain: QdaCertificateDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub effect_id: ProtocolOpaqueId,
    pub value_digest: Hash,
    pub journal_root: Hash,
    pub destination: Did,
    pub expected_host_service_id: Did,
    pub expected_host_epoch: u64,
    pub resulting_host_service_id: Did,
    pub resulting_host_epoch: u64,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub certificate_digest: Hash,
    pub receipts: Vec<QdaReceipt>,
}

impl QdaCertificate {
    pub fn digest(&self) -> arkret_wire::Result<Hash> {
        self.semantic_digest()
    }

    pub fn semantic_digest(&self) -> arkret_wire::Result<Hash> {
        #[derive(Serialize)]
        struct Core<'a> {
            domain: &'a QdaCertificateDomain,
            registry_digest: &'a Hash,
            pair_registry_id: &'a Hash,
            pair_key: &'a Hash,
            operation_id: &'a ProtocolOperationId,
            attempt_sequence: u64,
            effect_id: &'a ProtocolOpaqueId,
            value_digest: &'a Hash,
            journal_root: &'a Hash,
            destination: &'a Did,
            expected_host_service_id: &'a Did,
            expected_host_epoch: u64,
            resulting_host_service_id: &'a Did,
            resulting_host_epoch: u64,
            n: u64,
            f: u64,
            quorum: u64,
        }
        domain_hash(
            "ak.direct-conversation.qda-certificate.v1",
            &Core {
                domain: &self.domain,
                registry_digest: &self.registry_digest,
                pair_registry_id: &self.pair_registry_id,
                pair_key: &self.pair_key,
                operation_id: &self.operation_id,
                attempt_sequence: self.attempt_sequence,
                effect_id: &self.effect_id,
                value_digest: &self.value_digest,
                journal_root: &self.journal_root,
                destination: &self.destination,
                expected_host_service_id: &self.expected_host_service_id,
                expected_host_epoch: self.expected_host_epoch,
                resulting_host_service_id: &self.resulting_host_service_id,
                resulting_host_epoch: self.resulting_host_epoch,
                n: self.n,
                f: self.f,
                quorum: self.quorum,
            },
        )
    }

    pub fn validate_for_value(&self, value: &EffectValueCore) -> arkret_wire::Result<()> {
        validate_pbft_shape(self.n, self.f, self.quorum, self.receipts.len())?;
        let value_digest = value.value_digest()?;
        if self.semantic_digest()? != self.certificate_digest
            || self.registry_digest != value.registry_digest
            || self.pair_registry_id != value.pair_registry_id
            || self.pair_key != value.pair_key
            || self.operation_id != value.operation_id
            || self.attempt_sequence != value.attempt_sequence
            || self.effect_id != value.effect_id
            || self.value_digest != value_digest
            || self.journal_root != value.journal_root
            || self.destination != value.destination
            || self.expected_host_service_id != value.expected_host_service_id
            || self.expected_host_epoch != value.expected_host_epoch
            || self.resulting_host_service_id != value.resulting_host_service_id
            || self.resulting_host_epoch != value.resulting_host_epoch
        {
            return Err(arkret_wire::Error::Protocol(
                "qDA certificate does not match EffectValueCore".to_owned(),
            ));
        }
        require_unique(
            self.receipts.iter().map(|receipt| &receipt.replica_id),
            "qDA",
        )?;
        if self.receipts.iter().any(|receipt| {
            receipt.registry_digest != self.registry_digest
                || receipt.pair_registry_id != self.pair_registry_id
                || receipt.pair_key != self.pair_key
                || receipt.operation_id != self.operation_id
                || receipt.attempt_sequence != self.attempt_sequence
                || receipt.effect_id != self.effect_id
                || receipt.value_digest != self.value_digest
                || receipt.journal_root != self.journal_root
                || receipt.destination != self.destination
                || receipt.expected_host_service_id != self.expected_host_service_id
                || receipt.expected_host_epoch != self.expected_host_epoch
                || receipt.resulting_host_service_id != self.resulting_host_service_id
                || receipt.resulting_host_epoch != self.resulting_host_epoch
        }) {
            return Err(arkret_wire::Error::Protocol(
                "qDA receipt does not match certificate coordinates".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct QcommitCertificate {
    pub domain: QcommitCertificateDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub view: u64,
    pub value_digest: Hash,
    pub qda_certificate_digest: Hash,
    pub predecessor_head_digest: Hash,
    pub effect_head_digest: Hash,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub certificate_digest: Hash,
    pub commits: Vec<ConsensusEnvelope>,
}

impl QcommitCertificate {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_pbft_shape(self.n, self.f, self.quorum, self.commits.len())?;
        if self.semantic_digest()? != self.certificate_digest
            || self.effect_head_digest()? != self.effect_head_digest
        {
            return Err(arkret_wire::Error::Protocol(
                "qCOMMIT semantic digest binding is invalid".to_owned(),
            ));
        }
        validate_envelopes(
            &self.commits,
            ConsensusPhase::Commit,
            &self.registry_digest,
            &self.pair_registry_id,
            &self.pair_key,
            &self.predecessor_head_digest,
            &self.operation_id,
            self.attempt_sequence,
            self.view,
            &self.value_digest,
            &self.qda_certificate_digest,
        )
    }

    pub fn semantic_digest(&self) -> arkret_wire::Result<Hash> {
        #[derive(Serialize)]
        struct Core<'a> {
            domain: &'a QcommitCertificateDomain,
            registry_digest: &'a Hash,
            pair_registry_id: &'a Hash,
            pair_key: &'a Hash,
            operation_id: &'a ProtocolOperationId,
            attempt_sequence: u64,
            view: u64,
            value_digest: &'a Hash,
            qda_certificate_digest: &'a Hash,
            predecessor_head_digest: &'a Hash,
            effect_head_digest: &'a Hash,
            n: u64,
            f: u64,
            quorum: u64,
        }
        domain_hash(
            "ak.direct-conversation.qcommit-certificate.v1",
            &Core {
                domain: &self.domain,
                registry_digest: &self.registry_digest,
                pair_registry_id: &self.pair_registry_id,
                pair_key: &self.pair_key,
                operation_id: &self.operation_id,
                attempt_sequence: self.attempt_sequence,
                view: self.view,
                value_digest: &self.value_digest,
                qda_certificate_digest: &self.qda_certificate_digest,
                predecessor_head_digest: &self.predecessor_head_digest,
                effect_head_digest: &self.effect_head_digest,
                n: self.n,
                f: self.f,
                quorum: self.quorum,
            },
        )
    }

    pub fn effect_head_digest(&self) -> arkret_wire::Result<Hash> {
        #[derive(Serialize)]
        struct Core<'a> {
            registry_digest: &'a Hash,
            pair_registry_id: &'a Hash,
            pair_key: &'a Hash,
            operation_id: &'a ProtocolOperationId,
            attempt_sequence: u64,
            view: u64,
            predecessor_head_digest: &'a Hash,
            value_digest: &'a Hash,
            qda_certificate_digest: &'a Hash,
        }
        domain_hash(
            "ak.direct-conversation.effect-head.v1",
            &Core {
                registry_digest: &self.registry_digest,
                pair_registry_id: &self.pair_registry_id,
                pair_key: &self.pair_key,
                operation_id: &self.operation_id,
                attempt_sequence: self.attempt_sequence,
                view: self.view,
                predecessor_head_digest: &self.predecessor_head_digest,
                value_digest: &self.value_digest,
                qda_certificate_digest: &self.qda_certificate_digest,
            },
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ExecutionBundle {
    pub registry_authorization: OperationControlAuthorization,
    pub value_core: EffectValueCore,
    pub journal_validation_receipt: JournalValidationReceipt,
    pub qda_certificate: QdaCertificate,
    pub per_view_certificates: Vec<PerViewCertificate>,
    pub qcommit_certificate: QcommitCertificate,
    pub authenticated_encrypted_journal: AuthenticatedEncryptedJournal,
}

impl ExecutionBundle {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.value_core.validate()?;
        let expected_chain_len = 1usize
            .checked_add((self.qcommit_certificate.view as usize).saturating_mul(3))
            .ok_or_else(|| arkret_wire::Error::Protocol("view ancestry is too large".to_owned()))?;
        if self.per_view_certificates.len() != expected_chain_len {
            return Err(arkret_wire::Error::Protocol(
                "ExecutionBundle per-view ancestry is missing, reordered, or discontinuous"
                    .to_owned(),
            ));
        }
        self.qda_certificate.validate_for_value(&self.value_core)?;
        self.qcommit_certificate.validate()?;
        let value_digest = self.value_core.value_digest()?;
        let authorization_core = &self.registry_authorization.core;
        let aad = &self.authenticated_encrypted_journal.aad_core;
        let receipt = &self.journal_validation_receipt;
        let aad_digest = Hash::new(arkret_canonical::canonical_sha256(aad)?)
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))?;
        let journal_root = domain_hash(
            "ak.direct-conversation.journal-envelope.v1",
            &self.authenticated_encrypted_journal,
        )?;
        let receipt_digest = domain_hash(
            "ak.direct-conversation.journal-validation-receipt.v1",
            receipt,
        )?;
        let validation_core_digest = domain_hash(
            "ak.direct-conversation.journal-validation-core.v1",
            &self.value_core.journal_validation_core(),
        )?;
        let first_prepared = match &self.per_view_certificates[0] {
            PerViewCertificate::Prepared(prepared) if prepared.view == 0 => prepared,
            _ => {
                return Err(arkret_wire::Error::Protocol(
                    "per-view ancestry must begin with the view-0 prepared certificate".to_owned(),
                ));
            }
        };
        first_prepared.validate()?;
        validate_certificate_instance(first_prepared, &self.value_core)?;
        for view in 1..=self.qcommit_certificate.view {
            let base = 1 + ((view - 1) as usize * 3);
            let (view_change, new_view, prepared) = match (
                &self.per_view_certificates[base],
                &self.per_view_certificates[base + 1],
                &self.per_view_certificates[base + 2],
            ) {
                (
                    PerViewCertificate::ViewChange(view_change),
                    PerViewCertificate::NewView(new_view),
                    PerViewCertificate::Prepared(prepared),
                ) if view_change.target_view == view
                    && new_view.view == view
                    && prepared.view == view =>
                {
                    (view_change, new_view, prepared)
                }
                _ => {
                    return Err(arkret_wire::Error::Protocol(
                        "per-view ancestry must be ordered view-change, new-view, prepared"
                            .to_owned(),
                    ));
                }
            };
            view_change.validate()?;
            new_view.validate()?;
            prepared.validate()?;
            validate_view_change_instance(view_change, &self.value_core)?;
            validate_new_view_instance(new_view, &self.value_core)?;
            validate_certificate_instance(prepared, &self.value_core)?;
            if arkret_canonical::canonical_sha256(&new_view.view_change_certificate)?
                != arkret_canonical::canonical_sha256(view_change)?
                || arkret_canonical::canonical_sha256(&new_view.proposal)?
                    != arkret_canonical::canonical_sha256(&prepared.pre_prepare)?
            {
                return Err(arkret_wire::Error::Protocol(
                    "per-view certificates do not embed the exact canonical ancestors".to_owned(),
                ));
            }
        }
        let final_prepared = match self.per_view_certificates.last() {
            Some(PerViewCertificate::Prepared(prepared)) => prepared,
            _ => unreachable!("chain shape checked above"),
        };
        let final_prepared_digest = final_prepared.semantic_digest()?;
        if authorization_core.registry_digest != self.value_core.registry_digest
            || authorization_core.pair_registry_id != self.value_core.pair_registry_id
            || authorization_core.pair_key != self.value_core.pair_key
            || authorization_core.operation_id != self.value_core.operation_id
            || self.authenticated_encrypted_journal.recipient_service_id
                != self.value_core.destination
            || self.authenticated_encrypted_journal.plaintext_digest
                != self.value_core.payload_digest
            || self.authenticated_encrypted_journal.aad_digest != aad_digest
            || self.value_core.journal_root != journal_root
            || aad.registry_digest != self.value_core.registry_digest
            || aad.pair_registry_id != self.value_core.pair_registry_id
            || aad.pair_key != self.value_core.pair_key
            || aad.operation_id != self.value_core.operation_id
            || aad.attempt_sequence != self.value_core.attempt_sequence
            || aad.effect_id != self.value_core.effect_id
            || aad.effect_digest != self.value_core.effect_digest
            || aad.payload_digest != self.value_core.payload_digest
            || aad.destination != self.value_core.destination
            || aad.expected_host_service_id != self.value_core.expected_host_service_id
            || aad.expected_host_epoch != self.value_core.expected_host_epoch
            || aad.resulting_host_service_id != self.value_core.resulting_host_service_id
            || aad.resulting_host_epoch != self.value_core.resulting_host_epoch
            || aad.predecessor_head_digest != self.value_core.predecessor_head_digest
            || receipt.journal_root != self.value_core.journal_root
            || receipt.validation_core_digest != validation_core_digest
            || receipt.effect_digest != self.value_core.effect_digest
            || receipt.payload_digest != self.value_core.payload_digest
            || receipt.destination != self.value_core.destination
            || receipt.recipient_key_ref != self.authenticated_encrypted_journal.recipient_key_ref
            || receipt.issuer != self.value_core.destination
            || receipt.validated_at >= receipt.expires_at
            || self.qda_certificate.receipts.iter().any(|qda_receipt| {
                qda_receipt.signature.created_at < receipt.validated_at
                    || qda_receipt.signature.created_at >= receipt.expires_at
            })
            || self.value_core.journal_validation_receipt_digest != receipt_digest
            || self.qcommit_certificate.value_digest != value_digest
            || self.qcommit_certificate.registry_digest != self.value_core.registry_digest
            || self.qcommit_certificate.pair_registry_id != self.value_core.pair_registry_id
            || self.qcommit_certificate.pair_key != self.value_core.pair_key
            || self.qcommit_certificate.operation_id != self.value_core.operation_id
            || self.qcommit_certificate.attempt_sequence != self.value_core.attempt_sequence
            || self.qcommit_certificate.qda_certificate_digest != self.qda_certificate.digest()?
            || self.qcommit_certificate.predecessor_head_digest
                != self.value_core.predecessor_head_digest
            || final_prepared.value_digest != value_digest
            || final_prepared.qda_certificate_digest != self.qda_certificate.certificate_digest
            || self
                .qcommit_certificate
                .commits
                .iter()
                .any(|commit| commit.prepared_certificate_digest() != Some(&final_prepared_digest))
        {
            return Err(arkret_wire::Error::Protocol(
                "ExecutionBundle cross-binding is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_certificate_instance(
    certificate: &PreparedCertificate,
    value: &EffectValueCore,
) -> arkret_wire::Result<()> {
    if certificate.registry_digest != value.registry_digest
        || certificate.pair_registry_id != value.pair_registry_id
        || certificate.pair_key != value.pair_key
        || certificate.instance_predecessor_head_digest != value.predecessor_head_digest
        || certificate.operation_id != value.operation_id
        || certificate.attempt_sequence != value.attempt_sequence
    {
        return Err(arkret_wire::Error::Protocol(
            "prepared certificate belongs to another operation-control instance".to_owned(),
        ));
    }
    Ok(())
}

fn validate_view_change_instance(
    certificate: &ViewChangeCertificate,
    value: &EffectValueCore,
) -> arkret_wire::Result<()> {
    if certificate.registry_digest != value.registry_digest
        || certificate.pair_registry_id != value.pair_registry_id
        || certificate.pair_key != value.pair_key
        || certificate.instance_predecessor_head_digest != value.predecessor_head_digest
        || certificate.operation_id != value.operation_id
        || certificate.attempt_sequence != value.attempt_sequence
    {
        return Err(arkret_wire::Error::Protocol(
            "view-change certificate belongs to another operation-control instance".to_owned(),
        ));
    }
    Ok(())
}

fn validate_new_view_instance(
    certificate: &NewViewCertificate,
    value: &EffectValueCore,
) -> arkret_wire::Result<()> {
    if certificate.registry_digest != value.registry_digest
        || certificate.pair_registry_id != value.pair_registry_id
        || certificate.pair_key != value.pair_key
        || certificate.instance_predecessor_head_digest != value.predecessor_head_digest
        || certificate.operation_id != value.operation_id
        || certificate.attempt_sequence != value.attempt_sequence
    {
        return Err(arkret_wire::Error::Protocol(
            "new-view certificate belongs to another operation-control instance".to_owned(),
        ));
    }
    Ok(())
}

fn validate_operation_control_proposal(
    value: &EffectValueCore,
    receipt: &JournalValidationReceipt,
    qda: &QdaCertificate,
    journal: &AuthenticatedEncryptedJournal,
    pre_prepare: &ConsensusEnvelope,
    new_view: Option<&NewViewCertificate>,
) -> arkret_wire::Result<()> {
    value.validate()?;
    qda.validate_for_value(value)?;
    let value_digest = value.value_digest()?;
    let qda_digest = qda.semantic_digest()?;
    let aad_digest = Hash::new(arkret_canonical::canonical_sha256(&journal.aad_core)?)
        .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))?;
    let journal_root = domain_hash("ak.direct-conversation.journal-envelope.v1", journal)?;
    let receipt_digest = domain_hash(
        "ak.direct-conversation.journal-validation-receipt.v1",
        receipt,
    )?;
    let validation_core_digest = domain_hash(
        "ak.direct-conversation.journal-validation-core.v1",
        &value.journal_validation_core(),
    )?;
    validate_envelope_coordinates(
        pre_prepare,
        &value.registry_digest,
        &value.pair_registry_id,
        &value.pair_key,
        &value.predecessor_head_digest,
        &value.operation_id,
        value.attempt_sequence,
        pre_prepare.view(),
        &value_digest,
        &qda_digest,
    )?;
    if pre_prepare.phase() != ConsensusPhase::PrePrepare
        || journal.recipient_service_id != value.destination
        || journal.plaintext_digest != value.payload_digest
        || journal.aad_digest != aad_digest
        || journal_root != value.journal_root
        || journal.aad_core.registry_digest != value.registry_digest
        || journal.aad_core.pair_registry_id != value.pair_registry_id
        || journal.aad_core.pair_key != value.pair_key
        || journal.aad_core.operation_id != value.operation_id
        || journal.aad_core.attempt_sequence != value.attempt_sequence
        || journal.aad_core.effect_id != value.effect_id
        || journal.aad_core.effect_digest != value.effect_digest
        || journal.aad_core.payload_digest != value.payload_digest
        || journal.aad_core.destination != value.destination
        || journal.aad_core.expected_host_service_id != value.expected_host_service_id
        || journal.aad_core.expected_host_epoch != value.expected_host_epoch
        || journal.aad_core.resulting_host_service_id != value.resulting_host_service_id
        || journal.aad_core.resulting_host_epoch != value.resulting_host_epoch
        || journal.aad_core.predecessor_head_digest != value.predecessor_head_digest
        || receipt.validation_core_digest != validation_core_digest
        || receipt.journal_root != value.journal_root
        || receipt.effect_digest != value.effect_digest
        || receipt.payload_digest != value.payload_digest
        || receipt.destination != value.destination
        || receipt.recipient_key_ref != journal.recipient_key_ref
        || receipt.issuer != value.destination
        || receipt.validated_at >= receipt.expires_at
        || value.journal_validation_receipt_digest != receipt_digest
        || qda.receipts.iter().any(|qda_receipt| {
            qda_receipt.signature.created_at < receipt.validated_at
                || qda_receipt.signature.created_at >= receipt.expires_at
        })
    {
        return Err(arkret_wire::Error::Protocol(
            "operation-control proposal cross-binding is invalid".to_owned(),
        ));
    }
    match new_view {
        None if pre_prepare.view() == 0 => Ok(()),
        Some(certificate) if pre_prepare.view() > 0 => {
            certificate.validate()?;
            validate_new_view_instance(certificate, value)?;
            if certificate.view != pre_prepare.view()
                || arkret_canonical::canonical_sha256(&certificate.proposal)?
                    != arkret_canonical::canonical_sha256(pre_prepare)?
            {
                return Err(arkret_wire::Error::Protocol(
                    "successor proposal does not match NEW-VIEW certificate".to_owned(),
                ));
            }
            Ok(())
        }
        _ => Err(arkret_wire::Error::Protocol(
            "view-0 forbids NEW-VIEW and view>0 requires it".to_owned(),
        )),
    }
}

string_marker!(
    HostEpochPolicyDomain,
    V1,
    "ak.direct-conversation.host-epoch-policy.v1"
);
string_marker!(
    HostEpochTargetRule,
    EligibleHostsOnly,
    "eligible_hosts_only"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlHostEpochPolicy {
    pub domain: HostEpochPolicyDomain,
    pub target_rule: HostEpochTargetRule,
    pub graceful_receipt_ttl_seconds: u64,
    pub failover_min_unavailable_seconds: u64,
    pub read_certificate_max_age_seconds: u64,
}

string_marker!(
    OperationControlDomainPolicyDomain,
    V1,
    "ak.direct-conversation.operation-control-domain-policy.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlDomainPolicyCore {
    pub domain: OperationControlDomainPolicyDomain,
    pub trust_domain_id: TypedTrustDomainId,
    pub policy_version: u64,
    pub domain_root_id: Did,
    pub domain_root_verification_method: DidUrl,
    pub eligible_replicas: Vec<Did>,
    pub eligible_hosts: Vec<Did>,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub host_epoch_policy: OperationControlHostEpochPolicy,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlDomainPolicyStatement {
    pub core: OperationControlDomainPolicyCore,
    pub policy_digest: Hash,
    pub signature: ProtocolSignature,
}

string_marker!(
    PairRegistryCoreDomain,
    V1,
    "ak.direct-conversation.pair-registry-core.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PairRegistryCore {
    pub domain: PairRegistryCoreDomain,
    pub trust_domain_id: TypedTrustDomainId,
    pub domain_policy_digest: Hash,
    pub pair_slot_id: Hash,
    pub pair_key: Hash,
    pub participants: [Did; 2],
    pub origin_coordinator: Did,
    pub initial_host_service_id: Did,
    pub initial_host_epoch: u64,
    pub replicas: Vec<Did>,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub host_epoch_policy_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PairRegistryStatement {
    pub domain_policy_statement: OperationControlDomainPolicyStatement,
    pub core: PairRegistryCore,
    pub pair_registry_id: Hash,
    pub registry_digest: Hash,
    pub stable_operation_id: ProtocolOperationId,
    pub initial_requester_id: Did,
    pub slot_version: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub domain_root_verification_method: DidUrl,
    pub signature: ProtocolSignature,
}

string_marker!(
    OperationControlAuthorizationCoreDomain,
    V1,
    "ak.direct-conversation.operation-control-authorization.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlAuthorizationCore {
    pub domain: OperationControlAuthorizationCoreDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub requester_id: Did,
    pub materialization_genesis_digest: Hash,
    pub genesis_head_digest: Hash,
}

string_marker!(
    OperationControlAuthorizationCommitDomain,
    V1,
    "ak.direct-conversation.operation-control-authorization-commit.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlAuthorizationCommitReceipt {
    pub domain: OperationControlAuthorizationCommitDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub stable_operation_id: ProtocolOperationId,
    pub requester_id: Did,
    pub authorization_core_digest: Hash,
    pub materialization_genesis_digest: Hash,
    pub claim_request_digest: Hash,
    pub slot_version: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub committed_at: DateTime<Utc>,
    pub domain_root_verification_method: DidUrl,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlAuthorizationDraft {
    pub registry_statement: PairRegistryStatement,
    pub materialization_genesis: DirectConversationMaterializationGenesis,
    pub core: OperationControlAuthorizationCore,
    pub requester_signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlAuthorization {
    pub registry_statement: PairRegistryStatement,
    pub materialization_genesis: DirectConversationMaterializationGenesis,
    pub core: OperationControlAuthorizationCore,
    pub requester_signature: ProtocolSignature,
    pub commit_receipt: OperationControlAuthorizationCommitReceipt,
}

string_marker!(
    DirectConversationMaterializationGenesisDomain,
    V1,
    "ak.direct-conversation.materialization-genesis.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationMaterializationEventSlots {
    pub realm_create_event_id: EventId,
    pub peer_join_event_id: EventId,
    pub main_strand_event_id: EventId,
    pub mls_genesis_event_id: EventId,
    pub mls_commit_event_id: EventId,
    pub mls_welcome_event_id: EventId,
    pub binding_event_id: EventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationMaterializationGenesis {
    pub domain: DirectConversationMaterializationGenesisDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub coordinates: DirectConversationCoordinates,
    pub mls_group_id: ProtocolOpaqueId,
    pub event_slots: DirectConversationMaterializationEventSlots,
    pub compensation_delegation_core_digest: Hash,
    pub claim_authorization_draft: PeerKeyPackagesClaimAuthorizationDraft,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationMaterializationStep {
    FoundingUnit,
    MainStrand,
    MlsEpoch,
    WelcomeAdmission,
    BindingFinalize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationPreparedEventDraft {
    pub event_id: EventId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub kind: arkret_wire::EventKind,
    pub unsigned_event_bytes: Base64UrlString,
    pub event_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "materialization_step",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationPreparedStage {
    FoundingUnit {
        event_drafts: [DirectConversationPreparedEventDraft; 2],
    },
    MainStrand {
        event_drafts: [DirectConversationPreparedEventDraft; 1],
    },
    MlsEpoch {
        event_drafts: [DirectConversationPreparedEventDraft; 2],
    },
    WelcomeAdmission {
        event_drafts: [DirectConversationPreparedEventDraft; 1],
    },
    BindingFinalize {
        event_drafts: [DirectConversationPreparedEventDraft; 1],
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "materialization_step",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationSignedStage {
    FoundingUnit {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
        signed_events: [Event; 2],
    },
    MainStrand {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
        signed_events: [Event; 1],
    },
    MlsEpoch {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
        signed_events: [Event; 2],
    },
    WelcomeAdmission {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
        signed_events: [Event; 1],
    },
    BindingFinalize {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
        signed_events: [Event; 1],
    },
}

string_marker!(
    ExecutionBundleDeliveryReceiptDomain,
    V1,
    "ak.direct-conversation.execution-bundle-delivery-receipt.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ExecutionBundleDeliveryReceipt {
    Accepted {
        domain: ExecutionBundleDeliveryReceiptDomain,
        submitted_bundle_digest: Hash,
        effect_commitment_digest: Hash,
        value_digest: Hash,
        effect_head_digest: Hash,
        effect_id: ProtocolOpaqueId,
        destination: Did,
        host_service_id: Did,
        host_epoch: u64,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        recorded_at: DateTime<Utc>,
        signature: ProtocolSignature,
    },
    Duplicate {
        domain: ExecutionBundleDeliveryReceiptDomain,
        submitted_bundle_digest: Hash,
        effect_commitment_digest: Hash,
        value_digest: Hash,
        effect_head_digest: Hash,
        effect_id: ProtocolOpaqueId,
        destination: Did,
        host_service_id: Did,
        host_epoch: u64,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        recorded_at: DateTime<Utc>,
        signature: ProtocolSignature,
    },
    Deferred {
        domain: ExecutionBundleDeliveryReceiptDomain,
        submitted_bundle_digest: Hash,
        effect_commitment_digest: Hash,
        value_digest: Hash,
        effect_head_digest: Hash,
        effect_id: ProtocolOpaqueId,
        destination: Did,
        host_service_id: Did,
        host_epoch: u64,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        recorded_at: DateTime<Utc>,
        missing_dependency_digests: NonEmptyDigestList,
        signature: ProtocolSignature,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "materialization_step",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationMaterializationStepEvidence {
    FoundingUnit {
        claim_receipt: PeerKeyPackageClaimReceipt,
    },
    MainStrand {
        founding_delivery_receipt: ExecutionBundleDeliveryReceipt,
    },
    MlsEpoch {
        claim_receipt: PeerKeyPackageClaimReceipt,
        strand_delivery_receipt: ExecutionBundleDeliveryReceipt,
    },
    WelcomeAdmission {
        claim_receipt: PeerKeyPackageClaimReceipt,
        mls_delivery_receipt: ExecutionBundleDeliveryReceipt,
    },
    BindingFinalize {
        welcome_delivery_receipt: ExecutionBundleDeliveryReceipt,
        consume_receipt: KeyPackageConsumeReceipt,
    },
}

string_marker!(
    MaterializationStepCommitReceiptDomain,
    V1,
    "ak.direct-conversation.materialization-step-commit.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationMaterializationStepCommitReceipt {
    pub domain: MaterializationStepCommitReceiptDomain,
    pub registry_digest: Hash,
    pub pair_registry_id: Hash,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub materialization_step: DirectConversationMaterializationStep,
    pub prepared_step_digest: Hash,
    pub event_ids: Vec<EventId>,
    pub event_digests: Vec<Hash>,
    pub host_service_id: Did,
    pub host_epoch: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub committed_at: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectConversationLookupMarker;

impl Serialize for DirectConversationLookupMarker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for DirectConversationLookupMarker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            return Err(serde::de::Error::custom(
                "lookup request requires create=false",
            ));
        }
        Ok(Self)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectConversationCreateMarker;

impl Serialize for DirectConversationCreateMarker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for DirectConversationCreateMarker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if !bool::deserialize(deserializer)? {
            return Err(serde::de::Error::custom(
                "create request requires create=true",
            ));
        }
        Ok(Self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationLookupRequestBody {
    pub peer: ContactPeer,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub create: DirectConversationLookupMarker,
}

string_marker!(
    DirectConversationPrepareAuthorizationPhase,
    PrepareAuthorization,
    "prepare_authorization"
);
string_marker!(
    DirectConversationCommitAuthorizationPhase,
    CommitAuthorization,
    "commit_authorization"
);
string_marker!(
    DirectConversationPrepareMaterializationStepPhase,
    PrepareMaterializationStep,
    "prepare_materialization_step"
);
string_marker!(
    DirectConversationCommitMaterializationStepPhase,
    CommitMaterializationStep,
    "commit_materialization_step"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationPrepareAuthorizationRequestBody {
    pub peer: ContactPeer,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub create: DirectConversationCreateMarker,
    pub phase: DirectConversationPrepareAuthorizationPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: ProtocolOpaqueId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationCommitAuthorizationRequestBody {
    pub peer: ContactPeer,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub create: DirectConversationCreateMarker,
    pub phase: DirectConversationCommitAuthorizationPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: ProtocolOpaqueId,
    pub reservation_handle: ProtocolOpaqueId,
    pub operation_control_authorization: OperationControlAuthorizationDraft,
    pub peer_claim_request: PeerKeyPackagesClaimRequestBody,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationPrepareMaterializationStepRequestBody {
    pub peer: ContactPeer,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub create: DirectConversationCreateMarker,
    pub phase: DirectConversationPrepareMaterializationStepPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: ProtocolOpaqueId,
    pub operation_control_authorization: OperationControlAuthorization,
    pub step_evidence: DirectConversationMaterializationStepEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationCommitMaterializationStepRequestBody {
    pub peer: ContactPeer,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub create: DirectConversationCreateMarker,
    pub phase: DirectConversationCommitMaterializationStepPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: ProtocolOpaqueId,
    pub operation_control_authorization: OperationControlAuthorization,
    pub reservation_handle: ProtocolOpaqueId,
    pub signed_stage: DirectConversationSignedStage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationResolveRequestBody {
    Lookup(DirectConversationLookupRequestBody),
    PrepareAuthorization(DirectConversationPrepareAuthorizationRequestBody),
    CommitAuthorization(DirectConversationCommitAuthorizationRequestBody),
    PrepareMaterializationStep(DirectConversationPrepareMaterializationStepRequestBody),
    CommitMaterializationStep(DirectConversationCommitMaterializationStepRequestBody),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationSendBlocker {
    SessionMissing,
    PresenceOffline,
    KeypackageEmpty,
    GrantMissing,
    PolicyStale,
    ContactScopeStale,
    MlsReconcileRequired,
    PersonalBlocked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationCoordinates {
    pub pair_key: Hash,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub binding_event_ref: EventId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationSuspensionReason {
    ParticipantMembershipMissing,
    ContactDirectionRevoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationOperationState {
    Reserved,
    Materializing,
    Cleanup,
    CleanupCompleteRetryable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationUnavailableReason {
    DependencyPending,
    OperationControlStale,
    OpaqueUnavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationResolveOutcome {
    State(DirectConversationResolveStateOutcome),
    Tombstoned(DirectConversationTombstonedOutcome),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationResolveStateOutcome {
    AuthorizationPrepared {
        operation_id: ProtocolOperationId,
        reservation_handle: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        registry_statement: PairRegistryStatement,
        materialization_genesis: DirectConversationMaterializationGenesis,
        authorization_core: OperationControlAuthorizationCore,
        claim_authorization_draft: PeerKeyPackagesClaimAuthorizationDraft,
    },
    AuthorizationCommitted {
        operation_id: ProtocolOperationId,
        operation_control_authorization: OperationControlAuthorization,
    },
    MaterializationStepPrepared {
        operation_id: ProtocolOperationId,
        reservation_handle: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        prepared_step: DirectConversationPreparedStage,
        prepared_step_digest: Hash,
    },
    MaterializationStepCommitted {
        operation_id: ProtocolOperationId,
        step_commit_receipt: DirectConversationMaterializationStepCommitReceipt,
    },
    Found {
        coordinates: DirectConversationCoordinates,
        send_blockers: Vec<DirectConversationSendBlocker>,
    },
    Suspended {
        coordinates: DirectConversationCoordinates,
        suspension_reason: DirectConversationSuspensionReason,
    },
    Materializing {
        operation_id: ProtocolOperationId,
        attempt_sequence: u64,
        operation_state: DirectConversationOperationState,
    },
    TemporarilyUnavailable {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_id: Option<ProtocolOperationId>,
        reason: DirectConversationUnavailableReason,
    },
    CreationRequired,
}

string_marker!(DirectConversationTombstonedStatus, Tombstoned, "tombstoned");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationTombstonedOutcome {
    pub status: DirectConversationTombstonedStatus,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub coordinates: DirectConversationCoordinates,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MlsJoinAdmissionReceipt {
    pub reservation_id: ProtocolOpaqueId,
    pub realm_id: RealmId,
    pub member_id: Did,
    pub device_id: DeviceId,
    pub keypackage_ref: ProtocolOpaqueId,
    pub keypackage_claim_id: ProtocolOpaqueId,
    pub group_id: ProtocolOpaqueId,
    pub mls_generation: u64,
    pub expected_epoch: u64,
    pub security_frontier_digest: Hash,
    pub join_authorization_basis: Hash,
    pub member_event_draft_digest: Hash,
    pub member_event_id: EventId,
    pub eligible_committer: Did,
    pub committer_commitment_digest: Hash,
    pub ciphersuite: ProtocolOpaqueId,
    pub issuer: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

fn validate_pbft_shape(n: u64, f: u64, quorum: u64, members: usize) -> arkret_wire::Result<()> {
    if n != 3 * f + 1 || quorum != 2 * f + 1 || members != quorum as usize {
        return Err(arkret_wire::Error::Protocol(
            "PBFT threshold must satisfy N=3f+1, q=2f+1 with exactly q members".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_envelopes(
    envelopes: &[ConsensusEnvelope],
    phase: ConsensusPhase,
    registry_digest: &Hash,
    pair_registry_id: &Hash,
    pair_key: &Hash,
    predecessor_head_digest: &Hash,
    operation_id: &ProtocolOperationId,
    attempt: u64,
    view: u64,
    value_digest: &Hash,
    qda_digest: &Hash,
) -> arkret_wire::Result<()> {
    require_unique(envelopes.iter().map(ConsensusEnvelope::replica_id), "PBFT")?;
    if envelopes.iter().any(|envelope| {
        envelope.phase() != phase
            || envelope.registry_digest() != registry_digest
            || envelope.pair_registry_id() != pair_registry_id
            || envelope.pair_key() != pair_key
            || envelope.predecessor_head_digest() != predecessor_head_digest
            || envelope.operation_id() != operation_id
            || envelope.attempt_sequence() != attempt
            || envelope.view() != view
            || envelope.value_digest() != value_digest
            || envelope.qda_certificate_digest() != qda_digest
    }) {
        return Err(arkret_wire::Error::Protocol(
            "PBFT envelope coordinates do not match certificate".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_envelope_coordinates(
    envelope: &ConsensusEnvelope,
    registry_digest: &Hash,
    pair_registry_id: &Hash,
    pair_key: &Hash,
    predecessor_head_digest: &Hash,
    operation_id: &ProtocolOperationId,
    attempt: u64,
    view: u64,
    value_digest: &Hash,
    qda_digest: &Hash,
) -> arkret_wire::Result<()> {
    if envelope.registry_digest() != registry_digest
        || envelope.pair_registry_id() != pair_registry_id
        || envelope.pair_key() != pair_key
        || envelope.predecessor_head_digest() != predecessor_head_digest
        || envelope.operation_id() != operation_id
        || envelope.attempt_sequence() != attempt
        || envelope.view() != view
        || envelope.value_digest() != value_digest
        || envelope.qda_certificate_digest() != qda_digest
    {
        return Err(arkret_wire::Error::Protocol(
            "PBFT envelope coordinates do not match certificate".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn direct_conversation_create_discriminator_is_a_boolean_constant() {
        let lookup = json!({
            "peer": {"kind":"human", "principal_id":"did:web:alice.example"},
            "create": false
        });
        assert!(matches!(
            serde_json::from_value::<DirectConversationResolveRequestBody>(lookup).unwrap(),
            DirectConversationResolveRequestBody::Lookup(_)
        ));
        assert!(
            serde_json::from_value::<DirectConversationLookupRequestBody>(json!({
                "peer": {"kind":"human", "principal_id":"did:web:alice.example"},
                "create": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DirectConversationResolveRequestBody>(json!({
                "peer": {"kind":"human", "principal_id":"did:web:alice.example"},
                "create": "false"
            }))
            .is_err()
        );
    }
}

fn require_unique<'a>(
    values: impl Iterator<Item = &'a Did>,
    label: &str,
) -> arkret_wire::Result<()> {
    let values = values.map(Did::as_str).collect::<Vec<_>>();
    if values.iter().copied().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(arkret_wire::Error::Protocol(format!(
            "{label} signer identities must be distinct"
        )));
    }
    Ok(())
}

fn domain_hash<T: Serialize>(label: &str, value: &T) -> arkret_wire::Result<Hash> {
    let canonical = arkret_canonical::canonical_json_bytes(value)?;
    let mut preimage = format!("{label}\n").into_bytes();
    preimage.extend(canonical);
    Hash::new(arkret_canonical::canonical::sha256_digest(preimage))
        .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))
}
