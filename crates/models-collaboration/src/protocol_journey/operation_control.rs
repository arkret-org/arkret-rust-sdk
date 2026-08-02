use std::collections::BTreeSet;

use arkret_models_crypto::PeerKeyPackagesClaimRequestBody;
use arkret_wire::{Base64UrlString, DeviceId, Did, EventId, Hash, RealmId, StrandId};
pub use arkret_wire::{
    MembershipCompensationAction, MembershipCompensationCasToken,
    MembershipCompensationDelegationCore, MembershipCompensationDelegationRef,
    MembershipCompensationExecutorDelegation, MembershipCompensationSubmissionEvidence,
    MembershipCompensationTerminalCertificate, MembershipJoinAcceptedProof,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{ContactPeer, ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature, string_marker};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct EffectValueCore {
    pub pair_registry_id: ProtocolOpaqueId,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub effect_id: ProtocolOpaqueId,
    pub effect_digest: Hash,
    pub destination: Did,
    pub expected_host_epoch: u64,
    pub predecessor_head_digest: Hash,
    pub journal_root: Hash,
}

impl EffectValueCore {
    pub fn value_digest(&self) -> arkret_wire::Result<Hash> {
        let bytes = arkret_canonical::canonical_json_bytes(self)?;
        Hash::new(arkret_canonical::canonical::sha256_digest(bytes))
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))
    }
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
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ConsensusEnvelope {
    pub domain: ConsensusEnvelopeDomain,
    pub pair_registry_id: ProtocolOpaqueId,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub view: u64,
    pub phase: ConsensusPhase,
    pub value_digest: Hash,
    pub qda_certificate_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_certificate_digest: Option<Hash>,
    pub replica_id: Did,
    pub signature: ProtocolSignature,
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
    pub pair_registry_id: ProtocolOpaqueId,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub view: u64,
    pub value_digest: Hash,
    pub qda_certificate_digest: Hash,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub prepares: Vec<ConsensusEnvelope>,
}

impl PreparedCertificate {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_pbft_shape(self.n, self.f, self.quorum, self.prepares.len())?;
        validate_envelopes(
            &self.prepares,
            ConsensusPhase::Prepare,
            &self.pair_registry_id,
            &self.pair_key,
            &self.operation_id,
            self.attempt_sequence,
            self.view,
            &self.value_digest,
            &self.qda_certificate_digest,
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
        pair_registry_id: ProtocolOpaqueId,
        pair_key: Hash,
        operation_id: ProtocolOperationId,
        attempt_sequence: u64,
        from_view: u64,
        target_view: u64,
        replica_id: Did,
        signature: ProtocolSignature,
    },
    Prepared {
        domain: ViewChangeDomain,
        pair_registry_id: ProtocolOpaqueId,
        pair_key: Hash,
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
    pub pair_registry_id: ProtocolOpaqueId,
    pub pair_key: Hash,
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
        )
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
    pub pair_registry_id: ProtocolOpaqueId,
    pub pair_key: Hash,
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
            || self.proposal.phase != ConsensusPhase::PrePrepare
            || self.proposal.view != self.view
            || self.proposal.replica_id != self.proposer_id
            || self.proposal.value_digest != self.selected_value_digest
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

string_marker!(
    QdaReceiptDomain,
    V1,
    "ak.direct-conversation.qda-receipt.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct QdaReceipt {
    pub domain: QdaReceiptDomain,
    pub pair_registry_id: ProtocolOpaqueId,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub effect_id: ProtocolOpaqueId,
    pub value_digest: Hash,
    pub journal_root: Hash,
    pub destination: Did,
    pub expected_host_epoch: u64,
    pub replica_id: Did,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct QdaCertificate {
    pub pair_registry_id: ProtocolOpaqueId,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub effect_id: ProtocolOpaqueId,
    pub value_digest: Hash,
    pub journal_root: Hash,
    pub destination: Did,
    pub expected_host_epoch: u64,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub receipts: Vec<QdaReceipt>,
}

impl QdaCertificate {
    pub fn digest(&self) -> arkret_wire::Result<Hash> {
        let bytes = arkret_canonical::canonical_json_bytes(self)?;
        Hash::new(arkret_canonical::canonical::sha256_digest(bytes))
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))
    }

    pub fn validate_for_value(&self, value: &EffectValueCore) -> arkret_wire::Result<()> {
        validate_pbft_shape(self.n, self.f, self.quorum, self.receipts.len())?;
        let value_digest = value.value_digest()?;
        if self.pair_registry_id != value.pair_registry_id
            || self.pair_key != value.pair_key
            || self.operation_id != value.operation_id
            || self.attempt_sequence != value.attempt_sequence
            || self.effect_id != value.effect_id
            || self.value_digest != value_digest
            || self.journal_root != value.journal_root
            || self.destination != value.destination
            || self.expected_host_epoch != value.expected_host_epoch
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
            receipt.pair_registry_id != self.pair_registry_id
                || receipt.pair_key != self.pair_key
                || receipt.operation_id != self.operation_id
                || receipt.attempt_sequence != self.attempt_sequence
                || receipt.effect_id != self.effect_id
                || receipt.value_digest != self.value_digest
                || receipt.journal_root != self.journal_root
                || receipt.destination != self.destination
                || receipt.expected_host_epoch != self.expected_host_epoch
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
    pub pair_registry_id: ProtocolOpaqueId,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub attempt_sequence: u64,
    pub view: u64,
    pub value_digest: Hash,
    pub qda_certificate_digest: Hash,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub commits: Vec<ConsensusEnvelope>,
}

impl QcommitCertificate {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_pbft_shape(self.n, self.f, self.quorum, self.commits.len())?;
        validate_envelopes(
            &self.commits,
            ConsensusPhase::Commit,
            &self.pair_registry_id,
            &self.pair_key,
            &self.operation_id,
            self.attempt_sequence,
            self.view,
            &self.value_digest,
            &self.qda_certificate_digest,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ExecutionBundle {
    pub value_core: EffectValueCore,
    pub qda_certificate: QdaCertificate,
    pub per_view_certificates: Vec<PerViewCertificate>,
    pub qcommit_certificate: QcommitCertificate,
    pub authenticated_encrypted_journal_bytes: Base64UrlString,
}

impl ExecutionBundle {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.per_view_certificates.is_empty() {
            return Err(arkret_wire::Error::Protocol(
                "ExecutionBundle requires per-view ancestry".to_owned(),
            ));
        }
        self.qda_certificate.validate_for_value(&self.value_core)?;
        self.qcommit_certificate.validate()?;
        if self.qcommit_certificate.value_digest != self.value_core.value_digest()?
            || self.qcommit_certificate.qda_certificate_digest != self.qda_certificate.digest()?
        {
            return Err(arkret_wire::Error::Protocol(
                "qCOMMIT does not bind the ExecutionBundle value/qDA".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OperationControlAuthorization {
    pub domain_policy_digest: Hash,
    pub pair_registry_id: ProtocolOpaqueId,
    pub pair_key: Hash,
    pub operation_id: ProtocolOperationId,
    pub origin_coordinator: Did,
    pub replicas: Vec<Did>,
    pub n: u64,
    pub f: u64,
    pub quorum: u64,
    pub epoch_policy: Hash,
    pub requester_signature: ProtocolSignature,
}

impl OperationControlAuthorization {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_pbft_shape(self.n, self.f, self.quorum, self.replicas.len())?;
        require_unique(self.replicas.iter(), "operation-control replica")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AttemptAdvanceValue {
    pub operation_id: ProtocolOperationId,
    pub from_attempt: u64,
    pub to_attempt: u64,
    pub cleanup_terminal_proof: Hash,
    pub fresh_target_authorization: Hash,
    pub unclaimed_keypackage_ref: ProtocolOpaqueId,
    pub claim_request_digest: Hash,
}

impl AttemptAdvanceValue {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.from_attempt == 0 || self.to_attempt != self.from_attempt + 1 {
            return Err(arkret_wire::Error::Protocol(
                "attempt advance must increment exactly once".to_owned(),
            ));
        }
        Ok(())
    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationCreateRequestBody {
    pub peer: ContactPeer,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub create: DirectConversationCreateMarker,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: ProtocolOpaqueId,
    pub operation_control_authorization: OperationControlAuthorization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_claim_request: Option<PeerKeyPackagesClaimRequestBody>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationResolveRequestBody {
    Lookup(DirectConversationLookupRequestBody),
    Create(DirectConversationCreateRequestBody),
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
    registry: &ProtocolOpaqueId,
    pair_key: &Hash,
    operation_id: &ProtocolOperationId,
    attempt: u64,
    view: u64,
    value_digest: &Hash,
    qda_digest: &Hash,
) -> arkret_wire::Result<()> {
    require_unique(
        envelopes.iter().map(|envelope| &envelope.replica_id),
        "PBFT",
    )?;
    if envelopes.iter().any(|envelope| {
        envelope.phase != phase
            || &envelope.pair_registry_id != registry
            || &envelope.pair_key != pair_key
            || &envelope.operation_id != operation_id
            || envelope.attempt_sequence != attempt
            || envelope.view != view
            || &envelope.value_digest != value_digest
            || &envelope.qda_certificate_digest != qda_digest
    }) {
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
