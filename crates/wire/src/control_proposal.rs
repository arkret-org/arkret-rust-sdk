//! Bounded decisions for receipted CBA Control Move proposals.
//!
//! A proposal receipt is assembled from independently signed authority-member
//! receipts. Signed reject and signed defer decisions carry a quorum proof set,
//! but only inclusion in an accepted Seal provides control-plane finality.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::{Did, Hash, PayloadSignature, RealmId, canonical};

pub const MAX_PROPOSAL_DECISION_WINDOW: Duration = Duration::hours(24);
pub const MAX_PROPOSAL_ABSOLUTE_HORIZON: Duration = Duration::hours(72);
pub const MAX_PROPOSAL_DEFERS: u8 = 2;
pub const MAX_PROPOSAL_RECEIPT_MEMBERS: usize = 32;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlProposalReceiptKind {
    ProposalReceipt,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlProposalRejectReason {
    CapabilityDenied,
    CasConflict,
    PolicyDenied,
    SchemaViolation,
    Superseded,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlProposalDeferReason {
    DependencyMissing,
    QuorumUnreachable,
    TemporarilyUnavailable,
}

/// One authority member's immutable acknowledgement of a Control Move.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalMemberReceipt {
    pub realm_id: RealmId,
    pub proposal_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub decision_due_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub absolute_due_at: DateTime<Utc>,
    pub authority_set_ref: Hash,
    pub signature: PayloadSignature,
}

/// Canonical quorum set assembled from independently issued member receipts.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlProposalReceipt {
    pub kind: ControlProposalReceiptKind,
    pub realm_id: RealmId,
    pub proposal_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub decision_due_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub absolute_due_at: DateTime<Utc>,
    pub defer_count: u8,
    pub authority_set_ref: Hash,
    pub member_receipts: Vec<ProposalMemberReceipt>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlProposalDecision {
    SignedReject {
        realm_id: RealmId,
        proposal_digest: Hash,
        receipt_digest: Hash,
        #[serde(with = "crate::serde_helpers::canonical_timestamp")]
        decided_at: DateTime<Utc>,
        #[serde(with = "crate::serde_helpers::canonical_timestamp")]
        decision_due_at: DateTime<Utc>,
        #[serde(with = "crate::serde_helpers::canonical_timestamp")]
        absolute_due_at: DateTime<Utc>,
        defer_count: u8,
        reason_code: ControlProposalRejectReason,
        authority_set_ref: Hash,
        proofs: Vec<PayloadSignature>,
    },
    SignedDefer {
        realm_id: RealmId,
        proposal_digest: Hash,
        receipt_digest: Hash,
        #[serde(with = "crate::serde_helpers::canonical_timestamp")]
        decided_at: DateTime<Utc>,
        #[serde(with = "crate::serde_helpers::canonical_timestamp")]
        decision_due_at: DateTime<Utc>,
        #[serde(with = "crate::serde_helpers::canonical_timestamp")]
        absolute_due_at: DateTime<Utc>,
        defer_count: u8,
        reason_code: ControlProposalDeferReason,
        authority_set_ref: Hash,
        proofs: Vec<PayloadSignature>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlProposalDecisionPolicy {
    /// Receiver-relative common member-receipt window. `None` is used only
    /// when validating stored wire data without the originating Realm policy.
    pub receipt_sla: Option<Duration>,
    pub decision_window: Duration,
    pub absolute_horizon: Duration,
    pub max_defers: u8,
}

impl Default for ControlProposalDecisionPolicy {
    fn default() -> Self {
        Self {
            receipt_sla: Some(Duration::hours(24)),
            decision_window: Duration::seconds(30),
            absolute_horizon: Duration::seconds(90),
            max_defers: MAX_PROPOSAL_DEFERS,
        }
    }
}

fn canonical_bytes_without_field<T: Serialize>(value: &T, field: &str) -> Result<Vec<u8>> {
    let mut json = serde_json::to_value(value)?;
    if let Value::Object(map) = &mut json {
        map.remove(field);
    }
    Ok(canonical::canonical_json_bytes(&json)?)
}

fn digest_without_field<T: Serialize>(value: &T, field: &str) -> Result<Hash> {
    Ok(Hash::new(canonical::sha256_digest(
        &canonical_bytes_without_field(value, field)?,
    ))?)
}

fn digest_complete<T: Serialize>(value: &T) -> Result<Hash> {
    let json = serde_json::to_value(value)?;
    Ok(Hash::new(canonical::sha256_digest(
        &canonical::canonical_json_bytes(&json)?,
    ))?)
}

fn validate_signature(
    signature: &PayloadSignature,
    expected_digest: &Hash,
    expected_created_at: DateTime<Utc>,
) -> Result<()> {
    if signature.payload_digest != *expected_digest {
        return Err(Error::Protocol(
            "control proposal proof does not cover the canonical payload".to_owned(),
        ));
    }
    if signature.created_at != expected_created_at {
        return Err(Error::Protocol(
            "control proposal proof created_at does not match the signed statement time".to_owned(),
        ));
    }
    Ok(())
}

fn signer_controller(signature: &PayloadSignature) -> Result<&str> {
    let controller = signature
        .verification_method
        .split_once('#')
        .map(|(controller, _)| controller)
        .filter(|controller| !controller.is_empty())
        .ok_or_else(|| {
            Error::Protocol("control proposal verification_method must be a DID URL".to_owned())
        })?;
    Did::new(controller)?;
    Ok(controller)
}

fn validate_proof_set(
    proofs: &[PayloadSignature],
    expected_digest: &Hash,
    expected_created_at: DateTime<Utc>,
) -> Result<()> {
    if proofs.is_empty() || proofs.len() > MAX_PROPOSAL_RECEIPT_MEMBERS {
        return Err(Error::Protocol(format!(
            "control proposal evidence requires 1..={MAX_PROPOSAL_RECEIPT_MEMBERS} proofs"
        )));
    }
    let mut previous_method: Option<&str> = None;
    let mut controllers = std::collections::BTreeSet::new();
    for proof in proofs {
        validate_signature(proof, expected_digest, expected_created_at)?;
        if previous_method
            .is_some_and(|previous| previous >= proof.verification_method.as_str())
        {
            return Err(Error::Protocol(
                "control proposal proofs must be strictly sorted by verification_method".to_owned(),
            ));
        }
        let controller = signer_controller(proof)?;
        if !controllers.insert(controller) {
            return Err(Error::Protocol(
                "control proposal proofs contain a duplicate authority member".to_owned(),
            ));
        }
        previous_method = Some(&proof.verification_method);
    }
    Ok(())
}

impl ControlProposalDecisionPolicy {
    pub fn protocol_maximum() -> Self {
        Self {
            receipt_sla: None,
            decision_window: MAX_PROPOSAL_DECISION_WINDOW,
            absolute_horizon: MAX_PROPOSAL_ABSOLUTE_HORIZON,
            max_defers: MAX_PROPOSAL_DEFERS,
        }
    }

    pub fn validate(self) -> Result<()> {
        if self.receipt_sla.is_some_and(|receipt_sla| receipt_sla < Duration::zero()) {
            return Err(Error::Protocol(
                "proposal receipt_sla must be non-negative".to_owned(),
            ));
        }
        if self.decision_window <= Duration::zero()
            || self.decision_window > MAX_PROPOSAL_DECISION_WINDOW
        {
            return Err(Error::Protocol(
                "proposal decision window must be within 1ms..=24h".to_owned(),
            ));
        }
        if self.absolute_horizon < self.decision_window
            || self.absolute_horizon > MAX_PROPOSAL_ABSOLUTE_HORIZON
        {
            return Err(Error::Protocol(
                "proposal absolute horizon must cover the first decision window and be <=72h"
                    .to_owned(),
            ));
        }
        if self.max_defers > MAX_PROPOSAL_DEFERS {
            return Err(Error::Protocol(
                "proposal max_defers exceeds the protocol ceiling of 2".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ProposalMemberReceipt {
    pub fn canonical_bytes_for_signature(&self) -> Result<Vec<u8>> {
        canonical_bytes_without_field(self, "signature")
    }

    pub fn member_digest(&self) -> Result<Hash> {
        digest_without_field(self, "signature")
    }

    pub fn validate_structural(&self, policy: ControlProposalDecisionPolicy) -> Result<()> {
        policy.validate()?;
        if self.decision_due_at - self.received_at != policy.decision_window {
            return Err(Error::Protocol(
                "proposal member decision_due_at does not equal the effective decision window"
                    .to_owned(),
            ));
        }
        if self.absolute_due_at - self.received_at != policy.absolute_horizon {
            return Err(Error::Protocol(
                "proposal member absolute_due_at does not equal the effective absolute horizon"
                    .to_owned(),
            ));
        }
        validate_signature(&self.signature, &self.member_digest()?, self.received_at)
    }
}

impl ControlProposalReceipt {
    /// Digest of the complete canonical receipt set, including member proofs.
    pub fn receipt_digest(&self) -> Result<Hash> {
        digest_complete(self)
    }

    pub fn validate_structural(&self, policy: ControlProposalDecisionPolicy) -> Result<()> {
        policy.validate()?;
        if self.defer_count != 0 {
            return Err(Error::Protocol(
                "proposal receipt defer_count must be zero".to_owned(),
            ));
        }
        if self.member_receipts.is_empty()
            || self.member_receipts.len() > MAX_PROPOSAL_RECEIPT_MEMBERS
        {
            return Err(Error::Protocol(format!(
                "proposal receipt requires 1..={MAX_PROPOSAL_RECEIPT_MEMBERS} member receipts"
            )));
        }

        let mut previous_method: Option<&str> = None;
        let mut min_received_at = self.member_receipts[0].received_at;
        let mut max_received_at = self.member_receipts[0].received_at;
        let mut min_decision_due_at = self.member_receipts[0].decision_due_at;
        let mut min_absolute_due_at = self.member_receipts[0].absolute_due_at;

        for member in &self.member_receipts {
            member.validate_structural(policy)?;
            if member.realm_id != self.realm_id
                || member.proposal_digest != self.proposal_digest
                || member.authority_set_ref != self.authority_set_ref
            {
                return Err(Error::Protocol(
                    "proposal member receipt does not preserve the receipt-set binding".to_owned(),
                ));
            }
            if previous_method.is_some_and(|previous| {
                previous >= member.signature.verification_method.as_str()
            }) {
                return Err(Error::Protocol(
                    "proposal member receipts must be strictly sorted by verification_method"
                        .to_owned(),
                ));
            }
            previous_method = Some(&member.signature.verification_method);
            min_received_at = min_received_at.min(member.received_at);
            max_received_at = max_received_at.max(member.received_at);
            min_decision_due_at = min_decision_due_at.min(member.decision_due_at);
            min_absolute_due_at = min_absolute_due_at.min(member.absolute_due_at);
        }

        if policy
            .receipt_sla
            .is_some_and(|receipt_sla| max_received_at - min_received_at > receipt_sla)
        {
            return Err(Error::Protocol(
                "proposal member receipts exceed the effective receipt SLA window".to_owned(),
            ));
        }
        if self.received_at != max_received_at
            || self.decision_due_at != min_decision_due_at
            || self.absolute_due_at != min_absolute_due_at
            || self.received_at > self.decision_due_at
            || self.decision_due_at > self.absolute_due_at
        {
            return Err(Error::Protocol(
                "proposal receipt-set deadlines do not match the canonical member reduction"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_authority_quorum(
        &self,
        authority_members: &[Did],
        threshold: usize,
    ) -> Result<()> {
        let authority_member_set = authority_members
            .iter()
            .map(Did::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        if threshold == 0
            || threshold > authority_member_set.len()
            || authority_member_set.len() != authority_members.len()
        {
            return Err(Error::Protocol(
                "control proposal authority set or threshold is invalid".to_owned(),
            ));
        }
        let valid_signers = self
            .member_receipts
            .iter()
            .map(|member| signer_controller(&member.signature))
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        if !valid_signers.is_subset(&authority_member_set) || valid_signers.len() < threshold {
            return Err(Error::Protocol(
                "control proposal member receipts do not satisfy authority membership and quorum"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl ControlProposalDecision {
    pub fn canonical_bytes_for_signature(&self) -> Result<Vec<u8>> {
        canonical_bytes_without_field(self, "proofs")
    }

    pub fn decision_digest(&self) -> Result<Hash> {
        digest_without_field(self, "proofs")
    }

    fn proofs(&self) -> &[PayloadSignature] {
        match self {
            Self::SignedReject { proofs, .. } | Self::SignedDefer { proofs, .. } => proofs,
        }
    }

    pub fn validate_authority_quorum(
        &self,
        authority_members: &[Did],
        threshold: usize,
    ) -> Result<()> {
        let authority_member_set = authority_members
            .iter()
            .map(Did::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        if threshold == 0
            || threshold > authority_member_set.len()
            || authority_member_set.len() != authority_members.len()
        {
            return Err(Error::Protocol(
                "control proposal decision authority set or threshold is invalid".to_owned(),
            ));
        }
        let valid_signers = self
            .proofs()
            .iter()
            .map(signer_controller)
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        if !valid_signers.is_subset(&authority_member_set) || valid_signers.len() < threshold {
            return Err(Error::Protocol(
                "control proposal decision proofs do not satisfy authority membership and quorum"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn defer_count(&self) -> u8 {
        match self {
            Self::SignedReject { defer_count, .. } | Self::SignedDefer { defer_count, .. } => {
                *defer_count
            }
        }
    }

    pub fn decision_due_at(&self) -> DateTime<Utc> {
        match self {
            Self::SignedReject {
                decision_due_at, ..
            }
            | Self::SignedDefer {
                decision_due_at, ..
            } => *decision_due_at,
        }
    }

    pub fn decided_at(&self) -> DateTime<Utc> {
        match self {
            Self::SignedReject { decided_at, .. } | Self::SignedDefer { decided_at, .. } => {
                *decided_at
            }
        }
    }

    pub fn is_reject(&self) -> bool {
        matches!(self, Self::SignedReject { .. })
    }

    pub fn validate_chain(
        &self,
        receipt: &ControlProposalReceipt,
        previous_defers: &[ControlProposalDecision],
        policy: ControlProposalDecisionPolicy,
    ) -> Result<()> {
        receipt.validate_structural(policy)?;
        if previous_defers.len() > usize::from(policy.max_defers) {
            return Err(Error::Protocol(
                "proposal decision chain exceeds max_defers".to_owned(),
            ));
        }
        let receipt_digest = receipt.receipt_digest()?;
        let expected_count = u8::try_from(previous_defers.len())
            .map_err(|_| Error::Protocol("proposal defer count overflow".to_owned()))?;
        let previous_due_at = previous_defers
            .last()
            .map(Self::decision_due_at)
            .unwrap_or(receipt.decision_due_at);

        for (index, decision) in previous_defers.iter().enumerate() {
            if !matches!(decision, Self::SignedDefer { .. }) {
                return Err(Error::Protocol(
                    "only signed_defer may precede another proposal decision".to_owned(),
                ));
            }
            decision.validate_chain(receipt, &previous_defers[..index], policy)?;
        }

        let (
            realm_id,
            proposal_digest,
            bound_receipt_digest,
            absolute_due_at,
            authority_set_ref,
        ) = match self {
            Self::SignedReject {
                realm_id,
                proposal_digest,
                receipt_digest,
                absolute_due_at,
                authority_set_ref,
                ..
            }
            | Self::SignedDefer {
                realm_id,
                proposal_digest,
                receipt_digest,
                absolute_due_at,
                authority_set_ref,
                ..
            } => (
                realm_id,
                proposal_digest,
                receipt_digest,
                absolute_due_at,
                authority_set_ref,
            ),
        };
        if realm_id != &receipt.realm_id
            || proposal_digest != &receipt.proposal_digest
            || bound_receipt_digest != &receipt_digest
            || absolute_due_at != &receipt.absolute_due_at
            || authority_set_ref != &receipt.authority_set_ref
        {
            return Err(Error::Protocol(
                "proposal decision does not preserve its receipt binding".to_owned(),
            ));
        }

        match self {
            Self::SignedReject {
                decision_due_at,
                defer_count,
                ..
            } => {
                if *defer_count != expected_count || *decision_due_at != previous_due_at {
                    return Err(Error::Protocol(
                        "signed_reject must bind the current decision window".to_owned(),
                    ));
                }
            }
            Self::SignedDefer {
                decision_due_at,
                defer_count,
                ..
            } => {
                if expected_count >= policy.max_defers || *defer_count != expected_count + 1 {
                    return Err(Error::Protocol(
                        "signed_defer exceeds max_defers or skips defer_count".to_owned(),
                    ));
                }
                if *decision_due_at <= previous_due_at || *decision_due_at > receipt.absolute_due_at
                {
                    return Err(Error::Protocol(
                        "signed_defer must strictly advance within absolute_due_at".to_owned(),
                    ));
                }
            }
        }
        validate_proof_set(
            self.proofs(),
            &self.decision_digest()?,
            self.decided_at(),
        )
    }

    pub fn satisfied_current_deadline(&self, previous_due_at: DateTime<Utc>) -> bool {
        self.decided_at() <= previous_due_at
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_775_000_000 + seconds, 0).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn signature_for(
        verification_method: &str,
        payload_digest: Hash,
        created_at: DateTime<Utc>,
    ) -> PayloadSignature {
        PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.to_owned(),
            payload_digest,
            created_at,
            jws: "e30..c2ln".to_owned(),
        }
    }

    fn member_for(verification_method: &str, received_at: DateTime<Utc>) -> ProposalMemberReceipt {
        let policy = ControlProposalDecisionPolicy::default();
        let mut member = ProposalMemberReceipt {
            realm_id: RealmId::new("ak:realm:018f6b1d-7a20-7abc-8def-0123456789ab").unwrap(),
            proposal_digest: hash('a'),
            received_at,
            decision_due_at: received_at + policy.decision_window,
            absolute_due_at: received_at + policy.absolute_horizon,
            authority_set_ref: hash('b'),
            signature: signature_for(verification_method, hash('0'), received_at),
        };
        member.signature.payload_digest = member.member_digest().unwrap();
        member
    }

    fn receipt() -> ControlProposalReceipt {
        let member = member_for(
            "did:webvh:z6mkfixture:authority.example#notary-1",
            at(0),
        );
        ControlProposalReceipt {
            kind: ControlProposalReceiptKind::ProposalReceipt,
            realm_id: member.realm_id.clone(),
            proposal_digest: member.proposal_digest.clone(),
            received_at: member.received_at,
            decision_due_at: member.decision_due_at,
            absolute_due_at: member.absolute_due_at,
            defer_count: 0,
            authority_set_ref: member.authority_set_ref.clone(),
            member_receipts: vec![member],
        }
    }

    fn defer(
        receipt: &ControlProposalReceipt,
        count: u8,
        decided_at: DateTime<Utc>,
        due_at: DateTime<Utc>,
    ) -> ControlProposalDecision {
        let mut decision = ControlProposalDecision::SignedDefer {
            realm_id: receipt.realm_id.clone(),
            proposal_digest: receipt.proposal_digest.clone(),
            receipt_digest: receipt.receipt_digest().unwrap(),
            decided_at,
            decision_due_at: due_at,
            absolute_due_at: receipt.absolute_due_at,
            defer_count: count,
            reason_code: ControlProposalDeferReason::QuorumUnreachable,
            authority_set_ref: receipt.authority_set_ref.clone(),
            proofs: vec![signature_for(
                "did:webvh:z6mkfixture:authority.example#notary-1",
                hash('0'),
                decided_at,
            )],
        };
        let digest = decision.decision_digest().unwrap();
        if let ControlProposalDecision::SignedDefer { proofs, .. } = &mut decision {
            proofs[0].payload_digest = digest;
        }
        decision
    }

    #[test]
    fn receipt_reduces_member_deadlines_and_preserves_canonical_order() {
        let alpha = member_for(
            "did:webvh:z6mkfixture:authority-a.example#notary",
            at(0),
        );
        let bravo = member_for(
            "did:webvh:z6mkfixture:authority-b.example#notary",
            at(2),
        );
        let mut receipt = ControlProposalReceipt {
            kind: ControlProposalReceiptKind::ProposalReceipt,
            realm_id: alpha.realm_id.clone(),
            proposal_digest: alpha.proposal_digest.clone(),
            received_at: bravo.received_at,
            decision_due_at: alpha.decision_due_at,
            absolute_due_at: alpha.absolute_due_at,
            defer_count: 0,
            authority_set_ref: alpha.authority_set_ref.clone(),
            member_receipts: vec![alpha, bravo],
        };
        receipt
            .validate_structural(ControlProposalDecisionPolicy::default())
            .unwrap();

        receipt.member_receipts.reverse();
        assert!(
            receipt
                .validate_structural(ControlProposalDecisionPolicy::default())
                .is_err()
        );
    }

    #[test]
    fn receipt_requires_exact_member_deadlines() {
        let mut receipt = receipt();
        receipt.member_receipts[0].absolute_due_at = at(91);
        receipt.member_receipts[0].signature.payload_digest =
            receipt.member_receipts[0].member_digest().unwrap();
        receipt.absolute_due_at = at(91);
        assert!(
            receipt
                .validate_structural(ControlProposalDecisionPolicy::default())
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );
    }

    #[test]
    fn defer_chain_is_sequential_and_cannot_extend_absolute_deadline() {
        let receipt = receipt();
        let first = defer(&receipt, 1, at(20), at(60));
        first
            .validate_chain(&receipt, &[], ControlProposalDecisionPolicy::default())
            .unwrap();
        let second = defer(&receipt, 2, at(50), at(90));
        second
            .validate_chain(
                &receipt,
                std::slice::from_ref(&first),
                ControlProposalDecisionPolicy::default(),
            )
            .unwrap();

        let third = defer(&receipt, 3, at(80), at(90));
        assert!(
            third
                .validate_chain(
                    &receipt,
                    &[first, second],
                    ControlProposalDecisionPolicy::default(),
                )
                .is_err()
        );
    }

    #[test]
    fn receipt_and_decision_require_distinct_authority_members() {
        let authority = Did::new("did:webvh:z6mkfixture:authority.example").unwrap();
        let bravo = Did::new("did:webvh:z6mkfixture:bravo.example").unwrap();
        let members = [authority, bravo];
        let mut receipt = receipt();
        assert!(receipt.validate_authority_quorum(&members, 2).is_err());

        let bravo_member = member_for(
            "did:webvh:z6mkfixture:bravo.example#notary-1",
            receipt.received_at,
        );
        receipt.member_receipts.push(bravo_member);
        receipt.validate_authority_quorum(&members, 2).unwrap();

        let mut decision = defer(&receipt, 1, at(20), at(60));
        assert!(decision.validate_authority_quorum(&members, 2).is_err());
        let digest = decision.decision_digest().unwrap();
        if let ControlProposalDecision::SignedDefer { proofs, .. } = &mut decision {
            proofs.push(signature_for(
                "did:webvh:z6mkfixture:bravo.example#notary-1",
                digest,
                at(20),
            ));
        }
        decision.validate_authority_quorum(&members, 2).unwrap();
    }
}
