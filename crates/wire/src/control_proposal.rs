//! Bounded decisions for receipted CBA Control Move proposals.
//!
//! A proposal receipt commits the first decision deadline and an immutable
//! absolute deadline. Signed reject and signed defer are verifiable authority
//! decisions, but only inclusion in an accepted Seal provides control-plane
//! finality.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::{Hash, PayloadSignature, RealmId, canonical};

pub const MAX_PROPOSAL_DECISION_WINDOW: Duration = Duration::hours(24);
pub const MAX_PROPOSAL_ABSOLUTE_HORIZON: Duration = Duration::hours(72);
pub const MAX_PROPOSAL_DEFERS: u8 = 2;

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
    pub signature: PayloadSignature,
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
        signature: PayloadSignature,
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
        signature: PayloadSignature,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlProposalDecisionPolicy {
    pub decision_window: Duration,
    pub absolute_horizon: Duration,
    pub max_defers: u8,
}

impl Default for ControlProposalDecisionPolicy {
    fn default() -> Self {
        Self {
            decision_window: Duration::seconds(30),
            absolute_horizon: Duration::seconds(90),
            max_defers: MAX_PROPOSAL_DEFERS,
        }
    }
}

fn digest_without_signature<T: Serialize>(value: &T) -> Result<Hash> {
    Ok(Hash::new(canonical::sha256_digest(
        &canonical_bytes_without_signature(value)?,
    ))?)
}

fn canonical_bytes_without_signature<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut json = serde_json::to_value(value)?;
    if let Value::Object(map) = &mut json {
        map.remove("signature");
    }
    Ok(canonical::canonical_json_bytes(&json)?)
}

fn validate_signature(
    signature: &PayloadSignature,
    expected_digest: &Hash,
    expected_created_at: DateTime<Utc>,
) -> Result<()> {
    if signature.payload_digest != *expected_digest {
        return Err(Error::Protocol(
            "control proposal signature does not cover the canonical payload".to_owned(),
        ));
    }
    if signature.created_at != expected_created_at {
        return Err(Error::Protocol(
            "control proposal signature created_at does not match the signed decision time"
                .to_owned(),
        ));
    }
    Ok(())
}

impl ControlProposalDecisionPolicy {
    pub fn protocol_maximum() -> Self {
        Self {
            decision_window: MAX_PROPOSAL_DECISION_WINDOW,
            absolute_horizon: MAX_PROPOSAL_ABSOLUTE_HORIZON,
            max_defers: MAX_PROPOSAL_DEFERS,
        }
    }

    pub fn validate(self) -> Result<()> {
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

impl ControlProposalReceipt {
    pub fn canonical_bytes_for_signature(&self) -> Result<Vec<u8>> {
        canonical_bytes_without_signature(self)
    }

    pub fn receipt_digest(&self) -> Result<Hash> {
        digest_without_signature(self)
    }

    pub fn validate_structural(&self, policy: ControlProposalDecisionPolicy) -> Result<()> {
        policy.validate()?;
        if self.defer_count != 0 {
            return Err(Error::Protocol(
                "proposal receipt defer_count must be zero".to_owned(),
            ));
        }
        let decision_window = self.decision_due_at - self.received_at;
        if decision_window <= Duration::zero() || decision_window > policy.decision_window {
            return Err(Error::Protocol(
                "proposal receipt decision_due_at exceeds the effective decision window".to_owned(),
            ));
        }
        let absolute_horizon = self.absolute_due_at - self.received_at;
        if self.absolute_due_at < self.decision_due_at || absolute_horizon > policy.absolute_horizon
        {
            return Err(Error::Protocol(
                "proposal receipt absolute_due_at is outside the effective absolute horizon"
                    .to_owned(),
            ));
        }
        validate_signature(&self.signature, &self.receipt_digest()?, self.received_at)
    }
}

impl ControlProposalDecision {
    pub fn canonical_bytes_for_signature(&self) -> Result<Vec<u8>> {
        canonical_bytes_without_signature(self)
    }

    pub fn decision_digest(&self) -> Result<Hash> {
        digest_without_signature(self)
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
            signature,
        ) = match self {
            Self::SignedReject {
                realm_id,
                proposal_digest,
                receipt_digest,
                absolute_due_at,
                authority_set_ref,
                signature,
                ..
            }
            | Self::SignedDefer {
                realm_id,
                proposal_digest,
                receipt_digest,
                absolute_due_at,
                authority_set_ref,
                signature,
                ..
            } => (
                realm_id,
                proposal_digest,
                receipt_digest,
                absolute_due_at,
                authority_set_ref,
                signature,
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
        validate_signature(signature, &self.decision_digest()?, self.decided_at())
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

    fn signature(payload_digest: Hash, created_at: DateTime<Utc>) -> PayloadSignature {
        PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:authority.example#notary-1".to_owned(),
            payload_digest,
            created_at,
            jws: "e30..c2ln".to_owned(),
        }
    }

    fn receipt() -> ControlProposalReceipt {
        let mut receipt = ControlProposalReceipt {
            kind: ControlProposalReceiptKind::ProposalReceipt,
            realm_id: RealmId::new("ak:realm:018f6b1d-7a20-7abc-8def-0123456789ab").unwrap(),
            proposal_digest: hash('a'),
            received_at: at(0),
            decision_due_at: at(30),
            absolute_due_at: at(90),
            defer_count: 0,
            authority_set_ref: hash('b'),
            signature: signature(hash('0'), at(0)),
        };
        receipt.signature.payload_digest = receipt.receipt_digest().unwrap();
        receipt
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
            signature: signature(hash('0'), decided_at),
        };
        let digest = decision.decision_digest().unwrap();
        if let ControlProposalDecision::SignedDefer { signature, .. } = &mut decision {
            signature.payload_digest = digest;
        }
        decision
    }

    #[test]
    fn receipt_enforces_effective_and_protocol_deadlines() {
        receipt()
            .validate_structural(ControlProposalDecisionPolicy::default())
            .unwrap();
        let mut invalid = receipt();
        invalid.absolute_due_at = at(91);
        invalid.signature.payload_digest = invalid.receipt_digest().unwrap();
        assert!(
            invalid
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
    fn late_decision_is_valid_evidence_but_does_not_satisfy_the_deadline() {
        let receipt = receipt();
        let late = defer(&receipt, 1, at(31), at(60));
        late.validate_chain(&receipt, &[], ControlProposalDecisionPolicy::default())
            .unwrap();
        assert!(!late.satisfied_current_deadline(receipt.decision_due_at));
    }

    #[test]
    fn decision_chain_revalidates_every_signed_prefix() {
        let receipt = receipt();
        let mut first = defer(&receipt, 1, at(20), at(60));
        let second = defer(&receipt, 2, at(50), at(90));
        if let ControlProposalDecision::SignedDefer { signature, .. } = &mut first {
            signature.payload_digest = hash('f');
        }
        assert!(
            second
                .validate_chain(
                    &receipt,
                    std::slice::from_ref(&first),
                    ControlProposalDecisionPolicy::default(),
                )
                .is_err()
        );
    }
}
