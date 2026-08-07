//! Bounded decisions for acknowledged CBA Control Move proposals.
//!
//! A Control Proposal Ack commits the first decision deadline and an immutable
//! absolute deadline. Signed reject and signed defer are verifiable authority
//! decisions, but only inclusion in an accepted Seal provides control-plane
//! finality.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::notary::NotaryValue;
use crate::{
    AuthorizationLease, CbaProofBundle, Did, Event, EventSubmitContext, Hash, PayloadSignature,
    PayloadSigner, RealmId, canonical,
};

pub const MAX_PROPOSAL_DECISION_WINDOW: Duration = Duration::hours(24);
pub const MAX_PROPOSAL_ABSOLUTE_HORIZON: Duration = Duration::hours(72);
pub const MAX_PROPOSAL_INTAKE_SLA: Duration = Duration::hours(24);
pub const MAX_PROPOSAL_DEFERS: u8 = 2;
pub const MAX_PROPOSAL_AUTHORITY_PROOFS: usize = 32;
pub const MAX_PROPOSAL_AUTHORITY_ACKS: usize = MAX_PROPOSAL_AUTHORITY_PROOFS;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlProposalAckKind {
    SignedAck,
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
pub struct ControlProposalAuthorityAck {
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlProposalAck {
    pub kind: ControlProposalAckKind,
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
    pub authority_acks: Vec<ControlProposalAuthorityAck>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlProposalDecision {
    SignedReject {
        realm_id: RealmId,
        proposal_digest: Hash,
        proposal_ack_digest: Hash,
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
        proposal_ack_digest: Hash,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlProposalAckIssueRequest {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
    pub authorization_lease: AuthorizationLease,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlProposalAckIssueOutcome {
    pub authority_ack: ControlProposalAuthorityAck,
}

impl ControlProposalAckIssueRequest {
    pub fn validate_structural(&self) -> Result<()> {
        self.event
            .validate_for_submit_structural_in_context(EventSubmitContext::Standard)?;
        if self.event.seal_basis.is_none() {
            return Err(Error::Protocol(
                "Control Proposal Ack issuance accepts only non-genesis Control Moves".to_owned(),
            ));
        }
        self.authorization_lease.validate_structural()?;
        if self.authorization_lease.actor_id != self.event.actor_id
            || self.authorization_lease.scope_ref != self.event.scope_ref
        {
            return Err(Error::Protocol(
                "Control Proposal Ack authorization lease does not bind the Event".to_owned(),
            ));
        }
        if self.cba_proof_bundles.len() > 64 {
            return Err(Error::Protocol(
                "Control Proposal Ack issuance exceeds 64 CBA proof bundles".to_owned(),
            ));
        }
        for bundle in &self.cba_proof_bundles {
            bundle.validate_structural()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlProposalDecisionPolicy {
    pub proposal_intake_sla: Duration,
    pub decision_window: Duration,
    pub absolute_horizon: Duration,
    pub max_defers: u8,
}

impl Default for ControlProposalDecisionPolicy {
    fn default() -> Self {
        Self {
            proposal_intake_sla: MAX_PROPOSAL_INTAKE_SLA,
            decision_window: Duration::seconds(30),
            absolute_horizon: Duration::seconds(90),
            max_defers: MAX_PROPOSAL_DEFERS,
        }
    }
}

fn digest_without_field<T: Serialize>(value: &T, field: &str) -> Result<Hash> {
    Ok(Hash::new(canonical::sha256_digest(
        &canonical_bytes_without_field(value, field)?,
    ))?)
}

fn canonical_bytes_without_field<T: Serialize>(value: &T, field: &str) -> Result<Vec<u8>> {
    let mut json = serde_json::to_value(value)?;
    if let Value::Object(map) = &mut json {
        map.remove(field);
    }
    Ok(canonical::canonical_json_bytes(&json)?)
}

fn proof_transcript(
    context: &str,
    payload_digest: &Hash,
    verification_method: &str,
    created_at: DateTime<Utc>,
) -> Result<Vec<u8>> {
    canonical::canonical_json_bytes(&serde_json::json!({
        "context": context,
        "payload_digest": payload_digest,
        "verification_method": verification_method,
        "created_at": created_at,
    }))
    .map_err(Into::into)
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

/// Controller DID of a signature's verification method.
///
/// `verification_method` is a [`DidUrl`], so the `#fragment` split is
/// infallible and the "must be a DID URL" shape check that used to live here
/// is now enforced by the type. What remains is the narrower question of
/// whether the controller part is itself a well-formed bare DID.
fn signer_controller(signature: &PayloadSignature) -> Result<&str> {
    let (controller, _) = signature
        .verification_method
        .split_once('#')
        .expect("DidUrl always carries a fragment");
    Did::new(controller)?;
    Ok(controller)
}

fn validate_proofs(
    proofs: &[PayloadSignature],
    expected_digest: &Hash,
    expected_created_at: DateTime<Utc>,
) -> Result<()> {
    if proofs.is_empty() || proofs.len() > MAX_PROPOSAL_AUTHORITY_PROOFS {
        return Err(Error::Protocol(format!(
            "control proposal proof set requires 1..={MAX_PROPOSAL_AUTHORITY_PROOFS} members"
        )));
    }
    let mut previous_method: Option<&str> = None;
    let mut controllers = BTreeSet::new();
    for proof in proofs {
        if previous_method.is_some_and(|previous| previous >= proof.verification_method.as_str()) {
            return Err(Error::Protocol(
                "control proposal proofs must use distinct verification methods in canonical ascending order"
                    .to_owned(),
            ));
        }
        validate_signature(proof, expected_digest, expected_created_at)?;
        if !controllers.insert(signer_controller(proof)?) {
            return Err(Error::Protocol(
                "control proposal proofs contain a duplicate authority member".to_owned(),
            ));
        }
        previous_method = Some(proof.verification_method.as_str());
    }
    Ok(())
}

impl ControlProposalDecisionPolicy {
    pub fn protocol_maximum() -> Self {
        Self {
            proposal_intake_sla: MAX_PROPOSAL_INTAKE_SLA,
            decision_window: MAX_PROPOSAL_DECISION_WINDOW,
            absolute_horizon: MAX_PROPOSAL_ABSOLUTE_HORIZON,
            max_defers: MAX_PROPOSAL_DEFERS,
        }
    }

    pub fn validate(self) -> Result<()> {
        if self.proposal_intake_sla < Duration::zero()
            || self.proposal_intake_sla > MAX_PROPOSAL_INTAKE_SLA
        {
            return Err(Error::Protocol(
                "Control Proposal Ack SLA must be within 0ms..=24h".to_owned(),
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
        if self.max_defers > 0 && self.absolute_horizon == self.decision_window {
            return Err(Error::Protocol(
                "proposal absolute horizon must exceed the decision window when defers are enabled"
                    .to_owned(),
            ));
        }
        if self.max_defers > MAX_PROPOSAL_DEFERS {
            return Err(Error::Protocol(
                "proposal max_defers exceeds the protocol ceiling of 2".to_owned(),
            ));
        }
        if self.max_defers > 0 && self.decision_window == self.absolute_horizon {
            return Err(Error::Protocol(
                "proposal decision window must be shorter than the absolute horizon when defers are enabled"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl ControlProposalAuthorityAck {
    /// Issue one immutable authority-authority Ack with a local Agent,
    /// device, HSM, or service signer.
    ///
    /// The signer signs the same canonical transcript as the HTTP authority
    /// operation. Only the transport hop is omitted.
    pub fn issue_with_signer<S: PayloadSigner + ?Sized>(
        realm_id: RealmId,
        proposal_digest: Hash,
        authority_set_ref: Hash,
        received_at: DateTime<Utc>,
        policy: ControlProposalDecisionPolicy,
        signer: &S,
    ) -> Result<Self> {
        policy.validate()?;
        let received_at = canonical::normalize_timestamp_canonical(received_at);
        let verification_method = signer.verification_method_id().clone();
        let placeholder_digest = Hash::new(format!("sha256:{}", "0".repeat(64)))?;
        let signer_binding = PayloadSignature {
            verification_method: verification_method.clone(),
            payload_digest: placeholder_digest.clone(),
            created_at: received_at,
            jws: String::new(),
            extra: BTreeMap::new(),
        };
        if signer_controller(&signer_binding)? != signer.signer_did().as_str() {
            return Err(Error::Protocol(
                "proposal member signer DID does not control its verification method".to_owned(),
            ));
        }
        let mut member = Self {
            realm_id,
            proposal_digest,
            received_at,
            decision_due_at: received_at + policy.decision_window,
            absolute_due_at: received_at + policy.absolute_horizon,
            authority_set_ref,
            signature: PayloadSignature {
                verification_method,
                payload_digest: placeholder_digest,
                created_at: received_at,
                jws: String::new(),
                extra: BTreeMap::new(),
            },
        };
        member.signature.payload_digest = member.authority_ack_digest()?;
        let signed = signer.sign_payload(&member.canonical_bytes_for_signature()?)?;
        if signed.verification_method != member.signature.verification_method {
            return Err(Error::Protocol(
                "proposal member signer changed verification method while signing".to_owned(),
            ));
        }
        member.signature.jws = signed.jws;
        member.validate_structural(policy)?;
        Ok(member)
    }

    pub fn canonical_bytes_for_signature(&self) -> Result<Vec<u8>> {
        proof_transcript(
            "ak.control-proposal-authority-ack-proof-v1",
            &self.authority_ack_digest()?,
            &self.signature.verification_method,
            self.signature.created_at,
        )
    }

    pub fn authority_ack_digest(&self) -> Result<Hash> {
        digest_without_field(self, "signature")
    }

    pub fn validate_structural(&self, policy: ControlProposalDecisionPolicy) -> Result<()> {
        policy.validate()?;
        self.validate_protocol_bounds()?;
        if self.received_at.checked_add_signed(policy.decision_window) != Some(self.decision_due_at)
        {
            return Err(Error::Protocol(
                "proposal authority Ack decision_due_at must equal the effective decision window"
                    .to_owned(),
            ));
        }
        if self.received_at.checked_add_signed(policy.absolute_horizon)
            != Some(self.absolute_due_at)
        {
            return Err(Error::Protocol(
                "proposal authority Ack absolute_due_at must equal the effective absolute horizon"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_protocol_bounds(&self) -> Result<()> {
        let decision_window = self.decision_due_at - self.received_at;
        let absolute_horizon = self.absolute_due_at - self.received_at;
        if decision_window <= Duration::zero()
            || decision_window > MAX_PROPOSAL_DECISION_WINDOW
            || absolute_horizon < decision_window
            || absolute_horizon > MAX_PROPOSAL_ABSOLUTE_HORIZON
        {
            return Err(Error::Protocol(
                "proposal authority Ack deadlines exceed protocol bounds".to_owned(),
            ));
        }
        validate_signature(
            &self.signature,
            &self.authority_ack_digest()?,
            self.received_at,
        )
    }
}

impl ControlProposalAck {
    pub fn from_authority_acks(
        authority_acks: Vec<ControlProposalAuthorityAck>,
        policy: ControlProposalDecisionPolicy,
    ) -> Result<Self> {
        Self::from_authority_acks_inner(authority_acks, Some(policy))
    }

    /// Assemble a canonical set when the caller has not yet resolved the
    /// Realm's tighter decision policy. Protocol ceilings and all aggregate
    /// bindings are still enforced; authoritative admission must subsequently
    /// validate the exact Realm policy.
    pub fn from_authority_acks_protocol_bounds(
        authority_acks: Vec<ControlProposalAuthorityAck>,
    ) -> Result<Self> {
        Self::from_authority_acks_inner(authority_acks, None)
    }

    fn from_authority_acks_inner(
        mut authority_acks: Vec<ControlProposalAuthorityAck>,
        policy: Option<ControlProposalDecisionPolicy>,
    ) -> Result<Self> {
        if authority_acks.is_empty() {
            return Err(Error::Protocol(
                "Control Proposal Ack requires at least one authority Ack".to_owned(),
            ));
        }
        authority_acks.sort_by(|left, right| {
            left.signature
                .verification_method
                .cmp(&right.signature.verification_method)
        });
        let first = &authority_acks[0];
        let realm_id = first.realm_id.clone();
        let proposal_digest = first.proposal_digest.clone();
        let authority_set_ref = first.authority_set_ref.clone();
        let received_at = authority_acks
            .iter()
            .map(|member| member.received_at)
            .max()
            .expect("non-empty authority Acks");
        let decision_due_at = authority_acks
            .iter()
            .map(|member| member.decision_due_at)
            .min()
            .expect("non-empty authority Acks");
        let absolute_due_at = authority_acks
            .iter()
            .map(|member| member.absolute_due_at)
            .min()
            .expect("non-empty authority Acks");
        let ack = Self {
            kind: ControlProposalAckKind::SignedAck,
            realm_id,
            proposal_digest,
            received_at,
            decision_due_at,
            absolute_due_at,
            defer_count: 0,
            authority_set_ref,
            authority_acks,
        };
        if let Some(policy) = policy {
            ack.validate_structural(policy)?;
        } else {
            ack.validate_protocol_bounds()?;
        }
        Ok(ack)
    }

    /// Assemble the unique canonical member set and require that it satisfies
    /// the caller-resolved current notary profile.
    pub fn from_authority_acks_for_notary(
        authority_acks: Vec<ControlProposalAuthorityAck>,
        policy: ControlProposalDecisionPolicy,
        notary: &NotaryValue,
    ) -> Result<Self> {
        notary.validate()?;
        let ack = Self::from_authority_acks(authority_acks, policy)?;
        let mut signers = BTreeSet::new();
        for member in &ack.authority_acks {
            let (did, fragment) = member
                .signature
                .verification_method
                .rsplit_once('#')
                .ok_or_else(|| {
                    Error::Protocol(
                        "proposal member verification_method must be a DID URL".to_owned(),
                    )
                })?;
            if fragment.is_empty() {
                return Err(Error::Protocol(
                    "proposal member verification_method fragment is empty".to_owned(),
                ));
            }
            let did = Did::new(did).map_err(|error| {
                Error::Protocol(format!(
                    "proposal member verification_method DID is invalid: {error}"
                ))
            })?;
            if !signers.insert(did) {
                return Err(Error::Protocol(
                    "Control Proposal Ack repeats an authority member".to_owned(),
                ));
            }
        }
        if !notary.proposal_quorum_met(&signers) {
            return Err(Error::Protocol(
                "Control Proposal Ack authority quorum is unreachable".to_owned(),
            ));
        }
        Ok(ack)
    }

    pub fn proposal_ack_digest(&self) -> Result<Hash> {
        Ok(Hash::new(canonical::sha256_digest(
            &canonical::canonical_json_bytes(self)?,
        ))?)
    }

    pub fn validate_structural(&self, policy: ControlProposalDecisionPolicy) -> Result<()> {
        policy.validate()?;
        self.validate_common(policy.proposal_intake_sla, Some(policy))
    }

    pub fn validate_protocol_bounds(&self) -> Result<()> {
        self.validate_common(MAX_PROPOSAL_INTAKE_SLA, None)
    }

    fn validate_common(
        &self,
        proposal_intake_sla: Duration,
        policy: Option<ControlProposalDecisionPolicy>,
    ) -> Result<()> {
        if self.defer_count != 0 {
            return Err(Error::Protocol(
                "Control Proposal Ack defer_count must be zero".to_owned(),
            ));
        }
        if self.authority_acks.is_empty()
            || self.authority_acks.len() > MAX_PROPOSAL_AUTHORITY_PROOFS
        {
            return Err(Error::Protocol(format!(
                "Control Proposal Ack requires 1..={MAX_PROPOSAL_AUTHORITY_PROOFS} authority Acks"
            )));
        }
        let expected_received_at = self
            .authority_acks
            .iter()
            .map(|member| member.received_at)
            .max()
            .expect("authority Ack set is non-empty");
        let earliest_received_at = self
            .authority_acks
            .iter()
            .map(|member| member.received_at)
            .min()
            .expect("authority Ack set is non-empty");
        let expected_decision_due_at = self
            .authority_acks
            .iter()
            .map(|member| member.decision_due_at)
            .min()
            .expect("authority Ack set is non-empty");
        let expected_absolute_due_at = self
            .authority_acks
            .iter()
            .map(|member| member.absolute_due_at)
            .min()
            .expect("authority Ack set is non-empty");
        if expected_received_at - earliest_received_at > proposal_intake_sla
            || self.received_at != expected_received_at
            || self.decision_due_at != expected_decision_due_at
            || self.absolute_due_at != expected_absolute_due_at
            || self.received_at > self.decision_due_at
            || self.decision_due_at > self.absolute_due_at
        {
            return Err(Error::Protocol(
                "Control Proposal Ack aggregate timestamps do not match the canonical member window"
                    .to_owned(),
            ));
        }
        let mut previous_method: Option<&str> = None;
        for member in &self.authority_acks {
            if member.realm_id != self.realm_id
                || member.proposal_digest != self.proposal_digest
                || member.authority_set_ref != self.authority_set_ref
            {
                return Err(Error::Protocol(
                    "proposal authority Ack does not preserve the aggregate Control Proposal Ack \
                     binding"
                        .to_owned(),
                ));
            }
            if previous_method
                .is_some_and(|previous| previous >= member.signature.verification_method.as_str())
            {
                return Err(Error::Protocol(
                    "proposal authority Acks must use distinct verification methods in canonical ascending order"
                        .to_owned(),
                ));
            }
            if let Some(policy) = policy {
                member.validate_structural(policy)?;
            } else {
                member.validate_protocol_bounds()?;
            }
            previous_method = Some(member.signature.verification_method.as_str());
        }
        Ok(())
    }
}

impl ControlProposalDecision {
    pub fn canonical_bytes_for_signature(&self) -> Result<Vec<u8>> {
        let proof = match self {
            Self::SignedReject { proofs, .. } | Self::SignedDefer { proofs, .. } => {
                proofs.first().ok_or_else(|| {
                    Error::Protocol("control proposal decision has no proof".to_owned())
                })?
            }
        };
        proof_transcript(
            "ak.control-proposal-decision-proof-v1",
            &self.decision_digest()?,
            &proof.verification_method,
            proof.created_at,
        )
    }

    pub fn decision_digest(&self) -> Result<Hash> {
        digest_without_field(self, "proofs")
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

    /// Require the canonical proof set to satisfy the exact notary profile
    /// that governed the bound Control Proposal Ack.
    pub fn validate_notary_quorum(&self, notary: &NotaryValue) -> Result<()> {
        notary.validate()?;
        let proofs = match self {
            Self::SignedReject { proofs, .. } | Self::SignedDefer { proofs, .. } => proofs,
        };
        let signers = proofs
            .iter()
            .map(|proof| Did::new(signer_controller(proof)?).map_err(Into::into))
            .collect::<Result<BTreeSet<_>>>()?;
        if !notary.proposal_quorum_met(&signers) {
            return Err(Error::Protocol(
                "control proposal decision proof set does not satisfy the current notary quorum"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate the full defer/reject chain and every canonical decision proof
    /// set against the same Control Proposal Ack authority profile.
    pub fn validate_chain_for_notary(
        &self,
        ack: &ControlProposalAck,
        previous_defers: &[ControlProposalDecision],
        policy: ControlProposalDecisionPolicy,
        notary: &NotaryValue,
    ) -> Result<()> {
        self.validate_chain(ack, previous_defers, policy)?;
        for decision in previous_defers {
            decision.validate_notary_quorum(notary)?;
        }
        self.validate_notary_quorum(notary)
    }

    pub fn validate_chain(
        &self,
        ack: &ControlProposalAck,
        previous_defers: &[ControlProposalDecision],
        policy: ControlProposalDecisionPolicy,
    ) -> Result<()> {
        self.validate_chain_common(ack, previous_defers, Some(policy))
    }

    /// Validate a decision chain when the receiver has not resolved the
    /// proposal's frozen Realm policy. This preserves every Control Proposal Ack binding,
    /// chain transition, proof, and protocol hard ceiling without pretending
    /// that the hard ceilings are the Realm's exact effective policy.
    pub fn validate_chain_protocol_bounds(
        &self,
        ack: &ControlProposalAck,
        previous_defers: &[ControlProposalDecision],
    ) -> Result<()> {
        self.validate_chain_common(ack, previous_defers, None)
    }

    fn validate_chain_common(
        &self,
        ack: &ControlProposalAck,
        previous_defers: &[ControlProposalDecision],
        policy: Option<ControlProposalDecisionPolicy>,
    ) -> Result<()> {
        let max_defers = if let Some(policy) = policy {
            ack.validate_structural(policy)?;
            policy.max_defers
        } else {
            ack.validate_protocol_bounds()?;
            MAX_PROPOSAL_DEFERS
        };
        if previous_defers.len() > usize::from(max_defers) {
            return Err(Error::Protocol(
                "proposal decision chain exceeds max_defers".to_owned(),
            ));
        }
        let proposal_ack_digest = ack.proposal_ack_digest()?;
        let expected_count = u8::try_from(previous_defers.len())
            .map_err(|_| Error::Protocol("proposal defer count overflow".to_owned()))?;
        let previous_due_at = previous_defers
            .last()
            .map(Self::decision_due_at)
            .unwrap_or(ack.decision_due_at);

        for (index, decision) in previous_defers.iter().enumerate() {
            if !matches!(decision, Self::SignedDefer { .. }) {
                return Err(Error::Protocol(
                    "only signed_defer may precede another proposal decision".to_owned(),
                ));
            }
            decision.validate_chain_common(ack, &previous_defers[..index], policy)?;
        }

        let (
            realm_id,
            proposal_digest,
            bound_proposal_ack_digest,
            absolute_due_at,
            authority_set_ref,
            proofs,
        ) = match self {
            Self::SignedReject {
                realm_id,
                proposal_digest,
                proposal_ack_digest,
                absolute_due_at,
                authority_set_ref,
                proofs,
                ..
            }
            | Self::SignedDefer {
                realm_id,
                proposal_digest,
                proposal_ack_digest,
                absolute_due_at,
                authority_set_ref,
                proofs,
                ..
            } => (
                realm_id,
                proposal_digest,
                proposal_ack_digest,
                absolute_due_at,
                authority_set_ref,
                proofs,
            ),
        };
        if realm_id != &ack.realm_id
            || proposal_digest != &ack.proposal_digest
            || bound_proposal_ack_digest != &proposal_ack_digest
            || absolute_due_at != &ack.absolute_due_at
            || authority_set_ref != &ack.authority_set_ref
        {
            return Err(Error::Protocol(
                "proposal decision does not preserve its Control Proposal Ack binding".to_owned(),
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
                if expected_count >= max_defers || *defer_count != expected_count + 1 {
                    return Err(Error::Protocol(
                        "signed_defer exceeds max_defers or skips defer_count".to_owned(),
                    ));
                }
                if *decision_due_at <= previous_due_at || *decision_due_at > ack.absolute_due_at {
                    return Err(Error::Protocol(
                        "signed_defer must strictly advance within absolute_due_at".to_owned(),
                    ));
                }
            }
        }
        validate_proofs(proofs, &self.decision_digest()?, self.decided_at())
    }

    pub fn satisfied_current_deadline(&self, previous_due_at: DateTime<Utc>) -> bool {
        self.decided_at() <= previous_due_at
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::DidUrl;

    struct FixtureSigner {
        did: Did,
        verification_method: DidUrl,
    }

    impl PayloadSigner for FixtureSigner {
        fn signer_did(&self) -> &Did {
            &self.did
        }

        fn verification_method_id(&self) -> &DidUrl {
            &self.verification_method
        }

        fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<PayloadSignature> {
            Ok(PayloadSignature {
                verification_method: self.verification_method.clone(),
                payload_digest: Hash::new(canonical::sha256_digest(canonical_bytes))?,
                created_at: at(999),
                jws: "e30..c2ln".to_owned(),
                extra: BTreeMap::new(),
            })
        }
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_775_000_000 + seconds, 0).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn signature(payload_digest: Hash, created_at: DateTime<Utc>) -> PayloadSignature {
        PayloadSignature {
            verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#notary-1")
                .unwrap(),
            payload_digest,
            created_at,
            jws: "e30..c2ln".to_owned(),
            extra: BTreeMap::new(),
        }
    }

    fn ack() -> ControlProposalAck {
        let mut member = ControlProposalAuthorityAck {
            realm_id: RealmId::new("ak:realm:AeDdsjEvUHSY0isE04bQVgIHbwILn5uepI2iuvvak-25")
                .unwrap(),
            proposal_digest: hash('a'),
            received_at: at(0),
            decision_due_at: at(30),
            absolute_due_at: at(90),
            authority_set_ref: hash('b'),
            signature: signature(hash('0'), at(0)),
        };
        member.signature.payload_digest = member.authority_ack_digest().unwrap();
        ControlProposalAck {
            kind: ControlProposalAckKind::SignedAck,
            realm_id: member.realm_id.clone(),
            proposal_digest: member.proposal_digest.clone(),
            received_at: at(0),
            decision_due_at: at(30),
            absolute_due_at: at(90),
            defer_count: 0,
            authority_set_ref: hash('b'),
            authority_acks: vec![member],
        }
    }

    #[test]
    fn local_authority_ack_uses_the_canonical_signer_transcript() {
        let signer = FixtureSigner {
            did: Did::new("did:webvh:z6mkfixture:authority.example").unwrap(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#device-1")
                .unwrap(),
        };
        let member = ControlProposalAuthorityAck::issue_with_signer(
            RealmId::new("ak:realm:AeDdsjEvUHSY0isE04bQVgIHbwILn5uepI2iuvvak-25").unwrap(),
            hash('a'),
            hash('b'),
            at(0),
            ControlProposalDecisionPolicy::default(),
            &signer,
        )
        .unwrap();

        assert_eq!(member.decision_due_at, at(30));
        assert_eq!(member.absolute_due_at, at(90));
        assert_eq!(member.signature.created_at, member.received_at);
        assert_eq!(
            member.signature.payload_digest,
            member.authority_ack_digest().unwrap()
        );
        member
            .validate_structural(ControlProposalDecisionPolicy::default())
            .unwrap();
    }

    fn defer(
        ack: &ControlProposalAck,
        count: u8,
        decided_at: DateTime<Utc>,
        due_at: DateTime<Utc>,
    ) -> ControlProposalDecision {
        let mut decision = ControlProposalDecision::SignedDefer {
            realm_id: ack.realm_id.clone(),
            proposal_digest: ack.proposal_digest.clone(),
            proposal_ack_digest: ack.proposal_ack_digest().unwrap(),
            decided_at,
            decision_due_at: due_at,
            absolute_due_at: ack.absolute_due_at,
            defer_count: count,
            reason_code: ControlProposalDeferReason::QuorumUnreachable,
            authority_set_ref: ack.authority_set_ref.clone(),
            proofs: vec![signature(hash('0'), decided_at)],
        };
        let digest = decision.decision_digest().unwrap();
        if let ControlProposalDecision::SignedDefer { proofs, .. } = &mut decision {
            proofs[0].payload_digest = digest;
        }
        decision
    }

    #[test]
    fn ack_enforces_effective_and_protocol_deadlines() {
        ack()
            .validate_structural(ControlProposalDecisionPolicy::default())
            .unwrap();
        let mut invalid = ack();
        invalid.absolute_due_at = at(91);
        invalid.authority_acks[0].absolute_due_at = at(91);
        invalid.authority_acks[0].signature.payload_digest =
            invalid.authority_acks[0].authority_ack_digest().unwrap();
        assert!(
            invalid
                .validate_structural(ControlProposalDecisionPolicy::default())
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );
    }

    #[test]
    fn proposal_policy_enforces_window_horizon_and_defer_cross_field_rules() {
        let base = ControlProposalDecisionPolicy {
            proposal_intake_sla: Duration::seconds(1),
            decision_window: Duration::seconds(30),
            absolute_horizon: Duration::seconds(90),
            max_defers: 2,
        };
        base.validate().unwrap();

        assert!(
            ControlProposalDecisionPolicy {
                decision_window: Duration::seconds(31),
                absolute_horizon: Duration::seconds(30),
                ..base
            }
            .validate()
            .is_err()
        );
        ControlProposalDecisionPolicy {
            decision_window: Duration::seconds(30),
            absolute_horizon: Duration::seconds(30),
            max_defers: 0,
            ..base
        }
        .validate()
        .unwrap();
        assert!(
            ControlProposalDecisionPolicy {
                decision_window: Duration::seconds(30),
                absolute_horizon: Duration::seconds(30),
                max_defers: 1,
                ..base
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn canonical_ack_assembly_requires_current_threshold_quorum() {
        let first = ack().authority_acks.remove(0);
        let mut second = first.clone();
        second.signature.verification_method =
            DidUrl::new("did:webvh:z6mkfixture:authority-b.example#notary-1").unwrap();
        second.signature.payload_digest = second.authority_ack_digest().unwrap();
        let profile = NotaryValue::Threshold {
            threshold: 2,
            members: vec![
                Did::new("did:webvh:z6mkfixture:authority.example").unwrap(),
                Did::new("did:webvh:z6mkfixture:authority-b.example").unwrap(),
                Did::new("did:webvh:z6mkfixture:authority-c.example").unwrap(),
            ],
            forensic_attribution: crate::notary::ForensicAttribution::QuorumIntersection,
        };
        assert!(
            ControlProposalAck::from_authority_acks_for_notary(
                vec![first.clone()],
                ControlProposalDecisionPolicy::default(),
                &profile,
            )
            .is_err()
        );
        let assembled = ControlProposalAck::from_authority_acks_for_notary(
            vec![second, first],
            ControlProposalDecisionPolicy::default(),
            &profile,
        )
        .unwrap();
        assert_eq!(
            assembled
                .authority_acks
                .iter()
                .map(|member| member.signature.verification_method.as_str())
                .collect::<Vec<_>>(),
            [
                "did:webvh:z6mkfixture:authority-b.example#notary-1",
                "did:webvh:z6mkfixture:authority.example#notary-1",
            ]
        );
    }

    #[test]
    fn defer_chain_is_sequential_and_cannot_extend_absolute_deadline() {
        let ack = ack();
        let first = defer(&ack, 1, at(20), at(60));
        first
            .validate_chain(&ack, &[], ControlProposalDecisionPolicy::default())
            .unwrap();
        let second = defer(&ack, 2, at(50), at(90));
        second
            .validate_chain(
                &ack,
                std::slice::from_ref(&first),
                ControlProposalDecisionPolicy::default(),
            )
            .unwrap();

        let third = defer(&ack, 3, at(80), at(90));
        assert!(
            third
                .validate_chain(
                    &ack,
                    &[first, second],
                    ControlProposalDecisionPolicy::default(),
                )
                .is_err()
        );
    }

    #[test]
    fn decision_chain_protocol_bounds_do_not_invent_an_exact_realm_policy() {
        let ack = ack();
        let first = defer(&ack, 1, at(20), at(60));

        first
            .validate_chain_protocol_bounds(&ack, &[])
            .expect("30s/90s Ack and its defer are within protocol ceilings");
        assert!(
            first
                .validate_chain(&ack, &[], ControlProposalDecisionPolicy::protocol_maximum(),)
                .is_err(),
            "the protocol ceiling is not the Ack's exact effective policy"
        );
    }

    #[test]
    fn late_decision_is_valid_evidence_but_does_not_satisfy_the_deadline() {
        let ack = ack();
        let late = defer(&ack, 1, at(31), at(60));
        late.validate_chain(&ack, &[], ControlProposalDecisionPolicy::default())
            .unwrap();
        assert!(!late.satisfied_current_deadline(ack.decision_due_at));
    }

    #[test]
    fn decision_chain_revalidates_every_signed_prefix() {
        let ack = ack();
        let mut first = defer(&ack, 1, at(20), at(60));
        let second = defer(&ack, 2, at(50), at(90));
        if let ControlProposalDecision::SignedDefer { proofs, .. } = &mut first {
            proofs[0].payload_digest = hash('f');
        }
        assert!(
            second
                .validate_chain(
                    &ack,
                    std::slice::from_ref(&first),
                    ControlProposalDecisionPolicy::default(),
                )
                .is_err()
        );
    }

    #[test]
    fn proposal_window_policy_enforces_order_and_defer_headroom() {
        let cases = [
            (Duration::seconds(91), Duration::seconds(90), 0, false),
            (Duration::seconds(90), Duration::seconds(90), 0, true),
            (Duration::seconds(90), Duration::seconds(90), 1, false),
        ];

        for (decision_window, absolute_horizon, max_defers, expected_valid) in cases {
            let policy = ControlProposalDecisionPolicy {
                proposal_intake_sla: Duration::seconds(60),
                decision_window,
                absolute_horizon,
                max_defers,
            };
            assert_eq!(
                policy.validate().is_ok(),
                expected_valid,
                "unexpected verdict for decision={decision_window:?}, absolute={absolute_horizon:?}, defers={max_defers}"
            );
        }
    }
}
