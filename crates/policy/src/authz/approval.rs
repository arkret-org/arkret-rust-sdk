use arkret_wire::DidCoreId;

use super::*;

/// Status of a grant proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    /// Proposal is pending approvals.
    Pending,
    /// Proposal has been approved and the grant is active.
    Approved,
    /// Proposal was rejected.
    Rejected,
    /// Proposal expired before receiving enough approvals.
    Expired,
    /// Proposal was cancelled by the proposer.
    Cancelled,
}

/// A proposed grant that requires approval before it becomes active.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantProposal {
    /// Unique proposal ID.
    pub proposal_id: String,
    /// The proposed grant (spec wire form).
    pub grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    /// Actor who proposed the grant.
    pub proposer: DidCoreId,
    /// Required approvers.
    pub required_approvers: Vec<DidCoreId>,
    /// Approval mode.
    pub approval_mode: ApprovalMode,
    /// Current status.
    pub status: ProposalStatus,
    /// Collected approvals.
    pub approvals: Vec<ProposalApproval>,
    /// Creation time.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    /// Expiration time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Resolution time (when status became terminal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub resolved_at: Option<DateTime<Utc>>,
}

/// An individual approval or rejection of a grant proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalApproval {
    /// The proposal this approval is for.
    pub proposal_id: String,
    /// Actor providing the approval.
    pub approver: DidCoreId,
    /// Whether this is an approval or rejection.
    pub approved: bool,
    /// Optional reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Time of the approval.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Manages the lifecycle of grant proposals and approvals.
#[derive(Clone, Debug, Default)]
pub struct ApprovalStrandManager {
    proposals: BTreeMap<String, GrantProposal>,
}

impl ApprovalStrandManager {
    /// Create a new approval strand manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a new grant proposal for approval.
    pub fn submit_proposal(
        &mut self,
        grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
        proposer: DidCoreId,
        required_approvers: Vec<DidCoreId>,
        approval_mode: ApprovalMode,
        expires_at: Option<DateTime<Utc>>,
    ) -> GrantProposal {
        let proposal_id = format!("ak:proposal:{}", grant.id);
        let proposal = GrantProposal {
            proposal_id: proposal_id.clone(),
            grant,
            proposer,
            required_approvers,
            approval_mode,
            status: ProposalStatus::Pending,
            approvals: Vec::new(),
            created_at: Utc::now(),
            expires_at,
            resolved_at: None,
        };
        self.proposals.insert(proposal_id, proposal.clone());
        proposal
    }

    /// Record an approval or rejection for a proposal.
    pub fn record_approval(
        &mut self,
        proposal_id: &str,
        approver: DidCoreId,
        approved: bool,
        reason: Option<String>,
    ) -> Result<GrantProposal> {
        let now = Utc::now();
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| WireError::Protocol("proposal not found".to_owned()))?;

        if proposal.status != ProposalStatus::Pending {
            return Err(WireError::Protocol(format!(
                "proposal {} is not pending (status: {:?})",
                proposal_id, proposal.status
            )));
        }

        if let Some(expires_at) = proposal.expires_at
            && now >= expires_at
        {
            proposal.status = ProposalStatus::Expired;
            proposal.resolved_at = Some(now);
            return Err(WireError::Protocol("proposal has expired".to_owned()));
        }

        if !proposal.required_approvers.contains(&approver) {
            return Err(WireError::Protocol(
                "approver is not in the required approvers list".to_owned(),
            ));
        }

        if proposal.approvals.iter().any(|a| a.approver == approver) {
            return Err(WireError::Protocol(
                "approver has already responded".to_owned(),
            ));
        }

        proposal.approvals.push(ProposalApproval {
            proposal_id: proposal_id.to_owned(),
            approver,
            approved,
            reason,
            created_at: now,
        });

        self.evaluate_proposal_status(proposal_id);
        // Looked up successfully above; re-fetch after status evaluation
        // without assuming the map is unchanged.
        self.proposals
            .get(proposal_id)
            .cloned()
            .ok_or_else(|| WireError::Protocol("proposal not found".to_owned()))
    }

    /// Check if a proposal is approved.
    pub fn is_proposal_approved(&self, proposal_id: &str) -> bool {
        self.proposals
            .get(proposal_id)
            .is_some_and(|p| p.status == ProposalStatus::Approved)
    }

    /// Get a proposal by ID.
    pub fn proposal(&self, proposal_id: &str) -> Option<&GrantProposal> {
        self.proposals.get(proposal_id)
    }

    /// Expire all proposals that have passed their expiration time.
    pub fn expire_proposals(&mut self) -> usize {
        let now = Utc::now();
        let expired: Vec<String> = self
            .proposals
            .iter()
            .filter(|(_, p)| {
                p.status == ProposalStatus::Pending && p.expires_at.is_some_and(|exp| now >= exp)
            })
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for proposal_id in &expired {
            if let Some(proposal) = self.proposals.get_mut(proposal_id) {
                proposal.status = ProposalStatus::Expired;
                proposal.resolved_at = Some(now);
            }
        }
        count
    }

    /// Check if a grant has been approved through a proposal.
    pub fn is_grant_approved(&self, grant_id: &str) -> bool {
        let proposal_id = format!("ak:proposal:{grant_id}");
        self.is_proposal_approved(&proposal_id)
    }

    fn evaluate_proposal_status(&mut self, proposal_id: &str) {
        let Some(proposal) = self.proposals.get(proposal_id) else {
            return;
        };

        let approvals: Vec<DidCoreId> = proposal
            .approvals
            .iter()
            .filter(|a| a.approved)
            .map(|a| a.approver.clone())
            .collect();
        let rejections = proposal.approvals.iter().filter(|a| !a.approved).count();

        let approved = match &proposal.approval_mode {
            ApprovalMode::Any => !approvals.is_empty(),
            ApprovalMode::All => approvals.len() >= proposal.required_approvers.len(),
            ApprovalMode::Threshold { count } => approvals.len() >= *count as usize,
            ApprovalMode::Guardian => proposal.approvals.iter().any(|a| a.approved),
            ApprovalMode::Controller => proposal.approvals.iter().any(|a| a.approved),
        };

        let Some(proposal) = self.proposals.get_mut(proposal_id) else {
            return;
        };

        if approved {
            proposal.status = ProposalStatus::Approved;
            proposal.resolved_at = Some(Utc::now());
        } else if rejections > 0 {
            // For threshold/all modes, a single rejection can veto.
            match &proposal.approval_mode {
                ApprovalMode::Any => {} // Any rejection doesn't veto in "any" mode
                _ => {
                    proposal.status = ProposalStatus::Rejected;
                    proposal.resolved_at = Some(Utc::now());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::governance::grant_constraint::{
        CapabilityGrant, CapabilitySubject, IssuerAuthorityRef,
    };
    use arkret_wire::{GrantId, RealmId, SchemaId};

    use super::*;

    fn did(name: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn grant() -> CapabilityGrant {
        CapabilityGrant {
            id: GrantId::new("ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu").unwrap(),
            schema: SchemaId::CAPABILITY_V1.to_owned(),
            realm_id: None,
            issuer: did("alice"),
            issuer_principal_server_id: did("alice"),
            subject: CapabilitySubject::CoreDid(did("bob")),
            subject_principal_server_id: Some(did("alice")),
            actions: vec!["ak.message.create".to_owned()],
            resources: vec![serde_json::from_value(serde_json::json!({"kind": "*"})).unwrap()],
            capability_action_registry_digest: None,
            constraints: Vec::new(),
            issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                realm_id: RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI")
                    .unwrap(),
                cell_ref: arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
                controller_epoch_at_issuance: 0,
                authority_generation: 0,
            }],
            issued_at: "2026-08-18T00:00:00.000Z".parse().unwrap(),
            not_before: None,
            expires_at: None,
            updated_by: None,
            updated_at: None,
            revoked_by: None,
            revoked_at: None,
        }
    }

    #[test]
    fn grant_proposal_omitted_optional_timestamps_round_trip() {
        let proposal = GrantProposal {
            proposal_id: "proposal-1".to_owned(),
            grant: grant(),
            proposer: did("alice"),
            required_approvers: vec![did("bob")],
            approval_mode: ApprovalMode::Any,
            status: ProposalStatus::Pending,
            approvals: Vec::new(),
            created_at: "2026-08-18T00:00:00.000Z".parse().unwrap(),
            expires_at: None,
            resolved_at: None,
        };

        let serialized = serde_json::to_value(&proposal).unwrap();
        let object = serialized.as_object().unwrap();
        assert!(!object.contains_key("expires_at"));
        assert!(!object.contains_key("resolved_at"));

        let restored: GrantProposal = serde_json::from_value(serialized).unwrap();
        assert!(restored.expires_at.is_none());
        assert!(restored.resolved_at.is_none());
        assert_eq!(restored.proposal_id, proposal.proposal_id);
    }
}
