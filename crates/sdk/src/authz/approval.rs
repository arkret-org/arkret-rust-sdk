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
    pub grant: arkret_core::CapabilityGrant,
    /// Actor who proposed the grant.
    pub proposer: Did,
    /// Required approvers.
    pub required_approvers: Vec<Did>,
    /// Approval mode.
    pub approval_mode: ApprovalMode,
    /// Current status.
    pub status: ProposalStatus,
    /// Collected approvals.
    pub approvals: Vec<ProposalApproval>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Resolution time (when status became terminal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
}

/// An individual approval or rejection of a grant proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalApproval {
    /// The proposal this approval is for.
    pub proposal_id: String,
    /// Actor providing the approval.
    pub approver: Did,
    /// Whether this is an approval or rejection.
    pub approved: bool,
    /// Optional reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Time of the approval.
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
        grant: arkret_core::CapabilityGrant,
        proposer: Did,
        required_approvers: Vec<Did>,
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
        approver: Did,
        approved: bool,
        reason: Option<String>,
    ) -> Result<GrantProposal> {
        let now = Utc::now();
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| Error::Protocol("proposal not found".to_owned()))?;

        if proposal.status != ProposalStatus::Pending {
            return Err(Error::Protocol(format!(
                "proposal {} is not pending (status: {:?})",
                proposal_id, proposal.status
            )));
        }

        if let Some(expires_at) = proposal.expires_at
            && now >= expires_at
        {
            proposal.status = ProposalStatus::Expired;
            proposal.resolved_at = Some(now);
            return Err(Error::Protocol("proposal has expired".to_owned()));
        }

        if !proposal.required_approvers.contains(&approver) {
            return Err(Error::Protocol(
                "approver is not in the required approvers list".to_owned(),
            ));
        }

        if proposal.approvals.iter().any(|a| a.approver == approver) {
            return Err(Error::Protocol("approver has already responded".to_owned()));
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
            .ok_or_else(|| Error::Protocol("proposal not found".to_owned()))
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

        let approvals: Vec<Did> = proposal
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
