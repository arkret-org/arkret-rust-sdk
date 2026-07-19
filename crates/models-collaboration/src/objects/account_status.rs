//! Account lifecycle status projection (account-lifecycle.md §3).
//!
//! `project_account_status_heads` is a pure fold over caller-supplied
//! candidate heads and a visible-event-id set: it reads no store, clock,
//! or policy surface, so it travels with the `AccountStatus` type family.

use std::collections::BTreeSet;

use arkret_identifiers::{EventId, Hash};
use arkret_wire::error_codes::ReasonCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Account lifecycle status (account-lifecycle.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    ErasurePending,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AccountStatus::Active => "active",
            AccountStatus::SoftLoggedOut => "soft_logged_out",
            AccountStatus::Locked => "locked",
            AccountStatus::Suspended => "suspended",
            AccountStatus::Deactivated => "deactivated",
            AccountStatus::ErasurePending => "erasure_pending",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "active" => Some(AccountStatus::Active),
            "soft_logged_out" => Some(AccountStatus::SoftLoggedOut),
            "locked" => Some(AccountStatus::Locked),
            "suspended" => Some(AccountStatus::Suspended),
            "deactivated" => Some(AccountStatus::Deactivated),
            "erasure_pending" => Some(AccountStatus::ErasurePending),
            _ => None,
        }
    }

    /// Strictness order from account-lifecycle.md §3.
    pub fn severity_rank(self) -> u8 {
        match self {
            AccountStatus::Active => 0,
            AccountStatus::SoftLoggedOut => 1,
            AccountStatus::Locked => 2,
            AccountStatus::Suspended => 3,
            AccountStatus::Deactivated => 4,
            AccountStatus::ErasurePending => 5,
        }
    }

    pub fn is_stricter_than(self, other: Self) -> bool {
        self.severity_rank() > other.severity_rank()
    }

    pub fn is_less_strict_than(self, other: Self) -> bool {
        self.severity_rank() < other.severity_rank()
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, AccountStatus::ErasurePending)
    }

    pub fn can_transition_to(self, to: Self) -> bool {
        use AccountStatus::{
            Active, Deactivated, ErasurePending, Locked, SoftLoggedOut, Suspended,
        };

        if self == to {
            return true;
        }

        match (self, to) {
            (Active, SoftLoggedOut | Locked | Suspended | Deactivated | ErasurePending)
            | (SoftLoggedOut, Active | Locked | Suspended | Deactivated | ErasurePending)
            | (Locked, Active | SoftLoggedOut | Suspended | Deactivated | ErasurePending)
            | (Suspended, Active | SoftLoggedOut | Locked | Deactivated | ErasurePending)
            | (Deactivated, ErasurePending) => true,
            (Deactivated, Active | SoftLoggedOut | Locked | Suspended)
            | (ErasurePending, Active | SoftLoggedOut | Locked | Suspended | Deactivated) => false,
            _ => false,
        }
    }

    pub fn validate_transition_to(
        self,
        to: Self,
        supersedes_status_event_visible: bool,
    ) -> Result<(), AccountStatusTransitionRejection> {
        if self == AccountStatus::ErasurePending && to != AccountStatus::ErasurePending {
            return Err(AccountStatusTransitionRejection::ErasurePendingIsTerminal);
        }

        if !self.can_transition_to(to) {
            return Err(AccountStatusTransitionRejection::TransitionInvalid);
        }

        if to.is_less_strict_than(self) && !supersedes_status_event_visible {
            return Err(AccountStatusTransitionRejection::TransitionInvalid);
        }

        Ok(())
    }

    /// Return whether new writes are allowed in this state.
    pub fn allows_writes(self) -> bool {
        matches!(self, AccountStatus::Active)
    }

    /// Return whether refresh / re-auth is the only allowed transition.
    pub fn requires_reauth(self) -> bool {
        matches!(self, AccountStatus::SoftLoggedOut | AccountStatus::Locked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountStatusTransitionRejection {
    ErasurePendingIsTerminal,
    TransitionInvalid,
}

impl AccountStatusTransitionRejection {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::ErasurePendingIsTerminal => ReasonCode::ERASURE_PENDING_IS_TERMINAL,
            Self::TransitionInvalid => ReasonCode::ACCOUNT_STATUS_TRANSITION_INVALID,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusProjectionCandidate {
    pub event_id: EventId,
    pub status: AccountStatus,
    pub effective_at: DateTime<Utc>,
    pub event_digest: Hash,
    pub supersedes_status_event_id: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusProjection<'a> {
    pub current: Option<&'a AccountStatusProjectionCandidate>,
    pub rejected: Vec<AccountStatusProjectionRejected>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusProjectionRejected {
    pub event_id: EventId,
    pub reason_code: &'static str,
}

pub fn project_account_status_heads<'a>(
    heads: &'a [AccountStatusProjectionCandidate],
    visible_status_event_ids: &BTreeSet<EventId>,
) -> AccountStatusProjection<'a> {
    let mut rejected = Vec::new();
    let mut suppressed = BTreeSet::new();

    for candidate in heads {
        if let Some(superseded_id) = candidate.supersedes_status_event_id.as_ref() {
            if !visible_status_event_ids.contains(superseded_id) {
                continue;
            }

            if let Some(superseded) = heads.iter().find(|head| &head.event_id == superseded_id)
                && candidate.status.is_less_strict_than(superseded.status)
            {
                match superseded
                    .status
                    .validate_transition_to(candidate.status, true)
                {
                    Ok(()) => {
                        suppressed.insert(superseded.event_id.clone());
                    }
                    Err(rejection) => rejected.push(AccountStatusProjectionRejected {
                        event_id: candidate.event_id.clone(),
                        reason_code: rejection.reason_code(),
                    }),
                }
            }
        }
    }

    let current = heads
        .iter()
        .filter(|candidate| !suppressed.contains(&candidate.event_id))
        .filter(|candidate| {
            !rejected
                .iter()
                .any(|rejection| rejection.event_id == candidate.event_id)
        })
        .max_by(|left, right| {
            left.status
                .severity_rank()
                .cmp(&right.status.severity_rank())
                .then_with(|| left.effective_at.cmp(&right.effective_at))
                .then_with(|| left.event_digest.as_str().cmp(right.event_digest.as_str()))
        });

    AccountStatusProjection { current, rejected }
}
