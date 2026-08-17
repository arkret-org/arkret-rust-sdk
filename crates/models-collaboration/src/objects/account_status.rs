//! Account Authority issuer-ledger lifecycle status (account-lifecycle.md §3).

use arkret_wire::error_codes::ReasonCode;
use serde::{Deserialize, Serialize};

/// Account lifecycle status (account-lifecycle.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

    pub fn validate_transition_to(self, to: Self) -> Result<(), AccountStatusTransitionRejection> {
        if self == AccountStatus::ErasurePending && to != AccountStatus::ErasurePending {
            return Err(AccountStatusTransitionRejection::ErasurePendingIsTerminal);
        }

        if !self.can_transition_to(to) {
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
