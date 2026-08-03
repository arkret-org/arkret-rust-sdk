use std::fmt;

use arkret_wire::{HistoryVisibility, ReasonCode};
use serde::{Deserialize, Serialize};

/// Service-discovery capability required by `ak.profile.chat_mvp.v1`.
pub const DISCUSSION_HISTORY_VISIBILITY_FEATURE: &str = "discussion_history_visibility";

pub fn content_scheme_is_history_capable(content_scheme: Option<&str>) -> bool {
    matches!(content_scheme.map(str::trim), Some("mls_exporter_aead_v1"))
}

pub fn validate_history_visibility_content_scheme(
    history_visibility: HistoryVisibility,
    content_scheme: Option<&str>,
) -> Result<(), &'static str> {
    if history_visibility.admits_pre_join_history()
        && !content_scheme_is_history_capable(content_scheme)
    {
        return Err(ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME);
    }
    Ok(())
}

pub fn validate_history_visibility_content_scheme_values(
    history_visibility: &str,
    content_scheme: Option<&str>,
) -> Result<(), &'static str> {
    let history_visibility = history_visibility
        .parse::<HistoryVisibility>()
        .map_err(|_| "unknown history_visibility value")?;
    validate_history_visibility_content_scheme(history_visibility, content_scheme)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryKeyShareDefault {
    Deny,
    EventTimeVisibility,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum HistorySharingPreJoinPolicy {
    #[serde(rename = "deny")]
    Deny,
    #[serde(rename = "visibility_condition_allowed")]
    AllowIfVisibilityAllows,
    #[serde(rename = "rule_only")]
    RuleOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum HistorySharingPostRemovalRecoveryPolicy {
    #[serde(rename = "deny")]
    Deny,
    #[serde(rename = "t0_visibility_with_current_policy_allowed")]
    AllowT0VisibleWithCurrentPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryKeySource {
    OwnDevice,
    VerifiedMemberDevice,
    KeyBackup,
    ArchiveNode,
    RecoveryService,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistorySharingReceiverClass {
    ActiveMember,
    Invited,
    RemovedT0Visible,
    WorldReadableRequester,
    PreviewTokenHolder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistorySharingRange {
    AllVisibleAtT0,
    SinceInvite,
    SinceJoin,
    BoundedEpochRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistorySharingScopeKind {
    Realm,
    Circle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmKeyWithheldReasonCode {
    UnverifiedDevice,
    BlacklistedDevice,
    NotMember,
    HistoryNotVisible,
    PolicyDenied,
    UnknownSession,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryMembershipTransition {
    Invite,
    Join,
    RevokeInvite,
    RejectInvite,
    ExpireInvite,
    Leave,
    Ban,
    Remove,
    Deactivate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryMembershipEvent<F = String> {
    pub member: String,
    pub frontier: F,
    pub transition: HistoryMembershipTransition,
}

impl<F> HistoryMembershipEvent<F> {
    pub fn invite(member: impl Into<String>, frontier: F) -> Self {
        Self {
            member: member.into(),
            frontier,
            transition: HistoryMembershipTransition::Invite,
        }
    }

    pub fn join(member: impl Into<String>, frontier: F) -> Self {
        Self {
            member: member.into(),
            frontier,
            transition: HistoryMembershipTransition::Join,
        }
    }

    pub fn revoke_invite(member: impl Into<String>, frontier: F) -> Self {
        Self {
            member: member.into(),
            frontier,
            transition: HistoryMembershipTransition::RevokeInvite,
        }
    }

    pub fn leave(member: impl Into<String>, frontier: F) -> Self {
        Self {
            member: member.into(),
            frontier,
            transition: HistoryMembershipTransition::Leave,
        }
    }

    pub fn remove(member: impl Into<String>, frontier: F) -> Self {
        Self {
            member: member.into(),
            frontier,
            transition: HistoryMembershipTransition::Remove,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryMembershipFrontiers<F = String> {
    pub invite_frontier: Option<F>,
    pub join_frontier: Option<F>,
    pub remove_frontier: Option<F>,
}

impl<F> Default for HistoryMembershipFrontiers<F> {
    fn default() -> Self {
        Self {
            invite_frontier: None,
            join_frontier: None,
            remove_frontier: None,
        }
    }
}

impl<F> HistoryMembershipFrontiers<F> {
    pub fn current_state(&self) -> HistoryReaderEventState {
        if self.join_frontier.is_some() {
            HistoryReaderEventState::Joined
        } else if self.invite_frontier.is_some() {
            HistoryReaderEventState::Invited
        } else if self.remove_frontier.is_some() {
            HistoryReaderEventState::Removed
        } else {
            HistoryReaderEventState::None
        }
    }
}

pub fn history_membership_frontiers<'a, F: Clone + 'a>(
    member: &str,
    events: impl IntoIterator<Item = &'a HistoryMembershipEvent<F>>,
) -> HistoryMembershipFrontiers<F> {
    let mut frontiers = HistoryMembershipFrontiers::default();
    for event in events {
        if event.member != member {
            continue;
        }
        match event.transition {
            HistoryMembershipTransition::Invite => {
                frontiers.invite_frontier = Some(event.frontier.clone());
                frontiers.join_frontier = None;
                frontiers.remove_frontier = None;
            }
            HistoryMembershipTransition::Join => {
                if frontiers.invite_frontier.is_none() {
                    frontiers.invite_frontier = Some(event.frontier.clone());
                }
                frontiers.join_frontier = Some(event.frontier.clone());
                frontiers.remove_frontier = None;
            }
            HistoryMembershipTransition::RevokeInvite
            | HistoryMembershipTransition::RejectInvite
            | HistoryMembershipTransition::ExpireInvite => {
                frontiers.invite_frontier = None;
                frontiers.join_frontier = None;
                frontiers.remove_frontier = Some(event.frontier.clone());
            }
            HistoryMembershipTransition::Leave
            | HistoryMembershipTransition::Ban
            | HistoryMembershipTransition::Remove
            | HistoryMembershipTransition::Deactivate => {
                frontiers.invite_frontier = None;
                frontiers.join_frontier = None;
                frontiers.remove_frontier = Some(event.frontier.clone());
            }
        }
    }
    frontiers
}

pub fn join_frontier<'a, F: Clone + 'a>(
    member: &str,
    events: impl IntoIterator<Item = &'a HistoryMembershipEvent<F>>,
) -> Option<F> {
    history_membership_frontiers(member, events).join_frontier
}

pub fn invite_frontier<'a, F: Clone + 'a>(
    member: &str,
    events: impl IntoIterator<Item = &'a HistoryMembershipEvent<F>>,
) -> Option<F> {
    history_membership_frontiers(member, events).invite_frontier
}

pub fn remove_frontier<'a, F: Clone + 'a>(
    member: &str,
    events: impl IntoIterator<Item = &'a HistoryMembershipEvent<F>>,
) -> Option<F> {
    history_membership_frontiers(member, events).remove_frontier
}

pub fn history_reader_state_at_t0<F>(
    frontiers: &HistoryMembershipFrontiers<F>,
    mut t0_contains: impl FnMut(&F) -> bool,
) -> HistoryReaderEventState {
    let remove_visible = frontiers
        .remove_frontier
        .as_ref()
        .is_some_and(&mut t0_contains);
    if !remove_visible
        && frontiers
            .join_frontier
            .as_ref()
            .is_some_and(&mut t0_contains)
    {
        return HistoryReaderEventState::Joined;
    }
    if !remove_visible
        && frontiers
            .invite_frontier
            .as_ref()
            .is_some_and(&mut t0_contains)
    {
        return HistoryReaderEventState::Invited;
    }
    if remove_visible {
        HistoryReaderEventState::Removed
    } else {
        HistoryReaderEventState::None
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryReaderEventState {
    #[default]
    None,
    Invited,
    Joined,
    Removed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryReaderContext {
    pub current_active_member: bool,
    pub event_state: HistoryReaderEventState,
    pub has_discoverability: bool,
    pub has_preview_token: bool,
}

impl HistoryReaderContext {
    pub fn active_member_at_t0(current_active_member: bool, joined_at_t0: bool) -> Self {
        Self {
            current_active_member,
            event_state: if joined_at_t0 {
                HistoryReaderEventState::Joined
            } else {
                HistoryReaderEventState::None
            },
            has_discoverability: true,
            has_preview_token: false,
        }
    }

    pub fn receiver_class(self) -> Option<HistorySharingReceiverClass> {
        if self.current_active_member {
            Some(HistorySharingReceiverClass::ActiveMember)
        } else if self.event_state == HistoryReaderEventState::Invited {
            Some(HistorySharingReceiverClass::Invited)
        } else if self.event_state == HistoryReaderEventState::Removed {
            Some(HistorySharingReceiverClass::RemovedT0Visible)
        } else if self.has_preview_token {
            Some(HistorySharingReceiverClass::PreviewTokenHolder)
        } else if self.has_discoverability {
            Some(HistorySharingReceiverClass::WorldReadableRequester)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryRangeContext {
    pub since_invite: bool,
    pub since_join: bool,
    pub epoch_span: Option<u64>,
}

impl HistoryRangeContext {
    pub fn from_membership(since_invite: bool, since_join: bool) -> Self {
        Self {
            since_invite,
            since_join,
            epoch_span: None,
        }
    }

    pub fn matches(self, range: HistorySharingRange, max_epoch_span: Option<u64>) -> bool {
        match range {
            HistorySharingRange::AllVisibleAtT0 => true,
            HistorySharingRange::SinceInvite => self.since_invite || self.since_join,
            HistorySharingRange::SinceJoin => self.since_join,
            HistorySharingRange::BoundedEpochRange => {
                let (Some(actual), Some(max)) = (self.epoch_span, max_epoch_span) else {
                    return false;
                };
                actual <= max
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedRuleMatch {
    pub rule_id: String,
    pub audit_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryVisibilityDecision {
    pub allowed: bool,
    pub receiver_class: Option<HistorySharingReceiverClass>,
    pub matched_restricted_rules: Vec<RestrictedRuleMatch>,
}

impl HistoryVisibilityDecision {
    pub fn denied() -> Self {
        Self {
            allowed: false,
            receiver_class: None,
            matched_restricted_rules: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistorySharingRestrictedScopeRef<'a> {
    pub kind: HistorySharingScopeKind,
    pub circle_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryDeviceGate {
    pub revoked: bool,
    pub verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryAuditGate {
    pub required: bool,
    pub satisfied: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryKeyShareDecision {
    pub allowed: bool,
    pub withheld_reason_code: Option<RealmKeyWithheldReasonCode>,
    pub matched_restricted_rules: Vec<RestrictedRuleMatch>,
}

impl HistoryKeyShareDecision {
    pub fn allow(matched_restricted_rules: Vec<RestrictedRuleMatch>) -> Self {
        Self {
            allowed: true,
            withheld_reason_code: None,
            matched_restricted_rules,
        }
    }

    pub fn deny(reason: RealmKeyWithheldReasonCode) -> Self {
        Self {
            allowed: false,
            withheld_reason_code: Some(reason),
            matched_restricted_rules: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistorySharingPolicyValidationError {
    EmptyAllowedKeySources,
    EmptyAllowedReceiverStates,
    EmptyRuleReceiverClasses { rule_id: String },
    EmptyRuleAllowedVisibilityValues { rule_id: String },
    EmptyRuleKeySources { rule_id: String },
    DuplicateAllowedKeySource,
    DuplicateAllowedReceiverState,
    DuplicateRuleId { rule_id: String },
    DuplicateRuleReceiverClass { rule_id: String },
    DuplicateRuleVisibilityValue { rule_id: String },
    DuplicateRuleKeySource { rule_id: String },
    InvalidRuleId { rule_id: String },
    TooManyRestrictedRules { count: usize },
    CircleScopeRequiresCircleId { rule_id: String },
    RealmScopeMustNotCarryCircleId { rule_id: String },
    BoundedEpochRangeRequiresMaxEpochSpan { rule_id: String },
    NonBoundedRangeMustNotCarryMaxEpochSpan { rule_id: String },
}

impl fmt::Display for HistorySharingPolicyValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAllowedKeySources => f.write_str("allowed_key_sources must not be empty"),
            Self::EmptyAllowedReceiverStates => {
                f.write_str("allowed_receiver_states must not be empty")
            }
            Self::EmptyRuleReceiverClasses { rule_id } => {
                write!(
                    f,
                    "restricted rule {rule_id} receiver_classes must not be empty"
                )
            }
            Self::EmptyRuleAllowedVisibilityValues { rule_id } => write!(
                f,
                "restricted rule {rule_id} allowed_history_visibility_values must not be empty"
            ),
            Self::EmptyRuleKeySources { rule_id } => {
                write!(f, "restricted rule {rule_id} key_sources must not be empty")
            }
            Self::DuplicateAllowedKeySource => {
                f.write_str("allowed_key_sources must contain unique values")
            }
            Self::DuplicateAllowedReceiverState => {
                f.write_str("allowed_receiver_states must contain unique values")
            }
            Self::DuplicateRuleId { rule_id } => {
                write!(f, "restricted rule_id {rule_id} is duplicated")
            }
            Self::DuplicateRuleReceiverClass { rule_id } => {
                write!(
                    f,
                    "restricted rule {rule_id} receiver_classes contains duplicates"
                )
            }
            Self::DuplicateRuleVisibilityValue { rule_id } => write!(
                f,
                "restricted rule {rule_id} allowed_history_visibility_values contains duplicates"
            ),
            Self::DuplicateRuleKeySource { rule_id } => {
                write!(
                    f,
                    "restricted rule {rule_id} key_sources contains duplicates"
                )
            }
            Self::InvalidRuleId { rule_id } => {
                write!(f, "restricted rule_id {rule_id} is invalid")
            }
            Self::TooManyRestrictedRules { count } => {
                write!(f, "restricted_rules has {count} entries, maximum is 32")
            }
            Self::CircleScopeRequiresCircleId { rule_id } => {
                write!(
                    f,
                    "restricted rule {rule_id} circle scope requires circle_id"
                )
            }
            Self::RealmScopeMustNotCarryCircleId { rule_id } => {
                write!(
                    f,
                    "restricted rule {rule_id} realm scope must not carry circle_id"
                )
            }
            Self::BoundedEpochRangeRequiresMaxEpochSpan { rule_id } => write!(
                f,
                "restricted rule {rule_id} bounded_epoch_range requires max_epoch_span"
            ),
            Self::NonBoundedRangeMustNotCarryMaxEpochSpan { rule_id } => write!(
                f,
                "restricted rule {rule_id} max_epoch_span is only valid for bounded_epoch_range"
            ),
        }
    }
}

impl std::error::Error for HistorySharingPolicyValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_join_history_visibility_requires_history_capable_content_scheme() {
        assert_eq!(
            validate_history_visibility_content_scheme(
                HistoryVisibility::Shared,
                Some("mls_rfc9420")
            ),
            Err(ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME)
        );
        assert!(
            validate_history_visibility_content_scheme(
                HistoryVisibility::Shared,
                Some("mls_exporter_aead_v1")
            )
            .is_ok()
        );
    }

    #[test]
    fn joined_history_visibility_allows_both_content_schemes() {
        assert!(
            validate_history_visibility_content_scheme(
                HistoryVisibility::Joined,
                Some("mls_rfc9420")
            )
            .is_ok()
        );
        assert!(
            validate_history_visibility_content_scheme(
                HistoryVisibility::Joined,
                Some("mls_exporter_aead_v1")
            )
            .is_ok()
        );
    }

    #[test]
    fn frontiers_use_current_membership_chain_after_leave_rejoin() {
        let events = vec![
            HistoryMembershipEvent::invite("alice", "invite1"),
            HistoryMembershipEvent::join("alice", "join1"),
            HistoryMembershipEvent::leave("alice", "leave1"),
            HistoryMembershipEvent::invite("alice", "invite2"),
            HistoryMembershipEvent::join("alice", "join2"),
        ];
        let frontiers = history_membership_frontiers("alice", &events);
        assert_eq!(frontiers.invite_frontier, Some("invite2"));
        assert_eq!(frontiers.join_frontier, Some("join2"));
        assert_eq!(frontiers.remove_frontier, None);
    }

    #[test]
    fn frontiers_discard_revoked_invite_before_reinvite() {
        let events = vec![
            HistoryMembershipEvent::invite("alice", "invite1"),
            HistoryMembershipEvent::revoke_invite("alice", "revoke1"),
            HistoryMembershipEvent::invite("alice", "invite2"),
        ];
        let frontiers = history_membership_frontiers("alice", &events);
        assert_eq!(frontiers.invite_frontier, Some("invite2"));
        assert_eq!(frontiers.join_frontier, None);
        assert_eq!(frontiers.remove_frontier, None);
    }

    #[test]
    fn reader_state_at_t0_does_not_adopt_uncovered_join_frontier() {
        let frontiers = HistoryMembershipFrontiers {
            invite_frontier: Some("invite2"),
            join_frontier: Some("join2"),
            remove_frontier: None,
        };
        let state = history_reader_state_at_t0(&frontiers, |frontier| *frontier == "invite2");
        assert_eq!(state, HistoryReaderEventState::Invited);
    }

    #[test]
    fn withheld_reason_unknown_value_fails_closed() {
        let value = serde_json::json!("not_a_reason");
        let result = serde_json::from_value::<RealmKeyWithheldReasonCode>(value);
        assert!(result.is_err());
    }

    #[test]
    fn history_sharing_policy_enums_match_registered_wire_values() {
        assert_eq!(
            serde_json::to_value(HistorySharingPreJoinPolicy::AllowIfVisibilityAllows).unwrap(),
            serde_json::json!("visibility_condition_allowed")
        );
        assert_eq!(
            serde_json::to_value(
                HistorySharingPostRemovalRecoveryPolicy::AllowT0VisibleWithCurrentPolicy
            )
            .unwrap(),
            serde_json::json!("t0_visibility_with_current_policy_allowed")
        );
    }
}
