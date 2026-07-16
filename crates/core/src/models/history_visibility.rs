use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::{HistorySharingPolicyPayloadValue, HistorySharingRestrictedRule, HistoryVisibility};

pub fn content_scheme_is_history_capable(content_scheme: Option<&str>) -> bool {
    matches!(content_scheme.map(str::trim), Some("mls-exporter-aead-v1"))
}

pub fn validate_history_visibility_content_scheme(
    history_visibility: HistoryVisibility,
    content_scheme: Option<&str>,
) -> Result<(), &'static str> {
    if history_visibility.admits_pre_join_history()
        && !content_scheme_is_history_capable(content_scheme)
    {
        return Err(crate::error::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME);
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HistoryKeyShareDefault {
    Deny,
    EventTimeVisibility,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HistorySharingPreJoinPolicy {
    Deny,
    AllowIfVisibilityAllows,
    RuleOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HistorySharingPostRemovalRecoveryPolicy {
    Deny,
    AllowT0VisibleWithCurrentPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HistoryKeySource {
    OwnDevice,
    VerifiedMemberDevice,
    KeyBackup,
    ArchiveNode,
    RecoveryService,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HistorySharingReceiverClass {
    ActiveMember,
    Invited,
    RemovedT0Visible,
    WorldReadableRequester,
    PreviewTokenHolder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HistorySharingRange {
    AllVisibleAtT0,
    SinceInvite,
    SinceJoin,
    BoundedEpochRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HistorySharingScopeKind {
    Realm,
    Circle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

pub fn event_time_history_visible(
    visibility: HistoryVisibility,
    reader: HistoryReaderContext,
    range: HistoryRangeContext,
    policy: Option<&HistorySharingPolicyPayloadValue>,
) -> HistoryVisibilityDecision {
    let receiver_class = reader.receiver_class();
    let allowed = match visibility {
        HistoryVisibility::WorldReadable => reader.has_discoverability,
        HistoryVisibility::Shared => reader.current_active_member,
        HistoryVisibility::Invited => matches!(
            reader.event_state,
            HistoryReaderEventState::Invited | HistoryReaderEventState::Joined
        ),
        HistoryVisibility::Joined => reader.event_state == HistoryReaderEventState::Joined,
        HistoryVisibility::Restricted => false,
    };
    if visibility != HistoryVisibility::Restricted {
        return HistoryVisibilityDecision {
            allowed,
            receiver_class,
            matched_restricted_rules: Vec::new(),
        };
    }
    let Some(receiver_class) = receiver_class else {
        return HistoryVisibilityDecision::denied();
    };
    let Some(policy) = policy else {
        return HistoryVisibilityDecision::denied();
    };
    let matched_restricted_rules =
        matching_restricted_rules(policy, receiver_class, visibility, range, None, None);
    HistoryVisibilityDecision {
        allowed: !matched_restricted_rules.is_empty(),
        receiver_class: Some(receiver_class),
        matched_restricted_rules,
    }
}

pub fn matching_restricted_rules(
    policy: &HistorySharingPolicyPayloadValue,
    receiver_class: HistorySharingReceiverClass,
    visibility: HistoryVisibility,
    range: HistoryRangeContext,
    key_source: Option<HistoryKeySource>,
    scope: Option<&HistorySharingRestrictedScopeRef<'_>>,
) -> Vec<RestrictedRuleMatch> {
    policy
        .restricted_rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|rule| {
            rule.receiver_classes.contains(&receiver_class)
                && rule.allowed_history_visibility_values.contains(&visibility)
                && range.matches(rule.range, rule.max_epoch_span)
                && key_source.is_none_or(|source| rule.key_sources.contains(&source))
                && scope.is_none_or(|scope| rule_matches_scope(rule, scope))
        })
        .map(|rule| RestrictedRuleMatch {
            rule_id: rule.rule_id.clone(),
            audit_required: rule.audit_required.unwrap_or(true),
        })
        .collect()
}

fn rule_matches_scope(
    rule: &HistorySharingRestrictedRule,
    scope: &HistorySharingRestrictedScopeRef<'_>,
) -> bool {
    let Some(rule_scope) = rule.history_scope.as_ref() else {
        return true;
    };
    match (rule_scope.kind, scope.kind) {
        (HistorySharingScopeKind::Realm, HistorySharingScopeKind::Realm) => true,
        (HistorySharingScopeKind::Circle, HistorySharingScopeKind::Circle) => rule_scope
            .circle_id
            .as_ref()
            .is_some_and(|circle_id| circle_id.as_str() == scope.circle_id.unwrap_or_default()),
        _ => false,
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

#[derive(Clone, Debug)]
pub struct HistoryKeyShareGateInput<'a> {
    pub visibility: HistoryVisibility,
    pub reader: HistoryReaderContext,
    pub range: HistoryRangeContext,
    pub policy: Option<&'a HistorySharingPolicyPayloadValue>,
    pub key_source: HistoryKeySource,
    pub scope: Option<HistorySharingRestrictedScopeRef<'a>>,
    pub device: HistoryDeviceGate,
    pub safety_policy_allows: bool,
    pub audit: HistoryAuditGate,
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

pub fn evaluate_history_key_share_gates(
    input: HistoryKeyShareGateInput<'_>,
) -> HistoryKeyShareDecision {
    if input.device.revoked {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::BlacklistedDevice);
    }
    if !input.device.verified {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::UnverifiedDevice);
    }
    if !input.safety_policy_allows {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::PolicyDenied);
    }
    let visibility_decision =
        event_time_history_visible(input.visibility, input.reader, input.range, input.policy);
    if !visibility_decision.allowed {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::HistoryNotVisible);
    }
    let Some(receiver_class) = visibility_decision.receiver_class else {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::NotMember);
    };
    let Some(policy) = input.policy else {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::PolicyDenied);
    };
    if !policy.receiver_state_allowed(receiver_class) {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::PolicyDenied);
    }
    if !policy.allowed_key_sources.contains(&input.key_source) {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::PolicyDenied);
    }
    let restricted_matches = matching_restricted_rules(
        policy,
        receiver_class,
        input.visibility,
        input.range,
        Some(input.key_source),
        input.scope.as_ref(),
    );
    if input.visibility == HistoryVisibility::Restricted && restricted_matches.is_empty() {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::PolicyDenied);
    }
    if policy.default_key_share == HistoryKeyShareDefault::Deny && restricted_matches.is_empty() {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::PolicyDenied);
    }
    if input.audit.required && !input.audit.satisfied {
        return HistoryKeyShareDecision::deny(RealmKeyWithheldReasonCode::PolicyDenied);
    }
    HistoryKeyShareDecision::allow(restricted_matches)
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

pub fn validate_history_sharing_policy(
    policy: &HistorySharingPolicyPayloadValue,
) -> Result<(), HistorySharingPolicyValidationError> {
    if policy.allowed_key_sources.is_empty() {
        return Err(HistorySharingPolicyValidationError::EmptyAllowedKeySources);
    }
    if has_duplicates(policy.allowed_key_sources.iter()) {
        return Err(HistorySharingPolicyValidationError::DuplicateAllowedKeySource);
    }
    if let Some(receiver_states) = policy.allowed_receiver_states.as_ref() {
        if receiver_states.is_empty() {
            return Err(HistorySharingPolicyValidationError::EmptyAllowedReceiverStates);
        }
        if has_duplicates(receiver_states.iter()) {
            return Err(HistorySharingPolicyValidationError::DuplicateAllowedReceiverState);
        }
    }
    let Some(rules) = policy.restricted_rules.as_ref() else {
        return Ok(());
    };
    if rules.len() > 32 {
        return Err(
            HistorySharingPolicyValidationError::TooManyRestrictedRules { count: rules.len() },
        );
    }
    let mut rule_ids = BTreeSet::new();
    for rule in rules {
        if !valid_restricted_rule_id(&rule.rule_id) {
            return Err(HistorySharingPolicyValidationError::InvalidRuleId {
                rule_id: rule.rule_id.clone(),
            });
        }
        if !rule_ids.insert(rule.rule_id.clone()) {
            return Err(HistorySharingPolicyValidationError::DuplicateRuleId {
                rule_id: rule.rule_id.clone(),
            });
        }
        if rule.receiver_classes.is_empty() {
            return Err(
                HistorySharingPolicyValidationError::EmptyRuleReceiverClasses {
                    rule_id: rule.rule_id.clone(),
                },
            );
        }
        if has_duplicates(rule.receiver_classes.iter()) {
            return Err(
                HistorySharingPolicyValidationError::DuplicateRuleReceiverClass {
                    rule_id: rule.rule_id.clone(),
                },
            );
        }
        if rule.allowed_history_visibility_values.is_empty() {
            return Err(
                HistorySharingPolicyValidationError::EmptyRuleAllowedVisibilityValues {
                    rule_id: rule.rule_id.clone(),
                },
            );
        }
        if has_duplicates(rule.allowed_history_visibility_values.iter()) {
            return Err(
                HistorySharingPolicyValidationError::DuplicateRuleVisibilityValue {
                    rule_id: rule.rule_id.clone(),
                },
            );
        }
        if rule.key_sources.is_empty() {
            return Err(HistorySharingPolicyValidationError::EmptyRuleKeySources {
                rule_id: rule.rule_id.clone(),
            });
        }
        if has_duplicates(rule.key_sources.iter()) {
            return Err(
                HistorySharingPolicyValidationError::DuplicateRuleKeySource {
                    rule_id: rule.rule_id.clone(),
                },
            );
        }
        if let Some(scope) = rule.history_scope.as_ref() {
            match scope.kind {
                HistorySharingScopeKind::Realm => {
                    if scope.circle_id.is_some() {
                        return Err(
                            HistorySharingPolicyValidationError::RealmScopeMustNotCarryCircleId {
                                rule_id: rule.rule_id.clone(),
                            },
                        );
                    }
                }
                HistorySharingScopeKind::Circle => {
                    if scope.circle_id.is_none() {
                        return Err(
                            HistorySharingPolicyValidationError::CircleScopeRequiresCircleId {
                                rule_id: rule.rule_id.clone(),
                            },
                        );
                    }
                }
            }
        }
        match (rule.range, rule.max_epoch_span) {
            (HistorySharingRange::BoundedEpochRange, None) => {
                return Err(
                    HistorySharingPolicyValidationError::BoundedEpochRangeRequiresMaxEpochSpan {
                        rule_id: rule.rule_id.clone(),
                    },
                );
            }
            (HistorySharingRange::BoundedEpochRange, Some(_)) => {}
            (_, Some(_)) => {
                return Err(
                    HistorySharingPolicyValidationError::NonBoundedRangeMustNotCarryMaxEpochSpan {
                        rule_id: rule.rule_id.clone(),
                    },
                );
            }
            (_, None) => {}
        }
    }
    Ok(())
}

fn valid_restricted_rule_id(rule_id: &str) -> bool {
    let mut chars = rule_id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && rule_id.len() <= 64
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

fn has_duplicates<'a, T, I>(values: I) -> bool
where
    T: Ord + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut seen = BTreeSet::new();
    values.into_iter().any(|value| !seen.insert(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HistoryKeyShareDefault, HistoryKeySource, HistorySharingPolicyPayloadValueAudit,
        HistorySharingPreJoinPolicy,
    };

    fn base_policy() -> HistorySharingPolicyPayloadValue {
        HistorySharingPolicyPayloadValue {
            version: 1,
            default_key_share: HistoryKeyShareDefault::EventTimeVisibility,
            pre_join_history: Some(HistorySharingPreJoinPolicy::AllowIfVisibilityAllows),
            post_removal_recovery: None,
            allowed_key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
            allowed_receiver_states: Some(vec![HistorySharingReceiverClass::ActiveMember]),
            audit: HistorySharingPolicyPayloadValueAudit {
                share_audit_event_required: false,
                access_audit_required: false,
            },
            restricted_rules: None,
        }
    }

    #[test]
    fn pre_join_history_visibility_requires_history_capable_content_scheme() {
        assert_eq!(
            validate_history_visibility_content_scheme(
                HistoryVisibility::Shared,
                Some("mls-rfc9420")
            ),
            Err(crate::error::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME)
        );
        assert!(
            validate_history_visibility_content_scheme(
                HistoryVisibility::Shared,
                Some("mls-exporter-aead-v1")
            )
            .is_ok()
        );
    }

    #[test]
    fn joined_history_visibility_allows_both_content_schemes() {
        assert!(
            validate_history_visibility_content_scheme(
                HistoryVisibility::Joined,
                Some("mls-rfc9420")
            )
            .is_ok()
        );
        assert!(
            validate_history_visibility_content_scheme(
                HistoryVisibility::Joined,
                Some("mls-exporter-aead-v1")
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
    fn visibility_matrix_matches_v1_event_time_rules() {
        let active_joined = HistoryReaderContext {
            current_active_member: true,
            event_state: HistoryReaderEventState::Joined,
            has_discoverability: true,
            has_preview_token: false,
        };
        let active_not_t0_joined = HistoryReaderContext {
            current_active_member: true,
            event_state: HistoryReaderEventState::None,
            has_discoverability: true,
            has_preview_token: false,
        };
        let range = HistoryRangeContext::from_membership(false, false);
        assert!(
            event_time_history_visible(
                HistoryVisibility::Shared,
                active_not_t0_joined,
                range,
                None
            )
            .allowed
        );
        assert!(
            !event_time_history_visible(
                HistoryVisibility::Joined,
                active_not_t0_joined,
                range,
                None
            )
            .allowed
        );
        assert!(
            event_time_history_visible(HistoryVisibility::Joined, active_joined, range, None)
                .allowed
        );
    }

    #[test]
    fn restricted_rules_take_union_and_require_key_source_for_key_share() {
        let mut policy = base_policy();
        policy.restricted_rules = Some(vec![
            HistorySharingRestrictedRule {
                rule_id: "read_active".to_owned(),
                history_scope: None,
                receiver_classes: vec![HistorySharingReceiverClass::ActiveMember],
                allowed_history_visibility_values: vec![HistoryVisibility::Restricted],
                range: HistorySharingRange::AllVisibleAtT0,
                max_epoch_span: None,
                key_sources: vec![HistoryKeySource::KeyBackup],
                audit_required: Some(false),
            },
            HistorySharingRestrictedRule {
                rule_id: "member_device".to_owned(),
                history_scope: None,
                receiver_classes: vec![HistorySharingReceiverClass::ActiveMember],
                allowed_history_visibility_values: vec![HistoryVisibility::Restricted],
                range: HistorySharingRange::AllVisibleAtT0,
                max_epoch_span: None,
                key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
                audit_required: Some(false),
            },
        ]);
        let reader = HistoryReaderContext {
            current_active_member: true,
            event_state: HistoryReaderEventState::Joined,
            has_discoverability: true,
            has_preview_token: false,
        };
        let decision = evaluate_history_key_share_gates(HistoryKeyShareGateInput {
            visibility: HistoryVisibility::Restricted,
            reader,
            range: HistoryRangeContext::from_membership(true, true),
            policy: Some(&policy),
            key_source: HistoryKeySource::VerifiedMemberDevice,
            scope: None,
            device: HistoryDeviceGate {
                revoked: false,
                verified: true,
            },
            safety_policy_allows: true,
            audit: HistoryAuditGate {
                required: false,
                satisfied: false,
            },
        });
        assert!(decision.allowed);
        assert_eq!(decision.matched_restricted_rules.len(), 1);
        assert_eq!(
            decision.matched_restricted_rules[0].rule_id,
            "member_device"
        );
    }

    #[test]
    fn policy_validation_rejects_conflicting_restricted_rules() {
        let mut policy = base_policy();
        policy.restricted_rules = Some(vec![
            HistorySharingRestrictedRule {
                rule_id: "dup".to_owned(),
                history_scope: None,
                receiver_classes: vec![HistorySharingReceiverClass::ActiveMember],
                allowed_history_visibility_values: vec![HistoryVisibility::Restricted],
                range: HistorySharingRange::BoundedEpochRange,
                max_epoch_span: Some(8),
                key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
                audit_required: Some(true),
            },
            HistorySharingRestrictedRule {
                rule_id: "dup".to_owned(),
                history_scope: None,
                receiver_classes: vec![HistorySharingReceiverClass::ActiveMember],
                allowed_history_visibility_values: vec![HistoryVisibility::Restricted],
                range: HistorySharingRange::AllVisibleAtT0,
                max_epoch_span: None,
                key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
                audit_required: Some(true),
            },
        ]);
        assert!(matches!(
            validate_history_sharing_policy(&policy),
            Err(HistorySharingPolicyValidationError::DuplicateRuleId { .. })
        ));
    }

    #[test]
    fn withheld_reason_unknown_value_fails_closed() {
        let value = serde_json::json!("not_a_reason");
        let result = serde_json::from_value::<RealmKeyWithheldReasonCode>(value);
        assert!(result.is_err());
    }
}
