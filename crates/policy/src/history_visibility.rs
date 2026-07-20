//! History-sharing key-share policy evaluation.
//!
//! The wire vocabulary (receiver classes, key sources, ranges, decision and
//! gate types) lives in `arkret-models-collaboration`; this module holds the
//! policy-evaluation behavior that consumes the
//! `HistorySharingPolicyPayloadValue` payload and the `HistorySharingRestrictedRule`
//! family. `arkret-core` re-exports these functions so the
//! `arkret_core::models` panel is unchanged.

use std::collections::BTreeSet;

use arkret_models_collaboration::events_payloads::strand_history_join::{
    HistorySharingPolicyPayloadValue, HistorySharingRestrictedRule,
};
use arkret_models_collaboration::governance::history_visibility::{
    HistoryAuditGate, HistoryDeviceGate, HistoryKeyShareDecision, HistoryKeyShareDefault,
    HistoryKeySource, HistoryRangeContext, HistoryReaderContext, HistoryReaderEventState,
    HistorySharingPolicyValidationError, HistorySharingRange, HistorySharingReceiverClass,
    HistorySharingRestrictedScopeRef, HistorySharingScopeKind, HistoryVisibilityDecision,
    RealmKeyWithheldReasonCode, RestrictedRuleMatch,
};
use arkret_wire::HistoryVisibility;

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
mod policy_tests {
    use arkret_models_collaboration::events_payloads::strand_history_join::HistorySharingPolicyPayloadValueAudit;
    use arkret_models_collaboration::governance::history_visibility::HistorySharingPreJoinPolicy;

    use super::*;

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
}
