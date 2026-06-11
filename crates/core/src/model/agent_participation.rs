//! CKP-0010 — Agent participation policy.
//!
//! Three orthogonal autonomous-behavior bits a native personal agent's
//! controller may enable in a scope, each capped by a monotone
//! `deployment ⊇ Realm ⊇ Circle ⊇ Flow` ceiling. The effective
//! participation in a scope is `effective_ceiling ∩ controller_selection`,
//! where `effective_ceiling` is the bitwise AND of every enclosing
//! level's ceiling (CKP-0010 §3–§5).
//!
//! Enforcement is not in this module: `reply` / `act_on_behalf`
//! materialize into ordinary `ck.capability.grant` records, and
//! `accept_third_party_mention` drives the dispatcher's mention fanout
//! gate. This module only supplies the wire vocabulary and the
//! reducer-pure tighten-only validators that those layers call.

use serde::{Deserialize, Serialize};

use crate::{CircleId, FlowId, RealmId};

/// Controller-owned account-data type carrying a per-scope participation
/// selection (CKP-0010 §5.1).
pub const AGENT_PARTICIPATION_ACCOUNT_DATA_TYPE: &str = "ck.agent.participation.v1";

/// The three participation bits. Constructs a partial order under
/// implication: `a ⊆ b` iff every bit set in `a` is set in `b`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentParticipation {
    /// Agent may author `ck.message.create` / `ck.reaction.add` as
    /// itself (reply-as-agent) in this scope.
    #[serde(default)]
    pub reply: bool,
    /// A mention authored by a principal other than the agent's
    /// controller is delivered to the agent and may trigger autonomous
    /// handling. When false, only the controller's own mentions reach
    /// the agent.
    #[serde(default)]
    pub accept_third_party_mention: bool,
    /// Agent may author `actor_id=controller, executed_by=agent`
    /// (act-on-behalf), subject to CKP-0008 §4.10 approval constraints.
    #[serde(default)]
    pub act_on_behalf: bool,
}

impl AgentParticipation {
    /// Minimal element — every bit off.
    pub const NONE: Self =
        Self { reply: false, accept_third_party_mention: false, act_on_behalf: false };

    /// Maximal element — every bit on (the deployment-default ceiling
    /// fold seed).
    pub const ALL: Self =
        Self { reply: true, accept_third_party_mention: true, act_on_behalf: true };

    /// Bitwise AND. Used both for folding the ceiling chain and for
    /// `effective = ceiling ∩ selection`.
    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self {
            reply: self.reply && other.reply,
            accept_third_party_mention: self.accept_third_party_mention
                && other.accept_third_party_mention,
            act_on_behalf: self.act_on_behalf && other.act_on_behalf,
        }
    }

    /// `self ⊆ other`: every enabled bit of `self` is enabled in
    /// `other`.
    #[must_use]
    pub fn is_subset_of(self, other: Self) -> bool {
        (!self.reply || other.reply)
            && (!self.accept_third_party_mention || other.accept_third_party_mention)
            && (!self.act_on_behalf || other.act_on_behalf)
    }
}

/// The scope a participation selection / ceiling applies to. Realm,
/// Circle, or Flow — the three levels at which a controller can set a
/// selection and at which governance can declare a ceiling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentParticipationScope {
    Realm { realm_id: RealmId },
    Circle { realm_id: RealmId, circle_id: CircleId },
    Flow { realm_id: RealmId, flow_id: FlowId },
}

impl AgentParticipationScope {
    /// Canonical account-data scope_key suffix (CKP-0010 §5.1):
    /// `realm:<realm_uuid>` / `circle:<realm_uuid>:<circle_uuid>` /
    /// `flow:<realm_uuid>:<flow_uuid>`. The uuid part is the segment
    /// after the last `:` of each typed id.
    #[must_use]
    pub fn scope_key(&self) -> String {
        match self {
            Self::Realm { realm_id } => format!("realm:{}", uuid_part(realm_id.as_str())),
            Self::Circle { realm_id, circle_id } => {
                format!("circle:{}:{}", uuid_part(realm_id.as_str()), uuid_part(circle_id.as_str()))
            }
            Self::Flow { realm_id, flow_id } => {
                format!("flow:{}:{}", uuid_part(realm_id.as_str()), uuid_part(flow_id.as_str()))
            }
        }
    }

    /// The Realm this scope belongs to.
    #[must_use]
    pub fn realm_id(&self) -> &RealmId {
        match self {
            Self::Realm { realm_id }
            | Self::Circle { realm_id, .. }
            | Self::Flow { realm_id, .. } => realm_id,
        }
    }
}

fn uuid_part(typed_id: &str) -> &str {
    typed_id.rsplit(':').next().unwrap_or(typed_id)
}

/// Error surfaced by the reducer-pure participation validators.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AgentParticipationError {
    /// An inner-scope ceiling enables a bit its parent ceiling disables.
    #[error(
        "reason=agent_participation_ceiling_widen: child {child:?} widens parent ceiling {parent:?}"
    )]
    CeilingWiden { parent: AgentParticipation, child: AgentParticipation },
    /// A controller selection enables a bit the effective ceiling
    /// disables.
    #[error(
        "reason=agent_participation_exceeds_ceiling: selection {selection:?} exceeds ceiling {ceiling:?}"
    )]
    ExceedsCeiling { ceiling: AgentParticipation, selection: AgentParticipation },
}

/// Reducer-pure validator (CKP-0010 §3 invariant 1): an inner scope's
/// participation ceiling MAY only tighten (drop bits from) its parent
/// ceiling, never widen it. Returns `Ok(())` iff `child ⊆ parent`.
pub fn validate_agent_participation_tightens(
    parent: AgentParticipation,
    child: AgentParticipation,
) -> Result<(), AgentParticipationError> {
    if child.is_subset_of(parent) {
        Ok(())
    } else {
        Err(AgentParticipationError::CeilingWiden { parent, child })
    }
}

/// Fold a ceiling chain by intersection, seeded with [`AgentParticipation::ALL`].
/// Because invariant 1 already guarantees monotone tightening, this is
/// equivalent to taking the innermost explicit value, but folding by AND
/// is fail-closed against historically non-conforming data (CKP-0010 §4.4).
pub fn fold_ceiling_chain<I>(chain: I) -> AgentParticipation
where
    I: IntoIterator<Item = AgentParticipation>,
{
    chain.into_iter().fold(AgentParticipation::ALL, |acc, c| acc.intersect(c))
}

/// Effective participation = effective ceiling ∩ controller selection
/// (CKP-0010 §2).
#[must_use]
pub fn effective_participation(
    ceiling: AgentParticipation,
    selection: AgentParticipation,
) -> AgentParticipation {
    ceiling.intersect(selection)
}

/// Validate a controller selection against the effective ceiling: every
/// enabled bit MUST be permitted by the ceiling (CKP-0010 §8.1). Returns
/// `Ok(())` iff `selection ⊆ ceiling`.
pub fn validate_selection_within_ceiling(
    ceiling: AgentParticipation,
    selection: AgentParticipation,
) -> Result<(), AgentParticipationError> {
    if selection.is_subset_of(ceiling) {
        Ok(())
    } else {
        Err(AgentParticipationError::ExceedsCeiling { ceiling, selection })
    }
}

/// Request body for `ck.self.agent.participation.set`
/// (`PUT /_cokret/self/agents/{agent_principal_id}/participation`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentParticipationSetRequestBody {
    #[serde(rename = "participation_scope")]
    pub scope: AgentParticipationScope,
    pub selection: AgentParticipation,
}

/// One resolved per-scope participation entry: the controller-set
/// selection, the governance ceiling, and their effective intersection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentParticipationEntry {
    #[serde(rename = "participation_scope")]
    pub scope: AgentParticipationScope,
    pub selection: AgentParticipation,
    pub ceiling: AgentParticipation,
    pub effective: AgentParticipation,
}

/// Response for `ck.self.agent.participation.{set,get}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentParticipationOutcome {
    pub ok: bool,
    pub agent_principal_id: String,
    pub entries: Vec<AgentParticipationEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(reply: bool, mention: bool, aob: bool) -> AgentParticipation {
        AgentParticipation { reply, accept_third_party_mention: mention, act_on_behalf: aob }
    }

    #[test]
    fn subset_and_intersect() {
        assert!(AgentParticipation::NONE.is_subset_of(AgentParticipation::ALL));
        assert!(!AgentParticipation::ALL.is_subset_of(AgentParticipation::NONE));
        assert!(p(true, false, false).is_subset_of(p(true, true, false)));
        assert!(!p(true, true, false).is_subset_of(p(true, false, false)));
        assert_eq!(p(true, true, false).intersect(p(true, false, true)), p(true, false, false));
    }

    #[test]
    fn tighten_only_rejects_widening() {
        // Parent allows reply only; child tries to add mention → reject.
        let parent = p(true, false, false);
        let child = p(true, true, false);
        assert!(matches!(
            validate_agent_participation_tightens(parent, child),
            Err(AgentParticipationError::CeilingWiden { .. })
        ));
        // Child that only drops bits is accepted.
        assert!(validate_agent_participation_tightens(parent, p(false, false, false)).is_ok());
        assert!(validate_agent_participation_tightens(parent, parent).is_ok());
    }

    #[test]
    fn effective_is_ceiling_meet_selection() {
        let ceiling = p(true, true, false);
        let selection = p(true, false, true);
        assert_eq!(effective_participation(ceiling, selection), p(true, false, false));
    }

    #[test]
    fn selection_within_ceiling_gate() {
        let ceiling = p(true, false, false);
        assert!(validate_selection_within_ceiling(ceiling, p(true, false, false)).is_ok());
        assert!(matches!(
            validate_selection_within_ceiling(ceiling, p(true, true, false)),
            Err(AgentParticipationError::ExceedsCeiling { .. })
        ));
    }

    #[test]
    fn ceiling_chain_folds_by_intersection() {
        // deployment ⊇ realm ⊇ circle ⊇ flow.
        let chain = [
            p(true, true, true),   // deployment
            p(true, true, false),  // realm
            p(true, false, false), // circle
            p(true, false, false), // flow
        ];
        assert_eq!(fold_ceiling_chain(chain), p(true, false, false));
    }

    #[test]
    fn scope_key_canonical() {
        let realm =
            RealmId::new("ck:realm:01970000-0000-7000-8000-000000000000".to_owned()).unwrap();
        let flow = FlowId::new("ck:flow:01970000-0000-7000-8000-000000000001".to_owned()).unwrap();
        let scope = AgentParticipationScope::Flow { realm_id: realm, flow_id: flow };
        assert_eq!(
            scope.scope_key(),
            "flow:01970000-0000-7000-8000-000000000000:01970000-0000-7000-8000-000000000001"
        );
    }
}
