//! AKP-0010 — Agent participation policy.
//!
//! Five orthogonal autonomous-behavior bits a native personal agent's
//! controller may enable in a scope, each capped by a monotone
//! `deployment ⊇ Realm ⊇ Circle ⊇ Strand` ceiling. The effective
//! participation in a scope is `effective_ceiling ∩ controller_selection`,
//! where `effective_ceiling` is the bitwise AND of every enclosing
//! level's ceiling (AKP-0010 §3–§5).
//!
//! Participation is an additional execution gate, never a capability grant.
//! An action is allowed only when ordinary capability/lifecycle checks pass
//! and the current selection/ceiling intersection enables its bit.

use arkret_wire::{CircleId, RealmId, StrandId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationBits {
    pub reply_message: bool,
    pub reaction_add: bool,
    pub reaction_remove: bool,
    pub accept_third_party_mention: bool,
    pub act_on_behalf: bool,
}

impl ParticipationBits {
    pub const NONE: Self = Self {
        reply_message: false,
        reaction_add: false,
        reaction_remove: false,
        accept_third_party_mention: false,
        act_on_behalf: false,
    };

    pub const ALL: Self = Self {
        reply_message: true,
        reaction_add: true,
        reaction_remove: true,
        accept_third_party_mention: true,
        act_on_behalf: true,
    };

    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self {
            reply_message: self.reply_message && other.reply_message,
            reaction_add: self.reaction_add && other.reaction_add,
            reaction_remove: self.reaction_remove && other.reaction_remove,
            accept_third_party_mention: self.accept_third_party_mention
                && other.accept_third_party_mention,
            act_on_behalf: self.act_on_behalf && other.act_on_behalf,
        }
    }

    #[must_use]
    pub fn is_subset_of(self, ceiling: Self) -> bool {
        (!self.reply_message || ceiling.reply_message)
            && (!self.reaction_add || ceiling.reaction_add)
            && (!self.reaction_remove || ceiling.reaction_remove)
            && (!self.accept_third_party_mention || ceiling.accept_third_party_mention)
            && (!self.act_on_behalf || ceiling.act_on_behalf)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ParticipationScope {
    Realm {
        realm_id: RealmId,
    },
    Circle {
        realm_id: RealmId,
        circle_id: CircleId,
    },
    Strand {
        realm_id: RealmId,
        strand_id: StrandId,
    },
}

impl ParticipationScope {
    pub fn realm_id(&self) -> &RealmId {
        match self {
            Self::Realm { realm_id }
            | Self::Circle { realm_id, .. }
            | Self::Strand { realm_id, .. } => realm_id,
        }
    }

    /// Stable account-data key used by participation projections.
    #[must_use]
    pub fn scope_key(&self) -> String {
        match self {
            Self::Realm { realm_id } => format!("realm:{}", uuid_part(realm_id.as_str())),
            Self::Circle {
                realm_id,
                circle_id,
            } => format!(
                "circle:{}:{}",
                uuid_part(realm_id.as_str()),
                uuid_part(circle_id.as_str())
            ),
            Self::Strand {
                realm_id,
                strand_id,
            } => format!(
                "strand:{}:{}",
                uuid_part(realm_id.as_str()),
                uuid_part(strand_id.as_str())
            ),
        }
    }
}

fn uuid_part(typed_id: &str) -> &str {
    typed_id.rsplit(':').next().unwrap_or(typed_id)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationReplaceRequestBody {
    pub target_scope: ParticipationScope,
    pub selection: ParticipationBits,
    pub expected_version: u64,
}

/// Governance object shape used by Realm, Circle and Strand schemas.
/// Native personal-agent permissions are explicitly namespaced so future
/// applet-agent policy cannot be confused with this ceiling.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentParticipationPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_agent: Option<ParticipationBits>,
}

impl AgentParticipationPolicy {
    /// Materialize the native-agent declaration against its parent ceiling.
    #[must_use]
    pub fn materialize_native_agent(self, parent: ParticipationBits) -> ParticipationBits {
        self.native_agent.unwrap_or(parent)
    }
}

/// Error surfaced by the reducer-pure participation validators.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AgentParticipationError {
    /// An inner-scope ceiling enables a bit its parent ceiling disables.
    #[error(
        "reason=agent_participation_ceiling_widen: child {child:?} widens parent ceiling {parent:?}"
    )]
    CeilingWiden {
        parent: ParticipationBits,
        child: ParticipationBits,
    },
}

/// Reducer-pure validator (AKP-0010 §3 invariant 1): an inner scope's
/// participation ceiling MAY only tighten (drop bits from) its parent
/// ceiling, never widen it. Returns `Ok(())` iff `child ⊆ parent`.
pub fn validate_agent_participation_tightens(
    parent: ParticipationBits,
    child: ParticipationBits,
) -> Result<(), AgentParticipationError> {
    if child.is_subset_of(parent) {
        Ok(())
    } else {
        Err(AgentParticipationError::CeilingWiden { parent, child })
    }
}

/// Validate a partial child ceiling declaration against its parent and
/// return the materialized child ceiling.
pub fn validate_agent_participation_ceiling_tightens(
    parent: ParticipationBits,
    child: ParticipationBits,
) -> Result<ParticipationBits, AgentParticipationError> {
    validate_agent_participation_tightens(parent, child)?;
    Ok(child)
}

/// Fold a ceiling chain by intersection, seeded with [`ParticipationBits::ALL`].
/// Because invariant 1 already guarantees monotone tightening, this is
/// equivalent to taking the innermost explicit value, but folding by AND
/// is fail-closed against historically non-conforming data (AKP-0010 §4.4).
pub fn fold_ceiling_chain<I>(chain: I) -> ParticipationBits
where
    I: IntoIterator<Item = ParticipationBits>,
{
    chain
        .into_iter()
        .fold(ParticipationBits::ALL, |acc, c| acc.intersect(c))
}

/// Effective participation = effective ceiling ∩ controller selection
/// (AKP-0010 §2).
#[must_use]
pub fn effective_participation(
    ceiling: ParticipationBits,
    selection: ParticipationBits,
) -> ParticipationBits {
    ceiling.intersect(selection)
}

/// One controller-owned, versioned per-scope participation selection.
/// Governance and deployment ceilings are evaluated at action time and are
/// intentionally not copied into this authority record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentParticipationEntry {
    #[serde(rename = "target_scope")]
    pub scope: ParticipationScope,
    pub selection: ParticipationBits,
    pub version: u64,
}

/// Response for `ak.self.agent.participation.{set,get}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentParticipationOutcome {
    pub ok: bool,
    pub agent_id: String,
    pub entries: Vec<AgentParticipationEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkret_wire::{RealmId, StrandId};

    fn p(reply: bool, mention: bool, aob: bool) -> ParticipationBits {
        ParticipationBits {
            reply_message: reply,
            reaction_add: reply,
            reaction_remove: reply,
            accept_third_party_mention: mention,
            act_on_behalf: aob,
        }
    }

    #[test]
    fn subset_and_intersect() {
        assert!(ParticipationBits::NONE.is_subset_of(ParticipationBits::ALL));
        assert!(!ParticipationBits::ALL.is_subset_of(ParticipationBits::NONE));
        assert!(p(true, false, false).is_subset_of(p(true, true, false)));
        assert!(!p(true, true, false).is_subset_of(p(true, false, false)));
        assert_eq!(
            p(true, true, false).intersect(p(true, false, true)),
            p(true, false, false)
        );
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
    fn complete_ceiling_tightens_parent() {
        let parent = p(true, false, true);
        let child = p(false, false, true);
        assert_eq!(
            validate_agent_participation_ceiling_tightens(parent, child).unwrap(),
            p(false, false, true)
        );
    }

    #[test]
    fn governance_policy_wraps_native_agent_ceiling() {
        let policy = AgentParticipationPolicy {
            native_agent: Some(ParticipationBits {
                reply_message: true,
                reaction_add: false,
                reaction_remove: false,
                accept_third_party_mention: false,
                act_on_behalf: false,
            }),
        };
        assert_eq!(
            serde_json::to_value(policy).unwrap(),
            serde_json::json!({
                "native_agent": {
                    "reply_message": true,
                    "reaction_add": false,
                    "reaction_remove": false,
                    "accept_third_party_mention": false,
                    "act_on_behalf": false
                }
            })
        );
        assert!(
            serde_json::from_value::<AgentParticipationPolicy>(serde_json::json!({
                "reply_message": true
            }))
            .is_err()
        );
    }

    #[test]
    fn ceiling_declaration_rejects_explicit_widening() {
        let parent = p(true, false, false);
        let child = p(true, true, false);
        assert!(matches!(
            validate_agent_participation_ceiling_tightens(parent, child),
            Err(AgentParticipationError::CeilingWiden { .. })
        ));
    }

    #[test]
    fn effective_is_ceiling_meet_selection() {
        let ceiling = p(true, true, false);
        let selection = p(true, false, true);
        assert_eq!(
            effective_participation(ceiling, selection),
            p(true, false, false)
        );
    }

    #[test]
    fn ceiling_chain_folds_by_intersection() {
        // deployment ⊇ realm ⊇ circle ⊇ strand.
        let chain = [
            p(true, true, true),   // deployment
            p(true, true, false),  // realm
            p(true, false, false), // circle
            p(true, false, false), // strand
        ];
        assert_eq!(fold_ceiling_chain(chain), p(true, false, false));
    }

    #[test]
    fn scope_key_canonical() {
        let realm =
            RealmId::new("ak:realm:01970000-0000-7000-8000-000000000000".to_owned()).unwrap();
        let strand =
            StrandId::new("ak:strand:01970000-0000-7000-8000-000000000001".to_owned()).unwrap();
        let scope = ParticipationScope::Strand {
            realm_id: realm,
            strand_id: strand,
        };
        assert_eq!(
            scope.scope_key(),
            "strand:01970000-0000-7000-8000-000000000000:01970000-0000-7000-8000-000000000001"
        );
    }
}
