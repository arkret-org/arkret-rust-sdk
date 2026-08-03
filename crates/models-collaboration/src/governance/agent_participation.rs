//! AKP-0010 — Agent participation policy.
//!
//! Five orthogonal autonomous-behavior bits a native personal agent's
//! controller may enable in a scope, each capped by a monotone
//! `deployment ⊇ Realm ⊇ Circle ⊇ Strand` ceiling. The effective
//! participation in a scope is `effective_ceiling ∩ controller_selection`,
//! where `effective_ceiling` is the bitwise AND of every enclosing
//! level's ceiling (AKP-0010 §3–§5).
//!
//! Enforcement is not in this module: `reply` / `act_on_behalf`
//! materialize into ordinary `ak.capability.grant` records, and
//! `accept_third_party_mention` drives the dispatcher's mention fanout
//! gate. This module only supplies the wire vocabulary and the
//! reducer-pure tighten-only validators that those layers call.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub use crate::protocol_journey::{
    ParticipationBits as AgentParticipation,
    ParticipationReplacementBatch as AgentParticipationReplaceRequestBody,
    ParticipationScope as AgentParticipationScope,
};

/// Stable grant id for the capability materialized from one Agent
/// participation selection. Keeping this derivation shared lets the controller
/// replace or revoke the same grant cell across repeated selection changes.
#[must_use]
pub fn agent_participation_grant_id(agent_id: &str, scope_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ak:grant:agent_participation:v1:");
    hasher.update(agent_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(scope_key.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let hex = |slice: &[u8]| {
        slice
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    format!(
        "ak:grant:{}-{}-{}-{}-{}",
        hex(&bytes[0..4]),
        hex(&bytes[4..6]),
        hex(&bytes[6..8]),
        hex(&bytes[8..10]),
        hex(&bytes[10..16]),
    )
}

/// Optional per-bit governance ceiling declaration for Circle / Strand
/// objects. Omitted bits inherit the parent ceiling independently.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentParticipationCeiling {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_message: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction_add: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction_remove: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_third_party_mention: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_on_behalf: Option<bool>,
}

/// Governance object shape used by Realm, Circle and Strand schemas.
/// Native personal-agent permissions are explicitly namespaced so future
/// applet-agent policy cannot be confused with this ceiling.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentParticipationPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_agent: Option<AgentParticipationCeiling>,
}

impl AgentParticipationPolicy {
    /// Materialize the native-agent declaration against its parent ceiling.
    #[must_use]
    pub fn materialize_native_agent(self, parent: AgentParticipation) -> AgentParticipation {
        self.native_agent
            .map_or(parent, |ceiling| ceiling.materialize(parent))
    }
}

impl AgentParticipationCeiling {
    /// Materialize this declaration against its parent ceiling.
    #[must_use]
    pub fn materialize(self, parent: AgentParticipation) -> AgentParticipation {
        AgentParticipation {
            reply_message: self.reply_message.unwrap_or(parent.reply_message),
            reaction_add: self.reaction_add.unwrap_or(parent.reaction_add),
            reaction_remove: self.reaction_remove.unwrap_or(parent.reaction_remove),
            accept_third_party_mention: self
                .accept_third_party_mention
                .unwrap_or(parent.accept_third_party_mention),
            act_on_behalf: self.act_on_behalf.unwrap_or(parent.act_on_behalf),
        }
    }
}

impl From<AgentParticipation> for AgentParticipationCeiling {
    fn from(value: AgentParticipation) -> Self {
        Self {
            reply_message: Some(value.reply_message),
            reaction_add: Some(value.reaction_add),
            reaction_remove: Some(value.reaction_remove),
            accept_third_party_mention: Some(value.accept_third_party_mention),
            act_on_behalf: Some(value.act_on_behalf),
        }
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
        parent: AgentParticipation,
        child: AgentParticipation,
    },
    /// A controller selection enables a bit the effective ceiling
    /// disables.
    #[error(
        "reason=agent_participation_exceeds_ceiling: selection {selection:?} exceeds ceiling {ceiling:?}"
    )]
    ExceedsCeiling {
        ceiling: AgentParticipation,
        selection: AgentParticipation,
    },
}

/// Reducer-pure validator (AKP-0010 §3 invariant 1): an inner scope's
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

/// Validate a partial child ceiling declaration against its parent and
/// return the materialized child ceiling.
pub fn validate_agent_participation_ceiling_tightens(
    parent: AgentParticipation,
    child: AgentParticipationCeiling,
) -> Result<AgentParticipation, AgentParticipationError> {
    let materialized = child.materialize(parent);
    validate_agent_participation_tightens(parent, materialized)?;
    Ok(materialized)
}

/// Fold a ceiling chain by intersection, seeded with [`AgentParticipation::ALL`].
/// Because invariant 1 already guarantees monotone tightening, this is
/// equivalent to taking the innermost explicit value, but folding by AND
/// is fail-closed against historically non-conforming data (AKP-0010 §4.4).
pub fn fold_ceiling_chain<I>(chain: I) -> AgentParticipation
where
    I: IntoIterator<Item = AgentParticipation>,
{
    chain
        .into_iter()
        .fold(AgentParticipation::ALL, |acc, c| acc.intersect(c))
}

/// Effective participation = effective ceiling ∩ controller selection
/// (AKP-0010 §2).
#[must_use]
pub fn effective_participation(
    ceiling: AgentParticipation,
    selection: AgentParticipation,
) -> AgentParticipation {
    ceiling.intersect(selection)
}

/// Validate a controller selection against the effective ceiling: every
/// enabled bit MUST be permitted by the ceiling (AKP-0010 §8.1). Returns
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

/// One resolved per-scope participation entry: the controller-set
/// selection, the governance ceiling, and their effective intersection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentParticipationEntry {
    #[serde(rename = "target_scope")]
    pub scope: AgentParticipationScope,
    pub selection: AgentParticipation,
    pub ceiling: AgentParticipation,
    pub effective: AgentParticipation,
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

    fn p(reply: bool, mention: bool, aob: bool) -> AgentParticipation {
        AgentParticipation {
            reply,
            accept_third_party_mention: mention,
            act_on_behalf: aob,
        }
    }

    #[test]
    fn subset_and_intersect() {
        assert!(AgentParticipation::NONE.is_subset_of(AgentParticipation::ALL));
        assert!(!AgentParticipation::ALL.is_subset_of(AgentParticipation::NONE));
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
    fn ceiling_declaration_inherits_omitted_bits() {
        let parent = p(true, false, true);
        let child = AgentParticipationCeiling {
            reply: Some(false),
            accept_third_party_mention: None,
            act_on_behalf: None,
        };
        assert_eq!(
            validate_agent_participation_ceiling_tightens(parent, child).unwrap(),
            p(false, false, true)
        );
    }

    #[test]
    fn governance_policy_wraps_native_agent_ceiling() {
        let policy = AgentParticipationPolicy {
            native_agent: Some(AgentParticipationCeiling {
                reply: Some(true),
                accept_third_party_mention: None,
                act_on_behalf: Some(false),
            }),
        };
        assert_eq!(
            serde_json::to_value(policy).unwrap(),
            serde_json::json!({
                "native_agent": {
                    "reply": true,
                    "act_on_behalf": false
                }
            })
        );
        assert!(
            serde_json::from_value::<AgentParticipationPolicy>(serde_json::json!({
                "reply": true
            }))
            .is_err()
        );
    }

    #[test]
    fn ceiling_declaration_rejects_explicit_widening() {
        let parent = p(true, false, false);
        let child = AgentParticipationCeiling {
            reply: None,
            accept_third_party_mention: Some(true),
            act_on_behalf: None,
        };
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
        let scope = AgentParticipationScope::Strand {
            realm_id: realm,
            strand_id: strand,
        };
        assert_eq!(
            scope.scope_key(),
            "strand:01970000-0000-7000-8000-000000000000:01970000-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn participation_grant_id_is_stable_and_scope_specific() {
        let agent = "did:web:agent.example";
        let realm_scope = "realm:01970000-0000-7000-8000-000000000000";
        let first = agent_participation_grant_id(agent, realm_scope);
        assert_eq!(first, agent_participation_grant_id(agent, realm_scope));
        assert_ne!(
            first,
            agent_participation_grant_id(
                agent,
                "strand:01970000-0000-7000-8000-000000000000:01970000-0000-7000-8000-000000000001"
            )
        );
        assert!(arkret_wire::GrantId::new(first).is_ok());
    }
}
