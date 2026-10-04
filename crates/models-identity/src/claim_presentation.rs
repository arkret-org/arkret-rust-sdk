//! Controller-scoped Agent selector binding.

use arkret_wire::{AccountId, Result};
use serde::{Deserialize, Serialize};

use crate::handle::HandleVisibility;

/// Value of the `agent_selector_claim` typed current result
/// (`typed-current-result.schema.json#/$defs/agent_selector_claim_value`).
///
/// The selector is `(controller principal, agent_slug)`; the only writer is
/// the selector projection of the accepted `ak.agent.provision`. The value is
/// read only to verify a picker label against an Agent AccountId the client
/// already obtained from an authorized source; it never selects a target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSelectorClaimValue {
    /// Exact Agent account the provision bound this slug onto. A consumer
    /// compares it verbatim; it must not be rebuilt from a bare principal, the
    /// controller handle's Station, a DID default Station or the resolving
    /// facade.
    pub subject_account_id: AccountId,
    pub visibility: HandleVisibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

pub fn validate_agent_slug(value: &str) -> Result<()> {
    arkret_wire::validate_canonical_agent_slug(value)
}

/// Compare a known target with the already authenticated, currently visible
/// selector values for one label. This does not fetch claims, choose a target
/// or authorize disclosure; the caller must perform those independent gates.
pub fn agent_selector_matches_known_account(
    known: &AccountId,
    visible: &[AgentSelectorClaimValue],
) -> bool {
    matches!(visible, [value] if value.subject_account_id == *known)
}

#[cfg(test)]
mod agent_selector_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_agent_slug_pattern() {
        for value in ["s", "summary", "summary_v2", "summary-v2", "总结助手"] {
            validate_agent_slug(value).unwrap();
        }
        for value in ["", "Summary", "sum/mary", "e\u{301}xample"] {
            assert!(validate_agent_slug(value).is_err(), "{value}");
        }
    }

    #[test]
    fn selector_value_is_closed_and_account_scoped() {
        let account = json!({
            "principal_id": "ak:did_core:webvh:z6mkfixtureagentsacmeexamplealicesummary",
            "station_id": "ak:did_core:web:acme.example"
        });
        let value: AgentSelectorClaimValue = serde_json::from_value(json!({
            "subject_account_id": account,
            "visibility": "restricted",
            "audience": "ak:did_core:web:acme.example"
        }))
        .unwrap();
        assert_eq!(value.visibility, HandleVisibility::Restricted);
        for rejected in [
            json!({"subject_account_id": null, "visibility": "public"}),
            json!({"subject_account_id": account, "visibility": "public",
                   "expires_at": "2026-09-25T00:00:00.000Z"}),
            json!({"subject_account_id": account, "visibility": "public", "proofs": []}),
        ] {
            assert!(serde_json::from_value::<AgentSelectorClaimValue>(rejected).is_err());
        }
    }
}
