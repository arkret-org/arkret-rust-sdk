//! Authorization decision, grant listing, and invite listing wire DTOs.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, AuthorityStatus, AuthorizationDecision, CurrentRevision, FreshnessState, Hash,
    ReasonCode, WireResourceSelector,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::governance::grant_constraint::CapabilityGrant;
use crate::governance::operation_wire::Invite;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AuthorizationCheckRequestBody {
    pub actor_id: ActorId,
    pub action: String,
    /// Optional resource selector (Realm / Strand / Space / Morph / etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<WireResourceSelector>,
    /// Optional decision context — claim presentations, commit checkpoint
    /// reference, request metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AuthorizationCheckResponseBody {
    pub decision: AuthorizationDecision,
    #[serde(default)]
    pub matched_grants: Vec<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub applied_constraints: Vec<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub policy_evaluations: Vec<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub missing_proofs: Vec<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness_state: Option<FreshnessState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_checkpoint_age_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_status: Option<AuthorityStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub cache_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default)]
    pub obligations: Vec<serde_json::Map<String, Value>>,
}

/// One active effective grant and the exact revision of the same
/// `capability_grant` current result, read atomically by the governing Station.
///
/// The revision is the only valid CAS basis for subject-authored capability
/// relinquishment. Clients must not substitute the surrounding list digest,
/// an Event ID, or locally folded history.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveCapabilityGrantView {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub grant: CapabilityGrant,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revision: CurrentRevision,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectiveCapabilityGrantViewWire {
    grant: CapabilityGrant,
    revision: CurrentRevision,
}

impl<'de> Deserialize<'de> for EffectiveCapabilityGrantView {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EffectiveCapabilityGrantViewWire::deserialize(deserializer)?;
        if wire.grant.status != crate::governance::grant_constraint::CapabilityGrantStatus::Active {
            return Err(serde::de::Error::custom(
                "effective capability row must carry an active grant",
            ));
        }
        Ok(Self {
            grant: wire.grant,
            revision: wire.revision,
        })
    }
}

/// Atomic subject-visible snapshot returned by the governing Station.
///
/// Each entry is an [`EffectiveCapabilityGrantView`]. `state_digest` binds the
/// complete list snapshot and is not a per-grant revision or authoring basis.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveGrantSnapshot {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub grants: Vec<EffectiveCapabilityGrantView>,
    pub state_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationInvitePage {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub invites: Vec<Invite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[cfg(test)]
mod diagnostic_member_contract_tests {
    use serde_json::json;

    use super::AuthorizationCheckResponseBody;

    #[test]
    fn diagnostics_preserve_open_objects_and_reject_non_objects() {
        for name in [
            "matched_grants",
            "applied_constraints",
            "policy_evaluations",
            "missing_proofs",
            "obligations",
        ] {
            let mut value = json!({"decision":"allow"});
            value[name] = json!([{"profile_specific_detail":42}]);
            let typed: AuthorizationCheckResponseBody =
                serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(typed).unwrap()[name], value[name]);
            for invalid in [json!([null]), json!([1]), json!(["text"]), json!([[]])] {
                value[name] = invalid;
                assert!(
                    serde_json::from_value::<AuthorizationCheckResponseBody>(value.clone())
                        .is_err(),
                    "{name}"
                );
            }
        }
    }
}
