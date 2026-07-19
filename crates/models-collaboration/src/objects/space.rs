//! Space container model.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::constants::SPACE_SCHEMA;
use arkret_wire::{BlobRef, CircleId, Did, Error, RealmId, Result, SpaceId, SpaceState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Space {
    pub id: SpaceId,
    pub schema: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    // Declaration order mirrors `spec/v1/artifacts/schemas/space.schema.json`
    // (common-fields §3.2): the discriminator cluster `kind, rank, schema_refs`
    // precedes `title, summary`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_refs: Vec<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<SpaceState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// AKP-0007 (spec b7d35be) — optional Circle scope binding on the Space
    /// (container). Authorization-transparent: never carries its own
    /// membership/policy/E2EE group; this field places the Space's metadata
    /// inside an existing Circle encryption scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    /// AKP-0007 — reducer-enforced constraint on how child resources may
    /// pick their scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_scope_policy: Option<ChildScopePolicy>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// AKP-0007 (spec b7d35be) — Space `child_scope_policy` discriminator.
///
/// Mirrors `spec/v1/artifacts/schemas/space.schema.json` `$defs.child_scope_policy`.
/// The `require_scope_circle_id` variant carries the required Circle id.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChildScopePolicy {
    /// Any scope is accepted, including unscoped.
    AllowAny {},
    /// Child resources MUST live in an E2EE scope (any Circle or the
    /// Realm-default E2EE scope).
    RequireE2ee {},
    /// Child resources MUST share the parent Space's `scope_circle_id`.
    RequireSameScope {},
    /// Child resources MUST set `scope_circle_id` to the named Circle.
    RequireScopeCircleId { scope_circle_id: CircleId },
}

impl Space {
    pub fn new(
        id: SpaceId,
        realm_id: RealmId,
        kind: impl Into<String>,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            id,
            schema: SPACE_SCHEMA.to_owned(),
            realm_id,
            default_realm_id: None,
            parent_space_id: None,
            kind: kind.into(),
            rank: None,
            schema_refs: Vec::new(),
            title: title.into(),
            summary: None,
            fields: BTreeMap::new(),
            labels: Vec::new(),
            avatar_blob_ref: None,
            state: Some(SpaceState::Active),
            state_changed_at: None,
            scope_circle_id: None,
            child_scope_policy: None,
            created_by,
            created_at: DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0)
                .unwrap_or_else(Utc::now),
            updated_by: None,
            updated_at: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind.trim().is_empty() {
            return Err(Error::Protocol("space kind must not be empty".to_owned()));
        }
        if self.title.trim().is_empty() {
            return Err(Error::Protocol("space title must not be empty".to_owned()));
        }
        if self.labels.len() > 64
            || self.labels.iter().any(|label| label.chars().count() > 128)
            || self.labels.iter().collect::<BTreeSet<_>>().len() != self.labels.len()
        {
            return Err(Error::Protocol(
                "space labels must contain at most 64 entries of at most 128 bytes".to_owned(),
            ));
        }
        let wip_limit = self.fields.get("wip_limit");
        let enforcement = self.fields.get("wip_limit_enforcement");
        if self.kind != "list" && (wip_limit.is_some() || enforcement.is_some()) {
            return Err(Error::Protocol(
                "space WIP policy is only valid for kind=list".to_owned(),
            ));
        }
        if let Some(limit) = wip_limit {
            let valid = limit
                .as_u64()
                .is_some_and(|limit| (1..=100_000).contains(&limit));
            if !valid || enforcement.is_none() {
                return Err(Error::Protocol(
                    "list space wip_limit requires 1..=100000 and wip_limit_enforcement".to_owned(),
                ));
            }
        }
        if let Some(enforcement) = enforcement
            && (wip_limit.is_none()
                || !matches!(
                    enforcement.as_str(),
                    Some("warn" | "reject" | "require_review")
                ))
        {
            return Err(Error::Protocol(
                "space wip_limit_enforcement requires a registered value and wip_limit".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn space(kind: &str) -> Space {
        Space::new(
            SpaceId::new("ak:space:0196419b-0000-7000-8000-000000000001").unwrap(),
            RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000002").unwrap(),
            kind,
            "Work",
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        )
    }

    #[test]
    fn current_child_scope_policy_rejects_removed_fields() {
        assert!(
            serde_json::from_value::<ChildScopePolicy>(json!({
                "kind": "require_e2ee",
                "metadata_encryption_floor": "e2ee_required"
            }))
            .is_err()
        );
        let mut value = serde_json::to_value(space("board")).unwrap();
        value["default_scope_circle_id"] = json!("ak:circle:0196419b-0000-7000-8000-000000000003");
        assert!(serde_json::from_value::<Space>(value).is_err());
    }

    #[test]
    fn list_wip_policy_is_owned_by_space_fields() {
        let mut list = space("list");
        list.fields.insert("wip_limit".to_owned(), json!(5));
        assert!(list.validate().is_err());
        list.fields
            .insert("wip_limit_enforcement".to_owned(), json!("reject"));
        list.validate().unwrap();

        let mut board = space("board");
        board.fields.insert("wip_limit".to_owned(), json!(5));
        board
            .fields
            .insert("wip_limit_enforcement".to_owned(), json!("warn"));
        assert!(board.validate().is_err());
    }
}
