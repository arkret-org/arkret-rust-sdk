//! Capability delegation chain check — pure, in-memory predicates.
//!
//! This module hosts the *runtime* delegation-chain helpers that soland's
//! `AuthzEngine` (and any other consumer — yougen for client-side pre-validation,
//! sodmin for admin feedback) needs to enforce capabilities.md §10:
//!
//! - 再授权 MUST NOT 扩大动作范围 (`ActionsNotHeld`)
//! - 再授权 MUST NOT 扩大资源范围 (`ResourceOutOfScope`)
//! - 子 `expires_at` MUST ≤ 父 `expires_at` (`OverExpire`)
//! - 调用方 MUST 是父 grant 的 subject (`NotGrantHolder`)
//! - 父 grant 必须存在 (`ParentNotFound`), 未 revoke (`ParentRevoked`),
//!   未 expire (`ParentExpired`)
//!
//! These helpers operate on a [`Grant`] shape that intentionally mirrors
//! soland's in-memory runtime form (stringly-typed `resource`, single
//! [`GrantConstraint`] list, top-level `expires_at` + `delegated_from`). The
//! wire-spec shape — with typed [`crate::authz::ResourceSelector`] and richer
//! not_before/expires_at pairs — is the separate [`crate::authz::CapabilityGrant`]
//! used at the canonical event boundary. The two shapes are siblings, not
//! alternatives: typically a capability event resolves into a
//! `CapabilityGrant`, then projects down to a `Grant` for fast in-memory
//! check / delegation enforcement. The fields critical to delegation —
//! `delegated_from` and `expires_at` — live on both shapes verbatim per
//! `contrix-spec/spec/v1/zh/authz/capabilities.md` §3 + §10.
//!
//! All functions in this module are **pure**: they take a slice of grants
//! and a `now` instant and return a decision. No interior mutability, no
//! I/O. That makes them safe to call from yougen (compile-to-wasm) and
//! from sodmin admin UI as well as the server-side `AuthzEngine`.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use contrix_core::CircleId;
use serde::{Deserialize, Serialize};

/// A capability grant in its runtime / in-memory form.
///
/// Mirrors soland's `crate::authz::Grant`. The fields `delegated_from` and
/// `expires_at` are wire fields per `cx.schema.capability.v1`; the remaining
/// fields are runtime projections (`resource` is a stringly-typed selector
/// rather than the typed [`crate::authz::ResourceSelector`] enum so that this
/// module can be reused by client pre-checks without forcing the full
/// selector parser pipeline).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub grant_id: String,
    pub space_id: String,
    pub issuer: String,
    pub subject: String,
    pub resource: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<GrantConstraint>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
    /// Parent grant_id when this grant was issued via re-delegation. Revoking
    /// the parent cascade-revokes this child via [`revoke_with_cascade`].
    #[serde(default)]
    pub delegated_from: Option<String>,
    /// Top-level convenience denormalization of the temporal constraint
    /// inside `constraints[]`. When both forms are present the stricter
    /// one wins (see [`grant_effective_expiry`]).
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// A constraint entry attached to a [`Grant`].
///
/// Typed enum mirroring the v1 spec's `grant-constraint.schema.json`
/// `constraint_type` discriminator plus runtime-only families used by
/// soland's HTTP authz path (`Decision`, `AllowedObjectFacets`). The
/// upstream typed validator in [`crate::authz::ConstraintEntry`] /
/// [`crate::authz::Constraint`] remains the canonical schema-aligned
/// representation; this enum is the in-memory runtime projection that
/// soland threads through `AuthzEngine::check`.
///
/// CXP-0007 P1.3.4: the previous `{ constraint_type: String, value:
/// serde_json::Value }` weakly-typed form has been removed (no backwards
/// compat). All call sites construct one of these variants directly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "constraint_type", rename_all = "snake_case")]
pub enum GrantConstraint {
    /// Hard decision constraint used by soland to attach explicit
    /// allow/deny/quarantine/require_review verdicts to a grant
    /// (capabilities.md §B5 priority: deny > quarantine > require_review >
    /// allow). Maps onto the spec `effect` field but is materialised as a
    /// standalone constraint type because soland's engine treats decision
    /// constraints separately from the spec-typed evaluation families.
    Decision { decision: GrantDecisionVerdict },
    /// Temporal constraint with an optional `expires_at`. The top-level
    /// `Grant::expires_at` field and any `Temporal { expires_at }` entry
    /// are intersected; the stricter wins (see [`grant_effective_expiry`]).
    Temporal {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
    },
    /// CXP-0007 (spec b7d35be) — narrow a Circle-management capability
    /// (`cx.circle.manage`, `cx.circle.member.manage`,
    /// `cx.circle.member.add.others`, `cx.circle.audit`) to a specific set
    /// of Circle ids. Spec `capability-action-registry.json` declares
    /// `required_constraints=["allowed_circle_ids"]` on each gated
    /// action; unconstrained Realm-wide grants for these actions MUST be
    /// rejected by the grant-issue guard.
    AllowedCircleIds { allowed_circle_ids: BTreeSet<CircleId> },
    /// Resource must carry at least one of the listed facets. soland uses
    /// this on `cx:flow:` / `cx:space:` / `cx:morph:` projections; an
    /// unfaceted target falls outside scope (fail-closed).
    AllowedObjectFacets { facets: Vec<String> },
    /// Runtime mirror of the spec `max_operations` + `period` constraint
    /// used by high-risk burst surfaces such as
    /// `cx.message.mention.broadcast`. The pure delegation helper only
    /// preserves and validates shape; concrete counter enforcement is done
    /// by the service-side evaluator for the relevant action.
    RateLimiting { max_operations: u64, period: String },
    /// Delegation depth control. v1 always passes (depth is enforced at
    /// the chain-walking helper level rather than per-constraint).
    DelegationControl {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_delegation_depth: Option<u32>,
    },
}

/// Verdict carried by [`GrantConstraint::Decision`]. Mirrors the spec's
/// `effect` enum and capabilities.md §B5 priority ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantDecisionVerdict {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

/// A request to issue a delegated grant. See [`create_delegated_grant`].
#[derive(Clone, Debug)]
pub struct GrantReqBody {
    pub space_id: String,
    pub issuer: String,
    pub subject: String,
    pub resource: String,
    pub actions: Vec<String>,
    pub constraints: Vec<GrantConstraint>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Why a delegation request was rejected.
///
/// Surfaced through HTTP by soland as `parent_revoked` / `parent_expired` /
/// `not_grant_holder` / `capability_not_held` / `capability_over_expire` /
/// `resource_out_of_scope`. See capabilities.md §10.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegationError {
    /// Parent grant_id is unknown.
    ParentNotFound,
    /// Parent grant exists but is revoked (directly or via cascade).
    ParentRevoked,
    /// Parent grant exists but its effective expiry is already in the past.
    ParentExpired,
    /// Caller is not the subject of the parent grant — only the holder of a
    /// capability MAY further delegate it.
    NotGrantHolder,
    /// Delegated `actions[]` carries one or more actions the parent doesn't
    /// hold. capabilities.md §10 (再授权不得扩大动作范围) — wire form
    /// `capability_not_held`.
    ActionsNotHeld { offending: Vec<String> },
    /// Child `expires_at` is later than parent (or child unset while parent
    /// is set). capabilities.md §10 — wire form `capability_over_expire`.
    OverExpire,
    /// Delegated `resource` falls outside parent's `resource` scope.
    /// v1 only enforces exact match, prefix-wildcard, or parent="*"; richer
    /// subsumption lands when typed resource selectors arrive
    /// (authz/resource-selector-grammar.md).
    ResourceOutOfScope,
}

/// Returns the effective expiry for a grant, taking the stricter of the
/// top-level `expires_at` and any `constraint_type=temporal` entry inside
/// `constraints[]`. `None` means the grant never expires.
pub fn grant_effective_expiry(grant: &Grant) -> Option<DateTime<Utc>> {
    let top_level = grant.expires_at;
    let from_constraint = grant.constraints.iter().find_map(|constraint| match constraint {
        GrantConstraint::Temporal { expires_at } => *expires_at,
        _ => None,
    });
    match (top_level, from_constraint) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Returns `true` when the grant has reached or passed its effective
/// expiry. A grant with no expiry never expires.
pub fn is_grant_expired(grant: &Grant, now: DateTime<Utc>) -> bool {
    grant_effective_expiry(grant).is_some_and(|expiry| now >= expiry)
}

/// Check whether `child` resource is within the scope `parent` permits.
///
/// v1 only supports exact match and `parent="*"`; prefix-wildcard parents
/// (`pattern="...:*"`) accept any child sharing the prefix. Richer typed
/// resource selectors land later (authz/resource-selector-grammar.md).
pub fn resource_within(parent: &str, child: &str) -> bool {
    if parent == "*" {
        return true;
    }
    if parent == child {
        return true;
    }
    if let Some(prefix) = parent.strip_suffix('*') {
        return child.starts_with(prefix);
    }
    false
}

/// Returns `true` iff every ancestor in the delegation chain rooted at
/// `grant_id` is still active (not revoked, not expired). A grant with no
/// `delegated_from` is trivially chain-intact. Cycles are defended by a
/// 64-step visit budget (should never occur in practice — `delegated_from`
/// is set at creation time and no edit API exists).
///
/// `grants` is treated as a flat slice; lookup is O(N) per hop. For a hot
/// path with many grants, the caller may prefer to build a `BTreeMap` once
/// and call [`delegation_chain_intact_map`] directly.
pub fn delegation_chain_intact(grants: &[Grant], grant_id: &str, now: DateTime<Utc>) -> bool {
    let map: BTreeMap<&str, &Grant> = grants.iter().map(|g| (g.grant_id.as_str(), g)).collect();
    delegation_chain_intact_map(&map, grant_id, now)
}

/// `BTreeMap`-keyed variant of [`delegation_chain_intact`] for callers that
/// already maintain an id → grant lookup (e.g. soland's `AuthzEngine`).
pub fn delegation_chain_intact_map<G>(
    snapshot: &BTreeMap<&str, G>,
    grant_id: &str,
    now: DateTime<Utc>,
) -> bool
where
    G: std::borrow::Borrow<Grant>,
{
    let mut current = grant_id;
    let mut visited: usize = 0;
    while let Some(grant) = snapshot.get(current).map(|g| g.borrow()) {
        if visited > 64 {
            return false;
        }
        visited += 1;
        if grant.revoked || is_grant_expired(grant, now) {
            return false;
        }
        match &grant.delegated_from {
            Some(parent) => current = parent.as_str(),
            None => return true,
        }
    }
    // delegated_from pointed at an unknown grant — broken chain.
    false
}

/// Validate a re-delegation request against its parent grant.
///
/// Returns the constructed (but not yet stored) child [`Grant`] on success.
/// Caller is responsible for `grant_id` generation and persistence — this
/// keeps the helper pure and yougen-callable from a browser context. On
/// success the returned grant has an empty `grant_id` (caller MUST overwrite
/// before storing) and `created_at = now`.
///
/// Enforces capabilities.md §10:
/// - caller MUST be the subject of `parent_id`
/// - delegated actions MUST be a subset of parent's
/// - delegated expiry MUST NOT exceed parent's effective expiry
/// - resource MUST NOT widen parent's scope
pub fn create_delegated_grant(
    parent_id: &str,
    requested: &GrantReqBody,
    parents: &[Grant],
    now: DateTime<Utc>,
) -> Result<Grant, DelegationError> {
    let parent =
        parents.iter().find(|g| g.grant_id == parent_id).ok_or(DelegationError::ParentNotFound)?;

    if parent.revoked {
        return Err(DelegationError::ParentRevoked);
    }
    if parent.subject != requested.issuer {
        return Err(DelegationError::NotGrantHolder);
    }
    let parent_effective_expiry = grant_effective_expiry(parent);
    if let Some(parent_expiry) = parent_effective_expiry
        && parent_expiry <= now
    {
        return Err(DelegationError::ParentExpired);
    }

    let parent_actions_wildcard = parent.actions.iter().any(|action| action == "*");
    if !parent_actions_wildcard {
        let mut offending: Vec<String> = Vec::new();
        for action in &requested.actions {
            if action != "*" && !parent.actions.contains(action) {
                offending.push(action.clone());
            }
        }
        // Child requesting wildcard while parent isn't wildcard is also
        // an unheld action.
        if requested.actions.iter().any(|action| action == "*") {
            offending.push("*".to_owned());
        }
        if !offending.is_empty() {
            // Stable-dedup so error reads cleanly when caller listed an
            // action twice.
            offending.sort();
            offending.dedup();
            return Err(DelegationError::ActionsNotHeld { offending });
        }
    }

    if !resource_within(&parent.resource, &requested.resource) {
        return Err(DelegationError::ResourceOutOfScope);
    }

    if let Some(parent_expiry) = parent_effective_expiry {
        match requested.expires_at {
            None => return Err(DelegationError::OverExpire),
            Some(child_expiry) if child_expiry > parent_expiry => {
                return Err(DelegationError::OverExpire);
            }
            _ => {}
        }
    }

    Ok(Grant {
        grant_id: String::new(),
        space_id: requested.space_id.clone(),
        issuer: requested.issuer.clone(),
        subject: requested.subject.clone(),
        resource: requested.resource.clone(),
        actions: requested.actions.clone(),
        constraints: requested.constraints.clone(),
        revoked: false,
        created_at: now,
        delegated_from: Some(parent_id.to_owned()),
        expires_at: requested.expires_at,
    })
}

/// Compute the cascade revocation set for `grant_id`.
///
/// Returns the IDs of every descendant grant that would need to be
/// revoked, in BFS order (parents before children). Does **not** include
/// `grant_id` itself, mirroring soland's `AuthzEngine::revoke_grant_with_cascade`
/// return contract. Caller applies the actual `revoked = true` mutation.
///
/// Idempotent on already-revoked descendants: they are excluded from the
/// returned set (no state change to report).
pub fn revoke_with_cascade(grants: &[Grant], grant_id: &str) -> Vec<String> {
    // Cheap id → index lookup; we mutate locally to track which children
    // we've already absorbed into the cascade.
    let mut already_in_cascade: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut cascade: Vec<String> = Vec::new();
    let mut frontier: Vec<String> = vec![grant_id.to_owned()];

    while let Some(parent_id) = frontier.pop() {
        for child in grants {
            if child.delegated_from.as_deref() != Some(parent_id.as_str()) {
                continue;
            }
            if child.revoked {
                continue;
            }
            if !already_in_cascade.insert(child.grant_id.as_str()) {
                continue;
            }
            cascade.push(child.grant_id.clone());
            frontier.push(child.grant_id.clone());
        }
    }

    cascade
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn root_grant(id: &str, actions: &[&str], resource: &str) -> Grant {
        Grant {
            grant_id: id.to_owned(),
            space_id: "cx:space:1".to_owned(),
            issuer: "did:web:alice".to_owned(),
            subject: "did:web:bob".to_owned(),
            resource: resource.to_owned(),
            actions: actions.iter().map(|s| (*s).to_owned()).collect(),
            constraints: Vec::new(),
            revoked: false,
            created_at: Utc::now(),
            delegated_from: None,
            expires_at: None,
        }
    }

    fn child_grant(
        id: &str,
        parent: &str,
        issuer: &str,
        subject: &str,
        actions: &[&str],
        resource: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Grant {
        Grant {
            grant_id: id.to_owned(),
            space_id: "cx:space:1".to_owned(),
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            resource: resource.to_owned(),
            actions: actions.iter().map(|s| (*s).to_owned()).collect(),
            constraints: Vec::new(),
            revoked: false,
            created_at: Utc::now(),
            delegated_from: Some(parent.to_owned()),
            expires_at,
        }
    }

    #[test]
    fn happy_path_root_plus_one_delegation_chain_intact() {
        let root = root_grant("g1", &["read"], "cx:space:1");
        let child =
            child_grant("g2", "g1", "did:web:bob", "did:web:carol", &["read"], "cx:space:1", None);
        let grants = vec![root, child];
        let now = Utc::now();
        assert!(delegation_chain_intact(&grants, "g1", now));
        assert!(delegation_chain_intact(&grants, "g2", now));
    }

    #[test]
    fn parent_revoked_breaks_chain() {
        let mut root = root_grant("g1", &["read"], "cx:space:1");
        root.revoked = true;
        let child =
            child_grant("g2", "g1", "did:web:bob", "did:web:carol", &["read"], "cx:space:1", None);
        let grants = vec![root, child];
        let now = Utc::now();
        assert!(!delegation_chain_intact(&grants, "g1", now));
        assert!(!delegation_chain_intact(&grants, "g2", now));
    }

    #[test]
    fn parent_expired_breaks_chain() {
        let now = Utc::now();
        let mut root = root_grant("g1", &["read"], "cx:space:1");
        root.expires_at = Some(now - Duration::seconds(1));
        let child =
            child_grant("g2", "g1", "did:web:bob", "did:web:carol", &["read"], "cx:space:1", None);
        let grants = vec![root, child];
        assert!(!delegation_chain_intact(&grants, "g1", now));
        assert!(!delegation_chain_intact(&grants, "g2", now));
    }

    #[test]
    fn create_delegated_grant_happy_path() {
        let now = Utc::now();
        let mut root = root_grant("g1", &["read", "send"], "cx:space:1");
        root.expires_at = Some(now + Duration::hours(1));
        let parents = vec![root];
        let req = GrantReqBody {
            space_id: "cx:space:1".to_owned(),
            issuer: "did:web:bob".to_owned(),
            subject: "did:web:carol".to_owned(),
            resource: "cx:space:1".to_owned(),
            actions: vec!["read".to_owned()],
            constraints: Vec::new(),
            expires_at: Some(now + Duration::minutes(30)),
        };
        let child = create_delegated_grant("g1", &req, &parents, now).expect("valid delegation");
        assert_eq!(child.delegated_from.as_deref(), Some("g1"));
        assert_eq!(child.actions, vec!["read".to_owned()]);
        assert!(child.grant_id.is_empty(), "caller must assign grant_id");
    }

    #[test]
    fn create_delegated_grant_rejects_over_expire() {
        let now = Utc::now();
        let mut root = root_grant("g1", &["read"], "cx:space:1");
        root.expires_at = Some(now + Duration::hours(1));
        let parents = vec![root];
        let req = GrantReqBody {
            space_id: "cx:space:1".to_owned(),
            issuer: "did:web:bob".to_owned(),
            subject: "did:web:carol".to_owned(),
            resource: "cx:space:1".to_owned(),
            actions: vec!["read".to_owned()],
            constraints: Vec::new(),
            // Child outlives parent → reject.
            expires_at: Some(now + Duration::hours(2)),
        };
        assert!(matches!(
            create_delegated_grant("g1", &req, &parents, now),
            Err(DelegationError::OverExpire)
        ));

        // Also reject when child has no expiry but parent does.
        let req_none = GrantReqBody { expires_at: None, ..req };
        assert!(matches!(
            create_delegated_grant("g1", &req_none, &parents, now),
            Err(DelegationError::OverExpire)
        ));
    }

    #[test]
    fn create_delegated_grant_rejects_actions_overreach() {
        let now = Utc::now();
        let root = root_grant("g1", &["read"], "cx:space:1");
        let parents = vec![root];
        let req = GrantReqBody {
            space_id: "cx:space:1".to_owned(),
            issuer: "did:web:bob".to_owned(),
            subject: "did:web:carol".to_owned(),
            resource: "cx:space:1".to_owned(),
            // Parent only has `read`; child asking for `send` and `delete`.
            actions: vec!["read".to_owned(), "send".to_owned(), "delete".to_owned()],
            constraints: Vec::new(),
            expires_at: None,
        };
        let err = create_delegated_grant("g1", &req, &parents, now).unwrap_err();
        match err {
            DelegationError::ActionsNotHeld { offending } => {
                assert_eq!(offending, vec!["delete".to_owned(), "send".to_owned()]);
            }
            other => panic!("expected ActionsNotHeld, got {other:?}"),
        }
    }

    #[test]
    fn create_delegated_grant_rejects_resource_out_of_scope() {
        let now = Utc::now();
        let root = root_grant("g1", &["read"], "cx:space:1");
        let parents = vec![root];
        let req = GrantReqBody {
            space_id: "cx:space:2".to_owned(),
            issuer: "did:web:bob".to_owned(),
            subject: "did:web:carol".to_owned(),
            // Parent's resource is "cx:space:1"; child trying a sibling space.
            resource: "cx:space:2".to_owned(),
            actions: vec!["read".to_owned()],
            constraints: Vec::new(),
            expires_at: None,
        };
        assert!(matches!(
            create_delegated_grant("g1", &req, &parents, now),
            Err(DelegationError::ResourceOutOfScope)
        ));
    }

    #[test]
    fn create_delegated_grant_rejects_non_holder() {
        let now = Utc::now();
        let root = root_grant("g1", &["read"], "cx:space:1");
        let parents = vec![root];
        let req = GrantReqBody {
            space_id: "cx:space:1".to_owned(),
            // Bob is the parent's subject; Eve trying to delegate is not.
            issuer: "did:web:eve".to_owned(),
            subject: "did:web:carol".to_owned(),
            resource: "cx:space:1".to_owned(),
            actions: vec!["read".to_owned()],
            constraints: Vec::new(),
            expires_at: None,
        };
        assert!(matches!(
            create_delegated_grant("g1", &req, &parents, now),
            Err(DelegationError::NotGrantHolder)
        ));
    }

    #[test]
    fn three_level_chain_middle_revoke_breaks_both_descendants() {
        let now = Utc::now();
        let root = root_grant("g1", &["read"], "cx:space:1");
        let mut middle =
            child_grant("g2", "g1", "did:web:bob", "did:web:carol", &["read"], "cx:space:1", None);
        let leaf =
            child_grant("g3", "g2", "did:web:carol", "did:web:dave", &["read"], "cx:space:1", None);
        // Pre-condition: all three chain-intact.
        let intact = vec![root.clone(), middle.clone(), leaf.clone()];
        assert!(delegation_chain_intact(&intact, "g1", now));
        assert!(delegation_chain_intact(&intact, "g2", now));
        assert!(delegation_chain_intact(&intact, "g3", now));

        // Revoke the middle grant; root still intact, middle + leaf broken.
        middle.revoked = true;
        let broken = vec![root, middle, leaf];
        assert!(delegation_chain_intact(&broken, "g1", now));
        assert!(!delegation_chain_intact(&broken, "g2", now));
        assert!(!delegation_chain_intact(&broken, "g3", now));
    }

    #[test]
    fn revoke_with_cascade_includes_all_descendants() {
        let root = root_grant("g1", &["read"], "cx:space:1");
        let middle_a =
            child_grant("g2a", "g1", "did:web:bob", "did:web:carol", &["read"], "cx:space:1", None);
        let middle_b =
            child_grant("g2b", "g1", "did:web:bob", "did:web:dave", &["read"], "cx:space:1", None);
        let leaf_a = child_grant(
            "g3a",
            "g2a",
            "did:web:carol",
            "did:web:erin",
            &["read"],
            "cx:space:1",
            None,
        );
        let leaf_b = child_grant(
            "g3b",
            "g2b",
            "did:web:dave",
            "did:web:frank",
            &["read"],
            "cx:space:1",
            None,
        );
        let grants = vec![root, middle_a, middle_b, leaf_a, leaf_b];
        let mut cascade = revoke_with_cascade(&grants, "g1");
        cascade.sort();
        assert_eq!(
            cascade,
            vec!["g2a".to_owned(), "g2b".to_owned(), "g3a".to_owned(), "g3b".to_owned(),]
        );
        // Cascading on a leaf reports an empty set (no descendants).
        assert!(revoke_with_cascade(&grants, "g3a").is_empty());
    }

    #[test]
    fn parent_not_found_returns_specific_error() {
        let now = Utc::now();
        let parents: Vec<Grant> = Vec::new();
        let req = GrantReqBody {
            space_id: "cx:space:1".to_owned(),
            issuer: "did:web:bob".to_owned(),
            subject: "did:web:carol".to_owned(),
            resource: "cx:space:1".to_owned(),
            actions: vec!["read".to_owned()],
            constraints: Vec::new(),
            expires_at: None,
        };
        assert!(matches!(
            create_delegated_grant("g-missing", &req, &parents, now),
            Err(DelegationError::ParentNotFound)
        ));
    }

    #[test]
    fn grant_effective_expiry_picks_stricter_of_top_level_and_constraint() {
        let now = Utc::now();
        let mut grant = root_grant("g1", &["read"], "cx:space:1");
        grant.expires_at = Some(now + Duration::hours(2));
        grant
            .constraints
            .push(GrantConstraint::Temporal { expires_at: Some(now + Duration::hours(1)) });
        let effective = grant_effective_expiry(&grant).expect("has expiry");
        // The constraint says 1h; top-level says 2h. Stricter (1h) wins.
        assert!(effective <= now + Duration::hours(1));
        assert!(effective > now + Duration::minutes(59));
    }

    #[test]
    fn allowed_circle_ids_constraint_round_trips_through_serde() {
        let circle = CircleId::new("cx:circle:01904100-0000-7000-8000-000000000000".to_owned())
            .expect("valid CircleId");
        let constraint =
            GrantConstraint::AllowedCircleIds { allowed_circle_ids: BTreeSet::from([circle]) };
        let json = serde_json::to_string(&constraint).expect("serde round trip");
        assert!(json.contains("allowed_circle_ids"));
        assert!(json.contains("cx:circle:01904100-0000-7000-8000-000000000000"));
        let round_tripped: GrantConstraint =
            serde_json::from_str(&json).expect("deserialize typed");
        assert_eq!(constraint, round_tripped);
    }

    #[test]
    fn decision_constraint_round_trips_through_serde() {
        let constraint =
            GrantConstraint::Decision { decision: GrantDecisionVerdict::RequireReview };
        let json = serde_json::to_string(&constraint).expect("serde");
        assert!(json.contains("decision"));
        assert!(json.contains("require_review"));
        let round_tripped: GrantConstraint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(constraint, round_tripped);
    }
}
