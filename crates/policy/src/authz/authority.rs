//! Capability authority-chain checks — pure, in-memory predicates.
//!
//! This module hosts the runtime authority-chain helpers that soland's
//! authorization engine (and any other consumer — inkson for client-side
//! pre-validation, sodmin for admin feedback) needs to enforce
//! capabilities.md §10:
//!
//! - Re-granting MUST NOT widen the action scope (`ActionsNotHeld`).
//! - Re-granting MUST NOT widen the resource scope (`ResourceOutOfScope`).
//! - A child temporal expiry MUST be no later than its parent's effective temporal expiry
//!   (`OverExpire`).
//! - The caller MUST be the parent grant subject (`NotGrantHolder`).
//! - Only an ordinary authority-control constraint can authorize a regrant
//!   (`AuthorityRegrantDenied`).
//! - The parent grant must exist (`ParentNotFound`), not be revoked (`ParentRevoked`) and not be
//!   expired (`ParentExpired`).
//!
//! These helpers operate on a [`Grant`] shape that intentionally mirrors
//! soland's in-memory runtime form (stringly-typed `resource`, single
//! [`GrantConstraint`] list plus `issuer_authority_refs`). The
//! wire-spec shape is the core authority
//! [`arkret_models_collaboration::governance::grant_constraint::CapabilityGrant`]
//! (`capability-grant.schema.json`) used at the canonical event boundary.
//! The two shapes are siblings, not alternatives: typically a capability
//! event resolves into a
//! `arkret_models_collaboration::governance::grant_constraint::CapabilityGrant`, then projects down
//! to a `Grant` for fast in-memory authority enforcement. The
//! fields critical to re-granting live in `issuer_authority_refs` and temporal constraints per
//! `arkret-spec/spec/v1/zh/authz/capabilities.md` §3 + §10.
//!
//! All functions in this module are **pure**: they take a slice of grants
//! and a `now` instant and return a decision. No interior mutability, no
//! I/O. That makes them safe to call from inkson (compile-to-wasm) and
//! from sodmin admin UI as well as the server-side authorization engine.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind;
use arkret_wire::{AppletId, CircleId, DidCoreId, Hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authz::ConstraintDuration;

/// One entry of a grant's `issuer_authority_refs[]`.
///
/// The ref type is the whole difference between "the root controller issued
/// this" and "someone re-granted what they hold" — v1 carries no separate
/// separate child-grant event, cell family or wire bit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IssuerAuthorityRef {
    /// A grant the issuer holds. The issuer MUST be its subject, and it MUST
    /// be active at evaluation time.
    Grant { grant_id: String },
    /// The Realm authority-root cell. `controller_epoch_at_issuance` proves the
    /// issuer controlled the root when it signed and is never compared against
    /// the current epoch — doing so would make an owner transfer kill the whole
    /// authority tree. `authority_generation` IS compared: that is what an
    /// authority reset advances.
    RealmRoot {
        realm_id: String,
        cell_ref: String,
        controller_epoch_at_issuance: u64,
        authority_generation: u64,
    },
}

impl IssuerAuthorityRef {
    /// The grant id this ref names, if it is a grant edge.
    #[must_use]
    pub fn grant_id(&self) -> Option<&str> {
        match self {
            Self::Grant { grant_id } => Some(grant_id.as_str()),
            Self::RealmRoot { .. } => None,
        }
    }

    /// The authority generation this ref is anchored to, if it is a root.
    #[must_use]
    pub fn authority_generation(&self) -> Option<u64> {
        match self {
            Self::RealmRoot {
                authority_generation,
                ..
            } => Some(*authority_generation),
            Self::Grant { .. } => None,
        }
    }
}

/// A capability grant in its runtime / in-memory form.
///
/// Mirrors soland's `crate::authz::Grant`. The fields `issuer_authority_refs` and
/// `issuer_authority_refs` is a wire field per `ak.schema.capability.v1`; the remaining
/// fields are runtime projections (`resource` is a stringly-typed selector
/// rather than the typed [`crate::authz::ResourceSelector`] enum so that this
/// module can be reused by client pre-checks without forcing the full
/// selector parser pipeline).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub grant_id: String,
    pub realm_id: String,
    pub issuer: DidCoreId,
    pub issuer_principal_server_id: DidCoreId,
    pub subject: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_principal_server_id: Option<DidCoreId>,
    pub resource: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<GrantConstraint>,
    pub revoked: bool,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    /// The authority this grant was issued under (`capabilities.md` §10).
    /// A `realm_root` ref is a rooted terminal; a `grant` ref is an edge, and
    /// revoking the grant it names invalidates this one at read time.
    #[serde(default)]
    pub issuer_authority_refs: Vec<IssuerAuthorityRef>,
    /// Reducer-derived absolute distance from an authority root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_depth: Option<u64>,
    /// Reducer-derived identities of the roots reached by this grant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_root_refs:
        Vec<arkret_models_collaboration::governance::grant_constraint::AuthorityRootRef>,
}

/// A constraint entry attached to a [`Grant`].
///
/// In-memory runtime projection of the canonical v1
/// `arkret_models_collaboration::governance::grant_constraint::GrantConstraint`
/// shape, plus service-only evaluation families such as `Decision` and
/// `AllowedObjectFacets`. Soland threads this compact projection through its
/// authorization checks after validating the canonical event-boundary model.
///
/// AKP-0007 P1.3.4: the previous `{ constraint_kind: String, value:
/// serde_json::Value }` weakly-typed form has been removed (no backwards
/// compat). All call sites construct one of these variants directly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "constraint_kind", rename_all = "snake_case")]
pub enum GrantConstraint {
    /// Hard decision constraint used by soland to attach explicit
    /// allow/deny/quarantine/require_review verdicts to a grant
    /// (capabilities.md §B5 priority: deny > quarantine > require_review >
    /// allow). Maps onto the spec `effect` field but is materialised as a
    /// standalone constraint type because soland's engine treats decision
    /// constraints separately from the spec-typed evaluation families.
    Decision { decision: GrantDecisionVerdict },
    /// Temporal constraint (`constraint_kind: "temporal"`). Carries two
    /// independent facets that share the spec `temporal` discriminator:
    ///
    /// - Grant expiry: optional `expires_at`; multiple temporal constraints intersect and the
    ///   earliest expiry wins (see [`grant_effective_expiry`]).
    /// - Message edit / redact window (`constraint_subkind = "edit_window" | "redact_window"`,
    ///   constraint-schema.md §14.2). `message_edit_window` governs `ak.message.revise[.own]`;
    ///   `message_redact_window` governs `ak.message.redact[.own]`. `redact_after_window_allowed`
    ///   controls whether redact stays coupled to the edit window when no separate redact window is
    ///   declared (default `false` = coupled; omitting a redact window then means unbounded recall
    ///   once the edit window closes only if this flag is `true`). When `message_redact_window` is
    ///   declared it is authoritative for redact and the flag no longer changes the redact verdict.
    ///   Enforcement (which requires the target Message `created_at`) lives in the service-side
    ///   evaluator, not in the pure authority helper.
    Temporal {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        constraint_subkind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message_edit_window: Option<ConstraintDuration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message_redact_window: Option<ConstraintDuration>,
        #[serde(default, skip_serializing_if = "is_false")]
        redact_after_window_allowed: bool,
    },
    /// AKP-0007 (spec b7d35be) — narrow a Circle-management capability
    /// (`ak.circle.manage`, `ak.circle.member.manage`,
    /// `ak.circle.member.add.others`, `ak.circle.audit`) to a specific set
    /// of Circle ids. Spec `capability-action-registry.json` declares
    /// `required_constraints=["allowed_circle_ids"]` on each gated
    /// action; unconstrained Realm-wide grants for these actions MUST be
    /// rejected by the grant-issue guard.
    AllowedCircleIds {
        allowed_circle_ids: BTreeSet<CircleId>,
    },
    /// Limits applet interop-session writes to explicit session ids.
    AllowedSessionIds {
        allowed_session_ids: BTreeSet<String>,
    },
    /// Resource must carry at least one of the listed facets. soland uses
    /// this on `ak:strand:` / `ak:realm:` / `ak:morph:` projections; an
    /// unfaceted target falls outside scope (fail-closed).
    AllowedObjectFacets { facets: Vec<String> },
    /// Runtime mirror of the spec `max_operations` + `period` constraint
    /// used by high-risk burst surfaces such as
    /// `ak.message.mention.broadcast`. The pure authority helper only
    /// preserves and validates shape; concrete counter enforcement is done
    /// by the service-side evaluator for the relevant action.
    RateLimiting { max_operations: u64, period: String },
    /// Field-scoped access retained in the runtime projection.  These fields
    /// must not be collapsed away: DataEvent admission needs the exact dotted
    /// patch paths in order to distinguish, for example, Strand Description
    /// (`content`) from Synthesis (`tracks.synthesis.content`).
    FieldAccess {
        effect: GrantDecisionVerdict,
        #[serde(default)]
        allowed_write_fields: Vec<String>,
        #[serde(default)]
        denied_write_fields: Vec<String>,
        #[serde(default)]
        allowed_read_fields: Vec<String>,
        #[serde(default)]
        denied_read_fields: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        condition: Option<serde_json::Value>,
    },
    /// Strand/track scope retained in the runtime projection.  Base Strand
    /// fields have no track; only paths below `tracks.<name>` are checked
    /// against the track lists by the operation-aware evaluator.
    ScopeLimitation {
        effect: GrantDecisionVerdict,
        #[serde(default)]
        allowed_strand_ids: Vec<String>,
        #[serde(default)]
        denied_strand_ids: Vec<String>,
        #[serde(default)]
        allowed_tracks: Vec<String>,
        #[serde(default)]
        denied_tracks: Vec<String>,
        #[serde(default)]
        allowed_circle_ids: BTreeSet<CircleId>,
        #[serde(default)]
        allowed_session_ids: BTreeSet<String>,
    },
    /// Re-grant control. Ordinary child grants use `max_authority_depth`;
    /// Applet install grants use the registered
    /// `constraint_subkind=applet_authority` fields from
    /// `constraint-schema.md` §7.3.
    AuthorityControl {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_authority_depth: Option<u32>,
        #[serde(default, skip_serializing_if = "is_false")]
        authority_regrant_allowed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        constraint_subkind: Option<GrantConstraintSubkind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        applet_id: Option<AppletId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        executed_by: Option<DidCoreId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        registration_epoch: Option<Hash>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppletAuthorityBindingError {
    Missing,
    AppletIdMismatch,
    ExecutedByMismatch,
    RegistrationEpochMismatch,
}

impl std::fmt::Display for AppletAuthorityBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "applet authority binding constraint is missing"),
            Self::AppletIdMismatch => write!(f, "applet authority applet_id mismatch"),
            Self::ExecutedByMismatch => write!(f, "applet authority executed_by mismatch"),
            Self::RegistrationEpochMismatch => {
                write!(f, "applet authority registration_epoch mismatch")
            }
        }
    }
}

impl std::error::Error for AppletAuthorityBindingError {}

/// Returns the earliest expiry across the grant's temporal constraints.
/// `None` means the grant never expires.
pub fn grant_effective_expiry(grant: &Grant) -> Option<DateTime<Utc>> {
    grant_effective_expiry_from_constraints(&grant.constraints)
}

fn grant_effective_expiry_from_constraints(
    constraints: &[GrantConstraint],
) -> Option<DateTime<Utc>> {
    constraints
        .iter()
        .filter_map(|constraint| match constraint {
            GrantConstraint::Temporal { expires_at, .. } => *expires_at,
            _ => None,
        })
        .min()
}

/// serde `skip_serializing_if` helper — omits `redact_after_window_allowed`
/// from the wire form when it carries its default (`false`).
fn is_false(value: &bool) -> bool {
    !*value
}

/// Returns `true` when the grant has reached or passed its effective
/// expiry. A grant with no expiry never expires.
pub fn is_grant_expired(grant: &Grant, now: DateTime<Utc>) -> bool {
    grant_effective_expiry(grant).is_some_and(|expiry| now >= expiry)
}

/// Returns the strictest ordinary authority-depth ceiling carried by a grant.
///
/// `None` means the grant did not opt into a finite authority-depth seal.
/// When present, child grants must carry a `AuthorityControl` constraint no
/// greater than `parent_depth - 1`; a parent depth of zero cannot issue a child
/// grant. Applet-authority bindings do not contribute a depth ceiling.
pub fn max_authority_depth(grant: &Grant) -> Option<u32> {
    max_authority_depth_from_constraints(&grant.constraints)
}

fn max_authority_depth_from_constraints(constraints: &[GrantConstraint]) -> Option<u32> {
    constraints
        .iter()
        .filter_map(|constraint| match constraint {
            GrantConstraint::AuthorityControl {
                max_authority_depth,
                constraint_subkind: None,
                ..
            } => *max_authority_depth,
            _ => None,
        })
        .min()
}

/// Returns whether every ordinary authority-control constraint explicitly
/// permits the grant to act as an issuer authority. The field is fail-closed:
/// a missing value deserializes to `false`, as required by
/// constraint-schema.md §7.2. `constraint_subkind=applet_authority` is a
/// grant-local binding and never contributes regrant authority.
pub fn authority_regrant_allowed(grant: &Grant) -> bool {
    let mut saw_ordinary_authority_control = false;
    for constraint in &grant.constraints {
        if let GrantConstraint::AuthorityControl {
            authority_regrant_allowed,
            constraint_subkind: None,
            ..
        } = constraint
        {
            saw_ordinary_authority_control = true;
            if !authority_regrant_allowed {
                return false;
            }
        }
    }
    saw_ordinary_authority_control
}

pub fn validate_applet_authority_binding(
    grant: &Grant,
    applet_id: &str,
    executed_by: &str,
    registration_epoch: &str,
) -> Result<(), AppletAuthorityBindingError> {
    let Some(binding) = grant
        .constraints
        .iter()
        .find_map(|constraint| match constraint {
            GrantConstraint::AuthorityControl {
                constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
                applet_id,
                executed_by,
                registration_epoch,
                ..
            } => Some((
                applet_id.as_ref(),
                executed_by.as_ref(),
                registration_epoch.as_ref(),
            )),
            _ => None,
        })
    else {
        return Err(AppletAuthorityBindingError::Missing);
    };
    let Some(binding_applet_id) = binding.0 else {
        return Err(AppletAuthorityBindingError::Missing);
    };
    let Some(binding_executed_by) = binding.1 else {
        return Err(AppletAuthorityBindingError::Missing);
    };
    let Some(binding_registration_epoch) = binding.2 else {
        return Err(AppletAuthorityBindingError::Missing);
    };
    if binding_applet_id.as_str() != applet_id {
        return Err(AppletAuthorityBindingError::AppletIdMismatch);
    }
    if binding_executed_by.as_str() != executed_by {
        return Err(AppletAuthorityBindingError::ExecutedByMismatch);
    }
    if binding_registration_epoch.as_str() != registration_epoch {
        return Err(AppletAuthorityBindingError::RegistrationEpochMismatch);
    }
    Ok(())
}

/// Returns `true` iff every ancestor reachable through `issuer_authority_refs`
/// is still active (not revoked, not expired). A grant whose refs are all
/// `realm_root` is trivially intact — a root is a terminal, not an edge.
///
/// Multiple refs only ever *add* constraints: the grant holds iff **every**
/// path is intact. An alternate live path MUST NOT launder a revoked one.
/// Cycles are defended by a visit budget.
///
/// `grants` is treated as a flat slice; lookup is O(N) per hop. For a hot
/// path with many grants, the caller may prefer to build a `BTreeMap` once
/// and call [`authority_chain_intact_map`] directly.
pub fn authority_chain_intact(grants: &[Grant], grant_id: &str, now: DateTime<Utc>) -> bool {
    let map: BTreeMap<&str, &Grant> = grants.iter().map(|g| (g.grant_id.as_str(), g)).collect();
    authority_chain_intact_map(&map, grant_id, now)
}

/// `BTreeMap`-keyed variant of [`authority_chain_intact`] for callers that
/// already maintain an id → grant lookup (e.g. soland's authorization engine).
pub fn authority_chain_intact_map<G>(
    snapshot: &BTreeMap<&str, G>,
    grant_id: &str,
    now: DateTime<Utc>,
) -> bool
where
    G: std::borrow::Borrow<Grant>,
{
    let mut pending: Vec<&str> = vec![grant_id];
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        if visited.len() > 64 {
            return false;
        }
        // A ref that names no known grant is a broken chain, not a root: only
        // an absent grant edge can be missing, and a root is not an edge.
        let Some(grant) = snapshot.get(current).map(|g| g.borrow()) else {
            return false;
        };
        if grant.revoked || is_grant_expired(grant, now) {
            return false;
        }
        for parent in grant
            .issuer_authority_refs
            .iter()
            .filter_map(IssuerAuthorityRef::grant_id)
        {
            let Some(parent_grant) = snapshot.get(parent).map(|value| value.borrow()) else {
                return false;
            };
            if parent_grant.subject != grant.issuer
                || parent_grant.subject_principal_server_id.as_ref()
                    != Some(&grant.issuer_principal_server_id)
            {
                return false;
            }
            pending.push(parent);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn root_grant(id: &str, actions: &[&str], resource: &str) -> Grant {
        Grant {
            grant_id: id.to_owned(),
            realm_id: "ak:realm:1".to_owned(),
            issuer: DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            issuer_principal_server_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver")
                .unwrap(),
            subject: DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            subject_principal_server_id: Some(
                DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver").unwrap(),
            ),
            resource: resource.to_owned(),
            actions: actions.iter().map(|s| (*s).to_owned()).collect(),
            constraints: Vec::new(),
            revoked: false,
            created_at: Utc::now(),
            issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                realm_id: "ak:realm:1".to_owned(),
                cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null".to_owned(),
                controller_epoch_at_issuance: 0,
                authority_generation: 0,
            }],
            authority_depth: Some(1),
            authority_root_refs: Vec::new(),
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
            realm_id: "ak:realm:1".to_owned(),
            issuer: DidCoreId::new(issuer).unwrap(),
            issuer_principal_server_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver")
                .unwrap(),
            subject: DidCoreId::new(subject).unwrap(),
            subject_principal_server_id: Some(
                DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver").unwrap(),
            ),
            resource: resource.to_owned(),
            actions: actions.iter().map(|s| (*s).to_owned()).collect(),
            constraints: expires_at
                .map(|expires_at| GrantConstraint::Temporal {
                    expires_at: Some(expires_at),
                    constraint_subkind: None,
                    message_edit_window: None,
                    message_redact_window: None,
                    redact_after_window_allowed: false,
                })
                .into_iter()
                .collect(),
            revoked: false,
            created_at: Utc::now(),
            issuer_authority_refs: vec![IssuerAuthorityRef::Grant {
                grant_id: parent.to_owned(),
            }],
            authority_depth: None,
            authority_root_refs: Vec::new(),
        }
    }

    fn set_expiry(grant: &mut Grant, expires_at: DateTime<Utc>) {
        grant.constraints.extend(expiry_constraints(expires_at));
    }

    fn expiry_constraints(expires_at: DateTime<Utc>) -> Vec<GrantConstraint> {
        vec![GrantConstraint::Temporal {
            expires_at: Some(expires_at),
            constraint_subkind: None,
            message_edit_window: None,
            message_redact_window: None,
            redact_after_window_allowed: false,
        }]
    }

    #[test]
    fn happy_path_root_plus_one_authority_chain_intact() {
        let root = root_grant("g1", &["read"], "ak:realm:1");
        let child = child_grant(
            "g2",
            "g1",
            "ak:did_core:webvh:z6mkfixturebob",
            "ak:did_core:webvh:z6mkfixturecarol",
            &["read"],
            "ak:realm:1",
            None,
        );
        let grants = vec![root, child];
        let now = Utc::now();
        assert!(authority_chain_intact(&grants, "g1", now));
        assert!(authority_chain_intact(&grants, "g2", now));
    }

    #[test]
    fn parent_revoked_breaks_chain() {
        let mut root = root_grant("g1", &["read"], "ak:realm:1");
        root.revoked = true;
        let child = child_grant(
            "g2",
            "g1",
            "ak:did_core:webvh:z6mkfixturebob",
            "ak:did_core:webvh:z6mkfixturecarol",
            &["read"],
            "ak:realm:1",
            None,
        );
        let grants = vec![root, child];
        let now = Utc::now();
        assert!(!authority_chain_intact(&grants, "g1", now));
        assert!(!authority_chain_intact(&grants, "g2", now));
    }

    #[test]
    fn parent_expired_breaks_chain() {
        let now = Utc::now();
        let mut root = root_grant("g1", &["read"], "ak:realm:1");
        set_expiry(&mut root, now - Duration::seconds(1));
        let child = child_grant(
            "g2",
            "g1",
            "ak:did_core:webvh:z6mkfixturebob",
            "ak:did_core:webvh:z6mkfixturecarol",
            &["read"],
            "ak:realm:1",
            None,
        );
        let grants = vec![root, child];
        assert!(!authority_chain_intact(&grants, "g1", now));
        assert!(!authority_chain_intact(&grants, "g2", now));
    }

    #[test]
    fn authority_regrant_allowed_defaults_false_on_wire() {
        let constraint: GrantConstraint = serde_json::from_value(serde_json::json!({
            "constraint_kind": "authority_control",
            "max_authority_depth": 1
        }))
        .unwrap();
        assert!(matches!(
            constraint,
            GrantConstraint::AuthorityControl {
                authority_regrant_allowed: false,
                ..
            }
        ));
    }

    #[test]
    fn three_level_chain_middle_revoke_breaks_both_descendants() {
        let now = Utc::now();
        let root = root_grant("g1", &["read"], "ak:realm:1");
        let mut middle = child_grant(
            "g2",
            "g1",
            "ak:did_core:webvh:z6mkfixturebob",
            "ak:did_core:webvh:z6mkfixturecarol",
            &["read"],
            "ak:realm:1",
            None,
        );
        let leaf = child_grant(
            "g3",
            "g2",
            "ak:did_core:webvh:z6mkfixturecarol",
            "ak:did_core:webvh:z6mkfixturedave",
            &["read"],
            "ak:realm:1",
            None,
        );
        // Pre-condition: all three chain-intact.
        let intact = vec![root.clone(), middle.clone(), leaf.clone()];
        assert!(authority_chain_intact(&intact, "g1", now));
        assert!(authority_chain_intact(&intact, "g2", now));
        assert!(authority_chain_intact(&intact, "g3", now));

        // Revoke the middle grant; root still intact, middle + leaf broken.
        middle.revoked = true;
        let broken = vec![root, middle, leaf];
        assert!(authority_chain_intact(&broken, "g1", now));
        assert!(!authority_chain_intact(&broken, "g2", now));
        assert!(!authority_chain_intact(&broken, "g3", now));
    }

    #[test]
    fn deserialized_chain_with_cross_server_parent_edge_is_not_intact() {
        let now = Utc::now();
        let root = root_grant("g1", &["read"], "ak:realm:1");
        let mut forged = child_grant(
            "g2",
            "g1",
            "ak:did_core:webvh:z6mkfixturebob",
            "ak:did_core:webvh:z6mkfixturecarol",
            &["read"],
            "ak:realm:1",
            None,
        );
        forged.issuer_principal_server_id =
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureotherserver").unwrap();

        assert!(!authority_chain_intact(&[root, forged], "g2", now));
    }

    #[test]
    fn grant_effective_expiry_picks_earliest_temporal_constraint() {
        let now = Utc::now();
        let mut grant = root_grant("g1", &["read"], "ak:realm:1");
        set_expiry(&mut grant, now + Duration::hours(2));
        grant.constraints.push(GrantConstraint::Temporal {
            expires_at: Some(now + Duration::hours(1)),
            constraint_subkind: None,
            message_edit_window: None,
            message_redact_window: None,
            redact_after_window_allowed: false,
        });
        let effective = grant_effective_expiry(&grant).expect("has expiry");
        // Temporal constraints intersect, so the earliest expiry wins.
        assert!(effective <= now + Duration::hours(1));
        assert!(effective > now + Duration::minutes(59));
    }

    #[test]
    fn allowed_circle_ids_constraint_round_trips_through_serde() {
        let circle =
            CircleId::new("ak:circle:ARuquux-GRSwGPPZ0lJor6JUmVSERFPzPWlj1mjx8JCX".to_owned())
                .expect("valid CircleId");
        let constraint = GrantConstraint::AllowedCircleIds {
            allowed_circle_ids: BTreeSet::from([circle]),
        };
        let json = serde_json::to_string(&constraint).expect("serde round trip");
        assert!(json.contains("allowed_circle_ids"));
        assert!(json.contains("ak:circle:ARuquux-GRSwGPPZ0lJor6JUmVSERFPzPWlj1mjx8JCX"));
        let round_tripped: GrantConstraint =
            serde_json::from_str(&json).expect("deserialize typed");
        assert_eq!(constraint, round_tripped);
    }

    #[test]
    fn allowed_session_ids_constraint_round_trips_through_serde() {
        let session = "applet-session-1".to_owned();
        let constraint = GrantConstraint::AllowedSessionIds {
            allowed_session_ids: BTreeSet::from([session]),
        };
        let json = serde_json::to_string(&constraint).expect("serde round trip");
        assert!(json.contains("allowed_session_ids"));
        assert!(json.contains("applet-session-1"));
        let round_tripped: GrantConstraint =
            serde_json::from_str(&json).expect("deserialize typed");
        assert_eq!(constraint, round_tripped);
    }

    #[test]
    fn decision_constraint_round_trips_through_serde() {
        let constraint = GrantConstraint::Decision {
            decision: GrantDecisionVerdict::RequireReview,
        };
        let json = serde_json::to_string(&constraint).expect("serde");
        assert!(json.contains("decision"));
        assert!(json.contains("require_review"));
        let round_tripped: GrantConstraint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(constraint, round_tripped);
    }

    #[test]
    fn applet_authority_round_trips_only_the_registered_wire_shape() {
        let registration_epoch = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let constraint = GrantConstraint::AuthorityControl {
            max_authority_depth: None,
            authority_regrant_allowed: false,
            constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
            applet_id: Some(
                AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            ),
            executed_by: Some(DidCoreId::new("ak:did_core:web:calendar.example").unwrap()),
            registration_epoch: Some(registration_epoch),
        };
        let wire = serde_json::to_value(&constraint).unwrap();
        assert_eq!(wire["constraint_kind"], "authority_control");
        assert_eq!(wire["constraint_subkind"], "applet_authority");
        assert!(serde_json::from_value::<GrantConstraint>(wire).is_ok());
        assert!(
            serde_json::from_value::<GrantConstraint>(serde_json::json!({
                "constraint_kind": "applet_delegation_binding",
                "applet_id": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb",
                "executed_by": "ak:did_core:web:calendar.example",
                "registration_epoch": format!("sha256:{}", "a".repeat(64))
            }))
            .is_err()
        );
    }

    #[test]
    fn applet_authority_binding_must_match_epoch_subject_and_applet() {
        let mut grant = root_grant("g1", &["ak.message.create"], "ak:realm:1");
        let applet_id = "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb";
        let registration_epoch = format!("sha256:{}", "a".repeat(64));
        assert!(matches!(
            validate_applet_authority_binding(
                &grant,
                applet_id,
                "ak:did_core:webvh:z6mkfixture",
                &registration_epoch
            ),
            Err(AppletAuthorityBindingError::Missing)
        ));
        grant.constraints.push(GrantConstraint::AuthorityControl {
            max_authority_depth: None,
            authority_regrant_allowed: false,
            constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
            applet_id: Some(AppletId::new(applet_id).unwrap()),
            executed_by: Some(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()),
            registration_epoch: Some(Hash::new(registration_epoch.clone()).unwrap()),
        });
        assert!(
            validate_applet_authority_binding(
                &grant,
                applet_id,
                "ak:did_core:webvh:z6mkfixture",
                &registration_epoch
            )
            .is_ok()
        );
        let different_epoch = format!("sha256:{}", "b".repeat(64));
        assert!(matches!(
            validate_applet_authority_binding(
                &grant,
                applet_id,
                "ak:did_core:webvh:z6mkfixture",
                &different_epoch
            ),
            Err(AppletAuthorityBindingError::RegistrationEpochMismatch)
        ));
    }
}
