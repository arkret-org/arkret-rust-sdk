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
use arkret_wire::{AccountId, ActorId, AppletId, CircleId, EventId, Hash, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authz::ConstraintDuration;

/// One entry of a grant's `issuer_authority_refs[]`.
///
/// The ref type is the whole difference between "the root controller issued
/// this" and "someone re-granted what they hold" — v1 carries no separate
/// separate child-grant event, cell family or wire bit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IssuerAuthorityRef {
    OwnedAgent {
        realm_id: RealmId,
        controller_account_id: AccountId,
        controller_join_event_id: EventId,
        agent_join_event_id: EventId,
    },
    /// A grant the issuer holds. The issuer MUST be its subject, and it MUST
    /// be active at evaluation time.
    Grant { grant_id: String },
    /// A Realm authority root accepted by the governing Station.
    RealmRoot {
        realm_id: RealmId,
        authority_event_ref: EventId,
        authority_generation: u64,
    },
}

impl IssuerAuthorityRef {
    /// The grant id this ref names, if it is a grant edge.
    #[must_use]
    pub fn grant_id(&self) -> Option<&str> {
        match self {
            Self::Grant { grant_id } => Some(grant_id.as_str()),
            Self::RealmRoot { .. } | Self::OwnedAgent { .. } => None,
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
            Self::Grant { .. } | Self::OwnedAgent { .. } => None,
        }
    }
}

/// A capability grant in its runtime / in-memory form.
///
/// Mirrors soland's `crate::authz::Grant`. The fields `issuer_authority_refs` and
/// `issuer_authority_refs` is a wire field per `ak.schema.capability.v1`; the remaining
/// fields are runtime projections (`resource` is a stringly-typed selector
/// rather than the typed Soland `ResourceSelector` enum so that this
/// module can be reused by client pre-checks without forcing the full
/// selector parser pipeline).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub grant_id: String,
    pub realm_id: String,
    pub issuer_id: ActorId,
    pub subject_id: ActorId,
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
    /// Absolute distance from a committed authority decision.
    pub authority_depth: u64,
    /// Committed authority decisions reached by this grant.
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
    /// must not be collapsed away: ordinary Event admission needs the exact dotted
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
        #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
        allowed_managed_actor_roles:
            BTreeSet<arkret_models_collaboration::governance::grant_constraint::ManagedActorRole>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        constraint_subkind: Option<GrantConstraintSubkind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        applet_id: Option<AppletId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        executed_by: Option<ActorId>,
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
/// greater than `parent_depth - 1` when regrant is explicitly enabled; a zero
/// ceiling then prohibits children. The managed-role terminal-child exception
/// for an ordinary control with regrant disabled takes precedence and permits
/// an explicitly sealed depth-zero child. Applet bindings never supply a ceiling.
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
    executed_by: &ActorId,
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
    if binding_executed_by != executed_by {
        return Err(AppletAuthorityBindingError::ExecutedByMismatch);
    }
    if binding_registration_epoch.as_str() != registration_epoch {
        return Err(AppletAuthorityBindingError::RegistrationEpochMismatch);
    }
    Ok(())
}

/// Returns `true` iff every ancestor reachable through `issuer_authority_refs`
/// is still active (not revoked, not expired). A grant whose refs are all
/// `realm_root` is trivially intact: it is a terminal, not an edge.
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
        // A grant-only snapshot cannot prove current controller membership,
        // ownership or management policy. Never treat this execution root as
        // an unconditional Realm root or a delegable parent.
        if grant
            .issuer_authority_refs
            .iter()
            .any(|reference| matches!(reference, IssuerAuthorityRef::OwnedAgent { .. }))
        {
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
            if parent_grant.subject_id != grant.issuer_id {
                return false;
            }
            pending.push(parent);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidCoreId, EventId, RealmId};
    use chrono::Duration;

    use super::*;

    #[test]
    fn owned_agent_source_requires_current_facts_and_is_not_a_parent() {
        let mut grant = root_grant("owned", &["ak.message.create"], "ak:realm:1");
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [17; 32],
        ));
        let join = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [17; 32]);
        grant.issuer_authority_refs = vec![IssuerAuthorityRef::OwnedAgent {
            realm_id,
            controller_account_id: grant.issuer_id.as_account_id().unwrap().clone(),
            controller_join_event_id: join.clone(),
            agent_join_event_id: join,
        }];
        assert!(!authority_chain_intact(
            &[grant.clone()],
            "owned",
            Utc::now()
        ));
        let child = child_grant(
            "child",
            "owned",
            "ak:did_core:webvh:z6mkfixturebob",
            "ak:did_core:webvh:z6mkfixturecarol",
            &["ak.message.create"],
            "ak:realm:1",
            None,
        );
        assert!(!authority_chain_intact(
            &[grant, child],
            "child",
            Utc::now()
        ));
    }

    fn account_actor(principal_id: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(principal_id).unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver").unwrap(),
        ))
    }

    fn root_grant(id: &str, actions: &[&str], resource: &str) -> Grant {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        Grant {
            grant_id: id.to_owned(),
            realm_id: "ak:realm:1".to_owned(),
            issuer_id: account_actor("ak:did_core:webvh:z6mkfixturealice"),
            subject_id: account_actor("ak:did_core:webvh:z6mkfixturebob"),
            resource: resource.to_owned(),
            actions: actions.iter().map(|s| (*s).to_owned()).collect(),
            constraints: Vec::new(),
            revoked: false,
            created_at: Utc::now(),
            issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                realm_id: realm_id.clone(),
                authority_event_ref: EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [2; 32],
                ),
                authority_generation: 0,
            }],
            authority_depth: 1,
            authority_root_refs: vec![
                arkret_models_collaboration::governance::grant_constraint::AuthorityRootRef::RealmRoot {
                    realm_id,
                    authority_event_ref: EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [2; 32],
                    ),
                    authority_generation: 0,
                },
            ],
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
            issuer_id: account_actor(issuer),
            subject_id: account_actor(subject),
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
            authority_depth: 2,
            authority_root_refs: vec![
                arkret_models_collaboration::governance::grant_constraint::AuthorityRootRef::RealmRoot {
                    realm_id: RealmId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [1; 32],
                    )),
                    authority_event_ref: EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [2; 32],
                    ),
                    authority_generation: 0,
                },
            ],
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
    fn deserialized_chain_with_cross_station_parent_edge_is_not_intact() {
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
        forged.issuer_id = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureotherstation").unwrap(),
        ));

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
            allowed_managed_actor_roles: BTreeSet::new(),
            authority_regrant_allowed: false,
            constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
            applet_id: Some(
                AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            ),
            executed_by: Some(ActorId::service(
                DidCoreId::new("ak:did_core:web:calendar.example").unwrap(),
            )),
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
        let executor = ActorId::service(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
        let registration_epoch = format!("sha256:{}", "a".repeat(64));
        assert!(matches!(
            validate_applet_authority_binding(&grant, applet_id, &executor, &registration_epoch),
            Err(AppletAuthorityBindingError::Missing)
        ));
        grant.constraints.push(GrantConstraint::AuthorityControl {
            max_authority_depth: None,
            allowed_managed_actor_roles: BTreeSet::new(),
            authority_regrant_allowed: false,
            constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
            applet_id: Some(AppletId::new(applet_id).unwrap()),
            executed_by: Some(executor.clone()),
            registration_epoch: Some(Hash::new(registration_epoch.clone()).unwrap()),
        });
        assert!(
            validate_applet_authority_binding(&grant, applet_id, &executor, &registration_epoch)
                .is_ok()
        );
        let different_epoch = format!("sha256:{}", "b".repeat(64));
        assert!(matches!(
            validate_applet_authority_binding(&grant, applet_id, &executor, &different_epoch),
            Err(AppletAuthorityBindingError::RegistrationEpochMismatch)
        ));
        for station in [
            "ak:did_core:web:station-a.example",
            "ak:did_core:web:station-b.example",
        ] {
            let account_executor = ActorId::account(AccountId::new(
                executor.signing_principal_id().clone(),
                DidCoreId::new(station).unwrap(),
            ));
            assert_eq!(
                validate_applet_authority_binding(
                    &grant,
                    applet_id,
                    &account_executor,
                    &registration_epoch
                ),
                Err(AppletAuthorityBindingError::ExecutedByMismatch)
            );
        }
    }
}

/// A Service may issue only terminal children to verified managed Account subjects.
/// Parent quota accounting, current-cut installation verification and resource
/// hierarchy resolution remain caller-owned. `resource_is_narrower` must use the
/// same selector coverage verifier as ordinary capability issuance.
/// The caller must authenticate the accepted full Account provision and its
/// Applet/Service/hosting-Station/role provenance; a supplied role is not proof.
/// Only the exact Applet executor binding changes from the Service parent to
/// the Account child. All other retained runtime constraints remain at least
/// as strict; canonical constraint fields omitted by this runtime projection
/// must additionally be checked at the typed Event boundary.
pub fn validate_managed_service_child(
    parent: &Grant,
    child: &Grant,
    role: arkret_models_collaboration::governance::grant_constraint::ManagedActorRole,
    resource_is_narrower: impl FnOnce(&str, &str) -> bool,
) -> bool {
    let binding = |grant: &Grant| {
        let mut bindings = grant.constraints.iter().filter(|constraint| {
            matches!(
                constraint,
                GrantConstraint::AuthorityControl {
                    constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
                    ..
                }
            )
        });
        let first = bindings.next()?;
        if bindings.next().is_some() {
            return None;
        }
        Some(first.clone())
    };
    let (Some(mut rebound), Some(child_binding)) = (binding(parent), binding(child)) else {
        return false;
    };
    let GrantConstraint::AuthorityControl {
        applet_id: Some(_),
        executed_by: Some(executor),
        registration_epoch: Some(_),
        ..
    } = &mut rebound
    else {
        return false;
    };
    if executor != &parent.subject_id {
        return false;
    }
    *executor = child.subject_id.clone();
    if rebound != child_binding {
        return false;
    }
    let ordinary: Vec<_> = parent
        .constraints
        .iter()
        .filter_map(|v| match v {
            GrantConstraint::AuthorityControl {
                constraint_subkind: None,
                authority_regrant_allowed,
                max_authority_depth,
                allowed_managed_actor_roles,
                ..
            } => Some((
                *authority_regrant_allowed,
                *max_authority_depth,
                allowed_managed_actor_roles,
            )),
            _ => None,
        })
        .collect();
    matches!(parent.subject_id, ActorId::Service { .. })
        && child.issuer_id == parent.subject_id
        && matches!(child.subject_id, ActorId::Account { .. })
        && child
            .issuer_authority_refs
            .iter()
            .any(|v| v.grant_id() == Some(parent.grant_id.as_str()))
        && max_authority_depth(child) == Some(0)
        && !authority_regrant_allowed(child)
        && !ordinary.is_empty()
        && child.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                GrantConstraint::AuthorityControl {
                    constraint_subkind: None,
                    max_authority_depth: Some(0),
                    authority_regrant_allowed: false,
                    ..
                }
            )
        }) && child.constraints.iter().all(|constraint| {
        !matches!(
            constraint,
            GrantConstraint::AuthorityControl {
                constraint_subkind: None,
                ..
            }
        ) || matches!(
            constraint,
            GrantConstraint::AuthorityControl {
                max_authority_depth: Some(0),
                authority_regrant_allowed: false,
                allowed_managed_actor_roles,
                applet_id: None,
                executed_by: None,
                registration_epoch: None,
                ..
            } if ordinary.iter().all(|(_, _, roles)| allowed_managed_actor_roles.is_subset(roles))
        )
    }) && ordinary.iter().all(|(regrant, depth, roles)| {
        roles.contains(&role) && (!regrant || depth.is_none_or(|v| v > 0))
    }) && child.actions.iter().all(|v| parent.actions.contains(v))
        && child.realm_id == parent.realm_id
        && resource_is_narrower(&child.resource, &parent.resource)
        && parent
            .constraints
            .iter()
            .all(|constraint| match constraint {
                GrantConstraint::AuthorityControl {
                    constraint_subkind: None,
                    ..
                }
                | GrantConstraint::AuthorityControl {
                    constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
                    ..
                } => true,
                GrantConstraint::Temporal {
                    expires_at,
                    constraint_subkind,
                    message_edit_window,
                    message_redact_window,
                    redact_after_window_allowed,
                } => child.constraints.iter().any(|candidate| {
                    matches!(candidate, GrantConstraint::Temporal {
                    expires_at: child_expiry, constraint_subkind: child_subkind,
                    message_edit_window: child_edit, message_redact_window: child_redact,
                    redact_after_window_allowed: child_after,
                } if child_subkind == constraint_subkind
                    && child_edit == message_edit_window
                    && child_redact == message_redact_window
                    && child_after == redact_after_window_allowed
                    && expires_at.is_none_or(|parent_expiry|
                        child_expiry.is_some_and(|expiry| expiry <= parent_expiry)))
                }),
                _ => child.constraints.contains(constraint),
            })
        && match (
            grant_effective_expiry(parent),
            grant_effective_expiry(child),
        ) {
            (Some(p), Some(c)) => c <= p,
            (Some(_), None) => false,
            _ => true,
        }
}

#[cfg(test)]
mod managed_service_child_tests {
    use arkret_models_collaboration::governance::grant_constraint::ManagedActorRole;
    use arkret_wire::DidCoreId;

    use super::*;
    fn control(regrant: bool, depth: u32, roles: &[ManagedActorRole]) -> GrantConstraint {
        GrantConstraint::AuthorityControl {
            max_authority_depth: Some(depth),
            authority_regrant_allowed: regrant,
            allowed_managed_actor_roles: roles.iter().copied().collect(),
            constraint_subkind: None,
            applet_id: None,
            executed_by: None,
            registration_epoch: None,
        }
    }
    fn binding(executor: &ActorId) -> GrantConstraint {
        GrantConstraint::AuthorityControl {
            max_authority_depth: None,
            authority_regrant_allowed: false,
            allowed_managed_actor_roles: BTreeSet::new(),
            constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
            applet_id: Some(
                AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            ),
            executed_by: Some(executor.clone()),
            registration_epoch: Some(Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap()),
        }
    }
    fn pair() -> (Grant, Grant) {
        let service = ActorId::service(DidCoreId::new("ak:did_core:web:service.example").unwrap());
        let parent = Grant {
            grant_id: "parent".into(),
            realm_id: "realm".into(),
            issuer_id: service.clone(),
            subject_id: service.clone(),
            resource: "realm".into(),
            actions: vec!["ak.message.create".into()],
            constraints: vec![
                control(false, 0, &[ManagedActorRole::Bot]),
                binding(&service),
            ],
            revoked: false,
            created_at: Utc::now(),
            issuer_authority_refs: vec![],
            authority_depth: 1,
            authority_root_refs: vec![],
        };
        let mut child = parent.clone();
        child.grant_id = "child".into();
        child.subject_id = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:bot.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        child.resource = "space".into();
        child.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
            grant_id: "parent".into(),
        }];
        child.constraints = vec![control(false, 0, &[]), binding(&child.subject_id)];
        (parent, child)
    }
    fn covers(child: &str, parent: &str) -> bool {
        child == "space" && parent == "realm"
    }
    #[test]
    fn disabled_regrant_parent_can_issue_explicit_terminal_child_with_narrower_resource() {
        let (parent, child) = pair();
        assert!(validate_managed_service_child(
            &parent,
            &child,
            ManagedActorRole::Bot,
            covers
        ));
        assert!(!validate_managed_service_child(
            &parent,
            &child,
            ManagedActorRole::Ghost,
            covers
        ));
        assert!(!validate_managed_service_child(
            &parent,
            &child,
            ManagedActorRole::Bot,
            |_, _| false
        ));
    }
    #[test]
    fn ordinary_controls_roles_and_depth_are_required() {
        let (mut parent, mut child) = pair();
        parent.constraints.clear();
        assert!(!validate_managed_service_child(
            &parent,
            &child,
            ManagedActorRole::Bot,
            covers
        ));
        parent.constraints = vec![
            control(true, 0, &[ManagedActorRole::Bot]),
            binding(&parent.subject_id),
        ];
        assert!(!validate_managed_service_child(
            &parent,
            &child,
            ManagedActorRole::Bot,
            covers
        ));
        parent.constraints = vec![
            control(true, 1, &[ManagedActorRole::Bot]),
            binding(&parent.subject_id),
        ];
        assert!(validate_managed_service_child(
            &parent,
            &child,
            ManagedActorRole::Bot,
            covers
        ));
        child.constraints = vec![control(false, 1, &[]), binding(&child.subject_id)];
        assert!(!validate_managed_service_child(
            &parent,
            &child,
            ManagedActorRole::Bot,
            covers
        ));
        child.constraints = vec![control(true, 0, &[]), binding(&child.subject_id)];
        assert!(!validate_managed_service_child(
            &parent,
            &child,
            ManagedActorRole::Bot,
            covers
        ));
    }
    #[test]
    fn executor_rebinding_requires_unique_complete_matching_applet_bindings() {
        let (parent, child) = pair();
        let rejects = |parent: &Grant, child: &Grant| {
            assert!(!validate_managed_service_child(
                parent,
                child,
                ManagedActorRole::Bot,
                covers
            ));
        };
        let mut changed = parent.clone();
        changed.constraints.pop();
        rejects(&changed, &child);
        let mut changed = child.clone();
        changed.constraints.pop();
        rejects(&parent, &changed);
        for is_parent in [false, true] {
            let mut changed = if is_parent {
                parent.clone()
            } else {
                child.clone()
            };
            changed.constraints.push(changed.constraints[1].clone());
            if is_parent {
                rejects(&changed, &child);
            } else {
                rejects(&parent, &changed);
            }
        }
        for mutation in 0..7 {
            let mut changed = child.clone();
            let GrantConstraint::AuthorityControl {
                applet_id,
                executed_by,
                registration_epoch,
                ..
            } = &mut changed.constraints[1]
            else {
                unreachable!()
            };
            match mutation {
                0 => *executed_by = Some(parent.subject_id.clone()),
                1 => {
                    *applet_id = Some(
                        AppletId::new("ak:applet:01904100-0000-7000-8000-cccccccccccc").unwrap(),
                    )
                }
                2 => {
                    *registration_epoch =
                        Some(Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap())
                }
                3 => *applet_id = None,
                4 => *executed_by = None,
                5 => *registration_epoch = None,
                _ => {
                    *executed_by = Some(ActorId::account(AccountId::new(
                        child.subject_id.signing_principal_id().clone(),
                        DidCoreId::new("ak:did_core:web:another-station.example").unwrap(),
                    )))
                }
            }
            rejects(&parent, &changed);
        }
        let mut changed = parent;
        if let GrantConstraint::AuthorityControl { executed_by, .. } = &mut changed.constraints[1] {
            *executed_by = Some(child.subject_id.clone());
        }
        rejects(&changed, &child);
    }
    #[test]
    fn rebinding_cannot_escape_terminal_account_or_drop_other_constraints() {
        let (parent, child) = pair();
        for mutation in 0..4 {
            let mut changed = child.clone();
            match mutation {
                0 => changed.subject_id = parent.subject_id.clone(),
                1 => changed.issuer_id = child.subject_id.clone(),
                2 => changed.constraints.push(control(false, 1, &[])),
                _ => changed.issuer_authority_refs.clear(),
            }
            assert!(!validate_managed_service_child(
                &parent,
                &changed,
                ManagedActorRole::Bot,
                covers
            ));
        }
        for hard in [
            GrantConstraint::Decision {
                decision: GrantDecisionVerdict::Deny,
            },
            GrantConstraint::Decision {
                decision: GrantDecisionVerdict::RequireReview,
            },
            GrantConstraint::RateLimiting {
                max_operations: 5,
                period: "PT1H".into(),
            },
            GrantConstraint::Temporal {
                expires_at: Some(Utc::now()),
                constraint_subkind: Some("edit_window".into()),
                message_edit_window: None,
                message_redact_window: None,
                redact_after_window_allowed: false,
            },
        ] {
            let mut parent = parent.clone();
            parent.constraints.push(hard.clone());
            assert!(!validate_managed_service_child(
                &parent,
                &child,
                ManagedActorRole::Bot,
                covers
            ));
            let mut child = child.clone();
            child.constraints.push(hard);
            assert!(validate_managed_service_child(
                &parent,
                &child,
                ManagedActorRole::Bot,
                covers
            ));
        }
    }
    #[test]
    fn only_expiry_may_narrow_while_other_temporal_fields_are_preserved() {
        let (mut parent, mut child) = pair();
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let temporal = |expires_at, redact_after_window_allowed| GrantConstraint::Temporal {
            expires_at,
            constraint_subkind: Some("window".into()),
            message_edit_window: None,
            message_redact_window: None,
            redact_after_window_allowed,
        };
        parent.constraints.push(temporal(Some(expiry), false));
        child
            .constraints
            .push(temporal(Some(expiry - chrono::Duration::minutes(1)), false));
        assert!(validate_managed_service_child(
            &parent,
            &child,
            ManagedActorRole::Bot,
            covers
        ));
        for candidate in [
            temporal(None, false),
            temporal(Some(expiry + chrono::Duration::seconds(1)), false),
            temporal(Some(expiry), true),
        ] {
            *child.constraints.last_mut().unwrap() = candidate;
            assert!(!validate_managed_service_child(
                &parent,
                &child,
                ManagedActorRole::Bot,
                covers
            ));
        }
    }
}
