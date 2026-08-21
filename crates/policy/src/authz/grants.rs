//! Capability grant wire form + engine-internal projection.
//!
//! The **only** wire shape for capability grants in this SDK is the core
//! authority type [`arkret_models_collaboration::governance::grant_constraint::CapabilityGrant`]
//! (spec `capability-grant.schema.json`: required `id` / `schema` / `issuer` /
//! `subject` / `actions` / `resources` / `issuer_authority_refs`;
//! `resources` carrying spec
//! selector objects and `constraints` carrying the core typed grant constraint
//! DTO).
//!
//! For evaluation, the engine projects the core form into the
//! crate-internal, non-serializable [`GrantProjection`] (typed
//! [`ResourceSelector`] / [`ConstraintEntry`]). Projection failure carries
//! `schema_violation` semantics: the grant MUST be rejected, never
//! best-effort evaluated. The early-draft top-level `delegable` boolean is
//! removed per spec; re-grant control is expressed exclusively via an
//! `constraint_kind = "authority_control"` constraint with
//! `max_authority_depth` (no constraint ⇒ not delegable).

use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    GrantConstraintScope, GrantConstraintSubkind,
};
use arkret_wire::{DidCoreId, GrantId, Hash, SchemaId};

use super::*;

/// Engine-internal projection of a spec
/// [`arkret_models_collaboration::governance::grant_constraint::CapabilityGrant`].
///
/// NOT a wire type: deliberately not serializable, crate-visible only. It
/// exists so the evaluation hot path can pattern-match typed selectors and
/// constraints instead of re-reading wire DTOs. Always derived from the
/// core wire form via [`GrantProjection::from_wire`].
#[derive(Clone, Debug)]
pub(crate) struct GrantProjection {
    pub(crate) id: String,
    pub(crate) issuer: DidCoreId,
    pub(crate) issuer_principal_server_id: DidCoreId,
    pub(crate) subject: CapabilitySubject,
    pub(crate) subject_principal_server_id: Option<DidCoreId>,
    pub(crate) actions: Vec<String>,
    pub(crate) capability_action_registry_digest: Option<Hash>,
    pub(crate) resources: Vec<ResourceSelector>,
    pub(crate) constraints: Vec<ConstraintEntry>,
    pub(crate) issuer_authority_grant_refs: Vec<String>,
    pub(crate) has_realm_root_authority_ref: bool,
    pub(crate) not_before: Option<DateTime<Utc>>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) revoked_by: Option<DidCoreId>,
    pub(crate) revoked_at: Option<DateTime<Utc>>,
}

impl GrantProjection {
    /// Project the core wire form into the typed evaluation form.
    ///
    /// Failure means the grant violates `capability-grant.schema.json` (or
    /// carries constraint / selector shapes this evaluator cannot enforce,
    /// which MUST fail closed) — callers reject the grant with
    /// `schema_violation` semantics.
    pub(crate) fn from_wire(
        grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    ) -> Result<Self> {
        if grant.schema != SchemaId::CAPABILITY_V1 {
            return Err(Error::Protocol(format!(
                "schema_violation: capability grant schema must be '{}', got '{}'",
                SchemaId::CAPABILITY_V1,
                grant.schema
            )));
        }
        if grant.actions.is_empty() {
            return Err(Error::Protocol(
                "schema_violation: capability grant requires actions".to_owned(),
            ));
        }
        if grant.resources.is_empty() {
            return Err(Error::Protocol(
                "schema_violation: capability grant requires resources".to_owned(),
            ));
        }
        if grant.issuer_authority_refs.is_empty() {
            return Err(Error::Protocol(
                "schema_violation: capability grant requires issuer_authority_refs".to_owned(),
            ));
        }
        if grant.issuer_authority_refs.is_empty() {
            return Err(Error::Protocol(
                "schema_violation: capability grant requires issuer_authority_refs".to_owned(),
            ));
        }
        validate_capability_action_registry_binding(
            &grant.actions,
            grant.capability_action_registry_digest.as_ref(),
        )?;
        let resources = grant
            .resources
            .iter()
            .map(|value| {
                let value = serde_json::to_value(value)?;
                ResourceSelector::from_spec_value(&value)
            })
            .collect::<Result<Vec<_>>>()
            .map_err(|err| Error::Protocol(format!("schema_violation: {err}")))?;
        let mut constraints = Vec::new();
        for constraint in &grant.constraints {
            constraints.extend(
                constraint_entries_from_spec(constraint)
                    .map_err(|err| Error::Protocol(format!("schema_violation: {err}")))?,
            );
        }
        Ok(Self {
            id: grant.id.as_str().to_owned(),
            issuer: grant.issuer.clone(),
            issuer_principal_server_id: grant.issuer_principal_server_id.clone(),
            subject: grant.subject.clone(),
            subject_principal_server_id: grant.subject_principal_server_id.clone(),
            actions: grant.actions.clone(),
            capability_action_registry_digest: grant.capability_action_registry_digest.clone(),
            resources,
            constraints,
            issuer_authority_grant_refs: grant
                .issuer_authority_refs
                .iter()
                .filter_map(|r| match r {
                    arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant { grant_id } => {
                        Some(grant_id.as_str().to_owned())
                    }
                    arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::RealmRoot { .. } => None,
                })
                .collect(),
            has_realm_root_authority_ref: grant.issuer_authority_refs.iter().any(|r| {
                matches!(
                    r,
                    arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::RealmRoot { .. }
                )
            }),
            not_before: grant.not_before,
            expires_at: grant.expires_at,
            revoked_by: grant.revoked_by.clone(),
            revoked_at: grant.revoked_at,
        })
    }

    /// Subject DID when the grant names a concrete principal. Condition
    /// (selector) subjects return `None` — the engine fails closed on them.
    pub(crate) fn subject_did(&self) -> Option<&DidCoreId> {
        match &self.subject {
            CapabilitySubject::CoreDid(did) => Some(did),
            CapabilitySubject::Condition(_) => None,
        }
    }

    /// Effective grant-local authority-control policy. `None` means the grant
    /// carries no authority control and therefore cannot anchor a child grant.
    /// A missing depth inside a present control is unbounded (subject to the
    /// canonical DFS ceiling); `authority_regrant_allowed=false` seals the
    /// immediate child at depth zero rather than invalidating that child.
    pub(crate) fn authority_control_policy(&self) -> Option<(Option<u32>, bool)> {
        let mut depth: Option<u32> = None;
        let mut saw_control = false;
        let mut regrant_allowed = true;
        for entry in &self.constraints {
            if let Constraint::AuthorityControl {
                max_authority_depth,
                authority_regrant_allowed,
                ..
            } = &entry.constraint
            {
                saw_control = true;
                regrant_allowed &= *authority_regrant_allowed;
                if let Some(this) = max_authority_depth {
                    depth = Some(depth.map_or(*this, |current| current.min(*this)));
                }
            }
        }
        saw_control.then_some((depth, regrant_allowed))
    }
}

/// Return the JCS SHA-256 digest of the embedded complete capability-action
/// registry snapshot.
pub fn current_capability_action_registry_digest() -> Result<Hash> {
    let registry = arkret_schema::embedded_json_artifact(
        "registry/capability-action-registry.json",
    )
    .map_err(|_| {
        Error::Protocol(
            "capability_registry_basis_unavailable: embedded registry missing".to_owned(),
        )
    })?;
    capability_action_registry_digest(&registry)
}

fn capability_action_registry_digest(registry: &Value) -> Result<Hash> {
    let bytes = arkret_canonical::canonical_json_bytes(registry).map_err(|error| {
        Error::Protocol(format!(
            "capability_registry_basis_unavailable: registry JCS failed: {error}"
        ))
    })?;
    Hash::new(arkret_canonical::sha256_digest(&bytes)).map_err(|error| {
        Error::Protocol(format!(
            "capability_registry_basis_unavailable: invalid registry digest: {error}"
        ))
    })
}

/// Resolve the exact immutable capability-action registry snapshot named by a
/// signed digest. The live registry is only one possible snapshot: released
/// predecessors remain embedded under the append-only snapshot archive so a
/// newer receiver can evaluate an older Realm without reinterpreting it under
/// today's action set.
pub(crate) fn capability_action_registry_snapshot(basis: &Hash) -> Result<Value> {
    let current = arkret_schema::embedded_json_artifact("registry/capability-action-registry.json")
        .map_err(|_| {
            Error::Protocol(
                "capability_registry_basis_unavailable: embedded registry missing".to_owned(),
            )
        })?;
    if capability_action_registry_digest(&current)? == *basis {
        return Ok(current);
    }

    let digest = basis.as_str().strip_prefix("sha256:").ok_or_else(|| {
        Error::Protocol(
            "capability_registry_basis_unavailable: registry digest is not sha256".to_owned(),
        )
    })?;
    let path = format!("registry/snapshots/capability-action/sha256-{digest}.json");
    let snapshot = arkret_schema::embedded_json_artifact(&path).map_err(|_| {
        Error::Protocol(
            "capability_registry_basis_unavailable: registry snapshot is unknown or unavailable"
                .to_owned(),
        )
    })?;
    if capability_action_registry_digest(&snapshot)? != *basis {
        return Err(Error::Protocol(
            "capability_registry_basis_unavailable: archived registry digest mismatch".to_owned(),
        ));
    }
    Ok(snapshot)
}

pub(crate) fn capability_action_descriptor_in<'a>(
    registry: &'a Value,
    action: &str,
) -> Result<&'a Value> {
    registry
        .get("actions")
        .and_then(Value::as_array)
        .and_then(|actions| {
            actions.iter().find(|entry| {
                entry.get("action").and_then(Value::as_str) == Some(action)
            })
        })
        .ok_or_else(|| {
            Error::Protocol(format!(
                "schema_violation: capability action '{action}' is not registered in the bound snapshot"
            ))
        })
}

/// Validate the registry snapshot binding required by aggregate-admin actions.
/// Any supplied digest must identify the exact embedded snapshot; receivers
/// never fall back to a different/current registry for an unknown basis.
pub fn validate_capability_action_registry_binding(
    actions: &[String],
    digest: Option<&Hash>,
) -> Result<()> {
    let registry = match digest {
        Some(digest) => capability_action_registry_snapshot(digest)?,
        None => arkret_schema::embedded_json_artifact("registry/capability-action-registry.json")
            .map_err(|_| {
            Error::Protocol(
                "capability_registry_basis_unavailable: embedded registry missing".to_owned(),
            )
        })?,
    };
    let mut requires_binding = false;
    for action in actions {
        let descriptor = capability_action_descriptor_in(&registry, action)?;
        requires_binding |=
            descriptor.get("event_mapping_kind").and_then(Value::as_str) == Some("aggregate_admin");
    }
    if digest.is_some_and(|value| !value.as_str().starts_with("sha256:")) {
        return Err(Error::Protocol(
            "schema_violation: capability_action_registry_digest must be sha256".to_owned(),
        ));
    }
    if requires_binding && digest.is_none() {
        return Err(Error::Protocol(
            "capability_registry_basis_unavailable: aggregate_admin grant is missing capability_action_registry_digest"
                .to_owned(),
        ));
    }
    let Some(digest) = digest else {
        return Ok(());
    };
    capability_action_registry_snapshot(digest)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFrontierValidation {
    pub checked_grants: usize,
    pub max_authority_depth: u32,
}

/// Validate capability frontier invariants before using reduced grants.
///
/// Grants are the spec wire form
/// ([`arkret_models_collaboration::governance::grant_constraint::CapabilityGrant`]); each is
/// projected first, so schema violations (including any grant this evaluator
/// cannot faithfully enforce) reject the whole frontier.
pub fn validate_capability_frontier(
    grants: &[arkret_models_collaboration::governance::grant_constraint::CapabilityGrant],
) -> Result<CapabilityFrontierValidation> {
    let mut projections = Vec::with_capacity(grants.len());
    for grant in grants {
        projections.push(GrantProjection::from_wire(grant)?);
    }

    let mut by_id = HashMap::new();
    for projection in &projections {
        if by_id.insert(projection.id.clone(), projection).is_some() {
            return Err(Error::Protocol(format!(
                "duplicate capability grant id '{}'",
                projection.id
            )));
        }
    }

    let mut max_depth = 0;
    let mut memo = HashMap::new();
    let mut visiting = HashSet::new();
    for projection in &projections {
        let depth = validate_authority_chain(projection, &by_id, &mut memo, &mut visiting)?;
        max_depth = max_depth.max(depth);
    }

    Ok(CapabilityFrontierValidation {
        checked_grants: grants.len(),
        max_authority_depth: max_depth,
    })
}

/// Reject unknown critical constraint objects in wire JSON before typed deserialization.
pub fn reject_unknown_critical_constraints(value: &Value, supported: &[&str]) -> Result<()> {
    let Some(constraints) = value.get("constraints").and_then(Value::as_array) else {
        return Ok(());
    };
    for constraint in constraints {
        let critical = constraint
            .get("critical")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !critical {
            continue;
        }
        let constraint_kind = constraint
            .get("type")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                constraint.as_object().and_then(|object| {
                    object
                        .keys()
                        .find(|key| {
                            !matches!(
                                key.as_str(),
                                "critical" | "constraint_id" | "priority" | "effect"
                            )
                        })
                        .cloned()
                })
            })
            .ok_or_else(|| Error::Protocol("critical constraint is missing a type".to_owned()))?;
        if !supported
            .iter()
            .any(|supported| *supported == constraint_kind)
        {
            return Err(Error::Protocol(format!(
                "unknown critical constraint: {constraint_kind}"
            )));
        }
    }
    Ok(())
}

fn validate_authority_chain(
    grant: &GrantProjection,
    by_id: &HashMap<String, &GrantProjection>,
    memo: &mut HashMap<String, u32>,
    visiting: &mut HashSet<String>,
) -> Result<u32> {
    if let Some(depth) = memo.get(&grant.id) {
        return Ok(*depth);
    }
    if !visiting.insert(grant.id.clone()) {
        return Err(Error::Protocol(
            "capability authority cycle detected".to_owned(),
        ));
    }

    let result = (|| {
        if grant.issuer_authority_grant_refs.is_empty() {
            if !grant.has_realm_root_authority_ref {
                return Err(Error::Protocol(format!(
                    "capability grant '{}' has no authority root",
                    grant.id
                )));
            }
            return Ok(0);
        }

        let mut parents = Vec::with_capacity(grant.issuer_authority_grant_refs.len());
        let mut max_parent_depth = 0;
        for parent_id in &grant.issuer_authority_grant_refs {
            let parent = by_id.get(parent_id).ok_or_else(|| {
                Error::Protocol(format!(
                    "capability grant '{}' references missing issuer authority '{}'",
                    grant.id, parent_id
                ))
            })?;
            let parent_depth = validate_authority_chain(parent, by_id, memo, visiting)?;
            max_parent_depth = max_parent_depth.max(parent_depth);

            let parent_subject = parent.subject_did().ok_or_else(|| {
            Error::Protocol(format!(
                "capability parent '{}' has a condition subject and cannot anchor an authority chain",
                parent.id
            ))
        })?;
            if &grant.issuer != parent_subject
                || parent.subject_principal_server_id.as_ref()
                    != Some(&grant.issuer_principal_server_id)
            {
                return Err(Error::Protocol(format!(
                    "capability grant '{}' issuer authority does not match parent subject authority",
                    grant.id
                )));
            }
            if let (Some(child_basis), Some(parent_basis)) = (
                grant.capability_action_registry_digest.as_ref(),
                parent.capability_action_registry_digest.as_ref(),
            ) && child_basis != parent_basis
            {
                return Err(Error::Protocol(format!(
                    "capability grant '{}' uses a different registry basis than parent '{}'",
                    grant.id, parent.id
                )));
            }

            let Some((parent_max_depth, parent_allows_further)) = parent.authority_control_policy()
            else {
                return Err(Error::Protocol(format!(
                    "capability parent '{}' is not delegable",
                    parent.id
                )));
            };
            let child_max_depth = grant.authority_control_policy().and_then(|policy| policy.0);
            // An undeclared child depth is 0, not unbounded: a grant with no
            // authority_control constraint is non-delegable
            // (`models/governance-objects.md` grant `constraints` row, restated
            // in `authz/capabilities.md` §9 risk tiering). The "未声明视为无限"
            // note in §10.1 is about a *ref* that declares no depth, so that it
            // imposes no ceiling on the child.
            let child_depth_for_parent = child_max_depth.unwrap_or(0);
            if let Some(parent_max_depth) = parent_max_depth
                && (parent_max_depth == 0
                    || child_depth_for_parent > parent_max_depth.saturating_sub(1))
            {
                return Err(Error::Protocol(format!(
                    "capability grant '{}' exceeds parent '{}' max_authority_depth",
                    grant.id, parent.id
                )));
            }
            if !parent_allows_further && child_max_depth.unwrap_or(0) != 0 {
                return Err(Error::Protocol(format!(
                    "capability grant '{}' violates parent '{}' authority_regrant_allowed=false seal",
                    grant.id, parent.id
                )));
            }
            parents.push(*parent);
        }

        if !grant.has_realm_root_authority_ref {
            if !grant.actions.iter().all(|action| {
                parents.iter().any(|parent| {
                    actions_are_narrowed(std::slice::from_ref(action), &parent.actions)
                })
            }) {
                return Err(Error::Protocol(format!(
                    "capability grant '{}' widens authority-union actions",
                    grant.id
                )));
            }
            if !grant.resources.iter().all(|resource| {
                parents.iter().any(|parent| {
                    resources_are_narrowed(std::slice::from_ref(resource), &parent.resources)
                })
            }) {
                return Err(Error::Protocol(format!(
                    "capability grant '{}' widens authority-union resources",
                    grant.id
                )));
            }
        }

        if !grant.has_realm_root_authority_ref {
            for action in &grant.actions {
                let covering: Vec<_> = parents
                    .iter()
                    .copied()
                    .filter(|parent| {
                        actions_are_narrowed(std::slice::from_ref(action), &parent.actions)
                    })
                    .collect();
                if covering.is_empty() {
                    continue;
                }
                let earliest_not_before = covering.iter().filter_map(|p| p.not_before).min();
                if let (Some(child_from), Some(parent_from)) =
                    (grant.not_before, earliest_not_before)
                    && child_from < parent_from
                {
                    return Err(Error::Protocol(format!(
                        "capability grant '{}' starts before its covering authorities",
                        grant.id
                    )));
                }
                let covering_has_unbounded_expiry = covering.iter().any(|p| p.expires_at.is_none());
                let latest_expiry = covering.iter().filter_map(|p| p.expires_at).max();
                if !covering_has_unbounded_expiry
                    && let (Some(child_until), Some(parent_until)) =
                        (grant.expires_at, latest_expiry)
                    && child_until > parent_until
                {
                    return Err(Error::Protocol(format!(
                        "capability grant '{}' expires after its covering authorities",
                        grant.id
                    )));
                }
            }
        }

        let depth = max_parent_depth.saturating_add(1);
        arkret_wire::validate_authority_chain_depth(depth as usize)?;
        Ok(depth)
    })();

    visiting.remove(&grant.id);
    if let Ok(depth) = &result {
        memo.insert(grant.id.clone(), *depth);
    }
    result
}

fn actions_are_narrowed(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|child_action| {
        parent.iter().any(|parent_action| {
            if parent_action == child_action {
                return true;
            }
            let Some(parent_descriptor) = arkret_schema::capability_action(parent_action) else {
                return false;
            };
            if parent_descriptor.event_mapping_kind != "aggregate_admin" {
                return false;
            }
            let Some(child_descriptor) = arkret_schema::capability_action(child_action) else {
                return false;
            };
            child_descriptor.event_mapping_kind != "non_event_surface"
                && !child_descriptor.target_event_kinds.is_empty()
                && child_descriptor.target_event_kinds.iter().all(|target| {
                    parent_descriptor
                        .target_event_kinds
                        .iter()
                        .any(|parent_target| parent_target == target)
                })
        })
    })
}

fn resources_are_narrowed(child: &[ResourceSelector], parent: &[ResourceSelector]) -> bool {
    child.iter().all(|child| {
        parent
            .iter()
            .any(|parent| resource_is_narrowed(child, parent))
    })
}

fn resource_is_narrowed(child: &ResourceSelector, parent: &ResourceSelector) -> bool {
    if matches!(parent, ResourceSelector::Wildcard) || child == parent {
        return true;
    }
    match (child, parent) {
        (
            ResourceSelector::Strand {
                realm_id,
                strand_id,
            },
            ResourceSelector::Strand {
                realm_id: parent_realm,
                strand_id: parent_id,
            },
        ) => {
            realm_narrowed(realm_id, parent_realm)
                && option_narrowed(strand_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Object {
                realm_id,
                object_kind,
                object_ref,
                match_scope,
            },
            ResourceSelector::Object {
                realm_id: parent_realm,
                object_kind: parent_type,
                object_ref: parent_id,
                match_scope: parent_scope,
            },
        ) => {
            realm_narrowed(realm_id, parent_realm)
                && scope_narrowed(*match_scope, *parent_scope)
                && option_narrowed(object_kind.as_ref(), parent_type.as_ref())
                && option_narrowed(object_ref.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Message {
                realm_id,
                message_id,
            },
            ResourceSelector::Message {
                realm_id: parent_realm,
                message_id: parent_id,
            },
        ) => {
            realm_narrowed(realm_id, parent_realm)
                && option_narrowed(message_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Policy {
                realm_id,
                policy_id,
            },
            ResourceSelector::Policy {
                realm_id: parent_realm,
                policy_id: parent_id,
            },
        ) => {
            realm_narrowed(realm_id, parent_realm)
                && option_narrowed(policy_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Invite {
                realm_id,
                invite_id,
            },
            ResourceSelector::Invite {
                realm_id: parent_realm,
                invite_id: parent_id,
            },
        ) => {
            realm_narrowed(realm_id, parent_realm)
                && option_narrowed(invite_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Realm { realm_id },
            ResourceSelector::Realm {
                realm_id: parent_realm,
            },
        ) => realm_narrowed(realm_id, parent_realm),
        (
            ResourceSelector::Space {
                realm_id,
                space_id,
                match_scope,
            },
            ResourceSelector::Space {
                realm_id: parent_realm,
                space_id: parent_space,
                match_scope: parent_scope,
            },
        ) => {
            realm_narrowed(realm_id, parent_realm)
                && scope_narrowed(*match_scope, *parent_scope)
                && option_narrowed(space_id.as_ref(), parent_space.as_ref())
        }
        _ => false,
    }
}

fn scope_narrowed(
    child: ProtocolResourceSelectorScope,
    parent: ProtocolResourceSelectorScope,
) -> bool {
    parent == ProtocolResourceSelectorScope::RealmWide || child == parent
}

fn realm_narrowed(child: &str, parent: &str) -> bool {
    parent == "*" || child == parent
}

fn option_narrowed(child: Option<&String>, parent: Option<&String>) -> bool {
    match parent {
        None => true,
        Some(parent) => child.is_some_and(|child| child == parent),
    }
}

/// Extract active capability-grant events from a resolved Realm state.
///
/// Event content MUST be the spec grant artifact (`ak.schema.capability.v1`).
/// Content carrying the removed top-level `delegable` boolean, or failing to
/// deserialize into the core authority form, is rejected as
/// `schema_violation`.
/// Project a single resolved capability event into the spec wire-form
/// `CapabilityGrant`. The reducer runtime (`arkret-state`) owns
/// `RealmState`; the umbrella SDK iterates its `resolved_state` and calls
/// this per event, keeping `arkret-policy` free of any dependency on the
/// state runtime.
pub fn capability_grant_from_resolved_event(
    event: &arkret_models_collaboration::ResolvedStateEvent,
    default_realm_id: Option<RealmId>,
) -> Result<arkret_models_collaboration::governance::grant_constraint::CapabilityGrant> {
    use arkret_event_draft::ResolvedStateEventPayloadExt as _;

    let payload = event
        .typed_payload::<arkret_wire::event_spec::CapabilityGrant>()
        .map_err(|error| Error::Protocol(format!("schema_violation: {error}")))?;
    let grant = payload.grant;
    if grant.issuer != event.actor_id {
        return Err(Error::Protocol(
            "schema_violation: capability grant issuer must equal the accepted Event actor"
                .to_owned(),
        ));
    }
    Ok(
        arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::from_event_id(&event.source_event_id),
            schema: grant.schema,
            realm_id: grant.realm_id.or(default_realm_id),
            issuer: grant.issuer,
            issuer_principal_server_id: event.principal_server_id.clone(),
            subject: grant.subject,
            subject_principal_server_id: grant.subject_principal_server_id,
            actions: grant.actions,
            resources: grant.resources,
            capability_action_registry_digest: grant.capability_action_registry_digest,
            constraints: grant.constraints,
            issuer_authority_refs: grant.issuer_authority_refs,
            issued_at: grant.issued_at,
            not_before: grant.not_before,
            expires_at: grant.expires_at,
            updated_by: None,
            updated_at: None,
            revoked_by: None,
            revoked_at: None,
        },
    )
}

// ─── spec grant-constraint → engine constraint projection ─────────────────

/// Parse one spec `grant-constraint.schema.json` object into engine
/// [`ConstraintEntry`] values. A single spec constraint may project to
/// multiple engine entries (e.g. `field_access` carrying both allowed and
/// denied lists).
///
/// Fail-closed contract: families / subkinds / restriction fields this
/// evaluator cannot enforce return `Err` — silently dropping a restriction
/// would widen the grant. A declared `evaluation_class` must match the
/// canonical class derived by this evaluator; pure metadata
/// (`depends_on_moderation_state`, `x_*` extensions) is ignored.
pub(crate) fn constraint_entries_from_spec(
    constraint: &GrantConstraint,
) -> Result<Vec<ConstraintEntry>> {
    let constraint_kind = constraint.constraint_kind;
    let constraint_subkind = constraint.constraint_subkind;
    let constraint_id = constraint.constraint_id.clone();
    let declared_evaluation_class = constraint.evaluation_class.map(|value| match value {
        arkret_wire::EvaluationClass::Stateless => crate::EvaluationClass::Stateless,
        arkret_wire::EvaluationClass::GrantLocal => crate::EvaluationClass::GrantLocal,
        arkret_wire::EvaluationClass::RealmState => crate::EvaluationClass::RealmState,
        arkret_wire::EvaluationClass::External => crate::EvaluationClass::External,
    });
    let mut constraints: Vec<Constraint> = Vec::new();
    match constraint_kind {
        GrantConstraintKind::Temporal => match constraint_subkind {
            None | Some(GrantConstraintSubkind::Window) => {
                constraints.push(Constraint::Temporal {
                    not_before: constraint.not_before,
                    expires_at: constraint.expires_at,
                    recurrence: constraint
                        .recurrence
                        .as_ref()
                        .map(|value| {
                            serde_json::from_value::<Recurrence>(serde_json::to_value(value)?)
                                .map_err(|err| {
                                    Error::Protocol(format!("invalid recurrence: {err}"))
                                })
                        })
                        .transpose()?,
                });
            }
            Some(GrantConstraintSubkind::EditWindow | GrantConstraintSubkind::RedactWindow) => {
                constraints.push(Constraint::EditWindow {
                    applies_to_actions: constraint.applies_to_actions.clone(),
                    message_edit_window: optional_duration(
                        constraint.message_edit_window.as_deref(),
                    )?,
                    message_redact_window: optional_duration(
                        constraint.message_redact_window.as_deref(),
                    )?,
                    redact_after_window_allowed: constraint
                        .redact_after_window_allowed
                        .unwrap_or(false),
                });
            }
            Some(other) => {
                return Err(Error::Protocol(format!(
                    "unsupported temporal constraint constraint_subkind '{other:?}'"
                )));
            }
        },
        GrantConstraintKind::FieldAccess => {
            // Named conditions (constraint-schema.md §4.1) are not evaluated
            // by this engine; per the spec they MUST fail closed.
            if constraint.condition.is_some()
                || !constraint.sensitive_fields.is_empty()
                || constraint.sensitive_handling.is_some()
            {
                return Err(Error::Protocol("unsupported field_access condition/sensitive fields (cannot be enforced; failing closed)".to_owned()));
            }
            let effect = constraint_effect(constraint.effect);
            let denied_effect = match effect {
                ConstraintEffect::Allow => ConstraintEffect::Deny,
                other => other,
            };
            let allowed_write = constraint.allowed_write_fields.clone();
            if !allowed_write.is_empty() {
                constraints.push(Constraint::FieldAccess {
                    effect: ConstraintEffect::Allow,
                    scope: FieldScope::Write,
                    fields: allowed_write,
                });
            }
            let denied_write = constraint.denied_write_fields.clone();
            if !denied_write.is_empty() {
                constraints.push(Constraint::FieldAccess {
                    effect: denied_effect.clone(),
                    scope: FieldScope::Write,
                    fields: denied_write,
                });
            }
            let allowed_read = constraint.allowed_read_fields.clone();
            if !allowed_read.is_empty() {
                constraints.push(Constraint::FieldAccess {
                    effect: ConstraintEffect::Allow,
                    scope: FieldScope::Read,
                    fields: allowed_read,
                });
            }
            let denied_read = constraint.denied_read_fields.clone();
            if !denied_read.is_empty() {
                constraints.push(Constraint::FieldAccess {
                    effect: denied_effect,
                    scope: FieldScope::Read,
                    fields: denied_read,
                });
            }
        }
        GrantConstraintKind::KindRestriction => {
            if !constraint.allowed_space_kinds.is_empty()
                || !constraint.denied_space_kinds.is_empty()
            {
                return Err(Error::Protocol(
                    "unsupported space kind restriction (cannot be enforced; failing closed)"
                        .to_owned(),
                ));
            }
            constraints.push(Constraint::KindRestriction {
                allowed_object_kinds: nonempty_option(&constraint.allowed_object_kinds),
                denied_object_kinds: nonempty_option(&constraint.denied_object_kinds),
                allowed_morph_kinds: nonempty_option(&constraint.allowed_morph_kinds),
                denied_morph_kinds: nonempty_option(&constraint.denied_morph_kinds),
                allowed_facets: constraint.allowed_facets.clone(),
                denied_facets: constraint.denied_facets.clone(),
                scope_limitation: None,
            });
        }
        GrantConstraintKind::ScopeLimitation => {
            if !constraint.allowed_space_ids.is_empty()
                || !constraint.denied_space_ids.is_empty()
                || !constraint.allowed_data_labels.is_empty()
                || !constraint.allowed_endpoints.is_empty()
                || constraint.blob_presign_scope.is_some()
            {
                return Err(Error::Protocol(
                    "unsupported scope limitation field (cannot be enforced; failing closed)"
                        .to_owned(),
                ));
            }
            if !constraint.allowed_circle_ids.is_empty() {
                let allowed_circle_ids = constraint.allowed_circle_ids.iter().cloned().collect();
                constraints.push(Constraint::AllowedCircleIds { allowed_circle_ids });
            }
            if !constraint.allowed_session_ids.is_empty() {
                let allowed_session_ids = constraint.allowed_session_ids.iter().cloned().collect();
                constraints.push(Constraint::AllowedSessionIds {
                    allowed_session_ids,
                });
            }
            let allowed_relation_kinds = constraint.allowed_relation_kinds.clone();
            let allowed_view_ids = constraint.allowed_view_ids.clone();
            let allowed_from = constraint.allowed_from_container_refs.clone();
            let allowed_to = constraint.allowed_to_container_refs.clone();
            let has_container_move = !allowed_relation_kinds.is_empty()
                || !allowed_view_ids.is_empty()
                || !allowed_from.is_empty()
                || !allowed_to.is_empty()
                || constraint.wip_limit_override.is_some();
            if has_container_move {
                constraints.push(Constraint::ContainerMove {
                    allowed_relation_kinds,
                    allowed_view_ids,
                    allowed_from_container_refs: allowed_from,
                    allowed_to_container_refs: allowed_to,
                    wip_limit_override: constraint.wip_limit_override.unwrap_or(false),
                });
            }
            let scope = Constraint::ScopeLimitation {
                allowed_strand_ids: constraint.allowed_strand_ids.clone(),
                denied_strand_ids: constraint.denied_strand_ids.clone(),
                allowed_tracks: constraint.allowed_tracks.clone(),
                denied_tracks: constraint.denied_tracks.clone(),
                allowed_view_kinds: constraint.allowed_view_kinds.clone(),
                allowed_view_renderers: constraint.allowed_view_renderers.clone(),
                denied_view_kinds: constraint.denied_view_kinds.clone(),
                denied_view_renderers: constraint.denied_view_renderers.clone(),
            };
            let scope_is_empty = matches!(
                &scope,
                Constraint::ScopeLimitation {
                    allowed_strand_ids,
                    denied_strand_ids,
                    allowed_tracks,
                    denied_tracks,
                    allowed_view_kinds,
                    allowed_view_renderers,
                    denied_view_kinds,
                    denied_view_renderers,
                } if allowed_strand_ids.is_empty()
                    && denied_strand_ids.is_empty()
                    && allowed_tracks.is_empty()
                    && denied_tracks.is_empty()
                    && allowed_view_kinds.is_empty()
                    && allowed_view_renderers.is_empty()
                    && denied_view_kinds.is_empty()
                    && denied_view_renderers.is_empty()
            );
            if !scope_is_empty {
                constraints.push(scope);
            }
        }
        GrantConstraintKind::AuthorityControl => match constraint_subkind {
            None => {
                if constraint.applet_id.is_some()
                    || constraint.executed_by.is_some()
                    || constraint.registration_epoch.is_some()
                {
                    return Err(Error::Protocol("authority_control without applet subkind cannot carry applet binding fields".to_owned()));
                }
                constraints.push(Constraint::AuthorityControl {
                    max_authority_depth: constraint
                        .max_authority_depth
                        .map(|depth| u32::try_from(depth).unwrap_or(u32::MAX)),
                    authority_regrant_allowed: constraint
                        .authority_regrant_allowed
                        .unwrap_or(false),
                    constraint_subkind: None,
                    applet_id: None,
                    executed_by: None,
                    registration_epoch: None,
                });
            }
            Some(GrantConstraintSubkind::AppletAuthority) => {
                let applet_id = constraint.applet_id.clone().ok_or_else(|| {
                    Error::Protocol(
                        "authority_control.applet_authority requires applet_id".to_owned(),
                    )
                })?;
                let executed_by = constraint.executed_by.clone().ok_or_else(|| {
                    Error::Protocol(
                        "authority_control.applet_authority requires executed_by".to_owned(),
                    )
                })?;
                let registration_epoch =
                    constraint.registration_epoch.clone().ok_or_else(|| {
                        Error::Protocol(
                            "authority_control.applet_authority requires registration_epoch"
                                .to_owned(),
                        )
                    })?;
                constraints.push(Constraint::AuthorityControl {
                    max_authority_depth: constraint
                        .max_authority_depth
                        .map(|depth| u32::try_from(depth).unwrap_or(u32::MAX)),
                    authority_regrant_allowed: constraint
                        .authority_regrant_allowed
                        .unwrap_or(false),
                    constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
                    applet_id: Some(applet_id),
                    executed_by: Some(executed_by),
                    registration_epoch: Some(registration_epoch),
                });
            }
            Some(other) => {
                return Err(Error::Protocol(format!(
                    "unsupported authority_control constraint_subkind '{other:?}'"
                )));
            }
        },
        GrantConstraintKind::Quota => match constraint_subkind {
            Some(GrantConstraintSubkind::Rate) => {
                constraints.push(Constraint::RateLimiting {
                    max_operations: constraint.max_operations.ok_or_else(|| {
                        Error::Protocol("quota.rate constraint requires max_operations".to_owned())
                    })?,
                    period: optional_duration(constraint.period.as_deref())?.ok_or_else(|| {
                        Error::Protocol("quota.rate constraint requires period".to_owned())
                    })?,
                    scope: rate_limit_scope_typed(constraint.constraint_scope, "quota.rate", true)?,
                });
            }
            Some(GrantConstraintSubkind::Resource) => {
                if constraint.max_artifact_bytes.is_some() {
                    return Err(Error::Protocol(
                        "unsupported quota.resource max_artifact_bytes".to_owned(),
                    ));
                }
                let requires_scope =
                    constraint.max_total_blob_bytes.is_some() || constraint.max_resources.is_some();
                constraints.push(Constraint::ResourceLimit {
                    blob_max_bytes: constraint.blob_max_bytes,
                    max_total_blob_bytes: constraint.max_total_blob_bytes,
                    max_resources: constraint.max_resources,
                    resource_kind: constraint.resource_kind.clone(),
                    period: optional_duration(constraint.period.as_deref())?,
                    scope: rate_limit_scope_typed(
                        constraint.constraint_scope,
                        "quota.resource",
                        requires_scope,
                    )?,
                });
            }
            other => {
                return Err(Error::Protocol(format!(
                    "quota constraint requires constraint_subkind 'rate' or 'resource', got {other:?}"
                )));
            }
        },
        GrantConstraintKind::ClaimBased => match constraint_subkind {
            Some(GrantConstraintSubkind::Claim) => {
                let mut trusted_issuers = constraint.trusted_claim_issuers.clone();
                let mut required_claims = Vec::new();
                for item in &constraint.required_claims {
                    if !item.value_constraints.is_empty() || !item.extra.is_empty() {
                        return Err(Error::Protocol(
                            "unsupported required_claims value_constraints/extension field \
                             (cannot be enforced by this evaluator; failing closed)"
                                .to_owned(),
                        ));
                    }
                    let issuer = item.issuer.clone();
                    if let Some(issuer) = &issuer
                        && !trusted_issuers.contains(issuer)
                    {
                        trusted_issuers.push(issuer.clone());
                    }
                    for trusted in &item.trusted_issuers {
                        if !trusted_issuers.contains(trusted) {
                            trusted_issuers.push(trusted.clone());
                        }
                    }
                    required_claims.push(ClaimRequirement {
                        claim_kind: item.claim_kind.clone(),
                        issuer,
                        organization: item.organization.clone(),
                        status: item.status.clone(),
                        roles: (!item.roles.is_empty()).then(|| item.roles.clone()),
                    });
                }
                constraints.push(Constraint::ClaimBased {
                    required_claims,
                    trusted_issuers,
                    claim_refresh_required: constraint.claim_refresh_required.unwrap_or(false),
                    claim_max_age: optional_duration(constraint.claim_max_age.as_deref())?,
                });
            }
            Some(GrantConstraintSubkind::Approval) => {
                constraints.push(Constraint::ApprovalWorkflow {
                    approval_required: constraint.approval_required.unwrap_or(false),
                    approval_actor_ids: (!constraint.approval_actor_ids.is_empty())
                        .then(|| constraint.approval_actor_ids.clone()),
                    timeout: optional_duration(constraint.timeout.as_deref())?,
                    // The spec approval_mode enum (before_commit /
                    // proposal_then_approve / after_commit_review) describes
                    // timing, not quorum; the engine quorum mode is supplied
                    // by the caller via ApprovalStrandManager.
                    approval_mode: None,
                    approval_relation: constraint.approval_relation.map(|value| match value {
                        arkret_models_collaboration::governance::grant_constraint::GrantApprovalRelation::Responsible => "responsible",
                        arkret_models_collaboration::governance::grant_constraint::GrantApprovalRelation::Controller => "controller",
                        arkret_models_collaboration::governance::grant_constraint::GrantApprovalRelation::Guardian => "guardian",
                        arkret_models_collaboration::governance::grant_constraint::GrantApprovalRelation::RealmAdmin => "realm_admin",
                        arkret_models_collaboration::governance::grant_constraint::GrantApprovalRelation::Custom => "custom",
                    }.to_owned()),
                    guardian_approval_required: constraint.guardian_approval_required.unwrap_or(false),
                    controller_approval_required: constraint.controller_approval_required.unwrap_or(false),
                });
            }
            Some(GrantConstraintSubkind::Accountability) => {
                constraints.push(Constraint::Accountability {
                    accountability_required: constraint.accountability_required.unwrap_or(false),
                    responsible_actor: None,
                });
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unsupported claim_based constraint constraint_subkind {other:?}"
                )));
            }
        },
        GrantConstraintKind::Confidentiality => match constraint_subkind {
            Some(GrantConstraintSubkind::Encryption) => {
                constraints.push(Constraint::EncryptionRequirement {
                    encryption_required: constraint.encryption_required.unwrap_or(false),
                    min_encryption_level: None,
                });
            }
            Some(GrantConstraintSubkind::Visibility) => {
                constraints.push(Constraint::VisibilityControl {
                    allowed_history_access_values: constraint
                        .allowed_history_access_values
                        .iter()
                        .map(|value| value.as_str().to_owned())
                        .collect(),
                    denied_history_access_values: Vec::new(),
                    redacted_history_allowed: constraint.redacted_history_allowed.unwrap_or(false),
                });
            }
            other => {
                return Err(Error::Protocol(format!(
                    "confidentiality constraint requires constraint_subkind 'encryption' or \
                     'visibility', got {other:?}"
                )));
            }
        },
    }

    let entries: Vec<_> = constraints
        .into_iter()
        .map(|constraint| ConstraintEntry {
            constraint_id: constraint_id.clone(),
            constraint,
            priority: 0,
        })
        .collect();

    validate_declared_evaluation_class(
        constraint_kind,
        constraint_subkind,
        declared_evaluation_class,
        &entries,
    )?;

    Ok(entries)
}

fn validate_declared_evaluation_class(
    constraint_kind: GrantConstraintKind,
    constraint_subkind: Option<GrantConstraintSubkind>,
    declared: Option<crate::EvaluationClass>,
    entries: &[ConstraintEntry],
) -> Result<()> {
    let Some(declared) = declared else {
        return Ok(());
    };
    let Some(canonical) = dominant_evaluation_class(entries) else {
        return Ok(());
    };
    if declared != canonical {
        return Err(Error::Protocol(format!(
            "evaluation_class mismatch for {}{}: declared {}, canonical {}",
            constraint_kind.as_str(),
            constraint_subkind
                .map(|constraint_subkind| format!(".{constraint_subkind:?}"))
                .unwrap_or_default(),
            evaluation_class_name(declared),
            evaluation_class_name(canonical)
        )));
    }
    Ok(())
}

fn dominant_evaluation_class(entries: &[ConstraintEntry]) -> Option<crate::EvaluationClass> {
    entries
        .iter()
        .map(ConstraintEntry::evaluation_class)
        .max_by_key(|evaluation_class| match *evaluation_class {
            crate::EvaluationClass::Stateless => 0,
            crate::EvaluationClass::GrantLocal => 1,
            crate::EvaluationClass::RealmState => 2,
            crate::EvaluationClass::External => 3,
        })
}

fn evaluation_class_name(value: crate::EvaluationClass) -> &'static str {
    match value {
        crate::EvaluationClass::Stateless => "stateless",
        crate::EvaluationClass::GrantLocal => "grant_local",
        crate::EvaluationClass::RealmState => "realm_state",
        crate::EvaluationClass::External => "external",
    }
}

fn constraint_effect(value: GrantConstraintEffect) -> ConstraintEffect {
    match value {
        GrantConstraintEffect::Allow => ConstraintEffect::Allow,
        GrantConstraintEffect::Deny => ConstraintEffect::Deny,
        GrantConstraintEffect::Quarantine => ConstraintEffect::Quarantine,
        GrantConstraintEffect::RequireReview => ConstraintEffect::RequireReview,
    }
}

fn rate_limit_scope_typed(
    value: Option<GrantConstraintScope>,
    constraint: &str,
    required: bool,
) -> Result<GrantRateLimitScope> {
    match value {
        Some(GrantConstraintScope::PerActor) => Ok(GrantRateLimitScope::PerActor),
        Some(GrantConstraintScope::PerSpace) => Ok(GrantRateLimitScope::PerSpace),
        Some(GrantConstraintScope::PerRealm) => Ok(GrantRateLimitScope::PerRealm),
        Some(GrantConstraintScope::Global) => Ok(GrantRateLimitScope::Global),
        None if required => Err(Error::Protocol(format!(
            "{constraint} constraint requires constraint_scope"
        ))),
        None => Ok(GrantRateLimitScope::Global),
    }
}

fn optional_duration(value: Option<&str>) -> Result<Option<ConstraintDuration>> {
    value.map(parse_iso8601_duration).transpose()
}

fn nonempty_option<T: Clone>(values: &[T]) -> Option<Vec<T>> {
    (!values.is_empty()).then(|| values.to_vec())
}

/// Parse an ISO 8601 duration (`P…T…` per the spec constraint schema) into
/// the engine's [`ConstraintDuration`]. Calendar-ambiguous components
/// (years, months) fail closed.
fn parse_iso8601_duration(value: &str) -> Result<ConstraintDuration> {
    let invalid = || Error::Protocol(format!("invalid ISO 8601 duration '{value}'"));
    let rest = value.strip_prefix('P').ok_or_else(invalid)?;
    let (date_part, time_part) = match rest.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (rest, None),
    };

    let mut seconds: u64 = 0;
    let mut accumulate = |part: &str, time: bool| -> Result<()> {
        let mut digits = String::new();
        for ch in part.chars() {
            if ch.is_ascii_digit() {
                digits.push(ch);
                continue;
            }
            if digits.is_empty() {
                return Err(invalid());
            }
            let amount: u64 = digits.parse().map_err(|_| invalid())?;
            digits.clear();
            let factor = match (time, ch) {
                (false, 'W') => 7 * 86_400,
                (false, 'D') => 86_400,
                (true, 'H') => 3_600,
                (true, 'M') => 60,
                (true, 'S') => 1,
                (false, 'Y') | (false, 'M') => {
                    return Err(Error::Protocol(format!(
                        "calendar-ambiguous duration component '{ch}' in '{value}' \
                         is not supported"
                    )));
                }
                _ => return Err(invalid()),
            };
            seconds = seconds
                .checked_add(amount.checked_mul(factor).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
        }
        if !digits.is_empty() {
            return Err(invalid());
        }
        Ok(())
    };
    accumulate(date_part, false)?;
    if let Some(time_part) = time_part {
        if time_part.is_empty() {
            return Err(invalid());
        }
        accumulate(time_part, true)?;
    }

    let duration = if seconds > 0 && seconds.is_multiple_of(86_400) {
        ConstraintDuration {
            value: seconds / 86_400,
            unit: "d".to_owned(),
        }
    } else if seconds > 0 && seconds.is_multiple_of(3_600) {
        ConstraintDuration {
            value: seconds / 3_600,
            unit: "h".to_owned(),
        }
    } else if seconds > 0 && seconds.is_multiple_of(60) {
        ConstraintDuration {
            value: seconds / 60,
            unit: "m".to_owned(),
        }
    } else {
        ConstraintDuration {
            value: seconds,
            unit: "s".to_owned(),
        }
    };
    Ok(duration)
}

// ─── S-10 (savfox SDK gap): ak.capability.grant builder ───────────────────

/// Build a `ak.capability.grant` Event Envelope around a spec
/// [`arkret_models_collaboration::governance::grant_constraint::CapabilityGrant`].
///
/// Chain verification (subject ⇒ issuer narrowing, action / resource
/// narrowing, time-window narrowing, cycle detection) is already in
/// [`validate_capability_frontier`]. This builder is the bookend: it mints
/// the Envelope that goes onto the wire. The content is the canonical
/// `capability_grant_payload` wrapper (`{grant_id, grant}`) embedding the
/// core authority artifact — `schema` / `issued_at` / `proofs` are present
/// and the removed top-level `delegable` cannot occur; re-granting is
/// expressed via [`CapabilityGrantBuilder::with_authority_control`].
#[derive(Clone, Debug)]
pub struct CapabilityGrantBuilder {
    /// Producer-signed security scope of the Envelope this builder emits.
    scope_ref: arkret_wire::ScopeRef,
    /// The Envelope `actor_id` (signer / issuer of the grant).
    actor_id: DidCoreId,
    grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
}

impl CapabilityGrantBuilder {
    /// Construct a new builder bound to the issuing Realm + actor.
    /// `grant.issuer` MUST equal `actor_id`; the builder enforces this
    /// at `build` time.
    pub fn new(
        scope_ref: arkret_wire::ScopeRef,
        actor_id: DidCoreId,
        grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    ) -> Self {
        Self {
            scope_ref,
            actor_id,
            grant,
        }
    }

    /// Override the grant subject.
    pub fn with_subject(mut self, subject: DidCoreId) -> Self {
        self.grant.subject = CapabilitySubject::CoreDid(subject);
        self
    }

    /// Replace the allowed actions list.
    pub fn with_actions(mut self, actions: Vec<String>) -> Self {
        self.grant.actions = actions;
        self
    }

    /// Bind aggregate-admin action expansion to an exact registry snapshot.
    pub fn with_capability_action_registry_digest(mut self, digest: Hash) -> Self {
        self.grant.capability_action_registry_digest = Some(digest);
        self
    }

    /// Replace the resource selector list (serialized to the spec selector
    /// object form).
    pub fn with_resources(mut self, resources: Vec<ResourceSelector>) -> Self {
        self.grant.resources = resources
            .iter()
            .map(ResourceSelector::to_spec_value)
            .map(|value| {
                serde_json::from_value(value)
                    .expect("policy resource selectors serialize to the canonical wire schema")
            })
            .collect();
        self
    }

    /// Declare the authority re-grant budget via the canonical
    /// `authority_control` constraint (capabilities.md §10). Replaces the
    /// ordinary depth-control entry while preserving registered subkinds such
    /// as `applet_authority`. The removed
    /// removed top-level boolean is intentionally not expressible.
    pub fn with_authority_control(
        mut self,
        max_authority_depth: u32,
        authority_regrant_allowed: bool,
    ) -> Self {
        self.grant.constraints.retain(|constraint| {
            constraint.constraint_kind != GrantConstraintKind::AuthorityControl
                || constraint.constraint_subkind.is_some()
        });
        self.grant
            .constraints
            .push(GrantConstraint::authority_control(
                u64::from(max_authority_depth),
                authority_regrant_allowed,
            ));
        self
    }

    /// Bind this grant to an issuer-authority grant id.
    pub fn with_issuer_authority_grant(mut self, grant_id: GrantId) -> Self {
        self.grant.issuer_authority_refs.push(
            arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {
                grant_id,
            },
        );
        self
    }

    /// Replace the constraint list with spec-shaped typed
    /// `grant-constraint.schema.json` DTOs. They are validated at
    /// [`Self::build`] time via the engine projection.
    pub fn with_constraints(mut self, constraints: Vec<GrantConstraint>) -> Self {
        self.grant.constraints = constraints;
        self
    }

    pub fn with_not_before(mut self, not_before: DateTime<Utc>) -> Self {
        self.grant.not_before = Some(not_before);
        self
    }

    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.grant.expires_at = Some(expires_at);
        self
    }

    /// Materialize the unsigned `ak.capability.grant` Envelope.
    ///
    /// Validates the grant against the spec wire contract first (schema
    /// constant, non-empty actions / resources, parseable
    /// selectors / constraints) so a violating grant can never be encoded.
    pub fn build(self, created_at: DateTime<Utc>) -> Result<arkret_event_draft::EventIntent> {
        if self.grant.issuer != self.actor_id {
            return Err(Error::Protocol(format!(
                "CapabilityGrantBuilder: grant.issuer '{}' does not match actor_id '{}'",
                self.grant.issuer, self.actor_id
            )));
        }
        // Reject anything the spec schema would reject before it reaches the
        // wire (schema_violation semantics).
        GrantProjection::from_wire(&self.grant)?;
        let payload = arkret_models_collaboration::events_payloads::CapabilityGrantPayload {
            grant: arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
                schema: self.grant.schema,
                realm_id: self.grant.realm_id,
                issuer: self.grant.issuer,
                subject: self.grant.subject,
                subject_principal_server_id: self.grant.subject_principal_server_id,
                actions: self.grant.actions,
                resources: self.grant.resources,
                capability_action_registry_digest: self.grant.capability_action_registry_digest,
                constraints: self.grant.constraints,
                issuer_authority_refs: self.grant.issuer_authority_refs,
                issued_at: self.grant.issued_at,
                not_before: self.grant.not_before,
                expires_at: self.grant.expires_at,
            },
        };
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::CapabilityGrant>::new(
            self.scope_ref,
            self.actor_id.clone(),
            self.grant.issuer_principal_server_id,
            payload,
        )
        .map_err(|error| Error::Protocol(error.to_string()))?
        .into_intent(created_at)
        .map_err(|error| Error::Protocol(error.to_string()))
    }
}

/// Build an unsigned subject-only `ak.capability.relinquish` Event. This path
/// intentionally carries no `authorization_ref`: the reducer authorizes it by
/// matching the Event signer to the target grant subject.
pub fn build_capability_relinquish_intent(
    scope_ref: arkret_wire::ScopeRef,
    subject: DidCoreId,
    created_at: DateTime<Utc>,
    payload: arkret_models_collaboration::events_payloads::CapabilityRelinquishPayload,
) -> Result<arkret_event_draft::EventIntent> {
    arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::CapabilityRelinquish>::new(
        scope_ref,
        subject.clone(),
        subject,
        payload,
    )
    .map_err(|error| Error::Protocol(error.to_string()))?
    .into_intent(created_at)
    .map_err(|error| Error::Protocol(error.to_string()))
}

#[cfg(test)]
mod capability_grant_builder_tests {
    use arkret_wire::AppletId;
    use serde_json::json;

    use super::*;

    fn constraint_entries_from_spec(value: &Value) -> Result<Vec<ConstraintEntry>> {
        let constraint: GrantConstraint = serde_json::from_value(value.clone())?;
        super::constraint_entries_from_spec(&constraint)
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
    }

    fn scope() -> arkret_wire::ScopeRef {
        arkret_wire::ScopeRef::Realm { realm_id: realm() }
    }

    fn alice() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn bob() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:bob.example").unwrap()
    }

    fn bob_principal() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:bob.example").unwrap()
    }

    fn hlc() -> crate::Hlc {
        crate::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
    }

    fn created_at() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-05-26T10:30:00.000Z")
            .expect("a canonical test timestamp")
            .with_timezone(&chrono::Utc)
    }

    /// Finalize a built grant at a pinned chain position.
    ///
    /// The grant's own wire form only exists once the identity is derived from
    /// it; production positions the write from the accepted actor frontier and
    /// the durable signing stamp, which a unit test has neither of.
    fn authored(intent: arkret_event_draft::EventIntent) -> arkret_wire::AuthoredEvent {
        intent
            .author_with_digest_suite(
                1,
                crate::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .expect("a test grant intent finalizes")
    }

    fn base_grant() -> arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
        arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::new("ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu").unwrap(),
            schema: SchemaId::CAPABILITY_V1.to_owned(),
            realm_id: None,
            issuer: alice(),
            issuer_principal_server_id: alice(),
            subject: CapabilitySubject::CoreDid(bob()),
            subject_principal_server_id: Some(alice()),
            actions: vec!["ak.message.create".to_owned()],
            resources: vec![serde_json::from_value(json!({"kind": "*"})).unwrap()],
            capability_action_registry_digest: None,
            constraints: Vec::new(),
            issuer_authority_refs: vec![
                arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::RealmRoot {
                    realm_id: realm(),
                    cell_ref: arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
                    controller_epoch_at_issuance: 0,
                    authority_generation: 0,
                },
            ],
            issued_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            not_before: None,
            expires_at: None,
            updated_by: None,
            updated_at: None,
            revoked_by: None,
            revoked_at: None,
        }
    }

    #[test]
    fn capability_grant_builder_emits_spec_wire_form() {
        let event = authored(
            CapabilityGrantBuilder::new(scope(), alice(), base_grant())
                .build(created_at())
                .unwrap(),
        );
        assert_eq!(event.kind, arkret_wire::EventKind::CapabilityGrant);
        // Genesis carries only the grant create body; its GrantId is derived
        // from the accepted EventId by the reducer.
        assert!(!event.payload.contains_key("grant_id"));
        let artifact = &event.payload["grant"];
        assert!(artifact.get("id").is_none());
        assert_eq!(artifact["schema"], SchemaId::CAPABILITY_V1);
        assert_eq!(
            artifact["issuer"],
            "ak:did_core:webvh:z6mkfixture:alice.example"
        );
        assert_eq!(
            artifact["subject"],
            "ak:did_core:webvh:z6mkfixture:bob.example"
        );
        assert!(artifact.get("issued_at").is_some());
        assert_eq!(artifact["issuer_authority_refs"][0]["kind"], "realm_root");
        assert!(
            artifact.get("proofs").is_none(),
            "the grant body must not carry a second durable proof"
        );
        assert!(
            artifact.get("delegable").is_none(),
            "the removed top-level delegable boolean must never reach the wire"
        );
        // Wrapper round-trips back into the core authority form.
        let source_event_id =
            arkret_wire::EventId::new("ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim")
                .unwrap();
        let event_view = arkret_models_collaboration::ResolvedStateEvent {
            kind: event.kind.clone(),
            subject: "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu".to_owned(),
            source_event_id: source_event_id.clone(),
            actor_id: alice(),
            principal_server_id: alice(),
            actor_seq: 1,
            hlc: Some(hlc()),
            content: Value::Object(event.payload.clone().into_iter().collect()),
        };
        let grant = capability_grant_from_resolved_event(&event_view, None).unwrap();
        assert_eq!(grant.id, GrantId::from_event_id(&source_event_id));
    }

    #[test]
    fn capability_grant_builder_rejects_issuer_actor_mismatch() {
        let err = CapabilityGrantBuilder::new(scope(), bob(), base_grant())
            .build(created_at())
            .expect_err("issuer / actor mismatch must be rejected");
        assert!(format!("{err}").contains("does not match"));
    }

    #[test]
    fn capability_grant_deserialization_rejects_legacy_inner_proofs() {
        let mut value = serde_json::to_value(base_grant()).unwrap();
        value["proofs"] = json!([]);
        let error = serde_json::from_value::<
            arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
        >(value)
        .expect_err("the obsolete inner proof carrier must fail closed");
        assert!(error.to_string().contains("unknown field `proofs`"));
    }

    #[test]
    fn capability_grant_builder_rejects_missing_authority_refs() {
        let mut grant = base_grant();
        grant.issuer_authority_refs.clear();
        let err = CapabilityGrantBuilder::new(scope(), alice(), grant)
            .build(created_at())
            .expect_err("an authority-less grant must be rejected");
        assert!(format!("{err}").contains("requires issuer_authority_refs"));
    }

    #[test]
    fn capability_grant_deserialization_rejects_omitted_authority_refs() {
        let mut value = serde_json::to_value(base_grant()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("issuer_authority_refs");
        let error = serde_json::from_value::<
            arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
        >(value)
        .expect_err("the required authority refs field must not default");
        assert!(error.to_string().contains("issuer_authority_refs"));
    }

    #[test]
    fn capability_grant_builder_rejects_wrong_schema() {
        let mut grant = base_grant();
        grant.schema = "ak.schema.capability.unregistered.v1".to_owned();
        let err = CapabilityGrantBuilder::new(scope(), alice(), grant)
            .build(created_at())
            .expect_err("wrong schema constant must be rejected");
        assert!(format!("{err}").contains("schema_violation"));
    }

    #[test]
    fn aggregate_admin_grant_requires_registry_digest() {
        let mut grant = base_grant();
        grant.actions = vec!["ak.realm.admin".to_owned()];
        let err = CapabilityGrantBuilder::new(scope(), alice(), grant)
            .build(created_at())
            .expect_err("aggregate admin without registry basis must fail closed");
        assert!(format!("{err}").contains("capability_registry_basis_unavailable"));
    }

    #[test]
    fn aggregate_admin_grant_binds_current_registry_in_wire_body() {
        let digest = current_capability_action_registry_digest().unwrap();
        let mut grant = base_grant();
        grant.actions = vec!["ak.realm.admin".to_owned()];
        let event = authored(
            CapabilityGrantBuilder::new(scope(), alice(), grant)
                .with_capability_action_registry_digest(digest.clone())
                .build(created_at())
                .unwrap(),
        );
        assert_eq!(
            event.payload["grant"]["capability_action_registry_digest"],
            digest.as_str()
        );
    }

    #[test]
    fn supplied_unknown_registry_digest_fails_closed() {
        let mut grant = base_grant();
        grant.actions = vec!["ak.realm.admin".to_owned()];
        grant.capability_action_registry_digest =
            Some(Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap());
        let err = CapabilityGrantBuilder::new(scope(), alice(), grant)
            .build(created_at())
            .expect_err("unknown registry basis must fail closed");
        assert!(format!("{err}").contains("capability_registry_basis_unavailable"));
    }

    #[test]
    fn capability_grant_builder_encodes_authority_control_constraint() {
        let event = authored(
            CapabilityGrantBuilder::new(scope(), alice(), base_grant())
                .with_authority_control(2, true)
                .build(created_at())
                .unwrap(),
        );
        let constraints = event.payload["grant"]["constraints"].as_array().unwrap();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0]["constraint_kind"], "authority_control");
        assert_eq!(constraints[0]["max_authority_depth"], 2);
    }

    #[test]
    fn authority_depth_builder_preserves_applet_authority_subkind() {
        let mut grant = base_grant();
        grant.constraints.push(GrantConstraint::applet_authority(
            AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            DidCoreId::new("ak:did_core:web:calendar.example").unwrap(),
            Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        ));
        let event = authored(
            CapabilityGrantBuilder::new(scope(), alice(), grant)
                .with_authority_control(2, true)
                .build(created_at())
                .unwrap(),
        );
        let constraints = event.payload["grant"]["constraints"].as_array().unwrap();
        assert_eq!(constraints.len(), 2);
        assert!(constraints.iter().any(|constraint| {
            constraint["constraint_subkind"] == "applet_authority"
                && constraint["applet_id"] == "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        }));
    }

    #[test]
    fn capability_grant_deserialization_rejects_unknown_constraint_kind() {
        let mut artifact = serde_json::to_value(base_grant()).unwrap();
        artifact["constraints"] = json!([{
                "constraint_kind": "telepathy",
                "effect": "allow",
        }]);
        let err = serde_json::from_value::<
            arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
        >(artifact)
        .expect_err("unknown constraint family must fail closed");
        assert!(format!("{err}").contains("unknown variant"));
    }

    #[test]
    fn capability_chain_verifier_accepts_narrowing_child() {
        let parent = arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::new("ak:grant:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
            actions: vec!["ak.message.create".to_owned()],
            constraints: vec![GrantConstraint::authority_control(1, true)],
            ..base_grant()
        };
        let child = arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::new("ak:grant:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap(),
            issuer_authority_refs: vec![
                arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {
                    grant_id: parent.id.clone(),
                },
            ],
            issuer: bob(),
            subject: CapabilitySubject::CoreDid(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:carol.example").unwrap(),
            ),
            actions: vec!["ak.message.create".to_owned()],
            ..base_grant()
        };
        let validation = validate_capability_frontier(&[parent, child]).unwrap();
        assert_eq!(validation.checked_grants, 2);
        assert!(validation.max_authority_depth >= 1);
    }

    #[test]
    fn capability_chain_verifier_rejects_parent_without_authority_control() {
        let parent = arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::new("ak:grant:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
            actions: vec!["ak.message.create".to_owned()],
            ..base_grant()
        };
        let child = arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::new("ak:grant:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap(),
            issuer_authority_refs: vec![
                arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {
                    grant_id: parent.id.clone(),
                },
            ],
            issuer: bob(),
            subject: CapabilitySubject::CoreDid(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:carol.example").unwrap(),
            ),
            ..base_grant()
        };
        let err = validate_capability_frontier(&[parent, child]).unwrap_err();
        assert!(format!("{err}").contains("not delegable"));
    }

    #[test]
    fn capability_chain_verifier_accepts_multi_parent_union_and_derives_depth() {
        let parent_create =
            arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
                id: GrantId::new("ak:grant:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934").unwrap(),
                actions: vec!["ak.message.create".to_owned()],
                constraints: vec![GrantConstraint::authority_control(1, true)],
                ..base_grant()
            };
        let parent_update =
            arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
                id: GrantId::new("ak:grant:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu").unwrap(),
                actions: vec!["ak.message.revise".to_owned()],
                constraints: vec![GrantConstraint::authority_control(1, true)],
                ..base_grant()
            };
        let child = arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::new("ak:grant:AfYjtj18lO9CeLkb1-l4BiiXSDtfZT21Z_Ez69OUDDEK").unwrap(),
            issuer_authority_refs: vec![
                arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {
                    grant_id: parent_create.id.clone(),
                },
                arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {
                    grant_id: parent_update.id.clone(),
                },
            ],
            issuer: bob(),
            subject: CapabilitySubject::CoreDid(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:carol.example").unwrap(),
            ),
            actions: vec!["ak.message.create".to_owned(), "ak.message.revise".to_owned()],
            constraints: vec![GrantConstraint::authority_control(0, false)],
            ..base_grant()
        };

        let validation =
            validate_capability_frontier(&[parent_create, parent_update, child]).unwrap();
        assert_eq!(validation.max_authority_depth, 1);
    }

    #[test]
    fn resolved_event_with_top_level_delegable_is_schema_violation() {
        let mut artifact = serde_json::to_value(base_grant()).unwrap();
        artifact["delegable"] = json!(true);
        let content = json!({"grant": artifact});
        let event = arkret_models_collaboration::ResolvedStateEvent {
            kind: arkret_wire::EventKind::CapabilityGrant,
            subject: "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu".to_owned(),
            source_event_id: arkret_wire::EventId::new(
                "ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim",
            )
            .unwrap(),
            actor_id: alice(),
            principal_server_id: alice(),
            actor_seq: 1,
            hlc: Some(hlc()),
            content,
        };
        let err = capability_grant_from_resolved_event(&event, None).unwrap_err();
        assert!(format!("{err}").contains("schema_violation"));
        assert!(format!("{err}").contains("delegable"));
    }

    #[test]
    fn iso8601_durations_project_to_constraint_durations() {
        assert_eq!(
            parse_iso8601_duration("PT1H").unwrap(),
            ConstraintDuration {
                value: 1,
                unit: "h".to_owned()
            }
        );
        assert_eq!(
            parse_iso8601_duration("P7D").unwrap(),
            ConstraintDuration {
                value: 7,
                unit: "d".to_owned()
            }
        );
        assert_eq!(
            parse_iso8601_duration("PT90S").unwrap(),
            ConstraintDuration {
                value: 90,
                unit: "s".to_owned()
            }
        );
        assert!(parse_iso8601_duration("P1M").is_err(), "months fail closed");
        assert!(parse_iso8601_duration("about an hour").is_err());
    }

    #[test]
    fn spec_constraints_project_to_engine_entries() {
        let entries = constraint_entries_from_spec(&json!({
            "constraint_kind": "temporal",
            "effect": "allow",
            "expires_at": "2026-04-30T00:00:00.000Z",
        }))
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].constraint,
            Constraint::Temporal {
                expires_at: Some(_),
                ..
            }
        ));

        let entries = constraint_entries_from_spec(&json!({
            "constraint_kind": "field_access",
            "effect": "allow",
            "allowed_write_fields": ["metadata.title", "content"],
        }))
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            &entries[0].constraint,
            Constraint::FieldAccess { effect: ConstraintEffect::Allow, scope: FieldScope::Write, fields }
                if fields.len() == 2
        ));

        // claim_based requires a constraint_subkind (schema allOf gate).
        assert!(
            constraint_entries_from_spec(&json!({
                "constraint_kind": "claim_based",
                "effect": "allow",
            }))
            .is_err()
        );
    }

    #[test]
    fn quota_constraint_scope_is_closed_and_required_for_cumulative_quotas() {
        let entries = constraint_entries_from_spec(&json!({
            "constraint_kind": "quota",
            "constraint_subkind": "rate",
            "effect": "allow",
            "max_operations": 5,
            "period": "PT1H",
            "constraint_scope": "per_actor",
        }))
        .unwrap();
        assert!(matches!(
            entries[0].constraint,
            Constraint::RateLimiting {
                scope: GrantRateLimitScope::PerActor,
                ..
            }
        ));

        let entries = constraint_entries_from_spec(&json!({
            "constraint_kind": "quota",
            "constraint_subkind": "resource",
            "effect": "allow",
            "max_resources": 10,
            "constraint_scope": "per_realm",
        }))
        .unwrap();
        assert!(matches!(
            entries[0].constraint,
            Constraint::ResourceLimit {
                scope: GrantRateLimitScope::PerRealm,
                ..
            }
        ));

        assert!(
            constraint_entries_from_spec(&json!({
                "constraint_kind": "quota",
                "constraint_subkind": "rate",
                "effect": "allow",
                "max_operations": 5,
                "period": "PT1H",
            }))
            .is_err()
        );

        assert!(
            constraint_entries_from_spec(&json!({
                "constraint_kind": "quota",
                "constraint_subkind": "resource",
                "effect": "allow",
                "max_total_blob_bytes": 1024,
            }))
            .is_err()
        );

        assert!(
            constraint_entries_from_spec(&json!({
                "constraint_kind": "quota",
                "constraint_subkind": "rate",
                "effect": "allow",
                "max_operations": 5,
                "period": "PT1H",
                "constraint_scope": "per_planet",
            }))
            .is_err()
        );
    }

    #[test]
    fn applet_authority_projects_from_the_registered_spec_shape() {
        let epoch = format!("sha256:{}", "a".repeat(64));
        let entries = constraint_entries_from_spec(&json!({
            "constraint_kind": "authority_control",
            "constraint_subkind": "applet_authority",
            "effect": "allow",
            "evaluation_class": "grant_local",
            "applet_id": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb",
            "executed_by": "ak:did_core:web:calendar.example",
            "registration_epoch": epoch,
        }))
        .unwrap();
        assert!(matches!(
            &entries[0].constraint,
            Constraint::AuthorityControl {
                constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
                applet_id: Some(_),
                executed_by: Some(_),
                registration_epoch: Some(_),
                ..
            }
        ));

        assert!(
            constraint_entries_from_spec(&json!({
                "constraint_kind": "authority_control",
                "constraint_subkind": "applet_authority",
                "effect": "allow",
                "applet_id": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb",
                "executed_by": "ak:did_core:web:calendar.example",
            }))
            .is_err()
        );
        assert!(
            constraint_entries_from_spec(&json!({
                "constraint_kind": "applet_delegation_binding",
                "effect": "allow",
            }))
            .is_err()
        );
    }

    #[test]
    fn declared_evaluation_class_must_match_canonical_projection() {
        let err = constraint_entries_from_spec(&json!({
            "constraint_kind": "quota",
            "constraint_subkind": "rate",
            "effect": "allow",
            "evaluation_class": "stateless",
            "max_operations": 5,
            "period": "PT1H",
            "constraint_scope": "global",
        }))
        .expect_err("declared evaluation_class mismatch must fail closed");
        assert!(format!("{err}").contains("evaluation_class mismatch"));

        let entries = constraint_entries_from_spec(&json!({
            "constraint_kind": "quota",
            "constraint_subkind": "rate",
            "effect": "allow",
            "evaluation_class": "external",
            "max_operations": 5,
            "period": "PT1H",
            "constraint_scope": "global",
        }))
        .unwrap();
        assert_eq!(
            entries[0].evaluation_class(),
            crate::EvaluationClass::External
        );
    }

    #[test]
    fn relinquish_builder_is_subject_only_and_carries_no_authorization_ref() {
        let payload = arkret_models_collaboration::events_payloads::CapabilityRelinquishPayload {
            grant_id: GrantId::new("ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu")
                .unwrap(),
            reason: Some("no longer needed".to_owned()),
        };
        let intent =
            build_capability_relinquish_intent(scope(), bob_principal(), created_at(), payload)
                .unwrap();
        assert_eq!(intent.kind(), &arkret_wire::EventKind::CapabilityRelinquish);
        assert!(intent.authorization_ref().is_none());
        assert_eq!(intent.actor_id(), &bob());
    }
}
