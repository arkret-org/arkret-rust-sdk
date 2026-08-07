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
    CapabilitySubject, GrantConstraintSubkind,
};
use arkret_wire::{AppletId, GrantId, Hash, SchemaId};

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
    pub(crate) issuer: Did,
    pub(crate) subject: CapabilitySubject,
    pub(crate) actions: Vec<String>,
    pub(crate) capability_action_registry_digest: Option<Hash>,
    pub(crate) resources: Vec<ResourceSelector>,
    pub(crate) constraints: Vec<ConstraintEntry>,
    pub(crate) issuer_authority_grant_refs: Vec<String>,
    pub(crate) has_realm_root_authority_ref: bool,
    pub(crate) not_before: Option<DateTime<Utc>>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) revoked_by: Option<Did>,
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
            subject: grant.subject.clone(),
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
    pub(crate) fn subject_did(&self) -> Option<&Did> {
        match &self.subject {
            CapabilitySubject::Did(did) => Some(did),
            CapabilitySubject::Selector(_) => None,
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
            if &grant.issuer != parent_subject {
                return Err(Error::Protocol(format!(
                    "capability grant '{}' issuer does not match parent subject",
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
    let content = event
        .content
        .as_object()
        .ok_or_else(|| Error::Protocol("capability content must be an object".to_owned()))?;
    // Canonical event payload shape per event-payload.schema.json
    // `$defs/capability_grant_payload`: `{grant_id, grant: <artifact>}` —
    // only the branch embedding the full `capability-grant.schema.json`
    // artifact is evaluable; the summary branch (grant_id/subject/actions/
    // resources without `grant`) lacks issuer/proofs/constraints and MUST
    // NOT mint authority, so it fails closed here.
    let artifact = content.get("grant").ok_or_else(|| {
        Error::Protocol(
            "capability event payload does not embed the grant artifact \
             ('grant'); summary payloads cannot be evaluated"
                .to_owned(),
        )
    })?;
    // capability-grant.schema.json: "Implementations MUST reject grants
    // carrying a top-level 'delegable' field as schema_violation."
    if artifact.get("delegable").is_some() {
        return Err(Error::Protocol(
            "schema_violation: top-level 'delegable' is removed; \
             express re-granting via an authority_control constraint"
                .to_owned(),
        ));
    }
    let mut grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
        serde_json::from_value(artifact.clone()).map_err(|err| {
            Error::Protocol(format!(
                "schema_violation: invalid capability grant content: {err}"
            ))
        })?;
    if content.get("grant_id").and_then(Value::as_str) != Some(grant.id.as_str()) {
        return Err(Error::Protocol(format!(
            "schema_violation: capability event payload grant_id does not match \
             embedded grant id '{}'",
            grant.id
        )));
    }
    if grant.realm_id.is_none() {
        grant.realm_id = default_realm_id;
    }
    Ok(grant)
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
    constraint: &impl Serialize,
) -> Result<Vec<ConstraintEntry>> {
    let value = serde_json::to_value(constraint)?;
    let object = value
        .as_object()
        .ok_or_else(|| Error::Protocol("grant constraint must be an object".to_owned()))?;
    let str_field = |name: &str| -> Option<String> {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    let bool_field =
        |name: &str| -> bool { object.get(name).and_then(Value::as_bool).unwrap_or(false) };
    let u64_field = |name: &str| -> Option<u64> { object.get(name).and_then(Value::as_u64) };
    let constraint_kind = str_field("constraint_kind")
        .ok_or_else(|| Error::Protocol("grant constraint requires constraint_kind".to_owned()))?;
    let constraint_subkind = str_field("constraint_subkind");
    let constraint_id = str_field("constraint_id");
    let declared_evaluation_class = str_field("evaluation_class")
        .map(|value| parse_evaluation_class(&value))
        .transpose()?;
    let reject_unsupported_fields = |fields: &[&str]| -> Result<()> {
        for field in fields {
            if object.contains_key(*field) {
                return Err(Error::Protocol(format!(
                    "unsupported {constraint_kind} constraint field '{field}' \
                     (cannot be enforced by this evaluator; failing closed)"
                )));
            }
        }
        Ok(())
    };

    let mut constraints: Vec<Constraint> = Vec::new();
    match constraint_kind.as_str() {
        "temporal" => match constraint_subkind.as_deref() {
            None | Some("window") => {
                constraints.push(Constraint::Temporal {
                    not_before: datetime_field(object, "not_before")?,
                    expires_at: datetime_field(object, "expires_at")?,
                    recurrence: object
                        .get("recurrence")
                        .map(|value| {
                            serde_json::from_value::<Recurrence>(value.clone()).map_err(|err| {
                                Error::Protocol(format!("invalid recurrence: {err}"))
                            })
                        })
                        .transpose()?,
                });
            }
            Some("edit_window") | Some("redact_window") => {
                constraints.push(Constraint::EditWindow {
                    applies_to_actions: string_list(object, "applies_to_actions"),
                    message_edit_window: duration_field(object, "message_edit_window")?,
                    message_redact_window: duration_field(object, "message_redact_window")?,
                    redact_after_window_allowed: bool_field("redact_after_window_allowed"),
                });
            }
            Some(other) => {
                return Err(Error::Protocol(format!(
                    "unsupported temporal constraint constraint_subkind '{other}'"
                )));
            }
        },
        "field_access" => {
            // Named conditions (constraint-schema.md §4.1) are not evaluated
            // by this engine; per the spec they MUST fail closed.
            reject_unsupported_fields(&["condition", "sensitive_fields", "sensitive_handling"])?;
            let effect = constraint_effect(str_field("effect").as_deref());
            let denied_effect = match effect {
                ConstraintEffect::Allow => ConstraintEffect::Deny,
                other => other,
            };
            let allowed_write = string_list(object, "allowed_write_fields");
            if !allowed_write.is_empty() {
                constraints.push(Constraint::FieldAccess {
                    effect: ConstraintEffect::Allow,
                    scope: FieldScope::Write,
                    fields: allowed_write,
                });
            }
            let denied_write = string_list(object, "denied_write_fields");
            if !denied_write.is_empty() {
                constraints.push(Constraint::FieldAccess {
                    effect: denied_effect.clone(),
                    scope: FieldScope::Write,
                    fields: denied_write,
                });
            }
            let allowed_read = string_list(object, "allowed_read_fields");
            if !allowed_read.is_empty() {
                constraints.push(Constraint::FieldAccess {
                    effect: ConstraintEffect::Allow,
                    scope: FieldScope::Read,
                    fields: allowed_read,
                });
            }
            let denied_read = string_list(object, "denied_read_fields");
            if !denied_read.is_empty() {
                constraints.push(Constraint::FieldAccess {
                    effect: denied_effect,
                    scope: FieldScope::Read,
                    fields: denied_read,
                });
            }
        }
        "kind_restriction" => {
            reject_unsupported_fields(&["allowed_space_kinds", "denied_space_kinds"])?;
            constraints.push(Constraint::KindRestriction {
                allowed_object_kinds: optional_string_list(object, "allowed_object_kinds"),
                denied_object_kinds: optional_string_list(object, "denied_object_kinds"),
                allowed_morph_kinds: optional_string_list(object, "allowed_morph_kinds"),
                denied_morph_kinds: optional_string_list(object, "denied_morph_kinds"),
                allowed_facets: facet_list(object, "allowed_facets")?,
                denied_facets: facet_list(object, "denied_facets")?,
                scope_limitation: None,
            });
        }
        "scope_limitation" => {
            reject_unsupported_fields(&[
                "allowed_space_ids",
                "denied_space_ids",
                "allowed_data_labels",
                "allowed_endpoints",
                "blob_presign_scope",
            ])?;
            if let Some(circle_ids) = object.get("allowed_circle_ids") {
                let allowed_circle_ids: std::collections::BTreeSet<arkret_wire::CircleId> =
                    serde_json::from_value(circle_ids.clone()).map_err(|err| {
                        Error::Protocol(format!("invalid allowed_circle_ids: {err}"))
                    })?;
                constraints.push(Constraint::AllowedCircleIds { allowed_circle_ids });
            }
            if let Some(session_ids) = object.get("allowed_session_ids") {
                let allowed_session_ids: std::collections::BTreeSet<String> =
                    serde_json::from_value(session_ids.clone()).map_err(|err| {
                        Error::Protocol(format!("invalid allowed_session_ids: {err}"))
                    })?;
                constraints.push(Constraint::AllowedSessionIds {
                    allowed_session_ids,
                });
            }
            let allowed_relation_kinds = string_list(object, "allowed_relation_kinds");
            let allowed_view_ids = string_list(object, "allowed_view_ids");
            let allowed_from = string_list(object, "allowed_from_container_refs");
            let allowed_to = string_list(object, "allowed_to_container_refs");
            let has_container_move = !allowed_relation_kinds.is_empty()
                || !allowed_view_ids.is_empty()
                || !allowed_from.is_empty()
                || !allowed_to.is_empty()
                || object.contains_key("wip_limit_override");
            if has_container_move {
                constraints.push(Constraint::ContainerMove {
                    allowed_relation_kinds,
                    allowed_view_ids,
                    allowed_from_container_refs: allowed_from,
                    allowed_to_container_refs: allowed_to,
                    wip_limit_override: bool_field("wip_limit_override"),
                });
            }
            let scope = Constraint::ScopeLimitation {
                allowed_strand_ids: string_list(object, "allowed_strand_ids"),
                denied_strand_ids: string_list(object, "denied_strand_ids"),
                allowed_tracks: string_list(object, "allowed_tracks"),
                denied_tracks: string_list(object, "denied_tracks"),
                allowed_view_kinds: string_list(object, "allowed_view_kinds"),
                allowed_view_renderers: string_list(object, "allowed_view_renderers"),
                denied_view_kinds: string_list(object, "denied_view_kinds"),
                denied_view_renderers: string_list(object, "denied_view_renderers"),
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
        "authority_control" => match constraint_subkind.as_deref() {
            None => {
                reject_unsupported_fields(&["applet_id", "executed_by", "registration_epoch"])?;
                constraints.push(Constraint::AuthorityControl {
                    max_authority_depth: u64_field("max_authority_depth")
                        .map(|depth| u32::try_from(depth).unwrap_or(u32::MAX)),
                    authority_regrant_allowed: bool_field("authority_regrant_allowed"),
                    constraint_subkind: None,
                    applet_id: None,
                    executed_by: None,
                    registration_epoch: None,
                });
            }
            Some("applet_authority") => {
                let applet_id = AppletId::new(str_field("applet_id").ok_or_else(|| {
                    Error::Protocol(
                        "authority_control.applet_authority requires applet_id".to_owned(),
                    )
                })?)
                .map_err(Error::from)?;
                let executed_by = Did::new(str_field("executed_by").ok_or_else(|| {
                    Error::Protocol(
                        "authority_control.applet_authority requires executed_by".to_owned(),
                    )
                })?)
                .map_err(Error::from)?;
                let registration_epoch =
                    Hash::new(str_field("registration_epoch").ok_or_else(|| {
                        Error::Protocol(
                            "authority_control.applet_authority requires registration_epoch"
                                .to_owned(),
                        )
                    })?)
                    .map_err(Error::from)?;
                constraints.push(Constraint::AuthorityControl {
                    max_authority_depth: u64_field("max_authority_depth")
                        .map(|depth| u32::try_from(depth).unwrap_or(u32::MAX)),
                    authority_regrant_allowed: bool_field("authority_regrant_allowed"),
                    constraint_subkind: Some(GrantConstraintSubkind::AppletAuthority),
                    applet_id: Some(applet_id),
                    executed_by: Some(executed_by),
                    registration_epoch: Some(registration_epoch),
                });
            }
            Some(other) => {
                return Err(Error::Protocol(format!(
                    "unsupported authority_control constraint_subkind '{other}'"
                )));
            }
        },
        "quota" => match constraint_subkind.as_deref() {
            Some("rate") => {
                constraints.push(Constraint::RateLimiting {
                    max_operations: u64_field("max_operations").ok_or_else(|| {
                        Error::Protocol("quota.rate constraint requires max_operations".to_owned())
                    })?,
                    period: duration_field(object, "period")?.ok_or_else(|| {
                        Error::Protocol("quota.rate constraint requires period".to_owned())
                    })?,
                    scope: rate_limit_scope(
                        str_field("constraint_scope").as_deref(),
                        "quota.rate",
                        true,
                    )?,
                });
            }
            Some("resource") => {
                reject_unsupported_fields(&["max_artifact_bytes"])?;
                let requires_scope = u64_field("max_total_blob_bytes").is_some()
                    || u64_field("max_resources").is_some();
                constraints.push(Constraint::ResourceLimit {
                    blob_max_bytes: u64_field("blob_max_bytes"),
                    max_total_blob_bytes: u64_field("max_total_blob_bytes"),
                    max_resources: u64_field("max_resources"),
                    resource_kind: str_field("resource_kind"),
                    period: duration_field(object, "period")?,
                    scope: rate_limit_scope(
                        str_field("constraint_scope").as_deref(),
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
        "claim_based" => match constraint_subkind.as_deref() {
            Some("claim") => {
                let mut trusted_issuers = did_list(object, "trusted_claim_issuers")?;
                let mut required_claims = Vec::new();
                for item in object
                    .get("required_claims")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let item_object = item.as_object().ok_or_else(|| {
                        Error::Protocol("required_claims entries must be objects".to_owned())
                    })?;
                    if item_object
                        .get("value_constraints")
                        .and_then(Value::as_object)
                        .is_some_and(|map| !map.is_empty())
                    {
                        return Err(Error::Protocol(
                            "unsupported required_claims field 'value_constraints' \
                             (cannot be enforced by this evaluator; failing closed)"
                                .to_owned(),
                        ));
                    }
                    let claim_kind = item_object
                        .get("claim_kind")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            Error::Protocol("required_claims entry needs claim_kind".to_owned())
                        })?
                        .to_owned();
                    let issuer = item_object
                        .get("issuer")
                        .and_then(Value::as_str)
                        .map(Did::new)
                        .transpose()?;
                    if let Some(issuer) = &issuer
                        && !trusted_issuers.contains(issuer)
                    {
                        trusted_issuers.push(issuer.clone());
                    }
                    for trusted in item_object
                        .get("trusted_issuers")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                    {
                        let trusted = Did::new(trusted)?;
                        if !trusted_issuers.contains(&trusted) {
                            trusted_issuers.push(trusted);
                        }
                    }
                    required_claims.push(ClaimRequirement {
                        claim_kind,
                        issuer,
                        organization: item_object
                            .get("organization")
                            .and_then(Value::as_str)
                            .map(Did::new)
                            .transpose()?,
                        status: item_object
                            .get("status")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        roles: item_object
                            .get("roles")
                            .and_then(Value::as_array)
                            .map(|roles| {
                                roles
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(ToOwned::to_owned)
                                    .collect()
                            }),
                    });
                }
                constraints.push(Constraint::ClaimBased {
                    required_claims,
                    trusted_issuers,
                    claim_refresh_required: bool_field("claim_refresh_required"),
                    claim_max_age: duration_field(object, "claim_max_age")?,
                });
            }
            Some("approval") => {
                constraints.push(Constraint::ApprovalWorkflow {
                    approval_required: bool_field("approval_required"),
                    approval_actor_ids: if object.contains_key("approval_actor_ids") {
                        Some(did_list(object, "approval_actor_ids")?)
                    } else {
                        None
                    },
                    timeout: duration_field(object, "timeout")?,
                    // The spec approval_mode enum (before_commit /
                    // proposal_then_approve / after_commit_review) describes
                    // timing, not quorum; the engine quorum mode is supplied
                    // by the caller via ApprovalStrandManager.
                    approval_mode: None,
                    approval_relation: str_field("approval_relation"),
                    guardian_approval_required: bool_field("guardian_approval_required"),
                    controller_approval_required: bool_field("controller_approval_required"),
                });
            }
            Some("accountability") => {
                constraints.push(Constraint::Accountability {
                    accountability_required: bool_field("accountability_required"),
                    responsible_actor: None,
                });
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unsupported claim_based constraint constraint_subkind {other:?}"
                )));
            }
        },
        "confidentiality" => match constraint_subkind.as_deref() {
            Some("encryption") => {
                constraints.push(Constraint::EncryptionRequirement {
                    encryption_required: bool_field("encryption_required"),
                    min_encryption_level: None,
                });
            }
            Some("visibility") => {
                constraints.push(Constraint::VisibilityControl {
                    allowed_history_visibility_values: string_list(
                        object,
                        "allowed_history_visibility_values",
                    ),
                    denied_history_visibility_values: Vec::new(),
                    redacted_history_allowed: bool_field("redacted_history_allowed"),
                });
            }
            other => {
                return Err(Error::Protocol(format!(
                    "confidentiality constraint requires constraint_subkind 'encryption' or \
                     'visibility', got {other:?}"
                )));
            }
        },
        other => {
            return Err(Error::Protocol(format!(
                "unknown grant constraint type: {other}"
            )));
        }
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
        &constraint_kind,
        constraint_subkind.as_deref(),
        declared_evaluation_class,
        &entries,
    )?;

    Ok(entries)
}

fn parse_evaluation_class(value: &str) -> Result<crate::EvaluationClass> {
    match value {
        "stateless" => Ok(crate::EvaluationClass::Stateless),
        "grant_local" => Ok(crate::EvaluationClass::GrantLocal),
        "realm_state" => Ok(crate::EvaluationClass::RealmState),
        "external" => Ok(crate::EvaluationClass::External),
        other => Err(Error::Protocol(format!(
            "unknown evaluation_class '{other}'"
        ))),
    }
}

fn validate_declared_evaluation_class(
    constraint_kind: &str,
    constraint_subkind: Option<&str>,
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
            constraint_kind,
            constraint_subkind
                .map(|constraint_subkind| format!(".{constraint_subkind}"))
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

fn constraint_effect(value: Option<&str>) -> ConstraintEffect {
    match value {
        Some("deny") => ConstraintEffect::Deny,
        Some("quarantine") => ConstraintEffect::Quarantine,
        Some("require_review") => ConstraintEffect::RequireReview,
        _ => ConstraintEffect::Allow,
    }
}

fn rate_limit_scope(
    value: Option<&str>,
    constraint: &str,
    required: bool,
) -> Result<GrantRateLimitScope> {
    match value {
        Some("per_actor") => Ok(GrantRateLimitScope::PerActor),
        Some("per_space") => Ok(GrantRateLimitScope::PerSpace),
        Some("per_realm") => Ok(GrantRateLimitScope::PerRealm),
        Some("global") => Ok(GrantRateLimitScope::Global),
        Some(other) => Err(Error::Protocol(format!(
            "{constraint} constraint has unknown constraint_scope '{other}'"
        ))),
        None if required => Err(Error::Protocol(format!(
            "{constraint} constraint requires constraint_scope"
        ))),
        None => Ok(GrantRateLimitScope::Global),
    }
}

fn datetime_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>> {
    object
        .get(field)
        .map(|value| serde_json::from_value(value.clone()).map_err(Error::from))
        .transpose()
}

fn string_list(object: &serde_json::Map<String, Value>, field: &str) -> Vec<String> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn optional_string_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Option<Vec<String>> {
    object.get(field).and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn did_list(object: &serde_json::Map<String, Value>, field: &str) -> Result<Vec<Did>> {
    object
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|did| Did::new(did).map_err(Error::from))
        .collect()
}

fn facet_list(object: &serde_json::Map<String, Value>, field: &str) -> Result<Vec<Facet>> {
    object
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|value| {
            serde_json::from_value::<Facet>(value.clone())
                .map_err(|err| Error::Protocol(format!("invalid facet in {field}: {err}")))
        })
        .collect()
}

fn duration_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<ConstraintDuration>> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(parse_iso8601_duration)
        .transpose()
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
    actor_id: Did,
    grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
}

impl CapabilityGrantBuilder {
    /// Construct a new builder bound to the issuing Realm + actor.
    /// `grant.issuer` MUST equal `actor_id`; the builder enforces this
    /// at `build` time.
    pub fn new(
        scope_ref: arkret_wire::ScopeRef,
        actor_id: Did,
        grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    ) -> Self {
        Self {
            scope_ref,
            actor_id,
            grant,
        }
    }

    /// Override the grant subject.
    pub fn with_subject(mut self, subject: Did) -> Self {
        self.grant.subject = CapabilitySubject::Did(subject);
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
            constraint.constraint_kind
                != arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::AuthorityControl
                || constraint.constraint_subkind.is_some()
        });
        self.grant
            .constraints
            .push(arkret_models_collaboration::governance::grant_constraint::GrantConstraint::authority_control(
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
    pub fn with_constraints(
        mut self,
        constraints: Vec<
            arkret_models_collaboration::governance::grant_constraint::GrantConstraint,
        >,
    ) -> Self {
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
    pub fn build(self, actor_seq: u64, hlc: crate::Hlc) -> Result<crate::Event> {
        if self.grant.issuer != self.actor_id {
            return Err(Error::Protocol(format!(
                "CapabilityGrantBuilder: grant.issuer '{}' does not match actor_id '{}'",
                self.grant.issuer, self.actor_id
            )));
        }
        // Reject anything the spec schema would reject before it reaches the
        // wire (schema_violation semantics).
        GrantProjection::from_wire(&self.grant)?;
        // Canonical event payload shape per event-payload.schema.json
        // `$defs/capability_grant_payload`: the cell subject `grant_id` plus
        // the embedded `capability-grant.schema.json` artifact.
        let content = serde_json::json!({
            "grant_id": self.grant.id,
            "grant": serde_json::to_value(&self.grant)?,
        });
        crate::Event::new(
            arkret_wire::EventKind::CAPABILITY_GRANT,
            self.scope_ref,
            self.actor_id,
            actor_seq,
            hlc,
            content,
        )
    }
}

/// Build an unsigned subject-only `ak.capability.relinquish` Event. This path
/// intentionally carries no `authorization_ref`: the reducer authorizes it by
/// matching the Event signer to the target grant subject.
pub fn build_capability_relinquish_event(
    scope_ref: arkret_wire::ScopeRef,
    subject: Did,
    actor_seq: u64,
    hlc: crate::Hlc,
    payload: arkret_models_collaboration::events_payloads::CapabilityRelinquishPayload,
) -> Result<crate::Event> {
    crate::Event::new(
        arkret_wire::EventKind::CAPABILITY_RELINQUISH,
        scope_ref,
        subject,
        actor_seq,
        hlc,
        serde_json::to_value(payload)?,
    )
}

#[cfg(test)]
mod capability_grant_builder_tests {
    use serde_json::json;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
    }

    fn scope() -> arkret_wire::ScopeRef {
        arkret_wire::ScopeRef::Realm { realm_id: realm() }
    }

    fn alice() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn bob() -> Did {
        Did::new("did:webvh:z6mkfixture:bob.example").unwrap()
    }

    fn hlc() -> crate::Hlc {
        crate::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
    }

    fn base_grant() -> arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
        arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::new("ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu").unwrap(),
            schema: SchemaId::CAPABILITY_V1.to_owned(),
            realm_id: None,
            issuer: alice(),
            subject: CapabilitySubject::Did(bob()),
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
        let event = CapabilityGrantBuilder::new(scope(), alice(), base_grant())
            .build(1, hlc())
            .unwrap();
        assert_eq!(event.kind, arkret_wire::EventKind::CAPABILITY_GRANT);
        // Canonical capability_grant_payload wrapper: {grant_id, grant}.
        assert_eq!(
            event.payload["grant_id"],
            "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu"
        );
        let artifact = &event.payload["grant"];
        assert_eq!(
            artifact["id"],
            "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu"
        );
        assert_eq!(artifact["schema"], SchemaId::CAPABILITY_V1);
        assert_eq!(artifact["issuer"], "did:webvh:z6mkfixture:alice.example");
        assert_eq!(artifact["subject"], "did:webvh:z6mkfixture:bob.example");
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
        let event_view = arkret_models_collaboration::ResolvedStateEvent {
            kind: event.kind.to_string(),
            subject: "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu".to_owned(),
            source_event_id: arkret_wire::EventId::new(
                "ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim",
            )
            .unwrap(),
            actor_id: alice(),
            actor_seq: 1,
            hlc: Some(hlc()),
            content: Value::Object(event.payload.clone().into_iter().collect()),
        };
        let grant = capability_grant_from_resolved_event(&event_view, None).unwrap();
        assert_eq!(
            grant.id.as_str(),
            "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu"
        );
    }

    #[test]
    fn capability_grant_builder_rejects_issuer_actor_mismatch() {
        let err = CapabilityGrantBuilder::new(scope(), bob(), base_grant())
            .build(1, hlc())
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
            .build(1, hlc())
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
        grant.schema = "ak.schema.capability.v0".to_owned();
        let err = CapabilityGrantBuilder::new(scope(), alice(), grant)
            .build(1, hlc())
            .expect_err("wrong schema constant must be rejected");
        assert!(format!("{err}").contains("schema_violation"));
    }

    #[test]
    fn aggregate_admin_grant_requires_registry_digest() {
        let mut grant = base_grant();
        grant.actions = vec!["ak.realm.admin".to_owned()];
        let err = CapabilityGrantBuilder::new(scope(), alice(), grant)
            .build(1, hlc())
            .expect_err("aggregate admin without registry basis must fail closed");
        assert!(format!("{err}").contains("capability_registry_basis_unavailable"));
    }

    #[test]
    fn aggregate_admin_grant_binds_current_registry_in_wire_body() {
        let digest = current_capability_action_registry_digest().unwrap();
        let mut grant = base_grant();
        grant.actions = vec!["ak.realm.admin".to_owned()];
        let event = CapabilityGrantBuilder::new(scope(), alice(), grant)
            .with_capability_action_registry_digest(digest.clone())
            .build(1, hlc())
            .unwrap();
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
            .build(1, hlc())
            .expect_err("unknown registry basis must fail closed");
        assert!(format!("{err}").contains("capability_registry_basis_unavailable"));
    }

    #[test]
    fn capability_grant_builder_encodes_authority_control_constraint() {
        let event = CapabilityGrantBuilder::new(scope(), alice(), base_grant())
            .with_authority_control(2, true)
            .build(1, hlc())
            .unwrap();
        let constraints = event.payload["grant"]["constraints"].as_array().unwrap();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0]["constraint_kind"], "authority_control");
        assert_eq!(constraints[0]["max_authority_depth"], 2);
    }

    #[test]
    fn authority_depth_builder_preserves_applet_authority_subkind() {
        let mut grant = base_grant();
        grant.constraints.push(
            arkret_models_collaboration::governance::grant_constraint::GrantConstraint::applet_authority(
                AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
                Did::new("did:web:calendar.example").unwrap(),
                Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
        );
        let event = CapabilityGrantBuilder::new(scope(), alice(), grant)
            .with_authority_control(2, true)
            .build(1, hlc())
            .unwrap();
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
            constraints: vec![arkret_models_collaboration::governance::grant_constraint::GrantConstraint::authority_control(1, true)],
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
            subject: CapabilitySubject::Did(
                Did::new("did:webvh:z6mkfixture:carol.example").unwrap(),
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
            subject: CapabilitySubject::Did(
                Did::new("did:webvh:z6mkfixture:carol.example").unwrap(),
            ),
            ..base_grant()
        };
        let err = validate_capability_frontier(&[parent, child]).unwrap_err();
        assert!(format!("{err}").contains("not delegable"));
    }

    #[test]
    fn capability_chain_verifier_accepts_multi_parent_union_and_derives_depth() {
        let parent_create = arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::new("ak:grant:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934").unwrap(),
            actions: vec!["ak.message.create".to_owned()],
            constraints: vec![arkret_models_collaboration::governance::grant_constraint::GrantConstraint::authority_control(1, true)],
            ..base_grant()
        };
        let parent_update = arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
            id: GrantId::new("ak:grant:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu").unwrap(),
            actions: vec!["ak.message.revise".to_owned()],
            constraints: vec![arkret_models_collaboration::governance::grant_constraint::GrantConstraint::authority_control(1, true)],
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
            subject: CapabilitySubject::Did(
                Did::new("did:webvh:z6mkfixture:carol.example").unwrap(),
            ),
            actions: vec!["ak.message.create".to_owned(), "ak.message.revise".to_owned()],
            constraints: vec![arkret_models_collaboration::governance::grant_constraint::GrantConstraint::authority_control(0, false)],
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
        let content = json!({
            "grant_id": "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu",
            "grant": artifact,
        });
        let event = arkret_models_collaboration::ResolvedStateEvent {
            kind: "ak.capability.grant".to_owned(),
            subject: "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu".to_owned(),
            source_event_id: arkret_wire::EventId::new(
                "ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim",
            )
            .unwrap(),
            actor_id: alice(),
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
            "executed_by": "did:web:calendar.example",
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
                "executed_by": "did:web:calendar.example",
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
        let event = build_capability_relinquish_event(scope(), bob(), 7, hlc(), payload).unwrap();
        assert_eq!(
            event.kind.as_str(),
            arkret_wire::EventKind::CAPABILITY_RELINQUISH
        );
        assert!(event.authorization_ref.is_none());
        assert_eq!(event.actor_id, bob());
    }
}
