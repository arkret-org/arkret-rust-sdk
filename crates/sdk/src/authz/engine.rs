use super::*;

/// Authorization context for evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzContext {
    /// Current timestamp for evaluation
    pub now: DateTime<Utc>,
    /// Actor making the request
    pub actor_id: Did,
    /// Realm context.
    pub realm_id: Option<RealmId>,
    /// Operation being performed
    pub action: String,
    /// Resource being accessed
    pub resource: Resource,
    /// Facets attached to the target object at the current causal frontier.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<Facet>,
    /// Fields being read
    #[serde(default)]
    pub read_fields: Vec<String>,
    /// Fields being written
    #[serde(default)]
    pub write_fields: Vec<String>,
    /// Current delegation depth of the grant being evaluated. Root grants are depth 0.
    #[serde(default)]
    pub delegation_depth: u32,
    /// Operation count already observed in the current rate-limit window.
    #[serde(default)]
    pub rate_limit_count: Option<u64>,
    /// Verified claims available for claim-based constraints.
    #[serde(default)]
    pub verified_claims: Vec<VerifiedClaim>,
    /// Claim IDs that are revoked at the current causal frontier.
    #[serde(default)]
    pub revoked_claim_ids: Vec<String>,
    /// Whether the operation has an accountable audit/log record.
    #[serde(default)]
    pub accountability_logged: bool,
    /// Encryption level of the target operation/payload, if already verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_level: Option<String>,
    /// Effective `history_visibility` of the target Space at the current
    /// causal frontier (`world_readable` / `shared` / `invited` / `joined` /
    /// `restricted`). Used by `Constraint::VisibilityControl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<String>,
    /// Byte count of the blob being uploaded (single-call), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_byte_count: Option<u64>,
    /// Cumulative blob bytes already used in the scope (for
    /// `ResourceLimit.max_total_blob_bytes`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_blob_total_bytes: Option<u64>,
    /// Cumulative resource count in the scope (for
    /// `ResourceLimit.max_resources`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_resource_count: Option<u64>,
    /// Creation time of the target object (for `EditWindow`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_created_at: Option<DateTime<Utc>>,
    /// Active Strand track (`discussion` / `synthesis` / profile-defined)
    /// when the operation targets a Strand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_track: Option<String>,
    /// View kind when targeting a View resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_kind: Option<String>,
    /// View renderer when targeting a View resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_renderer: Option<String>,
    /// Container relation kind for `ContainerMove` evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation_kind: Option<String>,
    /// View ref for container move targeting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_id: Option<String>,
    /// `from` container reference for `ContainerMove`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_container_id: Option<String>,
    /// `to` container reference for `ContainerMove`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_container_id: Option<String>,
    /// Whether the destination container would exceed its WIP limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wip_over_limit: Option<bool>,
    /// AKP-0007 — Circle id when the operation targets a Circle-management
    /// capability (`ak.circle.manage`, `ak.circle.member.manage`,
    /// `ak.circle.member.add.others`, `ak.circle.audit`). Used by
    /// [`Constraint::AllowedCircleIds`] to membership-test against the
    /// grant's allow-list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<arkret_core::CircleId>,
    /// Agent interop session id for session-scoped status/result writes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_interop_session_id: Option<arkret_core::AgentInteropSessionId>,
    /// Accepted authorization frontier used to guard fast-path cache hits.
    ///
    /// When absent, this engine still evaluates grants but refuses to cache
    /// the result because the caller has not bound the decision to the current
    /// authorization state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_frontier: Option<AuthzCacheFrontier>,
}

/// Authorization-state fingerprint that guards capability fast-path cache use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthzCacheFrontier {
    /// Digest of the accepted authorization state used for this decision.
    pub auth_state_digest: String,
    /// Accepted authorization frontier event/control references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_frontier: Vec<String>,
    /// Optional policy frontier digest when policy cells affect this decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_frontier_digest: Option<String>,
    /// Optional membership frontier digest when membership affects this decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_frontier_digest: Option<String>,
}

impl AuthzContext {
    /// Create a new authorization context.
    pub fn new(actor_id: Did, action: String, resource: Resource) -> Self {
        Self {
            now: Utc::now(),
            actor_id,
            realm_id: None,
            action,
            resource,
            facets: Vec::new(),
            read_fields: Vec::new(),
            write_fields: Vec::new(),
            delegation_depth: 0,
            rate_limit_count: None,
            verified_claims: Vec::new(),
            revoked_claim_ids: Vec::new(),
            accountability_logged: false,
            encryption_level: None,
            history_visibility: None,
            blob_byte_count: None,
            scope_blob_total_bytes: None,
            scope_resource_count: None,
            target_created_at: None,
            strand_track: None,
            view_kind: None,
            view_renderer: None,
            relation_kind: None,
            view_id: None,
            from_container_id: None,
            to_container_id: None,
            wip_over_limit: None,
            circle_id: None,
            agent_interop_session_id: None,
            cache_frontier: None,
        }
    }

    /// Set the target Circle id for `AllowedCircleIds` constraint
    /// evaluation. Pass when the operation targets a Circle-management
    /// capability (`ak.circle.*`).
    pub fn with_circle_id(mut self, circle_id: arkret_core::CircleId) -> Self {
        self.circle_id = Some(circle_id);
        self
    }

    /// Set the target agent interop session id for `AllowedSessionIds`.
    pub fn with_agent_interop_session_id(
        mut self,
        session_id: arkret_core::AgentInteropSessionId,
    ) -> Self {
        self.agent_interop_session_id = Some(session_id);
        self
    }

    /// Bind fast-path cache use to the accepted authorization frontier.
    pub fn with_cache_frontier(mut self, frontier: AuthzCacheFrontier) -> Self {
        self.cache_frontier = Some(frontier);
        self
    }

    /// Set the Realm ID.
    pub fn with_realm_id(mut self, realm_id: RealmId) -> Self {
        self.realm_id = Some(realm_id);
        self
    }

    /// Set target object facets resolved at the current causal frontier.
    pub fn with_facets(mut self, facets: impl IntoIterator<Item = Facet>) -> Self {
        self.facets = facets.into_iter().collect();
        self
    }

    /// Set current delegation depth for delegation-control constraints.
    pub fn with_delegation_depth(mut self, depth: u32) -> Self {
        self.delegation_depth = depth;
        self
    }

    /// Set the observed operation count for rate-limit constraints.
    pub fn with_rate_limit_count(mut self, count: u64) -> Self {
        self.rate_limit_count = Some(count);
        self
    }

    /// Add a verified claim for claim-based constraints.
    pub fn with_verified_claim(mut self, claim: VerifiedClaim) -> Self {
        self.verified_claims.push(claim);
        self
    }

    /// Add a revoked claim ID for fail-closed claim validation.
    pub fn with_revoked_claim_id(mut self, claim_id: impl Into<String>) -> Self {
        self.revoked_claim_ids.push(claim_id.into());
        self
    }

    /// Mark that accountability logging has been completed.
    pub fn with_accountability_logged(mut self, logged: bool) -> Self {
        self.accountability_logged = logged;
        self
    }

    /// Set the verified encryption level for the target resource.
    pub fn with_encryption_level(mut self, level: impl Into<String>) -> Self {
        self.encryption_level = Some(level.into());
        self
    }
}

/// Policy-server response for `ak.self.policy.query.check`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyServerEffect {
    /// No policy restriction. This never grants access by itself.
    NoAction,
    Deny,
    Quarantine,
    RequireReview,
}

/// Internal request model for local policy evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyEvaluationRequest {
    pub operation: String,
    pub context: AuthzContext,
}

impl PolicyEvaluationRequest {
    pub fn new(context: AuthzContext) -> Self {
        Self {
            operation: "ak.self.policy.query.check".to_owned(),
            context,
        }
    }
}

/// Internal response model for local policy evaluation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEvaluationResult {
    pub operation: String,
    pub effect: PolicyServerEffect,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moderation_report_id: Option<String>,
}

impl PolicyEvaluationResult {
    pub fn no_action() -> Self {
        Self {
            operation: "ak.self.policy.query.check".to_owned(),
            effect: PolicyServerEffect::NoAction,
            reason: "no policy restriction".to_owned(),
            policy_id: None,
            moderation_report_id: None,
        }
    }
}

/// Client-local moderation report bound to a restrictive policy outcome.
///
/// Distinct from the wire `arkret_core::ModerationReport`
/// (moderation.md §3 report resource).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyModerationReport {
    pub report_id: String,
    pub policy_id: Option<String>,
    pub actor_id: Did,
    pub resource: Resource,
    pub effect: PolicyServerEffect,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

/// Authorization engine.
pub struct AuthzEngine {
    /// Cache of evaluated grants
    cache: HashMap<String, CachedDecision>,
    /// Maximum cache size
    max_cache_size: usize,
}

#[derive(Clone, Debug)]
struct CachedDecision {
    decision: EngineDecision,
    _cached_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

impl AuthzEngine {
    /// Create a new authorization engine.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            max_cache_size: 1000,
        }
    }

    /// Check authorization for a context against a list of spec wire-form
    /// grants ([`arkret_core::CapabilityGrant`]).
    ///
    /// Each grant is projected into the engine's internal typed form first;
    /// a grant that fails projection is rejected with `schema_violation`
    /// semantics (it contributes no authority, per
    /// `capability-grant.schema.json`).
    pub fn check_authorization(
        &mut self,
        ctx: &AuthzContext,
        grants: &[arkret_core::CapabilityGrant],
    ) -> EngineDecision {
        // Project the wire form; schema-violating grants are excluded.
        let mut projections = Vec::with_capacity(grants.len());
        let mut rejected = Vec::new();
        for grant in grants {
            match GrantProjection::from_wire(grant) {
                Ok(projection) => projections.push(projection),
                Err(err) => rejected.push(format!("grant '{}' rejected: {}", grant.id, err)),
            }
        }

        let cache_key = if rejected.is_empty()
            && ctx.cache_frontier.is_some()
            && projected_grants_fast_path_cacheable(&projections)
        {
            Some(self.cache_key(ctx, grants))
        } else {
            None
        };
        if let Some(cache_key) = cache_key.as_ref()
            && let Some(cached) = self.cache.get(cache_key)
            && cached
                .expires_at
                .as_ref()
                .is_none_or(|valid| &ctx.now < valid)
        {
            return cached.decision.clone();
        }

        // Evaluate grants
        let decision = self.evaluate_grants(ctx, &projections, &rejected);

        if let Some(cache_key) = cache_key {
            self.cache_decision(cache_key, &decision, ctx, &projections);
        }

        decision
    }

    /// Check authorization against grants reduced into a `RealmState` snapshot.
    pub fn check_authorization_from_realm_state(
        &mut self,
        ctx: &AuthzContext,
        state: &crate::RealmState,
    ) -> EngineDecision {
        match capability_grants_from_realm_state(state) {
            Ok(grants) => self.check_authorization(ctx, &grants),
            Err(err) => EngineDecision::Deny {
                reason: format!("invalid capability state: {}", err),
            },
        }
    }

    /// Combine local capability authorization with a policy-server response.
    ///
    /// Policy servers can only further restrict access. `NoAction` falls back to
    /// the local capability decision and cannot turn a deny into an allow.
    pub fn check_authorization_with_policy(
        &mut self,
        ctx: &AuthzContext,
        grants: &[arkret_core::CapabilityGrant],
        policy: &PolicyEvaluationResult,
    ) -> EngineDecision {
        apply_policy_response(self.check_authorization(ctx, grants), policy)
    }

    /// Check authorization, filtering out grants that require approval but have
    /// not been approved through the given `ApprovalStrandManager`.
    ///
    /// Grants with `ApprovalWorkflow { approval_required: true }` are only
    /// included if a matching approved proposal exists. Once approved, the
    /// approval constraint is stripped so that `evaluate_grants` does not
    /// return `RequireReview` for already-approved grants.
    pub fn check_authorization_with_approvals(
        &mut self,
        ctx: &AuthzContext,
        grants: &[arkret_core::CapabilityGrant],
        approvals: &ApprovalStrandManager,
    ) -> EngineDecision {
        let eligible_grants: Vec<arkret_core::CapabilityGrant> = grants
            .iter()
            .filter_map(|grant| {
                if grant_requires_approval(grant) {
                    if approvals.is_grant_approved(grant.id.as_str()) {
                        // Strip the approval constraint since it is already satisfied.
                        let mut approved = grant.clone();
                        approved
                            .constraints
                            .retain(|constraint| !is_approval_required_constraint(constraint));
                        Some(approved)
                    } else {
                        None
                    }
                } else {
                    Some(grant.clone())
                }
            })
            .collect();
        self.check_authorization(ctx, &eligible_grants)
    }

    /// Evaluate all projected grants and return the combined decision.
    /// `rejected` carries the schema_violation reasons of grants that failed
    /// wire → projection parsing, for diagnosis when nothing matches.
    fn evaluate_grants(
        &self,
        ctx: &AuthzContext,
        grants: &[GrantProjection],
        rejected: &[String],
    ) -> EngineDecision {
        let mut matching_grants = Vec::new();

        // Find grants that match the resource
        for grant in grants {
            if self.grant_matches_actor(ctx, grant)
                && self.grant_is_active(ctx, grant)
                && self.grant_matches_resource(ctx, grant)
            {
                matching_grants.push(grant);
            }
        }

        // If no matching grants, deny
        if matching_grants.is_empty() {
            let reason = if rejected.is_empty() {
                "no matching grant".to_owned()
            } else {
                format!("no matching grant ({})", rejected.join("; "))
            };
            return EngineDecision::Deny { reason };
        }

        // Check action match
        let action_grants: Vec<_> = matching_grants
            .into_iter()
            .filter(|g| g.actions.contains(&ctx.action) || g.actions.contains(&"*".to_owned()))
            .collect();

        if action_grants.is_empty() {
            return EngineDecision::Deny {
                reason: format!("action '{}' not granted", ctx.action),
            };
        }

        // Evaluate constraints for all matching grants
        for grant in &action_grants {
            match self.evaluate_constraints(ctx, grant) {
                EngineDecision::Deny { reason } => {
                    return EngineDecision::Deny {
                        reason: format!("grant '{}': {}", grant.id, reason),
                    };
                }
                EngineDecision::Quarantine { reason } => {
                    return EngineDecision::Quarantine {
                        reason: format!("grant '{}': {}", grant.id, reason),
                    };
                }
                EngineDecision::RequireReview { reason } => {
                    return EngineDecision::RequireReview {
                        reason: format!("grant '{}': {}", grant.id, reason),
                    };
                }
                EngineDecision::Allow => continue,
            }
        }

        // All checks passed
        EngineDecision::Allow
    }

    /// Check if a grant matches the resource.
    fn grant_matches_resource(&self, ctx: &AuthzContext, grant: &GrantProjection) -> bool {
        grant
            .resources
            .iter()
            .any(|selector| selector.matches(&ctx.resource))
    }

    /// Check if a grant applies to the requesting actor. Condition
    /// (selector) subjects are not evaluated by this engine and fail closed.
    fn grant_matches_actor(&self, ctx: &AuthzContext, grant: &GrantProjection) -> bool {
        grant
            .subject_did()
            .is_some_and(|subject| *subject == ctx.actor_id)
    }

    /// Check if a grant is currently usable.
    fn grant_is_active(&self, ctx: &AuthzContext, grant: &GrantProjection) -> bool {
        if grant.revoked_by.is_some() {
            return false;
        }
        if let Some(revoked_at) = grant.revoked_at
            && ctx.now >= revoked_at
        {
            return false;
        }
        if let Some(not_before) = grant.not_before
            && ctx.now < not_before
        {
            return false;
        }
        if let Some(expires_at) = grant.expires_at
            && ctx.now > expires_at
        {
            return false;
        }
        true
    }

    /// Evaluate all constraints for a grant.
    fn evaluate_constraints(&self, ctx: &AuthzContext, grant: &GrantProjection) -> EngineDecision {
        // Sort constraints by effect priority, then by entry priority within same effect.
        // deny (0) > quarantine (1) > require_review (2) > allow (3)
        // Higher priority number = evaluated first within the same effect group.
        let mut constraints = grant.constraints.clone();
        constraints.sort_by(|a, b| {
            let effect_a = match a.effect() {
                ConstraintEffect::Deny => 0i32,
                ConstraintEffect::Quarantine => 1,
                ConstraintEffect::RequireReview => 2,
                ConstraintEffect::Allow => 3,
            };
            let effect_b = match b.effect() {
                ConstraintEffect::Deny => 0i32,
                ConstraintEffect::Quarantine => 1,
                ConstraintEffect::RequireReview => 2,
                ConstraintEffect::Allow => 3,
            };
            effect_a
                .cmp(&effect_b)
                .then_with(|| b.priority.cmp(&a.priority))
        });

        for entry in &constraints {
            match self.evaluate_constraint(ctx, entry) {
                EngineDecision::Allow => continue,
                decision => return decision,
            }
        }

        EngineDecision::Allow
    }

    /// Evaluate a single constraint.
    fn evaluate_constraint(&self, ctx: &AuthzContext, entry: &ConstraintEntry) -> EngineDecision {
        match &entry.constraint {
            Constraint::Temporal {
                not_before,
                expires_at,
                recurrence,
            } => {
                if let Some(not_before) = not_before
                    && ctx.now < *not_before
                {
                    return EngineDecision::Deny {
                        reason: format!("before not_before: {}", not_before),
                    };
                }
                if let Some(expires_at) = expires_at
                    && ctx.now > *expires_at
                {
                    return EngineDecision::Deny {
                        reason: format!("after expires_at: {}", expires_at),
                    };
                }
                if let Some(recurrence) = recurrence
                    && let Err(err) = recurrence_allows(ctx.now, recurrence)
                {
                    // Render structured ConstraintParseError via Display so the
                    // public deny reason stays byte-equivalent with v0.
                    return EngineDecision::Deny {
                        reason: err.to_string(),
                    };
                }
                EngineDecision::Allow
            }
            Constraint::FieldAccess {
                effect,
                scope,
                fields,
            } => {
                let target_fields = match scope {
                    FieldScope::Read => &ctx.read_fields,
                    FieldScope::Write => &ctx.write_fields,
                };

                match effect {
                    ConstraintEffect::Allow => {
                        if let Some(field) =
                            target_fields.iter().find(|field| !fields.contains(*field))
                        {
                            return EngineDecision::Deny {
                                reason: format!("field access not allowed: {}", field),
                            };
                        }
                    }
                    ConstraintEffect::Deny => {
                        if let Some(field) =
                            target_fields.iter().find(|field| fields.contains(*field))
                        {
                            return EngineDecision::Deny {
                                reason: format!("field access denied: {}", field),
                            };
                        }
                    }
                    ConstraintEffect::Quarantine => {
                        if let Some(field) =
                            target_fields.iter().find(|field| fields.contains(*field))
                        {
                            return EngineDecision::Quarantine {
                                reason: format!("field access quarantined: {}", field),
                            };
                        }
                    }
                    ConstraintEffect::RequireReview => {
                        if let Some(field) =
                            target_fields.iter().find(|field| fields.contains(*field))
                        {
                            return EngineDecision::RequireReview {
                                reason: format!("field access requires review: {}", field),
                            };
                        }
                    }
                }
                EngineDecision::Allow
            }
            Constraint::TypeRestriction {
                allowed_object_types,
                denied_object_types,
                allowed_morph_types,
                denied_morph_types,
                allowed_facets,
                denied_facets,
                scope_limitation,
            } => {
                if let Some(scope_limitation) = scope_limitation {
                    let scope_matches = matches!(
                        (scope_limitation, &ctx.resource),
                        (ScopeLimitation::Space, Resource::Space { .. })
                            | (ScopeLimitation::Strand, Resource::Strand { .. })
                            | (ScopeLimitation::Morph, Resource::Morph { .. })
                            | (ScopeLimitation::Message, Resource::Message { .. })
                            | (ScopeLimitation::Relation, Resource::Relation { .. })
                            | (ScopeLimitation::View, Resource::View { .. })
                            | (ScopeLimitation::Policy, Resource::Policy { .. })
                            | (ScopeLimitation::Circle, Resource::Circle { .. })
                    );
                    if !scope_matches {
                        return EngineDecision::Deny {
                            reason: format!(
                                "resource does not match scope limitation: {:?}",
                                scope_limitation
                            ),
                        };
                    }
                }
                let (object_type, morph_type) = match &ctx.resource {
                    Resource::Strand { .. } => (Some("strand"), None),
                    Resource::Message { .. } => (Some("message"), None),
                    Resource::Morph { morph_type, .. } => {
                        (Some("morph"), Some(morph_type.as_str()))
                    }
                    Resource::Relation { .. } => (Some("relation"), None),
                    Resource::View { .. } => (Some("view"), None),
                    Resource::Space { .. } => (Some("space"), None),
                    Resource::Circle { .. } => (Some("circle"), None),
                    _ => (None, None),
                };

                if let Some(object_type) = object_type {
                    if let Some(deny_list) = denied_object_types
                        && deny_list.iter().any(|item| item == object_type)
                    {
                        return EngineDecision::Deny {
                            reason: format!("object type denied: {}", object_type),
                        };
                    }
                    if let Some(allow_list) = allowed_object_types
                        && !allow_list.iter().any(|item| item == object_type)
                    {
                        return EngineDecision::Deny {
                            reason: format!("object type not allowed: {}", object_type),
                        };
                    }
                }

                if let Some(morph_type) = morph_type {
                    if let Some(deny_list) = denied_morph_types
                        && deny_list.iter().any(|item| item == morph_type)
                    {
                        return EngineDecision::Deny {
                            reason: format!("morph type denied: {}", morph_type),
                        };
                    }
                    if let Some(allow_list) = allowed_morph_types
                        && !allow_list.iter().any(|item| item == morph_type)
                    {
                        return EngineDecision::Deny {
                            reason: format!("morph type not allowed: {}", morph_type),
                        };
                    }
                }

                if !denied_facets.is_empty()
                    && let Some(facet) = denied_facets
                        .iter()
                        .find(|facet| ctx.facets.contains(facet))
                {
                    return EngineDecision::Deny {
                        reason: format!("facet denied: {:?}", facet),
                    };
                }
                if !allowed_facets.is_empty() {
                    let missing = allowed_facets
                        .iter()
                        .find(|facet| !ctx.facets.contains(facet));
                    if let Some(facet) = missing {
                        return EngineDecision::Deny {
                            reason: format!("facet not allowed or unavailable: {:?}", facet),
                        };
                    }
                }
                EngineDecision::Allow
            }
            Constraint::DelegationControl {
                max_delegation_depth,
                prohibit_subdelegation,
            } => {
                if *prohibit_subdelegation && ctx.delegation_depth > 0 {
                    return EngineDecision::Deny {
                        reason: "subdelegation prohibited".to_owned(),
                    };
                }
                if let Some(max_depth) = max_delegation_depth
                    && ctx.delegation_depth > *max_depth
                {
                    return EngineDecision::Deny {
                        reason: format!(
                            "delegation depth {} exceeds max {}",
                            ctx.delegation_depth, max_depth
                        ),
                    };
                }
                EngineDecision::Allow
            }
            Constraint::RateLimiting {
                max_operations,
                period,
                scope,
            } => {
                if *max_operations == 0 {
                    return EngineDecision::Deny {
                        reason: "rate limit: max_operations is 0".to_owned(),
                    };
                }
                match ctx.rate_limit_count {
                    Some(count) if count >= *max_operations => EngineDecision::Deny {
                        reason: format!(
                            "rate limit exceeded: {}/{} operations in {}{} {:?} scope",
                            count, max_operations, period.value, period.unit, scope
                        ),
                    },
                    Some(_) => EngineDecision::Allow,
                    None => EngineDecision::RequireReview {
                        reason: "rate limit counter unavailable".to_owned(),
                    },
                }
            }
            Constraint::ApprovalWorkflow {
                approval_required,
                approval_actor_ids,
                timeout,
                approval_mode,
                approval_relation,
                guardian_approval_required,
                controller_approval_required,
            } => {
                if *approval_required {
                    let reason = if let Some(approvers) = approval_actor_ids {
                        format!(
                            "approval required from one of: {}",
                            approvers
                                .iter()
                                .map(|a| a.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    } else {
                        "approval required".to_owned()
                    };
                    let _ = (
                        timeout,
                        approval_mode,
                        approval_relation,
                        guardian_approval_required,
                        controller_approval_required,
                    );
                    EngineDecision::RequireReview { reason }
                } else {
                    EngineDecision::Allow
                }
            }
            Constraint::ClaimBased {
                requires_claims,
                trusted_issuers,
                claim_refresh_required,
                claim_max_age,
            } => {
                if requires_claims.is_empty() {
                    return EngineDecision::Allow;
                }
                if trusted_issuers.is_empty() {
                    return EngineDecision::RequireReview {
                        reason: format!(
                            "claims required ({}) but no trusted issuers specified",
                            requires_claims
                                .iter()
                                .map(|c| c.claim_kind.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    };
                }
                for requirement in requires_claims {
                    let satisfied = ctx.verified_claims.iter().any(|claim| {
                        let claim_id_active = claim
                            .claim_id
                            .as_ref()
                            .is_none_or(|claim_id| !ctx.revoked_claim_ids.contains(claim_id));
                        let freshness_basis = claim.refreshed_at.or(claim.issued_at);
                        claim.claim_kind == requirement.claim_kind
                            && claim.subject == ctx.actor_id
                            && trusted_issuers.contains(&claim.issuer)
                            && requirement
                                .issuer
                                .as_ref()
                                .is_none_or(|issuer| issuer == &claim.issuer)
                            && requirement
                                .organization
                                .as_ref()
                                .is_none_or(|org| claim.organization.as_ref() == Some(org))
                            && requirement
                                .status
                                .as_ref()
                                .is_none_or(|status| claim.status.as_ref() == Some(status))
                            && requirement.roles.as_ref().is_none_or(|roles| {
                                roles.iter().all(|role| claim.roles.contains(role))
                            })
                            && claim_id_active
                            && claim
                                .revoked_at
                                .is_none_or(|revoked_at| revoked_at > ctx.now)
                            && claim
                                .expires_at
                                .is_none_or(|expires_at| expires_at > ctx.now)
                            && (!*claim_refresh_required || claim.refreshed_at.is_some())
                            && claim_max_age.as_ref().is_none_or(|max_age| {
                                freshness_basis
                                    .is_some_and(|basis| max_age_contains(ctx.now - basis, max_age))
                            })
                    });
                    if !satisfied {
                        return EngineDecision::Deny {
                            reason: format!(
                                "required claim not satisfied: {}",
                                requirement.claim_kind
                            ),
                        };
                    }
                }
                EngineDecision::Allow
            }
            Constraint::Accountability {
                accountability_required,
                responsible_actor,
            } => {
                if *accountability_required {
                    if let Some(responsible) = responsible_actor
                        && ctx.actor_id != *responsible
                    {
                        return EngineDecision::RequireReview {
                            reason: format!(
                                "accountability: actor {} is not responsible actor {}",
                                ctx.actor_id, responsible
                            ),
                        };
                    }
                    if ctx.accountability_logged {
                        EngineDecision::Allow
                    } else {
                        EngineDecision::RequireReview {
                            reason: "accountability log missing".to_owned(),
                        }
                    }
                } else {
                    EngineDecision::Allow
                }
            }
            Constraint::EncryptionRequirement {
                encryption_required,
                min_encryption_level,
            } => {
                if *encryption_required {
                    let level = min_encryption_level.as_deref().unwrap_or("mls_rfc9420");
                    match ctx.encryption_level.as_deref() {
                        Some(actual) if actual == level || actual == "stronger" => {
                            EngineDecision::Allow
                        }
                        Some(actual) => EngineDecision::Deny {
                            reason: format!(
                                "encryption level '{}' does not satisfy '{}'",
                                actual, level
                            ),
                        },
                        None => EngineDecision::Deny {
                            reason: format!("encryption required: {}", level),
                        },
                    }
                } else {
                    EngineDecision::Allow
                }
            }
            Constraint::VisibilityControl {
                allowed_history_visibility_values,
                denied_history_visibility_values,
                ..
            } => {
                if let Some(level) = ctx.history_visibility.as_deref() {
                    if denied_history_visibility_values.iter().any(|v| v == level) {
                        return EngineDecision::Deny {
                            reason: format!("visibility level '{}' is denied", level),
                        };
                    }
                    if !allowed_history_visibility_values.is_empty()
                        && !allowed_history_visibility_values.iter().any(|v| v == level)
                    {
                        return EngineDecision::Deny {
                            reason: format!("visibility level '{}' not in allow list", level),
                        };
                    }
                }
                EngineDecision::Allow
            }
            Constraint::ResourceLimit {
                blob_max_bytes,
                max_total_blob_bytes,
                max_resources,
                ..
            } => {
                if let Some(max) = blob_max_bytes
                    && let Some(actual) = ctx.blob_byte_count
                    && actual > *max
                {
                    return EngineDecision::Deny {
                        reason: format!("blob size {} exceeds max {}", actual, max),
                    };
                }
                if let Some(max) = max_total_blob_bytes
                    && let Some(total) = ctx.scope_blob_total_bytes
                    && total > *max
                {
                    return EngineDecision::Deny {
                        reason: format!(
                            "scope blob total {} exceeds max_total_blob_bytes {}",
                            total, max
                        ),
                    };
                }
                if let Some(max) = max_resources
                    && let Some(count) = ctx.scope_resource_count
                    && count > *max
                {
                    return EngineDecision::Deny {
                        reason: format!("resource count {} exceeds max {}", count, max),
                    };
                }
                EngineDecision::Allow
            }
            Constraint::EditWindow {
                applies_to_actions,
                message_edit_window,
                message_redact_window,
                allow_redact_after_window,
            } => {
                let action_match = applies_to_actions.is_empty()
                    || applies_to_actions.iter().any(|a| a == &ctx.action);
                if !action_match {
                    return EngineDecision::Allow;
                }
                let Some(origin) = ctx.target_created_at else {
                    return EngineDecision::Allow;
                };
                let age = ctx.now - origin;
                // constraint-schema.md §14.2.
                //
                // Redact: `message_redact_window` is authoritative when
                // declared (and `allow_redact_after_window` no longer changes
                // the redact verdict). When no redact window is declared,
                // redact shares the edit window unless
                // `allow_redact_after_window` lifts that coupling — omitting a
                // redact window then means unbounded recall.
                //
                // Revise: governed solely by `message_edit_window`. Omitting it
                // means unbounded edits.
                if ctx.action.contains("redact") {
                    if let Some(window) = message_redact_window.as_ref() {
                        if max_age_contains(age, window) {
                            return EngineDecision::Allow;
                        }
                        return EngineDecision::Deny {
                            reason: format!(
                                "redact window {}{} elapsed",
                                window.value, window.unit
                            ),
                        };
                    }
                    // No explicit redact window: redact is coupled to the edit
                    // window unless the grant opts out via
                    // `allow_redact_after_window`.
                    if *allow_redact_after_window {
                        return EngineDecision::Allow;
                    }
                    if let Some(window) = message_edit_window.as_ref()
                        && !max_age_contains(age, window)
                    {
                        return EngineDecision::Deny {
                            reason: format!(
                                "redact shares edit window {}{}, which elapsed",
                                window.value, window.unit
                            ),
                        };
                    }
                    return EngineDecision::Allow;
                }
                if let Some(window) = message_edit_window.as_ref()
                    && !max_age_contains(age, window)
                {
                    return EngineDecision::Deny {
                        reason: format!("edit window {}{} elapsed", window.value, window.unit),
                    };
                }
                EngineDecision::Allow
            }
            Constraint::ContainerMove {
                allowed_relation_kinds,
                allowed_view_ids,
                allowed_from_container_refs,
                allowed_to_container_refs,
                wip_limit_override,
            } => {
                if !allowed_relation_kinds.is_empty()
                    && let Some(rk) = ctx.relation_kind.as_deref()
                    && !allowed_relation_kinds.iter().any(|k| k == rk)
                {
                    return EngineDecision::Deny {
                        reason: format!("relation_kind '{}' not in allow list", rk),
                    };
                }
                if !allowed_view_ids.is_empty()
                    && let Some(view_id) = ctx.view_id.as_deref()
                    && !allowed_view_ids.iter().any(|v| v == view_id)
                {
                    return EngineDecision::Deny {
                        reason: format!("view '{}' not allowed for container move", view_id),
                    };
                }
                if !allowed_from_container_refs.is_empty()
                    && let Some(from_id) = ctx.from_container_id.as_deref()
                    && !allowed_from_container_refs.iter().any(|v| v == from_id)
                {
                    return EngineDecision::Deny {
                        reason: format!("from container '{}' not allowed", from_id),
                    };
                }
                if !allowed_to_container_refs.is_empty()
                    && let Some(to_id) = ctx.to_container_id.as_deref()
                    && !allowed_to_container_refs.iter().any(|v| v == to_id)
                {
                    return EngineDecision::Deny {
                        reason: format!("to container '{}' not allowed", to_id),
                    };
                }
                if !*wip_limit_override
                    && let Some(over) = ctx.wip_over_limit
                    && over
                {
                    return EngineDecision::Deny {
                        reason: "WIP limit exceeded and override not granted".to_owned(),
                    };
                }
                EngineDecision::Allow
            }
            Constraint::ScopeLimitation {
                allowed_strand_ids,
                denied_strand_ids,
                allowed_tracks,
                denied_tracks,
                allowed_view_kinds,
                allowed_view_renderers,
                denied_view_kinds,
                denied_view_renderers,
            } => {
                if let Resource::Strand { strand_id, .. } = &ctx.resource {
                    if denied_strand_ids.iter().any(|v| v == strand_id) {
                        return EngineDecision::Deny {
                            reason: format!("strand '{}' is denied", strand_id),
                        };
                    }
                    if !allowed_strand_ids.is_empty()
                        && !allowed_strand_ids.iter().any(|v| v == strand_id)
                    {
                        return EngineDecision::Deny {
                            reason: format!("strand '{}' not in allow list", strand_id),
                        };
                    }
                }
                if let Some(track) = ctx.strand_track.as_deref() {
                    if denied_tracks.iter().any(|b| b == track) {
                        return EngineDecision::Deny {
                            reason: format!("track '{}' is denied", track),
                        };
                    }
                    if !allowed_tracks.is_empty() && !allowed_tracks.iter().any(|b| b == track) {
                        return EngineDecision::Deny {
                            reason: format!("track '{}' not in allow list", track),
                        };
                    }
                }
                if let Resource::View { .. } = &ctx.resource {
                    if let Some(kind) = ctx.view_kind.as_deref() {
                        if denied_view_kinds.iter().any(|k| k == kind) {
                            return EngineDecision::Deny {
                                reason: format!("view kind '{}' is denied", kind),
                            };
                        }
                        if !allowed_view_kinds.is_empty()
                            && !allowed_view_kinds.iter().any(|k| k == kind)
                        {
                            return EngineDecision::Deny {
                                reason: format!("view kind '{}' not in allow list", kind),
                            };
                        }
                    }
                    if let Some(renderer) = ctx.view_renderer.as_deref() {
                        if denied_view_renderers.iter().any(|r| r == renderer) {
                            return EngineDecision::Deny {
                                reason: format!("view renderer '{}' is denied", renderer),
                            };
                        }
                        if !allowed_view_renderers.is_empty()
                            && !allowed_view_renderers.iter().any(|r| r == renderer)
                        {
                            return EngineDecision::Deny {
                                reason: format!("view renderer '{}' not in allow list", renderer),
                            };
                        }
                    }
                }
                EngineDecision::Allow
            }
            // AKP-0007: gate Circle-management actions on a static
            // allow-list of Circle ids baked into the grant body. The
            // caller MUST set `ctx.circle_id` to the operation's target
            // Circle for Circle-scoped actions (`ak.circle.manage`,
            // `ak.circle.member.manage`, `ak.circle.member.add.others`,
            // `ak.circle.audit`). Non-Circle-scoped operations leave
            // `circle_id` unset; per the constraint's narrow scope it
            // does not apply and silently passes.
            Constraint::AllowedCircleIds { allowed_circle_ids } => {
                if allowed_circle_ids.is_empty() {
                    return EngineDecision::Deny {
                        reason: "allowed_circle_ids constraint requires a \
                                non-empty allow list"
                            .to_owned(),
                    };
                }
                match &ctx.circle_id {
                    Some(circle_id) => {
                        if allowed_circle_ids.contains(circle_id) {
                            EngineDecision::Allow
                        } else {
                            EngineDecision::Deny {
                                reason: format!(
                                    "circle '{}' not in allowed_circle_ids allow list",
                                    circle_id.as_ref()
                                ),
                            }
                        }
                    }
                    // Constraint is Circle-scoped — non-Circle-targeted
                    // operations are out of scope; pass through.
                    None => EngineDecision::Allow,
                }
            }
            Constraint::AllowedSessionIds {
                allowed_session_ids,
            } => {
                if allowed_session_ids.is_empty() {
                    return EngineDecision::Deny {
                        reason: "allowed_session_ids constraint requires a non-empty allow list"
                            .to_owned(),
                    };
                }
                match &ctx.agent_interop_session_id {
                    Some(session_id) => {
                        if allowed_session_ids.contains(session_id) {
                            EngineDecision::Allow
                        } else {
                            EngineDecision::Deny {
                                reason: format!(
                                    "agent interop session '{}' not in allowed_session_ids allow list",
                                    session_id.as_ref()
                                ),
                            }
                        }
                    }
                    None => EngineDecision::Allow,
                }
            }
        }
    }

    /// Generate a cache key for the context.
    fn cache_key(&self, ctx: &AuthzContext, grants: &[arkret_core::CapabilityGrant]) -> String {
        let grants_digest = crate::canonical::canonical_sha256(&grants)
            .unwrap_or_else(|_| format!("grant-count:{}", grants.len()));
        let claims_digest =
            crate::canonical::canonical_sha256(&(&ctx.verified_claims, &ctx.revoked_claim_ids))
                .unwrap_or_else(|_| format!("claim-count:{}", ctx.verified_claims.len()));
        let resource_digest = crate::canonical::canonical_sha256(&ctx.resource)
            .unwrap_or_else(|_| ctx.resource.realm_id().to_owned());
        let facets_digest = crate::canonical::canonical_sha256(&ctx.facets)
            .unwrap_or_else(|_| format!("facet-count:{}", ctx.facets.len()));
        let frontier_digest = crate::canonical::canonical_sha256(&ctx.cache_frontier)
            .unwrap_or_else(|_| "missing-authz-cache-frontier".to_owned());
        let field_digest =
            crate::canonical::canonical_sha256(&(&ctx.read_fields, &ctx.write_fields))
                .unwrap_or_else(|_| {
                    format!(
                        "fields:{}:{}",
                        ctx.read_fields.len(),
                        ctx.write_fields.len()
                    )
                });
        let request_digest = crate::canonical::canonical_sha256(&(
            &ctx.realm_id,
            &ctx.history_visibility,
            &ctx.blob_byte_count,
            &ctx.scope_blob_total_bytes,
            &ctx.scope_resource_count,
            &ctx.target_created_at,
            &ctx.strand_track,
            &ctx.view_kind,
            &ctx.view_renderer,
            &ctx.relation_kind,
            &ctx.view_id,
            &ctx.from_container_id,
            &ctx.to_container_id,
            &ctx.wip_over_limit,
            &ctx.circle_id,
            &ctx.agent_interop_session_id,
        ))
        .unwrap_or_else(|_| "request-context".to_owned());
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{:?}:{:?}:{}:{}:{}",
            ctx.actor_id,
            ctx.action,
            resource_digest,
            facets_digest,
            frontier_digest,
            field_digest,
            request_digest,
            ctx.delegation_depth,
            ctx.rate_limit_count,
            ctx.encryption_level,
            claims_digest,
            ctx.accountability_logged,
            grants_digest
        )
    }

    /// Cache a decision.
    fn cache_decision(
        &mut self,
        key: String,
        decision: &EngineDecision,
        ctx: &AuthzContext,
        grants: &[GrantProjection],
    ) {
        // Evict old entries if cache is full
        if self.cache.len() >= self.max_cache_size {
            self.cache.clear();
        }

        let expires_at = self.cache_expires_at(ctx, grants);
        self.cache.insert(
            key,
            CachedDecision {
                decision: decision.clone(),
                _cached_at: ctx.now,
                expires_at,
            },
        );
    }

    fn cache_expires_at(
        &self,
        ctx: &AuthzContext,
        grants: &[GrantProjection],
    ) -> Option<DateTime<Utc>> {
        let mut cache_expires_at = None;

        for grant in grants {
            update_earliest_future(&mut cache_expires_at, ctx.now, grant.not_before);
            update_earliest_future(&mut cache_expires_at, ctx.now, grant.expires_at);
            update_earliest_future(&mut cache_expires_at, ctx.now, grant.revoked_at);

            for entry in &grant.constraints {
                match &entry.constraint {
                    Constraint::Temporal {
                        not_before,
                        expires_at,
                        recurrence,
                    } => {
                        update_earliest_future(&mut cache_expires_at, ctx.now, *not_before);
                        update_earliest_future(&mut cache_expires_at, ctx.now, *expires_at);
                        if let Some(recurrence) = recurrence
                            && let Ok(next) = recurrence_next_transition_after(ctx.now, recurrence)
                        {
                            update_earliest_future(&mut cache_expires_at, ctx.now, next);
                        }
                    }
                    Constraint::EditWindow {
                        applies_to_actions,
                        message_edit_window,
                        message_redact_window,
                        allow_redact_after_window,
                    } => {
                        let action_match = applies_to_actions.is_empty()
                            || applies_to_actions
                                .iter()
                                .any(|action| action == &ctx.action);
                        let Some(origin) = ctx.target_created_at else {
                            continue;
                        };
                        if !action_match {
                            continue;
                        }
                        if ctx.action.contains("redact") {
                            if let Some(window) = message_redact_window.as_ref() {
                                update_earliest_future(
                                    &mut cache_expires_at,
                                    ctx.now,
                                    Self::constraint_duration_after(origin, window),
                                );
                            } else if !allow_redact_after_window
                                && let Some(window) = message_edit_window.as_ref()
                            {
                                update_earliest_future(
                                    &mut cache_expires_at,
                                    ctx.now,
                                    Self::constraint_duration_after(origin, window),
                                );
                            }
                        } else if let Some(window) = message_edit_window.as_ref() {
                            update_earliest_future(
                                &mut cache_expires_at,
                                ctx.now,
                                Self::constraint_duration_after(origin, window),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        cache_expires_at
    }

    fn constraint_duration_after(
        origin: DateTime<Utc>,
        duration: &ConstraintDuration,
    ) -> Option<DateTime<Utc>> {
        let delta = match duration.unit.as_str() {
            "s" => chrono::Duration::seconds(duration.value as i64),
            "m" => chrono::Duration::minutes(duration.value as i64),
            "h" => chrono::Duration::hours(duration.value as i64),
            "d" => chrono::Duration::days(duration.value as i64),
            _ => return None,
        };
        origin.checked_add_signed(delta)
    }

    /// Clear the cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Default for AuthzEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn projected_grants_fast_path_cacheable(grants: &[GrantProjection]) -> bool {
    grants.iter().all(|grant| {
        grant
            .constraints
            .iter()
            .all(ConstraintEntry::is_fast_path_cacheable)
    })
}

pub fn apply_policy_response(
    capability_decision: EngineDecision,
    policy: &PolicyEvaluationResult,
) -> EngineDecision {
    match policy.effect {
        PolicyServerEffect::NoAction => capability_decision,
        PolicyServerEffect::Deny => EngineDecision::Deny {
            reason: policy.reason.clone(),
        },
        PolicyServerEffect::Quarantine => EngineDecision::Quarantine {
            reason: policy.reason.clone(),
        },
        PolicyServerEffect::RequireReview => EngineDecision::RequireReview {
            reason: policy.reason.clone(),
        },
    }
}

/// Check if a grant requires approval through the proposal strand.
///
/// Operates on the spec wire form: an approval requirement is a constraint
/// with `constraint_type = "claim_based"`, `subtype = "approval"` and
/// `approval_required = true` (grant-constraint.schema.json).
pub fn grant_requires_approval(grant: &arkret_core::CapabilityGrant) -> bool {
    grant
        .constraints
        .iter()
        .any(is_approval_required_constraint)
}

/// Spec-shape predicate for an `approval_required = true` constraint object.
fn is_approval_required_constraint(constraint: &arkret_core::GrantConstraint) -> bool {
    constraint.constraint_type == arkret_core::GrantConstraintType::ClaimBased
        && constraint.subtype == Some(arkret_core::GrantConstraintSubtype::Approval)
        && constraint.approval_required.unwrap_or(false)
}

pub fn moderation_report_for_policy_outcome(
    ctx: &AuthzContext,
    policy: &PolicyEvaluationResult,
    now: DateTime<Utc>,
) -> Option<PolicyModerationReport> {
    if policy.effect == PolicyServerEffect::NoAction {
        return None;
    }
    Some(PolicyModerationReport {
        report_id: policy
            .moderation_report_id
            .clone()
            .unwrap_or_else(|| format!("ak:moderation:{}", now.timestamp_millis())),
        policy_id: policy.policy_id.clone(),
        actor_id: ctx.actor_id.clone(),
        resource: ctx.resource.clone(),
        effect: policy.effect.clone(),
        reason: policy.reason.clone(),
        created_at: now,
    })
}

#[cfg(test)]
mod engine_wire_tests {
    use arkret_core::{CAPABILITY_SCHEMA, CapabilitySubject, GrantId};
    use serde_json::json;

    use super::*;

    fn alice() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn bob() -> Did {
        Did::new("did:webvh:z6mkfixture:bob.example").unwrap()
    }

    fn proof(issuer: &Did) -> arkret_core::Proof {
        arkret_core::Proof {
            kind: arkret_core::proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: format!("{issuer}#device-1"),
            event_digest: arkret_core::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: "eyJhbGciOiJFZERTQSJ9..signature".to_owned(),
        }
    }

    fn constraint(value: Value) -> arkret_core::GrantConstraint {
        serde_json::from_value(value).expect("valid grant constraint")
    }

    fn wire_grant(constraints: Vec<arkret_core::GrantConstraint>) -> arkret_core::CapabilityGrant {
        arkret_core::CapabilityGrant {
            id: GrantId::new("ak:grant:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap(),
            schema: CAPABILITY_SCHEMA.to_owned(),
            realm_id: None,
            issuer: alice(),
            subject: CapabilitySubject::Did(bob()),
            actions: vec!["ak.message.create".to_owned()],
            resources: vec![json!({"kind": "*"})],
            constraints,
            parent_grant_id: None,
            issued_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            not_before: None,
            expires_at: None,
            effective_after_first_authorized_key: None,
            updated_by: None,
            updated_at: None,
            revoked_by: None,
            revoked_at: None,
            proofs: vec![proof(&alice())],
        }
    }

    fn ctx() -> AuthzContext {
        AuthzContext::new(
            bob(),
            "ak.message.create".to_owned(),
            Resource::Realm {
                realm_id: "ak:realm:01904100-0000-7000-8000-65c7feb295d7".to_owned(),
            },
        )
        .with_cache_frontier(AuthzCacheFrontier {
            auth_state_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            auth_frontier: vec!["ak:event:01964137-0000-7000-8000-000000000001".to_owned()],
            policy_frontier_digest: None,
            membership_frontier_digest: None,
        })
    }

    #[test]
    fn wire_grant_with_matching_action_allows() {
        let mut engine = AuthzEngine::new();
        let decision = engine.check_authorization(&ctx(), &[wire_grant(Vec::new())]);
        assert_eq!(decision, EngineDecision::Allow);
        assert_eq!(engine.cache.len(), 1);
    }

    #[test]
    fn fast_path_cache_requires_authz_frontier() {
        let mut engine = AuthzEngine::new();
        let mut ctx = ctx();
        ctx.cache_frontier = None;
        let decision = engine.check_authorization(&ctx, &[wire_grant(Vec::new())]);
        assert_eq!(decision, EngineDecision::Allow);
        assert!(
            engine.cache.is_empty(),
            "capability decisions without auth_state_digest/auth_frontier must not be cached"
        );
    }

    #[test]
    fn fast_path_cache_is_bound_to_authz_frontier() {
        let mut engine = AuthzEngine::new();
        let grant = wire_grant(Vec::new());
        let first = ctx();
        let first_decision = engine.check_authorization(&first, std::slice::from_ref(&grant));
        assert_eq!(first_decision, EngineDecision::Allow);
        assert_eq!(engine.cache.len(), 1);

        let mut second = ctx();
        second.cache_frontier = Some(AuthzCacheFrontier {
            auth_state_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            auth_frontier: vec!["ak:event:01964137-0000-7000-8000-000000000002".to_owned()],
            policy_frontier_digest: None,
            membership_frontier_digest: None,
        });
        let second_decision = engine.check_authorization(&second, &[grant]);
        assert_eq!(second_decision, EngineDecision::Allow);
        assert_eq!(
            engine.cache.len(),
            2,
            "auth_state_digest/auth_frontier changes must produce a distinct cache entry"
        );
    }

    #[test]
    fn spec_temporal_constraint_denies_after_expiry() {
        let mut engine = AuthzEngine::new();
        let grant = wire_grant(vec![constraint(json!({
            "constraint_type": "temporal",
            "effect": "allow",
            "expires_at": "2026-01-01T00:00:00Z",
        }))]);
        let mut ctx = ctx();
        ctx.now = "2026-02-01T00:00:00Z".parse().unwrap();
        let decision = engine.check_authorization(&ctx, std::slice::from_ref(&grant));
        assert!(
            matches!(decision, EngineDecision::Deny { reason } if reason.contains("expires_at"))
        );
    }

    #[test]
    fn schema_violating_grant_contributes_no_authority() {
        let mut engine = AuthzEngine::new();
        let mut grant = wire_grant(Vec::new());
        grant.schema = "ak.schema.capability.v0".to_owned();
        let decision = engine.check_authorization(&ctx(), &[grant]);
        assert!(matches!(
            decision,
            EngineDecision::Deny { reason } if reason.contains("schema_violation")
        ));
    }

    #[test]
    fn unknown_constraint_family_fails_closed_at_decode() {
        let mut artifact = serde_json::to_value(wire_grant(Vec::new())).unwrap();
        artifact["constraints"] = json!([{
            "constraint_type": "telepathy",
            "effect": "allow",
        }]);
        assert!(serde_json::from_value::<arkret_core::CapabilityGrant>(artifact).is_err());
    }

    #[test]
    fn external_constraints_are_not_fast_path_cached() {
        let mut engine = AuthzEngine::new();
        let grant = wire_grant(vec![constraint(json!({
            "constraint_type": "quota",
            "subtype": "rate",
            "effect": "allow",
            "evaluation_class": "external",
            "max_operations": 10,
            "period": "PT1H",
            "constraint_scope": "global",
        }))]);
        let mut ctx = ctx();
        ctx.rate_limit_count = Some(0);
        let decision = engine.check_authorization(&ctx, &[grant]);
        assert_eq!(decision, EngineDecision::Allow);
        assert!(
            engine.cache.is_empty(),
            "external evaluation_class must bypass the fast-path cache"
        );
    }

    #[test]
    fn realm_state_constraints_are_not_fast_path_cached() {
        let mut engine = AuthzEngine::new();
        let grant = wire_grant(vec![constraint(json!({
            "constraint_type": "confidentiality",
            "subtype": "visibility",
            "effect": "allow",
            "evaluation_class": "realm_state",
            "allowed_history_visibility_values": ["joined"],
        }))]);
        let mut ctx = ctx();
        ctx.history_visibility = Some("joined".to_owned());
        let decision = engine.check_authorization(&ctx, &[grant]);
        assert_eq!(decision, EngineDecision::Allow);
        assert!(
            engine.cache.is_empty(),
            "realm_state evaluation_class must bypass the fast-path cache"
        );
    }

    #[test]
    fn evaluation_class_mismatch_rejects_without_fast_path_cache() {
        let mut engine = AuthzEngine::new();
        let grant = wire_grant(vec![constraint(json!({
            "constraint_type": "quota",
            "subtype": "rate",
            "effect": "allow",
            "evaluation_class": "stateless",
            "max_operations": 10,
            "period": "PT1H",
            "constraint_scope": "global",
        }))]);
        let decision = engine.check_authorization(&ctx(), &[grant]);
        assert!(matches!(
            decision,
            EngineDecision::Deny { reason }
                if reason.contains("schema_violation")
                    && reason.contains("evaluation_class mismatch")
        ));
        assert!(
            engine.cache.is_empty(),
            "evaluation_class mismatch must fail closed outside the fast-path cache"
        );
    }

    #[test]
    fn approval_required_grant_is_held_until_approved() {
        let mut engine = AuthzEngine::new();
        let grant = wire_grant(vec![constraint(json!({
            "constraint_type": "claim_based",
            "subtype": "approval",
            "effect": "require_review",
            "approval_required": true,
            "approval_actor_ids": ["did:webvh:z6mkfixture:carol.example"],
        }))]);
        assert!(grant_requires_approval(&grant));

        let mut approvals = ApprovalStrandManager::new();
        let decision = engine.check_authorization_with_approvals(
            &ctx(),
            std::slice::from_ref(&grant),
            &approvals,
        );
        assert!(matches!(decision, EngineDecision::Deny { .. }));

        let proposal = approvals.submit_proposal(
            grant.clone(),
            alice(),
            vec![Did::new("did:webvh:z6mkfixture:carol.example").unwrap()],
            ApprovalMode::Any,
            None,
        );
        approvals
            .record_approval(
                &proposal.proposal_id,
                Did::new("did:webvh:z6mkfixture:carol.example").unwrap(),
                true,
                None,
            )
            .unwrap();
        engine.clear_cache();
        let decision = engine.check_authorization_with_approvals(&ctx(), &[grant], &approvals);
        assert_eq!(decision, EngineDecision::Allow);
    }
}
