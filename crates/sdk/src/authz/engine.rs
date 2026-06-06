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
    /// Active Flow track (`discussion` / `synthesis` / profile-defined)
    /// when the operation targets a Flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_track: Option<String>,
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
    /// CKP-0007 — Circle id when the operation targets a Circle-management
    /// capability (`ck.circle.manage`, `ck.circle.member.manage`,
    /// `ck.circle.member.add.others`, `ck.circle.audit`). Used by
    /// [`Constraint::AllowedCircleIds`] to membership-test against the
    /// grant's allow-list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<cokret_core::CircleId>,
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
            flow_track: None,
            view_kind: None,
            view_renderer: None,
            relation_kind: None,
            view_id: None,
            from_container_id: None,
            to_container_id: None,
            wip_over_limit: None,
            circle_id: None,
        }
    }

    /// Set the target Circle id for `AllowedCircleIds` constraint
    /// evaluation. Pass when the operation targets a Circle-management
    /// capability (`ck.circle.*`).
    pub fn with_circle_id(mut self, circle_id: cokret_core::CircleId) -> Self {
        self.circle_id = Some(circle_id);
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

/// Policy-server response for `ck.self.policy.check`.
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
        Self { operation: "ck.self.policy.check".to_owned(), context }
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
            operation: "ck.self.policy.check".to_owned(),
            effect: PolicyServerEffect::NoAction,
            reason: "no policy restriction".to_owned(),
            policy_id: None,
            moderation_report_id: None,
        }
    }
}

/// Moderation report bound to a restrictive policy outcome.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModerationReport {
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
    decision: AuthzDecision,
    _cached_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

impl AuthzEngine {
    /// Create a new authorization engine.
    pub fn new() -> Self {
        Self { cache: HashMap::new(), max_cache_size: 1000 }
    }

    /// Check authorization for a context against a list of grants.
    pub fn check_authorization(
        &mut self,
        ctx: &AuthzContext,
        grants: &[CapabilityGrant],
    ) -> AuthzDecision {
        // Check cache first
        let cache_key = self.cache_key(ctx, grants);
        if let Some(cached) = self.cache.get(&cache_key)
            && cached.expires_at.as_ref().is_none_or(|valid| &ctx.now < valid)
        {
            return cached.decision.clone();
        }

        // Evaluate grants
        let decision = self.evaluate_grants(ctx, grants);

        // Cache the result
        self.cache_decision(cache_key, &decision, ctx, grants);

        decision
    }

    /// Check authorization against grants reduced into a `RealmState` snapshot.
    pub fn check_authorization_from_realm_state(
        &mut self,
        ctx: &AuthzContext,
        state: &crate::RealmState,
    ) -> AuthzDecision {
        match capability_grants_from_realm_state(state) {
            Ok(grants) => self.check_authorization(ctx, &grants),
            Err(err) => {
                AuthzDecision::Deny { reason: format!("invalid capability state: {}", err) }
            }
        }
    }

    /// Combine local capability authorization with a policy-server response.
    ///
    /// Policy servers can only further restrict access. `NoAction` falls back to
    /// the local capability decision and cannot turn a deny into an allow.
    pub fn check_authorization_with_policy(
        &mut self,
        ctx: &AuthzContext,
        grants: &[CapabilityGrant],
        policy: &PolicyEvaluationResult,
    ) -> AuthzDecision {
        apply_policy_response(self.check_authorization(ctx, grants), policy)
    }

    /// Check authorization, filtering out grants that require approval but have
    /// not been approved through the given `ApprovalFlowManager`.
    ///
    /// Grants with `ApprovalWorkflow { approval_required: true }` are only
    /// included if a matching approved proposal exists. Once approved, the
    /// approval constraint is stripped so that `evaluate_grants` does not
    /// return `RequireReview` for already-approved grants.
    pub fn check_authorization_with_approvals(
        &mut self,
        ctx: &AuthzContext,
        grants: &[CapabilityGrant],
        approvals: &ApprovalFlowManager,
    ) -> AuthzDecision {
        let eligible_grants: Vec<CapabilityGrant> = grants
            .iter()
            .filter_map(|grant| {
                if grant_requires_approval(grant) {
                    if approvals.is_grant_approved(&grant.id) {
                        // Strip the approval constraint since it is already satisfied.
                        let mut approved = grant.clone();
                        approved.constraints.retain(|entry| {
                            !matches!(
                                &entry.constraint,
                                Constraint::ApprovalWorkflow { approval_required: true, .. }
                            )
                        });
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

    /// Evaluate all grants and return the combined decision.
    fn evaluate_grants(&self, ctx: &AuthzContext, grants: &[CapabilityGrant]) -> AuthzDecision {
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
            return AuthzDecision::Deny { reason: "no matching grant".to_owned() };
        }

        // Check action match
        let action_grants: Vec<_> = matching_grants
            .into_iter()
            .filter(|g| g.actions.contains(&ctx.action) || g.actions.contains(&"*".to_owned()))
            .collect();

        if action_grants.is_empty() {
            return AuthzDecision::Deny { reason: format!("action '{}' not granted", ctx.action) };
        }

        // Evaluate constraints for all matching grants
        for grant in &action_grants {
            match self.evaluate_constraints(ctx, grant) {
                AuthzDecision::Deny { reason } => {
                    return AuthzDecision::Deny {
                        reason: format!("grant '{}': {}", grant.id, reason),
                    };
                }
                AuthzDecision::Quarantine { reason } => {
                    return AuthzDecision::Quarantine {
                        reason: format!("grant '{}': {}", grant.id, reason),
                    };
                }
                AuthzDecision::RequireReview { reason } => {
                    return AuthzDecision::RequireReview {
                        reason: format!("grant '{}': {}", grant.id, reason),
                    };
                }
                AuthzDecision::Allow => continue,
            }
        }

        // All checks passed
        AuthzDecision::Allow
    }

    /// Check if a grant matches the resource.
    fn grant_matches_resource(&self, ctx: &AuthzContext, grant: &CapabilityGrant) -> bool {
        grant.resources.iter().any(|selector| selector.matches(&ctx.resource))
    }

    /// Check if a grant applies to the requesting actor.
    fn grant_matches_actor(&self, ctx: &AuthzContext, grant: &CapabilityGrant) -> bool {
        grant.subject == ctx.actor_id
    }

    /// Check if a grant is currently usable.
    fn grant_is_active(&self, ctx: &AuthzContext, grant: &CapabilityGrant) -> bool {
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
    fn evaluate_constraints(&self, ctx: &AuthzContext, grant: &CapabilityGrant) -> AuthzDecision {
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
            effect_a.cmp(&effect_b).then_with(|| b.priority.cmp(&a.priority))
        });

        for entry in &constraints {
            match self.evaluate_constraint(ctx, entry) {
                AuthzDecision::Allow => continue,
                decision => return decision,
            }
        }

        AuthzDecision::Allow
    }

    /// Evaluate a single constraint.
    fn evaluate_constraint(&self, ctx: &AuthzContext, entry: &ConstraintEntry) -> AuthzDecision {
        match &entry.constraint {
            Constraint::Temporal { not_before, expires_at, recurrence } => {
                if let Some(not_before) = not_before
                    && ctx.now < *not_before
                {
                    return AuthzDecision::Deny {
                        reason: format!("before not_before: {}", not_before),
                    };
                }
                if let Some(expires_at) = expires_at
                    && ctx.now > *expires_at
                {
                    return AuthzDecision::Deny {
                        reason: format!("after expires_at: {}", expires_at),
                    };
                }
                if let Some(recurrence) = recurrence
                    && let Err(err) = recurrence_allows(ctx.now, recurrence)
                {
                    // Render structured ConstraintParseError via Display so the
                    // public deny reason stays byte-equivalent with v0.
                    return AuthzDecision::Deny { reason: err.to_string() };
                }
                AuthzDecision::Allow
            }
            Constraint::FieldAccess { effect, scope, fields } => {
                let target_fields = match scope {
                    FieldScope::Read => &ctx.read_fields,
                    FieldScope::Write => &ctx.write_fields,
                };

                match effect {
                    ConstraintEffect::Allow => {
                        if let Some(field) =
                            target_fields.iter().find(|field| !fields.contains(*field))
                        {
                            return AuthzDecision::Deny {
                                reason: format!("field access not allowed: {}", field),
                            };
                        }
                    }
                    ConstraintEffect::Deny => {
                        if let Some(field) =
                            target_fields.iter().find(|field| fields.contains(*field))
                        {
                            return AuthzDecision::Deny {
                                reason: format!("field access denied: {}", field),
                            };
                        }
                    }
                    ConstraintEffect::Quarantine => {
                        if let Some(field) =
                            target_fields.iter().find(|field| fields.contains(*field))
                        {
                            return AuthzDecision::Quarantine {
                                reason: format!("field access quarantined: {}", field),
                            };
                        }
                    }
                    ConstraintEffect::RequireReview => {
                        if let Some(field) =
                            target_fields.iter().find(|field| fields.contains(*field))
                        {
                            return AuthzDecision::RequireReview {
                                reason: format!("field access requires review: {}", field),
                            };
                        }
                    }
                }
                AuthzDecision::Allow
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
                            | (ScopeLimitation::Flow, Resource::Flow { .. })
                            | (ScopeLimitation::Morph, Resource::Morph { .. })
                            | (ScopeLimitation::Message, Resource::Message { .. })
                            | (ScopeLimitation::Relation, Resource::Relation { .. })
                            | (ScopeLimitation::View, Resource::View { .. })
                            | (ScopeLimitation::Policy, Resource::Policy { .. })
                            | (ScopeLimitation::Circle, Resource::Circle { .. })
                    );
                    if !scope_matches {
                        return AuthzDecision::Deny {
                            reason: format!(
                                "resource does not match scope limitation: {:?}",
                                scope_limitation
                            ),
                        };
                    }
                }
                let (object_type, morph_type) = match &ctx.resource {
                    Resource::Flow { .. } => (Some("flow"), None),
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
                        return AuthzDecision::Deny {
                            reason: format!("object type denied: {}", object_type),
                        };
                    }
                    if let Some(allow_list) = allowed_object_types
                        && !allow_list.iter().any(|item| item == object_type)
                    {
                        return AuthzDecision::Deny {
                            reason: format!("object type not allowed: {}", object_type),
                        };
                    }
                }

                if let Some(morph_type) = morph_type {
                    if let Some(deny_list) = denied_morph_types
                        && deny_list.iter().any(|item| item == morph_type)
                    {
                        return AuthzDecision::Deny {
                            reason: format!("morph type denied: {}", morph_type),
                        };
                    }
                    if let Some(allow_list) = allowed_morph_types
                        && !allow_list.iter().any(|item| item == morph_type)
                    {
                        return AuthzDecision::Deny {
                            reason: format!("morph type not allowed: {}", morph_type),
                        };
                    }
                }

                if !denied_facets.is_empty()
                    && let Some(facet) =
                        denied_facets.iter().find(|facet| ctx.facets.contains(facet))
                {
                    return AuthzDecision::Deny { reason: format!("facet denied: {:?}", facet) };
                }
                if !allowed_facets.is_empty() {
                    let missing = allowed_facets.iter().find(|facet| !ctx.facets.contains(facet));
                    if let Some(facet) = missing {
                        return AuthzDecision::Deny {
                            reason: format!("facet not allowed or unavailable: {:?}", facet),
                        };
                    }
                }
                AuthzDecision::Allow
            }
            Constraint::DelegationControl { max_delegation_depth, prohibit_subdelegation } => {
                if *prohibit_subdelegation && ctx.delegation_depth > 0 {
                    return AuthzDecision::Deny { reason: "subdelegation prohibited".to_owned() };
                }
                if let Some(max_depth) = max_delegation_depth
                    && ctx.delegation_depth > *max_depth
                {
                    return AuthzDecision::Deny {
                        reason: format!(
                            "delegation depth {} exceeds max {}",
                            ctx.delegation_depth, max_depth
                        ),
                    };
                }
                AuthzDecision::Allow
            }
            Constraint::RateLimiting { max_operations, period, scope } => {
                if *max_operations == 0 {
                    return AuthzDecision::Deny {
                        reason: "rate limit: max_operations is 0".to_owned(),
                    };
                }
                match ctx.rate_limit_count {
                    Some(count) if count >= *max_operations => AuthzDecision::Deny {
                        reason: format!(
                            "rate limit exceeded: {}/{} operations in {}{} {:?} scope",
                            count, max_operations, period.value, period.unit, scope
                        ),
                    },
                    Some(_) => AuthzDecision::Allow,
                    None => AuthzDecision::RequireReview {
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
                            approvers.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(", ")
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
                    AuthzDecision::RequireReview { reason }
                } else {
                    AuthzDecision::Allow
                }
            }
            Constraint::ClaimBased {
                requires_claims,
                trusted_issuers,
                claim_refresh_required,
                claim_max_age,
            } => {
                if requires_claims.is_empty() {
                    return AuthzDecision::Allow;
                }
                if trusted_issuers.is_empty() {
                    return AuthzDecision::RequireReview {
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
                            && claim.revoked_at.is_none_or(|revoked_at| revoked_at > ctx.now)
                            && claim.expires_at.is_none_or(|expires_at| expires_at > ctx.now)
                            && (!*claim_refresh_required || claim.refreshed_at.is_some())
                            && claim_max_age.as_ref().is_none_or(|max_age| {
                                freshness_basis
                                    .is_some_and(|basis| max_age_contains(ctx.now - basis, max_age))
                            })
                    });
                    if !satisfied {
                        return AuthzDecision::Deny {
                            reason: format!(
                                "required claim not satisfied: {}",
                                requirement.claim_kind
                            ),
                        };
                    }
                }
                AuthzDecision::Allow
            }
            Constraint::Accountability { accountability_required, responsible_actor } => {
                if *accountability_required {
                    if let Some(responsible) = responsible_actor
                        && ctx.actor_id != *responsible
                    {
                        return AuthzDecision::RequireReview {
                            reason: format!(
                                "accountability: actor {} is not responsible actor {}",
                                ctx.actor_id, responsible
                            ),
                        };
                    }
                    if ctx.accountability_logged {
                        AuthzDecision::Allow
                    } else {
                        AuthzDecision::RequireReview {
                            reason: "accountability log missing".to_owned(),
                        }
                    }
                } else {
                    AuthzDecision::Allow
                }
            }
            Constraint::EncryptionRequirement { encryption_required, min_encryption_level } => {
                if *encryption_required {
                    let level = min_encryption_level.as_deref().unwrap_or("mls_rfc9420");
                    match ctx.encryption_level.as_deref() {
                        Some(actual) if actual == level || actual == "stronger" => {
                            AuthzDecision::Allow
                        }
                        Some(actual) => AuthzDecision::Deny {
                            reason: format!(
                                "encryption level '{}' does not satisfy '{}'",
                                actual, level
                            ),
                        },
                        None => AuthzDecision::Deny {
                            reason: format!("encryption required: {}", level),
                        },
                    }
                } else {
                    AuthzDecision::Allow
                }
            }
            Constraint::VisibilityControl {
                allowed_history_visibility_values,
                denied_history_visibility_values,
                ..
            } => {
                if let Some(level) = ctx.history_visibility.as_deref() {
                    if denied_history_visibility_values.iter().any(|v| v == level) {
                        return AuthzDecision::Deny {
                            reason: format!("visibility level '{}' is denied", level),
                        };
                    }
                    if !allowed_history_visibility_values.is_empty()
                        && !allowed_history_visibility_values.iter().any(|v| v == level)
                    {
                        return AuthzDecision::Deny {
                            reason: format!("visibility level '{}' not in allow list", level),
                        };
                    }
                }
                AuthzDecision::Allow
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
                    return AuthzDecision::Deny {
                        reason: format!("blob size {} exceeds max {}", actual, max),
                    };
                }
                if let Some(max) = max_total_blob_bytes
                    && let Some(total) = ctx.scope_blob_total_bytes
                    && total > *max
                {
                    return AuthzDecision::Deny {
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
                    return AuthzDecision::Deny {
                        reason: format!("resource count {} exceeds max {}", count, max),
                    };
                }
                AuthzDecision::Allow
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
                    return AuthzDecision::Allow;
                }
                let Some(origin) = ctx.target_created_at else {
                    return AuthzDecision::Allow;
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
                            return AuthzDecision::Allow;
                        }
                        return AuthzDecision::Deny {
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
                        return AuthzDecision::Allow;
                    }
                    if let Some(window) = message_edit_window.as_ref()
                        && !max_age_contains(age, window)
                    {
                        return AuthzDecision::Deny {
                            reason: format!(
                                "redact shares edit window {}{}, which elapsed",
                                window.value, window.unit
                            ),
                        };
                    }
                    return AuthzDecision::Allow;
                }
                if let Some(window) = message_edit_window.as_ref()
                    && !max_age_contains(age, window)
                {
                    return AuthzDecision::Deny {
                        reason: format!("edit window {}{} elapsed", window.value, window.unit),
                    };
                }
                AuthzDecision::Allow
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
                    return AuthzDecision::Deny {
                        reason: format!("relation_kind '{}' not in allow list", rk),
                    };
                }
                if !allowed_view_ids.is_empty()
                    && let Some(view_id) = ctx.view_id.as_deref()
                    && !allowed_view_ids.iter().any(|v| v == view_id)
                {
                    return AuthzDecision::Deny {
                        reason: format!("view '{}' not allowed for container move", view_id),
                    };
                }
                if !allowed_from_container_refs.is_empty()
                    && let Some(from_id) = ctx.from_container_id.as_deref()
                    && !allowed_from_container_refs.iter().any(|v| v == from_id)
                {
                    return AuthzDecision::Deny {
                        reason: format!("from container '{}' not allowed", from_id),
                    };
                }
                if !allowed_to_container_refs.is_empty()
                    && let Some(to_id) = ctx.to_container_id.as_deref()
                    && !allowed_to_container_refs.iter().any(|v| v == to_id)
                {
                    return AuthzDecision::Deny {
                        reason: format!("to container '{}' not allowed", to_id),
                    };
                }
                if !*wip_limit_override
                    && let Some(over) = ctx.wip_over_limit
                    && over
                {
                    return AuthzDecision::Deny {
                        reason: "WIP limit exceeded and override not granted".to_owned(),
                    };
                }
                AuthzDecision::Allow
            }
            Constraint::ScopeLimitation {
                allowed_flow_ids,
                denied_flow_ids,
                allowed_tracks,
                denied_tracks,
                allowed_view_kinds,
                allowed_view_renderers,
                denied_view_kinds,
                denied_view_renderers,
            } => {
                if let Resource::Flow { flow_id, .. } = &ctx.resource {
                    if denied_flow_ids.iter().any(|v| v == flow_id) {
                        return AuthzDecision::Deny {
                            reason: format!("flow '{}' is denied", flow_id),
                        };
                    }
                    if !allowed_flow_ids.is_empty()
                        && !allowed_flow_ids.iter().any(|v| v == flow_id)
                    {
                        return AuthzDecision::Deny {
                            reason: format!("flow '{}' not in allow list", flow_id),
                        };
                    }
                }
                if let Some(track) = ctx.flow_track.as_deref() {
                    if denied_tracks.iter().any(|b| b == track) {
                        return AuthzDecision::Deny {
                            reason: format!("track '{}' is denied", track),
                        };
                    }
                    if !allowed_tracks.is_empty() && !allowed_tracks.iter().any(|b| b == track) {
                        return AuthzDecision::Deny {
                            reason: format!("track '{}' not in allow list", track),
                        };
                    }
                }
                if let Resource::View { .. } = &ctx.resource {
                    if let Some(kind) = ctx.view_kind.as_deref() {
                        if denied_view_kinds.iter().any(|k| k == kind) {
                            return AuthzDecision::Deny {
                                reason: format!("view kind '{}' is denied", kind),
                            };
                        }
                        if !allowed_view_kinds.is_empty()
                            && !allowed_view_kinds.iter().any(|k| k == kind)
                        {
                            return AuthzDecision::Deny {
                                reason: format!("view kind '{}' not in allow list", kind),
                            };
                        }
                    }
                    if let Some(renderer) = ctx.view_renderer.as_deref() {
                        if denied_view_renderers.iter().any(|r| r == renderer) {
                            return AuthzDecision::Deny {
                                reason: format!("view renderer '{}' is denied", renderer),
                            };
                        }
                        if !allowed_view_renderers.is_empty()
                            && !allowed_view_renderers.iter().any(|r| r == renderer)
                        {
                            return AuthzDecision::Deny {
                                reason: format!("view renderer '{}' not in allow list", renderer),
                            };
                        }
                    }
                }
                AuthzDecision::Allow
            }
            // CKP-0007: gate Circle-management actions on a static
            // allow-list of Circle ids baked into the grant body. The
            // caller MUST set `ctx.circle_id` to the operation's target
            // Circle for Circle-scoped actions (`ck.circle.manage`,
            // `ck.circle.member.manage`, `ck.circle.member.add.others`,
            // `ck.circle.audit`). Non-Circle-scoped operations leave
            // `circle_id` unset; per the constraint's narrow scope it
            // does not apply and silently passes.
            Constraint::AllowedCircleIds { allowed_circle_ids } => {
                if allowed_circle_ids.is_empty() {
                    return AuthzDecision::Deny {
                        reason: "allowed_circle_ids constraint requires a \
                                non-empty allow list"
                            .to_owned(),
                    };
                }
                match &ctx.circle_id {
                    Some(circle_id) => {
                        if allowed_circle_ids.contains(circle_id) {
                            AuthzDecision::Allow
                        } else {
                            AuthzDecision::Deny {
                                reason: format!(
                                    "circle '{}' not in allowed_circle_ids allow list",
                                    circle_id.as_ref()
                                ),
                            }
                        }
                    }
                    // Constraint is Circle-scoped — non-Circle-targeted
                    // operations are out of scope; pass through.
                    None => AuthzDecision::Allow,
                }
            }
        }
    }

    /// Generate a cache key for the context.
    fn cache_key(&self, ctx: &AuthzContext, grants: &[CapabilityGrant]) -> String {
        let grants_digest = crate::canonical::canonical_sha256(&grants)
            .unwrap_or_else(|_| format!("grant-count:{}", grants.len()));
        let claims_digest =
            crate::canonical::canonical_sha256(&(&ctx.verified_claims, &ctx.revoked_claim_ids))
                .unwrap_or_else(|_| format!("claim-count:{}", ctx.verified_claims.len()));
        let resource_digest = crate::canonical::canonical_sha256(&ctx.resource)
            .unwrap_or_else(|_| ctx.resource.realm_id().to_owned());
        let facets_digest = crate::canonical::canonical_sha256(&ctx.facets)
            .unwrap_or_else(|_| format!("facet-count:{}", ctx.facets.len()));
        let field_digest =
            crate::canonical::canonical_sha256(&(&ctx.read_fields, &ctx.write_fields))
                .unwrap_or_else(|_| {
                    format!("fields:{}:{}", ctx.read_fields.len(), ctx.write_fields.len())
                });
        format!(
            "{}:{}:{}:{}:{}:{}:{:?}:{:?}:{}:{}:{}",
            ctx.actor_id,
            ctx.action,
            resource_digest,
            facets_digest,
            field_digest,
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
        decision: &AuthzDecision,
        ctx: &AuthzContext,
        grants: &[CapabilityGrant],
    ) {
        // Evict old entries if cache is full
        if self.cache.len() >= self.max_cache_size {
            self.cache.clear();
        }

        let expires_at = self.cache_expires_at(ctx, grants);
        self.cache.insert(
            key,
            CachedDecision { decision: decision.clone(), _cached_at: ctx.now, expires_at },
        );
    }

    fn cache_expires_at(
        &self,
        ctx: &AuthzContext,
        grants: &[CapabilityGrant],
    ) -> Option<DateTime<Utc>> {
        let mut cache_expires_at = None;

        for grant in grants {
            update_earliest_future(&mut cache_expires_at, ctx.now, grant.not_before);
            update_earliest_future(&mut cache_expires_at, ctx.now, grant.expires_at);
            update_earliest_future(&mut cache_expires_at, ctx.now, grant.revoked_at);

            for entry in &grant.constraints {
                if let Constraint::Temporal { not_before, expires_at, recurrence } =
                    &entry.constraint
                {
                    update_earliest_future(&mut cache_expires_at, ctx.now, *not_before);
                    update_earliest_future(&mut cache_expires_at, ctx.now, *expires_at);
                    if let Some(recurrence) = recurrence
                        && let Ok(next) = recurrence_next_transition_after(ctx.now, recurrence)
                    {
                        update_earliest_future(&mut cache_expires_at, ctx.now, next);
                    }
                }
            }
        }

        cache_expires_at
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

pub fn apply_policy_response(
    capability_decision: AuthzDecision,
    policy: &PolicyEvaluationResult,
) -> AuthzDecision {
    match policy.effect {
        PolicyServerEffect::NoAction => capability_decision,
        PolicyServerEffect::Deny => AuthzDecision::Deny { reason: policy.reason.clone() },
        PolicyServerEffect::Quarantine => {
            AuthzDecision::Quarantine { reason: policy.reason.clone() }
        }
        PolicyServerEffect::RequireReview => {
            AuthzDecision::RequireReview { reason: policy.reason.clone() }
        }
    }
}

/// Check if a grant requires approval through the proposal flow.
pub fn grant_requires_approval(grant: &CapabilityGrant) -> bool {
    grant.constraints.iter().any(|entry| {
        matches!(&entry.constraint, Constraint::ApprovalWorkflow { approval_required: true, .. })
    })
}

pub fn moderation_report_for_policy_outcome(
    ctx: &AuthzContext,
    policy: &PolicyEvaluationResult,
    now: DateTime<Utc>,
) -> Option<ModerationReport> {
    if policy.effect == PolicyServerEffect::NoAction {
        return None;
    }
    Some(ModerationReport {
        report_id: policy
            .moderation_report_id
            .clone()
            .unwrap_or_else(|| format!("ck:moderation:{}", now.timestamp_millis())),
        policy_id: policy.policy_id.clone(),
        actor_id: ctx.actor_id.clone(),
        resource: ctx.resource.clone(),
        effect: policy.effect.clone(),
        reason: policy.reason.clone(),
        created_at: now,
    })
}
