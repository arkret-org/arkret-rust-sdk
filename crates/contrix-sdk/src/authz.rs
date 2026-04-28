//! Authorization engine for Contrix v1 capability-based authorization.
//!
//! This module implements:
//! - Resource selector matching
//! - Constraint evaluation
//! - Grant validation and enforcement
//! - Delegation tracking

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result, SpaceId, Did};

/// Authorization decision result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthzDecision {
    /// Operation is allowed
    Allow,
    /// Operation is denied
    Deny { reason: String },
    /// Operation requires additional review
    RequireReview { reason: String },
    /// Operation should be quarantined
    Quarantine { reason: String },
}

impl AuthzDecision {
    /// Check if the decision allows the operation.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Resource selector for capability grants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceSelector {
    /// Space selector
    Space { space_id: String },
    /// Entity selector
    Entity {
        space_id: String,
        entity_type: Option<String>,
        entity_id: Option<String>,
    },
    /// Relation selector
    Relation {
        space_id: String,
        relation_kind: String,
    },
    /// View selector
    View {
        space_id: String,
        view_id: Option<String>,
    },
    /// Wildcard selector (all resources)
    Wildcard,
}

impl ResourceSelector {
    /// Check if this selector matches a target resource.
    pub fn matches(&self, resource: &Resource) -> bool {
        match (self, resource) {
            // Space selector
            (Self::Space { space_id }, Resource::Space { space_id: target_id }) => {
                space_id == target_id || space_id == "*"
            }
            (Self::Space { space_id: _ }, _) => false,

            // Entity selector
            (
                Self::Entity { space_id, entity_type, entity_id },
                Resource::Entity { space_id: target_space, entity_type: target_type, entity_id: target_id }
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let type_match = entity_type.as_ref().map_or(true, |t| t == target_type);
                let id_match = entity_id.as_ref().map_or(true, |id| id == target_id);
                space_match && type_match && id_match
            }
            (Self::Entity { .. }, _) => false,

            // Relation selector
            (
                Self::Relation { space_id, relation_kind },
                Resource::Relation { space_id: target_space, relation_kind: target_kind }
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match && relation_kind == target_kind
            }
            (Self::Relation { .. }, _) => false,

            // View selector
            (
                Self::View { space_id, view_id },
                Resource::View { space_id: target_space, view_id: target_id }
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let id_match = view_id.as_ref().map_or(true, |id| id == target_id);
                space_match && id_match
            }
            (Self::View { .. }, _) => false,

            // Wildcard matches everything
            (Self::Wildcard, _) => true,
        }
    }

    /// Parse a resource selector from a string.
    ///
    /// Supports formats like:
    /// - "space:cx:space:..."
    /// - "entity:cx:space:...:task"
    /// - "relation:cx:space:...:assigned_to"
    pub fn parse(selector: &str) -> Result<Self> {
        // Split on the first colon to get the type
        let parts: Vec<&str> = selector.splitn(2, ':').collect();

        if parts.len() != 2 {
            return Err(Error::Protocol(format!("invalid selector: {}", selector)));
        }

        let selector_type = parts[0];
        let remainder = parts[1];

        match selector_type {
            "space" => {
                Ok(Self::Space { space_id: remainder.to_owned() })
            }
            "entity" => {
                // Format: entity:cx:space:ULID:entity_type[:entity_id] OR entity:cx:space:ULID:*
                // The space_id is cx:space:ULID (including the ULID part)
                let entity_parts: Vec<&str> = remainder.split(':').collect();
                if entity_parts.len() < 3 {
                    return Err(Error::Protocol(format!("invalid entity selector: {}", selector)));
                }

                // Reconstruct space_id as "cx:space:ULID"
                let space_id = format!("{}:{}:{}", entity_parts[0], entity_parts[1], entity_parts[2]);

                // entity_type comes after the space ULID
                let entity_type = if entity_parts.len() > 3 && entity_parts[3] != "*" {
                    Some(entity_parts[3].to_owned())
                } else {
                    None
                };

                let entity_id = if entity_parts.len() > 4 && !entity_parts[4].is_empty() {
                    Some(entity_parts[4].to_owned())
                } else {
                    None
                };

                Ok(Self::Entity { space_id, entity_type, entity_id })
            }
            "relation" => {
                // Format: relation:space_id:relation_kind
                let relation_parts: Vec<&str> = remainder.splitn(2, ':').collect();
                if relation_parts.len() != 2 {
                    return Err(Error::Protocol(format!("invalid relation selector: {}", selector)));
                }
                Ok(Self::Relation {
                    space_id: relation_parts[0].to_owned(),
                    relation_kind: relation_parts[1].to_owned(),
                })
            }
            "view" => {
                // Format: view:space_id[:view_id]
                let view_parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = view_parts[0].to_owned();
                let view_id = if view_parts.len() > 1 && !view_parts[1].is_empty() {
                    Some(view_parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::View { space_id, view_id })
            }
            "*" => Ok(Self::Wildcard),
            _ => Err(Error::Protocol(format!("unknown selector type: {}", selector))),
        }
    }
}

/// Resource being accessed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// Space resource
    Space { space_id: String },
    /// Entity resource
    Entity {
        space_id: String,
        entity_type: String,
        entity_id: String,
    },
    /// Relation resource
    Relation {
        space_id: String,
        relation_kind: String,
    },
    /// View resource
    View {
        space_id: String,
        view_id: String,
    },
}

impl Resource {
    /// Get the space ID for this resource.
    pub fn space_id(&self) -> &str {
        match self {
            Self::Space { space_id } => space_id,
            Self::Entity { space_id, .. } => space_id,
            Self::Relation { space_id, .. } => space_id,
            Self::View { space_id, .. } => space_id,
        }
    }
}

/// Constraint types.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Constraint {
    /// Temporal constraint
    Temporal {
        #[serde(skip_serializing_if = "Option::is_none")]
        not_before: Option<DateTime<Utc>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recurrence: Option<Recurrence>,
    },
    /// Field access constraint
    FieldAccess {
        effect: ConstraintEffect,
        scope: FieldScope,
        fields: Vec<String>,
    },
    /// Type restriction constraint
    TypeRestriction {
        #[serde(skip_serializing_if = "Option::is_none")]
        entity_type_allow: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        entity_type_deny: Option<Vec<String>>,
    },
    /// Delegation control constraint
    DelegationControl {
        #[serde(skip_serializing_if = "Option::is_none")]
        max_delegation_depth: Option<u32>,
        #[serde(default = "default_false")]
        prohibit_subdelegation: bool,
    },
    /// Rate limiting constraint
    RateLimiting {
        max_operations: u64,
        period: ConstraintDuration,
        #[serde(default = "default_rate_limit_scope")]
        scope: RateLimitScope,
    },
    /// Approval workflow constraint
    ApprovalWorkflow {
        #[serde(default = "default_false")]
        approval_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        approval_actor_refs: Option<Vec<Did>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout: Option<ConstraintDuration>,
    },
    /// Claim-based constraint
    ClaimBased {
        requires_claims: Vec<ClaimRequirement>,
        trusted_issuers: Vec<Did>,
    },
    /// Accountability constraint
    Accountability {
        #[serde(default = "default_false")]
        accountability_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        responsible_actor: Option<Did>,
    },
    /// Encryption requirement constraint
    EncryptionRequirement {
        #[serde(default = "default_false")]
        encryption_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        min_encryption_level: Option<String>,
    },
}

/// Constraint effect.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

/// Field scope for access control.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldScope {
    Read,
    Write,
}

/// Recurrence pattern for temporal constraints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Recurrence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// Duration representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintDuration {
    pub value: u64,
    pub unit: String, // "s", "m", "h", "d"
}

/// Rate limit scope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    PerSpace,
    Global,
}

impl Default for RateLimitScope {
    fn default() -> Self {
        Self::Global
    }
}

fn default_rate_limit_scope() -> RateLimitScope {
    RateLimitScope::Global
}

fn default_false() -> bool {
    false
}

/// Claim requirement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRequirement {
    pub claim_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// Grant constraint with priority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint_id: Option<String>,
    pub constraint: Constraint,
    #[serde(default)]
    pub priority: i32,
}

impl ConstraintEntry {
    /// Create a new constraint entry.
    pub fn new(constraint: Constraint) -> Self {
        Self {
            constraint_id: None,
            constraint,
            priority: 0,
        }
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Get the effect of this constraint.
    pub fn effect(&self) -> ConstraintEffect {
        match &self.constraint {
            Constraint::Temporal { .. } => ConstraintEffect::Allow,
            Constraint::FieldAccess { effect, .. } => effect.clone(),
            Constraint::TypeRestriction { .. } => ConstraintEffect::Allow,
            Constraint::DelegationControl { .. } => ConstraintEffect::Allow,
            Constraint::RateLimiting { .. } => ConstraintEffect::Allow,
            Constraint::ApprovalWorkflow { .. } => ConstraintEffect::RequireReview,
            Constraint::ClaimBased { .. } => ConstraintEffect::Allow,
            Constraint::Accountability { .. } => ConstraintEffect::Allow,
            Constraint::EncryptionRequirement { .. } => ConstraintEffect::Allow,
        }
    }
}

/// Authorization context for evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzContext {
    /// Current timestamp for evaluation
    pub now: DateTime<Utc>,
    /// Actor making the request
    pub actor_id: Did,
    /// Space context
    pub space_id: Option<SpaceId>,
    /// Operation being performed
    pub action: String,
    /// Resource being accessed
    pub resource: Resource,
    /// Fields being read
    #[serde(default)]
    pub read_fields: Vec<String>,
    /// Fields being written
    #[serde(default)]
    pub write_fields: Vec<String>,
}

impl AuthzContext {
    /// Create a new authorization context.
    pub fn new(actor_id: Did, action: String, resource: Resource) -> Self {
        Self {
            now: Utc::now(),
            actor_id,
            space_id: None,
            action,
            resource,
            read_fields: Vec::new(),
            write_fields: Vec::new(),
        }
    }

    /// Set the space ID.
    pub fn with_space_id(mut self, space_id: SpaceId) -> Self {
        self.space_id = Some(space_id);
        self
    }
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
    cached_at: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
}

impl AuthzEngine {
    /// Create a new authorization engine.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            max_cache_size: 1000,
        }
    }

    /// Check authorization for a context against a list of grants.
    pub fn check_authorization(
        &mut self,
        ctx: &AuthzContext,
        grants: &[CapabilityGrant],
    ) -> AuthzDecision {
        // Check cache first
        let cache_key = self.cache_key(ctx);
        if let Some(cached) = self.cache.get(&cache_key) {
            if cached.valid_until.as_ref().map_or(true, |valid| &ctx.now < valid) {
                return cached.decision.clone();
            }
        }

        // Evaluate grants
        let decision = self.evaluate_grants(ctx, grants);

        // Cache the result
        self.cache_decision(cache_key, &decision, ctx);

        decision
    }

    /// Evaluate all grants and return the combined decision.
    fn evaluate_grants(&self, ctx: &AuthzContext, grants: &[CapabilityGrant]) -> AuthzDecision {
        let mut matching_grants = Vec::new();

        // Find grants that match the resource
        for grant in grants {
            if self.grant_matches_resource(ctx, grant) {
                matching_grants.push(grant);
            }
        }

        // If no matching grants, deny
        if matching_grants.is_empty() {
            return AuthzDecision::Deny {
                reason: "no matching grant".to_owned(),
            };
        }

        // Check action match
        let action_grants: Vec<_> = matching_grants
            .into_iter()
            .filter(|g| g.actions.contains(&ctx.action) || g.actions.contains(&"*".to_owned()))
            .collect();

        if action_grants.is_empty() {
            return AuthzDecision::Deny {
                reason: format!("action '{}' not granted", ctx.action),
            };
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

    /// Evaluate all constraints for a grant.
    fn evaluate_constraints(&self, ctx: &AuthzContext, grant: &CapabilityGrant) -> AuthzDecision {
        // Sort constraints by effect: deny > quarantine > require_review > allow
        let mut constraints = grant.constraints.clone();
        constraints.sort_by_key(|c| {
            match c.effect() {
                ConstraintEffect::Deny => 0,
                ConstraintEffect::Quarantine => 1,
                ConstraintEffect::RequireReview => 2,
                ConstraintEffect::Allow => 3,
            }
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
                if let Some(not_before) = not_before {
                    if ctx.now < *not_before {
                        return AuthzDecision::Deny {
                            reason: format!("before not_before: {}", not_before),
                        };
                    }
                }
                if let Some(expires_at) = expires_at {
                    if ctx.now > *expires_at {
                        return AuthzDecision::Deny {
                            reason: format!("after expires_at: {}", expires_at),
                        };
                    }
                }
                if let Some(_recurrence) = recurrence {
                    // TODO: Implement recurrence matching
                }
                AuthzDecision::Allow
            }
            Constraint::FieldAccess { effect, scope, fields } => {
                let target_fields = match scope {
                    FieldScope::Read => &ctx.read_fields,
                    FieldScope::Write => &ctx.write_fields,
                };

                for field in target_fields {
                    if fields.contains(field) {
                        return match effect {
                            ConstraintEffect::Allow => AuthzDecision::Allow,
                            ConstraintEffect::Deny => AuthzDecision::Deny {
                                reason: format!("field access denied: {}", field),
                            },
                            _ => AuthzDecision::Allow,
                        };
                    }
                }
                AuthzDecision::Allow
            }
            Constraint::TypeRestriction { entity_type_allow, entity_type_deny } => {
                if let Resource::Entity { entity_type, .. } = &ctx.resource {
                    if let Some(deny_list) = entity_type_deny {
                        if deny_list.contains(entity_type) {
                            return AuthzDecision::Deny {
                                reason: format!("entity type denied: {}", entity_type),
                            };
                        }
                    }
                    if let Some(allow_list) = entity_type_allow {
                        if !allow_list.contains(entity_type) {
                            return AuthzDecision::Deny {
                                reason: format!("entity type not allowed: {}", entity_type),
                            };
                        }
                    }
                }
                AuthzDecision::Allow
            }
            Constraint::DelegationControl { .. } => {
                // TODO: Implement delegation tracking
                AuthzDecision::Allow
            }
            Constraint::RateLimiting { .. } => {
                // TODO: Implement rate limiting
                AuthzDecision::Allow
            }
            Constraint::ApprovalWorkflow { approval_required, .. } => {
                if *approval_required {
                    AuthzDecision::RequireReview {
                        reason: "approval required".to_owned(),
                    }
                } else {
                    AuthzDecision::Allow
                }
            }
            Constraint::ClaimBased { .. } => {
                // TODO: Implement claim verification
                AuthzDecision::Allow
            }
            Constraint::Accountability { .. } => {
                // TODO: Implement accountability tracking
                AuthzDecision::Allow
            }
            Constraint::EncryptionRequirement { encryption_required, .. } => {
                if *encryption_required {
                    // Check if resource is encrypted
                    // For now, just allow
                    AuthzDecision::Allow
                } else {
                    AuthzDecision::Allow
                }
            }
        }
    }

    /// Generate a cache key for the context.
    fn cache_key(&self, ctx: &AuthzContext) -> String {
        format!("{}:{}:{}", ctx.actor_id, ctx.action, ctx.resource.space_id())
    }

    /// Cache a decision.
    fn cache_decision(&mut self, key: String, decision: &AuthzDecision, ctx: &AuthzContext) {
        // Evict old entries if cache is full
        if self.cache.len() >= self.max_cache_size {
            self.cache.clear();
        }

        self.cache.insert(key, CachedDecision {
            decision: decision.clone(),
            cached_at: ctx.now,
            valid_until: None, // TODO: Calculate from temporal constraints
        });
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

/// Capability grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub id: String,
    pub issuer: Did,
    pub subject: Did,
    pub actions: Vec<String>,
    pub resources: Vec<ResourceSelector>,
    #[serde(default)]
    pub constraints: Vec<ConstraintEntry>,
    #[serde(default)]
    pub delegable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_selector_parse_space() {
        let selector = ResourceSelector::parse("space:cx:space:01JS0SP000000000000000000").unwrap();
        assert_eq!(selector, ResourceSelector::Space {
            space_id: "cx:space:01JS0SP000000000000000000".to_owned()
        });
    }

    #[test]
    fn resource_selector_parse_entity() {
        let selector = ResourceSelector::parse("entity:cx:space:...:task").unwrap();
        assert_eq!(selector, ResourceSelector::Entity {
            space_id: "cx:space:...".to_owned(),
            entity_type: Some("task".to_owned()),
            entity_id: None,
        });
    }

    #[test]
    fn resource_selector_wildcard_matches_all() {
        let selector = ResourceSelector::Wildcard;
        assert!(selector.matches(&Resource::Space { space_id: "test".to_owned() }));
        assert!(selector.matches(&Resource::Entity {
            space_id: "test".to_owned(),
            entity_type: "task".to_owned(),
            entity_id: "id".to_owned(),
        }));
    }

    #[test]
    fn space_selector_matches_space() {
        let selector = ResourceSelector::Space {
            space_id: "cx:space:A".to_owned(),
        };
        assert!(selector.matches(&Resource::Space { space_id: "cx:space:A".to_owned() }));
        assert!(!selector.matches(&Resource::Space { space_id: "cx:space:B".to_owned() }));
    }

    #[test]
    fn entity_selector_matches_entity() {
        let selector = ResourceSelector::Entity {
            space_id: "cx:space:A".to_owned(),
            entity_type: Some("task".to_owned()),
            entity_id: None,
        };
        assert!(selector.matches(&Resource::Entity {
            space_id: "cx:space:A".to_owned(),
            entity_type: "task".to_owned(),
            entity_id: "cx:entity:123".to_owned(),
        }));
        assert!(!selector.matches(&Resource::Entity {
            space_id: "cx:space:A".to_owned(),
            entity_type: "message".to_owned(),
            entity_id: "cx:entity:123".to_owned(),
        }));
    }

    #[test]
    fn authz_engine_deny_without_grant() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "read".to_owned(),
            Resource::Space { space_id: "cx:space:A".to_owned() },
        );

        let decision = engine.check_authorization(&ctx, &[]);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn authz_engine_allow_with_matching_grant() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "read".to_owned(),
            Resource::Space { space_id: "cx:space:A".to_owned() },
        );

        let grant = CapabilityGrant {
            id: "grant-1".to_owned(),
            issuer: Did::new("did:web:authority.example.com").unwrap(),
            subject: Did::new("did:web:alice.example.com").unwrap(),
            actions: vec!["read".to_owned()],
            resources: vec![ResourceSelector::Space {
                space_id: "cx:space:A".to_owned(),
            }],
            constraints: vec![],
            delegable: false,
        };

        let decision = engine.check_authorization(&ctx, &[grant]);
        assert!(decision.is_allowed());
    }

    #[test]
    fn authz_engine_deny_wrong_action() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "write".to_owned(),
            Resource::Space { space_id: "cx:space:A".to_owned() },
        );

        let grant = CapabilityGrant {
            id: "grant-1".to_owned(),
            issuer: Did::new("did:web:authority.example.com").unwrap(),
            subject: Did::new("did:web:alice.example.com").unwrap(),
            actions: vec!["read".to_owned()],
            resources: vec![ResourceSelector::Space {
                space_id: "cx:space:A".to_owned(),
            }],
            constraints: vec![],
            delegable: false,
        };

        let decision = engine.check_authorization(&ctx, &[grant]);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn authz_engine_temporal_constraint_expires() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "read".to_owned(),
            Resource::Space { space_id: "cx:space:A".to_owned() },
        );

        let grant = CapabilityGrant {
            id: "grant-1".to_owned(),
            issuer: Did::new("did:web:authority.example.com").unwrap(),
            subject: Did::new("did:web:alice.example.com").unwrap(),
            actions: vec!["read".to_owned()],
            resources: vec![ResourceSelector::Space {
                space_id: "cx:space:A".to_owned(),
            }],
            constraints: vec![ConstraintEntry::new(Constraint::Temporal {
                not_before: None,
                expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
                recurrence: None,
            })],
            delegable: false,
        };

        let decision = engine.check_authorization(&ctx, &[grant]);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn authz_engine_field_access_deny() {
        let mut engine = AuthzEngine::new();
        let mut ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "update".to_owned(),
            Resource::Entity {
                space_id: "cx:space:A".to_owned(),
                entity_type: "task".to_owned(),
                entity_id: "cx:entity:123".to_owned(),
            },
        );
        ctx.write_fields = vec!["id".to_owned(), "title".to_owned()];

        let grant = CapabilityGrant {
            id: "grant-1".to_owned(),
            issuer: Did::new("did:web:authority.example.com").unwrap(),
            subject: Did::new("did:web:alice.example.com").unwrap(),
            actions: vec!["update".to_owned()],
            resources: vec![ResourceSelector::Entity {
                space_id: "cx:space:A".to_owned(),
                entity_type: Some("task".to_owned()),
                entity_id: None,
            }],
            constraints: vec![ConstraintEntry::new(Constraint::FieldAccess {
                effect: ConstraintEffect::Deny,
                scope: FieldScope::Write,
                fields: vec!["id".to_owned(), "created_by".to_owned()],
            })],
            delegable: false,
        };

        let decision = engine.check_authorization(&ctx, &[grant]);
        assert!(!decision.is_allowed());
    }
}
