//! Authorization engine for Contrix v1 capability-based authorization.
//!
//! This module implements:
//! - Resource selector matching
//! - Constraint evaluation
//! - Grant validation and enforcement
//! - Delegation tracking

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{Did, Error, Result, SpaceId};

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
    /// Board selector (entity_type = "board")
    Board { space_id: String, board_id: Option<String> },
    /// Collection selector (entity_type = "collection")
    Collection { space_id: String, collection_id: Option<String> },
    /// Entity selector
    Entity { space_id: String, entity_type: Option<String>, entity_id: Option<String> },
    /// Comment selector
    Comment { space_id: String, comment_id: Option<String> },
    /// Channel selector (entity_type = "channel")
    Channel { space_id: String, channel_id: Option<String> },
    /// Topic selector (entity_type = "topic")
    Topic { space_id: String, topic_id: Option<String> },
    /// Message selector (entity_type = "message")
    Message { space_id: String, message_id: Option<String> },
    /// Relation selector
    Relation { space_id: String, relation_kind: String },
    /// View selector
    View { space_id: String, view_id: Option<String> },
    /// Run selector (entity_type = "run")
    Run { space_id: String, run_id: Option<String> },
    /// Memory selector (entity_type = "memory")
    Memory { space_id: String, memory_id: Option<String> },
    /// Schema selector
    Schema { space_id: String, schema_id: Option<String> },
    /// Policy selector
    Policy { space_id: String, policy_id: Option<String> },
    /// Invite selector
    Invite { space_id: String, invite_id: Option<String> },
    /// Read marker selector
    ReadMarker { space_id: String },
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
            (Self::Space { .. }, _) => false,

            // Board selector — matches entities with entity_type="board"
            (
                Self::Board { space_id, board_id },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match
                    && target_type == "board"
                    && board_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Board { .. }, _) => false,

            // Collection selector — matches entities with entity_type="collection"
            (
                Self::Collection { space_id, collection_id },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match
                    && target_type == "collection"
                    && collection_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Collection { .. }, _) => false,

            // Entity selector
            (
                Self::Entity { space_id, entity_type, entity_id },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let type_match = entity_type.as_ref().is_none_or(|t| t == target_type);
                let id_match = entity_id.as_ref().is_none_or(|id| id == target_id);
                space_match && type_match && id_match
            }
            (Self::Entity { .. }, _) => false,

            // Comment selector — matches entities with entity_type="comment"
            (
                Self::Comment { space_id, comment_id },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match
                    && target_type == "comment"
                    && comment_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Comment { .. }, _) => false,

            // Channel selector — matches entities with entity_type="channel"
            (
                Self::Channel { space_id, channel_id },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match
                    && target_type == "channel"
                    && channel_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Channel { .. }, _) => false,

            // Topic selector — matches entities with entity_type="topic"
            (
                Self::Topic { space_id, topic_id },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match
                    && target_type == "topic"
                    && topic_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Topic { .. }, _) => false,

            // Message selector — matches entities with entity_type="message"
            (
                Self::Message { space_id, message_id },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match
                    && target_type == "message"
                    && message_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Message { .. }, _) => false,

            // Relation selector
            (
                Self::Relation { space_id, relation_kind },
                Resource::Relation { space_id: target_space, relation_kind: target_kind },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match && relation_kind == target_kind
            }
            (Self::Relation { .. }, _) => false,

            // View selector
            (
                Self::View { space_id, view_id },
                Resource::View { space_id: target_space, view_id: target_id },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let id_match = view_id.as_ref().is_none_or(|id| id == target_id);
                space_match && id_match
            }
            (Self::View { .. }, _) => false,

            // Run selector — matches entities with entity_type="run"
            (
                Self::Run { space_id, run_id },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match
                    && target_type == "run"
                    && run_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Run { .. }, _) => false,

            // Memory selector — matches entities with entity_type="memory"
            (
                Self::Memory { space_id, memory_id },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match
                    && target_type == "memory"
                    && memory_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Memory { .. }, _) => false,

            // Schema selector
            (
                Self::Schema { space_id, schema_id },
                Resource::Schema { space_id: target_space, schema_id: target_id },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match && schema_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Schema { .. }, _) => false,

            // Policy selector
            (
                Self::Policy { space_id, policy_id },
                Resource::Policy { space_id: target_space, policy_id: target_id },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match && policy_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Policy { .. }, _) => false,

            // Invite selector
            (
                Self::Invite { space_id, invite_id },
                Resource::Invite { space_id: target_space, invite_id: target_id },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match && invite_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Invite { .. }, _) => false,

            // Read marker selector
            (Self::ReadMarker { space_id }, Resource::ReadMarker { space_id: target_space }) => {
                space_id == target_space || space_id == "*"
            }
            (Self::ReadMarker { .. }, _) => false,

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
            "space" => Ok(Self::Space { space_id: remainder.to_owned() }),
            "board" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let board_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Board { space_id, board_id })
            }
            "collection" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let collection_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Collection { space_id, collection_id })
            }
            "entity" => {
                // Format: entity:cx:space:ULID:entity_type[:entity_id] OR entity:cx:space:ULID:*
                // The space_id is cx:space:ULID (including the ULID part)
                let entity_parts: Vec<&str> = remainder.split(':').collect();
                if entity_parts.len() < 3 {
                    return Err(Error::Protocol(format!("invalid entity selector: {}", selector)));
                }

                // Reconstruct space_id as "cx:space:ULID"
                let space_id =
                    format!("{}:{}:{}", entity_parts[0], entity_parts[1], entity_parts[2]);

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
            "comment" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let comment_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Comment { space_id, comment_id })
            }
            "channel" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let channel_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Channel { space_id, channel_id })
            }
            "topic" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let topic_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Topic { space_id, topic_id })
            }
            "message" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let message_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Message { space_id, message_id })
            }
            "relation" => {
                // Format: relation:space_id:relation_kind
                let relation_parts: Vec<&str> = remainder.splitn(2, ':').collect();
                if relation_parts.len() != 2 {
                    return Err(Error::Protocol(format!(
                        "invalid relation selector: {}",
                        selector
                    )));
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
            "run" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let run_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Run { space_id, run_id })
            }
            "memory" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let memory_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Memory { space_id, memory_id })
            }
            "schema" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let schema_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Schema { space_id, schema_id })
            }
            "policy" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let policy_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Policy { space_id, policy_id })
            }
            "invite" => {
                let parts: Vec<&str> = remainder.splitn(2, ':').collect();
                let space_id = parts[0].to_owned();
                let invite_id = if parts.len() > 1 && !parts[1].is_empty() {
                    Some(parts[1].to_owned())
                } else {
                    None
                };
                Ok(Self::Invite { space_id, invite_id })
            }
            "read_marker" => Ok(Self::ReadMarker { space_id: remainder.to_owned() }),
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
    /// Entity resource (covers board, collection, task, message, topic, channel, document, file, memory, run, etc.)
    Entity { space_id: String, entity_type: String, entity_id: String },
    /// Relation resource
    Relation { space_id: String, relation_kind: String },
    /// View resource
    View { space_id: String, view_id: String },
    /// Schema resource
    Schema { space_id: String, schema_id: String },
    /// Policy resource
    Policy { space_id: String, policy_id: String },
    /// Invite resource
    Invite { space_id: String, invite_id: String },
    /// Read marker resource
    ReadMarker { space_id: String },
}

impl Resource {
    /// Get the space ID for this resource.
    pub fn space_id(&self) -> &str {
        match self {
            Self::Space { space_id } => space_id,
            Self::Entity { space_id, .. } => space_id,
            Self::Relation { space_id, .. } => space_id,
            Self::View { space_id, .. } => space_id,
            Self::Schema { space_id, .. } => space_id,
            Self::Policy { space_id, .. } => space_id,
            Self::Invite { space_id, .. } => space_id,
            Self::ReadMarker { space_id } => space_id,
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
    FieldAccess { effect: ConstraintEffect, scope: FieldScope, fields: Vec<String> },
    /// Type restriction constraint
    TypeRestriction {
        #[serde(skip_serializing_if = "Option::is_none")]
        entity_type_allow: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        entity_type_deny: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope_limitation: Option<ScopeLimitation>,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        approval_mode: Option<ApprovalMode>,
        #[serde(skip_serializing_if = "Option::is_none")]
        approval_relation: Option<String>,
        #[serde(default)]
        guardian_approval_required: bool,
        #[serde(default)]
        controller_approval_required: bool,
    },
    /// Claim-based constraint
    ClaimBased {
        requires_claims: Vec<ClaimRequirement>,
        trusted_issuers: Vec<Did>,
        #[serde(default)]
        claim_refresh_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        claim_max_age: Option<ConstraintDuration>,
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
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        memory_kind_allow: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        memory_kind_deny: Vec<String>,
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
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    PerSpace,
    #[default]
    Global,
}

/// Scope limitation type for grant constraints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLimitation {
    Space,
    Channel,
    Topic,
    Thread,
    View,
    Entity,
    Relation,
    Policy,
}

/// Approval semantics for approval workflow constraints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    Any,
    All,
    Threshold { count: u32 },
    Guardian,
    Controller,
}

fn default_rate_limit_scope() -> RateLimitScope {
    RateLimitScope::Global
}

fn default_false() -> bool {
    false
}

fn max_age_contains(age: chrono::Duration, max_age: &ConstraintDuration) -> bool {
    let allowed = match max_age.unit.as_str() {
        "s" => chrono::Duration::seconds(max_age.value as i64),
        "m" => chrono::Duration::minutes(max_age.value as i64),
        "h" => chrono::Duration::hours(max_age.value as i64),
        "d" => chrono::Duration::days(max_age.value as i64),
        _ => return false,
    };
    age <= allowed
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

/// Verified claim evidence supplied by the caller during authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedClaim {
    pub claim_type: String,
    pub issuer: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<DateTime<Utc>>,
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
        Self { constraint_id: None, constraint, priority: 0 }
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
    /// Current delegation depth of the grant being evaluated. Root grants are depth 0.
    #[serde(default)]
    pub delegation_depth: u32,
    /// Operation count already observed in the current rate-limit window.
    #[serde(default)]
    pub rate_limit_count: Option<u64>,
    /// Verified claims available for claim-based constraints.
    #[serde(default)]
    pub verified_claims: Vec<VerifiedClaim>,
    /// Whether the operation has an accountable audit/log record.
    #[serde(default)]
    pub accountability_logged: bool,
    /// Encryption level of the target operation/payload, if already verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_level: Option<String>,
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
            delegation_depth: 0,
            rate_limit_count: None,
            verified_claims: Vec::new(),
            accountability_logged: false,
            encryption_level: None,
        }
    }

    /// Set the space ID.
    pub fn with_space_id(mut self, space_id: SpaceId) -> Self {
        self.space_id = Some(space_id);
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
    valid_until: Option<DateTime<Utc>>,
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
        let cache_key = self.cache_key(ctx);
        if let Some(cached) = self.cache.get(&cache_key)
            && cached.valid_until.as_ref().is_none_or(|valid| &ctx.now < valid)
        {
            return cached.decision.clone();
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
            Constraint::TypeRestriction {
                entity_type_allow,
                entity_type_deny,
                scope_limitation,
            } => {
                if let Some(scope_limitation) = scope_limitation {
                    let scope_matches = matches!(
                        (scope_limitation, &ctx.resource),
                        (ScopeLimitation::Space, Resource::Space { .. })
                            | (ScopeLimitation::Entity, Resource::Entity { .. })
                            | (ScopeLimitation::Relation, Resource::Relation { .. })
                            | (ScopeLimitation::View, Resource::View { .. })
                            | (ScopeLimitation::Policy, Resource::Policy { .. })
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
                if let Resource::Entity { entity_type, .. } = &ctx.resource {
                    if let Some(deny_list) = entity_type_deny
                        && deny_list.contains(entity_type)
                    {
                        return AuthzDecision::Deny {
                            reason: format!("entity type denied: {}", entity_type),
                        };
                    }
                    if let Some(allow_list) = entity_type_allow
                        && !allow_list.contains(entity_type)
                    {
                        return AuthzDecision::Deny {
                            reason: format!("entity type not allowed: {}", entity_type),
                        };
                    }
                }
                AuthzDecision::Allow
            }
            Constraint::DelegationControl { max_delegation_depth, prohibit_subdelegation } => {
                if *prohibit_subdelegation && ctx.delegation_depth > 0 {
                    return AuthzDecision::Deny { reason: "subdelegation prohibited".to_owned() };
                }
                if let Some(max_depth) = max_delegation_depth {
                    if ctx.delegation_depth > *max_depth {
                        return AuthzDecision::Deny {
                            reason: format!(
                                "delegation depth {} exceeds max {}",
                                ctx.delegation_depth, max_depth
                            ),
                        };
                    }
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
                approval_actor_refs,
                timeout,
                approval_mode,
                approval_relation,
                guardian_approval_required,
                controller_approval_required,
            } => {
                if *approval_required {
                    let reason = if let Some(approvers) = approval_actor_refs {
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
                                .map(|c| c.claim_type.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    };
                }
                for requirement in requires_claims {
                    let satisfied = ctx.verified_claims.iter().any(|claim| {
                        claim.claim_type == requirement.claim_type
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
                            && (!*claim_refresh_required || claim.refreshed_at.is_some())
                            && claim_max_age.as_ref().is_none_or(|max_age| {
                                claim.refreshed_at.is_some_and(|refreshed_at| {
                                    max_age_contains(ctx.now - refreshed_at, max_age)
                                })
                            })
                    });
                    if !satisfied {
                        return AuthzDecision::Deny {
                            reason: format!(
                                "required claim not satisfied: {}",
                                requirement.claim_type
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
            Constraint::EncryptionRequirement {
                encryption_required,
                min_encryption_level,
                memory_kind_allow,
                memory_kind_deny,
            } => {
                if let Resource::Entity { entity_type, .. } = &ctx.resource
                    && entity_type == "memory"
                {
                    if memory_kind_deny.iter().any(|kind| kind == "*") {
                        return AuthzDecision::Deny { reason: "memory kind denied".to_owned() };
                    }
                    let _ = memory_kind_allow;
                }
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
        }
    }

    /// Generate a cache key for the context.
    fn cache_key(&self, ctx: &AuthzContext) -> String {
        format!(
            "{}:{}:{}:{}:{:?}:{:?}:{}:{}",
            ctx.actor_id,
            ctx.action,
            ctx.resource.space_id(),
            ctx.delegation_depth,
            ctx.rate_limit_count,
            ctx.encryption_level,
            ctx.verified_claims.len(),
            ctx.accountability_logged
        )
    }

    /// Cache a decision.
    fn cache_decision(&mut self, key: String, decision: &AuthzDecision, ctx: &AuthzContext) {
        // Evict old entries if cache is full
        if self.cache.len() >= self.max_cache_size {
            self.cache.clear();
        }

        self.cache.insert(
            key,
            CachedDecision {
                decision: decision.clone(),
                _cached_at: ctx.now,
                valid_until: None, // TODO: Calculate from temporal constraints
            },
        );
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub issuer: Did,
    pub subject: Did,
    pub actions: Vec<String>,
    pub resources: Vec<ResourceSelector>,
    #[serde(default)]
    pub constraints: Vec<ConstraintEntry>,
    #[serde(default)]
    pub delegable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant_for(action: &str, resource: ResourceSelector) -> CapabilityGrant {
        CapabilityGrant {
            id: "grant-1".to_owned(),
            space_id: None,
            issuer: Did::new("did:web:authority.example.com").unwrap(),
            subject: Did::new("did:web:alice.example.com").unwrap(),
            actions: vec![action.to_owned()],
            resources: vec![resource],
            constraints: vec![],
            delegable: false,
            parent_grant_id: None,
            valid_from: None,
            valid_until: None,
            revoked_by: None,
            revoked_at: None,
        }
    }

    #[test]
    fn resource_selector_parse_space() {
        let selector = ResourceSelector::parse("space:cx:space:01JS0SP000000000000000000").unwrap();
        assert_eq!(
            selector,
            ResourceSelector::Space { space_id: "cx:space:01JS0SP000000000000000000".to_owned() }
        );
    }

    #[test]
    fn resource_selector_parse_entity() {
        let selector = ResourceSelector::parse("entity:cx:space:...:task").unwrap();
        assert_eq!(
            selector,
            ResourceSelector::Entity {
                space_id: "cx:space:...".to_owned(),
                entity_type: Some("task".to_owned()),
                entity_id: None,
            }
        );
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
        let selector = ResourceSelector::Space { space_id: "cx:space:A".to_owned() };
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

        let grant =
            grant_for("read", ResourceSelector::Space { space_id: "cx:space:A".to_owned() });

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

        let grant =
            grant_for("read", ResourceSelector::Space { space_id: "cx:space:A".to_owned() });

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

        let mut grant =
            grant_for("read", ResourceSelector::Space { space_id: "cx:space:A".to_owned() });
        grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
            not_before: None,
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            recurrence: None,
        })];

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

        let mut grant = grant_for(
            "update",
            ResourceSelector::Entity {
                space_id: "cx:space:A".to_owned(),
                entity_type: Some("task".to_owned()),
                entity_id: None,
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::FieldAccess {
            effect: ConstraintEffect::Deny,
            scope: FieldScope::Write,
            fields: vec!["id".to_owned(), "created_by".to_owned()],
        })];

        let decision = engine.check_authorization(&ctx, &[grant]);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn authz_engine_enforces_runtime_constraints() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "send".to_owned(),
            Resource::Entity {
                space_id: "cx:space:A".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:123".to_owned(),
            },
        )
        .with_delegation_depth(2)
        .with_rate_limit_count(3)
        .with_accountability_logged(true)
        .with_encryption_level("mls_rfc9420")
        .with_verified_claim(VerifiedClaim {
            claim_type: "employee".to_owned(),
            issuer: Did::new("did:web:issuer.example.com").unwrap(),
            organization: Some(Did::new("did:web:org.example.com").unwrap()),
            status: Some("active".to_owned()),
            roles: vec!["writer".to_owned()],
            refreshed_at: None,
        });
        let mut grant = grant_for(
            "send",
            ResourceSelector::Entity {
                space_id: "cx:space:A".to_owned(),
                entity_type: Some("message".to_owned()),
                entity_id: None,
            },
        );
        grant.constraints = vec![
            ConstraintEntry::new(Constraint::DelegationControl {
                max_delegation_depth: Some(2),
                prohibit_subdelegation: false,
            }),
            ConstraintEntry::new(Constraint::RateLimiting {
                max_operations: 4,
                period: ConstraintDuration { value: 1, unit: "m".to_owned() },
                scope: RateLimitScope::PerSpace,
            }),
            ConstraintEntry::new(Constraint::ClaimBased {
                requires_claims: vec![ClaimRequirement {
                    claim_type: "employee".to_owned(),
                    issuer: None,
                    organization: Some(Did::new("did:web:org.example.com").unwrap()),
                    status: Some("active".to_owned()),
                    roles: Some(vec!["writer".to_owned()]),
                }],
                trusted_issuers: vec![Did::new("did:web:issuer.example.com").unwrap()],
                claim_refresh_required: false,
                claim_max_age: None,
            }),
            ConstraintEntry::new(Constraint::Accountability {
                accountability_required: true,
                responsible_actor: Some(Did::new("did:web:alice.example.com").unwrap()),
            }),
            ConstraintEntry::new(Constraint::EncryptionRequirement {
                encryption_required: true,
                min_encryption_level: Some("mls_rfc9420".to_owned()),
                memory_kind_allow: Vec::new(),
                memory_kind_deny: Vec::new(),
            }),
        ];

        assert!(engine.check_authorization(&ctx, &[grant]).is_allowed());
    }

    #[test]
    fn authz_engine_denies_missing_encryption() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "send".to_owned(),
            Resource::Entity {
                space_id: "cx:space:A".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:123".to_owned(),
            },
        );
        let mut grant = grant_for(
            "send",
            ResourceSelector::Entity {
                space_id: "cx:space:A".to_owned(),
                entity_type: Some("message".to_owned()),
                entity_id: None,
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::EncryptionRequirement {
            encryption_required: true,
            min_encryption_level: Some("mls_rfc9420".to_owned()),
            memory_kind_allow: Vec::new(),
            memory_kind_deny: Vec::new(),
        })];

        assert!(!engine.check_authorization(&ctx, &[grant]).is_allowed());
    }
}
