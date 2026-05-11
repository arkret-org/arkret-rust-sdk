//! Authorization engine for Contrix v1 capability-based authorization.
//!
//! This module implements:
//! - Resource selector matching
//! - Constraint evaluation
//! - Grant validation and enforcement
//! - Delegation tracking

use chrono::{
    DateTime, Datelike, FixedOffset, LocalResult, NaiveDate, NaiveTime, TimeZone, Utc, Weekday,
};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{Did, Error, Result, SpaceId, model::EntityFacet};

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
    /// Flow selector (flow_id)
    Flow { space_id: String, flow_id: Option<String> },
    /// Object selector. Canonical replacement for legacy board / collection /
    /// entity / channel / topic / comment / run / memory selector kinds.
    Object { space_id: String, object_type: Option<String>, object_ref: Option<String> },
    /// Message selector (entity_type = "message")
    Message { space_id: String, message_id: Option<String> },
    /// Relation selector
    Relation { space_id: String, relation_kind: String },
    /// View selector
    View { space_id: String, view_id: Option<String> },
    /// Schema selector
    Schema { space_id: String, schema_id: Option<String> },
    /// Policy selector
    Policy { space_id: String, policy_id: Option<String> },
    /// Invite selector
    Invite { space_id: String, invite_id: Option<String> },
    /// Read marker selector
    ReadMarker { space_id: String },
    /// Morph selector — `morph_type` is the canonical filter per
    /// `resource-selector-grammar.md` §6 (matches by exact type name).
    Morph { space_id: String, morph_id: Option<String>, morph_type: Option<String> },
    /// Notification selector (per-actor private). `actor_did` may be `*`.
    Notification { actor_did: String, notification_id: Option<String> },
    /// Blob selector. `space_id` MAY be `*` for global blobs (e.g. avatars).
    Blob { space_id: String, blob_id: Option<String> },
    /// Event selector (audit/redaction). Matches by event kind / id.
    Event { space_id: String, event_kind: Option<String>, event_id: Option<String> },
    /// Actor selector (e.g. account-lifecycle, profile updates).
    Actor { actor_did: String },
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

            // Flow selector
            (
                Self::Flow { space_id, flow_id },
                Resource::Flow { space_id: target_space, flow_id: target_id },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let id_match = flow_id.as_ref().is_none_or(|id| id == target_id);
                space_match && id_match
            }
            (Self::Flow { .. }, _) => false,

            // Object selector
            (
                Self::Object { space_id, object_type, object_ref },
                Resource::Flow { space_id: target_space, flow_id: target_id },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let type_match = object_type.as_ref().is_none_or(|t| t == "flow");
                let ref_match = object_ref.as_ref().is_none_or(|id| id == target_id);
                space_match && type_match && ref_match
            }
            (
                Self::Object { space_id, object_type, object_ref },
                Resource::Entity {
                    space_id: target_space,
                    entity_type: target_type,
                    entity_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let type_match = object_type.as_ref().is_none_or(|t| t == target_type);
                let ref_match = object_ref.as_ref().is_none_or(|id| id == target_id);
                space_match && type_match && ref_match
            }
            (
                Self::Object { space_id, object_type, object_ref },
                Resource::Morph {
                    space_id: target_space,
                    morph_id: target_id,
                    morph_type: target_type,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let type_match = object_type.as_ref().is_none_or(|t| t == target_type);
                let ref_match = object_ref.as_ref().is_none_or(|id| id == target_id);
                space_match && type_match && ref_match
            }
            (Self::Object { .. }, _) => false,

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

            // Morph selector
            (
                Self::Morph { space_id, morph_id, morph_type },
                Resource::Morph {
                    space_id: target_space,
                    morph_id: target_id,
                    morph_type: target_type,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let id_match = morph_id.as_ref().is_none_or(|id| id == target_id);
                let type_match = morph_type.as_ref().is_none_or(|t| t == target_type);
                space_match && id_match && type_match
            }
            (Self::Morph { .. }, _) => false,

            // Notification selector
            (
                Self::Notification { actor_did, notification_id },
                Resource::Notification { actor_did: target_actor, notification_id: target_id },
            ) => {
                let actor_match = actor_did == target_actor || actor_did == "*";
                let id_match = notification_id.as_ref().is_none_or(|id| id == target_id);
                actor_match && id_match
            }
            (Self::Notification { .. }, _) => false,

            // Blob selector
            (
                Self::Blob { space_id, blob_id },
                Resource::Blob { space_id: target_space, blob_id: target_id },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let id_match = blob_id.as_ref().is_none_or(|id| id == target_id);
                space_match && id_match
            }
            (Self::Blob { .. }, _) => false,

            // Event selector
            (
                Self::Event { space_id, event_kind, event_id },
                Resource::Event {
                    space_id: target_space,
                    event_kind: target_kind,
                    event_id: target_id,
                },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                let kind_match = event_kind.as_ref().is_none_or(|k| k == target_kind);
                let id_match = event_id.as_ref().is_none_or(|id| id == target_id);
                space_match && kind_match && id_match
            }
            (Self::Event { .. }, _) => false,

            // Actor selector
            (Self::Actor { actor_did }, Resource::Actor { actor_did: target_actor }) => {
                actor_did == target_actor || actor_did == "*"
            }
            (Self::Actor { .. }, _) => false,

            // Wildcard matches everything
            (Self::Wildcard, _) => true,
        }
    }

    /// Parse a resource selector from a string.
    ///
    /// Supports formats like:
    /// - "space:cx:space:..."
    /// - "object:cx:space:...:task"
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
            "flow" => {
                let (space_id, flow_id) = split_space_tail(remainder, selector)?;
                Ok(Self::Flow { space_id, flow_id })
            }
            "object" => {
                let (space_id, tail) = split_space_tail(remainder, selector)?;
                let (object_type, object_ref) = match tail {
                    None => (None, None),
                    Some(tail) if tail == "*" => (None, None),
                    Some(tail) if tail.starts_with("cx:") || tail.starts_with("did:") => {
                        (None, Some(tail))
                    }
                    Some(tail) => (Some(tail), None),
                };
                Ok(Self::Object { space_id, object_type, object_ref })
            }
            "message" => {
                let (space_id, message_id) = split_space_tail(remainder, selector)?;
                Ok(Self::Message { space_id, message_id })
            }
            "relation" => {
                let (space_id, relation_kind) = split_space_tail(remainder, selector)?;
                let Some(relation_kind) = relation_kind else {
                    return Err(Error::Protocol(format!(
                        "invalid relation selector: {}",
                        selector
                    )));
                };
                Ok(Self::Relation { space_id, relation_kind })
            }
            "view" => {
                let (space_id, view_id) = split_space_tail(remainder, selector)?;
                Ok(Self::View { space_id, view_id })
            }
            "schema" => {
                let (space_id, schema_id) = split_space_tail(remainder, selector)?;
                Ok(Self::Schema { space_id, schema_id })
            }
            "policy" => {
                let (space_id, policy_id) = split_space_tail(remainder, selector)?;
                Ok(Self::Policy { space_id, policy_id })
            }
            "invite" => {
                let (space_id, invite_id) = split_space_tail(remainder, selector)?;
                Ok(Self::Invite { space_id, invite_id })
            }
            "read_marker" => Ok(Self::ReadMarker { space_id: remainder.to_owned() }),
            "*" => Ok(Self::Wildcard),
            _ => Err(Error::Protocol(format!("unknown selector type: {}", selector))),
        }
    }
}

/// Schema-aligned resource selector kind from `cx.schema.resource_selector.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolResourceSelectorKind {
    Space,
    Flow,
    Message,
    Morph,
    Object,
    Relation,
    View,
    Event,
    Actor,
    Schema,
    Policy,
    Invite,
    Notification,
    ReadMarker,
    Blob,
    Wildcard,
}

/// Scope field from `cx.schema.resource_selector.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolResourceSelectorScope {
    Exact,
    Subtree,
    Children,
    SpaceWide,
}

/// Schema-aligned selector facade used for REST/OpenAPI/scaffold surfaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolResourceSelector {
    pub kind: ProtocolResourceSelectorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ProtocolResourceSelectorScope>,
}

impl ProtocolResourceSelector {
    /// Minimal facade conversion from the current engine selector model.
    pub fn from_engine(selector: &ResourceSelector) -> Self {
        match selector {
            ResourceSelector::Space { space_id } => Self {
                kind: ProtocolResourceSelectorKind::Space,
                space_id: Some(space_id.clone()),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
            ResourceSelector::Flow { space_id, flow_id } => Self {
                kind: ProtocolResourceSelectorKind::Flow,
                space_id: Some(space_id.clone()),
                flow_id: flow_id.clone(),
                object_type: None,
                object_ref: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
            ResourceSelector::Object { space_id, object_type, object_ref } => Self {
                kind: ProtocolResourceSelectorKind::Object,
                space_id: Some(space_id.clone()),
                object_type: object_type.clone(),
                object_ref: object_ref.clone(),
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
            ResourceSelector::Message { space_id, message_id } => Self {
                kind: ProtocolResourceSelectorKind::Message,
                space_id: Some(space_id.clone()),
                message_id: message_id.clone(),
                object_type: None,
                object_ref: None,
                flow_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
            ResourceSelector::Relation { space_id, relation_kind } => Self {
                kind: ProtocolResourceSelectorKind::Relation,
                space_id: Some(space_id.clone()),
                relation_kind: Some(relation_kind.clone()),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
            ResourceSelector::View { space_id, view_id } => Self {
                kind: ProtocolResourceSelectorKind::View,
                space_id: Some(space_id.clone()),
                view_id: view_id.clone(),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
            ResourceSelector::Schema { space_id, schema_id } => Self {
                kind: ProtocolResourceSelectorKind::Schema,
                space_id: Some(space_id.clone()),
                schema_ref: schema_id.clone(),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
            ResourceSelector::Policy { space_id, policy_id } => Self {
                kind: ProtocolResourceSelectorKind::Policy,
                space_id: Some(space_id.clone()),
                policy_id: policy_id.clone(),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
            ResourceSelector::Invite { space_id, invite_id } => Self {
                kind: ProtocolResourceSelectorKind::Invite,
                space_id: Some(space_id.clone()),
                invite_id: invite_id.clone(),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                blob_ref: None,
                scope: None,
            },
            ResourceSelector::ReadMarker { space_id } => Self {
                kind: ProtocolResourceSelectorKind::ReadMarker,
                space_id: Some(space_id.clone()),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
            _ => Self {
                kind: ProtocolResourceSelectorKind::Wildcard,
                space_id: None,
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: None,
            },
        }
    }

    /// Schema-aligned scaffold examples for new selector kinds introduced by the
    /// 2026-05-04 protocol delta.
    pub fn scaffold_examples() -> Vec<Self> {
        vec![
            Self {
                kind: ProtocolResourceSelectorKind::Event,
                space_id: Some("cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                event_id: Some("cx:event:01904100-0000-7000-8000-51495aba0a08".to_owned()),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: Some(ProtocolResourceSelectorScope::Exact),
            },
            Self {
                kind: ProtocolResourceSelectorKind::Actor,
                space_id: Some("cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                actor_id: Some("did:web:alice.example".to_owned()),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: Some(ProtocolResourceSelectorScope::Exact),
            },
            Self {
                kind: ProtocolResourceSelectorKind::Notification,
                space_id: Some("cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                actor_id: Some("did:web:alice.example".to_owned()),
                object_type: Some("device_verification".to_owned()),
                object_ref: Some("cx:notify:01JS0NT000000000000000000".to_owned()),
                flow_id: Some("cx:flow:01904100-0000-7000-8000-a1fffe3a8cc9".to_owned()),
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                scope: Some(ProtocolResourceSelectorScope::Exact),
            },
            Self {
                kind: ProtocolResourceSelectorKind::Blob,
                space_id: Some("cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                blob_ref: Some("cx:blob:sha256:0123456789abcdef".to_owned()),
                object_type: Some("encrypted_backup".to_owned()),
                object_ref: Some("backup-scaffold-current-device".to_owned()),
                flow_id: None,
                message_id: None,
                morph_id: None,
                morph_type: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                scope: Some(ProtocolResourceSelectorScope::Exact),
            },
        ]
    }
}

/// Schema-aligned constraint family from `cx.schema.grant_constraint.v1`.
///
/// v1 uses 8 stable families plus the optional `subtype` field on
/// [`ProtocolGrantConstraint`] for evaluator-specific refinements:
///
/// - `temporal.{window,edit_window,redact_window,session}`
/// - `scope_limitation.container_move`
/// - `quota.{rate,resource}`
/// - `claim_based.{claim,approval,accountability,device_session}`
/// - `confidentiality.{encryption,visibility}`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolGrantConstraintType {
    Temporal,
    FieldAccess,
    TypeRestriction,
    ScopeLimitation,
    DelegationControl,
    Quota,
    ClaimBased,
    Confidentiality,
}

/// Schema-aligned constraint effect from `cx.schema.grant_constraint.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolGrantConstraintEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

/// Schema-aligned track selector inside grant constraints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolGrantConstraintTrack {
    Synthesis,
    Discussion,
}

/// Schema-aligned approval relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolGrantApprovalRelation {
    Responsible,
    Controller,
    Guardian,
    SpaceAdmin,
    Custom,
}

/// Schema-aligned claim requirement.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolGrantClaimRequirement {
    pub claim_type: String,
    pub issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Schema-aligned grant-constraint facade used by REST/OpenAPI/scaffold surfaces.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolGrantConstraint {
    pub constraint_type: ProtocolGrantConstraintType,
    /// Optional discriminator within a family. Standard values:
    /// `claim_based.{claim,approval,accountability,device_session}`,
    /// `quota.{rate,resource}`, `confidentiality.{encryption,visibility}`,
    /// `temporal.{window,edit_window,redact_window,session}`. Implementations
    /// MAY require subtype for these families and fail closed on unknown
    /// values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtype: Option<String>,
    pub effect: ProtocolGrantConstraintEffect,
    /// Evaluation class per `constraint-schema.md` §2.1 / §2.3 — gates how
    /// aggressively the result may be cached. `Stateless` and `GrantLocal`
    /// constraints are safe for fast-path caching; `SpaceState` requires
    /// re-evaluation on every frontier change; `External` (claim, policy
    /// server) MUST NOT be cached without an explicit TTL bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_class: Option<crate::EvaluationClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields_write_allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields_write_deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_type_allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_type_deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub space_kind_allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub space_kind_deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_kind_allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_kind_deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_semantic_kind_allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_semantic_kind_deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub morph_type_allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub morph_type_deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facet_allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facet_deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_view_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_kind_allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_from_container_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_to_container_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_limit_override: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_view_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tracks: Vec<ProtocolGrantConstraintTrack>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_tracks: Vec<ProtocolGrantConstraintTrack>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_actor_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_relation: Option<ProtocolGrantApprovalRelation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_claims: Vec<ProtocolGrantClaimRequirement>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl ProtocolGrantConstraint {
    /// Schema-aligned scaffold examples for approval/claim/container-move
    /// constraints introduced or expanded by the 2026-05-04 protocol delta.
    pub fn scaffold_examples() -> Vec<Self> {
        vec![
            Self {
                constraint_type: ProtocolGrantConstraintType::ClaimBased,
                subtype: Some("claim_based.approval".to_owned()),
                effect: ProtocolGrantConstraintEffect::RequireReview,
                priority: Some(100),
                not_before: None,
                expires_at: None,
                fields_write_allow: Vec::new(),
                fields_write_deny: vec!["assignee".to_owned(), "status".to_owned()],
                object_type_allow: vec!["flow".to_owned()],
                object_type_deny: Vec::new(),
                space_kind_allow: vec!["workspace".to_owned()],
                space_kind_deny: Vec::new(),
                flow_kind_allow: vec!["task".to_owned()],
                flow_kind_deny: Vec::new(),
                flow_semantic_kind_allow: vec!["work_item".to_owned()],
                flow_semantic_kind_deny: Vec::new(),
                morph_type_allow: Vec::new(),
                morph_type_deny: Vec::new(),
                facet_allow: Vec::new(),
                facet_deny: Vec::new(),
                allowed_view_refs: vec!["cx:view:01904100-0000-7000-8000-b74ef68eeddf".to_owned()],
                relation_kind_allow: vec!["responsible".to_owned()],
                allowed_from_container_refs: Vec::new(),
                allowed_to_container_refs: Vec::new(),
                wip_limit_override: Some(false),
                denied_view_kinds: vec!["public_board".to_owned()],
                allowed_tracks: vec![ProtocolGrantConstraintTrack::Discussion],
                denied_tracks: Vec::new(),
                max_delegation_depth: Some(1),
                approval_required: Some(true),
                approval_mode: Some("two_man_rule".to_owned()),
                approval_actor_refs: vec![
                    "did:web:controller.example".to_owned(),
                    "did:web:guardian.example".to_owned(),
                ],
                approval_relation: Some(ProtocolGrantApprovalRelation::Controller),
                requires_claims: Vec::new(),
                evaluation_class: None,
                extra: BTreeMap::new(),
            },
            Self {
                constraint_type: ProtocolGrantConstraintType::ClaimBased,
                subtype: Some("claim_based.claim".to_owned()),
                effect: ProtocolGrantConstraintEffect::Allow,
                priority: Some(80),
                not_before: None,
                expires_at: None,
                fields_write_allow: Vec::new(),
                fields_write_deny: Vec::new(),
                object_type_allow: vec!["key_backup".to_owned()],
                object_type_deny: Vec::new(),
                space_kind_allow: Vec::new(),
                space_kind_deny: Vec::new(),
                flow_kind_allow: Vec::new(),
                flow_kind_deny: Vec::new(),
                flow_semantic_kind_allow: Vec::new(),
                flow_semantic_kind_deny: Vec::new(),
                morph_type_allow: Vec::new(),
                morph_type_deny: Vec::new(),
                facet_allow: vec!["recovery".to_owned()],
                facet_deny: Vec::new(),
                allowed_view_refs: Vec::new(),
                relation_kind_allow: Vec::new(),
                allowed_from_container_refs: Vec::new(),
                allowed_to_container_refs: Vec::new(),
                wip_limit_override: None,
                denied_view_kinds: Vec::new(),
                allowed_tracks: Vec::new(),
                denied_tracks: Vec::new(),
                max_delegation_depth: Some(0),
                approval_required: Some(false),
                approval_mode: None,
                approval_actor_refs: Vec::new(),
                approval_relation: None,
                requires_claims: vec![ProtocolGrantClaimRequirement {
                    claim_type: "recovery_operator".to_owned(),
                    issuer: "did:web:coauth.example".to_owned(),
                    organization: Some("example-org".to_owned()),
                    status: Some("active".to_owned()),
                    roles: vec!["backup_admin".to_owned()],
                    extra: BTreeMap::new(),
                }],
                evaluation_class: None,
                extra: BTreeMap::new(),
            },
            Self {
                constraint_type: ProtocolGrantConstraintType::ScopeLimitation,
                subtype: None,
                effect: ProtocolGrantConstraintEffect::Deny,
                priority: Some(120),
                not_before: None,
                expires_at: None,
                fields_write_allow: Vec::new(),
                fields_write_deny: Vec::new(),
                object_type_allow: vec!["flow".to_owned()],
                object_type_deny: Vec::new(),
                space_kind_allow: Vec::new(),
                space_kind_deny: Vec::new(),
                flow_kind_allow: vec!["task".to_owned()],
                flow_kind_deny: Vec::new(),
                flow_semantic_kind_allow: Vec::new(),
                flow_semantic_kind_deny: Vec::new(),
                morph_type_allow: Vec::new(),
                morph_type_deny: Vec::new(),
                facet_allow: Vec::new(),
                facet_deny: Vec::new(),
                allowed_view_refs: Vec::new(),
                relation_kind_allow: Vec::new(),
                allowed_from_container_refs: vec!["cx:list:triage".to_owned()],
                allowed_to_container_refs: vec!["cx:list:ready".to_owned()],
                wip_limit_override: Some(false),
                denied_view_kinds: Vec::new(),
                allowed_tracks: vec![ProtocolGrantConstraintTrack::Synthesis],
                denied_tracks: vec![ProtocolGrantConstraintTrack::Discussion],
                max_delegation_depth: Some(0),
                approval_required: Some(true),
                approval_mode: Some("move_gate".to_owned()),
                approval_actor_refs: vec!["did:web:ops.example".to_owned()],
                approval_relation: Some(ProtocolGrantApprovalRelation::Responsible),
                requires_claims: Vec::new(),
                evaluation_class: None,
                extra: BTreeMap::new(),
            },
        ]
    }
}

fn split_space_tail(remainder: &str, selector: &str) -> Result<(String, Option<String>)> {
    if remainder == "*" {
        return Ok(("*".to_owned(), None));
    }
    if let Some(tail) = remainder.strip_prefix("*:") {
        return Ok(("*".to_owned(), if tail.is_empty() { None } else { Some(tail.to_owned()) }));
    }

    let parts = remainder.split(':').collect::<Vec<_>>();
    if parts.len() < 3 || parts[0] != "cx" || parts[1] != "space" || parts[2].is_empty() {
        return Err(Error::Protocol(format!("invalid space-scoped selector: {selector}")));
    }
    let space_id = format!("{}:{}:{}", parts[0], parts[1], parts[2]);
    let tail = if parts.len() > 3 {
        let tail = parts[3..].join(":");
        if tail.is_empty() { None } else { Some(tail) }
    } else {
        None
    };
    Ok((space_id, tail))
}

/// Resource being accessed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// Space resource
    Space { space_id: String },
    /// Flow resource
    Flow { space_id: String, flow_id: String },
    /// Entity resource (current reducer target for task, message, document, file
    /// and other typed object payloads).
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
    /// Morph resource (canonical open-typed object).
    Morph { space_id: String, morph_id: String, morph_type: String },
    /// Notification resource (per-actor private channel).
    Notification { actor_did: String, notification_id: String },
    /// Blob resource. `space_id` may be `*` for global blobs.
    Blob { space_id: String, blob_id: String },
    /// Event resource (audit / redaction / state-resolution targets).
    Event { space_id: String, event_kind: String, event_id: String },
    /// Actor resource (account-lifecycle, profile updates).
    Actor { actor_did: String },
}

impl Resource {
    /// Get the space ID for this resource. Returns the wildcard string for
    /// non-Space-bound resources (Notification, Actor) so callers retain a
    /// consistent shape.
    pub fn space_id(&self) -> &str {
        match self {
            Self::Space { space_id } => space_id,
            Self::Flow { space_id, .. } => space_id,
            Self::Entity { space_id, .. } => space_id,
            Self::Relation { space_id, .. } => space_id,
            Self::View { space_id, .. } => space_id,
            Self::Schema { space_id, .. } => space_id,
            Self::Policy { space_id, .. } => space_id,
            Self::Invite { space_id, .. } => space_id,
            Self::ReadMarker { space_id } => space_id,
            Self::Morph { space_id, .. } => space_id,
            Self::Blob { space_id, .. } => space_id,
            Self::Event { space_id, .. } => space_id,
            Self::Notification { .. } | Self::Actor { .. } => "*",
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
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_entity_facets: Vec<EntityFacet>,
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
    },
    /// Visibility control constraint (`confidentiality{subtype=visibility}`).
    /// See `constraint-schema.md` §13.
    VisibilityControl {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        visibility_allow: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        visibility_deny: Vec<String>,
        #[serde(default = "default_false")]
        deny_redacted_history: bool,
    },
    /// Resource quota constraint (`quota{subtype=resource}`).
    /// See `constraint-schema.md` §8.2 / §14.1.
    ResourceLimit {
        #[serde(skip_serializing_if = "Option::is_none")]
        blob_max_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_total_blob_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_resources: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        period: Option<ConstraintDuration>,
        #[serde(default = "default_rate_limit_scope")]
        scope: RateLimitScope,
    },
    /// Edit / redact temporal window for messages
    /// (`temporal{subtype=edit_window}`). See `constraint-schema.md` §14.2.
    EditWindow {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        applies_to_actions: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_edit_window: Option<ConstraintDuration>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_redact_window: Option<ConstraintDuration>,
        #[serde(default = "default_false")]
        allow_redact_after_window: bool,
    },
    /// Container move scope (`scope_limitation` with container refs).
    /// See `constraint-schema.md` §6.3.
    ContainerMove {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        relation_kind_allow: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_view_refs: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_from_container_refs: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_to_container_refs: Vec<String>,
        #[serde(default = "default_false")]
        wip_limit_override: bool,
    },
    /// Generic scope limitation (`scope_limitation`).
    /// See `constraint-schema.md` §6.1 / §6.2.
    ScopeLimitation {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_flow_refs: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_flow_refs: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_tracks: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_tracks: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_view_kinds: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_view_renderers: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_view_kinds: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_view_renderers: Vec<String>,
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
    Flow,
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

#[derive(Clone, Copy)]
enum RecurrenceZone {
    Named(Tz),
    Fixed(FixedOffset),
}

impl RecurrenceZone {
    fn local_parts(&self, now: DateTime<Utc>) -> (NaiveDate, Weekday, NaiveTime) {
        match self {
            Self::Named(tz) => {
                let local = now.with_timezone(tz);
                (local.date_naive(), local.weekday(), local.time())
            }
            Self::Fixed(offset) => {
                let local = now.with_timezone(offset);
                (local.date_naive(), local.weekday(), local.time())
            }
        }
    }

    fn local_to_utc_candidates(&self, date: NaiveDate, time: NaiveTime) -> Vec<DateTime<Utc>> {
        let local = date.and_time(time);
        match self {
            Self::Named(tz) => match tz.from_local_datetime(&local) {
                LocalResult::Single(value) => vec![value.with_timezone(&Utc)],
                LocalResult::Ambiguous(first, second) => {
                    vec![first.with_timezone(&Utc), second.with_timezone(&Utc)]
                }
                LocalResult::None => Vec::new(),
            },
            Self::Fixed(offset) => match offset.from_local_datetime(&local) {
                LocalResult::Single(value) => vec![value.with_timezone(&Utc)],
                LocalResult::Ambiguous(first, second) => {
                    vec![first.with_timezone(&Utc), second.with_timezone(&Utc)]
                }
                LocalResult::None => Vec::new(),
            },
        }
    }
}

fn recurrence_allows(
    now: DateTime<Utc>,
    recurrence: &Recurrence,
) -> std::result::Result<(), String> {
    let zone = parse_recurrence_zone(recurrence.timezone.as_deref())?;
    let (_, weekday, local_time) = zone.local_parts(now);

    recurrence_frequency_allows(recurrence.frequency.as_deref(), weekday)?;

    if let Some(days) = &recurrence.days
        && !days.is_empty()
    {
        let allowed_days = days
            .iter()
            .map(|day| parse_recurrence_day(day))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !allowed_days.contains(&weekday) {
            return Err(format!("outside recurrence days: {:?}", weekday));
        }
    }

    let window_start = recurrence.window_start.as_deref().map(parse_recurrence_time).transpose()?;
    let window_end = recurrence.window_end.as_deref().map(parse_recurrence_time).transpose()?;

    if !recurrence_window_contains(local_time, window_start, window_end) {
        return Err("outside recurrence window".to_owned());
    }

    Ok(())
}

fn recurrence_next_transition_after(
    now: DateTime<Utc>,
    recurrence: &Recurrence,
) -> std::result::Result<Option<DateTime<Utc>>, String> {
    let zone = parse_recurrence_zone(recurrence.timezone.as_deref())?;
    let (local_date, _, _) = zone.local_parts(now);
    let window_start = recurrence.window_start.as_deref().map(parse_recurrence_time).transpose()?;
    let window_end = recurrence.window_end.as_deref().map(parse_recurrence_time).transpose()?;
    let has_window = window_start.is_some() || window_end.is_some();
    let has_day_boundary = has_window || recurrence_uses_day_boundaries(recurrence);
    let midnight =
        NaiveTime::from_hms_opt(0, 0, 0).expect("00:00:00 must be a valid recurrence boundary");

    let mut candidates = Vec::new();
    for day_offset in 0..=8 {
        let Some(date) = local_date.checked_add_signed(chrono::Duration::days(day_offset)) else {
            continue;
        };

        if day_offset > 0 && has_day_boundary {
            candidates.extend(zone.local_to_utc_candidates(date, midnight));
        }
        if let Some(start) = window_start {
            candidates.extend(zone.local_to_utc_candidates(date, start));
        }
        if let Some(end) = window_end {
            candidates.extend(zone.local_to_utc_candidates(date, end));
        }
    }

    Ok(candidates.into_iter().filter(|candidate| *candidate > now).min())
}

fn parse_recurrence_zone(timezone: Option<&str>) -> std::result::Result<RecurrenceZone, String> {
    let value = timezone.unwrap_or("UTC").trim();
    if value.is_empty()
        || value.eq_ignore_ascii_case("utc")
        || value.eq_ignore_ascii_case("etc/utc")
        || value == "Z"
    {
        return Ok(RecurrenceZone::Fixed(
            FixedOffset::east_opt(0).expect("zero offset must be valid"),
        ));
    }

    if let Ok(tz) = value.parse::<Tz>() {
        return Ok(RecurrenceZone::Named(tz));
    }

    parse_fixed_offset(value)
        .map(RecurrenceZone::Fixed)
        .ok_or_else(|| format!("unsupported recurrence timezone: {}", value))
}

fn parse_fixed_offset(value: &str) -> Option<FixedOffset> {
    let value = value.trim();
    let without_utc = if value.len() >= 3 && value[..3].eq_ignore_ascii_case("utc") {
        &value[3..]
    } else {
        value
    };
    let (sign, rest) = if let Some(rest) = without_utc.strip_prefix('+') {
        (1, rest)
    } else if let Some(rest) = without_utc.strip_prefix('-') {
        (-1, rest)
    } else {
        return None;
    };

    let (hours, minutes) = if let Some((hours, minutes)) = rest.split_once(':') {
        (hours.parse::<i32>().ok()?, minutes.parse::<i32>().ok()?)
    } else if rest.len() == 4 {
        (rest[..2].parse::<i32>().ok()?, rest[2..].parse::<i32>().ok()?)
    } else {
        (rest.parse::<i32>().ok()?, 0)
    };

    if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
        return None;
    }

    FixedOffset::east_opt(sign * ((hours * 60 * 60) + (minutes * 60)))
}

fn parse_recurrence_day(day: &str) -> std::result::Result<Weekday, String> {
    match day.trim().to_ascii_lowercase().as_str() {
        "mon" | "monday" | "1" => Ok(Weekday::Mon),
        "tue" | "tues" | "tuesday" | "2" => Ok(Weekday::Tue),
        "wed" | "wednesday" | "3" => Ok(Weekday::Wed),
        "thu" | "thur" | "thurs" | "thursday" | "4" => Ok(Weekday::Thu),
        "fri" | "friday" | "5" => Ok(Weekday::Fri),
        "sat" | "saturday" | "6" => Ok(Weekday::Sat),
        "sun" | "sunday" | "0" | "7" => Ok(Weekday::Sun),
        _ => Err(format!("unsupported recurrence day: {}", day)),
    }
}

fn parse_recurrence_time(value: &str) -> std::result::Result<NaiveTime, String> {
    let value = value.trim();
    NaiveTime::parse_from_str(value, "%H:%M:%S")
        .or_else(|_| NaiveTime::parse_from_str(value, "%H:%M"))
        .map_err(|_| format!("unsupported recurrence time: {}", value))
}

fn recurrence_frequency_allows(
    frequency: Option<&str>,
    weekday: Weekday,
) -> std::result::Result<(), String> {
    let Some(frequency) = frequency.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };

    match frequency.to_ascii_lowercase().as_str() {
        "always" | "daily" | "weekly" => Ok(()),
        "weekdays" => {
            if matches!(
                weekday,
                Weekday::Mon | Weekday::Tue | Weekday::Wed | Weekday::Thu | Weekday::Fri
            ) {
                Ok(())
            } else {
                Err(format!("outside weekday recurrence: {:?}", weekday))
            }
        }
        "weekends" => {
            if matches!(weekday, Weekday::Sat | Weekday::Sun) {
                Ok(())
            } else {
                Err(format!("outside weekend recurrence: {:?}", weekday))
            }
        }
        _ => Err(format!("unsupported recurrence frequency: {}", frequency)),
    }
}

fn recurrence_uses_day_boundaries(recurrence: &Recurrence) -> bool {
    recurrence.days.as_ref().is_some_and(|days| !days.is_empty())
        || recurrence.frequency.as_deref().is_some_and(|frequency| {
            matches!(frequency.trim().to_ascii_lowercase().as_str(), "weekdays" | "weekends")
        })
}

fn recurrence_window_contains(
    time: NaiveTime,
    start: Option<NaiveTime>,
    end: Option<NaiveTime>,
) -> bool {
    match (start, end) {
        (None, None) => true,
        (Some(start), None) => time >= start,
        (None, Some(end)) => time < end,
        (Some(start), Some(end)) if start == end => true,
        (Some(start), Some(end)) if start < end => time >= start && time < end,
        (Some(start), Some(end)) => time >= start || time < end,
    }
}

fn update_earliest_future(
    earliest: &mut Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    candidate: Option<DateTime<Utc>>,
) {
    if let Some(candidate) = candidate
        && candidate > now
        && earliest.is_none_or(|current| candidate < current)
    {
        *earliest = Some(candidate);
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    pub subject: Did,
    pub claim_type: String,
    pub issuer: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
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
            Constraint::VisibilityControl { .. } => ConstraintEffect::Allow,
            Constraint::ResourceLimit { .. } => ConstraintEffect::Allow,
            Constraint::EditWindow { .. } => ConstraintEffect::Allow,
            Constraint::ContainerMove { .. } => ConstraintEffect::Allow,
            Constraint::ScopeLimitation { .. } => ConstraintEffect::Allow,
        }
    }

    /// Derive the canonical [`crate::EvaluationClass`] for this constraint per
    /// `constraint-schema.md` §2.3. The class controls whether the
    /// authorization engine may use a fast-path cache:
    ///
    /// - `Stateless` — pure inputs (clock, calendar). Safe to cache.
    /// - `GrantLocal` — inputs from the grant itself. Safe to cache as long
    ///   as the cache key binds the grant id and the constraint priority.
    /// - `SpaceState` — depends on Space membership/policy/capability state.
    ///   MUST be re-evaluated on every frontier change.
    /// - `External` — depends on out-of-band signals (policy server, claim
    ///   issuer, presentation). MUST NOT be cached without explicit TTL.
    pub fn evaluation_class(&self) -> crate::EvaluationClass {
        use crate::EvaluationClass;
        match &self.constraint {
            Constraint::Temporal { .. } => EvaluationClass::Stateless,
            Constraint::FieldAccess { .. } => EvaluationClass::GrantLocal,
            Constraint::TypeRestriction { .. } => EvaluationClass::GrantLocal,
            Constraint::DelegationControl { .. } => EvaluationClass::GrantLocal,
            Constraint::RateLimiting { .. } => EvaluationClass::SpaceState,
            Constraint::ApprovalWorkflow { .. } => EvaluationClass::SpaceState,
            Constraint::ClaimBased { .. } => EvaluationClass::External,
            Constraint::Accountability { .. } => EvaluationClass::GrantLocal,
            Constraint::EncryptionRequirement { .. } => EvaluationClass::SpaceState,
            Constraint::VisibilityControl { .. } => EvaluationClass::SpaceState,
            // single-call blob_max_bytes is stateless; per-scope total is external.
            // Default to SpaceState because the SDK can't tell at type-level.
            Constraint::ResourceLimit { .. } => EvaluationClass::SpaceState,
            Constraint::EditWindow { .. } => EvaluationClass::Stateless,
            Constraint::ContainerMove { .. } => EvaluationClass::SpaceState,
            Constraint::ScopeLimitation { .. } => EvaluationClass::Stateless,
        }
    }
}

/// Status of a grant proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    /// Proposal is pending approvals.
    Pending,
    /// Proposal has been approved and the grant is active.
    Approved,
    /// Proposal was rejected.
    Rejected,
    /// Proposal expired before receiving enough approvals.
    Expired,
    /// Proposal was cancelled by the proposer.
    Cancelled,
}

/// A proposed grant that requires approval before it becomes active.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantProposal {
    /// Unique proposal ID.
    pub proposal_id: String,
    /// The proposed grant.
    pub grant: CapabilityGrant,
    /// Actor who proposed the grant.
    pub proposer: Did,
    /// Required approvers.
    pub required_approvers: Vec<Did>,
    /// Approval mode.
    pub approval_mode: ApprovalMode,
    /// Current status.
    pub status: ProposalStatus,
    /// Collected approvals.
    pub approvals: Vec<ProposalApproval>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Resolution time (when status became terminal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
}

/// An individual approval or rejection of a grant proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalApproval {
    /// The proposal this approval is for.
    pub proposal_id: String,
    /// Actor providing the approval.
    pub approver: Did,
    /// Whether this is an approval or rejection.
    pub approved: bool,
    /// Optional reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Time of the approval.
    pub created_at: DateTime<Utc>,
}

/// Manages the lifecycle of grant proposals and approvals.
#[derive(Clone, Debug, Default)]
pub struct ApprovalFlowManager {
    proposals: BTreeMap<String, GrantProposal>,
}

impl ApprovalFlowManager {
    /// Create a new approval flow manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a new grant proposal for approval.
    pub fn submit_proposal(
        &mut self,
        grant: CapabilityGrant,
        proposer: Did,
        required_approvers: Vec<Did>,
        approval_mode: ApprovalMode,
        expires_at: Option<DateTime<Utc>>,
    ) -> GrantProposal {
        let proposal_id = format!("cx:proposal:{}", grant.id);
        let proposal = GrantProposal {
            proposal_id: proposal_id.clone(),
            grant,
            proposer,
            required_approvers,
            approval_mode,
            status: ProposalStatus::Pending,
            approvals: Vec::new(),
            created_at: Utc::now(),
            expires_at,
            resolved_at: None,
        };
        self.proposals.insert(proposal_id, proposal.clone());
        proposal
    }

    /// Record an approval or rejection for a proposal.
    pub fn record_approval(
        &mut self,
        proposal_id: &str,
        approver: Did,
        approved: bool,
        reason: Option<String>,
    ) -> Result<GrantProposal> {
        let now = Utc::now();
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| Error::Protocol("proposal not found".to_owned()))?;

        if proposal.status != ProposalStatus::Pending {
            return Err(Error::Protocol(format!(
                "proposal {} is not pending (status: {:?})",
                proposal_id, proposal.status
            )));
        }

        if let Some(expires_at) = proposal.expires_at
            && now >= expires_at
        {
            proposal.status = ProposalStatus::Expired;
            proposal.resolved_at = Some(now);
            return Err(Error::Protocol("proposal has expired".to_owned()));
        }

        if !proposal.required_approvers.contains(&approver) {
            return Err(Error::Protocol(
                "approver is not in the required approvers list".to_owned(),
            ));
        }

        if proposal.approvals.iter().any(|a| a.approver == approver) {
            return Err(Error::Protocol("approver has already responded".to_owned()));
        }

        proposal.approvals.push(ProposalApproval {
            proposal_id: proposal_id.to_owned(),
            approver,
            approved,
            reason,
            created_at: now,
        });

        self.evaluate_proposal_status(proposal_id);
        Ok(self.proposals.get(proposal_id).cloned().unwrap())
    }

    /// Check if a proposal is approved.
    pub fn is_proposal_approved(&self, proposal_id: &str) -> bool {
        self.proposals.get(proposal_id).is_some_and(|p| p.status == ProposalStatus::Approved)
    }

    /// Get a proposal by ID.
    pub fn proposal(&self, proposal_id: &str) -> Option<&GrantProposal> {
        self.proposals.get(proposal_id)
    }

    /// Expire all proposals that have passed their expiration time.
    pub fn expire_proposals(&mut self) -> usize {
        let now = Utc::now();
        let expired: Vec<String> = self
            .proposals
            .iter()
            .filter(|(_, p)| {
                p.status == ProposalStatus::Pending && p.expires_at.is_some_and(|exp| now >= exp)
            })
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for proposal_id in &expired {
            if let Some(proposal) = self.proposals.get_mut(proposal_id) {
                proposal.status = ProposalStatus::Expired;
                proposal.resolved_at = Some(now);
            }
        }
        count
    }

    /// Check if a grant has been approved through a proposal.
    pub fn is_grant_approved(&self, grant_id: &str) -> bool {
        let proposal_id = format!("cx:proposal:{grant_id}");
        self.is_proposal_approved(&proposal_id)
    }

    fn evaluate_proposal_status(&mut self, proposal_id: &str) {
        let Some(proposal) = self.proposals.get(proposal_id) else {
            return;
        };

        let approvals: Vec<Did> =
            proposal.approvals.iter().filter(|a| a.approved).map(|a| a.approver.clone()).collect();
        let rejections = proposal.approvals.iter().filter(|a| !a.approved).count();

        let approved = match &proposal.approval_mode {
            ApprovalMode::Any => !approvals.is_empty(),
            ApprovalMode::All => approvals.len() >= proposal.required_approvers.len(),
            ApprovalMode::Threshold { count } => approvals.len() >= *count as usize,
            ApprovalMode::Guardian => proposal.approvals.iter().any(|a| a.approved),
            ApprovalMode::Controller => proposal.approvals.iter().any(|a| a.approved),
        };

        let Some(proposal) = self.proposals.get_mut(proposal_id) else {
            return;
        };

        if approved {
            proposal.status = ProposalStatus::Approved;
            proposal.resolved_at = Some(Utc::now());
        } else if rejections > 0 {
            // For threshold/all modes, a single rejection can veto.
            match &proposal.approval_mode {
                ApprovalMode::Any => {} // Any rejection doesn't veto in "any" mode
                _ => {
                    proposal.status = ProposalStatus::Rejected;
                    proposal.resolved_at = Some(Utc::now());
                }
            }
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
    /// Facets attached to the target entity at the current causal frontier.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entity_facets: Vec<EntityFacet>,
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
            entity_facets: Vec::new(),
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
        }
    }

    /// Set the space ID.
    pub fn with_space_id(mut self, space_id: SpaceId) -> Self {
        self.space_id = Some(space_id);
        self
    }

    /// Set target entity facets resolved at the current causal frontier.
    pub fn with_entity_facets(mut self, facets: impl IntoIterator<Item = EntityFacet>) -> Self {
        self.entity_facets = facets.into_iter().collect();
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

/// Policy-server response for `cx.policy.check`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyServerEffect {
    /// No policy restriction. This never grants access by itself.
    NoAction,
    Deny,
    Quarantine,
    RequireReview,
}

/// Interoperable request model for policy checks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyCheckRequest {
    pub operation: String,
    pub context: AuthzContext,
}

impl PolicyCheckRequest {
    pub fn new(context: AuthzContext) -> Self {
        Self { operation: "cx.policy.check".to_owned(), context }
    }
}

/// Interoperable response model for policy checks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyCheckResponse {
    pub operation: String,
    pub effect: PolicyServerEffect,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moderation_report_id: Option<String>,
}

impl PolicyCheckResponse {
    pub fn no_action() -> Self {
        Self {
            operation: "cx.policy.check".to_owned(),
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
        let cache_key = self.cache_key(ctx, grants);
        if let Some(cached) = self.cache.get(&cache_key)
            && cached.valid_until.as_ref().is_none_or(|valid| &ctx.now < valid)
        {
            return cached.decision.clone();
        }

        // Evaluate grants
        let decision = self.evaluate_grants(ctx, grants);

        // Cache the result
        self.cache_decision(cache_key, &decision, ctx, grants);

        decision
    }

    /// Check authorization against grants reduced into a `SpaceState` snapshot.
    pub fn check_authorization_from_space_state(
        &mut self,
        ctx: &AuthzContext,
        state: &crate::SpaceState,
    ) -> AuthzDecision {
        match capability_grants_from_space_state(state) {
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
        policy: &PolicyCheckResponse,
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
        if let Some(valid_from) = grant.valid_from
            && ctx.now < valid_from
        {
            return false;
        }
        if let Some(valid_until) = grant.valid_until
            && ctx.now > valid_until
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
                    && let Err(reason) = recurrence_allows(ctx.now, recurrence)
                {
                    return AuthzDecision::Deny { reason };
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
                allowed_entity_facets,
                scope_limitation,
            } => {
                if let Some(scope_limitation) = scope_limitation {
                    let scope_matches = matches!(
                        (scope_limitation, &ctx.resource),
                        (ScopeLimitation::Space, Resource::Space { .. })
                            | (ScopeLimitation::Flow, Resource::Flow { .. })
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
                    if !allowed_entity_facets.is_empty() {
                        let missing = allowed_entity_facets
                            .iter()
                            .find(|facet| !ctx.entity_facets.contains(facet));
                        if let Some(facet) = missing {
                            return AuthzDecision::Deny {
                                reason: format!(
                                    "entity facet not allowed or unavailable: {:?}",
                                    facet
                                ),
                            };
                        }
                    }
                } else if !allowed_entity_facets.is_empty() {
                    return AuthzDecision::Deny {
                        reason: "entity facet constraint requires an entity resource".to_owned(),
                    };
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
                        let claim_id_active = claim
                            .claim_id
                            .as_ref()
                            .is_none_or(|claim_id| !ctx.revoked_claim_ids.contains(claim_id));
                        let freshness_basis = claim.refreshed_at.or(claim.issued_at);
                        claim.claim_type == requirement.claim_type
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
            Constraint::VisibilityControl { visibility_allow, visibility_deny, .. } => {
                if let Some(level) = ctx.history_visibility.as_deref() {
                    if visibility_deny.iter().any(|v| v == level) {
                        return AuthzDecision::Deny {
                            reason: format!("visibility level '{}' is denied", level),
                        };
                    }
                    if !visibility_allow.is_empty() && !visibility_allow.iter().any(|v| v == level)
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
                let pick_window = if ctx.action.contains("redact") {
                    message_redact_window.as_ref()
                } else {
                    message_edit_window.as_ref()
                };
                if let Some(window) = pick_window
                    && !max_age_contains(age, window)
                {
                    if ctx.action.contains("redact") && *allow_redact_after_window {
                        return AuthzDecision::Allow;
                    }
                    return AuthzDecision::Deny {
                        reason: format!(
                            "edit/redact window {}{} elapsed",
                            window.value, window.unit
                        ),
                    };
                }
                AuthzDecision::Allow
            }
            Constraint::ContainerMove {
                relation_kind_allow,
                allowed_view_refs,
                allowed_from_container_refs,
                allowed_to_container_refs,
                wip_limit_override,
            } => {
                if !relation_kind_allow.is_empty()
                    && let Some(rk) = ctx.relation_kind.as_deref()
                    && !relation_kind_allow.iter().any(|k| k == rk)
                {
                    return AuthzDecision::Deny {
                        reason: format!("relation_kind '{}' not in allow list", rk),
                    };
                }
                if !allowed_view_refs.is_empty()
                    && let Some(view_id) = ctx.view_id.as_deref()
                    && !allowed_view_refs.iter().any(|v| v == view_id)
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
                allowed_flow_refs,
                denied_flow_refs,
                allowed_tracks,
                denied_tracks,
                allowed_view_kinds,
                allowed_view_renderers,
                denied_view_kinds,
                denied_view_renderers,
            } => {
                if let Resource::Flow { flow_id, .. } = &ctx.resource {
                    if denied_flow_refs.iter().any(|v| v == flow_id) {
                        return AuthzDecision::Deny {
                            reason: format!("flow '{}' is denied", flow_id),
                        };
                    }
                    if !allowed_flow_refs.is_empty()
                        && !allowed_flow_refs.iter().any(|v| v == flow_id)
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
            .unwrap_or_else(|_| ctx.resource.space_id().to_owned());
        let facets_digest = crate::canonical::canonical_sha256(&ctx.entity_facets)
            .unwrap_or_else(|_| format!("facet-count:{}", ctx.entity_facets.len()));
        format!(
            "{}:{}:{}:{}:{}:{:?}:{:?}:{}:{}:{}",
            ctx.actor_id,
            ctx.action,
            resource_digest,
            facets_digest,
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

        let valid_until = self.cache_valid_until(ctx, grants);
        self.cache.insert(
            key,
            CachedDecision { decision: decision.clone(), _cached_at: ctx.now, valid_until },
        );
    }

    fn cache_valid_until(
        &self,
        ctx: &AuthzContext,
        grants: &[CapabilityGrant],
    ) -> Option<DateTime<Utc>> {
        let mut valid_until = None;

        for grant in grants {
            update_earliest_future(&mut valid_until, ctx.now, grant.valid_from);
            update_earliest_future(&mut valid_until, ctx.now, grant.valid_until);
            update_earliest_future(&mut valid_until, ctx.now, grant.revoked_at);

            for entry in &grant.constraints {
                if let Constraint::Temporal { not_before, expires_at, recurrence } =
                    &entry.constraint
                {
                    update_earliest_future(&mut valid_until, ctx.now, *not_before);
                    update_earliest_future(&mut valid_until, ctx.now, *expires_at);
                    if let Some(recurrence) = recurrence
                        && let Ok(next) = recurrence_next_transition_after(ctx.now, recurrence)
                    {
                        update_earliest_future(&mut valid_until, ctx.now, next);
                    }
                }
            }
        }

        valid_until
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
    policy: &PolicyCheckResponse,
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
    policy: &PolicyCheckResponse,
    now: DateTime<Utc>,
) -> Option<ModerationReport> {
    if policy.effect == PolicyServerEffect::NoAction {
        return None;
    }
    Some(ModerationReport {
        report_id: policy
            .moderation_report_id
            .clone()
            .unwrap_or_else(|| format!("cx:moderation:{}", now.timestamp_millis())),
        policy_id: policy.policy_id.clone(),
        actor_id: ctx.actor_id.clone(),
        resource: ctx.resource.clone(),
        effect: policy.effect.clone(),
        reason: policy.reason.clone(),
        created_at: now,
    })
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFrontierValidation {
    pub checked_grants: usize,
    pub max_delegation_depth: u32,
}

/// Validate capability frontier invariants before using reduced grants.
pub fn validate_capability_frontier(
    grants: &[CapabilityGrant],
) -> Result<CapabilityFrontierValidation> {
    let mut by_id = HashMap::new();
    for grant in grants {
        if grant.id.trim().is_empty() {
            return Err(Error::Protocol("capability grant id is empty".to_owned()));
        }
        if grant.actions.is_empty() {
            return Err(Error::Protocol(format!("capability grant '{}' has no actions", grant.id)));
        }
        if grant.resources.is_empty() {
            return Err(Error::Protocol(format!(
                "capability grant '{}' has no resources",
                grant.id
            )));
        }
        if by_id.insert(grant.id.clone(), grant).is_some() {
            return Err(Error::Protocol(format!("duplicate capability grant id '{}'", grant.id)));
        }
    }

    let mut max_depth = 0;
    for grant in grants {
        let depth = validate_delegation_chain(grant, &by_id)?;
        max_depth = max_depth.max(depth);
    }

    Ok(CapabilityFrontierValidation {
        checked_grants: grants.len(),
        max_delegation_depth: max_depth,
    })
}

/// Reject unknown critical constraint objects in wire JSON before typed deserialization.
pub fn reject_unknown_critical_constraints(value: &Value, supported: &[&str]) -> Result<()> {
    let Some(constraints) = value.get("constraints").and_then(Value::as_array) else {
        return Ok(());
    };
    for constraint in constraints {
        let critical = constraint.get("critical").and_then(Value::as_bool).unwrap_or(false);
        if !critical {
            continue;
        }
        let constraint_type = constraint
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
        if !supported.iter().any(|supported| *supported == constraint_type) {
            return Err(Error::Protocol(format!("unknown critical constraint: {constraint_type}")));
        }
    }
    Ok(())
}

fn validate_delegation_chain(
    grant: &CapabilityGrant,
    by_id: &HashMap<String, &CapabilityGrant>,
) -> Result<u32> {
    let mut depth = 0;
    let mut seen = HashSet::new();
    let mut child = grant;
    while let Some(parent_id) = &child.parent_grant_id {
        if !seen.insert(child.id.clone()) {
            return Err(Error::Protocol("capability delegation cycle detected".to_owned()));
        }
        let parent = by_id.get(parent_id).ok_or_else(|| {
            Error::Protocol(format!(
                "capability grant '{}' references missing parent '{}'",
                child.id, parent_id
            ))
        })?;
        if !parent.delegable {
            return Err(Error::Protocol(format!(
                "capability parent '{}' is not delegable",
                parent.id
            )));
        }
        if child.issuer != parent.subject {
            return Err(Error::Protocol(format!(
                "capability grant '{}' issuer does not match parent subject",
                child.id
            )));
        }
        if !actions_are_narrowed(&child.actions, &parent.actions) {
            return Err(Error::Protocol(format!(
                "capability grant '{}' widens delegated actions",
                child.id
            )));
        }
        if !resources_are_narrowed(&child.resources, &parent.resources) {
            return Err(Error::Protocol(format!(
                "capability grant '{}' widens delegated resources",
                child.id
            )));
        }
        if let (Some(child_from), Some(parent_from)) = (child.valid_from, parent.valid_from)
            && child_from < parent_from
        {
            return Err(Error::Protocol(format!(
                "capability grant '{}' starts before parent",
                child.id
            )));
        }
        if let (Some(child_until), Some(parent_until)) = (child.valid_until, parent.valid_until)
            && child_until > parent_until
        {
            return Err(Error::Protocol(format!(
                "capability grant '{}' expires after parent",
                child.id
            )));
        }
        depth += 1;
        child = parent;
    }
    Ok(depth)
}

fn actions_are_narrowed(child: &[String], parent: &[String]) -> bool {
    parent.iter().any(|action| action == "*")
        || child.iter().all(|action| parent.iter().any(|parent| parent == action))
}

fn resources_are_narrowed(child: &[ResourceSelector], parent: &[ResourceSelector]) -> bool {
    child.iter().all(|child| parent.iter().any(|parent| resource_is_narrowed(child, parent)))
}

fn resource_is_narrowed(child: &ResourceSelector, parent: &ResourceSelector) -> bool {
    if matches!(parent, ResourceSelector::Wildcard) || child == parent {
        return true;
    }
    match (child, parent) {
        (
            ResourceSelector::Flow { space_id, flow_id },
            ResourceSelector::Flow { space_id: parent_space, flow_id: parent_id },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(flow_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Object { space_id, object_type, object_ref },
            ResourceSelector::Object {
                space_id: parent_space,
                object_type: parent_type,
                object_ref: parent_id,
            },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(object_type.as_ref(), parent_type.as_ref())
                && option_narrowed(object_ref.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Message { space_id, message_id },
            ResourceSelector::Message { space_id: parent_space, message_id: parent_id },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(message_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Policy { space_id, policy_id },
            ResourceSelector::Policy { space_id: parent_space, policy_id: parent_id },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(policy_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Invite { space_id, invite_id },
            ResourceSelector::Invite { space_id: parent_space, invite_id: parent_id },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(invite_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Space { space_id },
            ResourceSelector::Space { space_id: parent_space },
        ) => space_narrowed(space_id, parent_space),
        _ => false,
    }
}

fn space_narrowed(child: &str, parent: &str) -> bool {
    parent == "*" || child == parent
}

fn option_narrowed(child: Option<&String>, parent: Option<&String>) -> bool {
    match parent {
        None => true,
        Some(parent) => child.is_some_and(|child| child == parent),
    }
}

/// Extract active grant/delegate capability events from a resolved space state.
pub fn capability_grants_from_space_state(
    state: &crate::SpaceState,
) -> Result<Vec<CapabilityGrant>> {
    let mut grants = Vec::new();

    for event in state.resolved_state.values() {
        if !matches!(event.kind.as_str(), "cx.capability.grant" | "cx.capability.delegate") {
            continue;
        }
        grants.push(capability_grant_from_resolved_event(event, Some(state.space_id.clone()))?);
    }

    Ok(grants)
}

fn capability_grant_from_resolved_event(
    event: &crate::resolver::ResolvedStateEvent,
    default_space_id: Option<SpaceId>,
) -> Result<CapabilityGrant> {
    let content = event
        .content
        .as_object()
        .ok_or_else(|| Error::Protocol("capability content must be an object".to_owned()))?;
    let id = optional_string(content, "capability_id")
        .or_else(|| optional_string(content, "id"))
        .or_else(|| optional_string(content, "grant_id"))
        // Capability events carry their grant_id in payload.
        .ok_or_else(|| Error::Protocol("capability event missing grant_id / id".to_owned()))?;
    let issuer = optional_did(content, "issuer")?.unwrap_or_else(|| event.actor_id.clone());
    let subject = optional_did(content, "subject")?
        .ok_or_else(|| Error::Protocol("capability grant requires subject".to_owned()))?;
    let actions = string_array(content.get("actions"))
        .ok_or_else(|| Error::Protocol("capability grant requires actions".to_owned()))?;
    let resources =
        resource_selectors(content.get("resources").or_else(|| content.get("resource_selectors")))?
            .unwrap_or_else(|| {
                default_space_id
                    .as_ref()
                    .map(|space_id| {
                        vec![ResourceSelector::Space { space_id: space_id.as_str().to_owned() }]
                    })
                    .unwrap_or_default()
            });
    if resources.is_empty() {
        return Err(Error::Protocol("capability grant requires resources".to_owned()));
    }

    Ok(CapabilityGrant {
        id,
        space_id: optional_space_id(content, "space_id")?.or(default_space_id),
        issuer,
        subject,
        actions,
        resources,
        constraints: optional_from_value(content.get("constraints"))?.unwrap_or_default(),
        delegable: content.get("delegable").and_then(Value::as_bool).unwrap_or(false),
        parent_grant_id: optional_string(content, "parent_grant_id"),
        valid_from: optional_from_value(content.get("valid_from"))?,
        valid_until: optional_from_value(content.get("valid_until"))?,
        revoked_by: optional_did(content, "revoked_by")?,
        revoked_at: optional_from_value(content.get("revoked_at"))?,
    })
}

fn optional_string(content: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    content.get(field).and_then(Value::as_str).map(ToOwned::to_owned)
}

fn optional_did(content: &serde_json::Map<String, Value>, field: &str) -> Result<Option<Did>> {
    Ok(optional_string(content, field).map(Did::new).transpose()?)
}

fn optional_space_id(
    content: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<SpaceId>> {
    Ok(optional_string(content, field).map(SpaceId::new).transpose()?)
}

fn optional_from_value<T: serde::de::DeserializeOwned>(value: Option<&Value>) -> Result<Option<T>> {
    value.map(|value| serde_json::from_value(value.clone()).map_err(Error::from)).transpose()
}

fn string_array(value: Option<&Value>) -> Option<Vec<String>> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items.iter().filter_map(Value::as_str).map(ToOwned::to_owned).collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
}

fn resource_selectors(value: Option<&Value>) -> Result<Option<Vec<ResourceSelector>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let array = value
        .as_array()
        .ok_or_else(|| Error::Protocol("capability resources must be an array".to_owned()))?;
    let mut selectors = Vec::with_capacity(array.len());
    for item in array {
        let selector = if let Some(selector) = item.as_str() {
            ResourceSelector::parse(selector)?
        } else {
            serde_json::from_value(item.clone())?
        };
        selectors.push(selector);
    }
    Ok(Some(selectors))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, EventId, Hlc, SpaceState};
    use serde_json::json;
    use std::collections::BTreeMap;

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

    fn utc(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value).unwrap().with_timezone(&Utc)
    }

    fn ctx_at(value: &str, action: &str, resource: Resource) -> AuthzContext {
        let mut ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            action.to_owned(),
            resource,
        );
        ctx.now = utc(value);
        ctx
    }

    fn capability_event(
        event_id: &str,
        kind: &str,
        actor_seq: u64,
        hlc: &str,
        content: Value,
    ) -> Event {
        Event {
            event_id: EventId::new(event_id).unwrap(),
            kind: kind.to_owned(),
            space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            space_version: "1".to_owned(),
            actor_id: Did::new("did:web:authority.example.com").unwrap(),
            actor_seq,
            created_at: utc("2026-04-29T00:00:00Z"),
            hlc: Hlc::new(hlc).unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            schema_profile_refs: vec![],
            reducer_profile_ref: None,
            required_features: vec![],
            critical_extensions: vec![],
            redacts: None,
            content,
            unsigned: BTreeMap::new(),
            proofs: vec![],
        }
    }

    #[test]
    fn resource_selector_parse_space() {
        let selector =
            ResourceSelector::parse("space:cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        assert_eq!(
            selector,
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()
            }
        );
    }

    #[test]
    fn resource_selector_parse_object() {
        let selector =
            ResourceSelector::parse("object:cx:space:01904100-0000-7000-8000-b721a5c84b0d:task")
                .unwrap();
        assert_eq!(
            selector,
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-b721a5c84b0d".to_owned(),
                object_type: Some("task".to_owned()),
                object_ref: None,
            }
        );
    }

    #[test]
    fn flow_selector_matches_flow_resource() {
        let selector = ResourceSelector::parse(
            "flow:cx:space:01904100-0000-7000-8000-9b64700c6ee8:cx:flow:01904100-0000-7000-8000-5a9f22e193a1",
        )
        .unwrap();
        assert_eq!(
            selector,
            ResourceSelector::Flow {
                space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
                flow_id: Some("cx:flow:01904100-0000-7000-8000-5a9f22e193a1".to_owned()),
            }
        );
        assert!(selector.matches(&Resource::Flow {
            space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
            flow_id: "cx:flow:01904100-0000-7000-8000-5a9f22e193a1".to_owned(),
        }));
        assert!(!selector.matches(&Resource::Flow {
            space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
            flow_id: "cx:flow:01904100-0000-7000-8000-9c74a047a052".to_owned(),
        }));
    }

    #[test]
    fn resource_selector_parse_space_scoped_resources_with_colon_ids() {
        assert_eq!(
            ResourceSelector::parse(
                "policy:cx:space:01904100-0000-7000-8000-9b64700c6ee8:policy-main"
            )
            .unwrap(),
            ResourceSelector::Policy {
                space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
                policy_id: Some("policy-main".to_owned()),
            }
        );
        assert_eq!(
            ResourceSelector::parse(
                "relation:cx:space:01904100-0000-7000-8000-9b64700c6ee8:assigned_to"
            )
            .unwrap(),
            ResourceSelector::Relation {
                space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
                relation_kind: "assigned_to".to_owned(),
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
        let selector = ResourceSelector::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
        };
        assert!(selector.matches(&Resource::Space {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned()
        }));
        assert!(!selector.matches(&Resource::Space {
            space_id: "cx:space:01904100-0000-7000-8000-2a9d538f2fcf".to_owned()
        }));
    }

    #[test]
    fn object_selector_matches_entity() {
        let selector = ResourceSelector::Object {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            object_type: Some("task".to_owned()),
            object_ref: None,
        };
        assert!(selector.matches(&Resource::Entity {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            entity_type: "task".to_owned(),
            entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
        }));
        assert!(!selector.matches(&Resource::Entity {
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            entity_type: "message".to_owned(),
            entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
        }));
    }

    #[test]
    fn type_restriction_respects_flow_scope_limitation() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "read".to_owned(),
            Resource::Flow {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                flow_id: "cx:flow:01904100-0000-7000-8000-f571eead1fc4".to_owned(),
            },
        );
        let mut grant = grant_for(
            "read",
            ResourceSelector::Flow {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                flow_id: None,
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::TypeRestriction {
            entity_type_allow: None,
            entity_type_deny: None,
            allowed_entity_facets: vec![],
            scope_limitation: Some(ScopeLimitation::Flow),
        })];

        assert!(engine.check_authorization(&ctx, &[grant]).is_allowed());
    }

    #[test]
    fn type_restriction_requires_entity_facets_from_context() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "write".to_owned(),
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                entity_type: "task".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
            },
        )
        .with_entity_facets([EntityFacet::Stateful, EntityFacet::Rankable]);
        let mut grant = grant_for(
            "write",
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                object_type: Some("task".to_owned()),
                object_ref: None,
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::TypeRestriction {
            entity_type_allow: Some(vec!["task".to_owned()]),
            entity_type_deny: None,
            allowed_entity_facets: vec![EntityFacet::Stateful, EntityFacet::Rankable],
            scope_limitation: None,
        })];

        assert!(engine.check_authorization(&ctx, &[grant.clone()]).is_allowed());

        let missing_facet_ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "write".to_owned(),
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                entity_type: "task".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
            },
        )
        .with_entity_facets([EntityFacet::Stateful]);
        assert!(!engine.check_authorization(&missing_facet_ctx, &[grant]).is_allowed());
    }

    #[test]
    fn authz_engine_deny_without_grant() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "read".to_owned(),
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
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
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        let grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        let decision = engine.check_authorization(&ctx, &[grant]);
        assert!(decision.is_allowed());
    }

    #[test]
    fn authz_engine_deny_wrong_action() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "write".to_owned(),
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        let grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        let decision = engine.check_authorization(&ctx, &[grant]);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn authz_engine_evaluates_grants_from_space_state() {
        let mut state = SpaceState::new(
            SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            "1".to_owned(),
        );
        let grant = capability_event(
            "cx:event:01904100-0000-7000-8000-db6fcaf186ba",
            "cx.capability.grant",
            1,
            "01970e589d21-00000004-a13f9c2e",
            json!({
                "capability_id": "cap-message-send",
                "subject": "did:web:alice.example.com",
                "actions": ["message.send"],
                "resources": ["object:cx:space:01904100-0000-7000-8000-9b64700c6ee8:message"]
            }),
        );
        state.apply_events(&[grant]).unwrap();

        let ctx = ctx_at(
            "2026-04-29T01:00:00Z",
            "message.send",
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-424c57fe6d8e".to_owned(),
            },
        );

        let mut engine = AuthzEngine::new();
        assert!(engine.check_authorization_from_space_state(&ctx, &state).is_allowed());
    }

    #[test]
    fn authz_engine_denies_after_revoke_wins_in_space_state() {
        let mut state = SpaceState::new(
            SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            "1".to_owned(),
        );
        let grant = capability_event(
            "cx:event:01904100-0000-7000-8000-4fe0190ae99f",
            "cx.capability.grant",
            1,
            "01970e589d21-00000004-a13f9c2e",
            json!({
                "capability_id": "cap-message-send",
                "subject": "did:web:alice.example.com",
                "actions": ["message.send"],
                "resources": ["object:cx:space:01904100-0000-7000-8000-9b64700c6ee8:message"]
            }),
        );
        let revoke = capability_event(
            "cx:event:01904100-0000-7000-8000-a85aaf6d56fc",
            "cx.capability.revoke",
            2,
            "01970e589d22-00000004-a13f9c2e",
            json!({ "target_capability_id": "cap-message-send" }),
        );
        state.apply_events(&[grant, revoke]).unwrap();

        let ctx = ctx_at(
            "2026-04-29T01:00:00Z",
            "message.send",
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-424c57fe6d8e".to_owned(),
            },
        );

        let mut engine = AuthzEngine::new();
        assert!(!engine.check_authorization_from_space_state(&ctx, &state).is_allowed());
    }

    #[test]
    fn authz_engine_denies_after_delegate_revoke_wins_in_space_state() {
        let mut state = SpaceState::new(
            SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            "1".to_owned(),
        );
        let delegate = capability_event(
            "cx:event:01904100-0000-7000-8000-cadd1669a70a",
            "cx.capability.delegate",
            1,
            "01970e589d21-00000004-a13f9c2e",
            json!({
                "capability_id": "cap-message-delegate",
                "parent_grant_id": "cap-root",
                "subject": "did:web:alice.example.com",
                "actions": ["message.send"],
                "resources": ["object:cx:space:01904100-0000-7000-8000-9b64700c6ee8:message"]
            }),
        );
        state.apply_events(std::slice::from_ref(&delegate)).unwrap();

        let ctx = ctx_at(
            "2026-04-29T01:00:00Z",
            "message.send",
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-424c57fe6d8e".to_owned(),
            },
        );

        let mut engine = AuthzEngine::new();
        assert!(engine.check_authorization_from_space_state(&ctx, &state).is_allowed());

        let revoke = capability_event(
            "cx:event:01904100-0000-7000-8000-738d5fbe3070",
            "cx.capability.revoke",
            2,
            "01970e589d22-00000004-a13f9c2e",
            json!({ "target_capability_id": "cap-message-delegate" }),
        );
        state.apply_events(&[revoke]).unwrap();

        assert!(!engine.check_authorization_from_space_state(&ctx, &state).is_allowed());
    }

    #[test]
    fn authz_engine_denies_wrong_subject() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:bob.example.com").unwrap(),
            "read".to_owned(),
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        let grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        let decision = engine.check_authorization(&ctx, &[grant]);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn policy_server_no_action_never_grants_without_capability() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "read".to_owned(),
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        let allow_policy = PolicyCheckResponse::no_action();
        assert!(!engine.check_authorization_with_policy(&ctx, &[], &allow_policy).is_allowed());

        let grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        assert!(engine.check_authorization_with_policy(&ctx, &[grant], &allow_policy).is_allowed());
    }

    #[test]
    fn policy_server_denies_quarantines_and_reports_moderation_outcomes() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "post".to_owned(),
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-c89a39a907e5".to_owned(),
            },
        );
        let grant = grant_for(
            "post",
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                object_type: Some("message".to_owned()),
                object_ref: None,
            },
        );
        let policy = PolicyCheckResponse {
            operation: "cx.policy.check".to_owned(),
            effect: PolicyServerEffect::Quarantine,
            reason: "possible abuse".to_owned(),
            policy_id: Some("policy-abuse".to_owned()),
            moderation_report_id: Some("report-1".to_owned()),
        };

        let decision = engine.check_authorization_with_policy(&ctx, &[grant], &policy);
        assert!(matches!(decision, AuthzDecision::Quarantine { .. }));
        let report =
            moderation_report_for_policy_outcome(&ctx, &policy, utc("2026-04-29T00:00:00Z"))
                .unwrap();
        assert_eq!(report.report_id, "report-1");
        assert_eq!(report.effect, PolicyServerEffect::Quarantine);
    }

    #[test]
    fn capability_frontier_rejects_cycles_widening_and_unknown_critical_constraints() {
        let authority = Did::new("did:web:authority.example.com").unwrap();
        let alice = Did::new("did:web:alice.example.com").unwrap();
        let bob = Did::new("did:web:bob.example.com").unwrap();
        let mut root = grant_for(
            "message.send",
            ResourceSelector::Message {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                message_id: None,
            },
        );
        root.id = "root".to_owned();
        root.issuer = authority;
        root.subject = alice.clone();
        root.delegable = true;
        let child = CapabilityGrant {
            id: "child".to_owned(),
            space_id: None,
            issuer: alice,
            subject: bob,
            actions: vec!["message.send".to_owned()],
            resources: vec![ResourceSelector::Message {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                message_id: Some("message-1".to_owned()),
            }],
            constraints: Vec::new(),
            delegable: false,
            parent_grant_id: Some("root".to_owned()),
            valid_from: None,
            valid_until: None,
            revoked_by: None,
            revoked_at: None,
        };
        let validation = validate_capability_frontier(&[root.clone(), child.clone()]).unwrap();
        assert_eq!(validation.max_delegation_depth, 1);

        let mut widened = child;
        widened.actions = vec!["message.delete".to_owned()];
        assert!(validate_capability_frontier(&[root, widened]).is_err());

        let wire = json!({
            "constraints": [
                {"type": "future_constraint", "critical": true}
            ]
        });
        assert!(reject_unknown_critical_constraints(&wire, &["temporal"]).is_err());
    }

    #[test]
    fn authz_engine_temporal_constraint_expires() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "read".to_owned(),
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        let mut grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
            not_before: None,
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            recurrence: None,
        })];

        let decision = engine.check_authorization(&ctx, &[grant]);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn authz_engine_temporal_recurrence_allows_weekday_window_in_timezone() {
        let mut engine = AuthzEngine::new();
        let ctx = ctx_at(
            "2026-04-29T02:30:00Z",
            "read",
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        let mut grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
            not_before: None,
            expires_at: None,
            recurrence: Some(Recurrence {
                frequency: Some("weekly".to_owned()),
                days: Some(vec!["wed".to_owned()]),
                window_start: Some("09:00".to_owned()),
                window_end: Some("17:00".to_owned()),
                timezone: Some("Asia/Shanghai".to_owned()),
            }),
        })];

        assert!(engine.check_authorization(&ctx, &[grant]).is_allowed());
    }

    #[test]
    fn authz_engine_temporal_recurrence_denies_outside_window() {
        let mut engine = AuthzEngine::new();
        let ctx = ctx_at(
            "2026-04-29T11:30:00Z",
            "read",
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        let mut grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
            not_before: None,
            expires_at: None,
            recurrence: Some(Recurrence {
                frequency: Some("daily".to_owned()),
                days: None,
                window_start: Some("09:00".to_owned()),
                window_end: Some("17:00".to_owned()),
                timezone: Some("Asia/Shanghai".to_owned()),
            }),
        })];

        assert!(!engine.check_authorization(&ctx, &[grant]).is_allowed());
    }

    #[test]
    fn authz_engine_temporal_recurrence_allows_cross_midnight_window() {
        let mut engine = AuthzEngine::new();
        let ctx = ctx_at(
            "2026-04-29T15:30:00Z",
            "read",
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        let mut grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
            not_before: None,
            expires_at: None,
            recurrence: Some(Recurrence {
                frequency: Some("daily".to_owned()),
                days: None,
                window_start: Some("22:00".to_owned()),
                window_end: Some("06:00".to_owned()),
                timezone: Some("+08:00".to_owned()),
            }),
        })];

        assert!(engine.check_authorization(&ctx, &[grant]).is_allowed());
    }

    #[test]
    fn authz_engine_temporal_recurrence_handles_dst_boundary() {
        let mut engine = AuthzEngine::new();
        let mut grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
            not_before: None,
            expires_at: None,
            recurrence: Some(Recurrence {
                frequency: Some("weekly".to_owned()),
                days: Some(vec!["sun".to_owned()]),
                window_start: Some("01:00".to_owned()),
                window_end: Some("04:00".to_owned()),
                timezone: Some("America/New_York".to_owned()),
            }),
        })];

        let before_jump = ctx_at(
            "2026-03-08T06:30:00Z",
            "read",
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        let after_jump = ctx_at(
            "2026-03-08T07:30:00Z",
            "read",
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        assert!(engine.check_authorization(&before_jump, &[grant.clone()]).is_allowed());
        assert!(engine.check_authorization(&after_jump, &[grant]).is_allowed());
    }

    #[test]
    fn authz_cache_expires_at_temporal_boundaries() {
        let mut engine = AuthzEngine::new();
        let mut grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::Temporal {
            not_before: None,
            expires_at: Some(utc("2026-04-29T03:00:00Z")),
            recurrence: None,
        })];

        let before_expiry = ctx_at(
            "2026-04-29T02:30:00Z",
            "read",
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        let after_expiry = ctx_at(
            "2026-04-29T03:30:00Z",
            "read",
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        assert!(engine.check_authorization(&before_expiry, &[grant.clone()]).is_allowed());
        assert!(!engine.check_authorization(&after_expiry, &[grant]).is_allowed());
    }

    #[test]
    fn authz_cache_rechecks_future_not_before_grants() {
        let mut engine = AuthzEngine::new();
        let mut grant = grant_for(
            "read",
            ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        grant.valid_from = Some(utc("2026-04-29T03:00:00Z"));

        let before_valid = ctx_at(
            "2026-04-29T02:30:00Z",
            "read",
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );
        let after_valid = ctx_at(
            "2026-04-29T03:30:00Z",
            "read",
            Resource::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            },
        );

        assert!(!engine.check_authorization(&before_valid, &[grant.clone()]).is_allowed());
        assert!(engine.check_authorization(&after_valid, &[grant]).is_allowed());
    }

    #[test]
    fn authz_engine_field_access_deny() {
        let mut engine = AuthzEngine::new();
        let mut ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "update".to_owned(),
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                entity_type: "task".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
            },
        );
        ctx.write_fields = vec!["id".to_owned(), "title".to_owned()];

        let mut grant = grant_for(
            "update",
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                object_type: Some("task".to_owned()),
                object_ref: None,
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
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
            },
        )
        .with_delegation_depth(2)
        .with_rate_limit_count(3)
        .with_accountability_logged(true)
        .with_encryption_level("mls_rfc9420")
        .with_verified_claim(VerifiedClaim {
            claim_id: None,
            subject: Did::new("did:web:alice.example.com").unwrap(),
            claim_type: "employee".to_owned(),
            issuer: Did::new("did:web:issuer.example.com").unwrap(),
            organization: Some(Did::new("did:web:org.example.com").unwrap()),
            status: Some("active".to_owned()),
            roles: vec!["writer".to_owned()],
            issued_at: None,
            expires_at: None,
            revoked_at: None,
            refreshed_at: None,
        });
        let mut grant = grant_for(
            "send",
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                object_type: Some("message".to_owned()),
                object_ref: None,
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
            }),
        ];

        assert!(engine.check_authorization(&ctx, &[grant]).is_allowed());
    }

    #[test]
    fn authz_claim_constraints_fail_closed_on_subject_time_and_revocation() {
        let mut engine = AuthzEngine::new();
        let base_claim = VerifiedClaim {
            claim_id: Some("claim-1".to_owned()),
            subject: Did::new("did:web:alice.example.com").unwrap(),
            claim_type: "employee".to_owned(),
            issuer: Did::new("did:web:issuer.example.com").unwrap(),
            organization: None,
            status: Some("active".to_owned()),
            roles: vec![],
            issued_at: Some(utc("2026-04-28T00:00:00Z")),
            expires_at: Some(utc("2026-04-30T00:00:00Z")),
            revoked_at: None,
            refreshed_at: None,
        };
        let ctx = ctx_at(
            "2026-04-29T00:00:00Z",
            "send",
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
            },
        )
        .with_verified_claim(base_claim.clone());
        let mut grant = grant_for(
            "send",
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                object_type: Some("message".to_owned()),
                object_ref: None,
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::ClaimBased {
            requires_claims: vec![ClaimRequirement {
                claim_type: "employee".to_owned(),
                issuer: None,
                organization: None,
                status: Some("active".to_owned()),
                roles: None,
            }],
            trusted_issuers: vec![Did::new("did:web:issuer.example.com").unwrap()],
            claim_refresh_required: false,
            claim_max_age: Some(ConstraintDuration { value: 2, unit: "d".to_owned() }),
        })];

        assert!(engine.check_authorization(&ctx, &[grant.clone()]).is_allowed());
        let revoked_ctx = ctx.clone().with_revoked_claim_id("claim-1");
        assert!(!engine.check_authorization(&revoked_ctx, &[grant.clone()]).is_allowed());

        let mut wrong_subject = base_claim;
        wrong_subject.subject = Did::new("did:web:bob.example.com").unwrap();
        let wrong_subject_ctx = ctx_at(
            "2026-04-29T00:00:00Z",
            "send",
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
            },
        )
        .with_verified_claim(wrong_subject);
        assert!(!engine.check_authorization(&wrong_subject_ctx, &[grant]).is_allowed());
    }

    #[test]
    fn authz_engine_denies_missing_encryption() {
        let mut engine = AuthzEngine::new();
        let ctx = AuthzContext::new(
            Did::new("did:web:alice.example.com").unwrap(),
            "send".to_owned(),
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
            },
        );
        let mut grant = grant_for(
            "send",
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                object_type: Some("message".to_owned()),
                object_ref: None,
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::EncryptionRequirement {
            encryption_required: true,
            min_encryption_level: Some("mls_rfc9420".to_owned()),
        })];

        assert!(!engine.check_authorization(&ctx, &[grant]).is_allowed());
    }

    #[test]
    fn approval_flow_manager_submits_records_and_resolves_proposals() {
        let mut manager = ApprovalFlowManager::new();
        let proposer = Did::new("did:web:alice.example.com").unwrap();
        let approver1 = Did::new("did:web:bob.example.com").unwrap();
        let approver2 = Did::new("did:web:carol.example.com").unwrap();

        let mut grant = grant_for(
            "send",
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                object_type: Some("message".to_owned()),
                object_ref: None,
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::ApprovalWorkflow {
            approval_required: true,
            approval_actor_refs: Some(vec![approver1.clone(), approver2.clone()]),
            timeout: None,
            approval_mode: Some(ApprovalMode::All),
            approval_relation: None,
            guardian_approval_required: false,
            controller_approval_required: false,
        })];

        let proposal = manager.submit_proposal(
            grant.clone(),
            proposer,
            vec![approver1.clone(), approver2.clone()],
            ApprovalMode::All,
            None,
        );
        assert_eq!(proposal.status, ProposalStatus::Pending);

        // First approval is not enough for ApprovalMode::All.
        let updated =
            manager.record_approval(&proposal.proposal_id, approver1, true, None).unwrap();
        assert_eq!(updated.status, ProposalStatus::Pending);
        assert!(!manager.is_grant_approved(&grant.id));

        // Second approval completes the proposal.
        let updated =
            manager.record_approval(&proposal.proposal_id, approver2, true, None).unwrap();
        assert_eq!(updated.status, ProposalStatus::Approved);
        assert!(manager.is_grant_approved(&grant.id));
    }

    #[test]
    fn approval_flow_rejects_unauthorized_approvers_and_duplicate_responses() {
        let mut manager = ApprovalFlowManager::new();
        let proposer = Did::new("did:web:alice.example.com").unwrap();
        let approver = Did::new("did:web:bob.example.com").unwrap();
        let outsider = Did::new("did:web:eve.example.com").unwrap();

        let grant = grant_for(
            "send",
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                object_type: Some("message".to_owned()),
                object_ref: None,
            },
        );

        let proposal = manager.submit_proposal(
            grant,
            proposer,
            vec![approver.clone()],
            ApprovalMode::Any,
            None,
        );

        // Outsider cannot approve.
        assert!(manager.record_approval(&proposal.proposal_id, outsider, true, None).is_err());

        // Approver can approve once.
        assert!(
            manager.record_approval(&proposal.proposal_id, approver.clone(), true, None).is_ok()
        );

        // Duplicate response is rejected.
        assert!(manager.record_approval(&proposal.proposal_id, approver, true, None).is_err());
    }

    #[test]
    fn authz_engine_filters_unapproved_grants_with_approval_flow() {
        let mut engine = AuthzEngine::new();
        let mut approvals = ApprovalFlowManager::new();
        let proposer = Did::new("did:web:alice.example.com").unwrap();
        let approver = Did::new("did:web:bob.example.com").unwrap();

        let ctx = ctx_at(
            "2026-04-29T12:00:00Z",
            "send",
            Resource::Entity {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                entity_type: "message".to_owned(),
                entity_id: "cx:entity:01904100-0000-7000-8000-20ec63a5423d".to_owned(),
            },
        );

        let mut grant = grant_for(
            "send",
            ResourceSelector::Object {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
                object_type: Some("message".to_owned()),
                object_ref: None,
            },
        );
        grant.constraints = vec![ConstraintEntry::new(Constraint::ApprovalWorkflow {
            approval_required: true,
            approval_actor_refs: Some(vec![approver.clone()]),
            timeout: None,
            approval_mode: Some(ApprovalMode::Any),
            approval_relation: None,
            guardian_approval_required: false,
            controller_approval_required: false,
        })];

        // Without approval, the grant is filtered out.
        let decision =
            engine.check_authorization_with_approvals(&ctx, &[grant.clone()], &approvals);
        assert!(!decision.is_allowed());

        // Submit and approve the proposal.
        let proposal = approvals.submit_proposal(
            grant.clone(),
            proposer,
            vec![approver.clone()],
            ApprovalMode::Any,
            None,
        );
        approvals.record_approval(&proposal.proposal_id, approver, true, None).unwrap();

        // With approval, the grant is included.
        let decision = engine.check_authorization_with_approvals(&ctx, &[grant], &approvals);
        assert!(decision.is_allowed());
    }
}
