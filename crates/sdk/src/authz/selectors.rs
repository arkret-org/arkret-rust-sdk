use super::*;

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
    /// Generic object selector.
    Object { space_id: String, object_type: Option<String>, object_ref: Option<String> },
    /// Message selector.
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
    ReadCursor { space_id: String },
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
    /// CXP-0007 (R3 spec-sync 2026-05-27) — Circle selector. Matches a
    /// specific Circle by its `cx:circle:<uuid>` identifier. The Circle
    /// is scoped to its parent Realm; cross-Realm selectors MUST be
    /// rejected by the resolver (`circle_realm_mismatch`).
    Circle { circle_id: contrix_core::CircleId },
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

            // Message selector
            (
                Self::Message { space_id, message_id },
                Resource::Message { space_id: target_space, message_id: target_id },
            ) => {
                let space_match = space_id == target_space || space_id == "*";
                space_match && message_id.as_ref().is_none_or(|id| id == target_id)
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
            (Self::ReadCursor { space_id }, Resource::ReadCursor { space_id: target_space }) => {
                space_id == target_space || space_id == "*"
            }
            (Self::ReadCursor { .. }, _) => false,

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

            // Circle selector
            (Self::Circle { circle_id }, Resource::Circle { circle_id: target_id }) => {
                circle_id == target_id
            }
            (Self::Circle { .. }, _) => false,

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
            "read_cursor" => Ok(Self::ReadCursor { space_id: remainder.to_owned() }),
            "circle" => {
                // Accept either `circle:cx:circle:<uuid>` (typed) or bare
                // `circle:<uuid>` (parser tail).
                let raw = if remainder.starts_with("cx:circle:") {
                    remainder.to_owned()
                } else {
                    format!("cx:circle:{remainder}")
                };
                let circle_id = contrix_core::CircleId::new(raw)
                    .map_err(|err| Error::Protocol(format!("invalid circle selector: {err}")))?;
                Ok(Self::Circle { circle_id })
            }
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
    ReadCursor,
    Blob,
    /// CXP-0007 (R3 spec-sync 2026-05-27).
    Circle,
    Wildcard,
}

/// Scope field from `cx.schema.resource_selector.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolResourceSelectorScope {
    Exact,
    Subtree,
    Children,
    RealmWide,
}

/// Schema-aligned selector facade used for REST/OpenAPI/scaffold surfaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolResourceSelector {
    pub kind: ProtocolResourceSelectorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<String>,
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
    pub match_scope: Option<ProtocolResourceSelectorScope>,
}

impl ProtocolResourceSelector {
    /// Minimal facade conversion from the current engine selector model.
    pub fn from_engine(selector: &ResourceSelector) -> Self {
        match selector {
            ResourceSelector::Space { space_id } => Self {
                kind: ProtocolResourceSelectorKind::Space,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::Flow { space_id, flow_id } => Self {
                kind: ProtocolResourceSelectorKind::Flow,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::Object { space_id, object_type, object_ref } => Self {
                kind: ProtocolResourceSelectorKind::Object,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::Message { space_id, message_id } => Self {
                kind: ProtocolResourceSelectorKind::Message,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::Relation { space_id, relation_kind } => Self {
                kind: ProtocolResourceSelectorKind::Relation,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::View { space_id, view_id } => Self {
                kind: ProtocolResourceSelectorKind::View,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::Schema { space_id, schema_id } => Self {
                kind: ProtocolResourceSelectorKind::Schema,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::Policy { space_id, policy_id } => Self {
                kind: ProtocolResourceSelectorKind::Policy,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::Invite { space_id, invite_id } => Self {
                kind: ProtocolResourceSelectorKind::Invite,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::ReadCursor { space_id } => Self {
                kind: ProtocolResourceSelectorKind::ReadCursor,
                space_id: Some(space_id.clone()),
                circle_id: None,
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
                match_scope: None,
            },
            ResourceSelector::Morph { space_id, morph_id, morph_type } => Self {
                kind: ProtocolResourceSelectorKind::Morph,
                space_id: Some(space_id.clone()),
                circle_id: None,
                morph_id: morph_id.clone(),
                morph_type: morph_type.clone(),
                object_type: None,
                object_ref: None,
                flow_id: None,
                message_id: None,
                relation_kind: None,
                relation_id: None,
                view_id: None,
                event_id: None,
                actor_id: None,
                schema_ref: None,
                policy_id: None,
                invite_id: None,
                blob_ref: None,
                match_scope: None,
            },
            ResourceSelector::Notification { actor_did, notification_id } => Self {
                kind: ProtocolResourceSelectorKind::Notification,
                space_id: None,
                circle_id: None,
                actor_id: Some(actor_did.clone()),
                object_ref: notification_id.clone(),
                object_type: None,
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
                match_scope: None,
            },
            ResourceSelector::Blob { space_id, blob_id } => Self {
                kind: ProtocolResourceSelectorKind::Blob,
                space_id: Some(space_id.clone()),
                circle_id: None,
                blob_ref: blob_id.clone(),
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
                match_scope: None,
            },
            ResourceSelector::Event { space_id, event_kind, event_id } => Self {
                kind: ProtocolResourceSelectorKind::Event,
                space_id: Some(space_id.clone()),
                circle_id: None,
                object_type: event_kind.clone(),
                event_id: event_id.clone(),
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
                match_scope: None,
            },
            ResourceSelector::Actor { actor_did } => Self {
                kind: ProtocolResourceSelectorKind::Actor,
                space_id: None,
                circle_id: None,
                actor_id: Some(actor_did.clone()),
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
                match_scope: None,
            },
            ResourceSelector::Circle { circle_id } => Self {
                kind: ProtocolResourceSelectorKind::Circle,
                space_id: None,
                circle_id: Some(circle_id.to_string()),
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
                match_scope: None,
            },
            ResourceSelector::Wildcard => Self {
                kind: ProtocolResourceSelectorKind::Wildcard,
                space_id: None,
                circle_id: None,
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
                match_scope: None,
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
                circle_id: None,
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
                match_scope: Some(ProtocolResourceSelectorScope::Exact),
            },
            Self {
                kind: ProtocolResourceSelectorKind::Actor,
                space_id: Some("cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                circle_id: None,
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
                match_scope: Some(ProtocolResourceSelectorScope::Exact),
            },
            Self {
                kind: ProtocolResourceSelectorKind::Notification,
                space_id: Some("cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                circle_id: None,
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
                match_scope: Some(ProtocolResourceSelectorScope::Exact),
            },
            Self {
                kind: ProtocolResourceSelectorKind::Blob,
                space_id: Some("cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                circle_id: None,
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
                match_scope: Some(ProtocolResourceSelectorScope::Exact),
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
