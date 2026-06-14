use super::*;

/// Authorization decision result produced by the runtime `AuthzEngine`.
///
/// Named `EngineDecision` (not `AuthzDecision`) to avoid colliding with
/// the wire enum `model::AuthzDecision` re-exported at the umbrella crate
/// root; this runtime type additionally carries a human-readable `reason`
/// and is never serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineDecision {
    /// Operation is allowed
    Allow,
    /// Operation is denied
    Deny { reason: String },
    /// Operation requires additional review
    RequireReview { reason: String },
    /// Operation should be quarantined
    Quarantine { reason: String },
}

impl EngineDecision {
    /// Check if the decision allows the operation.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Resource selector for capability grants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceSelector {
    /// Realm selector.
    Realm { realm_id: String },
    /// Space selector.
    Space { space_id: String },
    /// Strand selector (strand_id)
    Strand {
        realm_id: String,
        strand_id: Option<String>,
    },
    /// Generic object selector.
    Object {
        realm_id: String,
        object_type: Option<String>,
        object_ref: Option<String>,
    },
    /// Message selector.
    Message {
        realm_id: String,
        message_id: Option<String>,
    },
    /// Relation selector
    Relation {
        realm_id: String,
        relation_kind: String,
    },
    /// View selector
    View {
        realm_id: String,
        view_id: Option<String>,
    },
    /// Schema selector
    Schema {
        realm_id: String,
        schema_id: Option<String>,
    },
    /// Policy selector
    Policy {
        realm_id: String,
        policy_id: Option<String>,
    },
    /// Invite selector
    Invite {
        realm_id: String,
        invite_id: Option<String>,
    },
    /// Read marker selector
    ReadCursor { realm_id: String },
    /// Morph selector — `morph_type` is the canonical filter per
    /// `resource-selector-grammar.md` §6 (matches by exact type name).
    Morph {
        realm_id: String,
        morph_id: Option<String>,
        morph_type: Option<String>,
    },
    /// Notification selector (per-actor private). `actor_id` may be `*`.
    Notification {
        actor_id: String,
        notification_id: Option<String>,
    },
    /// Blob selector. `realm_id` MAY be `*` for global blobs (e.g. avatars).
    Blob {
        realm_id: String,
        blob_id: Option<String>,
    },
    /// Event selector (audit/redaction). Matches by event kind / id.
    Event {
        realm_id: String,
        event_kind: Option<String>,
        event_id: Option<String>,
    },
    /// Actor selector (e.g. account-lifecycle, profile updates).
    Actor { actor_id: String },
    /// CKP-0007 (R3 spec-sync 2026-05-27) — Circle selector. Matches a
    /// specific Circle by its `ck:circle:<uuid>` identifier. The Circle
    /// is scoped to its parent Realm; cross-Realm selectors MUST be
    /// rejected by the resolver (`circle_realm_mismatch`).
    Circle { circle_id: cokret_core::CircleId },
    /// Wildcard selector (all resources)
    Wildcard,
}

impl ResourceSelector {
    /// Check if this selector matches a target resource.
    pub fn matches(&self, resource: &Resource) -> bool {
        match (self, resource) {
            (
                Self::Realm { realm_id },
                Resource::Realm {
                    realm_id: target_id,
                },
            ) => realm_id == target_id || realm_id == "*",
            (Self::Realm { realm_id }, resource) => {
                let target_realm = resource.realm_id();
                realm_id == target_realm || realm_id == "*"
            }

            // Space selector
            (
                Self::Space { space_id },
                Resource::Space {
                    space_id: target_id,
                },
            ) => space_id == target_id || space_id == "*",
            (Self::Space { .. }, _) => false,

            // Strand selector
            (
                Self::Strand { realm_id, strand_id },
                Resource::Strand {
                    realm_id: target_realm,
                    strand_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let id_match = strand_id.as_ref().is_none_or(|id| id == target_id);
                realm_match && id_match
            }
            (Self::Strand { .. }, _) => false,

            // Object selector
            (
                Self::Object {
                    realm_id,
                    object_type,
                    object_ref,
                },
                Resource::Strand {
                    realm_id: target_realm,
                    strand_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let type_match = object_type.as_ref().is_none_or(|t| t == "strand");
                let ref_match = object_ref.as_ref().is_none_or(|id| id == target_id);
                realm_match && type_match && ref_match
            }
            (
                Self::Object {
                    realm_id,
                    object_type,
                    object_ref,
                },
                Resource::Morph {
                    realm_id: target_realm,
                    morph_id: target_id,
                    morph_type: target_type,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let type_match = object_type.as_ref().is_none_or(|t| t == target_type);
                let ref_match = object_ref.as_ref().is_none_or(|id| id == target_id);
                realm_match && type_match && ref_match
            }
            (Self::Object { .. }, _) => false,

            // Message selector
            (
                Self::Message {
                    realm_id,
                    message_id,
                },
                Resource::Message {
                    realm_id: target_realm,
                    message_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                realm_match && message_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Message { .. }, _) => false,

            // Relation selector
            (
                Self::Relation {
                    realm_id,
                    relation_kind,
                },
                Resource::Relation {
                    realm_id: target_realm,
                    relation_kind: target_kind,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                realm_match && relation_kind == target_kind
            }
            (Self::Relation { .. }, _) => false,

            // View selector
            (
                Self::View { realm_id, view_id },
                Resource::View {
                    realm_id: target_realm,
                    view_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let id_match = view_id.as_ref().is_none_or(|id| id == target_id);
                realm_match && id_match
            }
            (Self::View { .. }, _) => false,

            // Schema selector
            (
                Self::Schema {
                    realm_id,
                    schema_id,
                },
                Resource::Schema {
                    realm_id: target_realm,
                    schema_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                realm_match && schema_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Schema { .. }, _) => false,

            // Policy selector
            (
                Self::Policy {
                    realm_id,
                    policy_id,
                },
                Resource::Policy {
                    realm_id: target_realm,
                    policy_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                realm_match && policy_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Policy { .. }, _) => false,

            // Invite selector
            (
                Self::Invite {
                    realm_id,
                    invite_id,
                },
                Resource::Invite {
                    realm_id: target_realm,
                    invite_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                realm_match && invite_id.as_ref().is_none_or(|id| id == target_id)
            }
            (Self::Invite { .. }, _) => false,

            // Read marker selector
            (
                Self::ReadCursor { realm_id },
                Resource::ReadCursor {
                    realm_id: target_realm,
                },
            ) => realm_id == target_realm || realm_id == "*",
            (Self::ReadCursor { .. }, _) => false,

            // Morph selector
            (
                Self::Morph {
                    realm_id,
                    morph_id,
                    morph_type,
                },
                Resource::Morph {
                    realm_id: target_realm,
                    morph_id: target_id,
                    morph_type: target_type,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let id_match = morph_id.as_ref().is_none_or(|id| id == target_id);
                let type_match = morph_type.as_ref().is_none_or(|t| t == target_type);
                realm_match && id_match && type_match
            }
            (Self::Morph { .. }, _) => false,

            // Notification selector
            (
                Self::Notification {
                    actor_id,
                    notification_id,
                },
                Resource::Notification {
                    actor_id: target_actor,
                    notification_id: target_id,
                },
            ) => {
                let actor_match = actor_id == target_actor || actor_id == "*";
                let id_match = notification_id.as_ref().is_none_or(|id| id == target_id);
                actor_match && id_match
            }
            (Self::Notification { .. }, _) => false,

            // Blob selector
            (
                Self::Blob { realm_id, blob_id },
                Resource::Blob {
                    realm_id: target_realm,
                    blob_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let id_match = blob_id.as_ref().is_none_or(|id| id == target_id);
                realm_match && id_match
            }
            (Self::Blob { .. }, _) => false,

            // Event selector
            (
                Self::Event {
                    realm_id,
                    event_kind,
                    event_id,
                },
                Resource::Event {
                    realm_id: target_realm,
                    event_kind: target_kind,
                    event_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let kind_match = event_kind.as_ref().is_none_or(|k| k == target_kind);
                let id_match = event_id.as_ref().is_none_or(|id| id == target_id);
                realm_match && kind_match && id_match
            }
            (Self::Event { .. }, _) => false,

            // Actor selector
            (
                Self::Actor { actor_id },
                Resource::Actor {
                    actor_id: target_actor,
                },
            ) => actor_id == target_actor || actor_id == "*",
            (Self::Actor { .. }, _) => false,

            // Circle selector
            (
                Self::Circle { circle_id },
                Resource::Circle {
                    circle_id: target_id,
                },
            ) => circle_id == target_id,
            (Self::Circle { .. }, _) => false,

            // Wildcard matches everything
            (Self::Wildcard, _) => true,
        }
    }

    /// Parse a spec-shaped selector object (`resource-selector.schema.json`:
    /// `{"kind": "...", ...}`) into the engine selector model. String values
    /// fall back to the legacy compact grammar via [`Self::parse`].
    ///
    /// This is the wire → engine direction used when projecting a
    /// [`cokret_core::CapabilityGrant`] (whose `resources` are untyped spec
    /// values) for evaluation. Unknown `kind` values fail closed.
    pub fn from_spec_value(value: &Value) -> Result<Self> {
        if let Some(selector) = value.as_str() {
            return Self::parse(selector);
        }
        let object = value.as_object().ok_or_else(|| {
            Error::Protocol("resource selector must be an object or string".to_owned())
        })?;
        let field = |name: &str| -> Option<String> {
            object
                .get(name)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let realm_or_wildcard = || field("realm_id").unwrap_or_else(|| "*".to_owned());
        let kind = field("kind")
            .ok_or_else(|| Error::Protocol("resource selector requires 'kind'".to_owned()))?;
        match kind.as_str() {
            "realm" => Ok(Self::Realm {
                realm_id: realm_or_wildcard(),
            }),
            "space" => Ok(Self::Space {
                space_id: field("space_id").unwrap_or_else(|| "*".to_owned()),
            }),
            "circle" => {
                let raw = field("circle_id").ok_or_else(|| {
                    Error::Protocol("circle selector requires circle_id".to_owned())
                })?;
                let circle_id = cokret_core::CircleId::new(raw)
                    .map_err(|err| Error::Protocol(format!("invalid circle selector: {err}")))?;
                Ok(Self::Circle { circle_id })
            }
            "strand" => Ok(Self::Strand {
                realm_id: realm_or_wildcard(),
                strand_id: field("strand_id"),
            }),
            "message" => Ok(Self::Message {
                realm_id: realm_or_wildcard(),
                message_id: field("message_id"),
            }),
            "morph" => Ok(Self::Morph {
                realm_id: realm_or_wildcard(),
                morph_id: field("morph_id"),
                morph_type: field("morph_type"),
            }),
            "object" => Ok(Self::Object {
                realm_id: realm_or_wildcard(),
                object_type: field("object_type"),
                object_ref: field("object_ref"),
            }),
            "relation" => Ok(Self::Relation {
                realm_id: realm_or_wildcard(),
                relation_kind: field("relation_kind").ok_or_else(|| {
                    Error::Protocol("relation selector requires relation_kind".to_owned())
                })?,
            }),
            "view" => Ok(Self::View {
                realm_id: realm_or_wildcard(),
                view_id: field("view_id"),
            }),
            // The spec selector schema has no dedicated event-kind field;
            // mirror `ProtocolResourceSelector::from_engine`, which rides the
            // event kind in `object_type`.
            "event" => Ok(Self::Event {
                realm_id: realm_or_wildcard(),
                event_kind: field("object_type"),
                event_id: field("event_id"),
            }),
            "actor" => Ok(Self::Actor {
                actor_id: field("actor_id").ok_or_else(|| {
                    Error::Protocol("actor selector requires actor_id".to_owned())
                })?,
            }),
            "schema" => Ok(Self::Schema {
                realm_id: realm_or_wildcard(),
                schema_id: field("schema_ref"),
            }),
            "policy" => Ok(Self::Policy {
                realm_id: realm_or_wildcard(),
                policy_id: field("policy_id"),
            }),
            "invite" => Ok(Self::Invite {
                realm_id: realm_or_wildcard(),
                invite_id: field("invite_id"),
            }),
            // Spec: notification selectors are realm-scoped and *-only on the
            // object part. The engine notification resource is keyed by
            // actor; absent actor_id means any actor in scope.
            "notification" => Ok(Self::Notification {
                actor_id: field("actor_id").unwrap_or_else(|| "*".to_owned()),
                notification_id: None,
            }),
            "read_cursor" => Ok(Self::ReadCursor {
                realm_id: field("realm_id").ok_or_else(|| {
                    Error::Protocol("read_cursor selector requires realm_id".to_owned())
                })?,
            }),
            "blob" => Ok(Self::Blob {
                realm_id: realm_or_wildcard(),
                blob_id: field("blob_ref"),
            }),
            "*" => Ok(Self::Wildcard),
            other => Err(Error::Protocol(format!(
                "unknown resource selector kind: {other}"
            ))),
        }
    }

    /// Serialize this selector into the spec object form
    /// (`resource-selector.schema.json`). Wildcard realm/actor parts (`"*"`)
    /// are emitted by omitting the field, matching the schema's optionality
    /// semantics.
    pub fn to_spec_value(&self) -> Value {
        let mut object = serde_json::Map::new();
        let mut put = |key: &str, value: &str| {
            object.insert(key.to_owned(), Value::String(value.to_owned()));
        };
        let put_opt =
            |object: &mut serde_json::Map<String, Value>, key: &str, value: &Option<String>| {
                if let Some(value) = value {
                    object.insert(key.to_owned(), Value::String(value.clone()));
                }
            };
        match self {
            Self::Realm { realm_id } => {
                put("kind", "realm");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
            }
            Self::Space { space_id } => {
                put("kind", "space");
                if space_id != "*" {
                    put("space_id", space_id);
                }
            }
            Self::Circle { circle_id } => {
                put("kind", "circle");
                put("circle_id", circle_id.as_ref());
            }
            Self::Strand { realm_id, strand_id } => {
                put("kind", "strand");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "strand_id", strand_id);
            }
            Self::Message {
                realm_id,
                message_id,
            } => {
                put("kind", "message");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "message_id", message_id);
            }
            Self::Morph {
                realm_id,
                morph_id,
                morph_type,
            } => {
                put("kind", "morph");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "morph_id", morph_id);
                put_opt(&mut object, "morph_type", morph_type);
            }
            Self::Object {
                realm_id,
                object_type,
                object_ref,
            } => {
                put("kind", "object");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "object_type", object_type);
                put_opt(&mut object, "object_ref", object_ref);
            }
            Self::Relation {
                realm_id,
                relation_kind,
            } => {
                put("kind", "relation");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put("relation_kind", relation_kind);
            }
            Self::View { realm_id, view_id } => {
                put("kind", "view");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "view_id", view_id);
            }
            Self::Event {
                realm_id,
                event_kind,
                event_id,
            } => {
                put("kind", "event");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "object_type", event_kind);
                put_opt(&mut object, "event_id", event_id);
            }
            Self::Actor { actor_id } => {
                put("kind", "actor");
                put("actor_id", actor_id);
            }
            Self::Schema {
                realm_id,
                schema_id,
            } => {
                put("kind", "schema");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "schema_ref", schema_id);
            }
            Self::Policy {
                realm_id,
                policy_id,
            } => {
                put("kind", "policy");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "policy_id", policy_id);
            }
            Self::Invite {
                realm_id,
                invite_id,
            } => {
                put("kind", "invite");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "invite_id", invite_id);
            }
            Self::Notification { actor_id, .. } => {
                put("kind", "notification");
                if actor_id != "*" {
                    put("actor_id", actor_id);
                }
            }
            Self::ReadCursor { realm_id } => {
                put("kind", "read_cursor");
                put("realm_id", realm_id);
            }
            Self::Blob { realm_id, blob_id } => {
                put("kind", "blob");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "blob_ref", blob_id);
            }
            Self::Wildcard => {
                put("kind", "*");
            }
        }
        Value::Object(object)
    }

    /// Parse a resource selector from a string.
    ///
    /// Supports formats like:
    /// - "realm:ck:realm:..."
    /// - "space:ck:space:..."
    /// - "object:ck:realm:...:task"
    /// - "relation:ck:realm:...:assigned_to"
    pub fn parse(selector: &str) -> Result<Self> {
        // Split on the first colon to get the type
        let parts: Vec<&str> = selector.splitn(2, ':').collect();

        if parts.len() != 2 {
            return Err(Error::Protocol(format!("invalid selector: {}", selector)));
        }

        let selector_type = parts[0];
        let remainder = parts[1];

        match selector_type {
            "realm" => Ok(Self::Realm {
                realm_id: remainder.to_owned(),
            }),
            "space" => Ok(Self::Space {
                space_id: remainder.to_owned(),
            }),
            "strand" => {
                let (realm_id, strand_id) = split_realm_tail(remainder, selector)?;
                Ok(Self::Strand { realm_id, strand_id })
            }
            "object" => {
                let (realm_id, tail) = split_realm_tail(remainder, selector)?;
                let (object_type, object_ref) = match tail {
                    None => (None, None),
                    Some(tail) if tail == "*" => (None, None),
                    Some(tail) if tail.starts_with("ck:") || tail.starts_with("did:") => {
                        (None, Some(tail))
                    }
                    Some(tail) => (Some(tail), None),
                };
                Ok(Self::Object {
                    realm_id,
                    object_type,
                    object_ref,
                })
            }
            "message" => {
                let (realm_id, message_id) = split_realm_tail(remainder, selector)?;
                Ok(Self::Message {
                    realm_id,
                    message_id,
                })
            }
            "relation" => {
                let (realm_id, relation_kind) = split_realm_tail(remainder, selector)?;
                let Some(relation_kind) = relation_kind else {
                    return Err(Error::Protocol(format!(
                        "invalid relation selector: {}",
                        selector
                    )));
                };
                Ok(Self::Relation {
                    realm_id,
                    relation_kind,
                })
            }
            "view" => {
                let (realm_id, view_id) = split_realm_tail(remainder, selector)?;
                Ok(Self::View { realm_id, view_id })
            }
            "schema" => {
                let (realm_id, schema_id) = split_realm_tail(remainder, selector)?;
                Ok(Self::Schema {
                    realm_id,
                    schema_id,
                })
            }
            "policy" => {
                let (realm_id, policy_id) = split_realm_tail(remainder, selector)?;
                Ok(Self::Policy {
                    realm_id,
                    policy_id,
                })
            }
            "invite" => {
                let (realm_id, invite_id) = split_realm_tail(remainder, selector)?;
                Ok(Self::Invite {
                    realm_id,
                    invite_id,
                })
            }
            "read_cursor" => Ok(Self::ReadCursor {
                realm_id: realm_part(remainder, selector)?,
            }),
            "circle" => {
                // Accept either `circle:ck:circle:<uuid>` (typed) or bare
                // `circle:<uuid>` (parser tail).
                let raw = if remainder.starts_with("ck:circle:") {
                    remainder.to_owned()
                } else {
                    format!("ck:circle:{remainder}")
                };
                let circle_id = cokret_core::CircleId::new(raw)
                    .map_err(|err| Error::Protocol(format!("invalid circle selector: {err}")))?;
                Ok(Self::Circle { circle_id })
            }
            "*" => Ok(Self::Wildcard),
            _ => Err(Error::Protocol(format!(
                "unknown selector type: {}",
                selector
            ))),
        }
    }
}

/// Schema-aligned resource selector kind from `ck.schema.resource_selector.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolResourceSelectorKind {
    Realm,
    Space,
    Strand,
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
    /// CKP-0007 (R3 spec-sync 2026-05-27).
    Circle,
    /// Spec `resource-selector.schema.json` spells the wildcard kind as
    /// `"*"`, not `"wildcard"`.
    #[serde(rename = "*")]
    Wildcard,
}

/// Scope field from `ck.schema.resource_selector.v1`.
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
    pub realm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<String>,
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
            ResourceSelector::Realm { realm_id } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Realm);
                out.realm_id = Some(realm_id.clone());
                out
            }
            ResourceSelector::Space { space_id } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Space);
                out.space_id = Some(space_id.clone());
                out
            }
            ResourceSelector::Strand { realm_id, strand_id } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Strand);
                out.realm_id = Some(realm_id.clone());
                out.strand_id = strand_id.clone();
                out
            }
            ResourceSelector::Object {
                realm_id,
                object_type,
                object_ref,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Object);
                out.realm_id = Some(realm_id.clone());
                out.object_type = object_type.clone();
                out.object_ref = object_ref.clone();
                out
            }
            ResourceSelector::Message {
                realm_id,
                message_id,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Message);
                out.realm_id = Some(realm_id.clone());
                out.message_id = message_id.clone();
                out
            }
            ResourceSelector::Relation {
                realm_id,
                relation_kind,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Relation);
                out.realm_id = Some(realm_id.clone());
                out.relation_kind = Some(relation_kind.clone());
                out
            }
            ResourceSelector::View { realm_id, view_id } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::View);
                out.realm_id = Some(realm_id.clone());
                out.view_id = view_id.clone();
                out
            }
            ResourceSelector::Schema {
                realm_id,
                schema_id,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Schema);
                out.realm_id = Some(realm_id.clone());
                out.schema_ref = schema_id.clone();
                out
            }
            ResourceSelector::Policy {
                realm_id,
                policy_id,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Policy);
                out.realm_id = Some(realm_id.clone());
                out.policy_id = policy_id.clone();
                out
            }
            ResourceSelector::Invite {
                realm_id,
                invite_id,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Invite);
                out.realm_id = Some(realm_id.clone());
                out.invite_id = invite_id.clone();
                out
            }
            ResourceSelector::ReadCursor { realm_id } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::ReadCursor);
                out.realm_id = Some(realm_id.clone());
                out
            }
            ResourceSelector::Morph {
                realm_id,
                morph_id,
                morph_type,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Morph);
                out.realm_id = Some(realm_id.clone());
                out.morph_id = morph_id.clone();
                out.morph_type = morph_type.clone();
                out
            }
            ResourceSelector::Notification {
                actor_id,
                notification_id,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Notification);
                out.actor_id = Some(actor_id.clone());
                out.object_ref = notification_id.clone();
                out
            }
            ResourceSelector::Blob { realm_id, blob_id } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Blob);
                out.realm_id = Some(realm_id.clone());
                out.blob_ref = blob_id.clone();
                out
            }
            ResourceSelector::Event {
                realm_id,
                event_kind,
                event_id,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Event);
                out.realm_id = Some(realm_id.clone());
                out.object_type = event_kind.clone();
                out.event_id = event_id.clone();
                out
            }
            ResourceSelector::Actor { actor_id } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Actor);
                out.actor_id = Some(actor_id.clone());
                out
            }
            ResourceSelector::Circle { circle_id } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Circle);
                out.circle_id = Some(circle_id.to_string());
                out
            }
            ResourceSelector::Wildcard => Self::empty(ProtocolResourceSelectorKind::Wildcard),
        }
    }

    fn empty(kind: ProtocolResourceSelectorKind) -> Self {
        Self {
            kind,
            realm_id: None,
            space_id: None,
            circle_id: None,
            object_type: None,
            object_ref: None,
            strand_id: None,
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
        }
    }
    /// Schema-aligned scaffold examples for new selector kinds introduced by the
    /// 2026-05-04 protocol delta.
    pub fn scaffold_examples() -> Vec<Self> {
        vec![
            Self {
                kind: ProtocolResourceSelectorKind::Event,
                realm_id: Some("ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                space_id: None,
                circle_id: None,
                event_id: Some("ck:event:01904100-0000-7000-8000-51495aba0a08".to_owned()),
                object_type: None,
                object_ref: None,
                strand_id: None,
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
                realm_id: None,
                space_id: None,
                circle_id: None,
                actor_id: Some("did:web:alice.example".to_owned()),
                object_type: None,
                object_ref: None,
                strand_id: None,
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
                realm_id: Some("ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                space_id: None,
                circle_id: None,
                actor_id: Some("did:web:alice.example".to_owned()),
                object_type: Some("device_verification".to_owned()),
                object_ref: Some("ck:notify:01JS0NT000000000000000000".to_owned()),
                strand_id: Some("ck:strand:01904100-0000-7000-8000-a1fffe3a8cc9".to_owned()),
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
                realm_id: Some("ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                space_id: None,
                circle_id: None,
                blob_ref: Some("ck:blob:sha256:0123456789abcdef".to_owned()),
                object_type: Some("encrypted_backup".to_owned()),
                object_ref: Some("backup-scaffold-current-device".to_owned()),
                strand_id: None,
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

#[cfg(test)]
mod spec_selector_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn spec_object_round_trips_through_engine_form() {
        let spec = json!({
            "kind": "object",
            "realm_id": "ck:realm:01904100-0000-7000-8000-65c7feb295d7",
            "object_type": "strand"
        });
        let selector = ResourceSelector::from_spec_value(&spec).unwrap();
        assert_eq!(
            selector,
            ResourceSelector::Object {
                realm_id: "ck:realm:01904100-0000-7000-8000-65c7feb295d7".to_owned(),
                object_type: Some("strand".to_owned()),
                object_ref: None,
            }
        );
        assert_eq!(selector.to_spec_value(), spec);
    }

    #[test]
    fn wildcard_uses_star_kind() {
        let spec = json!({"kind": "*"});
        assert_eq!(
            ResourceSelector::from_spec_value(&spec).unwrap(),
            ResourceSelector::Wildcard
        );
        assert_eq!(ResourceSelector::Wildcard.to_spec_value(), spec);
    }

    #[test]
    fn unknown_kind_fails_closed() {
        let err = ResourceSelector::from_spec_value(&json!({"kind": "board"})).unwrap_err();
        assert!(format!("{err}").contains("unknown resource selector kind"));
    }

    #[test]
    fn string_selector_falls_back_to_compact_grammar() {
        let selector = ResourceSelector::from_spec_value(&json!(
            "realm:ck:realm:01904100-0000-7000-8000-65c7feb295d7"
        ))
        .unwrap();
        assert_eq!(
            selector,
            ResourceSelector::Realm {
                realm_id: "ck:realm:01904100-0000-7000-8000-65c7feb295d7".to_owned(),
            }
        );
    }
}

fn realm_part(remainder: &str, selector: &str) -> Result<String> {
    let (realm_id, tail) = split_realm_tail(remainder, selector)?;
    if tail.is_some() {
        return Err(Error::Protocol(format!(
            "invalid realm-only selector: {selector}"
        )));
    }
    Ok(realm_id)
}

fn split_realm_tail(remainder: &str, selector: &str) -> Result<(String, Option<String>)> {
    if remainder == "*" {
        return Ok(("*".to_owned(), None));
    }
    if let Some(tail) = remainder.strip_prefix("*:") {
        return Ok((
            "*".to_owned(),
            if tail.is_empty() {
                None
            } else {
                Some(tail.to_owned())
            },
        ));
    }

    let parts = remainder.split(':').collect::<Vec<_>>();
    if parts.len() < 3 || parts[0] != "ck" || parts[1] != "realm" || parts[2].is_empty() {
        return Err(Error::Protocol(format!(
            "invalid realm-scoped selector: {selector}"
        )));
    }
    let realm_id = format!("{}:{}:{}", parts[0], parts[1], parts[2]);
    let tail = if parts.len() > 3 {
        let tail = parts[3..].join(":");
        if tail.is_empty() { None } else { Some(tail) }
    } else {
        None
    };
    Ok((realm_id, tail))
}
