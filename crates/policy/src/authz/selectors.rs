use arkret_wire::SchemaId;

use super::*;

const SELECTOR_JSON_MAX_BYTES: usize = 64 * 1024;
const SELECTOR_FIELD_MAX_BYTES: usize = 1024;
const SELECTOR_UNKNOWN_FIELDS_MAX: usize = 256;
const RESOURCE_SELECTOR_KNOWN_FIELDS: &[&str] = &[
    "kind",
    "realm_id",
    "space_id",
    "circle_id",
    "object_kind",
    "object_ref",
    "strand_id",
    "message_id",
    "morph_id",
    "morph_kind",
    "relation_kind",
    "relation_id",
    "view_id",
    "event_id",
    "actor_id",
    "schema_ref",
    "policy_id",
    "invite_id",
    "blob_ref",
    "match_scope",
];

/// Authorization decision result produced by the runtime `AuthzEngine`.
///
/// Named `EngineDecision` (not `AuthzDecision`) to avoid colliding with
/// the wire enum `models::AuthzDecision` re-exported at the umbrella crate
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
    Space {
        realm_id: String,
        space_id: Option<String>,
        match_scope: ProtocolResourceSelectorScope,
    },
    /// Strand selector (strand_id)
    Strand {
        realm_id: String,
        strand_id: Option<String>,
    },
    /// Generic object selector.
    Object {
        realm_id: String,
        object_kind: Option<String>,
        object_ref: Option<String>,
        match_scope: ProtocolResourceSelectorScope,
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
    /// Morph selector — `morph_kind` is the canonical filter per
    /// `resource-selector-grammar.md` §6 (matches by exact type name).
    Morph {
        realm_id: String,
        morph_id: Option<String>,
        morph_kind: Option<String>,
        match_scope: ProtocolResourceSelectorScope,
    },
    /// Notification selector (per-actor private). `actor_id` may be `*`.
    Notification {
        realm_id: String,
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
    /// AKP-0007 (R3 spec-sync 2026-05-27) — Circle selector. Matches a
    /// specific Circle by its `ak:circle:<uuid>` identifier. The Circle
    /// is scoped to its parent Realm; cross-Realm selectors MUST be
    /// rejected by the resolver (`circle_realm_mismatch`).
    Circle {
        realm_id: String,
        circle_id: Option<crate::CircleId>,
        match_scope: ProtocolResourceSelectorScope,
    },
    /// Wildcard selector (all resources)
    Wildcard,
}

impl ResourceSelector {
    pub const SCHEMA: &'static str = SchemaId::RESOURCE_SELECTOR_V1;
    /// Check if this selector matches a target resource.
    pub fn matches(&self, resource: &Resource) -> bool {
        if let Some(realm_id) = self.realm_id()
            && realm_id != "*"
            && resource.realm_id() != realm_id
        {
            return false;
        }

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
                Self::Space {
                    space_id,
                    match_scope,
                    ..
                },
                Resource::Space {
                    space_id: target_id,
                    ..
                },
            ) => match match_scope {
                ProtocolResourceSelectorScope::Exact => {
                    space_id.as_ref().is_some_and(|id| id == target_id)
                }
                ProtocolResourceSelectorScope::RealmWide => true,
                ProtocolResourceSelectorScope::Children
                | ProtocolResourceSelectorScope::Subtree => false,
            },
            (Self::Space { .. }, _) => false,

            // Strand selector
            (
                Self::Strand {
                    realm_id,
                    strand_id,
                },
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
                    object_kind,
                    object_ref,
                    ..
                },
                Resource::Strand {
                    realm_id: target_realm,
                    strand_id: target_id,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let type_match = object_kind.as_ref().is_none_or(|t| t == "strand");
                let ref_match = object_ref.as_ref().is_none_or(|id| id == target_id);
                realm_match && type_match && ref_match
            }
            (
                Self::Object {
                    realm_id,
                    object_kind,
                    object_ref,
                    ..
                },
                Resource::Morph {
                    realm_id: target_realm,
                    morph_id: target_id,
                    morph_kind: target_type,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let type_match = object_kind.as_ref().is_none_or(|t| t == target_type);
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
                    morph_kind,
                    ..
                },
                Resource::Morph {
                    realm_id: target_realm,
                    morph_id: target_id,
                    morph_kind: target_type,
                },
            ) => {
                let realm_match = realm_id == target_realm || realm_id == "*";
                let id_match = morph_id.as_ref().is_none_or(|id| id == target_id);
                let type_match = morph_kind.as_ref().is_none_or(|t| t == target_type);
                realm_match && id_match && type_match
            }
            (Self::Morph { .. }, _) => false,

            // Notification selector
            (
                Self::Notification {
                    actor_id,
                    notification_id,
                    ..
                },
                Resource::Notification {
                    actor_id: target_actor,
                    notification_id: target_id,
                    ..
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
            ) => actor_id != "*" && actor_id == target_actor,
            (Self::Actor { .. }, _) => false,

            // Circle selector
            (
                Self::Circle {
                    circle_id,
                    match_scope,
                    ..
                },
                Resource::Circle {
                    circle_id: target_id,
                    ..
                },
            ) => match match_scope {
                ProtocolResourceSelectorScope::Exact => {
                    circle_id.as_ref().is_some_and(|id| id == target_id)
                }
                ProtocolResourceSelectorScope::RealmWide => true,
                ProtocolResourceSelectorScope::Children
                | ProtocolResourceSelectorScope::Subtree => false,
            },
            (Self::Circle { .. }, _) => false,

            // Wildcard matches everything
            (Self::Wildcard, _) => true,
        }
    }

    fn realm_id(&self) -> Option<&str> {
        match self {
            Self::Realm { realm_id }
            | Self::Space { realm_id, .. }
            | Self::Strand { realm_id, .. }
            | Self::Object { realm_id, .. }
            | Self::Message { realm_id, .. }
            | Self::Relation { realm_id, .. }
            | Self::View { realm_id, .. }
            | Self::Schema { realm_id, .. }
            | Self::Policy { realm_id, .. }
            | Self::Invite { realm_id, .. }
            | Self::ReadCursor { realm_id }
            | Self::Morph { realm_id, .. }
            | Self::Notification { realm_id, .. }
            | Self::Blob { realm_id, .. }
            | Self::Event { realm_id, .. }
            | Self::Circle { realm_id, .. } => Some(realm_id),
            Self::Actor { .. } | Self::Wildcard => None,
        }
    }

    /// Parse a spec-shaped selector object (`resource-selector.schema.json`:
    /// `{"kind": "...", ...}`) into the engine selector model.
    ///
    /// This is the wire → engine direction used when projecting a
    /// `arkret::CapabilityGrant` (whose `resources` are untyped spec
    /// values) for evaluation. Unknown `kind` values fail closed.
    pub fn from_spec_value(value: &Value) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| Error::Protocol("resource selector must be an object".to_owned()))?;
        validate_spec_selector_object(object)?;
        let field = |name: &str| -> Option<String> {
            object
                .get(name)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let realm_or_wildcard = || field("realm_id").unwrap_or_else(|| "*".to_owned());
        let kind = field("kind")
            .ok_or_else(|| Error::Protocol("resource selector requires 'kind'".to_owned()))?;
        let match_scope = parse_match_scope(object)?;
        validate_match_scope(&kind, match_scope, object.contains_key("realm_id"))?;
        match kind.as_str() {
            "realm" => Ok(Self::Realm {
                realm_id: realm_or_wildcard(),
            }),
            "space" => Ok(Self::Space {
                realm_id: field("realm_id").ok_or_else(|| {
                    Error::Protocol("space selector requires realm_id".to_owned())
                })?,
                space_id: field("space_id"),
                match_scope,
            }),
            "circle" => {
                let circle_id = field("circle_id")
                    .map(crate::CircleId::new)
                    .transpose()
                    .map_err(|err| Error::Protocol(format!("invalid circle selector: {err}")))?;
                Ok(Self::Circle {
                    realm_id: field("realm_id").ok_or_else(|| {
                        Error::Protocol("circle selector requires realm_id".to_owned())
                    })?,
                    circle_id,
                    match_scope,
                })
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
                morph_kind: field("morph_kind"),
                match_scope,
            }),
            "object" => Ok(Self::Object {
                realm_id: realm_or_wildcard(),
                object_kind: field("object_kind"),
                object_ref: field("object_ref"),
                match_scope,
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
            // event kind in `object_kind`.
            "event" => Ok(Self::Event {
                realm_id: realm_or_wildcard(),
                event_kind: field("object_kind"),
                event_id: field("event_id"),
            }),
            "actor" => {
                let actor_id = field("actor_id").ok_or_else(|| {
                    Error::Protocol("actor selector requires actor_id".to_owned())
                })?;
                if actor_id == "*" {
                    return Err(Error::Protocol(
                        "selector_actor_wildcard_forbidden".to_owned(),
                    ));
                }
                Ok(Self::Actor { actor_id })
            }
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
                realm_id: field("realm_id").ok_or_else(|| {
                    Error::Protocol("notification selector requires realm_id".to_owned())
                })?,
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
            Self::Space {
                realm_id,
                space_id,
                match_scope,
            } => {
                put("kind", "space");
                put("realm_id", realm_id);
                put_opt(&mut object, "space_id", space_id);
                if *match_scope != ProtocolResourceSelectorScope::Exact {
                    object.insert(
                        "match_scope".to_owned(),
                        Value::String(match_scope.as_str().to_owned()),
                    );
                }
            }
            Self::Circle {
                realm_id,
                circle_id,
                match_scope,
            } => {
                put("kind", "circle");
                put("realm_id", realm_id);
                if let Some(circle_id) = circle_id {
                    put("circle_id", circle_id.as_ref());
                }
                if *match_scope != ProtocolResourceSelectorScope::Exact {
                    put("match_scope", match_scope.as_str());
                }
            }
            Self::Strand {
                realm_id,
                strand_id,
            } => {
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
                morph_kind,
                match_scope,
            } => {
                put("kind", "morph");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "morph_id", morph_id);
                put_opt(&mut object, "morph_kind", morph_kind);
                if *match_scope != ProtocolResourceSelectorScope::Exact {
                    object.insert(
                        "match_scope".to_owned(),
                        Value::String(match_scope.as_str().to_owned()),
                    );
                }
            }
            Self::Object {
                realm_id,
                object_kind,
                object_ref,
                match_scope,
            } => {
                put("kind", "object");
                if realm_id != "*" {
                    put("realm_id", realm_id);
                }
                put_opt(&mut object, "object_kind", object_kind);
                put_opt(&mut object, "object_ref", object_ref);
                if *match_scope != ProtocolResourceSelectorScope::Exact {
                    object.insert(
                        "match_scope".to_owned(),
                        Value::String(match_scope.as_str().to_owned()),
                    );
                }
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
                put_opt(&mut object, "object_kind", event_kind);
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
            Self::Notification {
                realm_id, actor_id, ..
            } => {
                put("kind", "notification");
                put("realm_id", realm_id);
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
    /// - "realm:ak:realm:..."
    /// - "space:ak:space:..."
    /// - "object:ak:realm:...:task"
    /// - "relation:ak:realm:...:assigned_to"
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
            "space" => Err(Error::Protocol(
                "space shorthand cannot carry required realm_id; use a spec selector object"
                    .to_owned(),
            )),
            "strand" => {
                let (realm_id, strand_id) = split_realm_tail(remainder, selector)?;
                Ok(Self::Strand {
                    realm_id,
                    strand_id,
                })
            }
            "object" => {
                let (realm_id, tail) = split_realm_tail(remainder, selector)?;
                let (object_kind, object_ref) = match tail {
                    None => (None, None),
                    Some(tail) if tail == "*" => (None, None),
                    Some(tail) if tail.starts_with("ak:") || tail.starts_with("did:") => {
                        (None, Some(tail))
                    }
                    Some(tail) => (Some(tail), None),
                };
                Ok(Self::Object {
                    realm_id,
                    object_kind,
                    object_ref,
                    match_scope: ProtocolResourceSelectorScope::Exact,
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
            "circle" => Err(Error::Protocol(
                "circle shorthand cannot carry required realm_id; use a spec selector object"
                    .to_owned(),
            )),
            "*" => Ok(Self::Wildcard),
            _ => Err(Error::Protocol(format!(
                "unknown selector type: {}",
                selector
            ))),
        }
    }
}

/// Schema-aligned resource selector kind from `ak.schema.resource_selector.v1`.
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
    /// AKP-0007 (R3 spec-sync 2026-05-27).
    Circle,
    /// Spec `resource-selector.schema.json` spells the wildcard kind as
    /// `"*"`, not `"wildcard"`.
    #[serde(rename = "*")]
    Wildcard,
}

/// Scope field from `ak.schema.resource_selector.v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolResourceSelectorScope {
    Exact,
    Subtree,
    Children,
    RealmWide,
}

impl ProtocolResourceSelectorScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Subtree => "subtree",
            Self::Children => "children",
            Self::RealmWide => "realm_wide",
        }
    }
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
    pub object_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_kind: Option<String>,
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
            ResourceSelector::Space {
                realm_id,
                space_id,
                match_scope,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Space);
                out.realm_id = Some(realm_id.clone());
                out.space_id = space_id.clone();
                out.match_scope = Some(*match_scope);
                out
            }
            ResourceSelector::Strand {
                realm_id,
                strand_id,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Strand);
                out.realm_id = Some(realm_id.clone());
                out.strand_id = strand_id.clone();
                out
            }
            ResourceSelector::Object {
                realm_id,
                object_kind,
                object_ref,
                match_scope,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Object);
                out.realm_id = Some(realm_id.clone());
                out.object_kind = object_kind.clone();
                out.object_ref = object_ref.clone();
                out.match_scope = Some(*match_scope);
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
                morph_kind,
                match_scope,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Morph);
                out.realm_id = Some(realm_id.clone());
                out.morph_id = morph_id.clone();
                out.morph_kind = morph_kind.clone();
                out.match_scope = Some(*match_scope);
                out
            }
            ResourceSelector::Notification {
                realm_id,
                actor_id,
                notification_id,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Notification);
                out.realm_id = Some(realm_id.clone());
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
                out.object_kind = event_kind.clone();
                out.event_id = event_id.clone();
                out
            }
            ResourceSelector::Actor { actor_id } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Actor);
                out.actor_id = Some(actor_id.clone());
                out
            }
            ResourceSelector::Circle {
                realm_id,
                circle_id,
                match_scope,
            } => {
                let mut out = Self::empty(ProtocolResourceSelectorKind::Circle);
                out.realm_id = Some(realm_id.clone());
                out.circle_id = circle_id.as_ref().map(ToString::to_string);
                out.match_scope = Some(*match_scope);
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
            object_kind: None,
            object_ref: None,
            strand_id: None,
            message_id: None,
            morph_id: None,
            morph_kind: None,
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
                realm_id: Some("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned()),
                space_id: None,
                circle_id: None,
                event_id: Some("ak:event:ARVUUS5MsgtJTHxDUnT_24cP4k86XFFUI-95GFfyLv6j".to_owned()),
                object_kind: None,
                object_ref: None,
                strand_id: None,
                message_id: None,
                morph_id: None,
                morph_kind: None,
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
                actor_id: Some("did:webvh:z6mkfixture:alice.example".to_owned()),
                object_kind: None,
                object_ref: None,
                strand_id: None,
                message_id: None,
                morph_id: None,
                morph_kind: None,
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
                realm_id: Some("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned()),
                space_id: None,
                circle_id: None,
                actor_id: Some("did:webvh:z6mkfixture:alice.example".to_owned()),
                object_kind: Some("device_verification".to_owned()),
                object_ref: Some("ak:notify:01JS0NT000000000000000000".to_owned()),
                strand_id: Some(
                    "ak:strand:ATU_HP58N6HajSjsX__QnN4h0SpqBlJAn4cLuPuTJpzR".to_owned(),
                ),
                message_id: None,
                morph_id: None,
                morph_kind: None,
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
                realm_id: Some("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned()),
                space_id: None,
                circle_id: None,
                blob_ref: Some("ak:blob:sha256:0123456789abcdef".to_owned()),
                object_kind: Some("encrypted_backup".to_owned()),
                object_ref: Some("backup-scaffold-current-device".to_owned()),
                strand_id: None,
                message_id: None,
                morph_id: None,
                morph_kind: None,
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

fn validate_spec_selector_object(object: &serde_json::Map<String, Value>) -> Result<()> {
    let encoded = serde_json::to_vec(object)
        .map_err(|_| Error::Protocol("selector_too_complex".to_owned()))?;
    if encoded.len() > SELECTOR_JSON_MAX_BYTES {
        return Err(Error::Protocol("selector_too_complex".to_owned()));
    }
    if object.contains_key("schema_id") {
        return Err(Error::Protocol(
            "resource selector forbids legacy 'schema_id'; use 'schema_ref'".to_owned(),
        ));
    }
    let unknown_fields = object
        .keys()
        .filter(|key| !RESOURCE_SELECTOR_KNOWN_FIELDS.contains(&key.as_str()))
        .count();
    if unknown_fields > SELECTOR_UNKNOWN_FIELDS_MAX {
        return Err(Error::Protocol("selector_too_complex".to_owned()));
    }
    for value in object.values() {
        validate_spec_selector_field_value(value)?;
    }
    if object.get("actor_id").and_then(Value::as_str) == Some("*") {
        return Err(Error::Protocol(
            "selector_actor_wildcard_forbidden".to_owned(),
        ));
    }
    if selector_uses_governance_wildcard(object) {
        return Err(Error::Protocol(
            "selector_governance_wildcard_forbidden".to_owned(),
        ));
    }
    if let Some(kind) = object.get("kind").and_then(Value::as_str) {
        let realm_scoped = matches!(
            kind,
            "space"
                | "circle"
                | "strand"
                | "message"
                | "morph"
                | "object"
                | "relation"
                | "view"
                | "event"
                | "policy"
                | "invite"
                | "notification"
                | "read_cursor"
        );
        if realm_scoped && object.get("realm_id").and_then(Value::as_str).is_none() {
            return Err(Error::Protocol(format!(
                "{kind} selector requires realm_id"
            )));
        }
        if kind == "actor" && object.get("actor_id").and_then(Value::as_str).is_none() {
            return Err(Error::Protocol(
                "actor selector requires actor_id".to_owned(),
            ));
        }
    }
    Ok(())
}

fn parse_match_scope(
    object: &serde_json::Map<String, Value>,
) -> Result<ProtocolResourceSelectorScope> {
    match object.get("match_scope") {
        None => Ok(ProtocolResourceSelectorScope::Exact),
        Some(Value::String(value)) => match value.as_str() {
            "exact" => Ok(ProtocolResourceSelectorScope::Exact),
            "children" => Ok(ProtocolResourceSelectorScope::Children),
            "subtree" => Ok(ProtocolResourceSelectorScope::Subtree),
            "realm_wide" => Ok(ProtocolResourceSelectorScope::RealmWide),
            _ => Err(Error::Protocol("unknown match_scope".to_owned())),
        },
        Some(_) => Err(Error::Protocol("match_scope must be a string".to_owned())),
    }
}

fn validate_match_scope(
    kind: &str,
    match_scope: ProtocolResourceSelectorScope,
    has_realm_id: bool,
) -> Result<()> {
    match match_scope {
        ProtocolResourceSelectorScope::Exact => Ok(()),
        ProtocolResourceSelectorScope::Children | ProtocolResourceSelectorScope::Subtree => {
            if kind != "space" {
                return Err(Error::Protocol(
                    "children/subtree match_scope only valid for space".to_owned(),
                ));
            }
            Err(Error::Protocol(
                "space children/subtree matching requires a CBA-anchored parent resolver"
                    .to_owned(),
            ))
        }
        ProtocolResourceSelectorScope::RealmWide => {
            if !has_realm_id {
                return Err(Error::Protocol(
                    "realm_wide selector requires realm_id".to_owned(),
                ));
            }
            if !matches!(kind, "space" | "circle" | "object" | "morph") {
                return Err(Error::Protocol(
                    "realm_wide match_scope only valid for space/circle/object/morph".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

fn validate_spec_selector_field_value(value: &Value) -> Result<()> {
    match value {
        Value::String(value) if value.len() > SELECTOR_FIELD_MAX_BYTES => {
            Err(Error::Protocol("selector_too_complex".to_owned()))
        }
        Value::Array(values) => {
            for value in values {
                validate_spec_selector_field_value(value)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for value in object.values() {
                validate_spec_selector_field_value(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn selector_uses_governance_wildcard(object: &serde_json::Map<String, Value>) -> bool {
    match object.get("kind").and_then(Value::as_str) {
        Some("policy") => {
            selector_field_missing_or_wildcard(object, "policy_id")
                || selector_field_missing_or_wildcard(object, "realm_id")
        }
        Some("schema") => {
            selector_field_missing_or_wildcard(object, "schema_ref")
                || selector_field_missing_or_wildcard(object, "realm_id")
        }
        Some("object") => {
            let object_kind = object.get("object_kind").and_then(Value::as_str);
            let object_ref = object.get("object_ref").and_then(Value::as_str);
            let governance_type = matches!(object_kind, Some("policy" | "schema"));
            let governance_ref = object_ref.is_some_and(|value| {
                value.starts_with("ak:policy:") || value.starts_with("ak:schema:")
            });
            (governance_type
                && (selector_field_missing_or_wildcard(object, "object_ref")
                    || selector_field_missing_or_wildcard(object, "realm_id")))
                || (governance_ref && selector_field_missing_or_wildcard(object, "realm_id"))
        }
        _ => false,
    }
}

fn selector_field_missing_or_wildcard(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> bool {
    object
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(|value| value == "*")
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
    if parts.len() < 3 || parts[0] != "ak" || parts[1] != "realm" || parts[2].is_empty() {
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

#[cfg(test)]
mod spec_selector_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn spec_object_round_trips_through_engine_form() {
        let spec = json!({
            "kind": "object",
            "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
            "object_kind": "strand"
        });
        let selector = ResourceSelector::from_spec_value(&spec).unwrap();
        assert_eq!(
            selector,
            ResourceSelector::Object {
                realm_id: "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI".to_owned(),
                object_kind: Some("strand".to_owned()),
                object_ref: None,
                match_scope: ProtocolResourceSelectorScope::Exact,
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
    fn actor_wildcard_fails_closed() {
        let err = ResourceSelector::from_spec_value(&json!({"kind": "actor", "actor_id": "*"}))
            .unwrap_err();
        assert!(format!("{err}").contains("selector_actor_wildcard_forbidden"));
        assert!(
            !(ResourceSelector::Actor {
                actor_id: "*".to_owned(),
            }
            .matches(&Resource::Actor {
                actor_id: "did:webvh:z6mkfixture:alice.example".to_owned(),
            }))
        );
    }

    #[test]
    fn governance_wildcard_fails_closed() {
        let err = ResourceSelector::from_spec_value(&json!({
            "kind": "policy",
            "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"
        }))
        .unwrap_err();
        assert!(format!("{err}").contains("selector_governance_wildcard_forbidden"));
    }

    #[test]
    fn schema_selector_rejects_legacy_schema_id_field() {
        let realm_id = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
        for spec in [
            json!({
                "kind": "schema",
                "realm_id": realm_id,
                "schema_id": "ak.schema.strand.v1"
            }),
            json!({
                "kind": "schema",
                "realm_id": realm_id,
                "schema_ref": "ak.schema.strand.v1",
                "schema_id": "ak.schema.strand.v1"
            }),
        ] {
            let err = ResourceSelector::from_spec_value(&spec).unwrap_err();
            assert!(format!("{err}").contains("forbids legacy 'schema_id'"));
        }
    }

    #[test]
    fn schema_selector_serializes_only_canonical_schema_ref() {
        let spec = json!({
            "kind": "schema",
            "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
            "schema_ref": "ak.schema.strand.v1"
        });
        let selector = ResourceSelector::from_spec_value(&spec).unwrap();
        let serialized = selector.to_spec_value();
        assert_eq!(serialized, spec);
        assert!(serialized.get("schema_id").is_none());
    }

    #[test]
    fn shorthand_rejects_schema_id_token() {
        let err = ResourceSelector::parse("schema_id:ak.schema.strand.v1").unwrap_err();
        assert!(format!("{err}").contains("unknown selector type"));
    }

    #[test]
    fn spec_value_rejects_compact_string_selector() {
        let err = ResourceSelector::from_spec_value(&json!(
            "realm:ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("resource selector must be an object"));
    }

    #[test]
    fn space_selector_never_crosses_realm_boundaries() {
        let realm_a = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
        let realm_b = "ak:realm:AS_kCfsKrUvM5FgR86UV-7vc958OXCZsXmxn9cQDNCO6";
        let space_id = "ak:space:AUxdIEkid-uK2BuCduwFmnDwA4WWeCWsDUXjvxBkR7hW";
        let selector = ResourceSelector::from_spec_value(&json!({
            "kind": "space",
            "realm_id": realm_a,
            "space_id": space_id
        }))
        .unwrap();

        assert!(selector.matches(&Resource::Space {
            realm_id: realm_a.to_owned(),
            space_id: space_id.to_owned(),
        }));
        assert!(!selector.matches(&Resource::Space {
            realm_id: realm_b.to_owned(),
            space_id: space_id.to_owned(),
        }));
        assert_eq!(
            selector.to_spec_value(),
            json!({"kind": "space", "realm_id": realm_a, "space_id": space_id})
        );
    }

    #[test]
    fn exact_space_without_space_id_matches_nothing() {
        let realm_id = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
        let selector = ResourceSelector::from_spec_value(&json!({
            "kind": "space",
            "realm_id": realm_id
        }))
        .unwrap();
        assert!(!selector.matches(&Resource::Space {
            realm_id: realm_id.to_owned(),
            space_id: "ak:space:AUxdIEkid-uK2BuCduwFmnDwA4WWeCWsDUXjvxBkR7hW".to_owned(),
        }));
    }

    #[test]
    fn realm_wide_space_is_limited_to_its_realm() {
        let realm_a = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
        let realm_b = "ak:realm:AS_kCfsKrUvM5FgR86UV-7vc958OXCZsXmxn9cQDNCO6";
        let selector = ResourceSelector::from_spec_value(&json!({
            "kind": "space",
            "realm_id": realm_a,
            "match_scope": "realm_wide"
        }))
        .unwrap();

        assert!(selector.matches(&Resource::Space {
            realm_id: realm_a.to_owned(),
            space_id: "ak:space:AUxdIEkid-uK2BuCduwFmnDwA4WWeCWsDUXjvxBkR7hW".to_owned(),
        }));
        assert!(!selector.matches(&Resource::Space {
            realm_id: realm_b.to_owned(),
            space_id: "ak:space:AY5TqH5JZQmoRdlhA-QVB-IeCgI1Degluy38Gz_NUXwV".to_owned(),
        }));
        assert_eq!(
            selector.to_spec_value(),
            json!({"kind": "space", "realm_id": realm_a, "match_scope": "realm_wide"})
        );
    }

    #[test]
    fn notification_selector_never_crosses_realm_boundaries() {
        let realm_a = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
        let realm_b = "ak:realm:AS_kCfsKrUvM5FgR86UV-7vc958OXCZsXmxn9cQDNCO6";
        let selector = ResourceSelector::from_spec_value(&json!({
            "kind": "notification",
            "realm_id": realm_a
        }))
        .unwrap();
        let notification = |realm_id: &str| Resource::Notification {
            realm_id: realm_id.to_owned(),
            actor_id: "did:webvh:z6mkfixture:alice.example".to_owned(),
            notification_id: "ak:notify:01JS0NT000000000000000000".to_owned(),
        };

        assert!(selector.matches(&notification(realm_a)));
        assert!(!selector.matches(&notification(realm_b)));
        assert_eq!(
            selector.to_spec_value(),
            json!({"kind": "notification", "realm_id": realm_a})
        );
    }

    #[test]
    fn unsupported_hierarchical_scope_fails_closed() {
        let err = ResourceSelector::from_spec_value(&json!({
            "kind": "space",
            "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
            "space_id": "ak:space:AUxdIEkid-uK2BuCduwFmnDwA4WWeCWsDUXjvxBkR7hW",
            "match_scope": "subtree"
        }))
        .unwrap_err();
        assert!(format!("{err}").contains("CBA-anchored parent resolver"));
    }
}
