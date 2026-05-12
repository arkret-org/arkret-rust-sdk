use super::*;

/// Registry entry for one operation kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationKindSpec {
    pub kind: String,
    pub schema: String,
    #[serde(default)]
    pub required_content_fields: Vec<String>,
}

/// Result of validating an operation kind against the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationKindValidation {
    pub canonical_kind: String,
}

/// Canonical operation registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationKindRegistry {
    specs: BTreeMap<String, OperationKindSpec>,
}

impl OperationKindRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self { specs: BTreeMap::new() }
    }

    /// Register one operation kind.
    pub fn register(&mut self, spec: OperationKindSpec) {
        self.specs.insert(spec.kind.clone(), spec);
    }

    /// Return the spec for a canonical kind.
    pub fn spec(&self, kind: &str) -> Option<&OperationKindSpec> {
        self.specs.get(kind)
    }

    /// Resolve a canonical kind.
    pub fn canonicalize(&self, kind: &str) -> Result<OperationKindValidation> {
        if self.specs.contains_key(kind) {
            return Ok(OperationKindValidation { canonical_kind: kind.to_owned() });
        }
        Err(Error::Protocol(format!("unknown operation kind '{kind}'")))
    }

    /// Validate an operation envelope against registered semantic requirements.
    pub fn validate_envelope(
        &self,
        envelope: &OperationEnvelope,
    ) -> Result<OperationKindValidation> {
        let validation = self.canonicalize(&envelope.kind)?;
        let spec = self
            .specs
            .get(&validation.canonical_kind)
            .ok_or_else(|| Error::Protocol("operation kind registry is inconsistent".to_owned()))?;
        let Some(content) = envelope.content.as_object() else {
            return Err(Error::Protocol(
                "operation envelope content must be a JSON object".to_owned(),
            ));
        };
        for field in &spec.required_content_fields {
            if !content.contains_key(field) {
                return Err(Error::Protocol(format!(
                    "operation kind '{}' requires content field '{}'",
                    spec.kind, field
                )));
            }
        }
        Ok(validation)
    }

    /// Iterate registered canonical operation kinds.
    pub fn kinds(&self) -> impl Iterator<Item = &str> {
        self.specs.keys().map(String::as_str)
    }
}

impl Default for OperationKindRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        for kind in BUILT_IN_OPERATION_KINDS {
            registry.register(OperationKindSpec {
                kind: (*kind).to_owned(),
                schema: OPERATION_SCHEMA.to_owned(),
                required_content_fields: required_fields_for_operation_kind(kind),
            });
        }
        for kind in crate::events::STANDARD_EVENT_KINDS {
            registry.register(OperationKindSpec {
                kind: (*kind).to_owned(),
                schema: EVENT_SCHEMA.to_owned(),
                required_content_fields: required_fields_for_operation_kind(kind),
            });
        }
        registry
    }
}

pub(super) fn required_fields_for_operation_kind(kind: &str) -> Vec<String> {
    match kind {
        OP_FLOW_CREATE => vec!["object".to_owned()],
        OP_FLOW_UPDATE => vec!["flow_id".to_owned(), "patch".to_owned()],
        OP_FLOW_ARCHIVE | OP_FLOW_RESTORE => vec!["flow_id".to_owned()],
        OP_FLOW_MOVE => ["board_place_id", "flow_id", "target_place_id", "rank"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_FLOW_REORDER => ["board_place_id", "flow_id", "place_id", "rank"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_MORPH_CREATE => vec!["object".to_owned()],
        OP_MORPH_UPDATE => vec!["morph_id".to_owned(), "patch".to_owned()],
        OP_MORPH_ARCHIVE | OP_MORPH_RESTORE => vec!["morph_id".to_owned()],
        OP_PLACE_CREATE => vec!["object".to_owned()],
        OP_PLACE_UPDATE => vec!["place_id".to_owned(), "patch".to_owned()],
        OP_PLACE_PARENT => vec!["place_id".to_owned(), "parent_ref".to_owned()],
        OP_PLACE_ARCHIVE | OP_PLACE_TOMBSTONE => vec!["place_id".to_owned()],
        OP_RELATION_CREATE => vec!["object".to_owned()],
        OP_RELATION_UPDATE => vec!["relation_id".to_owned(), "patch".to_owned()],
        OP_RELATION_DELETE => vec!["relation_id".to_owned()],
        OP_CONTAINER_MOVE_ITEM => {
            ["scope_container_id", "relation_kind", "object_ref", "to_container_id", "rank"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        OP_CONTAINER_REBALANCE => [
            "scope_container_id",
            "container_id",
            "relation_kind",
            "expected_state_hash",
            "assignments",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        OP_MESSAGE_CREATE => vec!["flow_id".to_owned(), "track".to_owned()],
        OP_DEVICE_MESSAGES_PUT => {
            ["kind", "recipient_principal_id", "recipient_device_id", "content"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        OP_KEYS_BACKUPS_PUT => [
            "backup_id",
            "actor_id",
            "backup_class",
            "backup_version",
            "ciphertext",
            "ciphertext_digest",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        OP_KEYS_BACKUPS_LIST | OP_KEYS_BACKUPS_GET | OP_KEYS_BACKUPS_DELETE => {
            vec!["backup_id".to_owned()]
        }
        OP_KEYS_KEYPACKAGES_UPLOAD => {
            ["principal_id", "device_id", "keypackages"].into_iter().map(str::to_owned).collect()
        }
        OP_KEYS_KEYPACKAGES_CLAIM => {
            ["target_principal_id", "intended_space_id", "requester", "claim_nonce", "expires_at"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        OP_KEYS_KEYPACKAGES_CONSUME => {
            ["claim_id", "keypackage_ref"].into_iter().map(str::to_owned).collect()
        }
        OP_KEYS_KEYPACKAGES_REVOKE => {
            ["principal_id", "device_id", "keypackage_ref"].into_iter().map(str::to_owned).collect()
        }
        OP_DIRECTORY_RESOLVE_HANDLE => vec!["handle".to_owned()],
        OP_DIRECTORY_RESOLVE_ORGANIZATION | OP_DIRECTORY_RESOLVE_SPACE => {
            vec!["target".to_owned()]
        }
        OP_DIRECTORY_SEARCH_ACTORS
        | OP_DIRECTORY_SEARCH_ORGANIZATIONS
        | OP_DIRECTORY_SEARCH_SPACES
        | OP_DIRECTORY_SEARCH_USERS => vec!["query".to_owned()],
        OP_IDENTITY_GET_DOCUMENT | OP_IDENTITY_GET_LOG | OP_IDENTITY_GET_RECEIPTS => {
            vec!["did".to_owned()]
        }
        OP_IDENTITY_SUBMIT_DID_OPERATION => {
            ["did", "operation"].into_iter().map(str::to_owned).collect()
        }
        OP_ADMIN_REVOKE_DEVICE => {
            ["principal_id", "device_id"].into_iter().map(str::to_owned).collect()
        }
        OP_ADMIN_UPDATE_ACCOUNT_STATUS => {
            ["principal_id", "status"].into_iter().map(str::to_owned).collect()
        }
        OP_ACCOUNT_DEVICE_PAIR => {
            ["principal_id", "device_id"].into_iter().map(str::to_owned).collect()
        }
        OP_ACCOUNT_ISSUE_SESSION_GRANT => ["principal_id", "device_id", "audience", "scopes"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_PUSH_REGISTER_DEVICE => {
            ["device_id", "endpoint"].into_iter().map(str::to_owned).collect()
        }
        OP_PUSH_UNREGISTER_DEVICE => vec!["device_id".to_owned()],
        OP_MODERATION_REPORT => ["target_ref", "reason"].into_iter().map(str::to_owned).collect(),
        OP_POLICY_CHECK => vec!["resource".to_owned()],
        OP_AUTHZ_GET_EFFECTIVE_GRANTS => vec!["actor_id".to_owned()],
        OP_AUTHZ_GET_INVITES => vec!["space_id".to_owned()],
        OP_EVENTS_GET | OP_EVENTS_BATCH_GET => vec!["event_id".to_owned()],
        OP_EVENTS_FRONTIER => vec!["space_id".to_owned()],
        OP_EVENTS_QUERY => Vec::new(), // selector = spaces[]?+actors[]? — neither is strictly required
        OP_EVENTS_SUBSCRIBE => Vec::new(), // selector arrays may be empty for "all reachable"; subscription
        OP_EVENTS_SUBMIT => vec!["events".to_owned()],
        OP_SYNC_ACCOUNT => vec!["subscriptions".to_owned()],
        OP_SYNC_GET_SNAPSHOT_HEAD => vec!["space_id".to_owned()],
        _ => Vec::new(),
    }
}

/// Operation registry conformance vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationKindConformanceVector {
    pub input_kind: String,
    pub canonical_kind: String,
}

/// Conformance vectors for every built-in operation kind.
pub fn operation_kind_conformance_vectors() -> Vec<OperationKindConformanceVector> {
    BUILT_IN_OPERATION_KINDS
        .iter()
        .map(|kind| OperationKindConformanceVector {
            input_kind: (*kind).to_owned(),
            canonical_kind: (*kind).to_owned(),
        })
        .collect()
}

/// Protocol JSON Schema registry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProtocolSchemaRegistry {
    schemas: BTreeMap<String, Value>,
    trusted_extension_prefixes: Vec<String>,
}

/// JSON value type rule extracted from a supported JSON Schema document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum GeneratedSchemaValueType {
    Any,
    Array,
    Boolean,
    Integer,
    Null,
    Number,
    Object,
    String,
}

impl GeneratedSchemaValueType {
    fn from_schema(value: &Value) -> Self {
        match value.get("type").and_then(Value::as_str) {
            Some("array") => Self::Array,
            Some("boolean") => Self::Boolean,
            Some("integer") => Self::Integer,
            Some("null") => Self::Null,
            Some("number") => Self::Number,
            Some("object") => Self::Object,
            Some("string") => Self::String,
            _ => Self::Any,
        }
    }

    fn matches(&self, value: &Value) -> bool {
        match self {
            Self::Any => true,
            Self::Array => value.is_array(),
            Self::Boolean => value.is_boolean(),
            Self::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
            Self::Null => value.is_null(),
            Self::Number => value.is_number(),
            Self::Object => value.is_object(),
            Self::String => value.is_string(),
        }
    }

    fn as_schema_type(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Array => "array",
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Null => "null",
            Self::Number => "number",
            Self::Object => "object",
            Self::String => "string",
        }
    }
}

/// One field rule in a generated schema validator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GeneratedSchemaField {
    pub name: String,
    pub value_type: GeneratedSchemaValueType,
    pub required: bool,
}

/// Runtime validator generated from the JSON Schema subset supported by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GeneratedSchemaValidator {
    pub schema_id: String,
    pub fields: Vec<GeneratedSchemaField>,
    pub additional_properties: bool,
    pub trusted_extension_prefixes: Vec<String>,
}

impl GeneratedSchemaValidator {
    /// Validate one JSON object using the generated field rules.
    pub fn validate(&self, value: &Value) -> Result<()> {
        let object = value
            .as_object()
            .ok_or_else(|| Error::Protocol("schema target must be a JSON object".to_owned()))?;
        for field in &self.fields {
            match object.get(&field.name) {
                Some(field_value) if field.value_type.matches(field_value) => {}
                Some(_) => {
                    return Err(Error::Protocol(format!(
                        "schema '{}' field '{}' must be JSON type '{}'",
                        self.schema_id,
                        field.name,
                        field.value_type.as_schema_type()
                    )));
                }
                None if field.required => {
                    return Err(Error::Protocol(format!(
                        "schema '{}' requires field '{}'",
                        self.schema_id, field.name
                    )));
                }
                None => {}
            }
        }

        if !self.additional_properties {
            for field in object.keys() {
                if !self.fields.iter().any(|known| known.name == *field) {
                    return Err(Error::Protocol(format!(
                        "schema '{}' rejects additional field '{}'",
                        self.schema_id, field
                    )));
                }
            }
        }

        for field in object.keys() {
            if !is_security_sensitive_extension(field) {
                continue;
            }
            let trusted =
                self.trusted_extension_prefixes.iter().any(|prefix| field.starts_with(prefix));
            if !trusted {
                return Err(Error::Protocol(format!(
                    "schema '{}' rejects unknown security-sensitive extension '{}'",
                    self.schema_id, field
                )));
            }
        }
        Ok(())
    }
}

impl ProtocolSchemaRegistry {
    /// Create an empty schema registry.
    pub fn new() -> Self {
        Self { schemas: BTreeMap::new(), trusted_extension_prefixes: Vec::new() }
    }

    /// Register a schema document by `$id`.
    pub fn register(&mut self, schema_id: impl Into<String>, schema: Value) {
        self.schemas.insert(schema_id.into(), schema);
    }

    /// Return one schema by ID.
    pub fn schema(&self, schema_id: &str) -> Option<&Value> {
        self.schemas.get(schema_id)
    }

    /// Iterate schema IDs.
    pub fn schema_ids(&self) -> impl Iterator<Item = &str> {
        self.schemas.keys().map(String::as_str)
    }

    /// Trust a security-sensitive extension prefix for fail-closed validation.
    pub fn trust_extension_prefix(&mut self, prefix: impl Into<String>) {
        self.trusted_extension_prefixes.push(prefix.into());
    }

    /// Generate a runtime Rust validator from the supported JSON Schema subset.
    pub fn generated_validator(&self, schema_id: &str) -> Result<GeneratedSchemaValidator> {
        let schema = self
            .schema(schema_id)
            .ok_or_else(|| Error::Protocol(format!("unknown schema '{schema_id}'")))?;
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let mut fields = Vec::new();
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (name, property_schema) in properties {
                fields.push(GeneratedSchemaField {
                    name: name.clone(),
                    value_type: GeneratedSchemaValueType::from_schema(property_schema),
                    required: required.contains(name),
                });
            }
        }
        for name in required {
            if !fields.iter().any(|field| field.name == name) {
                fields.push(GeneratedSchemaField {
                    name,
                    value_type: GeneratedSchemaValueType::Any,
                    required: true,
                });
            }
        }
        fields.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(GeneratedSchemaValidator {
            schema_id: schema_id.to_owned(),
            fields,
            additional_properties: schema
                .get("additionalProperties")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            trusted_extension_prefixes: self.trusted_extension_prefixes.clone(),
        })
    }

    /// Validate required fields and basic JSON Schema `type` constraints.
    pub fn validate_value(&self, schema_id: &str, value: &Value) -> Result<()> {
        let schema = self
            .schema(schema_id)
            .ok_or_else(|| Error::Protocol(format!("unknown schema '{schema_id}'")))?;
        let object = value
            .as_object()
            .ok_or_else(|| Error::Protocol("schema target must be a JSON object".to_owned()))?;
        let required =
            schema.get("required").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
        for field in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(field) {
                return Err(Error::Protocol(format!(
                    "schema '{schema_id}' requires field '{field}'"
                )));
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (field, property_schema) in properties {
                if let Some(field_value) = object.get(field) {
                    validate_json_schema_type(schema_id, field, property_schema, field_value)?;
                }
            }
        }
        self.validate_security_extensions(schema_id, object)?;
        Ok(())
    }

    fn validate_security_extensions(
        &self,
        schema_id: &str,
        object: &serde_json::Map<String, Value>,
    ) -> Result<()> {
        for field in object.keys() {
            if !is_security_sensitive_extension(field) {
                continue;
            }
            let trusted =
                self.trusted_extension_prefixes.iter().any(|prefix| field.starts_with(prefix));
            if !trusted {
                return Err(Error::Protocol(format!(
                    "schema '{schema_id}' rejects unknown security-sensitive extension '{field}'"
                )));
            }
        }
        Ok(())
    }
}

impl Default for ProtocolSchemaRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.register(
            CURSOR_SCHEMA,
            object_schema(
                CURSOR_SCHEMA,
                &["v", "iat", "pos"],
                &[("v", "string"), ("iat", "string"), ("pos", "object")],
            ),
        );
        registry.register(
            EVENT_SCHEMA,
            object_schema(
                EVENT_SCHEMA,
                &[
                    "event_id",
                    "kind",
                    "space_id",
                    "actor_id",
                    "actor_seq",
                    "created_at",
                    "hlc",
                    "prev_refs",
                    "refs",
                    "payload",
                    "proofs",
                ],
                &[
                    ("schema", "string"),
                    ("event_id", "string"),
                    ("kind", "string"),
                    ("space_id", "string"),
                    ("actor_id", "string"),
                    ("actor_seq", "integer"),
                    ("created_at", "string"),
                    ("hlc", "string"),
                    ("prev_refs", "array"),
                    ("refs", "array"),
                    ("preconditions", "array"),
                    ("effects", "array"),
                    ("anchor_ref", "string"),
                    ("requirements", "object"),
                    ("redacts", "string"),
                    ("payload", "object"),
                    ("unsigned", "object"),
                    ("proofs", "array"),
                ],
            ),
        );
        registry.register(FLOW_SCHEMA, flow_schema_document());
        registry.register(PLACE_SCHEMA, place_schema_document());
        registry.register(VIEW_SCHEMA, view_schema_document());
        registry.register(
            EVENT_PAYLOAD_SCHEMA,
            object_schema(EVENT_PAYLOAD_SCHEMA, &[], &[("type", "string")]),
        );
        registry.register(
            ANCHOR_SCHEMA,
            object_schema(
                ANCHOR_SCHEMA,
                &["id", "space_id", "frontier", "state_root"],
                &[
                    ("id", "string"),
                    ("space_id", "string"),
                    ("frontier", "array"),
                    ("state_root", "string"),
                ],
            ),
        );
        registry.register(
            AGENT_AUTHORITY_SCHEMA,
            object_schema(
                AGENT_AUTHORITY_SCHEMA,
                &["agent_session_id", "actor_id", "authority"],
                &[("agent_session_id", "string"), ("actor_id", "string"), ("authority", "object")],
            ),
        );
        registry.register(
            BOTTOM_SCHEMA,
            object_schema(
                BOTTOM_SCHEMA,
                &["kind", "cells"],
                &[("kind", "string"), ("cells", "array")],
            ),
        );
        registry.register(
            SNAPSHOT_SCHEMA,
            object_schema(
                SNAPSHOT_SCHEMA,
                &["snapshot_id", "space_id", "frontier", "state_root"],
                &[
                    ("snapshot_id", "string"),
                    ("space_id", "string"),
                    ("frontier", "array"),
                    ("state_root", "string"),
                ],
            ),
        );
        registry.register(
            CAPABILITY_SCHEMA,
            object_schema(
                CAPABILITY_SCHEMA,
                &["schema", "id", "issuer", "subject", "actions", "resources"],
                &[
                    ("schema", "string"),
                    ("id", "string"),
                    ("issuer", "string"),
                    ("subject", "object"),
                    ("actions", "array"),
                    ("resources", "array"),
                ],
            ),
        );
        registry.register(
            ENCRYPTED_PAYLOAD_SCHEMA,
            object_schema(
                ENCRYPTED_PAYLOAD_SCHEMA,
                &["scheme", "group_id", "epoch", "content_type", "ciphertext", "payload_digest"],
                &[
                    ("scheme", "string"),
                    ("group_id", "string"),
                    ("epoch", "integer"),
                    ("content_type", "string"),
                    ("ciphertext", "string"),
                    ("payload_digest", "string"),
                ],
            ),
        );
        registry.register(
            CLIENT_SYNC_RESPONSE_SCHEMA,
            object_schema(
                CLIENT_SYNC_RESPONSE_SCHEMA,
                &["next_batch", "spaces"],
                &[("next_batch", "string"), ("spaces", "object")],
            ),
        );
        registry
    }
}

fn object_schema(schema_id: &str, required: &[&str], properties: &[(&str, &str)]) -> Value {
    let properties: serde_json::Map<String, Value> = properties
        .iter()
        .map(|(name, kind)| ((*name).to_owned(), json!({ "type": kind })))
        .collect();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": schema_id,
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": true,
    })
}

fn flow_schema_document() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": FLOW_SCHEMA,
        "type": "object",
        "required": ["id", "type", "schema", "space_id", "title", "tracks", "created_by", "created_at"],
        "not": { "required": ["body", "encrypted_payload"] },
        "properties": {
            "schema": { "type": "string" },
            "id": { "type": "string" },
            "type": { "type": "string" },
            "space_id": { "type": "string" },
            "title": { "type": "string" },
            "summary": { "type": "string" },
            "body": { "type": "object" },
            "encrypted_payload": { "type": "object" },
            "tracks": { "type": "object", "minProperties": 1 },
            "discussion_space_ref": { "type": "string" },
            "fields": { "type": "object" },
            "state": { "type": "string" },
            "state_changed_at": { "type": "string" },
            "created_by": { "type": "string" },
            "created_at": { "type": "string" },
            "updated_by": { "type": "string" },
            "updated_at": { "type": "string" },
        },
        "additionalProperties": true
    })
}

fn place_schema_document() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": PLACE_SCHEMA,
        "type": "object",
        "required": ["schema", "id", "space_id", "kind", "title", "created_by", "created_at"],
        "properties": {
            "schema": { "type": "string" },
            "id": { "type": "string" },
            "space_id": { "type": "string" },
            "kind": { "type": "string" },
            "title": { "type": "string" },
            "parent_ref": { "type": "string" },
            "rank": { "type": "string" },
            "state": { "type": "string" },
            "state_changed_at": { "type": "string" },
            "created_by": { "type": "string" },
            "created_at": { "type": "string" },
            "updated_by": { "type": "string" },
            "updated_at": { "type": "string" }
        },
        "additionalProperties": true
    })
}

fn view_schema_document() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": VIEW_SCHEMA,
        "type": "object",
        "required": ["id", "type", "space_id", "kind", "query", "created_by", "created_at"],
        "properties": {
            "schema": { "type": "string" },
            "id": { "type": "string" },
            "type": { "type": "string" },
            "space_id": { "type": "string" },
            "kind": { "type": "string" },
            "preset": { "type": "string" },
            "renderer": { "type": "string" },
            "query": { "type": "object" },
            "collection": { "type": "object" },
            "conversation": { "type": "object" },
            "graph": { "type": "object" },
            "queue": { "type": "object" },
            "created_by": { "type": "string" },
            "created_at": { "type": "string" }
        },
        "additionalProperties": true
    })
}

fn is_security_sensitive_extension(field: &str) -> bool {
    matches!(
        field,
        "x-authz"
            | "x-policy"
            | "x-security"
            | "x-contrix-authz"
            | "x-contrix-policy"
            | "x-contrix-security"
    ) || field.starts_with("x-authz-")
        || field.starts_with("x-policy-")
        || field.starts_with("x-security-")
        || field.starts_with("x-contrix-authz-")
        || field.starts_with("x-contrix-policy-")
        || field.starts_with("x-contrix-security-")
}

fn validate_json_schema_type(
    schema_id: &str,
    field: &str,
    property_schema: &Value,
    value: &Value,
) -> Result<()> {
    let Some(kind) = property_schema.get("type").and_then(Value::as_str) else {
        return Ok(());
    };
    let matches = match kind {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        _ => true,
    };
    if matches {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "schema '{schema_id}' field '{field}' must be JSON type '{kind}'"
        )))
    }
}
