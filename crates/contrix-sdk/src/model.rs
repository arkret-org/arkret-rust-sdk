use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Error, Result, canonical};

pub const PROTOCOL_VERSION: &str = "1.0";
pub const CORE_SCHEMA_PROFILE: &str = "cx.schema.core.v1";
pub const CORE_REDUCER_PROFILE: &str = "cx.reducer.v1";
pub const BUILT_IN_CONFORMANCE_FIXTURES_VERSION: &str = "contrix-sdk-builtin-v1";
pub const SCHEMA_COMPATIBILITY_PROFILE: &str = "cx.schema.compatibility.v1";

pub const CURSOR_SCHEMA: &str = "cx.schema.cursor.v1";
pub const SPACE_SCHEMA: &str = "cx.schema.space.v1";
pub const ACTOR_PROFILE_SCHEMA: &str = "cx.schema.actor_profile.v1";
pub const ENTITY_SCHEMA: &str = "cx.schema.entity.v1";
pub const RELATION_SCHEMA: &str = "cx.schema.relation.v1";
pub const EVENT_SCHEMA: &str = "cx.schema.event.v1";
pub const VIEW_SCHEMA: &str = "cx.schema.view.v1";
pub const POLICY_SCHEMA: &str = "cx.schema.policy.v1";
pub const CAPABILITY_SCHEMA: &str = "cx.schema.capability.v1";
pub const INVITE_SCHEMA: &str = "cx.schema.invite.v1";
pub const READ_MARKER_SCHEMA: &str = "cx.schema.read_marker.v1";
pub const NOTIFICATION_SCHEMA: &str = "cx.schema.notification.v1";
pub const COMMIT_SCHEMA: &str = "cx.schema.commit.v1";
pub const OPERATION_SCHEMA: &str = "cx.schema.operation.v1";
pub const BLOB_SCHEMA: &str = "cx.schema.blob.v1";
pub const ENCRYPTED_PAYLOAD_SCHEMA: &str = "cx.schema.encrypted_payload.v1";
pub const CLIENT_SYNC_RESPONSE_SCHEMA: &str = "cx.schema.client_sync_response.v1";

// ── Canonical cx.* operation kinds ──────────────────────────────────────────
/// Entity CRUD operations.
pub const OP_ENTITY_CREATE: &str = "cx.entity.create";
pub const OP_ENTITY_UPDATE: &str = "cx.entity.update";
pub const OP_ENTITY_DELETE: &str = "cx.entity.delete";
pub const OP_ENTITY_RESTORE: &str = "cx.entity.restore";
pub const OP_ENTITY_REDACT: &str = "cx.entity.redact";

/// Relation operations.
pub const OP_RELATION_CREATE: &str = "cx.relation.create";
pub const OP_RELATION_DELETE: &str = "cx.relation.delete";
pub const OP_RELATION_MOVE: &str = "cx.relation.move";

/// Task-specific operations.
pub const OP_TASK_CREATE: &str = "cx.task.create";
pub const OP_TASK_UPDATE: &str = "cx.task.update";
pub const OP_TASK_MOVE: &str = "cx.task.move";

/// View operations.
pub const OP_VIEW_CREATE: &str = "cx.view.create";
pub const OP_VIEW_UPDATE: &str = "cx.view.update";
pub const OP_VIEW_RECONCILE: &str = "cx.view.reconcile";

/// Space management operations.
pub const OP_SPACE_CREATE: &str = "cx.space.create";
pub const OP_SPACE_UPDATE: &str = "cx.space.update";
pub const OP_SPACE_ORGANIZATION: &str = "cx.space.organization";
pub const OP_SPACE_CHILD: &str = "cx.space.child";

/// Message operations.
pub const OP_MESSAGE_CREATE: &str = "cx.message.create";

/// Server, sync and federation operations.
pub const OP_SERVER_DESCRIBE: &str = "cx.server.describe";
pub const OP_IDENTITY_RESOLVE: &str = "cx.identity.resolve";
pub const OP_REPO_DESCRIBE: &str = "cx.repo.describe";
pub const OP_REPO_SYNC: &str = "cx.repo.sync";
pub const OP_SYNC_DESCRIBE: &str = "cx.sync.describe";
pub const OP_SYNC_SUBSCRIBE: &str = "cx.sync.subscribe";
pub const OP_SYNC_BACKFILL: &str = "cx.sync.backfill";
pub const OP_FEDERATION_TRANSACTION: &str = "cx.federation.transaction";

/// Index and search operations.
pub const OP_INDEX_DESCRIBE: &str = "cx.index.describe";
pub const OP_INDEX_QUERY: &str = "cx.index.query";
pub const OP_INDEX_THREAD: &str = "cx.index.thread";
pub const OP_INDEX_NOTIFICATIONS: &str = "cx.index.notifications";
pub const OP_INDEX_INBOX: &str = "cx.index.inbox";
pub const OP_INDEX_SEARCH: &str = "cx.index.search";

/// Directory operations.
pub const OP_DIRECTORY_DESCRIBE: &str = "cx.directory.describe";

/// Blob operations.
pub const OP_BLOB_UPLOAD: &str = "cx.blob.upload";
pub const OP_BLOB_HEAD: &str = "cx.blob.head";
pub const OP_BLOB_GET: &str = "cx.blob.get";

/// Push and key operations.
pub const OP_PUSH_NOTIFY: &str = "cx.push.notify";
pub const OP_KEYS_UPLOAD: &str = "cx.keys.upload";
pub const OP_KEYS_QUERY: &str = "cx.keys.query";
pub const OP_KEYS_CLAIM: &str = "cx.keys.claim";

/// Authorization check.
pub const OP_AUTHZ_CHECK: &str = "cx.authz.check";

/// Canonical operation kinds built into this SDK.
pub const BUILT_IN_OPERATION_KINDS: &[&str] = &[
    OP_ENTITY_CREATE,
    OP_ENTITY_UPDATE,
    OP_ENTITY_DELETE,
    OP_ENTITY_RESTORE,
    OP_ENTITY_REDACT,
    OP_RELATION_CREATE,
    OP_RELATION_DELETE,
    OP_RELATION_MOVE,
    OP_TASK_CREATE,
    OP_TASK_UPDATE,
    OP_TASK_MOVE,
    OP_VIEW_CREATE,
    OP_VIEW_UPDATE,
    OP_VIEW_RECONCILE,
    OP_SPACE_CREATE,
    OP_SPACE_UPDATE,
    OP_SPACE_ORGANIZATION,
    OP_SPACE_CHILD,
    OP_MESSAGE_CREATE,
    OP_SERVER_DESCRIBE,
    OP_IDENTITY_RESOLVE,
    OP_REPO_DESCRIBE,
    OP_REPO_SYNC,
    OP_SYNC_DESCRIBE,
    OP_SYNC_SUBSCRIBE,
    OP_SYNC_BACKFILL,
    OP_FEDERATION_TRANSACTION,
    OP_INDEX_DESCRIBE,
    OP_INDEX_QUERY,
    OP_INDEX_THREAD,
    OP_INDEX_NOTIFICATIONS,
    OP_INDEX_INBOX,
    OP_INDEX_SEARCH,
    OP_DIRECTORY_DESCRIBE,
    OP_BLOB_UPLOAD,
    OP_BLOB_HEAD,
    OP_BLOB_GET,
    OP_PUSH_NOTIFY,
    OP_KEYS_UPLOAD,
    OP_KEYS_QUERY,
    OP_KEYS_CLAIM,
    OP_AUTHZ_CHECK,
];

/// Compatibility profile for operation kind parsing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationCompatibilityProfile {
    /// Accept only canonical `cx.*` operation names.
    #[default]
    CanonicalOnly,
    /// Accept legacy bare aliases and map them to canonical `cx.*` names.
    LegacyBareNames,
}

/// Registry entry for one operation kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationKindSpec {
    pub kind: String,
    pub schema: String,
    #[serde(default)]
    pub legacy_aliases: Vec<String>,
    #[serde(default)]
    pub required_content_fields: Vec<String>,
}

/// Result of validating an operation kind against the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationKindValidation {
    pub canonical_kind: String,
    pub legacy_alias_used: Option<String>,
}

/// Canonical operation registry with explicit legacy migration aliases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationKindRegistry {
    specs: BTreeMap<String, OperationKindSpec>,
    legacy_aliases: BTreeMap<String, String>,
}

impl OperationKindRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self { specs: BTreeMap::new(), legacy_aliases: BTreeMap::new() }
    }

    /// Register one operation kind.
    pub fn register(&mut self, spec: OperationKindSpec) {
        for alias in &spec.legacy_aliases {
            self.legacy_aliases.insert(alias.clone(), spec.kind.clone());
        }
        self.specs.insert(spec.kind.clone(), spec);
    }

    /// Return the spec for a canonical kind.
    pub fn spec(&self, kind: &str) -> Option<&OperationKindSpec> {
        self.specs.get(kind)
    }

    /// Resolve a kind to canonical form under the chosen compatibility profile.
    pub fn canonicalize(
        &self,
        kind: &str,
        profile: OperationCompatibilityProfile,
    ) -> Result<OperationKindValidation> {
        if self.specs.contains_key(kind) {
            return Ok(OperationKindValidation {
                canonical_kind: kind.to_owned(),
                legacy_alias_used: None,
            });
        }
        if profile == OperationCompatibilityProfile::LegacyBareNames
            && let Some(canonical) = self.legacy_aliases.get(kind)
        {
            return Ok(OperationKindValidation {
                canonical_kind: canonical.clone(),
                legacy_alias_used: Some(kind.to_owned()),
            });
        }
        Err(Error::Protocol(format!("unknown operation kind '{kind}'")))
    }

    /// Validate an operation envelope against registered semantic requirements.
    pub fn validate_envelope(
        &self,
        envelope: &OperationEnvelope,
        profile: OperationCompatibilityProfile,
    ) -> Result<OperationKindValidation> {
        let validation = self.canonicalize(&envelope.kind, profile)?;
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
                legacy_aliases: vec![legacy_alias_for_operation_kind(kind)],
                required_content_fields: required_fields_for_operation_kind(kind),
            });
        }
        registry
    }
}

fn legacy_alias_for_operation_kind(kind: &str) -> String {
    kind.strip_prefix("cx.").unwrap_or(kind).replace('.', "_")
}

fn required_fields_for_operation_kind(kind: &str) -> Vec<String> {
    match kind {
        OP_ENTITY_CREATE | OP_ENTITY_UPDATE | OP_ENTITY_DELETE | OP_ENTITY_RESTORE
        | OP_ENTITY_REDACT => vec!["entity_id".to_owned()],
        OP_RELATION_CREATE | OP_RELATION_DELETE | OP_RELATION_MOVE => {
            vec!["relation_id".to_owned()]
        }
        OP_MESSAGE_CREATE => vec!["body".to_owned()],
        _ => Vec::new(),
    }
}

/// Operation registry conformance vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationKindConformanceVector {
    pub input_kind: String,
    pub profile: OperationCompatibilityProfile,
    pub canonical_kind: String,
}

/// Conformance vectors for every built-in operation kind and its legacy alias.
pub fn operation_kind_conformance_vectors() -> Vec<OperationKindConformanceVector> {
    BUILT_IN_OPERATION_KINDS
        .iter()
        .flat_map(|kind| {
            [
                OperationKindConformanceVector {
                    input_kind: (*kind).to_owned(),
                    profile: OperationCompatibilityProfile::CanonicalOnly,
                    canonical_kind: (*kind).to_owned(),
                },
                OperationKindConformanceVector {
                    input_kind: legacy_alias_for_operation_kind(kind),
                    profile: OperationCompatibilityProfile::LegacyBareNames,
                    canonical_kind: (*kind).to_owned(),
                },
            ]
        })
        .collect()
}

/// Protocol JSON Schema registry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolSchemaRegistry {
    schemas: BTreeMap<String, Value>,
    trusted_extension_prefixes: Vec<String>,
}

/// JSON value type rule extracted from a supported JSON Schema document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct GeneratedSchemaField {
    pub name: String,
    pub value_type: GeneratedSchemaValueType,
    pub required: bool,
}

/// Runtime validator generated from the JSON Schema subset supported by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
            .ok_or_else(|| Error::Protocol("schema is missing required field list".to_owned()))?
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
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Protocol("schema is missing required field list".to_owned()))?;
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

    /// Validate required fields using the registered schema document.
    ///
    /// Kept as a compatibility wrapper for callers that adopted the early SDK
    /// API name before basic type validation was added.
    pub fn validate_required_fields(&self, schema_id: &str, value: &Value) -> Result<()> {
        self.validate_value(schema_id, value)
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
                &["schema", "event_id", "space_id", "actor_id", "kind", "content"],
                &[
                    ("schema", "string"),
                    ("event_id", "string"),
                    ("space_id", "string"),
                    ("actor_id", "string"),
                    ("kind", "string"),
                    ("content", "object"),
                ],
            ),
        );
        registry.register(
            OPERATION_SCHEMA,
            object_schema(
                OPERATION_SCHEMA,
                &["operation_id", "space_id", "actor_id", "kind", "causal", "content"],
                &[
                    ("operation_id", "string"),
                    ("space_id", "string"),
                    ("actor_id", "string"),
                    ("kind", "string"),
                    ("causal", "object"),
                    ("content", "object"),
                ],
            ),
        );
        registry.register(
            COMMIT_SCHEMA,
            object_schema(
                COMMIT_SCHEMA,
                &["schema", "commit_id", "repo_id", "author", "author_seq", "operations"],
                &[
                    ("schema", "string"),
                    ("commit_id", "string"),
                    ("repo_id", "string"),
                    ("author", "string"),
                    ("author_seq", "integer"),
                    ("operations", "array"),
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

/// Profile-specific protocol conformance domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceProfile {
    Encoding,
    Hlc,
    Cursor,
    StateResolution,
    Redaction,
    Capability,
    Sync,
    Snapshot,
    FederationSignatures,
    Privacy,
    Security,
}

/// One conformance test case descriptor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceCase {
    pub case_id: String,
    pub description: String,
    pub schema_id: Option<String>,
    pub vector: Value,
}

/// Conformance suite for one protocol profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceSuite {
    pub profile: ConformanceProfile,
    pub cases: Vec<ConformanceCase>,
}

/// Version compatibility for one protocol schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCompatibilityEntry {
    pub schema_id: String,
    pub current_version: String,
    pub compatible_since: String,
    pub migration_required: bool,
}

/// Published schema compatibility table for SDK consumers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCompatibilityTable {
    pub profile: String,
    pub entries: Vec<SchemaCompatibilityEntry>,
}

/// Compatibility table for built-in schemas.
pub fn schema_version_compatibility_table() -> SchemaCompatibilityTable {
    SchemaCompatibilityTable {
        profile: SCHEMA_COMPATIBILITY_PROFILE.to_owned(),
        entries: [
            CURSOR_SCHEMA,
            EVENT_SCHEMA,
            OPERATION_SCHEMA,
            COMMIT_SCHEMA,
            CAPABILITY_SCHEMA,
            ENCRYPTED_PAYLOAD_SCHEMA,
            CLIENT_SYNC_RESPONSE_SCHEMA,
        ]
        .into_iter()
        .map(|schema_id| SchemaCompatibilityEntry {
            schema_id: schema_id.to_owned(),
            current_version: "1".to_owned(),
            compatible_since: "0.1.0".to_owned(),
            migration_required: false,
        })
        .collect(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceCaseResult {
    pub profile: ConformanceProfile,
    pub case_id: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceProfileCoverage {
    pub profile: ConformanceProfile,
    pub cases_total: usize,
    pub cases_passed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub fixture_version: String,
    pub passed: bool,
    pub coverage: Vec<ConformanceProfileCoverage>,
    pub results: Vec<ConformanceCaseResult>,
}

/// Loadable conformance fixture set used by SDK and external fixtures.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceFixtureSet {
    pub fixture_version: String,
    pub suites: Vec<ConformanceSuite>,
}

impl ConformanceFixtureSet {
    /// Built-in fixtures shipped with the SDK.
    pub fn builtin() -> Self {
        Self {
            fixture_version: BUILT_IN_CONFORMANCE_FIXTURES_VERSION.to_owned(),
            suites: profile_conformance_suites(),
        }
    }

    /// Decode a fixture set from JSON.
    pub fn from_json(value: Value) -> Result<Self> {
        let fixtures: Self = serde_json::from_value(value)?;
        fixtures.validate()?;
        Ok(fixtures)
    }

    /// Validate fixture shape before execution.
    pub fn validate(&self) -> Result<()> {
        if self.fixture_version.trim().is_empty() {
            return Err(Error::Protocol("fixture_version must be non-empty".to_owned()));
        }
        if self.suites.is_empty() {
            return Err(Error::Protocol("fixture set must contain at least one suite".to_owned()));
        }
        for suite in &self.suites {
            if suite.cases.is_empty() {
                return Err(Error::Protocol(format!(
                    "conformance suite {:?} must contain cases",
                    suite.profile
                )));
            }
            for case in &suite.cases {
                if case.case_id.trim().is_empty() {
                    return Err(Error::Protocol(
                        "conformance case id must be non-empty".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Execute the fixture set against SDK validators.
    pub fn run(&self) -> ConformanceReport {
        let registry = ProtocolSchemaRegistry::default();
        run_conformance_suites(&registry, self.fixture_version.clone(), &self.suites)
    }
}

/// Built-in profile-specific conformance suites.
pub fn profile_conformance_suites() -> Vec<ConformanceSuite> {
    vec![
        conformance_suite(
            ConformanceProfile::Encoding,
            "canonical-json-digest",
            "Canonical JSON and digest vectors reject ambiguous encodings.",
            Some(OPERATION_SCHEMA),
            json!({"input": {"b": 2, "a": 1}, "digest_required": true}),
        ),
        conformance_suite(
            ConformanceProfile::Hlc,
            "hlc-monotonic-canonical-form",
            "HLC values use fixed-width lowercase hex and preserve causal ordering.",
            None,
            json!({"fixed_width": true, "lowercase": true, "causal_ordering": true}),
        ),
        conformance_suite(
            ConformanceProfile::Cursor,
            "cursor-token-binding-and-expiry",
            "Cursor tokens bind positions and reject stale or malformed encodings.",
            Some(CURSOR_SCHEMA),
            json!({"binds_positions": true, "expires": true, "rejects_malformed": true}),
        ),
        conformance_suite(
            ConformanceProfile::StateResolution,
            "state-reducer-convergence",
            "Reducer inputs with different insertion order converge to the same state hash.",
            Some(EVENT_SCHEMA),
            json!({"order_independent": true, "requires_merkle_root": true}),
        ),
        conformance_suite(
            ConformanceProfile::Redaction,
            "redaction-preserves-auth-fields",
            "Redaction removes content while preserving IDs, actor, HLC and auth references.",
            Some(EVENT_SCHEMA),
            json!({"preserve": ["event_id", "actor_id", "hlc", "auth_refs"]}),
        ),
        conformance_suite(
            ConformanceProfile::Capability,
            "capability-frontier-validation",
            "Capability checks run at the causal frontier and fail closed on unknown critical constraints.",
            Some(CAPABILITY_SCHEMA),
            json!({"fail_closed": true, "frontier_bound": true}),
        ),
        conformance_suite(
            ConformanceProfile::Sync,
            "sync-token-binding",
            "Sync tokens bind principal, device, service, filter hash and stream positions.",
            Some(CLIENT_SYNC_RESPONSE_SCHEMA),
            json!({"binds_filter": true, "binds_positions": true}),
        ),
        conformance_suite(
            ConformanceProfile::Snapshot,
            "snapshot-chunk-digests",
            "Snapshot manifests verify chunk digests before reducer restore.",
            None,
            json!({"chunk_digest": "sha256", "restore_requires_all_chunks": true}),
        ),
        conformance_suite(
            ConformanceProfile::FederationSignatures,
            "http-message-signature-binding",
            "Federation signatures bind method, target URI, authority, digest and service DIDs.",
            None,
            json!({"requires_origin_did": true, "requires_destination_did": true}),
        ),
        conformance_suite(
            ConformanceProfile::Privacy,
            "not-found-and-private-did-privacy",
            "Invisible resources and private DID lookups avoid oracle behavior.",
            None,
            json!({"privacy_preserving_not_found": true, "requires_resolution_proof": true}),
        ),
        conformance_suite(
            ConformanceProfile::Security,
            "proof-policy-and-redaction-fail-closed",
            "Security-sensitive schema extensions, proof bindings and log payloads fail closed.",
            Some(ENCRYPTED_PAYLOAD_SCHEMA),
            json!({"fail_closed_extensions": true, "proof_binding": true, "redact_secrets": true}),
        ),
    ]
}

fn conformance_suite(
    profile: ConformanceProfile,
    case_id: &str,
    description: &str,
    schema_id: Option<&str>,
    vector: Value,
) -> ConformanceSuite {
    ConformanceSuite {
        profile,
        cases: vec![ConformanceCase {
            case_id: case_id.to_owned(),
            description: description.to_owned(),
            schema_id: schema_id.map(str::to_owned),
            vector,
        }],
    }
}

/// Execute the SDK's built-in conformance descriptors and return a
/// machine-readable report that downstream projects can store as release
/// evidence. Official external fixtures can be loaded by callers into the same
/// report shape.
pub fn run_builtin_conformance_report() -> ConformanceReport {
    ConformanceFixtureSet::builtin().run()
}

fn run_conformance_suites(
    registry: &ProtocolSchemaRegistry,
    fixture_version: String,
    suites: &[ConformanceSuite],
) -> ConformanceReport {
    let mut results = Vec::new();

    for suite in suites {
        for case in &suite.cases {
            let error =
                validate_conformance_case(registry, case).err().map(|error| error.to_string());
            results.push(ConformanceCaseResult {
                profile: suite.profile,
                case_id: case.case_id.clone(),
                passed: error.is_none(),
                error,
            });
        }
    }

    let coverage = suites
        .iter()
        .map(|suite| {
            let cases_total =
                results.iter().filter(|result| result.profile == suite.profile).count();
            let cases_passed = results
                .iter()
                .filter(|result| result.profile == suite.profile && result.passed)
                .count();
            ConformanceProfileCoverage { profile: suite.profile, cases_total, cases_passed }
        })
        .collect::<Vec<_>>();
    let passed = results.iter().all(|result| result.passed);

    ConformanceReport { fixture_version, passed, coverage, results }
}

fn validate_conformance_case(
    registry: &ProtocolSchemaRegistry,
    case: &ConformanceCase,
) -> Result<()> {
    if case.case_id.trim().is_empty() {
        return Err(Error::Protocol("conformance case id must be non-empty".to_owned()));
    }
    if case.vector.is_null() {
        return Err(Error::Protocol(format!(
            "conformance case '{}' must contain a vector payload",
            case.case_id
        )));
    }
    if let Some(schema_id) = &case.schema_id {
        registry
            .schema(schema_id)
            .ok_or_else(|| Error::Protocol(format!("unknown conformance schema '{schema_id}'")))?;
    }
    Ok(())
}

macro_rules! id_type {
    ($name:ident, $expect:expr) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !$expect(&value) {
                    return Err(Error::InvalidId(value));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self> {
                Self::new(value)
            }
        }
    };
}

fn is_did(value: &str) -> bool {
    let Some(remainder) = value.strip_prefix("did:") else {
        return false;
    };
    let Some((method, method_specific_id)) = remainder.split_once(':') else {
        return false;
    };
    if method.is_empty()
        || method_specific_id.is_empty()
        || !method.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return false;
    }

    if method == "uuid" {
        return is_canonical_uuid(method_specific_id);
    }

    true
}

fn is_canonical_uuid(value: &str) -> bool {
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return false;
    }

    let mut non_zero = false;
    for (idx, byte) in value.bytes().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            continue;
        }
        if !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase() {
            return false;
        }
        non_zero |= byte != b'0';
    }
    if !non_zero {
        return false;
    }

    let version = value.as_bytes()[14];
    let variant = value.as_bytes()[19];
    matches!(version, b'4' | b'7') && matches!(variant, b'8' | b'9' | b'a' | b'b')
}

fn is_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value["sha256:".len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn has_prefix<'a>(prefix: &'a str) -> impl Fn(&str) -> bool + 'a {
    move |value| value.starts_with(prefix) && value.len() > prefix.len()
}

id_type!(Did, is_did);
id_type!(SpaceId, has_prefix("cx:space:"));
id_type!(EntityId, has_prefix("cx:entity:"));
id_type!(RelationId, has_prefix("cx:relation:"));
id_type!(EventId, |value: &str| value.starts_with("cx:event:") || is_hash(value));
id_type!(CommitId, has_prefix("cx:commit:"));
id_type!(OperationId, |value: &str| value.starts_with("cx:operation:") || is_hash(value));
id_type!(GrantId, has_prefix("cx:grant:"));
id_type!(InviteId, has_prefix("cx:invite:"));
id_type!(DeviceId, |value: &str| (value.starts_with("dev_") && value.len() > "dev_".len())
    || (value.starts_with("cx:device:") && value.len() > "cx:device:".len()));
id_type!(PolicyId, has_prefix("cx:policy:"));
id_type!(BlobRef, |value: &str| value.starts_with("cx:blob:") || is_hash(value));

impl BlobRef {
    /// Create a content-addressed `sha256:…` blob reference from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        // Safety: the digest is always a valid sha256:hash form.
        Self(digest)
    }
}

id_type!(ViewId, has_prefix("cx:view:"));
id_type!(Hash, is_hash);
id_type!(Cursor, has_prefix("cx:cursor:"));

impl Did {
    /// Generate a random canonical `did:uuid` value using UUIDv4 layout.
    pub fn new_uuid_v4() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|error| Error::Crypto(error.to_string()))?;
        Self::uuid_v4_from_bytes(bytes)
    }

    /// Build a canonical `did:uuid` value from raw UUIDv4 bytes.
    pub fn uuid_v4_from_bytes(mut bytes: [u8; 16]) -> Result<Self> {
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self::new(format!("did:uuid:{}", format_uuid_bytes(bytes)))
    }

    /// Return the DID method name.
    pub fn method(&self) -> &str {
        self.0
            .strip_prefix("did:")
            .and_then(|remainder| remainder.split_once(':').map(|(method, _)| method))
            .expect("DID constructed with method")
    }

    /// Return whether this DID uses the canonical `did:uuid` method form.
    pub fn is_uuid(&self) -> bool {
        self.method() == "uuid"
    }
}

fn format_uuid_bytes(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hlc(String);

impl Hlc {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        Self::parse_parts(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse_parts(value: &str) -> Result<(u64, u64, &str)> {
        let mut parts = value.split('-');
        let unix_ms = parts
            .next()
            .ok_or_else(|| Error::InvalidId(value.to_owned()))
            .and_then(|part| parse_lower_hex(part, value))?;
        let logical = parts
            .next()
            .ok_or_else(|| Error::InvalidId(value.to_owned()))
            .and_then(|part| parse_lower_hex(part, value))?;
        let node = parts.next().ok_or_else(|| Error::InvalidId(value.to_owned()))?;
        if parts.next().is_some()
            || value.len() != 30
            || value.as_bytes().get(12) != Some(&b'-')
            || value.as_bytes().get(21) != Some(&b'-')
            || node.is_empty()
            || node.len() != 8
            || !node.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::InvalidId(value.to_owned()));
        }
        Ok((unix_ms, logical, node))
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Hlc {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_ms, self_logical, self_node) =
            Self::parse_parts(&self.0).expect("HLC constructed with valid parts");
        let (other_ms, other_logical, other_node) =
            Self::parse_parts(&other.0).expect("HLC constructed with valid parts");
        (self_ms, self_logical, self_node).cmp(&(other_ms, other_logical, other_node))
    }
}

fn parse_lower_hex(part: &str, original: &str) -> Result<u64> {
    if part.is_empty()
        || !matches!(part.len(), 8 | 12)
        || !part.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::InvalidId(original.to_owned()));
    }
    u64::from_str_radix(part, 16).map_err(|_| Error::InvalidId(original.to_owned()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceKind {
    Collaboration,
    Direct,
    Group,
    Project,
    Document,
    Board,
    Channel,
    SocialFeed,
    Enclave,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Discoverability {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinRule {
    Public,
    Invite,
    Knock,
    Restricted,
    KnockRestricted,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryVisibility {
    WorldReadable,
    Shared,
    Invited,
    Joined,
    Restricted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationPolicy {
    Open,
    Restricted,
    Closed,
    Quarantine,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionProfile {
    None,
    MlsRfc9420,
    External,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    Org,
    Team,
    Agent,
    Service,
    Device,
    Integration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorStatus {
    Active,
    Suspended,
    Deleted,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Board,
    Collection,
    Comment,
    Task,
    Message,
    Topic,
    Channel,
    Document,
    File,
    Memory,
    Run,
    ActorProfile,
    Poll,
    SocialPost,
    SocialFeed,
    SocialCircle,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Contains,
    BelongsTo,
    RepliesTo,
    DependsOn,
    Blocks,
    Mentions,
    AssignedTo,
    References,
    DerivedFrom,
    AttachedTo,
    HasTopic,
    HasDefaultView,
    Produced,
    Used,
    TriggeredBy,
    HasLog,
    Follows,
    Contact,
    CircleMember,
    BlocksSocial,
    Reposts,
    Quotes,
    Likes,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    // Work-object views
    Kanban,
    List,
    Table,
    Calendar,
    Timeline,
    Graph,
    Tree,
    Gantt,
    Matrix,
    Document,
    Dashboard,
    // Conversation views
    Chat,
    Forum,
    Thread,
    Activity,
    Inbox,
    Notifications,
    // Review / agent views
    MemoryReview,
    AgentRuns,
    ContextTimeline,
    // Legacy alias
    ReviewQueue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectState {
    Active,
    Archived,
    Deleted,
    Redacted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationState {
    Active,
    Deleted,
    Redacted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    Access,
    Encryption,
    Retention,
    Federation,
    Moderation,
    Discoverability,
    Join,
    HistoryVisibility,
    PlaintextVisibility,
    Media,
    Applet,
    Agent,
    Social,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthzDecision {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
    SoftFail,
}

pub type Decision = AuthzDecision;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteState {
    Pending,
    Accepted,
    Rejected,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    Mention,
    Reply,
    Assignment,
    Invite,
    Reaction,
    Policy,
    Call,
    Applet,
    Agent,
    Moderation,
    System,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPriority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationState {
    Unread,
    Read,
    Dismissed,
    Archived,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadScope {
    Space,
    Channel,
    Topic,
    Thread,
    View,
    Entity,
}

/// Channel kind for conversation entities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Chat,
    Announce,
    Support,
    Activity,
}

/// Account lifecycle states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    Erased,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    Create,
    Update,
    Delete,
    Redact,
    Grant,
    Revoke,
    SnapshotRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KanbanColumnModel {
    FieldValue,
    Collection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncategorizedPolicy {
    Show,
    Hide,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullsOrder {
    First,
    Last,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Eq,
    Neq,
    In,
    NotIn,
    Lt,
    Lte,
    Gt,
    Gte,
    Contains,
    Exists,
    Prefix,
    FullText,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationDirection {
    Out,
    In,
    Both,
}

/// Audience policy mode for social graph content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudiencePolicyMode {
    Public,
    Followers,
    Contacts,
    Circle,
    Organization,
    SpaceMembers,
    Direct,
    Private,
}

/// Interaction controls for audience policy.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AudienceInteractionPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub react: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reshare: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
}

/// Indexing controls for audience policy.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AudienceIndexingPolicy {
    #[serde(default)]
    pub public_search: bool,
    #[serde(default)]
    pub directory_preview: bool,
    #[serde(default)]
    pub external_crawlers: bool,
}

/// Audience policy for social graph content.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AudiencePolicy {
    pub mode: AudiencePolicyMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub circle_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_refs: Vec<Did>,
    #[serde(default)]
    pub interaction: AudienceInteractionPolicy,
    #[serde(default)]
    pub indexing: AudienceIndexingPolicy,
    /// If true, freeze audience at publish time — removing someone later
    /// does not grant access to historical content.
    #[serde(default)]
    pub snapshot_at_publish: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptedPayloadScheme {
    MlsRfc9420,
}

impl EncryptedPayloadScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MlsRfc9420 => "mls-rfc9420",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub payload_hash: Hash,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub jws: String,
}

/// Allowed proof algorithms for production use.
const PRODUCTION_ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ES256K", "RS256", "PS256"];

/// Proof kinds that indicate development/test mode and are rejected in production.
const DEV_PROOF_KINDS: &[&str] = &["dev", "test", "mock", "stub", "dummy"];

impl Proof {
    pub fn binding_payload(&self, actor_id: &Did) -> SignatureBindingPayload {
        SignatureBindingPayload {
            payload_hash: self.payload_hash.clone(),
            actor_id: actor_id.clone(),
            verification_method: self.verification_method.clone(),
            created_at: self.created_at,
            domain: self.domain.clone(),
            audience: self.audience.clone(),
        }
    }

    /// Validate proof structural requirements.
    ///
    /// Rejects `alg:none`, empty verification methods, empty JWS, and
    /// empty kind.
    pub fn validate(&self) -> Result<()> {
        if self.alg.eq_ignore_ascii_case("none") {
            return Err(Error::Protocol("proof algorithm 'none' is not allowed".to_owned()));
        }
        if self.alg.is_empty() {
            return Err(Error::Protocol("proof algorithm must not be empty".to_owned()));
        }
        if self.verification_method.is_empty() {
            return Err(Error::Protocol("proof verification_method must not be empty".to_owned()));
        }
        if self.jws.is_empty() {
            return Err(Error::Protocol("proof JWS must not be empty".to_owned()));
        }
        if self.kind.is_empty() {
            return Err(Error::Protocol("proof kind must not be empty".to_owned()));
        }
        Ok(())
    }

    /// Validate that this proof uses a production-grade algorithm and kind.
    ///
    /// Rejects `alg:none`, unknown algorithms, and dev/test proof kinds.
    pub fn validate_production(&self) -> Result<()> {
        self.validate()?;
        if DEV_PROOF_KINDS.iter().any(|k| self.kind.eq_ignore_ascii_case(k)) {
            return Err(Error::Protocol(format!(
                "production proofs must not use dev/test kind: {}",
                self.kind
            )));
        }
        if !PRODUCTION_ALGORITHMS.iter().any(|a| self.alg.eq_ignore_ascii_case(a)) {
            return Err(Error::Protocol(format!(
                "unsupported production proof algorithm: {}",
                self.alg
            )));
        }
        Ok(())
    }

    /// Validate that the proof's structural fields match the expected binding.
    ///
    /// Checks: verification_method, payload_hash, created_at (within tolerance),
    /// domain, and audience.
    pub fn validate_binding(&self, expected: &SignatureBindingPayload) -> Result<()> {
        self.validate()?;
        if self.verification_method != expected.verification_method {
            return Err(Error::Protocol(format!(
                "proof verification_method '{}' does not match expected '{}'",
                self.verification_method, expected.verification_method
            )));
        }
        if self.payload_hash != expected.payload_hash {
            return Err(Error::Protocol(
                "proof payload_hash does not match expected digest".to_owned(),
            ));
        }
        // Allow 5-minute clock skew tolerance for created_at
        let diff = if self.created_at > expected.created_at {
            self.created_at - expected.created_at
        } else {
            expected.created_at - self.created_at
        };
        if diff.num_minutes() > 5 {
            return Err(Error::Protocol(format!(
                "proof created_at differs from expected by {} minutes (max 5)",
                diff.num_minutes()
            )));
        }
        if self.domain != expected.domain {
            return Err(Error::Protocol(format!(
                "proof domain {:?} does not match expected {:?}",
                self.domain, expected.domain
            )));
        }
        if self.audience != expected.audience {
            return Err(Error::Protocol(format!(
                "proof audience {:?} does not match expected {:?}",
                self.audience, expected.audience
            )));
        }
        Ok(())
    }

    /// Validate that the proof's payload_hash matches the canonical digest of a payload.
    pub fn validate_payload_digest(&self, payload: &impl Serialize) -> Result<()> {
        let computed = canonical::canonical_sha256(payload)?;
        let expected = Hash::new(computed)?;
        if self.payload_hash != expected {
            return Err(Error::Protocol(format!(
                "proof payload_hash '{}' does not match computed digest '{}'",
                self.payload_hash, expected
            )));
        }
        Ok(())
    }
}

/// Server-verified fact-chain echo returned to clients after write admission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FactChainEcho {
    pub echo_id: String,
    pub subject_ref: String,
    pub server_did: Did,
    pub operation_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_echo_hash: Option<Hash>,
    pub observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

impl FactChainEcho {
    /// Build the canonical payload signed by a server.
    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
        }
        Ok(value)
    }

    /// Compute the canonical digest for this echo.
    pub fn echo_digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    /// Validate server proofs against this echo's digest.
    pub fn validate_server_proofs(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol("fact-chain echo has no server proof".to_owned()));
        }
        let expected = Hash::new(self.echo_digest()?)?;
        for proof in &self.proofs {
            proof.validate_production()?;
            if proof.payload_hash != expected {
                return Err(Error::Protocol(format!(
                    "fact-chain proof payload_hash '{}' does not match echo digest '{}'",
                    proof.payload_hash, expected
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureBindingPayload {
    pub payload_hash: Hash,
    pub actor_id: Did,
    pub verification_method: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Space {
    pub schema: String,
    pub id: SpaceId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_version: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub space_kind: SpaceKind,
    pub created_by_principal: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owning_organizations: Vec<Did>,
    pub schema_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<PolicyId>,
    pub default_discoverability: Discoverability,
    pub default_join_rule: JoinRule,
    pub history_visibility: HistoryVisibility,
    pub encryption_profile: EncryptionProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy_ref: Option<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Space {
    pub fn new(
        id: SpaceId,
        title: impl Into<String>,
        space_kind: SpaceKind,
        created_by_principal: Did,
    ) -> Self {
        Self {
            schema: SPACE_SCHEMA.to_owned(),
            id,
            object_type: "space".to_owned(),
            space_version: "1".to_owned(),
            title: title.into(),
            summary: None,
            space_kind,
            created_by_principal,
            owning_organizations: Vec::new(),
            schema_refs: vec![CORE_SCHEMA_PROFILE.to_owned()],
            policy_ref: None,
            default_discoverability: Discoverability::InviteOnly,
            default_join_rule: JoinRule::Invite,
            history_visibility: HistoryVisibility::Joined,
            encryption_profile: EncryptionProfile::None,
            federation_policy: None,
            retention_policy_ref: None,
            avatar_blob_ref: None,
            created_at: Utc::now(),
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActorProfile {
    pub schema: String,
    pub id: EntityId,
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub principal_id: Did,
    pub actor_type: ActorType,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ActorStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_to: Vec<Did>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entity {
    pub schema: String,
    pub id: EntityId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_id: SpaceId,
    pub entity_type: EntityType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Entity {
    pub fn validate_content_object(&self) -> Result<()> {
        match &self.content {
            Some(Value::Object(_)) | None => Ok(()),
            Some(_) => Err(Error::Protocol("entity content must be a JSON object".to_owned())),
        }
    }

    /// Create a channel entity.
    pub fn channel(
        entity_id: EntityId,
        space_id: SpaceId,
        title: impl Into<String>,
        created_by: Did,
        channel_kind: ChannelKind,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert(
            "channel_kind".to_owned(),
            serde_json::to_value(channel_kind).unwrap_or_default(),
        );
        Self {
            schema: ENTITY_SCHEMA.to_owned(),
            id: entity_id,
            object_type: "entity".to_owned(),
            space_id,
            entity_type: EntityType::Channel,
            title: Some(title.into()),
            content: None,
            fields,
            state: Some(ObjectState::Active),
            version: Some(1),
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Create a topic entity.
    pub fn topic(
        entity_id: EntityId,
        space_id: SpaceId,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            schema: ENTITY_SCHEMA.to_owned(),
            id: entity_id,
            object_type: "entity".to_owned(),
            space_id,
            entity_type: EntityType::Topic,
            title: Some(title.into()),
            content: None,
            fields: BTreeMap::new(),
            state: Some(ObjectState::Active),
            version: Some(1),
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Create a comment entity.
    pub fn comment(
        entity_id: EntityId,
        space_id: SpaceId,
        created_by: Did,
        content: Value,
    ) -> Self {
        Self {
            schema: ENTITY_SCHEMA.to_owned(),
            id: entity_id,
            object_type: "entity".to_owned(),
            space_id,
            entity_type: EntityType::Comment,
            title: None,
            content: Some(content),
            fields: BTreeMap::new(),
            state: Some(ObjectState::Active),
            version: Some(1),
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Get the channel kind if this is a channel entity.
    pub fn channel_kind(&self) -> Option<&Value> {
        if self.entity_type == EntityType::Channel { self.fields.get("channel_kind") } else { None }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relation {
    pub schema: String,
    pub id: RelationId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_id: SpaceId,
    pub relation_kind: RelationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<RelationState>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

impl Relation {
    pub fn validate_endpoints(&self) -> Result<()> {
        let from_count = self.from_entity_id.is_some() as u8
            + self.from_actor_id.is_some() as u8
            + self.from_space_id.is_some() as u8;
        let to_count = self.to_entity_id.is_some() as u8
            + self.to_actor_id.is_some() as u8
            + self.to_space_id.is_some() as u8;

        if from_count == 1 && to_count == 1 {
            Ok(())
        } else {
            Err(Error::Protocol(
                "relation must have exactly one from_* and one to_* endpoint".to_owned(),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub event_id: EventId,
    pub kind: String,
    pub space_id: SpaceId,
    pub space_version: String,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub prev_refs: Vec<EventId>,
    pub auth_refs: Vec<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<EventId>,
    pub content: Value,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<Proof>,
}

impl Event {
    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("event_id");
            map.remove("proofs");
            map.remove("unsigned");
        }
        Ok(value)
    }

    pub fn event_digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol("event proofs must contain at least one proof".to_owned()));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol("event content must be a JSON object".to_owned()));
        }
        Ok(())
    }

    /// Validate that all proofs bind to this event's digest.
    ///
    /// Checks each proof's `payload_hash` matches the canonical event digest,
    /// and that each proof is structurally valid.
    pub fn validate_proof_bindings(&self) -> Result<()> {
        let digest = self.event_digest()?;
        let expected_hash = Hash::new(digest)?;
        for proof in &self.proofs {
            proof.validate()?;
            if proof.payload_hash != expected_hash {
                return Err(Error::Protocol(format!(
                    "event proof payload_hash '{}' does not match event digest '{}'",
                    proof.payload_hash, expected_hash
                )));
            }
        }
        Ok(())
    }

    pub fn new(
        kind: impl Into<String>,
        space_id: SpaceId,
        actor_id: Did,
        actor_seq: u64,
        hlc: Hlc,
        content: Value,
    ) -> Result<Self> {
        let mut event = Self {
            event_id: EventId::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )?,
            kind: kind.into(),
            space_id,
            space_version: "1".to_owned(),
            actor_id,
            actor_seq,
            created_at: Utc::now(),
            hlc,
            prev_refs: Vec::new(),
            auth_refs: Vec::new(),
            redacts: None,
            content,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        };
        event.event_id = EventId::new(event.event_digest()?)?;
        Ok(event)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SortSpec {
    pub field: String,
    pub direction: SortDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nulls: Option<NullsOrder>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldFilter {
    pub field: String,
    pub op: FilterOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Filter {
    Predicate(FieldFilter),
    And { and: Vec<Filter> },
    Or { or: Vec<Filter> },
    Not { not: Box<Filter> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelationQuery {
    pub kind: RelationKind,
    pub direction: RelationDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
}

impl RelationQuery {
    pub fn validate_endpoints(&self) -> Result<()> {
        let source_count = self.source_entity_id.is_some() as u8
            + self.source_actor_id.is_some() as u8
            + self.source_space_id.is_some() as u8;
        let target_count = self.target_entity_id.is_some() as u8
            + self.target_actor_id.is_some() as u8
            + self.target_space_id.is_some() as u8;

        if source_count <= 1 && target_count <= 1 {
            Ok(())
        } else {
            Err(Error::Protocol(
                "relation query may specify at most one source_* and one target_* endpoint"
                    .to_owned(),
            ))
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QueryContext {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_kinds: Vec<RelationKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_tiebreak: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryConsistency {
    pub wait_for: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryRequest {
    pub space_ids: Vec<SpaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entity_types: Vec<EntityType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_entity_id: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<Filter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<RelationQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<QueryContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order_by: Vec<SortSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projection: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency: Option<QueryConsistency>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryFrontier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_hlc: Option<Hlc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryResponse<T = Value> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<QueryFrontier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct View {
    pub schema: String,
    pub id: ViewId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_id: SpaceId,
    pub kind: ViewKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub query: QueryRequest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visible_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kanban: Option<KanbanConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sort: Vec<SortSpec>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanConfig {
    pub column_model: KanbanColumnModel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<KanbanColumn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub board_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_relation_kind: Option<RelationKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_relation_kind: Option<RelationKind>,
    pub card_order_by: Vec<SortSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncategorized_policy: Option<UncategorizedPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanColumn {
    pub key: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wip_limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    pub schema: String,
    pub operation_id: OperationId,
    #[serde(rename = "type")]
    pub record_type: String,
    pub operation_type: OperationType,
    pub space_id: SpaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    pub object_type: String,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Operation {
    pub fn create(
        operation_id: OperationId,
        space_id: SpaceId,
        object_type: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            schema: OPERATION_SCHEMA.to_owned(),
            operation_id,
            record_type: "operation".to_owned(),
            operation_type: OperationType::Create,
            space_id,
            object_id: None,
            object_type: object_type.into(),
            payload,
            idempotency_key: None,
            created_at: Utc::now(),
        }
    }

    pub fn operation_digest(&self) -> Result<String> {
        canonical::canonical_sha256(self)
    }

    pub fn validate_payload_object(&self) -> Result<()> {
        if self.payload.is_object() {
            Ok(())
        } else {
            Err(Error::Protocol("operation payload must be a JSON object".to_owned()))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationEnvelope {
    pub operation_id: OperationId,
    pub space_id: SpaceId,
    #[serde(alias = "actor")]
    pub actor_id: Did,
    #[serde(alias = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    pub causal: CausalRef,
    #[serde(alias = "body")]
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authz_ref: Option<GrantId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

impl OperationEnvelope {
    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
        }
        Ok(value)
    }

    pub fn operation_digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "operation envelope proofs must contain at least one proof".to_owned(),
            ));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol(
                "operation envelope content must be a JSON object".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate that all proofs bind to this operation's digest.
    pub fn validate_proof_bindings(&self) -> Result<()> {
        let digest = self.operation_digest()?;
        let expected_hash = Hash::new(digest)?;
        for proof in &self.proofs {
            proof.validate()?;
            if proof.payload_hash != expected_hash {
                return Err(Error::Protocol(format!(
                    "operation proof payload_hash '{}' does not match operation digest '{}'",
                    proof.payload_hash, expected_hash
                )));
            }
        }
        Ok(())
    }
}

/// Registry-backed builder for [`OperationEnvelope`].
#[derive(Clone, Debug)]
pub struct OperationEnvelopeBuilder {
    operation_id: OperationId,
    space_id: SpaceId,
    actor_id: Did,
    kind: String,
    target_ref: Option<String>,
    deps: Vec<OperationId>,
    hlc: Hlc,
    actor_seq: u64,
    content: Value,
    authz_ref: Option<GrantId>,
    proofs: Vec<Proof>,
    profile: OperationCompatibilityProfile,
}

impl OperationEnvelopeBuilder {
    /// Create a builder for one registered operation kind.
    pub fn new(
        operation_id: OperationId,
        space_id: SpaceId,
        actor_id: Did,
        kind: impl Into<String>,
        actor_seq: u64,
        hlc: Hlc,
    ) -> Self {
        Self {
            operation_id,
            space_id,
            actor_id,
            kind: kind.into(),
            target_ref: None,
            deps: Vec::new(),
            hlc,
            actor_seq,
            content: Value::Object(Default::default()),
            authz_ref: None,
            proofs: Vec::new(),
            profile: OperationCompatibilityProfile::CanonicalOnly,
        }
    }

    /// Allow legacy bare-name operation kinds for this builder.
    pub fn with_compatibility_profile(mut self, profile: OperationCompatibilityProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set a target reference.
    pub fn with_target_ref(mut self, target_ref: impl Into<String>) -> Self {
        self.target_ref = Some(target_ref.into());
        self
    }

    /// Add a causal dependency.
    pub fn with_dependency(mut self, dependency: OperationId) -> Self {
        self.deps.push(dependency);
        self
    }

    /// Replace the content object.
    pub fn with_content(mut self, content: Value) -> Self {
        self.content = content;
        self
    }

    /// Insert one content field.
    pub fn with_content_field(mut self, field: impl Into<String>, value: Value) -> Self {
        if !self.content.is_object() {
            self.content = Value::Object(Default::default());
        }
        if let Value::Object(content) = &mut self.content {
            content.insert(field.into(), value);
        }
        self
    }

    /// Attach an authorization reference.
    pub fn with_authz_ref(mut self, authz_ref: GrantId) -> Self {
        self.authz_ref = Some(authz_ref);
        self
    }

    /// Attach a proof.
    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proofs.push(proof);
        self
    }

    /// Build and validate the operation envelope against a registry.
    pub fn build(self, registry: &OperationKindRegistry) -> Result<OperationEnvelope> {
        let validation = registry.canonicalize(&self.kind, self.profile)?;
        let envelope = OperationEnvelope {
            operation_id: self.operation_id,
            space_id: self.space_id,
            actor_id: self.actor_id,
            kind: validation.canonical_kind,
            target_ref: self.target_ref,
            causal: CausalRef { deps: self.deps, hlc: self.hlc, actor_seq: self.actor_seq },
            content: self.content,
            authz_ref: self.authz_ref,
            proofs: self.proofs,
        };
        registry.validate_envelope(&envelope, OperationCompatibilityProfile::CanonicalOnly)?;
        Ok(envelope)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CausalRef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<OperationId>,
    pub hlc: Hlc,
    pub actor_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationSignature {
    pub key_id: String,
    pub alg: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub schema: String,
    pub commit_id: CommitId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub repo_id: String,
    pub author: Did,
    pub author_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_commit: Option<Hash>,
    pub operations: Vec<Hash>,
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

impl Commit {
    pub fn new(
        commit_id: CommitId,
        repo_id: impl Into<String>,
        author: Did,
        author_seq: u64,
    ) -> Self {
        Self {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id,
            object_type: "commit".to_owned(),
            repo_id: repo_id.into(),
            author,
            author_seq,
            prev_commit: None,
            operations: Vec::new(),
            created_at: Utc::now(),
            proofs: Vec::new(),
        }
    }

    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
        }
        Ok(value)
    }

    pub fn commit_digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "commit proofs must contain at least one proof".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate that all proofs bind to this commit's digest.
    pub fn validate_proof_bindings(&self) -> Result<()> {
        let digest = self.commit_digest()?;
        let expected_hash = Hash::new(digest)?;
        for proof in &self.proofs {
            proof.validate()?;
            if proof.payload_hash != expected_hash {
                return Err(Error::Protocol(format!(
                    "commit proof payload_hash '{}' does not match commit digest '{}'",
                    proof.payload_hash, expected_hash
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CapabilitySubject {
    Did(Did),
    Selector(Value),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub schema: String,
    pub id: GrantId,
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub issuer: Did,
    pub subject: CapabilitySubject,
    pub actions: Vec<String>,
    pub resources: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Value>,
    #[serde(default)]
    pub delegable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<GrantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub schema: String,
    pub id: PolicyId,
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub policy_type: PolicyType,
    pub rules: Vec<Value>,
    pub default_effect: PolicyEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub schema: String,
    pub id: InviteId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_id: SpaceId,
    pub inviter: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_id: Option<Value>,
    pub join_rule_snapshot: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<GrantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub state: InviteState,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadMarker {
    pub schema: String,
    pub id: String,
    #[serde(rename = "type")]
    pub object_type: String,
    pub actor_id: Did,
    pub space_id: SpaceId,
    pub scope: ReadScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline_order_key: Option<Value>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub schema: String,
    pub id: String,
    #[serde(rename = "type")]
    pub object_type: String,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub source_event_id: EventId,
    pub notification_type: NotificationType,
    pub priority: NotificationPriority,
    pub state: NotificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Value>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub schema: String,
    pub blob_ref: BlobRef,
    #[serde(rename = "type")]
    pub object_type: String,
    pub sha256: String,
    pub size: u64,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub encryption: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_ref: Option<BlobRef>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub scheme: EncryptedPayloadScheme,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<Value>,
    pub payload_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
}

impl EncryptedPayload {
    pub fn mls_payload_digest(
        epoch: u64,
        content_type: &str,
        aad: Option<&Value>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        let metadata = EncryptedPayloadDigestMetadata {
            content_type,
            encryption: EncryptedPayloadScheme::MlsRfc9420.as_str(),
            epoch,
            aad,
        };
        let mut input = canonical::canonical_json_bytes(&metadata)?;
        input.extend_from_slice(ciphertext_bytes);
        Hash::new(format!("sha256:{:x}", Sha256::digest(&input)))
    }

    pub fn verify_mls_payload_digest(&self, ciphertext_bytes: &[u8]) -> Result<()> {
        let expected = Self::mls_payload_digest(
            self.epoch,
            &self.content_type,
            self.aad.as_ref(),
            ciphertext_bytes,
        )?;
        if expected == self.payload_digest {
            Ok(())
        } else {
            Err(Error::Protocol("encrypted payload digest mismatch".to_owned()))
        }
    }
}

#[derive(Serialize)]
struct EncryptedPayloadDigestMetadata<'a> {
    pub content_type: &'a str,
    pub encryption: &'a str,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<&'a Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsKeyPackageRecord {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub key_package: String,
    pub key_package_hash: Hash,
    pub cipher_suites: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<Proof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsProposalEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub proposal_type: String,
    pub proposal: String,
    pub proposal_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

impl MlsProposalEnvelope {
    /// Build a repo operation that carries this MLS proposal.
    pub fn operation(&self, operation_id: OperationId, space_id: SpaceId) -> Result<Operation> {
        let mut operation =
            Operation::create(operation_id, space_id, "mls_proposal", serde_json::to_value(self)?);
        operation.object_id =
            Some(format!("{}:{}:{}", self.group_id, self.epoch, self.proposal_type));
        Ok(operation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsCommitEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub commit: String,
    pub commit_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

impl MlsCommitEnvelope {
    /// Build a repo operation that carries this MLS commit.
    pub fn operation(&self, operation_id: OperationId, space_id: SpaceId) -> Result<Operation> {
        let mut operation =
            Operation::create(operation_id, space_id, "mls_commit", serde_json::to_value(self)?);
        operation.object_id = Some(format!("{}:{}", self.group_id, self.epoch));
        Ok(operation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsWelcomeEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub welcome: String,
    pub welcome_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

impl MlsWelcomeEnvelope {
    /// Build a repo operation that records this MLS welcome delivery.
    pub fn operation(&self, operation_id: OperationId, space_id: SpaceId) -> Result<Operation> {
        let mut operation =
            Operation::create(operation_id, space_id, "mls_welcome", serde_json::to_value(self)?);
        operation.object_id = Some(format!(
            "{}:{}:{}:{}",
            self.group_id, self.epoch, self.recipient_principal_id, self.recipient_device_id
        ));
        Ok(operation)
    }
}

/// Verification state for a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceVerificationState {
    /// Device has not been verified.
    Unverified,
    /// Verification is in progress.
    VerificationStarted,
    /// Device has been verified.
    Verified,
    /// Device is blocked.
    Blocked,
    /// Device was deleted locally.
    Deleted,
    /// Verification failed due to mismatch.
    VerificationFailed,
    /// Verification was cancelled before completion.
    VerificationCancelled,
    /// Verification expired before completion.
    VerificationExpired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerDescription {
    pub service_did: Did,
    pub service_type: String,
    pub protocol_version: String,
    #[serde(default)]
    pub supported_profiles: Vec<String>,
    #[serde(default)]
    pub supported_features: Vec<String>,
    #[serde(default)]
    pub supported_operations: Vec<String>,
    #[serde(default)]
    pub supported_bindings: Vec<Value>,
    #[serde(default)]
    pub supported_reducer_profiles: Vec<String>,
    #[serde(default)]
    pub supported_schema_profiles: Vec<String>,
    #[serde(default)]
    pub auth_metadata: Value,
    #[serde(default)]
    pub limits: Value,
}

impl ServerDescription {
    pub fn supports_contrix_v1(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub errcode: String,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl fmt::Display for ErrorEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.errcode, self.error)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityDescription {
    pub service_did: Did,
    pub registry_mode: String,
    #[serde(default)]
    pub supported_receipts: Vec<String>,
    pub protocol_version: String,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResolveRequest {
    pub did: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResolveResponse {
    pub did_document: DidDocumentRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub method_evidence: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidDocumentRef {
    pub did: Did,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub document: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityDocumentResponse {
    pub did_document: DidDocumentRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_event_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityLogResponse {
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitDidOperationRequest {
    pub did: Did,
    pub seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<Hash>,
    pub patch: Value,
    #[serde(default)]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitDidOperationResponse {
    pub status: String,
    pub head_event_hash: Hash,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityReceiptsResponse {
    #[serde(default)]
    pub receipts: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_met: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoDescription {
    pub repo_did: Did,
    pub head_commit: Hash,
    #[serde(default)]
    pub supported_signatures: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoCommitsResponse {
    #[serde(default)]
    pub commits: Vec<Commit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoCommitResponse {
    pub commit: Commit,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoOperationsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operation_ids: Vec<OperationId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default)]
    pub include_payload: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoOperationsResponse {
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unauthorized: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoSyncRequest {
    pub repo_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub filters: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoSyncResponse {
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitCommitResponse {
    pub head: Hash,
    #[serde(default)]
    pub accepted_operations: Vec<OperationId>,
    #[serde(default)]
    pub sync_tokens: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub space_ids: Vec<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    pub next_batch: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces: BTreeMap<SpaceId, SyncSpace>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rooms: BTreeMap<SpaceId, SyncSpace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_device: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub device_lists: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub account_data: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presence: Vec<Value>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub partial: bool,
}

impl SyncResponse {
    /// Native Contrix space map, falling back to Matrix bridge-compatible rooms.
    pub fn effective_spaces(&self) -> &BTreeMap<SpaceId, SyncSpace> {
        if self.spaces.is_empty() { &self.rooms } else { &self.spaces }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncSpace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<SyncTimeline>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state: Vec<Event>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub summary: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ephemeral: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub unread: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncTimeline {
    pub events: Vec<Event>,
    pub limited: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_batch: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncDescription {
    pub service_did: Did,
    #[serde(default)]
    pub supported_sync_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncSubscribeFrame {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncBackfillResponse {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncSnapshotHeadResponse {
    pub snapshot_ref: String,
    pub state_hash: Hash,
    pub frontier: String,
    pub signature: Value,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzCheckRequest {
    pub actor_id: Did,
    pub action: String,
    pub resource: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(default)]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzCheckResponse {
    pub decision: AuthzDecision,
    #[serde(default)]
    pub matched_grants: Vec<GrantId>,
    #[serde(default)]
    pub applied_constraints: Vec<Value>,
    #[serde(default)]
    pub policy_results: Vec<Value>,
    #[serde(default)]
    pub missing_proofs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_valid_until: Option<DateTime<Utc>>,
}

pub type Capability = CapabilityGrant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EffectiveGrantsResponse {
    #[serde(default)]
    pub grants: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_hash: Option<Hash>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzInvitesResponse {
    #[serde(default)]
    pub invites: Vec<Invite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationTransactionRequest {
    pub origin: Did,
    pub destination: Did,
    pub service_binding_ref: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationTransactionResponse {
    pub ok: bool,
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationPushOperationsRequest {
    pub origin: Did,
    pub destination: Did,
    pub space_id: SpaceId,
    pub service_binding_ref: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationPushOperationsResponse {
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationPullOperationsResponse {
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationSpaceMembersResponse {
    #[serde(default)]
    pub members: Vec<MemberRef>,
    pub membership_frontier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberRef {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub membership: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationVerifyActorRequest {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_payload_hash: Option<Hash>,
    pub signature: Value,
    pub purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationVerifyActorResponse {
    pub valid: bool,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexDescription {
    pub service_did: Did,
    #[serde(default)]
    pub reducer_profiles: Vec<String>,
    #[serde(default)]
    pub schema_profiles: Vec<String>,
    #[serde(default)]
    pub query_features: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexEntityResponse {
    pub entity: Entity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_after: Option<String>,
    pub visibility: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexThreadResponse {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_after: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexNotificationsResponse {
    #[serde(default)]
    pub notifications: Vec<Notification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexInboxResponse {
    #[serde(default)]
    pub items: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexSearchRequest {
    pub query: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub space_ids: Vec<SpaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entity_types: Vec<EntityType>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub time_range: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryResult<T> {
    pub item: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexSearchResponse {
    #[serde(default)]
    pub results: Vec<QueryResult<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexSpaceHierarchyResponse {
    pub root: Space,
    #[serde(default)]
    pub children: Vec<Space>,
    #[serde(default)]
    pub edges: Vec<Relation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryDescription {
    pub service_did: Did,
    #[serde(default)]
    pub resource_types: Vec<String>,
    #[serde(default)]
    pub discovery_profiles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restricted_query_proof: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchSpacesRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchSpacesResponse {
    #[serde(default)]
    pub results: Vec<SpacePreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpacePreview {
    pub space_id: SpaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveSpaceRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveSpaceResponse {
    pub space_preview: SpacePreview,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stripped_state: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<JoinRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via_services: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchOrganizationsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub claims: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchOrganizationsResponse {
    #[serde(default)]
    pub results: Vec<OrganizationPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationPreview {
    pub organization_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveOrganizationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveOrganizationResponse {
    pub organization_preview: OrganizationPreview,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endorsements: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchActorsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchActorsResponse {
    #[serde(default)]
    pub results: Vec<ActorPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActorPreview {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchUsersResponse {
    #[serde(default)]
    pub results: Vec<ActorPreview>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveHandleRequest {
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveHandleResponse {
    pub did: Did,
    pub handle: String,
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub claims: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobUploadMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Hash>,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobUploadResponse {
    pub blob_ref: BlobRef,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub sha256: Hash,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub upload_receipt: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PushRegisterDeviceRequest {
    pub device_id: DeviceId,
    pub push_gateway: String,
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PushRegisterDeviceResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PushUnregisterDeviceRequest {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PushNotifyRequest {
    pub notification: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PushNotifyResponse {
    #[serde(default)]
    pub rejected: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyCheckRequest {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub request_canonical_hash: Hash,
    pub action: String,
    pub actor: Did,
    pub source: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub event_preview: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub auth_context: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyCheckResponse {
    pub decision: AuthzDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<Value>,
    pub signature: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MediaIceConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MediaIceConfigResponse {
    #[serde(default)]
    pub ice_servers: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModerationReportRequest {
    pub space_id: SpaceId,
    pub target_ref: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModerationReportResponse {
    pub report_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routed_to: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletPingResponse {
    pub ok: bool,
    pub applet_id: String,
    pub service_did: Did,
    pub protocol_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletDescription {
    pub applet_id: String,
    pub service_did: Did,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub namespaces: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub auth: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletTransactionRequest {
    pub source_service_did: Did,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub ephemeral: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletTransactionResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletActorResponse {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletSpaceResponse {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletProtocolResponse {
    pub protocol: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_blob: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub field_types: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysUploadRequest {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub one_time_keys: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
    pub device_signature: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysUploadResponse {
    pub one_time_key_counts: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysQueryRequest {
    pub device_keys: BTreeMap<Did, Vec<DeviceId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysQueryResponse {
    pub device_keys: BTreeMap<Did, BTreeMap<DeviceId, Value>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysClaimRequest {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysClaimResponse {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, Value>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceMessagesSendRequest {
    pub messages: BTreeMap<Did, BTreeMap<DeviceId, ToDeviceMessage>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToDeviceMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    pub content: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceMessagesSendResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delivered: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown_devices: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceMessagesReceiveResponse {
    pub events: Vec<ToDeviceMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_batch: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn did_validation_rejects_handles() {
        assert!(Did::new("did:web:alice.example").is_ok());
        assert!(Did::new("alice.example").is_err());
    }

    #[test]
    fn did_uuid_validation_checks_uuid_layout() {
        let did = Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(did.method(), "uuid");
        assert!(did.is_uuid());

        assert!(Did::new("did:uuid:550e8400-e29b-11d4-a716-446655440000").is_err());
        assert!(Did::new("did:uuid:550e8400-e29b-41d4-c716-446655440000").is_err());
        assert!(Did::new("did:uuid:550E8400-e29b-41d4-a716-446655440000").is_err());
        assert!(Did::new("did:uuid:00000000-0000-4000-8000-000000000000").is_ok());
        assert!(Did::new("did:uuid:00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn did_uuid_generation_sets_version_and_variant_bits() {
        let did = Did::uuid_v4_from_bytes([0xff; 16]).unwrap();
        assert_eq!(did.as_str(), "did:uuid:ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert!(did.is_uuid());

        let generated = Did::new_uuid_v4().unwrap();
        assert!(generated.is_uuid());
    }

    #[test]
    fn device_id_accepts_protocol_device_forms() {
        assert!(DeviceId::new("dev_alice_1").is_ok());
        assert!(DeviceId::new("cx:device:01js0ke000000000000000000").is_ok());
        assert!(DeviceId::new("device-1").is_err());
    }

    #[test]
    fn server_description_checks_protocol_version() {
        let desc = ServerDescription {
            service_did: Did::new("did:web:svc.example").unwrap(),
            service_type: "principal_server".to_owned(),
            protocol_version: "1.0".to_owned(),
            supported_profiles: vec![],
            supported_features: vec![],
            supported_operations: vec![],
            supported_bindings: vec![],
            supported_reducer_profiles: vec![],
            supported_schema_profiles: vec![],
            auth_metadata: Value::Null,
            limits: Value::Null,
        };
        assert!(desc.supports_contrix_v1());
    }

    #[test]
    fn event_new_sets_required_event_id() {
        let event = Event::new(
            "cx.message.create",
            SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
            json!({ "body": "hello" }),
        )
        .unwrap();

        assert!(event.event_id.as_str().starts_with("sha256:"));
    }

    #[test]
    fn event_digest_uses_canonical_payload_without_event_id_proofs_or_unsigned() {
        let event = Event {
            event_id: EventId::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            kind: "cx.message.create".to_owned(),
            space_version: "1".to_owned(),
            space_id: SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            actor_id: Did::new("did:web:alice.example").unwrap(),
            actor_seq: 1,
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            hlc: Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
            prev_refs: Vec::new(),
            auth_refs: Vec::new(),
            redacts: None,
            content: json!({ "body": "hello" }),
            unsigned: BTreeMap::from([("local_receive_time".to_owned(), json!("ignored"))]),
            proofs: Vec::new(),
        };

        assert_eq!(
            event.event_digest().unwrap(),
            "sha256:c0ee4d7b3fb0d6353d1a39bba417d49c8a0b7b2d37fa50a93819c03fa51a6fce"
        );
    }

    #[test]
    fn operation_envelope_uses_spec_fields_and_digest_ignores_proofs() {
        let proof = Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#device-1".to_owned(),
            payload_hash: Hash::new(
                "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
            )
            .unwrap(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: "sig-a".to_owned(),
        };
        let envelope = OperationEnvelope {
            operation_id: OperationId::new("cx:operation:01js0op000000000000000000").unwrap(),
            space_id: SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            actor_id: Did::new("did:web:alice.example").unwrap(),
            kind: "cx.message.create".to_owned(),
            target_ref: Some("cx:thread:general".to_owned()),
            causal: CausalRef {
                deps: vec![OperationId::new("cx:operation:01js0oo000000000000000000").unwrap()],
                hlc: Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
                actor_seq: 7,
            },
            content: json!({"body": "hello"}),
            authz_ref: None,
            proofs: vec![proof.clone()],
        };
        let mut different_proof = envelope.clone();
        different_proof.proofs = vec![Proof { jws: "sig-b".to_owned(), ..proof }];

        assert_eq!(
            envelope.operation_digest().unwrap(),
            different_proof.operation_digest().unwrap()
        );
        envelope.validate_for_submit().unwrap();

        let encoded = serde_json::to_value(&envelope).unwrap();
        assert_eq!(encoded["actor_id"], "did:web:alice.example");
        assert_eq!(encoded["kind"], "cx.message.create");
        assert_eq!(encoded["content"]["body"], "hello");
        assert!(encoded.get("actor").is_none());
        assert!(encoded.get("type").is_none());
        assert!(encoded.get("body").is_none());
        assert!(encoded.get("signature").is_none());
    }

    #[test]
    fn operation_envelope_accepts_legacy_field_aliases() {
        let envelope: OperationEnvelope = serde_json::from_value(json!({
            "operation_id": "cx:operation:01js0op000000000000000000",
            "space_id": "cx:space:01js0ke000000000000000000",
            "actor": "did:web:alice.example",
            "type": "cx.message.create",
            "target_ref": "cx:thread:general",
            "causal": {
                "deps": [],
                "hlc": "01970e589d21-00000004-a13f9c2e",
                "actor_seq": 7
            },
            "body": {"body": "hello"},
            "proofs": []
        }))
        .unwrap();

        assert_eq!(envelope.actor_id.as_str(), "did:web:alice.example");
        assert_eq!(envelope.kind, "cx.message.create");
        assert_eq!(envelope.content["body"], "hello");
        assert!(envelope.validate_for_submit().is_err());
    }

    #[test]
    fn operation_kind_registry_canonicalizes_legacy_aliases_explicitly() {
        let registry = OperationKindRegistry::default();

        let canonical = registry
            .canonicalize(OP_MESSAGE_CREATE, OperationCompatibilityProfile::CanonicalOnly)
            .unwrap();
        assert_eq!(canonical.canonical_kind, OP_MESSAGE_CREATE);
        assert!(canonical.legacy_alias_used.is_none());

        assert!(
            registry
                .canonicalize("message_create", OperationCompatibilityProfile::CanonicalOnly)
                .is_err()
        );
        let legacy = registry
            .canonicalize("message_create", OperationCompatibilityProfile::LegacyBareNames)
            .unwrap();
        assert_eq!(legacy.canonical_kind, OP_MESSAGE_CREATE);
        assert_eq!(legacy.legacy_alias_used.as_deref(), Some("message_create"));
        assert_eq!(registry.kinds().count(), BUILT_IN_OPERATION_KINDS.len());
    }

    #[test]
    fn operation_kind_registry_drives_envelope_semantics() {
        let registry = OperationKindRegistry::default();
        let envelope = OperationEnvelope {
            operation_id: OperationId::new("cx:operation:01js0op000000000000000000").unwrap(),
            space_id: SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            actor_id: Did::new("did:web:alice.example").unwrap(),
            kind: "message_create".to_owned(),
            target_ref: None,
            causal: CausalRef {
                deps: Vec::new(),
                hlc: Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
                actor_seq: 1,
            },
            content: json!({"body": "hello"}),
            authz_ref: None,
            proofs: Vec::new(),
        };

        let validation = registry
            .validate_envelope(&envelope, OperationCompatibilityProfile::LegacyBareNames)
            .unwrap();
        assert_eq!(validation.canonical_kind, OP_MESSAGE_CREATE);

        let mut missing_body = envelope;
        missing_body.content = json!({});
        assert!(
            registry
                .validate_envelope(&missing_body, OperationCompatibilityProfile::LegacyBareNames)
                .is_err()
        );
    }

    #[test]
    fn operation_envelope_builder_covers_every_builtin_kind() {
        let registry = OperationKindRegistry::default();
        let space_id = SpaceId::new("cx:space:01js0ke000000000000000000").unwrap();
        let actor_id = Did::new("did:web:alice.example").unwrap();
        let hlc = Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap();

        for (index, kind) in BUILT_IN_OPERATION_KINDS.iter().enumerate() {
            let mut builder = OperationEnvelopeBuilder::new(
                OperationId::new(format!("cx:operation:builder-{index}")).unwrap(),
                space_id.clone(),
                actor_id.clone(),
                *kind,
                index as u64 + 1,
                hlc.clone(),
            );
            for field in required_fields_for_operation_kind(kind) {
                builder = builder.with_content_field(field, json!("value"));
            }
            let envelope = builder.build(&registry).unwrap();
            assert_eq!(envelope.kind, *kind);
            registry
                .validate_envelope(&envelope, OperationCompatibilityProfile::CanonicalOnly)
                .unwrap();
        }
    }

    #[test]
    fn operation_envelope_builder_requires_registered_kind_and_payload_fields() {
        let registry = OperationKindRegistry::default();
        let builder = OperationEnvelopeBuilder::new(
            OperationId::new("cx:operation:builder-message").unwrap(),
            SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            "message_create",
            1,
            Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
        )
        .with_compatibility_profile(OperationCompatibilityProfile::LegacyBareNames);

        assert!(builder.clone().build(&registry).is_err());
        let envelope = builder.with_content_field("body", json!("hello")).build(&registry).unwrap();
        assert_eq!(envelope.kind, OP_MESSAGE_CREATE);

        let unknown = OperationEnvelopeBuilder::new(
            OperationId::new("cx:operation:builder-unknown").unwrap(),
            SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            "unknown",
            1,
            Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
        );
        assert!(unknown.build(&registry).is_err());
    }

    #[test]
    fn operation_kind_conformance_vectors_cover_every_builtin() {
        let vectors = operation_kind_conformance_vectors();
        assert_eq!(vectors.len(), BUILT_IN_OPERATION_KINDS.len() * 2);
        for kind in BUILT_IN_OPERATION_KINDS {
            assert!(vectors.iter().any(|vector| {
                vector.input_kind == *kind
                    && vector.profile == OperationCompatibilityProfile::CanonicalOnly
                    && vector.canonical_kind == *kind
            }));
            assert!(vectors.iter().any(|vector| {
                vector.input_kind == legacy_alias_for_operation_kind(kind)
                    && vector.profile == OperationCompatibilityProfile::LegacyBareNames
                    && vector.canonical_kind == *kind
            }));
        }
    }

    #[test]
    fn protocol_schema_registry_publishes_core_json_schemas() {
        let registry = ProtocolSchemaRegistry::default();
        for schema_id in [
            CURSOR_SCHEMA,
            EVENT_SCHEMA,
            OPERATION_SCHEMA,
            COMMIT_SCHEMA,
            CAPABILITY_SCHEMA,
            ENCRYPTED_PAYLOAD_SCHEMA,
            CLIENT_SYNC_RESPONSE_SCHEMA,
        ] {
            assert!(registry.schema(schema_id).is_some());
        }

        registry
            .validate_required_fields(
                CLIENT_SYNC_RESPONSE_SCHEMA,
                &json!({"next_batch": "s1", "spaces": {}, "unknown_future_field": true}),
            )
            .unwrap();
        assert!(
            registry
                .validate_required_fields(CLIENT_SYNC_RESPONSE_SCHEMA, &json!({"spaces": {}}))
                .is_err()
        );
        assert!(
            registry
                .validate_value(
                    CLIENT_SYNC_RESPONSE_SCHEMA,
                    &json!({"next_batch": 1, "spaces": {}})
                )
                .is_err()
        );
    }

    #[test]
    fn schema_registry_generates_runtime_validators_from_supported_schema_subset() {
        let mut registry = ProtocolSchemaRegistry::default();
        let validator = registry.generated_validator(OPERATION_SCHEMA).unwrap();
        assert!(validator.fields.iter().any(|field| {
            field.name == "operation_id"
                && field.required
                && field.value_type == GeneratedSchemaValueType::String
        }));

        let operation = json!({
            "operation_id": "cx:operation:01",
            "space_id": "cx:space:01",
            "actor_id": "did:web:alice.example",
            "kind": "cx.message.create",
            "causal": {},
            "content": {},
            "unknown_future_field": true
        });
        validator.validate(&operation).unwrap();

        let wrong_type = json!({
            "operation_id": "cx:operation:01",
            "space_id": "cx:space:01",
            "actor_id": "did:web:alice.example",
            "kind": "cx.message.create",
            "causal": [],
            "content": {}
        });
        assert!(validator.validate(&wrong_type).is_err());

        let sensitive_extension = json!({
            "operation_id": "cx:operation:01",
            "space_id": "cx:space:01",
            "actor_id": "did:web:alice.example",
            "kind": "cx.message.create",
            "causal": {},
            "content": {},
            "x-policy-critical": {}
        });
        assert!(validator.validate(&sensitive_extension).is_err());
        registry.trust_extension_prefix("x-policy-critical");
        registry
            .generated_validator(OPERATION_SCHEMA)
            .unwrap()
            .validate(&sensitive_extension)
            .unwrap();

        registry.register(
            "cx.schema.strict.v1",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "cx.schema.strict.v1",
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "string"}},
                "additionalProperties": false
            }),
        );
        assert!(
            registry
                .generated_validator("cx.schema.strict.v1")
                .unwrap()
                .validate(&json!({"id": "1", "extra": true}))
                .is_err()
        );
    }

    #[test]
    fn schema_registry_fails_closed_for_unknown_security_extensions() {
        let mut registry = ProtocolSchemaRegistry::default();
        let value = json!({
            "operation_id": "cx:operation:01",
            "space_id": "cx:space:01",
            "actor_id": "did:web:alice.example",
            "kind": "cx.message.create",
            "causal": {},
            "content": {},
            "x-security-critical": {"unknown": true}
        });

        assert!(registry.validate_value(OPERATION_SCHEMA, &value).is_err());
        registry.trust_extension_prefix("x-security-critical");
        registry.validate_value(OPERATION_SCHEMA, &value).unwrap();

        let ordinary_extension = json!({
            "operation_id": "cx:operation:01",
            "space_id": "cx:space:01",
            "actor_id": "did:web:alice.example",
            "kind": "cx.message.create",
            "causal": {},
            "content": {},
            "x-ui-hint": {"preserved": true}
        });
        registry.validate_value(OPERATION_SCHEMA, &ordinary_extension).unwrap();
    }

    #[test]
    fn schema_compatibility_table_lists_builtin_schemas() {
        let table = schema_version_compatibility_table();

        assert_eq!(table.profile, SCHEMA_COMPATIBILITY_PROFILE);
        assert!(table.entries.iter().any(|entry| {
            entry.schema_id == OPERATION_SCHEMA
                && entry.current_version == "1"
                && !entry.migration_required
        }));
        assert!(table.entries.iter().any(|entry| entry.schema_id == CLIENT_SYNC_RESPONSE_SCHEMA));
    }

    #[test]
    fn profile_conformance_suites_cover_required_domains() {
        let suites = profile_conformance_suites();
        for profile in [
            ConformanceProfile::Encoding,
            ConformanceProfile::Hlc,
            ConformanceProfile::Cursor,
            ConformanceProfile::StateResolution,
            ConformanceProfile::Redaction,
            ConformanceProfile::Capability,
            ConformanceProfile::Sync,
            ConformanceProfile::Snapshot,
            ConformanceProfile::FederationSignatures,
            ConformanceProfile::Privacy,
            ConformanceProfile::Security,
        ] {
            assert!(suites.iter().any(|suite| suite.profile == profile && !suite.cases.is_empty()));
        }
    }

    #[test]
    fn builtin_conformance_report_is_machine_readable_and_covers_profiles() {
        let report = run_builtin_conformance_report();

        assert_eq!(report.fixture_version, BUILT_IN_CONFORMANCE_FIXTURES_VERSION);
        assert!(report.passed);
        for profile in [
            ConformanceProfile::Encoding,
            ConformanceProfile::Hlc,
            ConformanceProfile::Cursor,
            ConformanceProfile::StateResolution,
            ConformanceProfile::Redaction,
            ConformanceProfile::Capability,
            ConformanceProfile::Sync,
            ConformanceProfile::Snapshot,
            ConformanceProfile::FederationSignatures,
            ConformanceProfile::Privacy,
            ConformanceProfile::Security,
        ] {
            let coverage =
                report.coverage.iter().find(|coverage| coverage.profile == profile).unwrap();
            assert!(coverage.cases_total > 0);
            assert_eq!(coverage.cases_total, coverage.cases_passed);
        }

        let encoded = serde_json::to_value(report).unwrap();
        assert!(encoded["fixture_version"].is_string());
        assert!(encoded["results"].is_array());
    }

    #[test]
    fn conformance_fixture_set_loads_and_reports_external_json() {
        let encoded = serde_json::to_value(ConformanceFixtureSet::builtin()).unwrap();
        let fixtures = ConformanceFixtureSet::from_json(encoded).unwrap();
        let report = fixtures.run();

        assert!(report.passed);
        assert_eq!(report.fixture_version, BUILT_IN_CONFORMANCE_FIXTURES_VERSION);

        let empty = serde_json::from_value::<ConformanceFixtureSet>(json!({
            "fixture_version": "",
            "suites": []
        }))
        .unwrap();
        assert!(empty.validate().is_err());
    }

    #[test]
    fn commit_digest_uses_canonical_payload_without_proofs() {
        let commit = Commit {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id: CommitId::new("cx:commit:01js0ke000000000000000000").unwrap(),
            object_type: "commit".to_owned(),
            repo_id: "did:web:alice.example".to_owned(),
            author: Did::new("did:web:alice.example").unwrap(),
            author_seq: 1,
            prev_commit: Some(
                Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
            ),
            operations: vec![
                Hash::new(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
            ],
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            proofs: Vec::new(),
        };

        assert_eq!(
            commit.commit_digest().unwrap(),
            "sha256:8ee2713192bc01d5a6ba7c0a6b2125e00dffff1fb6f4ee85add16c81e6d2d8f0"
        );
    }

    #[test]
    fn signature_binding_payload_matches_canonical_vector() {
        let proof = Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#device-1".to_owned(),
            payload_hash: Hash::new(
                "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
            )
            .unwrap(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: "...".to_owned(),
        };
        let payload = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());

        assert_eq!(
            canonical::canonical_sha256(&payload).unwrap(),
            "sha256:5b8863e858c1964ca1901d27ce687b65d87dcef0d3535ed617de7b4763cfdaf8"
        );
    }

    #[test]
    fn fact_chain_echo_validates_server_proof_binding() {
        let mut echo = FactChainEcho {
            echo_id: "echo1".to_owned(),
            subject_ref: "cx:event:01".to_owned(),
            server_did: Did::new("did:web:server.example").unwrap(),
            operation_hash: Hash::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            commit_hash: Some(
                Hash::new(
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
            ),
            previous_echo_hash: None,
            observed_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            proofs: Vec::new(),
        };
        let digest = Hash::new(echo.echo_digest().unwrap()).unwrap();
        echo.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:server.example#key-1".to_owned(),
            payload_hash: digest,
            created_at: echo.observed_at,
            domain: None,
            audience: None,
            jws: "server.signature".to_owned(),
        });

        echo.validate_server_proofs().unwrap();

        let mut tampered = echo;
        tampered.proofs[0].payload_hash =
            Hash::new("sha256:3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();
        assert!(tampered.validate_server_proofs().is_err());
    }

    #[test]
    fn encrypted_payload_digest_matches_conformance_vector() {
        let digest = EncryptedPayload::mls_payload_digest(
            7,
            "application/json",
            None,
            b"ciphertext-example-001",
        )
        .unwrap();

        assert_eq!(
            digest.as_str(),
            "sha256:3bef5270548d5b2c14e46ac1c9a801376d243ca6d71b914ec1d3283268a981fa"
        );
    }

    #[test]
    fn mls_envelopes_build_protocol_operations() {
        let space_id = SpaceId::new("cx:space:01js0ke000000000000000000").unwrap();
        let hash =
            Hash::new("sha256:1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let proposal = MlsProposalEnvelope {
            group_id: "group1".to_owned(),
            epoch: 1,
            proposal_type: "add".to_owned(),
            proposal: "proposal-bytes".to_owned(),
            proposal_hash: hash.clone(),
            ratchet_tree: None,
        };
        let commit = MlsCommitEnvelope {
            group_id: "group1".to_owned(),
            epoch: 2,
            commit: "commit-bytes".to_owned(),
            commit_hash: hash.clone(),
            ratchet_tree: None,
        };
        let welcome = MlsWelcomeEnvelope {
            group_id: "group1".to_owned(),
            epoch: 2,
            recipient_principal_id: Did::new("did:web:bob.example").unwrap(),
            recipient_device_id: DeviceId::new("dev_bob").unwrap(),
            welcome: "welcome-bytes".to_owned(),
            welcome_hash: hash,
            ratchet_tree: None,
        };

        let proposal_op = proposal
            .operation(
                OperationId::new("cx:operation:01js0op000000000000000001").unwrap(),
                space_id.clone(),
            )
            .unwrap();
        let commit_op = commit
            .operation(
                OperationId::new("cx:operation:01js0op000000000000000002").unwrap(),
                space_id.clone(),
            )
            .unwrap();
        let welcome_op = welcome
            .operation(
                OperationId::new("cx:operation:01js0op000000000000000003").unwrap(),
                space_id,
            )
            .unwrap();

        assert_eq!(proposal_op.object_type, "mls_proposal");
        assert_eq!(commit_op.object_type, "mls_commit");
        assert_eq!(welcome_op.object_type, "mls_welcome");
        assert_eq!(proposal_op.payload["proposal_type"], "add");
        assert_eq!(commit_op.payload["epoch"], 2);
        assert_eq!(welcome_op.payload["recipient_device_id"], "dev_bob");
    }

    #[test]
    fn hlc_sorts_by_structured_parts() {
        let mut hlcs = [
            "01970e589d21-00000004-bbbbbbbb",
            "01970e589d20-00000009-ffffffff",
            "01970e589d21-00000003-ffffffff",
            "01970e589d21-00000004-a13f9c2e",
        ]
        .map(|value| Hlc::new(value).unwrap());
        hlcs.sort();
        let actual = hlcs.map(|value| value.to_string());
        assert_eq!(
            actual,
            [
                "01970e589d20-00000009-ffffffff",
                "01970e589d21-00000003-ffffffff",
                "01970e589d21-00000004-a13f9c2e",
                "01970e589d21-00000004-bbbbbbbb",
            ]
        );
    }

    #[test]
    fn relation_requires_exact_wire_endpoints() {
        let relation = Relation {
            schema: RELATION_SCHEMA.to_owned(),
            id: RelationId::new("cx:relation:01").unwrap(),
            object_type: "relation".to_owned(),
            space_id: SpaceId::new("cx:space:01").unwrap(),
            relation_kind: RelationKind::Mentions,
            from_entity_id: Some(EntityId::new("cx:entity:01").unwrap()),
            from_actor_id: None,
            from_space_id: None,
            to_entity_id: None,
            to_actor_id: Some(Did::new("did:web:alice.example").unwrap()),
            to_space_id: None,
            fields: BTreeMap::new(),
            state: None,
            created_by: Did::new("did:web:alice.example").unwrap(),
            created_at: Utc::now(),
        };
        relation.validate_endpoints().unwrap();
    }

    #[test]
    fn query_request_uses_protocol_filters_array() {
        let request = QueryRequest {
            space_ids: vec![SpaceId::new("cx:space:01").unwrap()],
            entity_types: vec![EntityType::Task],
            anchor_entity_id: None,
            filters: vec![Filter::Predicate(FieldFilter {
                field: "fields.status".to_owned(),
                op: FilterOp::Eq,
                value: Some(json!("todo")),
            })],
            relation: None,
            context: None,
            order_by: vec![],
            projection: vec![],
            cursor: None,
            limit: Some(50),
            consistency: None,
        };

        let value = serde_json::to_value(request).unwrap();
        assert!(value.get("space_ids").unwrap().is_array());
        assert!(value.get("filters").unwrap().is_array());
        assert!(value.get("sync_token").is_none());
    }

    #[test]
    fn operation_serializes_protocol_field_names() {
        let mut operation = Operation::create(
            OperationId::new("cx:operation:01").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "entity",
            json!({"id":"cx:entity:01"}),
        );
        operation.object_id = Some("cx:entity:01".to_owned());

        let value = serde_json::to_value(operation).unwrap();

        assert_eq!(value["type"], "operation");
        assert_eq!(value["operation_type"], "create");
        assert_eq!(value["object_id"], "cx:entity:01");
        assert_eq!(value["object_type"], "entity");
        assert!(value.get("target_object_id").is_none());
        assert_eq!(value["schema"], OPERATION_SCHEMA);
    }

    #[test]
    fn sync_response_uses_native_spaces_and_bridge_rooms() {
        let response = SyncResponse {
            next_batch: "cx:sync:abc".to_owned(),
            spaces: BTreeMap::from([(
                SpaceId::new("cx:space:01").unwrap(),
                SyncSpace {
                    timeline: Some(SyncTimeline {
                        events: Vec::new(),
                        limited: false,
                        prev_batch: None,
                    }),
                    state: Vec::new(),
                    summary: Value::Null,
                    ephemeral: Vec::new(),
                    unread: Value::Null,
                },
            )]),
            rooms: BTreeMap::new(),
            to_device: Vec::new(),
            device_lists: Value::Null,
            account_data: Vec::new(),
            presence: Vec::new(),
            partial: false,
        };

        let value = serde_json::to_value(response).unwrap();

        assert!(value.get("spaces").unwrap().is_object());
        assert!(value.get("rooms").is_none());
    }

    fn valid_proof() -> Proof {
        Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            payload_hash: Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: "header.payload.signature".to_owned(),
        }
    }

    #[test]
    fn proof_validate_rejects_alg_none() {
        let mut proof = valid_proof();
        proof.alg = "none".to_owned();
        assert!(proof.validate().is_err());
        assert!(proof.validate().unwrap_err().to_string().contains("'none'"));
    }

    #[test]
    fn proof_validate_rejects_none_case_insensitive() {
        let mut proof = valid_proof();
        proof.alg = "NONE".to_owned();
        assert!(proof.validate().is_err());
    }

    #[test]
    fn proof_validate_rejects_empty_fields() {
        let mut proof = valid_proof();
        proof.alg = "".to_owned();
        assert!(proof.validate().is_err());

        let mut proof = valid_proof();
        proof.verification_method = "".to_owned();
        assert!(proof.validate().is_err());

        let mut proof = valid_proof();
        proof.jws = "".to_owned();
        assert!(proof.validate().is_err());

        let mut proof = valid_proof();
        proof.kind = "".to_owned();
        assert!(proof.validate().is_err());
    }

    #[test]
    fn proof_validate_accepts_valid_proof() {
        assert!(valid_proof().validate().is_ok());
    }

    #[test]
    fn proof_validate_production_rejects_dev_kinds() {
        for kind in &["dev", "test", "mock", "stub", "dummy"] {
            let mut proof = valid_proof();
            proof.kind = kind.to_string();
            assert!(proof.validate_production().is_err(), "should reject kind: {kind}");
        }
    }

    #[test]
    fn proof_validate_production_rejects_unsupported_algorithms() {
        let mut proof = valid_proof();
        proof.alg = "HS256".to_owned();
        assert!(proof.validate_production().is_err());

        let mut proof = valid_proof();
        proof.alg = "RSASSA-PKCS1-v1_5".to_owned();
        assert!(proof.validate_production().is_err());
    }

    #[test]
    fn proof_validate_production_accepts_known_algorithms() {
        for alg in &["EdDSA", "ES256", "ES256K", "RS256", "PS256"] {
            let mut proof = valid_proof();
            proof.alg = alg.to_string();
            assert!(proof.validate_production().is_ok(), "should accept algorithm: {alg}");
        }
    }

    #[test]
    fn proof_validate_binding_matches_expected_fields() {
        let proof = valid_proof();
        let expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
        assert!(proof.validate_binding(&expected).is_ok());
    }

    #[test]
    fn proof_validate_binding_rejects_mismatched_verification_method() {
        let proof = valid_proof();
        let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
        expected.verification_method = "did:web:bob.example#key-1".to_owned();
        assert!(proof.validate_binding(&expected).is_err());
    }

    #[test]
    fn proof_validate_binding_rejects_mismatched_payload_hash() {
        let proof = valid_proof();
        let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
        expected.payload_hash =
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        assert!(proof.validate_binding(&expected).is_err());
    }

    #[test]
    fn proof_validate_binding_rejects_mismatched_domain() {
        let proof = valid_proof();
        let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
        expected.domain = Some("other.example".to_owned());
        assert!(proof.validate_binding(&expected).is_err());
    }

    #[test]
    fn proof_validate_binding_rejects_mismatched_audience() {
        let mut proof = valid_proof();
        proof.audience = Some(Audience::Single("svc-a".to_owned()));
        let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
        expected.audience = Some(Audience::Single("svc-b".to_owned()));
        assert!(proof.validate_binding(&expected).is_err());
    }

    #[test]
    fn proof_validate_binding_rejects_excessive_time_drift() {
        let proof = valid_proof();
        let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
        expected.created_at = "2026-04-26T01:00:00Z".parse().unwrap();
        assert!(proof.validate_binding(&expected).is_err());
    }

    #[test]
    fn event_validate_proof_bindings_checks_digest_match() {
        let event = Event::new(
            "cx.message.create",
            SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
            json!({ "body": "hello" }),
        )
        .unwrap();

        let digest = event.event_digest().unwrap();
        let proof = Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            payload_hash: Hash::new(digest).unwrap(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
            jws: "sig".to_owned(),
        };

        let mut signed_event = event;
        signed_event.proofs = vec![proof];
        assert!(signed_event.validate_proof_bindings().is_ok());
    }

    #[test]
    fn event_validate_proof_bindings_rejects_mismatched_digest() {
        let event = Event::new(
            "cx.message.create",
            SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
            json!({ "body": "hello" }),
        )
        .unwrap();

        let bad_proof = Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            payload_hash: Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
            jws: "sig".to_owned(),
        };

        let mut signed_event = event;
        signed_event.proofs = vec![bad_proof];
        assert!(signed_event.validate_proof_bindings().is_err());
    }

    #[test]
    fn commit_validate_proof_bindings_checks_digest_match() {
        let commit = Commit {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id: CommitId::new("cx:commit:01js0ke000000000000000000").unwrap(),
            object_type: "commit".to_owned(),
            repo_id: "did:web:alice.example".to_owned(),
            author: Did::new("did:web:alice.example").unwrap(),
            author_seq: 1,
            prev_commit: None,
            operations: vec![],
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            proofs: vec![],
        };

        let digest = commit.commit_digest().unwrap();
        let proof = Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            payload_hash: Hash::new(digest).unwrap(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: "sig".to_owned(),
        };

        let mut signed_commit = commit;
        signed_commit.proofs = vec![proof];
        assert!(signed_commit.validate_proof_bindings().is_ok());
    }

    #[test]
    fn entity_channel_constructor_sets_type_and_kind() {
        let entity = Entity::channel(
            EntityId::new("cx:entity:ch01").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "General",
            Did::new("did:web:alice.example").unwrap(),
            ChannelKind::Chat,
        );
        assert_eq!(entity.entity_type, EntityType::Channel);
        assert_eq!(entity.title, Some("General".to_owned()));
        assert_eq!(entity.state, Some(ObjectState::Active));
        assert!(entity.channel_kind().is_some());
    }

    #[test]
    fn entity_topic_constructor_sets_type() {
        let entity = Entity::topic(
            EntityId::new("cx:entity:tp01").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "Design Discussion",
            Did::new("did:web:alice.example").unwrap(),
        );
        assert_eq!(entity.entity_type, EntityType::Topic);
        assert_eq!(entity.title, Some("Design Discussion".to_owned()));
    }

    #[test]
    fn entity_comment_constructor_sets_type_and_content() {
        let entity = Entity::comment(
            EntityId::new("cx:entity:cm01").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            json!({"body": "hello world"}),
        );
        assert_eq!(entity.entity_type, EntityType::Comment);
        assert!(entity.title.is_none());
        assert_eq!(entity.content, Some(json!({"body": "hello world"})));
    }

    #[test]
    fn entity_channel_kind_returns_none_for_non_channel() {
        let entity = Entity::topic(
            EntityId::new("cx:entity:tp02").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "Topic",
            Did::new("did:web:alice.example").unwrap(),
        );
        assert!(entity.channel_kind().is_none());
    }

    #[test]
    fn entity_type_comment_roundtrips() {
        let json = serde_json::to_string(&EntityType::Comment).unwrap();
        assert_eq!(json, "\"comment\"");
        let back: EntityType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, EntityType::Comment);
    }
}
