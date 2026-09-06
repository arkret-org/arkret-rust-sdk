use std::error::Error as StdError;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use arkret_wire::{
    SchemaId, validate_canonical_acct_uri, validate_canonical_agent_slug,
    validate_canonical_handle, validate_canonical_handle_localpart, validate_canonical_idna_domain,
    validate_content_text, validate_short_text, validate_single_line_display_text,
};
use jsonschema::{Draft, Retrieve, Uri, Validator};
use serde_json::{Value, json};
use web_time::Instant;

use super::super::*;
use super::validators::is_security_sensitive_extension;

#[derive(Default)]
struct ValidatorCache {
    validators: RwLock<BTreeMap<String, Arc<Validator>>>,
    compile_lock: Mutex<()>,
    retriever_schemas: RwLock<Option<Arc<BTreeMap<String, Value>>>>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    compiled_validators: AtomicU64,
    validator_compile_failures: AtomicU64,
    validator_compile_micros: AtomicU64,
    catalog_compile_failures: AtomicU64,
    last_catalog_compile_micros: AtomicU64,
    last_failure_schema_id: RwLock<Option<String>>,
}

impl Clone for ValidatorCache {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl fmt::Debug for ValidatorCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self
            .validators
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        formatter
            .debug_struct("ValidatorCache")
            .field("compiled_validators", &len)
            .field("stats", &self.stats())
            .finish()
    }
}

impl ValidatorCache {
    fn stats(&self) -> SchemaValidatorStats {
        SchemaValidatorStats {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            compiled_validators: self.compiled_validators.load(Ordering::Relaxed),
            validator_compile_failures: self.validator_compile_failures.load(Ordering::Relaxed),
            validator_compile_micros: self.validator_compile_micros.load(Ordering::Relaxed),
            catalog_compile_failures: self.catalog_compile_failures.load(Ordering::Relaxed),
            last_catalog_compile_micros: self.last_catalog_compile_micros.load(Ordering::Relaxed),
            last_failure_schema_id: self
                .last_failure_schema_id
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
        }
    }

    fn reset(&self) {
        for counter in [
            &self.cache_hits,
            &self.cache_misses,
            &self.compiled_validators,
            &self.validator_compile_failures,
            &self.validator_compile_micros,
            &self.catalog_compile_failures,
            &self.last_catalog_compile_micros,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        *self
            .last_failure_schema_id
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

/// Snapshot of Draft 2020-12 validator cache and catalog compilation metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaValidatorStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub compiled_validators: u64,
    pub validator_compile_failures: u64,
    pub validator_compile_micros: u64,
    pub catalog_compile_failures: u64,
    pub last_catalog_compile_micros: u64,
    pub last_failure_schema_id: Option<String>,
}

impl SchemaValidatorStats {
    #[must_use]
    pub fn cache_hit_ratio(&self) -> Option<f64> {
        let lookups = self.cache_hits + self.cache_misses;
        (lookups != 0).then(|| self.cache_hits as f64 / lookups as f64)
    }
}

impl PartialEq for ValidatorCache {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

#[derive(Clone)]
struct InMemorySchemaRetriever {
    schemas: Arc<BTreeMap<String, Value>>,
}

impl Retrieve for InMemorySchemaRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> std::result::Result<Value, Box<dyn StdError + Send + Sync>> {
        self.schemas
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("schema reference is not registered: {uri}").into())
    }
}

/// Protocol JSON Schema registry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolSchemaRegistry {
    schemas: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    documents: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    fragments: BTreeMap<String, String>,
    trusted_extension_prefixes: Vec<String>,
    #[serde(skip, default)]
    validator_cache: ValidatorCache,
}

/// JSON value type rule extracted from a supported JSON Schema document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaValueTypeSummary {
    Any,
    Array,
    Boolean,
    Integer,
    Null,
    Number,
    Object,
    String,
}

impl SchemaValueTypeSummary {
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
}

/// One field in a metadata-only JSON object-shape summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaFieldSummary {
    pub name: String,
    pub value_type: SchemaValueTypeSummary,
    pub required: bool,
}

/// Metadata-only object-shape summary extracted from a small JSON Schema subset.
///
/// This type is not an admission validator. Security, write and
/// signature boundaries must call [`ProtocolSchemaRegistry::validate_value`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedObjectShape {
    pub schema_id: String,
    pub fields: Vec<SchemaFieldSummary>,
    pub additional_properties: bool,
    pub trusted_extension_prefixes: Vec<String>,
}

impl ProtocolSchemaRegistry {
    /// Create an empty schema registry.
    pub fn new() -> Self {
        Self {
            schemas: BTreeMap::new(),
            documents: BTreeMap::new(),
            fragments: BTreeMap::new(),
            trusted_extension_prefixes: Vec::new(),
            validator_cache: ValidatorCache::default(),
        }
    }

    /// Register a schema document by `$id`.
    pub fn register(&mut self, schema_id: impl Into<String>, schema: Value) {
        let schema_id = schema_id.into();
        self.fragments.remove(&schema_id);
        self.schemas.insert(schema_id, schema);
        self.clear_validator_cache();
    }

    /// Register a logical schema ID that targets a JSON Pointer fragment in a document.
    pub fn register_fragment(
        &mut self,
        schema_id: impl Into<String>,
        schema: Value,
        fragment: impl Into<String>,
    ) -> Result<()> {
        let schema_id = schema_id.into();
        let fragment = fragment.into();
        let pointer = fragment.strip_prefix('#').ok_or_else(|| {
            SchemaError::Protocol(format!(
                "schema '{schema_id}' fragment must start with '#': {fragment}"
            ))
        })?;
        if !pointer.is_empty() && schema.pointer(pointer).is_none() {
            return Err(SchemaError::Protocol(format!(
                "schema '{schema_id}' has unresolved fragment '{fragment}'"
            )));
        }
        self.schemas.insert(schema_id.clone(), schema);
        self.fragments.insert(schema_id, fragment);
        self.clear_validator_cache();
        Ok(())
    }

    /// Register a schema document that exists only to satisfy `$ref` targets.
    pub fn register_reference_document(&mut self, schema: Value) -> Result<()> {
        let document_id = schema
            .get("$id")
            .and_then(Value::as_str)
            .filter(|document_id| document_id.contains(':'))
            .ok_or_else(|| {
                SchemaError::Protocol(
                    "reference schema document must declare an absolute $id".to_owned(),
                )
            })?
            .to_owned();
        if let Some(previous) = self.documents.get(&document_id)
            && previous != &schema
        {
            return Err(SchemaError::Protocol(format!(
                "conflicting schema documents declare $id '{document_id}'"
            )));
        }
        self.documents.insert(document_id, schema);
        self.clear_validator_cache();
        Ok(())
    }

    /// Return one schema by ID.
    pub fn schema(&self, schema_id: &str) -> Option<&Value> {
        let (base, requested_fragment) = schema_id.split_once('#').unwrap_or((schema_id, ""));
        let root = self.schemas.get(base)?;
        let registered_fragment = self.fragments.get(base).map(String::as_str);
        let fragment = match (registered_fragment, requested_fragment.is_empty()) {
            (Some(fragment), true) => fragment.strip_prefix('#')?,
            (Some(_), false) => return None,
            (None, _) => requested_fragment,
        };
        if fragment.is_empty() {
            return Some(root);
        }
        root.pointer(fragment)
    }

    /// Iterate schema IDs.
    pub fn schema_ids(&self) -> impl Iterator<Item = &str> {
        self.schemas.keys().map(String::as_str)
    }

    /// Compile every registered logical schema with the Draft 2020-12 engine.
    ///
    /// Services can call this once during startup to reject an invalid or
    /// incomplete schema catalog before accepting protocol traffic.
    pub fn ensure_all_schemas_compile(&self) -> Result<()> {
        let started = Instant::now();
        for schema_id in self.schema_ids() {
            if let Err(error) = self.compiled_validator(schema_id) {
                let elapsed = duration_micros(started);
                self.validator_cache
                    .last_catalog_compile_micros
                    .store(elapsed, Ordering::Relaxed);
                self.validator_cache
                    .catalog_compile_failures
                    .fetch_add(1, Ordering::Relaxed);
                *self
                    .validator_cache
                    .last_failure_schema_id
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(schema_id.to_owned());
                tracing::error!(
                    failed_schema_id = schema_id,
                    catalog_compile_micros = elapsed,
                    "Draft 2020-12 schema catalog compilation failed"
                );
                return Err(error);
            }
        }
        let elapsed = duration_micros(started);
        self.validator_cache
            .last_catalog_compile_micros
            .store(elapsed, Ordering::Relaxed);
        tracing::info!(
            schema_count = self.schemas.len(),
            catalog_compile_micros = elapsed,
            "Draft 2020-12 schema catalog compiled"
        );
        Ok(())
    }

    /// Return a lock-free snapshot of cache and catalog compilation metrics.
    #[must_use]
    pub fn validator_stats(&self) -> SchemaValidatorStats {
        self.validator_cache.stats()
    }

    /// Trust a security-sensitive extension prefix for fail-closed validation.
    pub fn trust_extension_prefix(&mut self, prefix: impl Into<String>) {
        self.trusted_extension_prefixes.push(prefix.into());
    }

    /// Summarize the root object's fields without performing admission validation.
    pub fn generated_object_shape(&self, schema_id: &str) -> Result<GeneratedObjectShape> {
        let schema = self
            .schema(schema_id)
            .ok_or_else(|| SchemaError::Protocol(format!("unknown schema '{schema_id}'")))?;
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
                fields.push(SchemaFieldSummary {
                    name: name.clone(),
                    value_type: SchemaValueTypeSummary::from_schema(property_schema),
                    required: required.contains(name),
                });
            }
        }
        for name in required {
            if !fields.iter().any(|field| field.name == name) {
                fields.push(SchemaFieldSummary {
                    name,
                    value_type: SchemaValueTypeSummary::Any,
                    required: true,
                });
            }
        }
        fields.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(GeneratedObjectShape {
            schema_id: schema_id.to_owned(),
            fields,
            additional_properties: schema
                .get("additionalProperties")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            trusted_extension_prefixes: self.trusted_extension_prefixes.clone(),
        })
    }

    /// Validate one value against the registered JSON Schema document.
    pub fn validate_value(&self, schema_id: &str, value: &Value) -> Result<()> {
        let warnings = self.validate_value_with_warnings(schema_id, value)?;
        for warning in warnings {
            tracing::warn!(
                schema_id = %schema_id,
                warning = %warning,
                "schema validation warning"
            );
        }
        Ok(())
    }

    /// Validate one value with the complete JSON Schema Draft 2020-12 runtime.
    pub fn validate_value_with_warnings(
        &self,
        schema_id: &str,
        value: &Value,
    ) -> Result<Vec<String>> {
        let validator = self.compiled_validator(schema_id)?;
        if let Some(error) = validator.iter_errors(value).next() {
            let instance_path = error.instance_path().to_string();
            let schema_path = error.schema_path().to_string();
            return Err(SchemaError::Validation(SchemaValidationIssue {
                schema_id: schema_id.to_owned(),
                instance_pointer: instance_path,
                keyword: json_pointer_last_segment(&schema_path),
                schema_pointer: schema_path,
                reason: SchemaValidationReason::InstanceInvalid,
                message: error.masked().to_string(),
            }));
        }
        if let Some(object) = value.as_object() {
            self.validate_security_extensions(schema_id, object)?;
        }
        Ok(Vec::new())
    }

    fn compiled_validator(&self, schema_id: &str) -> Result<Arc<Validator>> {
        if let Some(validator) = self
            .validator_cache
            .validators
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(schema_id)
            .cloned()
        {
            self.validator_cache
                .cache_hits
                .fetch_add(1, Ordering::Relaxed);
            return Ok(validator);
        }

        // Validator construction walks the complete schema graph through the
        // retriever and is substantially more expensive than validation. More
        // importantly, concurrent cold-cache construction of the same graph
        // can block inside the Draft 2020-12 compiler. Serialize cold-cache
        // construction and re-check after taking the lock so only one caller
        // compiles a given validator.
        let _compile_guard = self
            .validator_cache
            .compile_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(validator) = self
            .validator_cache
            .validators
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(schema_id)
            .cloned()
        {
            self.validator_cache
                .cache_hits
                .fetch_add(1, Ordering::Relaxed);
            return Ok(validator);
        }
        self.validator_cache
            .cache_misses
            .fetch_add(1, Ordering::Relaxed);

        let (base_id, requested_fragment) = schema_id.split_once('#').unwrap_or((schema_id, ""));
        let root = self
            .schemas
            .get(base_id)
            .ok_or_else(|| SchemaError::Protocol(format!("unknown schema '{base_id}'")))?;
        let registered_fragment = self.fragments.get(base_id).map(String::as_str);
        let fragment = match (registered_fragment, requested_fragment.is_empty()) {
            (Some(fragment), true) => Some(fragment),
            (Some(_), false) => {
                return Err(SchemaError::Protocol(format!(
                    "schema '{base_id}' already targets a registered fragment"
                )));
            }
            (None, false) => Some(requested_fragment),
            (None, true) => None,
        };

        let schema = if let Some(fragment) = fragment {
            let fragment = fragment.strip_prefix('#').unwrap_or(fragment);
            let document_id = root.get("$id").and_then(Value::as_str).ok_or_else(|| {
                SchemaError::Protocol(format!(
                    "schema '{base_id}' needs an absolute $id to validate fragment '#{fragment}'"
                ))
            })?;
            if !document_id.contains(':') {
                return Err(SchemaError::Protocol(format!(
                    "schema '{base_id}' needs an absolute $id to validate fragment '#{fragment}'"
                )));
            }
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$ref": format!("{document_id}#{fragment}")
            })
        } else {
            root.clone()
        };

        let retriever = InMemorySchemaRetriever {
            schemas: self.retriever_schemas()?,
        };
        let started = Instant::now();
        let validator = jsonschema::options()
            .with_draft(Draft::Draft202012)
            .with_format("arkret-human-identifier", |value: &str| {
                validate_canonical_handle_localpart(value).is_ok()
            })
            .with_format("arkret-agent-slug", |value: &str| {
                validate_canonical_agent_slug(value).is_ok()
            })
            .with_format("arkret-idna-a-label-domain", |value: &str| {
                validate_canonical_idna_domain(value).is_ok()
            })
            .with_format("arkret-canonical-handle", |value: &str| {
                validate_canonical_handle(value).is_ok()
            })
            .with_format("arkret-acct-uri", |value: &str| {
                validate_canonical_acct_uri(value).is_ok()
            })
            .with_format("arkret-single-line-display-text", |value: &str| {
                validate_single_line_display_text(value, usize::MAX).is_ok()
            })
            .with_format("arkret-short-text", |value: &str| {
                validate_short_text(value, usize::MAX).is_ok()
            })
            .with_format("arkret-content-text", |value: &str| {
                validate_content_text(value).is_ok()
            })
            .should_validate_formats(true)
            .with_retriever(retriever)
            .build(&schema)
            .map_err(|error| {
                self.validator_cache
                    .validator_compile_failures
                    .fetch_add(1, Ordering::Relaxed);
                self.validator_cache
                    .validator_compile_micros
                    .fetch_add(duration_micros(started), Ordering::Relaxed);
                *self
                    .validator_cache
                    .last_failure_schema_id
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(schema_id.to_owned());
                SchemaError::Protocol(format!(
                    "schema '{schema_id}' could not compile as Draft 2020-12: {error}"
                ))
            })?;
        self.validator_cache
            .compiled_validators
            .fetch_add(1, Ordering::Relaxed);
        self.validator_cache
            .validator_compile_micros
            .fetch_add(duration_micros(started), Ordering::Relaxed);
        let validator = Arc::new(validator);
        self.validator_cache
            .validators
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(schema_id.to_owned(), Arc::clone(&validator));
        Ok(validator)
    }

    fn clear_validator_cache(&self) {
        self.validator_cache
            .validators
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        *self
            .validator_cache
            .retriever_schemas
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.validator_cache.reset();
    }

    fn retriever_schemas(&self) -> Result<Arc<BTreeMap<String, Value>>> {
        if let Some(schemas) = self
            .validator_cache
            .retriever_schemas
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            return Ok(schemas);
        }

        let mut retriever_schemas = BTreeMap::new();
        retriever_schemas.extend(self.documents.clone());
        for (logical_id, document) in &self.schemas {
            if let Some(document_id) = document.get("$id").and_then(Value::as_str)
                && document_id.contains(':')
                && let Some(previous) =
                    retriever_schemas.insert(document_id.to_owned(), document.clone())
                && previous != *document
            {
                return Err(SchemaError::Protocol(format!(
                    "conflicting schema documents declare $id '{document_id}'"
                )));
            }
            if logical_id.contains(':') {
                retriever_schemas.insert(logical_id.clone(), document.clone());
            }
        }
        let retriever_schemas = Arc::new(retriever_schemas);
        *self
            .validator_cache
            .retriever_schemas
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(Arc::clone(&retriever_schemas));
        Ok(retriever_schemas)
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
            let trusted = self
                .trusted_extension_prefixes
                .iter()
                .any(|prefix| field.starts_with(prefix));
            if !trusted {
                return Err(SchemaError::Protocol(format!(
                    "schema '{schema_id}' rejects unknown security-sensitive extension '{field}'"
                )));
            }
        }
        Ok(())
    }
}

fn duration_micros(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn json_pointer_last_segment(pointer: &str) -> String {
    pointer
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .replace("~1", "/")
        .replace("~0", "~")
}

impl Default for ProtocolSchemaRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.register(
            SchemaId::CURSOR_V1,
            object_schema(
                SchemaId::CURSOR_V1,
                &["v", "iat", "pos"],
                &[("v", "string"), ("iat", "string"), ("pos", "object")],
            ),
        );
        registry.register(
            SchemaId::EVENT_V1,
            object_schema(
                SchemaId::EVENT_V1,
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
                    ("seal_ref", "string"),
                    ("requirements", "object"),
                    ("payload", "object"),
                    ("unsigned", "object"),
                    ("proofs", "array"),
                ],
            ),
        );
        registry.register(SchemaId::STRAND_V1, strand_schema_document());
        registry.register(SchemaId::MORPH_V1, morph_schema_document());
        registry.register(SchemaId::SPACE_V1, space_schema_document());
        registry.register(SchemaId::VIEW_V1, view_schema_document());
        registry.register(
            SchemaId::EVENT_PAYLOAD_V1,
            object_schema(SchemaId::EVENT_PAYLOAD_V1, &[], &[("type", "string")]),
        );
        registry.register(
            SchemaId::SEAL_V1,
            object_schema(
                SchemaId::SEAL_V1,
                &["id", "realm_id", "frontier", "state_root"],
                &[
                    ("id", "string"),
                    ("realm_id", "string"),
                    ("frontier", "array"),
                    ("state_root", "string"),
                ],
            ),
        );
        registry.register(
            SchemaId::BOTTOM_V1,
            object_schema(
                SchemaId::BOTTOM_V1,
                &["kind", "cells"],
                &[("kind", "string"), ("cells", "array")],
            ),
        );
        registry.register(
            SchemaId::REALM_STATE_SNAPSHOT_V1,
            object_schema(
                SchemaId::REALM_STATE_SNAPSHOT_V1,
                &[
                    "realm_state_snapshot_id",
                    "realm_id",
                    "frontier",
                    "state_root",
                ],
                &[
                    ("realm_state_snapshot_id", "string"),
                    ("realm_id", "string"),
                    ("frontier", "array"),
                    ("state_root", "string"),
                ],
            ),
        );
        registry.register(
            SchemaId::CAPABILITY_V1,
            object_schema(
                SchemaId::CAPABILITY_V1,
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
            SchemaId::PERSONAL_PRODUCTIVITY_V1,
            object_schema(
                SchemaId::PERSONAL_PRODUCTIVITY_V1,
                &["kind"],
                &[("kind", "string")],
            ),
        );
        registry.register(
            SchemaId::DRAFT_SYNC_V1,
            object_schema(
                SchemaId::DRAFT_SYNC_V1,
                &[
                    "target_ref",
                    "kind",
                    "draft_slot",
                    "content",
                    "updated_hlc",
                    "origin_device_id",
                    "retention_expires_at",
                ],
                &[
                    ("target_ref", "string"),
                    ("kind", "string"),
                    ("draft_slot", "string"),
                    ("content", "object"),
                    ("updated_hlc", "string"),
                    ("origin_device_id", "string"),
                    ("retention_expires_at", "string"),
                ],
            ),
        );
        registry.register(
            SchemaId::CALENDAR_EVENT_V1,
            object_schema(
                SchemaId::CALENDAR_EVENT_V1,
                &["start", "end", "timezone", "all_day"],
                &[
                    ("start", "string"),
                    ("end", "string"),
                    ("timezone", "string"),
                    ("all_day", "boolean"),
                    ("recurrence", "object"),
                    ("location", "object"),
                    ("call_id", "string"),
                    ("attendees", "array"),
                ],
            ),
        );
        registry.register(
            SchemaId::SEARCH_SERVICE_V1,
            object_schema(SchemaId::SEARCH_SERVICE_V1, &[], &[("realm_id", "string")]),
        );
        registry.register(
            SchemaId::ENCRYPTED_ENVELOPE_V1,
            object_schema(
                SchemaId::ENCRYPTED_ENVELOPE_V1,
                &[
                    "scheme",
                    "group_id",
                    "epoch",
                    "content_type",
                    "ciphertext",
                    "payload_digest",
                ],
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
            SchemaId::ACCOUNT_SUBSCRIBE_FRAME_V1,
            object_schema(
                SchemaId::ACCOUNT_SUBSCRIBE_FRAME_V1,
                &["kind"],
                &[
                    ("kind", "string"),
                    ("cursor", "string"),
                    ("realms", "object"),
                ],
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

fn strand_schema_document() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SchemaId::STRAND_V1,
        "type": "object",
        "required": ["id", "schema", "realm_id", "stage", "tracks", "created_by", "created_at"],
        "not": {
            "anyOf": [
                { "required": ["title"] },
                { "required": ["summary"] },
                { "required": ["fields"] },
                { "required": ["encrypted_payload"] },
                { "required": ["content", "encrypted_content"] },
                { "required": ["metadata", "encrypted_metadata"] }
            ]
        },
        "properties": {
            "schema": { "type": "string" },
            "id": { "type": "string" },
            "realm_id": { "type": "string" },
            "metadata": { "type": "object" },
            "encrypted_metadata": { "type": "object" },
            "content": { "type": "object" },
            "encrypted_content": { "type": "object" },
            "tracks": { "type": "object", "minProperties": 1 },
            "state": { "type": "string" },
            "state_changed_at": { "type": "string" },
            "stage": {
                "type": "string",
                "enum": ["draft", "proposed", "planned", "in_progress", "blocked", "done", "cancelled", "superseded"]
            },
            "stage_changed_at": { "type": "string" },
            "created_by": { "type": "string" },
            "created_at": { "type": "string" },
            "updated_by": { "type": "string" },
            "updated_at": { "type": "string" },
        },
        "additionalProperties": false
    })
}

fn morph_schema_document() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SchemaId::MORPH_V1,
        "type": "object",
        "required": ["schema", "id", "realm_id", "schema_refs", "morph_kind", "created_by", "created_at"],
        "not": {
            "anyOf": [
                { "required": ["title"] },
                { "required": ["summary"] },
                { "required": ["encrypted_payload"] },
                { "required": ["content", "encrypted_content"] },
                { "required": ["metadata", "encrypted_metadata"] }
            ]
        },
        "properties": {
            "schema": { "type": "string" },
            "id": { "type": "string" },
            "realm_id": { "type": "string" },
            "scope_circle_id": { "type": "string" },
            "schema_refs": { "type": "array", "minItems": 1, "uniqueItems": true },
            "morph_kind": { "type": "string" },
            "facets": { "type": "object" },
            "metadata": {
                "type": "object",
                "not": {
                    "anyOf": [
                        { "required": ["id"] },
                        { "required": ["schema"] },
                        { "required": ["realm_id"] },
                        { "required": ["scope_circle_id"] },
                        { "required": ["schema_refs"] },
                        { "required": ["morph_kind"] },
                        { "required": ["facets"] },
                        { "required": ["fields"] },
                        { "required": ["stage"] },
                        { "required": ["stage_changed_at"] },
                        { "required": ["state"] },
                        { "required": ["state_changed_at"] },
                        { "required": ["created_by"] },
                        { "required": ["created_at"] },
                        { "required": ["updated_by"] },
                        { "required": ["updated_at"] },
                        { "required": ["content"] },
                        { "required": ["encrypted_content"] },
                        { "required": ["encrypted_payload"] }
                    ]
                },
                "properties": {
                    "title": { "type": "string", "minLength": 1, "maxLength": 512 },
                    "summary": { "type": "string", "maxLength": 2048 }
                },
                "additionalProperties": true
            },
            "encrypted_metadata": { "type": "object" },
            "content": { "type": "object" },
            "encrypted_content": { "type": "object" },
            "fields": { "type": "object" },
            "state": { "type": "string" },
            "state_changed_at": { "type": "string" },
            "stage": {
                "type": "string",
                "enum": ["draft", "proposed", "planned", "in_progress", "blocked", "done", "cancelled", "superseded"]
            },
            "stage_changed_at": { "type": "string" },
            "created_by": { "type": "string" },
            "created_at": { "type": "string" },
            "updated_by": { "type": "string" },
            "updated_at": { "type": "string" }
        },
        "additionalProperties": true
    })
}

fn space_schema_document() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SchemaId::SPACE_V1,
        "type": "object",
        "required": ["schema", "id", "space_id", "kind", "title", "created_by", "created_at"],
        "properties": {
            "schema": { "type": "string" },
            "id": { "type": "string" },
            "space_id": { "type": "string" },
            "kind": { "type": "string" },
            "title": { "type": "string" },
            "parent_space_id": { "type": "string" },
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
        "$id": SchemaId::VIEW_V1,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_enforces_json_schema_composition_and_value_rules() {
        let mut registry = ProtocolSchemaRegistry::new();
        registry.register(
            "ak.schema.deep_test.v1",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "ak.schema.deep_test.v1",
                "type": "object",
                "required": ["kind", "items", "target"],
                "properties": {
                    "kind": {"const": "demo"},
                    "items": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "pattern": "^[a-z]+$"}
                    },
                    "target": {
                        "oneOf": [
                            {"type": "string", "enum": ["user", "space"]},
                            {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
                        ]
                    }
                },
                "allOf": [{"properties": {"kind": {"type": "string"}}}],
                "patternProperties": {
                    "^x_[a-z][a-z0-9_]{0,63}$": {"type": "string"}
                },
                "additionalProperties": false
            }),
        );
        registry
            .validate_value(
                "ak.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "user", "x_role": "member"}),
            )
            .unwrap();
        for invalid in [
            json!({"kind": "demo", "items": [], "target": "user"}),
            json!({"kind": "demo", "items": ["alpha"], "target": "other"}),
            json!({"kind": "other", "items": ["alpha"], "target": "user"}),
            json!({"kind": "demo", "items": ["alpha"], "target": "user", "extra": true}),
            json!({"kind": "demo", "items": ["alpha"], "target": "user", "x_role": false}),
        ] {
            assert!(
                registry
                    .validate_value("ak.schema.deep_test.v1", &invalid)
                    .is_err()
            );
        }
    }
}
