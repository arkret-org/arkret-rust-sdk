use regex::Regex;
use serde_json::{Value, json};

use super::super::*;
use super::validators::{
    is_security_sensitive_extension, validate_json_schema_array_sizes, validate_json_schema_format,
    validate_json_schema_numbers, validate_json_schema_object_sizes, validate_json_schema_pattern,
    validate_json_schema_string_lengths, validate_json_schema_type_value,
};

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
            let trusted = self
                .trusted_extension_prefixes
                .iter()
                .any(|prefix| field.starts_with(prefix));
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
        Self {
            schemas: BTreeMap::new(),
            trusted_extension_prefixes: Vec::new(),
        }
    }

    /// Register a schema document by `$id`.
    pub fn register(&mut self, schema_id: impl Into<String>, schema: Value) {
        self.schemas.insert(schema_id.into(), schema);
    }

    /// Return one schema by ID.
    pub fn schema(&self, schema_id: &str) -> Option<&Value> {
        if let Some(schema) = self.schemas.get(schema_id) {
            return Some(schema);
        }
        let (base, fragment) = schema_id.split_once('#')?;
        let root = self.schemas.get(base)?;
        if fragment.is_empty() {
            return Some(root);
        }
        root.pointer(fragment)
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

    /// Validate one value against the registered JSON Schema document.
    pub fn validate_value(&self, schema_id: &str, value: &Value) -> Result<()> {
        let root_id = schema_id
            .split_once('#')
            .map(|(base, _)| base)
            .unwrap_or(schema_id);
        let root = self
            .schemas
            .get(root_id)
            .ok_or_else(|| Error::Protocol(format!("unknown schema '{root_id}'")))?;
        let schema = self
            .schema(schema_id)
            .ok_or_else(|| Error::Protocol(format!("unknown schema '{schema_id}'")))?;
        self.validate_schema(root_id, root, schema, value, "$", 0)?;
        if let Some(object) = value.as_object() {
            self.validate_security_extensions(schema_id, object)?;
        }
        Ok(())
    }

    fn validate_schema(
        &self,
        root_id: &str,
        root: &Value,
        schema: &Value,
        value: &Value,
        path: &str,
        depth: usize,
    ) -> Result<()> {
        if depth > 128 {
            return Err(Error::Protocol(format!(
                "schema '{root_id}' exceeded recursive validation depth at {path}"
            )));
        }
        let Some(schema_object) = schema.as_object() else {
            return Ok(());
        };

        if let Some(reference) = schema_object.get("$ref").and_then(Value::as_str) {
            let (resolved_root_id, resolved_root, resolved_schema) =
                self.resolve_schema_ref(root_id, root, reference)?;
            return self.validate_schema(
                resolved_root_id,
                resolved_root,
                resolved_schema,
                value,
                path,
                depth + 1,
            );
        }

        if let Some(constant) = schema_object.get("const")
            && value != constant
        {
            return Err(Error::Protocol(format!(
                "schema '{root_id}' const mismatch at {path}"
            )));
        }

        if let Some(enum_values) = schema_object.get("enum").and_then(Value::as_array)
            && !enum_values.iter().any(|candidate| candidate == value)
        {
            return Err(Error::Protocol(format!(
                "schema '{root_id}' enum mismatch at {path}"
            )));
        }

        if let Some(schema_type) = schema_object.get("type") {
            validate_json_schema_type_value(root_id, path, schema_type, value)?;
        }

        for keyword in ["allOf"] {
            if let Some(items) = schema_object.get(keyword).and_then(Value::as_array) {
                for item in items {
                    self.validate_schema(root_id, root, item, value, path, depth + 1)?;
                }
            }
        }

        for keyword in ["oneOf", "anyOf"] {
            if let Some(items) = schema_object.get(keyword).and_then(Value::as_array) {
                let matches = items
                    .iter()
                    .filter(|item| {
                        self.validate_schema(root_id, root, item, value, path, depth + 1)
                            .is_ok()
                    })
                    .count();
                let valid = if keyword == "oneOf" {
                    matches == 1
                } else {
                    matches >= 1
                };
                if !valid {
                    return Err(Error::Protocol(format!(
                        "schema '{root_id}' {keyword} matched {matches} branches at {path}"
                    )));
                }
            }
        }

        if let Some(not_schema) = schema_object.get("not")
            && self
                .validate_schema(root_id, root, not_schema, value, path, depth + 1)
                .is_ok()
        {
            return Err(Error::Protocol(format!(
                "schema '{root_id}' not schema matched at {path}"
            )));
        }

        if let Some(if_schema) = schema_object.get("if") {
            let branch = if self
                .validate_schema(root_id, root, if_schema, value, path, depth + 1)
                .is_ok()
            {
                schema_object.get("then")
            } else {
                schema_object.get("else")
            };
            if let Some(branch_schema) = branch {
                self.validate_schema(root_id, root, branch_schema, value, path, depth + 1)?;
            }
        }

        if let Some(format) = schema_object.get("format").and_then(Value::as_str) {
            validate_json_schema_format(root_id, path, format, value)?;
        }
        if let Some(pattern) = schema_object.get("pattern").and_then(Value::as_str) {
            validate_json_schema_pattern(root_id, path, pattern, value)?;
        }
        validate_json_schema_string_lengths(root_id, path, schema, value)?;
        validate_json_schema_numbers(root_id, path, schema, value)?;

        if let Some(object) = value.as_object() {
            validate_json_schema_object_sizes(root_id, path, schema, object)?;
            if let Some(required) = schema_object.get("required").and_then(Value::as_array) {
                for field in required.iter().filter_map(Value::as_str) {
                    if !object.contains_key(field) {
                        return Err(Error::Protocol(format!(
                            "schema '{root_id}' requires field '{field}' at {path}"
                        )));
                    }
                }
            }
            if let Some(properties) = schema_object.get("properties").and_then(Value::as_object) {
                for (field, property_schema) in properties {
                    if let Some(field_value) = object.get(field) {
                        self.validate_schema(
                            root_id,
                            root,
                            property_schema,
                            field_value,
                            &format!("{path}.{field}"),
                            depth + 1,
                        )?;
                    }
                }
            }
            if let Some(property_names) = schema_object.get("propertyNames") {
                for field in object.keys() {
                    self.validate_schema(
                        root_id,
                        root,
                        property_names,
                        &Value::String(field.clone()),
                        &format!("{path} property name"),
                        depth + 1,
                    )?;
                }
            }
            let mut pattern_matches = BTreeSet::new();
            if let Some(pattern_properties) = schema_object
                .get("patternProperties")
                .and_then(Value::as_object)
            {
                for (pattern, pattern_schema) in pattern_properties {
                    let regex = Regex::new(pattern).map_err(|error| {
                        Error::Protocol(format!(
                            "schema '{root_id}' has invalid patternProperties regex at {path}: {error}"
                        ))
                    })?;
                    for (field, field_value) in object {
                        if regex.is_match(field) {
                            pattern_matches.insert(field.clone());
                            self.validate_schema(
                                root_id,
                                root,
                                pattern_schema,
                                field_value,
                                &format!("{path}.{field}"),
                                depth + 1,
                            )?;
                        }
                    }
                }
            }
            if let Some(additional) = schema_object.get("additionalProperties") {
                let known = schema_object
                    .get("properties")
                    .and_then(Value::as_object)
                    .map(|properties| properties.keys().collect::<BTreeSet<_>>())
                    .unwrap_or_default();
                for (field, field_value) in object {
                    if known.contains(field) || pattern_matches.contains(field) {
                        continue;
                    }
                    match additional {
                        Value::Bool(true) => {}
                        Value::Bool(false) => {
                            return Err(Error::Protocol(format!(
                                "schema '{root_id}' rejects additional field '{field}' at {path}"
                            )));
                        }
                        schema => {
                            self.validate_schema(
                                root_id,
                                root,
                                schema,
                                field_value,
                                &format!("{path}.{field}"),
                                depth + 1,
                            )?;
                        }
                    }
                }
            }
        }

        if let Some(array) = value.as_array() {
            validate_json_schema_array_sizes(root_id, path, schema, array)?;
            if schema_object.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
                let mut seen = BTreeSet::new();
                for item in array {
                    let encoded = serde_json::to_string(item).map_err(|error| {
                        Error::Protocol(format!(
                            "schema '{root_id}' failed to compare uniqueItems at {path}: {error}"
                        ))
                    })?;
                    if !seen.insert(encoded) {
                        return Err(Error::Protocol(format!(
                            "schema '{root_id}' requires unique array items at {path}"
                        )));
                    }
                }
            }
            if let Some(item_schema) = schema_object.get("items") {
                for (index, item) in array.iter().enumerate() {
                    self.validate_schema(
                        root_id,
                        root,
                        item_schema,
                        item,
                        &format!("{path}[{index}]"),
                        depth + 1,
                    )?;
                }
            }
            // Per JSON Schema 2020-12: `contains` requires at least one
            // array item to validate against the subschema. Optional
            // `minContains` / `maxContains` further constrain the count.
            // Before this branch existed the validator silently treated
            // `contains` as a no-op, which made every `if: { array:
            // { contains: ... } }` block trivially pass and forced the
            // THEN branch to fire regardless of the array's content —
            // including the principal_control_realm guard on
            // realm.schema.json that requires `fields` only for that
            // very specific profile.
            if let Some(contains_schema) = schema_object.get("contains") {
                let matches: usize = array
                    .iter()
                    .enumerate()
                    .filter(|(index, item)| {
                        self.validate_schema(
                            root_id,
                            root,
                            contains_schema,
                            item,
                            &format!("{path}[{index}]"),
                            depth + 1,
                        )
                        .is_ok()
                    })
                    .count();
                let min = schema_object
                    .get("minContains")
                    .and_then(Value::as_u64)
                    .unwrap_or(1) as usize;
                let max = schema_object
                    .get("maxContains")
                    .and_then(Value::as_u64)
                    .map(|value| value as usize);
                if matches < min {
                    return Err(Error::Protocol(format!(
                        "schema '{root_id}' contains requires >= {min} matching items at {path} (got {matches})"
                    )));
                }
                if let Some(max) = max
                    && matches > max
                {
                    return Err(Error::Protocol(format!(
                        "schema '{root_id}' contains allows <= {max} matching items at {path} (got {matches})"
                    )));
                }
            }
        }
        Ok(())
    }

    fn resolve_schema_ref<'a>(
        &'a self,
        root_id: &'a str,
        root: &'a Value,
        reference: &str,
    ) -> Result<(&'a str, &'a Value, &'a Value)> {
        let (document_ref, fragment) = reference.split_once('#').unwrap_or((reference, ""));
        let (resolved_root_id, resolved_root) = if document_ref.is_empty() {
            (root_id, root)
        } else {
            self.resolve_external_schema(document_ref).ok_or_else(|| {
                Error::Protocol(format!("schema '{root_id}' has unresolved ref {reference}"))
            })?
        };
        let resolved_schema = if fragment.is_empty() {
            resolved_root
        } else {
            resolved_root.pointer(fragment).ok_or_else(|| {
                Error::Protocol(format!("schema '{root_id}' has unresolved ref {reference}"))
            })?
        };
        Ok((resolved_root_id, resolved_root, resolved_schema))
    }

    fn resolve_external_schema<'a>(&'a self, document_ref: &str) -> Option<(&'a str, &'a Value)> {
        let normalized = document_ref.trim_start_matches("./");
        self.schemas.iter().find_map(|(schema_id, schema)| {
            let json_id = schema
                .get("$id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if schema_id == document_ref
                || schema_id == normalized
                || json_id == document_ref
                || json_id.ends_with(normalized)
            {
                Some((schema_id.as_str(), schema))
            } else {
                None
            }
        })
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
                    ("seal_ref", "string"),
                    ("requirements", "object"),
                    ("redacts", "string"),
                    ("payload", "object"),
                    ("unsigned", "object"),
                    ("proofs", "array"),
                ],
            ),
        );
        registry.register(STRAND_SCHEMA, strand_schema_document());
        registry.register(MORPH_SCHEMA, morph_schema_document());
        registry.register(SPACE_SCHEMA, space_schema_document());
        registry.register(VIEW_SCHEMA, view_schema_document());
        registry.register(
            EVENT_PAYLOAD_SCHEMA,
            object_schema(EVENT_PAYLOAD_SCHEMA, &[], &[("type", "string")]),
        );
        registry.register(
            ANCHOR_SCHEMA,
            object_schema(
                ANCHOR_SCHEMA,
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
                &["snapshot_id", "realm_id", "frontier", "state_root"],
                &[
                    ("snapshot_id", "string"),
                    ("realm_id", "string"),
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
            PERSONAL_PRODUCTIVITY_SCHEMA,
            object_schema(
                PERSONAL_PRODUCTIVITY_SCHEMA,
                &["kind"],
                &[("kind", "string")],
            ),
        );
        registry.register(
            DRAFT_SYNC_SCHEMA,
            object_schema(
                DRAFT_SYNC_SCHEMA,
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
            CALENDAR_EVENT_SCHEMA,
            object_schema(
                CALENDAR_EVENT_SCHEMA,
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
            DISAPPEARING_MESSAGES_SCHEMA,
            object_schema(DISAPPEARING_MESSAGES_SCHEMA, &[], &[("enabled", "boolean")]),
        );
        registry.register(
            SEARCH_SERVICE_SCHEMA,
            object_schema(SEARCH_SERVICE_SCHEMA, &[], &[("realm_id", "string")]),
        );
        registry.register(
            ENCRYPTED_ENVELOPE_SCHEMA,
            object_schema(
                ENCRYPTED_ENVELOPE_SCHEMA,
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
            ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
            object_schema(
                ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
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
        "$id": STRAND_SCHEMA,
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
        "$id": MORPH_SCHEMA,
        "type": "object",
        "required": ["schema", "id", "realm_id", "schema_refs", "morph_type", "created_by", "created_at"],
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
            "morph_type": { "type": "string" },
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
                        { "required": ["morph_type"] },
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
        "$id": SPACE_SCHEMA,
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
