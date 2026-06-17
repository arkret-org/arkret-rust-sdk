use chrono::DateTime;
use regex::Regex;
use serde_json::Value;

use super::super::*;

pub(crate) fn is_security_sensitive_extension(field: &str) -> bool {
    matches!(
        field,
        "x-authz"
            | "x-policy"
            | "x-security"
            | "x-cokret-authz"
            | "x-cokret-policy"
            | "x-cokret-security"
    ) || field.starts_with("x-authz-")
        || field.starts_with("x-policy-")
        || field.starts_with("x-security-")
        || field.starts_with("x-cokret-authz-")
        || field.starts_with("x-cokret-policy-")
        || field.starts_with("x-cokret-security-")
}

pub(crate) fn validate_json_schema_type_value(
    schema_id: &str,
    path: &str,
    schema_type: &Value,
    value: &Value,
) -> Result<()> {
    let matches = match schema_type {
        Value::String(kind) => json_schema_type_matches(kind, value),
        Value::Array(kinds) => kinds
            .iter()
            .filter_map(Value::as_str)
            .any(|kind| json_schema_type_matches(kind, value)),
        _ => true,
    };
    if matches {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "schema '{schema_id}' type mismatch at {path}: expected {schema_type}"
        )))
    }
}

pub(crate) fn json_schema_type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        _ => true,
    }
}

pub(crate) fn validate_json_schema_pattern(
    schema_id: &str,
    path: &str,
    pattern: &str,
    value: &Value,
) -> Result<()> {
    let Some(text) = value.as_str() else {
        return Ok(());
    };
    let regex = Regex::new(pattern).map_err(|error| {
        Error::Protocol(format!(
            "schema '{schema_id}' has invalid regex at {path}: {error}"
        ))
    })?;
    if regex.is_match(text) {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "schema '{schema_id}' pattern mismatch at {path}"
        )))
    }
}

pub(crate) fn validate_json_schema_format(
    schema_id: &str,
    path: &str,
    format: &str,
    value: &Value,
) -> Result<()> {
    if format != "date-time" {
        return Ok(());
    }
    let Some(text) = value.as_str() else {
        return Ok(());
    };
    DateTime::parse_from_rfc3339(text)
        .map(|_| ())
        .map_err(|error| {
            Error::Protocol(format!(
                "schema '{schema_id}' date-time format mismatch at {path}: {error}"
            ))
        })
}

pub(crate) fn validate_json_schema_string_lengths(
    schema_id: &str,
    path: &str,
    schema: &Value,
    value: &Value,
) -> Result<()> {
    let Some(text) = value.as_str() else {
        return Ok(());
    };
    let len = text.chars().count() as u64;
    if let Some(min) = schema.get("minLength").and_then(Value::as_u64)
        && len < min
    {
        return Err(Error::Protocol(format!(
            "schema '{schema_id}' minLength mismatch at {path}"
        )));
    }
    if let Some(max) = schema.get("maxLength").and_then(Value::as_u64)
        && len > max
    {
        return Err(Error::Protocol(format!(
            "schema '{schema_id}' maxLength mismatch at {path}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_json_schema_array_sizes(
    schema_id: &str,
    path: &str,
    schema: &Value,
    value: &[Value],
) -> Result<()> {
    let len = value.len() as u64;
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
        && len < min
    {
        return Err(Error::Protocol(format!(
            "schema '{schema_id}' minItems mismatch at {path}"
        )));
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
        && len > max
    {
        return Err(Error::Protocol(format!(
            "schema '{schema_id}' maxItems mismatch at {path}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_json_schema_object_sizes(
    schema_id: &str,
    path: &str,
    schema: &Value,
    value: &serde_json::Map<String, Value>,
) -> Result<()> {
    let len = value.len() as u64;
    if let Some(min) = schema.get("minProperties").and_then(Value::as_u64)
        && len < min
    {
        return Err(Error::Protocol(format!(
            "schema '{schema_id}' minProperties mismatch at {path}"
        )));
    }
    if let Some(max) = schema.get("maxProperties").and_then(Value::as_u64)
        && len > max
    {
        return Err(Error::Protocol(format!(
            "schema '{schema_id}' maxProperties mismatch at {path}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_json_schema_numbers(
    schema_id: &str,
    path: &str,
    schema: &Value,
    value: &Value,
) -> Result<()> {
    let Some(number) = value.as_f64() else {
        return Ok(());
    };
    for (keyword, violated) in [
        (
            "minimum",
            schema
                .get("minimum")
                .and_then(Value::as_f64)
                .is_some_and(|min| number < min),
        ),
        (
            "maximum",
            schema
                .get("maximum")
                .and_then(Value::as_f64)
                .is_some_and(|max| number > max),
        ),
        (
            "exclusiveMinimum",
            schema
                .get("exclusiveMinimum")
                .and_then(Value::as_f64)
                .is_some_and(|min| number <= min),
        ),
        (
            "exclusiveMaximum",
            schema
                .get("exclusiveMaximum")
                .and_then(Value::as_f64)
                .is_some_and(|max| number >= max),
        ),
    ] {
        if violated {
            return Err(Error::Protocol(format!(
                "schema '{schema_id}' {keyword} mismatch at {path}"
            )));
        }
    }
    Ok(())
}
