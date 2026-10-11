use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::runtime_contracts::GeneratedOutput;

const OPENAPI_PATH: &str = "openapi/arkret-service-api.openapi.yaml";

pub fn generate(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let path = artifacts_dir.join(OPENAPI_PATH);
    let source = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let document: Value =
        serde_saphyr::from_str(&source).with_context(|| format!("parse {}", path.display()))?;
    let version = document
        .pointer("/info/version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .context("OpenAPI document has no nonempty info.version")?;
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .context("OpenAPI document has no paths object")?;

    let mut operations = BTreeMap::new();
    for (path, item) in paths {
        let Some(operation) = item.get("query") else {
            continue;
        };
        if !operation.is_object() {
            bail!("QUERY {path} is not an OpenAPI Operation Object");
        }
        operations.insert(path.clone(), operation.clone());
    }
    if operations.is_empty() {
        bail!("OpenAPI document declares no QUERY operations");
    }

    let mut references = BTreeSet::new();
    for operation in operations.values() {
        collect_component_references(operation, &mut references)?;
    }
    let mut components = serde_json::Map::new();
    let mut pending = references.into_iter().collect::<Vec<_>>();
    let mut emitted = BTreeSet::new();
    while let Some(reference) = pending.pop() {
        if !emitted.insert(reference.clone()) {
            continue;
        }
        let target = resolve_pointer(&document, &reference)
            .with_context(|| format!("resolve OpenAPI component reference {reference}"))?;
        let segments = reference
            .strip_prefix("#/components/")
            .context("local reference is outside components")?
            .split('/')
            .map(unescape_pointer_segment)
            .collect::<Vec<_>>();
        if segments.len() != 2 {
            bail!("unsupported OpenAPI component reference {reference}");
        }
        components
            .entry(segments[0].clone())
            .or_insert_with(|| Value::Object(serde_json::Map::new()))
            .as_object_mut()
            .context("generated OpenAPI component section is not an object")?
            .insert(segments[1].clone(), target.clone());
        let mut nested = BTreeSet::new();
        collect_component_references(target, &mut nested)?;
        pending.extend(nested);
    }

    let mut output = format!(
        "//! @generated; do not edit by hand.\n//! Generator: tools/spec-codegen\n//! Input: {OPENAPI_PATH}; version={version}; sha256={}\n\n",
        hex::encode(Sha256::digest(source.as_bytes()))
    );
    output.push_str("pub fn openapi_query_operations() -> Vec<(&'static str, serde_json::Value)> {\n    vec![\n");
    for (path, operation) in &operations {
        output.push_str("        (");
        output.push_str(&serde_json::to_string(path)?);
        output.push_str(", serde_json::json!(");
        output.push_str(&serde_json::to_string(operation)?);
        output.push_str(")),\n");
    }
    output.push_str("    ]\n}\n\n");
    output.push_str(
        "pub fn openapi_query_components() -> serde_json::Value {\n    serde_json::json!(",
    );
    output.push_str(&serde_json::to_string(&Value::Object(components))?);
    output.push_str(")\n}\n");

    Ok(GeneratedOutput {
        relative_path: "crates/schema/src/generated/openapi_query.rs".into(),
        contents: output,
    })
}

fn collect_component_references(value: &Value, references: &mut BTreeSet<String>) -> Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_component_references(value, references)?;
            }
        }
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str)
                && reference.starts_with("#/components/")
            {
                references.insert(reference.to_owned());
            }
            for value in object.values() {
                collect_component_references(value, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve_pointer<'a>(document: &'a Value, pointer: &str) -> Option<&'a Value> {
    let mut current = document;
    for segment in pointer.strip_prefix("#/")?.split('/') {
        current = current.get(unescape_pointer_segment(segment))?;
    }
    Some(current)
}

fn unescape_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_pointer_segments_are_unescaped() {
        assert_eq!(unescape_pointer_segment("a~1b~0c"), "a/b~c");
    }
}
