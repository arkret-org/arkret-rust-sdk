//! Lossless transport for generated JSON Schema 2020-12 components.
//!
//! Salvo's typed schema AST covers a subset of that dialect. Its flattened
//! object keyword map preserves canonical applicators (including `if`/`then`
//! and `$defs`) without coercing them into Rust memory-layout schemas.

use salvo_oapi::schema::Schema;
use salvo_oapi::{Components, RefOr};

pub(crate) fn decode_components(input: &str) -> Vec<(String, Schema)> {
    let components: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(input).expect("generated canonical OpenAPI JSON");
    components
        .into_iter()
        .map(|(name, value)| {
            let schema = match value {
                serde_json::Value::Bool(value) => Schema::Boolean(value),
                serde_json::Value::Object(keywords) => {
                    let mut schema =
                        salvo_oapi::schema::Object::with_type(salvo_oapi::SchemaType::any());
                    schema.extensions.extend(keywords);
                    Schema::Object(Box::new(schema))
                }
                _ => panic!("generated component is not a JSON Schema"),
            };
            (name, schema)
        })
        .collect()
}

pub(crate) fn register_components(components: &mut Components, schemas: &[(String, Schema)]) {
    let mut batch = std::collections::BTreeMap::new();
    for (name, schema) in schemas {
        let value = RefOr::Type(schema.clone());
        if let Some(existing) = components.schemas.get(name) {
            assert_eq!(existing, &value, "canonical OpenAPI component collision");
        }
        if let Some(existing) = batch.insert(name, value) {
            assert_eq!(
                existing,
                RefOr::Type(schema.clone()),
                "canonical OpenAPI batch collision"
            );
        }
    }
    for (name, schema) in batch {
        components.schemas.insert(name.clone(), schema);
    }
}

#[cfg(test)]
mod tests;
