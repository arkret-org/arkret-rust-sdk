use std::fmt::Write as _;

use crate::model::LoadedArtifact;

pub fn variant(value: &str, prefixes: &[&str]) -> String {
    let value = prefixes
        .iter()
        .find_map(|prefix| value.strip_prefix(prefix))
        .unwrap_or(value);
    let mut result = String::new();
    for part in value.split(|character: char| !character.is_ascii_alphanumeric()) {
        if part.is_empty() {
            continue;
        }
        let mut characters = part.chars();
        if let Some(first) = characters.next() {
            result.extend(first.to_uppercase());
            result.extend(characters);
        }
    }
    if result.is_empty() || result.starts_with(|character: char| character.is_ascii_digit()) {
        result.insert_str(0, "Value");
    }
    result
}

pub fn associated_name(value: &str, prefixes: &[&str]) -> String {
    let value = prefixes
        .iter()
        .find_map(|prefix| value.strip_prefix(prefix))
        .unwrap_or(value);
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

pub fn rust_string(value: &str) -> String {
    serde_json::to_string(value).expect("a Rust string is valid JSON")
}

pub fn string_slice(values: &[String]) -> String {
    format!(
        "&[{}]",
        values
            .iter()
            .map(|value| rust_string(value))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub fn event_kind_slice(values: &[String]) -> String {
    format!(
        "&[{}]",
        values
            .iter()
            .map(|value| format!("event_kind_str::{}", associated_name(value, &["ak."])))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub fn option_string(value: Option<&str>) -> String {
    value.map_or_else(
        || "None".to_owned(),
        |value| format!("Some({})", rust_string(value)),
    )
}

/// Render one registry rule node as an `arkret_wire::EventCellRule` literal.
///
/// The AST is lossless: object keys become `EventCellRuleKey` variants, a `kind`
/// member becomes an `EventCellRuleOperator`, and every other scalar keeps its
/// JSON shape. `tools/generate-sdk-event-kinds.ps1` folds the same nodes into
/// those two enums, so a node this function can render is a node the wire crate
/// can name.
pub fn cell_rule(value: &serde_json::Value) -> String {
    cell_rule_node(value, false)
}

pub fn option_cell_rule(value: Option<&serde_json::Value>) -> String {
    value.map_or_else(
        || "None".to_owned(),
        |value| format!("Some({})", cell_rule(value)),
    )
}

fn cell_rule_node(value: &serde_json::Value, is_operator: bool) -> String {
    match value {
        serde_json::Value::Null => "EventCellRule::Null".to_owned(),
        serde_json::Value::Bool(value) => format!("EventCellRule::Bool({value})"),
        serde_json::Value::Number(number) => {
            let integer = number
                .as_i64()
                .unwrap_or_else(|| panic!("cell rule integer exceeds i64: {number}"));
            format!("EventCellRule::Integer({integer})")
        }
        serde_json::Value::String(text) if is_operator => format!(
            "EventCellRule::Operator(EventCellRuleOperator::{})",
            variant(text, &[])
        ),
        serde_json::Value::String(text) => format!("EventCellRule::String({})", rust_string(text)),
        serde_json::Value::Array(items) => format!(
            "EventCellRule::Array(&[{}])",
            items
                .iter()
                .map(|item| cell_rule_node(item, false))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        serde_json::Value::Object(members) => format!(
            "EventCellRule::Object(&[{}])",
            members
                .iter()
                .map(|(key, member)| format!(
                    "EventCellRuleField {{ key: EventCellRuleKey::{}, value: {} }}",
                    variant(key, &[]),
                    cell_rule_node(member, key == "kind")
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub fn header(inputs: &[&LoadedArtifact], counts: &str) -> String {
    let mut output =
        String::from("//! @generated; do not edit by hand.\n//! Generator: tools/spec-codegen\n");
    for input in inputs {
        writeln!(
            output,
            "//! Input: {}; version={}; sha256={}",
            input.relative_path, input.version, input.digest
        )
        .expect("write to String");
    }
    writeln!(output, "//! Entries: {counts}\n").expect("write to String");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_map_to_existing_rust_naming_convention() {
        assert_eq!(
            variant("ak.self.events.read.frontier.v1", &["ak."]),
            "SelfEventsReadFrontierV1"
        );
        assert_eq!(associated_name("ak.realm.create", &["ak."]), "REALM_CREATE");
    }

    #[test]
    fn cell_rule_nodes_render_the_shared_closed_grammar() {
        let condition = serde_json::json!({
            "kind": "field_equals",
            "field": "payload.target_state",
            "const": "revoked"
        });
        let rendered = cell_rule(&condition);
        assert!(
            rendered.starts_with("EventCellRule::Object(&["),
            "{rendered}"
        );
        assert!(rendered.contains("EventCellRuleKey::Const"), "{rendered}");
        assert!(
            rendered.contains("EventCellRuleOperator::FieldEquals"),
            "{rendered}"
        );
        assert!(
            rendered.contains("EventCellRule::String(\"payload.target_state\")"),
            "{rendered}"
        );
        assert_eq!(option_cell_rule(None), "None");
    }

    #[test]
    fn rust_strings_are_escaped_by_the_json_string_grammar() {
        assert_eq!(rust_string("a\n\"b"), "\"a\\n\\\"b\"");
    }
}
