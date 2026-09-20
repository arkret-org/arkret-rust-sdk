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
            variant("ak.self.committed_events.read.scan.v1", &["ak."]),
            "SelfCommittedEventsReadScanV1"
        );
        assert_eq!(associated_name("ak.realm.create", &["ak."]), "REALM_CREATE");
    }

    #[test]
    fn rust_strings_are_escaped_by_the_json_string_grammar() {
        assert_eq!(rust_string("a\n\"b"), "\"a\\n\\\"b\"");
    }
}
