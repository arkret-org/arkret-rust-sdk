//! Consumer surface for `registry/forbidden-wire-fields.json`.
//!
//! The registry is the source of truth for field names that MUST NOT appear
//! on the current v1 wire in a named context (a payload class, a patch
//! document, the envelope, ...). Its canonical projection is
//! [`crate::generated::FORBIDDEN_WIRE_FIELDS`]. Admission and replay interpret
//! its typed-instance selectors and literal matchers without private tables.

use serde_json::Value;

use crate::generated::{FORBIDDEN_WIRE_FIELDS, ForbiddenWireFieldDescriptor};
use crate::patch::patch_path_covers;

/// Whether `path` hits a `hard_reject` registry entry in `context`.
///
/// `path` is a dotted payload or patch path (`metadata.fields.status`,
/// `stage`, ...). An entry matches when its literal matcher equals the path or is a dotted
/// ancestor of it, so a ban on `metadata.fields.status` also bans a write at
/// `metadata.fields.status.anything`. Literal paths come from generated
/// matcher values; the entry id is only an audit label.
pub fn forbidden_wire_path_hard_reject(context: &str, path: &str) -> bool {
    FORBIDDEN_WIRE_FIELDS.iter().any(|entry| {
        entry.context == context
            && entry.rejection_level == "hard_reject"
            && matches!(entry.match_kind, "field" | "path" | "patch_path")
            && entry
                .match_values
                .iter()
                .any(|value| patch_path_covers(value, path))
    })
}

/// Check one typed instance using only generated context selectors and matchers.
/// The caller supplies its owning contract, never a schema claimed by the value.
pub fn forbidden_wire_violation(
    document_kind: &str,
    schema_ref: &str,
    value: &Value,
) -> Option<&'static ForbiddenWireFieldDescriptor> {
    let schema_ref = schema_ref
        .trim_start_matches("./")
        .trim_start_matches("schemas/");
    FORBIDDEN_WIRE_FIELDS.iter().find(|entry| {
        entry.rejection_level == "hard_reject"
            && entry.selectors.iter().any(|selector| {
                let kind_matches = selector.document_kind == document_kind
                    || selector.document_kind == "schema_instance"
                    || (selector.document_kind == "wire" && document_kind != "executable_artifact");
                kind_matches
                    && (selector.schema_ref == "*" || selector.schema_ref == schema_ref)
                    && at_pointer(value, selector.instance_pointer, &|root| {
                        if selector.match_scope == "patch" {
                            matches!(entry.match_kind, "field" | "path")
                                && entry
                                    .match_values
                                    .iter()
                                    .any(|path| matches_patch(root, path))
                        } else {
                            matches_entry(root, entry, selector.match_scope == "descendants")
                        }
                    })
            })
    })
}

/// Apply the catalog's owning payload schema to an Event payload.
pub fn validate_event_payload_forbidden_fields(
    kind: &crate::EventKind,
    payload: &Value,
) -> crate::Result<()> {
    let Some(schema_ref) = kind.descriptor().and_then(|d| d.payload_schema_ref) else {
        return Ok(());
    };
    if let Some(entry) = forbidden_wire_violation("event_payload", schema_ref, payload) {
        return Err(crate::WireError::Protocol(format!(
            "forbidden wire field {} in {}",
            entry.id, entry.context
        )));
    }
    Ok(())
}

fn at_pointer(value: &Value, pointer: &str, predicate: &impl Fn(&Value) -> bool) -> bool {
    if pointer.is_empty() {
        return predicate(value);
    }
    let Some(pointer) = pointer.strip_prefix('/') else {
        return false;
    };
    let (token, rest) = pointer
        .split_once('/')
        .map_or((pointer, ""), |(t, r)| (t, r));
    let rest = if rest.is_empty() {
        String::new()
    } else {
        format!("/{rest}")
    };
    if token == "*" {
        return match value {
            Value::Object(map) => map.values().any(|v| at_pointer(v, &rest, predicate)),
            Value::Array(items) => items.iter().any(|v| at_pointer(v, &rest, predicate)),
            _ => false,
        };
    }
    let token = token.replace("~1", "/").replace("~0", "~");
    let child = match value {
        Value::Object(map) => map.get(&token),
        Value::Array(items) => token.parse::<usize>().ok().and_then(|i| items.get(i)),
        _ => None,
    };
    child.is_some_and(|v| at_pointer(v, &rest, predicate))
}

fn matches_entry(value: &Value, entry: &ForbiddenWireFieldDescriptor, recursive: bool) -> bool {
    let direct = entry
        .match_values
        .iter()
        .any(|expected| match entry.match_kind {
            "field" => value.as_object().is_some_and(|m| m.contains_key(*expected)),
            "path" => at_pointer(value, &format!("/{}", expected.replace('.', "/")), &|_| {
                true
            }),
            "patch_path" => matches_patch(value, expected),
            "value" => at_pointer(value, entry.value_pointer, &|v| {
                v.as_str() == Some(*expected)
            }),
            "prefix" => at_pointer(value, entry.value_pointer, &|v| {
                v.as_str().is_some_and(|s| s.starts_with(expected))
            }),
            "pattern" => at_pointer(value, entry.value_pointer, &|v| {
                v.as_str()
                    .is_some_and(|s| regex::Regex::new(expected).is_ok_and(|re| re.is_match(s)))
            }),
            _ => false,
        });
    direct
        || (recursive
            && match value {
                Value::Object(map) => map.values().any(|v| matches_entry(v, entry, true)),
                Value::Array(items) => items.iter().any(|v| matches_entry(v, entry, true)),
                _ => false,
            })
}

fn matches_patch(value: &Value, expected: &str) -> bool {
    value
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch.iter().any(|(path, operation)| {
                if patch_path_covers(expected, path) {
                    return true;
                }
                let Some(suffix) = expected.strip_prefix(&format!("{path}.")) else {
                    return false;
                };
                let replacement = match operation.get("$op").and_then(Value::as_str) {
                    Some("set" | "add") => operation.get("value"),
                    Some(_) => None,
                    None => Some(operation),
                };
                replacement.is_some_and(|v| {
                    at_pointer(v, &format!("/{}", suffix.replace('.', "/")), &|_| true)
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn owning_context_distinguishes_message_object_and_signed_payload() {
        let value = json!({"track_name": "discussion"});
        assert_eq!(
            forbidden_wire_violation("materialized_object", "message.schema.json", &value)
                .unwrap()
                .id,
            "track_name"
        );
        assert!(
            forbidden_wire_violation(
                "event_payload",
                "event-payload.schema.json#/$defs/message_create_payload",
                &value
            )
            .is_none()
        );
        assert!(
            forbidden_wire_violation(
                "materialized_object",
                "message.schema.json",
                &json!({"metadata": {"track_name": "custom"}})
            )
            .is_none()
        );
    }

    #[test]
    fn payload_scope_guards_are_generated_for_all_kinds() {
        assert!(
            validate_event_payload_forbidden_fields(
                &crate::EventKind::MessageCreate,
                &json!({"message_id": "forbidden"})
            )
            .is_err()
        );
        assert!(
            validate_event_payload_forbidden_fields(
                &crate::EventKind::StrandCreate,
                &json!({"object": {"metadata": {"fields": {"status": "closed"}}}})
            )
            .is_err()
        );
        assert!(
            validate_event_payload_forbidden_fields(
                &crate::EventKind::MessageCreate,
                &json!({"metadata": {"fields": {"status": "custom"}}, "track_name": "discussion"})
            )
            .is_ok()
        );
        assert!(
            forbidden_wire_violation(
                "schema_instance",
                "key-backup.schema.json",
                &json!({"encryption": {"kdf": {"params": {"hash": "SHA256"}}}})
            )
            .is_some()
        );
        assert!(
            forbidden_wire_violation(
                "schema_instance",
                "key-backup.schema.json",
                &json!({"other": {"hash": "SHA256"}})
            )
            .is_none()
        );
    }

    #[test]
    fn retired_id_prefix_is_a_typed_value_rule_not_a_free_text_rule() {
        assert!(forbidden_wire_violation("typed_id_value", "*", &json!("ak:notif:old")).is_some());
        assert!(
            validate_event_payload_forbidden_fields(
                &crate::EventKind::MessageCreate,
                &json!({"track_name": "discussion", "content": {"body": "ak:notif:quoted text"}})
            )
            .is_ok()
        );
    }

    #[test]
    fn registry_projects_strand_and_morph_contexts() {
        // The counts pin the registry surface this module projects; a spec-side
        // entry addition or removal must be reflected here deliberately.
        let count = |context: &str| {
            FORBIDDEN_WIRE_FIELDS
                .iter()
                .filter(|entry| entry.context == context)
                .count()
        };
        assert_eq!(count("strand_payload"), 12);
        assert_eq!(count("strand_patch_payload"), 9);
        assert_eq!(count("morph_payload"), 6);
        assert_eq!(count("morph_update_payload"), 2);
    }

    #[test]
    fn dotted_payload_entries_match_exactly_and_cover_descendants() {
        assert!(forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.fields.status"
        ));
        assert!(forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.fields.status.detail"
        ));
        assert!(!forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.fields.jira_status"
        ));
        assert!(!forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.title"
        ));
        // An ancestor of a registered path is not itself registered; callers
        // that accept a whole-object set value must descend into it.
        assert!(!forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.fields"
        ));
    }

    #[test]
    fn patch_prefixed_entries_match_the_bare_path() {
        assert!(forbidden_wire_path_hard_reject(
            "strand_patch_payload",
            "stage"
        ));
        assert!(forbidden_wire_path_hard_reject(
            "strand_patch_payload",
            "metadata.fields.assignee"
        ));
        assert!(forbidden_wire_path_hard_reject(
            "morph_update_payload",
            "morph_kind"
        ));
        assert!(!forbidden_wire_path_hard_reject(
            "morph_update_payload",
            "metadata.title"
        ));
        // Contexts are pinned: a name forbidden in one context may be legal
        // in another.
        assert!(!forbidden_wire_path_hard_reject(
            "morph_payload",
            "metadata.fields.status"
        ));
    }

    #[test]
    fn canonical_patch_map_checks_direct_explicit_and_ancestor_replacements() {
        for patch in [
            json!({"metadata.fields.status.detail": "closed"}),
            json!({"metadata.fields.status": {"$op": "unset"}}),
            json!({"metadata": {"fields": {"status": "closed"}}}),
            json!({"metadata.fields": {"$op": "set", "value": {"status": "closed"}}}),
        ] {
            assert!(
                validate_event_payload_forbidden_fields(
                    &crate::EventKind::StrandUpdate,
                    &json!({"patch": patch})
                )
                .is_err()
            );
        }
        assert!(
            validate_event_payload_forbidden_fields(
                &crate::EventKind::StrandUpdate,
                &json!({"patch": {"metadata": {"fields": {"jira_status": "custom"}}}})
            )
            .is_ok()
        );
    }

    #[test]
    fn morph_reserved_field_names_are_hard_reject() {
        for leaf in [
            "lifecycle",
            "progress_state",
            "stage",
            "stage_changed_at",
            "stage_note",
            "stage_reason",
        ] {
            let path = format!("fields.{leaf}");
            assert!(
                forbidden_wire_path_hard_reject("morph_payload", &path),
                "{path} is hard_reject in morph_payload"
            );
        }
    }
}
