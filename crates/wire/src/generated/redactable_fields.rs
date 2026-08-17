//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/redactable-field-registry.json; version=2026-08-17;
//! sha256=1fb9d682568336bb6b885277dcf7b03e246659f367edcff766b3501851dcd387
//! Entries: redactable_fields=6, distinct_paths=2

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedactableFieldDescriptor {
    pub object_kind: &'static str,
    pub path: &'static str,
    pub paired_path: &'static str,
    pub non_terminal_clear_op: &'static str,
    pub terminal_clear_event_kinds: &'static [&'static str],
}

/// Registered redactable content-carrier slots
/// (`event-and-patch.md` section 4.2.4).
pub const REDACTABLE_FIELDS: &[RedactableFieldDescriptor] = &[
    RedactableFieldDescriptor {
        object_kind: "message",
        path: "content",
        paired_path: "encrypted_content",
        non_terminal_clear_op: "set",
        terminal_clear_event_kinds: &["ak.message.redact"],
    },
    RedactableFieldDescriptor {
        object_kind: "message",
        path: "encrypted_content",
        paired_path: "content",
        non_terminal_clear_op: "set",
        terminal_clear_event_kinds: &["ak.message.redact"],
    },
    RedactableFieldDescriptor {
        object_kind: "morph",
        path: "content",
        paired_path: "encrypted_content",
        non_terminal_clear_op: "set",
        terminal_clear_event_kinds: &["ak.redaction"],
    },
    RedactableFieldDescriptor {
        object_kind: "morph",
        path: "encrypted_content",
        paired_path: "content",
        non_terminal_clear_op: "set",
        terminal_clear_event_kinds: &["ak.redaction"],
    },
    RedactableFieldDescriptor {
        object_kind: "strand",
        path: "content",
        paired_path: "encrypted_content",
        non_terminal_clear_op: "set",
        terminal_clear_event_kinds: &["ak.redaction"],
    },
    RedactableFieldDescriptor {
        object_kind: "strand",
        path: "encrypted_content",
        paired_path: "content",
        non_terminal_clear_op: "set",
        terminal_clear_event_kinds: &["ak.redaction"],
    },
];

/// Distinct slot paths a patch `$op="unset"` must never address.
/// Realm-defined `redactable: true` fields are declared by their own
/// Realm schema and are enforced separately.
pub const REDACTABLE_FIELD_PATHS: &[&str] = &["content", "encrypted_content"];
