//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/redactable-field-registry.json; version=2026-08-18; sha256=72c8d0a4858200155579877f7ff637bd2c83547abdf7dea257255c7e07cfecc1
//! Entries: redactable_fields=8, distinct_paths=4

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
    RedactableFieldDescriptor {
        object_kind: "strand",
        path: "tracks.synthesis.content",
        paired_path: "tracks.synthesis.encrypted_content",
        non_terminal_clear_op: "set",
        terminal_clear_event_kinds: &["ak.redaction"],
    },
    RedactableFieldDescriptor {
        object_kind: "strand",
        path: "tracks.synthesis.encrypted_content",
        paired_path: "tracks.synthesis.content",
        non_terminal_clear_op: "set",
        terminal_clear_event_kinds: &["ak.redaction"],
    },
];

/// Distinct slot paths a patch `$op="unset"` must never address.
/// Realm-defined `redactable: true` fields are declared by their own
/// Realm schema and are enforced separately.
pub const REDACTABLE_FIELD_PATHS: &[&str] = &[
    "content",
    "encrypted_content",
    "tracks.synthesis.content",
    "tracks.synthesis.encrypted_content",
];
