//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/redactable-field-registry.json; version=2026-09-16.6;
//! sha256=dd2f7bf79edb18556fd41cd6c5bf278d93a17665b074f79ef94c4a941c951b9d
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
