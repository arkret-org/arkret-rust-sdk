use super::*;

/// Structured `@mention` node embedded in message body.
///
/// Spec source: `models/flow-and-message.md §9.4` + `identity/identity-handles.md §3.8.1`
/// (contrix-spec @ b56cab1, 2026-05-28).
///
/// R3.2 wire-breaking change: the authoritative reference field is
/// `subject_id` (principal DID). The handle / display strings are now
/// **audit metadata only** (`handle_at_time` / `display_name_at_time` /
/// `mention_text_original`) and MUST NOT be used as the current display
/// value or for actor attribution — verifier / reducer / policy engine
/// MUST ignore them and read `subject_id` exclusively.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Mention {
    /// Principal DID of the mentioned subject. The ONLY field that
    /// participates in actor attribution, authorization, resolution and
    /// render lookup.
    pub subject_id: Did,
    /// Snapshot of the canonical `<localpart>:<domain>` handle at compose
    /// time. Audit / search / fallback metadata only; MUST NOT be used as
    /// the current display handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_at_time: Option<Handle>,
    /// Snapshot of the subject's display name at compose time. Persistent
    /// snapshot semantics (anti-impersonation guard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_at_time: Option<String>,
    /// Original string the user typed (e.g. `@alice:acme.com`). Audit /
    /// search-index use only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention_text_original: Option<String>,
    /// When the handle was resolved. Audit metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
}

impl Mention {
    /// Construct a mention from its authoritative `subject_id`. Audit
    /// metadata is attached via the builder setters.
    pub fn new(subject_id: Did) -> Self {
        Self {
            subject_id,
            handle_at_time: None,
            display_name_at_time: None,
            mention_text_original: None,
            resolved_at: None,
        }
    }

    pub fn with_handle_at_time(mut self, handle: Handle) -> Self {
        self.handle_at_time = Some(handle);
        self
    }

    pub fn with_display_name_at_time(mut self, name: impl Into<String>) -> Self {
        self.display_name_at_time = Some(name.into());
        self
    }

    pub fn with_mention_text_original(mut self, text: impl Into<String>) -> Self {
        self.mention_text_original = Some(text.into());
        self
    }

    pub fn with_resolved_at(mut self, at: DateTime<Utc>) -> Self {
        self.resolved_at = Some(at);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mention_minimal_shape_round_trips() {
        let m = Mention::new(Did::new("did:web:alice.example".to_owned()).unwrap());
        let json = serde_json::to_value(&m).unwrap();
        assert!(json.get("subject_id").is_some());
        // Audit metadata omitted when unset.
        assert!(json.get("handle_at_time").is_none());
        assert!(json.get("display_name_at_time").is_none());
        let decoded: Mention = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn mention_rejects_legacy_fields() {
        // The pre-R3.2 shape used `subject` / `handle` / `display_snapshot`.
        let raw = serde_json::json!({
            "subject": "did:web:alice.example",
            "handle": "alice:acme.example",
            "display_snapshot": "@alice:acme.example",
            "resolved_at": "2026-05-19T10:00:00Z"
        });
        let parsed: std::result::Result<Mention, _> = serde_json::from_value(raw);
        assert!(parsed.is_err(), "legacy mention shape must be rejected");
    }
}
