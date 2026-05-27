use super::*;

/// Structured `@mention` node embedded in message body.
///
/// Spec source: `models/flow-and-message.md §9.4` (contrix-spec @ 7157ee8,
/// 2026-05-27) — `subject` is the protocol-level DID, `handle` is the
/// canonical `<localpart>:<domain>` handle at compose time,
/// `display_snapshot` is the human label captured at compose time (so
/// subsequent handle reassignment doesn't silently rewrite historic
/// mentions), and `resolved_at` records when the handle was last resolved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Mention {
    pub subject: Did,
    /// Canonical `<localpart>:<domain>` handle (R3.1 wire rename from
    /// the prior `handle_uri` field name).
    pub handle: Handle,
    pub display_snapshot: String,
    pub resolved_at: DateTime<Utc>,
}

impl Mention {
    pub fn new(
        subject: Did,
        handle: Handle,
        display_snapshot: impl Into<String>,
        resolved_at: DateTime<Utc>,
    ) -> Self {
        Self { subject, handle, display_snapshot: display_snapshot.into(), resolved_at }
    }
}
