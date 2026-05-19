use super::*;

/// Structured `@mention` node embedded in message body.
///
/// Spec source: `models/flow-and-message.md §9.4` (commit 0a5ab85,
/// 2026-05-19) — `subject` is the protocol-level DID, `handle_uri` is
/// the canonical handle URI at compose time, `display_snapshot` is the
/// human label captured at compose time (so subsequent handle
/// reassignment doesn't silently rewrite historic mentions), and
/// `resolved_at` records when the handle was last resolved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Mention {
    pub subject: Did,
    pub handle_uri: HandleUri,
    pub display_snapshot: String,
    pub resolved_at: DateTime<Utc>,
}

impl Mention {
    pub fn new(
        subject: Did,
        handle_uri: HandleUri,
        display_snapshot: impl Into<String>,
        resolved_at: DateTime<Utc>,
    ) -> Self {
        Self { subject, handle_uri, display_snapshot: display_snapshot.into(), resolved_at }
    }
}
