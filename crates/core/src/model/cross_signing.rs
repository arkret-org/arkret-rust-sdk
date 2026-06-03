//! Cross-signing reset payloads and helpers.

use super::*;
/// Round R2/R3 (2026-05-20) — typed payload for `ck.cross_signing.reset`.
///
/// Wire-breaking: `trust_domain` and `reset_event_id` are now required.
/// `trust_domain` enters every proof's canonical transcript so the same
/// proof bytes cannot be replayed from deployment A into deployment B.
/// `reset_event_id` MUST equal the enclosing `Event.event_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CrossSigningResetPayload {
    pub trust_domain: TypedTrustDomainId,

    pub reset_event_id: EventId,

    pub principal_id: Did,

    pub previous_generation: u64,

    pub new_generation: u64,

    pub reset_reason: String,
    /// One of `principal_signing` / `recovery_unlock` / `device_quorum` /
    /// `trusted_recovery_service`. Validated in the proof verification
    /// path (see zh/crypto-media/device-lifecycle.md §14.4).
    pub proof: Value,

    pub issued_at: DateTime<Utc>,
}

impl CrossSigningResetPayload {
    pub const SCHEMA: &'static str = "ck.schema.cross_signing_reset.v1";
}
