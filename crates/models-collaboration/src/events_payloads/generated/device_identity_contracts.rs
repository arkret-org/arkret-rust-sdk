// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=36cd224e905e42c33740bf6c3c3d893497e38b5305cadc8d0fb51c1cfdba9c0d
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Bindings: tools/closed-model-bindings.json
// sha256=b381c96b67ab466bbb82afb539a5bf9f04c5809ca15139346195d6a0eed4e539

/// Counterpart: `event-payload.schema.json#/$defs/device_revoke_payload`.
/// Counterpart for
/// `event-payload.schema.json#/$defs/device_revoke_payload`.
///
/// The revoked subject account is derived exclusively from the Event envelope
/// `actor_id`, so the payload carries no `principal_id` mirror. It likewise
/// carries no checkpoint, generation or pending-selector member: the permanent
/// cutoff is the accepted `RealmCommit` covering this Event, and the
/// `revocation_pending` record for the reducer-derived authorization and
/// generation is created by first durable acceptance, never self-reported by
/// the producer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokePayload {
    pub device_id: DeviceId,
    pub revoked_by: DeviceOrPrincipalRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    pub reason: DeviceRevocationReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub proof: Option<SignatureMaterial>,
}
