// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=30f8a7bac2a387091f550a02d6f44c69afc5fde62df0cd0be521f28a963726c0
//
// Input: schemas/account-operations.schema.json
// sha256=694f553340eeccd86deab4c0bb637d741e62e4babab325d516ffa30352ceb03d
//
// Bindings: tools/closed-model-bindings.json
// sha256=3bfe22afd0deee9b00a0fd4b2c1e2c7eee318ee6752681d944e4cc4b38492100

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

/// Counterpart: `event-payload.schema.json#/$defs/applet_managed_device_scope`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedDeviceScope {
    pub effective_scope: ScopeRef,
    pub actions: Vec<CapabilityActionId>,
}
