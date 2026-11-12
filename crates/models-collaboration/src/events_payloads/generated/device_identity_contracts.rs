// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e57f2773764165f5a2e6047ae5491cdf152476deb73c83b2f6c14fff58925305
//
// Input: schemas/account-operations.schema.json
// sha256=0ae0fec5fd63dca4b9df9293eb71936cf73a3eeeae13b2268dc99699c1ed7607
//
// Bindings: tools/closed-model-bindings.json
// sha256=2db9dc0b757e082d561722a2301e943a7422e79691dd5632a5a2ec129045cc3f

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
