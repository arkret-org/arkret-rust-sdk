// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=b42ab7eb500df851ff7e7c4ad9383751d8e8dd62ccae338246d81a59bf646259
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Bindings: tools/closed-model-bindings.json
// sha256=6fcfadb0c7e06a31e4528be5ebd9b087cda5b2394c144df9292de9b946c7d7a8

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
