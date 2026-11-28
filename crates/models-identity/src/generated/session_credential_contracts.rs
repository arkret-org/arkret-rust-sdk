// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=c024ba46dd3ec67e5118371121cba60e7c0d684a051e37378bebcda318274c07
//
// Input: schemas/grant-constraint.schema.json
// sha256=07f2984156af2b412eaea2816cc46e73d8b27af4311ee5718c03f899ac31fc6f
//
// Input: schemas/common-ids.schema.json
// sha256=dadc47194ca411baa38f3a7f44ae8115bec7cbcd98e68a2fffd389fdfc039713
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

/// Counterpart: `service-operation-dtos.schema.json#/$defs/SessionGrantDeviceBinding`.
/// Authorization state committed into a standard human-device grant.
///
/// The Account Authority populates it from a Station-local revocation
/// admission record, which is the only source of the origin-derived
/// authorization Event and generation. That record deliberately carries no
/// RealmCommit witness, so this binding names the authorization Event alone —
/// it is not a `CommittedEventRef` and MUST NOT be taken from client input, a
/// local cache or a private lookup.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantDeviceBinding {
    pub device_id: DeviceId,
    pub authorization_event_id: EventId,
    pub model_generation_ref: u64,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/SessionGrantScope/properties/resources`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantScopeResources {
    pub realm_ids: Vec<arkret_wire::RealmId>,
    pub strand_ids: Vec<arkret_wire::StrandId>,
}

/// Counterpart:
/// `service-operation-dtos.schema.json#/$defs/SessionGrantScope/properties/constraints`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantScopeConstraints {
    pub allowed_tracks: Vec<String>,
    pub allowed_data_labels: Vec<String>,
    pub allowed_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub allowed_strand_ids: Option<Vec<arkret_wire::StrandId>>,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/SessionGrantScope`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantScope {
    pub controller_principal_id: DidCoreId,
    pub agent_key_authorization_ref: EventId,
    pub realm_ids: Vec<arkret_wire::RealmId>,
    pub strand_ids: Vec<arkret_wire::StrandId>,
    pub resources: SessionGrantScopeResources,
    pub constraints: SessionGrantScopeConstraints,
    pub capability_grant_refs: Vec<String>,
    pub policy_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub participations: Option<Vec<crate::agent_participation::AgentParticipationView>>,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/SessionGrantResponseBody`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantResponseBody {
    pub account_id: AccountId,
    pub issuer_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub device_id: Option<DeviceId>,
    pub session_grant: arkret_wire::SessionGrantSecret,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub session_grant_id: SessionGrantId,
    pub session_public_key: CanonicalSessionPublicJwk,
    pub audience_id: DidCoreId,
    pub granted_scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub previous_session_grant_id: Option<SessionGrantId>,
}
