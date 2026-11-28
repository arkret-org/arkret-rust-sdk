// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-operations.schema.json
// sha256=694f553340eeccd86deab4c0bb637d741e62e4babab325d516ffa30352ceb03d
//
// Input: schemas/string-profiles.schema.json
// sha256=7c7522a769204b050b9711b53c1b911bc660645962ed6c0243f95fae72473f78
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=90e21e77dae771f2c5ed933d3a57a684de6d47d3e4b73f568536e81a8e4fb8b9

/// Counterpart: `account-operations.schema.json#/$defs/device_summary`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/device_summary`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSummary {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub display_name: Option<String>,
    pub status: DeviceSummaryStatus,
    pub verification_state: DeviceSummaryVerificationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub verification_source: Option<DeviceSummaryVerificationSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub authorized_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub revocation_states: Option<Vec<AccountDeviceRevocationGateRecord>>,
}
