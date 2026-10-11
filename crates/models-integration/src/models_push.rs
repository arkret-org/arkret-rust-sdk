use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;

use arkret_wire::{
    Audience, DeviceId, Did, DidCoreId, DidUrl, EventId, Hash, MessageId, OpaqueLocalId,
    PayloadProof, PushTargetId, RealmId, ReasonCode, Result as WireResult, SchemaId, StrandId,
    WireError, canonical, project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// Opaque service-generated routing token.
///
/// Counterpart for
/// `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_route_token`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PushRouteToken(String);

impl PushRouteToken {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if !(22..=512).contains(&value.len())
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
            })
        {
            return Err("push route token must match ^[A-Za-z0-9._~-]{22,512}$");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for PushRouteToken {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for PushRouteToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for PushRouteToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for PushRouteToken {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PushRouteToken> for String {
    fn from(value: PushRouteToken) -> Self {
        value.into_string()
    }
}

impl<'de> Deserialize<'de> for PushRouteToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Provider registration token bounded by the push operation contract.
///
/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_key`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PushKey(String);

impl PushKey {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if !(1..=4096).contains(&value.chars().count()) {
            return Err("push key must contain between 1 and 4096 Unicode code points");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for PushKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for PushKey {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for PushKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for PushKey {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PushKey> for String {
    fn from(value: PushKey) -> Self {
        value.into_string()
    }
}

impl<'de> Deserialize<'de> for PushKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Pairwise Station-generated registration identity used by the public
/// Station-to-Gateway handoff contract.
///
/// Unlike the more general deployment-local identifier, this wire type is
/// deliberately restricted to `^(?!ak:)[A-Za-z0-9._~-]{22,128}$`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PushRegistrationId(String);

impl PushRegistrationId {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if !(22..=128).contains(&value.len())
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
            })
        {
            return Err("push registration id must match ^(?!ak:)[A-Za-z0-9._~-]{22,128}$");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for PushRegistrationId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for PushRegistrationId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for PushRegistrationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for PushRegistrationId {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PushRegistrationId> for String {
    fn from(value: PushRegistrationId) -> Self {
        value.into_string()
    }
}

impl<'de> Deserialize<'de> for PushRegistrationId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegisterDeviceRequestBody {
    pub device_id: DeviceId,
    pub push_gateway_url: String,
    pub push_key: PushKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub visible_notification_opt_in: bool,
}

/// Authenticated registration persisted by a Station and read within its trusted
/// deployment boundary. This is storage state, never a notify wire envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationRecord {
    pub registration_id: OpaqueLocalId,
    pub account_id: arkret_wire::AccountId,
    pub device_id: DeviceId,
    pub push_gateway: String,
    pub push_key: PushKey,
    pub platform: Option<String>,
    pub app_id: Option<String>,
    pub visible_notification_opt_in: bool,
    pub push_route_id: String,
    pub push_target_id: PushTargetId,
    pub salt_epoch_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub retained_push_targets: Vec<RetainedPushTarget>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedPushTarget {
    pub push_target_id: PushTargetId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub retained_until: DateTime<Utc>,
}

impl PushRegistrationRecord {
    pub fn accepts_target(&self, target: &PushTargetId, at: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expires| at < expires)
            && (&self.push_target_id == target
                || self
                    .retained_push_targets
                    .iter()
                    .any(|old| &old.push_target_id == target && at < old.retained_until))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegisterDeviceOutcome {
    /// Server-derived pairwise pseudonym for this registration
    /// (`common-ids.schema.json#/$defs/push_target_id`); the caller and the
    /// device MUST use this exact value as the notify target and MUST NOT mint
    /// their own.
    pub push_target_id: PushTargetId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<OpaqueLocalId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushUnregisterDeviceRequestBody {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<PushKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PushUnregisterDeviceOutcome;

/// Closed desired state submitted by a Station to one trusted public Push
/// Gateway. Source and destination identities remain in the authenticated HTTP
/// signature and are intentionally absent from this body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PushRegistrationHandoffRequestBody {
    Active {
        registration_id: PushRegistrationId,
        push_target_id: PushTargetId,
        device_id: DeviceId,
        push_key: PushKey,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        platform: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        app_id: Option<String>,
        visible_notification_opt_in: bool,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
        )]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        supersedes_registration_id: Option<PushRegistrationId>,
    },
    Revoked {
        registration_id: PushRegistrationId,
        push_target_id: PushTargetId,
        device_id: DeviceId,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushRegistrationHandoffState {
    Active,
    Revoked,
}

impl PushRegistrationHandoffState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

impl PushRegistrationHandoffRequestBody {
    pub fn registration_id(&self) -> &PushRegistrationId {
        match self {
            Self::Active {
                registration_id, ..
            }
            | Self::Revoked {
                registration_id, ..
            } => registration_id,
        }
    }

    pub fn push_target_id(&self) -> &PushTargetId {
        match self {
            Self::Active { push_target_id, .. } | Self::Revoked { push_target_id, .. } => {
                push_target_id
            }
        }
    }

    pub fn device_id(&self) -> &DeviceId {
        match self {
            Self::Active { device_id, .. } | Self::Revoked { device_id, .. } => device_id,
        }
    }

    pub const fn state(&self) -> PushRegistrationHandoffState {
        match self {
            Self::Active { .. } => PushRegistrationHandoffState::Active,
            Self::Revoked { .. } => PushRegistrationHandoffState::Revoked,
        }
    }

    pub fn validate(&self) -> WireResult<()> {
        if let Self::Active {
            registration_id,
            platform,
            app_id,
            supersedes_registration_id,
            ..
        } = self
        {
            if platform.as_deref().is_some_and(str::is_empty) {
                return Err(WireError::Protocol(
                    "push handoff platform must not be empty".to_owned(),
                ));
            }
            if app_id
                .as_deref()
                .is_some_and(|value| value.is_empty() || value.starts_with("ak:"))
            {
                return Err(WireError::Protocol(
                    "push handoff app_id must be non-empty and outside the ak: namespace"
                        .to_owned(),
                ));
            }
            if supersedes_registration_id.as_ref() == Some(registration_id) {
                return Err(WireError::Protocol(
                    "push handoff cannot supersede the registration being installed".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn request_digest(&self) -> WireResult<Hash> {
        self.validate()?;
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }
}

/// Gateway-signed durable confirmation for an exact active installation or
/// terminal revocation tombstone.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationInstallationReceipt {
    pub registration_id: PushRegistrationId,
    pub push_target_id: PushTargetId,
    pub device_id: DeviceId,
    pub state: PushRegistrationHandoffState,
    pub request_digest: Hash,
    pub source_station_id: DidCoreId,
    pub destination_gateway_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub stored_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

impl PushRegistrationInstallationReceipt {
    pub fn expected_payload_digest(&self) -> WireResult<Hash> {
        let value = canonical::unsigned_value(self, &["proof"])?;
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }

    pub fn proof_binding_bytes(&self) -> WireResult<Vec<u8>> {
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": arkret_wire::ProofContextId::PUSH_REGISTRATION_INSTALLATION_RECEIPT_PROOF_V1,
            "payload_digest": self.proof.payload_digest,
            "registration_id": self.registration_id,
            "push_target_id": self.push_target_id,
            "device_id": self.device_id,
            "state": self.state,
            "request_digest": self.request_digest,
            "source_station_id": self.source_station_id,
            "destination_gateway_id": self.destination_gateway_id,
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
            "audience": self.proof.audience,
        }))
        .map_err(Into::into)
    }

    /// Validate every receipt/proof binding that does not require resolving the
    /// Gateway verification method or checking its detached JWS bytes.
    pub fn validate_proof_binding(&self) -> WireResult<()> {
        self.proof.validate_production()?;
        if self.proof.payload_digest != self.expected_payload_digest()? {
            return Err(WireError::Protocol(
                "push registration receipt payload digest mismatch".to_owned(),
            ));
        }
        if self.proof.created_at != self.stored_at
            || self.proof.domain.is_some()
            || self.proof.proof_purpose.is_some()
        {
            return Err(WireError::Protocol(
                "push registration receipt proof metadata mismatch".to_owned(),
            ));
        }
        let expected_audience = Audience::Single(self.source_station_id.as_str().to_owned());
        if self.proof.audience.as_ref() != Some(&expected_audience) {
            return Err(WireError::Protocol(
                "push registration receipt audience must equal source_station_id".to_owned(),
            ));
        }
        if proof_controller(&self.proof.verification_method).as_ref()
            != Some(&self.destination_gateway_id)
        {
            return Err(WireError::Protocol(
                "push registration receipt signer must be the destination Gateway".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_handoff(
        &self,
        request: &PushRegistrationHandoffRequestBody,
        source_station_id: &DidCoreId,
        destination_gateway_id: &DidCoreId,
    ) -> WireResult<()> {
        request.validate()?;
        self.validate_proof_binding()?;
        if self.registration_id != *request.registration_id()
            || self.push_target_id != *request.push_target_id()
            || self.device_id != *request.device_id()
            || self.state != request.state()
            || self.request_digest != request.request_digest()?
            || self.source_station_id != *source_station_id
            || self.destination_gateway_id != *destination_gateway_id
        {
            return Err(WireError::Protocol(
                "push registration receipt does not bind the exact handoff".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationHandoffOutcome {
    pub receipt: PushRegistrationInstallationReceipt,
}

fn proof_controller(method: &DidUrl) -> Option<DidCoreId> {
    method
        .as_str()
        .rsplit_once('#')
        .map(|(controller, _)| controller)
        .and_then(|controller| Did::new(controller.to_owned()).ok())
        .and_then(|controller| project_did_to_core_id(&controller).ok())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OkOutcome {
    pub ok: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<PushCountIndicator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread_increment: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missed_call: Option<PushCountIndicator>,
}

/// Privacy-preserving absolute-count indicator used by blind push payloads.
///
/// The wire value is either a boolean presence bit or a policy-declared bucket
/// label. Plain integer absolute counts are deliberately not representable.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum PushCountIndicator {
    Present(bool),
    Bucket(String),
}

impl<'de> Deserialize<'de> for PushCountIndicator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Bool(value) => Ok(Self::Present(value)),
            Value::String(value) if is_valid_push_count_bucket(&value) => Ok(Self::Bucket(value)),
            Value::String(_) => Err(serde::de::Error::custom("invalid push count bucket")),
            _ => Err(serde::de::Error::custom(
                "push count indicator must be a boolean or bucket string",
            )),
        }
    }
}

impl PushCountIndicator {
    #[must_use]
    pub fn is_present(&self) -> bool {
        match self {
            Self::Present(value) => *value,
            Self::Bucket(value) => value != "0",
        }
    }

    #[must_use]
    pub fn bucket(&self) -> Option<&str> {
        match self {
            Self::Present(_) => None,
            Self::Bucket(value) => Some(value),
        }
    }
}

fn is_valid_push_count_bucket(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    if value == "0" {
        return true;
    }
    let parse_positive = |digits: &str| {
        !digits.is_empty()
            && !digits.starts_with('0')
            && digits.bytes().all(|byte| byte.is_ascii_digit())
    };
    if let Some(lower) = value.strip_suffix('+') {
        return parse_positive(lower);
    }
    if let Some((lower, upper)) = value.split_once('-') {
        return parse_positive(lower)
            && parse_positive(upper)
            && matches!(
                (lower.parse::<u128>(), upper.parse::<u128>()),
                (Ok(lower), Ok(upper)) if lower < upper
            );
    }
    parse_positive(value)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushDeviceRoute {
    pub device_id: DeviceId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_route_token: Option<PushRouteToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_route_token: Option<PushRouteToken>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotificationEnvelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id: Option<PushTargetId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wakeup_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint_l10n_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_locus_unresolved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<PushCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_tokens: Option<PushRouteTokens>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<PushDeviceRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_actor_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_actor_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_is_target: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushAuditEnvelopeMetadata {
    pub access_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
}

/// Open, validated `reason_code` for a push-notify request.
///
/// The request-side vocabulary is deliberately not an enum: the push wire
/// contract accepts every value matching `^[a-z][a-z0-9_]{0,63}$`, including
/// values introduced by newer specifications such as `historical_only`.
/// Gateway outcome reason codes remain a separate closed enum because their
/// schema is closed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PushNotifyRequestReasonCode(String);

impl PushNotifyRequestReasonCode {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if !ReasonCode::is_valid_wire(&value) {
            return Err("push notify request reason_code must match ^[a-z][a-z0-9_]{0,63}$");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for PushNotifyRequestReasonCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl TryFrom<String> for PushNotifyRequestReasonCode {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PushNotifyRequestReasonCode> for String {
    fn from(value: PushNotifyRequestReasonCode) -> Self {
        value.into_string()
    }
}

impl Serialize for PushNotifyRequestReasonCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PushNotifyRequestReasonCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ToSchema for PushNotifyRequestReasonCode {
    fn to_schema(
        _components: &mut salvo_oapi::Components,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        salvo_oapi::schema::Object::new()
            .schema_type(salvo_oapi::schema::BasicType::String)
            .pattern("^[a-z][a-z0-9_]{0,63}$")
            .max_length(64)
            .into()
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ComposeSchema for PushNotifyRequestReasonCode {
    fn compose(
        components: &mut salvo_oapi::Components,
        generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        let _ = generics;
        <Self as salvo_oapi::ToSchema>::to_schema(components)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotifyRequestBody {
    pub notification: PushNotificationEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<PushNotifyRequestReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_envelope: Option<PushAuditEnvelopeMetadata>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotifyOutcome {
    pub push_target_id: PushTargetId,
    pub outcomes: Vec<PushNotifyDeviceOutcome>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_notify_device_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotifyDeviceOutcome {
    pub device_id: DeviceId,
    pub gateway_status: PushNotifyGatewayStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<PushNotifyReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl PushNotifyDeviceOutcome {
    pub fn accepted(device_id: DeviceId) -> Self {
        Self {
            device_id,
            gateway_status: PushNotifyGatewayStatus::Accepted,
            reason_code: None,
            retry_after_ms: None,
        }
    }

    pub fn duplicate(device_id: DeviceId) -> Self {
        Self {
            device_id,
            gateway_status: PushNotifyGatewayStatus::Duplicate,
            reason_code: None,
            retry_after_ms: None,
        }
    }

    pub fn rejected(
        device_id: DeviceId,
        reason_code: PushNotifyReasonCode,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self {
            device_id,
            gateway_status: PushNotifyGatewayStatus::Rejected,
            reason_code: Some(reason_code),
            retry_after_ms,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self.gateway_status {
            PushNotifyGatewayStatus::Accepted | PushNotifyGatewayStatus::Duplicate => {
                if self.reason_code.is_some() || self.retry_after_ms.is_some() {
                    return Err(
                        "accepted and duplicate push notify outcomes must not carry rejection fields"
                            .to_owned(),
                    );
                }
            }
            PushNotifyGatewayStatus::Rejected => {
                let Some(reason_code) = self.reason_code else {
                    return Err("rejected push notify outcomes require reason_code".to_owned());
                };
                if self.retry_after_ms == Some(0) {
                    return Err("retry_after_ms must be greater than zero".to_owned());
                }
                if self.retry_after_ms.is_some() && !reason_code.is_caller_retryable() {
                    return Err(
                        "retry_after_ms is only valid for caller-retryable push notify reasons"
                            .to_owned(),
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushNotifyGatewayStatus {
    Accepted,
    Duplicate,
    Rejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushNotifyReasonCode {
    PushTargetUnknown,
    PushPayloadTooLarge,
    UnsupportedProfile,
    PushTokenUnknown,
    PushTokenInvalid,
    PushGatewayUnreachable,
    RateLimited,
}

impl PushNotifyReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PushTargetUnknown => "push_target_unknown",
            Self::PushPayloadTooLarge => "push_payload_too_large",
            Self::UnsupportedProfile => "unsupported_profile",
            Self::PushTokenUnknown => "push_token_unknown",
            Self::PushTokenInvalid => "push_token_invalid",
            Self::PushGatewayUnreachable => "push_gateway_url_unreachable",
            Self::RateLimited => "rate_limited",
        }
    }

    pub const fn is_caller_retryable(self) -> bool {
        matches!(self, Self::PushGatewayUnreachable | Self::RateLimited)
    }
}

const FORBIDDEN_PLAINTEXT_PARENT_LEAF: &[(&str, &str)] = &[
    ("binding_proof", "signature"),
    ("subject_proof", "signature"),
];

pub const AGENT_LIFECYCLE_SILENT_KINDS: &[&str] = &[
    arkret_wire::event_kind_str::SELF_AGENT_PAUSE,
    arkret_wire::event_kind_str::SELF_AGENT_RESUME,
    arkret_wire::event_kind_str::SELF_AGENT_DEACTIVATE,
];

pub const AGENT_ACTOR_PRIVATE_KINDS: &[&str] = &[
    arkret_wire::event_kind_str::AGENT_DRAFT_PROPOSE,
    arkret_wire::event_kind_str::AGENT_ACTION_REQUEST,
    arkret_wire::event_kind_str::AGENT_ACTION_APPROVE,
    arkret_wire::event_kind_str::AGENT_ACTION_REJECT,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentEventRouting {
    DurableLifecycle,
    ActorPrivateDrop,
}

pub fn classify_agent_event_kind(event_kind: &str) -> Option<AgentEventRouting> {
    if AGENT_LIFECYCLE_SILENT_KINDS.contains(&event_kind) {
        return Some(AgentEventRouting::DurableLifecycle);
    }
    if AGENT_ACTOR_PRIVATE_KINDS.contains(&event_kind) {
        return Some(AgentEventRouting::ActorPrivateDrop);
    }
    None
}

pub fn validate_push_notify_contract_shape(request: &PushNotifyRequestBody) -> Result<(), String> {
    let raw = serde_json::to_value(request)
        .map_err(|error| format!("push notify request serialization failed: {error}"))?;
    reject_forbidden_plaintext_fields("", &raw)?;

    let notification = &request.notification;
    if notification.push_target_id.is_none() {
        return Err("notification.push_target_id is required".to_owned());
    }
    validate_wakeup_kind(notification.wakeup_kind.as_deref())?;

    if notification.devices.is_empty() {
        return Err("notification.devices must contain at least one device".to_owned());
    }
    let mut device_ids = HashSet::with_capacity(notification.devices.len());
    for device in &notification.devices {
        if !device_ids.insert(device.device_id.as_str()) {
            return Err(format!(
                "notification.devices contains duplicate device_id `{}`",
                device.device_id.as_str()
            ));
        }
    }

    Ok(())
}

fn reject_forbidden_plaintext_fields(path: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let leaf = key.to_ascii_lowercase();
                let next_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if let Some(parent_key) = path.rsplit('.').next() {
                    let parent_lower = parent_key.to_ascii_lowercase();
                    if FORBIDDEN_PLAINTEXT_PARENT_LEAF
                        .iter()
                        .any(|(parent, leaf_name)| {
                            parent.eq_ignore_ascii_case(&parent_lower)
                                && leaf_name.eq_ignore_ascii_case(&leaf)
                        })
                    {
                        return Err(format!(
                            "field `{next_path}` is forbidden on the push wire model"
                        ));
                    }
                }
                reject_forbidden_plaintext_fields(&next_path, nested)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                reject_forbidden_plaintext_fields(&format!("{path}[{index}]"), nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_wakeup_kind(value: Option<&str>) -> Result<(), String> {
    let Some(value) = value else {
        return Err("notification.wakeup_kind is required".to_owned());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("notification.wakeup_kind must not be empty".to_owned());
    }
    if !crate::push_vocab::is_valid_wakeup_kind(value) {
        return Err(format!(
            "notification.wakeup_kind must be one of {}",
            crate::push_vocab::ALLOWED_WAKEUP_KINDS.join(", ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn valid_request() -> PushNotifyRequestBody {
        PushNotifyRequestBody {
            notification: PushNotificationEnvelope {
                push_target_id: Some(
                    PushTargetId::new(
                        "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                    )
                    .unwrap(),
                ),
                wakeup_kind: Some("message".to_owned()),

                devices: vec![
                    PushDeviceRoute {
                        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
                            .unwrap(),
                    },
                    PushDeviceRoute {
                        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002")
                            .unwrap(),
                    },
                ],
                ..PushNotificationEnvelope::default()
            },
            event_kind: None,
            reason_code: None,
            audit_envelope: None,
        }
    }

    #[test]
    fn notify_device_routes_cannot_override_registration() {
        let valid = valid_request();
        assert!(validate_push_notify_contract_shape(&valid).is_ok());
        for (key, value) in [
            ("push_key", json!("token")),
            ("app_id", json!("app")),
            ("platform", json!("ios")),
            ("target_route_token", json!("opaque")),
            ("visible_notification_opt_in", json!(true)),
        ] {
            let mut raw = serde_json::to_value(&valid).unwrap();
            raw["notification"]["devices"][0][key] = value;
            assert!(
                serde_json::from_value::<PushNotifyRequestBody>(raw).is_err(),
                "{key}"
            );
        }
        let mut raw = serde_json::to_value(&valid).unwrap();
        raw["notification"]["timing_profile_hint"] = json!("default");
        assert!(serde_json::from_value::<PushNotifyRequestBody>(raw).is_err());
        let mut raw = serde_json::to_value(&valid).unwrap();
        raw["notification"]["route_tokens"] = json!({"mention_redirect_target_route_tokens": []});
        assert!(serde_json::from_value::<PushNotifyRequestBody>(raw).is_err());
    }

    #[test]
    fn push_notify_request_reason_code_is_open_and_wire_validated() {
        for code in ["historical_only", "future_reason_42"] {
            let parsed: PushNotifyRequestReasonCode =
                serde_json::from_value(json!(code)).expect("valid open request reason code");
            assert_eq!(parsed.as_str(), code);
            assert_eq!(serde_json::to_value(parsed).unwrap(), json!(code));
        }

        let max_length = format!("a{}", "_".repeat(63));
        assert!(PushNotifyRequestReasonCode::new(max_length).is_ok());

        for invalid in ["", "HistoricalOnly", "historical-only", "1historical_only"] {
            assert!(
                serde_json::from_value::<PushNotifyRequestReasonCode>(json!(invalid)).is_err(),
                "{invalid:?} must not be a legal reason_code"
            );
        }

        let mut request = valid_request();
        request.reason_code = Some(PushNotifyRequestReasonCode::new("historical_only").unwrap());
        assert_eq!(
            serde_json::to_value(request).unwrap()["reason_code"],
            "historical_only"
        );
    }

    #[test]
    fn classifies_agent_event_kinds() {
        assert_eq!(
            classify_agent_event_kind("ak.self.agent.pause"),
            Some(AgentEventRouting::DurableLifecycle)
        );
        assert_eq!(
            classify_agent_event_kind("ak.agent.action_request"),
            Some(AgentEventRouting::ActorPrivateDrop)
        );
        assert_eq!(classify_agent_event_kind("ak.message.create"), None);
    }

    #[test]
    fn validates_push_notify_shape() {
        let request = valid_request();
        validate_push_notify_contract_shape(&request).unwrap();
    }

    #[test]
    fn rejects_duplicate_push_notify_request_device_ids() {
        let mut request = valid_request();
        request.notification.devices[1].device_id =
            request.notification.devices[0].device_id.clone();

        let error = validate_push_notify_contract_shape(&request).unwrap_err();
        assert!(error.contains("duplicate device_id"));
    }

    #[test]
    fn push_notify_outcome_serializes_gateway_status_and_reason_code() {
        let request = valid_request();
        let outcome = PushNotifyOutcome {
            push_target_id: request.notification.push_target_id.clone().unwrap(),
            outcomes: vec![
                PushNotifyDeviceOutcome::accepted(
                    request.notification.devices[0].device_id.clone(),
                ),
                PushNotifyDeviceOutcome::rejected(
                    request.notification.devices[1].device_id.clone(),
                    PushNotifyReasonCode::RateLimited,
                    Some(500),
                ),
            ],
        };

        let encoded = serde_json::to_value(&outcome).unwrap();
        assert_eq!(encoded["outcomes"][0]["gateway_status"], "accepted");
        assert_eq!(encoded["outcomes"][1]["reason_code"], "rate_limited");
        assert!(encoded["outcomes"][0].get("reason_code").is_none());
    }

    #[test]
    fn rejects_invalid_push_notify_device_outcome_fields() {
        let device_id = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap();
        let accepted_with_reason = PushNotifyDeviceOutcome {
            device_id: device_id.clone(),
            gateway_status: PushNotifyGatewayStatus::Accepted,
            reason_code: Some(PushNotifyReasonCode::PushTokenInvalid),
            retry_after_ms: None,
        };
        assert!(accepted_with_reason.validate().is_err());

        let rejected_without_reason = PushNotifyDeviceOutcome {
            device_id: device_id.clone(),
            gateway_status: PushNotifyGatewayStatus::Rejected,
            reason_code: None,
            retry_after_ms: None,
        };
        assert!(rejected_without_reason.validate().is_err());

        let non_retryable_backoff = PushNotifyDeviceOutcome::rejected(
            device_id,
            PushNotifyReasonCode::PushTokenInvalid,
            Some(500),
        );
        assert!(non_retryable_backoff.validate().is_err());
    }

    #[test]
    fn push_count_indicators_reject_absolute_counts_and_invalid_buckets() {
        for invalid in [
            json!(1),
            json!(-1),
            json!("01"),
            json!("5-2"),
            json!("1--2"),
        ] {
            assert!(serde_json::from_value::<PushCountIndicator>(invalid).is_err());
        }
        assert_eq!(
            serde_json::from_value::<PushCountIndicator>(json!(true)).unwrap(),
            PushCountIndicator::Present(true)
        );
        assert_eq!(
            serde_json::from_value::<PushCountIndicator>(json!("6-20")).unwrap(),
            PushCountIndicator::Bucket("6-20".to_owned())
        );
    }

    #[test]
    fn push_route_token_enforces_the_exact_schema_lexical_space() {
        for valid in ["a".repeat(22), "A0._~-".repeat(85) + "ab"] {
            let token = PushRouteToken::new(valid.clone()).unwrap();
            assert_eq!(token.as_str(), valid);
            assert_eq!(serde_json::to_value(&token).unwrap(), json!(valid));
        }

        for invalid in [
            "a".repeat(21),
            "a".repeat(513),
            format!("{}:", "a".repeat(21)),
            format!("{} ", "a".repeat(21)),
        ] {
            assert!(PushRouteToken::new(invalid.clone()).is_err());
            assert!(serde_json::from_value::<PushRouteToken>(json!(invalid)).is_err());
        }
    }

    #[test]
    fn push_key_enforces_schema_length_in_unicode_code_points() {
        for valid in ["令".to_owned(), "x".repeat(4096)] {
            let key = PushKey::new(valid.clone()).unwrap();
            assert_eq!(key.as_str(), valid);
            assert_eq!(serde_json::to_value(&key).unwrap(), json!(valid));
        }

        for invalid in [String::new(), "密".repeat(4097)] {
            assert!(PushKey::new(invalid.clone()).is_err());
            assert!(serde_json::from_value::<PushKey>(json!(invalid)).is_err());
        }
    }

    #[test]
    fn push_registration_id_enforces_the_closed_handoff_lexical_space() {
        for valid in ["r".repeat(22), "A0._~-".repeat(21) + "ab"] {
            let registration_id = PushRegistrationId::new(valid.clone()).unwrap();
            assert_eq!(registration_id.as_str(), valid);
            assert_eq!(
                serde_json::to_value(&registration_id).unwrap(),
                json!(valid)
            );
        }

        for invalid in [
            "r".repeat(21),
            "r".repeat(129),
            "ak:registration:not-opaque".to_owned(),
            format!("{}:", "r".repeat(21)),
        ] {
            assert!(PushRegistrationId::new(invalid.clone()).is_err());
            assert!(serde_json::from_value::<PushRegistrationId>(json!(invalid)).is_err());
        }
    }

    fn active_handoff() -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "apns",
            "visible_notification_opt_in": false
        }))
        .unwrap()
    }

    #[test]
    fn handoff_request_is_a_closed_active_or_revoked_union() {
        let active = active_handoff();
        active.validate().unwrap();
        assert_eq!(active.state(), PushRegistrationHandoffState::Active);
        assert_eq!(active.request_digest().unwrap().as_str().len(), 71);

        let revoked: PushRegistrationHandoffRequestBody = serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "revoked"
        }))
        .unwrap();
        revoked.validate().unwrap();
        assert_eq!(revoked.state(), PushRegistrationHandoffState::Revoked);

        let surplus = json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "revoked",
            "push_key": "must-not-survive-a-tombstone"
        });
        assert!(serde_json::from_value::<PushRegistrationHandoffRequestBody>(surplus).is_err());

        let reserved_app_id: PushRegistrationHandoffRequestBody = serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "app_id": "ak:not-an-external-app-id",
            "visible_notification_opt_in": false
        }))
        .unwrap();
        assert!(reserved_app_id.validate().is_err());
    }

    #[test]
    fn installation_receipt_binds_exact_handoff_and_gateway_signer() {
        let request = active_handoff();
        let source_station_id =
            project_did_to_core_id(&Did::new("did:web:source.example").unwrap()).unwrap();
        let destination_gateway_id =
            project_did_to_core_id(&Did::new("did:web:gateway.example").unwrap()).unwrap();
        let stored_at = DateTime::parse_from_rfc3339("2026-09-20T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut receipt = PushRegistrationInstallationReceipt {
            registration_id: request.registration_id().clone(),
            push_target_id: request.push_target_id().clone(),
            device_id: request.device_id().clone(),
            state: request.state(),
            request_digest: request.request_digest().unwrap(),
            source_station_id: source_station_id.clone(),
            destination_gateway_id: destination_gateway_id.clone(),
            stored_at,
            proof: PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new("did:web:gateway.example#key-1").unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: stored_at,
                domain: None,
                audience: Some(Audience::Single(source_station_id.as_str().to_owned())),
                proof_purpose: None,
                jws: "a..b".to_owned(),
            },
        };
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        receipt
            .validate_for_handoff(&request, &source_station_id, &destination_gateway_id)
            .unwrap();

        let transcript: Value =
            serde_json::from_slice(&receipt.proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(
            transcript["context"],
            arkret_wire::ProofContextId::PUSH_REGISTRATION_INSTALLATION_RECEIPT_PROOF_V1
        );
        assert_eq!(transcript["audience"], source_station_id.as_str());

        receipt.proof.audience = Some(Audience::Single("did:web:other.example".to_owned()));
        assert!(receipt.validate_proof_binding().is_err());
    }
}

// ── Push schema artifact counterparts ────────────────────────────────────
// The `arkret` umbrella re-exports these owner-defined shapes at its root.

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum PushOperations {
    PushRegisterDeviceRequestBody(PushRegisterDeviceRequestBody),
    PushRegisterDeviceOutcome(PushRegisterDeviceOutcome),
    PushUnregisterDeviceRequestBody(PushUnregisterDeviceRequestBody),
    PushRegistrationHandoffRequestBody(PushRegistrationHandoffRequestBody),
    PushRegistrationHandoffOutcome(PushRegistrationHandoffOutcome),
    PushNotifyRequestBody(PushNotifyRequestBody),
    PushNotifyOutcome(PushNotifyOutcome),
}

impl PushOperations {
    pub const SCHEMA: &'static str = SchemaId::PUSH_OPERATIONS_V1;
}
