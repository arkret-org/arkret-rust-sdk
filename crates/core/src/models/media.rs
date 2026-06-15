use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MediaIceMode {
    P2p,
    Sfu,
    Turn,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MediaIceConfigRequestBody {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub mode: MediaIceMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MediaIceConfigOutcome {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    #[serde(default)]
    pub ice_servers: Vec<Value>,
    pub ttl_seconds: u32,
    pub refresh_lead_seconds: u32,
    pub issued_at: DateTime<Utc>,
    pub issued_at_bucket: DateTime<Utc>,
    pub bucket_seconds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub force_turn: bool,
    pub signature: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallMediaDesiredMedia {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub video: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallMediaTokenExchangeRequestBody {
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub focus_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_refs: Vec<GrantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_media: Option<CallMediaDesiredMedia>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallMediaParticipantBinding {
    pub scheme: String,
    pub sig: String,
    pub issuer_kid: String,
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub focus_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub participant_identity: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl CallMediaParticipantBinding {
    pub const SCHEME: &'static str = PARTICIPANT_BINDING_SCHEMA;
}

/// Detached service signature over the token-exchange response, carried as a
/// typed `{kid, sig}` object (`media-service-binding.md` §3). The `kid` MUST
/// resolve to a realm media-service anchor; `sig` is the backend-specific
/// detached signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallMediaServiceSignature {
    pub kid: String,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallMediaTokenExchangeOutcome {
    pub focus_id: String,
    #[serde(rename = "type")]
    pub backend_type: String,
    pub connect_url: String,
    pub backend_token: String,
    pub participant_identity: String,
    pub participant_binding: CallMediaParticipantBinding,
    pub expires_at: DateTime<Utc>,
    pub service_signature: CallMediaServiceSignature,
}
