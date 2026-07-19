//! ICE configuration and call media token wire shapes.

use arkret_wire::constants::PARTICIPANT_BINDING_SCHEMA;
use arkret_wire::{CallId, DeviceId, Did, GrantId, Hash, RealmId, XExtensionMap};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MediaIceMode {
    P2p,
    Sfu,
    Turn,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MediaIceConfigRequestBody {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub mode: MediaIceMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MediaIceConfigOutcome {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub ice_servers: Vec<MediaIceServer>,
    pub ttl_seconds: u32,
    pub refresh_lead_seconds: u32,
    pub issued_at: DateTime<Utc>,
    pub issued_at_bucket: DateTime<Utc>,
    pub bucket_seconds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub force_turn: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<MediaIceConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
    pub signature: MediaIceConfigSignature,
    #[serde(default, flatten)]
    pub extensions: XExtensionMap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum MediaIceCredentialType {
    Password,
    OAuth,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MediaIceServer {
    #[serde(
        deserialize_with = "deserialize_ice_server_urls",
        serialize_with = "serialize_ice_server_urls"
    )]
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<MediaIceCredentialType>,
}

impl MediaIceServer {
    pub fn is_turn(&self) -> bool {
        self.urls
            .iter()
            .any(|url| url.starts_with("turn:") || url.starts_with("turns:"))
    }

    pub fn is_stun(&self) -> bool {
        !self.is_turn()
            && self
                .urls
                .iter()
                .any(|url| url.starts_with("stun:") || url.starts_with("stuns:"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MediaIceConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_udp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_tcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_ipv6: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub enum MediaIceSignatureAlgorithm {
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub enum MediaIceSignatureInput {
    #[serde(rename = "ak.media.ice_config.v1")]
    IceConfigV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MediaIceConfigSignature {
    pub kid: String,
    pub alg: MediaIceSignatureAlgorithm,
    pub signature_input: MediaIceSignatureInput,
    pub payload_digest: Hash,
    pub sig: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MediaIceServerUrls {
    One(String),
    Many(Vec<String>),
}

fn deserialize_ice_server_urls<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match MediaIceServerUrls::deserialize(deserializer)? {
        MediaIceServerUrls::One(url) => Ok(vec![url]),
        MediaIceServerUrls::Many(urls) if !urls.is_empty() => Ok(urls),
        MediaIceServerUrls::Many(_) => Err(serde::de::Error::custom(
            "ice server urls must not be empty",
        )),
    }
}

fn serialize_ice_server_urls<S>(urls: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    urls.serialize(serializer)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct CallMediaDesiredMedia {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub video: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct CallMediaServiceSignature {
    pub kid: String,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
