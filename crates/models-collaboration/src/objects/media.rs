//! ICE configuration and call media token wire shapes.

use arkret_wire::constants::PARTICIPANT_BINDING_SCHEMA;
use arkret_wire::{CallId, DeviceId, Did, DidUrl, GrantId, Hash, RealmId, XExtensionMap};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Domain separator for the canonical ICE configuration signature transcript.
pub const MEDIA_ICE_CONFIG_SIGNING_LABEL: &str = "ak.media.ice_config.v1";

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MediaIceMode {
    P2p,
    Sfu,
    Turn,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MediaIceConfigRequestBody {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub mode: MediaIceMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MediaIceConfigOutcome {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub ice_servers: Vec<MediaIceServer>,
    pub ttl_seconds: u32,
    pub refresh_lead_seconds: u32,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at_bucket: DateTime<Utc>,
    pub bucket_seconds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub turn_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<MediaIceConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub next_retry_at: Option<DateTime<Utc>>,
    pub signature: MediaIceConfigSignature,
    #[serde(default, flatten)]
    pub extensions: XExtensionMap,
}

impl MediaIceConfigOutcome {
    /// Canonicalize the signed response payload after removing the detached
    /// signature container. Timestamp spelling is enforced by this model's
    /// canonical serializers before JCS encoding.
    pub fn canonical_signature_payload(&self) -> arkret_canonical::Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().ok_or_else(|| {
            arkret_canonical::CanonicalError::Protocol(
                "ICE configuration must serialize as an object".to_owned(),
            )
        })?;
        object.remove("signature");
        arkret_canonical::canonical_json_bytes(&value)
    }

    /// Build the single protocol-defined signature transcript.
    pub fn signature_input(&self) -> arkret_canonical::Result<Vec<u8>> {
        let payload = self.canonical_signature_payload()?;
        let mut input =
            Vec::with_capacity(MEDIA_ICE_CONFIG_SIGNING_LABEL.len() + payload.len() + 1);
        input.extend_from_slice(MEDIA_ICE_CONFIG_SIGNING_LABEL.as_bytes());
        input.push(0x00);
        input.extend_from_slice(&payload);
        Ok(input)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MediaIceCredentialType {
    Password,
    OAuth,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MediaIceConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_allowed: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MediaIceSignatureAlgorithm {
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MediaIceSignatureInput {
    #[serde(rename = "ak.media.ice_config.v1")]
    IceConfigV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CallMediaDesiredMedia {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub video: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CallMediaParticipantBinding {
    pub scheme: String,
    pub sig: String,
    pub issuer_kid: DidUrl,
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub focus_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub participant_identity: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CallMediaServiceSignature {
    pub kid: DidUrl,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CallMediaTokenExchangeOutcome {
    pub focus_id: String,
    pub backend_kind: String,
    pub connect_url: String,
    pub backend_token: String,
    pub participant_identity: String,
    pub participant_binding: CallMediaParticipantBinding,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    pub service_signature: CallMediaServiceSignature,
}
