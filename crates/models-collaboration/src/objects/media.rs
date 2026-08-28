//! ICE configuration and call media token wire shapes.

use arkret_wire::{CallId, DeviceId, DidCoreId, DidUrl, GrantId, RealmId, XExtensionMap};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Domain separator for the canonical ICE configuration signature transcript.
pub const MEDIA_ICE_CONFIG_SIGNING_LABEL: &str = "ak.media.ice_config.v1";
pub const MEDIA_ICE_BUCKET_SECONDS: i64 = 300;

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
    pub actor_id: DidCoreId,
    pub device_id: DeviceId,
    pub mode: MediaIceMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MediaIceConfigOutcome {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: DidCoreId,
    pub device_id: DeviceId,
    pub ice_servers: Vec<MediaIceServer>,
    pub ttl_seconds: u32,
    pub refresh_lead_seconds: u32,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub turn_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<MediaIceConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub next_retry_at: Option<DateTime<Utc>>,
    pub signature: MediaIceConfigSignature,
    #[serde(default, flatten)]
    pub extensions: XExtensionMap,
}

impl MediaIceConfigOutcome {
    pub const fn bucket_seconds(&self) -> i64 {
        MEDIA_ICE_BUCKET_SECONDS
    }

    pub fn expires_at(&self) -> arkret_wire::Result<DateTime<Utc>> {
        self.issued_at
            .checked_add_signed(chrono::Duration::seconds(i64::from(self.ttl_seconds)))
            .ok_or_else(|| {
                arkret_wire::WireError::Protocol("ICE configuration expiry overflows".to_owned())
            })
    }

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
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MediaIceConfigSignature {
    pub kid: String,
    pub signature_algorithm: MediaIceSignatureAlgorithm,
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
    pub actor_id: DidCoreId,
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
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub focus_id: String,
    pub actor_id: DidCoreId,
    pub device_id: DeviceId,
    pub participant_identity: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub issuer_kid: DidUrl,
    pub sig: String,
}

/// Closed media backend registry used by both focus selection and token exchange.
///
/// Mirrors the wire enum `ak.realm.media_service.foci[].type`. The registry is
/// closed, so successful deserialization *is* the known-backend check: an
/// unrecognized label fails to deserialize rather than surviving as a
/// catch-all variant, and receivers MUST fail closed with
/// [`ReasonCode::UNKNOWN_FOCUS_TYPE`](arkret_wire::ReasonCode::UNKNOWN_FOCUS_TYPE).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MediaBackendKind {
    Livekit,
    Mediasoup,
    Janus,
    ArkretNative,
    MoqRelay,
}

/// Media permissions carried by an Arkret-native backend token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ArkretNativeMediaPermissions {
    pub audio: bool,
    pub video: bool,
    pub screen: bool,
}

/// Signed Arkret-native token payload. Other backend bindings deliberately keep
/// their token string opaque to the Arkret protocol layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ArkretNativeMediaTokenPayload {
    pub call_id: CallId,
    pub focus_id: String,
    pub participant_identity: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub media: ArkretNativeMediaPermissions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ArkretNativeMediaSignatureAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

/// Closed object token used only by the `arkret_native` backend binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ArkretNativeMediaBackendToken {
    pub kid: DidUrl,
    pub payload: ArkretNativeMediaTokenPayload,
    pub sig: String,
    pub signature_algorithm: ArkretNativeMediaSignatureAlgorithm,
}

/// Wire token shape. The containing outcome validates this structural branch
/// against its sibling `backend_kind`; no JSON-string wrapper or open `Value`
/// fallback exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MediaBackendToken {
    ArkretNative(ArkretNativeMediaBackendToken),
    Opaque(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallMediaTokenExchangeOutcomeWire {
    focus_id: String,
    connect_uri: String,
    backend_token: MediaBackendToken,
    participant_identity: String,
    participant_binding: CallMediaParticipantBinding,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
    backend_kind: MediaBackendKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CallMediaTokenExchangeOutcomeWire")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CallMediaTokenExchangeOutcome {
    pub focus_id: String,
    pub connect_uri: String,
    pub backend_token: MediaBackendToken,
    pub participant_identity: String,
    pub participant_binding: CallMediaParticipantBinding,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub backend_kind: MediaBackendKind,
}

impl TryFrom<CallMediaTokenExchangeOutcomeWire> for CallMediaTokenExchangeOutcome {
    type Error = &'static str;

    fn try_from(value: CallMediaTokenExchangeOutcomeWire) -> Result<Self, Self::Error> {
        match (&value.backend_kind, &value.backend_token) {
            (MediaBackendKind::ArkretNative, MediaBackendToken::ArkretNative(_)) => {}
            (MediaBackendKind::ArkretNative, MediaBackendToken::Opaque(_)) => {
                return Err("arkret_native backend_token must be the typed object branch");
            }
            (_, MediaBackendToken::ArkretNative(_)) => {
                return Err("non-arkret-native backend_token must be an opaque string");
            }
            (_, MediaBackendToken::Opaque(token)) if token.trim().is_empty() => {
                return Err("opaque backend_token must not be empty");
            }
            (_, MediaBackendToken::Opaque(_)) => {}
        }
        Ok(Self {
            focus_id: value.focus_id,
            connect_uri: value.connect_uri,
            backend_token: value.backend_token,
            participant_identity: value.participant_identity,
            participant_binding: value.participant_binding,
            expires_at: value.expires_at,
            backend_kind: value.backend_kind,
        })
    }
}
