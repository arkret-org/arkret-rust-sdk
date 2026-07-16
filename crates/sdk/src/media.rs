//! Media, blob and attachment helpers.

use std::collections::BTreeMap;

use arkret_canonical::base64url::base64url_decode;
use arkret_canonical::canonical::canonical_json_bytes;
use arkret_core::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
};
#[cfg(feature = "client")]
use arkret_core::{MediaIceConfigOutcome, MediaIceConfigRequestBody};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::canonical::sha256_hex;
use crate::{AEAD_ALGORITHM, BlobRef, CallId, DeviceId, Did, Error, RealmId, Result, crypto};

/// Fixed ASCII domain-separation label that prefixes the participant-binding
/// signing input (`media-service-binding.md` §3). Equals the v1 binding
/// `scheme` byte-for-byte; a single `0x00` separates it from the canonical
/// JSON of the seven authoritative fields.
pub const PARTICIPANT_BINDING_LABEL: &str = "ak.media.participant_binding.v1";

/// Derivation profile for the SDK's deterministic local thumbnail preview.
pub const THUMBNAIL_DERIVATION_PROFILE: &str = "ak.profile.media.thumbnail_preview.v1";

// ─── AKP-0010 (R3 spec-sync 2026-05-27) — media token exchange ────────────

/// Backend type for a call's media focus. Wire enum mirrors
/// `ak.realm.media_service.foci[].type`. Receivers MUST fail closed with
/// [`unknown_focus_type`](arkret_core::error::ERROR_CODE_UNKNOWN_FOCUS_TYPE)
/// on unrecognized variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaBackendType {
    Livekit,
    Mediasoup,
    Janus,
    ArkretNative,
    MoqRelay,
    /// Unknown / forward-compat backend label. Helpers MUST reject this
    /// with `unknown_focus_type` before forwarding to the wire layer.
    #[serde(other)]
    Unknown,
}

impl MediaBackendType {
    /// Reject the focus when the SDK does not understand the backend
    /// label. Surface: [`unknown_focus_type`].
    pub fn ensure_known(&self) -> Result<()> {
        match self {
            Self::Unknown => Err(Error::Protocol(format!(
                "unknown_focus_type: media focus backend label not recognised"
            ))),
            _ => Ok(()),
        }
    }
}

/// Validate that `expires_at - now` is within the spec TTL ceiling
/// ([`MEDIA_TOKEN_TTL_MAX_SECS`](arkret_core::MEDIA_TOKEN_TTL_MAX_SECS)).
/// Returns [`Ok(())`] when the TTL is within bounds, otherwise a
/// `participant_binding_invalid` protocol error.
pub fn validate_token_ttl(now: DateTime<Utc>, expires_at: DateTime<Utc>) -> Result<()> {
    let remaining = (expires_at - now).num_seconds();
    if remaining <= 0 {
        return Err(Error::Protocol(format!(
            "participant_binding_invalid: token already expired"
        )));
    }
    if (remaining as u64) > arkret_core::MEDIA_TOKEN_TTL_MAX_SECS {
        return Err(Error::Protocol(format!(
            "participant_binding_invalid: token TTL exceeds 600s ceiling"
        )));
    }
    Ok(())
}

/// Client helper that builds a `ak.self.call.media.exchange.issue_token` request body.
///
/// The reqwest-backed transport (`arkret_http_client::Client::media_token_exchange`)
/// POSTs this body to `/_arkret/self/rtc/token` and returns the raw
/// [`CallMediaTokenExchangeOutcome`]. Callers MUST then pass the response through
/// [`verify_call_media_token_outcome`], which anchors `participant_binding.issuer_kid`
/// and the `service_signature` issuer to the current
/// `ak.realm.media_service.service_id` ([`MediaServiceAnchors`]), enforces the
/// ≤ 600s TTL ([`validate_token_ttl`]), and checks the binding six-tuple against
/// this request. Focus backend labels are rejected up front via
/// [`MediaBackendType::ensure_known`].
pub fn call_media_token_exchange(
    realm_id: RealmId,
    call_id: CallId,
    actor_id: Did,
    device_id: DeviceId,
    focus_id: impl Into<String>,
) -> CallMediaTokenExchangeRequestBody {
    CallMediaTokenExchangeRequestBody {
        realm_id,
        call_id,
        actor_id,
        device_id,
        focus_id: focus_id.into(),
        capability_refs: Vec::new(),
        desired_media: None,
    }
}

/// The set of media-service DIDs anchored by the current epoch's
/// `ak.realm.media_service.service_id` (`media-service-binding.md` §2.1 / §3),
/// together with the ed25519 verifying keys those DIDs publish.
///
/// Token issuer `kid`s MUST resolve to one of these DIDs, otherwise the client
/// rejects the token with `token_issuer_unauthorised`. The SDK is a pure
/// verification library and performs no DID resolution itself: the caller
/// resolves the media-service service DID document and supplies the
/// `kid -> ed25519 public key` map via [`with_keys`](Self::with_keys) /
/// [`insert_key`](Self::insert_key). [`verify_call_media_token_outcome`] looks
/// up the binding's `issuer_kid` and the `service_signature.kid` in this map to
/// verify the EdDSA signatures; a missing key or a failed signature is rejected
/// with `token_issuer_unauthorised`.
#[derive(Clone, Debug, Default)]
pub struct MediaServiceAnchors {
    service_ids: BTreeMap<String, ()>,
    /// Issuer verifying keys keyed by their full `kid` (`did:...#fragment`).
    keys: BTreeMap<String, VerifyingKey>,
}

impl MediaServiceAnchors {
    /// Build an anchor set from the current epoch's media-service DIDs.
    ///
    /// The returned set carries no verifying keys; callers MUST add them with
    /// [`with_keys`](Self::with_keys) / [`insert_key`](Self::insert_key) before
    /// passing it to [`verify_call_media_token_outcome`], otherwise signature
    /// verification fails closed with `token_issuer_unauthorised`.
    pub fn new(service_ids: impl IntoIterator<Item = Did>) -> Self {
        Self {
            service_ids: service_ids
                .into_iter()
                .map(|did| (did.as_str().to_owned(), ()))
                .collect(),
            keys: BTreeMap::new(),
        }
    }

    /// Register an issuer verifying key under its full `kid`
    /// (`did:...#fragment`). Returns `self` for builder-style chaining.
    pub fn with_keys(mut self, keys: impl IntoIterator<Item = (String, VerifyingKey)>) -> Self {
        for (kid, key) in keys {
            self.keys.insert(kid, key);
        }
        self
    }

    /// Register a single issuer verifying key under its full `kid`.
    pub fn insert_key(&mut self, kid: impl Into<String>, key: VerifyingKey) {
        self.keys.insert(kid.into(), key);
    }

    /// True when `did` (a bare DID, no `#fragment`) is anchored.
    pub fn contains(&self, did: &str) -> bool {
        self.service_ids.contains_key(did)
    }

    /// Look up the verifying key for a full `kid` (`did:...#fragment`).
    pub(crate) fn verifying_key(&self, kid: &str) -> Option<&VerifyingKey> {
        self.keys.get(kid)
    }

    /// True when the anchor set is empty (no media service declared); callers
    /// MUST treat this as fail-closed for issuer anchoring.
    pub fn is_empty(&self) -> bool {
        self.service_ids.is_empty()
    }
}

/// Outcome of verifying a [`CallMediaTokenExchangeOutcome`] against the request
/// and the realm media-service anchors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallMediaTokenVerification {
    /// The anchored media-service DID that issued the participant binding.
    pub issuer_did: Did,
    /// The verified participant identity (SFU-local handle).
    pub participant_identity: String,
}

/// Verified result returned by [`MediaClient::call_media_token_exchange`].
#[cfg(feature = "client")]
#[derive(Clone, Debug)]
pub struct VerifiedCallMediaTokenExchange {
    /// Raw server response for callers that need backend-specific fields such
    /// as the LiveKit JWT or SFU connection URL.
    pub outcome: CallMediaTokenExchangeOutcome,
    /// SDK verification summary proving the binding tuple, issuer anchoring,
    /// service signature and TTL have already been checked.
    pub verification: CallMediaTokenVerification,
}

/// Verified ICE config returned by [`MediaClient::media_ice_config`].
#[cfg(feature = "client")]
#[derive(Clone, Debug)]
pub struct VerifiedMediaIceConfig {
    /// Raw server response, including the server signature object.
    pub outcome: MediaIceConfigOutcome,
    /// Strongly typed projection after issuer anchoring, TTL and TURN privacy
    /// checks.
    pub config: crate::webrtc::IceConfig,
}

/// High-level media client that combines transport with fail-closed SDK
/// verification.
///
/// This wrapper intentionally keeps DID resolution outside the transport:
/// callers resolve the current `ak.realm.media_service.service_id` documents
/// and pass the anchored keys in [`MediaServiceAnchors`]. The methods below
/// then perform the HTTP request and reject unanchored, expired or tampered
/// responses before returning them to media setup code.
#[cfg(feature = "client")]
#[derive(Clone, Debug)]
pub struct MediaClient {
    client: arkret_http_client::Client,
}

#[cfg(feature = "client")]
impl MediaClient {
    /// Wrap an authenticated [`arkret_http_client::Client`].
    pub fn new(client: arkret_http_client::Client) -> Self {
        Self { client }
    }

    /// Borrow the underlying HTTP client for shared connection-pool use.
    pub fn client(&self) -> &arkret_http_client::Client {
        &self.client
    }

    /// `POST /_arkret/self/rtc/token`, followed by participant-binding and
    /// service-signature verification.
    pub async fn call_media_token_exchange(
        &self,
        request: &CallMediaTokenExchangeRequestBody,
        anchors: &MediaServiceAnchors,
        now: DateTime<Utc>,
    ) -> Result<VerifiedCallMediaTokenExchange> {
        let outcome = self.client.media_token_exchange(request).await?;
        let verification = verify_call_media_token_outcome(request, &outcome, anchors, now)?;
        Ok(VerifiedCallMediaTokenExchange {
            outcome,
            verification,
        })
    }

    /// `POST /_arkret/self/rtc/ice-config`, followed by issuer, TTL and TURN
    /// credential privacy checks.
    pub async fn media_ice_config(
        &self,
        request: &MediaIceConfigRequestBody,
        anchors: &MediaServiceAnchors,
    ) -> Result<VerifiedMediaIceConfig> {
        let outcome = self.client.media_ice_config(request).await?;
        let config = crate::webrtc::verify_ice_config_outcome(&outcome, anchors)?;
        Ok(VerifiedMediaIceConfig { outcome, config })
    }
}

#[cfg(feature = "client")]
impl From<arkret_http_client::Client> for MediaClient {
    fn from(client: arkret_http_client::Client) -> Self {
        Self::new(client)
    }
}

/// Extract the bare DID from a `kid` of the form `did:...#fragment`.
fn did_from_kid(kid: &str) -> &str {
    kid.split('#').next().unwrap_or(kid)
}

/// The seven authoritative fields the participant binding signature covers
/// (`media-service-binding.md` §3). Serialized via canonical JSON, which sorts
/// keys, so the on-wire signing bytes are stable regardless of declaration
/// order. Unsigned metadata (`scheme` / `issuer_kid` / `issued_at`) MUST NOT
/// appear here.
#[derive(Serialize)]
struct ParticipantBindingSigningFields<'a> {
    actor_id: &'a Did,
    call_id: &'a CallId,
    device_id: &'a DeviceId,
    expires_at: DateTime<Utc>,
    focus_id: &'a str,
    participant_identity: &'a str,
    realm_id: &'a RealmId,
}

/// Rebuild the normative `signing_input` for a participant binding:
///
/// ```text
/// "ak.media.participant_binding.v1" || 0x00 ||
/// canonical_json({ actor_id, call_id, device_id, expires_at,
///                  focus_id, participant_identity, realm_id })
/// ```
///
/// The first segment is the fixed ASCII label, then a single `0x00`, then the
/// canonical JSON of exactly the seven authoritative fields. Implementations
/// MUST NOT introduce a private domain prefix or fold metadata into the input.
///
/// This is `pub` so issuers (e.g. soland) can lock their construction against
/// the SDK verifier byte-for-byte: the bytes returned here are exactly what
/// `participant_binding.sig` and `service_signature.sig` cover, so a
/// cross-implementation test can assert the issuer's signing input equals this.
pub fn participant_binding_signing_input(binding: &CallMediaParticipantBinding) -> Result<Vec<u8>> {
    let fields = ParticipantBindingSigningFields {
        actor_id: &binding.actor_id,
        call_id: &binding.call_id,
        device_id: &binding.device_id,
        expires_at: binding.expires_at,
        focus_id: &binding.focus_id,
        participant_identity: &binding.participant_identity,
        realm_id: &binding.realm_id,
    };
    let mut input = Vec::new();
    input.extend_from_slice(PARTICIPANT_BINDING_LABEL.as_bytes());
    input.push(0x00);
    input.extend_from_slice(&canonical_json_bytes(&fields)?);
    Ok(input)
}

/// Verify an EdDSA(ed25519) signature `sig_b64` (base64url, no padding) over
/// `signing_input` using the verifying key registered under `kid` in `anchors`.
/// Any missing key, malformed signature or failed verification surfaces as
/// `token_issuer_unauthorised` (`media-service-binding.md` §3 default path).
fn verify_issuer_signature(
    anchors: &MediaServiceAnchors,
    kid: &str,
    sig_b64: &str,
    signing_input: &[u8],
    what: &str,
) -> Result<()> {
    let key = anchors.verifying_key(kid).ok_or_else(|| {
        Error::Protocol(format!(
            "{}: no verifying key registered for {what} kid {kid}",
            arkret_core::error::ReasonCode::TOKEN_ISSUER_UNAUTHORISED
        ))
    })?;
    let sig_bytes = base64url_decode(sig_b64).map_err(|err| {
        Error::Protocol(format!(
            "{}: {what} signature is not base64url: {err}",
            arkret_core::error::ReasonCode::TOKEN_ISSUER_UNAUTHORISED
        ))
    })?;
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::Protocol(format!(
            "{}: {what} signature must be 64 bytes, got {}",
            arkret_core::error::ReasonCode::TOKEN_ISSUER_UNAUTHORISED,
            sig_bytes.len()
        ))
    })?;
    let signature = Signature::from_bytes(&sig_array);
    key.verify_strict(signing_input, &signature).map_err(|err| {
        Error::Protocol(format!(
            "{}: {what} signature verification failed: {err}",
            arkret_core::error::ReasonCode::TOKEN_ISSUER_UNAUTHORISED
        ))
    })
}

/// Verify a media token-exchange response against the issuing request and the
/// realm media-service anchors (`media-service-binding.md` §3 client rules).
///
/// Checks performed (all fail closed):
/// - required fields present (`connect_url`, `backend_token`, `participant_identity`,
///   `participant_binding.sig`, `issuer_kid`);
/// - `participant_binding.issuer_kid` and the `service_signature.kid` resolve to an anchored
///   `ak.realm.media_service.service_id` → else `token_issuer_unauthorised`;
/// - the binding's `(realm_id, call_id, focus_id, actor_id, device_id)` six-tuple matches the
///   request and `participant_identity` matches the top-level one;
/// - the binding's `expires_at` is after its `issued_at`;
/// - TTL ≤ 600s and not already expired (via [`validate_token_ttl`]);
/// - **both** `participant_binding.sig` and `service_signature.sig` verify as EdDSA(ed25519)
///   signatures over the normative `signing_input` ([`participant_binding_signing_input`]) under
///   the issuer verifying keys in `anchors`. Per `media-service-binding.md` §3 the default
///   verification path MUST verify both signatures; either failing — or a missing key — rejects
///   with `token_issuer_unauthorised`. Because the signature covers the seven authoritative fields,
///   tampering with any of them fails verification.
///
/// The caller resolves the media-service service DID document and supplies the
/// `kid -> ed25519 public key` map through [`MediaServiceAnchors::with_keys`] /
/// [`MediaServiceAnchors::insert_key`]; this helper performs no DID resolution.
pub fn verify_call_media_token_outcome(
    request: &CallMediaTokenExchangeRequestBody,
    outcome: &CallMediaTokenExchangeOutcome,
    anchors: &MediaServiceAnchors,
    now: DateTime<Utc>,
) -> Result<CallMediaTokenVerification> {
    let binding = &outcome.participant_binding;

    if outcome.connect_url.trim().is_empty()
        || outcome.backend_token.trim().is_empty()
        || outcome.participant_identity.trim().is_empty()
        || binding.sig.trim().is_empty()
        || binding.issuer_kid.trim().is_empty()
    {
        return Err(Error::Protocol(format!(
            "participant_binding_invalid: token response missing required fields"
        )));
    }

    if binding.scheme != arkret_core::PARTICIPANT_BINDING_SCHEMA {
        return Err(Error::Protocol(format!(
            "participant_binding_invalid: unexpected scheme {:?}",
            binding.scheme
        )));
    }

    // Issuer DID anchoring — the binding issuer and the service_signature kid
    // MUST both resolve to an anchored service_id.
    let issuer_did = did_from_kid(&binding.issuer_kid);
    if anchors.is_empty() || !anchors.contains(issuer_did) {
        return Err(Error::Protocol(format!(
            "token_issuer_unauthorised: participant_binding issuer {issuer_did} not in realm media_service anchors"
        )));
    }
    let service_id = did_from_kid(&outcome.service_signature.kid);
    if !anchors.contains(service_id) {
        return Err(Error::Protocol(format!(
            "token_issuer_unauthorised: service_signature issuer {service_id} not in realm media_service anchors"
        )));
    }

    // Six-tuple binding MUST match the request the client made.
    if binding.realm_id != request.realm_id
        || binding.call_id != request.call_id
        || binding.focus_id != request.focus_id
        || binding.actor_id != request.actor_id
        || binding.device_id != request.device_id
    {
        return Err(Error::Protocol(format!(
            "participant_binding_invalid: binding tuple does not match the request"
        )));
    }
    if binding.participant_identity != outcome.participant_identity {
        return Err(Error::Protocol(format!(
            "participant_binding_invalid: participant_identity mismatch between binding and outcome"
        )));
    }

    // The binding's issued_at MUST precede its expiry (a non-positive TTL
    // window is a malformed binding).
    if binding.expires_at <= binding.issued_at {
        return Err(Error::Protocol(format!(
            "participant_binding_invalid: binding expires_at not after issued_at"
        )));
    }

    // TTL ceiling — both the binding and the outcome expiry MUST be ≤ 600s.
    validate_token_ttl(now, binding.expires_at)?;
    validate_token_ttl(now, outcome.expires_at)?;

    // Default verification path (spec §3): MUST verify BOTH the participant
    // binding signature and the service signature over the same signing_input.
    // Either failing — or a key the anchors do not publish — is
    // `token_issuer_unauthorised`.
    let signing_input = participant_binding_signing_input(binding)?;
    verify_issuer_signature(
        anchors,
        &binding.issuer_kid,
        &binding.sig,
        &signing_input,
        "participant_binding",
    )?;
    verify_issuer_signature(
        anchors,
        &outcome.service_signature.kid,
        &outcome.service_signature.sig,
        &signing_input,
        "service_signature",
    )?;

    Ok(CallMediaTokenVerification {
        issuer_did: Did::new(issuer_did.to_owned())?,
        participant_identity: outcome.participant_identity.clone(),
    })
}

/// Blob visibility class used by media metadata and thumbnails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaVisibility {
    Public,
    RealmBound,
    ActorPrivate,
    DeviceBound,
}

/// Access metadata for an uploaded blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaAccess {
    pub visibility: MediaVisibility,
}

/// Stored media metadata.
///
/// `realm_id` is the Realm seal used by `media-and-blob.md` §5 to scope
/// download authorization and garbage-collect blobs when a Realm is
/// dissolved or migrated. It is `None` only for genuinely global blobs
/// (e.g. a public organization avatar) — those callers MUST guarantee the
/// blob does not contain Realm-private content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaMetadata {
    /// Blob reference.
    pub blob_ref: BlobRef,
    /// SHA-256 digest.
    pub sha256: String,
    /// Size in bytes.
    ///
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    /// Media type.
    pub media_type: String,
    /// Optional filename.
    pub filename: Option<String>,
    /// Uploading user.
    pub uploaded_by: Did,
    /// Upload time.
    pub uploaded_at: DateTime<Utc>,
    /// Realm seal for download authorization and GC (B-23,
    /// `media-and-blob.md` §2). `None` only for global blobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    /// Visibility policy inherited by derived media such as thumbnails.
    pub access: MediaAccess,
}

/// Thumbnail metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thumbnail {
    /// Source blob reference.
    pub source_blob_ref: BlobRef,
    /// Optional digest for encrypted source media.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ciphertext_digest: Option<String>,
    /// Thumbnail blob reference.
    pub thumbnail_blob_ref: BlobRef,
    /// Optional digest for encrypted thumbnail media.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail_ciphertext_digest: Option<String>,
    /// Maximum width requested.
    pub width: u32,
    /// Maximum height requested.
    pub height: u32,
    /// Thumbnail media type.
    pub media_type: String,
    /// Service DID that derived the thumbnail, when server-generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_by_service_id: Option<Did>,
    /// Visibility inherited from the source blob metadata.
    pub visibility: MediaVisibility,
    /// Profile describing the deterministic thumbnail derivation.
    pub derivation_profile: String,
}

/// Attachment metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// Attachment ID.
    pub id: String,
    /// Blob reference.
    pub blob_ref: BlobRef,
    /// Filename.
    pub filename: String,
    /// Media type.
    pub media_type: String,
    /// Plaintext size for encrypted attachments, blob size otherwise.
    ///
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    /// Encryption metadata if stored encrypted.
    pub encryption: Option<EncryptedAttachment>,
}

/// Encrypted attachment envelope metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedAttachment {
    /// Algorithm identifier for the local envelope.
    pub algorithm: String,
    /// Key digest for matching restore keys.
    pub key_sha256: String,
    /// Plaintext SHA-256 digest.
    pub plaintext_sha256: String,
}

/// Authenticated download grant scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadGrantScope {
    Blob,
    Attachment,
}

/// Time- and use-bound grant for authenticated blob downloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedDownloadGrant {
    pub grant_id: String,
    pub blob_ref: BlobRef,
    pub subject: Did,
    pub issuer: Did,
    pub scope: DownloadGrantScope,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

impl AuthenticatedDownloadGrant {
    /// Validate the grant against a caller, target blob and observed use count.
    pub fn validate(
        &self,
        subject: &Did,
        blob_ref: &BlobRef,
        at: DateTime<Utc>,
        uses: u32,
    ) -> Result<()> {
        if &self.subject != subject {
            return Err(Error::Protocol(
                "download grant subject mismatch".to_owned(),
            ));
        }
        if &self.blob_ref != blob_ref {
            return Err(Error::Protocol("download grant blob mismatch".to_owned()));
        }
        if at > self.expires_at {
            return Err(Error::Protocol("download grant expired".to_owned()));
        }
        if let Some(max_uses) = self.max_uses
            && uses >= max_uses
        {
            return Err(Error::Protocol(
                "download grant use limit exceeded".to_owned(),
            ));
        }
        Ok(())
    }
}

/// In-memory blob and media store.
#[derive(Clone, Debug, Default)]
pub struct MemoryBlobStore {
    blobs: BTreeMap<BlobRef, Vec<u8>>,
    metadata: BTreeMap<BlobRef, MediaMetadata>,
    thumbnails: BTreeMap<BlobRef, Thumbnail>,
    attachments: BTreeMap<String, Attachment>,
    download_grants: BTreeMap<String, AuthenticatedDownloadGrant>,
    download_grant_uses: BTreeMap<String, u32>,
}

impl MemoryBlobStore {
    /// Create an empty blob store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Upload bytes and return metadata.
    pub fn upload(
        &mut self,
        bytes: impl AsRef<[u8]>,
        media_type: impl Into<String>,
        filename: Option<String>,
        uploaded_by: Did,
    ) -> Result<MediaMetadata> {
        self.upload_in_realm(bytes, media_type, filename, uploaded_by, None)
    }

    /// Upload bytes scoped to a Realm — preferred when the blob is private
    /// to that Realm so it can be GC'd on Realm migration / dissolution.
    pub fn upload_in_realm(
        &mut self,
        bytes: impl AsRef<[u8]>,
        media_type: impl Into<String>,
        filename: Option<String>,
        uploaded_by: Did,
        realm_id: Option<RealmId>,
    ) -> Result<MediaMetadata> {
        let bytes = bytes.as_ref();
        let blob_ref = blob_ref_for(bytes)?;
        let visibility = if realm_id.is_some() {
            MediaVisibility::RealmBound
        } else {
            MediaVisibility::Public
        };
        let metadata = MediaMetadata {
            blob_ref: blob_ref.clone(),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
            media_type: media_type.into(),
            filename,
            uploaded_by,
            uploaded_at: Utc::now(),
            realm_id,
            access: MediaAccess { visibility },
        };
        self.blobs.insert(blob_ref.clone(), bytes.to_vec());
        self.metadata.insert(blob_ref, metadata.clone());
        Ok(metadata)
    }

    /// Download bytes by blob reference.
    pub fn download(&self, blob_ref: &BlobRef) -> Option<&[u8]> {
        self.blobs.get(blob_ref).map(Vec::as_slice)
    }

    /// Get metadata by blob reference.
    pub fn metadata(&self, blob_ref: &BlobRef) -> Option<&MediaMetadata> {
        self.metadata.get(blob_ref)
    }

    /// Generate and store a lightweight thumbnail preview.
    ///
    /// This does not decode image pixels. It creates a deterministic preview
    /// blob from the first bytes and requested dimensions, which is enough for
    /// clients to cache and later replace with a platform image pipeline.
    pub fn generate_thumbnail(
        &mut self,
        source_blob_ref: &BlobRef,
        width: u32,
        height: u32,
    ) -> Result<Thumbnail> {
        self.generate_thumbnail_with_service(source_blob_ref, width, height, None)
    }

    /// Generate and store a thumbnail derived by a plaintext-visible media service.
    pub fn generate_thumbnail_by_service(
        &mut self,
        source_blob_ref: &BlobRef,
        width: u32,
        height: u32,
        service_id: Did,
    ) -> Result<Thumbnail> {
        self.generate_thumbnail_with_service(source_blob_ref, width, height, Some(service_id))
    }

    fn generate_thumbnail_with_service(
        &mut self,
        source_blob_ref: &BlobRef,
        width: u32,
        height: u32,
        generated_by_service_id: Option<Did>,
    ) -> Result<Thumbnail> {
        let source = self
            .blobs
            .get(source_blob_ref)
            .ok_or_else(|| Error::Protocol("source blob not found".to_owned()))?;
        let source_ciphertext_digest = format!("sha256:{}", sha256_hex(source));
        let mut preview = format!("thumbnail:{width}x{height}:").into_bytes();
        preview.extend(source.iter().take(256));
        let blob_ref = blob_ref_for(&preview)?;
        self.blobs.insert(blob_ref.clone(), preview.clone());
        let thumbnail_ciphertext_digest = format!("sha256:{}", sha256_hex(&preview));
        let visibility = self
            .metadata
            .get(source_blob_ref)
            .map(|metadata| metadata.access.visibility)
            .unwrap_or(MediaVisibility::Public);

        let thumbnail = Thumbnail {
            source_blob_ref: source_blob_ref.clone(),
            source_ciphertext_digest: Some(source_ciphertext_digest),
            thumbnail_blob_ref: blob_ref,
            thumbnail_ciphertext_digest: Some(thumbnail_ciphertext_digest),
            width,
            height,
            media_type: "image/preview".to_owned(),
            generated_by_service_id,
            visibility,
            derivation_profile: THUMBNAIL_DERIVATION_PROFILE.to_owned(),
        };
        self.thumbnails
            .insert(source_blob_ref.clone(), thumbnail.clone());
        Ok(thumbnail)
    }

    /// Get the generated thumbnail for a source blob.
    pub fn thumbnail(&self, source_blob_ref: &BlobRef) -> Option<&Thumbnail> {
        self.thumbnails.get(source_blob_ref)
    }

    /// Upload an attachment.
    pub fn upload_attachment(
        &mut self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl AsRef<[u8]>,
        uploaded_by: Did,
    ) -> Result<Attachment> {
        let filename = filename.into();
        let media_type = media_type.into();
        let metadata = self.upload(
            bytes.as_ref(),
            media_type.clone(),
            Some(filename.clone()),
            uploaded_by,
        )?;
        let attachment = Attachment {
            id: id.into(),
            blob_ref: metadata.blob_ref,
            filename,
            media_type,
            size_bytes: metadata.size_bytes,
            encryption: None,
        };
        self.attachments
            .insert(attachment.id.clone(), attachment.clone());
        Ok(attachment)
    }

    /// Download attachment bytes.
    pub fn download_attachment(&self, id: &str) -> Option<&[u8]> {
        self.attachments
            .get(id)
            .and_then(|attachment| self.download(&attachment.blob_ref))
    }

    /// Upload an encrypted attachment using authenticated encryption.
    pub fn upload_encrypted_attachment(
        &mut self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        plaintext: impl AsRef<[u8]>,
        key: &[u8],
        uploaded_by: Did,
    ) -> Result<Attachment> {
        let plaintext = plaintext.as_ref();
        let ciphertext = crypto::seal(plaintext, key, b"arkret-media-attachment-v1")?;
        let filename = filename.into();
        let media_type = media_type.into();
        let metadata = self.upload(
            &ciphertext,
            "application/octet-stream",
            Some(filename.clone()),
            uploaded_by,
        )?;
        let attachment = Attachment {
            id: id.into(),
            blob_ref: metadata.blob_ref,
            filename,
            media_type,
            size_bytes: plaintext.len() as u64,
            encryption: Some(EncryptedAttachment {
                algorithm: AEAD_ALGORITHM.to_owned(),
                key_sha256: sha256_hex(key),
                plaintext_sha256: sha256_hex(plaintext),
            }),
        };
        self.attachments
            .insert(attachment.id.clone(), attachment.clone());
        Ok(attachment)
    }

    /// Download and decrypt an encrypted attachment.
    pub fn download_decrypted_attachment(&self, id: &str, key: &[u8]) -> Result<Vec<u8>> {
        let attachment = self
            .attachments
            .get(id)
            .ok_or_else(|| Error::Protocol("attachment not found".to_owned()))?;
        let encryption = attachment
            .encryption
            .as_ref()
            .ok_or_else(|| Error::Protocol("attachment is not encrypted".to_owned()))?;
        if encryption.key_sha256 != sha256_hex(key) {
            return Err(Error::Protocol("attachment key mismatch".to_owned()));
        }
        let ciphertext = self
            .download(&attachment.blob_ref)
            .ok_or_else(|| Error::Protocol("attachment blob not found".to_owned()))?;
        if encryption.algorithm != AEAD_ALGORITHM {
            return Err(Error::Protocol(
                "unsupported attachment encryption algorithm".to_owned(),
            ));
        }
        let plaintext = crypto::open(ciphertext, key, b"arkret-media-attachment-v1")?;
        if encryption.plaintext_sha256 != sha256_hex(&plaintext) {
            return Err(Error::Protocol("attachment digest mismatch".to_owned()));
        }
        Ok(plaintext)
    }

    /// Get an attachment by ID.
    pub fn attachment(&self, id: &str) -> Option<&Attachment> {
        self.attachments.get(id)
    }

    /// Remove an attachment by ID. Returns `true` if the attachment existed.
    pub fn remove_attachment(&mut self, id: &str) -> bool {
        self.attachments.remove(id).is_some()
    }

    /// Return the number of stored attachments.
    pub fn attachment_count(&self) -> usize {
        self.attachments.len()
    }

    /// Iterate over all stored attachments.
    pub fn all_attachments(&self) -> impl Iterator<Item = &Attachment> {
        self.attachments.values()
    }

    /// Issue an authenticated download grant for an existing blob.
    pub fn issue_download_grant(
        &mut self,
        grant_id: impl Into<String>,
        blob_ref: BlobRef,
        subject: Did,
        issuer: Did,
        expires_at: DateTime<Utc>,
        max_uses: Option<u32>,
    ) -> Result<AuthenticatedDownloadGrant> {
        if !self.blobs.contains_key(&blob_ref) {
            return Err(Error::Protocol(
                "download grant target blob not found".to_owned(),
            ));
        }
        if expires_at <= Utc::now() {
            return Err(Error::Protocol(
                "download grant expires in the past".to_owned(),
            ));
        }
        let grant = AuthenticatedDownloadGrant {
            grant_id: grant_id.into(),
            blob_ref,
            subject,
            issuer,
            scope: DownloadGrantScope::Blob,
            issued_at: Utc::now(),
            expires_at,
            max_uses,
            proof: None,
        };
        self.download_grant_uses.insert(grant.grant_id.clone(), 0);
        self.download_grants
            .insert(grant.grant_id.clone(), grant.clone());
        Ok(grant)
    }

    /// Download blob bytes through an authenticated grant.
    pub fn download_with_grant(
        &mut self,
        grant_id: &str,
        subject: &Did,
        at: DateTime<Utc>,
    ) -> Result<&[u8]> {
        let grant = self
            .download_grants
            .get(grant_id)
            .cloned()
            .ok_or_else(|| Error::Protocol("download grant not found".to_owned()))?;
        let uses = self
            .download_grant_uses
            .get(grant_id)
            .copied()
            .unwrap_or_default();
        grant.validate(subject, &grant.blob_ref, at, uses)?;
        *self
            .download_grant_uses
            .entry(grant_id.to_owned())
            .or_default() += 1;
        self.download(&grant.blob_ref)
            .ok_or_else(|| Error::Protocol("download grant target blob not found".to_owned()))
    }

    /// Get a stored authenticated download grant.
    pub fn download_grant(&self, grant_id: &str) -> Option<&AuthenticatedDownloadGrant> {
        self.download_grants.get(grant_id)
    }
}

/// Sanitize a media type for safe `Content-Type` headers.
///
/// Strips parameters, validates the `type/subtype` form, and lowercases.
/// Returns `None` for obviously invalid or injection-prone values.
pub fn safe_content_type(media_type: &str) -> Option<String> {
    let trimmed = media_type
        .trim()
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();
    let (type_part, subtype_part) = trimmed.split_once('/')?;
    if type_part.is_empty()
        || subtype_part.is_empty()
        || !type_part.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'&' | b'.' | b'+' | b'-' | b'^' | b'_'
                )
        })
        || !subtype_part.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'&' | b'.' | b'+' | b'-' | b'^' | b'_'
                )
        })
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains('\0')
    {
        return None;
    }
    Some(trimmed)
}

/// Build a safe `Content-Disposition: attachment` header value.
///
/// The filename is percent-encoded to prevent header injection. Falls back to
/// `file.bin` if the name is empty or contains only unsafe characters.
pub fn safe_content_disposition(filename: &str) -> String {
    let sanitized: String = filename
        .chars()
        .filter(|c| !matches!(c, '\n' | '\r' | '\0' | '"' | '\\'))
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        return "attachment; filename=\"file.bin\"".to_owned();
    }
    let encoded: String = sanitized
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect();
    format!("attachment; filename=\"{encoded}\"")
}

fn blob_ref_for(bytes: &[u8]) -> Result<BlobRef> {
    Ok(BlobRef::new(format!(
        "ak:blob:sha256:{}",
        sha256_hex(bytes)
    ))?)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const ISSUER_KID: &str = "did:webvh:z6mkfixture:media.example#media-token";

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    /// Anchor set carrying the issuer verifying key under [`ISSUER_KID`].
    fn anchors_with_issuer_key(key: &SigningKey) -> MediaServiceAnchors {
        MediaServiceAnchors::new([did("media")])
            .with_keys([(ISSUER_KID.to_owned(), key.verifying_key())])
    }

    #[cfg(feature = "client")]
    #[test]
    fn media_client_wraps_authenticated_http_client() {
        let http = arkret_http_client::Client::new(
            reqwest::Url::parse("https://alice.example/arkret/").unwrap(),
        )
        .unwrap();
        let media = MediaClient::new(http.clone());
        let _: &arkret_http_client::Client = media.client();

        let media_from: MediaClient = http.into();
        let _: &arkret_http_client::Client = media_from.client();
    }

    fn token_request() -> CallMediaTokenExchangeRequestBody {
        call_media_token_exchange(
            RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            CallId::new("ak:call:0196441c-0000-7000-8000-000000000000").unwrap(),
            did("alice"),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
            "fra-1",
        )
    }

    /// Build an unsigned outcome (placeholder signatures); callers sign it via
    /// [`sign_outcome`] after any field tampering.
    fn token_outcome(
        request: &CallMediaTokenExchangeRequestBody,
        expires_at: DateTime<Utc>,
    ) -> CallMediaTokenExchangeOutcome {
        let identity = "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000".to_owned();
        CallMediaTokenExchangeOutcome {
            focus_id: request.focus_id.clone(),
            backend_type: "livekit".to_owned(),
            connect_url: "wss://livekit-fra.example.com".to_owned(),
            backend_token: "opaque-backend-token".to_owned(),
            participant_identity: identity.clone(),
            participant_binding: CallMediaParticipantBinding {
                scheme: arkret_core::PARTICIPANT_BINDING_SCHEMA.to_owned(),
                sig: String::new(),
                issuer_kid: ISSUER_KID.to_owned(),
                realm_id: request.realm_id.clone(),
                call_id: request.call_id.clone(),
                focus_id: request.focus_id.clone(),
                actor_id: request.actor_id.clone(),
                device_id: request.device_id.clone(),
                participant_identity: identity,
                issued_at: expires_at - chrono::Duration::minutes(5),
                expires_at,
            },
            expires_at,
            service_signature: arkret_core::CallMediaServiceSignature {
                kid: ISSUER_KID.to_owned(),
                sig: String::new(),
            },
        }
    }

    /// Sign the binding and the service signature over the spec signing_input
    /// with `key`, mutating `outcome` in place. Call this AFTER any tampering so
    /// signatures cover the (possibly tampered) authoritative fields.
    fn sign_outcome(outcome: &mut CallMediaTokenExchangeOutcome, key: &SigningKey) {
        let input = participant_binding_signing_input(&outcome.participant_binding).unwrap();
        let sig = arkret_canonical::base64url::base64url_encode(key.sign(&input).to_bytes());
        outcome.participant_binding.sig = sig.clone();
        outcome.service_signature.sig = sig;
    }

    /// A fully signed, verifiable outcome over the request and issuer key.
    fn signed_outcome(
        request: &CallMediaTokenExchangeRequestBody,
        key: &SigningKey,
        expires_at: DateTime<Utc>,
    ) -> CallMediaTokenExchangeOutcome {
        let mut outcome = token_outcome(request, expires_at);
        sign_outcome(&mut outcome, key);
        outcome
    }

    #[test]
    fn media_token_outcome_roundtrips_and_verifies() {
        let request = token_request();
        let key = issuer_key();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(5);
        let outcome = signed_outcome(&request, &key, expires_at);

        // Wire roundtrip: request + outcome survive a JSON round-trip.
        let request_json = serde_json::to_string(&request).unwrap();
        let request_back: CallMediaTokenExchangeRequestBody =
            serde_json::from_str(&request_json).unwrap();
        assert_eq!(request_back.focus_id, "fra-1");
        let outcome_json = serde_json::to_string(&outcome).unwrap();
        let outcome_back: CallMediaTokenExchangeOutcome =
            serde_json::from_str(&outcome_json).unwrap();
        assert_eq!(
            outcome_back.participant_identity,
            outcome.participant_identity
        );

        let anchors = anchors_with_issuer_key(&key);
        let verified = verify_call_media_token_outcome(&request, &outcome, &anchors, now).unwrap();
        assert_eq!(verified.issuer_did, did("media"));
        assert_eq!(verified.participant_identity, outcome.participant_identity);

        // Anchor: the signing input is label-prefixed (`media-service-binding.md`
        // §3). soland's cross-implementation lock asserts byte equality against
        // this same function.
        let signing_input =
            participant_binding_signing_input(&outcome.participant_binding).unwrap();
        assert!(signing_input.starts_with(b"ak.media.participant_binding.v1\x00"));
    }

    #[test]
    fn media_token_rejects_unanchored_issuer() {
        let request = token_request();
        let key = issuer_key();
        let now = Utc::now();
        let outcome = signed_outcome(&request, &key, now + chrono::Duration::minutes(5));

        // Issuer DID not in the anchor set.
        let anchors = MediaServiceAnchors::new([did("other")])
            .with_keys([(ISSUER_KID.to_owned(), key.verifying_key())]);
        let err = verify_call_media_token_outcome(&request, &outcome, &anchors, now).unwrap_err();
        assert!(err.to_string().contains("token_issuer_unauthorised"));

        // Empty anchor set is fail-closed.
        let empty = MediaServiceAnchors::default();
        assert!(verify_call_media_token_outcome(&request, &outcome, &empty, now).is_err());
    }

    #[test]
    fn media_token_verifies_signatures_and_rejects_tampering() {
        let request = token_request();
        let key = issuer_key();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(5);
        let anchors = anchors_with_issuer_key(&key);

        // A correctly signed outcome verifies.
        let good = signed_outcome(&request, &key, expires_at);
        assert!(verify_call_media_token_outcome(&request, &good, &anchors, now).is_ok());

        // Anchor DID present but no verifying key registered → fail closed.
        let keyless = MediaServiceAnchors::new([did("media")]);
        let err = verify_call_media_token_outcome(&request, &good, &keyless, now).unwrap_err();
        assert!(err.to_string().contains("token_issuer_unauthorised"));

        // A different issuer key produces a signature that does not verify.
        let other = SigningKey::from_bytes(&[22u8; 32]);
        let wrong_key = signed_outcome(&request, &other, expires_at);
        let err = verify_call_media_token_outcome(&request, &wrong_key, &anchors, now).unwrap_err();
        assert!(err.to_string().contains("token_issuer_unauthorised"));

        // Tamper each of the seven authoritative fields AFTER signing → the
        // recomputed signing_input no longer matches the signature.
        // participant_identity: also update the top-level field so the
        // structural cross-check passes and the failure is signature-only.
        let mut t_identity = signed_outcome(&request, &key, expires_at);
        t_identity.participant_binding.participant_identity =
            "ak:rtc_participant:tampered".to_owned();
        t_identity.participant_identity = "ak:rtc_participant:tampered".to_owned();
        assert!(
            verify_call_media_token_outcome(&request, &t_identity, &anchors, now)
                .unwrap_err()
                .to_string()
                .contains("token_issuer_unauthorised")
        );

        // expires_at: re-sign would change it; here we move it within TTL but
        // do NOT re-sign, so the signature over the old expires_at fails.
        let mut t_expiry = signed_outcome(&request, &key, expires_at);
        t_expiry.participant_binding.expires_at = expires_at - chrono::Duration::seconds(30);
        assert!(
            verify_call_media_token_outcome(&request, &t_expiry, &anchors, now)
                .unwrap_err()
                .to_string()
                .contains("token_issuer_unauthorised")
        );

        // service_signature tampered alone → only the second signature fails.
        let mut t_service = signed_outcome(&request, &key, expires_at);
        t_service.service_signature.sig = signed_outcome(&request, &other, expires_at)
            .service_signature
            .sig;
        let err = verify_call_media_token_outcome(&request, &t_service, &anchors, now).unwrap_err();
        assert!(err.to_string().contains("token_issuer_unauthorised"));
        assert!(err.to_string().contains("service_signature"));
    }

    #[test]
    fn media_token_rejects_ttl_over_ceiling_and_tuple_mismatch() {
        let request = token_request();
        let key = issuer_key();
        let now = Utc::now();
        let anchors = anchors_with_issuer_key(&key);

        // TTL over 600s ceiling.
        let long = signed_outcome(&request, &key, now + chrono::Duration::minutes(20));
        assert!(verify_call_media_token_outcome(&request, &long, &anchors, now).is_err());

        // Focus mismatch in the binding tuple (re-signed so the failure is the
        // structural tuple check, not the signature).
        let mut tampered = token_outcome(&request, now + chrono::Duration::minutes(5));
        tampered.participant_binding.focus_id = "fra-2".to_owned();
        sign_outcome(&mut tampered, &key);
        let err = verify_call_media_token_outcome(&request, &tampered, &anchors, now).unwrap_err();
        assert!(err.to_string().contains("participant_binding_invalid"));

        // participant_identity mismatch between binding and outcome.
        let mut id_mismatch = signed_outcome(&request, &key, now + chrono::Duration::minutes(5));
        id_mismatch.participant_identity = "ak:rtc_participant:elsewhere".to_owned();
        assert!(verify_call_media_token_outcome(&request, &id_mismatch, &anchors, now).is_err());
    }

    #[test]
    fn media_uploads_downloads_metadata_and_thumbnail() {
        let mut store = MemoryBlobStore::new();
        let metadata = store
            .upload(
                b"image-bytes",
                "image/png",
                Some("a.png".to_owned()),
                did("alice"),
            )
            .unwrap();

        assert_eq!(
            store.download(&metadata.blob_ref),
            Some(&b"image-bytes"[..])
        );
        assert_eq!(
            store.metadata(&metadata.blob_ref).unwrap().media_type,
            "image/png"
        );

        let thumbnail = store
            .generate_thumbnail(&metadata.blob_ref, 64, 64)
            .unwrap();
        assert_eq!(thumbnail.source_blob_ref, metadata.blob_ref);
        assert!(
            thumbnail
                .thumbnail_blob_ref
                .as_str()
                .starts_with("ak:blob:")
        );
        let expected_source_digest = format!("sha256:{}", metadata.sha256);
        assert_eq!(
            thumbnail.source_ciphertext_digest.as_deref(),
            Some(expected_source_digest.as_str())
        );
        assert!(
            thumbnail
                .thumbnail_ciphertext_digest
                .as_deref()
                .is_some_and(|digest| digest.starts_with("sha256:"))
        );
        assert_eq!(thumbnail.visibility, MediaVisibility::Public);
        assert_eq!(thumbnail.derivation_profile, THUMBNAIL_DERIVATION_PROFILE);
        assert!(store.thumbnail(&thumbnail.source_blob_ref).is_some());

        let service_thumbnail = store
            .generate_thumbnail_by_service(
                &metadata.blob_ref,
                32,
                32,
                Did::new("did:webvh:z6mkfixture:media.example".to_owned()).unwrap(),
            )
            .unwrap();
        let media_service_id = Did::new("did:webvh:z6mkfixture:media.example".to_owned()).unwrap();
        assert_eq!(
            service_thumbnail.generated_by_service_id.as_ref(),
            Some(&media_service_id)
        );
    }

    #[test]
    fn media_uploads_downloads_and_encrypts_attachments() {
        let mut store = MemoryBlobStore::new();
        let attachment = store
            .upload_attachment("a1", "note.txt", "text/plain", b"hello", did("alice"))
            .unwrap();
        assert_eq!(attachment.size_bytes, 5);
        assert_eq!(store.download_attachment("a1"), Some(&b"hello"[..]));

        let encrypted = store
            .upload_encrypted_attachment(
                "a2",
                "secret.txt",
                "text/plain",
                b"secret",
                b"key",
                did("alice"),
            )
            .unwrap();
        assert!(encrypted.encryption.is_some());
        assert_ne!(store.download_attachment("a2"), Some(&b"secret"[..]));
        assert_eq!(
            store.download_decrypted_attachment("a2", b"key").unwrap(),
            b"secret"
        );
        assert!(store.download_decrypted_attachment("a2", b"wrong").is_err());
    }

    #[test]
    fn media_remove_attachment_and_count() {
        let mut store = MemoryBlobStore::new();
        store
            .upload_attachment("a1", "file.txt", "text/plain", b"data", did("alice"))
            .unwrap();
        store
            .upload_attachment("a2", "img.png", "image/png", b"png", did("bob"))
            .unwrap();
        assert_eq!(store.attachment_count(), 2);

        assert!(store.remove_attachment("a1"));
        assert_eq!(store.attachment_count(), 1);
        assert!(store.attachment("a1").is_none());
        assert!(!store.remove_attachment("a1"));

        let all: Vec<_> = store.all_attachments().map(|a| a.id.as_str()).collect();
        assert_eq!(all, vec!["a2"]);
    }

    #[test]
    fn media_download_grants_validate_subject_expiry_and_use_limit() {
        let mut store = MemoryBlobStore::new();
        let metadata = store
            .upload(
                b"download",
                "text/plain",
                Some("d.txt".to_owned()),
                did("alice"),
            )
            .unwrap();
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let subject = did("bob");
        let grant = store
            .issue_download_grant(
                "grant1",
                metadata.blob_ref.clone(),
                subject.clone(),
                did("alice"),
                expires_at,
                Some(1),
            )
            .unwrap();

        assert_eq!(store.download_grant("grant1"), Some(&grant));
        assert_eq!(
            store
                .download_with_grant("grant1", &subject, Utc::now())
                .unwrap(),
            &b"download"[..]
        );
        assert!(
            store
                .download_with_grant("grant1", &subject, Utc::now())
                .is_err()
        );
        assert!(
            grant
                .validate(&did("mallory"), &metadata.blob_ref, Utc::now(), 0)
                .is_err()
        );
        assert!(
            grant
                .validate(
                    &subject,
                    &metadata.blob_ref,
                    Utc::now() + chrono::Duration::minutes(10),
                    0,
                )
                .is_err()
        );
    }

    #[test]
    fn safe_content_type_validates_and_lowercases() {
        assert_eq!(
            safe_content_type("text/plain"),
            Some("text/plain".to_owned())
        );
        assert_eq!(
            safe_content_type("Image/PNG; charset=utf-8"),
            Some("image/png".to_owned())
        );
        assert_eq!(
            safe_content_type("  application/json  "),
            Some("application/json".to_owned())
        );
        assert!(safe_content_type("not-a-mime-type").is_none());
        assert!(safe_content_type("").is_none());
        assert!(safe_content_type("text/").is_none());
        assert!(safe_content_type("/plain").is_none());
        assert!(safe_content_type("text/plain\nX-Injected: evil").is_none());
    }

    #[test]
    fn safe_content_disposition_encodes_unsafe_chars() {
        assert_eq!(
            safe_content_disposition("report.pdf"),
            "attachment; filename=\"report.pdf\""
        );
        assert_eq!(
            safe_content_disposition("my file (1).txt"),
            "attachment; filename=\"my%20file%20%281%29.txt\""
        );
        assert_eq!(
            safe_content_disposition(""),
            "attachment; filename=\"file.bin\""
        );
        assert!(safe_content_disposition("file\nname.txt").contains("file"));
    }
}
