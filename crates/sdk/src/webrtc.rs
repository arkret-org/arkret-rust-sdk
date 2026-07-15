//! WebRTC signaling and conference state helpers.

use arkret_canonical::base64url::base64url_decode;
use arkret_canonical::canonical::canonical_json_bytes;
use arkret_core::{
    MediaIceConfigOutcome, MediaIceConstraints, MediaIceServer, MediaIceSignatureAlgorithm,
    XExtensionMap,
};
#[cfg(test)]
use arkret_core::{MediaIceConfigSignature, MediaIceSignatureInput};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::Value;

/// SDP description type used by the SDK's WebRTC transport helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SdpType {
    Offer,
    Answer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallSessionDescription {
    pub sdp_type: SdpType,
    pub sdp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_m_line_index: Option<u32>,
}
use crate::media::MediaServiceAnchors;
use crate::{Did, Error, RealmId, Result};

const ICE_CONFIG_SIGNING_LABEL: &str = "ak.media.ice_config.v1";

/// To-device WebRTC signaling message kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcSignalKind {
    Offer,
    Answer,
    IceCandidate,
}

/// To-device WebRTC offer/answer/ICE signaling envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebRtcSignalMessage {
    pub message_id: String,
    pub call_id: String,
    pub realm_id: RealmId,
    pub sender: Did,
    pub recipient: Did,
    pub kind: WebRtcSignalKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_description: Option<CallSessionDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ice_candidate: Option<IceCandidate>,
    pub created_at: DateTime<Utc>,
}

impl WebRtcSignalMessage {
    /// Build an offer signaling message.
    pub fn offer(
        realm_id: RealmId,
        call_id: impl Into<String>,
        sender: Did,
        recipient: Did,
        sdp: impl Into<String>,
    ) -> Self {
        Self::with_session_description(
            realm_id,
            call_id,
            sender,
            recipient,
            CallSessionDescription {
                sdp_type: SdpType::Offer,
                sdp: sdp.into(),
            },
        )
    }

    /// Build an answer signaling message.
    pub fn answer(
        realm_id: RealmId,
        call_id: impl Into<String>,
        sender: Did,
        recipient: Did,
        sdp: impl Into<String>,
    ) -> Self {
        Self::with_session_description(
            realm_id,
            call_id,
            sender,
            recipient,
            CallSessionDescription {
                sdp_type: SdpType::Answer,
                sdp: sdp.into(),
            },
        )
    }

    /// Build an ICE-candidate signaling message.
    pub fn ice_candidate(
        realm_id: RealmId,
        call_id: impl Into<String>,
        sender: Did,
        recipient: Did,
        ice_candidate: IceCandidate,
    ) -> Self {
        Self {
            message_id: format!("webrtc_{}", uuid::Uuid::now_v7()),
            call_id: call_id.into(),
            realm_id,
            sender,
            recipient,
            kind: WebRtcSignalKind::IceCandidate,
            session_description: None,
            ice_candidate: Some(ice_candidate),
            created_at: Utc::now(),
        }
    }

    fn with_session_description(
        realm_id: RealmId,
        call_id: impl Into<String>,
        sender: Did,
        recipient: Did,
        session_description: CallSessionDescription,
    ) -> Self {
        let kind = match session_description.sdp_type {
            SdpType::Offer => WebRtcSignalKind::Offer,
            SdpType::Answer => WebRtcSignalKind::Answer,
        };
        Self {
            message_id: format!("webrtc_{}", uuid::Uuid::now_v7()),
            call_id: call_id.into(),
            realm_id,
            sender,
            recipient,
            kind,
            session_description: Some(session_description),
            ice_candidate: None,
            created_at: Utc::now(),
        }
    }
}

/// Strongly-typed ICE configuration parsed from a verified
/// [`MediaIceConfigOutcome`] (`webrtc-signaling.md` §4 / §4.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceConfig {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    /// STUN / TURN servers offered for this call leg.
    pub ice_servers: Vec<MediaIceServer>,
    /// Credential lifetime in seconds.
    pub ttl_seconds: u32,
    /// Refresh lead — clients SHOULD re-fetch once remaining ≤ this (always
    /// `< ttl_seconds` per §4.1).
    pub refresh_lead_seconds: u32,
    /// `true` when the caller MUST relay through TURN (no host/srflx).
    pub force_turn: bool,
    /// The media-service DID that signed the config (from `signature.kid`).
    pub issuer_did: Did,
}

impl IceConfig {
    /// TURN servers only.
    pub fn turn_servers(&self) -> impl Iterator<Item = &MediaIceServer> {
        self.ice_servers.iter().filter(|server| server.is_turn())
    }

    /// STUN servers only.
    pub fn stun_servers(&self) -> impl Iterator<Item = &MediaIceServer> {
        self.ice_servers.iter().filter(|server| server.is_stun())
    }
}

fn validate_ice_server_credential_privacy(server: &MediaIceServer) -> Result<()> {
    const FORBIDDEN_PREFIXES: &[&str] = &[
        "did:web:",
        "did:plc:",
        "did:key:",
        "did:webvh:",
        "did:webs:",
        "did:keri:",
    ];
    for value in [&server.username, &server.credential].into_iter().flatten() {
        if FORBIDDEN_PREFIXES
            .iter()
            .any(|prefix| value.contains(prefix))
        {
            return Err(Error::Protocol(
                "ICE server credential leaks a DID; use a Realm-scoped pairwise pseudonym"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct IceConfigSigningFields<'a> {
    realm_id: &'a RealmId,
    call_id: &'a str,
    actor_id: &'a Did,
    device_id: &'a crate::DeviceId,
    ice_servers: &'a [MediaIceServer],
    ttl_seconds: u32,
    refresh_lead_seconds: u32,
    issued_at: DateTime<Utc>,
    issued_at_bucket: DateTime<Utc>,
    bucket_seconds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    force_turn: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    constraints: &'a Option<MediaIceConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_retry_at: &'a Option<DateTime<Utc>>,
    #[serde(flatten)]
    extensions: &'a XExtensionMap,
}

fn ice_config_signing_input(
    outcome: &MediaIceConfigOutcome,
    include_default_force_turn: bool,
) -> Result<Vec<u8>> {
    let fields = IceConfigSigningFields {
        realm_id: &outcome.realm_id,
        call_id: &outcome.call_id,
        actor_id: &outcome.actor_id,
        device_id: &outcome.device_id,
        ice_servers: &outcome.ice_servers,
        ttl_seconds: outcome.ttl_seconds,
        refresh_lead_seconds: outcome.refresh_lead_seconds,
        issued_at: outcome.issued_at,
        issued_at_bucket: outcome.issued_at_bucket,
        bucket_seconds: outcome.bucket_seconds,
        expires_at: outcome.expires_at,
        force_turn: if outcome.force_turn || include_default_force_turn {
            Some(outcome.force_turn)
        } else {
            None
        },
        constraints: &outcome.constraints,
        next_retry_at: &outcome.next_retry_at,
        extensions: &outcome.extensions,
    };
    let canonical = canonical_json_bytes(&fields).map_err(|err| {
        Error::Protocol(format!("ice_config_denied: canonicalization failed: {err}"))
    })?;
    let mut input = Vec::with_capacity(ICE_CONFIG_SIGNING_LABEL.len() + canonical.len() + 1);
    input.extend_from_slice(ICE_CONFIG_SIGNING_LABEL.as_bytes());
    input.push(0x00);
    input.extend_from_slice(&canonical);
    Ok(input)
}

fn verify_ice_config_signature(
    outcome: &MediaIceConfigOutcome,
    anchors: &MediaServiceAnchors,
    kid: &str,
) -> Result<()> {
    if outcome.signature.alg != MediaIceSignatureAlgorithm::EdDsa {
        return Err(Error::Protocol(
            "ice_config_denied: unsupported signature algorithm".to_owned(),
        ));
    }
    let sig_b64 = &outcome.signature.sig;
    let key = anchors.verifying_key(kid).ok_or_else(|| {
        Error::Protocol(format!(
            "ice_config_denied: no verifying key registered for ICE config kid {kid}"
        ))
    })?;
    let sig_bytes = base64url_decode(sig_b64).map_err(|err| {
        Error::Protocol(format!(
            "ice_config_denied: signature.sig is not base64url: {err}"
        ))
    })?;
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::Protocol(format!(
            "ice_config_denied: signature.sig must be 64 bytes, got {}",
            sig_bytes.len()
        ))
    })?;
    let signature = Signature::from_bytes(&sig_array);

    let mut signing_inputs = vec![ice_config_signing_input(outcome, true)?];
    if !outcome.force_turn {
        signing_inputs.push(ice_config_signing_input(outcome, false)?);
    }
    if signing_inputs
        .iter()
        .any(|input| key.verify_strict(input, &signature).is_ok())
    {
        return Ok(());
    }
    Err(Error::Protocol(
        "ice_config_denied: signature.sig verification failed".to_owned(),
    ))
}

/// Verify an ICE config response and project it into a strongly-typed
/// [`IceConfig`] (`webrtc-signaling.md` §4 client rules).
///
/// Checks (fail closed):
/// - the top-level `signature.kid` resolves to an anchored media-service DID → else
///   `ice_config_denied`;
/// - `refresh_lead_seconds < ttl_seconds` (§4.1) and `ttl_seconds > 0`;
/// - `signature.sig` verifies as EdDSA(ed25519) over `ak.media.ice_config.v1 || 0x00 ||
///   canonical_json(response minus signature)`;
/// - every `ice_servers[]` TURN credential passes the pairwise-pseudonym privacy guard (no embedded
///   DID, B-14).
pub fn verify_ice_config_outcome(
    outcome: &MediaIceConfigOutcome,
    anchors: &MediaServiceAnchors,
) -> Result<IceConfig> {
    let kid = outcome.signature.kid.clone();
    if kid.is_empty() {
        return Err(Error::Protocol(
            "ice_config_denied: signature missing kid".to_owned(),
        ));
    }
    let issuer_did = kid.split('#').next().unwrap_or(&kid).to_owned();
    if anchors.is_empty() || !anchors.contains(&issuer_did) {
        return Err(Error::Protocol(format!(
            "ice_config_denied: signature issuer {issuer_did} not in realm media_service anchors"
        )));
    }

    if outcome.ttl_seconds == 0 || outcome.refresh_lead_seconds >= outcome.ttl_seconds {
        return Err(Error::Protocol(
            "ice_config_denied: refresh_lead_seconds must be below a positive ttl_seconds"
                .to_owned(),
        ));
    }
    verify_ice_config_signature(outcome, anchors, &kid)?;

    // TURN pseudonym bucket — issued_at_bucket MUST equal
    // floor(issued_at / bucket_seconds) * bucket_seconds so usernames cannot be
    // correlated across buckets by rewriting metadata (ice-config-response
    // schema). v1 fixes bucket_seconds at 300s.
    if outcome.bucket_seconds == 0 {
        return Err(Error::Protocol(
            "ice_config_denied: bucket_seconds must be positive".to_owned(),
        ));
    }
    let bucket = i64::from(outcome.bucket_seconds);
    let expected_bucket_secs = (outcome.issued_at.timestamp().div_euclid(bucket)) * bucket;
    if outcome.issued_at_bucket.timestamp() != expected_bucket_secs
        || outcome.issued_at_bucket.timestamp_subsec_nanos() != 0
    {
        return Err(Error::Protocol(
            "ice_config_denied: issued_at_bucket must equal floor(issued_at / bucket_seconds)"
                .to_owned(),
        ));
    }

    for server in &outcome.ice_servers {
        if server.urls.is_empty() {
            return Err(Error::Protocol(
                "ice_config_denied: ice server entry has no urls".to_owned(),
            ));
        }
        validate_ice_server_credential_privacy(server)?;
    }

    Ok(IceConfig {
        realm_id: outcome.realm_id.clone(),
        call_id: outcome.call_id.clone(),
        actor_id: outcome.actor_id.clone(),
        ice_servers: outcome.ice_servers.clone(),
        ttl_seconds: outcome.ttl_seconds,
        refresh_lead_seconds: outcome.refresh_lead_seconds,
        force_turn: outcome.force_turn,
        issuer_did: Did::new(issuer_did)?,
    })
}

// ── Typed `ak.call.signal` payload.data (webrtc-signaling.md §6.1 / §8) ──────

/// Media negotiation change reason (`renegotiate` payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenegotiateReason {
    AddTrack,
    RemoveTrack,
    CodecChange,
    IceRestart,
}

/// Media track set a sender expects to send after a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaTrackSet {
    pub audio: bool,
    pub video: bool,
    pub screen: bool,
}

/// `signal_type=renegotiate` `payload.data` (§6.1). A frame carries exactly one
/// of `offer` / `answer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenegotiateData {
    pub reason: RenegotiateReason,
    #[serde(default)]
    pub ice_restart: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer: Option<CallSessionDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answer: Option<CallSessionDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<MediaTrackSet>,
}

impl RenegotiateData {
    /// §6.1: a frame MUST carry exactly one of `offer` / `answer`, and
    /// `ice_restart=true` requires a session description to carry the new
    /// ufrag/pwd.
    pub fn validate(&self) -> Result<()> {
        if self.offer.is_some() == self.answer.is_some() {
            return Err(Error::Protocol(
                "renegotiate frame MUST carry exactly one of offer / answer".to_owned(),
            ));
        }
        if self.ice_restart && self.offer.is_none() && self.answer.is_none() {
            return Err(Error::Protocol(
                "renegotiate with ice_restart MUST carry an SDP description".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Source of a mute action (`mute_state` payload, §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MuteSource {
    /// The participant muted themselves.
    #[serde(rename = "self")]
    Selff,
    /// A moderator (holder of `ak.call.moderate`) forced the mute.
    Moderator,
}

/// `signal_type=mute_state` `payload.data` (§6.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MuteStateData {
    pub audio_muted: bool,
    pub video_muted: bool,
    pub by: MuteSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<crate::DeviceId>,
}

impl MuteStateData {
    /// §6.1: `by=moderator` MUST carry `target_*`; `by=self` MUST NOT.
    pub fn validate(&self) -> Result<()> {
        match self.by {
            MuteSource::Moderator => {
                if self.target_actor_id.is_none() || self.target_device_id.is_none() {
                    return Err(Error::Protocol(
                        "mute_state by=moderator MUST carry target_actor_id and target_device_id"
                            .to_owned(),
                    ));
                }
            }
            MuteSource::Selff => {
                if self.target_actor_id.is_some() || self.target_device_id.is_some() {
                    return Err(Error::Protocol(
                        "mute_state by=self MUST NOT carry target_* fields".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Screen-share sub-state (`media_state` payload, §8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenShareState {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default)]
    pub with_audio: bool,
}

/// `signal_type=media_state` `payload.data` (§8 screen share).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaStateData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen: Option<ScreenShareState>,
}

/// `signal_type=speaking` `payload.data` (§6.1, high-frequency best-effort).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpeakingData {
    pub speaking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_level: Option<f64>,
}

impl SpeakingData {
    /// §6.1: `audio_level` is a normalized RMS in `[0.0, 1.0]`.
    pub fn validate(&self) -> Result<()> {
        if let Some(level) = self.audio_level
            && !(0.0..=1.0).contains(&level)
        {
            return Err(Error::Protocol(
                "speaking audio_level MUST be within [0.0, 1.0]".to_owned(),
            ));
        }
        Ok(())
    }
}

// ── Recording / transcribe / moderation (call-state.md §5) ──────────────────

/// Recording capture mode (`ak.call.recording.start`, `call-state.md` §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordingMode {
    #[serde(rename = "audio")]
    AudioOnly,
    #[serde(rename = "audio_video")]
    AudioVideo,
}

/// Capture dimension selected by `ak.call.recording.start`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingCaptureKind {
    Recording,
    Transcript,
}

/// `ak.call.recording.start` payload (`call-state.md` §5). Field names are
/// snake_case per spec; the recording artifact key is derived separately via
/// [`crate::sframe::derive_recording_key`] over the
/// `(realm_id, call_id, focus_id, recording_id, media_service_id,
/// recording_start_event_id)` tuple.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingStartPayload {
    pub call_id: crate::CallId,
    pub recording_id: String,
    /// Service DID performing the capture (backend egress agent).
    pub recording_agent: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_kind: Option<RecordingCaptureKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<RecordingMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible_notice: Option<bool>,
}

/// Recording lifecycle state published on `ak.call.state.recording_state`
/// (`call-state.md` §4.2 / §5). Orthogonal to call `state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingState {
    Recording,
    Stopped,
    Ready,
    Failed,
}

/// `ak.call.state.recording_result` artifact reference (`call-state.md` §5).
/// Published after a recording reaches `ready`; the artifact MUST be a Arkret
/// encrypted blob (no backend-hosted URL).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingResult {
    /// `ak.call.recording.start` event id this segment derives from.
    pub recording_start_event_id: crate::EventId,
    /// Content digest of the encrypted recording blob.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<crate::Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<crate::PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<crate::CallRecordingRetention>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<crate::CallRecordingArtifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

/// `ak.call.transcribe` request payload (`webrtc-signaling.md` §3 capability,
/// `call-state.md` §5). Transcript text is stored as a Morph / Artifact under
/// the same Realm policy; only the binding metadata travels on the call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscribePayload {
    pub call_id: crate::CallId,
    pub transcribe_id: String,
    /// Service DID performing transcription.
    pub transcribe_agent: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcribe_initiator_capability_ref: Option<String>,
}

/// Moderation action kind for a `ak.call.moderate` operation
/// (`webrtc-signaling.md` §3, §6.1 `mute_state by=moderator`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationAction {
    /// Force-mute a participant's audio/video.
    Mute,
    /// Stop a participant's screen share.
    StopScreenShare,
    /// Remove a participant from the call.
    Remove,
    /// End the call for everyone.
    EndForAll,
}

/// `ak.call.moderate` payload (`webrtc-signaling.md` §3 / §6.1). A moderator
/// action MUST carry the moderator capability ref; participant-scoped actions
/// MUST carry the target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeratePayload {
    pub call_id: crate::CallId,
    pub action: ModerationAction,
    pub moderate_capability_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<crate::DeviceId>,
}

impl ModeratePayload {
    /// Participant-scoped actions (`mute` / `stop_screen_share` / `remove`)
    /// MUST name a target; `end_for_all` MUST NOT.
    pub fn validate(&self) -> Result<()> {
        let target_required = !matches!(self.action, ModerationAction::EndForAll);
        let has_target = self.target_actor_id.is_some();
        if target_required && !has_target {
            return Err(Error::Protocol(
                "moderation action MUST name a target_actor_id".to_owned(),
            ));
        }
        if !target_required && has_target {
            return Err(Error::Protocol(
                "end_for_all moderation MUST NOT carry a target".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url::base64url_encode;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap()
    }

    const MEDIA_KID: &str = "did:webvh:z6mkfixture:media.example#notary-key";

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn anchors_with_issuer_key(key: &SigningKey) -> MediaServiceAnchors {
        MediaServiceAnchors::new([did("media")])
            .with_keys([(MEDIA_KID.to_owned(), key.verifying_key())])
    }

    fn sign_ice_outcome(
        mut outcome: MediaIceConfigOutcome,
        kid: &str,
        key: &SigningKey,
    ) -> MediaIceConfigOutcome {
        outcome.signature.kid = kid.to_owned();
        outcome.signature.sig.clear();
        let signing_input = ice_config_signing_input(&outcome, true).unwrap();
        let signature = key.sign(&signing_input);
        outcome.signature.sig = base64url_encode(signature.to_bytes());
        outcome
    }

    fn signed_ice_outcome(kid: &str, key: &SigningKey) -> MediaIceConfigOutcome {
        sign_ice_outcome(ice_outcome(kid), kid, key)
    }

    fn ice_outcome(kid: &str) -> MediaIceConfigOutcome {
        MediaIceConfigOutcome {
            realm_id: realm(),
            call_id: "ak:call:0196441c-0000-7000-8000-000000000000".to_owned(),
            actor_id: did("alice"),
            device_id: crate::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005")
                .unwrap(),
            ice_servers: vec![
                MediaIceServer {
                    urls: vec!["stun:stun.example.com".to_owned()],
                    username: None,
                    credential: None,
                    credential_type: None,
                },
                MediaIceServer {
                    urls: vec!["turn:turn.example.com".to_owned()],
                    username: Some("1718000000:rand".to_owned()),
                    credential: Some("secret".to_owned()),
                    credential_type: None,
                },
            ],
            ttl_seconds: 300,
            refresh_lead_seconds: 60,
            issued_at: "2026-05-27T12:29:56Z".parse().unwrap(),
            issued_at_bucket: "2026-05-27T12:25:00Z".parse().unwrap(),
            bucket_seconds: 300,
            expires_at: None,
            force_turn: false,
            constraints: None,
            next_retry_at: None,
            signature: MediaIceConfigSignature {
                kid: kid.to_owned(),
                alg: MediaIceSignatureAlgorithm::EdDsa,
                signature_input: MediaIceSignatureInput::IceConfigV1,
                payload_digest: crate::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                sig: "AAAA".to_owned(),
            },
            extensions: XExtensionMap::default(),
        }
    }

    #[test]
    fn ice_config_verifies_parses_and_classifies_servers() {
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let outcome = signed_ice_outcome(MEDIA_KID, &key);
        let config = verify_ice_config_outcome(&outcome, &anchors).unwrap();

        assert_eq!(config.issuer_did, did("media"));
        assert_eq!(config.ttl_seconds, 300);
        assert_eq!(config.stun_servers().count(), 1);
        assert_eq!(config.turn_servers().count(), 1);
        assert!(!config.force_turn);
    }

    #[test]
    fn ice_config_rejects_unanchored_issuer_and_bad_ttl() {
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);

        let stranger = signed_ice_outcome("did:webvh:z6mkfixture:evil.example#notary-key", &key);
        let err = verify_ice_config_outcome(&stranger, &anchors).unwrap_err();
        assert!(err.to_string().contains("ice_config_denied"));

        let mut bad_ttl = signed_ice_outcome(MEDIA_KID, &key);
        bad_ttl.refresh_lead_seconds = bad_ttl.ttl_seconds;
        assert!(verify_ice_config_outcome(&bad_ttl, &anchors).is_err());
    }

    #[test]
    fn ice_config_rejects_turn_credential_leaking_did() {
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let mut leaky = ice_outcome(MEDIA_KID);
        leaky.ice_servers[1].username = Some("did:webvh:z6mkfixture:alice.example".to_owned());
        let leaky = sign_ice_outcome(leaky, MEDIA_KID, &key);
        assert!(verify_ice_config_outcome(&leaky, &anchors).is_err());
    }

    #[test]
    fn ice_config_rejects_missing_or_bad_signature() {
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);

        let mut missing_sig = ice_outcome(MEDIA_KID);
        missing_sig.signature.sig.clear();
        assert!(verify_ice_config_outcome(&missing_sig, &anchors).is_err());

        let mut tampered = signed_ice_outcome(MEDIA_KID, &key);
        tampered.ttl_seconds += 1;
        assert!(verify_ice_config_outcome(&tampered, &anchors).is_err());

        let no_key = MediaServiceAnchors::new([did("media")]);
        let signed = signed_ice_outcome(MEDIA_KID, &key);
        assert!(verify_ice_config_outcome(&signed, &no_key).is_err());
    }

    #[test]
    fn renegotiate_data_requires_exactly_one_description() {
        let offer = RenegotiateData {
            reason: RenegotiateReason::AddTrack,
            ice_restart: false,
            offer: Some(CallSessionDescription {
                sdp_type: SdpType::Offer,
                sdp: "v=0".to_owned(),
            }),
            answer: None,
            media: Some(MediaTrackSet {
                audio: true,
                video: true,
                screen: false,
            }),
        };
        offer.validate().unwrap();

        // Roundtrip and confirm the nested data shape.
        let value = serde_json::to_value(&offer).unwrap();
        assert_eq!(value["reason"], "add_track");
        assert_eq!(value["offer"]["sdp_type"], "offer");
        let back: RenegotiateData = serde_json::from_value(value).unwrap();
        assert_eq!(back, offer);

        // Carrying both offer and answer is invalid.
        let mut both = offer;
        both.answer = Some(CallSessionDescription {
            sdp_type: SdpType::Answer,
            sdp: "v=0".to_owned(),
        });
        assert!(both.validate().is_err());

        // ice_restart with no SDP is invalid.
        let restart = RenegotiateData {
            reason: RenegotiateReason::IceRestart,
            ice_restart: true,
            offer: None,
            answer: None,
            media: None,
        };
        assert!(restart.validate().is_err());
    }

    #[test]
    fn mute_state_data_enforces_moderator_target_rules() {
        let self_mute = MuteStateData {
            audio_muted: true,
            video_muted: false,
            by: MuteSource::Selff,
            target_actor_id: None,
            target_device_id: None,
        };
        self_mute.validate().unwrap();
        // `self` serializes verbatim per spec.
        assert_eq!(
            serde_json::to_value(&self_mute).unwrap()["by"],
            serde_json::json!("self")
        );

        let moderator = MuteStateData {
            audio_muted: true,
            video_muted: true,
            by: MuteSource::Moderator,
            target_actor_id: Some(did("bob")),
            target_device_id: Some(
                crate::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000000").unwrap(),
            ),
        };
        moderator.validate().unwrap();

        // moderator without target is invalid; self with target is invalid.
        let mut bad_mod = moderator;
        bad_mod.target_actor_id = None;
        bad_mod.target_device_id = None;
        assert!(bad_mod.validate().is_err());

        let mut bad_self = self_mute;
        bad_self.target_actor_id = Some(did("bob"));
        assert!(bad_self.validate().is_err());
    }

    #[test]
    fn speaking_and_media_state_serialize_per_spec() {
        let speaking = SpeakingData {
            speaking: true,
            audio_level: Some(0.42),
        };
        speaking.validate().unwrap();
        let value = serde_json::to_value(speaking).unwrap();
        assert_eq!(value["speaking"], true);
        assert_eq!(value["audio_level"], 0.42);

        let mut loud = speaking;
        loud.audio_level = Some(1.5);
        assert!(loud.validate().is_err());

        let screen = MediaStateData {
            screen: Some(ScreenShareState {
                enabled: true,
                source_id: Some("screen_01".to_owned()),
                with_audio: false,
            }),
        };
        let value = serde_json::to_value(&screen).unwrap();
        assert_eq!(value["screen"]["enabled"], true);
        assert_eq!(value["screen"]["source_id"], "screen_01");
        let back: MediaStateData = serde_json::from_value(value).unwrap();
        assert_eq!(back, screen);
    }

    #[test]
    fn moderate_payload_enforces_target_presence() {
        let mute = ModeratePayload {
            call_id: crate::CallId::new("ak:call:0196441c-0000-7000-8000-000000000000").unwrap(),
            action: ModerationAction::Mute,
            moderate_capability_ref: "ak:grant:01".to_owned(),
            target_actor_id: Some(did("bob")),
            target_device_id: None,
        };
        mute.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&mute).unwrap()["action"],
            serde_json::json!("mute")
        );

        let mut no_target = mute;
        no_target.target_actor_id = None;
        assert!(no_target.validate().is_err());

        let end_for_all = ModeratePayload {
            call_id: crate::CallId::new("ak:call:0196441c-0000-7000-8000-000000000000").unwrap(),
            action: ModerationAction::EndForAll,
            moderate_capability_ref: "ak:grant:01".to_owned(),
            target_actor_id: None,
            target_device_id: None,
        };
        end_for_all.validate().unwrap();
        let mut bad_end = end_for_all;
        bad_end.target_actor_id = Some(did("bob"));
        assert!(bad_end.validate().is_err());
    }

    #[test]
    fn recording_and_transcribe_payloads_serialize_snake_case() {
        let start = RecordingStartPayload {
            call_id: crate::CallId::new("ak:call:0196441c-0000-7000-8000-000000000000").unwrap(),
            recording_id: "rtc-recording-1".to_owned(),
            recording_agent: did("recorder"),
            capture_kind: Some(RecordingCaptureKind::Recording),
            mode: Some(RecordingMode::AudioVideo),
            visible_notice: Some(true),
        };
        let value = serde_json::to_value(&start).unwrap();
        assert_eq!(value["capture_kind"], "recording");
        assert_eq!(value["mode"], "audio_video");
        assert_eq!(value["visible_notice"], true);
        assert_eq!(value["recording_id"], "rtc-recording-1");
        let back: RecordingStartPayload = serde_json::from_value(value).unwrap();
        assert_eq!(back, start);

        let transcribe = TranscribePayload {
            call_id: start.call_id,
            transcribe_id: "tx-1".to_owned(),
            transcribe_agent: did("scribe"),
            language: Some("zh-CN".to_owned()),
            transcribe_initiator_capability_ref: None,
        };
        assert_eq!(
            serde_json::to_value(&transcribe).unwrap()["language"],
            "zh-CN"
        );

        let result = RecordingResult {
            recording_start_event_id: crate::EventId::new(
                "ak:event:019a7360-0000-7000-8000-000000000003",
            )
            .unwrap(),
            content_digest: Some(
                crate::Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
            ),
            duration_ms: Some(120_000),
            media_type: Some("video/webm".to_owned()),
            retention_policy_id: None,
            retention: None,
            artifact: None,
            failure_reason_code: None,
            failure_message: None,
        };
        assert_eq!(
            serde_json::to_value(&result).unwrap()["recording_start_event_id"],
            "ak:event:019a7360-0000-7000-8000-000000000003"
        );
    }

    #[test]
    fn webrtc_builds_to_device_signaling_messages() {
        let offer =
            WebRtcSignalMessage::offer(realm(), "call1", did("alice"), did("bob"), "offer-sdp");
        let answer =
            WebRtcSignalMessage::answer(realm(), "call1", did("bob"), did("alice"), "answer-sdp");
        let ice = WebRtcSignalMessage::ice_candidate(
            realm(),
            "call1",
            did("alice"),
            did("bob"),
            IceCandidate {
                candidate: "candidate".to_owned(),
                sdp_mid: Some("0".to_owned()),
                sdp_m_line_index: Some(0),
            },
        );

        assert_eq!(offer.kind, WebRtcSignalKind::Offer);
        assert_eq!(
            offer.session_description.as_ref().unwrap().sdp_type,
            SdpType::Offer
        );
        assert_eq!(answer.kind, WebRtcSignalKind::Answer);
        assert_eq!(ice.kind, WebRtcSignalKind::IceCandidate);
        assert!(ice.ice_candidate.is_some());
    }
}
