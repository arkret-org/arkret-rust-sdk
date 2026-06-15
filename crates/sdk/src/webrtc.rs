//! WebRTC signaling and conference state helpers.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use cokret_core::MediaIceConfigOutcome;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Signaling DTOs are owned by the SDK's `client_api` module; re-export the
// authoritative definitions instead of keeping a parallel copy here.
pub use crate::client_api::{CallSessionDescription, IceCandidate, SdpType};
use crate::media::MediaServiceAnchors;
use crate::{Did, Error, RealmId, Result};

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

/// Call state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallState {
    Offering,
    Answered,
    Connected,
    Ended,
}

/// Media track kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaTrackKind {
    Audio,
    Video,
}

/// Media track state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaTrack {
    pub track_id: String,
    pub kind: MediaTrackKind,
    pub enabled: bool,
}

/// Conference backend mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConferenceMode {
    Sfu,
    Mcu,
}

/// Conference session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConferenceSession {
    pub conference_id: String,
    pub mode: ConferenceMode,
    pub participants: BTreeSet<Did>,
    pub joined_at: DateTime<Utc>,
}

/// ICE server kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IceServerKind {
    Stun,
    Turn,
}

/// STUN/TURN server config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceServer {
    pub kind: IceServerKind,
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

impl IceServer {
    /// Reject TURN configurations whose `username` embeds a raw DID. The
    /// TURN operator MUST NOT learn cross-Realm stable identities; clients
    /// SHOULD derive the username from a short-lived ephemeral identifier
    /// such as `<unix>:<random_b64>` instead.
    pub fn validate_credential_privacy(&self) -> Result<()> {
        const FORBIDDEN_PREFIXES: &[&str] = &[
            "did:web:",
            "did:plc:",
            "did:key:",
            "did:webvh:",
            "did:webs:",
            "did:keri:",
        ];
        for value in [&self.username, &self.credential].into_iter().flatten() {
            for prefix in FORBIDDEN_PREFIXES {
                if value.contains(prefix) {
                    return Err(crate::Error::Protocol(format!(
                        "ICE server credential leaks DID prefix '{prefix}'; use a Realm-scoped pairwise pseudonym (B-14)"
                    )));
                }
            }
            // Reject colon-separated pairs whose tail is a DID-shaped substring.
            if let Some((_left, tail)) = value.split_once(':')
                && FORBIDDEN_PREFIXES.iter().any(|p| tail.contains(p))
            {
                return Err(crate::Error::Protocol(
                    "ICE server username embeds a DID after a colon separator; use an ephemeral token (B-14)"
                        .to_owned(),
                ));
            }
        }
        Ok(())
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
    pub ice_servers: Vec<IceServer>,
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
    pub fn turn_servers(&self) -> impl Iterator<Item = &IceServer> {
        self.ice_servers
            .iter()
            .filter(|server| server.kind == IceServerKind::Turn)
    }

    /// STUN servers only.
    pub fn stun_servers(&self) -> impl Iterator<Item = &IceServer> {
        self.ice_servers
            .iter()
            .filter(|server| server.kind == IceServerKind::Stun)
    }
}

/// Parse one wire `ice_servers[]` entry (an open `Value`, since the server
/// emits a transport-specific descriptor) into a strongly-typed [`IceServer`].
fn ice_server_from_value(value: &Value) -> Result<IceServer> {
    let object = value.as_object().ok_or_else(|| {
        Error::Protocol("ice_config_denied: ice server entry is not an object".to_owned())
    })?;
    let urls = match object.get("urls") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect::<Vec<_>>(),
        Some(Value::String(single)) => vec![single.clone()],
        _ => Vec::new(),
    };
    if urls.is_empty() {
        return Err(Error::Protocol(
            "ice_config_denied: ice server entry has no urls".to_owned(),
        ));
    }
    let kind = if urls
        .iter()
        .any(|url| url.starts_with("turn:") || url.starts_with("turns:"))
    {
        IceServerKind::Turn
    } else {
        IceServerKind::Stun
    };
    Ok(IceServer {
        kind,
        urls,
        username: object
            .get("username")
            .and_then(Value::as_str)
            .map(str::to_owned),
        credential: object
            .get("credential")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Extract the signing `kid` from the top-level ICE config `signature` object.
fn ice_signature_kid(signature: &Value) -> Result<String> {
    signature
        .get("kid")
        .and_then(Value::as_str)
        .filter(|kid| !kid.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Error::Protocol("ice_config_denied: signature missing kid".to_owned()))
}

/// Verify an ICE config response and project it into a strongly-typed
/// [`IceConfig`] (`webrtc-signaling.md` §4 client rules).
///
/// Checks (fail closed):
/// - the top-level `signature.kid` resolves to an anchored media-service DID → else
///   `ice_config_denied`;
/// - `refresh_lead_seconds < ttl_seconds` (§4.1) and `ttl_seconds > 0`;
/// - every `ice_servers[]` TURN credential passes the pairwise-pseudonym privacy guard (no embedded
///   DID, B-14).
///
/// The media-service DID signs over the canonical config payload; callers
/// holding the verifying key SHOULD additionally check `signature.sig` against
/// the canonical bytes. This helper anchors issuer trust to realm policy and
/// enforces the TTL / privacy invariants.
pub fn verify_ice_config_outcome(
    outcome: &MediaIceConfigOutcome,
    anchors: &MediaServiceAnchors,
) -> Result<IceConfig> {
    let kid = ice_signature_kid(&outcome.signature)?;
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

    let mut ice_servers = Vec::with_capacity(outcome.ice_servers.len());
    for entry in &outcome.ice_servers {
        let server = ice_server_from_value(entry)?;
        server.validate_credential_privacy()?;
        ice_servers.push(server);
    }

    Ok(IceConfig {
        realm_id: outcome.realm_id.clone(),
        call_id: outcome.call_id.clone(),
        actor_id: outcome.actor_id.clone(),
        ice_servers,
        ttl_seconds: outcome.ttl_seconds,
        refresh_lead_seconds: outcome.refresh_lead_seconds,
        force_turn: outcome.force_turn,
        issuer_did: Did::new(issuer_did)?,
    })
}

// ── Typed `ck.call.signal` payload.data (webrtc-signaling.md §6.1 / §8) ──────

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
    /// A moderator (holder of `ck.call.moderate`) forced the mute.
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

/// Recording capture mode (`ck.call.recording.start`, `call-state.md` §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingMode {
    AudioOnly,
    AudioVideo,
}

/// `ck.call.recording.start` payload (`call-state.md` §5). Field names are
/// snake_case per spec; the recording artifact key is derived separately via
/// [`crate::sframe::derive_recording_key`] over the
/// `(realm_id, call_id, focus_id, recording_id, media_service_did,
/// recording_start_event_id)` tuple.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingStartPayload {
    pub call_id: crate::CallId,
    pub recording_id: String,
    /// Service DID performing the capture (backend egress agent).
    pub recording_agent: Did,
    pub mode: RecordingMode,
    /// Capability grant proving the initiator holds `ck.call.record`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording_initiator_capability_ref: Option<String>,
}

/// Recording lifecycle state published on `ck.call.state.recording_state`
/// (`call-state.md` §4.2 / §5). Orthogonal to call `state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingState {
    Recording,
    Stopped,
    Ready,
    Failed,
}

/// `ck.call.state.recording_result` artifact reference (`call-state.md` §5).
/// Published after a recording reaches `ready`; the artifact MUST be a Cokret
/// encrypted blob (no backend-hosted URL).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingResult {
    /// `ck.call.recording.start` event id this segment derives from.
    pub recording_start_event_id: String,
    /// Content digest of the encrypted recording blob.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<String>,
}

/// `ck.call.transcribe` request payload (`webrtc-signaling.md` §3 capability,
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

/// Moderation action kind for a `ck.call.moderate` operation
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

/// `ck.call.moderate` payload (`webrtc-signaling.md` §3 / §6.1). A moderator
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

/// WebRTC call state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebRtcCall {
    pub call_id: String,
    pub realm_id: RealmId,
    pub caller: Did,
    pub callees: BTreeSet<Did>,
    pub state: CallState,
    pub offer: Option<CallSessionDescription>,
    pub answer: Option<CallSessionDescription>,
    pub ice_candidates: Vec<IceCandidate>,
    pub tracks: BTreeMap<String, MediaTrack>,
    pub screen_sharing: bool,
    pub conference: Option<ConferenceSession>,
}

/// WebRTC manager.
#[derive(Clone, Debug, Default)]
pub struct WebRtcManager {
    calls: BTreeMap<String, WebRtcCall>,
    ice_servers: Vec<IceServer>,
}

impl WebRtcManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an offer call.
    pub fn create_offer(
        &mut self,
        realm_id: RealmId,
        caller: Did,
        callees: BTreeSet<Did>,
        sdp: impl Into<String>,
    ) -> WebRtcCall {
        let call_id = format!("call_{}", uuid::Uuid::now_v7());
        let call = WebRtcCall {
            call_id: call_id.clone(),
            realm_id,
            caller,
            callees,
            state: CallState::Offering,
            offer: Some(CallSessionDescription {
                sdp_type: SdpType::Offer,
                sdp: sdp.into(),
            }),
            answer: None,
            ice_candidates: Vec::new(),
            tracks: BTreeMap::new(),
            screen_sharing: false,
            conference: None,
        };
        self.calls.insert(call_id, call.clone());
        call
    }

    /// Store an answer.
    pub fn receive_answer(&mut self, call_id: &str, sdp: impl Into<String>) -> Option<&WebRtcCall> {
        let call = self.calls.get_mut(call_id)?;
        call.answer = Some(CallSessionDescription {
            sdp_type: SdpType::Answer,
            sdp: sdp.into(),
        });
        call.state = CallState::Answered;
        Some(call)
    }

    /// Add an ICE candidate.
    pub fn add_ice_candidate(&mut self, call_id: &str, candidate: IceCandidate) -> Option<()> {
        self.calls.get_mut(call_id)?.ice_candidates.push(candidate);
        Some(())
    }

    /// Update call state.
    pub fn update_state(&mut self, call_id: &str, state: CallState) -> Option<()> {
        self.calls.get_mut(call_id)?.state = state;
        Some(())
    }

    /// Join a conference through SFU or MCU.
    pub fn join_conference(
        &mut self,
        call_id: &str,
        conference_id: impl Into<String>,
        mode: ConferenceMode,
        participant: Did,
    ) -> Option<&ConferenceSession> {
        let call = self.calls.get_mut(call_id)?;
        let conference = call.conference.get_or_insert_with(|| ConferenceSession {
            conference_id: conference_id.into(),
            mode,
            participants: BTreeSet::new(),
            joined_at: Utc::now(),
        });
        conference.participants.insert(participant);
        Some(conference)
    }

    /// Add or update a media track.
    pub fn set_track(&mut self, call_id: &str, track: MediaTrack) -> Option<()> {
        self.calls
            .get_mut(call_id)?
            .tracks
            .insert(track.track_id.clone(), track);
        Some(())
    }

    /// Enable or disable a track.
    pub fn set_track_enabled(
        &mut self,
        call_id: &str,
        track_id: &str,
        enabled: bool,
    ) -> Option<()> {
        self.calls
            .get_mut(call_id)?
            .tracks
            .get_mut(track_id)?
            .enabled = enabled;
        Some(())
    }

    /// Enable or disable screen sharing.
    pub fn set_screen_sharing(&mut self, call_id: &str, enabled: bool) -> Option<()> {
        self.calls.get_mut(call_id)?.screen_sharing = enabled;
        Some(())
    }

    /// Register an ICE server.
    pub fn add_ice_server(&mut self, server: IceServer) {
        self.ice_servers.push(server);
    }

    /// STUN servers.
    pub fn stun_servers(&self) -> Vec<&IceServer> {
        self.ice_servers
            .iter()
            .filter(|server| server.kind == IceServerKind::Stun)
            .collect()
    }

    /// TURN servers.
    pub fn turn_servers(&self) -> Vec<&IceServer> {
        self.ice_servers
            .iter()
            .filter(|server| server.kind == IceServerKind::Turn)
            .collect()
    }

    /// Get a call.
    pub fn call(&self, call_id: &str) -> Option<&WebRtcCall> {
        self.calls.get(call_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn Realm() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap()
    }

    #[test]
    fn webrtc_exchanges_offer_answer_ice_and_state() {
        let mut manager = WebRtcManager::new();
        let call = manager.create_offer(
            Realm(),
            did("alice"),
            BTreeSet::from([did("bob")]),
            "offer-sdp",
        );
        manager.receive_answer(&call.call_id, "answer-sdp").unwrap();
        manager
            .add_ice_candidate(
                &call.call_id,
                IceCandidate {
                    candidate: "candidate".to_owned(),
                    sdp_mid: Some("0".to_owned()),
                    sdp_m_line_index: Some(0),
                },
            )
            .unwrap();
        manager
            .update_state(&call.call_id, CallState::Connected)
            .unwrap();

        let call = manager.call(&call.call_id).unwrap();
        assert_eq!(call.state, CallState::Connected);
        assert_eq!(call.ice_candidates.len(), 1);
    }

    #[test]
    fn webrtc_joins_conference_and_controls_tracks() {
        let mut manager = WebRtcManager::new();
        let call =
            manager.create_offer(Realm(), did("alice"), BTreeSet::from([did("bob")]), "offer");
        manager
            .join_conference(&call.call_id, "conf1", ConferenceMode::Sfu, did("alice"))
            .unwrap();
        manager
            .set_track(
                &call.call_id,
                MediaTrack {
                    track_id: "audio1".to_owned(),
                    kind: MediaTrackKind::Audio,
                    enabled: true,
                },
            )
            .unwrap();
        manager
            .set_track_enabled(&call.call_id, "audio1", false)
            .unwrap();
        manager.set_screen_sharing(&call.call_id, true).unwrap();

        let call = manager.call(&call.call_id).unwrap();
        assert!(call.screen_sharing);
        assert!(!call.tracks["audio1"].enabled);
        assert_eq!(call.conference.as_ref().unwrap().mode, ConferenceMode::Sfu);
    }

    #[test]
    fn webrtc_manages_stun_and_turn_servers() {
        let mut manager = WebRtcManager::new();
        manager.add_ice_server(IceServer {
            kind: IceServerKind::Stun,
            urls: vec!["stun:stun.example.com".to_owned()],
            username: None,
            credential: None,
        });
        manager.add_ice_server(IceServer {
            kind: IceServerKind::Turn,
            urls: vec!["turn:turn.example.com".to_owned()],
            username: Some("user".to_owned()),
            credential: Some("pass".to_owned()),
        });

        assert_eq!(manager.stun_servers().len(), 1);
        assert_eq!(manager.turn_servers().len(), 1);
    }

    fn ice_outcome(kid: &str) -> MediaIceConfigOutcome {
        MediaIceConfigOutcome {
            realm_id: Realm(),
            call_id: "ck:call:0196441c-0000-7000-8000-000000000000".to_owned(),
            actor_id: did("alice"),
            device_id: crate::DeviceId::new("ck:device:01904100-0000-7000-8000-000000000005")
                .unwrap(),
            ice_servers: vec![
                serde_json::json!({ "urls": ["stun:stun.example.com"] }),
                serde_json::json!({
                    "urls": ["turn:turn.example.com"],
                    "username": "1718000000:rand",
                    "credential": "secret"
                }),
            ],
            ttl_seconds: 300,
            refresh_lead_seconds: 60,
            issued_at: "2026-05-27T12:29:56Z".parse().unwrap(),
            issued_at_bucket: "2026-05-27T12:25:00Z".parse().unwrap(),
            bucket_seconds: 300,
            expires_at: None,
            force_turn: false,
            signature: serde_json::json!({
                "alg": "EdDSA",
                "kid": kid,
                "sig": "AAAA"
            }),
        }
    }

    #[test]
    fn ice_config_verifies_parses_and_classifies_servers() {
        let anchors = MediaServiceAnchors::new([did("media")]);
        let outcome = ice_outcome("did:web:media.example#media-ice");
        let config = verify_ice_config_outcome(&outcome, &anchors).unwrap();

        assert_eq!(config.issuer_did, did("media"));
        assert_eq!(config.ttl_seconds, 300);
        assert_eq!(config.stun_servers().count(), 1);
        assert_eq!(config.turn_servers().count(), 1);
        assert!(!config.force_turn);
    }

    #[test]
    fn ice_config_rejects_unanchored_issuer_and_bad_ttl() {
        let anchors = MediaServiceAnchors::new([did("media")]);

        let stranger = ice_outcome("did:web:evil.example#media-ice");
        let err = verify_ice_config_outcome(&stranger, &anchors).unwrap_err();
        assert!(err.to_string().contains("ice_config_denied"));

        let mut bad_ttl = ice_outcome("did:web:media.example#media-ice");
        bad_ttl.refresh_lead_seconds = bad_ttl.ttl_seconds;
        assert!(verify_ice_config_outcome(&bad_ttl, &anchors).is_err());
    }

    #[test]
    fn ice_config_rejects_turn_credential_leaking_did() {
        let anchors = MediaServiceAnchors::new([did("media")]);
        let mut leaky = ice_outcome("did:web:media.example#media-ice");
        leaky.ice_servers[1] = serde_json::json!({
            "urls": ["turn:turn.example.com"],
            "username": "did:web:alice.example",
            "credential": "secret"
        });
        assert!(verify_ice_config_outcome(&leaky, &anchors).is_err());
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
        let mut both = offer.clone();
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
                crate::DeviceId::new("ck:device:01964137-0000-7000-8000-000000000000").unwrap(),
            ),
        };
        moderator.validate().unwrap();

        // moderator without target is invalid; self with target is invalid.
        let mut bad_mod = moderator.clone();
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
        let value = serde_json::to_value(&speaking).unwrap();
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
            call_id: crate::CallId::new("ck:call:0196441c-0000-7000-8000-000000000000").unwrap(),
            action: ModerationAction::Mute,
            moderate_capability_ref: "ck:grant:01".to_owned(),
            target_actor_id: Some(did("bob")),
            target_device_id: None,
        };
        mute.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&mute).unwrap()["action"],
            serde_json::json!("mute")
        );

        let mut no_target = mute.clone();
        no_target.target_actor_id = None;
        assert!(no_target.validate().is_err());

        let end_for_all = ModeratePayload {
            call_id: crate::CallId::new("ck:call:0196441c-0000-7000-8000-000000000000").unwrap(),
            action: ModerationAction::EndForAll,
            moderate_capability_ref: "ck:grant:01".to_owned(),
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
            call_id: crate::CallId::new("ck:call:0196441c-0000-7000-8000-000000000000").unwrap(),
            recording_id: "rtc-recording-1".to_owned(),
            recording_agent: did("recorder"),
            mode: RecordingMode::AudioVideo,
            recording_initiator_capability_ref: Some("ck:grant:rec".to_owned()),
        };
        let value = serde_json::to_value(&start).unwrap();
        assert_eq!(value["mode"], "audio_video");
        assert_eq!(value["recording_id"], "rtc-recording-1");
        let back: RecordingStartPayload = serde_json::from_value(value).unwrap();
        assert_eq!(back, start);

        let transcribe = TranscribePayload {
            call_id: start.call_id.clone(),
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
            recording_start_event_id: "ck:event:01".to_owned(),
            content_digest: Some("sha256:abcd".to_owned()),
            media_type: Some("video/webm".to_owned()),
            duration_seconds: Some(120),
            retention_policy: None,
        };
        assert_eq!(
            serde_json::to_value(&result).unwrap()["recording_start_event_id"],
            "ck:event:01"
        );
    }

    #[test]
    fn webrtc_builds_to_device_signaling_messages() {
        let offer =
            WebRtcSignalMessage::offer(Realm(), "call1", did("alice"), did("bob"), "offer-sdp");
        let answer =
            WebRtcSignalMessage::answer(Realm(), "call1", did("bob"), did("alice"), "answer-sdp");
        let ice = WebRtcSignalMessage::ice_candidate(
            Realm(),
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
