//! Closed plaintext carried by encrypted `ak.call.signal` envelopes.

use arkret_wire::{CallId, DeviceId, Did, Error, NonEmptyString, Result, canonical};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallSignalPlaintextKind {
    #[serde(rename = "ak.call.signal")]
    CallSignal,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallSignalKind {
    Invite,
    Answer,
    Candidate,
    Reject,
    Hangup,
    Renegotiate,
    MuteState,
    MediaState,
    Speaking,
    FocusJoin,
    FocusLeave,
    Moderation,
    Error,
    Ack,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallMode {
    P2p,
    Mesh,
    Sfu,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionDescriptionType {
    Offer,
    Answer,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionDescription {
    #[serde(rename = "type")]
    pub sdp_type: SessionDescriptionType,
    pub sdp: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMediaSelection {
    pub audio: bool,
    pub video: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screen: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInviteSignalData {
    pub lifetime_ms: u64,
    pub mode: CallMode,
    pub offer: SessionDescription,
    pub media: CallMediaSelection,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallAnswerSignalData {
    pub answer: SessionDescription,
    pub accepted_media: CallMediaSelection,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp_m_line_index: Option<u32>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCandidateSignalData {
    pub candidates: Vec<IceCandidate>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallEndSignalData {
    pub reason: NonEmptyString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenegotiationReason {
    AddTrack,
    RemoveTrack,
    CodecChange,
    IceRestart,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRenegotiateSignalData {
    pub reason: RenegotiationReason,
    pub ice_restart: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer: Option<SessionDescription>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<SessionDescription>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<CallMediaSelection>,
}

impl CallRenegotiateSignalData {
    pub fn validate(&self) -> Result<()> {
        if self.offer.is_some() == self.answer.is_some() {
            return Err(Error::Protocol(
                "renegotiate data requires exactly one of offer or answer".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MuteChangedBy {
    #[serde(rename = "self")]
    SelfActor,
    Moderator,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMuteStateSignalData {
    pub audio_muted: bool,
    pub video_muted: bool,
    #[serde(rename = "by")]
    pub changed_by: MuteChangedBy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<DeviceId>,
}

impl CallMuteStateSignalData {
    pub fn validate(&self) -> Result<()> {
        let has_target = self.target_actor_id.is_some() && self.target_device_id.is_some();
        if (self.changed_by == MuteChangedBy::Moderator) != has_target {
            return Err(Error::Protocol(
                "moderator mute requires target_actor_id and target_device_id; self mute forbids them"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenMediaState {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub with_audio: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMediaStateSignalData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screen: Option<ScreenMediaState>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSpeakingSignalData {
    pub speaking: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_level: Option<f64>,
}

impl CallSpeakingSignalData {
    pub fn validate(&self) -> Result<()> {
        if self
            .audio_level
            .is_some_and(|level| !(0.0..=1.0).contains(&level))
        {
            return Err(Error::Protocol(
                "speaking audio_level must be within 0.0..=1.0".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallFocusSignalData {
    pub focus_id: NonEmptyString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallModerationAction {
    Kick,
    Ban,
    EndForAll,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallModerationSignalData {
    pub action: CallModerationAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
}

impl CallModerationSignalData {
    pub fn validate(&self) -> Result<()> {
        let needs_target = self.action != CallModerationAction::EndForAll;
        let has_target = self.target_actor_id.is_some()
            && (self.action == CallModerationAction::Ban || self.target_device_id.is_some());
        if needs_target != has_target {
            return Err(Error::Protocol(
                "kick/ban moderation requires its target; end_for_all forbids a target".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallErrorSignalData {
    pub code: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallAckSignalData {
    pub acknowledged_seq: u64,
}

/// Closed binding between `signal_kind` and the corresponding `data` shape.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "signal_kind", content = "data", rename_all = "snake_case")]
pub enum CallSignalData {
    Invite(CallInviteSignalData),
    Answer(CallAnswerSignalData),
    Candidate(CallCandidateSignalData),
    Reject(CallEndSignalData),
    Hangup(CallEndSignalData),
    Renegotiate(CallRenegotiateSignalData),
    MuteState(CallMuteStateSignalData),
    MediaState(CallMediaStateSignalData),
    Speaking(CallSpeakingSignalData),
    FocusJoin(CallFocusSignalData),
    FocusLeave(CallFocusSignalData),
    Moderation(CallModerationSignalData),
    Error(CallErrorSignalData),
    Ack(CallAckSignalData),
}

impl CallSignalData {
    pub const fn kind(&self) -> CallSignalKind {
        match self {
            Self::Invite(_) => CallSignalKind::Invite,
            Self::Answer(_) => CallSignalKind::Answer,
            Self::Candidate(_) => CallSignalKind::Candidate,
            Self::Reject(_) => CallSignalKind::Reject,
            Self::Hangup(_) => CallSignalKind::Hangup,
            Self::Renegotiate(_) => CallSignalKind::Renegotiate,
            Self::MuteState(_) => CallSignalKind::MuteState,
            Self::MediaState(_) => CallSignalKind::MediaState,
            Self::Speaking(_) => CallSignalKind::Speaking,
            Self::FocusJoin(_) => CallSignalKind::FocusJoin,
            Self::FocusLeave(_) => CallSignalKind::FocusLeave,
            Self::Moderation(_) => CallSignalKind::Moderation,
            Self::Error(_) => CallSignalKind::Error,
            Self::Ack(_) => CallSignalKind::Ack,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Renegotiate(data) => data.validate(),
            Self::MuteState(data) => data.validate(),
            Self::Speaking(data) => data.validate(),
            Self::Moderation(data) => data.validate(),
            _ => Ok(()),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CallSignalPlaintext {
    pub kind: CallSignalPlaintextKind,
    /// Signal-rail dedupe component, third member of the
    /// `(sender_device_id, scope_ref, payload_sequence)` triple
    /// (`sync/signal.md` §1.1).
    ///
    /// It coexists with [`Self::seq`] and neither may be omitted: `seq` is the
    /// per-call anti-rollback sequence monotonic over
    /// `(realm_id, call_id, actor_id, device_id)`, while this one is monotonic
    /// per sender device and signed scope across every Signal the device sends.
    /// Substituting one for the other degrades the receiver dedupe triple.
    pub payload_sequence: u64,
    pub call_id: CallId,
    pub seq: u64,
    #[serde(flatten)]
    pub signal: CallSignalData,
}

#[derive(Deserialize)]
struct CallSignalPlaintextWire {
    kind: CallSignalPlaintextKind,
    payload_sequence: u64,
    call_id: CallId,
    seq: u64,
    #[serde(flatten)]
    signal: CallSignalData,
}

impl<'de> Deserialize<'de> for CallSignalPlaintext {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("call signal plaintext must be an object"))?;
        const FIELDS: [&str; 6] = [
            "kind",
            "payload_sequence",
            "call_id",
            "signal_kind",
            "seq",
            "data",
        ];
        if object.len() != FIELDS.len()
            || object.keys().any(|field| !FIELDS.contains(&field.as_str()))
        {
            return Err(serde::de::Error::custom(
                "call signal plaintext contains an unknown field",
            ));
        }
        let wire: CallSignalPlaintextWire =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        let CallSignalPlaintextWire {
            kind: CallSignalPlaintextKind::CallSignal,
            payload_sequence,
            call_id,
            seq,
            signal,
        } = wire;
        Self::new(payload_sequence, call_id, seq, signal).map_err(serde::de::Error::custom)
    }
}

impl CallSignalPlaintext {
    pub fn new(
        payload_sequence: u64,
        call_id: CallId,
        seq: u64,
        signal: CallSignalData,
    ) -> Result<Self> {
        signal.validate()?;
        Ok(Self {
            kind: CallSignalPlaintextKind::CallSignal,
            payload_sequence,
            call_id,
            seq,
            signal,
        })
    }

    pub fn from_plaintext(bytes: &[u8]) -> Result<Self> {
        let plaintext: Self = canonical::from_canonical_json_slice(bytes)?;
        plaintext.signal.validate()?;
        Ok(plaintext)
    }

    pub fn canonical_plaintext(&self) -> Result<Vec<u8>> {
        self.signal.validate()?;
        canonical::canonical_json_bytes(self)
            .map_err(|error| Error::Protocol(format!("call signal plaintext: {error}")))
    }

    pub const fn signal_kind(&self) -> CallSignalKind {
        self.signal.kind()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn call_id() -> CallId {
        CallId::new("ak:call:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()
    }

    #[test]
    fn call_signal_plaintext_is_closed_and_requires_data() {
        let valid = json!({
            "kind": "ak.call.signal",
            "payload_sequence": 11,
            "call_id": call_id(),
            "signal_kind": "candidate",
            "seq": 3,
            "data": {"candidates": [{"candidate": "opaque"}]}
        });
        let decoded: CallSignalPlaintext = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(decoded.seq, 3);
        // The two sequences are independent axes; carrying one is not carrying
        // the other.
        assert_eq!(decoded.payload_sequence, 11);
        assert_eq!(decoded.signal_kind(), CallSignalKind::Candidate);

        let mut missing_data = valid.clone();
        missing_data.as_object_mut().unwrap().remove("data");
        assert!(serde_json::from_value::<CallSignalPlaintext>(missing_data).is_err());

        for required in ["payload_sequence", "seq"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<CallSignalPlaintext>(missing).is_err(),
                "{required} must not be omissible"
            );
        }

        let mut extra = valid;
        extra["actor_id"] = json!("did:webvh:z6mkfixture:alice.example");
        assert!(serde_json::from_value::<CallSignalPlaintext>(extra).is_err());
    }
}
