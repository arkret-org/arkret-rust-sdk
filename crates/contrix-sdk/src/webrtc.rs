//! WebRTC signaling and conference state helpers.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{Did, SpaceId};

/// SDP description type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdpType {
    Offer,
    Answer,
}

/// Session description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDescription {
    pub sdp_type: SdpType,
    pub sdp: String,
}

/// ICE candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCandidate {
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u32>,
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

/// WebRTC call state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebRtcCall {
    pub call_id: String,
    pub space_id: SpaceId,
    pub caller: Did,
    pub callees: BTreeSet<Did>,
    pub state: CallState,
    pub offer: Option<SessionDescription>,
    pub answer: Option<SessionDescription>,
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
        space_id: SpaceId,
        caller: Did,
        callees: BTreeSet<Did>,
        sdp: impl Into<String>,
    ) -> WebRtcCall {
        let call_id = format!("call_{}", Ulid::new());
        let call = WebRtcCall {
            call_id: call_id.clone(),
            space_id,
            caller,
            callees,
            state: CallState::Offering,
            offer: Some(SessionDescription { sdp_type: SdpType::Offer, sdp: sdp.into() }),
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
        call.answer = Some(SessionDescription { sdp_type: SdpType::Answer, sdp: sdp.into() });
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
        self.calls.get_mut(call_id)?.tracks.insert(track.track_id.clone(), track);
        Some(())
    }

    /// Enable or disable a track.
    pub fn set_track_enabled(
        &mut self,
        call_id: &str,
        track_id: &str,
        enabled: bool,
    ) -> Option<()> {
        self.calls.get_mut(call_id)?.tracks.get_mut(track_id)?.enabled = enabled;
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
        self.ice_servers.iter().filter(|server| server.kind == IceServerKind::Stun).collect()
    }

    /// TURN servers.
    pub fn turn_servers(&self) -> Vec<&IceServer> {
        self.ice_servers.iter().filter(|server| server.kind == IceServerKind::Turn).collect()
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

    fn space() -> SpaceId {
        SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap()
    }

    #[test]
    fn webrtc_exchanges_offer_answer_ice_and_state() {
        let mut manager = WebRtcManager::new();
        let call =
            manager.create_offer(space(), did("alice"), BTreeSet::from([did("bob")]), "offer-sdp");
        manager.receive_answer(&call.call_id, "answer-sdp").unwrap();
        manager
            .add_ice_candidate(
                &call.call_id,
                IceCandidate {
                    candidate: "candidate".to_owned(),
                    sdp_mid: Some("0".to_owned()),
                    sdp_mline_index: Some(0),
                },
            )
            .unwrap();
        manager.update_state(&call.call_id, CallState::Connected).unwrap();

        let call = manager.call(&call.call_id).unwrap();
        assert_eq!(call.state, CallState::Connected);
        assert_eq!(call.ice_candidates.len(), 1);
    }

    #[test]
    fn webrtc_joins_conference_and_controls_tracks() {
        let mut manager = WebRtcManager::new();
        let call =
            manager.create_offer(space(), did("alice"), BTreeSet::from([did("bob")]), "offer");
        manager.join_conference(&call.call_id, "conf1", ConferenceMode::Sfu, did("alice")).unwrap();
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
        manager.set_track_enabled(&call.call_id, "audio1", false).unwrap();
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
}
