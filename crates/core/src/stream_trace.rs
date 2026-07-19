//! Request-aware validation for account and Event subscription frame traces.
//!
//! The protocol-invariant validator, trait, and error family migrated to
//! `arkret-models-collaboration` (`sync_frames::stream_trace`, re-exported
//! below). This module keeps the [`StreamTraceFrame`] impl for the core
//! [`EventsSubscribeFrame`] HTTP body DTO and the bridge into the unified
//! SDK [`Error`].

pub use arkret_models_collaboration::sync_frames::stream_trace::{
    StreamTraceError, StreamTraceFrame, StreamTraceFrameKind, StreamTraceUpdate,
    StreamTraceValidator,
};

use crate::{Error, EventsSubscribeFrame, EventsSubscribeFrameKind};

impl StreamTraceFrame for EventsSubscribeFrame {
    fn trace_kind(&self) -> StreamTraceFrameKind {
        match self.kind {
            EventsSubscribeFrameKind::Event => StreamTraceFrameKind::Data,
            EventsSubscribeFrameKind::Frontier => StreamTraceFrameKind::Frontier,
            EventsSubscribeFrameKind::Heartbeat => StreamTraceFrameKind::Heartbeat,
            EventsSubscribeFrameKind::CatchupComplete => StreamTraceFrameKind::CatchupComplete,
            EventsSubscribeFrameKind::EpochRotation => StreamTraceFrameKind::EpochRotation,
            EventsSubscribeFrameKind::Dropped => StreamTraceFrameKind::Dropped,
            EventsSubscribeFrameKind::ResyncRequired => StreamTraceFrameKind::ResyncRequired,
            EventsSubscribeFrameKind::Unauthorized => StreamTraceFrameKind::Unauthorized,
        }
    }

    fn trace_cursor(&self) -> Option<&str> {
        self.cursor.as_ref().map(|cursor| cursor.as_str())
    }
}

impl From<StreamTraceError> for Error {
    fn from(error: StreamTraceError) -> Self {
        Self::Protocol(format!("stream trace {}: {error}", error.violation()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::models::AccountSubscribeFrame;

    const FIXTURE_PATH: &str = "fixtures/sync-fixture.json";

    #[derive(Clone, Copy)]
    enum Surface {
        Account,
        Events,
    }

    enum SurfaceFrame {
        Account(Box<AccountSubscribeFrame>),
        Events(EventsSubscribeFrame),
    }

    impl StreamTraceFrame for SurfaceFrame {
        fn trace_kind(&self) -> StreamTraceFrameKind {
            match self {
                Self::Account(frame) => frame.trace_kind(),
                Self::Events(frame) => frame.trace_kind(),
            }
        }

        fn trace_cursor(&self) -> Option<&str> {
            match self {
                Self::Account(frame) => frame.trace_cursor(),
                Self::Events(frame) => frame.trace_cursor(),
            }
        }
    }

    fn surface_frame(surface: Surface, value: &Value) -> SurfaceFrame {
        match surface {
            Surface::Account => {
                SurfaceFrame::Account(Box::new(serde_json::from_value(value.clone()).unwrap()))
            }
            Surface::Events => {
                let kind = match value["kind"].as_str().unwrap() {
                    "delta" => EventsSubscribeFrameKind::Event,
                    "frontier" => EventsSubscribeFrameKind::Frontier,
                    "heartbeat" => EventsSubscribeFrameKind::Heartbeat,
                    "catchup_complete" => EventsSubscribeFrameKind::CatchupComplete,
                    "dropped" => EventsSubscribeFrameKind::Dropped,
                    "resync_required" => EventsSubscribeFrameKind::ResyncRequired,
                    "unauthorized" => EventsSubscribeFrameKind::Unauthorized,
                    other => panic!("unknown fixture frame kind {other}"),
                };
                SurfaceFrame::Events(EventsSubscribeFrame {
                    kind,
                    realm_id: None,
                    cursor: value["cursor"]
                        .as_str()
                        .map(|cursor| crate::identifiers::Cursor::new(cursor.to_owned()).unwrap()),
                    payload: None,
                    reconnect_after_ms: value["reconnect_after_ms"].as_u64(),
                })
            }
        }
    }

    #[test]
    fn registered_stream_sequence_vector_applies_to_both_surfaces() {
        let fixture = crate::schema::embedded_json_artifact(FIXTURE_PATH).unwrap();
        let vector = &fixture["stream_frame_sequence"];
        assert_eq!(
            vector["vector_id"].as_str(),
            Some("ak.vector.sync.stream_frame_sequence.v1")
        );

        for surface in [Surface::Account, Surface::Events] {
            for case in vector["cases"].as_array().unwrap() {
                let catchup = case["request"]["catchup"].as_bool().unwrap();
                let initial_cursor = case["initial_reconnect_cursor"]
                    .as_str()
                    .map(ToOwned::to_owned);

                if case["name"] == "missing_drop_cursor_uses_resync_required" {
                    let mut rejected = StreamTraceValidator::new(catchup, initial_cursor.clone());
                    let error = rejected
                        .push(&surface_frame(surface, &case["forbidden_frame"]))
                        .unwrap_err();
                    assert_eq!(error.violation(), "dropped_missing_cursor");

                    let mut required = StreamTraceValidator::new(catchup, initial_cursor);
                    let update = required
                        .push(&surface_frame(surface, &case["required_frame"]))
                        .unwrap();
                    assert!(update.terminal);
                    assert!(!update.cursor_advanced);
                    assert!(required.reconnect_cursor().is_none());
                    continue;
                }

                let mut validator = StreamTraceValidator::new(catchup, initial_cursor);
                let mut rejection = None;
                for frame in case["frames"].as_array().unwrap() {
                    if let Err(error) = validator.push(&surface_frame(surface, frame)) {
                        rejection = Some(error);
                        break;
                    }
                }

                if case["expected"]["result"] == "reject" {
                    let error = rejection.expect("invalid trace must be rejected");
                    assert_eq!(
                        error.violation(),
                        case["expected"]["trace_violation"].as_str().unwrap()
                    );
                    assert!(
                        validator
                            .push(&surface_frame(surface, &json!({"kind": "heartbeat"})))
                            .is_err()
                    );
                    continue;
                }

                assert!(rejection.is_none());
                validator.finish().unwrap();
                if let Some(expected_cursor) = case["expected"]["reconnect_after"].as_str() {
                    assert_eq!(validator.reconnect_cursor(), Some(expected_cursor));
                }
                if case["expected"]["reconnect_cursor_advanced"] == false {
                    assert!(validator.reconnect_cursor().is_none());
                }
            }
        }
    }
}
