//! Request-aware validation for account and Event subscription frame traces.
//!
//! The protocol-invariant validator, trait, and error family migrated to
//! `arkret-models-collaboration` (`sync_frames::stream_trace`, re-exported
//! below, together with the [`StreamTraceFrame`] impl for the
//! [`EventsSubscribeFrame`] HTTP body DTO). This module keeps the bridge
//! into the unified SDK [`Error`].

pub use arkret_models_collaboration::sync_frames::stream_trace::{
    StreamTraceError, StreamTraceFrame, StreamTraceFrameKind, StreamTraceUpdate,
    StreamTraceValidator,
};

use crate::Error;

impl From<StreamTraceError> for Error {
    fn from(error: StreamTraceError) -> Self {
        Self::Protocol(format!("stream trace {}: {error}", error.violation()))
    }
}
