//! Request-aware validation for account and Event subscription frame traces.
//!
//! The protocol-invariant validator, trait, and error family migrated to
//! `arkret-models-collaboration` (`sync_frames::stream_trace`, re-exported
//! below, together with the [`StreamTraceFrame`] impl for the
//! [`EventsSubscribeFrame`] HTTP body DTO). This module preserves the
//! transitional Core re-export path only.

pub use arkret_models_collaboration::sync_frames::stream_trace::{
    StreamTraceError, StreamTraceFrame, StreamTraceFrameKind, StreamTraceUpdate,
    StreamTraceValidator,
};
