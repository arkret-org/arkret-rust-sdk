//! Request-aware validation for account and Event subscription frame traces.

use arkret_wire::error_codes::ErrorCode;

use crate::sync_frames::account_subscribe::{AccountSubscribeFrame, AccountSubscribeFrameKind};

/// Shared semantic frame kinds used by both v1 subscription surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamTraceFrameKind {
    Data,
    Frontier,
    Heartbeat,
    CatchupComplete,
    EpochRotation,
    Dropped,
    ResyncRequired,
    Unauthorized,
}

impl StreamTraceFrameKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Frontier => "frontier",
            Self::Heartbeat => "heartbeat",
            Self::CatchupComplete => "catchup_complete",
            Self::EpochRotation => "epoch_rotation",
            Self::Dropped => "dropped",
            Self::ResyncRequired => "resync_required",
            Self::Unauthorized => "unauthorized",
        }
    }

    const fn requires_cursor(self) -> bool {
        matches!(
            self,
            Self::Data | Self::Frontier | Self::CatchupComplete | Self::Dropped
        )
    }

    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Dropped | Self::ResyncRequired | Self::Unauthorized
        )
    }
}

/// Minimal frame view consumed by the common trace validator.
pub trait StreamTraceFrame {
    fn trace_kind(&self) -> StreamTraceFrameKind;
    fn trace_cursor(&self) -> Option<&str>;
}

impl StreamTraceFrame for AccountSubscribeFrame {
    fn trace_kind(&self) -> StreamTraceFrameKind {
        match self.kind {
            AccountSubscribeFrameKind::Delta => StreamTraceFrameKind::Data,
            AccountSubscribeFrameKind::Frontier => StreamTraceFrameKind::Frontier,
            AccountSubscribeFrameKind::Heartbeat => StreamTraceFrameKind::Heartbeat,
            AccountSubscribeFrameKind::CatchupComplete => StreamTraceFrameKind::CatchupComplete,
            AccountSubscribeFrameKind::Dropped => StreamTraceFrameKind::Dropped,
            AccountSubscribeFrameKind::ResyncRequired => StreamTraceFrameKind::ResyncRequired,
            AccountSubscribeFrameKind::Unauthorized => StreamTraceFrameKind::Unauthorized,
        }
    }

    fn trace_cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}

/// A rejected whole-trace invariant. Every variant maps to schema_violation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StreamTraceError {
    #[error("stream frame `{kind}` requires a non-empty cursor")]
    MissingCursor { kind: &'static str },
    #[error("catchup_complete arrived before the first baseline data frame")]
    CatchupCompleteBeforeData,
    #[error("catchup_complete is forbidden when catchup=false")]
    UnexpectedCatchupComplete,
    #[error("stream frame arrived after terminal `{terminal}`")]
    FrameAfterTerminal { terminal: &'static str },
    #[error("stream trace was already rejected")]
    TraceAlreadyRejected,
    #[error("stream ended before catchup_complete")]
    CatchupIncomplete,
}

impl StreamTraceError {
    pub const fn error_code(&self) -> ErrorCode {
        ErrorCode::SchemaViolation
    }

    /// Stable vector diagnostic for the rejected sequence invariant.
    pub fn violation(&self) -> &'static str {
        match self {
            Self::MissingCursor { kind: "dropped" } => "dropped_missing_cursor",
            Self::MissingCursor { .. } => "cursor_required",
            Self::CatchupCompleteBeforeData => "catchup_complete_before_delta",
            Self::UnexpectedCatchupComplete => "unexpected_catchup_complete",
            Self::FrameAfterTerminal { .. } => "frame_after_terminal",
            Self::TraceAlreadyRejected => "trace_already_rejected",
            Self::CatchupIncomplete => "catchup_incomplete",
        }
    }
}

/// Mutation performed by one accepted frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamTraceUpdate {
    pub cursor_advanced: bool,
    pub terminal: bool,
}

/// Common request-aware trace validator for account and Event streams.
#[derive(Clone, Debug)]
pub struct StreamTraceValidator {
    catchup: bool,
    baseline_data_seen: bool,
    catchup_complete_seen: bool,
    reconnect_cursor: Option<String>,
    terminal: Option<StreamTraceFrameKind>,
    rejected: bool,
}

impl StreamTraceValidator {
    pub fn new(catchup: bool, reconnect_cursor: Option<String>) -> Self {
        Self {
            catchup,
            baseline_data_seen: false,
            catchup_complete_seen: false,
            reconnect_cursor,
            terminal: None,
            rejected: false,
        }
    }

    pub fn push<F: StreamTraceFrame + ?Sized>(
        &mut self,
        frame: &F,
    ) -> Result<StreamTraceUpdate, StreamTraceError> {
        let result = self.validate_and_apply(frame);
        if result.is_err() {
            self.rejected = true;
        }
        result
    }

    fn validate_and_apply<F: StreamTraceFrame + ?Sized>(
        &mut self,
        frame: &F,
    ) -> Result<StreamTraceUpdate, StreamTraceError> {
        if self.rejected {
            return Err(StreamTraceError::TraceAlreadyRejected);
        }
        if let Some(terminal) = self.terminal {
            return Err(StreamTraceError::FrameAfterTerminal {
                terminal: terminal.as_str(),
            });
        }

        let kind = frame.trace_kind();
        let cursor = frame
            .trace_cursor()
            .filter(|cursor| !cursor.trim().is_empty());
        if kind.requires_cursor() && cursor.is_none() {
            return Err(StreamTraceError::MissingCursor {
                kind: kind.as_str(),
            });
        }
        if kind == StreamTraceFrameKind::CatchupComplete {
            if !self.catchup {
                return Err(StreamTraceError::UnexpectedCatchupComplete);
            }
            if !self.baseline_data_seen {
                return Err(StreamTraceError::CatchupCompleteBeforeData);
            }
        }

        // A frontier is an explicit server baseline for an empty catch-up.
        // It therefore satisfies the same completion-ordering precondition as
        // a replayed data frame while remaining projection-neutral.
        if matches!(
            kind,
            StreamTraceFrameKind::Data | StreamTraceFrameKind::Frontier
        ) {
            self.baseline_data_seen = true;
        }
        if kind == StreamTraceFrameKind::CatchupComplete {
            self.catchup_complete_seen = true;
        }

        let mut cursor_advanced = false;
        match kind {
            StreamTraceFrameKind::Data
            | StreamTraceFrameKind::Frontier
            | StreamTraceFrameKind::CatchupComplete
            | StreamTraceFrameKind::Dropped => {
                self.reconnect_cursor = cursor.map(ToOwned::to_owned);
                cursor_advanced = true;
            }
            StreamTraceFrameKind::ResyncRequired => self.reconnect_cursor = None,
            StreamTraceFrameKind::Heartbeat
            | StreamTraceFrameKind::EpochRotation
            | StreamTraceFrameKind::Unauthorized => {}
        }
        if kind.is_terminal() {
            self.terminal = Some(kind);
        }

        Ok(StreamTraceUpdate {
            cursor_advanced,
            terminal: kind.is_terminal(),
        })
    }

    pub fn finish(&mut self) -> Result<(), StreamTraceError> {
        if self.rejected {
            return Err(StreamTraceError::TraceAlreadyRejected);
        }
        if self.catchup && !self.catchup_complete_seen && self.terminal.is_none() {
            self.rejected = true;
            return Err(StreamTraceError::CatchupIncomplete);
        }
        Ok(())
    }

    pub fn reconnect_cursor(&self) -> Option<&str> {
        self.reconnect_cursor.as_deref()
    }

    pub const fn baseline_data_seen(&self) -> bool {
        self.baseline_data_seen
    }

    pub const fn catchup_complete_seen(&self) -> bool {
        self.catchup_complete_seen
    }

    pub const fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursorless_controls_never_overwrite_a_saved_position() {
        for kind in [
            StreamTraceFrameKind::Heartbeat,
            StreamTraceFrameKind::EpochRotation,
            StreamTraceFrameKind::Unauthorized,
        ] {
            struct Frame(StreamTraceFrameKind);
            impl StreamTraceFrame for Frame {
                fn trace_kind(&self) -> StreamTraceFrameKind {
                    self.0
                }

                fn trace_cursor(&self) -> Option<&str> {
                    Some("ak:cursor:must-not-advance")
                }
            }

            let mut validator =
                StreamTraceValidator::new(false, Some("ak:cursor:saved".to_owned()));
            let update = validator.push(&Frame(kind)).unwrap();
            assert!(!update.cursor_advanced);
            assert_eq!(validator.reconnect_cursor(), Some("ak:cursor:saved"));
        }
    }

    #[test]
    fn frontier_baseline_allows_empty_catchup_completion() {
        struct Frame(StreamTraceFrameKind, Option<&'static str>);
        impl StreamTraceFrame for Frame {
            fn trace_kind(&self) -> StreamTraceFrameKind {
                self.0
            }

            fn trace_cursor(&self) -> Option<&str> {
                self.1
            }
        }

        let cursor = "ak:cursor:empty-catchup";
        let mut validator = StreamTraceValidator::new(true, Some(cursor.to_owned()));
        validator
            .push(&Frame(StreamTraceFrameKind::Frontier, Some(cursor)))
            .unwrap();
        validator
            .push(&Frame(StreamTraceFrameKind::CatchupComplete, Some(cursor)))
            .unwrap();
        validator.finish().unwrap();
        assert!(validator.baseline_data_seen());
        assert!(validator.catchup_complete_seen());
        assert_eq!(validator.reconnect_cursor(), Some(cursor));
    }
}
