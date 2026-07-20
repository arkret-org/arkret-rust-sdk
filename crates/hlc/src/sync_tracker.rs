//! Incremental-synchronization position tracker.
//!
//! [`SyncTracker`] is a small client-side runtime helper that couples the
//! issuing-service [`Cursor`] surface with per-service sync tokens. It lives
//! next to the [`cursor`](crate::cursor) family it depends on. Migrated out of
//! `arkret-core` (core-retirement batch 2): the previous `update` method bound
//! the `AccountSubscribeBatch` wire model owned by `arkret-models-collaboration`
//! — an edge that would invert the layering (`hlc -> models-collaboration` is
//! not an allowed edge). Since the tracker only ever records the batch's cursor
//! value, `update` now takes that value directly, which removes the model
//! coupling without any behavior change.

use std::collections::HashMap;

use crate::Result;
use crate::cursor::{Cursor, SyncPositions};

/// Sync positions for tracking incremental synchronization.
#[derive(Clone, Debug, Default)]
pub struct SyncTracker {
    /// Current sync positions.
    pub positions: SyncPositions,
    /// Received sync tokens for different services.
    pub sync_tokens: HashMap<String, String>,
}

impl SyncTracker {
    /// Create a new sync tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the default sync cursor after accepting an account-subscribe
    /// batch. Callers pass the batch's `cursor` value directly.
    pub fn update(&mut self, cursor: impl Into<String>) -> Result<()> {
        self.sync_tokens.insert("default".to_owned(), cursor.into());

        Ok(())
    }

    /// Get the current cursor for resuming sync.
    pub fn current_cursor(&self) -> Result<Cursor> {
        Cursor::from_positions(self.positions.clone())
            .map_err(|error| crate::HlcError::Protocol(error.to_string()))
    }

    /// Clear all tracked positions.
    pub fn clear(&mut self) {
        self.positions.realms.clear();
        self.positions.devices = None;
    }
}
