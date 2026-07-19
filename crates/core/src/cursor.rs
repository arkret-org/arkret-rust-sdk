//! Cursor facade retained by `arkret-core`.
//!
//! The issuing-service cursor surface ([`Cursor`], handle generation, TTL
//! validation, [`SyncPositions`]) migrated to the `arkret-hlc` behavior
//! crate — it is a clock/entropy-backed protocol value generator of the
//! same nature as the HLC generator. [`SyncTracker`] stays here because it
//! binds the core [`crate::AccountSubscribeBatch`] wire model.

use std::collections::HashMap;

pub use arkret_hlc::cursor::{
    CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, RealmSyncPosition, SyncPositions,
    generate_cursor_handle,
};

use crate::Result;

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

    /// Update the tracker after accepting an account-subscribe batch.
    pub fn update(&mut self, batch: &crate::AccountSubscribeBatch) -> Result<()> {
        self.sync_tokens
            .insert("default".to_owned(), batch.cursor.clone());

        Ok(())
    }

    /// Get the current cursor for resuming sync.
    pub fn current_cursor(&self) -> Result<Cursor> {
        Ok(Cursor::from_positions(self.positions.clone())?)
    }

    /// Clear all tracked positions.
    pub fn clear(&mut self) {
        self.positions.realms.clear();
        self.positions.devices = None;
    }
}
