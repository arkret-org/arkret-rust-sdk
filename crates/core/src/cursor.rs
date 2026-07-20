//! Cursor facade retained by `arkret-core`.
//!
//! The issuing-service cursor surface ([`Cursor`], handle generation, TTL
//! validation, [`SyncPositions`]) migrated to the `arkret-hlc` behavior
//! crate — it is a clock/entropy-backed protocol value generator of the
//! same nature as the HLC generator. [`SyncTracker`] migrated there too
//! (core-retirement batch 2): it is the natural neighbour of the cursor
//! family, and its former `AccountSubscribeBatch` coupling was reduced to a
//! plain cursor value so the move stays within the `hlc -> wire` edge set.

pub use arkret_hlc::cursor::{
    CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, RealmSyncPosition, SyncPositions,
    generate_cursor_handle,
};
pub use arkret_hlc::sync_tracker::SyncTracker;
