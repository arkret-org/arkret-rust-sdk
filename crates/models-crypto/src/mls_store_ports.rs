//! Narrow persistence ports for the MLS behavior layer.
//!
//! Dependency-inversion boundary between the MLS group machine
//! (`arkret-mls`, which owns the OpenMLS dependency) and whatever durable
//! crypto store persists its records. The two capabilities the MLS layer needs
//! — sinking a group-state snapshot and sourcing the commit log for a group —
//! are expressed here over the record shapes this crate already owns
//! ([`MlsGroupStateRecord`], [`MlsCommitEnvelope`]).
//!
//! These traits live in `arkret-models-crypto` (not `arkret-mls`) on purpose:
//! the SDK `CryptoStore` binds them as supertraits, and that contract must be
//! expressible by any consumer of the crypto store **without**
//! dragging OpenMLS into the build. The heavier `ArkretMlsGroup` surface stays
//! behind the `mls` feature; these ports carry no OpenMLS dependency.

use arkret_wire::WireError;

use crate::{MlsCommitEnvelope, MlsGroupStateRecord};

/// Sink for the provider-opaque MLS group-state snapshot record.
pub trait MlsGroupStateSink {
    /// Persist (or roll-forward) a group-state snapshot.
    fn put_mls_group_state(&mut self, record: MlsGroupStateRecord) -> Result<(), WireError>;
}

/// Read-only source of the commit log for a group, used to build epoch
/// recovery responses for offline devices.
pub trait MlsCommitSource {
    /// Return every commit envelope retained for `group_id`.
    fn commits_for_group(&self, group_id: &str) -> Vec<&MlsCommitEnvelope>;
}
