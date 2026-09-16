//! Arkret v1 authority-commit state runtime.
//!
//! Shared state is produced by typed domain reducers after the current Realm
//! governance Station appends an authority-signed [`arkret_wire::RealmCommit`].
//! A Realm, each Circle, and each Sidecar have separate linear streams; this
//! crate exposes no Seal, Cell, CRDT, fork-resolution, or cross-stream ordering
//! APIs.

mod commit_log;

pub use commit_log::*;
