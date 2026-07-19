//! Member-roster wire models.
//!
//! The member-identity segment, payload carrier, and digest helpers live
//! in `arkret-models-identity` (re-exported below). The roster projection
//! entry carried by `account.subscribe` frames lives in
//! `arkret-models-collaboration` (`sync_frames::account_sync`) and reaches
//! the `arkret_core::models` panel through the artifacts shim.

pub use arkret_models_identity::member_identity::*;
