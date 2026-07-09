//! R3.2 (arkret-spec @ b56cab1) — §3.2.1 primary handle selection,
//! `claim_digest(c)`, and §3.8.2 mention rendering.
//!
//! The authoritative, wasm-safe implementation now lives in
//! `arkret-core` (`arkret_core::identity::primary_handle`) so wasm-only
//! consumers (e.g. sodmin) can depend on it directly without pulling the
//! SDK's native-only client / keystore / salvo / MLS dependencies
//! (SOD-05-001 / SPEC-CR-019). This module is a thin re-export so the
//! existing `arkret::identity::*` API surface is unchanged.

pub use arkret_core::identity::primary_handle::{
    DidDocumentSnapshotResolver, MentionRender, NoHolderPreferenceResolver,
    PrimaryHandleSelectInput, SubjectRender, claim_digest, render_mention, render_subject,
    select_primary_handle, select_primary_handle_string,
};
