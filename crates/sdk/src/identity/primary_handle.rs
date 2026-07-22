//! R3.2 (arkret-spec @ b56cab1) — §3.2.1 primary handle selection,
//! `claim_digest(c)`, and §3.8.2 mention rendering.
//!
//! The authoritative, wasm-safe implementation lives in
//! `arkret-models-identity` so wasm-only consumers can depend on the owner
//! directly without pulling the SDK's native-only client / keystore / salvo /
//! MLS dependencies. This module is a thin re-export so the existing
//! `arkret::identity::*` API surface is unchanged.

pub use arkret_models_identity::primary_handle::{
    DidDocumentSnapshotResolver, MentionRender, NoHolderPreferenceResolver,
    PrimaryHandleSelectInput, SubjectRender, claim_digest, render_mention, render_subject,
    select_primary_handle, select_primary_handle_string,
};
