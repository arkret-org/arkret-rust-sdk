//! DID, DID document and handle management.
//!
//! The DID/handle/control-proof/resolver behavior now lives in the standalone
//! `arkret-identity` crate; this module re-exports it so `arkret::identity::*`
//! is unchanged for downstream consumers. The state-bootstrap assembly
//! (`bootstrap`) stays here because it drives the `lattice_registry` /
//! `RealmState` cell-registry, which `arkret-identity` must not depend on.

pub use arkret_bootstrap as bootstrap;
/// R3.2 primary-handle selection / claim-digest / mention rendering. Stays in
/// `arkret-core` (`arkret_core::identity::primary_handle`) because its
/// `HandleClaim` input is owned by `arkret-models-collaboration`, outside the
/// `arkret-identity` allowed-edge set; this thin module keeps the historical
/// `arkret::identity::primary_handle` path stable.
pub mod primary_handle;

pub use arkret_bootstrap::*;
pub use arkret_identity::*;
pub use primary_handle::{
    DidDocumentSnapshotResolver, MentionRender, NoHolderPreferenceResolver,
    PrimaryHandleSelectInput, SubjectRender, claim_digest, render_mention, render_subject,
    select_primary_handle, select_primary_handle_string,
};
