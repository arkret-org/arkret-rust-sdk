//! Arkret v1 MLS behavior over OpenMLS.
//!
//! The crate owns member-held MLS state, Genesis/Commit processing, live
//! Signal encryption and authority-issued Welcome delivery consumption. It
//! does not expose prior-epoch keys or implement a network recovery
//! protocol.

mod error;
mod group;
mod identity;
mod message;
mod public_group_state;
mod recovery;
mod signal;

pub use arkret_policy::{
    AgentMlsLeafBindingError, AgentMlsSignerClaim, AgentMlsSignerView, AuthorGroupStateView,
    AuthorLeaf, AuthorLeafCredential, MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS,
    MinimalMetadataAuthorClaim, MinimalMetadataAuthorError, MinimalMetadataAuthorViolation,
    VerifiedAuthorLeaf, minimal_metadata_epoch_overdue, minimal_metadata_max_epoch_lifetime,
    verify_minimal_metadata_author, verify_ordinary_agent_mls_binding,
};
pub use error::MlsError;
pub(crate) use error::Result;
pub use group::*;
pub use identity::*;
pub use message::*;
pub use public_group_state::*;
pub use recovery::*;
pub use signal::*;

pub const ARKRET_MLS_ALGORITHM: &str = "ak.mls.v1";
