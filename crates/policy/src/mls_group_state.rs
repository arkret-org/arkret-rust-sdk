//! Generic authenticated MLS group-state material used by active admission rules.
//!
//! These types describe a verified historical leaf set. They are intentionally
//! profile-neutral: the retired minimal-metadata Realm profile and its
//! pairwise-author policy no longer exist, while ordinary Agent and
//! identity-link admission still need the exact winning leaf material.

use arkret_wire::MlsGroupId;

/// Credential carried by an active leaf in an [`AuthorGroupStateView`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorLeafCredential {
    /// RFC 9420 BasicCredential; `identity` is the raw credential content.
    Basic { identity: Vec<u8> },
    /// Any non-basic credential type.
    Other { credential_type: String },
}

/// One leaf that is active (present in the ratchet tree) at the view's epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorLeaf {
    pub leaf_index: u32,
    pub credential: AuthorLeafCredential,
    /// The leaf's MLS `signature_key` bytes.
    pub signature_key: Vec<u8>,
    /// Exact RFC 9420 TLS serialization of the active LeafNode.
    pub leaf_node_canonical_bytes: Vec<u8>,
}

/// An already-authenticated historical MLS group-state view.
///
/// The caller is responsible for verifying that `group_state_ref` is the
/// winning state for `epoch` and that `active_leaves` is complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorGroupStateView {
    pub group_id: MlsGroupId,
    pub epoch: u64,
    pub group_state_ref: String,
    pub active_leaves: Vec<AuthorLeaf>,
}
