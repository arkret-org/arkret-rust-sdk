//! RFC 9420 validation for externally supplied public epoch state.

use arkret_canonical::base64url_encode;
use arkret_models_crypto::MlsSecurityFrontierLeaf;
use openmls::prelude::{
    MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProposalStore, PublicGroup, RatchetTreeIn,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize as TlsDeserializeTrait;

use crate::identity::decode_leaf_credential;
use crate::{MlsError as Error, Result};

/// Validate an MLSMessage carrying GroupInfo together with the exact external
/// ratchet tree, then return occupied leaves with their real tree indices.
///
/// `PublicGroup::from_external` verifies the GroupInfo signature, ratchet-tree
/// node semantics, tree hash, MLS version, leaf-node validity, and uniqueness
/// constraints. No leaves or tree bytes are accepted from a governance proof
/// bundle; callers obtain these two byte strings only from the typed standard
/// group-state-material operation after its content-address checks pass.
pub fn validate_public_group_state(
    group_info_bytes: &[u8],
    ratchet_tree_bytes: &[u8],
    expected_mls_group_id: &str,
    expected_epoch: u64,
) -> Result<Vec<MlsSecurityFrontierLeaf>> {
    let message = MlsMessageIn::tls_deserialize_exact(group_info_bytes).map_err(mls_error)?;
    let MlsMessageBodyIn::GroupInfo(group_info) = message.extract() else {
        return Err(Error::Protocol(
            "MLS group_info bytes do not contain an RFC 9420 GroupInfo message".to_owned(),
        ));
    };
    if base64url_encode(group_info.group_id().as_slice()) != expected_mls_group_id {
        return Err(Error::Protocol(
            "MLS GroupInfo group_id does not match accepted genesis".to_owned(),
        ));
    }
    if group_info.epoch().as_u64() != expected_epoch {
        return Err(Error::Protocol(
            "MLS GroupInfo epoch does not match accepted genesis".to_owned(),
        ));
    }

    let ratchet_tree =
        RatchetTreeIn::tls_deserialize_exact(ratchet_tree_bytes).map_err(mls_error)?;
    let provider = OpenMlsRustCrypto::default();
    let (public_group, _) = PublicGroup::from_external(
        provider.crypto(),
        provider.storage(),
        ratchet_tree,
        group_info,
        ProposalStore::new(),
    )
    .map_err(mls_error)?;

    let mut leaves = public_group
        .members()
        .map(|member| {
            let (principal_id, credential_ref) =
                decode_leaf_credential(member.credential.serialized_content())?;
            Ok(MlsSecurityFrontierLeaf {
                leaf_index: member.index.u32(),
                principal_id,
                credential_ref,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    leaves.sort_by_key(|leaf| leaf.leaf_index);
    if leaves.is_empty() {
        return Err(Error::Protocol(
            "MLS public group state contains no occupied leaves".to_owned(),
        ));
    }
    Ok(leaves)
}

fn mls_error(error: impl std::fmt::Debug) -> Error {
    Error::Protocol(format!(
        "MLS public group-state validation failed: {error:?}"
    ))
}
