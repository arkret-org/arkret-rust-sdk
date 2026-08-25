//! RFC 9420 validation for externally supplied public epoch state.

use arkret_canonical::base64url_encode;
use arkret_models_crypto::{MLS_GOVERNANCE_BINDING_EXTENSION_TYPE, MlsGovernanceBindingPayload};
use arkret_wire::NonEmptyString;
use openmls::prelude::{
    MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProposalStore, PublicGroup, RatchetTreeIn,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize as TlsDeserializeTrait;

use crate::identity::{MlsLeafEndpointIdentity, decode_leaf_endpoint_identity};
use crate::{MlsError as Error, Result};

/// Validate an MLSMessage carrying GroupInfo together with the exact external
/// ratchet tree, then return occupied leaves with their real tree indices.
///
/// `PublicGroup::from_external` verifies the GroupInfo signature, ratchet-tree
/// node semantics, tree hash, MLS version, leaf-node validity, and uniqueness
/// constraints. No leaves or tree bytes are accepted from a governance proof
/// bundle; callers obtain these two byte strings only from the typed standard
/// group-state-material operation after its content-address checks pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsPublicEndpointLeaf {
    pub leaf_index: u32,
    pub endpoint_identity: MlsLeafEndpointIdentity,
    pub credential_ref: NonEmptyString,
    pub signature_key: Vec<u8>,
}

pub fn validate_public_group_state(
    group_info_bytes: &[u8],
    ratchet_tree_bytes: &[u8],
    expected_mls_group_id: &str,
    expected_epoch: u64,
) -> Result<Vec<MlsPublicEndpointLeaf>> {
    validate_public_group_state_inner(
        group_info_bytes,
        ratchet_tree_bytes,
        expected_mls_group_id,
        expected_epoch,
        None,
    )
}

/// Validate public MLS state and require the transcript-authenticated Arkret
/// governance binding to equal the binding accepted in the source Event.
pub fn validate_public_group_state_with_governance_binding(
    group_info_bytes: &[u8],
    ratchet_tree_bytes: &[u8],
    expected_mls_group_id: &str,
    expected_epoch: u64,
    expected_governance_binding: &MlsGovernanceBindingPayload,
) -> Result<Vec<MlsPublicEndpointLeaf>> {
    validate_public_group_state_inner(
        group_info_bytes,
        ratchet_tree_bytes,
        expected_mls_group_id,
        expected_epoch,
        Some(expected_governance_binding),
    )
}

fn validate_public_group_state_inner(
    group_info_bytes: &[u8],
    ratchet_tree_bytes: &[u8],
    expected_mls_group_id: &str,
    expected_epoch: u64,
    expected_governance_binding: Option<&MlsGovernanceBindingPayload>,
) -> Result<Vec<MlsPublicEndpointLeaf>> {
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
    if let Some(expected) = expected_governance_binding {
        let encoded = public_group
            .group_context()
            .extensions()
            .unknown(MLS_GOVERNANCE_BINDING_EXTENSION_TYPE)
            .ok_or_else(|| {
                Error::Protocol(
                    "MLS public group state omits the governance binding extension".to_owned(),
                )
            })?;
        let actual = MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded.0)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if &actual != expected {
            return Err(Error::Protocol(
                "MLS GroupContext governance binding does not match accepted genesis".to_owned(),
            ));
        }
    }

    let mut leaves = public_group
        .members()
        .map(|member| {
            let (endpoint_identity, credential_ref) =
                decode_leaf_endpoint_identity(member.credential.serialized_content())?;
            Ok(MlsPublicEndpointLeaf {
                leaf_index: member.index.u32(),
                endpoint_identity,
                credential_ref,
                signature_key: member.signature_key,
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
