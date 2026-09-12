//! Device-signed Seal construction for a self principal-control Realm: the
//! rooted bootstrap Seal and its verified successor histories.

use std::collections::BTreeSet;

use arkret_state::control_event_set_root;
use arkret_wire::{
    ActorId, CommandResult, Did, Event, Hash, Hlc, PayloadSigner, Result, Seal, UnsignedSeal,
    WireError, project_did_to_core_id,
};
use serde_json::Value;

use crate::projection::{CellWriteProjector, state_root_and_effects_from_projection};
use crate::self_principal::validate_self_principal_pcr_genesis_unit;

const SELF_PRINCIPAL_PCR_DIGEST_SUITE: arkret_canonical::DigestSuite =
    arkret_canonical::DigestSuite::Sha256;

fn signer_projects_to_actor(signer: &Did, actor_id: &ActorId) -> Result<bool> {
    Ok(project_did_to_core_id(signer)? == *actor_id.signing_principal_id())
}

/// Build and sign the first principal-control Seal after the closed bootstrap
/// unit has been accepted. The Seal is rooted (no predecessors), covers both
/// bootstrap Event digests, and reproduces the receiver's derived Realm
/// create/member/notary cell state before the authorized device signs it.
pub fn build_self_principal_bootstrap_seal<S: PayloadSigner + ?Sized>(
    create: &Event,
    authorize: &Event,
    hlc: Hlc,
    signer: &S,
    project: CellWriteProjector<'_>,
) -> Result<Seal> {
    validate_self_principal_pcr_genesis_unit(create, authorize, project)?;
    if !signer_projects_to_actor(signer.signer_did(), &create.actor_id)? {
        return Err(WireError::Protocol(
            "bootstrap Seal signer DID must equal the principal DID".to_owned(),
        ));
    }

    let create_digest =
        Hash::new(create.event_digest_with_digest_suite(SELF_PRINCIPAL_PCR_DIGEST_SUITE)?)?;
    let authorize_digest =
        Hash::new(authorize.event_digest_with_digest_suite(SELF_PRINCIPAL_PCR_DIGEST_SUITE)?)?;
    let covered = [create_digest.clone(), authorize_digest.clone()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if covered.len() != 2 {
        return Err(WireError::Protocol(
            "bootstrap Event digests must be distinct".to_owned(),
        ));
    }
    let delta = covered.iter().cloned().collect::<Vec<_>>();
    let (state_root, effects) = self_principal_bootstrap_state_root(create, authorize, project)?;
    let control_root = control_event_set_root(&covered, SELF_PRINCIPAL_PCR_DIGEST_SUITE)
        .map_err(|error| WireError::Protocol(format!("bootstrap Seal coverage root: {error}")))?;
    let command_results = vec![CommandResult::committed(
        create_digest.clone(),
        vec![create_digest, authorize_digest],
        effects,
        SELF_PRINCIPAL_PCR_DIGEST_SUITE,
    )?];
    Seal::sign_with_signers(
        UnsignedSeal {
            realm_id: create.realm_id.clone(),
            predecessor_ref: None,
            delta: delta.clone(),
            control_event_set_root: control_root,
            state_root,
            notary_seq: 0,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: delta,
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: chrono::Utc::now(),
            hlc,
            configuration_ref: create.event_id.clone(),
            command_results,
            authorization_closures: Vec::new(),
            existence_anchors: Vec::new(),
            transaction_records: Vec::new(),
        },
        0,
        SELF_PRINCIPAL_PCR_DIGEST_SUITE,
        &[signer],
    )
}

fn self_principal_bootstrap_state_root(
    create: &Event,
    authorize: &Event,
    project: CellWriteProjector<'_>,
) -> Result<(Hash, Vec<arkret_wire::CommandResultEffect>)> {
    let create_digest =
        Hash::new(create.event_digest_with_digest_suite(SELF_PRINCIPAL_PCR_DIGEST_SUITE)?)?;
    let authorize_digest =
        Hash::new(authorize.event_digest_with_digest_suite(SELF_PRINCIPAL_PCR_DIGEST_SUITE)?)?;
    if create_digest == authorize_digest {
        return Err(WireError::Protocol(
            "bootstrap Event digests must be distinct".to_owned(),
        ));
    }
    let object = create
        .payload
        .get("object")
        .and_then(Value::as_object)
        .ok_or_else(|| WireError::Protocol("bootstrap Realm object is missing".to_owned()))?;
    // `created_by` is reducer-derived from the signed create envelope's
    // `actor_id`; it is not repeated in the closed Realm genesis payload.
    // Requiring a payload echo here would make the seal builder reject the
    // canonical wire shape (and would reintroduce two competing authorities).
    if !object.contains_key("notary") {
        return Err(WireError::Protocol(
            "bootstrap Realm notary is missing".to_owned(),
        ));
    }

    // Both bootstrap Events are in the Seal `delta`, so both contribute their
    // derived writes. Omitting the authorize Event would leave the device
    // authorization cell out of the root that `apply_seal` step 11 compares
    // byte-for-byte.
    state_root_and_effects_from_projection(
        &create.realm_id,
        &[(create, create_digest), (authorize, authorize_digest)],
        SELF_PRINCIPAL_PCR_DIGEST_SUITE,
        project,
    )
}
