//! Device-signed Seal construction for a self principal-control Realm: the
//! rooted bootstrap Seal and its three successor shapes.

use std::collections::BTreeSet;

use arkret_models_collaboration::event_sync::RealmSealFrontierView;
use arkret_state::control_event_set_root;
use arkret_wire::{
    Error, Event, EventKind, Hash, Hlc, NotarySig, PayloadSignature, PayloadSigner, Result, Seal,
    SealId, SealKind,
};
use chrono::Utc;
use serde_json::Value;

use crate::projection::{CellWriteProjector, state_root_from_projection};
use crate::self_principal::validate_self_principal_bootstrap_unit;

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
    validate_self_principal_bootstrap_unit(create, authorize, project)?;
    if signer.signer_did() != &create.actor_id {
        return Err(Error::Protocol(
            "bootstrap Seal signer DID must equal the principal DID".to_owned(),
        ));
    }

    let create_digest = Hash::new(create.event_digest()?)?;
    let authorize_digest = Hash::new(authorize.event_digest()?)?;
    let covered = [create_digest, authorize_digest]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if covered.len() != 2 {
        return Err(Error::Protocol(
            "bootstrap Event digests must be distinct".to_owned(),
        ));
    }
    let delta = covered.iter().cloned().collect::<Vec<_>>();
    let state_root = self_principal_bootstrap_state_root(create, authorize, project)?;
    let control_root = control_event_set_root(&covered)
        .map_err(|error| Error::Protocol(format!("bootstrap Seal coverage root: {error}")))?;
    let completeness_root = arkret_state::control_event_completeness_root(
        &[create.clone(), authorize.clone()],
        &covered,
    )
    .map_err(|error| Error::Protocol(format!("bootstrap Seal completeness root: {error}")))?;
    let sealed_at = Utc::now();
    let zero_hash = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))?,
        realm_id: create.realm_id.clone(),
        predecessor_refs: Vec::new(),
        delta: delta.clone(),
        control_event_set_root: control_root,
        state_root,
        completeness_root,
        notary_seq: 0,
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: delta,
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(PayloadSignature {
            verification_method: signer.verification_method_id().clone(),
            payload_digest: zero_hash,
            created_at: sealed_at,
            jws: String::new(),
            extra: Default::default(),
        }),
        sealed_at,
        hlc,
        kind: SealKind::Normal,
    };
    let canonical_bytes = seal.canonical_bytes_for_id()?;
    seal.id = Seal::id_from_canonical_bytes(&canonical_bytes)?;
    seal.notary_signature = NotarySig::Single(signer.sign_payload(&canonical_bytes)?);
    seal.validate_structural()?;
    seal.validate_id()?;
    Ok(seal)
}

/// Build the first device-signed successor Seal for a self principal-control
/// Realm after its closed two-Event bootstrap unit.
///
/// The first recovery-policy `ak.policy.set` is the only persistent write
/// allowed before the first-backup gate is satisfied, so its predecessor must
/// be the exact bootstrap Seal and its notary sequence is necessarily one.
/// The caller supplies the registered projector so the post-state root is
/// byte-identical to receiver replay.
pub fn build_self_principal_first_successor_seal<S: PayloadSigner + ?Sized>(
    create: &Event,
    authorize: &Event,
    successor: &Event,
    predecessor: &RealmSealFrontierView,
    hlc: Hlc,
    signer: &S,
    project: CellWriteProjector<'_>,
) -> Result<Seal> {
    validate_self_principal_bootstrap_unit(create, authorize, project)?;
    if successor.realm_id != create.realm_id
        || successor.actor_id != create.actor_id
        || successor.actor_seq != 2
        || successor.prev_refs != vec![authorize.event_id.clone()]
        || successor.kind != EventKind::POLICY_SET
    {
        return Err(Error::Protocol(
            "self principal first successor must be the actor_seq=2 recovery policy Event"
                .to_owned(),
        ));
    }
    if signer.signer_did() != &create.actor_id {
        return Err(Error::Protocol(
            "self principal successor Seal signer DID must equal the principal DID".to_owned(),
        ));
    }

    let create_digest = Hash::new(create.event_digest()?)?;
    let authorize_digest = Hash::new(authorize.event_digest()?)?;
    let successor_digest = Hash::new(successor.event_digest()?)?;
    let bootstrap_covered = [create_digest.clone(), authorize_digest.clone()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let bootstrap_control_root = control_event_set_root(&bootstrap_covered)
        .map_err(|error| Error::Protocol(format!("bootstrap Seal coverage root: {error}")))?;
    let bootstrap_state_root = self_principal_bootstrap_state_root(create, authorize, project)?;
    if predecessor.realm_id != create.realm_id
        || predecessor.control_event_set_root != bootstrap_control_root
        || predecessor.state_root != bootstrap_state_root
    {
        return Err(Error::Protocol(
            "self principal first successor predecessor is not the accepted bootstrap Seal"
                .to_owned(),
        ));
    }

    let covered = [create_digest, authorize_digest, successor_digest.clone()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if covered.len() != 3 {
        return Err(Error::Protocol(
            "self principal first successor Event digests must be distinct".to_owned(),
        ));
    }
    let state_root = state_root_from_projection(
        &create.realm_id,
        &[
            (create, Hash::new(create.event_digest()?)?),
            (authorize, Hash::new(authorize.event_digest()?)?),
            (successor, successor_digest.clone()),
        ],
        project,
    )?;
    let control_event_set_root = control_event_set_root(&covered).map_err(|error| {
        Error::Protocol(format!("self principal successor coverage root: {error}"))
    })?;
    let events = [create.clone(), authorize.clone(), successor.clone()];
    let completeness_root = arkret_state::control_event_completeness_root(&events, &covered)
        .map_err(|error| {
            Error::Protocol(format!(
                "self principal successor completeness root: {error}"
            ))
        })?;
    let sealed_at = Utc::now();
    let zero_hash = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))?,
        realm_id: create.realm_id.clone(),
        predecessor_refs: vec![predecessor.seal_id.clone()],
        delta: vec![successor_digest],
        control_event_set_root,
        state_root,
        completeness_root,
        notary_seq: 1,
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: covered.into_iter().collect(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(PayloadSignature {
            verification_method: signer.verification_method_id().clone(),
            payload_digest: zero_hash,
            created_at: sealed_at,
            jws: String::new(),
            extra: Default::default(),
        }),
        sealed_at,
        hlc,
        kind: SealKind::Normal,
    };
    let canonical_bytes = seal.canonical_bytes_for_id()?;
    seal.id = Seal::id_from_canonical_bytes(&canonical_bytes)?;
    seal.notary_signature = NotarySig::Single(signer.sign_payload(&canonical_bytes)?);
    seal.validate_structural()?;
    seal.validate_id()?;
    Ok(seal)
}

/// Build a later device-signed Seal for a self principal-control Realm.
///
/// `events` is the complete accepted control history through the desired
/// frontier. The predecessor coverage must be a strict subset of that history;
/// the resulting delta contains every newly accepted Control Move.
pub fn build_self_principal_event_seal<S: PayloadSigner + ?Sized>(
    events: &[Event],
    predecessor: &Seal,
    hlc: Hlc,
    signer: &S,
    project: CellWriteProjector<'_>,
) -> Result<Seal> {
    let first = events
        .first()
        .ok_or_else(|| Error::Protocol("self principal Seal history is empty".to_owned()))?;
    if events
        .iter()
        .any(|event| event.realm_id != first.realm_id || event.actor_id != first.actor_id)
    {
        return Err(Error::Protocol(
            "self principal Seal Events must share one Realm and actor".to_owned(),
        ));
    }
    if signer.signer_did() != &first.actor_id {
        return Err(Error::Protocol(
            "self principal Seal signer DID must equal the principal DID".to_owned(),
        ));
    }
    if predecessor.realm_id != first.realm_id || predecessor.covered_event_digests.is_empty() {
        return Err(Error::Protocol(
            "self principal predecessor has incompatible Realm or coverage".to_owned(),
        ));
    }

    let covered = events
        .iter()
        .map(|event| Ok((event, Hash::new(event.event_digest()?)?)))
        .collect::<Result<Vec<_>>>()?;
    let target = covered
        .iter()
        .map(|(_, digest)| digest.clone())
        .collect::<BTreeSet<_>>();
    let current = predecessor
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !current.is_subset(&target) {
        return Err(Error::Protocol(
            "self principal predecessor coverage is not a subset of the target".to_owned(),
        ));
    }
    let delta = target.difference(&current).cloned().collect::<Vec<_>>();
    if delta.is_empty() {
        return Err(Error::Protocol(
            "self principal Seal has no new Event delta".to_owned(),
        ));
    }

    let control_event_set_root = control_event_set_root(&target)
        .map_err(|error| Error::Protocol(format!("self principal control root: {error}")))?;
    let state_root = state_root_from_projection(&first.realm_id, &covered, project)?;
    let completeness_root = arkret_state::control_event_completeness_root(events, &target)
        .map_err(|error| Error::Protocol(format!("self principal completeness root: {error}")))?;
    let sealed_at = Utc::now();
    let zero_hash = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))?,
        realm_id: first.realm_id.clone(),
        predecessor_refs: vec![predecessor.id.clone()],
        delta,
        control_event_set_root,
        state_root,
        completeness_root,
        notary_seq: predecessor
            .notary_seq
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("self principal notary sequence overflow".to_owned()))?,
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: target.into_iter().collect(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(PayloadSignature {
            verification_method: signer.verification_method_id().clone(),
            payload_digest: zero_hash,
            created_at: sealed_at,
            jws: String::new(),
            extra: Default::default(),
        }),
        sealed_at,
        hlc,
        kind: SealKind::Compaction,
    };
    let canonical_bytes = seal.canonical_bytes_for_id()?;
    seal.id = Seal::id_from_canonical_bytes(&canonical_bytes)?;
    seal.notary_signature = NotarySig::Single(signer.sign_payload(&canonical_bytes)?);
    seal.validate_structural()?;
    seal.validate_id()?;
    Ok(seal)
}

/// Build the next Seal for a linear self-principal control history when the
/// server exposes only its accepted frontier view rather than the full
/// predecessor Seal.
///
/// The final Event is the only new delta. All preceding Events must reproduce
/// the server frontier's cumulative control and state roots exactly.
pub fn build_self_principal_linear_successor_seal<S: PayloadSigner + ?Sized>(
    events: &[Event],
    predecessor: &RealmSealFrontierView,
    hlc: Hlc,
    signer: &S,
    project: CellWriteProjector<'_>,
) -> Result<Seal> {
    if events.len() < 3 {
        return Err(Error::Protocol(
            "self principal linear successor requires preserved history and one new Event"
                .to_owned(),
        ));
    }
    let prior = &events[..events.len() - 1];
    let first = &events[0];
    if events.iter().enumerate().any(|(index, event)| {
        event.realm_id != first.realm_id
            || event.actor_id != first.actor_id
            || event.actor_seq != index as u64
    }) {
        return Err(Error::Protocol(
            "self principal linear history must have one actor and contiguous actor_seq".to_owned(),
        ));
    }
    let prior_with_digests = prior
        .iter()
        .map(|event| Ok((event, Hash::new(event.event_digest()?)?)))
        .collect::<Result<Vec<_>>>()?;
    let prior_covered = prior_with_digests
        .iter()
        .map(|(_, digest)| digest.clone())
        .collect::<BTreeSet<_>>();
    let prior_control_root = control_event_set_root(&prior_covered)
        .map_err(|error| Error::Protocol(format!("self principal control root: {error}")))?;
    let prior_state_root =
        state_root_from_projection(&first.realm_id, &prior_with_digests, project)?;
    if predecessor.realm_id != first.realm_id
        || predecessor.control_event_set_root != prior_control_root
        || predecessor.state_root != prior_state_root
    {
        return Err(Error::Protocol(
            "self principal preserved history does not reproduce the accepted frontier".to_owned(),
        ));
    }

    let zero_hash = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let predecessor_seal = Seal {
        id: predecessor.seal_id.clone(),
        realm_id: predecessor.realm_id.clone(),
        predecessor_refs: Vec::new(),
        delta: Vec::new(),
        control_event_set_root: predecessor.control_event_set_root.clone(),
        state_root: predecessor.state_root.clone(),
        completeness_root: predecessor.control_event_set_root.clone(),
        notary_seq: u64::try_from(prior.len() - 2)
            .map_err(|_| Error::Protocol("self principal notary sequence overflow".to_owned()))?,
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: prior_covered.into_iter().collect(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(PayloadSignature {
            verification_method: signer.verification_method_id().clone(),
            payload_digest: zero_hash,
            created_at: Utc::now(),
            jws: String::new(),
            extra: Default::default(),
        }),
        sealed_at: Utc::now(),
        hlc: predecessor.hlc.clone().unwrap_or_else(|| hlc.clone()),
        kind: SealKind::Normal,
    };
    build_self_principal_event_seal(events, &predecessor_seal, hlc, signer, project)
}

fn self_principal_bootstrap_state_root(
    create: &Event,
    authorize: &Event,
    project: CellWriteProjector<'_>,
) -> Result<Hash> {
    let create_digest = Hash::new(create.event_digest()?)?;
    let authorize_digest = Hash::new(authorize.event_digest()?)?;
    if create_digest == authorize_digest {
        return Err(Error::Protocol(
            "bootstrap Event digests must be distinct".to_owned(),
        ));
    }
    let object = create
        .payload
        .get("object")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Protocol("bootstrap Realm object is missing".to_owned()))?;
    let created_by = object
        .get("created_by")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Protocol("bootstrap Realm created_by is missing".to_owned()))?;
    if created_by != create.actor_id.as_str() {
        return Err(Error::Protocol(
            "bootstrap Realm created_by differs from actor_id".to_owned(),
        ));
    }
    if !object.contains_key("notary") {
        return Err(Error::Protocol(
            "bootstrap Realm notary is missing".to_owned(),
        ));
    }

    // Both bootstrap Events are in the Seal `delta`, so both contribute their
    // derived writes. Omitting the authorize Event would leave the device
    // authorization cell out of the root that `apply_seal` step 11 compares
    // byte-for-byte.
    state_root_from_projection(
        &create.realm_id,
        &[(create, create_digest), (authorize, authorize_digest)],
        project,
    )
}
