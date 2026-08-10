//! Independent verification of owner-published principal resolution evidence.
//!
//! The public Principal Server response is discovery material, not an
//! authorization oracle. This evaluator closes the portable PCR/Event/Seal
//! and method-coordinate bindings while requiring the caller to supply its own
//! Event, Seal and DID-method verification callbacks.

use arkret_models_identity::{
    DidDocument, PrincipalCurrentResolutionEvent, PrincipalResolutionEvidence,
    PrincipalResolutionProjection, PrincipalResolutionUpdatePayload, ResolutionCommitment,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
};
use arkret_wire::{CellRef, Did, Event, EventKind, FullId, Hash, ScopeRef, Seal};

const RESOLUTION_CELL: &str = "ak:cell:ak.component.identity.resolution.v1:null";
const MAX_PREDECESSORS: usize = 256;
const MAX_METHOD_EVIDENCE_BYTES: usize = 1024 * 1024;

/// Verify one freshly fetched principal resolution response.
///
/// `verify_event` must authenticate each disclosed Event under the PCR's
/// accepted control history. `verify_seal` must authenticate the accepted
/// Seal under the PCR notary/control state. `verify_method_history` must run
/// the local registered adapter and trust policy over the supplied full id,
/// evidence boundary and normalized current DID Document. The evaluator then
/// cross-binds those independently verified results to the response.
pub fn verify_principal_resolution_evidence<VerifyEvent, VerifySeal, VerifyMethod>(
    evidence: &PrincipalResolutionEvidence,
    normalized_did_document: &DidDocument,
    verify_event: VerifyEvent,
    verify_seal: VerifySeal,
    verify_method_history: VerifyMethod,
) -> arkret_wire::Result<()>
where
    VerifyEvent: Fn(&Event) -> arkret_wire::Result<()>,
    VerifySeal: Fn(&Seal) -> arkret_wire::Result<()>,
    VerifyMethod:
        Fn(&FullId, &ResolutionMethodHistoryEvidence, &DidDocument) -> arkret_wire::Result<()>,
{
    if evidence.predecessor_resolution_events.len() > MAX_PREDECESSORS {
        return protocol("principal resolution evidence exceeds the predecessor limit");
    }
    let genesis = &evidence.principal_genesis_event.0;
    verify_genesis(evidence, genesis)?;
    verify_event(genesis)?;
    let initial = genesis_commitment(genesis)?;

    let (current, current_commitment, current_previous) = match &evidence.current_resolution_event {
        PrincipalCurrentResolutionEvent::Genesis(current) => {
            if current.0 != *genesis || !evidence.predecessor_resolution_events.is_empty() {
                return protocol(
                    "genesis current resolution must equal principal_genesis_event and have no predecessors",
                );
            }
            (genesis, initial.clone(), None)
        }
        PrincipalCurrentResolutionEvent::Update(current) => {
            verify_resolution_update_shape(evidence, &current.0)?;
            verify_event(&current.0)?;
            let payload = update_payload(&current.0)?;
            (
                &current.0,
                payload.next.clone(),
                Some((
                    payload.previous_resolution_event_ref,
                    payload.previous_method_history_head,
                )),
            )
        }
    };

    let projection = &evidence.resolution_cell_proof.cell_value;
    verify_projection(evidence, current, &current_commitment, projection)?;
    verify_resolution_history(
        evidence,
        genesis,
        &initial,
        current,
        current_previous,
        &verify_event,
    )?;
    verify_seal_and_cell(evidence, current, &verify_seal)?;
    verify_method_binding(
        evidence,
        genesis,
        current,
        projection,
        normalized_did_document,
        &verify_method_history,
    )
}

fn verify_genesis(
    evidence: &PrincipalResolutionEvidence,
    genesis: &Event,
) -> arkret_wire::Result<()> {
    genesis.verify_event_id_matches_content()?;
    let derived_realm = arkret_wire::derive_genesis_realm_id(&genesis.event_id);
    let purpose = genesis
        .payload
        .get("object")
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get("purpose"))
        .and_then(serde_json::Value::as_str);
    if genesis.kind != EventKind::RealmCreate
        || genesis.scope_ref != ScopeRef::RealmGenesis
        || genesis.realm_id != derived_realm
        || evidence.principal_control_realm_id != derived_realm
        || genesis.actor_id.as_str() != evidence.principal_id.as_str()
        || !matches!(purpose, Some("principal_control" | "managed_agent_control"))
    {
        return protocol(
            "principal genesis does not bind the stable principal, derived PCR Realm and control purpose",
        );
    }
    let initial = genesis_commitment(genesis)?;
    if arkret_wire::project_full_id_to_core_id(&initial.full_id)? != evidence.principal_id {
        return protocol("principal genesis full_id projects to a different core_id");
    }
    Ok(())
}

fn verify_resolution_update_shape(
    evidence: &PrincipalResolutionEvidence,
    event: &Event,
) -> arkret_wire::Result<()> {
    event.verify_event_id_matches_content()?;
    if event.kind != EventKind::IdentityResolutionUpdate
        || event.realm_id != evidence.principal_control_realm_id
        || event.scope_ref.realm_id_opt() != Some(&evidence.principal_control_realm_id)
        || event.actor_id.as_str() != evidence.principal_id.as_str()
    {
        return protocol("resolution update Event authority or PCR scope mismatch");
    }
    let payload = update_payload(event)?;
    if arkret_wire::project_full_id_to_core_id(&payload.next.full_id)? != evidence.principal_id {
        return protocol("resolution update full_id projects to a different core_id");
    }
    Ok(())
}

fn verify_projection(
    evidence: &PrincipalResolutionEvidence,
    current: &Event,
    commitment: &ResolutionCommitment,
    projection: &PrincipalResolutionProjection,
) -> arkret_wire::Result<()> {
    if projection.full_id != commitment.full_id
        || projection.method_history_head != commitment.method_history_head
        || projection.version_id != commitment.version_id
        || projection.resolution_event_ref != current.event_id.as_str()
        || projection.updated_at != current.created_at
        || arkret_wire::project_full_id_to_core_id(&projection.full_id)? != evidence.principal_id
    {
        return protocol("resolution cell projection does not equal the current Event commitment");
    }
    Ok(())
}

fn verify_resolution_history<VerifyEvent>(
    evidence: &PrincipalResolutionEvidence,
    genesis: &Event,
    initial: &ResolutionCommitment,
    current: &Event,
    current_previous: Option<(String, String)>,
    verify_event: &VerifyEvent,
) -> arkret_wire::Result<()>
where
    VerifyEvent: Fn(&Event) -> arkret_wire::Result<()>,
{
    let Some((mut expected_event_ref, mut expected_history_head)) = current_previous else {
        return Ok(());
    };
    let mut newer_actor_seq = current.actor_seq;
    let mut seen = std::collections::BTreeSet::new();
    for predecessor in &evidence.predecessor_resolution_events {
        let event = &predecessor.0;
        verify_resolution_update_shape(evidence, event)?;
        verify_event(event)?;
        if !seen.insert(event.event_id.clone())
            || event.event_id.as_str() != expected_event_ref
            || event.actor_seq >= newer_actor_seq
        {
            return protocol(
                "resolution predecessor Events are duplicated, out of order or gapped",
            );
        }
        let payload = update_payload(event)?;
        if payload.next.method_history_head != expected_history_head {
            return protocol("resolution predecessor method-history head mismatch");
        }
        expected_event_ref = payload.previous_resolution_event_ref;
        expected_history_head = payload.previous_method_history_head;
        newer_actor_seq = event.actor_seq;
    }
    if expected_event_ref == genesis.event_id.as_str()
        && expected_history_head != initial.method_history_head
    {
        return protocol("resolution history does not close onto the genesis commitment");
    }
    Ok(())
}

fn verify_seal_and_cell<VerifySeal>(
    evidence: &PrincipalResolutionEvidence,
    current: &Event,
    verify_seal: &VerifySeal,
) -> arkret_wire::Result<()>
where
    VerifySeal: Fn(&Seal) -> arkret_wire::Result<()>,
{
    let seal = &evidence.accepted_seal;
    seal.validate_structural()?;
    seal.validate_id()?;
    verify_seal(seal)?;
    let current_digest = Hash::new(current.event_digest()?)?;
    let proof = &evidence.resolution_cell_proof;
    let cell = CellRef::new(proof.cell_ref.clone())?;
    let cell_value = serde_json::to_value(&proof.cell_value)?;
    let recomputed_leaf = arkret_state::state_value_leaf_digest(&cell, &cell_value)
        .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))?;
    let included = arkret_state::verify_state_inclusion_proof(
        &proof.leaf_digest,
        proof.leaf_index,
        proof.leaf_count,
        &proof.inclusion_proof,
        &seal.state_root,
    )
    .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))?;
    if proof.cell_ref != RESOLUTION_CELL
        || proof.seal_id != seal.id.as_str()
        || proof.state_root != seal.state_root
        || proof.leaf_digest != recomputed_leaf
        || seal.realm_id != evidence.principal_control_realm_id
        || (!seal.delta.contains(&current_digest)
            && !seal.covered_event_digests.contains(&current_digest))
        || !included
    {
        return protocol(
            "accepted Seal or resolution-cell inclusion proof is not bound to current state",
        );
    }
    Ok(())
}

fn verify_method_binding<VerifyMethod>(
    evidence: &PrincipalResolutionEvidence,
    genesis: &Event,
    current: &Event,
    projection: &PrincipalResolutionProjection,
    document: &DidDocument,
    verify_method_history: &VerifyMethod,
) -> arkret_wire::Result<()>
where
    VerifyMethod:
        Fn(&FullId, &ResolutionMethodHistoryEvidence, &DidDocument) -> arkret_wire::Result<()>,
{
    let method_evidence = evidence.method_history_evidence.as_ref().ok_or_else(|| {
        arkret_wire::Error::Protocol(
            "principal resolution method-history evidence is required for verification".to_owned(),
        )
    })?;
    method_evidence.validate_shape()?;
    if arkret_canonical::canonical_json_bytes(method_evidence)?.len() > MAX_METHOD_EVIDENCE_BYTES {
        return protocol("principal resolution method-history evidence exceeds 1 MiB");
    }
    if document.id.as_str() != projection.full_id.as_str() {
        return protocol("resolved DID Document id differs from the current full_id");
    }
    let document_digest = Hash::new(arkret_canonical::canonical_sha256(document)?)?;
    if method_evidence.evidence().document_digest != document_digest {
        return protocol("method-history evidence DID Document digest mismatch");
    }
    let full_id = &projection.full_id;
    let method = Did::new(full_id.to_string())?.method().to_owned();
    verify_method_boundary(
        evidence,
        genesis,
        current,
        projection,
        &method,
        method_evidence.boundary(),
    )?;
    match (method.as_str(), method_evidence) {
        ("webvh", ResolutionMethodHistoryEvidence::WebvhLog { evidence, .. }) => {
            if evidence.method_proofs[0].history_head != projection.method_history_head {
                return protocol("did:webvh proof does not name the current history head");
            }
        }
        ("web", ResolutionMethodHistoryEvidence::DidWebDocument { .. }) => {
            validate_synthetic_coordinates(projection, &document_digest, "synthetic-jcs-sha256:")?;
        }
        ("key", ResolutionMethodHistoryEvidence::DidKeyExpansion { .. }) => {
            let digest = Hash::new(arkret_canonical::sha256_digest(full_id.as_str().as_bytes()))?;
            validate_synthetic_coordinates(projection, &digest, "synthetic-full-id-sha256:")?;
        }
        _ => return protocol("full_id method and evidence adapter discriminator mismatch"),
    }
    verify_method_history(full_id, method_evidence, document)
}

fn verify_method_boundary(
    evidence: &PrincipalResolutionEvidence,
    genesis: &Event,
    current: &Event,
    projection: &PrincipalResolutionProjection,
    method: &str,
    boundary: &ResolutionMethodEvidenceBoundary,
) -> arkret_wire::Result<()> {
    if boundary.to_method_history_head != projection.method_history_head
        || boundary.to_version_id != projection.version_id
    {
        return protocol("method-history evidence does not end at the current projection");
    }
    if method != "webvh" {
        if boundary.from_method_history_head != boundary.to_method_history_head
            || boundary.from_version_id != boundary.to_version_id
        {
            return protocol(
                "non-history DID adapter must use a degenerate current-state boundary",
            );
        }
        return Ok(());
    }
    if current.kind == EventKind::RealmCreate {
        let initial = genesis_commitment(genesis)?;
        if boundary.from_method_history_head != initial.method_history_head
            || boundary.from_version_id != initial.version_id
        {
            return protocol("did:webvh genesis evidence boundary mismatch");
        }
        return Ok(());
    }
    let oldest = evidence
        .predecessor_resolution_events
        .last()
        .map(|event| &event.0)
        .unwrap_or(current);
    let payload = update_payload(oldest)?;
    if boundary.from_method_history_head != payload.previous_method_history_head {
        return protocol("did:webvh evidence omits the oldest disclosed transition's pre-state");
    }
    if payload.previous_resolution_event_ref == genesis.event_id.as_str() {
        let initial = genesis_commitment(genesis)?;
        if boundary.from_version_id != initial.version_id {
            return protocol("did:webvh evidence genesis boundary version mismatch");
        }
    }
    Ok(())
}

fn genesis_commitment(event: &Event) -> arkret_wire::Result<ResolutionCommitment> {
    serde_json::from_value(
        event
            .payload
            .get("object")
            .and_then(serde_json::Value::as_object)
            .and_then(|object| object.get("initial_resolution"))
            .cloned()
            .ok_or_else(|| {
                arkret_wire::Error::Protocol(
                    "principal genesis omits initial_resolution".to_owned(),
                )
            })?,
    )
    .map_err(Into::into)
}

fn update_payload(event: &Event) -> arkret_wire::Result<PrincipalResolutionUpdatePayload> {
    serde_json::from_value(serde_json::to_value(&event.payload)?).map_err(Into::into)
}

fn validate_synthetic_coordinates(
    projection: &PrincipalResolutionProjection,
    digest: &Hash,
    version_prefix: &str,
) -> arkret_wire::Result<()> {
    let hex = digest.as_str().strip_prefix("sha256:").ok_or_else(|| {
        arkret_wire::Error::Protocol("canonical digest lost sha256 prefix".to_owned())
    })?;
    if projection.method_history_head != digest.as_str()
        || projection.version_id != format!("{version_prefix}{hex}")
    {
        return protocol("deterministic DID adapter coordinates mismatch");
    }
    Ok(())
}

fn protocol<T>(message: impl Into<String>) -> arkret_wire::Result<T> {
    Err(arkret_wire::Error::Protocol(message.into()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_models_identity::{
        PrincipalGenesisEvent, PrincipalResolutionCellProof, PrincipalResolutionUpdateEvent,
        ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
        ResolutionDidBindingMethodProof, ResolutionDidBindingMethodProofKind,
    };
    use arkret_wire::{ActorId, CoreId, DidUrl, Hlc, RealmId};
    use chrono::{TimeZone as _, Utc};

    use super::*;
    use crate::Ed25519PayloadSigner;

    fn fixture() -> (PrincipalResolutionEvidence, DidDocument) {
        let full_id = FullId::new("did:web:alice.example").unwrap();
        let principal_id = arkret_wire::project_full_id_to_core_id(&full_id).unwrap();
        let document: DidDocument = serde_json::from_value(serde_json::json!({
            "id": full_id,
            "verificationMethod": []
        }))
        .unwrap();
        let document_digest =
            Hash::new(arkret_canonical::canonical_sha256(&document).unwrap()).unwrap();
        let digest_hex = document_digest.as_str().strip_prefix("sha256:").unwrap();
        let commitment = ResolutionCommitment {
            full_id,
            method_history_head: document_digest.to_string(),
            version_id: format!("synthetic-jcs-sha256:{digest_hex}"),
        };
        let genesis = arkret_wire::test_support::raw_event_at(
            EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            ActorId::from(principal_id.clone()),
            0,
            Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({
                "object": {
                    "purpose": "principal_control",
                    "initial_resolution": commitment
                }
            }),
            Utc.with_ymd_and_hms(2026, 8, 10, 1, 0, 0).unwrap(),
        )
        .unwrap();
        let update_payload = PrincipalResolutionUpdatePayload {
            next: commitment.clone(),
            previous_resolution_event_ref: genesis.event_id.to_string(),
            previous_method_history_head: commitment.method_history_head.clone(),
        };
        let update = arkret_wire::test_support::raw_event_at(
            EventKind::IdentityResolutionUpdate.as_str(),
            ScopeRef::Realm {
                realm_id: genesis.realm_id.clone(),
            },
            ActorId::from(principal_id.clone()),
            1,
            Hlc::new("019f00000000-0001-00000001").unwrap(),
            serde_json::to_value(update_payload).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 10, 1, 0, 1).unwrap(),
        )
        .unwrap();
        let projection = PrincipalResolutionProjection {
            full_id: commitment.full_id.clone(),
            method_history_head: commitment.method_history_head.clone(),
            version_id: commitment.version_id.clone(),
            resolution_event_ref: update.event_id.to_string(),
            updated_at: update.created_at,
        };
        let cell_ref = CellRef::new(RESOLUTION_CELL.to_owned()).unwrap();
        let cells = BTreeMap::from([(
            cell_ref.clone(),
            arkret_state::lattice::CellState::Value(serde_json::to_value(&projection).unwrap()),
        )]);
        let state_root = arkret_state::compute_state_root(&cells).unwrap();
        let inclusion = arkret_state::state_inclusion_proof(&cells, &cell_ref).unwrap();
        let signer_did = Did::new("did:key:z6MkfixtureNotary").unwrap();
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            [41; 32],
            signer_did.clone(),
            DidUrl::new(format!("{signer_did}#key-1")).unwrap(),
        );
        let update_digest = Hash::new(update.event_digest().unwrap()).unwrap();
        let seal = Seal::sign_single(
            genesis.realm_id.clone(),
            Vec::new(),
            vec![update_digest],
            state_root.clone(),
            Hlc::new("019f00000000-0002-00000001").unwrap(),
            &signer,
        )
        .unwrap();
        let boundary = ResolutionMethodEvidenceBoundary {
            from_method_history_head: commitment.method_history_head.clone(),
            from_version_id: commitment.version_id.clone(),
            to_method_history_head: commitment.method_history_head.clone(),
            to_version_id: commitment.version_id.clone(),
        };
        let method_history_evidence = ResolutionMethodHistoryEvidence::DidWebDocument {
            adapter_version: "did:web:1".to_owned(),
            boundary,
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "web".to_owned(),
                document_digest,
                method_proofs: Vec::new(),
            },
        };
        (
            PrincipalResolutionEvidence {
                principal_id: CoreId::new(principal_id.to_string()).unwrap(),
                principal_control_realm_id: RealmId::new(genesis.realm_id.to_string()).unwrap(),
                principal_genesis_event: PrincipalGenesisEvent(genesis),
                current_resolution_event: PrincipalCurrentResolutionEvent::Update(
                    PrincipalResolutionUpdateEvent(update),
                ),
                predecessor_resolution_events: Vec::new(),
                accepted_seal: seal.clone(),
                resolution_cell_proof: PrincipalResolutionCellProof {
                    cell_ref: cell_ref.to_string(),
                    cell_value: projection,
                    seal_id: seal.id.to_string(),
                    state_root,
                    leaf_digest: inclusion.leaf_digest,
                    leaf_index: inclusion.leaf_index,
                    leaf_count: inclusion.leaf_count,
                    inclusion_proof: inclusion.inclusion_proof,
                },
                method_history_evidence: Some(method_history_evidence),
            },
            document,
        )
    }

    fn verify(evidence: &PrincipalResolutionEvidence, document: &DidDocument) -> bool {
        verify_principal_resolution_evidence(
            evidence,
            document,
            |_| Ok(()),
            |_| Ok(()),
            |_, _, _| Ok(()),
        )
        .is_ok()
    }

    fn webvh_fixture() -> (PrincipalResolutionEvidence, DidDocument) {
        let full_id = FullId::new("did:webvh:z6mkfixture:alice.example").unwrap();
        let principal_id = arkret_wire::project_full_id_to_core_id(&full_id).unwrap();
        let document: DidDocument = serde_json::from_value(serde_json::json!({
            "id": full_id,
            "verificationMethod": []
        }))
        .unwrap();
        let initial = ResolutionCommitment {
            full_id: full_id.clone(),
            method_history_head: format!("sha256:{}", "1".repeat(64)),
            version_id: "1-inception".to_owned(),
        };
        let middle = ResolutionCommitment {
            full_id: full_id.clone(),
            method_history_head: format!("sha256:{}", "2".repeat(64)),
            version_id: "2-rotation".to_owned(),
        };
        let current = ResolutionCommitment {
            full_id,
            method_history_head: format!("sha256:{}", "3".repeat(64)),
            version_id: "3-relocation".to_owned(),
        };
        let genesis = arkret_wire::test_support::raw_event_at(
            EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            ActorId::from(principal_id.clone()),
            0,
            Hlc::new("019f00000000-0000-00000011").unwrap(),
            serde_json::json!({
                "object": {
                    "purpose": "principal_control",
                    "initial_resolution": initial
                }
            }),
            Utc.with_ymd_and_hms(2026, 8, 10, 2, 0, 0).unwrap(),
        )
        .unwrap();
        let middle_event = arkret_wire::test_support::raw_event_at(
            EventKind::IdentityResolutionUpdate.as_str(),
            ScopeRef::Realm {
                realm_id: genesis.realm_id.clone(),
            },
            ActorId::from(principal_id.clone()),
            1,
            Hlc::new("019f00000000-0001-00000011").unwrap(),
            serde_json::to_value(PrincipalResolutionUpdatePayload {
                next: middle.clone(),
                previous_resolution_event_ref: genesis.event_id.to_string(),
                previous_method_history_head: initial.method_history_head.clone(),
            })
            .unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 10, 2, 0, 1).unwrap(),
        )
        .unwrap();
        let current_event = arkret_wire::test_support::raw_event_at(
            EventKind::IdentityResolutionUpdate.as_str(),
            ScopeRef::Realm {
                realm_id: genesis.realm_id.clone(),
            },
            ActorId::from(principal_id.clone()),
            2,
            Hlc::new("019f00000000-0002-00000011").unwrap(),
            serde_json::to_value(PrincipalResolutionUpdatePayload {
                next: current.clone(),
                previous_resolution_event_ref: middle_event.event_id.to_string(),
                previous_method_history_head: middle.method_history_head.clone(),
            })
            .unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 10, 2, 0, 2).unwrap(),
        )
        .unwrap();
        let projection = PrincipalResolutionProjection {
            full_id: current.full_id.clone(),
            method_history_head: current.method_history_head.clone(),
            version_id: current.version_id.clone(),
            resolution_event_ref: current_event.event_id.to_string(),
            updated_at: current_event.created_at,
        };
        let cell_ref = CellRef::new(RESOLUTION_CELL.to_owned()).unwrap();
        let cells = BTreeMap::from([(
            cell_ref.clone(),
            arkret_state::lattice::CellState::Value(serde_json::to_value(&projection).unwrap()),
        )]);
        let state_root = arkret_state::compute_state_root(&cells).unwrap();
        let inclusion = arkret_state::state_inclusion_proof(&cells, &cell_ref).unwrap();
        let signer_did = Did::new("did:key:z6MkfixtureNotary").unwrap();
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            [42; 32],
            signer_did.clone(),
            DidUrl::new(format!("{signer_did}#key-1")).unwrap(),
        );
        let seal = Seal::sign_single(
            genesis.realm_id.clone(),
            Vec::new(),
            vec![Hash::new(current_event.event_digest().unwrap()).unwrap()],
            state_root.clone(),
            Hlc::new("019f00000000-0003-00000011").unwrap(),
            &signer,
        )
        .unwrap();
        let document_digest =
            Hash::new(arkret_canonical::canonical_sha256(&document).unwrap()).unwrap();
        let witness_proofs_digest = Hash::new(
            arkret_canonical::canonical_sha256(&Vec::<serde_json::Value>::new()).unwrap(),
        )
        .unwrap();
        let method_history_evidence = ResolutionMethodHistoryEvidence::WebvhLog {
            adapter_version: "did:webvh:1.0".to_owned(),
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: initial.method_history_head,
                from_version_id: initial.version_id,
                to_method_history_head: current.method_history_head.clone(),
                to_version_id: current.version_id.clone(),
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".to_owned(),
                document_digest,
                method_proofs: vec![ResolutionDidBindingMethodProof {
                    kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: current.method_history_head,
                    witnesses: Vec::new(),
                    witness_proofs_digest,
                }],
            },
        };
        (
            PrincipalResolutionEvidence {
                principal_id,
                principal_control_realm_id: genesis.realm_id.clone(),
                principal_genesis_event: PrincipalGenesisEvent(genesis),
                current_resolution_event: PrincipalCurrentResolutionEvent::Update(
                    PrincipalResolutionUpdateEvent(current_event),
                ),
                predecessor_resolution_events: vec![PrincipalResolutionUpdateEvent(middle_event)],
                accepted_seal: seal.clone(),
                resolution_cell_proof: PrincipalResolutionCellProof {
                    cell_ref: cell_ref.to_string(),
                    cell_value: projection,
                    seal_id: seal.id.to_string(),
                    state_root,
                    leaf_digest: inclusion.leaf_digest,
                    leaf_index: inclusion.leaf_index,
                    leaf_count: inclusion.leaf_count,
                    inclusion_proof: inclusion.inclusion_proof,
                },
                method_history_evidence: Some(method_history_evidence),
            },
            document,
        )
    }

    #[test]
    fn current_resolution_closes_pcr_seal_cell_and_method_bindings() {
        let (evidence, document) = fixture();
        assert!(verify(&evidence, &document));
    }

    #[test]
    fn resolution_evaluator_rejects_event_cell_and_adapter_tampering() {
        let (evidence, document) = fixture();

        let mut event_fork = evidence.clone();
        let PrincipalCurrentResolutionEvent::Update(update) =
            &mut event_fork.current_resolution_event
        else {
            unreachable!();
        };
        update.0.payload.insert(
            "previous_method_history_head".to_owned(),
            serde_json::Value::String(format!("sha256:{}", "0".repeat(64))),
        );
        assert!(!verify(&event_fork, &document));

        let mut cell_substitution = evidence.clone();
        cell_substitution
            .resolution_cell_proof
            .cell_value
            .version_id = "synthetic-jcs-sha256:forged".to_owned();
        assert!(!verify(&cell_substitution, &document));

        let mut adapter_mismatch = evidence;
        let method = adapter_mismatch.method_history_evidence.take().unwrap();
        let ResolutionMethodHistoryEvidence::DidWebDocument {
            boundary, evidence, ..
        } = method
        else {
            unreachable!();
        };
        adapter_mismatch.method_history_evidence =
            Some(ResolutionMethodHistoryEvidence::DidKeyExpansion {
                adapter_version: "did:key:1".to_owned(),
                boundary,
                evidence: ResolutionDidBindingEvidenceReceipt {
                    method: "key".to_owned(),
                    ..evidence
                },
            });
        assert!(!verify(&adapter_mismatch, &document));
    }

    #[test]
    fn webvh_two_update_boundary_starts_at_oldest_disclosed_transition_pre_state() {
        let (evidence, document) = webvh_fixture();
        assert!(verify(&evidence, &document));

        let mut omitted_pre_state = evidence;
        let method = omitted_pre_state.method_history_evidence.as_mut().unwrap();
        let ResolutionMethodHistoryEvidence::WebvhLog { boundary, .. } = method else {
            unreachable!();
        };
        boundary.from_method_history_head = format!("sha256:{}", "2".repeat(64));
        boundary.from_version_id = "2-rotation".to_owned();
        assert!(!verify(&omitted_pre_state, &document));
    }
}
