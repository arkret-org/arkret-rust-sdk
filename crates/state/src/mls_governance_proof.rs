//! Verification for complete-materialization MLS governance proofs.
//!
//! The proof request / bundle / chunk data shapes and the chunk build /
//! assemble commitment machinery live in
//! `arkret_models_crypto::mls_governance_proof` (re-exported here). This
//! module owns the verification and control-state root derivation that need
//! `arkret-state` (Move/Seal state roots, `CellState`).
//!
//! `verify_mls_governance_proof_bundle` is generic over the caller's error
//! type `E` (with `E: From<WireError>`): the injected signature callbacks and
//! the returned `Result` share `E`, so a consumer that already works in the
//! `arkret-core` facade `Error` (which bridges `WireError`) keeps compiling
//! unchanged, while callers in the state/wire layer use `WireError` directly.

use std::collections::{BTreeMap, BTreeSet};

pub use arkret_models_crypto::mls_governance_proof::*;
use arkret_models_crypto::mls_payloads::MlsGovernanceBindingPayload;
use arkret_wire::cell::CellId;
use arkret_wire::event_envelope::Event;
use arkret_wire::{
    CellRef, Error, EventId, Hash, MoveId, NotarySig, Result, Seal, SealId, canonical,
};

use crate::{CellState, compute_state_root, control_event_set_root};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMlsGovernanceProof {
    pub accepted_seal_id: SealId,
    pub membership_frontier: Vec<EventId>,
    pub policy_root: Hash,
    pub capability_root: Hash,
    pub discussion_metadata_digest: Hash,
}

/// Verify a complete-materialization proof bundle.
///
/// The callbacks own cryptographic signature verification and authorization
/// resolution. This function always validates the signed object digests,
/// topology, complete Merkle materializations, scope, and governance roots
/// before invoking a successful result.
///
/// The error type `E` is chosen by the caller through the injected callbacks:
/// both callbacks return `Result<(), E>` and the function returns
/// `Result<_, E>`. `E: From<WireError>` lets the internal fail-closed checks
/// raise `WireError` and surface it as the caller's `E` (the `arkret-core`
/// facade `Error` satisfies this bridge).
pub fn verify_mls_governance_proof_bundle<E, VerifySeal, VerifyEvent>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    expected_binding: &MlsGovernanceBindingPayload,
    trusted_anchor: &SealId,
    verify_seal_signature: VerifySeal,
    verify_event_signature: VerifyEvent,
) -> std::result::Result<VerifiedMlsGovernanceProof, E>
where
    E: From<Error>,
    VerifySeal: Fn(&Seal) -> std::result::Result<(), E>,
    VerifyEvent: Fn(&Event) -> std::result::Result<(), E>,
{
    verify_bundle_header(bundle, expected_binding, trusted_anchor)?;
    let accepted_seal = verify_seal_path(bundle, verify_seal_signature)?;
    let covered = verify_covered_event_materialization(bundle, accepted_seal)?;
    let control_state = verify_control_state_materialization(bundle, accepted_seal)?;
    verify_frontier_events(bundle, expected_binding, &covered, verify_event_signature)?;

    let policy_root = derive_mls_policy_root(&control_state)?;
    if &policy_root != expected_binding.policy_root() {
        return stale("policy_root does not match the complete control state");
    }
    let capability_root = derive_mls_capability_root(&control_state)?;
    if expected_binding.capability_root() != Some(&capability_root) {
        return stale("capability_root does not match the complete control state");
    }
    let discussion_metadata_digest = derive_mls_discussion_metadata_digest(&bundle.control_state)?;
    if expected_binding.discussion_metadata_digest() != Some(&discussion_metadata_digest) {
        return stale("discussion_metadata_digest does not match the complete control state");
    }

    Ok(VerifiedMlsGovernanceProof {
        accepted_seal_id: bundle.accepted_seal_id.clone(),
        membership_frontier: expected_binding.membership_frontier().to_vec(),
        policy_root,
        capability_root,
        discussion_metadata_digest,
    })
}

fn verify_bundle_header(
    bundle: &MaterializedMlsGovernanceProofBundle,
    expected: &MlsGovernanceBindingPayload,
    trusted_anchor: &SealId,
) -> Result<()> {
    if bundle.bundle_version != MLS_GOVERNANCE_PROOF_BUNDLE_VERSION {
        return schema("unsupported MLS governance proof bundle_version");
    }
    if bundle.materialization_profile != MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE {
        return schema("unsupported MLS governance proof materialization_profile");
    }
    if &bundle.trusted_anchor_seal_id != trusted_anchor {
        return state_mismatch("bundle trust anchor does not match the locally trusted anchor");
    }
    if &bundle.governance_binding != expected {
        return state_mismatch("bundle governance_binding differs from the MLS transcript binding");
    }
    if &bundle.realm_id != expected.realm_id()
        || &bundle.effective_scope != expected.effective_scope()
        || bundle.reducer_profile != expected.reducer_profile()
    {
        return state_mismatch("bundle Realm, scope, or reducer profile mismatch");
    }
    Ok(())
}

fn verify_seal_path<E, VerifySeal>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    verify_seal_signature: VerifySeal,
) -> std::result::Result<&Seal, E>
where
    E: From<Error>,
    VerifySeal: Fn(&Seal) -> std::result::Result<(), E>,
{
    if bundle.seal_path.is_empty() {
        return schema("seal_path must not be empty");
    }
    if bundle.seal_path.last().map(|seal| &seal.id) != Some(&bundle.accepted_seal_id) {
        return state_mismatch("accepted_seal_id must identify the final seal_path entry");
    }

    let mut prior = BTreeSet::new();
    let mut path = BTreeMap::new();
    for seal in &bundle.seal_path {
        if seal.realm_id != bundle.realm_id {
            return state_mismatch("seal_path contains a cross-Realm Seal");
        }
        seal.validate_id()?;
        seal.validate_structural()?;
        verify_seal_payload_digest(seal)?;
        verify_seal_signature(seal)?;
        if path.insert(seal.id.clone(), seal).is_some() {
            return schema("seal_path contains duplicate Seal ids");
        }
        if seal.id != bundle.trusted_anchor_seal_id {
            if seal.predecessor_refs.is_empty() {
                return state_mismatch("untrusted seal_path entry has no predecessor");
            }
            for predecessor in &seal.predecessor_refs {
                if predecessor != &bundle.trusted_anchor_seal_id && !prior.contains(predecessor) {
                    return state_mismatch(
                        "seal_path is not topologically complete from the trusted anchor",
                    );
                }
            }
        }
        prior.insert(seal.id.clone());
    }

    let mut reachable = BTreeSet::new();
    let mut pending = vec![bundle.accepted_seal_id.clone()];
    while let Some(id) = pending.pop() {
        if !reachable.insert(id.clone()) || id == bundle.trusted_anchor_seal_id {
            continue;
        }
        if let Some(seal) = path.get(&id) {
            pending.extend(seal.predecessor_refs.iter().cloned());
        }
    }
    if path.keys().filter(|id| reachable.contains(*id)).count() != path.len() {
        return schema("seal_path contains entries outside the accepted Seal ancestry");
    }

    bundle
        .seal_path
        .last()
        .ok_or_else(|| E::from(Error::Protocol("seal_path unexpectedly empty".to_owned())))
}

fn verify_seal_payload_digest(seal: &Seal) -> Result<()> {
    let expected = Hash::new(canonical::sha256_digest(seal.canonical_bytes_for_id()?))?;
    match &seal.notary_signature {
        NotarySig::Single(signature) => {
            if signature.payload_digest != expected {
                return state_mismatch("Seal signature payload_digest mismatch");
            }
        }
        NotarySig::Multi(multi) => {
            if multi
                .signatures
                .iter()
                .any(|signature| signature.payload_digest != expected)
            {
                return state_mismatch("Seal multi-signature payload_digest mismatch");
            }
        }
        NotarySig::Threshold(_) => {}
    }
    Ok(())
}

fn verify_covered_event_materialization(
    bundle: &MaterializedMlsGovernanceProofBundle,
    accepted_seal: &Seal,
) -> Result<BTreeSet<MoveId>> {
    ensure_canonical_order(
        "covered_event_digests",
        bundle
            .covered_event_digests
            .iter()
            .map(|digest| digest.as_str()),
    )?;
    let covered = bundle
        .covered_event_digests
        .iter()
        .map(|digest| MoveId::new(digest.as_str().to_owned()).map_err(Error::from))
        .collect::<Result<BTreeSet<_>>>()?;
    let recomputed = control_event_set_root(&covered)
        .map_err(|error| Error::Protocol(format!("control_event_set_root: {error}")))?;
    if recomputed != accepted_seal.control_event_set_root {
        return state_mismatch("covered_event_digests do not reconstruct control_event_set_root");
    }
    if !accepted_seal.covered_event_digests.is_empty()
        && accepted_seal
            .covered_event_digests
            .iter()
            .ne(covered.iter())
    {
        return state_mismatch(
            "bundle covered_event_digests differ from the compaction Seal manifest",
        );
    }
    Ok(covered)
}

fn verify_control_state_materialization(
    bundle: &MaterializedMlsGovernanceProofBundle,
    accepted_seal: &Seal,
) -> Result<BTreeMap<CellRef, CellState>> {
    ensure_canonical_order(
        "control_state",
        bundle.control_state.iter().map(|leaf| leaf.cell.as_str()),
    )?;
    let control_state = bundle
        .control_state
        .iter()
        .map(|leaf| {
            (
                leaf.cell.clone(),
                CellState::Value(leaf.state.value.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if control_state.len() != bundle.control_state.len() {
        return schema("control_state contains duplicate cell ids");
    }
    let recomputed = compute_state_root(&control_state)?;
    if recomputed != accepted_seal.state_root {
        return state_mismatch("control_state does not reconstruct the accepted Seal state_root");
    }
    Ok(control_state)
}

fn verify_frontier_events<E, VerifyEvent>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    expected: &MlsGovernanceBindingPayload,
    covered: &BTreeSet<MoveId>,
    verify_event_signature: VerifyEvent,
) -> std::result::Result<(), E>
where
    E: From<Error>,
    VerifyEvent: Fn(&Event) -> std::result::Result<(), E>,
{
    ensure_canonical_order(
        "membership_frontier",
        expected.membership_frontier().iter().map(EventId::as_str),
    )?;
    ensure_canonical_order(
        "frontier_events",
        bundle
            .frontier_events
            .iter()
            .map(|event| event.event_id.as_str()),
    )?;
    let expected_ids = expected
        .membership_frontier()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual_ids = bundle
        .frontier_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<BTreeSet<_>>();
    if expected_ids != actual_ids || actual_ids.len() != bundle.frontier_events.len() {
        return state_mismatch(
            "frontier_events do not exactly match governance_binding.membership_frontier",
        );
    }

    for event in &bundle.frontier_events {
        if event.realm_id != bundle.realm_id
            || event.effective_scope.as_ref() != Some(&bundle.effective_scope)
        {
            return state_mismatch("frontier Event Realm or effective_scope mismatch");
        }
        if event.seal_ref.is_some() || event.effects.is_empty() {
            return schema("frontier Event is not a Control Move");
        }
        if !event.effects.iter().any(|effect| {
            CellId::from_ref(&effect.cell)
                .map(|cell| is_mls_membership_frontier_component(cell.component()))
                .unwrap_or(false)
        }) {
            return schema("frontier Event does not affect a membership/device/lifecycle cell");
        }
        event.validate_proof_bindings()?;
        verify_event_signature(event)?;
        let digest = MoveId::new(event.event_digest()?).map_err(Error::from)?;
        if !covered.contains(&digest) {
            return state_mismatch("frontier Event digest is absent from the accepted covered set");
        }
    }
    Ok(())
}

pub fn derive_mls_policy_root(control_state: &BTreeMap<CellRef, CellState>) -> Result<Hash> {
    filtered_control_state_root(control_state, |cell| {
        let component = cell.component();
        (component.starts_with("ak.component.realm.")
            && (component.contains("policy")
                || matches!(
                    component,
                    "ak.component.realm.join_rule.v1"
                        | "ak.component.realm.history_visibility.v1"
                        | "ak.component.realm.media_service.v1"
                        | "ak.component.realm.policy_components.v1"
                        | "ak.component.realm.plaintext_visible_services.v1"
                )))
            || (component.starts_with("ak.component.circle.")
                && ["policy", "history", "encryption", "lifecycle"]
                    .iter()
                    .any(|marker| component.contains(marker)))
    })
}

pub fn derive_mls_capability_root(control_state: &BTreeMap<CellRef, CellState>) -> Result<Hash> {
    filtered_control_state_root(control_state, |cell| {
        cell.component().starts_with("ak.component.capability.")
    })
}

fn filtered_control_state_root(
    control_state: &BTreeMap<CellRef, CellState>,
    include: impl Fn(&CellId) -> bool,
) -> Result<Hash> {
    let mut filtered = BTreeMap::new();
    for (cell_ref, state) in control_state {
        let cell = CellId::from_ref(cell_ref)?;
        if include(&cell) {
            filtered.insert(cell_ref.clone(), state.clone());
        }
    }
    Ok(compute_state_root(&filtered)?)
}

fn ensure_canonical_order<'a>(
    field: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return schema(&format!(
            "{field} must be canonical sorted and duplicate-free"
        ));
    }
    Ok(())
}

fn schema<T, E>(message: &str) -> std::result::Result<T, E>
where
    E: From<Error>,
{
    Err(Error::Protocol(format!("{message} (schema_violation)")).into())
}

fn state_mismatch<T, E>(message: &str) -> std::result::Result<T, E>
where
    E: From<Error>,
{
    Err(Error::Protocol(format!("{message} (state_mismatch)")).into())
}

fn stale<T, E>(message: &str) -> std::result::Result<T, E>
where
    E: From<Error>,
{
    Err(Error::Protocol(format!("{message} (mls_governance_binding_stale)")).into())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use arkret_models_crypto::mls_payloads::{
        MLS_GOVERNANCE_BINDING_FULL_PROFILE, MlsGovernanceBindingPayload,
    };
    use arkret_wire::error_codes::{ErrorCode, ReasonCode};
    use arkret_wire::event_envelope::{EffectiveScope, Event};
    use arkret_wire::{
        CellRef, Did, Effect, Error, EventId, EventRequirements, Hash, Hlc, LatticeOp,
        LatticeOpType, MoveId, MoveSignature, NotarySig, Proof, RealmId, Seal, SealId, SealKind,
        canonical,
    };
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::{CellState, compute_state_root, control_event_set_root};

    struct Fixture {
        bundle: MaterializedMlsGovernanceProofBundle,
        binding: MlsGovernanceBindingPayload,
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014a").unwrap()
    }

    fn event_id() -> EventId {
        EventId::new("ak:event:0196419b-0000-7000-8000-000000000002").unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn cell(component: &str, subject: &str) -> CellRef {
        CellRef::new(format!("ak:cell:{component}:{subject}")).unwrap()
    }

    fn control_state() -> Vec<MlsGovernanceControlStateLeaf> {
        let mut leaves = vec![
            MlsGovernanceControlStateLeaf {
                cell: cell("ak.component.member.state.v1", "did.web.alice.example"),
                state: MlsGovernanceControlStateValue {
                    value: json!({"state": "joined"}),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell("ak.component.realm.policy_components.v1", realm().as_str()),
                state: MlsGovernanceControlStateValue {
                    value: json!({"media_service_decrypts": true}),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell(
                    "ak.component.realm.plaintext_visible_services.v1",
                    realm().as_str(),
                ),
                state: MlsGovernanceControlStateValue {
                    value: json!({
                        "services": [{
                            "service_id": "did:webvh:z6mkfixture:media.example",
                            "data_classes": ["media_plaintext"],
                            "visibility": "realm",
                            "purposes": ["video transcoding"]
                        }]
                    }),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell("ak.component.capability.grant.v1", "ak.grant.fixture"),
                state: MlsGovernanceControlStateValue {
                    value: json!({"active": true}),
                },
            },
        ];
        leaves.sort_by(|left, right| left.cell.as_str().cmp(right.cell.as_str()));
        leaves
    }

    fn state_map(leaves: &[MlsGovernanceControlStateLeaf]) -> BTreeMap<CellRef, CellState> {
        leaves
            .iter()
            .map(|leaf| {
                (
                    leaf.cell.clone(),
                    CellState::Value(leaf.state.value.clone()),
                )
            })
            .collect()
    }

    fn frontier_event(scope: EffectiveScope) -> Event {
        let mut event = Event {
            event_id: event_id(),
            kind: "ak.member.state".into(),
            realm_id: realm(),
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            actor_seq: 1,
            created_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 0).unwrap(),
            hlc: Hlc::new("01980b44cc00-0000-aabbccdd").unwrap(),
            prev_refs: Vec::new(),
            effective_scope: Some(scope),
            refs: Vec::new(),
            preconditions: Vec::new(),
            effects: vec![Effect {
                cell: cell("ak.component.member.state.v1", "did.web.alice.example"),
                op: LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!({"state": "joined"})),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            }],
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            redacts: None,
            payload: BTreeMap::new(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        };
        let digest = Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:alice.example#device-key".to_owned(),
            event_digest: digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            jws: "AAAA.BBBB.CCCC".to_owned(),
        });
        event
    }

    fn seal(
        state_root: Hash,
        covered_event_digests: Vec<MoveId>,
        control_event_set_root: Hash,
    ) -> Seal {
        let mut seal = Seal {
            id: SealId::new(format!("ak:seal:{}", hash(0).as_str())).unwrap(),
            realm_id: realm(),
            predecessor_refs: Vec::new(),
            delta: Vec::new(),
            control_event_set_root,
            state_root,
            completeness_root: hash(0xcc),
            notary_seq: 1,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests,
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: "did:webvh:z6mkfixture:notary.example#key-1".to_owned(),
                payload_digest: hash(0),
                created_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 0).unwrap(),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            }),
            sealed_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 1).unwrap(),
            hlc: Hlc::new("01980b44cc01-0000-aabbccdd").unwrap(),
            kind: SealKind::Compaction,
        };
        let payload_digest = Hash::new(canonical::sha256_digest(
            seal.canonical_bytes_for_id().unwrap(),
        ))
        .unwrap();
        if let NotarySig::Single(signature) = &mut seal.notary_signature {
            signature.payload_digest = payload_digest;
        }
        seal.id = seal.derive_id().unwrap();
        seal
    }

    fn fixture() -> Fixture {
        let effective_scope = EffectiveScope::Realm { realm_id: realm() };
        let frontier_event = frontier_event(effective_scope.clone());
        let frontier_digest = MoveId::new(frontier_event.event_digest().unwrap()).unwrap();
        let covered_event_digests = vec![frontier_digest.clone()];
        let covered = BTreeSet::from([frontier_digest]);
        let control_state = control_state();
        let states = state_map(&control_state);
        let policy_root = derive_mls_policy_root(&states).unwrap();
        let capability_root = derive_mls_capability_root(&states).unwrap();
        let discussion_metadata_digest =
            derive_mls_discussion_metadata_digest(&control_state).unwrap();
        let binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            policy_root,
            capability_root,
            discussion_metadata_digest,
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        let seal = seal(
            compute_state_root(&states).unwrap(),
            covered_event_digests.clone(),
            control_event_set_root(&covered).unwrap(),
        );
        let seal_id = seal.id.clone();
        Fixture {
            bundle: MaterializedMlsGovernanceProofBundle {
                bundle_version: MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
                proof_request_digest: hash(0),
                bundle_digest: hash(0),
                materialization_profile: MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE.to_owned(),
                realm_id: realm(),
                effective_scope,
                reducer_profile: "ak.reducer.v1".to_owned(),
                governance_binding: binding.clone(),
                trusted_anchor_seal_id: seal_id.clone(),
                accepted_seal_id: seal_id,
                seal_path: vec![seal],
                covered_event_digests: covered_event_digests
                    .into_iter()
                    .map(|digest| Hash::new(digest.as_str().to_owned()).unwrap())
                    .collect(),
                control_state,
                frontier_events: vec![frontier_event],
            },
            binding,
        }
    }

    fn verify(fixture: &Fixture) -> Result<VerifiedMlsGovernanceProof> {
        verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
        )
    }

    fn proof_request(fixture: &Fixture) -> MlsGovernanceProofRequest {
        MlsGovernanceProofRequest {
            realm_id: fixture.bundle.realm_id.clone(),
            effective_scope: fixture.bundle.effective_scope.clone(),
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 0,
            next_epoch: 1,
            binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE.to_owned(),
            reducer_profile: fixture.bundle.reducer_profile.clone(),
            trusted_anchor_seal_id: fixture.bundle.trusted_anchor_seal_id.clone(),
            chunk_index: 0,
            expected_bundle_digest: None,
        }
    }

    #[test]
    fn complete_bundle_verifies() {
        let fixture = fixture();
        let verified = verify(&fixture).unwrap();
        assert_eq!(verified.accepted_seal_id, fixture.bundle.accepted_seal_id);
        assert_eq!(verified.membership_frontier, vec![event_id()]);
    }

    #[test]
    fn chunked_bundle_round_trips_before_verification() {
        let fixture = fixture();
        let request = proof_request(&fixture);
        let chunks = build_mls_governance_proof_chunks(&request, &fixture.bundle).unwrap();
        assert!(chunks.len() >= 2);
        let assembled = assemble_mls_governance_proof_chunks(&request, &chunks).unwrap();
        assert_eq!(assembled.seal_path, fixture.bundle.seal_path);
        assert_eq!(assembled.control_state, fixture.bundle.control_state);
        verify_mls_governance_proof_bundle::<Error, _, _>(
            &assembled,
            &fixture.binding,
            &request.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
    }

    #[test]
    fn incomplete_duplicate_and_out_of_order_chunks_fail_closed() {
        let fixture = fixture();
        let request = proof_request(&fixture);
        let chunks = build_mls_governance_proof_chunks(&request, &fixture.bundle).unwrap();

        let mut missing = chunks.clone();
        missing.pop();
        assert!(
            assemble_mls_governance_proof_chunks(&request, &missing)
                .unwrap_err()
                .to_string()
                .contains("mls_governance_proof_incomplete")
        );

        let mut duplicate = chunks.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(assemble_mls_governance_proof_chunks(&request, &duplicate).is_err());

        let mut out_of_order = chunks;
        out_of_order.swap(0, 1);
        assert!(
            assemble_mls_governance_proof_chunks(&request, &out_of_order)
                .unwrap_err()
                .to_string()
                .contains("chunk_index order")
        );
    }

    #[test]
    fn tampered_and_mixed_chunks_fail_closed() {
        let fixture = fixture();
        let request = proof_request(&fixture);
        let chunks = build_mls_governance_proof_chunks(&request, &fixture.bundle).unwrap();

        let mut tampered = chunks.clone();
        tampered[0].chunk = match tampered[0].chunk.clone() {
            MlsGovernanceProofChunk::SealPath {
                chunk_index,
                start_index,
                mut items,
                chunk_digest,
                chunk_proof,
            } => {
                items[0].notary_seq += 1;
                MlsGovernanceProofChunk::SealPath {
                    chunk_index,
                    start_index,
                    items,
                    chunk_digest,
                    chunk_proof,
                }
            }
            _ => panic!("first chunk must be seal_path"),
        };
        assert!(
            assemble_mls_governance_proof_chunks(&request, &tampered)
                .unwrap_err()
                .to_string()
                .contains("chunk_digest mismatch")
        );

        let mut mixed = chunks;
        mixed[1].accepted_seal_id =
            SealId::new(format!("ak:seal:{}", hash(0xfe).as_str())).unwrap();
        assert!(
            assemble_mls_governance_proof_chunks(&request, &mixed)
                .unwrap_err()
                .to_string()
                .contains("mix different bundles")
        );
    }

    #[test]
    fn rejected_seal_signature_is_propagated() {
        let fixture = fixture();
        let error = verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| {
                Err(Error::Protocol(
                    "fixture Seal signature rejected".to_owned(),
                ))
            },
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fixture Seal signature rejected")
        );
    }

    #[test]
    fn rejected_frontier_event_signature_is_propagated() {
        let fixture = fixture();
        let error = verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| {
                Err(Error::Protocol(
                    "fixture frontier Event signature rejected".to_owned(),
                ))
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fixture frontier Event signature rejected")
        );
    }

    #[test]
    fn seal_signature_payload_digest_tampering_is_rejected() {
        let mut fixture = fixture();
        let NotarySig::Single(signature) = &mut fixture.bundle.seal_path[0].notary_signature else {
            panic!("fixture must use a single notary signature");
        };
        signature.payload_digest = hash(0xef);
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn proof_request_rejects_epoch_skip() {
        let request = MlsGovernanceProofRequest {
            realm_id: realm(),
            effective_scope: EffectiveScope::Realm { realm_id: realm() },
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 3,
            next_epoch: 5,
            binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE.to_owned(),
            reducer_profile: "ak.reducer.v1".to_owned(),
            trusted_anchor_seal_id: SealId::new(format!("ak:seal:{}", hash(0).as_str())).unwrap(),
            chunk_index: 0,
            expected_bundle_digest: None,
        };
        let error = request.validate().unwrap_err();
        assert!(error.to_string().contains(ErrorCode::SCHEMA_VIOLATION));
    }

    #[test]
    fn proof_request_accepts_genesis_epoch() {
        let request = MlsGovernanceProofRequest {
            realm_id: realm(),
            effective_scope: EffectiveScope::Realm { realm_id: realm() },
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 0,
            next_epoch: 0,
            binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE.to_owned(),
            reducer_profile: "ak.reducer.v1".to_owned(),
            trusted_anchor_seal_id: SealId::new(format!("ak:seal:{}", hash(0).as_str())).unwrap(),
            chunk_index: 0,
            expected_bundle_digest: None,
        };
        request.validate().unwrap();
    }

    #[test]
    fn bundle_epoch_tampering_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.governance_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            1,
            2,
            vec![event_id()],
            fixture.binding.policy_root().clone(),
            fixture.binding.capability_root().unwrap().clone(),
            fixture
                .binding
                .discussion_metadata_digest()
                .unwrap()
                .clone(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn bundle_scope_tampering_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.effective_scope = EffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014b").unwrap(),
        };
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn bundle_reducer_profile_tampering_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.reducer_profile = "ak.reducer.tampered.v1".to_owned();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn omitted_control_leaf_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.control_state.remove(0);
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn incomplete_covered_manifest_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.covered_event_digests.clear();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn missing_frontier_event_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.frontier_events.clear();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn cross_scope_frontier_event_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.frontier_events[0].effective_scope = None;
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn discussion_metadata_tampering_is_rejected() {
        let mut fixture = fixture();
        let bad_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            fixture.binding.policy_root().clone(),
            fixture.binding.capability_root().unwrap().clone(),
            hash(0xee),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        fixture.bundle.governance_binding = bad_binding.clone();
        fixture.binding = bad_binding;
        let error = verify(&fixture).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }

    #[test]
    fn policy_root_tampering_is_rejected() {
        let mut fixture = fixture();
        let bad_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            hash(0xed),
            fixture.binding.capability_root().unwrap().clone(),
            fixture
                .binding
                .discussion_metadata_digest()
                .unwrap()
                .clone(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        fixture.bundle.governance_binding = bad_binding.clone();
        fixture.binding = bad_binding;
        let error = verify(&fixture).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }

    #[test]
    fn capability_root_tampering_is_rejected() {
        let mut fixture = fixture();
        let bad_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            fixture.binding.policy_root().clone(),
            hash(0xec),
            fixture
                .binding
                .discussion_metadata_digest()
                .unwrap()
                .clone(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        fixture.bundle.governance_binding = bad_binding.clone();
        fixture.binding = bad_binding;
        let error = verify(&fixture).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }
}
