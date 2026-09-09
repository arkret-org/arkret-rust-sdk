//! Full portable-context regressions derived from the real HTTP pairing fixture.
//! All modified authority statements are re-signed; there is no trust callback bypass.

use arkret_models_collaboration::current_signer_evidence::{
    CompactAgentSignerResolutionEvidence, CurrentSignerEvidenceItem,
    CurrentSignerEvidenceQueryRequestBody, CurrentSignerEvidenceSelector,
};
use arkret_models_identity::{AgentAdmissionEvidence, AgentAuthorityState};
use arkret_wire::{ActorId, DidUrl, NotarySig, NotarySignerDescriptor, SealSignature};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::SeedableRng as _;

use super::*;

#[derive(Clone, serde::Deserialize)]
struct Fixture {
    actor: ActorId,
    verification_method: DidUrl,
    realm_id: RealmId,
    recipient_account_id: arkret_wire::AccountId,
    root: AuthenticatedSignerResolutionEvidence,
    dependencies: Vec<AuthenticatedSignerResolutionEvidence>,
}

impl Fixture {
    fn load() -> Self {
        serde_json::from_str(include_str!("../tests/fixtures/agent-current-context.json")).unwrap()
    }

    fn admission(&self) -> &AgentAdmissionEvidence {
        let AuthenticatedSignerResolutionEvidence::Agent {
            agent_signer_evidence,
            ..
        } = &self.root
        else {
            panic!("Agent root")
        };
        agent_signer_evidence.admission_evidence()
    }

    fn admission_mut(&mut self) -> &mut AgentAdmissionEvidence {
        let AuthenticatedSignerResolutionEvidence::Agent {
            agent_signer_evidence,
            ..
        } = &mut self.root
        else {
            panic!("Agent root")
        };
        let AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        } = agent_signer_evidence.as_mut()
        else {
            panic!("current root")
        };
        admission_evidence
    }

    fn state_mut(&mut self) -> &mut AgentAuthorityState {
        &mut self.admission_mut().agent_authority_state_evidence.state
    }

    fn resign_state(&mut self, signer: &SigningKey) {
        let admission = self.admission_mut();
        let snapshot = &mut admission.agent_authority_state_evidence;
        snapshot.state_digest =
            Hash::new(arkret_canonical::canonical_sha256(&snapshot.state).unwrap()).unwrap();
        snapshot.lease.state_digest = snapshot.state_digest.clone();
        arkret_signatures::agent_evidence::sign_agent_authority_state_lease(
            &mut snapshot.lease,
            signer,
        )
        .unwrap();
        admission.admission_evidence_digest =
            arkret_signatures::agent_evidence::agent_admission_evidence_digest(
                snapshot,
                &admission.controller_account_gate_attestation,
            )
            .unwrap();
    }

    fn verify(&self) -> Result<VerifiedAgentCurrentContext, WireError> {
        // Exercise the consumer's exact closure gate before the cryptographic entry.
        let item = CurrentSignerEvidenceItem::Agent {
            actor: self.actor.clone(),
            verification_method: self.verification_method.clone(),
            authenticated_signer_evidence: CompactAgentSignerResolutionEvidence::from_full(
                &self.root,
                &[],
            )?,
            dependencies: self.dependencies.clone(),
        };
        let request = CurrentSignerEvidenceQueryRequestBody {
            request_id: arkret_wire::RequestId::new(
                "ak:request:01904100-0000-7000-8000-a11ce0000001".to_owned(),
            )?,
            realm_id: self.realm_id.clone(),
            recipient_account_id: self.recipient_account_id.clone(),
            queries: vec![CurrentSignerEvidenceSelector::Agent {
                actor: self.actor.clone(),
                verification_method: self.verification_method.clone(),
            }],
            known_agent_state_digests: vec![],
            known_signer_evidence_refs: vec![],
        };
        let (root, dependencies) = item.hydrate_agent(&request, &BTreeMap::new(), &[])?;
        let dependencies = dependencies
            .into_iter()
            .map(|evidence| {
                Ok(
                    GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                        selector:
                            GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                                content_digest: evidence.canonical_sha256_digest()?,
                            },
                        authenticated_signer_resolution_evidence: Box::new(evidence),
                    },
                )
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        let callback_root = std::sync::Arc::new(root.clone());
        let callback_dependencies = std::sync::Arc::new(dependencies.clone());
        let future = verify_agent_current_context(
            &self.actor,
            &self.verification_method,
            &root,
            &dependencies,
            self.admission().valid_from(),
            None,
            move |request| {
                let root = callback_root.clone();
                let dependencies = callback_dependencies.clone();
                Box::pin(async move { verify_agent_portable_trust(request, &root, &dependencies) })
            },
        );
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => panic!("portable verification attempted network I/O"),
        }
    }
}

fn station_key() -> SigningKey {
    SigningKey::from_bytes(&arkret_canonical::sha256_bytes(
        b"soland:test-fixture-notary:https://server.test",
    ))
}

fn seal_signature(seal: &Seal, method: &DidUrl, key: &SigningKey) -> NotarySig {
    let bytes = seal.canonical_bytes_for_id().unwrap();
    let protected = arkret_canonical::base64url_encode(
        arkret_canonical::canonical_json_bytes(&serde_json::json!({"alg":"Ed25519", "kid":method}))
            .unwrap(),
    );
    let signature =
        key.sign(format!("{protected}.{}", arkret_canonical::base64url_encode(&bytes)).as_bytes());
    NotarySig::Single(SealSignature {
        verification_method: method.clone(),
        payload_digest: Hash::new(arkret_canonical::digest(
            seal.state_root.digest_suite().unwrap(),
            &bytes,
        ))
        .unwrap(),
        jws: format!(
            "{protected}..{}",
            arkret_canonical::base64url_encode(signature.to_bytes())
        ),
    })
}

fn replace_seal_signer(
    fixture: &mut Fixture,
    descriptor: &NotarySignerDescriptor,
    key: &SigningKey,
    delegated: bool,
) {
    let state = fixture.state_mut();
    for seal in &mut state.seal_lineages {
        seal.notary_signature = seal_signature(seal, &descriptor.verification_method, key);
    }
    for seal in [
        &mut state.key_state_witness.seal,
        &mut state.agent_lifecycle_witness.seal,
    ] {
        seal.notary_signature = seal_signature(seal, &descriptor.verification_method, key);
    }
    state.accepted_delegated_notary_signers = if delegated {
        vec![descriptor.clone()]
    } else {
        vec![]
    };
    fixture.resign_state(&station_key());
}

#[test]
fn portable_agent_root_notary_full_context_uses_frozen_genesis_key() {
    let mut fixture = Fixture::load();
    fixture.verify().unwrap();
    let state = &fixture.admission().agent_authority_state_evidence.state;
    let authority = arkret_bootstrap::AgentPcrGenesisAuthority::from_accepted_create(
        &state.pcr_genesis_event,
        &|event| {
            arkret_schema::project_registered_cell_writes(
                event,
                event
                    .event_id
                    .event_digest()
                    .digest_suite()
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        },
    )
    .unwrap();
    let payload: arkret_models_collaboration::events_payloads::realm::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&state.pcr_genesis_event.payload).unwrap())
            .unwrap();
    let arkret_wire::NotaryValue::SingleSigner {
        signer: descriptor, ..
    } = payload.object.notary
    else {
        panic!("single frozen Agent root")
    };
    // The HTTP fixture's configured PCR notary is a frozen Agent-owned key,
    // distinct from its DID update key (test_single_signer_notary uses 0x53).
    let root_key = SigningKey::from_bytes(&[0x53; 32]);
    assert_eq!(
        descriptor.frozen_public_key_b64u,
        arkret_canonical::base64url_encode(root_key.verifying_key().to_bytes())
    );
    assert_eq!(authority.agent_id(), &fixture.actor);
    replace_seal_signer(&mut fixture, &descriptor, &root_key, false);
    fixture.verify().unwrap();
    let mut wrong_key = fixture.clone();
    replace_seal_signer(
        &mut wrong_key,
        &descriptor,
        &SigningKey::from_bytes(&[92; 32]),
        false,
    );
    assert!(wrong_key.verify().is_err());
}

#[test]
fn portable_agent_another_controller_device_seals_with_exact_retained_key() {
    let mut fixture = Fixture::load();
    let state = &fixture.admission().agent_authority_state_evidence.state;
    let mut descriptor = state.accepted_delegated_notary_signers[0].clone();
    let method = DidUrl::new(
        "did:web:alice.example#ak:device:01904100-0000-7000-8000-a11ce0000002".to_owned(),
    )
    .unwrap();
    for event in [
        &state.pcr_genesis_event,
        &state.key_authorization_event,
        &state.agent_lifecycle_witness.accepted_status_event,
    ] {
        assert!(
            event
                .proofs
                .iter()
                .filter_map(EventProof::as_station_admission)
                .all(|proof| proof.producer_verification_method != method)
        );
    }
    let key = SigningKey::from_bytes(&[92; 32]);
    descriptor.verification_method = method;
    descriptor.frozen_public_key_b64u =
        arkret_canonical::base64url_encode(key.verifying_key().to_bytes());
    descriptor.frozen_public_key_digest = Hash::new(arkret_canonical::sha256_digest(
        key.verifying_key().to_bytes(),
    ))
    .unwrap();
    descriptor.validate().unwrap();
    replace_seal_signer(&mut fixture, &descriptor, &key, true);
    fixture.verify().unwrap();
    for mutation in 0..7 {
        let mut rejected = fixture.clone();
        let state = rejected.state_mut();
        match mutation {
            0 => state.accepted_delegated_notary_signers.clear(),
            1 => state.accepted_delegated_notary_signers[0].actor_id = fixture.actor.clone(),
            2 => {
                state.accepted_delegated_notary_signers[0].verification_method =
                    DidUrl::new("did:web:alice.example#unrelated".to_owned()).unwrap()
            }
            3 => {
                let bad = SigningKey::from_bytes(&[93; 32]).verifying_key().to_bytes();
                state.accepted_delegated_notary_signers[0].frozen_public_key_b64u =
                    arkret_canonical::base64url_encode(bad);
                state.accepted_delegated_notary_signers[0].frozen_public_key_digest =
                    Hash::new(arkret_canonical::sha256_digest(bad)).unwrap();
            }
            4 => {
                state.accepted_delegated_notary_signers[0].frozen_public_key_digest =
                    Hash::new(arkret_canonical::sha256_digest(b"wrong digest")).unwrap()
            }
            5 => state
                .accepted_delegated_notary_signers
                .push(descriptor.clone()),
            _ => state.key_authorization_event.authorization_ref = None,
        }
        rejected.resign_state(&station_key());
        assert!(
            rejected.verify().is_err(),
            "re-signed invalid mapping mutation {mutation}"
        );
    }
    let mut wrong_realm = fixture.clone();
    wrong_realm.state_mut().key_authorization_event.realm_id = fixture.realm_id.clone();
    wrong_realm.resign_state(&station_key());
    assert!(wrong_realm.verify().is_err());
}

fn resign_station_refs(
    state: &mut AgentAuthorityState,
    reference: &arkret_wire::SignerEvidenceRef,
) {
    for event in [
        &mut state.pcr_genesis_event,
        &mut state.key_authorization_event,
        &mut state.agent_lifecycle_witness.accepted_status_event,
    ] {
        for proof in &mut event.proofs {
            if let EventProof::StationAdmission(proof) = proof {
                proof.signer_resolution_evidence_ref = reference.clone();
                proof.jws = arkret_signatures::sign_ed25519_detached_jws(
                    &station_key(),
                    &proof.canonical_binding_bytes().unwrap(),
                )
                .unwrap();
            }
        }
    }
}

#[test]
fn portable_agent_resume_cold_context_retains_original_root_notary() {
    use arkret_models_identity::{
        AgentLifecycleHead, AgentLifecycleProvenance, AgentLifecycleStatus,
    };
    let mut fixture = Fixture::load();
    let now = fixture.admission().valid_from() + chrono::Duration::seconds(5);
    let state = fixture.state_mut();
    let genesis = state.pcr_genesis_event.clone();
    let mut accepted_events = vec![genesis.clone(), state.key_authorization_event.clone()];
    for (kind, transition, previous_status, status, offset) in [
        (
            arkret_wire::EventKind::SelfAgentPause,
            "pause",
            "active",
            AgentLifecycleStatus::Paused,
            4,
        ),
        (
            arkret_wire::EventKind::SelfAgentResume,
            "resume",
            "paused",
            AgentLifecycleStatus::Active,
            2,
        ),
    ] {
        let mut resumed = state.key_authorization_event.clone();
        resumed.kind = kind;
        resumed.actor_seq += if transition == "pause" { 1 } else { 2 };
        resumed.created_at = now - chrono::Duration::seconds(offset);
        resumed.hlc = Some(
            arkret_identifiers::Hlc::new(format!(
                "{:012x}-0001-a13f9c2e",
                resumed.created_at.timestamp_millis()
            ))
            .unwrap(),
        );
        resumed.prev_refs = vec![if transition == "pause" {
            state.key_authorization_event.event_id.clone()
        } else {
            state
                .agent_lifecycle_witness
                .accepted_status_event
                .event_id
                .clone()
        }];
        resumed.seal_basis = Some(state.agent_lifecycle_witness.seal.seal_basis());
        resumed.payload = serde_json::from_value(serde_json::json!({"transition":transition, "previous_status":previous_status, "status_changed_at":arkret_canonical::format_timestamp_canonical(resumed.created_at)})).unwrap();
        resumed.requirements = Default::default();
        resumed
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let mut producer = resumed.proofs[0].as_producer().unwrap().clone();
        producer.created_at = resumed.created_at;
        producer.event_digest = resumed.event_id.event_digest();
        producer.jws = arkret_signatures::sign_ed25519_detached_jws(
            &SigningKey::from_bytes(&[91; 32]),
            &producer.canonical_binding_bytes(&resumed.actor_id).unwrap(),
        )
        .unwrap();
        let mut proof = resumed.proofs[1].as_station_admission().unwrap().clone();
        proof.event_digest = producer.event_digest.clone();
        proof.accepted_at = resumed.created_at;
        proof.producer_proof_digest =
            arkret_wire::StationAdmissionProof::producer_proof_digest(&producer).unwrap();
        proof.jws = arkret_signatures::sign_ed25519_detached_jws(
            &station_key(),
            &proof.canonical_binding_bytes().unwrap(),
        )
        .unwrap();
        resumed.proofs = vec![
            EventProof::Producer(producer),
            EventProof::StationAdmission(proof),
        ];
        let witness = &mut state.agent_lifecycle_witness;
        witness.provenance = if transition == "pause" {
            AgentLifecycleProvenance::PauseAccepted {
                pause_event_id: resumed.event_id.clone(),
            }
        } else {
            AgentLifecycleProvenance::ResumeAccepted {
                resume_event_id: resumed.event_id.clone(),
            }
        };
        witness.cell_value = status;
        witness.cell_heads = vec![AgentLifecycleHead {
            event_id: resumed.event_id.clone(),
            value: status,
        }];
        witness.accepted_status_event = resumed.clone();
        witness.leaf_digest = arkret_state::state::state_root::state_leaf_hash_from_state_object(
            &arkret_wire::CellRef::new(witness.cell_ref.as_str().to_owned()).unwrap(),
            serde_json::json!({"heads":witness.cell_heads}),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        // Preserve every sibling of the real accepted state, changing only its
        // lifecycle head. This keeps the other eight cells (including key state).
        let raw = |hash: &Hash| -> Vec<u8> {
            hash.as_str()
                .split_once(':')
                .unwrap()
                .1
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        };
        let mut hash = witness.leaf_digest.clone();
        let mut index = witness.leaf_index;
        let mut width = witness.leaf_count;
        let mut siblings = witness.inclusion_proof.iter();
        while width > 1 {
            if !index.is_multiple_of(2) || index + 1 < width {
                let sibling = siblings.next().unwrap();
                let (left, right) = if index.is_multiple_of(2) {
                    (raw(&hash), raw(sibling))
                } else {
                    (raw(sibling), raw(&hash))
                };
                hash = Hash::new(arkret_canonical::sha256_digest(
                    [vec![1], left, right].concat(),
                ))
                .unwrap();
            }
            index /= 2;
            width = width.div_ceil(2);
        }
        assert!(siblings.next().is_none());
        let mut seal = witness.seal.clone();
        seal.predecessor_refs = vec![state.frontier_seal_id.clone()];
        seal.delta = vec![resumed.event_id.event_digest()];
        seal.covered_event_digests
            .push(resumed.event_id.event_digest());
        seal.covered_event_digests.sort();
        accepted_events.push(resumed.clone());
        let covered = seal
            .covered_event_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            covered,
            accepted_events
                .iter()
                .map(|event| event.event_id.event_digest())
                .collect()
        );
        seal.control_event_set_root = arkret_state::state::seal::control_event_set_root(
            &covered,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        seal.completeness_root =
            arkret_state::state::seal::control_event_completeness_root_from_listed(
                &accepted_events
                    .iter()
                    .map(|event| arkret_state::state::seal::ListedControlEvent {
                        actor_id: event.actor_id.clone(),
                        actor_seq: event.actor_seq,
                        event_digest: event.event_id.event_digest(),
                    })
                    .collect::<Vec<_>>(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
        seal.state_root = hash.clone();
        seal.sealed_at = resumed.created_at + chrono::Duration::seconds(1);
        seal.notary_seq += 1;
        seal.hlc = arkret_identifiers::Hlc::new(format!(
            "{:012x}-0002-a13f9c2e",
            seal.sealed_at.timestamp_millis()
        ))
        .unwrap();
        seal.id = seal
            .derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        witness.seal_id = seal.id.clone();
        witness.state_root = hash.clone();
        witness.seal = seal.clone();
        state.frontier_seal_id = seal.id.clone();
        state.frontier_state_root = hash;
        state.seal_lineages.push(seal);
    }
    let resumed = state.agent_lifecycle_witness.accepted_status_event.clone();
    let payload: arkret_models_collaboration::events_payloads::realm::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&genesis.payload).unwrap()).unwrap();
    let arkret_wire::NotaryValue::SingleSigner {
        signer: descriptor, ..
    } = payload.object.notary
    else {
        panic!("single Agent root")
    };
    {
        let admission = fixture.admission_mut();
        admission.agent_authority_state_evidence.lease.issued_at = now;
        admission.agent_authority_state_evidence.lease.expires_at =
            now + chrono::Duration::seconds(120);
    }
    replace_seal_signer(
        &mut fixture,
        &descriptor,
        &SigningKey::from_bytes(&[0x53; 32]),
        false,
    );
    assert_eq!(
        fixture
            .admission()
            .agent_authority_state_evidence
            .state
            .pcr_genesis_event,
        genesis
    );
    fixture.verify().unwrap();
    let mut missing_genesis = fixture.clone();
    missing_genesis.state_mut().pcr_genesis_event = resumed;
    missing_genesis.resign_state(&station_key());
    assert!(missing_genesis.verify().is_err());
}

#[test]
fn portable_agent_old_station_method_is_verified_from_complete_rotated_history() {
    let mut fixture = Fixture::load();
    let original = fixture.dependencies[0].clone();
    let AuthenticatedSignerResolutionEvidence::Service {
        signer_id,
        verification_method: old_method,
        authenticated_resolution,
    } = &original
    else {
        panic!("Service leaf")
    };
    let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
        &authenticated_resolution.method_history_evidence
    else {
        panic!("native history")
    };
    let did = authenticated_resolution.normalized_did_document.id.clone();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(arkret_canonical::sha256_bytes(
        b"soland:test-fixture-webvh-update:https://server.test",
    ));
    let endpoint = "https://server.test/".parse().unwrap();
    let inception = arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: "2026-01-01T00:00:00Z".parse().unwrap(),
            did_key_fragment: Some("notary-key"),
        },
        &station_key().to_bytes(),
    )
    .unwrap();
    let now = fixture.admission().valid_from() + chrono::Duration::seconds(2);
    let rotation_at = now - chrono::Duration::seconds(1);
    let new_key = SigningKey::from_bytes(&[94; 32]);
    let new_method = DidUrl::new(format!("{did}#rotated-notary")).unwrap();
    let mut document = log_entries.last().unwrap()["state"].clone();
    document["verificationMethod"] = serde_json::json!([{"id":new_method, "type":"Multikey", "controller":did, "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(new_key.verifying_key().as_bytes())}]);
    document["assertionMethod"] = serde_json::json!([new_method]);
    document["authentication"] = serde_json::json!([new_method]);
    let rotation = arkret_signatures::webvh::prepare_service_rotation(
        &arkret_signatures::webvh::ServiceRotationInput {
            did: did.as_str(),
            previous_entries: log_entries,
            state: &document,
            current_update_seed: &inception.next_update_key_seed,
            next_update_public_key_multibase:
                &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    SigningKey::from_bytes(&[95; 32]).verifying_key().as_bytes(),
                ),
            version_time: rotation_at,
        },
    )
    .unwrap();
    let mut logs = log_entries.clone();
    logs.push(rotation.log_entry);
    let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
        signer_id.clone(),
        "station".to_owned(),
        serde_json::from_value(document).unwrap(),
        logs,
        vec![],
        now,
    )
    .unwrap();
    let old_leaf = AuthenticatedSignerResolutionEvidence::Service {
        signer_id: signer_id.clone(),
        verification_method: old_method.clone(),
        authenticated_resolution: resolution.clone(),
    };
    let new_leaf = AuthenticatedSignerResolutionEvidence::Service {
        signer_id: signer_id.clone(),
        verification_method: new_method.clone(),
        authenticated_resolution: resolution,
    };
    // Source head has already removed the old method, yet all three original
    // admissions select its genuine historical key at their accepted_at.
    assert!(authenticated_document_key(&old_leaf, &[], now).is_err());
    assert!(
        authenticated_document_key(
            &old_leaf,
            &[],
            fixture
                .admission()
                .agent_authority_state_evidence
                .state
                .key_authorization_event
                .proofs
                .iter()
                .find_map(EventProof::as_station_admission)
                .unwrap()
                .accepted_at
        )
        .is_ok()
    );
    resign_station_refs(fixture.state_mut(), &old_leaf.evidence_ref().unwrap());
    {
        let admission = fixture.admission_mut();
        let lease = &mut admission.agent_authority_state_evidence.lease;
        lease.verification_method = new_method.clone();
        lease.issued_at = now;
        lease.expires_at = now + chrono::Duration::seconds(120);
        let gate = &mut admission.controller_account_gate_attestation;
        gate.verification_method = new_method;
        gate.issued_at = now;
        gate.expires_at = now + chrono::Duration::seconds(120);
        arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(gate, &new_key)
            .unwrap();
    }
    fixture.resign_state(&new_key);
    let AuthenticatedSignerResolutionEvidence::Agent {
        attester_signer_evidence_ref,
        account_authority_signer_evidence_ref,
        ..
    } = &mut fixture.root
    else {
        unreachable!()
    };
    *attester_signer_evidence_ref = new_leaf.evidence_ref().unwrap();
    *account_authority_signer_evidence_ref = new_leaf.evidence_ref().unwrap();
    fixture.dependencies = vec![old_leaf, new_leaf];
    fixture.verify().unwrap();
    let mut missing = fixture.clone();
    missing.dependencies.remove(0);
    assert!(missing.verify().is_err());
    let mut surplus = fixture.clone();
    surplus.dependencies.push(original);
    assert!(surplus.verify().is_err());
    let mut wrong_method = fixture.clone();
    let current_ref = wrong_method.dependencies[1].evidence_ref().unwrap();
    resign_station_refs(wrong_method.state_mut(), &current_ref);
    wrong_method.dependencies.remove(0);
    wrong_method.resign_state(&new_key);
    assert!(wrong_method.verify().is_err());
    let mut changed_proof = fixture.clone();
    let EventProof::StationAdmission(proof) =
        &mut changed_proof.state_mut().key_authorization_event.proofs[1]
    else {
        panic!("Station proof")
    };
    proof.producer_signing_key_did = arkret_wire::DidKey::new(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[96; 32]).verifying_key().as_bytes()
        )
    ))
    .unwrap();
    proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &station_key(),
        &proof.canonical_binding_bytes().unwrap(),
    )
    .unwrap();
    changed_proof.resign_state(&new_key);
    assert!(changed_proof.verify().is_err());
}
