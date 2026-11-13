//! Isolated RFC 9420 feasibility experiment, not an Arkret admission path.
//!
//! The recovery subprocess receives only public group material and ciphertext.
//! Old private providers remain exclusively in the parent as adversarial copies.
//! Current Arkret ExternalInit/new_member_commit rejection is tested separately.

use std::path::{Path, PathBuf};
use std::process::Command;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use arkret_identifiers::project_did_to_core_id;
use arkret_mls::{ARKRET_MLS_CIPHERSUITE, decode_leaf_credential};
use arkret_models_collaboration::events_payloads::{
    MlsDecodedProposalType, MlsProposalMemberBinding, MlsProposalSenderClass, MlsProposalType,
    admit_inline_mls_proposal,
};
use arkret_models_crypto::mls_basic_credential_identity;
use arkret_wire::{AccountId, ActorId, Did, DidCoreId, EventId, RealmId, ScopeRef};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as _, Serialize as _};

const CHILD_NAME: &str = "external_recovery_subprocess";
const EXPORT_LABEL: &str = "external-recovery-feasibility";
const EXPORT_CONTEXT: &[u8] = b"post-removal-isolation";
const PROBE_NONCE: [u8; 12] = [0x37; 12];
const BEFORE: &[u8] = b"positive control: external join alone does not evict old devices";
const AFTER: &[u8] = b"recovered PCR message after every old endpoint was removed";

mod archive_recovery;

mod epoch_content_recovery;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    did: Did,
    account: AccountId,
    pcr: RealmId,
    scope: ScopeRef,
    group_id: Vec<u8>,
}

impl Binding {
    fn fixture(kind: &str) -> Self {
        assert!(matches!(kind, "human" | "agent"));
        let scid = if kind == "human" {
            "QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey"
        } else {
            "QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hweZ"
        };
        let did = Did::new(format!("did:webvh:{scid}:{kind}.example")).unwrap();
        let account = AccountId::new(
            project_did_to_core_id(&did).unwrap(),
            DidCoreId::new("ak:did_core:web:recovery-station.example").unwrap(),
        );
        let pcr = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [if kind == "human" { 0x45 } else { 0x46 }; 32],
        ));
        let scope = ScopeRef::Realm {
            realm_id: pcr.clone(),
        };
        let group_id = scope.canonical_mls_group_id_bytes().unwrap().to_vec();
        Self {
            did,
            account,
            pcr,
            scope,
            group_id,
        }
    }

    fn actor(&self) -> ActorId {
        ActorId::account(self.account.clone())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicCapsule {
    binding: Binding,
    epoch: u64,
    group_info: Vec<u8>,
    ratchet_tree: Vec<u8>,
    old_ciphertext: Vec<u8>,
    retired_signature_keys: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicResult {
    binding: Binding,
    base_epoch: u64,
    joined_epoch: u64,
    isolated_epoch: u64,
    new_signature_key: Vec<u8>,
    external_commit: Vec<u8>,
    removal_commit: Vec<u8>,
    before_removal_message: Vec<u8>,
    after_removal_message: Vec<u8>,
    exporter_ciphertext: Vec<u8>,
    removed_leaves: usize,
    restart_and_bidirectional_messages: bool,
    old_history_not_recovered: bool,
}

struct Endpoint {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl Endpoint {
    fn fresh(binding: &Binding) -> Self {
        let provider = OpenMlsRustCrypto::default();
        assert!(provider.storage().values.read().unwrap().is_empty());
        let signer = SignatureKeyPair::new(ARKRET_MLS_CIPHERSUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(
                mls_basic_credential_identity(&binding.actor()).unwrap(),
            )
            .into(),
            signature_key: signer.to_public_vec().into(),
        };
        Self {
            provider,
            signer,
            credential,
        }
    }

    fn key_package(&self) -> KeyPackageBundle {
        KeyPackage::builder()
            .build(
                ARKRET_MLS_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .unwrap()
    }
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build()
}

fn protocol(bytes: &[u8]) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .unwrap()
        .try_into_protocol_message()
        .unwrap()
}

fn apply_commit(endpoint: &Endpoint, group: &mut MlsGroup, bytes: &[u8]) {
    let processed = group
        .process_message(&endpoint.provider, protocol(bytes))
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(commit) = processed.into_content() else {
        panic!("expected a real staged Commit");
    };
    group
        .merge_staged_commit(&endpoint.provider, *commit)
        .unwrap();
}

fn decrypt(endpoint: &Endpoint, group: &mut MlsGroup, bytes: &[u8]) -> Vec<u8> {
    let processed = group
        .process_message(&endpoint.provider, protocol(bytes))
        .unwrap();
    let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
        panic!("expected an RFC PrivateMessage application payload");
    };
    message.into_bytes()
}

fn encrypt(endpoint: &Endpoint, group: &mut MlsGroup, bytes: &[u8]) -> Vec<u8> {
    group
        .create_message(&endpoint.provider, &endpoint.signer, bytes)
        .unwrap()
        .tls_serialize_detached()
        .unwrap()
}

fn exported_key(endpoint: &Endpoint, group: &MlsGroup) -> Vec<u8> {
    group
        .export_secret(endpoint.provider.crypto(), EXPORT_LABEL, EXPORT_CONTEXT, 16)
        .unwrap()
}

fn welcome_join(endpoint: &Endpoint, welcome: MlsMessageOut, tree: RatchetTreeIn) -> MlsGroup {
    let MlsMessageBodyIn::Welcome(welcome) =
        MlsMessageIn::tls_deserialize_exact(welcome.tls_serialize_detached().unwrap())
            .unwrap()
            .extract()
    else {
        panic!("expected Welcome");
    };
    StagedWelcome::new_from_welcome(&endpoint.provider, &join_config(), welcome, Some(tree))
        .unwrap()
        .into_group(&endpoint.provider)
        .unwrap()
}

fn original_devices(binding: &Binding, count: usize) -> (PublicCapsule, Vec<(Endpoint, MlsGroup)>) {
    let first = Endpoint::fresh(binding);
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ARKRET_MLS_CIPHERSUITE)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group = MlsGroup::new_with_group_id(
        &first.provider,
        &first.signer,
        &config,
        GroupId::from_slice(&binding.group_id),
        first.credential.clone(),
    )
    .unwrap();
    let mut others: Vec<(Endpoint, MlsGroup)> = Vec::new();
    for _ in 1..count {
        let endpoint = Endpoint::fresh(binding);
        let package = endpoint.key_package();
        let (commit, welcome, _) = group
            .add_members(
                &first.provider,
                &first.signer,
                &[package.key_package().clone()],
            )
            .unwrap();
        let bytes = commit.tls_serialize_detached().unwrap();
        group.merge_pending_commit(&first.provider).unwrap();
        for (existing, state) in &mut others {
            apply_commit(existing, state, &bytes);
        }
        let state = welcome_join(&endpoint, welcome, group.export_ratchet_tree().into());
        others.push((endpoint, state));
    }
    let old_ciphertext = encrypt(&first, &mut group, b"pre-loss encrypted history");
    for (endpoint, state) in &mut others {
        assert_eq!(
            decrypt(endpoint, state, &old_ciphertext),
            b"pre-loss encrypted history"
        );
    }
    let group_info = group
        .export_group_info(first.provider.crypto(), &first.signer, false)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let capsule = PublicCapsule {
        binding: binding.clone(),
        epoch: group.epoch().as_u64(),
        group_info,
        ratchet_tree: group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .unwrap(),
        old_ciphertext,
        retired_signature_keys: group.members().map(|member| member.signature_key).collect(),
    };
    others.push((first, group));
    (capsule, others)
}

fn external_join(
    capsule: &PublicCapsule,
    expected: &Binding,
    expected_epoch: u64,
) -> Result<(Endpoint, MlsGroup, Vec<u8>), String> {
    external_join_with_endpoint(capsule, expected, expected_epoch, Endpoint::fresh(expected))
}

fn external_join_with_endpoint(
    capsule: &PublicCapsule,
    expected: &Binding,
    expected_epoch: u64,
    fresh: Endpoint,
) -> Result<(Endpoint, MlsGroup, Vec<u8>), String> {
    if &capsule.binding != expected || capsule.epoch != expected_epoch {
        return Err("independent expected identity/scope/current-epoch mismatch".into());
    }
    let MlsMessageBodyIn::GroupInfo(info) =
        MlsMessageIn::tls_deserialize_exact(&capsule.group_info)
            .map_err(|error| format!("GroupInfo decode: {error:?}"))?
            .extract()
    else {
        return Err("not GroupInfo".into());
    };
    if info.group_id().as_slice() != expected.group_id || info.epoch().as_u64() != expected_epoch {
        return Err("signed GroupInfo differs from the expected current group".into());
    }
    let tree = RatchetTreeIn::tls_deserialize_exact(&capsule.ratchet_tree)
        .map_err(|error| format!("tree decode: {error:?}"))?;
    if capsule
        .retired_signature_keys
        .iter()
        .any(|key| key == fresh.signer.public())
    {
        return Err("new endpoint reused an old signing key".into());
    }
    let builder = MlsGroup::external_commit_builder()
        .with_config(join_config())
        .with_ratchet_tree(tree)
        .build_group(&fresh.provider, info, fresh.credential.clone())
        .map_err(|error| format!("external base validation: {error:?}"))?;
    let (mut group, bundle) = builder
        .load_psks(fresh.provider.storage())
        .map_err(|error| format!("PSK: {error:?}"))?
        .build(
            fresh.provider.rand(),
            fresh.provider.crypto(),
            &fresh.signer,
            |_| true,
        )
        .map_err(|error| format!("external Commit: {error:?}"))?
        .finalize(&fresh.provider)
        .map_err(|error| format!("external finalize: {error:?}"))?;
    if group.pending_commit().is_some() {
        group.merge_pending_commit(&fresh.provider).unwrap();
    }
    assert_eq!(group.group_id().as_slice(), expected.group_id);
    assert_eq!(group.epoch().as_u64(), expected_epoch + 1);
    assert_eq!(
        decode_leaf_credential(
            group
                .own_leaf_node()
                .unwrap()
                .credential()
                .serialized_content()
        )
        .unwrap(),
        expected.actor()
    );
    let bytes = bundle.into_commit().tls_serialize_detached().unwrap();
    let MlsMessageBodyIn::PublicMessage(message) = MlsMessageIn::tls_deserialize_exact(&bytes)
        .unwrap()
        .extract()
    else {
        panic!("external Commit must be a public handshake");
    };
    assert!(matches!(message.sender(), Sender::NewMemberCommit));
    let rejection = admit_inline_mls_proposal(
        MlsProposalSenderClass::NewMemberCommit,
        MlsDecodedProposalType::ExternalInit,
        MlsProposalType::Add,
        MlsProposalMemberBinding {
            leaf_occupied_in_exact_base: false,
            leaf_binds_verified_producer: false,
        },
    )
    .unwrap_err();
    assert_eq!(
        rejection.error_code,
        arkret_wire::ErrorCode::UnsupportedFeature
    );
    Ok((fresh, group, bytes))
}

fn recover(capsule: PublicCapsule, expected: Binding, expected_epoch: u64) -> PublicResult {
    recover_with_observer(capsule, expected, expected_epoch, |_, _, _| {})
}

fn recover_with_observer(
    capsule: PublicCapsule,
    expected: Binding,
    expected_epoch: u64,
    observe_isolated: impl FnOnce(&Endpoint, &mut MlsGroup, &[u8]),
) -> PublicResult {
    let endpoint = Endpoint::fresh(&expected);
    recover_with_endpoint(
        capsule,
        expected,
        expected_epoch,
        endpoint,
        observe_isolated,
    )
}

fn recover_with_endpoint(
    capsule: PublicCapsule,
    expected: Binding,
    expected_epoch: u64,
    endpoint: Endpoint,
    observe_isolated: impl FnOnce(&Endpoint, &mut MlsGroup, &[u8]),
) -> PublicResult {
    let (endpoint, mut group, external_commit) =
        external_join_with_endpoint(&capsule, &expected, expected_epoch, endpoint).unwrap();
    let joined_epoch = group.epoch().as_u64();
    let old_history_not_recovered = group
        .process_message(&endpoint.provider, protocol(&capsule.old_ciphertext))
        .is_err();
    assert!(old_history_not_recovered);
    let before_removal_message = encrypt(&endpoint, &mut group, BEFORE);
    let old_indices: Vec<_> = group
        .members()
        .filter(|member| {
            capsule
                .retired_signature_keys
                .contains(&member.signature_key)
        })
        .map(|member| member.index)
        .collect();
    assert_eq!(old_indices.len(), capsule.retired_signature_keys.len());
    let (removal, ..) = group
        .remove_members(&endpoint.provider, &endpoint.signer, &old_indices)
        .unwrap();
    group.merge_pending_commit(&endpoint.provider).unwrap();
    assert_eq!(group.members().count(), 1);
    assert_eq!(group.group_id().as_slice(), expected.group_id);
    let isolated_epoch = group.epoch().as_u64();
    assert_eq!(isolated_epoch, joined_epoch + 1);
    let after_removal_message = encrypt(&endpoint, &mut group, AFTER);
    let key = exported_key(&endpoint, &group);
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let exporter_ciphertext = cipher.encrypt(&Nonce::from(PROBE_NONCE), AFTER).unwrap();
    assert_eq!(
        cipher
            .decrypt(&Nonce::from(PROBE_NONCE), exporter_ciphertext.as_slice())
            .unwrap(),
        AFTER
    );

    observe_isolated(&endpoint, &mut group, &after_removal_message);

    let peer = Endpoint::fresh(&expected);
    let package = peer.key_package();
    let (_, welcome, _) = group
        .add_members(
            &endpoint.provider,
            &endpoint.signer,
            &[package.key_package().clone()],
        )
        .unwrap();
    group.merge_pending_commit(&endpoint.provider).unwrap();
    let mut peer_group = welcome_join(&peer, welcome, group.export_ratchet_tree().into());
    let message = encrypt(&endpoint, &mut group, b"recovered endpoint sends");
    assert_eq!(
        decrypt(&peer, &mut peer_group, &message),
        b"recovered endpoint sends"
    );

    let new_only_storage = endpoint.provider.storage().values.read().unwrap().clone();
    drop(group);
    let reopened = OpenMlsRustCrypto::default();
    *reopened.storage().values.write().unwrap() = new_only_storage;
    let mut group = MlsGroup::load(reopened.storage(), &GroupId::from_slice(&expected.group_id))
        .unwrap()
        .unwrap();
    let reply = encrypt(
        &peer,
        &mut peer_group,
        b"new peer replies after recovery restart",
    );
    let processed = group.process_message(&reopened, protocol(&reply)).unwrap();
    let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
        panic!("expected recovered endpoint to decrypt after storage reopen");
    };
    assert_eq!(
        message.into_bytes(),
        b"new peer replies after recovery restart"
    );

    PublicResult {
        binding: expected,
        base_epoch: expected_epoch,
        joined_epoch,
        isolated_epoch,
        new_signature_key: endpoint.signer.to_public_vec(),
        external_commit,
        removal_commit: removal.tls_serialize_detached().unwrap(),
        before_removal_message,
        after_removal_message,
        exporter_ciphertext,
        removed_leaves: old_indices.len(),
        restart_and_bidirectional_messages: true,
        old_history_not_recovered,
    }
}

#[test]
#[ignore = "subprocess worker; invoked by the public-material-only parent tests"]
fn external_recovery_subprocess() {
    let input = std::env::var_os("ARKRET_EXTERNAL_RECOVERY_INPUT").unwrap();
    let output = std::env::var_os("ARKRET_EXTERNAL_RECOVERY_OUTPUT").unwrap();
    let kind = std::env::var("ARKRET_EXTERNAL_RECOVERY_KIND").unwrap();
    let expected_epoch = std::env::var("ARKRET_EXTERNAL_RECOVERY_EPOCH")
        .unwrap()
        .parse()
        .unwrap();
    let capsule: PublicCapsule = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let result = recover(capsule, Binding::fixture(&kind), expected_epoch);
    std::fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
}

fn evidence_directory(kind: &str, count: usize) -> PathBuf {
    let root = std::env::var_os("ARKRET_EXTERNAL_RECOVERY_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("arkret-external-recovery"));
    let path = root.join(format!("{kind}-{count}-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn run_child(capsule: &PublicCapsule, kind: &str, directory: &Path) -> PublicResult {
    let input = directory.join("public-input.json");
    let output = directory.join("public-result.json");
    std::fs::write(&input, serde_json::to_vec_pretty(capsule).unwrap()).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD_NAME, "--ignored", "--nocapture"])
        .env("ARKRET_EXTERNAL_RECOVERY_INPUT", &input)
        .env("ARKRET_EXTERNAL_RECOVERY_OUTPUT", &output)
        .env("ARKRET_EXTERNAL_RECOVERY_KIND", kind)
        .env("ARKRET_EXTERNAL_RECOVERY_EPOCH", capsule.epoch.to_string());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x08000000);
    }
    let status = command.output().unwrap();
    assert!(
        status.status.success(),
        "recovery subprocess failed: {} {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap()
}

fn all_old_endpoints_lost(kind: &str, count: usize) {
    let binding = Binding::fixture(kind);
    let (capsule, mut attacker_copies) = original_devices(&binding, count);
    let directory = evidence_directory(kind, count);
    let result = run_child(&capsule, kind, &directory);
    assert_old_endpoints_excluded(&binding, &capsule, &result, &mut attacker_copies);
    println!(
        "{kind}: {count} old endpoints; epochs {} -> {} -> {}; fresh-process recovery; all old keys denied; {}",
        result.base_epoch,
        result.joined_epoch,
        result.isolated_epoch,
        directory.display()
    );
}

fn assert_old_endpoints_excluded(
    binding: &Binding,
    capsule: &PublicCapsule,
    result: &PublicResult,
    attacker_copies: &mut [(Endpoint, MlsGroup)],
) {
    assert_eq!(&result.binding, binding);
    assert_eq!(result.removed_leaves, attacker_copies.len());
    assert!(result.restart_and_bidirectional_messages);
    assert!(result.old_history_not_recovered);
    assert!(
        !capsule
            .retired_signature_keys
            .contains(&result.new_signature_key)
    );
    for (endpoint, old_group) in attacker_copies {
        let original_key = exported_key(endpoint, old_group);
        apply_commit(endpoint, old_group, &result.external_commit);
        assert!(old_group.is_active());
        assert_eq!(
            decrypt(endpoint, old_group, &result.before_removal_message),
            BEFORE
        );
        let bridge_key = exported_key(endpoint, old_group);
        let retained_storage = endpoint.provider.storage().values.read().unwrap().clone();
        let retained_provider = OpenMlsRustCrypto::default();
        *retained_provider.storage().values.write().unwrap() = retained_storage;
        let mut retained_group = MlsGroup::load(
            retained_provider.storage(),
            &GroupId::from_slice(&binding.group_id),
        )
        .unwrap()
        .unwrap();
        let removal = retained_group
            .process_message(&retained_provider, protocol(&result.removal_commit))
            .unwrap();
        let ProcessedMessageContent::StagedCommitMessage(removal) = removal.into_content() else {
            panic!("retained attacker state must validate the removal handshake");
        };
        assert!(removal.self_removed());
        assert!(retained_group.is_active());
        assert!(
            retained_group
                .process_message(&retained_provider, protocol(&result.after_removal_message))
                .is_err()
        );
        apply_commit(endpoint, old_group, &result.removal_commit);
        assert!(!old_group.is_active());
        assert!(
            old_group
                .process_message(&endpoint.provider, protocol(&result.after_removal_message))
                .is_err()
        );
        for retained_key in [original_key, bridge_key] {
            assert!(
                Aes128Gcm::new_from_slice(&retained_key)
                    .unwrap()
                    .decrypt(
                        &Nonce::from(PROBE_NONCE),
                        result.exporter_ciphertext.as_slice()
                    )
                    .is_err(),
                "retained old exporter material must fail cryptographic AEAD verification"
            );
        }
    }
}

#[test]
fn single_human_device_lost_recovers_same_account_pcr_and_group() {
    all_old_endpoints_lost("human", 1);
}

#[test]
fn every_human_device_lost_recovers_and_excludes_all_old_keys() {
    all_old_endpoints_lost("human", 3);
}

#[test]
fn agent_runtime_lost_recovers_same_agent_account_pcr_and_group() {
    all_old_endpoints_lost("agent", 2);
}

#[test]
fn tampered_public_material_and_identity_scope_drift_are_rejected() {
    let binding = Binding::fixture("human");
    let (capsule, _) = original_devices(&binding, 2);
    let mut wrong_binding = binding.clone();
    wrong_binding.account.station_id =
        DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    assert!(external_join(&capsule, &wrong_binding, capsule.epoch).is_err());
    assert!(external_join(&capsule, &Binding::fixture("agent"), capsule.epoch).is_err());
    assert!(external_join(&capsule, &binding, capsule.epoch + 1).is_err());
    let mut tampered = capsule.clone();
    *tampered.group_info.last_mut().unwrap() ^= 1;
    assert!(external_join(&tampered, &binding, capsule.epoch).is_err());
    let mut tampered = capsule.clone();
    *tampered.ratchet_tree.last_mut().unwrap() ^= 1;
    assert!(external_join(&tampered, &binding, capsule.epoch).is_err());
}

#[test]
fn old_recovery_base_can_fork_without_an_application_current_epoch_fence() {
    let binding = Binding::fixture("human");
    let (capsule, _) = original_devices(&binding, 1);
    let (first, mut group, commit) = external_join(&capsule, &binding, capsule.epoch).unwrap();
    let (_, competing, _) = external_join(&capsule, &binding, capsule.epoch).unwrap();
    assert_eq!(group.epoch(), competing.epoch());
    assert_ne!(group.export_ratchet_tree(), competing.export_ratchet_tree());
    assert!(external_join(&capsule, &binding, capsule.epoch + 1).is_err());
    assert!(
        group
            .process_message(&first.provider, protocol(&commit))
            .is_err()
    );
}
