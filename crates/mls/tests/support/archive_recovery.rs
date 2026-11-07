//! Test-only encrypted archive composition; not a registered backup format.
//! Recovery receives the mnemonic over stdin, never an old endpoint secret.

use std::io::Write as _;
use std::process::Stdio;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::Payload;
use arkret_canonical::canonical::canonical_json_bytes;
use arkret_crypto::hpke::{open_x25519_chacha20poly1305, seal_x25519_chacha20poly1305};
use arkret_crypto::identity_root::{
    derive_identity_recovery_key_material_from_bip39, generate_bip39_identity_recovery_mnemonic,
};
use openmls_traits::signatures::Signer as _;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::*;

const WORKER: &str = "archive_recovery::archive_recovery_subprocess";
const WRAP_INFO: &[u8] = b"isolated PCR archive PoC: HPKE data-key wrap";
type RestoredArchive = (Vec<Record>, Vec<Zeroizing<Vec<u8>>>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Origin {
    epoch: u64,
    sender: Vec<u8>,
    ordinal: u32,
    ciphertext_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    origin: Origin,
    plaintext: Vec<u8>,
    source_signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    binding: Binding,
    sequence: usize,
    previous: Option<[u8; 32]>,
    recovery_base_digest: [u8; 32],
    recovery_public_key: [u8; 32],
    origins: Vec<Origin>,
    archive_signer: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    header: Header,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    wrapped_key: String,
    signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryInput {
    public: PublicCapsule,
    archives: Vec<Archive>,
    source_ciphertexts: Vec<Vec<u8>>,
    known_signers: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryOutput {
    mls: PublicResult,
    next_archive: Archive,
    recovered_record_count: usize,
    recovered_content_digest: [u8; 32],
    original_mls_history_still_unreadable: bool,
    fresh_archive_key_rejects_all_old_data_keys: bool,
}

struct Fixture {
    input: RecoveryInput,
    attackers: Vec<(Endpoint, MlsGroup)>,
    plaintext: Vec<Record>,
    old_keys: Vec<Zeroizing<[u8; 32]>>,
    old_account_secret: Zeroizing<[u8; 32]>,
}

fn bytes(value: &impl Serialize) -> Vec<u8> {
    canonical_json_bytes(value).unwrap()
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn archive_digest(archive: &Archive) -> [u8; 32] {
    digest(&bytes(archive))
}

fn record_transcript(binding: &Binding, origin: &Origin, plaintext: &[u8]) -> Vec<u8> {
    bytes(&(
        "isolated archive source fixture",
        binding,
        origin,
        plaintext,
    ))
}

fn signed_record(
    binding: &Binding,
    endpoint: &Endpoint,
    epoch: u64,
    ordinal: u32,
    ciphertext: &[u8],
    plaintext: &[u8],
) -> Record {
    let origin = Origin {
        epoch,
        sender: endpoint.signer.to_public_vec(),
        ordinal,
        ciphertext_digest: digest(ciphertext),
    };
    let source_signature = endpoint
        .signer
        .sign(&record_transcript(binding, &origin, plaintext))
        .unwrap();
    Record {
        origin,
        plaintext: plaintext.to_vec(),
        source_signature,
    }
}

fn archive_transcript(archive: &Archive) -> Vec<u8> {
    bytes(&(
        "isolated archive manifest fixture",
        &archive.header,
        archive.nonce,
        &archive.ciphertext,
        &archive.wrapped_key,
    ))
}

fn verify_signature(key: &[u8], signature: &[u8], content: &[u8]) -> Result<(), String> {
    let key: [u8; 32] = key.try_into().map_err(|_| "signature key length")?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| "signature key")?;
    let signature =
        ed25519_dalek::Signature::from_slice(signature).map_err(|_| "signature length")?;
    key.verify_strict(content, &signature)
        .map_err(|_| "signature verification".into())
}

fn seal_archive(
    mut header: Header,
    records: &[Record],
    endpoint: &Endpoint,
    data_key: &[u8; 32],
) -> Archive {
    header.origins = records.iter().map(|record| record.origin.clone()).collect();
    header.archive_signer = endpoint.signer.to_public_vec();
    let aad = bytes(&header);
    let nonce = endpoint.provider.rand().random_array::<12>().unwrap();
    let plaintext = Zeroizing::new(bytes(&records));
    let ciphertext = Aes256Gcm::new_from_slice(data_key)
        .unwrap()
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    let wrapped_key =
        seal_x25519_chacha20poly1305(&header.recovery_public_key, data_key, WRAP_INFO, &aad)
            .unwrap();
    let mut archive = Archive {
        header,
        nonce,
        ciphertext,
        wrapped_key,
        signature: Vec::new(),
    };
    archive.signature = endpoint.signer.sign(&archive_transcript(&archive)).unwrap();
    archive
}

fn decrypt_data(archive: &Archive, key: &[u8]) -> Result<Vec<Record>, String> {
    let aad = bytes(&archive.header);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "data key length")?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(archive.nonce),
                Payload {
                    msg: &archive.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "archive AEAD authentication")?,
    );
    serde_json::from_slice(&plaintext).map_err(|_| "archive records decoding".into())
}

fn restore(
    input: &RecoveryInput,
    expected: &Binding,
    expected_head: [u8; 32],
    recovery_private_key: &[u8],
) -> Result<RestoredArchive, String> {
    if &input.public.binding != expected
        || input.archives.last().map(archive_digest) != Some(expected_head)
    {
        return Err("independently expected identity or archive head differs".into());
    }
    let mut previous = None;
    let mut records = Vec::new();
    let mut keys = Vec::new();
    for (index, archive) in input.archives.iter().enumerate() {
        if archive.header.binding != *expected
            || archive.header.sequence != index
            || archive.header.previous != previous
            || archive.header.recovery_base_digest != digest(&input.public.group_info)
            || !input.known_signers.contains(&archive.header.archive_signer)
        {
            return Err("archive identity, sequence, predecessor, base or signer differs".into());
        }
        verify_signature(
            &archive.header.archive_signer,
            &archive.signature,
            &archive_transcript(archive),
        )?;
        let key = Zeroizing::new(
            open_x25519_chacha20poly1305(
                recovery_private_key,
                &archive.wrapped_key,
                WRAP_INFO,
                &bytes(&archive.header),
            )
            .map_err(|_| "HPKE key unwrap")?,
        );
        let chunk = decrypt_data(archive, &key)?;
        if chunk
            .iter()
            .map(|record| &record.origin)
            .collect::<Vec<_>>()
            != archive.header.origins.iter().collect::<Vec<_>>()
        {
            return Err("archive source manifest differs".into());
        }
        for record in &chunk {
            if !input.known_signers.contains(&record.origin.sender)
                || !input
                    .source_ciphertexts
                    .iter()
                    .any(|ciphertext| digest(ciphertext) == record.origin.ciphertext_digest)
            {
                return Err("unknown source signer or missing source ciphertext".into());
            }
            verify_signature(
                &record.origin.sender,
                &record.source_signature,
                &record_transcript(expected, &record.origin, &record.plaintext),
            )?;
        }
        records.extend(chunk);
        keys.push(key);
        previous = Some(archive_digest(archive));
    }
    Ok((records, keys))
}

fn setup(kind: &str, recovery_public_key: [u8; 32]) -> Fixture {
    let binding = Binding::fixture(kind);
    let (mut public, mut attackers) = original_devices(&binding, 3);
    let first = attackers.last().unwrap();
    let mut plaintext = vec![signed_record(
        &binding,
        &first.0,
        public.epoch,
        0,
        &public.old_ciphertext,
        b"pre-loss encrypted history",
    )];
    let mut source_ciphertexts = vec![public.old_ciphertext.clone()];
    let mut chunks = Vec::new();
    for epoch_round in 0..2 {
        for round in 0..2 {
            for sender in 0..attackers.len() {
                let content = bytes(&serde_json::json!({
                    "fixture_private_control_field": format!("field-{epoch_round}-{sender}-{round}"),
                    "value": format!("private PCR value {kind} {epoch_round} {sender} {round}")
                }));
                let (endpoint, group) = &mut attackers[sender];
                let epoch = group.epoch().as_u64();
                let ciphertext = encrypt(endpoint, group, &content);
                let ordinal = round + u32::from(epoch_round == 0 && sender == 2);
                let record =
                    signed_record(&binding, endpoint, epoch, ordinal, &ciphertext, &content);
                for (index, (endpoint, group)) in attackers.iter_mut().enumerate() {
                    if index != sender {
                        assert_eq!(decrypt(endpoint, group, &ciphertext), content);
                    }
                }
                plaintext.push(record);
                source_ciphertexts.push(ciphertext);
            }
        }
        chunks.push(plaintext.len());
        if epoch_round == 0 {
            let (endpoint, group) = &mut attackers[0];
            let (commit, ..) = group
                .self_update(
                    &endpoint.provider,
                    &endpoint.signer,
                    LeafNodeParameters::default(),
                )
                .unwrap()
                .into_contents();
            group.merge_pending_commit(&endpoint.provider).unwrap();
            let commit = commit.tls_serialize_detached().unwrap();
            for (endpoint, group) in &mut attackers[1..] {
                apply_commit(endpoint, group, &commit);
            }
        }
    }
    let (endpoint, group) = &attackers[0];
    public.epoch = group.epoch().as_u64();
    public.group_info = group
        .export_group_info(endpoint.provider.crypto(), &endpoint.signer, false)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    public.ratchet_tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();
    let old_account_secret = Zeroizing::new(endpoint.provider.rand().random_array::<32>().unwrap());
    let mut archives = Vec::new();
    let mut old_keys = Vec::new();
    let mut start = 0;
    for end in chunks {
        let key = Zeroizing::new(endpoint.provider.rand().random_array::<32>().unwrap());
        let header = Header {
            binding: binding.clone(),
            sequence: archives.len(),
            previous: archives.last().map(archive_digest),
            recovery_base_digest: digest(&public.group_info),
            recovery_public_key,
            origins: Vec::new(),
            archive_signer: Vec::new(),
        };
        archives.push(seal_archive(header, &plaintext[start..end], endpoint, &key));
        old_keys.push(key);
        start = end;
    }
    let known_signers = public.retired_signature_keys.clone();
    Fixture {
        input: RecoveryInput {
            public,
            archives,
            source_ciphertexts,
            known_signers,
        },
        attackers,
        plaintext,
        old_keys,
        old_account_secret,
    }
}

fn run_worker(
    input: &RecoveryInput,
    kind: &str,
    mnemonic: &str,
    directory: &Path,
    read_only: bool,
) -> Vec<u8> {
    let stem = if read_only { "reopen" } else { "recover" };
    let input_path = directory.join(format!("{stem}-encrypted-input.json"));
    let output_path = directory.join(format!("{stem}-public-output.json"));
    std::fs::write(&input_path, serde_json::to_vec_pretty(input).unwrap()).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", WORKER, "--ignored", "--nocapture"])
        .env("ARKRET_PCR_ARCHIVE_INPUT", input_path)
        .env("ARKRET_PCR_ARCHIVE_OUTPUT", &output_path)
        .env("ARKRET_PCR_ARCHIVE_KIND", kind)
        .env("ARKRET_PCR_ARCHIVE_READ_ONLY", read_only.to_string())
        .env(
            "ARKRET_PCR_ARCHIVE_HEAD",
            hex::encode(archive_digest(input.archives.last().unwrap())),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(mnemonic.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    std::fs::write(directory.join(format!("{stem}-worker.log")), &output.stdout).unwrap();
    std::fs::write(
        directory.join(format!("{stem}-worker.stderr.log")),
        &output.stderr,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "archive subprocess failed; no private input is logged"
    );
    std::fs::read(output_path).unwrap()
}

#[test]
#[ignore = "stdin-only mnemonic worker; explicitly executed by archive scenario tests"]
fn archive_recovery_subprocess() {
    use std::io::Read as _;
    let mut mnemonic = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut mnemonic).unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    let material = derive_identity_recovery_key_material_from_bip39(&mnemonic, "", 0).unwrap();
    let kind = std::env::var("ARKRET_PCR_ARCHIVE_KIND").unwrap();
    let input: RecoveryInput = serde_json::from_slice(
        &std::fs::read(std::env::var_os("ARKRET_PCR_ARCHIVE_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    let head: [u8; 32] = hex::decode(std::env::var("ARKRET_PCR_ARCHIVE_HEAD").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let expected = Binding::fixture(&kind);
    let (records, old_keys) = restore(
        &input,
        &expected,
        head,
        &material.backup_hpke_serialized_private_key,
    )
    .unwrap();
    let output = std::env::var_os("ARKRET_PCR_ARCHIVE_OUTPUT").unwrap();
    if std::env::var("ARKRET_PCR_ARCHIVE_READ_ONLY").unwrap() == "true" {
        assert_eq!(records.last().unwrap().plaintext, AFTER);
        std::fs::write(output, bytes(&(records.len(), digest(&bytes(&records))))).unwrap();
        return;
    }
    let recovered_record_count = records.len();
    let recovered_content_digest = digest(&bytes(&records));
    let mut next_archive = None;
    let mut fresh_archive_key_rejects_all_old_data_keys = false;
    let mut original_mls_history_still_unreadable = false;
    let mls = recover_with_observer(
        input.public.clone(),
        expected.clone(),
        input.public.epoch,
        |endpoint, group, message| {
            original_mls_history_still_unreadable =
                input.source_ciphertexts.iter().all(|ciphertext| {
                    group
                        .process_message(&endpoint.provider, protocol(ciphertext))
                        .is_err()
                });
            assert!(original_mls_history_still_unreadable);
            let key = Zeroizing::new(endpoint.provider.rand().random_array::<32>().unwrap());
            let record = signed_record(
                &expected,
                endpoint,
                group.epoch().as_u64(),
                0,
                message,
                AFTER,
            );
            let header = Header {
                binding: expected.clone(),
                sequence: input.archives.len(),
                previous: Some(head),
                recovery_base_digest: digest(&input.public.group_info),
                recovery_public_key: material.backup_hpke_public_key,
                origins: Vec::new(),
                archive_signer: Vec::new(),
            };
            let archive = seal_archive(header, &[record], endpoint, &key);
            fresh_archive_key_rejects_all_old_data_keys = old_keys
                .iter()
                .all(|old_key| decrypt_data(&archive, old_key).is_err());
            assert!(fresh_archive_key_rejects_all_old_data_keys);
            next_archive = Some(archive);
        },
    );
    let result = RecoveryOutput {
        original_mls_history_still_unreadable: original_mls_history_still_unreadable
            && mls.old_history_not_recovered,
        mls,
        next_archive: next_archive.unwrap(),
        recovered_record_count,
        recovered_content_digest,
        fresh_archive_key_rejects_all_old_data_keys,
    };
    std::fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
}

fn combined_recovery(kind: &str) {
    let mnemonic = Zeroizing::new(generate_bip39_identity_recovery_mnemonic().unwrap());
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    let recovery_public = {
        let material = derive_identity_recovery_key_material_from_bip39(&mnemonic, "", 0).unwrap();
        material.backup_hpke_public_key
    };
    // Old daily endpoints only receive the public recipient; private recovery
    // material above is dropped and zeroized before those endpoints are made.
    let mut fixture = setup(kind, recovery_public);
    let old_readable: Vec<_> = fixture
        .input
        .archives
        .iter()
        .zip(&fixture.old_keys)
        .flat_map(|(archive, key)| decrypt_data(archive, key.as_slice()).unwrap())
        .collect();
    assert_eq!(old_readable, fixture.plaintext);
    let directory = evidence_directory(&format!("archive-{kind}"), fixture.attackers.len());
    let result: RecoveryOutput = serde_json::from_slice(&run_worker(
        &fixture.input,
        kind,
        &mnemonic,
        &directory,
        false,
    ))
    .unwrap();
    assert_eq!(result.recovered_record_count, fixture.plaintext.len());
    assert_eq!(
        result.recovered_content_digest,
        digest(&bytes(&fixture.plaintext))
    );
    assert!(result.original_mls_history_still_unreadable);
    assert!(result.fresh_archive_key_rejects_all_old_data_keys);
    assert_old_endpoints_excluded(
        &fixture.input.public.binding,
        &fixture.input.public,
        &result.mls,
        &mut fixture.attackers,
    );
    for (endpoint, _) in &fixture.attackers {
        #[derive(Deserialize)]
        struct RetainedSigner {
            private: Vec<u8>,
        }
        // Read the actual retained old signer through its persistence codec,
        // without enabling upstream test-utils or writing secret bytes to disk.
        let encoded = Zeroizing::new(serde_json::to_vec(&endpoint.signer).unwrap());
        let signer: RetainedSigner = serde_json::from_slice(&encoded).unwrap();
        let signature_seed = Zeroizing::new(signer.private);
        for key in fixture.old_keys.iter().map(|key| key.as_slice()).chain([
            fixture.old_account_secret.as_slice(),
            signature_seed.as_slice(),
            &recovery_public,
        ]) {
            assert!(decrypt_data(&result.next_archive, key).is_err());
            assert!(
                open_x25519_chacha20poly1305(
                    key,
                    &result.next_archive.wrapped_key,
                    WRAP_INFO,
                    &bytes(&result.next_archive.header),
                )
                .is_err()
            );
        }
    }
    let mut complete = fixture.input.clone();
    complete
        .known_signers
        .push(result.mls.new_signature_key.clone());
    complete
        .source_ciphertexts
        .push(result.mls.after_removal_message.clone());
    complete.archives.push(result.next_archive);
    let reopened: (usize, [u8; 32]) =
        serde_json::from_slice(&run_worker(&complete, kind, &mnemonic, &directory, true)).unwrap();
    assert_eq!(reopened.0, fixture.plaintext.len() + 1);
    assert_ne!(reopened.1, result.recovered_content_digest);
    println!(
        "archive {kind}: {} old records, 2 epochs, 3 senders, stdin-only 24 words; old endpoints denied new MLS and backup; fresh subprocess reopened {} records; {}",
        fixture.plaintext.len(),
        reopened.0,
        directory.display()
    );
}

#[test]
fn all_human_devices_lost_restore_archives_then_same_pcr_and_exclude_new_backups() {
    combined_recovery("human");
}

#[test]
fn all_agent_runtimes_lost_restore_same_agent_archive_and_exclude_new_backups() {
    combined_recovery("agent");
}

#[test]
fn wrong_mnemonic_tampering_missing_sources_and_rollback_are_rejected() {
    let mnemonic = Zeroizing::new(generate_bip39_identity_recovery_mnemonic().unwrap());
    let material = derive_identity_recovery_key_material_from_bip39(&mnemonic, "", 0).unwrap();
    let fixture = setup("human", material.backup_hpke_public_key);
    let input = &fixture.input;
    let head = archive_digest(input.archives.last().unwrap());
    let check = |input: &RecoveryInput, head| {
        restore(
            input,
            &Binding::fixture("human"),
            head,
            &material.backup_hpke_serialized_private_key,
        )
    };
    let wrong = Zeroizing::new(generate_bip39_identity_recovery_mnemonic().unwrap());
    let wrong = derive_identity_recovery_key_material_from_bip39(&wrong, "", 0).unwrap();
    assert!(
        restore(
            input,
            &Binding::fixture("human"),
            head,
            &wrong.backup_hpke_serialized_private_key
        )
        .is_err()
    );
    assert!(derive_identity_recovery_key_material_from_bip39("invalid mnemonic", "", 0).is_err());
    let mut changed = input.clone();
    changed.archives[1].ciphertext[0] ^= 1;
    assert!(decrypt_data(&changed.archives[1], fixture.old_keys[1].as_slice()).is_err());
    let altered_head = archive_digest(&changed.archives[1]);
    assert!(check(&changed, altered_head).is_err());
    let mut changed = input.clone();
    changed.archives[1].wrapped_key.push('A');
    assert!(
        open_x25519_chacha20poly1305(
            &material.backup_hpke_serialized_private_key,
            &changed.archives[1].wrapped_key,
            WRAP_INFO,
            &bytes(&changed.archives[1].header),
        )
        .is_err()
    );
    let altered_head = archive_digest(&changed.archives[1]);
    assert!(check(&changed, altered_head).is_err());
    let mut changed = input.clone();
    changed.archives[1].header.origins[0].ciphertext_digest[0] ^= 1;
    assert!(decrypt_data(&changed.archives[1], fixture.old_keys[1].as_slice()).is_err());
    let altered_head = archive_digest(&changed.archives[1]);
    assert!(check(&changed, altered_head).is_err());
    let mut forged_records = fixture.plaintext[..7].to_vec();
    forged_records[0].plaintext[0] ^= 1;
    let forged = seal_archive(
        input.archives[0].header.clone(),
        &forged_records,
        &fixture.attackers[0].0,
        &fixture.old_keys[0],
    );
    let mut changed = input.clone();
    changed.archives = vec![forged];
    let altered_head = archive_digest(&changed.archives[0]);
    assert_eq!(
        check(&changed, altered_head).err().as_deref(),
        Some("signature verification")
    );
    let mut changed = input.clone();
    changed.archives[1].header.binding = Binding::fixture("agent");
    let altered_head = archive_digest(&changed.archives[1]);
    assert!(check(&changed, altered_head).is_err());
    let mut changed = input.clone();
    changed.source_ciphertexts.pop();
    assert!(check(&changed, head).is_err());
    let mut missing = input.clone();
    missing.archives.remove(0);
    assert!(check(&missing, head).is_err());
    let mut reordered = input.clone();
    reordered.archives.swap(0, 1);
    let reordered_head = archive_digest(reordered.archives.last().unwrap());
    assert!(check(&reordered, reordered_head).is_err());
    let mut old_prefix = input.clone();
    old_prefix.archives.pop();
    assert!(check(&old_prefix, head).is_err());
    // A valid old prefix is still decryptable without an independent latest head.
    assert!(check(&old_prefix, archive_digest(&old_prefix.archives[0])).is_ok());
}

#[test]
fn reusing_old_archive_key_or_leaking_recovery_secret_defeats_backup_isolation() {
    let mnemonic = Zeroizing::new(generate_bip39_identity_recovery_mnemonic().unwrap());
    let material = derive_identity_recovery_key_material_from_bip39(&mnemonic, "", 0).unwrap();
    let fixture = setup("human", material.backup_hpke_public_key);
    let endpoint = &fixture.attackers[0].0;
    let header = fixture.input.archives[0].header.clone();
    let record = fixture.plaintext[0].clone();
    let unsafe_archive = seal_archive(
        header.clone(),
        std::slice::from_ref(&record),
        endpoint,
        &fixture.old_account_secret,
    );
    assert!(decrypt_data(&unsafe_archive, fixture.old_account_secret.as_slice()).is_ok());
    let fresh_key = Zeroizing::new(endpoint.provider.rand().random_array::<32>().unwrap());
    let fresh_archive = seal_archive(header, &[record], endpoint, &fresh_key);
    assert!(decrypt_data(&fresh_archive, fixture.old_account_secret.as_slice()).is_err());
    let leaked = derive_identity_recovery_key_material_from_bip39(&mnemonic, "", 0).unwrap();
    let exposed_key = Zeroizing::new(
        open_x25519_chacha20poly1305(
            &leaked.backup_hpke_serialized_private_key,
            &fresh_archive.wrapped_key,
            WRAP_INFO,
            &bytes(&fresh_archive.header),
        )
        .unwrap(),
    );
    assert!(decrypt_data(&fresh_archive, &exposed_key).is_ok());
}
