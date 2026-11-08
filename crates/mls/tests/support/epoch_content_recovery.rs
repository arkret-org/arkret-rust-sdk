//! Candidate application ciphertext experiment, not a registered Arkret wire format.
//! The trusted fixture manifest substitutes for native accepted authority proofs.

use std::io::{Read as _, Write as _};
use std::process::{Child, Stdio};

use aes_gcm::aead::Payload;
use arkret_canonical::canonical::canonical_json_bytes;
use arkret_crypto::hpke::{
    generate_x25519_keypair, open_x25519_chacha20poly1305, seal_x25519_chacha20poly1305,
};
use arkret_crypto::identity_root::{
    derive_identity_recovery_key_material_from_bip39, generate_bip39_identity_recovery_mnemonic,
};
use arkret_crypto::mls_exporter::mls_expand_with_label;
use ed25519_dalek::{Signer as _, SigningKey};
use openmls_traits::signatures::Signer as _;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::*;

const WORKER: &str = "epoch_content_recovery::recovery_worker";
const ROOT_LABEL: &str = "ak.epoch-content-root-v1";
const KEY_LABEL: &str = "ak.content-v1";
const ZERO_NONCE: [u8; 12] = [0; 12];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coordinate {
    scope: ScopeRef,
    genesis: RealmId,
    epoch: String,
    public_state_digest: [u8; 32],
    suite: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochFact {
    coordinate: Coordinate,
    historical_members: Vec<(Vec<u8>, ActorId)>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentContext {
    coordinate: Coordinate,
    root_ref: [u8; 32],
    purpose: String,
    encryption_algorithm: String,
    actor: ActorId,
    endpoint: Vec<u8>,
    salt: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentHeader {
    context: ContentContext,
    key_commitment: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalContent {
    header: ContentHeader,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootHeader {
    coordinate: Coordinate,
    root_ref: [u8; 32],
    owner: ActorId,
    signer: Vec<u8>,
    recipient: [u8; 32],
    policy: [u8; 32],
    sequence: usize,
    previous: Option<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootPacket {
    header: RootHeader,
    sealed: String,
    signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    public: PublicCapsule,
    facts: Vec<EpochFact>,
    sources: Vec<OriginalContent>,
    backups: Vec<RootPacket>,
    recipient: [u8; 32],
    controller_recovery_public: [u8; 32],
    policy: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    mls: PublicResult,
    fact: EpochFact,
    next_source: OriginalContent,
    next_backup: RootPacket,
    restored_count: usize,
    plaintext_digest: [u8; 32],
    endpoint: Vec<u8>,
}

struct Root {
    coordinate: Coordinate,
    secret: Zeroizing<Vec<u8>>,
}

fn bytes(value: &impl Serialize) -> Vec<u8> {
    canonical_json_bytes(value).unwrap()
}

fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn verify(key: &[u8], transcript: &[u8], signature: &[u8]) -> Result<(), String> {
    let raw: [u8; 32] = key.try_into().map_err(|_| "signature key length")?;
    ed25519_dalek::VerifyingKey::from_bytes(&raw)
        .map_err(|_| "signature key")?
        .verify_strict(
            transcript,
            &ed25519_dalek::Signature::from_slice(signature).map_err(|_| "signature length")?,
        )
        .map_err(|_| "signature mismatch".into())
}

fn root_ref(root: &Root) -> [u8; 32] {
    hash(&bytes(&(
        "candidate epoch root commitment",
        &root.coordinate,
        root.secret.as_slice(),
    )))
}

fn key(root: &Root, context: &ContentContext) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(mls_expand_with_label(&root.secret, KEY_LABEL, &bytes(context), 16).unwrap())
}

fn key_commitment(key: &[u8], context: &ContentContext) -> [u8; 32] {
    hash(&bytes(&("candidate content key commitment", context, key)))
}

fn fact_and_root(endpoint: &Endpoint, group: &MlsGroup, binding: &Binding) -> (EpochFact, Root) {
    let public = group
        .export_group_info(endpoint.provider.crypto(), &endpoint.signer, false)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let coordinate = Coordinate {
        scope: binding.scope.clone(),
        genesis: match &binding.scope {
            ScopeRef::Realm { realm_id } => realm_id.clone(),
            _ => unreachable!("this fixture only constructs Realm scopes"),
        },
        epoch: group.epoch().as_u64().to_string(),
        public_state_digest: hash(&public),
        suite: u16::from(ARKRET_MLS_CIPHERSUITE),
    };
    let secret = Zeroizing::new(
        group
            .export_secret(
                endpoint.provider.crypto(),
                ROOT_LABEL,
                &bytes(&coordinate),
                32,
            )
            .unwrap(),
    );
    (
        EpochFact {
            coordinate: coordinate.clone(),
            historical_members: group
                .members()
                .map(|member| {
                    (
                        member.signature_key,
                        decode_leaf_credential(member.credential.serialized_content()).unwrap(),
                    )
                })
                .collect(),
        },
        Root { coordinate, secret },
    )
}

fn publish(
    endpoint: &Endpoint,
    root: &Root,
    binding: &Binding,
    plaintext: &[u8],
    salt: [u8; 32],
) -> OriginalContent {
    let context = ContentContext {
        coordinate: root.coordinate.clone(),
        root_ref: root_ref(root),
        purpose: "event_body".into(),
        encryption_algorithm: "aes128_gcm".into(),
        actor: binding.actor(),
        endpoint: endpoint.signer.to_public_vec(),
        salt,
    };
    let key = key(root, &context);
    let header = ContentHeader {
        key_commitment: key_commitment(&key, &context),
        context,
    };
    let ciphertext = Aes128Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            &Nonce::from(ZERO_NONCE),
            Payload {
                msg: plaintext,
                aad: &bytes(&header),
            },
        )
        .unwrap();
    let signature = endpoint
        .signer
        .sign(&bytes(&(&header, &ciphertext)))
        .unwrap();
    OriginalContent {
        header,
        ciphertext,
        signature,
    }
}

fn verify_source(source: &OriginalContent, facts: &[EpochFact]) -> Result<(), String> {
    let context = &source.header.context;
    if !facts.iter().any(|fact| {
        fact.coordinate == context.coordinate
            && fact
                .historical_members
                .contains(&(context.endpoint.clone(), context.actor.clone()))
    }) {
        return Err("source absent from independently authenticated historical facts".into());
    }
    verify(
        &context.endpoint,
        &bytes(&(&source.header, &source.ciphertext)),
        &source.signature,
    )
}

fn open_content(
    source: &OriginalContent,
    facts: &[EpochFact],
    key: &[u8],
) -> Result<Vec<u8>, String> {
    verify_source(source, facts)?;
    if key_commitment(key, &source.header.context) != source.header.key_commitment {
        return Err("originally signed content key commitment mismatch".into());
    }
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| "content key length")?
        .decrypt(
            &Nonce::from(ZERO_NONCE),
            Payload {
                msg: &source.ciphertext,
                aad: &bytes(&source.header),
            },
        )
        .map_err(|_| "original ciphertext authentication failed".into())
}

fn open_history(input: &Input, roots: &[Root]) -> Result<Vec<Vec<u8>>, String> {
    input
        .sources
        .iter()
        .map(|source| {
            let context = &source.header.context;
            let root = roots
                .iter()
                .find(|root| {
                    root.coordinate == context.coordinate && root_ref(root) == context.root_ref
                })
                .ok_or("missing exact original root")?;
            open_content(source, &input.facts, &key(root, context))
        })
        .collect()
}

fn backup(endpoint: &Endpoint, root: &Root, input: &Input) -> RootPacket {
    let header = RootHeader {
        coordinate: root.coordinate.clone(),
        root_ref: root_ref(root),
        owner: input.public.binding.actor(),
        signer: endpoint.signer.to_public_vec(),
        recipient: input.recipient,
        policy: input.policy,
        sequence: input.backups.len(),
        previous: input.backups.last().map(|packet| hash(&bytes(packet))),
    };
    let context = bytes(&header);
    let sealed =
        seal_x25519_chacha20poly1305(&input.recipient, &root.secret, &context, &context).unwrap();
    let signature = endpoint.signer.sign(&bytes(&(&header, &sealed))).unwrap();
    RootPacket {
        header,
        sealed,
        signature,
    }
}

fn restore(input: &Input, private: &[u8]) -> Result<Vec<Root>, String> {
    let mut previous = None;
    let mut roots = Vec::new();
    for (sequence, packet) in input.backups.iter().enumerate() {
        let h = &packet.header;
        if h.sequence != sequence
            || h.previous != previous
            || h.recipient != input.recipient
            || h.policy != input.policy
            || h.owner != input.public.binding.actor()
            || h.coordinate.scope != input.public.binding.scope
            || !input.facts.iter().any(|fact| {
                fact.coordinate == h.coordinate
                    && fact
                        .historical_members
                        .contains(&(h.signer.clone(), h.owner.clone()))
            })
        {
            return Err("backup authority/chain/recipient/policy mismatch".into());
        }
        verify(
            &h.signer,
            &bytes(&(&packet.header, &packet.sealed)),
            &packet.signature,
        )?;
        let context = bytes(h);
        let secret = Zeroizing::new(
            open_x25519_chacha20poly1305(private, &packet.sealed, &context, &context)
                .map_err(|_| "backup HPKE failure")?,
        );
        let root = Root {
            coordinate: h.coordinate.clone(),
            secret,
        };
        if root.secret.len() != 32 || root_ref(&root) != h.root_ref {
            return Err("backup root commitment mismatch".into());
        }
        roots.push(root);
        previous = Some(hash(&bytes(packet)));
    }
    Ok(roots)
}

struct Fixture {
    input: Input,
    attackers: Vec<(Endpoint, MlsGroup)>,
    roots: Vec<Root>,
    plaintext: Vec<Vec<u8>>,
    old_device_secrets: Vec<Zeroizing<Vec<u8>>>,
}

fn setup(kind: &str, recipient: [u8; 32], recovery_public: [u8; 32]) -> Fixture {
    let mut binding = Binding::fixture(if kind == "collaboration" {
        "human"
    } else {
        kind
    });
    if kind == "collaboration" {
        // Ordinary collaboration group, distinct from the fixture user's PCR.
        binding.scope = ScopeRef::Realm {
            realm_id: RealmId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x61; 32],
            )),
        };
        binding.group_id = binding
            .scope
            .canonical_mls_group_id_bytes()
            .unwrap()
            .to_vec();
    }
    let (public, mut attackers) = original_devices(&binding, 3);
    let mut input = Input {
        public,
        facts: vec![],
        sources: vec![],
        backups: vec![],
        recipient,
        controller_recovery_public: recovery_public,
        policy: hash(b"accepted fixture backup policy"),
    };
    let mut roots = Vec::new();
    let mut plaintext = Vec::new();
    for epoch_round in 0..2 {
        let (fact, root) = fact_and_root(&attackers[0].0, &attackers[0].1, &binding);
        for (endpoint, group) in &attackers {
            assert_eq!(
                group
                    .export_secret(
                        endpoint.provider.crypto(),
                        ROOT_LABEL,
                        &bytes(&root.coordinate),
                        32
                    )
                    .unwrap(),
                *root.secret
            );
        }
        input.facts.push(fact);
        input.backups.push(backup(&attackers[0].0, &root, &input));
        for round in 0..2 {
            for (sender, (endpoint, _)) in attackers.iter().enumerate() {
                let plain = bytes(&(
                    kind,
                    epoch_round,
                    sender,
                    round,
                    "original private PCR field",
                ));
                let source = publish(
                    endpoint,
                    &root,
                    &binding,
                    &plain,
                    endpoint.provider.rand().random_array::<32>().unwrap(),
                );
                input.sources.push(source);
                plaintext.push(plain);
            }
        }
        roots.push(root);
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
    input.public.epoch = group.epoch().as_u64();
    input.public.group_info = group
        .export_group_info(endpoint.provider.crypto(), &endpoint.signer, false)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    input.public.ratchet_tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();
    assert_eq!(open_history(&input, &roots).unwrap(), plaintext);
    let mut old_device_secrets = Vec::new();
    for (endpoint, _) in &attackers {
        let daily_hpke = generate_x25519_keypair().unwrap();
        old_device_secrets.push(Zeroizing::new(daily_hpke.private_key().to_vec()));
        old_device_secrets.push(Zeroizing::new(
            endpoint
                .provider
                .rand()
                .random_array::<32>()
                .unwrap()
                .to_vec(),
        ));
    }
    Fixture {
        input,
        attackers,
        roots,
        plaintext,
        old_device_secrets,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    binding: Binding,
    endpoint: Vec<u8>,
    hpke: [u8; 32],
    input_digest: [u8; 32],
    challenge: [u8; 32],
    signature: Vec<u8>,
}

fn hello_transcript(hello: &Hello) -> Vec<u8> {
    bytes(&(
        &hello.binding,
        &hello.endpoint,
        hello.hpke,
        hello.input_digest,
        hello.challenge,
    ))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantEntry {
    coordinate: Coordinate,
    root_ref: [u8; 32],
    sealed: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeGrant {
    hello_digest: [u8; 32],
    controller_device: Vec<u8>,
    recovery_session_proof: Vec<u8>,
    entries: Vec<GrantEntry>,
    device_signature: Vec<u8>,
}

fn session_transcript(hello: &Hello, device: &[u8]) -> Vec<u8> {
    bytes(&(
        "candidate controller recovery session",
        hash(&bytes(hello)),
        device,
    ))
}

fn grant_context(hello: &Hello, coordinate: &Coordinate, reference: [u8; 32]) -> Vec<u8> {
    bytes(&(
        "candidate authorized runtime root grant",
        hash(&bytes(hello)),
        coordinate,
        reference,
    ))
}

fn finish(input: &Input, roots: &[Root], endpoint: Endpoint) -> Output {
    let plaintext = open_history(input, roots).unwrap();
    let mut next = None;
    let mls = recover_with_endpoint(
        input.public.clone(),
        input.public.binding.clone(),
        input.public.epoch,
        endpoint,
        |endpoint, group, _| {
            let (fact, root) = fact_and_root(endpoint, group, &input.public.binding);
            for old in roots {
                assert_ne!(*old.secret, *root.secret);
            }
            let source = publish(
                endpoint,
                &root,
                &input.public.binding,
                b"new original PCR content after recovery fence",
                endpoint.provider.rand().random_array::<32>().unwrap(),
            );
            let packet = backup(endpoint, &root, input);
            next = Some((fact, source, packet));
        },
    );
    let (fact, next_source, next_backup) = next.unwrap();
    Output {
        endpoint: mls.new_signature_key.clone(),
        mls,
        fact,
        next_source,
        next_backup,
        restored_count: plaintext.len(),
        plaintext_digest: hash(&bytes(&plaintext)),
    }
}

fn load_pinned_input() -> Input {
    let encoded = std::fs::read(std::env::var_os("ARKRET_EPOCH_INPUT").unwrap()).unwrap();
    let expected: [u8; 32] = hex::decode(std::env::var("ARKRET_EPOCH_INPUT_DIGEST").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(hash(&encoded), expected);
    serde_json::from_slice(&encoded).unwrap()
}

#[test]
#[ignore = "isolated recovery worker, invoked with explicit pinned fixture input"]
fn recovery_worker() {
    let input = load_pinned_input();
    let role = std::env::var("ARKRET_EPOCH_ROLE").unwrap();
    let mut stdin = Zeroizing::new(String::new());
    if role == "runtime" {
        let endpoint = Endpoint::fresh(&input.public.binding);
        let hpke = generate_x25519_keypair().unwrap();
        let mut hello = Hello {
            binding: input.public.binding.clone(),
            endpoint: endpoint.signer.to_public_vec(),
            hpke: *hpke.public_key(),
            input_digest: hash(&bytes(&input)),
            challenge: endpoint.provider.rand().random_array::<32>().unwrap(),
            signature: vec![],
        };
        hello.signature = endpoint.signer.sign(&hello_transcript(&hello)).unwrap();
        let hello_file = std::env::var_os("ARKRET_EPOCH_HELLO").unwrap();
        std::fs::write(hello_file, bytes(&hello)).unwrap();
        std::io::stdin().read_to_string(&mut stdin).unwrap();
        let grant: RuntimeGrant = serde_json::from_str(&stdin).unwrap();
        assert_eq!(grant.hello_digest, hash(&bytes(&hello)));
        verify(
            &input.controller_recovery_public,
            &session_transcript(&hello, &grant.controller_device),
            &grant.recovery_session_proof,
        )
        .unwrap();
        verify(
            &grant.controller_device,
            &bytes(&(grant.hello_digest, &grant.entries)),
            &grant.device_signature,
        )
        .unwrap();
        let roots: Vec<_> = grant
            .entries
            .iter()
            .map(|entry| {
                let context = grant_context(&hello, &entry.coordinate, entry.root_ref);
                let root = Root {
                    coordinate: entry.coordinate.clone(),
                    secret: Zeroizing::new(
                        open_x25519_chacha20poly1305(
                            hpke.private_key(),
                            &entry.sealed,
                            &context,
                            &context,
                        )
                        .unwrap(),
                    ),
                };
                assert_eq!(root_ref(&root), entry.root_ref);
                root
            })
            .collect();
        // This role accepts a typed grant only: no mnemonic or controller backup private key.
        let output = finish(&input, &roots, endpoint);
        std::fs::write(
            std::env::var_os("ARKRET_EPOCH_OUTPUT").unwrap(),
            bytes(&output),
        )
        .unwrap();
        return;
    }
    std::io::stdin().read_to_string(&mut stdin).unwrap();
    let material = derive_identity_recovery_key_material_from_bip39(stdin.trim(), "", 0).unwrap();
    assert_eq!(material.backup_hpke_public_key, input.recipient);
    let roots = restore(&input, &material.backup_hpke_serialized_private_key).unwrap();
    if role == "controller" {
        let hello_bytes = std::fs::read(std::env::var_os("ARKRET_EPOCH_HELLO").unwrap()).unwrap();
        assert_eq!(
            hex::encode(hash(&hello_bytes)),
            std::env::var("ARKRET_EPOCH_HELLO_DIGEST").unwrap()
        );
        let hello: Hello = serde_json::from_slice(&hello_bytes).unwrap();
        assert_eq!(hello.binding, input.public.binding);
        assert_eq!(hello.input_digest, hash(&bytes(&input)));
        verify(&hello.endpoint, &hello_transcript(&hello), &hello.signature).unwrap();
        assert_eq!(
            open_history(&input, &roots).unwrap().len(),
            input.sources.len()
        );
        let device = Endpoint::fresh(&Binding::fixture("human"));
        let entries = roots
            .iter()
            .map(|root| {
                let reference = root_ref(root);
                let context = grant_context(&hello, &root.coordinate, reference);
                GrantEntry {
                    coordinate: root.coordinate.clone(),
                    root_ref: reference,
                    sealed: seal_x25519_chacha20poly1305(
                        &hello.hpke,
                        &root.secret,
                        &context,
                        &context,
                    )
                    .unwrap(),
                }
            })
            .collect::<Vec<_>>();
        let device_key = device.signer.to_public_vec();
        let proof = SigningKey::from_bytes(&material.recovery_proof_seed)
            .sign(&session_transcript(&hello, &device_key))
            .to_bytes()
            .to_vec();
        let hello_digest = hash(&bytes(&hello));
        let signature = device
            .signer
            .sign(&bytes(&(hello_digest, &entries)))
            .unwrap();
        let grant = RuntimeGrant {
            hello_digest,
            controller_device: device_key,
            recovery_session_proof: proof,
            entries,
            device_signature: signature,
        };
        std::fs::write(
            std::env::var_os("ARKRET_EPOCH_OUTPUT").unwrap(),
            bytes(&grant),
        )
        .unwrap();
    } else if role == "read-only" {
        let plaintext = open_history(&input, &roots).unwrap();
        std::fs::write(
            std::env::var_os("ARKRET_EPOCH_OUTPUT").unwrap(),
            bytes(&(plaintext.len(), hash(&bytes(&plaintext)))),
        )
        .unwrap();
    } else {
        assert_eq!(role, "human");
        let output = finish(&input, &roots, Endpoint::fresh(&input.public.binding));
        std::fs::write(
            std::env::var_os("ARKRET_EPOCH_OUTPUT").unwrap(),
            bytes(&output),
        )
        .unwrap();
    }
}

fn spawn_worker(directory: &Path, input: &Input, role: &str, output: &str) -> Child {
    let path = directory.join(format!("{role}.input.json"));
    std::fs::write(&path, bytes(input)).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", WORKER, "--ignored", "--nocapture"])
        .env("ARKRET_EPOCH_INPUT", path)
        .env(
            "ARKRET_EPOCH_INPUT_DIGEST",
            hex::encode(hash(&bytes(input))),
        )
        .env("ARKRET_EPOCH_ROLE", role)
        .env("ARKRET_EPOCH_OUTPUT", directory.join(output))
        .env("ARKRET_EPOCH_HELLO", directory.join("hello.json"))
        .stdin(Stdio::piped())
        .stdout(std::fs::File::create(directory.join(format!("{role}.stdout.log"))).unwrap())
        .stderr(std::fs::File::create(directory.join(format!("{role}.stderr.log"))).unwrap());
    if role == "controller" {
        command.env(
            "ARKRET_EPOCH_HELLO_DIGEST",
            hex::encode(hash(&std::fs::read(directory.join("hello.json")).unwrap())),
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000);
    }
    command.spawn().unwrap()
}

fn submit_and_wait(mut child: Child, secret: &[u8]) {
    child.stdin.take().unwrap().write_all(secret).unwrap();
    assert!(
        child.wait().unwrap().success(),
        "recovery subprocess failed; inspect role logs"
    );
}

fn exercise(kind: &str) {
    let mnemonic = Zeroizing::new(generate_bip39_identity_recovery_mnemonic().unwrap());
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    let material = derive_identity_recovery_key_material_from_bip39(&mnemonic, "", 0).unwrap();
    let mut fixture = setup(
        kind,
        material.backup_hpke_public_key,
        material.recovery_proof_public_key,
    );
    let directory = evidence_directory(&format!("epoch-content-{kind}"), 3);
    let output_name = "recovered.json";
    if kind == "agent" {
        let mut runtime = spawn_worker(&directory, &fixture.input, "runtime", output_name);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !directory.join("hello.json").exists() {
            assert!(
                runtime.try_wait().unwrap().is_none(),
                "runtime failed before hello"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "runtime hello timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Complete JSON is polled: the create and the write are separate OS operations.
        loop {
            if serde_json::from_slice::<Hello>(
                &std::fs::read(directory.join("hello.json")).unwrap(),
            )
            .is_ok()
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let controller = spawn_worker(&directory, &fixture.input, "controller", "grant.json");
        submit_and_wait(controller, mnemonic.as_bytes());
        let grant = std::fs::read(directory.join("grant.json")).unwrap();
        submit_and_wait(runtime, &grant);
    } else {
        submit_and_wait(
            spawn_worker(&directory, &fixture.input, "human", output_name),
            mnemonic.as_bytes(),
        );
    }
    let result: Output =
        serde_json::from_slice(&std::fs::read(directory.join(output_name)).unwrap()).unwrap();
    assert_eq!(result.restored_count, 12);
    assert_eq!(result.plaintext_digest, hash(&bytes(&fixture.plaintext)));
    assert_old_endpoints_excluded(
        &fixture.input.public.binding,
        &fixture.input.public,
        &result.mls,
        &mut fixture.attackers,
    );
    if kind == "agent" {
        let hello: Hello =
            serde_json::from_slice(&std::fs::read(directory.join("hello.json")).unwrap()).unwrap();
        assert_eq!(result.endpoint, hello.endpoint);
    }
    for old in &fixture.roots {
        let old_derived_key = key(old, &result.next_source.header.context);
        assert!(
            open_content(
                &result.next_source,
                std::slice::from_ref(&result.fact),
                &old_derived_key
            )
            .is_err()
        );
        let aad = bytes(&result.next_source.header);
        assert!(
            Aes128Gcm::new_from_slice(&old_derived_key)
                .unwrap()
                .decrypt(
                    &Nonce::from(ZERO_NONCE),
                    Payload {
                        msg: &result.next_source.ciphertext,
                        aad: &aad
                    }
                )
                .is_err()
        );
        assert!(
            open_x25519_chacha20poly1305(
                &old.secret,
                &result.next_backup.sealed,
                &bytes(&result.next_backup.header),
                &bytes(&result.next_backup.header)
            )
            .is_err()
        );
    }
    for (endpoint, _) in &fixture.attackers {
        #[derive(Deserialize)]
        struct RetainedSigner {
            private: Vec<u8>,
        }
        let encoded = Zeroizing::new(serde_json::to_vec(&endpoint.signer).unwrap());
        let retained: RetainedSigner = serde_json::from_slice(&encoded).unwrap();
        let private = Zeroizing::new(retained.private);
        assert!(
            open_x25519_chacha20poly1305(
                &private,
                &result.next_backup.sealed,
                &bytes(&result.next_backup.header),
                &bytes(&result.next_backup.header)
            )
            .is_err()
        );
    }
    for private in &fixture.old_device_secrets {
        assert!(
            open_x25519_chacha20poly1305(
                private,
                &result.next_backup.sealed,
                &bytes(&result.next_backup.header),
                &bytes(&result.next_backup.header)
            )
            .is_err()
        );
    }
    // Deliberately leaked mnemonic is a positive control: future backups ARE readable.
    assert!(
        open_x25519_chacha20poly1305(
            &material.backup_hpke_serialized_private_key,
            &result.next_backup.sealed,
            &bytes(&result.next_backup.header),
            &bytes(&result.next_backup.header)
        )
        .is_ok()
    );
    fixture.input.facts.push(result.fact);
    fixture.input.sources.push(result.next_source);
    fixture.input.backups.push(result.next_backup);
    fixture
        .plaintext
        .push(b"new original PCR content after recovery fence".to_vec());
    submit_and_wait(
        spawn_worker(
            &directory,
            &fixture.input,
            "read-only",
            "second-restore.json",
        ),
        mnemonic.as_bytes(),
    );
    let actual: (usize, [u8; 32]) =
        serde_json::from_slice(&std::fs::read(directory.join("second-restore.json")).unwrap())
            .unwrap();
    assert_eq!(actual, (13, hash(&bytes(&fixture.plaintext))));
    println!(
        "candidate original-ciphertext recovery {kind}: 12 old + 1 new; runtime receives no mnemonic; artifacts={}",
        directory.display()
    );
}

#[test]
fn human_original_ciphertexts_survive_all_endpoint_loss() {
    exercise("human");
}

#[test]
fn controller_recovers_agent_without_exposing_mnemonic_to_runtime() {
    exercise("agent");
}

// The pinned complete fixture catalogue substitutes for an accepted sealed epoch.
// Native current authority and full catalogue coverage remain production work.
fn select_whole_epoch_root<'a>(
    input: &Input,
    roots: &'a [Root],
    requested: &Coordinate,
    permitted_sources: &[[u8; 32]],
    current_scope: Option<&ScopeRef>,
) -> Result<&'a Root, String> {
    if current_scope != Some(&requested.scope)
        || requested.scope != input.public.binding.scope
        || requested.epoch.parse::<u64>().map_err(|_| "epoch")? >= input.public.epoch
    {
        return Err("not a currently authorized closed epoch".into());
    }
    let sources: Vec<_> = input
        .sources
        .iter()
        .filter(|source| source.header.context.coordinate == *requested)
        .collect();
    if sources.is_empty()
        || !sources
            .iter()
            .all(|source| permitted_sources.contains(&hash(&bytes(source))))
    {
        return Err("partial epoch authorization requires individual content keys".into());
    }
    roots
        .iter()
        .find(|root| root.coordinate == *requested)
        .ok_or("missing root".into())
}

#[test]
fn late_reader_selective_grant_source_tampering_and_derivation_boundaries() {
    let mnemonic = Zeroizing::new(generate_bip39_identity_recovery_mnemonic().unwrap());
    let material = derive_identity_recovery_key_material_from_bip39(&mnemonic, "", 0).unwrap();
    let fixture = setup(
        "collaboration",
        material.backup_hpke_public_key,
        material.recovery_proof_public_key,
    );
    let source = &fixture.input.sources[0];
    let root = &fixture.roots[0];
    let correct_key = key(root, &source.header.context);
    assert_eq!(
        open_content(source, &fixture.input.facts, &correct_key).unwrap(),
        fixture.plaintext[0]
    );
    for bad in [
        Root {
            coordinate: root.coordinate.clone(),
            secret: Zeroizing::new(vec![0x44; 32]),
        },
        Root {
            coordinate: root.coordinate.clone(),
            secret: fixture.roots[1].secret.clone(),
        },
    ] {
        assert!(
            open_content(
                source,
                &fixture.input.facts,
                &key(&bad, &source.header.context)
            )
            .is_err()
        );
    }
    let mut context = source.header.context.clone();
    context.coordinate.scope = Binding::fixture("agent").scope;
    assert!(open_content(source, &fixture.input.facts, &key(root, &context)).is_err());
    context = source.header.context.clone();
    context.coordinate.epoch = "999".into();
    assert!(open_content(source, &fixture.input.facts, &key(root, &context)).is_err());
    context = source.header.context.clone();
    context.purpose = "blob_content".into();
    assert!(open_content(source, &fixture.input.facts, &key(root, &context)).is_err());
    context = source.header.context.clone();
    context.encryption_algorithm = "another_unregistered_algorithm".into();
    assert!(open_content(source, &fixture.input.facts, &key(root, &context)).is_err());
    // Forced same salt and counter are safe across authenticated endpoint domains.
    let other = &fixture.input.sources[1];
    let mut same_salt_other_endpoint = other.header.context.clone();
    same_salt_other_endpoint.salt = source.header.context.salt;
    assert_ne!(*correct_key, *key(root, &same_salt_other_endpoint));
    let mut tampered = source.clone();
    tampered.ciphertext[0] ^= 1;
    assert!(open_content(&tampered, &fixture.input.facts, &correct_key).is_err());
    tampered = source.clone();
    tampered.header.context.actor = Binding::fixture("agent").actor();
    // Even a valid signature from the original key cannot substitute its Actor.
    tampered.signature = fixture.attackers[0]
        .0
        .signer
        .sign(&bytes(&(&tampered.header, &tampered.ciphertext)))
        .unwrap();
    assert!(open_content(&tampered, &fixture.input.facts, &correct_key).is_err());
    let mut bad_input = fixture.input.clone();
    bad_input.backups[0].header.policy[0] ^= 1;
    assert!(restore(&bad_input, &material.backup_hpke_serialized_private_key).is_err());
    bad_input = fixture.input.clone();
    bad_input.backups.reverse();
    assert!(restore(&bad_input, &material.backup_hpke_serialized_private_key).is_err());
    bad_input = fixture.input.clone();
    bad_input.backups.pop();
    let incomplete = restore(&bad_input, &material.backup_hpke_serialized_private_key).unwrap();
    assert!(open_history(&bad_input, &incomplete).is_err());
    let all: Vec<_> = fixture
        .input
        .sources
        .iter()
        .map(|source| hash(&bytes(source)))
        .collect();
    let scope = &fixture.input.public.binding.scope;
    assert!(
        select_whole_epoch_root(
            &fixture.input,
            &fixture.roots,
            &root.coordinate,
            &all,
            Some(scope)
        )
        .is_ok()
    );
    assert!(
        select_whole_epoch_root(
            &fixture.input,
            &fixture.roots,
            &root.coordinate,
            &all[..1],
            Some(scope)
        )
        .is_err()
    );
    assert!(
        select_whole_epoch_root(
            &fixture.input,
            &fixture.roots,
            &root.coordinate,
            &[],
            Some(scope)
        )
        .is_err()
    );
    assert!(
        select_whole_epoch_root(&fixture.input, &fixture.roots, &root.coordinate, &all, None)
            .is_err()
    );
    assert!(
        select_whole_epoch_root(
            &fixture.input,
            &fixture.roots,
            &root.coordinate,
            &all,
            Some(&Binding::fixture("agent").scope)
        )
        .is_err()
    );
    assert!(
        select_whole_epoch_root(
            &fixture.input,
            &fixture.roots,
            &fixture.roots[1].coordinate,
            &all,
            Some(scope)
        )
        .is_err()
    );
    // A different Actor really joins via Add/Welcome, without possessing old roots.
    let reader_binding = Binding::fixture("agent");
    let reader = Endpoint::fresh(&reader_binding);
    let mut endpoints = fixture.attackers;
    let (writer, group) = &mut endpoints[0];
    let package = reader.key_package();
    let (_, welcome, _) = group
        .add_members(
            &writer.provider,
            &writer.signer,
            &[package.key_package().clone()],
        )
        .unwrap();
    group.merge_pending_commit(&writer.provider).unwrap();
    let reader_group = welcome_join(&reader, welcome, group.export_ratchet_tree().into());
    let unavailable_old_root = Root {
        coordinate: root.coordinate.clone(),
        secret: Zeroizing::new(
            reader_group
                .export_secret(
                    reader.provider.crypto(),
                    ROOT_LABEL,
                    &bytes(&root.coordinate),
                    32,
                )
                .unwrap(),
        ),
    };
    assert!(
        open_content(
            source,
            &fixture.input.facts,
            &key(&unavailable_old_root, &source.header.context)
        )
        .is_err()
    );
    let hpke = generate_x25519_keypair().unwrap();
    let grant_context = bytes(&(
        "candidate selective content key grant",
        hash(&bytes(source)),
        hpke.public_key(),
    ));
    let sealed = seal_x25519_chacha20poly1305(
        hpke.public_key(),
        &correct_key,
        &grant_context,
        &grant_context,
    )
    .unwrap();
    let granted = Zeroizing::new(
        open_x25519_chacha20poly1305(hpke.private_key(), &sealed, &grant_context, &grant_context)
            .unwrap(),
    );
    assert_eq!(
        open_content(source, &fixture.input.facts, &granted).unwrap(),
        fixture.plaintext[0]
    );
    assert!(open_content(other, &fixture.input.facts, &granted).is_err());
    let wrong_recipient = generate_x25519_keypair().unwrap();
    assert!(
        open_x25519_chacha20poly1305(
            wrong_recipient.private_key(),
            &sealed,
            &grant_context,
            &grant_context
        )
        .is_err()
    );
    // A complete-epoch grant opens all that epoch, never the next epoch.
    let context = bytes(&(
        "candidate complete epoch grant",
        &root.coordinate,
        hpke.public_key(),
    ));
    let sealed =
        seal_x25519_chacha20poly1305(hpke.public_key(), &root.secret, &context, &context).unwrap();
    let granted_root = Root {
        coordinate: root.coordinate.clone(),
        secret: Zeroizing::new(
            open_x25519_chacha20poly1305(hpke.private_key(), &sealed, &context, &context).unwrap(),
        ),
    };
    assert_eq!(
        open_content(
            source,
            &fixture.input.facts,
            &key(&granted_root, &source.header.context)
        )
        .unwrap(),
        fixture.plaintext[0]
    );
    let next = &fixture.input.sources[6];
    assert!(
        open_content(
            next,
            &fixture.input.facts,
            &key(&granted_root, &next.header.context)
        )
        .is_err()
    );
}
