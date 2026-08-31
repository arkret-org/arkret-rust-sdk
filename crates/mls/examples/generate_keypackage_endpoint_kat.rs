use std::path::PathBuf;

use arkret_canonical::{
    base64url_decode, base64url_encode, canonical, ed25519_pubkey_to_did_key_multibase,
};
use arkret_mls::{
    ArkretMlsIdentity, ArkretMlsSigner, AuthorLeafCredential, author_leaf_from_key_package_bytes,
};
use arkret_wire::{DeviceId, DidCoreId, DidUrl, EventId};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: generate_keypackage_endpoint_kat <output.json>")?;

    let ordinary_seed = [0x11; 32];
    let ordinary = ArkretMlsIdentity::new_human_device(
        DidCoreId::new("ak:did_core:webvh:z6mkkatordinary".to_owned())?,
        DeviceId::new("ak:device:01904100-0000-7000-8000-00000000aa11".to_owned())?,
        ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&ordinary_seed)),
    )?;

    let agent_seed = [0x22; 32];
    let agent = ArkretMlsIdentity::new_agent(
        DidCoreId::new("ak:did_core:web:kat-agent.example".to_owned())?,
        DidUrl::new("did:web:kat-agent.example#runtime-1".to_owned())?,
        EventId::new("ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g".to_owned())?,
        ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&agent_seed)),
    )?;

    let pairwise_seed = [0x33; 32];
    let pairwise_public = SigningKey::from_bytes(&pairwise_seed)
        .verifying_key()
        .to_bytes();
    let pairwise_multibase = ed25519_pubkey_to_did_key_multibase(&pairwise_public);
    let pairwise_actor = DidCoreId::new(format!("ak:did_core:key:{pairwise_multibase}"))?;
    let pairwise_method =
        DidUrl::new(format!("did:key:{pairwise_multibase}#{pairwise_multibase}"))?;
    let pairwise = ArkretMlsIdentity::new_minimal_metadata_pairwise(
        pairwise_actor,
        pairwise_method,
        ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&pairwise_seed)),
    )?;

    let cases = [
        kat_case("ordinary_human_device", &ordinary)?,
        kat_case("agent_runtime", &agent)?,
        kat_case("minimal_metadata_pairwise", &pairwise)?,
    ];
    let fixture = json!({
        "profile": "ak.profile.e2ee_client.v1",
        "version": "2026-08-26",
        "suite": "mls_keypackage_endpoint_known_answers",
        "runner": {
            "kind": "known_answer_tests"
        },
        "description": "Frozen real RFC 9420 KeyPackages for every Arkret endpoint branch. Each vector pins the BasicCredential, LeafNode signature key, complete KeyPackage bytes, and their SHA-256 digests.",
        "cases": cases,
        "negative_contract": {
            "ordinary_credential": "must equal the selected canonical DeviceId",
            "ordinary_leaf_and_batch_key": "must both equal the current accepted device identity key",
            "actor_credential": "must equal the selected Agent or pairwise ActorId",
            "actor_leaf_and_batch_key": "must both equal the selected accepted endpoint key",
            "deprecated_fields": [
                "keypackages[].endpoint_signature",
                "mls_keypackage_payload.endpoint_signature",
                "available_count"
            ]
        }
    });
    std::fs::write(output, serde_json::to_vec_pretty(&fixture)?)?;
    Ok(())
}

fn kat_case(name: &str, identity: &ArkretMlsIdentity) -> Result<Value, Box<dyn std::error::Error>> {
    let record = identity.key_package_record()?;
    let bytes = base64url_decode(record.keypackage.as_bytes())?;
    let leaf = author_leaf_from_key_package_bytes(&bytes, 0)?;
    let AuthorLeafCredential::Basic {
        identity: credential,
    } = leaf.credential
    else {
        return Err("generated KeyPackage did not contain a BasicCredential".into());
    };
    let entry = identity.key_package_upload_entry(&record)?;
    let entry_bytes = canonical::canonical_json_bytes(&entry)?;
    Ok(json!({
        "name": name,
        "endpoint": record.endpoint,
        "keypackage": record.keypackage,
        "keypackage_ref": record.keypackage_ref,
        "keypackage_sha256": canonical::sha256_digest(&bytes),
        "leaf_credential": base64url_encode(&credential),
        "leaf_signature_key": base64url_encode(&leaf.signature_key),
        "batch_signature_public_key": base64url_encode(&leaf.signature_key),
        "leaf_node_sha256": canonical::sha256_digest(&leaf.leaf_node_canonical_bytes),
        "upload_entry_jcs": String::from_utf8(entry_bytes.clone())?,
        "upload_entry_sha256": canonical::sha256_digest(&entry_bytes)
    }))
}
