//! Criterion microbenchmark for detached-JWS proof verification (SDK-SOTA-03).
//!
//! Run on demand with `cargo bench -p arkret-signatures`; never run in CI.
//! Benches the Ed25519 detached-JWS proof verifier — the per-event signature
//! check on every ingest / federation path — over a fully valid proof so the
//! crypto cost (binding-object canonicalization + Ed25519 verify) is measured,
//! not an early rejection.

use arkret_canonical::canonical;
use arkret_signatures::proof::{
    PublicKeyMaterial, build_proof_envelope, sign_eddsa_detached_jws,
    verify_eddsa_detached_jws_proof,
};
use arkret_wire::{Did, DidUrl, Hash};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_proof_verify(c: &mut Criterion) {
    let seed = [7u8; 32];
    let verification_method = DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap();
    let actor_id = Did::new("did:webvh:z6mkfixture:alice.example").expect("static did");
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };

    // Canonical event bytes the proof is anchored to.
    let canonical_bytes = canonical::canonical_json_bytes(&serde_json::json!({
        "actor_id": "did:webvh:z6mkfixture:alice.example",
        "kind": "ak.message.create",
        "created_at": "2026-06-29T00:00:00.000Z"
    }))
    .expect("canonicalize event");

    // Build a proof whose event_digest matches the bytes, then sign the
    // canonical binding object (what the verifier actually checks).
    let mut proof = build_proof_envelope(
        "detached_jws",
        "EdDSA",
        verification_method,
        Hash::new(canonical::sha256_digest(&canonical_bytes)).expect("digest"),
        None,
        None,
        "",
    );
    let binding_bytes = proof
        .canonical_binding_bytes(&actor_id)
        .expect("binding bytes");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    proof.jws = sign_eddsa_detached_jws(&signing_key, &binding_bytes).expect("sign binding");

    // Sanity: the constructed proof must verify before we benchmark it.
    verify_eddsa_detached_jws_proof(&proof, &canonical_bytes, &actor_id, &public_key)
        .expect("constructed proof must verify");

    c.bench_function("verify_eddsa_detached_jws_proof", |b| {
        b.iter(|| {
            verify_eddsa_detached_jws_proof(
                std::hint::black_box(&proof),
                std::hint::black_box(&canonical_bytes),
                std::hint::black_box(&actor_id),
                std::hint::black_box(&public_key),
            )
            .unwrap()
        })
    });
}

criterion_group!(benches, bench_proof_verify);
criterion_main!(benches);
