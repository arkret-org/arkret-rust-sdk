# arkret-signatures

Arkret canonical signature, proof binding, and HTTP message signature models.

This crate is the single source of truth for:

- Canonical JSON → to-be-signed bytes (`EventProofBuilder`).
- The `EventSigner` / `EventVerifier` traits each backend implements.
- Generic Ed25519 detached-JWS primitives (`Ed25519DetachedJwsSigner` /
  `Ed25519DetachedJwsVerifier`) for protocol binding objects supplied by callers.
- The `sign_event` / `verify_ed25519_detached_jws_proof` event-proof pipeline,
  which constructs and signs the mandatory `ak.event-proof-v1` binding object.
- Wire-level proof-kind validation that refuses dev/test proof kinds.
- HTTP message signature input construction and binding validators.

## Migrating downstream services

`coauth`, `soland`, and `inkson` historically grew their own canonical JSON
plumbing and detached-JWS construction. Round 22 (T5.1, 2026-05-19)
consolidates them into one pipeline. Migration steps:

1. Replace local `canonical_*` helpers with `EventProofBuilder::canonical_bytes`.
2. Replace local Event proof signers with `sign_event` and verification with
   `verify_ed25519_detached_jws_proof`. Do not sign raw Event-envelope bytes.
3. Validate incoming `ProducerEventProof` values with
   `ProducerEventProof::validate_production` before cryptographic verification,
   so dev kinds (`dev`, `test`, `mock`, `stub`, `dummy`) are rejected at the edge.
4. Use the canonical / Ed25519 / dev-proof test vectors under
   `tests/vectors/` as the migration checkpoint — any drift in the bytes,
   the hash, the signature, or the JWS string is a breaking change.

## Quick example

```rust,no_run
use arkret_signatures::{EventProofBuilder, EventSigner, EventVerifier, PublicKeyMaterial};
# #[cfg(feature = "signer")]
# {
use arkret_signatures::{Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier};
use serde_json::json;

let signer = Ed25519DetachedJwsSigner::from_seed([1u8; 32], "did:webvh:z6mkfixture:alice.example#key-1");
let builder = EventProofBuilder::new();
let bytes = builder.canonical_bytes(&json!({"actor_id": "did:webvh:z6mkfixture:alice.example"})).unwrap();
let signature = signer.sign(&bytes).unwrap();

let verifier = Ed25519DetachedJwsVerifier::new();
let public = PublicKeyMaterial::Ed25519Raw { bytes: signer.verifying_key().to_bytes().to_vec() };
verifier.verify(&bytes, &signature, &public).unwrap();
# }
```

## Feature flags

- `collaboration`: enables Agent, call-media, Realm organization, and
  ephemeral-envelope signing helpers that consume collaboration models.
- `keypackages`: enables MLS KeyPackage request signing helpers.
- `service-identity`: enables service-identity statement helpers.
- `webvh`: enables `did:webvh` inception and validation helpers.
- `signer`: enables `Ed25519DetachedJwsSigner` / `Ed25519DetachedJwsVerifier`
  and `Ed25519MoveSigner`.

The default surface contains proof/JWS/JWT/DPoP and HTTP Message Signature
primitives without depending on any Arkret model leaf.

## Test vectors

`tests/vectors/canonical_json.json`, `tests/vectors/ed25519_jws.json`, and
`tests/vectors/dev_proofs.json` are the cross-implementation conformance
suite. They are exercised by `tests/proof_vectors.rs` and must reproduce
byte-for-byte under any compatible implementation.
