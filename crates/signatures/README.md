# cokret-signatures

Cokret canonical signature, proof binding, and HTTP message signature models.

This crate is the single source of truth for:

- Canonical JSON → to-be-signed bytes (`EventProofBuilder`).
- The `EventSigner` / `EventVerifier` traits each backend implements.
- The production Ed25519 detached-JWS adapter (`Ed25519DetachedJwsSigner` /
  `Ed25519DetachedJwsVerifier`) — RFC 7797 unencoded-payload shape with
  the payload segment stripped on the wire.
- A `ProofType` tag and `ProductionVerifier` adapter that refuse dev/test
  proofs in production deployments.
- HTTP message signature input construction and binding validators.

## Migrating downstream services

`coauth`, `soland`, and `yougen` historically grew their own canonical JSON
plumbing and detached-JWS construction. Round 22 (T5.1, 2026-05-19)
consolidates them into one pipeline. Migration steps:

1. Replace local `canonical_*` helpers with `EventProofBuilder::canonical_bytes`.
2. Replace local detached-JWS signers with `Ed25519DetachedJwsSigner`
   (`signer` feature). The wire shape is `b64u(header) ".." b64u(signature)`
   and the signing input is `b64u(header) "." b64u(canonical_bytes)`.
3. Wrap every verifier with `ProductionVerifier::wrap(...)` and pass the
   incoming proof through `assert_production_proof` so any dev-kind
   (`dev`, `test`, `mock`, `stub`, `dummy`) proof or `ProofType::Development`
   is rejected at the edge.
4. Use the canonical / Ed25519 / dev-proof test vectors under
   `tests/vectors/` as the migration checkpoint — any drift in the bytes,
   the hash, the signature, or the JWS string is a breaking change.

## Quick example

```rust,no_run
use cokret_signatures::{
    EventProofBuilder, EventSigner, EventVerifier, ProductionVerifier, PublicKeyMaterial,
};
# #[cfg(feature = "signer")]
# {
use cokret_signatures::{Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier};
use serde_json::json;

let signer = Ed25519DetachedJwsSigner::from_seed([1u8; 32], "did:web:alice.example#key-1");
let builder = EventProofBuilder::new();
let bytes = builder.canonical_bytes(&json!({"actor_id": "did:web:alice.example"})).unwrap();
let signature = signer.sign(&bytes).unwrap();

let verifier = ProductionVerifier::wrap(Ed25519DetachedJwsVerifier::new());
let public = PublicKeyMaterial::Ed25519Raw { bytes: signer.verifying_key().to_bytes().to_vec() };
verifier.verify(&bytes, &signature, &public).unwrap();
# }
```

## Feature flags

- `signer`: enables `Ed25519DetachedJwsSigner` / `Ed25519DetachedJwsVerifier`
  and the legacy `Ed25519MoveSigner`. Pulls in `ed25519-dalek` and `sha2`.

## Test vectors

`tests/vectors/canonical_json.json`, `tests/vectors/ed25519_jws.json`, and
`tests/vectors/dev_proofs.json` are the cross-implementation conformance
suite. They are exercised by `tests/proof_vectors.rs` and must reproduce
byte-for-byte under any compatible implementation.
