# arkret-identity

Arkret v1 DID identity behavior layer.

DID resolution (`did:key` / `did:web` / `did:webvh`, composite + caching),
handle-claim challenges, DID key-log records with controller proofs, and the
DID-resolver-driven detached-JWS verify pipeline. Depends only on the wire /
model / signature data crates and the outbound egress classifier; the
umbrella `arkret` crate re-exports this surface under `arkret::identity::*`.
