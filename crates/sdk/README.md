# Cokret Rust SDK

Release status: active Cokret v1 development SDK, with workspace crates still at
`0.3.0` until an explicit release cut. The crate exposes protocol types,
client/server bindings and authenticated local encryption helpers. Production
deployments should still use platform key storage and run service-level
conformance tests.

This crate is the Cokret v1 SDK entry point. It exposes the protocol model
directly and re-exports the shared contracts crate as `cokret::api`:

- DID principal identity
- Realm / Space / ActorProfile / Strand / Morph / Message / Relation / Event / View graph
- append-only Repo commits, canonical Operations and signed Operation envelopes
- capability-based authorization
- OpenMLS-backed MLS RFC 9420 group E2EE
- service discovery over Principal Server, Repo, Sync, Index, Blob, Directory and Authz surfaces
- protocol-shaped Query and Client Sync response models

The narrower contract facades are `cokret::client_api`,
`cokret::identity_api`, `cokret::federation_api` and
`cokret::push_gateway_api`. Use those when a caller needs DTOs shared across
services such as floria, chime and inkson without taking on server runtime
dependencies.

The default feature set enables the HTTP client and MLS support. Use
`default-features = false` for model-only consumers.
