# Arkret Rust SDK

Release status: active Arkret v1 development SDK, with workspace crates still at
`0.3.0` until an explicit release cut. The crate exposes protocol types by
default. Client/server bindings, MLS support and high-level runtime helpers are
explicit opt-in features. Production deployments should still use platform key
storage and run service-level conformance tests.

This crate is the Arkret v1 SDK entry point. It exposes the protocol model
directly and re-exports the shared contracts crate as `arkret::api`:

- DID principal identity
- Realm / Space / ActorProfile / Strand / Morph / Message / Relation / Event / View graph
- append-only Repo commits, canonical Operations and signed Operation envelopes
- capability-based authorization
- OpenMLS-backed MLS RFC 9420 group E2EE
- service discovery over Station, Repo, Sync, Index, Blob, Directory and Authz surfaces
- protocol-shaped Query and Client Sync response models

The canonical contract modules are `arkret::identity`, `arkret::federation` and
`arkret::push`. Use those when a caller needs DTOs shared across
services such as floria, chime and inkson without taking on server runtime
dependencies.

The default feature set is the protocol/type surface only. It does not enable
`openmls`, `reqwest`, `tokio` or server framework integrations.

Common opt-ins:

- `client`: reqwest/tokio HTTP client bindings.
- `mls`: OpenMLS-backed MLS helpers.
- `server`: framework-independent server contracts.
- Applet wire contracts are always available from `arkret-models-integration`;
  use `arkret-event-draft` for bridge-error Event construction and enable
  `client` and/or `server` when those runtime layers are needed.
