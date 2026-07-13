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
- service discovery over Principal Server, Repo, Sync, Index, Blob, Directory and Authz surfaces
- protocol-shaped Query and Client Sync response models

The narrower contract facades are `arkret::identity_api`, `arkret::federation_api` and
`arkret::push_gateway_api`. Use those when a caller needs DTOs shared across
services such as floria, chime and inkson without taking on server runtime
dependencies.

The default feature set is the protocol/type surface only. It does not enable
`openmls`, `reqwest`, `tokio`, `full-surface`, `applet-runtime`,
`device-runtime`, `sync-runtime` or `timeline-runtime`.

Common opt-ins:

- `client`: reqwest/tokio HTTP client bindings.
- `full-surface`: high-level SDK managers and local runtime facades.
- `mls`: OpenMLS-backed MLS helpers.
- `applet`: Applet convenience surface (`applet-runtime`, `client`, `server`,
  `salvo`).
