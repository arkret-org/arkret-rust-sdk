# Contrix Rust SDK

Release status: release candidate for Contrix v1 SDK `0.1.0`. The SDK includes
authenticated local encryption helpers based on XChaCha20-Poly1305, OpenMLS MLS
group encryption, framework-independent server contracts, HTTP client bindings
and conformance-oriented tests. Before a stable non-0.x guarantee, run an
external security review and at least one real server interoperability suite.

This repository contains the Rust SDK for Contrix v1. The public SDK surface is
centered on:

- DID principals
- Space / Flow / Message / Morph / Relation / Event / View
- signed Event Envelopes as the canonical wire facts for durable history
- Operations as SDK builders and offline draft objects before Event Envelope wrapping
- capability grants and policy checks
- MLS RFC 9420 group E2EE based on OpenMLS
- Principal Server, Events, Sync, Index, Blob, Directory and Authz service surfaces

The active v1 wire contract follows `contrix-spec/spec/v1/zh` plus `contrix-spec/spec/v1/artifacts`.
All public SDK surfaces are expected to use `flow`, branch, relation and
message semantics directly.

## Entry Point

Use the top-level crate:

```toml
contrix = { path = "crates/sdk" }
```

The workspace is split into focused crates and the top-level `contrix` crate
re-exports the public SDK surface:

- `contrix-core`: protocol identifiers, canonical JSON, wire models, sync/cursor types and service metadata
- `contrix-identifiers`: validated DIDs, typed IDs, hashes, cursors and HLC values
- `contrix-http-client`: HTTP transport bindings
- `contrix-server`: framework-independent protocol request/response contracts and endpoint fixture coverage
- `contrix`: umbrella SDK crate with high-level state managers and feature forwarding

The workspace default members include all crates:

```sh
cargo check
cargo test
```

## Guides

- [Quick start](docs/quick-start.md)
- [API and error handling](docs/api-and-errors.md)
- [Authentication flows](docs/authentication.md)
- [Sync best practices](docs/sync-best-practices.md)
- [Deployment](docs/deployment.md)
- [Feature matrix](docs/feature-matrix.md)
- [Release readiness](docs/release-readiness.md)
- [Security audit checklist](docs/security-audit.md)
- [Conformance certification](docs/conformance-certification.md)
- [LTS policy](docs/lts-policy.md)

## Project documents

- [Changelog](CHANGELOG.md) — release notes and unreleased changes.
- [Security policy](SECURITY.md) — supported versions and how to report
  vulnerabilities responsibly.
- [Releasing](RELEASING.md) — how the 11-crate workspace is published in
  topological order.
- [Contributing](CONTRIBUTING.md) — development checks, API rules, commit
  style.

## Implemented Contrix Surface

The first Contrix crate currently includes:

- v1 identifiers and protocol constants
- canonical JSON and SHA-256 digest helpers
- Space, ActorProfile, Flow, Message, Morph, Relation, Event Envelope, View, Operation draft and Capability models
- protocol-shaped Query and Client Sync response models (`space_ids`, filter arrays, `spaces`)
- Event Envelope digest payload calculation
- HLC parsing and deterministic ordering
- Proof signature-binding payload calculation
- Policy, Invite, Read Marker, Notification, Blob Metadata and Encrypted Payload models
- encrypted payload digest calculation over cleartext routing metadata plus ciphertext bytes
- MLS KeyPackage, Commit and Welcome envelopes
- OpenMLS-backed group creation, member add, Welcome join, payload encryption and decryption
- in-memory persistence helpers for event cache, verified state snapshots and account-local records
- Server description and profile version checks
- HTTP client methods for the Contrix v1 service HTTP binding, including request metadata, retry/backoff and `Retry-After` handling
- framework-independent server protocol contracts, endpoint fixture coverage and Salvo OAPI DTO support through `contrix-core`
- high-level sync loop, membership, devices, receipts, notifications, content,
  media, profile/settings, discovery, E2EE, auth/identity, federation, push,
  typing, WebRTC, store and event-handler helpers

## License

Apache-2.0
