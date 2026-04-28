# Contrix Rust SDK

This repository contains the Rust SDK for Contrix v1. The public SDK surface is
centered on:

- DID principals
- Space / ActorProfile / Entity / Relation / Event / View
- append-only Repo commits, canonical Operations and signed Operation envelopes
- capability grants and policy checks
- MLS RFC 9420 group E2EE based on OpenMLS
- Principal Server, Repo, Sync, Index, Blob, Directory and Authz service surfaces

## Entry Point

Use the new crate:

```toml
contrix-sdk = { path = "crates/contrix-sdk" }
```

The workspace default member is `crates/contrix-sdk`, so these commands target
the Contrix SDK:

```sh
cargo check
cargo test
```

## Guides

- [Quick start](docs/quick-start.md)
- [API and error handling](docs/api-and-errors.md)
- [Authentication flows](docs/authentication.md)
- [Sync best practices](docs/sync-best-practices.md)
- [Matrix migration notes](docs/migration-from-matrix.md)
- [Security audit checklist](docs/security-audit.md)
- [Conformance certification](docs/conformance-certification.md)
- [LTS policy](docs/lts-policy.md)

## Implemented Contrix Surface

The first Contrix crate currently includes:

- v1 identifiers and protocol constants
- canonical JSON and SHA-256 digest helpers
- Space, ActorProfile, Entity, Relation, Event, View, Operation, Commit and Capability models
- protocol-shaped Query and Client Sync response models (`space_ids`, filter arrays, `rooms`)
- Event and Commit digest payload calculation
- HLC parsing and deterministic ordering
- Proof signature-binding payload calculation
- Policy, Invite, Read Marker, Notification, Blob Metadata and Encrypted Payload models
- encrypted payload digest calculation over cleartext routing metadata plus ciphertext bytes
- MLS KeyPackage, Commit and Welcome envelopes
- OpenMLS-backed group creation, member add, Welcome join, payload encryption and decryption
- in-memory Repo store with idempotent operation/commit insertion and conflict detection
- Server description and profile version checks
- HTTP client methods for `/server`, `/repo`, `/sync`, `/index`, `/authz`, `/blob`,
  `/keys` and `/device_messages`
- high-level sync loop, membership, devices, receipts, notifications, content,
  media, profile/settings, discovery, E2EE, auth/identity, federation, push,
  typing, WebRTC, store and event-handler helpers

## License

Apache-2.0
