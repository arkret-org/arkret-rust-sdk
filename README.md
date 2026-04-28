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

## License

Apache-2.0
