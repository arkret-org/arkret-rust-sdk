# Arkret Rust SDK

> **Spec target**: [arkret-spec @ 431f6acd](../arkret-spec) (v1 artifacts 2026-07-20)

[![codecov](https://codecov.io/gh/arkret-org/arkret-rust-sdk/branch/main/graph/badge.svg)](https://codecov.io/gh/arkret-org/arkret-rust-sdk)

Release status: active Arkret v1 SDK `0.3.x` development line, with workspace
crates still at `0.3.0` until an explicit release cut. The default `arkret`
feature set is the protocol/type surface only. Authenticated local encryption
helpers, OpenMLS MLS group encryption, framework-independent server contracts,
HTTP client bindings and runtime helpers are explicit opt-in features. The
local security-review packet and cotest release-gate interoperability suite are
recorded under `docs/`.

This repository contains the Rust SDK for Arkret v1. The public SDK surface is
centered on:

- DID principals
- Realm / Space / Strand / Message / Morph / Relation / Event / View
- signed Event Envelopes as the canonical wire facts for durable history
- Operations as SDK builders and offline draft objects before Event Envelope wrapping
- capability grants and policy checks
- MLS RFC 9420 group E2EE based on OpenMLS behind the `mls` feature
- Principal Server, Events, Index, Blob, Directory and Authz service surfaces

The active v1 wire contract follows `arkret-spec/spec/v1/zh` plus `arkret-spec/spec/v1/artifacts`.
All public SDK surfaces are expected to use `strand`, `track`, relation and
message semantics directly.

## Realm vs Space

- **Realm:** security boundary — membership, capability, E2EE, and federation
  are governed at this level.
- **Space:** navigation container — board, list, section, calendar bucket.
  Lives inside a Realm.

The wire layer and Rust model types use the same names: `Realm` for the
security boundary, `Space` for the product container.

## Entry Point

Use the top-level crate:

```toml
arkret = { path = "crates/sdk" }
```

The default feature set exposes protocol IDs, wire models, canonical helpers
and shared DTO contracts without enabling `openmls`, `reqwest`, `tokio`,
`full-surface` or runtime modules. Enable only the surface a consumer needs:

```toml
arkret = { path = "crates/sdk", features = ["client"] }
arkret = { path = "crates/sdk", features = ["mls"] }
arkret = { path = "crates/sdk", features = ["full-surface"] }
```

The workspace is split into focused crates and the top-level `arkret` crate
re-exports the public SDK surface:

- `arkret-canonical`: canonical JSON, digest, base64url and multibase primitives
- `arkret-crypto`: local encryption, backup and key-management helpers
- `arkret-identifiers`: validated DIDs, typed IDs, hashes, cursors and HLC values
- `arkret-http-client`: HTTP transport bindings
- `arkret-keystore`: platform KeyStore backends behind target-specific feature gates
- `arkret-policy`: protocol policy, authorization and resource-selector models
- `arkret-schema`: generated protocol registries and schema/artifact validation
- `arkret-server`: framework-independent server handler contracts, service route metadata and endpoint fixture coverage
- `arkret-signatures`: HTTP signatures, JWS/JWT and proof verification helpers
- `arkret-state`: reducer, snapshot, lattice and state-transition primitives
- `arkret-wire`: foundational wire constants, identifiers and protocol primitives
- `arkret-models-*`: identity, crypto, collaboration, discovery and integration protocol model leaves
- `arkret`: umbrella SDK crate with high-level state managers and feature forwarding

The workspace default members include all crates:

```sh
cargo check
cargo test
```

## Guides

- [Quick start](docs/quick-start.md)
- [API and error handling](docs/api-and-errors.md)
- [Authentication strands](docs/authentication.md)
- [Sync best practices](docs/sync-best-practices.md)
- [Deployment](docs/deployment.md)
- [Feature matrix](docs/feature-matrix.md)
- [Release readiness](docs/release-readiness.md)
- [Security audit checklist](docs/security-audit.md)
- [Conformance certification](docs/conformance-certification.md)
- [LTS policy](docs/lts-policy.md)

## Protocol review closures

Spec review closure `arkret-spec` range `2a4d39b..a77b995` (8 commits)
lands in the SDK as domain-named model modules re-exported from the
umbrella crate.
See [`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` for the canonical
wire-breaking list.
Headline additions:

- **Types**: `EventsSubscribeFrame` (8-kind enum), `SnapshotBootstrap`,
  `EventsFrontierState` oneOf (`AccountClient` / `FederationPeer` /
  `AnonymousHealth`), `PolicyCheckRequestBody` / `PolicyCheckOutcome`,
  `FederationServiceBindingRef` (6 required fields),
  `EventsSubmitBatchRequestBody` / `EventsSubmitFederationRequestBody`,
  `ThirdPartyInvite{oob_code_kind}`, `SpaceStateTransitionPayload` /
  `SpaceObjectTombstonePayload`, `AppletId` enum.
- **DID method-name regex** tightened to `^did:[a-z0-9]+:[^\s]+$`
  (method segment lowercase alnum only).
- **3 new error code constants**: `delivery_binding_stale` /
  `delivery_binding_handed_over` / `historical_only`.
- **1 new capability action**: `ak.morph.create` (medium risk).
- **3 new federation header constants**: `Source-Trust-Domain` /
  `Destination-Trust-Domain` / `Request-Canonical-Digest` (entered into
  the HTTP-message-signature transcript).
- **CAS upgrade**: `CrossSigningPublishPayload` gains required
  `expected_previous_generation`; `compute_audit_policy_version_digest`
  takes 4 args (`realm_id, trust_domain, audit_disclosure,
  audit_assurance`).
- **`ak.call.signal` (Round 4 wire revision)**: 13-value `signal_type`
  enum, required `proof`, monotonic `seq` validator.
- **`Realm` / `ServiceDescribe` / `AuditRywReceipt`** gain required
  `trust_domain`; the revised `ServiceDescribe` carries 17 required fields.

## Project documents

- [Changelog](CHANGELOG.md) — release notes and unreleased SDK changes.
  Normative protocol changes remain sourced from the sibling `arkret-spec`
  repository and its machine-readable registries.
- [Security policy](SECURITY.md) — supported versions and how to report
  vulnerabilities responsibly.
- [Releasing](RELEASING.md) — local package checks for the 15-crate workspace
  in topological order.
- [Contributing](CONTRIBUTING.md) — development checks, API rules, commit
  style.

## Implemented Arkret Surface

The first Arkret crate currently includes:

- v1 identifiers and protocol constants
- canonical JSON and SHA-256 digest helpers
- Space, ActorProfile, Strand, Message, Morph, Relation, Event Envelope, View, Operation draft and Capability models
- protocol-shaped Query and Client Sync response models (`space_ids`, filter arrays, `spaces`)
- Event Envelope digest payload calculation
- HLC parsing and deterministic ordering
- Proof signature-binding payload calculation
- Policy, Invite, Read Cursor, Notification, Blob Metadata and Encrypted Envelope models
- encrypted content digest calculation over plaintext routing metadata plus ciphertext bytes
- MLS KeyPackage, Commit and Welcome envelopes
- OpenMLS-backed group creation, member add, Welcome join, payload encryption and decryption behind the `mls` feature
- in-memory persistence helpers for event cache, verified state snapshots and account-local records
- Server description and profile version checks
- HTTP client methods for the Arkret v1 service HTTP binding behind the `client` feature, including request metadata, retry/backoff and `Retry-After` handling
- shared contract DTOs live in semantic model leaves; the umbrella SDK exposes a curated root surface and namespaced `arkret::models` aggregate
- framework-independent server handler contracts and endpoint fixture coverage live in `arkret-server`; the umbrella forwards the optional server and Salvo surfaces
- high-level `full-surface` sync loop, membership, devices, receipts,
  media, profile/settings, discovery, E2EE, auth/identity, federation, push,
  typing, WebRTC, store and event-handler helpers

## License

Apache-2.0

---

<!-- circle-rollout milestone pointer -->
> **Active milestone tracking** (local-only, gitignored): see
> `_arkret-rust-sdk_todos.md` in the parent `arkret/` directory for the
> circle-rollout (AKP-0007) work item list and per-stage checkpoints.
