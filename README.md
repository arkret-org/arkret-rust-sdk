# Cokret Rust SDK

> **Spec target**: [cokret-spec @ c2848a4](../cokret-spec) (R3.4 sync 2026-05-31)

[![codecov](https://codecov.io/gh/cokret/cokret-rust-sdk/branch/main/graph/badge.svg)](https://codecov.io/gh/cokret/cokret-rust-sdk)

Release status: active Cokret v1 development SDK, with workspace crates still at
`0.3.0` until an explicit release cut. The SDK includes authenticated local
encryption helpers based on XChaCha20-Poly1305, OpenMLS MLS group encryption,
framework-independent server contracts, HTTP client bindings and
conformance-oriented tests. Local security-review and cotest release-readiness
evidence are recorded under `docs/`.

This repository contains the Rust SDK for Cokret v1. The public SDK surface is
centered on:

- DID principals
- Realm / Space / Flow / Message / Morph / Relation / Event / View
- signed Event Envelopes as the canonical wire facts for durable history
- Operations as SDK builders and offline draft objects before Event Envelope wrapping
- capability grants and policy checks
- MLS RFC 9420 group E2EE based on OpenMLS
- Principal Server, Events, Index, Blob, Directory and Authz service surfaces

The active v1 wire contract follows `cokret-spec/spec/v1/zh` plus `cokret-spec/spec/v1/artifacts`.
All public SDK surfaces are expected to use `flow`, `track`, relation and
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
cokret = { path = "crates/sdk" }
```

The workspace is split into focused crates and the top-level `cokret` crate
re-exports the public SDK surface:

- `cokret-core`: protocol identifiers, canonical JSON, wire models, sync/cursor types and service metadata
- `cokret-contracts`: shared wire-contract DTOs for product-local client APIs, identity, federation and push gateway integration
- `cokret-identifiers`: validated DIDs, typed IDs, hashes, cursors and HLC values
- `cokret-http-client`: HTTP transport bindings
- `cokret-server`: framework-independent server handler contracts, service route metadata and endpoint fixture coverage
- `cokret`: umbrella SDK crate with high-level state managers and feature forwarding

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

## Protocol review closures

Spec review closure `cokret-spec` range `2a4d39b..a77b995` (8 commits)
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
- **1 new capability action**: `ck.morph.create` (medium risk).
- **3 new federation header constants**: `Source-Trust-Domain` /
  `Destination-Trust-Domain` / `Request-Canonical-Digest` (entered into
  the HTTP-message-signature transcript).
- **CAS upgrade**: `CrossSigningPublishPayload` gains required
  `expected_previous_generation`; `compute_audit_policy_version_digest`
  takes 4 args (`realm_id, trust_domain, audit_disclosure,
  audit_assurance`).
- **`ck.call.signal` (Round 4 wire revision)**: 13-value `signal_type`
  enum, required `proof`, monotonic `seq` validator.
- **`Realm` / `ServiceDescribe` / `AuditRywReceipt`** gain required
  `trust_domain`; the revised `ServiceDescribe` carries 17 required fields.

## Project documents

- [Changelog](CHANGELOG.md) — release notes and unreleased changes. The
  `[Unreleased]` Round R4 / R2 / R3 entries track the most recent
  spec close-outs (round 4 ranges `2a4d39b..a77b995`; round 2+3 lands
  4 new event kinds, 3 new schemas, 2 new typed ID kinds, 15 new error
  codes); see [`../cokret-spec/CHANGELOG.md`](../cokret-spec/CHANGELOG.md)
  for the normative source.
- [Security policy](SECURITY.md) — supported versions and how to report
  vulnerabilities responsibly.
- [Releasing](RELEASING.md) — local package checks for the 11-crate workspace
  in topological order.
- [Contributing](CONTRIBUTING.md) — development checks, API rules, commit
  style.

## Implemented Cokret Surface

The first Cokret crate currently includes:

- v1 identifiers and protocol constants
- canonical JSON and SHA-256 digest helpers
- Space, ActorProfile, Flow, Message, Morph, Relation, Event Envelope, View, Operation draft and Capability models
- protocol-shaped Query and Client Sync response models (`space_ids`, filter arrays, `spaces`)
- Event Envelope digest payload calculation
- HLC parsing and deterministic ordering
- Proof signature-binding payload calculation
- Policy, Invite, Read Cursor, Notification, Blob Metadata and Encrypted Envelope models
- encrypted content digest calculation over plaintext routing metadata plus ciphertext bytes
- MLS KeyPackage, Commit and Welcome envelopes
- OpenMLS-backed group creation, member add, Welcome join, payload encryption and decryption
- in-memory persistence helpers for event cache, verified state snapshots and account-local records
- Server description and profile version checks
- HTTP client methods for the Cokret v1 service HTTP binding, including request metadata, retry/backoff and `Retry-After` handling
- shared contract DTOs exposed through `cokret-contracts` and re-exported from the umbrella SDK as `cokret::api`, `cokret::client_api`, `cokret::identity_api`, `cokret::federation_api` and `cokret::push_gateway_api`
- framework-independent server handler contracts, endpoint fixture coverage and Salvo OAPI DTO support through `cokret-core`
- high-level sync loop, membership, devices, receipts, notifications, content,
  media, profile/settings, discovery, E2EE, auth/identity, federation, push,
  typing, WebRTC, store and event-handler helpers

## License

Apache-2.0

---

<!-- circle-rollout milestone pointer -->
> **Active milestone tracking** (local-only, gitignored): see
> `_cokret-rust-sdk_todos.md` in the parent `cokret/` directory for the
> circle-rollout (CKP-0007) work item list and per-stage checkpoints.
