# Contrix Rust SDK

> **Spec target**: [contrix-spec @ b56cab1](../contrix-spec) (R3.2 sync 2026-05-28)

[![codecov](https://codecov.io/gh/contrix/contrix-rust-sdk/branch/main/graph/badge.svg)](https://codecov.io/gh/contrix/contrix-rust-sdk)

Release status: local Contrix v1 SDK `1.0.0` freeze candidate. The SDK includes
authenticated local encryption helpers based on XChaCha20-Poly1305, OpenMLS MLS
group encryption, framework-independent server contracts, HTTP client bindings
and conformance-oriented tests. The local security-review packet and cotest
release-gate interoperability suite are recorded under `docs/`.

This repository contains the Rust SDK for Contrix v1. The public SDK surface is
centered on:

- DID principals
- Realm / Space / Flow / Message / Morph / Relation / Event / View
- signed Event Envelopes as the canonical wire facts for durable history
- Operations as SDK builders and offline draft objects before Event Envelope wrapping
- capability grants and policy checks
- MLS RFC 9420 group E2EE based on OpenMLS
- Principal Server, Events, Sync, Index, Blob, Directory and Authz service surfaces

The active v1 wire contract follows `contrix-spec/spec/v1/zh` plus `contrix-spec/spec/v1/artifacts`.
All public SDK surfaces are expected to use `flow`, branch, relation and
message semantics directly.

## Realm vs Space

After the Phase 1–4 terminology inversion (Round R1.x):

- **Realm:** security boundary — membership, capability, E2EE, and federation
  are governed at this level. Previously called `Space` on the wire.
- **Space:** navigation container — board, list, section, calendar bucket.
  Lives inside a Realm. Previously called `Place` on the wire.

The 0.8 line uses the realm/space names directly; the 0.7 compile-time aliases
are removed. See [`CHANGELOG.md`](CHANGELOG.md) for the wire-breaking rename
notes.

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

## Round R4 (protocol review closures)

Spec round 4 (`contrix-spec` range `2a4d39b..a77b995`, 8 commits) lands
in the SDK as a new `round4` module re-exported from the umbrella crate.
See [`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` for the canonical
wire-breaking list.
Headline additions:

- **Types**: `EventsSubscribeFrame` (8-kind enum), `SnapshotBootstrap`,
  `EventsFrontierResponse` oneOf (`AccountClient` / `FederationPeer` /
  `AnonymousHealth`), `PolicyCheckRequest` / `PolicyCheckResponse`,
  `FederationServiceBindingRef` (6 required fields),
  `EventsSubmitBatchRequest` / `EventsSubmitFederationRequest`,
  `ThirdPartyInvite{oob_code_kind}`, `SpaceStateTransitionPayload` /
  `SpaceObjectTombstonePayload`, `AppletId` enum.
- **DID method-name regex** tightened to `^did:[a-z0-9]+:[^\s]+$`
  (method segment lowercase alnum only).
- **3 new error code constants**: `delivery_binding_stale` /
  `delivery_binding_handed_over` / `historical_only`.
- **1 new capability action**: `cx.morph.create` (medium risk).
- **3 new federation header constants**: `Source-Trust-Domain` /
  `Destination-Trust-Domain` / `Request-Canonical-Digest` (entered into
  the HTTP-message-signature transcript).
- **CAS upgrade**: `CrossSigningPublishPayload` gains required
  `expected_previous_generation`; `compute_audit_policy_version_digest`
  takes 4 args (`realm_id, trust_domain, audit_disclosure,
  audit_assurance`).
- **`cx.call.signal` v2**: 13-value `signal_type` enum, required
  `proof`, monotonic `seq` validator.
- **`Realm` / `ServiceDescribe` / `AuditRywReceipt`** gain required
  `trust_domain`; `ServiceDescribe` v2 carries 17 required fields.

## Project documents

- [Changelog](CHANGELOG.md) — release notes and unreleased changes. The
  `[Unreleased]` Round R4 / R2 / R3 entries track the most recent
  spec close-outs (round 4 ranges `2a4d39b..a77b995`; round 2+3 lands
  4 new event kinds, 3 new schemas, 2 new typed ID kinds, 15 new error
  codes); see [`../contrix-spec/CHANGELOG.md`](../contrix-spec/CHANGELOG.md)
  for the normative source.
- [Security policy](SECURITY.md) — supported versions and how to report
  vulnerabilities responsibly.
- [Releasing](RELEASING.md) — local package checks for the 11-crate workspace
  in topological order.
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

---

<!-- circle-rollout milestone pointer -->
> **Active milestone tracking** (local-only, gitignored): see
> `_contrix-rust-sdk_todos.md` in the parent `contrix-dev/` directory for the
> circle-rollout (CXP-0007) work item list and per-stage checkpoints.
