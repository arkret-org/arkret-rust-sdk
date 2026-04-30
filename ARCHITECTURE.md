# Architecture

The workspace follows the same broad shape as Ruma and matrix-rust-sdk: focused
crates own protocol layers and runtime boundaries, while the top-level SDK crate
re-exports the cohesive public surface.

```text
application
    |
contrix (umbrella SDK)
    |-- contrix-core: wire models, canonical JSON, sync/cursor and service metadata
    |-- contrix-client: HTTP client for Contrix service endpoints
    |-- contrix-server: endpoint registry, adapter contracts, OpenAPI helpers and optional Salvo integration
    |-- base/sync_client: local client state, response processing and sliding sync
    |-- membership/devices/receipts/notifications: client business state
    |-- content/media/profile/settings/search/discovery: feature helpers
    |-- auth/identity/e2ee/federation/push: production protocol services
    |-- typing/webrtc/event_handler: realtime client features
    |-- mls: OpenMLS-backed group encryption and epoch handling
    `-- store: local Repo persistence traits and in-memory implementation
```

## Protocol Model

`crates/core/src/model.rs` owns protocol identifiers, HLC ordering,
object state enums, Space / ActorProfile / Entity / Relation / View objects,
signed Events, canonical Operations, signed Operation envelopes, Commits,
capability grants, policies, invites, read markers, notifications, blob
metadata and service request/response envelopes.

Model types should remain stable, explicit and serializable. Validation that is
required for protocol safety belongs close to these types, especially when it
protects canonical digests, authorization bindings or graph endpoint semantics.

## Canonical Digests

`crates/core/src/canonical.rs` implements deterministic JSON encoding and
digest calculation. Signed payloads must use this module instead of ad-hoc JSON
formatting so that different clients compute identical hashes.

The current canonical encoder sorts object keys, preserves array order, emits
integer numbers only and rejects floating point values.

## Client Layer

`crates/client/src/lib.rs` is a thin HTTP adapter. It is responsible for
base URL handling, authentication headers, JSON transport, service description
verification and Contrix error envelope parsing.

It must not hide protocol concepts behind application-specific abstractions.
Higher-level workflows can be added as helpers, but the low-level endpoints
should remain available.

## MLS Layer

`crates/sdk/src/mls.rs` binds Contrix encrypted Spaces to OpenMLS. It
creates device KeyPackages, creates MLS groups, adds members, consumes Welcome
messages, emits Commit / Welcome envelopes and encrypts application payloads
into Contrix `EncryptedPayload` values.

The SDK treats MLS state as local cryptographic state. Repo and Sync services
carry Commit, Welcome and encrypted application bytes, but they do not decrypt
payloads or gain group secrets.

Encrypted payload integrity follows the Contrix envelope rule:
`sha256(canonical_json(cleartext_metadata) || ciphertext_bytes)`. The SDK does
not hash plaintext payloads into `payload_digest`.

## Service Profiles

`crates/core/src/service.rs` verifies that a remote service advertises
the expected service type, protocol version, schema profile, reducer profile and
required operations before a client depends on it.

This keeps service discovery explicit and prevents silent downgrade or partial
implementation mistakes.

## Store Layer

`crates/sdk/src/store.rs` defines local Repo storage behavior. Stores
must be idempotent for repeated identical Operations or Commits and must report
conflicts when an existing identifier is reused with a different digest.

Persistent stores should implement the same trait contract as the in-memory
store before they are exposed publicly.

## Data Flow

```text
HTTP client / federation / push
    -> sync protocol responses
    -> sync_client::SyncResponseProcessor
    -> base::BaseClient state
    -> high-level managers (Space, Timeline, Presence, Receipts, Notifications)
    -> application event handlers
```

Managers are intentionally IO-light. Network transports, platform push
providers, platform WebRTC stacks and real SQLite/IndexedDB adapters can wrap
these state machines without changing SDK-facing types.

## Security Notes

- Use canonical digests for any signed payload.
- Validate service profiles before depending on remote capabilities.
- Treat E2EE, identity and federation helpers as state/control-plane helpers;
  production deployments should connect them to platform-grade key storage and
  cryptographic signing.
- Keep push payloads redacted for encrypted events.
