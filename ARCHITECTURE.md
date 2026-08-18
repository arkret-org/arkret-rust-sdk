# Architecture

The workspace follows the same broad shape as Ruma and matrix-rust-sdk: focused
crates own protocol layers and runtime boundaries, while the top-level SDK crate
re-exports the cohesive public surface.

```text
application
    |
arkret (umbrella SDK)
    |-- arkret-identifiers: validated DIDs, typed IDs, hashes, cursors and HLC values
    |-- arkret-wire: cross-domain wire primitives, registries and error codes
    |-- arkret-models-*: protocol model leaves split by consumer surface
    |-- arkret-crypto: local encryption, backup and key-management helpers
    |-- arkret-http-client: HTTP transport for Arkret service endpoints
    |-- arkret-keystore: platform KeyStore backends behind target feature gates
    |-- arkret-server: endpoint registry, routed dispatch, server middleware, adapter contracts and OpenAPI helpers
    |-- arkret-signatures: HTTP signatures, JWS/JWT and proof verification
    |-- focused model/behavior crates: protocol types and semantic operations
    |-- arkret-auth / arkret-identity: session grants, device and service identity, binding verification
    |-- arkret-models-collaboration: realm and conversation semantics, including
    |   the `ak.peer.*` federation frames (`crates/models-collaboration/src/federation/`),
    |   `ak.typing` composition indicators (`src/signal_plaintext.rs`) and
    |   `ak.call.*` signalling (`src/call_signal.rs`); WebRTC media/ICE config
    |   verification lives in `crates/signatures/src/media_ice.rs`
    |-- arkret-push-policy: push payload redaction policy
    |-- arkret-mls: OpenMLS-backed group encryption and epoch handling
    `-- arkret-bootstrap / arkret-lattice-registry: bootstrap and lattice behavior
```

Client runtime, synchronization, timeline and persistence orchestration live in
Garth rather than this SDK workspace.

## Protocol Model

`crates/identifiers/src/lib.rs` owns identifier validation for DIDs, typed
Arkret IDs, hashes, cursor tokens and HLC values. Serde decoding validates
the same invariants as constructors so malformed wire identifiers fail at the
edge.

The `crates/models-identity`, `crates/models-crypto`,
`crates/models-collaboration`, `crates/models-discovery`, and
`crates/models-integration` leaves own protocol data shapes. There is no
aggregate `crates/models` package; SDK-internal and server consumers depend
on the semantic leaves directly.

Model types should remain stable, explicit and serializable. Validation that is
required for protocol safety belongs close to these types, especially when it
protects canonical digests, authorization bindings or graph endpoint semantics.

## Canonical Digests

`crates/canonical/src/canonical.rs` implements deterministic JSON encoding and
digest calculation. Signed payloads must use this module instead of ad-hoc JSON
formatting so that different clients compute identical hashes.

The current canonical encoder sorts object keys, preserves array order, emits
integer numbers only and rejects floating point values.

## Client Layer

`arkret-http-client` (`crates/http-client/src/lib.rs`) is a thin HTTP adapter. It is responsible for
base URL handling, authentication headers, JSON transport, service description
verification and Arkret error envelope parsing.

It must not hide protocol concepts behind application-specific abstractions.
Higher-level workflows can be added as helpers, but the low-level endpoints
should remain available.

## MLS Layer

`crates/mls` (the `arkret-mls` crate, re-exported as `arkret::mls` under the
`mls` feature) is the workspace's sole OpenMLS boundary. It binds Arkret
encrypted Realms to OpenMLS: it creates device KeyPackages, creates MLS
groups, adds members, consumes Welcome messages, emits Commit / Welcome
envelopes and encrypts application payloads into Arkret `EncryptedPayload`
values.

The SDK treats MLS state as local cryptographic state. Repo and Sync services
carry Commit, Welcome and encrypted application bytes, but they do not decrypt
payloads or gain group secrets.

Encrypted payload integrity follows the Arkret envelope rule:
`sha256(canonical_json(payload_metadata) || base64url_decode(ciphertext))`. The
SDK does not hash plaintext payloads into `payload_digest`.

## Service Profiles

`crates/models-discovery/src/service_requirements.rs` defines the advertised
service requirements. Consuming behavior crates verify the expected service
type, protocol version, schema profile, reducer profile and required operations
before a client depends on a remote service.

This keeps service discovery explicit and prevents silent downgrade or partial
implementation mistakes.

## Store Layer

`crates/state/src/state/store/mod.rs` defines the store trait contracts for
the control-plane Event / Seal / Lattice runtime: `ControlEventStore`
(pending and sealed control-plane Event log keyed by the canonical
`event_digest`), `SealStore` (the Seal DAG), `CellStore` (per-cell sealed op
log and effective-state cache) and `CellRegistry`. Stores must report
conflicts when an existing identifier is reused with a different digest.

Persistent stores should implement the same trait contract as the in-memory
store before they are exposed publicly.

## Data Strand

```text
HTTP client / federation / push
    -> sync protocol responses
    -> garth::sync_client::SyncResponseProcessor
    -> garth::ArkretClient / ProjectionMount
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
