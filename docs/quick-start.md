# Quick Start

Add the SDK crate:

```toml
contrix = { path = "crates/sdk" }
```

Create local client state and a session:

```rust
use std::sync::Arc;
use contrix::{BaseClient, DeviceId, Did, SessionMeta};

let base = Arc::new(BaseClient::new());
base.set_session_meta(SessionMeta::new(
    Did::new("did:web:alice.example")?,
    DeviceId::new("dev_desktop")?,
))?;
# Ok::<(), contrix::Error>(())
```

Process events and query a space:

```rust
use contrix::{EntityQuery, Space, SpaceId};

let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000")?;
let space = Space::new(space_id, base);
let tasks = space.query_entities(EntityQuery::default());
# Ok::<(), contrix::Error>(())
```

Run verification:

```sh
cargo test
```

## Task Guides

### Build A Simple Client

Use `BaseClient` for local session and space state, then enable the `client`
feature when the application is ready to call a Contrix service over HTTP.

### Build A Bot

Register typed handlers with `EventHandlerRegistry`, filter incoming
`ClientEvent` values and send replies through the host application's transport
or high-level client facade.

### Run Sync With Durable Storage

Persist repo objects, sync positions and state snapshots through the storage
traits before entering a long-running sync loop. On a gap or invalid snapshot,
replay repo events and reset the cursor to the verified frontier.

`SqliteRepoStore`, `IndexedDbRepoStore` and `EncryptedMemoryCryptoStore` provide
dependency-free conformance facades for repository, browser and crypto-store
behavior. Use them to validate migrations, transaction atomicity, browser restart
state, encrypted-at-rest records and rollback protection before wiring a real
SQLite, IndexedDB or platform keychain adapter.

### Review Security Gates

Run `security_review_checklist()` for internal pre-audit evidence and
`current_feature_safety_report().validate()` for the published feature set.
Use `redact_log_value()` on structured diagnostics that may contain tokens,
proofs, signatures or private key references.

### Model Capability Facets

Use `EntityFacet` as the primary capability signal for views, queries and
capability constraints. `entity_type` remains available for legacy filtering and
product labels, but authorization should prefer facet selectors such as
`stateful + rankable` over type names such as `task`.

### Send And Receive Encrypted Messages

Enable the `mls` feature, publish device key packages, process Welcomes, and
store group state in a durable `CryptoStore` implementation. Undecryptable
timeline items should be retained and retried after keys arrive.

### Write A Server Adapter

Use the framework-independent endpoint registry and `EndpointHandler` shape.
The SDK ships a Salvo adapter behind the `salvo-adapter` feature. It adapts
Salvo requests into the framework-independent `HttpAdapterRequest` shape and
writes `HttpAdapterResponse` values back to Salvo responses without changing
operation IDs.

### Migrate From Matrix Concepts

See `docs/migration-from-matrix.md` for the Matrix-to-Contrix mapping. Treat
Contrix spaces as signed reducer state over repos rather than mutable room
state snapshots.
