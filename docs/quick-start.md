# Quick Start

Add the SDK crate:

```toml
cokret = { path = "crates/sdk" }
```

Create local client state and a session:

```rust
use std::sync::Arc;
use cokret::{BaseClient, DeviceId, Did, SessionMeta};

let base = Arc::new(BaseClient::new());
base.set_session_meta(SessionMeta::new(
    Did::new("did:web:alice.example")?,
    DeviceId::new("dev_desktop")?,
))?;
# Ok::<(), cokret::Error>(())
```

Process events and query a Realm-local Space container:

```rust
use cokret::{Realm, RealmId, SpaceId};

let realm_id = RealmId::new("ck:realm:01JS0RL000000000000000000")?;
let space_id = SpaceId::new("ck:space:01JS0SP000000000000000000")?;
let realm = Realm::new(realm_id, base);
let maybe_space = realm.get_space(&space_id);
# Ok::<(), cokret::Error>(())
```

Run verification:

```sh
cargo test
```

## Task Guides

### Build A Simple Client

Use `BaseClient` for local session and space state, then enable the `client`
feature when the application is ready to call a Cokret service over HTTP.

### Run Sync With Durable Storage

Persist sync positions, cached events and verified state snapshots through the
storage traits before entering a long-running sync loop. On a gap or invalid
snapshot, replay cached events and reset the cursor to the verified frontier.

`MemoryPersistenceStore` and `EncryptedMemoryCryptoStore` provide
dependency-free facades for event/state persistence and encrypted-at-rest
crypto records. Use them to validate snapshot replay, idempotent cache writes
and key rotation behavior before wiring a real database or platform keychain
adapter.

### Review Security Gates

Run `security_review_checklist()` for internal pre-audit evidence and
`current_feature_safety_report().validate()` for the published feature set.
Use `redact_log_value()` on structured diagnostics that may contain tokens,
proofs, signatures or private key references.

### Model Capability Facets

Use `Strand` for the stable semantic center of work and link Views, Morphs or
other surfaces as explicit `has_surface` relations. `EntityFacet` remains
available for open projections and capability constraints, but standard
objects should use their protocol type and resource selector directly.

### Send And Receive Encrypted Messages

Enable the `mls` feature, publish device key packages, process Welcomes, and
store group state in a durable `CryptoStore` implementation. Undecryptable
timeline items should be retained and retried after keys arrive.

### Write A Server

Use the `EndpointHandler` shape and the typed `ServerRequest` /
`ServerResponse` protocol enums. Host applications own HTTP parsing, routing,
authentication and response writing.

When `salvo` is enabled, every public `cokret-core` model and identifier
type derives `salvo::oapi::ToSchema` / `ToParameters`, so applications that use
Salvo OAPI can attach real field-level schemas directly to their own handlers.

For TLS, CORS, rate-limit, body size, systemd and other production concerns, see
[`docs/deployment.md`](deployment.md).
