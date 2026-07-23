# Quick Start

Add the SDK crate:

```toml
arkret = { path = "crates/sdk" }
```

This default dependency exposes protocol IDs, wire models, canonical helpers
and shared DTO contracts only. It does not enable the HTTP client, OpenMLS or
high-level runtime modules.

For the local client-state examples below, enable the high-level SDK surface:

```toml
arkret = { path = "crates/sdk", features = ["full-surface"] }
```

Create local client state and a session:

```rust
use std::sync::Arc;
use arkret::{BaseClient, DeviceId, Did, SessionMeta};

let base = Arc::new(BaseClient::new());
base.set_session_meta(SessionMeta::new(
    Did::new("did:webvh:z6mkexample:alice.example")?,
    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")?,
))?;
# Ok::<(), arkret::Error>(())
```

Process events and query a Realm-local Space container. Typed ids carry a
canonical lowercase UUIDv7 payload — mint fresh ones with
`arkret::new_prefixed_uuid7("ak:realm:")`:

```rust
use arkret::{Realm, RealmId, SpaceId};

let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d")?;
let space_id = SpaceId::new("ak:space:01904100-0000-7000-8000-6c663fa0205f")?;
let realm = Realm::new(realm_id, base);
let maybe_space = realm.get_space(&space_id);
# Ok::<(), arkret::Error>(())
```

Run verification:

```sh
cargo test -p arkret --features full-surface
```

## Task Guides

### Build A Simple Client

Use `BaseClient` for local session and space state, then enable the `client`
feature when the application is ready to call a Arkret service over HTTP.

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

Review `docs/security-audit.md` for internal pre-audit evidence. Use
`feature_safety_report(...)` to validate feature strings that downstream
services self-report (describe/manifest payloads); note its scope — it is not
a compile gate for this SDK's own Cargo features. Cargo's feature graph plus
the `compile_error!` guards at the top of `crates/sdk/src/lib.rs` enforce the
reviewed feature combinations at build time.
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

When `salvo` is enabled, every public `arkret` model and identifier
type derives `salvo::oapi::ToSchema` / `ToParameters`, so applications that use
Salvo OAPI can attach real field-level schemas directly to their own handlers.

For TLS, CORS, rate-limit, body size, systemd and other production concerns, see
[`docs/deployment.md`](deployment.md).
