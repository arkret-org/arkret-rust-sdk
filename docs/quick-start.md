# Quick Start

Add the umbrella SDK for protocol IDs, wire models, canonical helpers and
shared DTO contracts:

```toml
arkret = { path = "crates/sdk" }
```

Create validated protocol identifiers:

```rust
use arkret::{DeviceId, Did, RealmId};

let actor_id = Did::new("did:webvh:z6mkexample:alice.example")?;
let device_id =
    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")?;
let realm_id =
    RealmId::new("ak:realm:01904100-0000-8000-8000-668e2181b41d")?;

assert_eq!(actor_id.as_str(), "did:webvh:z6mkexample:alice.example");
assert!(device_id.as_str().starts_with("ak:device:"));
assert!(realm_id.as_str().starts_with("ak:realm:"));
# Ok::<(), arkret::WireError>(())
```

Enable only the integration surface the application uses:

```toml
arkret = { path = "crates/sdk", features = ["client"] }
arkret = { path = "crates/sdk", features = ["mls"] }
arkret = { path = "crates/sdk", features = ["server"] }
```

Runtime-neutral crypto capabilities are selected directly on their owner:

```toml
arkret-crypto = { path = "crates/crypto", features = ["blob-aead", "sframe"] }
```

Run verification:

```sh
cargo test -p arkret
cargo test -p arkret --all-features
```

## Task Guides

### Build A Client

Enable `client` for the reqwest/Tokio HTTP binding. Application state,
durability, retry scheduling and UI orchestration belong to the consuming
runtime; the shared runtime-neutral engine lives in Garth.

### Run Sync With Durable Storage

Persist sync positions, cached events and verified state snapshots through
application-owned durable storage. On a gap or invalid snapshot, replay from a
verified frontier rather than trusting unverified local cache state.

### Review Security Gates

Review `docs/security-audit.md` for internal pre-audit evidence. Do not log
payloads that may contain tokens, proofs, signatures or private key material;
applications must apply field-aware redaction at their logging boundary.

### Send And Receive Encrypted Messages

Enable `mls` for the OpenMLS-backed group machine. Publish device key packages,
process Welcomes and persist group state through durable application storage.
Undecryptable timeline items should be retained and retried after keys arrive.

Attachment AEAD, SFrame derivation, key backup, key verification and
secret-share helpers are independently feature-gated by `arkret-crypto`.

### Write A Server

Enable `server` for framework-independent handler contracts and endpoint
fixture coverage. Host applications own HTTP parsing, routing, authentication
and response writing.

OpenAPI is served from the canonical Spec artifact. Framework adapters must not
derive a second protocol document from SDK DTO metadata.

For TLS, CORS, rate limits, body size, systemd and other production concerns,
see [`docs/deployment.md`](deployment.md).
