# Quick Start

Add the SDK crate:

```toml
contrix-sdk = { path = "crates/contrix-sdk" }
```

Create local client state and a session:

```rust
use std::sync::Arc;
use contrix_sdk::{BaseClient, DeviceId, Did, SessionMeta};

let base = Arc::new(BaseClient::new());
base.set_session_meta(SessionMeta::new(
    Did::new("did:web:alice.example")?,
    DeviceId::new("dev_desktop")?,
))?;
# Ok::<(), contrix_sdk::Error>(())
```

Process events and query a space:

```rust
use contrix_sdk::{EntityQuery, Space, SpaceId};

let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000")?;
let space = Space::new(space_id, base);
let tasks = space.query_entities(EntityQuery::default());
# Ok::<(), contrix_sdk::Error>(())
```

Run verification:

```sh
cargo test
```
