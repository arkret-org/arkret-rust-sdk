# Migrating From 0.7

This release candidate removes the transitional Realm/Space aliases that were
kept during the protocol rename window.

## Container IDs

Use `SpaceId` for container IDs. `PlaceId` has been removed from the public
identifier crate and from SDK builders.

```rust
use contrix::SpaceId;

let container_id = SpaceId::new("cx:space:01904100-0000-7000-8000-000000000001")?;
```

## Container Event Kinds

Use the `OP_SPACE_*` constants for container lifecycle events:

- `OP_SPACE_CREATE`
- `OP_SPACE_UPDATE`
- `OP_SPACE_PARENT`
- `OP_SPACE_ARCHIVE`
- `OP_SPACE_RESTORE`
- `OP_SPACE_TOMBSTONE`

The old `OP_PLACE_*` constants are gone. Wire event kinds remain the canonical
`cx.space.*` values.

## Schema IDs

Use `SPACE_SCHEMA` for the container schema. The retired compile-time
`PLACE_SCHEMA` alias is gone; the wire schema is `cx.schema.space.v1`.

## Realm Governance

Realm governance uses the `OP_REALM_*` family. The old security-boundary
`OP_SPACE_CHILD`, `OP_SPACE_ORGANIZATION`, and
`OP_SPACE_DELIVERY_BINDING_POLICY` aliases have been removed.
