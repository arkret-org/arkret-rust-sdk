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

## CXP-0007 follow-up (Circle primitive)

Spec commit b7d35be (`spec/v1/artifacts/registry/forbidden-wire-fields.json`
entry `identifier_suffix_ref_to_id_batch`) hardens the naming convention:

- Single concrete protocol object identifiers use `_id` (typed
  `cx:<kind>:<uuid>`).
- `_ref` is reserved for causal, proof, schema/profile, content-addressed,
  or polymorphic reference material.

Deleted from the public SDK in this round:

- `Flow.discussion_realm_ref` (hard-removed; replaced by
  `Flow.scope_circle_id` referencing the new `Circle` primitive)
- The wire fields `parent_ref`, `default_realm_ref`, `scope_ref`,
  `default_scope_ref`, `retention_policy_ref`, `disclosure_policy_ref`,
  `rate_limit_policy_ref`, and `policy_ref` on Policy objects are listed
  in [`forbidden_wire_fields::FORBIDDEN_WIRE_FIELDS`] and MUST be
  hard-rejected by receivers.

Minimum migration code:

```rust
use contrix::{Circle, CircleId, CircleDisplay, CircleColorToken, CircleGlyph,
              CircleSymbol, RealmId, Did};

let circle_id = CircleId::new(
    "cx:circle:0196419b-0000-7000-8000-000000000001".to_owned()
)?;
let realm_id = RealmId::new(
    "cx:realm:0196419b-0000-7000-8000-000000000002".to_owned()
)?;
let creator: Did = "did:web:alice.example".parse()?;
let display = CircleDisplay {
    short_name: "Ops".to_owned(),
    color_token: CircleColorToken::Indigo,
    symbol: CircleSymbol::Glyph { glyph: CircleGlyph::Shield },
};
let circle = Circle::new(circle_id.clone(), realm_id, "Ops Circle", display,
                         creator);

// Then bind a Flow to that Circle's encryption scope:
use contrix::{FlowCreateMetadata};
let meta = FlowCreateMetadata { scope_circle_id: Some(circle_id), ..Default::default() };
```

Capability and reason-code surfaces:

- New `cx.circle.*` event kinds: see `CIRCLE_CREATE`, `CIRCLE_UPDATE`,
  `CIRCLE_ARCHIVE`, `CIRCLE_RESTORE`, `CIRCLE_TOMBSTONE`,
  `CIRCLE_MEMBER_STATE`, `CIRCLE_ANCHOR_COMMIT` (the last is
  reducer-derived).
- New capability action constants `CAP_ACTION_CIRCLE_*` (6 actions).
- New reason codes `REASON_CIRCLE_REALM_MISMATCH`,
  `REASON_CIRCLE_NOT_ACTIVE`, `REASON_CIRCLE_MEMBER_MUST_BE_REALM_MEMBER`,
  `REASON_SCOPE_REBIND_FORBIDDEN`,
  `REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION` plus the existing
  `ERROR_CODE_DELIVERY_BINDING_HANDED_OVER`.

The version number of the `contrix` workspace is **not** bumped for this
round. See `CHANGELOG.md` `[Unreleased]` for the full breaking-change
list.
