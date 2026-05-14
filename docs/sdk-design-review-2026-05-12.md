# SDK Design Review - 2026-05-12

Scope: `D:\Works\contrix-dev\contrix-rust-sdk` checked against
`D:\Works\contrix-dev\contrix-spec\spec\v1\zh` and
`D:\Works\contrix-dev\contrix-spec\spec\v1\artifacts`.

## Summary

The current SDK design is broadly reasonable and mostly aligned with the v1
spec. The workspace split is healthy: identifiers validate wire IDs,
`contrix-core` owns protocol models and canonical behavior, `contrix-api` owns
the service operation catalog, `contrix-server` owns framework-neutral routing
plus Salvo integration, and the top-level SDK crate keeps high-level client
state and feature helpers out of the protocol core.

The strongest parts are the spec-drift checks, canonical JSON/digest handling,
typed identifier validation, service profile checks, and the separation between
canonical service APIs and product-local/legacy surfaces. The canonical OpenAPI
document is loaded from spec artifacts; Salvo support is kept on the Rust DTO
types themselves through `ToSchema` / `ToParameters` derives.

## Findings

### P0 - No Blocking Spec Gap Found In Operation Coverage

`contrix-api` currently exposes 79 endpoint contracts, matching the 79 active
operation IDs in `operation-registry.json`. Existing tests also enforce this
drift boundary. This is the right design: service surface truth is constrained
by spec artifacts rather than by an unbounded hand-written SDK list.

### P1 - Salvo OAPI Types Were Previously Incomplete

The codebase has many `#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]`
annotations and hand-written identifier schemas, so the concern that data
structures have no `ToSchema` support is not generally true. However, previous
Salvo support relied on manually maintained component-registration helpers and
synthetic endpoint schema names. C17 event surfaces now use typed endpoint role
structs instead.

This made the OpenAPI support partially scientific but not closed-loop: code
could compile while Salvo-native endpoint handlers had no real field-level DTO
types to attach.

Status: fixed in this review by adding explicit `<Operation>Params`,
`<Operation>Billet`, and `<Operation>Output` structs with Salvo OAPI derives.

### P1 - Synthetic Schemas Are Useful But Too Opaque

The old endpoint role schema names included synthetic placeholders for HTTP
path/query/header bundles and body/output wrappers. This has been replaced by
typed DTO structs so Salvo can describe the fields directly.

### P2 - Salvo-Native OpenAPI Belongs In Host Handlers

The standalone server OpenAPI artifact loader has been removed from the SDK.
Salvo-native schema derives remain framework integration support on DTO types,
not the protocol source of truth. Host services should build their OpenAPI
documents through their own Salvo route wiring.

### P2 - SDK Architecture Is Sensible, But Facade Boundaries Need Ongoing Tests

The architecture separates protocol wire models, local builders, client helper
state, and product-local APIs. That separation is reasonable and matches the
spec direction. Because there are many facade modules, continued conformance
tests are important: product-local features must not silently become required
protocol capabilities, and SDK-local drafts must not leak back into canonical
wire schema registries.

## Verification Performed

- `cargo check -p contrix-server --features salvo`
- `cargo test -p contrix-core --features salvo --no-default-features`
- `cargo test -p contrix-api`
- `cargo test -p contrix-server --features salvo`
- `cargo check -p contrix --features salvo --no-default-features`
