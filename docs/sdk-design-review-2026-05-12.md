# SDK Design Review - 2026-05-12

> Historical record. Superseded on 2026-07-24: OpenAPI is now owned solely by
> the canonical Spec artifact, and all SDK Salvo/ToSchema features, derives and
> dependencies have been removed. The findings and commands below describe the
> repository state at the original review date.

Scope: `D:\Works\arkret\arkret-rust-sdk` checked against
`D:\Works\arkret\arkret-spec\spec\v1\zh` and
`D:\Works\arkret\arkret-spec\spec\v1\artifacts`.

## Summary

The current SDK design is broadly reasonable and mostly aligned with the v1
spec. The workspace split is healthy: identifiers validate wire IDs,
semantic model leaves own protocol data, `arkret-canonical` owns canonical
behavior, and `arkret-server` owns framework-neutral routing
plus Salvo integration, and the top-level SDK crate keeps high-level client
state and feature helpers out of the protocol core.

The strongest parts are the spec-drift checks, canonical JSON/digest handling,
typed identifier validation, service profile checks, and the separation between
canonical service APIs and product-local surfaces. The canonical OpenAPI
document is loaded from spec artifacts; Salvo support is kept on the Rust DTO
types themselves through `ToSchema` / `ToParameters` derives.

## Findings

### P0 - No Blocking Spec Gap Found In Operation Coverage

Historically the API-named contracts crate exposed endpoint contracts matching the active
operation IDs in `operation-registry.json`. The crate has since been renamed to
the semantic model leaves, and service route truth now lives with the server
registries while this crate carries shared DTO contracts.

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
`<Operation>ReqBody`, and `<Operation>Output` structs with Salvo OAPI derives.

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

- `cargo check -p arkret-server --features salvo`
- `cargo test -p arkret --features salvo --no-default-features`
- `cargo test -p arkret-models-collaboration`
- `cargo test -p arkret-server --features salvo`
- `cargo check -p arkret --features salvo --no-default-features`
