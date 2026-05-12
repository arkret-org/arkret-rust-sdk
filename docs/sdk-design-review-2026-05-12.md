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
canonical service APIs and product-local/legacy surfaces. The highest-risk
remaining area is OpenAPI/schema generation: the canonical OpenAPI document is
loaded from spec artifacts, but Salvo-native OpenAPI component registration was
not previously guaranteed to cover every schema name referenced by the endpoint
catalog.

## Findings

### P0 - No Blocking Spec Gap Found In Operation Coverage

`contrix-api` currently exposes 79 endpoint contracts, matching the 79 active
operation IDs in `operation-registry.json`. Existing tests also enforce this
drift boundary. This is the right design: service surface truth is constrained
by spec artifacts rather than by an unbounded hand-written SDK list.

### P1 - Salvo OAPI Component Coverage Was Incomplete

The codebase has many `#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]`
annotations and hand-written identifier schemas, so the concern that data
structures have no `ToSchema` support is not generally true. However, the
Salvo adapter used a manually maintained component-registration list. New C17
event endpoint schema names such as `EventsSubmitRequest`,
`EventsQueryResponse`, `EventsSubscribeFrame`, and `MimiRoomUpdateRequest`
were referenced by the endpoint catalog but not registered in
`contrix_oapi_components()`.

This makes the OpenAPI support partially scientific but not closed-loop: code
could compile while a Salvo-native document misses catalog-referenced
components.

Status: fixed in this review by deriving coverage from
`endpoint_schema_bindings()` and adding a regression test.

### P1 - Synthetic Schemas Are Useful But Too Opaque

Several endpoint schemas are currently synthetic placeholders because the SDK
does not yet have typed request/response structs for every HTTP path/query
bundle or extension surface. This is acceptable for framework routing, but it
is weaker for API consumers: generated clients will see generic objects instead
of precise field-level contracts.

The next improvement should prioritize typed DTOs for the canonical event
service schemas and key package flows before lower-priority Mimi/admin
extension surfaces.

### P2 - Spec Artifact OpenAPI And Salvo-Native OpenAPI Have Different Roles

`crates/server/src/openapi.rs` correctly treats
`contrix-service-api.openapi.yaml` from spec artifacts as canonical. The
Salvo-native `contrix_openapi()` is a framework integration helper, not the
protocol source of truth. This distinction should be made explicit in docs and
tests so SDK users do not assume Salvo-derived OpenAPI is the normative spec
document.

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

