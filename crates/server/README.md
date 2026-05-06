# Contrix Server

Framework-independent endpoint contracts, routed request dispatch, server
middleware, request/response adapter types, OpenAPI helpers and optional Salvo
router generation for Contrix v1 services.

## Salvo OpenAPI integration

Enable the `salvo` feature to compile the Salvo adapter, `ContrixJson<T>`
response wrapper and Salvo OAPI component registration helpers. The base
build (no features) remains framework-independent and stays free of any
Salvo dependency.

The Salvo OAPI integration follows the palpo pattern: every `pub struct` and
`pub enum` in `contrix-core` and `contrix-identifiers` carries a feature-gated
`#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]` so the
generated component schemas describe real fields rather than opaque objects.
DIDs, typed IDs, hashes and HLCs use hand-written impls so they appear as
strings with the right regex pattern.

```rust
# #[cfg(feature = "salvo")]
# {
use contrix_server::salvo_adapter::{contrix_oapi_components, contrix_openapi, ContrixJson};

// Register every wire-relevant Contrix schema into a fresh `Components`.
let components = contrix_oapi_components();
assert!(components.schemas.contains_key("ServerDescription"));

// Or build a complete `OpenApi` with components seeded.
let openapi = contrix_openapi();

// `ContrixJson<T>` is a Salvo `Scribe` + `ToResponse` wrapper. Default 200,
// override with `.status(...)` and `.description(...)`.
fn handler() -> ContrixJson<contrix_core::ServerDescription> {
    ContrixJson::ok(server_description()).description("Server identity and capability advertisement")
}
# fn server_description() -> contrix_core::ServerDescription { unimplemented!() }
# }
```

`contrix_oapi_components()` invokes `install_contrix_oapi_namer()` once to
configure salvo-oapi's global namer to short mode (`ServerDescription` rather
than `contrix_core.model.ServerDescription`). Call the installer manually if
you build components piecemeal.
