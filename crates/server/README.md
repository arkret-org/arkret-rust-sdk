# Contrix Server

Protocol request/response enums and OpenAPI artifact loading for Contrix v1
services.

> **Not a reference implementation.** `contrix-server` ships protocol contract
> types. It does not provide a backing protocol service. A production
> deployment plugs in its own implementation (`soland` is the canonical one
> today).

## OpenAPI integration

The base build remains framework-independent and stays free of any HTTP runtime
dependency.

There is one full OpenAPI surface with protocol authority:

- `contrix_server::openapi_document()` loads the canonical Contrix service
  OpenAPI artifact from `contrix-spec` when that checkout is available. This is
  the normative protocol document for service conformance and client
  generation.

When the `salvo` feature is enabled, the DTO types in `contrix-core` and
`contrix-identifiers` carry feature-gated Salvo OAPI derives. Endpoint
path/query/header inputs are grouped as `<Operation>Params`, JSON request
bodies as `<Operation>Billet`, and successful outputs as `<Operation>Output`.
Host applications wire these types into their own framework handlers.
