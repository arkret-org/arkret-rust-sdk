# Contrix Server

Protocol request/response enums for Contrix v1 services.

> **Not a reference implementation.** `contrix-server` ships protocol contract
> types. It does not provide a backing protocol service. A production
> deployment plugs in its own implementation (`soland` is the canonical one
> today).

## Salvo OAPI integration

The base build remains framework-independent and stays free of any HTTP runtime
dependency.

When the `salvo` feature is enabled, the DTO types in `contrix-core` and
`contrix-identifiers` carry feature-gated Salvo OAPI derives. Endpoint
path/query/header inputs are grouped as `<Operation>Params`, JSON request
bodies as `<Operation>ReqBody`, and successful outputs as `<Operation>Output`.
Host applications wire these types into their own framework handlers.
