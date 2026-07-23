# Arkret Server

Framework-independent server handler contracts for Arkret v1 services.

> **Not a reference implementation.** `arkret-server` ships protocol contract
> types. It does not provide a backing protocol service. A production
> deployment plugs in its own implementation (`soland` is the canonical one
> today). Shared DTOs used by both producers and consumers live in
> semantic model leaves and are re-exported here for server-side users.

## Salvo OAPI integration

The base build remains framework-independent and stays free of any HTTP runtime
dependency.

When the `salvo` feature is enabled, the DTO types in the `arkret` umbrella and
`arkret-identifiers` carry feature-gated Salvo OAPI derives. Endpoint
path/query/header inputs are grouped as `<Operation>Params`, JSON request
bodies as `<Operation>RequestBody`, and successful outputs as
`<Operation>Outcome`.
Host applications wire these types into their own framework handlers.
