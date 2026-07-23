# Arkret Server

Framework-independent server handler contracts for Arkret v1 services.

> **Not a reference implementation.** `arkret-server` ships protocol contract
> types. It does not provide a backing protocol service. A production
> deployment plugs in its own implementation (`soland` is the canonical one
> today). Shared DTOs used by both producers and consumers live in
> semantic model leaves and are re-exported here for server-side users.

## Framework integration

The crate is framework-independent and stays free of HTTP runtime dependencies.
Host applications parse path/query/header inputs, JSON request bodies and
successful outputs with framework-local adapters.

The canonical OpenAPI document is owned by the Arkret Spec artifact. Host
applications may add a separately declared product appendix, but must not
derive a competing protocol schema from SDK DTO metadata.
