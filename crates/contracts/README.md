# contrix-contracts

Contrix shared wire contracts.

This crate is a narrow contract boundary: it exposes shared request/response
DTOs, product-local API models, identity/federation/push helper contracts, and
optional schema derives without requiring a server runtime or Salvo adapter.

New DTOs belong here only when at least one of these is true:

- two or more repositories consume the same wire shape;
- `contrix-spec` defines it as a cross-service wire contract;
- a producer and consumer must share a product-local contract.

Otherwise keep the type in the owning service or SDK feature module.

Currently admitted shared surfaces:

- `push`: floria/chime/yougen push gateway bridge contracts.
- `integration`: common `/api/v1/integration/describe` manifest used by
  floria, soland, coauth, and consumers.
- `principal`: soland/yougen principal auth bridge describe contract.
- `identity`: shared DID document helper and identity wire helpers.
- `federation`: shared federation discovery/envelope/replay/helper contracts.

Currently deferred surfaces:

- coauth-specific auth/admin bridge DTOs stay with coauth/coauth-admin-types
  until they need to be consumed through the Contrix SDK boundary.
- SDK runtime state, store records, MLS/device/auth manager models, and
  generated protocol request/response bodies stay in their owning crates.

This crate deliberately does not own the canonical service route registry.
Canonical protocol truth remains in `contrix-spec`; SDK operation and service
route drift checks live in `contrix-core` and `contrix-server`.

The umbrella SDK re-exports this crate as `contrix::api` for compatibility,
with narrower facades such as `contrix::client_api`,
`contrix::identity_api`, `contrix::federation_api`,
`contrix::integration_api`, `contrix::principal_api`, and
`contrix::push_gateway_api`.
