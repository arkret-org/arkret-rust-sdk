# contrix-contracts

Contrix shared wire contracts.

This crate is a contract boundary: it exposes shared request/response DTOs,
product-local API models, identity/federation/push helper contracts, and
optional schema derives without requiring a server runtime or Salvo adapter.

This crate deliberately does not own the canonical service route registry.
Canonical protocol truth remains in `contrix-spec`; SDK operation and service
route drift checks live in `contrix-core` and `contrix-server`.

The umbrella SDK re-exports this crate as `contrix::api` for compatibility,
with narrower facades such as `contrix::client_api`,
`contrix::identity_api`, `contrix::federation_api` and
`contrix::push_gateway_api`.
