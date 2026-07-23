# arkret-models-integration

Arkret v1 push gateway, webhook, applet, and external integration exchange
models.

Owner of the edge interaction wire shapes consumed by push gateways (floria),
gateway clients (chime), applet services / bridges, and integration services.
Blind-payload sanitization and push-rule evaluation live in `arkret-policy`;
behavior that needs schema validation, state reduction, or signature
verification lives in the `arkret` umbrella. This crate holds data shapes and
type-local invariants only.
