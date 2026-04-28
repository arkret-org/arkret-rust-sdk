# Contrix Rust SDK Completion TODOs

## Protocol Core

- [x] Make HLC validation match Contrix v1 fixed-width format everywhere.
- [x] Align client sync wire models with the spec: native `spaces`, optional Matrix bridge `rooms`.
- [x] Implement cursor validation against the v1 cursor schema, including event / operation / device-message IDs and hash checks.
- [x] Replace placeholder state-resolution logic with deterministic event ordering, processed-event tracking, frontier computation, redaction handling, tombstone state, and stable state hashes.
- [x] Add conformance-style tests for HLC, cursor, sync wire compatibility, and state reducer convergence.

## Business Logic Follow-Ups

- [x] Expand reducer coverage for membership, capability grant/revoke/delegate, invite/read marker, and policy state events.
- [x] Expand reducer coverage for message/reaction revision, redaction, and OR-Set semantics.
- [x] Connect authz decisions to reducer ordering so revokes and grants converge with business writes.
- [x] Add durable store adapters or explicit adapter traits for SQLite/IndexedDB instead of dependency-free facades.
- [x] Add repo commit chain verification: prev hash, author sequence monotonicity, operation digest presence, and signature hooks.
- [x] Add Matrix-migration parity checks against Ruma / matrix-rust-sdk areas: timeline, room/space list, encryption, device verification, account data, and event cache.
- [x] Add SDK repo-store list helpers needed by serverx repo read endpoints.
- [x] Re-run SDK tests after serverx/clientx integration changes.
