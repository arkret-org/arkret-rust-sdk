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

## Feature Split and API Surface Gaps

- [x] Audit the SDK against `E:\Works\contrix-dev\contrix-spec` and `E:\Works\palpo-im\ruma` feature organization.
- [x] Add a dedicated `server` Cargo feature so server-side protocol helpers can be gated separately from the reqwest HTTP `client` feature.
- [x] Add a framework-free server endpoint registry with stable operation IDs, methods and paths for the protocol HTTP binding.
- [x] Expand the HTTP client with named entry points for the missing REST endpoint groups: identity, repo read/sync, sync describe/subscribe/backfill/snapshot-head, federation, index, directory, blob head/upload entry, push, authz effective grants/invites, policy, media ICE config, moderation and applet.
- [x] Verify `server` feature compilation with `cargo check --no-default-features --features server`.
- [x] Verify `client` feature compilation with `cargo check --no-default-features --features client`.
- [x] Verify combined feature compilation with `cargo check --all-features`.

## Remaining Protocol Completion Gaps

- [ ] Replace generic `serde_json::Value` REST responses with stable request/response structs for every endpoint in the service HTTP binding.
- [ ] Add server-side handler traits or adapter interfaces for every endpoint contract, while staying framework-independent.
- [ ] Add OpenAPI generation or export support from the endpoint registry, including standard error envelope responses.
- [ ] Add conformance tests that compare the SDK endpoint registry against the spec operation table.
- [ ] Add typed binary/multipart blob upload and authenticated byte download helpers, including `Range`, `Content-Disposition`, `Digest`, cache and redirect header behavior.
- [ ] Add streaming transport support for `GET /api/v1/sync/subscribe` instead of only JSON-shaped low-level access.
- [ ] Add complete repo read models for describe, list commits, get commit, get operations and repo sync.
- [ ] Add complete federation request/response models for transaction, push operations, pull operations, space members and verify actor.
- [ ] Add complete directory discovery models for spaces, organizations, actors, users and handle resolution.
- [ ] Add complete index models for entity, thread, notifications, inbox, search and space hierarchy responses.
- [ ] Add complete push registration, unregister and notify wire models.
- [ ] Add complete policy, moderation, applet and media ICE config wire models.

## Remaining Crypto and MLS Gaps

- [ ] Replace the `xor_sha256_stream` key-backup helper in E2EE state with production-grade authenticated encryption or mark it test-only.
- [ ] Replace the `xorsha256.v1` push payload helper with production-grade authenticated encryption or mark it test-only.
- [ ] Add a durable crypto store abstraction for MLS group state, key packages, welcomes, commits, epoch secrets and device verification state.
- [ ] Wire MLS commit and welcome envelopes into repo/sync/device-message workflows end to end.
- [ ] Add recovery flows for missing MLS epochs, lost local group state and late device joins.
- [ ] Add cross-device verification flows beyond metadata state tracking.
- [ ] Add key backup restore APIs that rehydrate usable local crypto state, not only raw serialized bytes.
- [ ] Add encrypted timeline workflow tests that cover send, sync, decrypt, preserve-undecryptable payload and later decrypt after key arrival.
