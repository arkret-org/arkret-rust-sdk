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

- [x] Replace generic `serde_json::Value` REST responses with stable request/response structs for every endpoint in the service HTTP binding.
- [x] Add server-side handler traits or adapter interfaces for every endpoint contract, while staying framework-independent.
- [x] Add OpenAPI generation or export support from the endpoint registry, including standard error envelope responses.
- [x] Add conformance tests that compare the SDK endpoint registry against the spec operation table.
- [x] Add typed binary/multipart blob upload and authenticated byte download helpers, including `Range`, `Content-Disposition`, `Digest`, cache and redirect header behavior.
- [x] Add streaming transport support for `GET /api/v1/sync/subscribe` instead of only JSON-shaped low-level access.
- [x] Add complete repo read models for describe, list commits, get commit, get operations and repo sync.
- [x] Add complete federation request/response models for transaction, push operations, pull operations, space members and verify actor.
- [x] Add complete directory discovery models for spaces, organizations, actors, users and handle resolution.
- [x] Add complete index models for entity, thread, notifications, inbox, search and space hierarchy responses.
- [x] Add complete push registration, unregister and notify wire models.
- [x] Add complete policy, moderation, applet and media ICE config wire models.

## Remaining Crypto and MLS Gaps

- [x] Replace the legacy key-backup helper in E2EE state with production-grade authenticated encryption.
- [x] Replace the legacy push payload helper with production-grade authenticated encryption.
- [x] Add a durable crypto store abstraction for MLS group state, key packages, welcomes, commits, epoch secrets and device verification state.
- [x] Wire MLS commit and welcome envelopes into repo/sync/device-message workflows end to end.
- [x] Add recovery flows for missing MLS epochs, lost local group state and late device joins.
- [x] Add cross-device verification flows beyond metadata state tracking.
- [x] Add key backup restore APIs that rehydrate usable local crypto state, not only raw serialized bytes.
- [x] Add encrypted timeline workflow tests that cover send, sync, decrypt, preserve-undecryptable payload and later decrypt after key arrival.

## Release Readiness Before Public Alpha

- [x] Document the release status as a 0.1.0 release candidate and explicitly state external security review / interoperability gates.
- [x] Add a release readiness checklist covering CI, docs, OpenAPI, conformance and security gates.
- [x] Add a feature matrix that explains `client`, `server`, `mls`, default and model-only builds.
- [x] Add CI workflow coverage for `fmt`, all feature combinations and all-feature tests on Rust 1.92.
- [x] Add an OpenAPI export example so the endpoint registry can produce a reviewable artifact.
- [x] Add a server handler mock conformance test that exercises the framework-independent adapter shape.
- [x] Remove existing compiler warnings from release-check builds.
- [x] Run final release-check commands and record them here: `cargo fmt --all -- --check`; `cargo check --no-default-features`; `cargo check --no-default-features --features client`; `cargo check --no-default-features --features server`; `cargo check --no-default-features --features mls`; `cargo check --all-features`; `cargo test --all-features`; `cargo run --example export_openapi --features server`.

## Production Crypto Release Hardening

- [x] Remove all legacy placeholder encryption helpers from SDK code paths.
- [x] Add a shared XChaCha20-Poly1305 AEAD helper with random nonces and AAD authentication.
- [x] Use authenticated encryption for E2EE key backup.
- [x] Use authenticated encryption for push payload encryption.
- [x] Use authenticated encryption for encrypted media attachments.
- [x] Use authenticated encryption for encrypted repo-store bytes.
- [x] Update release docs to 0.1.0 release-candidate language with external review gates.
- [x] Add clippy `-D warnings` to release/CI checks.

## Spec Compliance Gaps — Resolver Event Coverage

The resolver currently handles 23 of 44 registered event kinds. The following 21 core lifecycle events are missing:

- [ ] Add `cx.space.create` and `cx.space.update` event handling to the resolver.
- [ ] Add `cx.space.organization`, `cx.space.child`, `cx.space.parent` event handling.
- [ ] Add `cx.space.inheritance_policy`, `cx.space.join_rule`, `cx.space.history_visibility`, `cx.space.discovery` event handling.
- [ ] Add `cx.space.archive`, `cx.space.freeze`, `cx.space.destroy` event handling.
- [ ] Add `cx.entity.restore` event handling to the resolver.
- [ ] Add `cx.relation.move` event handling to the resolver.
- [ ] Add `cx.task.create`, `cx.task.update`, `cx.task.move` event handling.
- [ ] Add `cx.view.create`, `cx.view.update`, `cx.view.reconcile` event handling.
- [ ] Add `cx.redaction` generic redaction event handling.

## Spec Compliance Gaps — ViewKind Expansion

The spec defines 22 view kinds; the SDK has 12. Missing 10:

- [ ] Add `Matrix`, `Document`, `Dashboard` work-object view kinds to `ViewKind` enum.
- [ ] Add `Activity`, `Inbox`, `Notifications` conversation view kinds to `ViewKind` enum.
- [ ] Add `MemoryReview`, `AgentRuns`, `ContextTimeline` review/agent view kinds to `ViewKind` enum.

## Spec Compliance Gaps — ResourceSelector Expansion

The spec defines 15 resource selector kinds; the SDK has 5. Missing 10:

- [ ] Add `Board`, `Collection`, `Comment` resource selector kinds.
- [ ] Add `Channel`, `Topic`, `Message` resource selector kinds.
- [ ] Add `Run`, `Memory` resource selector kinds.
- [ ] Add `Schema`, `Policy`, `Invite`, `ReadMarker` resource selector kinds.

## Spec Compliance Gaps — Authz Constraint Evaluation

Five constraint types have TODO stubs that always return Allow:

- [ ] Implement `DelegationControl` constraint evaluation (depth tracking, scope narrowing).
- [ ] Implement `RateLimiting` constraint evaluation (operation counting, period windows).
- [ ] Implement `ClaimBased` constraint evaluation (claim type matching, issuer validation).
- [ ] Implement `Accountability` constraint evaluation (responsible actor check, logging).
- [ ] Fix `EncryptionRequirement` constraint evaluation (currently no-op, should verify encryption).
- [ ] Add missing constraint fields: `scope_limitation` type, `approval_mode`, `approval_relation`, `guardian_approval_required`, `controller_approval_required`, `claim_refresh_required`, `claim_max_age`, `memory_kind_allow/deny`.

## Spec Compliance Gaps — Server Endpoint Alignment

- [ ] Fix 7 operation_id mismatches between SDK server registry and spec.
- [ ] Add missing `cx.applet.third_party_users` endpoint.
- [ ] Add missing `cx.applet.third_party_locations` endpoint.

## Spec Compliance Gaps — Model Field Gaps

- [ ] Add `space_id`, `revoked_by`, `revoked_at`, `parent_grant_id`, `valid_from`, `valid_until` fields to `CapabilityGrant`.
- [ ] Add `scope` enum (space/channel/topic/thread/view/entity) to `ReadMarker` model.
- [ ] Add `space_version` field to `Space` model.
- [ ] Add `ChannelKind` enum (chat/announce/support/activity) to model.
- [ ] Add `InviteState` enum variants: `rejected`, `expired`.

## Spec Compliance Gaps — Account Lifecycle

- [ ] Add `AccountState` enum: `soft_logged_out`, `locked`, `suspended`, `deactivated`, `erased`.
- [ ] Add account recovery method types: DID proof, password reset, passkey/WebAuthn rebinding.
- [ ] Add session-to-DID-principal binding model.

## Spec Compliance Gaps — Social Graph

- [ ] Add `AudiencePolicy` struct with mode, interaction controls, indexing controls.
- [ ] Add `AudiencePolicyMode` enum: public/followers/contacts/circle/organization/space_members/direct/private.
- [ ] Add social graph relation kinds to resolver: `follows`, `contact`, `circle_member`, `blocks_social`, `reposts`, `quotes`, `likes`.

## Spec Compliance Gaps — Agent Memory Layers

- [ ] Add `MemoryLayer` enum: `working`, `episodic`, `semantic`, `task`.
- [ ] Expand `AgentMemory` with `memory_kind`, `subject_ref`, `source_refs`, `confidence`, `valid_from`, `valid_until`, `supersedes` fields.

## Spec Compliance Gaps — Cursor Encoding

- [ ] Add structured cursor encoding: JSON → canonical JSON → Base64URL.
- [ ] Add cursor fields: `v`, `t`, `s` (per-space positions), `d` (device positions), `x` (expiry).
- [ ] Add cursor TTL validation (recommended 7 days).
