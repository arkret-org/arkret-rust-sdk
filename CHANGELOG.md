# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the SDK is on the `0.1.x` line, breaking changes within a minor are
permitted; once `1.0` ships, breaking changes will require a major bump.

## [Unreleased]

### Tightened — Archive / tombstone / update source-state guards (2026-05-16)

Completes spec `common-fields.md §5.1` canonical state-transition table
across all three lifecycle families (Flow / Morph / Place). Round 8 added
`*.restore` source-state guard for Place; round 9 mirrored that for Flow
and Morph; this round (round 10) closes the remaining matrix: archive on
non-active source, tombstone on a terminal source, and the §5.1 final
paragraph rule that `*.update` MUST fail on a non-active object (otherwise
edits would silently revive an archived/tombstoned object, conflicting
with `*.restore` semantics).

- **`contrix` (sdk)** — all changes in `crates/sdk/src/resolver/state.rs`:
  - `archive_flow` previously delegated unconditionally to
    `set_flow_state(Archived)`. It now validates
    `state == Some(ObjectState::Active)` first; non-Active source MUST
    `failed_precondition` with `flow_not_active`. Unknown Flow is
    tolerated (causal / backfill) — same as the restore guards.
  - `archive_morph` (a new helper; previously the dispatcher inlined
    `set_morph_state(Archived)`) and `archive_place` (a new helper;
    previously inlined `set_place_state(Archived)`) follow the same
    contract: `morph_not_active` / `place_not_active` on non-Active
    source; unknown object tolerated. The dispatcher
    (`process_event_content`) now routes through the named helpers.
  - `tombstone_place` is a new helper (previously inlined
    `set_place_state(Tombstoned)`). Per §5.1, `cx.<kind>.tombstone` is
    legal from `active` OR `archived`; reject `tombstoned` (terminal
    self-transition) with `place_already_terminal`. Note that `*.tombstone`
    events exist for Place only in the spec registry; Flow / Morph
    don't have dedicated tombstone events.
  - `update_flow`, `update_morph`, and `update_place` now reject when the
    target's current state is non-Active (per `common-fields.md §5.1`
    final paragraph). Reasons mirror archive: `flow_not_active`,
    `morph_not_active`, `place_not_active`. This is a behavioural
    tightening — prior code allowed updating archived objects, silently
    bypassing the canonical `*.restore` re-entry path.
  - Eight new resolver tests in `crates/sdk/src/resolver/tests.rs`:
    `place_archive_rejected_when_already_archived`,
    `place_archive_rejected_when_tombstoned`,
    `place_tombstone_rejected_when_already_terminal`,
    `flow_archive_rejected_when_already_archived`,
    `morph_archive_rejected_when_already_archived`,
    `place_update_rejected_when_archived`,
    `flow_update_rejected_when_archived`,
    `morph_update_rejected_when_archived`. Each asserts the canonical
    reason_code is present in the error AND that the failed reducer
    write left no side effects.

- **Spec references**:
  - `common-fields.md §5.1` — canonical state-transition table introducing
    the symmetric reason_code family: `<kind>_not_active` /
    `<kind>_not_archived` / `<kind>_already_terminal`.
  - `common-fields.md §5.1` final paragraph — `*.update` MUST fail on
    non-active object as an invariant.
  - `common-fields.md §5.1` "未知对象容忍" — unknown object is tolerated;
    only state checks on materialised objects run.

- **Out of scope (follow-up)**:
  - `cx.redaction` source-state guard for Flow / Morph / Message — spec
    §5.1 also covers `cx.<kind>.redact` / `cx.redaction` with the same
    `<kind>_already_terminal` semantics, but the redaction reducer path
    lives in a different code surface than the lifecycle dispatcher.

### Tightened — Flow / Morph restore state-machine guards (2026-05-15)

Completes the spec `common-fields.md §5` symmetry across all three lifecycle
families (Flow / Morph / Place). Prior to this round, only `cx.place.restore`
validated source state (added in the cx.place.restore round); `cx.flow.restore`
and `cx.morph.restore` unconditionally flipped state to Active regardless of
source. Spec is explicit: `*.restore` is the canonical `archived → active`
path, and `tombstoned` / `deleted` / `redacted` MUST NOT be restored. This
round pins that invariant in the reducer for Flow and Morph as well.

- **`contrix` (sdk)**:
  - `restore_flow` in `crates/sdk/src/resolver/state.rs` now validates
    `state == Some(ObjectState::Archived)` before delegating to
    `set_flow_state(Active)`. Source state Active / Deleted / Redacted /
    unset MUST `failed_precondition` with `flow_not_archived` and the
    reducer makes no mutations. Unknown Flow (causal / backfill not yet
    caught up) is tolerated — same policy as `restore_place`.
  - `OP_MORPH_RESTORE` dispatcher branch in the same file no longer
    routes directly to `set_morph_state(Active)`; it now calls a new
    `restore_morph` helper. Same contract as `restore_flow`: validate
    `state == Some(ObjectState::Archived)`, reject otherwise with
    `morph_not_archived`. Morph has no `state_changed_at` field so the
    success path is symmetric only on what Morph actually carries.
  - Four resolver tests added in `crates/sdk/src/resolver/tests.rs`:
    `flow_archive_then_restore_round_trip` (state transitions back to
    Active, `state_changed_at` matches the restore Event's `created_at`),
    `flow_restore_rejected_when_active` (verifies error contains
    `flow_not_archived` AND that the failed reducer write doesn't
    promote `state_changed_at`), `morph_archive_then_restore_round_trip`,
    and `morph_restore_rejected_when_active`. The "reject when
    tombstoned" path is logically equivalent to the "reject when active"
    path — both exercise the same `state != Some(Archived)` branch — so
    one rejection test per family covers the unit-level guard.

- **Spec references**:
  - `common-fields.md §5` — canonical state machine, `*.restore`
    semantics, `tombstoned / deleted / redacted MUST NOT 被 restore`.
  - `space-and-place.md §4.4` — the Place precedent this round mirrors.

- **Wire compat**: backward-compatible. New rejection paths only fire on
  inputs that were silently being miscategorized before (e.g. an
  attacker's attempt to restore a tombstoned Flow); well-behaved clients
  emit restore only after archive, which still works.

- **Out of scope (follow-up)**:
  - `cx.flow.archive` / `cx.morph.archive` / `cx.place.archive` /
    `cx.*.tombstone` themselves still don't validate source state. Spec
    doesn't have explicit MUST for those transitions — likely needs spec
    work first to nail down (e.g. is archive-of-tombstoned a
    `failed_precondition` or an idempotent no-op?). Separate PR.

### Added — `cx.place.restore` (2026-05-15)

Mirror the new `cx.place.restore` event kind landed in `../contrix-spec`
(Unreleased changelog entry "新增 `cx.place.restore` 修正 Place 生命周期对称性").
Previously the SDK had `cx.place.archive` / `cx.place.tombstone` but no way to
reverse archive — clients had no wire-legal path to unarchive a board / list,
and reducers had no spec-aligned state-machine entry. With this round the SDK
implements the canonical `archived -> active` transition end-to-end.

- **`contrix-core`**:
  - `events::PLACE_RESTORE` constant (`"cx.place.restore"`) added in
    `crates/core/src/events/kinds.rs`, inserted into the sorted
    `STANDARD_EVENT_KINDS` array (binary-searched by
    `is_standard_event_kind`) between `PLACE_PARENT` and `PLACE_TOMBSTONE`,
    and added to the `Place` arm of `classify_event_kind`.
  - `model::OP_PLACE_RESTORE` constant added in
    `crates/core/src/model/constants.rs` alongside `OP_PLACE_ARCHIVE` /
    `OP_PLACE_TOMBSTONE`; auto-re-exported via `pub use constants::*`.
  - `required_fields_for_operation_kind` (in `crates/core/src/model/registry.rs`)
    extends its existing `OP_PLACE_ARCHIVE | OP_PLACE_TOMBSTONE` arm to
    `OP_PLACE_ARCHIVE | OP_PLACE_RESTORE | OP_PLACE_TOMBSTONE` — restore
    requires the same single `place_id` field as archive.

- **`contrix` (sdk)**:
  - `Space::restore_place_operation(place_id)` constructs the spec-shaped
    `cx.place.restore` operation, mirroring `archive_place_operation`
    (same `OperationType::Update`, same `{ "place_id": ... }` payload).
  - Resolver `SpaceState::process_event_content` adds an `OP_PLACE_RESTORE`
    branch backed by a new `restore_place` reducer in
    `crates/sdk/src/resolver/state.rs`. The reducer validates current
    `state == Archived` per `contrix-spec` `space-and-place.md §4.4`; any
    other state (`Active`, `Tombstoned`, unset) MUST `failed_precondition`
    with `place_not_archived` and the reducer makes no mutations. Unknown
    Place (causal / backfill not yet caught up) is tolerated, matching the
    existing `set_place_state` policy.
  - Three resolver tests added in `crates/sdk/src/resolver/tests.rs`:
    `place_archive_then_restore_round_trip` (state transitions back to
    Active with correct `state_changed_at`),
    `place_restore_rejected_when_active`, and
    `place_restore_rejected_when_tombstoned`. Both rejection tests verify
    the error string contains `place_not_archived` and that the failing
    event does not mutate the Place state.

- **Spec references**:
  - `contrix-spec` event_kind_registry / capability_action_registry now
    list `cx.place.restore`.
  - `space-and-place.md §4.4` "Restore Place" subsection is the normative
    source for the reducer guard above.
  - `conformance-vectors.md §6.2-6.4` are the wire-level conformance
    vectors this SDK round satisfies.

- **Migration**: writers that previously had no wire path for unarchiving
  Places (or were emitting `cx.place.update` with a top-level `state`
  patch as a workaround) MUST switch to `cx.place.restore`. The reducer
  here enforces the new guard; downstream impls (soland, yougen) need to
  catch up separately — tracked in their own `_todos.md` files.

- **Out of scope (follow-up)**:
  - `cx.place.archive` / `cx.place.tombstone` themselves still don't
    validate the source state (a pre-existing gap not introduced here);
    same is true for `cx.flow.restore` / `cx.morph.restore`. Addressing
    that surface is a separate PR.

### Added — round 8 (2026-05-15): MAL-11 + snapshot v2 + per-admin signing

Three new SDK surfaces requested by the soland principal server.

- **MAL-11 anchor compaction primitives** in `contrix-core`:
  - New `AnchorKind` enum (`Normal` / `Compaction`) added to the
    `Anchor` struct as a `#[serde(default)]` field — `Normal` is
    omitted from the wire, so pre-MAL-11 envelopes deserialize as
    `Normal` and serialize byte-identically. `Compaction` participates
    in the canonical-bytes-for-id hash, so an attacker can't relabel a
    normal anchor as compaction without invalidating its id.
  - `Anchor::sign_single_kind` / `sign_threshold_kind` /
    `sign_multi_kind` companion methods accept an explicit
    `AnchorKind`. The non-`_kind` shortcuts default to `Normal` and
    remain source-compatible.
  - `AnchorStore::successors(space_id, anchor_id)` returns direct
    children — used by the compaction pipeline to find what to rewire
    when pruning.
  - `AnchorStore::prune_predecessor(space_id, anchor_id)` drops the
    named anchor and rewires its direct successors' `predecessor_refs`
    to bypass it (deduped against grandparents). Refuses to prune a
    leaf; refuses to prune if the anchor isn't in the store. Returns
    the list of rewired successor ids.
  - `MemoryAnchorStore` implements both new trait methods. Other
    backends inherit `Err(Backend("not implemented"))` defaults so
    they compile but fail-closed.
  - New `CompactionPolicy` + `PruneCandidate` + `PruneEligibility`
    types in `state::compaction`. Policy fields:
    `min_anchor_age_seconds` (default 7 days),
    `min_compaction_witnesses` (default 1), `preserve_genesis`
    (default true), `prune_only_singleton_successors` (default true).
- **Snapshot chunk v2 primitives** in `contrix-core::snapshot`:
  - `SnapshotChunker` — deterministic byte-range partitioning with
    configurable `target_chunk_bytes` (default 256 KiB).
  - `SnapshotChunk` — `{chunk_id, bytes, digest}` with base64-url
    wire encoding.
  - `SnapshotMerkleTree` — RFC 6962-style binary Merkle over chunk
    digests; `audit_path(leaf_index)` returns the sibling chain;
    stateless `SnapshotMerkleTree::verify` lets receivers verify a
    single chunk without rebuilding the tree.
  - `GeneratorProof` — generator's signed commitment to
    `(state_root, merkle_root, chunk_count, total_bytes, chunk_bytes)`.
    `body_digest` returns the canonical payload hash; receivers call
    `verify_payload_hash()` then run their own JWS verifier on
    `signature.jws`.
- **Per-admin signing key + session-grant introspection** in
  `contrix-core::admin_signer`:
  - `AdminKeyStore` wraps any `KeyStore` and addresses per-admin
    signing keys via canonical id
    `contrix:signer:admin:<application_id>:<did>`. `load_admin_key` /
    `store_admin_key` / `delete_admin_key` / `has_admin_key` /
    `list_admin_dids` all key off `Did`.
  - `SessionGrantIntrospection` is the typed view of an OAuth-style
    introspection response carrying `(principal_did, admin_scopes[],
    expires_at_unix, device_id, audit_context)`.
    `is_currently_active`, `has_admin_scope`, and `require_admin_scope`
    are convenience guards for handler code.
  - `admin_scopes` module exposes conventional scope strings
    (`ANCHORER_RECONFIGURE`, `ANCHOR_COMPACT`, `ANCHOR_PRUNE`,
    `BOTTOM_REPAIR`, `ADMIN_READ`, etc.).

### Test coverage

`contrix-core` lib tests: **298 → 342 passed** (rounds 6/7 baseline →
round 8, +44 new). Highlights:
- 6 new tests for `AnchorKind` (default, wire omission, canonical-id
  forgery defense, JSON round-trip, missing-field default).
- 4 new tests for `AnchorStore::successors` /
  `AnchorStore::prune_predecessor` (rewire, leaf rejection, dedup).
- 10 new tests for `CompactionPolicy` (per-flag rejection, eligibility
  composition, serde round-trip).
- 17 new tests for snapshot v2 (chunker determinism, Merkle round-trip
  at sizes 1/2/3/4/5/8/11, audit-path verify success + tamper
  rejection, GeneratorProof digest stability + serde round-trip).
- 13 new tests for `AdminKeyStore` + `SessionGrantIntrospection`
  (per-admin id format, isolation, list/sort, missing-key NotFound,
  introspection expiry + scope gating).

### Compat notes

- `Anchor` struct gained one required field (`kind: AnchorKind`).
  Source-compat: callers must initialize it (`AnchorKind::Normal`
  preserves prior behavior). Wire-compat: `Normal` round-trips
  byte-identically because of `skip_serializing_if`.
- All three new modules are additive; no other public API is changed.

## [0.7.0] – 2026-05-10 — wasm32 workspace closure + release hardening

This release closes the wasm32 build story for the entire workspace and is
the first release where `cargo build --target wasm32-unknown-unknown
--workspace --lib --locked` is fully green alongside the native
`774 / 0 / 0` lib test suite. No wire-level breaking changes vs `0.6.0`;
the bump is for the SDK API surface adjustments described below.

### Added

- **Per-target `openmls` feature gating** in `crates/sdk/Cargo.toml`. The
  workspace `openmls` dependency is now declared once for native (lean,
  no extra features) and once for `cfg(target_arch = "wasm32")` with the
  `js` feature enabled, which transitively activates
  `fluvio_wasm_timer` + `js-sys` so MLS group state machinery has a
  browser-compatible timer source.
- **`uuid` wasm32 randomness**: `crates/identifiers/Cargo.toml` declares
  a `cfg(target_arch = "wasm32")` block enabling `uuid`'s `js` feature
  plus `getrandom = { features = ["wasm_js"] }` and a renamed
  `getrandom_02 = { package = "getrandom", version = "0.2", features = ["js"] }`
  so both the v0.3 and v0.2 (transitive via `rand_core` from
  `ed25519-dalek`) lines wire to the wasm-bindgen RNG path. (C35.1)

### Changed

- **`contrix-client` `TransportConfig` is now per-target.** The native
  variant retains the full set of fields (`timeout`, `connect_timeout`,
  `pool_idle_timeout`, `pool_max_idle_per_host`, `tcp_nodelay`,
  `tcp_keepalive`, `http2_keep_alive_*`, `proxies`, `no_proxy`,
  `redirect`, `gzip`); on `cfg(target_arch = "wasm32")` it is a unit
  struct with no-op `is_default()` / `apply()` because the browser
  `fetch` transport governs those policies. The 13 corresponding
  builder methods (`timeout`, `connect_timeout`, `pool_*`, `tcp_*`,
  `http2_keep_alive_*`, `proxy`, `no_proxy`, `redirect`, `gzip`) are
  `#[cfg(not(target_arch = "wasm32"))]`. `RetryConfig` fields are
  annotated `cfg_attr(target_arch = "wasm32", allow(dead_code))`.
  (C36.0)
- **`Client::execute` is split per-target.** Native retains the retry
  loop driven by `tokio::time::sleep`; on wasm32 the body collapses to
  `validate_request_builder` + `builder.send().await` — embedders that
  want retry/backoff in the browser should layer it on top with
  `gloo-timers` since neither `tokio::time::sleep` nor
  `reqwest::Error::is_connect()` are available in that environment.
  (C36.0)
- **`crates/sdk/src/lib.rs::http_did_resolver` and the
  `AsyncSyncTransport` / `EventsSubscribeTransport` impls in
  `crates/sdk/src/sync_client.rs`** are `cfg`-gated to native targets.
  Their `Send`-bound `BoxSyncFuture` return types are incompatible with
  the wasm32 `reqwest::Response` (carries `JsValue` / `Closure` /
  `JsFuture`, all `!Send`); the underlying traits remain `pub` so
  downstream wasm crates can supply a `LocalBoxFuture`-style transport.
  (C36.0)
- **Crate version `0.6.0 → 0.7.0`** across the workspace (root
  `[workspace.dependencies]` plus the 23 member crates).

### Security / Maintenance

- **`rustls-webpki` bumped `0.103.3 → 0.103.13`** to clear
  `RUSTSEC-2026-0049`, `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, and
  `RUSTSEC-2026-0104` (CRL handling, name-constraint matching, and a
  reachable parser panic). Pulled in transitively via
  `reqwest -> hyper-rustls -> tokio-rustls -> rustls`.
- **`Cargo.lock` rolls** — futures family bumped to 0.3.32 to resolve a
  conflict between `multra`/`hyper`/`h2` and openmls's wasm `js`
  feature; new transitives `fluvio-wasm-timer 0.2.5`, `bitflags 1.3.2`,
  `instant 0.1.13`, `parking_lot 0.11`, `redox_syscall 0.2.16`,
  `winapi 0.3.9` appear on the wasm32 side only.
- **`.deny.toml`** advisory ignore list pruned: removed two stale
  entries (`RUSTSEC-2024-0436` paste, `RUSTSEC-2024-0388` derivative)
  that no longer match anything in the lock; added
  `RUSTSEC-2024-0384` (unmaintained `instant`, transitive via
  `openmls 0.8.1` → `fluvio-wasm-timer` on the wasm path; no upgrade
  available pending an openmls upstream bump). `cargo deny check` is
  green: `advisories ok, bans ok, licenses ok, sources ok`.

## [0.6.0] – 2026-05-10 — Spec sync (`contrix-spec` `f724863..48898bf`)

Wire-breaking spec alignment pass. v1 is unreleased so this is a hard
break with no compat shims, no `#[deprecated]` adapters, and no
legacy-form fallback in `Deserialize`.

### Breaking

- **`Flow.tracks` is now an object/map**, not an array.
  - `Flow.tracks: Vec<FlowTrack>` → `Flow.tracks: BTreeMap<String,
    FlowTrackConfig>`. The track name is the map key and is no longer
    carried as a struct field.
  - Renamed `FlowTrack` → `FlowTrackConfig` and dropped the `name`
    field. Custom `Deserialize` impl (which accepted bare-string and
    full-object forms) is removed; the struct now derives
    `Deserialize` directly.
  - Helper constructors return a `FlowTrackConfig` to be inserted
    under the canonical map key (`FLOW_TRACK_NAME_SYNTHESIS` /
    `FLOW_TRACK_NAME_DISCUSSION`):
    `FlowTrackConfig::synthesis()`, `FlowTrackConfig::discussion()`,
    `FlowTrackConfig::discussion_primary()`, plus the chainable
    `with_profile(..)` / `primary()` builders.
  - `FlowTrack::validate_name` (instance method) is replaced by the
    free function `validate_flow_track_name(name: &str)` that validates
    a candidate map key against `^[a-z][a-z0-9_]{0,63}$`.
  - `resolve_primary_track` signature is now
    `fn(&BTreeMap<String, FlowTrackConfig>, Option<&str>) ->
     Result<Option<(&String, &FlowTrackConfig)>>`. Same fail-closed
    rule when more than one track sets `is_primary=true`; fallback
    rules (synthesis-by-default, single-track, profile_default) match
    against the map key.
  - `Flow::discussion(..)` constructs the chat-style room form by
    inserting `FlowTrackConfig::synthesis()` and
    `FlowTrackConfig::discussion_primary()` under the canonical names.
- **`/device_messages` is now `POST` + `Idempotency-Key` header**.
  - Endpoint registry: `cx.device_messages.put` is `POST
    /api/v1/device_messages` (was `PUT
    /api/v1/device_messages/{txn_id}`).
  - `Client::send_device_messages(idempotency_key, request)` switches
    to `POST` and propagates the key via the `Idempotency-Key`
    request header.
  - `ToDeviceMessage` (in both `contrix_core::model` and
    `contrix_core::sync`) drops its `Option<String> txn_id` field —
    the wire envelope no longer carries it.
  - `OP_DEVICE_MESSAGES_PUT` required-fields list drops `txn_id`.
  - `DeviceMessageEnvelope` (`crates/sdk/src/devices.rs`) drops its
    `txn_id` field to match
    `device-message.schema.json`.
- **`/applet/transactions` is now `POST` + `Idempotency-Key` header**.
  - Endpoint registry: `cx.applet.transaction` is `POST
    /api/v1/applet/transactions` (was `PUT
    /api/v1/applet/transactions/{txn_id}`).
  - `Client::applet_transaction(idempotency_key, request)` switches to
    `POST` + `Idempotency-Key` header.
  - Server route table, OpenAPI document, conformance vectors, and
    Salvo router debug strings updated to the new shape.
- API endpoint headers list: both `cx.device_messages.put` and
  `cx.applet.transaction` declare a required `Idempotency-Key` header.

### Changed

- Crate version `0.5.2 → 0.6.0` across the workspace.

## [0.5.1] – 2026-05-09 — Platform `KeyStore` native backends

Round 23 of the SDK: turns the Round-22 `KeyStore` platform stubs into
real implementations behind per-target feature flags. `v1` wire is
unchanged; this is an additive SDK API release.

### Added

- **`MacOsKeychainKeyStore` (macOS Keychain Services)** behind the new
  `keystore-macos` feature, wired to the `security-framework` crate's
  generic-password APIs (`set_generic_password` / `get_generic_password`
  / `delete_generic_password` plus `ItemSearchOptions` for `list()`).
  Items live under service name `"contrix.<application_id>"`. 5 unit
  tests gated on `cfg(target_os = "macos")`.
- **`LinuxSecretServiceKeyStore` (D-Bus Secret Service)** behind the new
  `keystore-linux` feature, wired to the `secret-service` crate's
  blocking client. Items are tagged with `service` + `account`
  attributes for namespaced enumeration. 5 unit tests gated on
  `cfg(target_os = "linux")` plus `CONTRIX_TEST_LINUX_KEYSTORE=1` env
  guard for runtime D-Bus access.
- **`WindowsCredentialKeyStore` (Windows Credential Manager)** behind
  the new `keystore-windows` feature, wired to the `windows` crate's
  `Cred*W` family (`CredReadW` / `CredWriteW` / `CredDeleteW` /
  `CredEnumerateW`). Target name pattern
  `"contrix.<application_id>:<key_id>"`. 5 unit tests; on Windows CI
  these run live against the user's Credential Manager.
- **`KeyStoreError`** strongly-typed error enum (`Unsupported` /
  `NotFound` / `InvalidId` / `Backend`) convertible to
  `Error::Protocol`. Off-target / feature-disabled builds keep all
  three platform types visible (so downstream FFI / docs continue to
  compile cross-target) but their constructors return
  `KeyStoreError::Unsupported { reason }`.
- **`platform_default_keystore(application_id)`** helper that picks the
  matching native backend for the active target/feature combo and
  falls back to `InMemoryKeyStore` when none is available. Lets
  downstream apps do `let ks = platform_default_keystore("yougen");`
  without per-platform `cfg` blocks at the call site.
- Workspace `Cargo.toml` gains pinned versions for
  `security-framework = 3.5`, `secret-service = 5.0`, and
  `windows = 0.62`. Each is brought in only by its `target_os` via
  `[target.cfg(target_os = "...")]` blocks in `crates/core/Cargo.toml`,
  so cross-target builds don't pull unrelated platform crates.

### Changed

- Crate version `0.5.0 → 0.5.1` across the workspace; `v1` wire format
  unchanged. Public re-export at `contrix_core::{KeyStoreError,
  platform_default_keystore}`.

## [0.5.0] – 2026-05-09 — Move/Anchor signer surface + EventsQuery typed wrappers

This release completes round 21 of the SDK: the public Move/Anchor signer
trait, an Ed25519 backend for production signing, the `EventsQueryRequest`
/ `EventsQueryResponse` typed wrappers downstream agents (coauth / soland /
yougen) need for `cx.events.query`, and the workspace bump to 0.5.0
(folds C19.B follow-ups + completes signer surface). v1 wire is unchanged
from 0.4.0; this is an additive SDK API release.

### Added

- **`contrix-core::MoveSigner` trait + `UnsignedMove` builder** — public
  signer abstraction for Move/Anchor signing. `Move::sign(&unsigned, &signer)`
  produces a fully-signed Move whose `id` matches canonical bytes hash
  and `sig.payload_hash` matches the same canonical bytes. 8 unit tests.
- **`Anchor::sign_single` / `Anchor::sign_threshold` / `Anchor::sign_multi`**
  constructors that take a [`MoveSigner`] (or threshold proof bytes) +
  predecessor refs + frontier and produce a fully-signed [`Anchor`]
  with `id` derived from canonical bytes.
- **`contrix-signatures::Ed25519MoveSigner`** behind the new `signer`
  feature: wraps `ed25519_dalek::SigningKey`, exposes
  `new(signing_key, did, kid)` + `from_did_key_seed(seed)`, produces
  detached EdDSA JWS strings. Includes
  `verify_ed25519_move_signature` helper for round-trip vectors. 5
  unit tests.
- Re-exported at the top-level `contrix` crate root behind the
  `contrix/signer = ["contrix-signatures/signer"]` feature flag.
- **`contrix::EventsQueryRequest` / `EventsQueryResponse`** typed
  wrappers in `sync_client.rs` for `cx.events.query`. Multi-selector
  (`spaces[] ∪ actors[]`), `from` / `until` HLC bounds, `direction`
  (forward/backward), `limit`. `EventsQueryResponse` carries `events`,
  `next_cursor`, `prev_cursor`, `limited`. From/Into impls bridge with
  the existing `SyncBackfillResponse` wire shape soland accepts. 4 new
  unit tests.
- **`EventsSubscribeFrame::Frontier { cursor }` round-trip test** —
  rounds out the existing 9-variant frame deserializer (already had
  Event / CatchupComplete / Heartbeat / Dropped / EpochRotation /
  ResyncRequired / Unauthorized / Unknown coverage).

### Changed

- `EventsQueryDirection` now derives `Default` (= `Forward`) so
  `EventsQueryRequest` defaults match spec convention.
- All 23 workspace crates bumped 0.4.0 → 0.5.0; workspace dep table
  updated in lockstep.
- Pre-existing clippy `derivable_impls` warnings on
  `ReadReceiptDisclosure` / `ReadReceiptVisibility` cleaned up using
  `#[derive(Default)]` + `#[default]` markers.

### Test baseline

- `cargo build --workspace --all-features` clean.
- `cargo clippy --workspace --all-features --tests -- -D warnings` clean.
- `cargo test --workspace --lib --all-features` **728 passed / 0 failed
  / 0 ignored** (was 704 in 0.4.0; +24 new tests covering signer trait,
  Ed25519 backend, EventsQuery typed wrappers, and Frontier frame).

## [0.2.0] – 2026-05-08 — Move / Anchor / Lattice rebase ⚠ wire-breaking

This release rebases the SDK onto the Move/Anchor/Lattice three-primitive
state-convergence model introduced by `contrix-spec` 2026-05-08. The
v1 wire surface is **incompatible** with 0.1.0: `cx.consent.*` events,
the legacy `StateReducer` API, and the host-endorsement / writer-model
typed model are all gone. v1 was unreleased; no compat shim is provided.

### Added

- **`contrix-lattice` crate** — new independent crate providing the
  closed `Lattice` trait and six normative implementations
  (`or-set` / `mv-register` / `cas-register` / `fsm` / `counter` /
  `ordered-log`) plus `AnchoredOp` / `CellState` types. 55 unit tests.
- **`contrix-core::Move`** typed model with canonical-bytes id derivation
  (spec §3); 13 unit tests covering id round-trip / signature payload
  hash / SemanticRef default-skip / snake-case op enums.
- **`contrix-core::Anchor`** typed model with three signature shapes
  (`Single` / `Multi` / `Threshold`); 13 unit tests covering id
  round-trip + threshold below-quorum reject + wire `kind`
  discriminator.
- **`contrix-core::Bottom`** structured diagnostic typed model with six
  `BottomKind` variants matching `bottom.schema.json`.
- **`contrix-core::AnchorerValue`** four-variant typed enum
  (`SingleDid` / `Threshold` / `OpenSet` / `Mixed`); validates the
  anchorer cell's cas-register value shape per spec §4.4.
- **`contrix-core::CellId`** parser + `composite_subject` (base64url +
  sha256 hash form per encoding.md §9.5) + `composite_subject_pipe`
  diagnostic form.
- New typed identifiers: `MoveId` (`cx:move:sha256:<hex>`), `AnchorId`
  (`cx:anchor:sha256:<hex>`), `CellRef` (`cx:cell:<component>:<subject>`)
  with OpenAPI schemas.
- **`contrix-state-res` rewrite** — `MoveStore` / `AnchorStore` /
  `CellStore` / `CellRegistry` trait contracts + Memory backends +
  `verify_move` five-step pipeline + `apply_anchor` eight-step
  algorithm + `effective_anchor_view` pure function +
  `compute_state_root` (RFC 6962 Merkle, empty-list root locked to
  spec §4.2). 32 unit tests.
- **`contrix::consent`** rewritten as or-set Move builder per spec
  consent-model §3:
  `grant_effect` / `revoke_effect_with_precondition` /
  `evaluate_consent` / `require_consent_precondition`. Cell family
  `cx.component.consent.grant.v1`. Tag form
  `grant:<consent_id>:<peer>:<scope>` for deterministic dedupe.
- **`contrix::mls_move`** new module — MLS commit Move helpers per
  spec §10: `mls_commit_preconditions` / `mls_commit_effects` /
  `e2ee_message_precondition` / `covered_frontier_contains` plus
  cell families `cx.component.mls_epoch.v1` (cas-register, reject) /
  `cx.component.key_schedule.v1` (cas-register, reject) /
  `cx.component.covered_frontier.v1` (or-set, **expose**).
- `docs/move-anchor-runtime.md` — SDK-internal runtime architecture
  design (≈540 lines): module split, store trait contracts, verifier
  pipeline, `apply_anchor` walk-through, caching strategy (L0/L1/L2),
  user-facing projection vs cell effective state separation,
  CellRegistry loading, migration roadmap.

### Removed (wire-breaking)

- **Old `contrix-state-res` API**: `StateReducer`, `state_hash`,
  `is_state_event`, `subject_for_event`, `candidate_wins`,
  `ResolvedStateEvent`, `ConflictRecord`, `StateResolutionSnapshot`,
  `StateAuthority`, `evaluate_state_auth`, `BoardReducer` —
  ≈30 unit tests removed; replaced by 32 new tests on the new
  primitives.
- **Old `Proof` extensions**: `Proof::host_did`, `Proof::endorsed_at`,
  `proof_kind::HOST_ENDORSEMENT`. Move signatures use detached JWS
  exclusively now (signatures are anchorer-side concerns for
  multi/threshold flows, not Move-issuer concerns).
- **`SpaceWriterModel`** enum + `Space.space_writer_model` /
  `Space.space_host` fields + `derived_writer_model()` /
  `validate_writer_model()` helpers. Anchor authority is determined
  by the anchorer cell value, not a per-Space typed enum.
- **`crates/sdk/src/space_host.rs`** module deleted in entirety
  (`SpaceHostPayload` / `SpaceHostTransferPayload`).
- **Old `consent::ConsentState`** enum (`Granted` / `Revoked` /
  `Absent`) and the typed `ConsentGrantPayload` /
  `ConsentRevokePayload` envelopes. Effective consent is now derived
  from the consent cell's or-set join via `evaluate_consent`.
- All legacy `state_key` fields, `LegacyStateKey` errors, and
  `assert_no_legacy_state_key` helpers across the workspace.

### Changed

- `contrix-state-res` Cargo.toml gains `contrix-lattice`, `sha2`,
  `thiserror` deps to support the new runtime.
- `contrix-testing::state_resolution_vectors` rewritten to drive
  `apply_anchor` end-to-end. `StateResolutionVector` struct fields
  changed from `{name, winner_event_id, conflict_count}` to
  `{name, anchor, accepted_count, rejected_count, post_state_root}`
  to reflect the new "no per-cell winner" semantics.
- `MemoryCellRegistry` ships built-in bindings for nine cell
  families: `member.state` (FSM with membership transitions),
  `capability.grant` / `consent.grant` (or-set), `anchorer` /
  `space.policy` / `mls_epoch` / `key_schedule` (cas-register),
  `space.title` (mv-register, expose), `metric.counter` (counter),
  `audit.log` (ordered-log), `covered_frontier` (or-set, expose).
- 23-crate workspace bumped from `0.1.0` to `0.2.0`.

### Test baseline

- `cargo test --workspace --all-features`: **614 passed, 1
  pre-existing failure** (schema artifact-load test that requires
  spec workspace at a specific path; unrelated to this rebase).
- Net test delta vs 0.1.0: −≈35 (old state-res / consent /
  space-host tests removed) + 99 new (Move 13, Cell 10, Bottom 6,
  Anchor 13, AnchorerValue 10, Lattice 55, state-res 32, consent
  16, mls_move 11) = **+64 unit tests**.
- `cargo clippy --workspace --all-features --tests -- -D warnings`:
  clean.

### Migration

Downstream consumers MUST:

1. Replace `StateReducer::new(...).apply_events(events)` with
   `apply_anchor(anchor, &move_store, &anchor_store, &cell_store,
   &registry, verify_jws_closure)`.
2. Stop emitting `cx.consent.grant` / `cx.consent.revoke` event
   envelopes; build Moves whose effects come from
   `consent::grant_effect` / `consent::revoke_effect_with_precondition`
   instead.
3. Remove all references to `SpaceWriterModel` / `Space.space_host`.
   Anchor authority lookup goes through the anchorer cell.
4. For E2EE Spaces, attach `mls_move::e2ee_message_precondition` to
   message Moves; build MLS commit Moves with
   `mls_move::MlsCommitMoveSpec::build`.

See `docs/move-anchor-runtime.md` for the full architecture.

## [0.1.0-prep] (rolling work toward 0.2.0)

### Added

- `ClientBuilder` transport configuration: `connect_timeout`,
  `pool_idle_timeout`, `pool_max_idle_per_host`, `tcp_nodelay`,
  `tcp_keepalive`, `http2_keep_alive_interval`, `http2_keep_alive_timeout`,
  `http2_keep_alive_while_idle`, `proxy`, `no_proxy`, `redirect`, and
  `gzip`. See `crates/http-client/src/lib.rs`.
- `RedirectPolicy` enum (`None` / `Limited(usize)`) used by
  `ClientBuilder::redirect`.
- `SECURITY.md` describing supported versions, the responsible disclosure
  process and the project's response timeline.
- CI hardening: `cargo audit`, `cargo deny check`, `cargo doc --all-features`
  with `-D rustdoc::broken_intra_doc_links`, and a separate MSRV job.
- `RELEASING.md` enumerates the full 22-crate publish set in topological
  order and is now in lockstep with `.github/workflows/release-crates.yml`.

### Changed

- `ClientBuilder::build` now rejects calls that combine a pre-built
  `http_client(...)` with any transport-shaping option, instead of silently
  ignoring the option.
- `.github/workflows/release-crates.yml` publishes every workspace crate in
  dependency order, not just the umbrella `contrix` crate.
- `.github/workflows/ci.yml` corrects the publish dry-run package spec from
  `-p contrix-sdk` (which never matched any crate) to `-p contrix`.

## [0.1.0] – TBD

Initial release candidate for Contrix v1 SDK.

### Added

- Workspace of 22 focused crates plus an umbrella `contrix` crate
  re-exporting the public SDK surface (high-level state managers, sync
  client, MLS encryption, identity, federation, push, presence, …).
- Wire models for Space / Flow / Message / Morph / Relation / Event / View
  matching the Contrix v1 `data-structures.md` shape, including `FlowBranch`
  end-to-end migration and `Morph` as a canonical object.
- Canonical JSON encoder + SHA-256 digest helpers; signed payloads use this
  module so different clients compute identical hashes.
- HLC parsing and deterministic ordering, RFC 9421 / RFC 9530 transcript
  helpers, and replay/CommitFork detection.
- HTTP `contrix-client` with HTTPS-by-default, retry/backoff, idempotency,
  read-your-writes wait header support, and query-string-auth rejection.
- Framework-independent server endpoint registry plus optional Salvo
  adapter and OpenAPI integration. Every public model carries
  `salvo::oapi::ToSchema` under the `salvo` feature.
- MLS RFC 9420 group encryption based on OpenMLS, including `KeyPackage`,
  `Commit`, `Welcome` envelopes and `cx_app_state_ref` GroupContext
  extension.
- 42 canonical error code constants plus an `is_known_error_code` helper
  mirroring the spec's `error-code-registry.json`.
- Conformance vector library covering canonical-JSON, redaction, capability
  evaluation and sync-cursor binding (`crates/testing`).
- Authorization engine covering the 8 v1 constraint families
  (`temporal`, `field_access`, `type_restriction`, `scope_limitation`,
  `delegation_control`, `quota`, `claim_based`, `confidentiality`) with
  optional `subtype` discriminators, `ApprovalMode` quorum semantics +
  `ApprovalWorkflowMode` workflow stages, evaluation order
  (`deny → quarantine → require_review → allow`), and a `partial_auth_state`
  read-only marker.
- Push privacy validator that rejects raw-DID payloads outside an explicit
  `plaintext_visible_services` allowlist; TURN credential validator that
  rejects DID-bearing usernames/credentials.
- `MerkleProofStep` + `verify_snapshot_inclusion` for snapshot manifest
  inclusion proofs.
- Round-1 through Round-8 spec-alignment work (see commit history for
  the per-round task lists; the closed punch list is preserved in git).

### Security

- The `0.1.x` line targets functional parity for an external security
  review. See `SECURITY.md` for the disclosure process and
  `docs/security-audit.md` for current evidence.

[Unreleased]: https://github.com/contrix/contrix-rust-sdk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/contrix/contrix-rust-sdk/releases/tag/v0.1.0
