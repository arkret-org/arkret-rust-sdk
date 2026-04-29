# Contrix Rust SDK Parallel Roadmap

Status: post-`0.1.0` release-candidate follow-up plan.

This file is organized by parallel workstream. Items in different workstreams
may be implemented concurrently when their write scopes do not overlap. Items
inside the same workstream usually share ownership boundaries and should be
sequenced by that workstream owner.

## Current Parallel Batch

These are the next SDK-owned items selected from the backlog because they are
small enough to complete independently in this repository without pretending to
finish external audits, real deployment interop, or full durable database work.

- [x] WS-C Auth: provider-backed authentication interfaces.
  - [x] Password hashing verifier using Argon2id or an app-supplied verifier.
  - [x] OIDC code/token verification contract with issuer metadata and JWKS hooks.
  - [x] WebAuthn/passkey ceremony verification contract.
  - [x] DID proof verification against DID documents and verification methods.
- [x] WS-L Identity: DID resolver and key-log foundations.
  - [x] Implement `did:uuid` bit layout validation.
  - [x] Structured `did:uuid` generation and validation.
  - [x] `did:web`, `did:key` and `did:keri` resolver adapter traits.
  - [x] DID key-log verification: inception, rotate, recover, deactivate.
  - [x] Key rotation that does not change the DID.
- [x] WS-F Sync/Snapshot: snapshot manifest and chunk verification.
  - [x] Reducer snapshot manifest fields and signature model.
  - [x] Snapshot chunk digest verification.
  - [x] State hash / Merkle root helpers.
  - [x] Client fallback-to-repo-replay behavior when snapshot verification fails.
- [x] WS-D Authz: reducer-backed authorization.
  - [x] Implement recurrence matching for temporal constraints.
  - [x] Calculate authz cache `valid_until` from temporal constraints.
  - [x] Add tests for recurrence, daylight-boundary and expiry edge cases.
  - [x] Evaluate active grants from `SpaceState` snapshots.
  - [x] Handle grant revoke / delegate races with deterministic ordering.
  - [x] Add negative conformance vectors for denied writes.

## WS-A Release Gates

Parallel-safe with code work except while producing final release evidence.

- [ ] Keep `0.1.x` marked as release-candidate until external security review and real server interoperability pass.
- [ ] Add a release evidence document for every public tag:
  - [ ] `cargo fmt --all -- --check`
  - [ ] `cargo check --no-default-features`
  - [ ] `cargo check --no-default-features --features client`
  - [ ] `cargo check --no-default-features --features server`
  - [ ] `cargo check --no-default-features --features mls`
  - [ ] `cargo check --all-features`
  - [ ] `cargo clippy --all-features --all-targets -- -D warnings`
  - [ ] `cargo test --all-features`
  - [ ] OpenAPI export reviewed against the Contrix spec.
- [ ] Define alpha / beta / stable exit criteria:
  - [ ] Alpha: typed API surface, durable native store, basic real-server sync.
  - [ ] Beta: multi-device crypto recovery, interop conformance, migration tests.
  - [ ] Stable: external audit, compatibility policy, semver API freeze.

## WS-B Storage And Persistence

Owned files: `store.rs`, future storage crates, storage docs and storage tests.

- [ ] Replace dependency-free store facades with real durable adapters.
  - [ ] Implement `SqliteRepoStore` on top of SQLite transactions.
  - [ ] Implement SQLite schema migrations with versioned migration files.
  - [ ] Add indexed lookups for operations, commits, cursors, spaces and events.
  - [ ] Add crash-recovery tests for partial commit / operation writes.
  - [ ] Add concurrent writer / reader tests and lock strategy documentation.
- [ ] Implement a real browser `IndexedDbRepoStore`.
  - [ ] Persist repo objects, sync cursors and space state snapshots.
  - [ ] Add quota handling that survives browser restarts.
  - [ ] Add WASM/browser integration tests.
- [ ] Add encrypted-at-rest storage paths.
  - [ ] Use platform key storage integration points instead of passphrase-only derivation for production callers.
  - [ ] Add key rotation and re-encryption workflows.
  - [ ] Add backup / restore roundtrips across versions.
- [x] Split storage traits by responsibility where needed.
  - [x] Repo object store.
  - [x] State snapshot store.
  - [x] Event cache store.
  - [x] Crypto store.
  - [x] Account/session store.
- [x] Define reusable persistence contracts and test suites.
  - [x] Define store traits for repo, state snapshots, event cache, crypto, account/session, blob metadata, audit and federation replay state.
  - [x] Define migration contracts and schema-version metadata.
  - [x] Add transactional write-path conformance tests.
  - [x] Add projection rebuild helpers from durable repo/events.
  - [x] Add crash recovery and idempotency conformance tests.

## WS-C Authentication And Identity

Owned files: `auth.rs`, `identity.rs`, `model.rs` DID helpers, auth docs and auth tests.

- [x] Replace local test verifiers with provider-backed interfaces.
  - [x] Password hashing verifier using Argon2id or an app-supplied verifier.
  - [x] OIDC code/token verification with issuer metadata and JWKS validation.
  - [x] WebAuthn/passkey challenge verification.
  - [x] DID proof verification against DID documents and verification methods.
- [ ] Persist auth state.
  - [ ] Durable sessions and refresh token metadata.
  - [ ] Session revocation list and device binding.
  - [ ] Soft logout / locked / suspended / deactivated account handling.
- [x] Harden auth APIs.
  - [x] Constant-time secret comparisons where applicable.
  - [x] Token redaction in `Debug` output and logs.
  - [x] Rate-limit hooks for login, MFA and recovery.
  - [x] Recovery flow completion APIs, not only request modeling.
- [ ] Production auth and identity foundations imported from `chask`.
  - [x] WebAuthn/passkey ceremony interfaces.
  - [x] OIDC callback and token verification helpers.
  - [ ] Refresh-token safe storage contract.
  - [x] Account recovery proof verification.
  - [x] DID control proof verifier.
- [ ] Claims, attestations and progressive disclosure.
  - [ ] Presentation request models.
  - [ ] Disclosure policy models.
  - [ ] Verified handle and email-domain claims.
  - [ ] Organization membership and role claims.
  - [ ] Device trust, MFA level and risk-level claims.
  - [ ] Claim revocation and fail-closed validation hooks.

## WS-D Authorization And Policy

Owned files: `authz.rs`, reducer/authz integration tests, policy models and policy docs.

- [x] Finish remaining constraint behavior.
  - [x] Implement recurrence matching for temporal constraints.
  - [x] Calculate authz cache `valid_until` from temporal constraints.
  - [x] Add tests for recurrence, daylight-boundary and expiry edge cases.
- [x] Connect authz decisions to real reducer state.
  - [x] Evaluate active grants from `SpaceState` snapshots.
  - [x] Handle grant revoke / delegate races with deterministic ordering.
  - [x] Add negative conformance vectors for denied writes.
- [ ] Add policy-server interoperability tests.
  - [ ] `cx.policy.check` happy path and denial path.
  - [ ] Quarantine / require-review flows.
  - [ ] Moderation report flow tied to policy outcome.
- [ ] Capability at causal frontier.
  - [x] Model grant/delegate/revoke as reducer input.
  - [x] Evaluate business operations against the effective grant at the causal frontier.
  - [ ] Fully implement resource selector grammar.
  - [ ] Fail closed for unknown critical constraints.
  - [ ] Validate delegation depth, scope narrowing and cycle detection.
  - [ ] Validate claims and attestations with issuer trust, subject, time and revocation.
  - [ ] Model approval/proposal flows.
  - [ ] Keep policy-server decisions limited to deny/quarantine/review unless a capability exists.

## WS-E Crypto And E2EE

Owned files: `crypto.rs`, `crypto_store.rs`, `e2ee.rs`, `mls.rs`, `devices.rs`, crypto docs and tests.

- [ ] Persist OpenMLS state through the `CryptoStore`.
  - [ ] Serialize and restore MLS group state across process restarts.
  - [ ] Store KeyPackages, Welcomes, Commits and epoch secrets durably.
  - [ ] Encrypt crypto-store records at rest.
- [ ] Complete multi-device MLS workflows.
  - [ ] Publish and revoke device KeyPackages.
  - [ ] Add late-device join and missing-Welcome recovery.
  - [ ] Apply missed MLS commits after offline periods.
  - [ ] Request and process epoch recovery when local state is behind.
- [ ] Add real device verification.
  - [ ] SAS-style challenge flow with canonical commitment checks.
  - [ ] QR verification payload format and scanner-facing API.
  - [ ] Cross-device trust propagation.
  - [ ] Verification cancellation / timeout / mismatch states.
- [ ] Add key backup and recovery beyond raw blob restore.
  - [ ] Restore usable local crypto state from backup.
  - [ ] Validate backup authenticity and sender identity.
  - [ ] Add backup version rotation and rollback tests.
- [ ] Expand crypto failure handling.
  - [ ] Preserve undecryptable timeline events with reason codes.
  - [ ] Retry decryption after key arrival.
  - [ ] Detect replay, wrong epoch, wrong sender and stale membership.
  - [ ] Add fuzz/property tests for envelope parsing and canonical digests.
- [ ] Encrypted envelope compliance.
  - [ ] AAD model covering `space_id`, event type, event ID and causal refs.
  - [ ] `payload_digest` and `aad_digest` verification.
  - [ ] MLS epoch mismatch recovery.
  - [ ] Device revocation causing future encrypted writes to fail closed.
- [ ] Prepare for external security review.
  - [ ] Threat model document.
  - [ ] Key lifecycle document.
  - [ ] MLS transcript and state persistence review notes.
  - [ ] Audit checklist mapped to source files and tests.

## WS-F Sync, Timeline And Runtime

Owned files: `sync.rs`, `sync_client.rs`, `timeline.rs`, `resolver.rs`, runtime docs and tests.

- [ ] Turn sync helpers into an async production runtime.
  - [ ] Async `SyncTransport` implementation for the HTTP `Client`.
  - [ ] Streaming support for `GET /api/v1/sync/subscribe`.
  - [ ] Cancellation, backpressure and retry policy.
  - [ ] Token persistence and reset-on-gap strategy.
- [ ] Build an event cache layer.
  - [ ] Deduplicate events by event ID and digest.
  - [ ] Store raw events and processed timeline items.
  - [ ] Reconcile limited timelines and backfilled chunks.
  - [ ] Persist gaps and paginate through them.
- [ ] Add send queue support.
  - [ ] Local echo for outbound messages.
  - [ ] Idempotent transaction IDs.
  - [ ] Offline queue persistence.
  - [ ] Retry, cancellation and dependent-event ordering.
  - [ ] Edit/redact/reaction queue semantics.
- [ ] Improve timeline APIs.
  - [ ] Stable timeline item model for UI consumers.
  - [ ] Message edit and redaction aggregation.
  - [ ] Reaction summary updates.
  - [ ] Read receipt and typing ephemeral updates.
  - [ ] Pinned/focused event loading.
- [ ] Build a room / space list service.
  - [ ] Sliding-window subscriptions backed by persisted list state.
  - [ ] Sorting by recency/name/unread/favorite.
  - [ ] Filtering by joined/invited/left/favorite/unread/category.
  - [ ] Incremental updates suitable for UI bindings.
- [ ] Snapshot and bootstrap contract.
  - [x] Reducer snapshot manifest fields and signature model.
  - [x] Snapshot chunk digest verification.
  - [x] State hash / Merkle root helpers.
  - [ ] Bootstrap sequence: resolve, discover services, fetch invite/grants, fetch snapshot, pull increments, run reducer, enter cursor subscription.
  - [x] Client fallback-to-repo-replay behavior when snapshot verification fails.
- [ ] Client sync correctness contract.
  - [ ] Bind sync tokens to principal, device, service, filter hash, stream positions and expiry.
  - [ ] Persist sync positions.
  - [ ] Specify initial and incremental sync semantics.
  - [ ] Model join, invite, knock and leave buckets.
  - [ ] Specify deterministic timeline order using causal depth, HLC, actor ID, actor sequence and event ID.
  - [ ] Model `timeline.limited`, backfill gaps and token expiry errors.
  - [ ] Specify `X-Contrix-Wait-For` frontier wait and timeout behavior.
  - [ ] Specify to-device delivery and acknowledgement semantics.

## WS-G HTTP, Federation And Interop

Owned files: `client.rs`, `server.rs`, `federation.rs`, `service.rs`, OpenAPI examples and interop tests.

- [x] Make OpenAPI output schema-complete.
  - [x] Generate typed request / response schemas for every endpoint.
  - [x] Include error envelope, auth schemes, headers and binary bodies.
  - [x] Add example payloads for key flows.
- [ ] Add framework adapters outside the core crate.
  - [ ] Axum adapter.
  - [ ] Salvo adapter.
  - [x] Tower/service abstraction if useful.
  - [x] Ensure adapters use the framework-independent endpoint registry.
- [ ] Build a protocol conformance suite.
  - [x] Golden vectors for identifiers, HLC, cursor, canonical JSON and digests.
  - [x] Wire-level request / response tests for every endpoint group.
  - [x] Negative tests for invalid IDs, bad auth, stale cursors and bad digests.
  - [ ] Server fixture that exercises repo, sync, blob, authz and federation flows.
- [ ] Run real server interoperability.
  - [ ] At least one Contrix server implementation.
  - [ ] End-to-end login, repo write, sync, media, push and encrypted message flow.
  - [ ] Federation push / pull smoke test across two services.
  - [ ] Record compatibility results in release evidence.
- [x] Federation and service identity primitives.
  - [x] Service DID allowlist model.
  - [x] HTTP Message Signature helpers.
  - [x] Federation transaction envelope models.
  - [x] Fork/quarantine models for duplicate commit or operation conflicts.
  - [x] Backfill authorization helpers.
  - [x] `.well-known/contrix/server` discovery models.
- [x] Federation security helpers.
  - [x] HTTP Message Signatures over method, target URI, authority, content digest, origin service DID, destination service DID and time bounds.
  - [x] Origin/destination DID Document service endpoint verification.
  - [x] Federation transaction idempotency and duplicate-conflict rules.
  - [x] Persistent replay protection contract.
  - [x] Commit/operation fork quarantine model.
  - [x] Pull authorization using history visibility, service delegation and plaintext-visible-service rules.
  - [x] `verify-actor` challenge signature model that avoids public DID oracle behavior.
- [x] API conventions, anti-abuse and observability metadata.
  - [x] Standard not-found privacy semantics for nonexistent vs invisible resources.
  - [x] Query-auth rejection helpers and tests.
  - [x] Error envelope schemas for 404, 405, 429 and 503.
  - [x] Per-actor and per-IP rate-limit metadata models.
  - [x] Quota models for blobs, account storage, operation windows and device/OTK counts.
  - [x] Structured tracing metadata: request, actor, device, space, operation and commit IDs.

## WS-H Bot, Appservice And Ergonomics

Owned files: `base.rs`, `space.rs`, `event_handler.rs`, `applet.rs`, `agent.rs`, bot examples and ergonomics docs.

- [x] Add high-level client convenience APIs.
  - [x] Login/session restore helpers around `Client` and `BaseClient`.
  - [x] `send_message`, `send_text`, `edit_message`, `redact_message`.
  - [x] `join_space`, `leave_space`, `invite`, `ban`, `unban`.
  - [x] `upload_media`, `download_media`, encrypted attachment helpers.
  - [x] `whoami`, profile, presence, account data and settings helpers.
- [x] Add bot runtime primitives.
  - [x] Event handler registration with typed event filters.
  - [x] Command parsing helper.
  - [x] Preprocessor/filter pipeline.
  - [x] Long-running sync loop with graceful shutdown.
  - [x] Bot example that handles commands and sends replies.
- [x] Add appservice / bridge primitives.
  - [x] Appservice registration model.
  - [x] Framework adapter routes for appservice transactions.
  - [x] Intent / virtual actor API.
  - [x] Idempotent transaction handling.
  - [x] Third-party user/location query hooks.
  - [x] Bridge mapping storage for remote users and rooms.
- [x] Applet, agent and sovereign deployment models.
  - [x] Signed applet registration and namespace declarations.
  - [x] Ghost actor and portal space mapping.
  - [x] Third-party user/location lookup contracts.
  - [x] Agent run lifecycle and memory lifecycle.
  - [x] A2A/ACP/MCP bridge metadata.
  - [x] Sovereign deployment policy primitives.
- [x] Extended profile primitives.
  - [x] Agent principal, delegated actor, run lifecycle, tool audit, memory lifecycle and kill-switch models.
  - [x] Applet registration, namespace conflict, transaction idempotency, ghost actor accountability and portal mapping models.
  - [x] Social graph feed, circle, follow/contact/block/repost/quote/like/reply and audience-policy models.
  - [x] Sovereign deployment allowlist, closed federation, resolver pinning, external device approval and data-classification models.
  - [x] Space export/import validation and service replacement contracts.
  - [x] Optional TSP trust binding and pairwise control-message hooks.

## WS-I Platform Bindings And Packaging

Owned files: Cargo feature configuration, WASM/FFI boundary modules and packaging docs.

- [ ] Decide supported embedding targets.
  - [ ] Native Rust only for `0.1.x`.
  - [ ] WASM/browser once IndexedDB storage is real.
  - [ ] Optional UniFFI Swift/Kotlin bindings after API stabilization.
- [ ] Prepare WASM support.
  - [ ] Feature-gate native-only dependencies.
  - [ ] Browser HTTP transport.
  - [ ] IndexedDB crypto and repo stores.
  - [ ] WASM tests for sync/state/cache logic.
- [ ] Prepare FFI boundary if needed.
  - [ ] Stable opaque handles for Client, SyncService, Timeline and Crypto.
  - [ ] Callback-safe event stream API.
  - [ ] Error mapping and cancellation handles.

## WS-J Observability, Performance And Reliability

Owned files: `performance.rs`, tracing/metrics integration points, benches and robustness tests.

- [ ] Add structured tracing.
  - [ ] Sync loop spans.
  - [ ] HTTP request IDs and retry spans.
  - [ ] Store transaction spans.
  - [ ] Crypto operation spans without leaking secrets.
- [ ] Add metrics hooks.
  - [ ] Sync latency and error counters.
  - [ ] Timeline/event-cache sizes.
  - [ ] Store read/write latency.
  - [ ] Crypto decrypt success/failure counts.
- [ ] Add benchmarks.
  - [ ] Canonical JSON hashing.
  - [ ] State reducer convergence.
  - [ ] Store insert/query.
  - [ ] Timeline pagination/backfill.
  - [ ] MLS encrypt/decrypt and commit application.
- [ ] Add robustness testing.
  - [ ] Property tests for reducer convergence.
  - [ ] Fuzz tests for cursor, event and encrypted payload decoding.
  - [ ] Load tests for large space lists and high event volume.
  - [ ] Fault-injection tests for network and store failures.

## WS-K Documentation And Developer Experience

Owned files: `docs/*`, examples, crate README and release docs.

- [ ] Update docs to distinguish current support levels.
  - [ ] Protocol model support.
  - [ ] Local helper support.
  - [ ] Production-ready support.
  - [ ] Experimental / facade support.
- [ ] Add task-oriented guides.
  - [ ] Build a simple client.
  - [ ] Build a bot.
  - [ ] Run sync with durable storage.
  - [ ] Send and receive encrypted messages.
  - [ ] Write a server adapter.
  - [ ] Migrate from Matrix concepts to Contrix concepts.
- [ ] Expand examples.
  - [ ] Basic authenticated client.
  - [ ] Durable sync client.
  - [ ] Encrypted messaging workflow.
  - [ ] Media upload/download.
  - [ ] Bot command example.
  - [ ] Server endpoint adapter example.
- [ ] Maintain public API quality.
  - [ ] Add rustdoc examples for main public types.
  - [ ] Add compile-fail examples for invalid usage where useful.
  - [ ] Run `cargo semver-checks` before non-patch releases.
  - [ ] Keep changelog entries tied to public API changes.

## WS-L Cross-Project Protocol Integration

Source files reviewed:

- `E:\Works\contrix-dev\chask\_todos.md`
- `E:\Works\contrix-dev\soland\_todos.md`

These items were imported because they are shared protocol/runtime foundations
that should live in the SDK instead of being independently reimplemented by the
client app or reference server. `chask` should validate UI and product flows;
`soland` should validate server persistence and interop. The SDK should provide
the common models, builders, validators, conformance vectors and reusable
client/server helper contracts.

- [ ] DID, handle and key-log foundations.
  - [x] Structured `did:uuid` generation and validation.
  - [x] `did:web`, `did:key` and `did:keri` resolver adapters or adapter traits.
  - [x] DID key-log verification: inception, rotate, recover, deactivate.
  - [x] Key rotation that does not change the DID.
  - [ ] Bidirectional handle verification through DID Document `also_known_as`.
  - [ ] Pairwise/private DID visibility controls.
- [ ] Signed fact and write-plane support.
  - [ ] Event detached signatures.
  - [ ] Canonical reducer input digests.
  - [ ] Operation and commit proof binding helpers.
  - [ ] Server-verified fact-chain echo models for clients.
- [ ] Object and operation-family completeness.
  - [ ] Invite object lifecycle and operation builders.
  - [ ] Channel and topic entity helpers.
  - [ ] Comment object helpers distinct from message helpers.
  - [ ] Structured mention references and mention relations.
  - [ ] Attachment add/remove operation helpers.
  - [ ] Run and memory operation helpers.
  - [ ] MLS proposal, commit and welcome operation helpers.
- [ ] Blob, media and WebRTC protocol foundations.
  - [ ] Content-addressed blob helpers.
  - [ ] Authenticated download grant models.
  - [ ] Encrypted attachment helpers and conformance vectors.
  - [ ] Thumbnail metadata and safe preview policy models.
  - [ ] Safe `Content-Type` and `Content-Disposition` helpers.
  - [ ] To-device WebRTC offer/answer/ICE signaling models.
- [ ] Canonical operation and event registry.
  - [ ] Standardize all built-in operation kinds as canonical `cx.*` names.
  - [ ] Provide legacy bare-name migration adapters behind an explicit profile.
  - [ ] Add complete operation envelope fields: actor, kind, target ref, causal deps, HLC, actor sequence, authz ref and proofs.
  - [ ] Drive operation semantic validation from a schema registry.
  - [ ] Publish conformance vectors for every built-in operation.
- [ ] Canonical JSON, digest and signature binding.
  - [ ] Define canonical UTF-8 JSON bytes with deterministic key order and no insignificant whitespace.
  - [ ] Reject invalid number and timestamp forms for signed payloads.
  - [ ] Digest operations from canonical operation bytes.
  - [ ] Digest commits from canonical commit-without-proofs bytes.
  - [ ] Bind proofs to actor DID, verification method, payload hash, audience/domain and creation time.
  - [ ] Provide production proof validators that reject `alg:none` and dev proof modes.
- [ ] DID identity, key log and service DID primitives.
  - [x] Implement `did:uuid` bit layout validation.
  - [x] Provide resolver adapter traits for `did:uuid`, limited `did:web` and temporary/test `did:key`.
  - [ ] Normalize DID Documents into current control keys, service bindings and method evidence.
  - [x] Verify append-only key logs and current key derivation from inception.
  - [ ] Verify registry receipt signatures.
  - [ ] Gate private/pairwise DID resolution behind proof checks.
  - [x] Validate service DID endpoints used by server description, identity, sync, directory, index, blob and snapshot metadata.
- [ ] Schema registry, OpenAPI and conformance generation.
  - [ ] JSON Schemas for cursor, event, operation, commit, grant, encrypted envelope and client sync response.
  - [x] OpenAPI 3.1 schema output with canonical operation IDs.
  - [ ] Profile-specific conformance suites for encoding, state resolution, redaction, capability, sync, snapshot, federation signatures and privacy.
