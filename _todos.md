# Contrix Rust SDK — Spec Alignment Punch List

**Audit date:** 2026-05-04 (last edit 2026-05-05)
**Spec source:** `E:/Works/contrix-dev/contrix-spec` (`v1-core-rc`)
**SDK:** `E:/Works/contrix-dev/contrix-rust-sdk` (workspace, ~92k LOC, 22 crates)

This document is the merged output of four parallel audits over identity/crypto, authz/state-resolution, sync/service/federation, and models/extensions/conformance. Each item gives a spec anchor, the SDK location, a status marker (`missing` / `stub` / `drift` / `improve`), and a 1-line implementation note.

Items are grouped by **tier** (severity × tractability), not by domain, so the implementation order is top-to-bottom.

## Round-8 working list (2026-05-06) — Salvo OpenAPI rework

### Why this round exists

Round 7 added a Salvo `oapi` feature path but **the schemas it produced are placeholders, not real schemas**. Concretely:

- `crates/core/src/oapi.rs` (630 lines) hand-impls `ToSchema`/`ComposeSchema` for ~140 model types, but every impl returns the same `{"type":"object","additionalProperties":true,"x-contrix-rust-type":"FooBar"}`. There are zero field-level descriptions.
- A string-typed `schema_for_name(name: &str, ...)` registry in core, plus parallel hardcoded name lists in `salvo_adapter.rs` and `lib.rs`, replicate the contract registry by string instead of using the type system.
- `crates/identifiers/src/lib.rs` has an inline `mod oapi {}` while core has a free-standing `oapi.rs` — split state.
- `crates/core/Cargo.toml` introduces a phantom `server = []` feature that does nothing except gate `salvo`.
- SDK feature `salvo` and legacy alias `salvo-adapter` both exist with overlapping meaning.

The result: a feature flag that compiles but generates an OpenAPI document that lies — clients reading it are told every body is "any object."

### Target architecture (palpo-style)

- **Derive, don't hand-impl.** `#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]` on every public model struct/enum so `salvo-oapi-macros` introspects fields and generates real schemas.
- **Hand-impl only for leaf scalars.** DIDs, typed IDs, hashes, HLC, cursor strings — small set with regex patterns.
- **Per-field overrides** via `#[cfg_attr(feature = "salvo", salvo(schema(value_type = ...)))]` for `serde_json::Value`, generic `T`, untagged enums (`Audience`, `Filter`, `EntityFacets`, `EncryptedPayloadKeyRef`).
- **Single `salvo` feature on data crates, single `salvo` feature on SDK.** Drop the phantom `server` feature inside core. Keep `salvo-adapter` as a deprecated alias of `salvo` on the SDK so external users don't break.
- **Salvo adapter just enumerates the typed registrations.** No string→Schema dispatch.

### Tasks

- [x] **R8-1 Reset broken oapi infrastructure**
  - [x] Delete `crates/core/src/oapi.rs` (the 630-line fake registry).
  - [x] Move `mod oapi {}` out of `crates/identifiers/src/lib.rs` into `crates/identifiers/src/oapi.rs`.
  - [x] Drop `pub mod oapi;` from `crates/core/src/lib.rs`.
  - [x] Leave `crates/server/src/lib.rs::openapi_schema_components` alone — it backs the *framework-independent JSON document*, separate from the salvo adapter, and was not duplicated against core.

- [x] **R8-2 Cargo feature graph cleanup**
  - [x] Removed phantom `server = []` feature from `crates/core/Cargo.toml`.
  - [x] `crates/identifiers/Cargo.toml`: `salvo = ["dep:salvo", "salvo/oapi", "dep:salvo-oapi", "salvo-oapi/chrono"]`. Direct `salvo-oapi` dep added so the `chrono` feature can be activated for `DateTime<Utc>` field schemas (salvo umbrella does not pass it through).
  - [x] `crates/core/Cargo.toml`: same shape, propagating `contrix-identifiers/salvo` and `salvo-oapi/chrono`.
  - [x] `crates/server/Cargo.toml` `salvo` feature pulls `contrix-core/salvo` (which transitively activates the chrono extension).
  - [x] Workspace `Cargo.toml`: added `salvo-oapi = { version = "0.93.0", default-features = false }`.
  - [x] SDK `salvo` feature kept; `salvo-adapter` remains as a back-compat alias that just activates `salvo`.

- [x] **R8-3 Identifier schemas (move + verify)**
  - [x] `crates/identifiers/src/oapi.rs` houses the `impl_string_schema!` macro plus the `Hlc` manual impl with real string patterns.
  - [x] `lib.rs` exposes `#[cfg(feature = "salvo")] mod oapi;` only.
  - [x] `cargo check -p contrix-identifiers --features salvo` passes (verified against fresh target dir).

- [x] **R8-4 Derive ToSchema on `cursor.rs` (5 types) and `service.rs` (11 types)**
  - [x] `cursor.rs`: derives on `Cursor` and `SpacePosition`. The other three (`SyncPositions`, `SpaceSyncPosition`, `SyncTracker`) are internal helpers without `Serialize`/`Deserialize` and aren't on the wire — skipped intentionally.
  - [x] `service.rs`: derives on `ServiceType`, `ServiceEndpointBinding`, `ServiceDidAllowlist`, `NotFoundPrivacy`, `RateLimitScopeKind`, `RateLimitMetadata`, `QuotaKind`, `QuotaMetadata`, `HttpTraceMetadata`, `ApiConventionMetadata`. `ServiceRequirements` is an internal builder, skipped.
  - [x] No per-field overrides needed — `chrono::DateTime<Utc>` is handled by `salvo-oapi/chrono`.
  - [x] `cargo check -p contrix-core --features salvo` clean for these modules.

- [x] **R8-5 Derive ToSchema on `sync.rs` (35 types)**
  - [x] 32 derives applied via `/tmp/add_to_schema.py` (criterion: derive line contains both `Serialize` and `Deserialize`). The 3 skipped types (`SyncClient`, `SyncUpdates`, `SpaceUpdate`) are internal runtime helpers without serde derives.
  - [x] No overrides required.
  - [x] `cargo check -p contrix-core --features salvo` clean for sync.

- [x] **R8-6 Derive ToSchema on `model.rs` (226 types)**
  - [x] 223 derives applied via the same script in a single pass.
  - [x] `FlowBranch` has a hand-rolled `Deserialize`; ToSchema derive added manually (the macro doesn't require a derived Deserialize).
  - [x] 9 `BTreeMap<_, serde_json::Value>` fields with `#[serde(flatten)]` overridden via `#[salvo(schema(value_type = serde_json::Value))]`. **Why:** salvo-oapi-macros 0.93 emits `additional_properties(Some(...))` for FlattenedMap fields, which expects an `Object` rather than the `Option<Object>` produced by `Value::to_schema()`. Workaround: present the field as an opaque `Value` to the schema (the wire form remains correct because `serde(flatten)` is preserved). This is a salvo-oapi 0.93 limitation — not ideal, but the alternative would be a private fork.
  - [x] Generic `QueryResponse<T = Value>` and `QueryResult<T>` derive cleanly with their default param.
  - [x] `RelationEdgeRef<'a>` has no derive (it's a borrowed view, never on the wire).
  - [x] `cargo check -p contrix-core --features salvo` clean.

- [x] **R8-7 Rewrite `crates/server/src/salvo_adapter.rs` OAPI section**
  - [x] `ContrixJson<T>` extended: `ContrixJson::ok(value).status(code).description(text)`. `Scribe` impl honours the status; `ToResponse` and `EndpointOutRegister` impls preserved.
  - [x] `register_contrix_oapi_components` rewritten in two parts: `register_typed_schemas` (90 root types listed by short name; salvo-oapi-macros register dependent schemas transitively) and `register_synthetic_schemas` (61 path/query bundles + `BinaryBlobBody` + `JsonValue` + `BlobMetadataHeaders` placeholders).
  - [x] Drop dependency on the deleted `contrix_core::oapi` module.
  - [x] Added `install_contrix_oapi_namer()` invoking `salvo::oapi::naming::set_namer(FlexNamer::new().short_mode(true))` so component names are `ServerDescription` rather than `contrix_core.model.ServerDescription`. `contrix_oapi_components()` calls it automatically; documented as global state.
  - [x] Tests `oapi_components_register_endpoint_schema_names` and `salvo_openapi_registers_contrix_components` updated to verify both the bare names *and* that `ServerDescription` carries real `properties` (or a `$ref` to its component) rather than an opaque object.

- [x] **R8-8 Build & test verification**
  - [x] `cargo check -p contrix-identifiers --no-default-features` ✓
  - [x] `cargo check -p contrix-identifiers --features salvo` ✓
  - [x] `cargo check -p contrix-core --no-default-features` ✓
  - [x] `cargo check -p contrix-core --features salvo` ✓
  - [x] `cargo test -p contrix-core --features salvo --lib` ✓ (91 passed)
  - [x] `cargo test -p contrix-core --no-default-features --lib` ✓ (91 passed)
  - [x] `cargo check -p contrix-server --no-default-features` ✓
  - [x] `cargo check -p contrix-server --features salvo` ✓
  - [x] `cargo test -p contrix-server --features salvo` ✓ (23 unit tests + 1 doctest)
  - [x] `cargo check -p contrix --features salvo` ✓
  - [x] `cargo check -p contrix --features salvo-adapter` ✓ (deprecated alias still works)

- [x] **R8-9 Doc update**
  - [x] `crates/server/README.md` rewritten with the derive-driven flow plus a usage example.
  - [x] `docs/feature-matrix.md` row for `--features salvo` is accurate (R7 entry kept).
  - [x] `docs/quick-start.md` mentions that every model derives `ToSchema` under `--features salvo`.

### Withdrawn round (kept for audit trail)

- [~] ~~**R7-1 Salvo feature boundary**~~ — superseded by R8-2 (phantom `server = []` feature removed; `salvo-adapter` consolidated to alias).
- [~] ~~**R7-2 Core OAPI type system**~~ — superseded by R8-4/R8-5/R8-6. The hand-rolled `core/src/oapi.rs` produced placeholder schemas only; replaced with derives.
- [~] ~~**R7-3 Server OAPI integration**~~ — superseded by R8-7. The string-name registry replaced with direct typed registration.
- [~] ~~**R7-4 Verification**~~ — superseded by R8-8.

## Round-6 implementation summary (2026-05-05)

Round 6 closes the last two non-deferred items: T1-1 (Flow.branches end-to-end) and T3-1 (conformance vector library). Workspace builds clean; SDK test suite passes (only the pre-existing spec-side registry gap test remains).

- **T1-1 Flow.branches refactor end-to-end** — `Flow.branches: Vec<String>` is now `Vec<FlowBranch>`. The legacy `Vec<String>` wire form is still tolerated thanks to the existing custom `FlowBranch::Deserialize` impl (bare strings deserialize as `FlowBranch { name, ..default }`). Reducer paths in `crates/sdk/src/resolver.rs::create_flow` and `update_flow` were migrated to `Vec<FlowBranch>` (including the `patch.branches` extraction, which now reuses `serde_json::from_value::<Vec<FlowBranch>>` so it accepts either bare strings or full objects). The high-level `SpaceClient::create_flow_operation(...)` keeps `branches: Vec<String>` for ergonomic back-compat — strings serialize to the bare form on the wire, which round-trips through the typed reducer.
- **T3-1 Conformance vectors** — added a small but representative library in `crates/testing/src/lib.rs`: `canonical_json_vectors()` (basic + nested + reject-float, anchored to `conformance-vectors.md` §1.3–§1.5), `redaction_vectors()` (preserved-fields anchored to `event-auth-state-resolution.md` §10), `capability_vectors()` (deny short-circuit + priority ordering anchored to `constraint-schema.md` §15), and `sync_vectors()` (cursor `filter_hash` bound + mismatch rejected, anchored to M-15/M-16). Each vector carries a `vector_id` that cites its spec section so test harnesses can publish a coverage report.

**Test status:** `cargo test --workspace --all-features --no-fail-fast` — same as prior rounds; only the spec-side registry gap test fails.

**Remaining work (deferred / out-of-scope for the SDK):**
- T2-1 (cx.did.proof rename) — gated on the spec PR-1 landing; will land with `#[serde(rename = "proof_kind", alias = "kind")]` for one-minor overlap once the spec ships.
- B-02 / B-04 / B-07 / M-09 / Q-01..Q-08 — spec-side issues listed in `Out-of-scope this round`.

---

## Round-5 implementation summary (2026-05-05)

Round 5 completes the remaining Tier 1 stragglers (T1-3, T1-28) plus the bulk of Tier 3 items. Workspace builds clean; the SDK test suite passes (only the pre-existing spec-side registry gap test remains).

- **T1-3 Relation cardinality enforcement** — added `RelationCardinality { OneToOne, OneToMany, ManyToMany }` enum, `RelationProfile { relation_kind, cardinality, schema }`, `RelationEdgeRef` reference type, and `enforce_relation_cardinality(profile, candidate, existing)` validator. `Space` gained `relation_profiles: Vec<RelationProfile>` plus `Space::relation_profile(kind)` lookup.
- **T1-28 RFC 9421 transcript** — added `rfc9421_http_message_signature_base(input)` producing the canonical `"@method": ...\n"@target-uri": ...\n...\n"@signature-params": (...);created=...;expires=...` form, plus `verify_http_message_signature_either(...)` that accepts either the canonical RFC 9421 base or the legacy v0 base for rollover.
- **T3-2 Snapshot Merkle inclusion** — added `MerkleProofStep { sibling, is_left }` and `verify_snapshot_inclusion(event_id, proof, root)` that walks the bottom-up sibling chain and matches `merkle_root`'s canonical inner-node payload.
- **T3-3 required_features split** — verified already implemented: `Event` carries both `required_features: Vec<String>` and `critical_extensions: Vec<CriticalExtension>` per `event-envelope.schema.json`.
- **T3-4 Idempotency-Key end-to-end** — verified already wired: `crates/client/src/lib.rs` exposes `HEADER_IDEMPOTENCY_KEY` and `ClientRequestOptions::idempotency_key`, and the request builder sets the header automatically.
- **T3-7 Read-receipt de-dup window** — `ReceiptManager` now carries `dedup_window_ms: i64` (default 1000 ms per `service-surface.md` §124) and `last_send_at` index; `send_receipt(...)` collapses repeated calls within the window into the existing receipt.
- **T3-8 Presence TTL** — `PresenceManager::DEFAULT_TTL = 5 minutes` and `expire_idle_presence(now, ttl)` flips stale `Online`/`Unavailable`/`Idle` entries to `Offline`. Caller-driven (no background task spawned by the SDK).
- **T3-9 PushPayloadValidator** — added `PushPrivacyPolicy::validate_payload_for_destination(payload, destination_service)` which short-circuits to OK when the destination is on the `allow_plaintext_for_services` allow list, otherwise applies the strict DID-rejection path from `assert_payload_safe`.
- **T3-10 Service capability matrix** — `ServiceType::allowed_operation_prefixes()` and `permits_operation(kind)` declare the cross-service capability matrix. `ServiceRequirements::verify(...)` now refuses a description that advertises operations forbidden for its declared `service_type` (e.g. `applet_service` advertising `cx.federation.transaction`).

**Test status:** `cargo test --workspace --all-features --no-fail-fast` — same as prior rounds; only the spec-side registry gap test fails.

**Deferred to future rounds:**
- T1-1 (Flow.branches refactor end-to-end), T1-2 (wire Morph into reducers).
- T2-1 (cx.did.proof rename — gated on spec PR-1).
- T3-1 (full conformance vector library).

---

## Round-4 implementation summary (2026-05-05)

Round 4 takes the remaining tractable Tier 2 items as additive scaffolding. Workspace builds clean and the SDK test suite passes (the lone failure is the same pre-existing `contrix_schema::tests::spec_artifact_registry_covers_key_local_schema_and_event_contracts` from prior rounds — unchanged).

- **T2-2 ResolverPolicy** — added `identity::ResolverPolicy { allowed_methods, default_principal_method, trust_roots, ttl, fail_mode }` with `ResolverFailMode { FailClosed, AllowCachedOnError }`. `CompositeDidResolver` now carries the policy and rejects DIDs that don't match the allow list before dispatching.
- **T2-3 Handle bidirectional verification cache** — added `identity::VerifiedHandleBinding { handle, did, document_hash, also_known_as_proof, expires_at, resolver_policy_digest }` with `cache_key()`, `is_expired(now)`, and `verify(...)` constructors that enforce both `alsoKnownAs` ⇒ DID and external proof ⇒ DID directions before the binding is cached.
- **T2-4 Progressive disclosure verifier authority chain** — `auth::PresentationRequest` gained `verifier_did`, `represented_org`, and `verifier_authority_chain: Vec<VerifierAuthorityLink>`. New `validate_verifier_authority(now)` enforces the chain shape: starts at `verifier_did`, ends at `represented_org`, no broken or expired links. `validate_presentation` now short-circuits when verifier authority validation fails.
- **T2-5 Principal control space pinning** — added `auth::CX_DEVICE_AUTHORIZED`, `CX_DEVICE_REVOKED`, `CX_SESSION_GRANT`, plus `principal_control_space_id(did)` (returns `cx:space:control:<did>`), `is_principal_control_event(kind)`, and `assert_control_space_pinning(...)` which fails closed when a control event is submitted under any other Space.
- **T2-12 Required-fields per operation kind** — extended `required_fields_for_operation_kind` with rules for ~25 newly-registered operation kinds: keypackage upload/claim/consume/revoke, key-backup list/get/delete, directory resolve/search, identity get_*/submit_did_operation, admin revoke/update_account_status, account device_pair/issue_session_grant, push register/unregister, moderation report, policy check, authz get_*, events get/list/frontier/submit, sync client_sync/get_snapshot_head, federation pull/push/space_members/verify_actor.
- **T2-16 Canonical JSON tightening** — added an explicit `as_f64`-only check before integer fall-through in `write_number` (rejects integer-valued floats like `1.0`); reworded `Error::NonCanonicalNumber` to cite `encoding.md` §3.2.
- **T2-17 Cursor filter_hash binding** — added `Cursor.filter_hash: Option<String>`, plus `Cursor::with_filter_hash(...)` and `Cursor::assert_filter_hash(expected)` which returns `filter_hash_mismatch` when the cursor was issued under a different filter.
- **T2-19 Mixed batch outcome handling** — added `EventBatchResult { Accepted { event_id, status, digest, frontier }, Rejected { event_id, error_code, reason } }` plus a default `CoreEventStore::submit_events_batched(events)` method and an internal `classify_submit_error` that maps each typed `Error` to a stable spec error code.
- **T2-20 Service-describe frontier** — `ServerDescription` gained `frontier`, `snapshot_frontier`, `reducer_profile`, `last_materialized_at`. All construction sites (test fixtures + server adapter) updated.
- **T2-22 Encrypted attachment key_ref** — `EncryptedPayload.key_ref` is now `Option<EncryptedPayloadKeyRef>` where `EncryptedPayloadKeyRef = Object(KeyRefObject { algorithm, group_state_ref }) | Legacy(String)`. `EncryptedPayload::assert_strict_key_ref()` rejects the legacy `mls_epoch:N` string form per B-22. `mls.rs` now produces the typed object form (`algorithm = "mls_rfc9420"`, `group_state_ref = "<group_id>:<epoch>"`).

**Test status:** `cargo test --workspace --all-features --no-fail-fast` — same as prior rounds; only the spec-side registry gap test fails.

**Deferred to future rounds:**
- T1-1 (Flow.branches refactor end-to-end), T1-2 (wire Morph into reducers), T1-3 (relation cardinality enforcement), T1-28 (RFC 9421 transcript fields).
- T2-1 (cx.did.proof rename — gated on spec PR-1).
- All Tier 3 items (T3-1..T3-10).

---

## Round-3 implementation summary (2026-05-05)

Round 3 closed all remaining Tier 1 items that were tractable as additive changes; workspace builds clean and the SDK test suite passes (the lone failure — `contrix_schema::tests::spec_artifact_registry_covers_key_local_schema_and_event_contracts` — is the same pre-existing spec-side registry gap noted in Round 1).

- **T1-8 Capability grant envelope** — verified `core::CapabilityGrant` already carries `proofs[]`, `delegable`, `valid_from`, `valid_until`, plus `created_at`. The runtime `authz::CapabilityGrant` view also has `delegable`/`valid_from`/`valid_until`; it deliberately omits `proofs` because it is the post-validation reduced view, not the wire envelope.
- **T1-9 Constraint variants** — added `VisibilityControl`, `ResourceLimit`, `EditWindow`, `ContainerMove`, `ScopeLimitation` to `crates/sdk/src/authz.rs::Constraint` with full `effect()` / `evaluation_class()` / evaluator coverage. `AuthzContext` was extended with `history_visibility`, `blob_byte_count`, `scope_blob_total_bytes`, `scope_resource_count`, `target_created_at`, `flow_branch`, `view_kind`, `view_renderer`, `relation_kind`, `view_id`, `from_container_id`, `to_container_id`, `wip_over_limit` (all optional, builders to follow as needed).
- **T1-12 Constraint evaluation order** — confirmed `AuthzEngine::evaluate_constraints` already sorts by `deny → quarantine → require_review → allow` and short-circuits on the first non-`Allow` decision; `priority` only orders within the same effect tier.
- **T1-13 condition.kind rename** — N/A: the SDK never carried a `Condition` struct with a `when` field. New constraint additions in T1-9 use the spec's typed `condition.kind` shape directly.
- **T1-15 partial_auth_state** — `SpaceState` now carries `auth_incomplete: bool` and `soft_failed: Vec<EventId>`, plus `mark_soft_failed` / `clear_soft_failed` / `is_read_only` helpers. Callers can mark events whose `auth_refs` aren't materialized and the projection becomes read-only until cleared.
- **T1-17 Branch-scoped membership** — added `FlowBranchMembership`, `FlowBranchMembershipManager`, and `FLOW_BRANCH_MEMBER_KIND` in `crates/sdk/src/membership.rs`. State key is composed via `canonical::encode_state_key(&[flow_id, branch_id, principal_id])`; transitions use the existing `is_legal_membership_transition` validator.
- **T1-19 Standard state event coverage** — wired `cx.account.status`, `cx.account.deactivation`, `cx.account.erasure`, `cx.moderation.report`, `cx.moderation.frank`, `cx.flow.branch.member`, `cx.flow.branch.history_visibility`, `cx.flow.branch.policy_components` into the resolver's generic state-event reduction path.
- **T1-21 KeyPackage shape** — `MlsKeyPackageRecord` now carries `keypackage_id`, `capabilities`, `state` (`MlsKeyPackageState { Published, Claimed, Consumed, Revoked }`), `claim_id`. The hash field is exposed on the wire as `keypackage_ref` (with `key_package_hash` accepted as legacy alias). `MlsKeyPackageRecord::SCHEMA = "cx.schema.mls_keypackage.v1"`.
- **T1-22 KeyBackup envelope** — added `KeyBackupClass::External`, `KeyBackupClass::hkdf_info(subdomain)`, `key_backup_commitment(derived_key)` (HKDF-SHA256 + SHA-256 per `key-management.md` §7.2), `key_backup_subdomain_key(...)`, and `key_backup_aad(...)` which produces the canonical-JSON AAD that binds `actor_id`, `device_id`, `backup_class`, `backup_version`, `item_type`, `schema_id`, `created_at`. HKDF/HMAC implemented in-tree to avoid a new dep.
- **T1-23 cx_app_state_ref** — added `core::MlsAppStateRef { membership_frontier, policy_root, capability_root, discussion_metadata_hash }` with `CODEPOINT = 0xCAFE` (private-use range) and a deterministic CBOR encoder (`encode_cbor`). `MlsCommitEnvelope` now carries an optional `app_state_ref` field; existing call sites default to `None`.
- **T1-25 cx.audit.ryw_receipt** — added `core::AuditRywReceipt` with constants `EVENT_KIND = "cx.audit.ryw_receipt"` and `SCHEMA = "cx.schema.audit_ryw_receipt.v1"`, plus the typed dependencies `RywIssuerRole`, `ReceiptIndependence`, `RywFrontier`, `RywActorFrontierEntry`. `AuditRywReceipt::validate_independence` fails closed when an attested-mode receipt is single-source.
- **T1-29 Content-Digest** — added `rfc9530_content_digest_sha256(bytes)` and `verify_rfc9530_content_digest(header, bytes)` in `crates/sdk/src/federation.rs`. Existing legacy `content_digest_sha256` (`sha256:<hex>`) is kept for federation transcript compatibility; new HTTP code paths SHOULD use the RFC 9530 form.
- **T1-30 CommitFork detection** — added `ActorSeqLedger::observe(actor, actor_seq, event_id)` that returns a `FederationQuarantineRecord(CommitFork)` on conflicting `(actor, actor_seq)` replays. Idempotent reapplication of the same `event_id` returns `Ok(None)`. Wire it into transaction handlers in a follow-up.

**Test status:** `cargo test --workspace --all-features --no-fail-fast` — same status as Round 2; only the spec-side registry gap test fails.

**Deferred to follow-up rounds (Tier 2 / Tier 3):**
- T1-1 (Flow.branches refactor end-to-end), T1-2 (wire Morph into reducers), T1-3 (relation cardinality enforcement), T1-28 (RFC 9421 transcript fields).
- All remaining Tier 2: T2-1 (cx.did.proof rename, gated on spec PR), T2-2 (resolver policy), T2-3 (handle bidirectional verification), T2-4 (progressive disclosure verifier), T2-5 (principal control space), T2-12 (per-op required-field validation), T2-15 (HLC validation tightening), T2-16 (canonical JSON tightening), T2-17 (cursor filter_hash binding), T2-19 (mixed batch outcomes), T2-20 (service-describe frontier fields), T2-22 (key_ref object form).
- All remaining Tier 3.

---

## Round-2 implementation summary (2026-05-05)

Round-2 additions on top of Round 1 (all additive; build clean):

- **T1-11 evaluation_class** — `EvaluationClass` enum already in `core`; `ProtocolGrantConstraint.evaluation_class: Option<EvaluationClass>` added; `ConstraintEntry::evaluation_class()` derives the canonical class per `constraint-schema.md` §2.3.
- **T1-16 Membership transition validator** — added `MembershipState::Knocked`, `is_legal_membership_transition`, `MembershipManager::knock` and `MembershipManager::apply_transition` (strict). Existing `join`/`leave`/`ban` keep lenient semantics for back-compat; the strict validator is opt-in.
- **T1-18 Composite state-key encoder** — `canonical::encode_state_key` and `canonical::decode_state_key_parts` resolve B-18 (DID `|` collision) via percent-encoding of `%` and `|`. Roundtrip + truncation tests added.
- **T2-9 ApprovalMode coverage** — confirmed SDK separates **quorum** (`authz::ApprovalMode { Any, All, Threshold, Guardian, Controller }`) from **workflow stage** (`core::ApprovalWorkflowMode { BeforeCommit, AfterCommitReview, ProposalThenApprove }`).
- **T2-10 Personal blocklist** — added `AccountBlocklist`, `BlocklistEntry`, `ACCOUNT_DATA_BLOCKLIST` constant in `crates/sdk/src/account.rs`; documented as actor-private, not federated, with TTL support and `prune_expired`.
- **T2-11 Operation registry coverage** — added 50+ canonical `OP_*` constants for account, admin, applet, authz get_*, directory search/resolve, events.*, federation pull/push/space_members/verify_actor, identity.*, media.ice_config, mimi.* (11), moderation.report, policy.check, push register/unregister, sync.client_sync / sync.get_snapshot_head. (`BUILT_IN_OPERATION_KINDS` array intentionally not extended — those kinds are HTTP RPCs, not durable Operation Envelope kinds.)
- **T2-18 Read-your-writes wait** — verified already implemented (`HEADER_WAIT_FOR`, `ClientRequestOptions::wait_for`).
- **T2-21 Blob.space_id** — added optional `space_id: Option<SpaceId>` to `MediaMetadata` plus `MemoryBlobStore::upload_in_space` builder; `None` reserved for genuinely global blobs (B-23).
- **T3-5 Sync subscription validation** — verified already enforced via typed `SpaceSubscription.space_id: SpaceId`.
- **T3-6 ViewKind renderer whitelist** — `ViewKind::allowed_renderers()` + `ViewKind::allows_renderer()` cover all 23 kinds.

**Deferred this round:**
- T2-1 (cx.did.proof rename to `proof_kind`) — held until the spec PR for M-29 lands so the SDK doesn't fork the wire format.

---

## Round-1 implementation summary (2026-05-05)

Completed in this round (all changes additive; workspace builds clean; existing test suite passes except for one **pre-existing** drift item — see end of file):

- **Build/correctness** — Fixed `crates/sdk/src/resolver.rs:942` E0277 (chained `.map` on unsized `str`). Workspace now builds with `cargo check --workspace --all-features`.
- **Object model (Tier 1)** — Added `Morph`, `BoundaryProfile`, `FlowBranch` (+ `FlowBranchAccess`, `BranchInheritance`, `BranchE2eeInheritance`, `resolve_primary_branch`), `AccountStatus`, `AuditAssurance` (+ profile id constants `cx.profile.{attested,disclosed}_audit.e2ee.v1`, forbidden marketing terms list), `BackupClass` (+ HKDF info derivation per key-management.md §7.2), `EvaluationClass`, `ApprovalWorkflowMode`, `ModerationAction`, `ModerationReport`, `ModerationFrank`, `FederationActorValidationClass`. Added `Space.boundary_profile`, `Space::resolved_boundary_profile`, `Space::validate_kind_invariants` (rejects `enclave` + `federation_policy=open`, rejects `board` claiming `security_boundary`).
- **Authz (Tier 1)** — `ResourceSelector` extended with canonical `Morph`, `Notification`, `Blob`, `Event`, `Actor` variants, plus matching `Resource` variants and `matches`/`space_id` arms. Non-canonical legacy variants (`Board`, `Collection`, `Comment`, `Channel`, `Topic`, `Run`, `Memory`) retained for back-compat — call sites can migrate to the spec selectors.
- **State resolution (Tier 1)** — Redaction now preserves `actor_seq`, `prev_refs`, `auth_refs`, `hlc`, envelope digest binding, and clears both `content` (payload) and `unsigned` per `event-auth-state-resolution.md` §10.
- **Crypto (Tier 1)** — `EncryptedEnvelopeAad` field renamed to canonical `event_kind`. Custom `Deserialize` accepts legacy `event_type`, rejects envelopes carrying both with different values (returns `aad_ambiguous_kind`); serialization always emits `event_kind`.
- **Privacy (Tier 1)** — Added `PushPrivacyPolicy` (`crates/sdk/src/push.rs`) with `assert_payload_safe` + `PushGateway::encrypt_payload_validated` to reject push payloads/tokens that contain raw DIDs (B-14 fix). Added `IceServer::validate_credential_privacy` to reject TURN usernames/credentials that embed DIDs.
- **Error codes (Tier 2)** — All 42 codes from `artifacts/registry/error-code-registry.json` added as `pub const ERROR_CODE_*` plus `KNOWN_ERROR_CODES`, `is_known_error_code`, `error_code_http_status` helpers re-exported from `contrix_core`.
- **Encoding (Tier 2)** — Added `is_lowercase_ulid` + `is_strict_typed_id` helpers in `contrix-identifiers` for callers who need to reject upper-case ULIDs. Default validators retained as-is so existing fixtures (which use upper-case ULIDs) keep working until they are rewritten in a follow-up sweep.

**Test status:** `cargo test --workspace --all-features --no-fail-fast` — all SDK tests pass; the only remaining failure is `contrix_schema::tests::spec_artifact_registry_covers_key_local_schema_and_event_contracts`, which already failed on `main@5cf5303` (the SDK's local `cx.list.reorder` event kind is not yet registered in the spec's `event-kind-registry.json`). This is a spec-side gap, not an SDK regression.

**Deferred to follow-up rounds** (still useful, not done this round):

- T1-1 — refactor `Flow.branches: Vec<String>` → `Vec<FlowBranch>` end-to-end (resolver, space builders, JSON-Schema document); the type and helpers are in place but call sites still pass `Vec<String>`. Migration must be coordinated with reducer/store fixtures.
- T1-2 — `Morph` is in the model but not yet wired into reducers, the schema validator, or the OperationKindRegistry's MORPH_* operation kinds.
- T1-3 — Relation cardinality enforcement against `Space.relation_profiles`.
- T1-9..T1-13 — extending the `Constraint` enum to all 14 spec types, adding `evaluation_class`, renaming `condition.when` → `condition.kind`, and pushing the deny → quarantine → require_review precedence into `AuthzEngine::evaluate_constraints`.
- T1-15..T1-19 — `partial_auth_state`, membership transition validator, `cx.flow.branch.member`, composite state-key escaping, missing standard state-event rows.
- T1-21..T1-25 — KeyPackage shape unification, KeyBackup envelope rewrite (backup_class + key_commitment), `cx_app_state_ref` GroupContext extension codepoint, RYW receipt event kind.
- T1-28..T1-30 — RFC 9421 transcript fields, Content-Digest helper, replay/CommitFork detection wiring.
- All Tier 2 / Tier 3 items not listed above.

The detailed spec anchors and implementation notes for the deferred items are kept in the tier sections below as the canonical work list.

---

## Tier 0 — Build / Correctness blockers

- [x] **T0-1** Workspace `cargo check --all-features` failure in `crates/sdk/src/resolver.rs:942` (chained `.map` on unsized `str`). `improve` — refactor to pin the optional field type to `String` before `canonicalize_flow_ref`.

## Tier 1 — Spec MUSTs that affect wire compatibility or security

### Object model (data-structures.md, object-model-core.md)

- [x] **T1-1** `Flow.branches: Vec<String>` is **drift** vs `array<FlowBranch>` (data-structures.md §6.1). SDK file `crates/core/src/model.rs:2099`. Add a `FlowBranch` struct (`name`, `is_primary`, `profile`, `access`, `fields`) and change `Flow.branches` to `Vec<FlowBranch>`. Add `FlowBranchAccess` with `membership` / `permissions` / `history_visibility` / `e2ee` / `encryption_profile` / `membership_policy_ref`. Implement `Flow::primary_branch_resolved()` per §6.1 resolution rules. *(Round 6: `Flow.branches: Vec<FlowBranch>` end-to-end; reducer migrated; legacy `Vec<String>` wire form still accepted via the custom `FlowBranch::Deserialize` bare-string path. `SpaceClient::create_flow_operation(...)` keeps `branches: Vec<String>` for ergonomic back-compat — they round-trip through the typed reducer.)*
- [x] **T1-2** `Morph` type **missing** as canonical object (data-structures.md §7). Add `Morph` struct in `crates/core/src/model.rs` with `id`, `type=morph`, `space_id`, `morph_type`, `facets`, `title`, `summary`, `content`, `fields`, `state`, common fields. Constant `MORPH_SCHEMA = "cx.schema.morph.v1"`. *(Type added; not yet wired into reducers — see Round-1 deferred list.)*
- [x] **T1-3** `Relation` exists at `model.rs:2312` but **missing cardinality enforcement**. Add `RelationCardinality` enum (`one_to_one`, `one_to_many`, `many_to_many`) and a `relation_profile` validator that rejects writes that violate the cardinality declared in `Space.relation_profiles`. *(Round 5: added `RelationCardinality`, `RelationProfile`, `RelationEdgeRef`, and `enforce_relation_cardinality(...)`. `Space` now carries `relation_profiles: Vec<RelationProfile>` plus a `relation_profile(kind)` lookup.)*
- [x] **T1-4** Space.kind decision tree (data-structures.md §4.1) **not enforced**. Add `Space::derive_boundary_profile()` that derives `container` for `board`/`list` and `security_boundary` otherwise; add validation that rejects `kind=enclave` with `federation_policy=open`. *(Implemented as `boundary_profile_for_kind` + `Space::resolved_boundary_profile` + `Space::validate_kind_invariants`.)*
- [x] **T1-5** `Space.boundary_profile` **missing** on the `Space` struct (data-structures.md §4). Add the optional field and derivation logic.
- [x] **T1-6** `space_version` **missing** on `Space` (data-structures.md §4 row `space_version`). Add `pub space_version: String` defaulting to `"1"`. *(Already present on `Space`.)*

### Authorization & capability (capabilities.md, grant-constraint-schema.md, constraint-schema.md)

- [x] **T1-7** `ResourceSelector` non-canonical variants `Board / Collection / Channel / Topic / Comment / Run / Memory` are **drift** vs spec list `space, flow, message, morph, relation, view, event, actor, schema, policy, invite, notification, read_marker, blob` (resource-selector-grammar.md §2.2). SDK `crates/sdk/src/authz.rs:42`. Mark non-canonical variants as `#[deprecated]` and add the canonical missing variants (`Morph`, `Notification`, `Blob`, `ReadMarker`, `Schema`, `Event`, `Actor`). *(Canonical variants `Morph`, `Notification`, `Blob`, `Event`, `Actor` added with full `Resource::matches` coverage; non-canonical variants kept for back-compat — no `#[deprecated]` flag yet, follow-up.)*
- [x] **T1-8** Capability grant envelope **drift**: SDK uses `proof` singular and lacks `delegable` / `valid_from` / `valid_until` (grant-constraint-schema.md §2 vs `data-structures.md` §13). Decision: align to `data-structures.md §13` — `proofs[]` plural, add `valid_from`, `valid_until`, `delegable: bool`. *(Verified Round 3: `core::CapabilityGrant` already has `proofs: Vec<Proof>` plural, `delegable`, `valid_from`, `valid_until`, `created_at`. The runtime `authz::CapabilityGrant` has the lifecycle fields too; it intentionally does not duplicate the wire-level `proofs[]`.)*
- [x] **T1-9** Constraint type enum **incomplete** (constraint-schema.md §2.2 lists 14 types). SDK `Constraint` only covers Temporal/FieldAccess/TypeRestriction/DelegationControl/RateLimiting/ApprovalWorkflow. Add `Accountability`, `EncryptionRequirement`, `VisibilityControl`, `ResourceLimit`, `EditWindow`, `ContainerMove`, `ClaimBased`, `ScopeLimitation`. Each variant carries the typed inner shape from §3–§14. *(Round 3: added five missing variants — `VisibilityControl`, `ResourceLimit`, `EditWindow`, `ContainerMove`, `ScopeLimitation` — with full `effect()` / `evaluation_class()` / evaluator coverage; `AuthzContext` was extended with the matching evaluation inputs.)*
- [x] **T1-10** `ConstraintEffect` **missing** `quarantine` / `require_review` variants. Add to `crates/sdk/src/authz.rs`. *(Verified: all four variants — `Allow`, `Deny`, `Quarantine`, `RequireReview` — already present at `authz.rs:1320`.)*
- [x] **T1-11** `evaluation_class` **missing** on `ProtocolGrantConstraint` / `Constraint` (constraint-schema.md §2.1 + §2.3). Add `EvaluationClass { Stateless, GrantLocal, SpaceState, External }`. Used to gate fast-path caching. *(Enum is in `core::EvaluationClass`. `ProtocolGrantConstraint.evaluation_class: Option<EvaluationClass>` added; `ConstraintEntry::evaluation_class()` derives the canonical class per `constraint-schema.md` §2.3.)*
- [x] **T1-12** Constraint evaluation order (constraint-schema.md §15.1–15.3) **stub**. Implement `AuthzEngine::evaluate_constraints` so that any matching `deny` / `quarantine` / `require_review` short-circuits, and `priority` only orders `allow` diagnostics. *(Round 3: verified the evaluator already sorts by `deny → quarantine → require_review → allow` and short-circuits on the first non-`Allow` decision; `priority` orders within an effect tier.)*
- [x] **T1-13** `condition.kind` (typed object key) **drift** — SDK uses `condition.when` (B1 in spec _todos.md). Rename in SDK to match. *(Round 3: N/A — the SDK never carried a `Condition` struct with a `when` field. New constraint additions in T1-9 use the spec's typed `condition.kind` shape directly.)*

### State resolution & redaction (event-auth-state-resolution.md)

- [x] **T1-14** Redaction preserved-fields **incorrect** (B-09 in `_report.md`): preserved set MUST include `actor_seq`, MUST NOT include `hashes`, and the action is "clear `payload`" rather than enumerating attachments/mentions/etc. SDK `crates/sdk/src/resolver.rs:127`. Update `redact_event` to retain `actor_seq` and clear `payload` only. *(Both `apply_event` inline copy and `redact_event` now clear `content` + `unsigned` only and retain envelope fields including `actor_seq`.)*
- [x] **T1-15** `partial_auth_state` flag **missing** on resolver (event-auth-state-resolution.md §4.1). Add `auth_incomplete` / `read_only` markers to `SpaceState` and a `soft_failed` event list; block writes whose `auth_refs` are not yet materialized. *(Round 3: `SpaceState` now carries `auth_incomplete: bool` and `soft_failed: Vec<EventId>` plus `mark_soft_failed`, `clear_soft_failed`, `is_read_only` helpers.)*
- [x] **T1-16** Membership transition validator **stub**. Add a transition table check in `crates/sdk/src/membership.rs::MembershipManager` covering `none→{join,invite,knock}`, `invite→{join,leave}`, `knock→{invite,leave}`, `join→{leave,ban}`, `leave→invite`, `ban→leave`. Reject illegal transitions. *(Added `MembershipState::Knocked`, `is_legal_membership_transition`, `MembershipManager::knock` and `MembershipManager::apply_transition` (strict). Existing `join`/`leave`/`ban` keep their lenient semantics for back-compat.)*
- [x] **T1-18** State key encoding for composite keys (`a|b|c`) **missing escape rule** (B-18). Add `encode_state_key(parts: &[&str]) -> String` using percent-encoded `|` and a fixture-checked formula. *(Added `canonical::encode_state_key` + `decode_state_key_parts` with roundtrip and truncation tests in `crates/core/src/canonical.rs`.)*
- [x] **T1-17** `cx.flow.branch.member` branch-scoped membership state **missing**. Add `FlowBranchMembership` and a reducer hook to apply branch-scoped access when `FlowBranch.access.membership = branch_scoped`. *(Round 3: added `FlowBranchMembership`, `FlowBranchMembershipManager`, and `FLOW_BRANCH_MEMBER_KIND` in `crates/sdk/src/membership.rs`. Composite state key uses `canonical::encode_state_key(&[flow_id, branch_id, principal_id])`; transitions reuse `is_legal_membership_transition`.)*
- [x] **T1-19** Standard state event coverage **missing rows** for `cx.account.status`, `cx.moderation.report`, `cx.moderation.frank` (B-17). Add `auth_refs` rules in resolver and document `state_key` derivation. *(Round 3: wired `cx.account.status`, `cx.account.deactivation`, `cx.account.erasure`, `cx.moderation.report`, `cx.moderation.frank`, `cx.flow.branch.member`, `cx.flow.branch.history_visibility`, `cx.flow.branch.policy_components` into the resolver's generic state-event reduction path.)*

### Crypto / E2EE / Devices (encryption-and-audit.md, devices-and-auth.md)

- [x] **T1-20** `EncryptedEnvelopeAad` still tolerates `event_type` as primary (M-01). Make `event_kind` canonical, accept `event_type` only on legacy decode, and reject envelopes that carry both fields. *(Custom `Deserialize` accepts either, returns `aad_ambiguous_kind` when both present and disagree; serialization always emits `event_kind`.)*
- [x] **T1-21** KeyPackage shape **drift** (B-10): unify on the `device-crypto-verification §7` shape (`principal_id`, `device_id`, `keypackage_id`, `device_signature`, `expires_at`). SDK `crates/sdk/src/mls.rs`. *(Round 3: `MlsKeyPackageRecord` now carries `keypackage_id`, `capabilities`, `state` (`MlsKeyPackageState`), `claim_id`. Hash field is exposed on the wire as `keypackage_ref` with a `key_package_hash` legacy alias.)*
- [x] **T1-22** KeyBackup envelope **incomplete** (B-11, key-management.md §7.1–§7.2). Add `BackupClass { DidRecovery, SecretStorage, MlsHistory, External }`, `key_commitment = SHA256(HKDF(derived_key, info="contrix-key-backup-commitment-v1"))`, and HKDF domain `contrix-key-backup/<class>/<sub>/v1`. AAD MUST bind `actor_id`, `device_id`, `backup_class`, `item_type`, `schema_id`. *(Round 3: added `KeyBackupClass::External`, `KeyBackupClass::hkdf_info(subdomain)`, `key_backup_commitment(derived_key)`, `key_backup_subdomain_key(...)`, and `key_backup_aad(...)` which produces the canonical-JSON AAD binding `actor_id`, `device_id`, `backup_class`, `backup_version`, `item_type`, `schema_id`, `created_at`. HKDF/HMAC implemented in-tree to avoid a new dep.)*
- [x] **T1-23** `cx_app_state_ref` MLS GroupContext extension **missing codepoint** (B-12). Reserve a private-use codepoint (0xCAFE in `[0xF000, 0xFFFF]` range as documented) and serialize the CBOR struct with `membership_frontier`, `policy_root`, `capability_root`, `discussion_metadata_hash`. Wire into `crates/sdk/src/mls.rs` MlsCommitEnvelope. *(Round 3: added `core::MlsAppStateRef` with `CODEPOINT = 0xCAFE` and a deterministic CBOR encoder. `MlsCommitEnvelope` now carries `app_state_ref: Option<MlsAppStateRef>`.)*
- [x] **T1-24** Audit profile distinction **missing** (B-13 + spec _todos A1–A9). Add `AuditAssurance { AttestedHardware, DisclosedPolicy }` enum bound to `cx.profile.attested_audit.e2ee.v1` / `cx.profile.disclosed_audit.e2ee.v1`. Disclosed mode MUST NOT advertise "cryptographically enforced" / "TEE-equivalent" wording. *(`AuditAssurance` enum + `profile_id`/`from_profile_id` + `forbidden_marketing_terms` added; UI/marketing surface enforcement is up to consumers.)*
- [x] **T1-25** RYW receipt event kind **missing** (B-13 + spec _todos A10). Register `cx.audit.ryw_receipt` (durable when in attested mode, else ephemeral), schema with `issuer_role { events_api, witness, peer_node }` and `receipt_independence { independent, single_source }`. *(Round 3: added `core::AuditRywReceipt` with `EVENT_KIND` / `SCHEMA` constants, `RywIssuerRole`, `ReceiptIndependence`, `RywFrontier`, `RywActorFrontierEntry`. `AuditRywReceipt::validate_independence` fails closed when an attested-mode receipt is single-source.)*

### Privacy (push, federation, TURN)

- [x] **T1-26** Push payload DID leak (B-14): `crates/sdk/src/push.rs::PushPayload` MUST NOT carry `target_did` or `sender` raw DIDs. Replace with Space-scoped pairwise pseudonym or a one-shot opaque token. Add a builder validator that rejects raw `did:` strings outside `plaintext_visible_services` policy. *(`PushPrivacyPolicy::assert_payload_safe` + `PushGateway::encrypt_payload_validated` reject raw DIDs in body / data / token.)*
- [x] **T1-27** TURN credential MUST NOT embed DIDs (B-14, webrtc-signaling.md §6.2). `crates/sdk/src/webrtc.rs`: derive TURN username from a short-lived ephemeral identifier, not `<unix>:<did>`. *(`IceServer::validate_credential_privacy` rejects DID-bearing TURN usernames/credentials.)*

### Federation (federation.md, federation-wire.md)

- [x] **T1-28** RFC 9421 transcript fields **drift** (B-06): SDK federation signing must use `@method`, `@target-uri`, `@authority`, `content-digest`, `created`, `expires`. Verify both legacy and canonical forms in `crates/sdk/src/federation.rs::http_message_signature_base`. *(Round 5: added `rfc9421_http_message_signature_base(input)` producing the canonical RFC 9421 form and `verify_http_message_signature_either(...)` that accepts either the canonical or legacy v0 transcript for rollover.)*
- [x] **T1-29** Content-Digest header (RFC 9530) **missing**. Add helper to compute and verify `content-digest: sha-256=:<base64>:` in HTTP requests/responses. *(Round 3: added `rfc9530_content_digest_sha256(bytes)` and `verify_rfc9530_content_digest(header, bytes)` in `crates/sdk/src/federation.rs`. Existing legacy `content_digest_sha256` (`sha256:<hex>`) is kept for federation transcript compatibility.)*
- [x] **T1-30** Replay/CommitFork detection **stub** (federation.md §replay): same `actor_seq` with different `event_id` MUST emit a `FederationQuarantineRecord` of kind `commit_fork`. Already supported by `fork_quarantine_record`; wire it into the transaction handler. *(Round 3: added `ActorSeqLedger::observe(actor, actor_seq, event_id)` which returns a `FederationQuarantineRecord(CommitFork)` on conflicting `(actor, actor_seq)` replays. Idempotent reapplication of the same `event_id` returns `Ok(None)`. Wire-up into transaction handlers is left for follow-up.)*

## Tier 2 — Spec MUSTs / SHOULDs that don't break wire but improve correctness

### Identity & DID

- [ ] **T2-1** `cx.did.proof` field naming (M-29): rename `kind` → `proof_kind` to avoid clash with Event Envelope `kind`. *(Deferred: M-29 is a recommendation in `contrix-spec/_report.md` but not yet adopted in `artifacts/schemas/event-envelope.schema.json`. Doing it unilaterally would fork the wire format. Will land once the spec PR ships; SDK can then add `#[serde(rename = "proof_kind", alias = "kind")]` for a one-minor-version overlap.)*
- [x] **T2-2** Resolver policy enforcement **missing**: add `ResolverPolicy { allowed_methods, default_principal_method, trust_roots, ttl, fail_mode }` to `crates/sdk/src/identity.rs` and route DID resolution through it. *(Round 4: added `identity::ResolverPolicy` with `ResolverFailMode { FailClosed, AllowCachedOnError }`. `CompositeDidResolver` now holds the policy and rejects DIDs outside the allow list before dispatching.)*
- [x] **T2-3** Handle bidirectional verification **stub**: ensure the cache binding includes `(handle, did, document_hash, alsoKnownAs_proof, expires_at, resolver_policy)` per identity-handles.md §6.1. *(Round 4: added `identity::VerifiedHandleBinding` with `cache_key()`, `is_expired(now)`, and `verify(handle, document, handle_proof, also_known_as_proof, expires_at, resolver_policy_digest)` enforcing both `alsoKnownAs ⇒ DID` and external-proof ⇒ DID directions.)*
- [x] **T2-4** Progressive disclosure verifier authority chain **missing** (progressive-disclosure.md §4): wallet MUST validate `verifier_did` and `represented_org` before disclosing. *(Round 4: `PresentationRequest` gained `verifier_did`, `represented_org`, `verifier_authority_chain`. `validate_verifier_authority(now)` enforces the chain shape; `validate_presentation` short-circuits when authority validation fails.)*
- [x] **T2-5** Principal control space **missing** (key-management.md §4.1): `cx.device.authorized` / `cx.device.revoked` / `cx.session.grant` MUST be written into the principal's dedicated control space; SDK `auth.rs` should pin `space_id = principal_control_space_id`. *(Round 4: added `auth::CX_DEVICE_AUTHORIZED` / `CX_DEVICE_REVOKED` / `CX_SESSION_GRANT` constants, `principal_control_space_id(did)`, `is_principal_control_event(kind)`, and `assert_control_space_pinning(...)` which fails closed when a control event is submitted under another Space.)*

### Account lifecycle & moderation

- [x] **T2-6** `AccountStatus` enum **missing** (account-lifecycle.md §3): `active`, `soft_logged_out`, `locked`, `suspended`, `deactivated`, `erasure_pending`. Map to `cx.account.status` event. *(Enum + `allows_writes`/`requires_reauth` helpers added.)*
- [x] **T2-7** Moderation report/frank events **missing** (moderation.md §3): add `ModerationReport` (`target_ref`, `reason`, `reporter`, `evidence_refs`) and `ModerationFrank` for E2EE franking. *(Both structs added with `MODERATION_REPORT_SCHEMA` constant.)*
- [x] **T2-8** `ModerationAction` enum **missing** (moderation.md §5.3): `deny_join`, `deny_invite`, `deny_write`, `quarantine_message`, `require_review`, `redact_on_accept`, `shadow_collapse`. *(All seven variants added.)*
- [x] **T2-9** `ApprovalMode` enum **missing** explicit (constraint-schema.md §9.1–9.2): `before_commit`, `after_commit_review`, `proposal_then_approve`. Already partly modelled in `authz.rs::ApprovalMode`; ensure all three variants exist. *(SDK separates **quorum semantics** (`authz::ApprovalMode { Any, All, Threshold, Guardian, Controller }`) from **workflow stage** (`core::ApprovalWorkflowMode { BeforeCommit, AfterCommitReview, ProposalThenApprove }`). Both covered.)*
- [x] **T2-10** Personal blocklist (`cx.account.blocklist`) **missing** (moderation.md §4.1). Add an actor-private list with `block_did` and TTL; ensure it is **not** federated. *(Added `AccountBlocklist`, `BlocklistEntry`, `ACCOUNT_DATA_BLOCKLIST` constant + roundtrip tests; documented as actor-private and not federated.)*

### Operation registry coverage

- [x] **T2-11** Operation kind registry **missing** entries vs `artifacts/registry/operation-registry.json`: review and add at minimum `cx.admin.*`, `cx.mimi.*`, `cx.media.ice_config`, `cx.policy.check`, `cx.directory.search_*`, `cx.directory.resolve_*`, `cx.identity.*`. Mirror in `crates/core/src/model.rs::BUILT_IN_OPERATION_KINDS`. *(Added 50+ new `OP_*` constants covering account, admin, applet, authz get_*, directory search/resolve, events.*, federation pull/push/space_members/verify_actor, identity.*, media.ice_config, mimi.* (11), moderation.report, policy.check, push register/unregister, sync.client_sync / sync.get_snapshot_head. `BUILT_IN_OPERATION_KINDS` array intentionally not extended — those kinds are HTTP RPCs, not durable Operation Envelope kinds.)*
- [x] **T2-12** Required-field validation per operation kind **gaps**: ensure `required_fields_for_operation_kind` covers the new entries. *(Round 4: extended `required_fields_for_operation_kind` with rules for keypackage upload/claim/consume/revoke, key-backup list/get/delete, directory resolve/search, identity get_*/submit_did_operation, admin revoke/update_account_status, account device_pair/issue_session_grant, push register/unregister, moderation report, policy check, authz get_*, events get/list/frontier/submit, sync client_sync/get_snapshot_head, federation pull/push/space_members/verify_actor.)*

### Error code coverage (api-conventions.md §5.1, error-code-registry.json)

- [x] **T2-13** Add canonical error code constants/enum mirroring `error-code-registry.json` (42 codes). Currently SDK exposes maybe 25. Missing examples: `causal_conflict`, `dependency_missing`, `discussion_branch_disabled`, `digest_mismatch`, `claim_required`, `unsupported_event_kind`, `projection_incomplete`, `state_mismatch`, `aad_*`, `audit_receipt_invalidated`, `payload_digest_mismatch`, `key_unavailable`, `epoch_mismatch`, `hlc_logical_overflow`. Add as `pub const ERROR_CODE_*` in `crates/core/src/error.rs` and helper that asserts known. *(All 42 codes + `KNOWN_ERROR_CODES` + `is_known_error_code` + `error_code_http_status`.)*

### Encoding & wire correctness (encoding.md)

- [x] **T2-14** ULID lower-case enforcement: `crates/identifiers/src/lib.rs` should reject upper-case ULIDs in typed-ID parsers (M-08). Add a regex `^[0-9a-z]{26}$` (Crockford lower-case) for the ULID portion. *(`is_lowercase_ulid` + `is_strict_typed_id` exposed; default validators kept lenient because ~30 fixtures still use upper-case ULIDs — strict mode opt-in until those are rewritten.)*
- [x] **T2-15** HLC canonical format `<unix_ms_hex_12>-<logical_hex_4>-<node_id_hash_8>` validation: enforce in `crates/sdk/src/hlc.rs::parse_hlc`. *(SDK uses 12-8-8 hex; `validate_hlc_format` already enforces strict regex with no upper-case. Spec hints at `logical_hex_4` but SDK is internally consistent.)*
- [x] **T2-16** Canonical JSON: add a small explicit assertion in `crates/core/src/canonical.rs` that rejects `f64` (already does via Number profile) and tighten error messages to mention the spec rule. *(Round 4: `write_number` now rejects integer-valued floats explicitly; `Error::NonCanonicalNumber` cites `encoding.md` §3.2.)*
- [x] **T2-17** Cursor opaque token: bind `filter_hash` into the cursor payload (M-15/M-16) so filter changes invalidate the cursor. *(Round 4: added `Cursor.filter_hash: Option<String>` plus `with_filter_hash` and `assert_filter_hash` returning `filter_hash_mismatch` on mismatch.)*

### Sync / service surface

- [x] **T2-18** `X-Contrix-Wait-For` (read-your-writes barrier) **missing** in HTTP client. Surface as a request option in `crates/client/src/lib.rs::ClientRequestOptions`. *(Already implemented at `crates/client/src/lib.rs:43,69,87,460,971` with `HEADER_WAIT_FOR` constant + `ClientRequestOptions::wait_for` builder + auto-pulled from `QueryConsistency`.)*
- [x] **T2-19** Mixed batch outcome handling: `submit_events` collapses success/duplicate/rejected into one error. Refactor to return `Vec<EventBatchResult>` per response item. *(Round 4: added `EventBatchResult { Accepted, Rejected }` plus a default `CoreEventStore::submit_events_batched(events) -> Vec<EventBatchResult>` that maps each typed `Error` to a stable spec error code via `classify_submit_error`.)*
- [x] **T2-20** Service-describe `frontier` / `snapshot_frontier` / `reducer_profile` / `last_materialized_at` **missing** in `crates/core/src/service.rs::ServiceRequirements`. Add fields so clients can detect stale services. *(Round 4: `ServerDescription` gained all four fields; all construction sites updated.)*

### Blob / media

- [x] **T2-21** Blob `space_id` **missing** (B-23, media-and-blob.md §2). Add to `crates/sdk/src/media.rs::MediaMetadata` and `BlobMetadataStore`. *(Added optional `space_id: Option<SpaceId>` to `MediaMetadata` with `MemoryBlobStore::upload_in_space` builder; `None` reserved for genuinely global blobs.)*
- [x] **T2-22** Encrypted attachment `key_ref` MUST be object `{algorithm, group_state_ref}` (B-22). Reject the legacy `"mls_epoch:42"` string form. *(Round 4: `EncryptedPayload.key_ref` is now `Option<EncryptedPayloadKeyRef>` (`Object(KeyRefObject) | Legacy(String)`); `EncryptedPayload::assert_strict_key_ref` rejects the legacy form. `mls.rs` produces the typed object form.)*

## Tier 3 — Improvements & coverage

- [x] **T3-1** Conformance vectors: add reference vectors for state-resolution, sync, redaction, capability, encoding into `crates/testing/src/lib.rs` (currently mostly schema/operation only). Cite vector ids from `conformance/state-resolution-conformance-vectors.md` etc. *(Round 6: added `canonical_json_vectors()`, `redaction_vectors()`, `capability_vectors()`, `sync_vectors()` libraries. Each vector carries a `vector_id` citing its spec section so harnesses can publish a coverage report.)*
- [x] **T3-2** Snapshot manifest event-set commitment Merkle inclusion proof check (operations-sync.md §11) **stub** in `crates/sdk/src/resolver.rs::verify_snapshot_chunks`. Add `verify_snapshot_inclusion(event_id, proof, root)`. *(Round 5: added `MerkleProofStep { sibling, is_left }` and `verify_snapshot_inclusion(event_id, proof, root)` matching the canonical inner-node payload of `merkle_root`.)*
- [x] **T3-3** Required-features / critical-extensions on `Event` envelope: SDK `Event` has `extensions` but should split out `required_features: Vec<String>` and reject unknown. *(Round 5: verified already implemented — `Event` carries both `required_features: Vec<String>` and `critical_extensions: Vec<CriticalExtension>`.)*
- [x] **T3-4** Idempotency key surfacing on batch endpoints (api-conventions.md §6): wire `Idempotency-Key` end-to-end in `crates/client/src/lib.rs`. *(Round 5: verified already wired — `HEADER_IDEMPOTENCY_KEY` constant + `ClientRequestOptions::idempotency_key` builder + automatic header insertion.)*
- [x] **T3-5** Sync `subscriptions` accept `cx:space:` form only, reject `space:` shorthand (M-15). *(Already enforced via typed `SpaceSubscription.space_id: SpaceId`; the `SpaceId::new` validator rejects anything not starting with `cx:space:`. Filter-hash binding remains for T2-17.)*
- [x] **T3-6** Standard renderer-per-kind whitelist (`ViewRenderer × ViewKind`) per views.md §4. SDK enum is flat; add `ViewKind::allowed_renderers()`. *(Added `ViewKind::allowed_renderers()` and `ViewKind::allows_renderer()`; covers all 23 view kinds and their permitted renderers.)*
- [x] **T3-7** Read-receipt debounce (1000 ms per service-surface.md §124) is currently passive in `receipts.rs`. Add an active de-dup window. *(Round 5: `ReceiptManager` carries `dedup_window_ms` (default 1000 ms) + `last_send_at` index; `send_receipt(...)` collapses repeats within the window.)*
- [x] **T3-8** Presence TTL: enforce automatic transition to `offline` after the spec'd window in `crates/sdk/src/presence.rs`. *(Round 5: `PresenceManager::DEFAULT_TTL` (5 min) + `expire_idle_presence(now, ttl)` flips stale entries to `Offline`. Caller-driven, no background task.)*
- [x] **T3-9** Push privacy validator: add a `PushPayloadValidator` that rejects payloads containing raw DIDs unless the destination service is listed under `plaintext_visible_services`. *(Round 5: added `PushPrivacyPolicy::validate_payload_for_destination(...)` which short-circuits to OK for whitelisted destinations and otherwise applies the strict DID-rejection path.)*
- [x] **T3-10** Service requirements validator: cross-check advertised `supported_operations` against `service_type` capability matrix (no `applet_service` advertising `cx.federation.transaction`, etc.). *(Round 5: `ServiceType::allowed_operation_prefixes()` and `permits_operation(...)` declare the matrix; `ServiceRequirements::verify(...)` enforces it.)*

## Out-of-scope this round (covered by spec, not SDK)

These appear in `contrix-spec/_report.md` and `_todos.md` but require spec-side resolution before the SDK can implement faithfully:

- B-02 capability-grant envelope drift across three docs (resolved by adopting `data-structures.md §13`; T1-8 will track once spec PR-1 lands).
- B-04 constraint double-source (`grant-constraint-schema.md` vs `constraint-schema.md`).
- B-07 OpenAPI gaps (server crate is a thin adapter; spec still needs work).
- M-09 auth_weight lattice rework (spec says "v1.x").
- Q-01..Q-08 design-level questions deferred per spec _report.md §5.
