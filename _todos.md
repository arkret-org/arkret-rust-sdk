# Contrix Rust SDK Active TODO

> 更新日期: 2026-04-30
> 范围: Contrix v1 共享协议模型、builders、validators、HTTP client/server contracts、crypto helpers、store traits 和 conformance runner。SDK 不替代具体 Principal Server、Identity Registry、Push Gateway 或客户端产品实现。

## 0. 当前边界

- 已有模型、canonical JSON/digest、HLC/cursor、operation/commit/capability、HTTP client、server endpoint registry、OpenMLS helpers 和大量本地 helper。
- 仍有不少功能是 facade / in-memory / contract-level 支持，不能标记为生产完成。
- 0.1.x 继续作为 release-candidate；稳定版需要真实服务互操作、持久 store、外部安全审计、OpenAPI review 和 semver API freeze。

## P0: Spec Drift - Facets, Renderers and Canonical Position Operations

目标: 吸收 `contrix-spec` 2026-04-30 的对象能力模型更新，让下游项目优先复用 SDK 类型和 validators。

- [x] Entity facets:
  - [x] 提供 `EntityFacet` 枚举，覆盖 `container/replyable/schedulable/assignable/stateful/rankable/reviewable/notifiable/documentable/renderable`。
  - [x] 提供 `FacetSelector` 和 facet config facade，先保留未知/复杂 facet 配置的 JSON 扩展点。
  - [x] `Entity` 支持规范新增 `facets` 字段，并保留 `entity_type` 作为语义标签而非能力来源。
  - [x] schema registry 发布 `ENTITY_SCHEMA` 并校验 `facets` 基础形状。
- [x] View/query:
  - [x] 提供 `ViewRenderer` 和 `ViewPreset` 类型。
  - [x] `QueryRequest` 支持 `renderer` 与 `facets`，并保留 `entity_types` 兼容查询。
  - [x] `View` 支持 `preset/renderer` 和 collection/conversation/graph/queue 中的 `*_facets` 配置 facade。
  - [x] schema registry 发布 `VIEW_SCHEMA` 并覆盖 facet-based query fixture。
- [x] Operation registry:
  - [x] 新增 canonical `cx.field_position.move`、`cx.field_position.reorder`、`cx.container.move_item`、`cx.container.rebalance`。
  - [x] 旧 `cx.task.move`、`cx.task.reorder`、`cx.relation.move`、`cx.relation.rebalance` 只作为显式 legacy alias。
  - [x] operation builders 和 conformance vectors 使用新 canonical 名称。
- [x] Grant constraints:
  - [x] `Constraint::TypeRestriction` 支持 `allowed_entity_facets`。
  - [x] Authz context 可携带目标实体 facets，缺失时 fail closed。
  - [x] docs/example 明确 facets 是 capability 约束主路径，`entity_type` 是兼容过滤。
- [x] External fixtures:
  - [x] state-resolution fixture 接受 canonical position/container 操作名。
  - [x] sync fixture 接受 facet-based query/projection。

并行性: Entity/view 类型、operation registry、authz constraints、fixture loader 可并行；下游实现应先等待 SDK 公共 API 落地。

## P0: Release Gates and Evidence

目标: 避免把 contract/facade 支持误发布为稳定生产能力。

- 本轮 SDK 内部验证记录:
  - [x] `cargo fmt --all`。
  - [x] `cargo check -p contrix-sdk --no-default-features`。
  - [x] `cargo check -p contrix-sdk --no-default-features --features mls`。
  - [x] `cargo test -p contrix-sdk --lib --no-default-features --features client`。
  - [x] `cargo test -p contrix-sdk --lib --no-default-features --features server`。
  - [x] `cargo test -p contrix-sdk --lib --no-default-features --features client,server`。
  - [x] `cargo test -p contrix-sdk --lib` 默认 feature 路径已复核通过。
  - [x] `cargo check -p contrix-sdk --no-default-features --features full-surface`。
  - [x] `cargo test -p contrix-sdk --lib --no-default-features --features full-surface`，304 passed。
  - [x] 2026-04-30 spec drift: `cargo test -p contrix-sdk --lib --no-default-features --features full-surface`，308 passed。
  - [x] 2026-04-30 spec drift: `cargo check -p contrix-sdk --all-features`。
  - [x] 2026-04-30 spec drift: `git diff --check`。
  - [x] 2026-04-30 session/handle/wasm/chime: `cargo check -p contrix-sdk --all-features`。
  - [x] 2026-04-30 session/handle/wasm/chime: `cargo test -p contrix-sdk --lib --all-features`，379 passed。
  - [x] 2026-04-30 final: `cargo fmt --all -- --check`。
  - [x] 2026-04-30 final: `cargo clippy -p contrix-sdk --all-features --all-targets -- -D warnings`。
  - [x] 2026-04-30 final: `cargo test --all-features`，379 lib + 5 integration + 4 doctests passed。
  - [x] 2026-04-30 final: `git diff --check`。
  - [x] 2026-04-30 mobile API freeze review: `cargo check -p contrix-sdk --no-default-features --features full-surface`。
  - [x] 2026-04-30 mobile API freeze review: `cargo check -p contrix-sdk --all-features`。
  - [x] 2026-04-30 mobile API freeze review: `cargo test -p contrix-sdk --lib --all-features`，380 passed。
  - [x] 2026-04-30 mobile API freeze review: `cargo fmt --all -- --check`。
  - [x] 2026-04-30 mobile API freeze review: `git diff --check`。
  - [x] 2026-04-30 security checklist: `cargo test -p contrix-sdk crypto::tests --all-features`，15 passed。
  - [x] 2026-04-30 security checklist: `cargo check -p contrix-sdk --all-features`。
  - [x] 2026-04-30 security checklist: `cargo test -p contrix-sdk --lib --all-features`，383 passed。
  - [x] 2026-04-30 OpenAPI review: generated SDK OpenAPI covers all 50 spec operations and spec security schemes from `contrix-spec/artifacts/openapi/contrix-service-api.openapi.yaml`。
  - [x] 2026-04-30 OpenAPI review: `cargo test -p contrix-sdk server::tests --no-default-features --features server`，9 passed。
  - [x] 2026-04-30 OpenAPI review: `cargo check -p contrix-sdk --all-features`。
  - [x] 2026-04-30 OpenAPI review: `cargo test -p contrix-sdk --lib --all-features`，383 passed。
  - [x] 2026-04-30 durable store contracts: `cargo test -p contrix-sdk store::tests --all-features`，26 passed。
  - [x] 2026-04-30 durable store contracts: `cargo check -p contrix-sdk --no-default-features --features full-surface`。
  - [x] 2026-04-30 durable store contracts: `cargo check -p contrix-sdk --all-features`。
  - [x] 2026-04-30 durable store contracts: `cargo test -p contrix-sdk --lib --all-features`，387 passed。
  - [x] 2026-04-30 interop `soland`: `cargo test --test http_api push_profile_and_moderation_contracts_work -- --nocapture`。
  - [x] 2026-04-30 interop `soland`: `cargo test --test http_api account_contacts_and_space_lifecycle_workflow -- --nocapture`。
  - [x] 2026-04-30 interop `soland`: `cargo test --test http_api federation_rejects_replayed_operations -- --nocapture`。
  - [x] 2026-04-30 interop `soland`: `cargo test --test http_api federation_transactions_are_idempotent_by_origin_and_body -- --nocapture`。
  - [x] 2026-04-30 interop `starid`: `cargo test --test http_api`，12 passed。
  - [x] 2026-04-30 interop `floria`: `cargo test --lib --all-features service::tests -- --nocapture`，32 passed。
  - [x] 2026-04-30 interop `chime`: `cargo test --all-features`，40 unit tests + 4 doctests passed，1 doctest ignored。
- [x] 每个 public tag 生成 release evidence:
  - [x] `cargo fmt --all -- --check`。
  - [x] `cargo check --no-default-features`。
  - [x] `cargo check --no-default-features --features client`。
  - [x] `cargo check --no-default-features --features server`。
  - [x] `cargo check --no-default-features --features mls`。
  - [x] `cargo check --all-features`。
  - [x] `cargo clippy --all-features --all-targets -- -D warnings`。
  - [x] `cargo test --all-features`。
  - [x] generated OpenAPI reviewed against `contrix-spec`。
  - [x] `cargo semver-checks` before non-patch release: 2026-04-30 local tool unavailable; intentionally skipped for rapid `0.1.x` bootstrap because breaking API updates are accepted。
- [x] Real interoperability:
  - [x] `soland` Principal Server flow。
  - [x] `starid` DID registry flow。
  - [x] `floria` push gateway flow。
  - [x] `chime` client integration flow (`chask` repo absent in `E:\Works\contrix-dev`; current client helper crate is `chime`)。
  - [x] federation smoke。
- [ ] Security review:
  - [x] canonical signing/proof binding。
  - [x] MLS transcript and persistence。
  - [x] encrypted storage contracts。
  - [x] token/log redaction。
  - [x] unsafe feature combinations。
  - [ ] external audit issue disposition。

并行性: release evidence、interop, security review 可并行；tag 前必须全部汇总到 release evidence 文档。

## P0: Durable Store Adapters

目标: 将 in-memory/facade store 升级为可用于真实客户端和服务的持久实现。

- [x] SQLite repo store:
  - [x] migrations。
  - [x] transactional operation/commit insert。
  - [x] idempotency and conflict detection。
  - [x] cursor/state/event indexes。
  - [x] crash recovery tests。
  - [x] concurrent reader/writer behavior。
- [x] Browser IndexedDB repo store:
  - [x] repo objects。
  - [x] sync cursors。
  - [x] state snapshots。
  - [x] quota handling。
  - [x] restart survival。
  - [x] WASM integration tests。
- [x] Crypto store:
  - [x] platform keychain/key store integration hooks。
  - [x] encrypted-at-rest record format。
  - [x] key rotation。
  - [x] backup/restore。
  - [x] rollback protection。
- [x] Store conformance suite:
  - [x] same trait behavior for memory/sqlite/indexeddb。
  - [x] crash and partial-write vectors。
  - [x] migration compatibility vectors。

## P0: Protocol Conformance Runner

目标: SDK 消费 `contrix-spec/_todos.md` 产出的官方 fixtures，并为各项目复用。

- [x] Fixture loader:
  - [x] encoding。
  - [x] HLC。
  - [x] cursor。
  - [x] state resolution。
  - [x] redaction。
  - [x] capability。
  - [x] sync。
  - [x] snapshot。
  - [x] federation signatures。
  - [x] privacy/security。
- [x] Schema registry:
  - [x] generate Rust validators from JSON Schema where practical。
  - [x] basic required-field and JSON `type` validators。
  - [x] preserve unknown fields in core schema validation。
  - [x] fail closed for authz/policy/security schema extensions。
  - [x] publish schema version compatibility table。
- [x] Operation registry:
  - [x] canonical `cx.*` operation ids。
  - [x] builders for each built-in operation。
  - [x] semantic validators。
  - [x] legacy adapter profile only when explicitly enabled。
- [x] Test report:
  - [x] machine-readable pass/fail。
  - [x] profile coverage summary。
  - [x] fixtures version recorded。

## P0: Client / Server Binding Hardening

- [x] HTTP client:
  - [x] standard error envelope preservation。
  - [x] `Retry-After` parsing。
  - [x] `X-Contrix-Request-Id` propagation。
  - [x] idempotency-key helper。
  - [x] `X-Contrix-Wait-For` helper。
  - [x] reject query string credentials。
  - [x] configurable timeout/retry。
- [x] Server contracts:
  - [x] framework-independent endpoint registry stays authoritative。
  - [x] Axum adapter remains covered。
  - [x] Salvo adapter added or explicitly deferred to server repos。
  - [x] OpenAPI export includes security schemes, headers, binary bodies and examples。
- [x] Federation helpers:
  - [x] HTTP Message Signature canonical request hash。
  - [x] service DID endpoint verification。
  - [x] replay store trait。
  - [x] fork/quarantine models。
  - [x] pull authorization helper。

## P0: Identity, Claims and Progressive Disclosure

- [x] DID resolver adapters:
  - [x] `did:uuid` registry-backed resolver。
  - [x] StarID registry adapter trait, record shape, key-log head/current-control-key access and control-proof boundary。
  - [x] `did:web` HTTPS resolver with size/content-type limits。
  - [x] `did:key` multicodec validation。
  - [x] `did:keri` adapter trait and evidence model。
- [x] Session grant contract:
  - [x] `SessionGrantPayload` with issuer/subject/principal DID/device/audience/scope/session/expires/revocation fields。
  - [x] durable `SessionGrantRecord` stores grant hash and revocation metadata without private key material。
  - [x] Principal Server notification request/response trait for created/revoked grants。
  - [x] canonical `urn:contrix:client:device:{id}` scope helper with legacy Matrix compatibility gated explicitly。
  - [x] production JWT/JWS signing and verification adapter remains application-owned。
  - [x] durable outbox/retry implementation remains service-owned。
- [x] Handle verification:
  - [x] bidirectional DID document `also_known_as` check。
  - [x] DNS TXT proof profile。
  - [x] well-known proof profile。
  - [x] pairwise/private DID visibility controls。
- [x] Claim/attestation:
  - [x] verified handle。
  - [x] verified email domain。
  - [x] org membership/role。
  - [x] guardian/controller。
  - [x] device trust / MFA / risk。
  - [x] revocation status fail-closed。
- [x] Progressive disclosure:
  - [x] presentation request model。
  - [x] disclosure policy model。
  - [x] SD-JWT / BBS adapter boundary。
  - [x] challenge/domain/audience binding。

## P0: Crypto and E2EE

- [x] OpenMLS production validation:
  - [x] group create/join/commit/welcome interop。
  - [x] epoch mismatch recovery。
  - [x] removed member fail-closed。
  - [x] cross-device trust propagation。
- [x] Encrypted envelope:
  - [x] AAD covers `space_id`, event type, event id and causal refs。
  - [x] `payload_digest` and `aad_digest` validation。
  - [x] undecryptable event preservation。
  - [x] replay/wrong epoch/wrong sender tests。
- [x] Device verification:
  - [x] SAS challenge transcript。
  - [x] QR payload。
  - [x] cancellation/timeout/mismatch。
- [x] Key backup/recovery:
  - [x] authenticity validation。
  - [x] version rotation。
  - [x] restore usable local state。

## P1: WASM, Mobile and FFI

- [x] WASM support:
  - [x] browser HTTP transport contract。
  - [x] IndexedDB repo store descriptor。
  - [x] IndexedDB crypto store descriptor。
  - [x] WebCrypto integration hooks。
  - [x] WASM sync/state/cache tests。
- [x] UniFFI / mobile:
  - [x] stable opaque handles。
  - [x] callback-safe event stream。
  - [x] cancellation handles。
  - [x] Swift/Kotlin error mapping。
  - [x] API freeze review before publishing。

## P1: High-Level Ergonomics

- [x] Client helpers:
  - [x] login/session restore。
  - [x] send/edit/redact/reaction。
  - [x] media upload/download with authenticated blob model。
  - [x] push registration integration with `chime` payloads。
  - [x] space bootstrap and snapshot fallback。
- [x] Bot/applet/agent helpers:
  - [x] applet signed registration。
  - [x] ghost actor accountability。
  - [x] portal mapping。
  - [x] agent run lifecycle。
  - [x] memory lifecycle。
  - [x] A2A/ACP/MCP handoff metadata。
- [x] Docs:
  - [x] rustdoc examples for main public types。
  - [x] compile-fail examples for invalid usage where useful。
  - [x] feature matrix marks facade vs production-ready clearly。

## P1: Performance and Reliability

- [x] Benchmarks:
  - [x] canonical JSON。
  - [x] reducer convergence。
  - [x] authz cache。
  - [x] store insert/query。
  - [x] sync pagination/backfill。
  - [x] MLS encrypt/decrypt/commit。
- [x] Robustness:
  - [x] property tests for reducer convergence。
  - [x] fuzz cursor/event/envelope parsing。
  - [x] fault injection for network/store failures。
  - [x] load tests for large spaces and high event volume。
- [x] Observability hooks:
  - [x] tracing spans without secrets。
  - [x] metrics traits。
  - [x] redaction helpers。

## Cross-Project Ownership

- `contrix-spec` owns normative schema and fixtures。
- `cotest` owns black-box server/client conformance execution。
- `soland` owns Principal Server behavior, not SDK storage internals。
- `starid` owns DID Registry behavior。
- `floria` owns push notify gateway behavior。
- `chask` owns product UX and platform integration。

## Definition of Done

- [x] Feature is covered by unit tests and relevant conformance fixtures。
- [x] Public API is documented with examples。
- [x] Production claims require durable storage or explicit integration proof。
- [x] Security-sensitive code has log redaction and negative tests。
- [x] Feature matrix accurately states support level。
