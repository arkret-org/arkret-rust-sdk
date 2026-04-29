# Contrix Rust SDK Active TODO

> 更新日期: 2026-04-29
> 范围: Contrix v1 共享协议模型、builders、validators、HTTP client/server contracts、crypto helpers、store traits 和 conformance runner。SDK 不替代具体 Principal Server、Identity Registry、Push Gateway 或客户端产品实现。

## 0. 当前边界

- 已有模型、canonical JSON/digest、HLC/cursor、operation/commit/capability、HTTP client、server endpoint registry、OpenMLS helpers 和大量本地 helper。
- 仍有不少功能是 facade / in-memory / contract-level 支持，不能标记为生产完成。
- 0.1.x 继续作为 release-candidate；稳定版需要真实服务互操作、持久 store、外部安全审计、OpenAPI review 和 semver API freeze。

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
- [ ] 每个 public tag 生成 release evidence:
  - [x] `cargo fmt --all -- --check`。
  - [x] `cargo check --no-default-features`。
  - [x] `cargo check --no-default-features --features client`。
  - [x] `cargo check --no-default-features --features server`。
  - [x] `cargo check --no-default-features --features mls`。
  - [x] `cargo check --all-features`。
  - [x] `cargo clippy --all-features --all-targets -- -D warnings`。
  - [x] `cargo test --all-features`。
  - [ ] generated OpenAPI reviewed against `contrix-spec`。
  - [ ] `cargo semver-checks` before non-patch release。
- [ ] Real interoperability:
  - [ ] `soland` Principal Server flow。
  - [ ] `starid` DID registry flow。
  - [ ] `floria` push gateway flow。
  - [ ] `chask` client integration flow。
  - [ ] federation two-service smoke。
- [ ] Security review:
  - [ ] canonical signing/proof binding。
  - [ ] MLS transcript and persistence。
  - [ ] encrypted storage contracts。
  - [ ] token/log redaction。
  - [ ] unsafe feature combinations。

并行性: release evidence、interop, security review 可并行；tag 前必须全部汇总到 release evidence 文档。

## P0: Durable Store Adapters

目标: 将 in-memory/facade store 升级为可用于真实客户端和服务的持久实现。

- [ ] SQLite repo store:
  - [ ] migrations。
  - [ ] transactional operation/commit insert。
  - [ ] idempotency and conflict detection。
  - [ ] cursor/state/event indexes。
  - [ ] crash recovery tests。
  - [ ] concurrent reader/writer behavior。
- [ ] Browser IndexedDB repo store:
  - [ ] repo objects。
  - [ ] sync cursors。
  - [ ] state snapshots。
  - [ ] quota handling。
  - [ ] restart survival。
  - [ ] WASM integration tests。
- [ ] Crypto store:
  - [ ] platform keychain/key store integration hooks。
  - [ ] encrypted-at-rest record format。
  - [ ] key rotation。
  - [ ] backup/restore。
  - [ ] rollback protection。
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
- [ ] Session grant contract:
  - [x] `SessionGrantPayload` with issuer/subject/principal DID/device/audience/scope/session/expires/revocation fields。
  - [x] durable `SessionGrantRecord` stores grant hash and revocation metadata without private key material。
  - [x] Principal Server notification request/response trait for created/revoked grants。
  - [x] canonical `urn:contrix:client:device:{id}` scope helper with legacy Matrix compatibility gated explicitly。
  - [ ] production JWT/JWS signing and verification adapter remains application-owned。
  - [ ] durable outbox/retry implementation remains service-owned。
- [ ] Handle verification:
  - [x] bidirectional DID document `also_known_as` check。
  - [ ] DNS TXT proof profile。
  - [ ] well-known proof profile。
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

- [ ] WASM support:
  - [ ] browser HTTP transport。
  - [ ] IndexedDB repo store。
  - [ ] IndexedDB crypto store。
  - [ ] WebCrypto integration hooks。
  - [ ] WASM sync/state/cache tests。
- [ ] UniFFI / mobile:
  - [x] stable opaque handles。
  - [x] callback-safe event stream。
  - [x] cancellation handles。
  - [x] Swift/Kotlin error mapping。
  - [ ] API freeze review before publishing。

## P1: High-Level Ergonomics

- [ ] Client helpers:
  - [x] login/session restore。
  - [x] send/edit/redact/reaction。
  - [x] media upload/download with authenticated blob model。
  - [ ] push registration integration with `chime` payloads。
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

- [ ] Feature is covered by unit tests and relevant conformance fixtures。
- [ ] Public API is documented with examples。
- [ ] Production claims require durable storage or explicit integration proof。
- [ ] Security-sensitive code has log redaction and negative tests。
- [ ] Feature matrix accurately states support level。
