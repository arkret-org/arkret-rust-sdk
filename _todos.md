# contrix-rust-sdk Active TODO

更新时间: 2026-05-02

本文件按 Contrix v1 最新规范重排。已完成的历史拆分工作不再逐条保留；未勾选项是后续可执行任务。

完成记录: 2026-05-02 已对 SDK 边界、artifact drift API、core event store、Operation draft -> Event Envelope、schema payload catalog、proof verifier、rank/rebalance、Board reducer、fixture runner 与 DoD 命令完成实现和验证。

## 0. 当前边界

- [x] Rust workspace 已拆出 identifiers、events、api、client-api、federation-api、push-gateway-api、identity-api、signatures、state-res、operations、schema、store、crypto、ui、testing、ffi 等 crate。
- [x] SDK 已有 typed ID、canonical JSON、HLC、cursor、proof、service description、client/server API glue、store/crypto/UI/testing 初始能力。
- [x] README 仍描述 “Repo commits / signed Operation envelopes” 为主路径，需要改成 v1 当前结论: wire canonical fact 是 signed `Event Envelope`，Operation 只是 SDK builder / 离线草稿中间对象。
- [x] SDK crate 边界还需要按 `artifacts/registry/*` 和 `artifacts/schemas/*` 重新校验，避免继续承载旧 operation-first 语义。

## P0: 协议工件同步与代码生成

这组任务可与 `contrix-spec` artifact lint 并行推进。

- [x] 建立 `contrix-spec/artifacts` 导入器:
  - 读取 schema registry、event-kind registry、operation registry、id-kind registry。
  - 生成或校验 Rust 常量、enum、typed ID 前缀、schema id、event kind、service operation id。
  - 在 CI 中检测本地 hardcoded registry 与 spec artifact drift。
- [x] 将 `cx.schema.event.v1` 作为主 wire model:
  - `EventEnvelope` 顶层字段覆盖 `event_id`、`space_id`、`actor_id`、`actor_seq`、`kind`、`created_at`、`hlc`、`prev_refs`、`auth_refs`、`content`、`proofs`。
  - `required_features`、`critical_extensions`、`schema_profile_refs`、`reducer_profile_ref` 必须参与 canonical bytes、event digest 和 proof payload hash。
  - Unknown non-critical 字段在 decode/store/forward/backfill/hash/signature 校验路径中保留。
- [x] 降级 Operation 为内部 builder:
  - `crates/operations` 输出必须显式转换为 `EventEnvelope` 后才能交给 network/reducer/sync/federation。
  - 删除或标记任何“wire Operation Envelope”公共 API。
  - `operation_id` 只能作为服务 operation id 或旧客户端本地幂等别名；不能进入独立排序、去重或签名规则。
- [x] 补齐 JSON Schema validator catalog:
  - Event envelope 先验 schema。
  - `Event.kind -> payload schema` 二级校验。
  - canonical object schema。
  - DTO schema。
  - negative vectors 和 unknown-field preservation tests。

## P0: Core Event Store 与签名链

可由 `identifiers`、`events`、`signatures`、`store`、`server` 并行分工。

- [x] 实现 `cx.profile.core_event_store.v1` SDK surface:
  - event submit/fetch/batch-get/backfill/frontier request/response。
  - Event idempotent duplicate accept。
  - Same `event_id` different canonical bytes conflict。
  - per-actor `actor_seq` monotonic validation。
  - `prev_refs` causal dependency validation。
  - `auth_refs` minimal dependency validation hook。
- [x] 固化 canonical digest:
  - Event digest。
  - encrypted payload digest。
  - event batch receipt digest。
  - snapshot manifest digest。
  - federation transaction canonical body hash。
- [x] 建立 proof verifier trait:
  - DID resolver 输入。
  - verification method key lookup。
  - payload hash check。
  - domain / audience / service DID binding。
  - created/expires/replay window。
- [x] 补齐 HLC/cursor/rank helpers:
  - HLC 文本格式 `<unix_ms_hex_12>-<logical_hex_4>-<node_id_hash_8>`。
  - opaque cursor encode/decode 只供服务端使用；客户端类型不得暴露内部字段依赖。
  - `rank_between`、`rank_exhausted`、`cx.container.rebalance` assignment generator。

## P0: Reducer、State Resolution 与 Authz

这些任务是 `state-res`、`schema`、`testing` 的主要工作，可与 server runtime 并行。

- [x] `state-res` 支持规范 state keys:
  - Space policy / schema / membership / join rule / history visibility。
  - Room membership。
  - Capability grant/revoke frontier。
  - Device/key state。
  - Moderation/policy component state。
- [x] 实现 deterministic event order:
  - causal dependency。
  - actor chain。
  - HLC。
  - event id tie-break。
  - 禁止使用数据库自增 ID 或接收顺序。
- [x] 实现 Board/List/Card reducer:
  - `contains` Relation position edge。
  - `(board_id, card_id)` 唯一主位置。
  - `cx.card.move` CAS。
  - `cx.card.reorder` 不跨 List。
  - `cx.list.reorder`。
  - duplicate active position loser 记录到 `conflict_records`。
- [x] 实现 capability engine reference:
  - resource selector AST。
  - grant/delegation 展开。
  - delegation cycle detection。
  - claim/attestation verifier hook。
  - approval/proposal constraints。
  - explicit revoke。
  - `allow/deny/soft_fail/quarantine/require_review` result model。
- [x] Authz Snapshot Bitmap:
  - cache key 绑定 `space_id`、actor/device/session grant、resource selector、action family、membership frontier、grant/revoke frontier、claim status frontier、policy root、reducer profile。
  - grant/revoke/membership/policy/claim/device/key 变化时 stale。
  - 高频路径 stale cache 不得继续产生 allow。

## P0: Client Runtime

这组可由 client、store、ui、crypto 并行，但最终需要端到端合并。

- [x] Client sync:
  - `POST /api/v1/sync` initial/incremental。
  - `next_batch` 作为唯一 resume token。
  - `timeline.limited` gap repair。
  - `state_after` 应用。
  - lazy member loading。
  - to-device delivery acknowledgement。
- [x] Offline write queue:
  - 本地 canonical Operation draft。
  - EventEnvelope 生成。
  - actor_seq 分配与冲突恢复。
  - idempotency key。
  - retry/backoff。
  - rejected/soft-failed/conflict UX state。
- [x] Projection runtime:
  - Board projection DTO。
  - Chat timeline DTO。
  - Graph/tree lazy link DTO。
  - Inbox/notification DTO。
  - Access explanation。
  - Pending operation / conflict record store。
- [x] E2EE client:
  - MLS KeyPackage binding。
  - Welcome/Commit/Proposal event preservation。
  - device verification。
  - key backup/recovery。
  - encrypted event unable-to-decrypt state。
  - local search boundary for encrypted Spaces。

## P0: Server Runtime

这些任务可和 `soland` 并行；SDK 提供可复用的 framework-independent contracts。

- [x] Server endpoint registry 以 service operation registry 为源:
  - `/server/describe`。
  - `/events/*`。
  - `/sync/*`。
  - `/index/query`。
  - `/identity/*`。
  - `/blob/*`。
  - `/authz/*`。
  - `/federation/*`。
  - `/push/*`。
- [x] Middleware:
  - DID/session authentication。
  - HTTP Message Signature verification。
  - Idempotency-Key store。
  - rate limit。
  - standard error envelope。
  - request id propagation。
  - plaintext-visible service guard。
- [x] Salvo route generation:
  - 保持可选 feature。
  - route metadata 必须能导出 OpenAPI。
  - endpoint tests 对比 operation registry，避免路径/operation id 漂移。

## P1: Identity, Account and Discovery SDK

- [x] DID resolver adapters:
  - `did:uuid` public/private trust domain。
  - `did:web`。
  - `did:key`。
  - reserved `did:keri` trait shape。
  - normalized principal view + raw document sidecar。
- [x] DID proof helpers:
  - service account binding challenge。
  - device binding challenge。
  - resolve proof。
  - session grant proof。
  - domain/audience/origin/expiry/nonce binding。
- [x] Handle and progressive disclosure:
  - handle claim builder/verifier。
  - pairwise DID presentation response type。
  - disclosure policy private state type。
  - overbroad request rejection helper。

## P1: Federation and Push

- [x] Federation API:
  - HTTP Message Signature transcript。
  - Content-Digest。
  - `(origin, destination, txn_id)` idempotency。
  - destination service DID binding。
  - push/pull events with preserved actor signatures。
  - backfill authorization and plaintext visibility checks。
  - fork/quarantine evidence model。
- [x] Push gateway/client:
  - `cx.profile.push_gateway.v1` type set。
  - register/unregister request/response。
  - notify blind-wakeup validator。
  - push token redaction type。
  - push rule / notification projection DTO。

## P1: Test and Release Evidence

- [x] `contrix-testing` fixture package:
  - load official fixtures from `contrix-spec/artifacts/fixtures`。
  - expose negative vectors。
  - support feature/profile selection。
  - generate conformance report JSON/Markdown。
- [x] Property/fuzz targets:
  - canonical JSON。
  - typed IDs。
  - HLC。
  - cursor。
  - rank generation。
  - event digest/proof。
  - grant selector AST。
- [x] Interop smoke:
  - SDK client against `soland`。
  - identity resolver against `starid`。
  - push registration against `soland` + `floria` mock。
  - federation minimal two-node flow。
  - encrypted Space key lifecycle smoke。
- [x] Release readiness:
  - feature matrix distinguishes "types only", "validator", "client runtime", "server runtime", "production adapter", "interop tested"。
  - README/docs updated to Event Envelope terminology。
  - no public API promises Operation-first semantics as Contrix v1 wire。

## Definition of Done

- [x] `cargo fmt --all -- --check`。
- [x] `cargo check --all-features`。
- [x] `cargo test --all-features`。
- [x] Artifact drift check passes against `contrix-spec/artifacts`。
- [x] `cotest` can consume SDK fixture runner for at least `core_event_store`。
- [x] README no longer describes Repo/Operation as v1 canonical wire truth。
