# Contrix Rust SDK Active TODO

> 更新日期: 2026-05-01
> 范围: Contrix v1 共享协议模型、builders、validators、HTTP client/server contracts、crypto helpers、store traits 和 conformance runner。SDK 不替代具体 Principal Server、Identity Registry、Push Gateway 或客户端产品实现。

## 0. 当前边界

- 已有模型、canonical JSON/digest、HLC/cursor、operation/commit/capability、HTTP client、server endpoint registry、OpenMLS helpers 和大量本地 helper。
- 仍有不少功能是 facade / in-memory / contract-level 支持，不能标记为生产完成。
- 当前阶段允许破坏性更新，优先快速收敛到完整 Contrix-native 协议能力；不保留 legacy / Matrix 兼容 API。
- 0.1.x 继续作为 release-candidate；稳定版需要真实服务互操作、持久 store、外部安全审计、OpenAPI review 和 API freeze。

## P0: Matrix / Ruma Maturity Gap Roadmap

目标: 用 Matrix SDK / Ruma 的成熟度做参照，补齐 Contrix SDK 的协议深度、生产 runtime、持久化、crypto、联邦和 conformance，而不是只做表面 crate 拆分。

基准差距:

- 当前 Contrix SDK 约 55 个 Rust 文件、3.9 万行；本地 `matrix-rust-sdk` 约 468 个文件、18.6 万行；本地 `ruma` 约 816 个文件、11.2 万行。
- 当前代码已有较宽的协议面，但很多能力仍偏 contract / facade / in-memory，需要生产实现、互操作证据和协议级测试。
- 下一阶段优先做“基础层拆分 + 行为闭环”，每次拆 crate 都必须带来更清晰的所有权、验证边界或生产实现。
- 旧 release evidence 中的 `contrix-sdk` 是重组前包名；当前 umbrella package 是 `contrix`，crate 目录是 `crates/sdk`。

协议 crate 拓扑:

- [x] 新增 `crates/identifiers` / `contrix-identifiers`，对齐 Ruma 的 identifiers-validation 边界。
- [x] `contrix-core` 重导出 identifiers，保持 `contrix::{Did, SpaceId, Hlc, ...}` 使用路径。
- [x] identifier Serde 反序列化走构造器校验，避免无校验 wire value 进入模型。
- [x] 移除 operation legacy alias/profile，只接受 canonical `cx.*` operation kind。
- [x] 移除 sync `rooms` fallback，wire response 只保留 native `spaces`。
- [x] 移除 Matrix device scope 解析，只接受 `urn:contrix:client:device:{id}`。
- [x] 移除 agent `Legacy` 协议 variant 和 A2A legacy bridge helper。
- [x] 从 `core/src/model.rs` 继续拆出 `events` / `operations` / `schema` / `api` 模块或 crate，降低巨型 model 文件风险。
  - [x] 已新增 `crates/events`、`crates/api`、`crates/operations`、`crates/schema` 作为独立协议边界。
  - [ ] 后续将 `core::OperationKindRegistry` / `core::ProtocolSchemaRegistry` 的实现所有权迁入对应 crate，`core` 只保留稳定 wire model 和 canonical helpers。
- [ ] 明确 `core` 只保留稳定协议模型和 canonical helpers；runtime 状态机继续向 `sdk` 或专门 crate 下沉。

生产 runtime 缺口:

- [ ] Server runtime: 把 endpoint registry 接到真实 request dispatch、authn/authz、idempotency、rate limit、error envelope 和 Salvo route 生成。
  - [x] 提供 framework-independent routed dispatch，统一 route match、path params、query token 拒绝、standard error envelope 和 `X-Contrix-Operation-Id` response header。
  - [x] 将 routed dispatch 接入 Salvo adapter 自动路由注册，并加 catch-all 返回 Contrix 标准错误 envelope。
  - [x] 接入 framework-independent authn/authz/idempotency/rate-limit middleware：Bearer token principal、operation scope authorizer、mutating endpoint idempotency key enforcement、idempotent response replay/conflict detection、per-principal operation rate limit。
  - [ ] 将 middleware 状态后端从内存实现扩展到服务自有持久/分布式 store。
- [ ] Client runtime: 补全离线发送队列、幂等重试、增量恢复、gap repair、分页和通知联动。
  - [x] HTTP client retry 不再热循环：支持 bounded exponential backoff，并按 `Retry-After` 等待 429/503 等 transient status。
  - [x] 本地 sync/send queue 已有 idempotent transaction、retry timestamp、snapshot/restore 和 dependent cancellation。
  - [ ] 将 HTTP retry、send queue、sync gap repair 和通知联动合并成统一 durable client runtime。
- [ ] Store runtime: 将当前 trait / in-memory 能力推进到真实 SQLite / IndexedDB adapter、迁移、崩溃恢复和并发行为。
- [ ] Crypto runtime: 补齐多设备密钥生命周期、设备验证、备份恢复、迁移、失败恢复和跨实现向量。
- [ ] Federation runtime: 补齐事务验签、重放窗口、fork/quarantine、backfill authorization、pull/push 互操作流程。

Conformance 和发布门禁:

- [ ] 将 golden vectors、negative wire vectors、schema compatibility、state resolution、sync 和 federation 测试外置成可复用 fixture 包。
- [ ] 增加 property / fuzz 测试目标，优先覆盖 canonical JSON、identifier parsing、operation envelope、cursor 和 authz reducer。
- [ ] 建立跨实现 interop suite：client-server、server-federation、encrypted space/group、identity registry、push gateway。
- [ ] 更新 release evidence，区分“contract 已有”“本地 helper 已有”“生产 adapter 已有”“通过真实互操作”。

## P0: Protocol / SDK Boundary Backlog From Matrix Ecosystem Scan

参考扫描来源:
- Ruma 的边界: `ruma-common`, `ruma-events`, `ruma-client-api`, `ruma-federation-api`, `ruma-appservice-api`, `ruma-identity-service-api`, `ruma-push-gateway-api`, `ruma-signatures`, `ruma-state-res`, `ruma-html`, `ruma-macros`, identifier validation。
- Matrix Rust SDK 的边界: client runtime, base sync/state, crypto, sqlite/indexeddb stores, store encryption, qrcode, UI/timeline, bindings, testing, examples, labs, xtask。
- Matrix Bot SDK 的边界: bot client, appservice, admin APIs, storage adapters, preprocessors, strategies, content scanner, identity, metrics/logging, E2EE, external encryption adapter。

目标边界:
- [ ] SDK 不只提供基础 HTTP client/server glue；它必须覆盖协议类型、API endpoint、事件系统、状态归并、加密、存储、同步、联邦、机器人/桥接、UI runtime、测试工具和平台绑定。
- [ ] 保持 Contrix-native 术语和模型，不恢复 Matrix compatibility layer；参考项目只用于发现协议 SDK 应有的完整边界。
- [ ] 对每个大功能建立验收标准: type model, endpoint model, client runtime, server dispatch, persistent store, conformance tests, examples, docs。
- [ ] 把产品业务逻辑和协议 SDK 边界分开: Principal Server 的产品规则留在上层，但协议级 API、验证、签名、同步、状态、存储 trait 必须在 SDK 内完整定义。

Crate topology:
- [x] 新增 `crates/events`: Contrix-native event taxonomy，覆盖 message/state/ephemeral/account-data/E2EE/call/RTC/collaboration/custom content，提供 unknown/custom raw preservation 和序列化测试。
  - [ ] 后续将 `core::Event` envelope 所有权进一步从 `core/src/model.rs` 迁入 event 边界，避免巨型 model 文件继续膨胀。
- [x] 新增 `crates/api`: client-server endpoint catalog、surface 分类、method/path/schema binding、参数 metadata，并由 server 测试校验与现有 endpoint registry 不漂移。
  - [ ] 后续将 server OpenAPI 和 route registry 的 source of truth 迁到 `contrix-api`，server crate 只保留 runtime dispatch/middleware。
- [x] 新增 `crates/client-api`: Ruma-style client-server API contract，覆盖 account/session、UIAA-like interactive auth、device management、messaging、sync/sliding sync、media、moderation 和 call signaling。
  - [x] 已扩展 profile/presence、space lifecycle、membership、state、search/context、directory 和 extensibility discovery typed endpoint contract。
  - [ ] 后续把 `core/src/model.rs` 中散落 request/response 收敛到 `contrix-client-api`，并接入 server dispatch / generated OpenAPI source of truth。
- [x] 新增 `crates/federation-api`: server-server discovery, transaction, event, membership, backfill, query, key, policy, media endpoint 类型，包含 endpoint catalog、transaction envelope digest validation、replay window、quarantine/backfill/delta contract。
  - [ ] 后续把 federation endpoint source of truth、验签、重放窗口、fork quarantine 和 backfill authorization 接入真实 server dispatch / federation runtime。
- [x] 新增 `crates/appservice-api`: appservice registration, namespace, permissions, endpoint catalog, transaction slot, virtual actor intent, third-party lookup, bridge mapping store。
  - [ ] 后续将 `sdk::applet` 中重复的 appservice/appservice bridge 类型收敛到 `contrix-appservice-api`，避免双模型长期共存。
- [x] 新增 `crates/push-gateway-api`: push rule, pusher, notification payload, delivery receipt, gateway callback 类型，包含 pusher registration projection、encrypted push redaction、gateway endpoint catalog 和 rule-set facade。
  - [ ] 后续把 push rule evaluator、pusher store、gateway retry/delivery receipt、通知计数和 client runtime 通知联动做成生产闭环。
- [x] 新增 `crates/identity-api`: identity discovery, 3PID-like binding, verification, invitation lookup；明确独立 identity service 的 extension 边界，包含 DID document、handle binding、privacy-preserving invitation lookup 和 key log head。
  - [ ] 后续补充 handle proof 验证、外部 identity registry client/server contract、反枚举限流和真实 lookup privacy proof。
- [x] 新增 `crates/signatures`: canonical JSON/CBOR, signing key, verification key, key rotation, detached signature, federation auth header，当前覆盖 canonical payload hash、detached signature binding 和 HTTP message signature helper。
  - [ ] 后续接入真实签名算法抽象、key discovery/cache、rotation proof、federation auth header verifier 和 negative signature fixtures。
- [x] 新增 `crates/state-res`: deterministic state reducer、state-key extraction、conflict records、frontier maintenance、snapshot hash/verify。
  - [ ] 补 conflict graph、auth rule evaluation、snapshot/delta proof 和 federation backfill proof 验证。
- [x] 新增 `crates/operations`: operation registry、surface catalog、operation DAG validation、builder/conformance boundary。
  - [ ] 后续将 operation registry source of truth 从 `core/src/model.rs` 迁入 `contrix-operations`，并补 auth rule / semantic reducer / negative DAG vectors。
- [x] 新增 `crates/schema`: schema registry、generated validator catalog、compatibility table、negative schema vectors、schema evolution plan。
  - [ ] 后续将 schema document source of truth 从 `core/src/model.rs` 迁入 `contrix-schema`，并接入 OpenAPI/schema generation pipeline。
- [x] 新增 `crates/html`: rich text sanitizer、Markdown subset renderer、plain-text fallback、mention/link normalization、safe link preview extraction。
  - [ ] 后续用更完整 HTML parser/sanitizer adapter 替换当前 lightweight sanitizer，并补 media preview extraction / mention resolution store。
- [x] 新增 `crates/store`: runtime store traits, memory/sqlite/indexeddb feature adapters, migration contract, store lock, failure cache，当前覆盖 repo object store、event cache、snapshot store、migration/checksum、failure cache 和 memory conformance report。
  - [ ] 后续将 `sdk::store` 的 SQLite/IndexedDB/encrypted store facade 收敛到 `contrix-store` 契约，并补真实 adapter / migration / crash recovery。
- [x] 新增 `crates/crypto`: protocol crypto machine, key lifecycle, verification, media encryption, secret backup, encrypted store integration，当前覆盖 device key bundle、one-time key claim、secret backup descriptor、media encryption digest、unable-to-decrypt preservation 和 crypto store binding。
  - [ ] 后续将 `sdk::crypto` / `sdk::crypto_store` / `sdk::mls` 收敛到 `contrix-crypto`，接入真实 MLS machine、设备验证、key backup/restore 和跨实现向量。
- [x] 新增 `crates/ui`: timeline model, room/space list service, notification client, sync service, unable-to-decrypt hook, preview model，当前覆盖 timeline edit/redaction/reaction projection、space list activity/count sorting、push-rule notification evaluation 和 UTD item。
  - [ ] 后续将 `sdk::timeline` / `sdk::notifications` / `sdk::sync_client` 的 runtime 行为收敛到 `contrix-ui` 投影契约，并补 live update / gap repair / local echo。
- [x] 新增 `crates/testing`: fixture server, request/response golden tests, conformance harness, federation simulation, property test helpers 的初始 conformance report/vector 边界。
  - [ ] 后续把官方 fixtures loader、golden wire vectors、negative vectors、federation simulation 和 property-test helpers 从 crate 单元测试外置出来。
- [x] 新增 `crates/ffi`: UniFFI/WASM/mobile binding facade，稳定 opaque handles 和异步 callback contract，当前覆盖 handle table、FFI error、event sink、cancellation、WASM HTTP/IndexedDB/WebCrypto runtime contract 和 freeze review。
  - [ ] 后续生成真实 UniFFI/WASM binding，补 callback backpressure、host lifetime、mobile API freeze 和浏览器互操作测试。
- [ ] 评估是否需要 `crates/macros`: endpoint/event derive 宏、operation schema 宏、test vector generation；只在能显著减少重复时引入。
- [ ] 增加 `examples/`, `testing/`, `benchmarks/`, `xtask/`, `labs/` workspace 边界，避免所有验证逻辑挤在 crate 单元测试里。

本轮验证记录:
- [x] `cargo test -p contrix-events`。
- [x] `cargo test -p contrix-api`。
- [x] `cargo test -p contrix-appservice-api`。
- [x] `cargo test -p contrix-state-res`。
- [x] `cargo test -p contrix-server`。
- [x] `cargo test -p contrix-signatures`。
- [x] `cargo test -p contrix-federation-api`。
- [x] `cargo test -p contrix-push-gateway-api`。
- [x] `cargo test -p contrix-identity-api`。
- [x] `cargo test -p contrix-testing`。
- [x] 2026-05-01 runtime boundary crates: `cargo test -p contrix-store`。
- [x] 2026-05-01 runtime boundary crates: `cargo test -p contrix-crypto`。
- [x] 2026-05-01 runtime boundary crates: `cargo test -p contrix-ffi`。
- [x] 2026-05-01 runtime boundary crates: `cargo test -p contrix-ui`。
- [x] 2026-05-01 runtime boundary crates: `cargo test -p contrix-testing`。
- [x] 2026-05-01 protocol split crates: `cargo test -p contrix-operations`。
- [x] 2026-05-01 protocol split crates: `cargo test -p contrix-schema`。
- [x] 2026-05-01 protocol split crates: `cargo test -p contrix-html`。
- [x] 2026-05-01 protocol split crates: `cargo test -p contrix-testing`。
- [x] 2026-05-01 client API contract: `cargo test -p contrix-client-api`。
- [x] 2026-05-01 client API contract: `cargo test -p contrix-testing`。
- [x] `cargo check --all-features`。
- [x] 2026-05-01 runtime boundary crates: `cargo check --all-features`。
- [x] 2026-05-01 protocol split crates: `cargo check --all-features`。
- [x] 2026-05-01 client API contract: `cargo check --all-features`。
- [x] 2026-05-01 boundary crates: `cargo fmt --all -- --check`。
- [x] 2026-05-01 boundary crates: `cargo test --all-features`，all workspace tests/doctests passed。
- [x] 2026-05-01 boundary crates: `git diff --check`。
- [x] 2026-05-01 runtime boundary crates final: `cargo fmt --all -- --check`。
- [x] 2026-05-01 runtime boundary crates final: `cargo test --all-features`，all workspace tests/doctests passed。
- [x] 2026-05-01 runtime boundary crates final: `git diff --check`。
- [x] 2026-05-01 protocol split crates final: `cargo fmt --all -- --check`。
- [x] 2026-05-01 protocol split crates final: `cargo test --all-features`，all workspace tests/doctests passed。
- [x] 2026-05-01 protocol split crates final: `git diff --check`。
- [x] 2026-05-01 client API contract final: `cargo fmt --all -- --check`。
- [x] 2026-05-01 client API contract final: `cargo test --all-features`，all workspace tests/doctests passed。
- [x] 2026-05-01 client API contract final: `git diff --check`。

Client-server protocol API:
- [x] Account/session: register, login, refresh, logout, whoami, deactivate, account data, password/token/session renewal。
  - [ ] 后续接入真实 server runtime store、token rotation/revocation、account lifecycle 和 session renewal interop。
- [x] UIAA-like flows: 多步骤认证 challenge/response、fallback、retry、错误类型、server advertised flows。
  - [ ] 后续补 fallback HTML/URI、stage retry policy、server-advertised flow discovery 和 negative vectors。
- [x] Device management: device list, device display name, delete devices, key upload/query/claim, dehydrated/offline device。
  - [ ] 后续将 `sdk::devices` / key endpoints / dehydrated device runtime 收敛到 `contrix-client-api` contract。
- [x] Profile/presence: display name, avatar, status, activity, presence subscription, profile visibility。
  - [ ] 后续补 profile visibility policy、activity stream 和 presence server fanout runtime。
- [x] Space/room lifecycle: create, upgrade/migrate, delete/archive, aliases, canonical alias, visibility, directory listing, preview。
  - [ ] 后续补 upgrade/migrate/delete/archive server semantics、canonical alias collision policy 和 directory publishing workflow。
- [x] Membership: invite, join, leave, knock/request access, kick, ban, unban, membership reasons, third-party invite。
  - [ ] 后续补 third-party invite exchange、knock policy、membership auth rules 和 federation join proof。
- [x] Messaging: send event, send message, edit, redact, reaction, relation, thread, reply, poll, receipt, read marker。
  - [ ] 后续补 relation/thread/poll 的完整 event content schema 和 server validation。
- [x] State: get/set state, batch state, power/capability levels, tags, pinned events, policy events, room config。
  - [ ] 后续补 state-key typed content schemas、power/capability rule validation 和 policy-event conformance vectors。
- [x] Sync: full sync, incremental sync, sliding sync, sticky parameters, filters, timeline gaps, state deltas, to-device events。
  - [ ] 后续将 core sync models 和 `sdk::sync_client` durable runtime 收敛到 typed client API contract。
- [x] Search/context: global search, space search, message search, event context, nearest timestamp, pagination tokens。
  - [ ] 后续补 ranking contract、pagination token binding、nearest timestamp endpoint behavior 和 indexed store integration。
- [x] Media: upload, download, thumbnail, authenticated media, encrypted media, upload progress, content scanner hooks。
  - [ ] 后续补 streaming body、resumable upload state machine、scanner verdict enforcement 和 encrypted media decrypt pipeline。
- [ ] Push/notifications: pushers, push rules, notification settings, highlight count, unread count, notification client。
- [x] Reporting/moderation: report event/user/space, abuse categories, admin review hooks。
  - [ ] 后续补 admin review queue、policy propagation 和 moderation audit trail。
- [x] VoIP/RTC/calls: call event types, session negotiation, widget/call settings if Contrix protocol includes real-time collaboration。
  - [ ] 后续补 ICE server config、call membership/device mapping 和 widget/call settings contract。
- [x] Third-party/extensibility: custom event type, custom endpoint, feature discovery, unstable/labs namespace policy。
  - [ ] 后续补 unstable namespace lifecycle、custom endpoint registration validation 和 labs feature gates。

Event and content taxonomy:
- [ ] Message content variants: text, notice, emote, HTML/rich text, file, image, audio, video, voice note, document, location, sticker。
- [ ] Interactive variants: reaction, poll start/response/end, form/task update, acknowledgement, ephemeral indicator。
- [ ] Collaboration variants: operation batch, document patch, cursor/selection, typing/composing, presence, activity beacon。
- [ ] Call/RTC variants: invite, answer, candidates, hangup, negotiation, membership, device mapping。
- [ ] State variants: membership, profile, power/capability, policy, tags, pinned, topic/name/avatar, notification settings。
- [ ] Account-data variants: direct chats/spaces, ignored users, recent emoji, drafts, per-space settings。
- [ ] Ephemeral variants: typing, receipt, read marker, presence, transient device signals。
- [ ] E2EE variants: encrypted event, room key, forwarded key, key request, secret send/request, verification event。
- [ ] Unknown/custom event preservation: deserialize unknown type losslessly and reserialize without dropping fields。
- [ ] Unsigned metadata separation: age, transaction id, relation aggregation, redaction metadata, server annotations。
- [x] Rich text crate: HTML/rich text sanitizer, plain-text fallback, mention/link normalization, media preview extraction。
  - [x] `contrix-html` 覆盖 sanitizer、Markdown subset、plain-text fallback、mention/link normalization。
  - [ ] 后续补媒体 preview extraction、HTML parser adapter 和更多 malicious HTML negative fixtures。

State resolution and operation semantics:
- [ ] Define Contrix auth rules for state-changing operations: creator/admin/member/device/server authority。
- [ ] Implement deterministic conflict resolution for concurrent state updates, including tie-breakers and canonical ordering。
- [ ] Model event/operation DAG, causal edges, redaction/tombstone semantics, fork detection and quarantine。
- [ ] Implement snapshot + delta validation so clients can verify server-supplied state efficiently。
- [ ] Add property tests for commutativity/idempotency where protocol promises it。
- [ ] Add negative conformance vectors for invalid auth chains, stale membership, forged signatures, duplicate transaction ids。
- [ ] Document which parts are CRDT-like, which parts are server-authoritative, and which parts require federation consensus。

Client runtime:
- [ ] Durable sync service with start/stop/resume, cancellation, retry/backoff, token persistence, server timeout handling。
- [ ] Sliding sync/service-window support for large space lists and timeline subsets。
- [ ] Timeline service with live updates, pagination, gap repair, relation aggregation, redaction application, local echo。
- [ ] Event cache with chunks/gaps/origin tracking, bounded memory, persistent restore, deduplication。
- [ ] Send queue with persistent pending operations, retry classification, transaction id deduplication, offline resume。
- [ ] Event handler system with typed contexts, once/permanent handlers, async cancellation, ordering guarantees。
- [ ] Room/space list service with filters, sorting, unread counters, preview summaries, membership grouping。
- [ ] Notification client with push-rule evaluation, mentions, highlight/unread counts, quiet hours/mute state。
- [ ] Media client with progress callbacks, resumable upload/download, cache, encrypted media decrypt pipeline。
- [ ] Room/space directory search client with pagination and visibility filters。
- [ ] Account/profile convenience APIs mirroring protocol endpoints without hiding errors。
- [ ] Connection quality telemetry and failure cache to avoid hammering broken endpoints。

Storage:
- [ ] Memory store for tests and minimal runtime。
- [ ] SQLite state store with migrations, WAL config, transaction boundaries, schema versioning。
- [ ] IndexedDB/WASM state store for browser clients。
- [ ] Crypto store separated from state store but able to share encrypted backend。
- [ ] Store encryption crate/feature: passphrase/key-provider, key rotation, metadata authentication。
- [ ] Persistent send queue and sync token storage。
- [ ] Event cache tables with chunks/gaps, pagination tokens, timeline item projections。
- [ ] Media cache with size limits, content hash validation, encrypted blob metadata。
- [ ] Store lock and multi-process/multi-tab coordination。
- [ ] Backup/restore/export tools for client stores。
- [ ] Benchmarks for store hot paths: sync apply, timeline load, search index, crypto key lookup。

Crypto and E2EE:
- [ ] Crypto machine actor with explicit request/response queue for key upload/query/claim。
- [ ] Device identity model: local device, remote device, cross-signing/trust graph equivalent for Contrix。
- [ ] Key lifecycle: one-time/pre-key generation, upload accounting, rotation, exhaustion recovery。
- [ ] Session lifecycle: creation, inbound/outbound session tracking, replay protection, withheld keys。
- [ ] Secret storage: bootstrap, unlock, export, import, recovery key/passphrase。
- [ ] Key backup: server backup protocol, backup versioning, restore, verification, garbage collection。
- [ ] Secret gossiping: request/forward room secrets between own verified devices。
- [ ] Dehydrated/offline device support if protocol allows offline message bootstrap。
- [ ] Verification state machines: SAS, QR, request/accept/cancel/done flows, timeout handling。
- [ ] QR code crate or feature for verification payload generation/scan parsing。
- [ ] Unable-to-decrypt hook and retry/deferred-decrypt pipeline for UI/runtime。
- [ ] Encrypted media: attachment encryption, digest, key metadata, streaming decrypt。
- [ ] Encrypted store integration and test vectors for corrupted/tampered ciphertext。
- [ ] Clear threat model and compatibility story for native Contrix crypto, without inheriting Matrix Olm naming。

Federation:
- [ ] Server discovery: well-known, delegated server, signing key discovery, version/feature discovery。
- [ ] Federation transaction format with idempotency, retry, ordering, batching, failure classification。
- [ ] Signature verification for incoming federation requests and events。
- [ ] Event authorization and auth-chain validation across servers。
- [ ] Membership federation: invite, join, leave, knock/request, reject, ban, partial-state join。
- [ ] Backfill and gap repair across servers with state/auth proof validation。
- [ ] Query APIs: profile, room/space state, directory, keys, devices, third-party data。
- [ ] Federation media, including authenticated/encrypted media and remote thumbnail policy。
- [ ] Policy/moderation propagation: server blocks, user blocks, room policy, content takedown。
- [ ] Replay/fork/quarantine stores and admin introspection APIs。
- [ ] Federation conformance simulator with multiple local servers and adversarial cases。

Appservice, bot, and bridge:
- [ ] Appservice registration model with namespaces, sender/localpart, rate limits, permissions。
- [ ] Salvo appservice router: transaction, query_user, query_room_alias, key query/claim, third-party lookup。
- [ ] Transaction slot/ack model so bridge code can process batches safely and idempotently。
- [ ] Intent API for virtual actors: ensure registered, ensure joined, send message/event/state, redact。
- [ ] Membership operations: invite, kick, ban, unban, leave, set power/capability。
- [ ] Bridge mapping store: remote user, remote room, portal/space, puppet/device metadata。
- [ ] Bot command framework: preprocessors, filters, strategies, mention parsing, permission checks。
- [ ] Bot storage adapters: memory/sqlite/postgres traits and migrations。
- [ ] Admin client APIs: user CRUD, room/space list/details/members/state, purge/delete, media listing, shadow ban。
- [ ] Content scanner integration for uploads and remote media。
- [ ] Metrics/logging middleware with request ids, transaction ids, redaction of secrets。
- [ ] External encryption adapter boundary for deployments that delegate E2EE to another process。

Server runtime:
- [ ] Salvo first-class server crate with route generation from endpoint metadata。
- [ ] Shared request extraction: auth token, device id, user id, server signature, transaction id。
- [ ] Middleware stack: tracing, metrics, rate limit, CORS, body limits, auth, federation signature verification。
- [ ] Endpoint error mapping with stable error codes and JSON bodies。
- [ ] Streaming body support for media upload/download。
- [ ] Server-side store traits for accounts, devices, rooms/spaces, state, media, federation queues。
- [ ] Background workers for push delivery, federation send, media cleanup, key upload accounting。
- [ ] Admin route group separated from client/federation/appservice route groups。
- [ ] No Axum support; remove any future accidental Axum feature from workspace policy.

UI-facing SDK:
- [ ] Timeline item projection: message, state update, virtual day divider, read receipt, typing, local echo, error item。
- [ ] Room/space list model: grouped, filtered, sorted, unread/highlight counters, preview text。
- [ ] Sync service facade with observable state: offline, catching up, live, error, terminated。
- [ ] Notification settings and notification evaluation client。
- [ ] Pinned events cache and room preview service。
- [ ] Widget/call settings boundary if protocol embeds collaborative widgets/calls。
- [ ] Stable DTOs for mobile/UI bindings so UI apps do not depend on raw protocol internals。

FFI, WASM, and platform:
- [ ] UniFFI bindings for client, store, crypto, timeline, sync, media, appservice admin subsets。
- [ ] WASM package with IndexedDB store, WebCrypto integration where possible, browser fetch adapter。
- [ ] Mobile callback model for long-running sync, media progress, verification, notification。
- [ ] Cancellation and shutdown semantics across FFI boundary。
- [ ] API freeze/golden tests for generated bindings。
- [ ] Example apps for CLI, bot, web/WASM, and mobile binding smoke tests。

Testing, conformance, and release evidence:
- [ ] Protocol golden fixtures for every event and endpoint request/response。
- [ ] Negative fixtures for malformed JSON, unknown fields, wrong signatures, invalid ids, auth failures。
- [ ] Wiremock/fake server tests for client runtime。
- [ ] Multi-server federation tests with deterministic clocks and failure injection。
- [ ] Crypto test vectors for keys, sessions, backups, encrypted media, store encryption。
- [ ] State resolution property tests and fuzz targets。
- [ ] Serialization snapshot tests across all public protocol types。
- [ ] Benchmark suite for sync apply, state resolution, crypto decrypt, store load, route dispatch。
- [ ] CI matrix for feature combinations: default, server, salvo, crypto, sqlite, indexeddb/wasm, ffi。
- [ ] Release checklist mapping every public SDK API to spec section and conformance coverage。

Docs and examples:
- [ ] Architecture guide explaining crate responsibilities and extension points。
- [ ] Client quickstart: login, sync, send message, timeline, media。
- [ ] Server quickstart: Salvo routes, auth extractor, storage implementation, federation toggle。
- [ ] Appservice/bot quickstart: registration, namespaces, intents, command handler。
- [ ] Crypto guide: bootstrap, verification, backup, recovery, encrypted media。
- [ ] Store guide: memory/sqlite/indexeddb, migrations, encryption, backup。
- [ ] Federation guide: discovery, signing keys, transactions, backfill, failure handling。
- [ ] Protocol evolution guide: stable vs unstable/labs endpoints, deprecation policy, feature flags。
- [ ] Migration notes for current breaking workspace split, explicitly stating Axum support was replaced by Salvo。

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
  - [x] 旧 `cx.task.move`、`cx.task.reorder`、`cx.relation.move`、`cx.relation.rebalance` 已移除。
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
  - [x] no legacy adapter profile。
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
  - [x] Axum support removed from SDK。
  - [x] Salvo adapter is the current framework integration。
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
  - [x] canonical `urn:contrix:client:device:{id}` scope helper; Matrix scopes rejected。
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
