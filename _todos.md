# contrix-rust-sdk TODO

> 整理日期: 2026-05-07
> 范围: Contrix Rust typed model、client/server adapter、schema/artifact 消费、SDK helper。
> 协议参考: `../contrix-spec/spec/v1/artifacts/`。

## 当前状态摘要

- R1-R9 主体已完成；最近一次验证: fmt、clippy、workspace tests (527 passed)、doc warnings、salvo example 均通过。
- 当前开放项: spec-gated wire rename (S1)、DID resolver production adapter (H1)、device/recovery helper 从 scaffold 升级 (H2-H4)、schema drift CI 报告 (Q2)。

## 标记说明

- `[ ]` 未完成
- `[~]` 部分完成 / 等 spec 或 server
- `🅿` parallel-safe
- `🔒` sequential
- `⚠` wire / public API 高风险

## P0 · Spec-gated wire alignment

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| S1 ⚠ | `[~]` | `cx.did.proof` 字段命名等待 spec 决策 | `crates/sdk/src/identity.rs`、schema mirror | 历史建议是 `kind -> proof_kind`，但当前 `event-envelope.schema.json` 尚未采用。等 `contrix-spec` 登记后用 `#[serde(rename = "proof_kind", alias = "kind")]` 做一轮兼容。 |

## P0 · v1 wire model rework（spec Phase 1-5）⚠ 🔒

> 起源：`contrix-spec` 2026-05-07 完成 Phase 1-5。详见根 [`../_todos.md` C10.A](../_todos.md) 与 [`../contrix-spec/_state_todos.md`](../contrix-spec/_state_todos.md)。
>
> 本仓是 C10 链路的第一个串行 gate——SDK 没消化前，soland reducer 扩面 / cotest fixture refresh / yougen 真实 event submit 都在错误的 wire 上工作。
>
> **2026-05-07 进度**：W1+W2+W5+W6+W7+W8+W11 已落地；workspace 530+ lib tests 全绿。剩余 W9（component metadata API）/ W10（MLS state binding API）/ W12（version bump）作为 follow-up。

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| W1 ⚠ | `[x]` | Event envelope 移除 `state_key` 字段 | `crates/core/src/canonical.rs`、`crates/state-res/src/lib.rs` | `state_key_for_event` 不再回退到 `payload.state_key`：现在显式 `Protocol("legacy state_key field on event payload — spec Phase 1 requires typed subject fields")`。subject 全部从 typed payload 字段派生，按 schema registry `state_subject_field` 规则。 |
| W2 ⚠ | `[x]` | state-res 主键 + 新 kinds 注册 | `crates/state-res/src/lib.rs` | `is_state_event` 重写：覆盖 17 个 per-facet space kinds、`cx.space.host`/`host.transfer`、`cx.consent.grant`/`revoke`、`cx.profile.create`/`update`、`cx.device.authorized`/`revoked`、`cx.session.grant`、`cx.account.status`、`cx.view.*`、`cx.flow.branch.*`、`cx.policy.rule`。`state_map_key` 把共享 slot 的 paired kinds 映射到同一 family（`cx.capability.grant`/revoke 共享、`cx.profile.create`/update 共享、`cx.device.authorized`/revoked 共享、`cx.consent.grant`/revoke 共享）。新增 `composite_subject` helper 处理 `(flow_id,branch,actor_id)` 等复合 subject。 |
| W3 / W4 | `[x]` | 17 per-facet kinds 已通过 W2 wired in `is_state_event` + `state_key_for_event` typed 派生 | 同上 | 无独立 builder API（事件构造走通用 builder + typed payload struct）；旧聚合 kind `cx.space.policy.set` / `cx.space.lifecycle.set` 在 spec 端硬移除，SDK 不再 match。 |
| W5 🅿 | `[x]` | `cx.consent.*` typed model | 新 `crates/sdk/src/consent.rs` | `Scope` enum（6 个 + `Any`）、`ConsentGrantPayload` / `ConsentRevokePayload`、`ConsentState` 派生（含 valid_until 窗口检查 + `Scope::Any` 满足判定）。5 个单元测试。 |
| W6 ⚠ | `[x]` | `host_endorsement` proof 类型 | `crates/core/src/model.rs` | `Proof` 新增 `host_did: Option<Did>` + `endorsed_at: Option<DateTime<Utc>>`；`proof_kind::{DETACHED_JWS, HOST_ENDORSEMENT}` 常量；`Proof::validate()` 强制 `kind=host_endorsement` 时 host_did/endorsed_at 必填，其它 kind 必须为空（防泄漏）；`Proof::is_host_endorsement()` 判定 helper。10 处 Proof 字面量构造点同步增加 None 字段。 |
| W7 ⚠ | `[x]` | `cx.space.host` / `cx.space.host.transfer` typed model | 新 `crates/sdk/src/space_host.rs` | `SpaceHostPayload`（host_did + standby_hosts + activation_timeout_ms + endorsement_method + host_endpoint）、`SpaceHostTransferPayload`（mode enum + activation_frontier + smooth_dual_signature/governance_quorum_proof）；`TransferMode::{Smooth, Emergency}` + `validate()` mode-conditional invariants。5 个单元测试。 |
| W8 ⚠ | `[x]` | `Space.space_writer_model` / `Space.space_host` 字段 | `crates/core/src/model.rs` | `SpaceWriterModel::{Hub, PeerMesh}` enum 加 `derive(federation_policy)` 默认派生（closed/restricted/quarantine→Hub；open→PeerMesh；None→Hub sovereign-leaning）；`Space::derived_writer_model()` + `Space::validate_writer_model()` 强制 hub MUST 有 space_host、peer_mesh MUST NOT 有。 |
| W9 🅿 | `[ ]` | Component metadata API（type/version/criticality 查询） | `crates/sdk/src/registry.rs`（或 `crates/schema/src/lib.rs`） | 新 helper `Registry::component(kind) -> ComponentDescriptor { component_type, component_version, criticality, slot_alias_of }`；与 schema-drift CI（Q2）联动。**deferred 到下一轮**——当前 component metadata 由 schema registry JSON 直接消费，typed Rust API 是优化项。 |
| W10 ⚠ | `[ ]` | MLS application_state_ref + covered_frontier API | `crates/crypto/src/mls.rs`、`crates/sdk/src/mls.rs` | `cx_app_state_ref` GroupContext extension 编/解码（CBOR canonical）；`covered_frontier` 状态查询；`pending_mls_binding` 状态判断。**deferred 到下一轮**——需要先与 soland MLS commit 验证逻辑联调。 |
| W11 🅿 | `[x]` | Composite state subject encoding helper | `crates/core/src/canonical.rs` | `encode_state_subject` / `decode_state_subject_parts` 是新 canonical 名；`encode_state_key` / `decode_state_key_parts` 标 `#[deprecated]` 但仍可用（向后兼容期）。`FlowBranchMembership::state_subject()` 是新 method，`state_key()` deprecated alias。 |
| W12 🔒 | `[~]` | `cargo test` workspace + clippy + fmt | CI | workspace cargo test 全绿（530+ lib tests）；clippy/fmt 在最终发布前再过一轮。 |
| W13 🔒 | `[ ]` | SDK 升级到 wire-breaking major | 全 workspace `Cargo.toml` | 等 W9/W10 落地后一次性 bump。 |

## P1 · Production helper surface

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| H1 🅿 | `[~]` | Production DID resolver network adapter | `crates/sdk/src/identity.rs`、`crates/sdk/src/resolver.rs` | SDK 端 `StaridRegistryAdapter` doc 已收敛；production HTTP adapter 等 `starid` / public resolver policy。 |
| H2 🅿 | `[ ]` | Device message helper 从 scaffold 升级 | `crates/sdk/src/devices.rs` | 等 `soland /api/v1/device_messages/*` durable lifecycle。 |
| H3 🅿 | `[ ]` | Key verification helper 从 scaffold 升级 | `crates/sdk/src/devices.rs`、`crates/sdk/src/mls.rs` | 等 soland device verification reducer/state。 |
| H4 🅿 | `[~]` | Key backup / restore-ticket client 从 scaffold 升级 | `crates/sdk/src/devices.rs`、client crate | typed contract 上 wire 占位字段已删除；剩余升级等 soland recovery/key-backup durable store。 |

## P2 · API cleanup / quality

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| Q2 🅿 | `[~]` | schema drift constants 自动生成 | `crates/schema/src/lib.rs`、build tooling | `ArtifactDriftReport` 已带 `unlisted_event_kinds` 软信号；剩余把 soft signal 接到 CI/任务报告。 |

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C1 | 暴露 v1.0 constraint family/subtype typed model，给 soland/cotest/sodmin 使用。✅ 已完成。 |
| C5 | 提供 key-backup / restore-ticket / device-message typed client helper；cotest release gate 已覆盖 soland scaffold restore surface，SDK 仍需把 helper 从 scaffold 升级到 typed durable API。 |
| C6 | 提供公共 DID resolver / starid client helper；soland/cotest 已能发现 optional StarID resolver profile，SDK 仍需 live resolver adapter 与 StarID client helper。 |
| C10.A | **本仓是 C10 串行 gate 的第一站**——P0 W1-W13 是消化 spec Phase 1-5 wire 改动的全部本仓任务。SDK 升级前 soland / cotest / yougen 不应在 wire 上做改动。 |

## 已完成（changelog）

- `[x]` 2026-05-07 — **彻底移除旧 state_key 模型**（W11 second-pass cleanup）：
  - state-res `ResolvedStateEvent.state_key: String` → `subject: String`（reducer-internal subject 字段，不是 wire 字段）
  - `state_key_for_event` → `subject_for_event`、`state_map_key` → `state_slot_key`（含参数名 `state_key` → `subject`）
  - sdk 自有 `resolver::ResolvedStateEvent.state_key` → `subject`；私有 `state_key_for_event` → `subject_for_event`；测试 fixture `content: { state_key: ... }` 改为 `content: { actor_id: ... }`（spec-correct payload field）
  - sdk 自有 `subject_for_event` 也加了 legacy `payload.state_key` 拒绝逻辑，与 state-res 行为一致
  - client-api `StateGetRequest`/`StateSetRequest`/`StateEventResponse` 的 `state_key: String` 字段全部 → `subject: String`
  - 移除 `canonical::encode_state_key` / `decode_state_key_parts` deprecated 别名 + 对应 test
  - 移除 `FlowBranchMembership::state_key()` deprecated method
  - 移除 sdk 端所有 `#[deprecated]` `state_key` 别名（v1 未发布，无兼容包袱）
  - workspace `cargo test --workspace --lib` 全绿（22 crate test suites，0 failure）
- `[x]` 2026-05-07 — **W1+W2+W5+W6+W7+W8+W11 spec Phase 1-5 wire 改动 SDK 端首轮落地**：
  - state-res `state_key_for_event` 不再回退 `payload.state_key`；29 个 state event kind subject 全部走 typed payload 派生
  - state-res `is_state_event` 注册新 kinds（17 per-facet space + cx.space.host{,.transfer} + cx.consent.{grant,revoke} + 11 个原 Phase 1.B 漏网 state kind）
  - `Proof.host_did` + `Proof.endorsed_at` + `proof_kind::{DETACHED_JWS,HOST_ENDORSEMENT}` 常量；`validate()` 强制 host_endorsement 必填、其它 kind 禁带
  - `Space.space_writer_model: Option<SpaceWriterModel>` + `Space.space_host: Option<Did>`；`derive(federation_policy)` 默认派生 + create-time invariant 校验
  - 新模块 `consent` (5 tests) + `space_host` (5 tests)
  - canonical helpers `encode_state_subject` / `decode_state_subject_parts` 新名；旧 `state_key` API 走 `#[deprecated]` alias
  - workspace `cargo test --workspace --lib` 全绿（22 个 crate 共 530+ tests）
- `[x]` R9 client/server configuration、CI/release、docs.rs metadata、deployment guide。
- `[x]` S2 清理旧 spec 路径和历史审计编号引用。
- `[x]` S3 constraint family API 对齐 v1.0（8 family + subtype）。
- `[x]` H5 server adapter examples 标注非生产 501。
- `[x]` Q1 公开 builder 过长参数改 option struct（`FlowCreateMetadata` / `FlowUpdateMetadata`）。
- `[x]` Q3 `cargo metadata` / release order 验证纳入本地 xtask。
- `[x]` H1 SDK 端 `StaridRegistryAdapter` doc 收敛。
- `[x]` H4 typed contract 去掉 wire 上的 `todo`/`note` 占位字段。
