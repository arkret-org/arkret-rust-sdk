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

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| W1 ⚠ | `[ ]` | Event envelope 移除 `state_key` 字段 | `crates/core/src/canonical.rs`、`crates/state-res/src/lib.rs` | wire-breaking。`encode_state_key` / `decode_state_key_parts` 改为 reducer-side helper（subject 派生工具），不再是 wire 字段。需要重写 19 行测试。 |
| W2 ⚠ | `[ ]` | state-res 主键改为 `(space_id, kind, subject?)` | `crates/state-res/src/lib.rs` | `state_key_for_event` / `state_map_key` 改用 schema registry 的 `state_cardinality` + `state_subject_field` 派生 subject；singleton kind 主键退化为 `(space_id, kind)`。 |
| W3 ⚠ | `[ ]` | 17 个 per-facet kind 加 typed envelope + payload | `crates/sdk/src/space.rs` 或新 `crates/sdk/src/space_state.rs` | 覆盖 `cx.space.policy / join_rule / history_visibility / discovery / policy_server / policy_components / history_sharing_policy / asset_privacy_policy / moderation_policy / plaintext_visible_services / media_service / schema / inheritance_policy / archive / freeze / tombstone / destroy`。 |
| W4 ⚠ | `[ ]` | 移除旧聚合 kind builder | `crates/sdk/src/space.rs`、`crates/sdk/src/membership.rs` | `cx.space.policy.set` / `cx.space.lifecycle.set` 的 builder API 删除（spec 已硬移除）。 |
| W5 🅿 | `[ ]` | `cx.consent.*` typed model | 新 `crates/sdk/src/consent.rs` | grant / revoke + scope enum (`invite` / `direct_message` / `voice_call` / `video_call` / `presence` / `any`) + valid_until + evidence_ref。 |
| W6 ⚠ | `[ ]` | `host_endorsement` proof 类型 | `crates/core/src/proofs.rs`（或类似）、`crates/sdk/src/wire.rs` | `ProofKind` 加 `HostEndorsement { host_did, endorsed_at }`；canonical event bytes 计算保持不变（host endorsement 与 actor proof 都覆盖相同 canonical bytes）。需要 host endorsement 验证 helper：`verify_host_endorsement(event, current_host_did)`。 |
| W7 ⚠ | `[ ]` | `cx.space.host` / `cx.space.host.transfer` typed model | `crates/sdk/src/space_host.rs`（新） | 含 smooth dual-sign / emergency governance-quorum 两 mode payload；transfer activation_frontier 边界辅助函数。 |
| W8 ⚠ | `[ ]` | `Space.space_writer_model` / `Space.space_host` 字段 | `crates/sdk/src/space.rs` Space schema mirror | create-locked 字段；客户端检测目标 Space 的 writer_model 决定提交路径（hub Space 必须经 host endpoint）。 |
| W9 🅿 | `[ ]` | Component metadata API（type/version/criticality 查询） | `crates/sdk/src/registry.rs`（或 `crates/schema/src/lib.rs`） | 新 helper `Registry::component(kind) -> ComponentDescriptor { component_type, component_version, criticality, slot_alias_of }`；与 schema-drift CI（Q2）联动。 |
| W10 ⚠ | `[ ]` | MLS application_state_ref + covered_frontier API | `crates/crypto/src/mls.rs`、`crates/sdk/src/mls.rs` | `cx_app_state_ref` GroupContext extension 编/解码（CBOR canonical）；`covered_frontier` 状态查询；`pending_mls_binding` 状态判断。 |
| W11 🅿 | `[ ]` | Composite state subject encoding helper（替代旧 composite state_key） | `crates/core/src/canonical.rs` | 保留 base64url(sha256(canonical_json([components...]))) 工具，但 rename 为 `encode_state_subject` / `decode_state_subject_components`，且明确这是 reducer 派生路径，不是 wire 字段。 |
| W12 🔒 | `[ ]` | SDK 升级到 wire-breaking major（v0.X → v0.Y 或 v1.0-pre） | 全 workspace | 单一 PR 一次性 break；不留 alias / shim（v1 未发布，无兼容包袱）。同步更新 `crates/*/Cargo.toml` 版本号、CHANGELOG。 |
| W13 🔒 | `[ ]` | `cargo test` workspace + clippy + fmt 全绿 | CI | 验证基线；与 cotest 联调前必须先本仓全绿。 |

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

- `[x]` R9 client/server configuration、CI/release、docs.rs metadata、deployment guide。
- `[x]` S2 清理旧 spec 路径和历史审计编号引用。
- `[x]` S3 constraint family API 对齐 v1.0（8 family + subtype）。
- `[x]` H5 server adapter examples 标注非生产 501。
- `[x]` Q1 公开 builder 过长参数改 option struct（`FlowCreateMetadata` / `FlowUpdateMetadata`）。
- `[x]` Q3 `cargo metadata` / release order 验证纳入本地 xtask。
- `[x]` H1 SDK 端 `StaridRegistryAdapter` doc 收敛。
- `[x]` H4 typed contract 去掉 wire 上的 `todo`/`note` 占位字段。
