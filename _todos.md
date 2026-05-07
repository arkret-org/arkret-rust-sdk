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

## P0 · v1 wire model rework（spec Phase 1-5）⚠ 🔒 — **整体作废 (2026-05-08)**

> ⚠ **Supersession 通知 (2026-05-08)**：`contrix-spec` 已用 **Move / Anchor / Lattice** 三原语替换旧 state slot / hub-writer / host endorsement 模型（见 [`../contrix-spec/_state_todos.md`](../contrix-spec/_state_todos.md)）。本节 W1-W13 中：
>
> - **W1 / W2 / W11（subject helpers / state-res 主键 / canonical encoding）** — 概念被 cell_family / cell_subject 替代，仅作为基础构件部分保留；
> - **W3 / W4（17 per-facet space kind）** — 仍在 spec event-kind-registry 中存在，typed payload 部分保留；
> - **W5（cx.consent.*）** — typed model 必须重写为 consent cell or-set Move，旧 reducer slot 表述废弃；
> - **W6（host_endorsement proof）** — **整体作废**，相关 `Proof::host_did` / `endorsed_at` / `proof_kind::HOST_ENDORSEMENT` 删除；
> - **W7（cx.space.host / .transfer typed model）** — **整体作废**，`crates/sdk/src/space_host.rs` 整模块删除；
> - **W8（Space.space_writer_model / space_host）** — **整体作废**，相关字段 + `derived_writer_model()` / `validate_writer_model()` 删除；
> - **W9（component metadata API）** — 保留并复用；
> - **W10（MLS application_state_ref / covered_frontier）** — 改写为 covered_frontier cell 上的 Move precondition 检查；
> - **W12（cargo test workspace）** — 仍是验证基线；
> - **W13（major bump）** — 推迟到新 C10.A 完成后。
>
> **新工作请见根 [`../_todos.md` C10.A](../_todos.md) 与本文件下方 P0 · Move / Anchor / Lattice 章节。**

> 起源（历史）：`contrix-spec` 2026-05-07 完成 Phase 1-5。
>
> **2026-05-07 进度（已作废）**：W1+W2+W5+W6+W7+W8+W11 已落地；workspace 530+ lib tests 全绿。W9 已落地（保留）。

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| W1 ⚠ | `[x]` | Event envelope 移除 `state_key` 字段 | `crates/core/src/canonical.rs`、`crates/state-res/src/lib.rs` | `state_key_for_event` 不再回退到 `payload.state_key`：现在显式 `Protocol("legacy state_key field on event payload — spec Phase 1 requires typed subject fields")`。subject 全部从 typed payload 字段派生，按 schema registry `state_subject_field` 规则。 |
| W2 ⚠ | `[x]` | state-res 主键 + 新 kinds 注册 | `crates/state-res/src/lib.rs` | `is_state_event` 重写：覆盖 17 个 per-facet space kinds、`cx.space.host`/`host.transfer`、`cx.consent.grant`/`revoke`、`cx.profile.create`/`update`、`cx.device.authorized`/`revoked`、`cx.session.grant`、`cx.account.status`、`cx.view.*`、`cx.flow.branch.*`、`cx.policy.rule`。`state_map_key` 把共享 slot 的 paired kinds 映射到同一 family（`cx.capability.grant`/revoke 共享、`cx.profile.create`/update 共享、`cx.device.authorized`/revoked 共享、`cx.consent.grant`/revoke 共享）。新增 `composite_subject` helper 处理 `(flow_id,branch,actor_id)` 等复合 subject。 |
| W3 / W4 | `[x]` | 17 per-facet kinds 已通过 W2 wired in `is_state_event` + `state_key_for_event` typed 派生 | 同上 | 无独立 builder API（事件构造走通用 builder + typed payload struct）；旧聚合 kind `cx.space.policy.set` / `cx.space.lifecycle.set` 在 spec 端硬移除，SDK 不再 match。 |
| W5 🅿 | `[x]` | `cx.consent.*` typed model | 新 `crates/sdk/src/consent.rs` | `Scope` enum（6 个 + `Any`）、`ConsentGrantPayload` / `ConsentRevokePayload`、`ConsentState` 派生（含 valid_until 窗口检查 + `Scope::Any` 满足判定）。5 个单元测试。 |
| W6 ⚠ | `[x]` | `host_endorsement` proof 类型 | `crates/core/src/model.rs` | `Proof` 新增 `host_did: Option<Did>` + `endorsed_at: Option<DateTime<Utc>>`；`proof_kind::{DETACHED_JWS, HOST_ENDORSEMENT}` 常量；`Proof::validate()` 强制 `kind=host_endorsement` 时 host_did/endorsed_at 必填，其它 kind 必须为空（防泄漏）；`Proof::is_host_endorsement()` 判定 helper。10 处 Proof 字面量构造点同步增加 None 字段。 |
| W7 ⚠ | `[x]` | `cx.space.host` / `cx.space.host.transfer` typed model | 新 `crates/sdk/src/space_host.rs` | `SpaceHostPayload`（host_did + standby_hosts + activation_timeout_ms + endorsement_method + host_endpoint）、`SpaceHostTransferPayload`（mode enum + activation_frontier + smooth_dual_signature/governance_quorum_proof）；`TransferMode::{Smooth, Emergency}` + `validate()` mode-conditional invariants。5 个单元测试。 |
| W8 ⚠ | `[x]` | `Space.space_writer_model` / `Space.space_host` 字段 | `crates/core/src/model.rs` | `SpaceWriterModel::{Hub, PeerMesh}` enum 加 `derive(federation_policy)` 默认派生（closed/restricted/quarantine→Hub；open→PeerMesh；None→Hub sovereign-leaning）；`Space::derived_writer_model()` + `Space::validate_writer_model()` 强制 hub MUST 有 space_host、peer_mesh MUST NOT 有。 |
| W9 🅿 | `[x]` | Component metadata API（type/version/criticality 查询） | `crates/schema/src/lib.rs` | `SpecArtifactBundle::component(event_kind) -> Result<Option<ComponentDescriptor>>` 已落地；返回 `ComponentDescriptor { event_kind, component_type, component_version, criticality, component_slot_alias_of }`，`Criticality` 是 `required/optional/ignore` enum。`cx.capability.revoke -> cx.capability.grant` 别名链接也覆盖了。带单元测试 `component_descriptor_resolves_canonical_and_alias_kinds`。 |
| W10 ⚠ | `[ ]` | MLS application_state_ref + covered_frontier API | `crates/crypto/src/mls.rs`、`crates/sdk/src/mls.rs` | `cx_app_state_ref` GroupContext extension 编/解码（CBOR canonical）；`covered_frontier` 状态查询；`pending_mls_binding` 状态判断。**deferred 到下一轮**——需要先与 soland MLS commit 验证逻辑联调。 |
| W11 🅿 | `[x]` | Composite state subject encoding helper | `crates/core/src/canonical.rs` | `encode_state_subject` / `decode_state_subject_parts` 是新 canonical 名；`encode_state_key` / `decode_state_key_parts` 标 `#[deprecated]` 但仍可用（向后兼容期）。`FlowBranchMembership::state_subject()` 是新 method，`state_key()` deprecated alias。 |
| W12 🔒 | `[x]` | `cargo test` workspace + clippy + fmt | CI | 2026-05-07 final pass: fmt（auto-fixed `canonical.rs`/`model.rs`/`consent.rs`/`resolver.rs`/`state-res/lib.rs`）、clippy（修了 consent.rs `collapsible_if` x2 + redundant_clone x2、space_host.rs redundant_clone x1）、`cargo test --workspace --all-features` 538 passed / 0 failed / 2 ignored、rustdoc with `-D broken_intra_doc_links -D warnings`、`tools/check-publish-order.py` 22 crates 通过。 |
| W13 🔒 | `[ ]` | SDK 升级到 wire-breaking major | 全 workspace `Cargo.toml` | 等 W9/W10 落地后一次性 bump。 |

## P0 · Move / Anchor / Lattice typed model（取代旧 P0）⚠ 🔒

> 起源：`contrix-spec` 2026-05-08 用 Move/Anchor/Lattice 三原语替换旧模型。详见根 [`../_todos.md` C10.A](../_todos.md)。
>
> 本仓仍是 C10 链路第一个串行 gate——下游 soland / cotest / yougen 不应在 raw JSON 上做 Move/Anchor wire 改动。

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| M0 ⚠ | `[ ]` | 旧 W6/W7/W8 wire-breaking artifact 删除 | `crates/core/src/model.rs`（`Proof::host_did`/`endorsed_at`/`proof_kind::HOST_ENDORSEMENT`）、`crates/sdk/src/space_host.rs`（整模块删）、`Space.space_writer_model`/`space_host`/`derived_writer_model()`/`validate_writer_model()` | v1 未发布无兼容包袱；先删旧的避免新模型多一层判空。10+ 处 Proof literal 中的 None 字段同步清理。 |
| M1 ⚠ | `[ ]` | `Move` typed model + canonical bytes | 新 `crates/core/src/move_event.rs` | `Move { id, issuer, space_id, preconditions, effects, anchor_ref, refs, hlc, sig }`；`canonical_bytes(&Move) -> Vec<u8>` + `Move::id_from_bytes`；签名走通用 detached JWS。Preconditions: `head_eq` / `head_in` / `satisfies` / `contains`。Effect lattice ops: `add`/`remove`/`set`/`transition`/`inc`/`dec`/`append`。 |
| M2 ⚠ | `[ ]` | `Anchor` typed model + 三种签名形态 | 新 `crates/core/src/anchor.rs` | `Anchor { id, space_id, predecessor_refs, frontier, state_root, anchorer_sig, hlc }`；`AnchorerSig::{Single(Signature), Multi(Vec<Signature>), Threshold { threshold, signers, proof }}`；`canonical_bytes(&Anchor)`。 |
| M3 🅿 | `[ ]` | Cell ID + cell_family + cell_subject helpers | 新 `crates/core/src/cell.rs` | `CellId` 解析 `cx:cell:<component>:<subject>` 与等价 canonical tuple；与 spec event-kind-registry 的 `cell_family` / `cell_subject` 字段对齐；composite subject 通过 `composite` descriptor 派生。 |
| M4 ⚠ | `[ ]` | Lattice trait + 6 个核心 type 实现 | 新 `crates/lattice/`（独立 crate） | `trait Lattice { type Op; type Value; fn join(moves: &[Move]) -> Result<Self::Value, Bottom>; fn validate_op(&Op) -> Result<(), SchemaError>; }`；6 个 impl：or-set / mv-register / cas-register / fsm / counter / ordered-log。每个含 ≥10 unit test 覆盖 deterministic join + bottom diagnostics。 |
| M5 🅿 | `[ ]` | `Bottom` 诊断 typed model | `crates/core/src/bottom.rs` | `BottomKind::{Conflict, InvalidTransition, MissingDependency, Unauthorized, AnchorerSplit, SchemaError}`；`Bottom { kind, cells, move_ids, details }`；与 spec event-payload.schema.json 对齐。 |
| M6 🅿 | `[ ]` | Anchorer cell typed value + Space schema mirror | `crates/core/src/space.rs` | `AnchorerValue::{SingleDid(Did), Threshold { k, n, members }, OpenSet(Vec<Did>), Mixed { primary, recovery_members }}`；`Space.anchor_profile` / `Space.anchorer` / `Space.max_anchor_staleness_ms` / `Space.cell_lattices` / `Space.co_write_policy` 字段镜像更新。 |
| M7 ⚠ | `[ ]` | state-res crate 重定位 | `crates/state-res/src/lib.rs` 整体重写 | 旧主键 `(space_id, kind, subject?)` 模型替换为：(a) Move precondition / effect 验证；(b) Anchor batch apply；(c) per-cell Lattice join。`is_state_event` / `subject_for_event` 等概念被 cell_family / cell_subject 派生替代。 |
| M8 ⚠ | `[ ]` | `cx.consent.*` 改写为 consent cell Move | `crates/sdk/src/consent.rs` 重写 | grant=add tag, revoke=remove tag on `cx:cell:cx.component.consent.v1:<consent_id>`；effective state 由 or-set join 决定（非 reducer slot supersede）。 |
| M9 ⚠ | `[ ]` | `covered_frontier` cell + MLS Move 联动 | `crates/crypto/src/mls.rs`、`crates/sdk/src/mls.rs` | `MlsCommitMove` builder：preconditions 含 `mls_epoch_cell.head_eq(prev_epoch)` + `covered_frontier_cell.contains(governance_frontier_required)`；effects 写新 epoch / key schedule / covered_frontier 三 cell。 |
| M10 ⚠ | `[ ]` | Apply Anchor 算法 + Effective Anchor View | `crates/state-res/src/anchor.rs`（新） | `apply_anchor(A, store) -> Result<AnchorEffect, AnchorReject>`：predecessor_refs / frontier superset / anchorer_sig / deterministic_order / verify_move / atomic effects / state_root recompute。`effective_anchor_view(leaves)` 纯函数。 |
| M11 🔒 | `[ ]` | SDK 升级到 wire-breaking major | 全 workspace `Cargo.toml` | 单一 PR 一次性 break；不留 alias / shim（v1 未发布）。 |
| M12 🔒 | `[ ]` | `cargo test` workspace + clippy + fmt 全绿 | CI | 含新 lattice crate 测试。 |

---

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
| Q2 🅿 | `[x]` | schema drift constants 自动生成 | `crates/schema/src/lib.rs`、`crates/sdk/examples/spec_drift_report.rs`、`.github/workflows/ci.yml` | `ArtifactDriftReport` 加了 `unlisted_event_kinds` 软信号 + `has_unlisted()`；新 example `cargo run --example spec_drift_report` 把 hard drift（exit 1）/ soft drift（informational, exit 0）打印出来；`spec-drift` CI job 在 PR 上 checkout `contrix-spec` 并运行该 example，`continue-on-error: true` 保证 spec 仓库未公开时不挂 main pipeline。本地一跑发现 117 个 active event kind SDK 还没声明覆盖——给下一轮 typed reducer 工作的清单。 |

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C1 | 暴露 v1.0 constraint family/subtype typed model，给 soland/cotest/sodmin 使用。✅ 已完成。 |
| C5 | 提供 key-backup / restore-ticket / device-message typed client helper；cotest release gate 已覆盖 soland scaffold restore surface，SDK 仍需把 helper 从 scaffold 升级到 typed durable API。 |
| C6 | 提供公共 DID resolver / starid client helper；soland/cotest 已能发现 optional StarID resolver profile，SDK 仍需 live resolver adapter 与 StarID client helper。 |
| C10.A | **本仓是 C10 串行 gate 的第一站**——新 P0 M0-M12 是消化 spec 2026-05-08 Move/Anchor/Lattice rewrite 的全部本仓任务。旧 W1-W13（Phase 1-5 host endorsement / writer_model）整体作废，复用部分见上方废弃通知。 |
| C11 | 本仓需要执行的旧产物清理：W6/W7/W8 删除，含 10+ 处 Proof literal 中的 None 字段、`crates/sdk/src/space_host.rs` 整模块、`Space.space_writer_model` / `space_host`。 |
| C12 | 本仓不直接持有协议文档；但跨项目登记表里的旧 C10.* 描述需要由本文件 update 反映新 C10.A。|

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
- `[x]` 2026-05-07 — **W9 + W12 + Q2 收尾**：
  - W9: `SpecArtifactBundle::component(event_kind)` 返回 `ComponentDescriptor { event_kind, component_type, component_version, criticality, component_slot_alias_of }`；`Criticality` enum (`required/optional/ignore`)；带单元测试覆盖 canonical (`cx.capability.grant`) + alias (`cx.capability.revoke`) + unknown 三种路径
  - W12: 全 workspace fmt + clippy + 538 lib tests + rustdoc(`-D broken_intra_doc_links -D warnings`) + `tools/check-publish-order.py` 22 crates 全绿
  - Q2: `cargo run --example spec_drift_report` 把 hard/soft drift 都打出来；`.github/workflows/ci.yml` 加了 `spec-drift` informational job（`continue-on-error: true`，等 contrix-spec checkout 之后跑）；本地一跑发现 117 个 active event kind 等下一轮 typed reducer 覆盖
- 仍开放：S1（等 spec PR）、W10（MLS state binding，等 soland 联调）、W13（等 W10 后整体 bump）、H2/H3（等 soland durable lifecycle）。
