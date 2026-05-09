# contrix-rust-sdk TODO

> 整理日期: 2026-05-07
> 范围: Contrix Rust typed model、client/server adapter、schema/artifact 消费、SDK helper。
> 协议参考: `../contrix-spec/spec/v1/artifacts/`。

## Changelog

### 2026-05-09 (round 20，激进模式) — C19.B 收尾：strict UUIDv7 typed-id validators + 528-fixture mass-rename

- **typed-id validators 全部 tighten**：`crates/identifiers/src/lib.rs:215-237` 把 `SpaceId / FlowId / EntityId / RelationId / EventId / CommitId / OperationId / GrantId / InviteId / DeviceId / PolicyId / ViewId` 的 closure 从 `has_prefix("cx:<kind>:")` 切到 `is_strict_typed_id(value, "cx:<kind>:")`，强制 RFC 9562 lowercase UUIDv7 payload。`EventId` / `OperationId` 保留 `is_hash` 备路；`DeviceId` 保留 `dev_<...>` 备路。Legacy mixed-case ULID-form (`cx:space:01JS0SP000000000000000000`) 和 UUIDv4 / 大写 hex / 错 variant nibble 全部硬拒绝。
- **fixture mass-rename**：跨 45 个 `.rs` 文件、528 处 fixture-id（含 12 个嵌套于 `space:cx:space:...:cx:flow:...` 的解析输入）从 ULID-shape `cx:<kind>:01<25-29 alphanumerics>` 重写为确定性 UUIDv7 envelope `cx:<kind>:01904100-0000-7000-8000-<sha1(kind:suffix)[:12]>`。映射 content-addressed → 不同 legacy id 总映射不同 hex tail，可重现 / 易调试。
  - **机械替换 (mass sweep)**: 第一遍 `"cx:<kind>:<suffix>"` quoted-literal 重写 ~320 处；第二遍嵌套 `cx:<kind>:01...` substring 重写 ~12 处（catch `flow:cx:space:...:cx:flow:01JS0FL...` 这类解析器输入）。
  - **手工修复 (manual fixups)**: 11 处需要语义修订（机械替换不足）：
    - `crates/identifiers/src/lib.rs::is_strict_typed_id_rejects_legacy_ulid_and_bad_uuid_payloads` + `device_id_accepts_protocol_device_forms` + `flow_id_accepts_active_flow_prefix`：恢复故意保留的 legacy ULID 字符串作为 reject 测试输入（sweep 把它们误当 wire-id 重写了）。
    - `crates/identifiers/src/lib.rs::serde_deserialization_validates_identifier_values`：旧测试 `cx:space:01` 仅 2 字符，新 strict validator 拒绝；改用 canonical UUIDv7。
    - `crates/sdk/src/timeline.rs::create_test_event` + `crates/sdk/src/space.rs::event` + `crates/sdk/tests/sdk_workflows.rs::event` + `crates/core/src/model.rs::operation_envelope_builder_covers_every_builtin_kind`：`format!("cx:event:{seq:026}")` / `format!("cx:operation:builder-{index}")` 等模板长度变了，改 `format!("cx:event:01904100-0000-7000-8000-{seq:012x}")`。
    - `crates/store/src/lib.rs` + `crates/sdk/src/store.rs::conformance_operation/conformance_commit`：原本 `format!("cx:operation:store-{suffix}")` 这类 ad-hoc 字符串，新增 `fixture_uuid7(seed: &str)` helper 把 sha256 截断 12 字节 hex 塞进 UUIDv7 envelope，保留 suffix 唯一性。
    - `crates/sdk/src/resolver.rs::deterministic_flow_surface_relation_id`：旧实现 `format!("cx:relation:{}", &digest[..26])` 产 26-char ULID-form；新版重排成 `xxxxxxxx-xxxx-7xxx-8xxx-xxxxxxxxxxxx` UUIDv7 envelope（version=7 / variant=8）。
    - `crates/sdk/src/sync_client.rs::sliding_sync_builds_windowed_subscriptions_and_applies_deltas` + `crates/sdk/src/timeline.rs::timeline_paginates_from_event_id` + `crates/sdk/src/resolver.rs::space_state_sorts_events_by_hlc`：测试依赖 lex-顺序 / 索引一致性，hash-derived 12-hex tail 打乱顺序；改用 `01904100-0000-7000-8000-000000000001..N` 序列 fixture。
    - `crates/sdk/src/authz.rs::resource_selector_parse_entity` + `flow_selector_matches_flow_resource`：解析器输入字符串里 `cx:space:...:task` 的 `...` 占位符 / `01JS0FL...` 截断符与 RHS 期望值不一致，改用 canonical UUIDv7。
    - `crates/core/src/canonical.rs::state_subject_encoding_roundtrips_simple_parts` + `crates/core/src/model.rs::event_digest_uses_canonical_payload_*` + `commit_digest_*`：fixture 内容变了导致 `expected_encoded` / `expected_hash` 漂移 → 更新 expected 字符串和 sha256 hash。
- **测试 & 校验**：
  - `cargo build --workspace --all-features` exit 0。
  - `cargo test --workspace --lib --no-fail-fast` **704 passed / 0 failed / 0 ignored**（基线持平）。
  - `cargo test --workspace --no-fail-fast`（lib + integration + examples） **712 passed / 0 failed / 2 ignored**。
- **C19.B 全部完成**：helper + SDK-internal 替换（round 18） + strict validators tightening + fixture migration（round 20）三件全部 land。下一轮可以开始 conformance-doc 收尾或 P1 helper 升级。

### 2026-05-09 (round 18，激进模式) — C19.B 主体落地：UUIDv7 wire-id helper + SDK-internal 替换 + v0.4.0 minor bump

- **C19.B 主体**：所有写出 Contrix typed wire id 的 SDK 站点改用 RFC 9562 UUIDv7（lowercase hex 36-char）替代旧 ULID：
  - `crates/sdk/src/space.rs::generate_id` 19 处 `cx:flow:` / `cx:operation:` / `cx:entity:` / `cx:relation:` 调用全部改 `uuid::Uuid::now_v7()`。
  - `crates/sdk/src/membership.rs::generate_id` 3 处 `cx:invite:` / `cx:operation:` 同上。
  - `crates/sdk/src/agent.rs` 4 处 `cx:operation:{}` 直调 `uuid::Uuid::now_v7()`。
  - `crates/sdk/src/mls.rs:307` `cx:mls:kp:{}` 改 `uuid::Uuid::now_v7()`。
  - 非 Contrix-wire 内部 token（`mem_<id>` / `run_<id>` / `tool_audit_<id>` / `a2a_<id>` / `sess_<id>` / `atk_<id>` / `rtk_<id>` / `recovery_<id>` / `passkey:<id>` / `as_<id>` / `applet_reg_<id>` / `portal_<id>` / `webrtc_<id>` / `call_<id>` / `txn_<id>` / `req_<id>` / `deploy_<id>`）保留 ULID 格式（spec 不约束这些）。
- **新 helper**：`contrix-identifiers::new_prefixed_uuid7(prefix)` 工厂函数，输出 `<prefix><uuidv7>` canonical wire 形态；`is_strict_typed_id(value, prefix)` helper 已就位作为 strict 校验 entry（暂未挂到 typed-id validators，参见下方“开放项”）。
- **依赖更新**：`crates/identifiers/Cargo.toml` + `crates/sdk/Cargo.toml` 加 `uuid.workspace = true`（workspace 已声明 `uuid = { version = "1.10", features = ["std","v7","serde"] }`）。
- **doc sweep**：`crates/core/src/model.rs:4208` `MlsKeyPackageRecord.keypackage_id` doc 字段格式 `cx:mls:kp:<ulid>` → `cx:mls:kp:<uuid>` (RFC 9562 UUIDv7)。
- **SDK minor bump v0.3.0 → v0.4.0**：`Cargo.toml` workspace.dependencies (23 entries) + 23 个 `crates/*/Cargo.toml` 的 `[package].version` 全部 `0.3.0` → `0.4.0`。`contrix v0.4.0` 全 workspace 链接通过。
- **测试 & 校验**：
  - `cargo check --workspace --all-features` exit 0。
  - `cargo test --workspace --lib` **704 passed / 0 failed / 0 ignored**（基线 +2，来自新增 `new_prefixed_uuid7` 与 `is_strict_typed_id` helper 单测）。
- **开放项（C19.B 收尾）** — **2026-05-09 round 20 已完成**：
  - typed-id validators 全部切到 `is_strict_typed_id`；528 处 fixture migration 跨 45 个 `.rs` 文件 land。
  - cursor.rs 已在前一轮完成 `has_prefixed_uuid7` 改写，本轮无需变动。

## 当前状态摘要

- R1-R9 主体已完成；C11 旧产物清理 + C13 doc sweep 全部完成 (2026-05-08)。
- **C10.A 全部完成** (M0-M12, 2026-05-08)。SDK 已升到 0.2.0 → 0.3.0 (C17/C18 wire-break) → **0.4.0** (C19.B UUIDv7 wire-break, 2026-05-09 round 18)。Move/Anchor/Lattice typed model + lattice crate + state-res rewrite + consent or-set + MLS commit Move + workspace 终验全部就位。
- C10.A 设计决策已写入文档:[`docs/move-anchor-runtime.md`](docs/move-anchor-runtime.md)（Rust SDK 实现层）+ contrix-spec §4.2（`state_root` canonical Merkle 编码 normative）。
- 当前开放项: spec-gated wire rename (S1)、DID resolver production adapter (H1)、device/recovery helper 从 scaffold 升级 (H2-H4)。下游 (soland / cotest / yougen) C10.B/C/D 的真正 server/client 接线工作可以基于 0.2.0 typed surface 开始。
- 0.2.0 终验 (2026-05-08)：`cargo fmt --all --check` exit 0；`cargo build --workspace --all-features` 干净；`cargo clippy --workspace --all-features --tests -- -D warnings` 干净；`cargo test --workspace --all-features` **614 passed / 1 pre-existing failure** (schema artifact-load test, 与本轮无关)。

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

## P0 · Move / Anchor / Lattice typed model ⚠ 🔒

> 起源：`contrix-spec` 2026-05-08 用 Move/Anchor/Lattice 三原语替换旧模型。详见根 [`../_todos.md` C10.A](../_todos.md)。
>
> 本仓是 C10 链路第一个串行 gate——下游 soland / cotest / yougen 不应在 raw JSON 上做 Move/Anchor wire 改动。

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| M0 ⚠ | `[x]` | 旧 W6/W7/W8 wire-breaking artifact 删除 | `crates/core/src/model.rs`、`crates/sdk/src/space_host.rs` | 已完成 (2026-05-08 C11)：`Proof::host_did` / `endorsed_at` / `proof_kind::HOST_ENDORSEMENT`、`SpaceWriterModel` / `Space.space_writer_model` / `Space.space_host` / `derived_writer_model()` / `validate_writer_model()`、`crates/sdk/src/space_host.rs` 整模块全部删除；10+ 处 Proof literal 同步清理。 |
| M1 ⚠ | `[x]` | `Move` typed model + canonical bytes | `crates/core/src/move_event.rs` | 已落地 (2026-05-08)：`Move { id, issuer, space_id, preconditions, effects, anchor_ref, refs, hlc, sig }`；`canonical_bytes_for_id()` 排除 `id` + `sig`；`derive_id()` / `id_from_canonical_bytes()` / `validate_id()` / `validate_structural()`；4 个 PredicateOp + 7 个 LatticeOpType + SemanticRef (含 critical=true 默认 skip)；新增 `MoveId` / `AnchorId` / `CellRef` typed identifier (含 oapi schemas)；13 个单元测试覆盖 id round-trip、id mismatch reject、effects 空集 reject、unknown alg reject、payload_hash drift reject、canonical bytes 排除、snake_case 序列化、SemanticRef critical 默认 skip。`cargo test -p contrix-core` 110/110 通过；`cargo clippy --all-features -D warnings` 干净。 |
| M2 ⚠ | `[x]` | `Anchor` typed model + 三种签名形态 | `crates/core/src/anchor.rs` | 已落地 (2026-05-08)：`Anchor { id, space_id, predecessor_refs, frontier, state_root, anchorer_sig, hlc }`；`AnchorerSig::{Single, Multi, Threshold}` 用 serde untagged + `kind` 内部 discriminator；`canonical_bytes_for_id()` 排除 `id` + `anchorer_sig`；`derive_id()` / `validate_id()` / `validate_structural()` 强制 threshold ≤ signer 数、空 multi 拒绝、unknown alg 拒绝、空 frontier+pred 拒绝。13 个单元测试。 |
| M3 🅿 | `[x]` | Cell ID + cell_family + cell_subject helpers | `crates/core/src/cell.rs` | 已落地 (2026-05-08)：`CellId::parse` 严格解析 `cx:cell:<component>:<subject>`（subject 内部 colon 保留）；`composite_subject` (base64url(sha256(canonical_json([..])))) 用于 spec encoding §9.5 wire-canonical hash 形态；`composite_subject_pipe` 用于诊断输出（绝非 wire-canonical）。10 个单元测试。 |
| M4 ⚠ | `[x]` | Lattice trait + 6 个核心 type 实现 | `crates/lattice/`（新独立 crate） | 已落地 (2026-05-08)：6 个 Lattice impl 全部就位（or-set / mv-register / cas-register / fsm / counter / ordered-log）；`Lattice` trait + `LatticeKind` 6-variant closed enum + `OpError` 区分 schema-violation 与 cell-level Bottom。`AnchoredOp` / `IssuedOp` / `CellState` 类型、deterministic join + Bottom diagnostics 全部覆盖。**55 个单元测试** 通过 `cargo test -p contrix-lattice`。Workspace `Cargo.toml` 已加 `contrix-lattice` 路径依赖。 |
| M5 🅿 | `[x]` | `Bottom` 诊断 typed model | `crates/core/src/bottom.rs` | 已落地 (2026-05-08)：`BottomKind::{Conflict, InvalidTransition, MissingDependency, Unauthorized, AnchorerSplit, SchemaError}` snake_case 序列化；`Bottom { kind, cells, move_ids, anchor_view, heads, details, escalated_at }` 与 `bottom.schema.json` 对齐；`AnchorView { leaves, state_root? }`；deserialize 拒绝 unknown kind（fail closed）。6 个单元测试。 |
| M6 🅿 | `[x]` | Anchorer cell typed value | `crates/core/src/anchorer.rs` | 已落地 (2026-05-08)：`AnchorerValue::{SingleDid, Threshold {k,n,members}, OpenSet, Mixed {primary, recovery_members}}` 内部 tag (`kind`) 序列化；`validate()` 强制 k≤n + 唯一 members + Mixed primary 不在 recovery + 非空成员；`includes_signer_as_primary()` / `is_recovery_member()` 帮助 anchorer cell join 判定；deserialize 拒绝 unknown kind。10 个单元测试。**Space schema mirror（M6 子任务）改为 M7 reducer/state-res 重写时再做** —— 需要等 state-res 设计落地后整体重写 `Space` 字段。 |
| M7 ⚠ | `[x]` | state-res crate 重定位 | `crates/state-res/src/{lib,store/mod,store/memory,verify,anchor,state_root}.rs` 整体重写 | 已落地 (2026-05-08)：旧 `StateReducer` / `state_hash` / `is_state_event` / `subject_for_event` / `candidate_wins` / `StateAuthority` / `evaluate_state_auth` 全部删除（v1 未发布无 backward-compat shim）。新 surface：`MoveStore` / `AnchorStore` / `CellStore` / `CellRegistry` 四 trait + Memory backends + `verify_move` 五步流水线 + `apply_anchor` 八步算法 + `effective_anchor_view` 纯函数 + `compute_state_root` (RFC 6962 Merkle, 空 list 锁死 sha256:e3b0c44...)。32 个单元测试覆盖：store CRUD/idempotency/rollback、CellRegistry 解析 + 8 个 cell family 默认 binding、verify_move 5 reject 类型、apply_anchor genesis/state_root mismatch/unknown predecessor，effective_anchor_view 多 leaf 收敛。`cargo test -p contrix-state-res` 32/32 通过；`cargo clippy --tests -D warnings` 干净。 |
| M8 ⚠ | `[x]` | `cx.consent.*` 改写为 consent cell Move | `crates/sdk/src/consent.rs` | 已落地 (2026-05-08)：旧 `ConsentState::{Granted,Revoked,Absent}` 枚举（reducer slot supersede 模型）整体删除。新 API：`grant_effect(consent_id, peer, scope, options) -> Effect` 产 or-set add op；`revoke_effect_with_precondition(...)` 产 or-set remove op + spec §3.3 `contains` precondition；`evaluate_consent(cell_state, peer, scope, now) -> bool` 从 or-set join 派生当前 consent；`require_consent_precondition(...)` 助手用于上游 invite/DM/call-init Move gate。Cell 命名对齐 spec 的 `cx.component.consent.grant.v1`（之前 MemoryCellRegistry 用 `cx.component.consent.v1`，已修正）；tag 编码为 `grant:<consent_id>:<peer>:<scope>`（spec §3.2 deterministic dedupe rule）。16 个单元测试覆盖：cell id canonical/empty reject、tag determinism、grant/revoke effect shape、window respect、Scope::Any 满足任何 concrete scope、idempotent grant dedupe、revoke 后 evaluate 转 false、空 cell 拒绝。 |
| M9 ⚠ | `[x]` | `covered_frontier` cell + MLS Move 联动 | `crates/sdk/src/mls_move.rs`（新模块）、`crates/state-res/src/store/memory.rs`（cell registry） | 已落地 (2026-05-08)：新 `mls_move` 模块给出 cell family 常量（`cx.component.mls_epoch.v1` cas-register / `cx.component.key_schedule.v1` cas-register / `cx.component.covered_frontier.v1` or-set, bottom=expose）+ `mls_epoch_cell_id` / `key_schedule_cell_id` / `covered_frontier_cell_id` cell helpers + `governance_frontier_tag` 把 anchor id 当 or-set tag + `mls_commit_preconditions(group_id, space_id, prev_epoch, required_anchor)` (head_eq + contains 两条 precondition) + `mls_commit_effects(group_id, space_id, new_epoch, new_schedule, attested_anchor)` (set/set/add 三条 effect, 对齐 spec §10) + `MlsCommitMoveSpec::build` 一站式 + `e2ee_message_precondition` 给 E2EE 消息 Move 用 + `covered_frontier_contains` 接收侧 or-set join 检查。`MemoryCellRegistry` 注册三个新 cell family。11 单元测试覆盖：cell id canonical/empty reject、precondition/effect shape vs spec §10、frontier tag 形态、build round trip、E2EE precondition 引用 covered_frontier、or-set join 后 contains 命中、多 commit 累积。无依赖于 openmls；纯 Move/Anchor 类型层。 |
| M10 ⚠ | `[x]` | Apply Anchor 算法 + Effective Anchor View | `crates/state-res/src/anchor.rs` | 已落地 (2026-05-08)：作为 M7 一并落地。`apply_anchor` 8 步：structural → predecessor known → frontier 单调 → pre_state from predecessor view → deterministic_order verify_move → 原子 append → recompute state_root + 比对 → persist Anchor + mark Moves anchored。state_root 不匹配自动 rollback。`effective_anchor_view(leaves)` 纯函数返回 sorted predecessor_refs / union frontier / recompute state_root。`view_hash` 工具用作 cache key。 |
| M11 🔒 | `[x]` | SDK 升级到 wire-breaking major | 全 workspace `Cargo.toml` + `CHANGELOG.md` | 已落地 (2026-05-08)：23 crate 全部从 `0.1.0` → `0.2.0`（workspace.dependencies + 每个 `[package].version`）。CHANGELOG 加 `[0.2.0] – 2026-05-08 — Move/Anchor/Lattice rebase ⚠ wire-breaking` 段，详列 Added (10 大类新 surface) / Removed (老 state-res/StateAuthority/SpaceWriterModel/host_endorsement/旧 ConsentState 全删) / Changed / Test baseline / Migration（4 步下游迁移 checklist）。`cargo build --workspace --all-features` 全部 23 crate 链接 0.2.0 通过。 |
| M12 🔒 | `[x]` | `cargo test` workspace + clippy + fmt 全绿 | CI | 已落地 (2026-05-08)：`cargo fmt --all --check` exit 0；`cargo build --workspace --all-features` 干净；`cargo clippy --workspace --all-features --tests -- -D warnings` 干净；`cargo test --workspace --all-features` **614 passed / 1 pre-existing 失败**（schema artifact-load test 与本轮无关）。 |

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
| C10.A | **本仓是 C10 串行 gate 的第一站**——P0 M0-M12 是消化 spec 2026-05-08 Move/Anchor/Lattice rewrite 的全部本仓任务。 |
| C11 | 旧产物清理已完成 (2026-05-08)：W6/W7/W8 删除、`crates/sdk/src/space_host.rs` 整模块、`Space.space_writer_model` / `space_host` 字段、10+ 处 Proof literal None 字段全部删除。 |

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
