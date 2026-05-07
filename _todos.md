# contrix-rust-sdk TODO

> 整理日期: 2026-05-07
> 范围: Contrix Rust typed model、client/server adapter、schema/artifact 消费、SDK helper。
> 协议参考: `../contrix-spec/spec/v1/artifacts/`。

## 当前状态摘要

- R1-R9 主体已完成；最近一次验证记录: fmt、clippy、workspace tests、doc warnings、salvo example 均通过。
- 当前开放项不是编译阻塞，主要是 spec-gated wire rename、DID resolver production adapter、device/recovery helper 从 scaffold 升级。
- 仓内有已修改文件；本轮只整理 `_todos.md`。

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
| S2 🔒 | `[x]` | 清理旧 spec 路径和历史审计编号引用 | docs、tests、schema crate | 文档和测试已指向 `../contrix-spec/spec/v1/artifacts/` 与 `spec/v1/zh/` 当前源；不存在的历史审计报告引用已清掉。 |
| S3 🔒 | `[x]` | constraint family API 对齐 v1.0 | `crates/sdk/src/authz.rs` | `ProtocolGrantConstraintType` collapse 到 8 family（`temporal/field_access/type_restriction/scope_limitation/delegation_control/quota/claim_based/confidentiality`），`ProtocolGrantConstraint` 加 `subtype: Option<String>`，scaffold 示例换到 `claim_based.{approval,claim}` / `scope_limitation`；CHANGELOG 同步成 8 family + subtype。 |

## P1 · Production helper surface

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| H1 🅿 | `[~]` | Production DID resolver network adapter | `crates/sdk/src/identity.rs`、`crates/sdk/src/resolver.rs` | SDK 端的 `StaridRegistryAdapter` doc 已收敛成稳定 trait + 实现要求（timeouts / size limits / signed key-log receipts / fail-closed-on-stale），剩下的 production HTTP adapter 是 `starid` / public resolver policy 一侧的事。 |
| H2 🅿 | `[ ]` | Device message helper 从 scaffold 升级 | `crates/sdk/src/devices.rs` | 等 `soland /api/v1/device_messages/*` durable lifecycle。 |
| H3 🅿 | `[ ]` | Key verification helper 从 scaffold 升级 | `crates/sdk/src/devices.rs`、`crates/sdk/src/mls.rs` | 等 soland device verification reducer/state。 |
| H4 🅿 | `[~]` | Key backup / restore-ticket client 从 scaffold 升级 | `crates/sdk/src/devices.rs`、client crate | typed contract 上 wire-不存在的 `todo: String` / `note: String` 占位字段已经从 `ProtocolKeyBackupRestoreRequest` / `Ticket` / `TicketAdvanceRequest` 删掉（修了把 placeholder 文案 leak 上 wire 的 bug），scaffold builder 的 method doc 也改成"wire 形状已稳定，service-side lifecycle 还在 scaffold"。剩余的真正升级仍需等 soland recovery/key-backup durable store。 |
| H5 🅿 | `[x]` | Server adapter examples 标注非生产 501 | `crates/server/README.md`、`crates/sdk/examples/*` | `crates/server/README.md` 加了 "Not a reference implementation" banner；`server_endpoint_adapter.rs` 加了模块级 doc 说明它只是 adapter smoke test，并指明 `soland` 是 canonical 实现。`salvo_server.rs` 已经返回 501 + 注释清晰。 |

## P2 · API cleanup / quality

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| Q1 ⚠ | `[x]` | 公开 builder 过长参数改 option struct | `crates/sdk/src/space.rs` | 新增 `FlowCreateMetadata` / `FlowUpdateMetadata` option struct（都 `Default`）；`create_flow_operation_with_metadata` / `update_flow_operation_with_metadata` 改用 metadata 参数，去掉 `#[allow(clippy::too_many_arguments)]`；短形式 helper 透传 `Default::default()`。 |
| Q2 🅿 | `[~]` | schema drift constants 自动生成 | `crates/schema/src/lib.rs`、build tooling | 自动生成不合适：`ARTIFACT_BACKED_*` 表示 SDK 自身已声明覆盖的 spec surface，不是 spec mirror。已加 doc 说明；`ArtifactDriftReport` 现在带 `unlisted_event_kinds` 软信号字段（`has_unlisted()`），把 spec 新增但 SDK 未声明覆盖的 active event kind 列出来供下一轮工作参考。剩余真正待做的是把这份 soft signal 接到一个 CI/任务报告里。 |
| Q3 🅿 | `[x]` | `cargo metadata` / release order 验证纳入本地 xtask | release tooling | `tools/check-publish-order.py` 用 `cargo metadata --no-deps` 验证 `.github/workflows/release-crates.yml` 的 `CRATES` 列是 valid 拓扑序（每个 crate 都在它 workspace dep 之后；missing/extra 都报错）；`--print` 可打印一个新 topo order。`RELEASING.md` 加了使用说明。 |

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C0 | 修正旧 spec path / 不存在 `_report.md` 的引用。 |
| C1 | 暴露 v1.0 constraint family/subtype typed model，给 soland/cotest/sodmin 使用。 |
| C5 | 提供 key-backup / restore-ticket / device-message typed client helper；cotest 已把 soland scaffold restore surface 纳入 release gate，SDK 仍需把 helper 从 scaffold 升级到 typed durable API。 |
| C6 | 提供公共 DID resolver / starid client helper；soland/cotest 已能发现 optional StarID resolver profile，SDK 仍需 live resolver adapter 与 StarID client helper。 |

## 已完成（短 changelog）

- `[x]` R9 client/server configuration、CI/release、docs.rs metadata、deployment guide 完成。
- `[x]` R9 后 fmt、clippy、workspace tests、doc warnings、salvo example 验证通过。
- `[x]` spec artifact 新路径 fallback 和 registry 常量的最近一次漂移修复已完成；soft drift（`unlisted_event_kinds`）已接进 `ArtifactDriftReport`。
- `[x]` 2026-05-07: S2/S3/H5/Q1/Q3 落地，Q2 部分落地（见上文）。
- `[x]` 2026-05-07 (post-continue): H1 SDK 端 `StaridRegistryAdapter` doc 收敛、H4 typed contract 去掉 wire 上的 `todo`/`note` 占位字段。

### 2026-05-07 verification

- `cargo fmt --all -- --check` ✓
- `cargo clippy --workspace --all-features --all-targets -- -D warnings` ✓
- `cargo test --workspace --all-features --no-fail-fast` ✓ (527 passed, 0 failed, 2 ignored)
- `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D warnings" cargo doc --no-deps --all-features --workspace` ✓
- `python tools/check-publish-order.py` ✓ (valid 22-crate topological order)
