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
| S2 🔒 | `[ ]` | 清理旧 spec 路径和历史审计编号引用 | docs、tests、schema crate | 使用 `../contrix-spec/spec/v1/artifacts/`；旧 `contrix-spec/artifacts/` 只能作为 fallback，不作为文档主路径。 |
| S3 🔒 | `[ ]` | constraint family API 对齐 v1.0 | `crates/sdk/src/authz.rs` | 当前下游任务仍提“14 constraints”；SDK public enum / examples 应明确 v1.0 是 8 family + subtype。 |

## P1 · Production helper surface

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| H1 🅿 | `[ ]` | Production DID resolver network adapter | `crates/sdk/src/identity.rs`、`crates/sdk/src/resolver.rs` | `starid` / public resolver policy；替换仅示例级 resolver TODO。 |
| H2 🅿 | `[ ]` | Device message helper 从 scaffold 升级 | `crates/sdk/src/devices.rs` | 等 `soland /api/v1/device_messages/*` durable lifecycle。 |
| H3 🅿 | `[ ]` | Key verification helper 从 scaffold 升级 | `crates/sdk/src/devices.rs`、`crates/sdk/src/mls.rs` | 等 soland device verification reducer/state。 |
| H4 🅿 | `[ ]` | Key backup / restore-ticket client 从 scaffold 升级 | `crates/sdk/src/devices.rs`、client crate | 等 soland recovery/key-backup durable store。 |
| H5 🅿 | `[ ]` | Server adapter examples 标注非生产 501 | `crates/server/README.md`、`crates/sdk/examples/*` | 保留示例，但文档必须避免让使用方误以为 placeholder server 是 reference implementation。 |

## P2 · API cleanup / quality

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| Q1 ⚠ | `[ ]` | 公开 builder 过长参数改 option struct | `crates/sdk/src/space.rs` | `create_flow_operation_with_metadata` / `update_flow_operation_with_metadata` 当前为了兼容暂时 allow；需要单独 API-cleanup round。 |
| Q2 🅿 | `[ ]` | schema drift constants 自动生成 | `crates/schema/src/lib.rs`、build tooling | 避免每次 spec registry 变更手动增删 `ARTIFACT_BACKED_*` 常量。 |
| Q3 🅿 | `[ ]` | `cargo metadata` / release order 验证纳入本地 xtask | release tooling | 保证 22 crates 发布顺序可本地复现。 |

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C0 | 修正旧 spec path / 不存在 `_report.md` 的引用。 |
| C1 | 暴露 v1.0 constraint family/subtype typed model，给 soland/cotest/sodmin 使用。 |
| C5 | 提供 key-backup / restore-ticket / device-message typed client helper。 |
| C6 | 提供公共 DID resolver / starid client helper。 |

## 已完成（短 changelog）

- `[x]` R9 client/server configuration、CI/release、docs.rs metadata、deployment guide 完成。
- `[x]` R9 后 fmt、clippy、workspace tests、doc warnings、salvo example 验证通过。
- `[x]` spec artifact 新路径 fallback 和 registry 常量的最近一次漂移修复已完成；后续要自动化。
