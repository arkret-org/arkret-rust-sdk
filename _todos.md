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

## 已完成（changelog）

- `[x]` R9 client/server configuration、CI/release、docs.rs metadata、deployment guide。
- `[x]` S2 清理旧 spec 路径和历史审计编号引用。
- `[x]` S3 constraint family API 对齐 v1.0（8 family + subtype）。
- `[x]` H5 server adapter examples 标注非生产 501。
- `[x]` Q1 公开 builder 过长参数改 option struct（`FlowCreateMetadata` / `FlowUpdateMetadata`）。
- `[x]` Q3 `cargo metadata` / release order 验证纳入本地 xtask。
- `[x]` H1 SDK 端 `StaridRegistryAdapter` doc 收敛。
- `[x]` H4 typed contract 去掉 wire 上的 `todo`/`note` 占位字段。
