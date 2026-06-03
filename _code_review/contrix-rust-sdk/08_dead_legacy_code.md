# contrix-rust-sdk 审查报告 #08：历史陈旧 / 废弃应删除代码

## 审查范围

实际通读 / 检索的路径（相对 `D:/Works/contrix-dev/contrix-rust-sdk`）：

- `crates/core/src/model/operation.rs`（`LegacyReadMarker`、`Notification`）
- `crates/core/src/model/constants.rs`（`OP_RELATION_DELETE`、`OP_DIRECTORY_SUBSCRIBE` 等别名常量）
- `crates/core/src/blind_payload_sanitizer.rs`（`is_valid_custom_wakeup_kind` legacy helper）
- `crates/core/src/keystore/windows.rs`（`#[allow(dead_code)] fn _unused`）
- `crates/sdk/src/space/relation.rs`、`crates/sdk/src/resolver/state.rs`（`delete_relation` 系列）
- `crates/core/src/error.rs`（legacy error code 常量）
- 全仓 `grep -rni "TODO\|FIXME\|deprecated\|legacy\|no longer"`、`grep allow(dead_code)`

对照 spec 漂移制品：`contrix-spec/spec/v1/artifacts/registry/{removed-event-kinds.json, removed-operation-ids.json, forbidden-wire-fields.json, forbidden-model-terms.json}`。

复验命令：

```
grep -rn "LegacyReadMarker\|pub struct Notification\b" crates --include=*.rs
grep -rn "OP_RELATION_DELETE\|OP_DIRECTORY_SUBSCRIBE" crates --include=*.rs
grep -rn "is_valid_custom_wakeup_kind" crates --include=*.rs
grep -rn "allow(dead_code)" crates/*/src
```

未覆盖：`crates/crypto` / `crates/signatures` / `crates/server` / `crates/html` 仅做关键字扫描，未逐文件审；优先覆盖 wire 协议类型与 SDK facade。注意：与 Realm/Space 倒置相关的 `Place` 结构 / `pub type Realm = Space` 别名同时是「死历史命名」与「自相矛盾」素材，主述放在报告 #03，本报告仅在 08-2 交叉引用其「应删除」一面。

## 结论摘要

共保留 5 条有效问题，最高严重级别 **P1**。最确凿的是两个完全无引用的 `pub` 类型（`LegacyReadMarker`、`Notification`），均建模 spec 已 removed 的概念，可直接删除。其余为：复活 removed event-kind 词汇的 `relation.delete` 系列别名/方法名、指向 removed operation-id 的 `OP_DIRECTORY_SUBSCRIBE` 别名常量、以及仅对外 re-export 但仓内无调用的 legacy wakeup 校验器。

---

## 问题 08-1：`LegacyReadMarker` 无任何引用，且建模 removed 的 `cx.read.marker`

- **严重级别**：P1
- **证据**：`crates/core/src/model/operation.rs:491-507` 定义 `pub struct LegacyReadMarker`（含 `space_id: SpaceId`、`scope: ReadScope`、`type` 字段）。全仓检索 `LegacyReadMarker` 仅命中该定义本身一处，无任何构造/使用。
  - spec 对照：`removed-event-kinds.json` 将 `cx.read.marker` / `cx.read.cursor` 标记为 removed（替换为 `cx.read_cursor.advance`）；该结构的 `space_id`（前倒置 Space 锚定）+ 顶层 `type` 字段亦命中 `forbidden-wire-fields`。同文件已有 spec 对齐的 `ReadCursor`（`operation.rs:455`）与 `ReadReceipt`（`:479`，Realm-scoped）取而代之。
- **影响**：一个公开导出（经 `model/mod.rs:84 pub use objects::*` 同级 glob 暴露面）的 wire 类型，建模的是已删除概念，对 SDK 使用者构成误导，并污染 ToSchema 生成的 OpenAPI 面。
- **建议**：直接删除 `LegacyReadMarker`（按任务前提不考虑兼容性）。
- **复验结论**：已重新打开 `operation.rs:491-507` 并全仓搜索，确认零引用，描述属实。

---

## 问题 08-2：`Notification`（operation.rs）无引用，且为前倒置 / 非 spec 形状

- **严重级别**：P1
- **证据**：`crates/core/src/model/operation.rs:509-529` 定义 `pub struct Notification`，字段含顶层 `space_id: Option<SpaceId>`、独立 `type`（`object_type`）字段、`track`。全仓检索该类型仅命中定义本身（`grep -rn "\bNotification\b"` 在 core 内除 `NotificationType/Priority/State/Delta/Settings` 外无消费点）。
  - spec 对照：`notification.schema.json` 真源以 `actor_id` 锚定、主键统一 `id`、不带顶层 `space_id`、不单列 `type` 字段；该结构均违背。投影类型另有 `sync.rs:193 NotificationDelta` 与 sdk 侧实现在用。
- **影响**：又一个无引用的公开 wire 类型，形状与 spec / 倒置后语义冲突，构成可被误用的死结构（亦见报告 #09-5 的平行建模）。
- **建议**：删除该 `Notification` 结构；通知投影统一走 spec 对齐的单一类型。
- **复验结论**：已打开 `operation.rs:509-529` 并搜索引用，确认零消费点，属实。

---

## 问题 08-3：`relation.delete` 词汇被别名常量与公开方法名复活

- **严重级别**：P2
- **证据**：
  - `crates/core/src/model/constants.rs:233`：`pub const OP_RELATION_DELETE: &str = OP_RELATION_TOMBSTONE;`
  - `crates/sdk/src/space/relation.rs:59-70`：公开方法 `delete_relation_operation`，doc 注释 "Create a relation delete operation"。
  - `crates/sdk/src/resolver/state.rs:196`：`OP_RELATION_DELETE => self.delete_relation(event)?`（reducer 分派方法名 `delete_relation`）。
  - spec 对照：`removed-event-kinds.json` 将 `cx.relation.delete` 标为 removed（替换 `cx.relation.tombstone`）；`forbidden-wire-fields.json` 亦把 `cx.relation.delete` 列为 EventKind context 禁用项（见 `crates/core/src/forbidden_wire_fields.rs:392`，本项目自己也声明它被禁）。
- **影响**：wire 取值本身正确（别名解析到 `cx.relation.tombstone`），但仓内同时存在「禁止 `cx.relation.delete`」的守卫与「以 `delete` 命名复活该概念」的别名/方法，是 removed 词汇的活化石；新代码若误用 `OP_RELATION_DELETE` 名也会误以为存在 delete 语义。
- **建议**：删除 `OP_RELATION_DELETE` 别名常量，公开 API 一律改用 `OP_RELATION_TOMBSTONE` / `tombstone_relation*` 命名；reducer 分派与 sdk 方法重命名为 tombstone。
- **复验结论**：已核对常量别名、sdk 方法、reducer 分派与 forbidden 守卫四处 file:line，确为 removed 词汇遗留。

---

## 问题 08-4：`OP_DIRECTORY_SUBSCRIBE` 别名常量指向 removed operation-id

- **严重级别**：P3
- **证据**：
  - `crates/core/src/model/constants.rs:502`：`pub const OP_DIRECTORY_SUBSCRIBE: &str = OP_DIRECTORY_PUSH_REGISTER;`
  - 仍被 `crates/core/src/model/registry.rs:262`、`operations.rs:99 / :448 / :522` 当作有效路由 key 处理。
  - spec 对照：`removed-operation-ids.json:181` `cx.directory.subscribe` → 标记 removed，replacement `cx.directory.push.register`。spec §4.5 规则：current parser MUST 直接拒绝旧标识符，不做别名消歧。
- **影响**：以「removed operation-id 的旧名」作为内建路由别名，等于在解析层接受了应被拒绝的标识符（与本仓自带的 removed/forbidden 守卫意图相悖）。属应清理的兼容垫片。
- **建议**：删除 `OP_DIRECTORY_SUBSCRIBE` 常量及其在 `registry.rs` / `operations.rs` 中的分支，仅保留 `OP_DIRECTORY_PUSH_REGISTER`。
- **复验结论**：已核对常量定义与四处使用点及 `removed-operation-ids.json:181`，属实。

---

## 问题 08-5：`is_valid_custom_wakeup_kind` legacy helper 仓内零调用

- **严重级别**：P3
- **证据**：`crates/core/src/blind_payload_sanitizer.rs:542-557` 定义 `pub fn is_valid_custom_wakeup_kind`，doc 自述 "Legacy helper retained for callers that need to validate private extension tokens"。全仓除 `crates/core/src/lib.rs:43` 的 re-export 外无任何调用点（同模块的 `is_valid_wakeup_kind` / `is_valid_push_hint` 才是被实际使用的封闭 enum 校验）。
- **影响**：自我标注 legacy 的 helper，仓内无消费、仅对外暴露；与「私有扩展 token → 封闭 v1 wakeup_kind」的迁移路径绑定，属过时兼容面。
- **建议**：确认无外部消费后删除该 helper 及其 re-export；若确有外部依赖，应改为文档明确的 deprecated 通道而非静默保留。
- **复验结论**：已搜索全仓引用，仅命中定义与一处 re-export，无调用点；doc 注释明确标注 legacy。属实（删除前建议确认下游 repo 无引用）。
