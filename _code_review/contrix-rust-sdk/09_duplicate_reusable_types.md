# contrix-rust-sdk 审查报告 #09：类型/逻辑重复定义或可复用副本未使用

## 审查范围

实际通读 / 检索的路径（均相对 `D:/Works/contrix-dev/contrix-rust-sdk`）：

- `crates/identifiers/src/lib.rs`（ID 校验器、`new_prefixed_uuid7`、`is_lowercase_uuidv7`、`is_strict_typed_id`）
- `crates/core/src/cursor.rs`（`is_uuid7` / `has_prefixed_uuid7`）
- `crates/core/src/canonical.rs`（canonical JSON / digest 真源）
- `crates/core/src/sync.rs` 与 `crates/core/src/model/api.rs`（两套 `SyncReqBody` / `SyncResBody`）
- `crates/core/src/model/operation.rs`、`crates/sdk/src/receipts.rs`、`crates/sdk/src/notifications.rs`（ReadReceipt / Notification 平行类型）
- `crates/sdk/src/membership.rs`、`crates/sdk/src/space/mod.rs`、`crates/sdk/src/mls.rs`、`crates/sdk/src/crypto_store.rs`（`generate_id` / 内联 uuid7 生成）
- `crates/core/src/model/objects.rs`、`crates/core/src/model/mod.rs`（`Space`/`Realm`/`Place` 结构与 re-export）

复验命令：

```
grep -rn "fn generate_id\|Uuid::now_v7" crates/*/src --include=*.rs
grep -rn "fn is_uuid7\|fn is_strict_typed_id\|fn is_lowercase_uuidv7" crates/*/src --include=*.rs
grep -rn "pub struct SyncReqBody\|pub struct SyncResBody" crates --include=*.rs
grep -rn "pub struct ReadReceipt\|pub struct Notification\b" crates --include=*.rs
```

未覆盖：`crates/crypto`、`crates/signatures`、`crates/http-client`、`crates/server`、`crates/html` 内部仅做关键字检索，未逐文件通读；重点放在 wire/协议类型与 SDK facade（`crates/core` / `crates/contracts` / `crates/sdk`）。

## 结论摘要

本维度共保留 5 条有效问题，最高严重级别 **P1**。核心模式是：`crates/sdk`（umbrella facade）与 `crates/core`、`crates/identifiers` 已提供权威实现，却另起炉灶手抄了 ID 生成、UUIDv7 校验、ReadReceipt / Notification 类型；并且 `SyncReqBody/ResBody` 在 `core` 内部就被定义了两份。多数副本应直接复用既有 SDK core/identifiers 实现（标注于各条「建议」与「疑似应上移」）。

---

## 问题 09-1：`generate_id` 在两处被逐字复制，且重复 `contrix_identifiers::new_prefixed_uuid7`

- **严重级别**：P2
- **证据**：
  - `crates/sdk/src/membership.rs:13-15`
    ```rust
    fn generate_id(prefix: &str) -> String {
        format!("{prefix}{}", uuid::Uuid::now_v7())
    }
    ```
  - `crates/sdk/src/space/mod.rs:43-45`（与上面逐字节相同）
  - 权威实现：`crates/identifiers/src/lib.rs:169-170`
    ```rust
    pub fn new_prefixed_uuid7(prefix: &str) -> String {
        format!("{prefix}{}", uuid::Uuid::now_v7())
    }
    ```
    （`crates/core/src/model/events.rs:384`、`crates/crypto/src/backup.rs:343` 已正确复用此公开函数。）
- **影响**：同一逻辑三份维护。`new_prefixed_uuid7` 在 identifiers 中带有 `conformance/encoding.md §4` 的小写 hex 契约文档与测试（`lib.rs:560`），手抄副本没有任何契约保证；若将来 UUID 生成策略（如版本/大小写规范化）调整，两个 `generate_id` 不会同步。
- **建议**：删除 `membership.rs:13` 与 `space/mod.rs:43` 两个私有 `generate_id`，统一改用 `contrix_identifiers::new_prefixed_uuid7`（SDK 已通过 `contrix_core` re-export 可达）。
- **疑似应上移**：无需上移——目标已在 `crates/identifiers`，属「复用既有实现」而非「上移」。
- **复验结论**：已重新打开三处 file:line 核对，两个 `generate_id` 函数体与 `new_prefixed_uuid7` 字符串拼接完全一致，属真实重复。

---

## 问题 09-2：`cursor.rs` 手写 `is_uuid7` / `has_prefixed_uuid7`，重复 identifiers 的权威 UUIDv7 校验

- **严重级别**：P1
- **证据**：
  - `crates/core/src/cursor.rs:495-527`：`has_prefixed_uuid7` + `is_uuid7` 手工校验「36 字符、连字符在 8/13/18/23、版本 nibble=`7`（idx14）、变体 nibble∈{8,9,a,b}（idx19）、其余小写 hex」。
  - 权威实现：`crates/identifiers/src/lib.rs:158-163` `is_strict_typed_id` + `:179` `pub fn is_lowercase_uuidv7`，文档明言「Strict typed-ID validator … 36 chars, lower-case hex `xxxxxxxx-xxxx-7xxx-Nxxx-...` where N ∈ {8,9,a,b} per `conformance/encoding.md §4`」——与 cursor.rs 的手写逻辑逐条对应。
- **影响**：协议安全相关的 ID 合法性校验出现两套独立实现。cursor.rs 副本是私有 `fn`、无单独测试；identifiers 版本有 `lib.rs:572` 的负例测试（拒绝 ULID / UUIDv4）。两套若对「大小写」「变体位」判定出现细微分歧，会导致同一 ID 在 cursor 层与 typed-id 层接受/拒绝不一致——属可被利用的校验漂移面。
- **建议**：删除 `cursor.rs` 的 `is_uuid7`，`has_prefixed_uuid7(value, prefix)` 改为调用 `contrix_identifiers::is_strict_typed_id(value, prefix)`（语义等价：strip 前缀 + `is_lowercase_uuidv7`）。
- **疑似应上移**：目标已在 `crates/identifiers`（最底层 crate），属复用而非上移。
- **复验结论**：已逐行比对 `cursor.rs:502-527` 与 `identifiers/lib.rs:158-179` 注释/逻辑，两者校验同一规范的同一约束，确为重复实现。

---

## 问题 09-3：`SyncReqBody` / `SyncResBody` 在 `core` 内部存在两份定义

- **严重级别**：P1
- **证据**：
  - `crates/core/src/sync.rs:19` `pub struct SyncReqBody`（字段 `after / catchup / set_presence / filter: Option<SyncFilter> / subscriptions / wait_for`）。
  - `crates/core/src/model/api.rs:543` `pub struct SyncReqBody`（字段 `after / catchup / filter: Value / set_presence: Option<String>`）。
  - 对应的 `SyncResBody` 同样两份：`sync.rs`（其 module 注释见 `sync.rs:39` "Sync result for a single Space / Realm payload entry"）与 `api.rs:566`。
- **影响**：两个同名 wire DTO 字段集合并不一致（`filter` 一处是强类型 `SyncFilter`、另一处是 `Value`；`subscriptions`/`wait_for` 仅在 sync.rs 版本存在）。下游通过 glob re-export 暴露时，到底命中哪一个取决于 use 路径，极易产生「同一请求体两种序列化形状」的隐性分叉，与「防漂移」初衷相悖。
- **建议**：保留单一权威 `SyncReqBody/ResBody`（建议以 `model/api.rs` 为 wire 真源），让 `sync.rs` 的 SDK 内部聚合类型改名（如 `SyncLoopRequest`）或直接复用 api.rs 类型，消除同名二义。
- **疑似应上移**：二者已同在 `crates/core`，属内部去重；wire 真源应收敛到 `model` 子树。
- **复验结论**：已分别打开 `sync.rs:19/39` 与 `api.rs:543/566` 核对，确为两个同名但字段不同的 `pub struct`，重复属实。

---

## 问题 09-4：`ReadReceipt` 在 `core::model::operation` 与 `sdk::receipts` 平行定义且语义不一致

- **严重级别**：P2
- **证据**：
  - `crates/core/src/model/operation.rs:479` `pub struct ReadReceipt`：以 `realm_id: RealmId` + `read_scope: ReadScope` + `actor_id` 建模（与 spec `read-cursor.schema.json` 的 Realm 锚定一致）。
  - `crates/sdk/src/receipts.rs:52` `pub struct ReadReceipt`：以 `space_id: SpaceId` + `user_id` + `thread_id` + `visibility` 建模（Space 锚定 + thread 维度），并被 `ReceiptManager`（`receipts.rs:75`）以 `(SpaceId, EventId, Option<String>)` 为键索引。
- **影响**：同一概念两套类型，一套 Realm-scoped（spec 对齐），一套 Space/thread-scoped（前倒置语义，`thread_id` 非 `track_name`）。消费者拿到哪个 `ReadReceipt` 取决于导入路径；SDK facade 层把过时形状当作权威对外暴露，是字段语义漂移源。
- **建议**：以 `core::model::operation::ReadReceipt`（Realm-scoped、spec 对齐）为唯一真源；`sdk::receipts` 的本地管理器改为包裹/复用该类型，移除其自定义 `space_id`/`thread_id` 形状。
- **疑似应上移**：`sdk::receipts::ReadReceipt` 的 wire 形状应被 `core::model` 版本取代（去重而非新增）；本地仅保留管理器逻辑。
- **复验结论**：已打开两处 file:line 核对，字段集合（realm_id+read_scope vs space_id+thread_id+visibility）确实不同且并存。

---

## 问题 09-5：Notification 投影类型多处平行建模

- **严重级别**：P3
- **证据**：
  - `crates/core/src/model/operation.rs:511` `pub struct Notification`（`space_id: Option<SpaceId>` + `type` 字段 + `track`），
  - `crates/sdk/src/notifications.rs:40` `pub struct NotificationItem`（`space_id: Option<SpaceId>` + `sender` + `cleared`），
  - 计数类型亦双份：`crates/contracts/src/client.rs:925` `NotificationCounts` 与 `crates/sdk/src/notifications.rs:63` `NotificationCounts`。
- **影响**：通知投影在 core / sdk / contracts 三处各有一套结构，字段命名（`cleared` vs `state`、`sender` vs `actor_id`）不统一；spec `notification.schema.json` 是单一真源，三套手抄增加漂移与对账成本。（其中 `operation.rs:511` 的 `Notification` 还无任何引用，见报告 #08。）
- **建议**：以 spec `notification.schema.json` 对齐的单一 core 类型为真源，sdk/contracts 复用之；移除字段语义分叉。
- **疑似应上移**：通知投影类型应收敛到 `core::model`（spec 真源落点），sdk 仅保留本地状态管理逻辑。
- **复验结论**：已核对三处 file:line，结构确实并存且字段命名不一致；属真实平行维护。
