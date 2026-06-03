# contrix-rust-sdk 审查报告 #03：自相矛盾之处

## 审查范围

实际通读 / 检索的路径（相对 `D:/Works/contrix-dev/contrix-rust-sdk`）：

- `README.md`（§Realm vs Space，公开 SDK 面承诺）
- `crates/core/src/model/objects.rs`（`pub type Realm = Space`、`Space` 结构 / 构造器、`Place` 结构）
- `crates/core/src/model/constants.rs`（`OP_REALM_CREATE` / `OP_SPACE_CREATE` 等）
- `crates/identifiers/src/lib.rs`（`RealmId` / `SpaceId` 两个独立类型）
- `crates/core/src/forbidden_wire_fields.rs`（`branch` 守卫）
- `crates/core/src/sync.rs`、`crates/core/src/model/api.rs`（`SyncReqBody/ResBody` 双定义、`spaces`/`left_spaces` 字段）
- `crates/sdk/src/receipts.rs`（`dedup_window_ms` 常量与注释）

对照 spec：`contrix-spec/spec/v1/artifacts/registry/{forbidden-wire-fields.json, forbidden-model-terms.json, id-kind-registry.json}` 与 `_reference/spec_digest.md`（Realm/Space 倒置 = revision `59ac1d4`）。

复验命令：

```
grep -n "pub type Realm = Space\|pub struct Space\|pub struct Place" crates/core/src/model/objects.rs
grep -c "RealmId" crates/core/src/model/objects.rs
grep -n "id_type!(RealmId\|id_type!(SpaceId" crates/identifiers/src/lib.rs
grep -n "branch\|Place\|0.7 compile-time aliases" README.md
```

未覆盖：crypto/signatures/server/html 仅关键字扫描。优先覆盖 wire 协议类型与 README/代码一致性。

## 结论摘要

共保留 4 条有效问题，最高严重级别 **P0**。最严重的矛盾集中在 Realm/Space 倒置的「半完成」状态：README 声称倒置已完成、0.7 兼容别名已移除，但 `crates/core` 仍以 `pub type Realm = Space` + `Place` 结构 + 全量 `SpaceId` 主键承载 Realm 语义——文档与实现直接对立，且 Realm 对象在 wire 上发出 `cx:space:` ID 与自身 `cx.realm.create` 事件、与独立的 `RealmId` 类型互斥。

---

## 问题 03-1：README 宣称「0.7 编译期别名已移除」，但 `pub type Realm = Space` 与 `Place` 结构仍在

- **严重级别**：P0
- **证据**：
  - `README.md:30-39`：「After the Phase 1–4 terminology inversion … The 0.8 line uses the realm/space names directly; **the 0.7 compile-time aliases are removed.**」并称 Space「Previously called `Place` on the wire」。
  - 与之矛盾的实现：`crates/core/src/model/objects.rs:10` `pub type Realm = Space;`（注释 `:3-9` 自述「`Realm` is exposed as a type alias so downstream code can migrate gradually … kept under its old name for transitional compile-only compatibility」）。同文件 `:262` 仍定义 `pub struct Place`，且经 `crates/core/src/model/mod.rs:84 pub use objects::*` 公开导出。
- **影响**：README 是对 SDK 使用者的权威承诺。它断言别名已删、命名已倒置完成，而真源 crate 实际仍以 `Space`=安全边界、`Place`=容器的「倒置前」命名运行，仅靠 `type Realm = Space` 别名遮掩。使用者按 README 预期 `Realm`/`Space` 为独立类型，实则 `Realm` 只是 `Space` 的别名、容器类型叫 `Place`——文档与实现根本性对立。
- **建议**：二者择一并消除矛盾——要么完成倒置（把结构真正改名为 `Realm` / `Space`，删除 `type Realm = Space` 与 `Place`），要么修正 README 如实说明别名仍在。鉴于硬规则与 spec 已定稿倒置，应推进前者。
- **复验结论**：已逐字核对 `README.md:30-39` 与 `objects.rs:3-10,262`，文档「aliases are removed」与代码「别名 + Place 结构在用」确为直接矛盾。

---

## 问题 03-2：承载 Realm（安全边界）语义的对象，主键类型却是 `SpaceId`（`cx:space:`），与 `RealmId` / `cx.realm.create` 互斥

- **严重级别**：P0
- **证据**：
  - `crates/core/src/model/objects.rs:14-16`：`pub struct Space { schema, id: SpaceId, title, … }`，注释 `:18-25` 明确「This field is `Realm`-scoped because `Space` is the security-boundary type (Realm/Space inversion)」——即该结构=Realm。其构造器 `objects.rs:159-164 Space::new(id: SpaceId, …)` doc 又写「trust domain captured at `cx.realm.create` time」。
  - 全仓事实：`grep -c "RealmId" crates/core/src/model/objects.rs` = **0**（整个对象模块零处用 `RealmId`）。
  - 但独立类型确实存在：`crates/identifiers/src/lib.rs:267` `id_type!(RealmId, |v| is_strict_typed_id(v, "cx:realm:"));` 与 `SpaceId`（`cx:space:`）并列；`crates/core/src/model/constants.rs:244` `OP_REALM_CREATE = "cx.realm.create"`、`:222` `OP_SPACE_CREATE = "cx.space.create"` 也并列。
- **影响**：Realm 对象由 `cx.realm.create` 事件创建、其 ID 本应是 `cx:realm:`（`RealmId`），但该结构在 wire 上发出的是 `cx:space:`（`SpaceId`）。同一仓库内：(a) 存在 `RealmId`/`cx:realm:` 类型却无人在 Realm 对象上使用；(b) `cx.realm.create` 与 `cx:space:` 主键并存——事件命名空间与 ID 命名空间自相矛盾。这是会污染所有 Realm 持久对象 wire 形状的根因级矛盾。
- **建议**：Realm 对象主键统一改用 `RealmId`（`cx:realm:`），与 `cx.realm.create` 对齐；`SpaceId`/`cx:space:` 仅用于容器（现 `Place`）对象。
- **复验结论**：已核对 `objects.rs:14-16,159-164`、`identifiers/lib.rs:267`、`constants.rs:222,244` 并确认 `RealmId` 在 objects.rs 零引用，矛盾属实。

---

## 问题 03-3：README 要求公开面使用 `branch`，但 `forbidden_wire_fields` 把 `branch` 列为禁用字段

- **严重级别**：P1
- **证据**：
  - `README.md:25-26`：「All public SDK surfaces are expected to use `flow`, **branch**, relation and message semantics directly.」
  - `crates/core/src/forbidden_wire_fields.rs:158` 与 `:242`：`ForbiddenEntry { field: "branch", context: WireContext::TimelineEventTopLevel }`，注释 `:104` 「Generic timeline-event top-level property (legacy 'branch' guard).」
  - spec 对照：`forbidden-wire-fields.json` 将 `branch` 标为禁用（→ `track_name`）；`forbidden-model-terms.json` 将 `flow_branch` 标为禁用（→ `flow_track`）。
- **影响**：同一仓库一边在文档里指示使用 `branch`，一边在运行时守卫里拒绝 `branch`。任何遵循 README 的集成都会被本仓自带的 forbidden-field 校验拒绝——文档与执行逻辑互斥。
- **建议**：修正 `README.md:25-26`，把 `branch` 改为 `track`/`track_name`，与 forbidden 守卫和 spec 一致。
- **复验结论**：已核对 README 文句与 `forbidden_wire_fields.rs:158,242` 守卫条目，矛盾属实。

---

## 问题 03-4：`SyncResBody` 的 Realm 形状内部命名自相矛盾（`spaces`/`left_spaces` 承载 Realm，且双定义字段不一致）

- **严重级别**：P2
- **证据**：
  - `crates/core/src/model/api.rs:566-596` `SyncResBody`：字段名为 `spaces: BTreeMap<String, Value>`（注释 `:570-571` 自述「Realm sync bodies keyed by `cx:space:*` / `cx:realm:*`」）、`left_spaces: Vec<String>`（注释 `:575-578` 自述「**Realms** the viewer no longer has access to」），且方法 `effective_spaces()`（`:600`）返回的是「Realm sync map」。
  - 同名第二定义：`crates/core/src/sync.rs:19` 另有一个 `SyncReqBody`（字段 `filter: Option<SyncFilter>` + `subscriptions` + `wait_for`），与 `api.rs:543` 版本（`filter: Value`、无 `subscriptions`/`wait_for`）字段集合不一致。
- **影响**：(a) 字段名 `spaces`/`left_spaces` 与其注释/语义（实为 Realm 列表，键含 `cx:realm:*`）自相矛盾——读字段名得到「Space」、读注释得到「Realm」；这正是倒置未落地在 wire 字段名上的残留（`space_frontier`→`realm_frontier` 同类）。(b) 同名 `SyncReqBody` 双定义且字段不同，谁是权威取决于导入路径（详见报告 #09-3）。
- **建议**：wire 字段名随语义改为 `realms`/`left_realms`（或按 spec `cx.account.subscribe` 投影命名）；`SyncReqBody/ResBody` 收敛为单一权威定义。
- **复验结论**：已核对 `api.rs:566-600` 字段名与其注释、以及 `sync.rs:19` 与 `api.rs:543` 两个 `SyncReqBody`，「字段名 vs 注释语义」矛盾与「双定义字段不一致」均属实。
