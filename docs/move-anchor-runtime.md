---
title: Move / Seal / State Model Runtime — arkret-rust-sdk 实现设计
---

> 本文是 **arkret-rust-sdk 内部实现设计**，不是 normative 协议。
> 协议层规则参见 arkret-spec：
>
> - Move/Seal/state-model 语义：[`authz/event-auth-state-resolution.md`](../../arkret-spec/spec/v1/zh/authz/event-auth-state-resolution.md) §3-§5
> - `state_root` canonical Merkle 编码（normative）：同上 §4.2
> - Seal batch 语义（`apply_seal` pseudocode）：同上 §4.3
> - Bottom diagnostics typed wire：[`bottom.schema.json`](../../arkret-spec/spec/v1/artifacts/schemas/bottom.schema.json)
>
> 本文给出 SDK 侧的 Rust 落地：crate 拆分、trait 签名、Move verifier
> 实现细节、缓存策略、与 soland 现有 reducer/projection 代码的迁移路径。
> 第三方 server 实现者可参考 §3 的 store trait 契约，但 SDK 不强制——
> spec 只 normative store 边界与跨实现需要互通的部分（state_root、
> apply_seal 步骤），具体 trait shape 是 SDK 选择。

## 1. 范围与读者

读者：在 arkret-rust-sdk 上写 M7-M10 PR 的开发者、要在 soland 上接线 store
backend 的开发者、需要理解 SDK 内部边界的 third-party 用户。

涵盖：

1. SDK 内部模块拆分与 crate 依赖方向。
2. Store trait 契约（MoveStore / SealStore / CellStore / CellRegistry）。
3. Move verifier 流水线 Rust 实现细节。
4. `apply_seal(A)` Rust 伪代码（行为对齐 spec §4.3）。
5. 三层缓存策略（L0 全历史 / L1 per-view / L2 process LRU）。
6. 权威 cell 状态层与用户面 projection 层的边界。
7. soland 旧 `StateReducer` / `ReducerKind` / `ProjectionState` 的迁移路径。

不涵盖：

- 协议层 normative 规则（在 arkret-spec）。
- wire schema 字段（在 [`arkret-spec/spec/v1/artifacts/schemas/`](../../arkret-spec/spec/v1/artifacts/schemas/)）。
- HTTP binding（在 [`arkret-spec/spec/v1/zh/sync/service-http-binding.md`](../../arkret-spec/spec/v1/zh/sync/service-http-binding.md)）。
- `state_root` Merkle 编码（normative，在 spec §4.2）。

## 2. 模块拆分

```text
                ┌───────────────────────────────┐
                │  Application / UI projection  │  user-facing 视图
                │  (messages, kanban, members)  │  从 cell state 派生
                └────────────────┬──────────────┘
                                 │ derive
                ┌────────────────▼──────────────┐
                │        Cell Effective State    │  权威源
                │  (cell_id → Value | Bottom)    │
                └─────┬───────────────────┬──────┘
                      │                   │
            ┌─────────▼────────┐  ┌───────▼────────────┐
            │   apply_seal   │  │  Move verifier     │
            │  (per-Seal)    │  │  (per-Move,        │
            │                  │  │   pre-Seal)      │
            └────────┬─────────┘  └────────┬───────────┘
                     │                     │
            ┌────────▼────────┐   ┌────────▼─────────┐
            │  SealStore +  │   │  MoveStore       │
            │  CellStore      │   │  (pending +      │
            │  (sealed op   │   │   sealed)      │
            │   log + cache)  │   │                  │
            └────────┬────────┘   └────────┬─────────┘
                     │                     │
                     └──────────┬──────────┘
                                │
                       ┌────────▼─────────┐
                       │  CellRegistry    │  cell_family →
                       │  (State model +      │  state model 实例 + 参数
                       │   bottom + 参数) │
                       └──────────────────┘
```

依赖方向：上层只依赖下层抽象；下层不引用上层具体类型。

- `arkret-wire`：typed model（`Move`、`Seal`、`Bottom`、`CellId`、`NotaryValue`）。
- `arkret_state::state_model`：五种正式 state model 实现，不依赖 store。
- `arkret_state::state`：托管 verifier 流水线、`apply_seal`、
  `effective_seal_view`、`state_root` 编码。**store traits 也住在这里**，
  让 SDK 用户 / soland / 第三方 server 三方都能依赖一份。
- `soland` / 第三方 server：实现 `MoveStore` / `SealStore` / `CellStore` /
  `CellRegistry`，并把 effective cell state 写入持久后端（Pg / RocksDB / 内存）。
- 用户面 projection（soland 的 `ProjectionState`、inkson 的 UI store）：从 cell
  state 派生，**不再直接消费 Move/Seal**，避免双源真相。

## 3. Store 接口契约

四个 trait 全部住在 `arkret_state::state::store` 模块。所有方法都返回 `Result`，
错误用 `arkret_wire::WireError` 表达 wire 级问题，用专属
`StoreError` 表达 IO / 后端失败。

### 3.1 MoveStore

```rust
trait MoveStore: Send + Sync {
    /// 暂存通过本地格式 / 签名初检的 pending Move。
    /// 同 id 重复 put MUST 是 idempotent（保留首次写入的 received_at）。
    fn put_pending(&self, m: &Move) -> Result<()>;

    /// 把 Move 标记为 sealed（被某 Seal.frontier 收纳）。
    /// 同 id 重复 seal MUST idempotent。
    fn mark_sealed(&self, id: &MoveId, seal: &SealId) -> Result<()>;

    fn get(&self, id: &MoveId) -> Result<Option<Move>>;

    /// 列出 notary worker 待处理的 pending Move（按 received_at 升序）。
    /// 实现 SHOULD 限制返回数量并支持游标，避免单次拉爆内存。
    fn list_pending_for_notary(
        &self,
        space_id: &SpaceId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> Result<Vec<Move>>;

    /// 列出已 sealed 的 Move（按 sealed_at + Move.id tiebreak）。
    /// 用于 federation backfill 与 audit replay。
    fn list_sealed(
        &self,
        space_id: &SpaceId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> Result<Vec<Move>>;
}
```

### 3.2 SealStore

```rust
trait SealStore: Send + Sync {
    fn put(&self, a: &Seal) -> Result<()>;
    fn get(&self, id: &SealId) -> Result<Option<Seal>>;

    /// Space 当前唯一已确认 Seal head。
    fn confirmed_head(&self, space_id: &SpaceId) -> Result<Option<SealId>>;

    /// 用于 apply_seal pre-check：非 genesis Seal 的 predecessor_ref 已知。
    fn predecessor_known(&self, predecessor_ref: Option<&SealId>) -> Result<bool>;

    /// genesis Seal。每个 Space 最多一个。
    fn genesis(&self, space_id: &SpaceId) -> Result<Option<SealId>>;
}
```

### 3.3 CellStore

```rust
trait CellStore: Send + Sync {
    /// 该 Space 内出现过至少一次 effect 的全部 cell。
    /// 用于 state_root 计算与全 Space 重 join。
    fn list_cells(&self, space_id: &SpaceId) -> Result<Vec<CellRef>>;

    /// 该 cell 全部 sealed Move 的 effect ops，按 deterministic 顺序。
    ///
    /// 顺序 = 各 Seal 内 Move 的 deterministic_order，按
    /// (Seal 拓扑序, Move.id) 串接（同 Seal 内 Move 间无序，由 state model
    /// commutativity 保证收敛）。
    fn sealed_ops_for_cell(
        &self,
        space_id: &SpaceId,
        cell: &CellRef,
    ) -> Result<Vec<SealedOp>>;

    /// 缓存的 effective cell state，键是当前 Seal leaf 集合的 hash。
    /// None 表示需要重 join。
    fn cached_state(
        &self,
        space_id: &SpaceId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> Result<Option<CellState>>;

    fn put_cached_state(
        &self,
        space_id: &SpaceId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &CellState,
    ) -> Result<()>;

    /// apply_seal 写入：把这一批新 sealed Move 的 effect 落到 cell log。
    /// 实现 MUST 在同一事务内更新 anchored_ops 与失效缓存条目。
    fn append_sealed_effects(
        &self,
        space_id: &SpaceId,
        seal: &SealId,
        new_ops: &[(CellRef, SealedOp)],
    ) -> Result<()>;
}
```

### 3.4 CellRegistry

```rust
trait CellRegistry: Send + Sync {
    /// 给定 cell，返回该 cell 的五种正式 state model 之一。
    ///
    /// 实现典型从 spec event-kind-registry 的 cell_family / lattice 字段加载。
    /// ordinary causal_register 总是产生唯一确定性 winner；Bottom 只可能由
    /// 另行注册的跨 Cell 领域不变量产生。内建 family 不允许由 Space 或 Realm 覆盖；
    /// Realm-specific extension family 按其显式登记解析。
    fn resolve(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<CellStateModelBinding>;
}

struct CellStateModelBinding {
    pub model: Box<dyn StateModel>,
}

```

实现注意：`CellRegistry::resolve` 调用频次很高（每条 Move precondition 都会
打），实现可缓存 `(realm_id, cell_family) → CellStateModelBinding`；内建 family 的 lattice 来自规范生成表，
Realm extension 的缓存须绑定其实际登记状态，不能用 Space schema 覆盖内建规则。

## 4. Move Verifier 流水线

每条 Move 在进入 Seal frontier 前 MUST 走完下面 4 步。失败的 Move 不进
frontier，已落进的旧 Move 不重验。

```text
verify_move(M, pre_state, registry) -> Result<(), MoveReject>:
  step 1: structural
    Move::validate_id(M)
    Move::validate_structural(M)
    M.sig.alg ∈ MOVE_SIGNATURE_ALGS

  step 2: signature
    canonical = M.canonical_bytes_for_id()
    digest = sha256(canonical)
    assert M.sig.payload_digest == digest
    verify_jws(M.sig.jws, canonical, M.sig.verification_method, M.issuer)

  step 3: capability
    for ref in M.refs where ref.role == "authorized_by":
      grant = resolve_grant(ref.id, pre_state)
      assert grant covers (M.issuer, M.effects, M.space_id)
    if no authorized_by ref: M.issuer MUST be a Space-builtin role
      (creator / member / device-owner) sufficient for all M.effects per
      cell schema.

  step 4: preconditions
    for (cell, predicate) in M.preconditions:
      binding = registry.resolve(M.space_id, cell)
      cell_state = pre_state[cell]   // CellState::Value or Bottom
      if cell_state.is_bottom():
        return Err(failed_bottom { cell, move_id: M.id })
      evaluate_predicate(predicate, cell_state)?

  step 5: effects shape
    for (cell, op) in M.effects:
      binding = registry.resolve(M.space_id, cell)
      binding.model.validate_op(op)?
      // Note: 不在这里执行 op；apply_all_effects_atomically 才执行。
```

`MoveReject` 区分四类原因，对应 spec
[`error-code-registry.json`](../../arkret-spec/spec/v1/artifacts/registry/error-code-registry.json)
中已有的 wire error codes：

| MoveReject 变体 | wire error_code |
| --- | --- |
| `SchemaViolation { detail }` | `schema_violation` |
| `InvalidSignature` | `invalid_signature` |
| `CapabilityDenied { grant_id?, missing }` | `capability_denied` |
| `FailedPrecondition { cell, predicate, observed }` | `state_mismatch` |
| `FailedBottom { cell, bottom }` | `failed_bottom` |

## 5. `apply_seal` 算法

`apply_seal(A, stores, registry)` 是 server 接收 Seal 时的入口。算法实现
spec §4.2 normative 文本，可以放在 `arkret_state::state::seal::apply_seal`。

```rust
fn apply_seal(
    a: &Seal,
    moves: &dyn MoveStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<SealEffect, SealReject> {
    // Step 1: structural + signature
    a.validate_id()?;
    a.validate_structural()?;
    verify_anchorer_sig(a, anchorer_value_at(a.predecessor_ref.as_ref(), cells, registry)?)?;

    // Step 2: predecessor 已知
    if !seals.predecessor_known(a.predecessor_ref.as_ref())? {
        return Err(SealReject::UnknownPredecessor);
    }

    // Step 3: frontier 单调
    let predecessor_frontier: HashSet<MoveId> =
        predecessor_frontier(a.predecessor_ref.as_ref(), seals, moves)?;
    if !is_superset(&a.frontier, &predecessor_frontier) {
        return Err(SealReject::FrontierNotMonotonic);
    }

    // Step 4: pre_state = state at the single confirmed predecessor
    let pre_state = effective_state_at(a.predecessor_ref.as_ref(), cells, registry)?;

    // Step 5: deterministic_order 走 new_moves，逐条 verify
    let new_move_ids: Vec<MoveId> =
        a.frontier.iter().filter(|m| !predecessor_frontier.contains(m)).cloned().collect();
    let new_moves: Vec<Move> = load_moves(&new_move_ids, moves)?;

    let ordered = deterministic_order(&new_moves);
    let mut accepted: Vec<Move> = Vec::with_capacity(ordered.len());
    let mut rejected: Vec<(MoveId, MoveReject)> = Vec::new();
    for m in ordered {
        match verify_move(&m, &pre_state, registry) {
            Ok(()) => accepted.push(m),
            Err(reject) => rejected.push((m.id.clone(), reject)),
        }
    }

    // Step 6: 原子 apply effects
    //   - 同 Seal 内 Move 视为并发批；一个 Move 不能读取同批另一 Move 的 effect
    //     （已被 verifier step 4 用 pre_state 而非滚动状态保证）。
    //   - 把 accepted 的 effects 一次性写入 CellStore.append_sealed_effects。
    let new_ops: Vec<(CellRef, SealedOp)> =
        flatten_effects(&accepted, &a.id);
    cells.append_sealed_effects(&a.space_id, &a.id, &new_ops)?;

    // Step 7: 计算 post_state Merkle root，比对 A.state_root
    let post_state = effective_state_at(&[a.id.clone()], cells, registry)?;
    let recomputed = merkle_state_root(&post_state)?;
    if recomputed != a.state_root {
        // 回滚 step 6
        cells.rollback_seal(&a.space_id, &a.id)?;
        return Err(SealReject::StateRootMismatch {
            declared: a.state_root.clone(),
            recomputed,
        });
    }

    // Step 8: 落 Seal，更新 leaves
    seals.put(a)?;
    for m in &accepted {
        moves.mark_sealed(&m.id, &a.id)?;
    }

    Ok(SealEffect { accepted_move_ids: ..., rejected, post_state_root: recomputed })
}
```

设计说明：

- **Move 部分接受不阻塞 Seal**：单条 Move 失败时只把它从这个 Seal 中剔除，
  Seal 仍可以接受。这与 spec §4.2 一致（"verify_move(M, pre_state)" 是 per-M
  谓词；pseudocode 没说 fail 整个 Seal）。但 notary 在签发 Seal 时
  SHOULD 已经把会 fail 的 Move 排掉；接收方再发现 fail Move 是 notary 失职信号，
  实现 SHOULD 记审计但仍接受 Seal。

- **state_root 不匹配 → 整个 Seal reject + 回滚**：这是硬错误，意味着
  notary 与本节点的 state model 实现 / cell registry / canonical encoding 不一致。
  没有"部分接受"的语义可言。

- **回滚原子性**：`cells.append_sealed_effects` 与 `cells.rollback_seal`
  必须由后端在同一事务内提供。Pg 实现走 SAVEPOINT；内存实现保留 seal →
  ops 反向索引。

## 6. `state_root` 计算（Rust 实现层）

`state_root` 的 canonical Merkle 编码是 **normative**，定义在
[arkret-spec event-auth-state-resolution.md §4.2](../../arkret-spec/spec/v1/zh/authz/event-auth-state-resolution.md)
（leaf shape、tree 形、空 list 处理、`bottom.anchor_view` 字段必须省略）。
SDK 实现 MUST 严格遵循。

实现位置：`arkret_state::state::state_root::compute_state_root(view: &SealView, cells: &dyn CellStore) -> Result<Hash>`。

实现要点：

- Leaf JSON 序列化复用 `arkret_canonical::canonical::canonical_json_bytes`，确保
  与 Move/Seal canonical bytes 同一编码 profile（key 排序、no whitespace、
  integer-only number、UTF-8）。
- `Bottom` 序列化时 set `bottom.anchor_view = None` 后再 canonical_json，
  避免自递归。这是 [`bottom.rs`](../crates/wire/src/bottom.rs) 已有的
  `#[serde(skip_serializing_if = "Option::is_none")]` 行为，无需特殊代码。
- Merkle 树 SHOULD 用增量算法（只重算受影响 leaf 所在的分支）；wire 上的
  `state_root` 必须 byte-for-byte 等于全量重算结果——以全量重算结果作为
  conformance 测试基线。
- 空 list 的 root 是 `sha256("")`（spec §4.2.2 锁定的常量）：
  `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。

genesis Seal 的 state_root 不是固定常量——它取决于 genesis frontier 内
Move 写入的 cell 集合（典型至少含 `ak:cell:ak.component.space.lifecycle.v1:<space_id>`
等核心 cell）。compute_state_root 一视同仁不分 genesis/非 genesis。

## 7. 缓存策略

`StateModel::resolve` 是 stateless：每次取全量 sealed ops。这对小 cell 没问题，
对大 cell（消息 ordered-log、长生命周期 or-set）必须分层缓存，否则一次读
退化到 O(n)。

### 7.1 三层

```text
L0: sealed_ops_for_cell(space, cell)  // 全历史，权威
L1: cached_state(space, cell, view_hash) // per-view 快照
L2: process-local LRU                    // 单进程内热点
```

- L0 是事实源；任何时候可以用 L0 重算 L1 / L2。
- L1 写入条件：L1 cache 为空，或 view_hash 变了，或 cache TTL 过期。Seal
  落地后 L1 失效条件 = 该 Seal 触动的 cell 集合（来自
  `append_sealed_effects(new_ops)` 输入的 cell 集）。
- L2 是实现细节，同进程多请求复用，绝不持久化。

### 7.2 view_hash 计算

```text
view_hash = sha256(canonical_json(sorted([leaf.id for leaf in leaves])))
```

只看 leaf id 集合，不看 leaf 内容；compaction Seal 会换 leaf id 但保持等
价 effective state，因此换 view_hash 是预期行为（cache 重算一次即可）。

### 7.3 增量重 join

`apply_seal` 提交时已经知道哪些 cell 被新 Move 触及（`new_ops` 的 cell 集
合）。增量重 join 只对这些 cell 重跑 `StateModel::resolve`，其他 cell 的 L1 cache
直接 promote 到新 view_hash 下复用。

## 8. 用户面 Projection

cell effective state 是协议授权与 Seal finality 的源。用户面 projection
（chat 消息列表、kanban 看板、成员列表）是从 cell state 派生的视图层，可以
带语义优化：

- `messages` projection 维护 `(realm_id, strand_id, track_name) → ordered list of MessageState`，从
  消息 cell（ordered-log）派生 + 解密 + 应用本地隐私规则。
- `members` projection 维护 `(realm_id, member_did) → MembershipState`，从
  member.state sequenced_state cell派生 + 跨 cell 聚合（presence、device、profile）。
- `kanban` projection 维护看板布局，从 Space cell（`kind=board`）+ Strand cell
  派生。

设计原则：

1. **projection 不是真相源**：它可以重建（对 `list_cells` + 重 join 加局部
   后处理），不能用于 Move precondition 评估或 Seal state_root 计算。
2. **异步派生**：projection 可以在 `append_sealed_effects` 后异步更新，
   API 读 projection 时如果 lag 严重 SHOULD 退化到从 cell state 重建。
3. **没有专属 store trait**：每个 projection 自己定义存储；soland 的
   `ProjectionState` 是一个具体例子，第三方 server 不必复用。

## 9. CellRegistry 加载

cell_family → state model 的映射来自 spec event-kind-registry。每个 active
state-bearing kind 在
[`event-kind-registry.json`](../../arkret-spec/spec/v1/artifacts/registry/event-kind-registry.json)
中声明：

```json
{
  "kind": "ak.member.state",
  "cell_family": "ak.component.member.state.v1",
  "cell_subject": { "form": "did", "field": "actor_id" },
  "lattice": {
    "state_model": "sequenced_state",
    "allowed_transitions": [
      ["invited", "join"],
      ["join", "leave"],
      ["join", "ban"],
      ["leave", "join"]
    ],
    "initial": "invited"
  }
}
```

`CellRegistry::resolve` 默认实现：

```rust
fn resolve(&self, space_id, cell) -> Result<CellStateModelBinding> {
    let cell_id = CellId::from_ref(cell)?;
    let family = cell_id.component();

    // Space-级 schema 偏离（写到 Space schema cell 的 Move）有最高优先级。
    if let Some(override_) = self.space_schema(space_id)?.cell_lattice(family) {
        return Ok(self.instantiate(override_));
    }

    // 默认从 spec registry 加载。
    let entry = self.spec_registry.find_by_cell_family(family)
        .ok_or_else(|| Error::Protocol(format!("unknown cell family: {family}")))?;
    Ok(self.instantiate(entry.lattice))
}
```

未注册的 cell_family MUST 走 fail-closed：`Error::Protocol("unknown cell family")`，
对应 wire error code `unsupported_event_kind`。

## 10. 实现路线图

落地顺序（每条 ≤1 PR）：

1. **store traits + 内存实现**（`arkret_state::state::store::memory`）：让 SDK
   测试不依赖 Pg。
2. **CellRegistry + spec registry 加载器**：消费 event-kind-registry.json 的
   `cell_family` / `lattice` 字段。
3. **Move verifier**：四步流水线，单元测试使用现有
   [`seal-submit-fixture.json`](../../arkret-spec/spec/v1/artifacts/fixtures/seal-submit-fixture.json)
   的 schema 与 semantic admission cases 固定期望。
4. **state_root Merkle 计算**：纯函数（按 spec §4.2 normative 编码），可单测。
5. **`apply_seal` 算法**：把上面 1-4 串起来。
6. **`effective_seal_view` 纯函数**：多 leaf 收敛 + signed compaction。
7. **soland 适配**：实现 store traits 后端（先内存，再 Pg），把 `ProjectionState`
   降级为派生层。

每一步都能独立合并 + 测试。前 6 步全在 SDK 内（不动 server），第 7 步是
soland 接线。

## 11. 与现有 state-res / reducer 的关系

- 旧 `StateReducer` / `state_digest` / `is_state_event`
  / `subject_for_event` / `candidate_wins` **整体删除**，不保留并行入口。
- 旧 `soland::reducer::ReducerKind` (per event_kind) 改为 spec
  registry 的 `cell_family` 表现，soland 不再为每个 kind 写一个 ZST。
- 旧 `soland::reducer::ProjectionState` **保留**，作为 §8 用户面 projection
  示例。注释说明它是从 cell state 派生的视图层。

## 12. 不在本文范围

- Move / Seal wire schema 字段细节 →
  [`seal.schema.json`](../../arkret-spec/spec/v1/artifacts/schemas/seal.schema.json)
  及 event/auth-state 规范中的 Move 语义。
- HTTP binding（Move Event Envelope 经 `POST /_arkret/self/events` 提交，
  Seal 经 `POST /_arkret/self/events/seals` 提交）→
  [`service-http-binding.md`](../../arkret-spec/spec/v1/zh/sync/service-http-binding.md)。
- Federation Move 广播 + Seal 拉取语义 →
  [`federation.md`](../../arkret-spec/spec/v1/zh/sync/federation.md)。
- MLS commit Move 与 security frontier 的联动细节 →
  [`audited-e2ee.md`](../../arkret-spec/spec/v1/zh/crypto-media/audited-e2ee.md)。
- Recovery notary / emergency quorum 启用程序 →
  [`event-auth-state-resolution.md`](../../arkret-spec/spec/v1/zh/authz/event-auth-state-resolution.md) §13。
