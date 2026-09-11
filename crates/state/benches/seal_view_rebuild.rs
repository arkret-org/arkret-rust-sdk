//! What a Seal actually costs: the whole-Realm view rebuild, not one prebuilt
//! op array.
//!
//! review/spec-open/2026-09-05-1655-cas-causal-context-final-design-and-protocol-closure.md
//!
//! §8 says it plainly:
//! "当前 SDK `state/seal.rs` 对已覆盖操作全量收集再 join, 必须一起改为共享 view/checkpoint 与 delta
//! 更新, 否则即使新 join 是线性的, 每次全量重放仍可能造成总计二次成本." `causal_register.rs`
//! measures the new join and finds it linear, which is the half that was never in doubt. This
//! bench measures the half that is: [`effective_joined_view_at`] walks the Seal
//! predecessor closure, lists every cell in the Realm, reads every sealed op
//! batch of each, filters by the covered set and re-joins from scratch — on
//! every Seal.
//!
//! So a chain of `n` Seals pays `Θ(n)` per Seal and `Θ(n²)` in total, and a
//! bench that only ever calls the join once cannot see that. Read the two
//! groups together:
//!
//! - `seal_view_rebuild/chain_len` is one rebuild at the far end of an `n`-Seal chain. Linear
//!   growth here is the per-Seal cost, and it is the term that gets multiplied.
//! - `seal_chain_total/chain_len` replays the whole chain the way a receiver catching up does — one
//!   rebuild after each Seal. Its shape against `n` is the total, and it is what a checkpoint +
//!   delta design has to flatten.
//!
//! Run on demand with `cargo bench -p arkret-state --bench seal_view_rebuild`;
//! never run in CI.

use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;

use arkret_canonical::DigestSuite;
use arkret_identifiers::{CellRef, Hash, RealmId, SealId};
use arkret_state::lattice::SealedOp;
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::state::{
    CellStore, GovernanceView, MemoryCellRegistry, MemoryCellStore, MemorySealStore, SealStore,
    compute_state_root, control_event_set_root, effective_joined_view_at,
};
use arkret_wire::seal::{NotarySig, Seal, SealSignature};
use arkret_wire::{ActorId, DidCoreId, DidUrl, Hlc, LatticeOp, LatticeOpType};
use chrono::{TimeZone, Utc};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::json;

const SUITE: DigestSuite = DigestSuite::Sha256;

/// One rebuild each at 10³ / 10⁴ / 10⁵, the scales §10 asks for.
const REBUILD_SCALES: [usize; 3] = [1_000, 10_000, 100_000];

/// The whole-chain replay is quadratic by construction, so it is measured on a
/// decade the wall clock can still finish. The point is the *shape* across
/// these three, which extrapolates to the ones above.
const TOTAL_SCALES: [usize; 3] = [100, 200, 400];

fn realm() -> RealmId {
    RealmId::new("ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN".to_owned())
        .expect("a canonical realm id")
}

fn cell() -> CellRef {
    CellRef::new("ak:cell:ak.component.realm.policy.v1:null".to_owned())
        .expect("a registered policy cell reference")
}

fn move_id(index: usize) -> Hash {
    Hash::new(format!("sha256:{index:064x}")).expect("a padded hex digest is a valid Hash")
}

fn seal_seed(index: usize) -> SealId {
    SealId::new(format!("ak:seal:sha256:{index:064x}"))
        .expect("a padded hex digest is a valid SealId")
}

fn signature() -> SealSignature {
    SealSignature {
        verification_method: DidUrl::new("did:webvh:z6mkfixture:notary.example#k1")
            .expect("a fixture verification method"),
        payload_digest: move_id(0xff),
        jws: "AAAA.BBBB.CCCC".to_owned(),
    }
}

fn issuer() -> ActorId {
    ActorId::service(
        DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).expect("a fixture actor"),
    )
}

/// One Seal covering exactly one Move, chained onto its predecessor.
fn chained_seal(index: usize, predecessor: Option<&SealId>) -> Seal {
    let covered = vec![move_id(index)];
    let covered_set = covered.iter().cloned().collect::<BTreeSet<_>>();
    let mut seal = Seal {
        id: seal_seed(index),
        realm_id: realm(),
        predecessor_refs: predecessor.into_iter().cloned().collect(),
        delta: Vec::new(),
        control_event_set_root: control_event_set_root(&covered_set, SUITE)
            .expect("a covered set roots"),
        state_root: compute_state_root(GovernanceView::values_only(&BTreeMap::new()), SUITE)
            .expect("an empty state roots"),
        completeness_root: move_id(0x33),
        notary_seq: index as u64,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: covered,
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(signature()),
        sealed_at: Utc
            .with_ymd_and_hms(2026, 5, 8, 0, 0, 0)
            .single()
            .expect("a fixed timestamp"),
        hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).expect("a fixture HLC"),
    };
    seal.id = seal.derive_id(SUITE).expect("a Seal derives its own id");
    seal
}

/// The write that Seal carries: one `cas_register` set superseding its
/// predecessor, so the chain keeps exactly one head.
fn chained_write(index: usize) -> IssuedOp {
    let op = LatticeOp {
        op_type: LatticeOpType::Set,
        value: Some(json!({ "policy_revision": index })),
        ..LatticeOp::empty()
    };
    let sealed = if index == 0 {
        SealedOp::new(move_id(index), op)
    } else {
        SealedOp::superseding(move_id(index), op, vec![move_id(index - 1)])
    };
    IssuedOp {
        issuer_id: issuer(),
        op: sealed,
    }
}

struct Chain {
    seals: MemorySealStore,
    cells: MemoryCellStore,
    registry: MemoryCellRegistry,
    leaf: SealId,
}

async fn build_chain(len: usize) -> Chain {
    let realm = realm();
    let cell = cell();
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let mut previous: Option<SealId> = None;
    for index in 0..len {
        let seal = chained_seal(index, previous.as_ref());
        cells
            .append_sealed_effects(&realm, &seal.id, &[(cell.clone(), chained_write(index))])
            .await
            .expect("the memory store accepts a sealed effect");
        seals
            .put(&seal, SUITE)
            .await
            .expect("the memory store accepts a Seal");
        previous = Some(seal.id.clone());
    }
    Chain {
        seals,
        cells,
        registry: MemoryCellRegistry::default(),
        leaf: previous.expect("a chain has at least one Seal"),
    }
}

/// One view rebuild at the end of an `n`-Seal chain: what accepting Seal `n+1`
/// pays before it can check anything.
fn bench_one_rebuild(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime");
    let realm = realm();
    let mut group = criterion.benchmark_group("seal_view_rebuild");
    for len in REBUILD_SCALES {
        let chain = runtime.block_on(build_chain(len));
        group.throughput(Throughput::Elements(len as u64));
        group.bench_with_input(BenchmarkId::new("chain_len", len), &chain, |b, chain| {
            b.iter(|| {
                runtime.block_on(async {
                    black_box(
                        effective_joined_view_at(
                            black_box(std::slice::from_ref(&chain.leaf)),
                            &realm,
                            &chain.seals,
                            &chain.cells,
                            &chain.registry,
                        )
                        .await
                        .expect("the chain resolves"),
                    )
                })
            });
        });
    }
    group.finish();
}

/// The catch-up a receiver actually performs: rebuild the view once per Seal.
/// If the per-Seal cost is linear in the chain, this is quadratic, and that is
/// the claim §8 makes and this measures.
fn bench_chain_total(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime");
    let realm = realm();
    let mut group = criterion.benchmark_group("seal_chain_total");
    group.sample_size(10);
    for len in TOTAL_SCALES {
        let chain = runtime.block_on(build_chain(len));
        let leaves: Vec<SealId> = runtime.block_on(async {
            // Replaying the chain means rebuilding at every prefix, so each
            // prefix's leaf is needed. They are recomputed rather than kept
            // from `build_chain` so the measured loop reads exactly what a
            // receiver holds: a leaf id.
            let mut out = Vec::with_capacity(len);
            let mut previous: Option<SealId> = None;
            for index in 0..len {
                let seal = chained_seal(index, previous.as_ref());
                previous = Some(seal.id.clone());
                out.push(seal.id);
            }
            out
        });
        group.throughput(Throughput::Elements(len as u64));
        group.bench_with_input(
            BenchmarkId::new("chain_len", len),
            &(chain, leaves),
            |b, (chain, leaves)| {
                b.iter(|| {
                    runtime.block_on(async {
                        for leaf in leaves {
                            black_box(
                                effective_joined_view_at(
                                    std::slice::from_ref(leaf),
                                    &realm,
                                    &chain.seals,
                                    &chain.cells,
                                    &chain.registry,
                                )
                                .await
                                .expect("every prefix resolves"),
                            );
                        }
                    })
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_one_rebuild, bench_chain_total);
criterion_main!(benches);
