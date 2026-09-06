//! Scale measurements for the causal-register recompute path.
//!
//! `arkret-work/review/spec-open/
//! 2026-09-05-1655-cas-causal-context-final-design-and-protocol-closure.md` §10 asks for 10³ / 10⁴
//! / 10⁵ numbers on the register, because the whole design rests on recomputing a
//! cell's active head set from its op log on every view. If that recompute is
//! superlinear, the design is only correct on paper.
//!
//! Run on demand with `cargo bench -p arkret-state`; never run in CI.

use std::hint::black_box;

use arkret_identifiers::{CellRef, Hash};
use arkret_state::lattice::cas_register::cas_heads;
use arkret_state::lattice::{CasRegister, Lattice, SealedOp};
use arkret_wire::{LatticeOp, LatticeOpType};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::json;

const SCALES: [usize; 3] = [1_000, 10_000, 100_000];

fn move_id(index: usize) -> Hash {
    Hash::new(format!("sha256:{index:064x}")).expect("a padded hex digest is a valid Hash")
}

fn cell() -> CellRef {
    CellRef::new(
        "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
    )
    .expect("a registered policy cell reference")
}

/// A linear history: every write supersedes exactly its predecessor, so one
/// head survives. This is the shape a long-lived governance cell actually has.
fn linear_chain(len: usize) -> Vec<SealedOp> {
    (0..len)
        .map(|index| {
            let op = LatticeOp {
                op_type: LatticeOpType::Set,
                value: Some(json!({ "policy_revision": index })),
                ..LatticeOp::empty()
            };
            if index == 0 {
                SealedOp::new(move_id(index), op)
            } else {
                SealedOp::superseding(move_id(index), op, vec![move_id(index - 1)])
            }
        })
        .collect()
}

/// A wide history: every write supersedes the same first write, so the whole
/// tail stays a head. This is the worst case for the head set's own size, and
/// the shape a cell in `⊥` is stuck in until a recovery lands.
fn wide_fan(len: usize) -> Vec<SealedOp> {
    (0..len)
        .map(|index| {
            let op = LatticeOp {
                op_type: LatticeOpType::Set,
                value: Some(json!({ "branch": index })),
                ..LatticeOp::empty()
            };
            if index == 0 {
                SealedOp::new(move_id(index), op)
            } else {
                SealedOp::superseding(move_id(index), op, vec![move_id(0)])
            }
        })
        .collect()
}

fn bench_cas_heads(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("cas_heads");
    for len in SCALES {
        group.throughput(Throughput::Elements(len as u64));
        let chain = linear_chain(len);
        group.bench_with_input(BenchmarkId::new("linear_chain", len), &chain, |b, ops| {
            b.iter(|| black_box(cas_heads(black_box(ops)).expect("a linear chain resolves")));
        });
        let fan = wide_fan(len);
        group.bench_with_input(BenchmarkId::new("wide_fan", len), &fan, |b, ops| {
            b.iter(|| black_box(cas_heads(black_box(ops)).expect("a wide fan resolves")));
        });
    }
    group.finish();
}

/// The same histories through `Lattice::join`, which is what a read path calls:
/// it collapses the heads to one value, or to `⊥` when they disagree.
fn bench_join(criterion: &mut Criterion) {
    let cell = cell();
    let mut group = criterion.benchmark_group("cas_register_join");
    for len in SCALES {
        group.throughput(Throughput::Elements(len as u64));
        let chain = linear_chain(len);
        group.bench_with_input(BenchmarkId::new("linear_chain", len), &chain, |b, ops| {
            b.iter(|| black_box(CasRegister.join(black_box(&cell), black_box(ops))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_cas_heads, bench_join);
criterion_main!(benches);
