//! Criterion microbenchmarks for the canonical-JSON hot path (SDK-SOTA-03).
//!
//! Run on demand with `cargo bench -p arkret-canonical`; never run in CI. Provides a
//! regression baseline for canonical serialization, strict-form validation and
//! parsing — the inner loop of every signing input and wire-envelope read.

use arkret_canonical as canonical;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

fn sample_value() -> serde_json::Value {
    json!({
        "actor_id": "ak:did_core:webvh:z6mkfixture",
        "created_at": "2026-06-29T00:00:00.000Z",
        "kind": arkret_wire::event_kind_str::MESSAGE_CREATE,
        "nested": {
            "a": [1, 2, 3, 4, 5],
            "b": {"x": "string value", "y": "另一个字符串", "z": true},
            "c": null
        },
        "items": (0..32).map(|i| json!({"i": i, "v": format!("item-{i}")})).collect::<Vec<_>>()
    })
}

fn bench_canonical(c: &mut Criterion) {
    let value = sample_value();
    let bytes = canonical::canonical_json_bytes(&value).expect("canonicalize sample");

    c.bench_function("canonical_json_bytes", |b| {
        b.iter(|| canonical::canonical_json_bytes(std::hint::black_box(&value)).unwrap())
    });

    c.bench_function("validate_canonical_bytes", |b| {
        b.iter(|| canonical::validate_canonical_bytes(std::hint::black_box(&bytes)).unwrap())
    });

    c.bench_function("parse_canonical_json", |b| {
        b.iter(|| canonical::parse_canonical_json(std::hint::black_box(&bytes)).unwrap())
    });

    c.bench_function("canonical_sha256", |b| {
        b.iter(|| canonical::canonical_sha256(std::hint::black_box(&value)).unwrap())
    });
}

criterion_group!(benches, bench_canonical);
criterion_main!(benches);
