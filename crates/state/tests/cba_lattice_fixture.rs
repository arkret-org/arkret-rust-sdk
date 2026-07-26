//! Executable consumer for the spec fixture
//! `fixtures/cba-lattice-fixture.json`.
//!
//! Coverage split (mirrors the fixture's own `lattice_round_trip` metadata):
//!
//! * The `lattice_round_trip.cases` block names the pure-lattice and Realm Link FSM vectors whose
//!   join semantics are implemented directly by [`arkret_state::lattice`]. This test executes every
//!   declared assertion of those cases against the SDK lattice types, so a join-semantics drift
//!   fails in the SDK's own CI.
//! * The sixteen `vectors` entries are dual-plane CBA scenarios (DataEvent vs control Move, seal
//!   coverage, quarantine, notary faults). They need the full CBA reducer + seal pipeline, which
//!   the SDK does not host; the cotest state-resolution harness remains their executable owner.
//!   Here they are pinned as an inventory gate (vector_id + expected block present) so silent
//!   fixture renames/removals still surface in the SDK.

use arkret_models_collaboration::governance::realm_governance::{
    REALM_LINK_ALLOWED_TRANSITIONS, REALM_LINK_INITIAL_STATES, REALM_LINK_TERMINAL_STATES,
    RealmLinkKind, RealmLinkPayload, RealmLinkStatus, RealmLinkTransitionCandidate,
    RealmLinkTransitionOutcome, evaluate_realm_link_transition,
};
use arkret_schema::embedded_json_artifact;
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{
    CasRegister, CellState, Counter, Fsm, Lattice, MvRegister, OrderedLog, SealedOp,
};
use arkret_wire::{CellRef, Did, LatticeOp, LatticeOpType, MoveId, RealmId, ReasonCode};
use serde_json::{Value, json};

const FIXTURE_PATH: &str = "fixtures/cba-lattice-fixture.json";

fn fixture() -> Value {
    embedded_json_artifact(FIXTURE_PATH).expect("embedded cba-lattice fixture must load")
}

fn cell() -> CellRef {
    CellRef::new("ak:cell:ak.component.fixture.v1:ak.subject.fixture".to_owned())
        .expect("fixture cell id must be valid")
}

fn move_id(suffix: &str) -> MoveId {
    let padding = 64usize.saturating_sub(suffix.len());
    MoveId::new(format!("sha256:{suffix}{}", "0".repeat(padding)))
        .expect("fixture move id must be valid")
}

fn base_op() -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Add,
        tag: None,
        value: None,
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    }
}

fn op_set(value: Value) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Set,
        value: Some(value),
        ..base_op()
    }
}

fn op_inc(value: u64) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Inc,
        value: Some(json!(value)),
        ..base_op()
    }
}

fn op_dec(value: u64) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Dec,
        value: Some(json!(value)),
        ..base_op()
    }
}

fn op_transition(from: Value, to: Value) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Transition,
        from: Some(from),
        to: Some(to),
        ..base_op()
    }
}

fn op_append(value: Value, issuer_seq: u64) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Append,
        value: Some(value),
        issuer_seq: Some(issuer_seq),
        ..base_op()
    }
}

fn issued(issuer: &str, suffix: &str, op: LatticeOp) -> IssuedOp {
    IssuedOp {
        issuer: Did::new(issuer.to_owned()).expect("fixture issuer must be a valid DID"),
        op: SealedOp::new(move_id(suffix), op),
    }
}

fn value_of(state: CellState) -> Value {
    match state {
        CellState::Value(value) => value,
        CellState::Bottom(bottom) => panic!("expected a resolved value, got Bottom: {bottom:?}"),
    }
}

fn realm_link_payload(status: RealmLinkStatus, target_realm_id: RealmId) -> RealmLinkPayload {
    RealmLinkPayload {
        target_realm_id,
        link_kind: RealmLinkKind::GovernedBy,
        status,
        label: None,
        commitment: None,
    }
}

fn realm_id(suffix: &str) -> RealmId {
    RealmId::new(format!("ak:realm:01904100-0000-7000-8000-{suffix:0>12}")).unwrap()
}

/// Dispatch table: executes every assertion string the fixture's
/// `lattice_round_trip.cases` declare, against the SDK lattice types.
/// Unknown assertions fail the test so newly added fixture assertions
/// cannot be silently skipped.
fn run_assertion(lattice_kind: &str, assertion: &str, case: &Value) {
    let cref = cell();
    match (lattice_kind, assertion) {
        ("mv_register", "concurrent_set_surfaces_all_heads") => {
            // The SDK's reference MvRegister renders concurrent heads through
            // a Bottom whose `heads[]` carries every value (a Value array is
            // also spec-acceptable); both concurrent values MUST be visible.
            let ops = vec![
                SealedOp::new(move_id("aa"), op_set(json!("left"))),
                SealedOp::new(move_id("bb"), op_set(json!("right"))),
            ];
            let surfaces_both = match MvRegister.join(&cref, &ops) {
                CellState::Value(value) => {
                    let text = serde_json::to_string(&value).unwrap();
                    text.contains("left") && text.contains("right")
                }
                CellState::Bottom(bottom) => {
                    let heads: Vec<&str> = bottom.heads.iter().filter_map(Value::as_str).collect();
                    heads.contains(&"left")
                        && heads.contains(&"right")
                        && bottom.move_ids.len() >= 2
                }
            };
            assert!(surfaces_both, "mv_register must surface both heads");
        }
        ("mv_register", "does_not_choose_winner") => {
            // Neither surfacing form may collapse to exactly one input value.
            let ops = vec![
                SealedOp::new(move_id("aa"), op_set(json!("left"))),
                SealedOp::new(move_id("bb"), op_set(json!("right"))),
            ];
            match MvRegister.join(&cref, &ops) {
                CellState::Value(value) => {
                    assert!(
                        value != json!("left") && value != json!("right"),
                        "mv_register must not pick a single winner: {value}"
                    );
                }
                CellState::Bottom(bottom) => {
                    assert!(
                        bottom.heads.len() >= 2,
                        "mv_register Bottom must keep every head: {bottom:?}"
                    );
                }
            }
            // Contrast: single-writer CAS still resolves to a plain value.
            let single = vec![SealedOp::new(move_id("aa"), op_set(json!("only")))];
            assert_eq!(value_of(CasRegister.join(&cref, &single)), json!("only"));
        }
        ("counter", "pn_sum_is_deterministic") => {
            let ops = vec![
                SealedOp::new(move_id("aa"), op_inc(5)),
                SealedOp::new(move_id("bb"), op_dec(2)),
                SealedOp::new(move_id("cc"), op_inc(1)),
            ];
            let first = value_of(Counter.join(&cref, &ops));
            let second = value_of(Counter.join(&cref, &ops));
            assert_eq!(first, second, "counter join must be deterministic");
            assert_eq!(
                first["count"].as_i64().or_else(|| first.as_i64()),
                Some(4),
                "PN counter must sum to 4: {first}"
            );
        }
        ("counter", "inc_dec_replay_order_independent") => {
            let forward = vec![
                SealedOp::new(move_id("aa"), op_inc(5)),
                SealedOp::new(move_id("bb"), op_dec(2)),
            ];
            let reversed = vec![
                SealedOp::new(move_id("bb"), op_dec(2)),
                SealedOp::new(move_id("aa"), op_inc(5)),
            ];
            assert_eq!(
                value_of(Counter.join(&cref, &forward)),
                value_of(Counter.join(&cref, &reversed)),
                "counter join must be arrival-order independent"
            );
        }
        ("ordered_log", "per_issuer_sequence_order") => {
            let ops = vec![
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a2",
                    op_append(json!("second"), 1),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a1",
                    op_append(json!("first"), 0),
                ),
            ];
            let resolved = value_of(OrderedLog.join_with_issuers(&cref, &ops));
            let text = serde_json::to_string(&resolved).unwrap();
            let first_pos = text.find("first").expect("log must contain first entry");
            let second_pos = text.find("second").expect("log must contain second entry");
            assert!(
                first_pos < second_pos,
                "per-issuer seq order must linearize 0 before 1: {text}"
            );
        }
        ("ordered_log", "issuer_prefix_starts_at_seq_zero") => {
            // Only seq 3 arrived. The prefix is anchored at 0, so nothing
            // materializes and the gap is reported against seq 0 — starting at
            // the lowest seq actually seen would publish an entry whose own
            // predecessors are still missing.
            let ops = vec![issued(
                "did:webvh:z6mkfixture:alice.example",
                "a3",
                op_append(json!("late"), 3),
            )];
            let report = OrderedLog.join_with_issuer_report(&ops);
            assert!(
                report.entries.is_empty(),
                "contiguous prefix must not start at seq 3"
            );
            assert_eq!(report.pending_gaps.len(), 1);
            assert_eq!(report.pending_gaps[0].missing_seq, 0);
            assert_eq!(report.pending_gaps[0].pending_seq, 3);
        }
        ("ordered_log", "byte_identical_effect_op_is_idempotent") => {
            let ops = vec![
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a1",
                    op_append(json!("same"), 0),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a2",
                    op_append(json!("same"), 0),
                ),
            ];
            let report = OrderedLog.join_with_issuer_report(&ops);
            assert_eq!(report.entries.len(), 1, "byte-identical op must dedupe");
            assert!(
                report.equivocations.is_empty(),
                "an idempotent reappend is not equivocation"
            );
            assert!(report.fail_closed.is_empty());
        }
        ("ordered_log", "same_issuer_seq_equivocation_uses_max_event_digest") => {
            // Same slot, different canonical `effect.op`: the greater
            // event_digest wins. `entry_id` inside op.value must not decide it,
            // so the loser here carries the lexicographically smaller id.
            let ops = vec![
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a1",
                    op_append(json!({"entry_id": "entry-a"}), 0),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "b2",
                    op_append(json!({"entry_id": "entry-b"}), 0),
                ),
            ];
            let report = OrderedLog.join_with_issuer_report(&ops);
            assert_eq!(report.entries.len(), 1);
            let text = serde_json::to_string(&report.entries).unwrap();
            assert!(
                text.contains("entry-b") && !text.contains("entry-a"),
                "greatest event_digest must win, not the smallest entry_id: {text}"
            );
        }
        ("ordered_log", "equivocation_winner_is_independent_of_causal_edges") => {
            // The lattice sees no causal edges, so the observable requirement is
            // that no input permutation can change the winner.
            let ops = vec![
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a1",
                    op_append(json!("left"), 0),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "b2",
                    op_append(json!("right"), 0),
                ),
            ];
            let forward = OrderedLog.join_with_issuer_report(&ops);
            let mut reversed_ops = ops;
            reversed_ops.reverse();
            let reversed = OrderedLog.join_with_issuer_report(&reversed_ops);
            assert_eq!(
                forward.entries, reversed.entries,
                "arrival order must not change the slot winner"
            );
            assert_eq!(forward.equivocations, reversed.equivocations);
        }
        ("ordered_log", "equivocation_loser_remains_in_canonical_log") => {
            let ops = vec![
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a1",
                    op_append(json!("loser"), 0),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "b2",
                    op_append(json!("winner"), 0),
                ),
            ];
            let report = OrderedLog.join_with_issuer_report(&ops);
            assert_eq!(report.equivocations.len(), 1, "losers must stay auditable");
            assert_eq!(report.equivocations[0].issuer_seq, 0);
            assert_eq!(report.equivocations[0].loser_event_digests.len(), 1);
            assert_ne!(
                report.equivocations[0].winner_event_digest,
                report.equivocations[0].loser_event_digests[0]
            );
        }
        ("ordered_log", "max_event_digest_compares_decoded_octets_across_suites") => {
            // As UTF-8 wire strings "sha256:00.." sorts above "blake3:ff..",
            // but the decoded octets order the other way. §4.2 compares octets,
            // so the blake3 candidate must win.
            let alice = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
            let ops = vec![
                IssuedOp {
                    issuer: alice.clone(),
                    op: SealedOp::new(
                        MoveId::new(format!("blake3:{}", "ff".repeat(32))).unwrap(),
                        op_append(json!("greatest-octets"), 0),
                    ),
                },
                IssuedOp {
                    issuer: alice,
                    op: SealedOp::new(
                        MoveId::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
                        op_append(json!("greatest-wire-string"), 0),
                    ),
                },
            ];
            let report = OrderedLog.join_with_issuer_report(&ops);
            assert_eq!(report.entries.len(), 1);
            let text = serde_json::to_string(&report.entries).unwrap();
            assert!(
                text.contains("greatest-octets"),
                "winner must follow decoded octets, not the typed wire string: {text}"
            );
        }
        ("ordered_log", "distinct_digest_preimage_same_event_digest_fails_closed") => {
            // `effect.op` is part of the digest preimage, so two different ops
            // under one typed digest are a collision.
            let alice = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
            let colliding = move_id("cc");
            let ops = vec![
                IssuedOp {
                    issuer: alice.clone(),
                    op: SealedOp::new(colliding.clone(), op_append(json!("one"), 0)),
                },
                IssuedOp {
                    issuer: alice,
                    op: SealedOp::new(colliding, op_append(json!("other"), 0)),
                },
            ];
            let report = OrderedLog.join_with_issuer_report(&ops);
            assert!(
                report.entries.is_empty(),
                "a colliding slot must not materialize an entry"
            );
            assert_eq!(report.fail_closed.len(), 1);
            assert_eq!(report.fail_closed[0].reason, "digest_collision");
        }
        ("ordered_log", "proofs_or_reducer_stamp_difference_is_not_a_digest_collision") => {
            // `proofs`, `unsigned` and reducer stamps are excluded from the
            // digest preimage, so two such variants reach the lattice as the
            // same digest over the same canonical op — a duplicate, never a
            // collision.
            let alice = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
            let shared = move_id("dd");
            let ops = vec![
                IssuedOp {
                    issuer: alice.clone(),
                    op: SealedOp::new(shared.clone(), op_append(json!("same"), 0)),
                },
                IssuedOp {
                    issuer: alice,
                    op: SealedOp::new(shared, op_append(json!("same"), 0)),
                },
            ];
            let report = OrderedLog.join_with_issuer_report(&ops);
            assert!(
                report.fail_closed.is_empty(),
                "identical digest preimage must not be reported as a collision"
            );
            assert_eq!(report.entries.len(), 1);
        }
        ("ordered_log", "gap_after_contiguous_prefix_is_pending_diagnostic") => {
            let ops = vec![
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a0",
                    op_append(json!("zero"), 0),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a1",
                    op_append(json!("one"), 1),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a3",
                    op_append(json!("three"), 3),
                ),
            ];
            let report = OrderedLog.join_with_issuer_report(&ops);
            assert_eq!(
                report.pending_gaps.len(),
                1,
                "seq gap (0,1 then 3) must be reported as pending"
            );
            assert_eq!(report.pending_gaps[0].missing_seq, 2);
            assert_eq!(report.pending_gaps[0].reason, "dependency_missing");
        }
        ("ordered_log", "pending_gap_entry_does_not_enter_cell_value") => {
            let ops = vec![
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a1",
                    op_append(json!("one"), 0),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a3",
                    op_append(json!("three"), 3),
                ),
            ];
            let resolved = value_of(OrderedLog.join_with_issuers(&cref, &ops));
            let text = serde_json::to_string(&resolved).unwrap();
            assert!(
                text.contains("one"),
                "contiguous prefix must be visible: {text}"
            );
            assert!(
                !text.contains("three"),
                "post-gap entry must stay out of the cell value: {text}"
            );
        }
        ("ordered_log", "backfill_recompute_is_arrival_order_independent") => {
            let complete = vec![
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a1",
                    op_append(json!("one"), 0),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a2",
                    op_append(json!("two"), 1),
                ),
                issued(
                    "did:webvh:z6mkfixture:alice.example",
                    "a3",
                    op_append(json!("three"), 2),
                ),
            ];
            let mut shuffled = complete.clone();
            shuffled.swap(0, 2);
            assert_eq!(
                value_of(OrderedLog.join_with_issuers(&cref, &complete)),
                value_of(OrderedLog.join_with_issuers(&cref, &shuffled)),
                "backfilled recompute must be arrival-order independent"
            );
        }
        ("fsm", "duplicate_same_transition_idempotent") => {
            let fsm =
                Fsm::new(vec![(json!("draft"), json!("active"))]).with_initial(json!("draft"));
            let ops = vec![
                SealedOp::new(
                    move_id("aa"),
                    op_transition(json!("draft"), json!("active")),
                ),
                SealedOp::new(
                    move_id("bb"),
                    op_transition(json!("draft"), json!("active")),
                ),
            ];
            let resolved = value_of(fsm.join(&cell(), &ops));
            let text = serde_json::to_string(&resolved).unwrap();
            assert!(
                text.contains("active"),
                "duplicate identical transition must be idempotent: {text}"
            );
        }
        ("fsm", "same_from_different_to_returns_bottom") => {
            let fsm = Fsm::new(vec![
                (json!("draft"), json!("active")),
                (json!("draft"), json!("archived")),
            ])
            .with_initial(json!("draft"));
            let ops = vec![
                SealedOp::new(
                    move_id("aa"),
                    op_transition(json!("draft"), json!("active")),
                ),
                SealedOp::new(
                    move_id("bb"),
                    op_transition(json!("draft"), json!("archived")),
                ),
            ];
            assert!(
                fsm.join(&cell(), &ops).is_bottom(),
                "conflicting transitions from one state must produce Bottom"
            );
        }
        ("fsm", "all_declared_initial_states_are_accepted") => {
            let declared: Vec<&str> = case["parameters"]["initial_states"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect();
            let canonical: Vec<&str> = REALM_LINK_INITIAL_STATES
                .iter()
                .map(|status| status.as_str())
                .collect();
            assert_eq!(declared, canonical);
            assert!(
                REALM_LINK_INITIAL_STATES
                    .iter()
                    .all(|status| status.is_initial())
            );
        }
        ("fsm", "every_declared_transition_is_accepted") => {
            let declared = case["parameters"]["allowed_transitions"]
                .as_array()
                .unwrap();
            assert_eq!(declared.len(), REALM_LINK_ALLOWED_TRANSITIONS.len());
            for pair in declared {
                let pair = pair.as_array().unwrap();
                let from = RealmLinkStatus::parse(pair[0].as_str().unwrap()).unwrap();
                let to = RealmLinkStatus::parse(pair[1].as_str().unwrap()).unwrap();
                assert!(from.can_transition_to(to));
            }
        }
        ("fsm", "undeclared_transition_rejects_with_realm_link_invalid_transition") => {
            let source = realm_id("1");
            let current_payload = realm_link_payload(RealmLinkStatus::Tombstoned, realm_id("2"));
            for to in [RealmLinkStatus::Active, RealmLinkStatus::Rejected] {
                let next_payload = realm_link_payload(to, realm_id("2"));
                let error = evaluate_realm_link_transition(
                    &source,
                    Some(RealmLinkTransitionCandidate {
                        payload: &current_payload,
                        canonical_move_bytes: b"tombstone",
                        canonical_basis_bytes: b"basis-1",
                    }),
                    RealmLinkTransitionCandidate {
                        payload: &next_payload,
                        canonical_move_bytes: b"candidate",
                        canonical_basis_bytes: b"basis-2",
                    },
                )
                .unwrap_err();
                assert_eq!(
                    error.reason_code(),
                    ReasonCode::REALM_LINK_INVALID_TRANSITION
                );
            }
        }
        ("fsm", "tombstoned_is_terminal_except_byte_equivalent_replay") => {
            assert_eq!(REALM_LINK_TERMINAL_STATES, &[RealmLinkStatus::Tombstoned]);
            let source = realm_id("1");
            let current_payload = realm_link_payload(RealmLinkStatus::Tombstoned, realm_id("2"));
            let replay_payload = current_payload.clone();
            let outcome = evaluate_realm_link_transition(
                &source,
                Some(RealmLinkTransitionCandidate {
                    payload: &current_payload,
                    canonical_move_bytes: b"tombstone",
                    canonical_basis_bytes: b"basis",
                }),
                RealmLinkTransitionCandidate {
                    payload: &replay_payload,
                    canonical_move_bytes: b"tombstone",
                    canonical_basis_bytes: b"basis",
                },
            )
            .unwrap();
            assert_eq!(outcome, RealmLinkTransitionOutcome::IdempotentReplay);
        }
        ("fsm", "same_status_same_basis_replay_is_idempotent") => {
            let source = realm_id("1");
            let current_payload = realm_link_payload(RealmLinkStatus::Active, realm_id("2"));
            let replay_payload = current_payload.clone();
            let outcome = evaluate_realm_link_transition(
                &source,
                Some(RealmLinkTransitionCandidate {
                    payload: &current_payload,
                    canonical_move_bytes: b"same",
                    canonical_basis_bytes: b"same-basis",
                }),
                RealmLinkTransitionCandidate {
                    payload: &replay_payload,
                    canonical_move_bytes: b"same",
                    canonical_basis_bytes: b"same-basis",
                },
            )
            .unwrap();
            assert_eq!(outcome, RealmLinkTransitionOutcome::IdempotentReplay);
        }
        ("fsm", "same_basis_different_status_siblings_return_bottom") => {
            let source = realm_id("1");
            let current_payload = realm_link_payload(RealmLinkStatus::Active, realm_id("2"));
            let sibling_payload = realm_link_payload(RealmLinkStatus::Rejected, realm_id("2"));
            let outcome = evaluate_realm_link_transition(
                &source,
                Some(RealmLinkTransitionCandidate {
                    payload: &current_payload,
                    canonical_move_bytes: b"active",
                    canonical_basis_bytes: b"same-basis",
                }),
                RealmLinkTransitionCandidate {
                    payload: &sibling_payload,
                    canonical_move_bytes: b"rejected",
                    canonical_basis_bytes: b"same-basis",
                },
            )
            .unwrap();
            assert_eq!(outcome, RealmLinkTransitionOutcome::Bottom);
        }
        ("fsm", "general_graph_cycles_are_not_an_admission_error") => {
            let source = realm_id("1");
            let payload = realm_link_payload(RealmLinkStatus::Active, realm_id("2"));
            assert_eq!(
                evaluate_realm_link_transition(
                    &source,
                    None,
                    RealmLinkTransitionCandidate {
                        payload: &payload,
                        canonical_move_bytes: b"cycle-edge",
                        canonical_basis_bytes: b"basis",
                    },
                )
                .unwrap(),
                RealmLinkTransitionOutcome::Apply
            );
        }
        ("fsm", "self_reference_rejects_with_realm_link_self_reference") => {
            let source = realm_id("1");
            let payload = realm_link_payload(RealmLinkStatus::Active, source.clone());
            let error = evaluate_realm_link_transition(
                &source,
                None,
                RealmLinkTransitionCandidate {
                    payload: &payload,
                    canonical_move_bytes: b"self-link",
                    canonical_basis_bytes: b"basis",
                },
            )
            .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::REALM_LINK_SELF_REFERENCE);
        }
        other => panic!("unknown lattice_round_trip assertion {other:?}; extend this driver"),
    }
}

/// Execute every assertion the fixture's `lattice_round_trip.cases`
/// declare against the SDK lattice implementations.
#[test]
fn lattice_round_trip_cases_execute_against_sdk_lattices() {
    let fixture = fixture();
    let metadata = &fixture["lattice_round_trip"];
    let covers = metadata["covers_vectors"]
        .as_array()
        .expect("lattice_round_trip.covers_vectors must be an array");
    let cases = metadata["cases"]
        .as_array()
        .expect("lattice_round_trip.cases must be an array");
    assert!(!cases.is_empty());

    let mut executed_assertions = 0usize;
    for case in cases {
        let vector_id = case["vector_id"]
            .as_str()
            .expect("lattice_round_trip case missing vector_id");
        assert!(
            covers.iter().any(|entry| entry.as_str() == Some(vector_id)),
            "case {vector_id} missing from covers_vectors"
        );
        let lattice_kind = case["lattice"]
            .as_str()
            .expect("lattice_round_trip case missing lattice kind");
        let assertions = case["assertions"]
            .as_array()
            .expect("lattice_round_trip case missing assertions");
        assert!(!assertions.is_empty(), "{vector_id} declares no assertions");
        for assertion in assertions {
            run_assertion(lattice_kind, assertion.as_str().unwrap(), case);
            executed_assertions += 1;
        }
    }
    assert!(
        executed_assertions >= 12,
        "expected the full declared assertion inventory, executed {executed_assertions}"
    );
}

/// Inventory gate over the dual-plane CBA scenario vectors plus the actor-chain
/// Realm-scoping vector carried by the same fixture. Their
/// full semantics (DataEvent vs control Move planes, seal coverage,
/// quarantine, notary faults) require the CBA reducer + seal pipeline and
/// are executed by the cotest state-resolution harness; the SDK pins the
/// vector inventory and the invariants it CAN check so fixture renames or
/// shape changes surface here.
#[test]
fn dual_plane_vector_inventory_is_pinned() {
    let fixture = fixture();
    assert_eq!(
        fixture["profile"].as_str(),
        Some("ak.vector_group.cba_lattice.v1")
    );
    let vectors = fixture["vectors"]
        .as_array()
        .expect("cba-lattice fixture missing vectors");
    assert!(
        vectors.len() >= 16,
        "dual-plane vector inventory shrank: {}",
        vectors.len()
    );
    for vector in vectors {
        let vector_id = vector["vector_id"]
            .as_str()
            .expect("dual-plane vector missing vector_id");
        assert!(
            vector_id.starts_with("ak.vector.cba_lattice.")
                || vector_id == "ak.vector.actor_chain.realm_scope.v1"
                || vector_id == "ak.vector.seal.same_batch_bottom_reject_serialization.v1"
                // Genesis state_root closure: ak.realm.create carries all four
                // registered effects explicitly, and every cell_subject: null
                // family uses the literal `null` wire segment. Both land in the
                // CBA lattice fixture because they are state_root leaf-set
                // invariants, not per-domain reducer behaviour.
                || vector_id == "ak.vector.event_kind.realm_create_effects_closure.v1"
                || vector_id == "ak.vector.event_kind.null_cell_subject_wire_form.v1",
            "unexpected vector id {vector_id}"
        );
        // Expectations are carried either as a top-level `expected*` block or
        // inside per-case `cases[]` entries (multi-step scenario vectors).
        let has_top_level_expected = vector
            .as_object()
            .unwrap()
            .keys()
            .any(|key| key.contains("expected"));
        let has_cases = vector
            .get("cases")
            .and_then(Value::as_array)
            .is_some_and(|cases| !cases.is_empty());
        assert!(
            has_top_level_expected || has_cases,
            "{vector_id} carries neither an expected block nor cases[]"
        );
        // Every embedded event must carry a plane marker consistent with the
        // CBA dual-plane notes (data / control) when present.
        if let Some(event) = vector.get("event")
            && let Some(plane) = event.get("plane").and_then(Value::as_str)
        {
            assert!(
                plane == "data" || plane == "control",
                "{vector_id}: unknown plane {plane}"
            );
        }
    }
}
