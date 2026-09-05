//! CAS register Lattice: a causal register over write identities.
//!
//! `event-auth-state-resolution.md` §9.3.1.1 to §9.3.1.4. The state of a cell is
//! the map from the EventId of each still-active write to its canonical value.
//! A write supersedes exactly the heads its own signed `seal_basis` observed for
//! that cell, so the join never has to guess a causal edge from the business
//! value — which is what the deleted v1 definition did, and why it could not
//! tell `A -> B -> A` from `A -> B -> A -> B`.
//!
//! Reading collapses the heads to one value (§9.3.1.2):
//!
//! - no heads: the cell was never written, and reads `null`;
//! - all heads canonically equal: that value, `null` included — a *released* cell keeps its release
//!   write's head, so it is a different protocol state from an unwritten one even though both read
//!   `null`;
//! - two or more distinct values: `⊥`. Dependent Moves on a `bottom=reject` cell fail closed.
//!
//! Bottom is a function of the view, not a sticky flag (§9.1.1). Two branches
//! that each write a successor without having seen the other converge on that
//! successor once both are covered, so a receiver that pinned `⊥` on a partial
//! view would disagree with one that saw the whole history.
//!
//! Unlike `mv_register`, dependent Moves must fail closed on Bottom because this
//! Lattice serves safety-critical state (e.g. `ak.component.realm.policy.v1`,
//! `ak.component.notary.v1`); the implicit `bottom=reject` semantics are
//! enforced by whichever cell registry uses it.

use std::collections::BTreeSet;

use serde_json::Value;

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{Bottom, BottomKind, CellRef, Hash, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct CasRegister;

/// One still-active write: its identity and the value it wrote.
///
/// This is the SDK form of the `{"event_id":…,"value":…}` entry
/// `event-auth-state-resolution.md` §6.2.1 puts in the `state_root` leaf. The
/// identity is held as the Control Move's `event_digest` because that is what
/// the op log stores; `EventId` is recovered losslessly from it when the leaf is
/// serialized, so the two are the same identity in different spellings.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CasHead {
    pub move_id: Hash,
    pub value: Value,
}

/// The still-active writes of one `cas_register` cell, in `state_root` order.
///
/// A write is active unless some other write in the same view names it in its
/// derived `supersedes` set. Under a causally closed coverage set that is
/// equivalent to "no write whose signed basis covered it", because a write whose
/// superseder is present drags that superseder into the view with it.
///
/// Ordering is by the decoded 33-octet `event_id` token (§6.2.1), which is the
/// suite code byte followed by the digest bytes — so comparing
/// `EventIdentityKey` is comparing exactly those octets. It fixes bytes only and
/// selects no winner.
///
/// `Err` is a fail-closed diagnostic: the same identity carrying two different
/// canonical effects is a verification error or a §6.3.3 digest collision, and
/// §9.3.1.1 forbids letting the lattice pick one.
pub fn cas_heads(sealed_ops: &[SealedOp]) -> Result<Vec<CasHead>, Box<Bottom>> {
    let mut writes: Vec<&SealedOp> = Vec::new();
    for entry in sealed_ops {
        if CasRegister.validate_op(&entry.op).is_err() {
            continue;
        }
        match writes
            .iter()
            .find(|existing| existing.move_id == entry.move_id)
        {
            // Exact replay of one identity is idempotent (§9.3.1.1).
            Some(existing) if existing.op.value == entry.op.value => continue,
            Some(existing) => {
                let mut bottom = Bottom::new(BottomKind::Conflict, Vec::new());
                bottom.move_ids.push(entry.move_id.clone());
                bottom
                    .head_ids
                    .push(existing.op.value.clone().unwrap_or(Value::Null));
                bottom
                    .head_ids
                    .push(entry.op.value.clone().unwrap_or(Value::Null));
                return Err(Box::new(bottom));
            }
            None => writes.push(entry),
        }
    }

    let superseded: BTreeSet<&str> = writes
        .iter()
        .flat_map(|entry| entry.supersedes.iter().map(Hash::as_str))
        .collect();

    let mut heads: Vec<CasHead> = writes
        .into_iter()
        .filter(|entry| !superseded.contains(entry.move_id.as_str()))
        .map(|entry| CasHead {
            move_id: entry.move_id.clone(),
            value: entry.op.value.clone().unwrap_or(Value::Null),
        })
        .collect();
    heads.sort_by_key(|head| head_order_key(&head.move_id));
    Ok(heads)
}

/// The decoded 33-octet `event_id` token this head sorts under (§6.2.1).
///
/// A digest the identifier crate cannot decode sorts last under its raw wire
/// string rather than panicking: ordering must stay total even for a store that
/// handed us something malformed, and the value comparison below is what decides
/// the cell state anyway.
fn head_order_key(move_id: &Hash) -> (u8, [u8; 33], String) {
    match arkret_wire::EventId::from_event_digest(move_id) {
        Ok(event_id) => (0, event_id.token_bytes(), String::new()),
        Err(_) => (1, [0_u8; 33], move_id.as_str().to_owned()),
    }
}

impl Lattice for CasRegister {
    fn kind(&self) -> LatticeKind {
        LatticeKind::CasRegister
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Set => {
                if op.value.is_none() {
                    return Err(OpError::MissingField {
                        kind: "cas_register",
                        field: "value",
                    });
                }
                Ok(())
            }
            other => Err(OpError::UnsupportedOpType {
                got: other.as_str().to_owned(),
                expected_kind: "cas_register",
            }),
        }
    }

    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        let heads = match cas_heads(sealed_ops) {
            Ok(heads) => heads,
            Err(mut bottom) => {
                bottom.cell_ids.push(cell.clone());
                return CellState::Bottom(*bottom);
            }
        };
        let Some(first) = heads.first() else {
            // §9.3.1.2: an unwritten cell reads `null` on every family. There is
            // no registered per-family initial value.
            return CellState::Value(Value::Null);
        };
        if heads.iter().all(|head| head.value == first.value) {
            return CellState::Value(first.value.clone());
        }
        let mut bottom = Bottom::new(BottomKind::Conflict, vec![cell.clone()]);
        for head in &heads {
            bottom.move_ids.push(head.move_id.clone());
            bottom.head_ids.push(head.value.clone());
        }
        CellState::Bottom(bottom)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{Hash, LatticeOp};

    fn cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
        )
        .unwrap()
    }

    /// The reusable claim/release slot family. It has no registered initial
    /// value: `governance-objects.md` section 5.3 requires the claiming
    /// `ak.invite.create` to assert `head_eq: null`, and the release Move to
    /// `set null`.
    fn slot_cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.invite.live_target.v1:fAWD6k02hF3JHnquwsCU7inqyb8Qdajftruz5xEWFGc"
                .to_owned(),
        )
        .unwrap()
    }

    fn move_id(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn set_op(value: Value) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(value),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    /// A first write: its basis observed no head on this cell.
    fn first(id: u8, value: Value) -> SealedOp {
        SealedOp::new(move_id(id), set_op(value))
    }

    /// A write whose basis observed exactly `saw` as this cell's heads.
    fn after(id: u8, value: Value, saw: &[u8]) -> SealedOp {
        SealedOp::superseding(
            move_id(id),
            set_op(value),
            saw.iter().copied().map(move_id).collect(),
        )
    }

    fn expect_bottom(state: CellState) -> Bottom {
        match state {
            CellState::Bottom(bottom) => {
                assert_eq!(bottom.kind, BottomKind::Conflict);
                bottom
            }
            other => panic!("expected Bottom, got {other:?}"),
        }
    }

    #[test]
    fn kind_is_cas_register() {
        assert_eq!(CasRegister.kind(), LatticeKind::CasRegister);
        assert_eq!(LatticeKind::CasRegister.as_wire_str(), "cas_register");
    }

    #[test]
    fn validate_rejects_non_set() {
        let op = LatticeOp {
            op_type: LatticeOpType::Inc,
            ..set_op(json!(1))
        };
        CasRegister
            .validate_op(&op)
            .expect_err("non-set op must fail");
    }

    /// Section 9.3.1.2: an unwritten cell reads `null` on **every** family. The
    /// slot family is included now that the registry declares no initial value.
    #[test]
    fn an_unwritten_cell_reads_null_on_every_family() {
        for target in [cell(), slot_cell()] {
            assert_eq!(
                CasRegister.join(&target, &[]),
                CellState::Value(Value::Null)
            );
            assert_eq!(cas_heads(&[]).expect("empty heads"), Vec::new());
        }
    }

    #[test]
    fn a_single_write_is_the_only_head() {
        let ops = vec![first(1, json!({"policy": "open"}))];
        assert_eq!(
            CasRegister.join(&cell(), &ops),
            CellState::Value(json!({"policy": "open"}))
        );
        let heads = cas_heads(&ops).expect("one head");
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].move_id, move_id(1));
    }

    /// A linear lifecycle: each write supersedes what its basis saw, so only the
    /// last one survives.
    #[test]
    fn a_linear_lifecycle_leaves_one_head() {
        let declaration = json!({"policy": "declared"});
        let tombstone = json!({"tombstone": true});
        let redeclaration = json!({"policy": "declared_again"});
        let ops = vec![
            first(1, declaration.clone()),
            after(2, tombstone.clone(), &[1]),
            after(3, redeclaration.clone(), &[2]),
        ];
        assert_eq!(
            CasRegister.join(&cell(), &ops),
            CellState::Value(redeclaration)
        );
        assert_eq!(cas_heads(&ops).expect("one head").len(), 1);

        // Any prefix-closed subset recomputes that subset's historical view.
        assert_eq!(
            CasRegister.join(&cell(), &ops[..1]),
            CellState::Value(declaration)
        );
        assert_eq!(
            CasRegister.join(&cell(), &ops[..2]),
            CellState::Value(tombstone)
        );
    }

    /// The case the deleted value-edge join could not express: `A -> B -> A` and
    /// `A -> B -> A -> B` dedup to the same `(value, from)` set, so it had to
    /// give both the same answer. Write identities keep them apart.
    #[test]
    fn aba_and_abab_read_their_own_last_write() {
        let a = json!("A");
        let b = json!("B");
        let aba = vec![
            first(1, a.clone()),
            after(2, b.clone(), &[1]),
            after(3, a.clone(), &[2]),
        ];
        assert_eq!(CasRegister.join(&cell(), &aba), CellState::Value(a));

        let mut abab = aba;
        abab.push(after(4, b.clone(), &[3]));
        assert_eq!(CasRegister.join(&cell(), &abab), CellState::Value(b));
    }

    /// `governance-objects.md` section 5.3: the slot is a reusable register. The
    /// release writes `null` and keeps its own head, so a released slot and an
    /// unwritten one read the same value but are different protocol states —
    /// which is exactly what the `state_root` leaf has to preserve.
    #[test]
    fn a_released_slot_reads_null_but_still_has_a_head() {
        let claim = json!("ak:event:AUC6BgHput8c8rn_dCCz43Ytxt5ZSdlxtE9subQRQcDF");
        let reclaim = json!("ak:event:AVqlgW6dOb9VNRGuL5Gff6mz-9IKoTzaekCAJaNi2z43");
        let released = vec![first(1, claim), after(2, Value::Null, &[1])];

        assert_eq!(
            CasRegister.join(&slot_cell(), &released),
            CellState::Value(Value::Null)
        );
        let heads = cas_heads(&released).expect("one head");
        assert_eq!(heads.len(), 1, "the release write keeps its own head");
        assert_eq!(heads[0].move_id, move_id(2));
        assert!(
            cas_heads(&[]).expect("unwritten").is_empty(),
            "an unwritten cell has no head at all, which is what separates it              from this released one",
        );

        let mut reclaimed = released;
        reclaimed.push(after(3, reclaim.clone(), &[2]));
        assert_eq!(
            CasRegister.join(&slot_cell(), &reclaimed),
            CellState::Value(reclaim)
        );
    }

    /// Two writes that each saw nothing are concurrent, and a `bottom=reject`
    /// cell materializes `failed_bottom` rather than picking one.
    #[test]
    fn concurrent_writes_with_different_values_are_bottom() {
        let ops = vec![
            first(1, json!({"policy": "open"})),
            first(2, json!({"policy": "closed"})),
        ];
        let bottom = expect_bottom(CasRegister.join(&cell(), &ops));
        assert_eq!(bottom.cell_ids, vec![cell()]);
        assert_eq!(bottom.head_ids.len(), 2);
        assert_eq!(bottom.move_ids.len(), 2);
    }

    /// Two concurrent claims of one free slot are still siblings: the whole
    /// point of the register is that only one of them can hold it.
    #[test]
    fn concurrent_claims_on_a_free_slot_conflict() {
        let ops = vec![
            first(1, json!("ak:event:AUC6Bg")),
            first(2, json!("ak:event:AVqlgW")),
        ];
        let bottom = expect_bottom(CasRegister.join(&slot_cell(), &ops));
        assert_eq!(bottom.head_ids.len(), 2);
    }

    /// Same value, two identities. The value collapses to one head value for
    /// readers, but **both identities survive** — otherwise a successor that saw
    /// only one branch would silently drop the branch it never observed.
    #[test]
    fn concurrent_writes_with_the_same_value_keep_both_identities() {
        let shared = json!("A");
        let ops = vec![first(1, shared.clone()), first(2, shared.clone())];
        assert_eq!(CasRegister.join(&cell(), &ops), CellState::Value(shared));
        let heads = cas_heads(&ops).expect("two heads");
        assert_eq!(heads.len(), 2);

        // A successor that observed only head 1 removes only head 1. Head 2 is
        // still active, so the cell is now genuinely in conflict.
        let mut partial = ops.clone();
        partial.push(after(3, json!("B"), &[1]));
        let bottom = expect_bottom(CasRegister.join(&cell(), &partial));
        assert_eq!(bottom.head_ids.len(), 2, "head 2 must survive");

        // A successor that observed both supersedes both.
        let mut complete = ops;
        complete.push(after(4, json!("B"), &[1, 2]));
        assert_eq!(
            CasRegister.join(&cell(), &complete),
            CellState::Value(json!("B"))
        );
    }

    /// Section 9.3.1.1: exact replay of one identity and one canonical effect is
    /// idempotent and does not open a second head.
    #[test]
    fn exact_replay_of_one_identity_is_idempotent() {
        let value = json!({"policy": "declared"});
        let ops = vec![first(1, value.clone()), first(1, value.clone())];
        assert_eq!(CasRegister.join(&cell(), &ops), CellState::Value(value));
        assert_eq!(cas_heads(&ops).expect("one head").len(), 1);
    }

    /// One identity carrying two different canonical effects is a verification
    /// error or a section 6.3.3 collision. The lattice MUST NOT pick one.
    #[test]
    fn one_identity_with_two_effects_fails_closed() {
        let ops = vec![first(1, json!("A")), first(1, json!("B"))];
        let bottom = expect_bottom(CasRegister.join(&cell(), &ops));
        assert_eq!(bottom.cell_ids, vec![cell()]);
        assert_eq!(bottom.head_ids, vec![json!("A"), json!("B")]);
    }

    /// Section 9.1.1: Bottom is a function of the view. Two branches write `A`
    /// and `B`, then each writes the same `T` without having seen the other. The
    /// full view has two heads that agree on `T`, so it reads `T` — a receiver
    /// that had latched `⊥` on the partial view would never converge.
    #[test]
    fn bottom_is_recomputed_per_view_and_converges() {
        let a = json!("A");
        let b = json!("B");
        let t = json!("T");
        let diverged = vec![first(1, a), first(2, b)];
        expect_bottom(CasRegister.join(&cell(), &diverged));

        let mut converged = diverged;
        converged.push(after(3, t.clone(), &[1]));
        converged.push(after(4, t.clone(), &[2]));
        assert_eq!(CasRegister.join(&cell(), &converged), CellState::Value(t));
        assert_eq!(
            cas_heads(&converged).expect("two heads").len(),
            2,
            "both successors stay heads; they agree on the value",
        );
    }

    /// Heads are ordered by the decoded 33-octet `event_id` token, not by the
    /// `sha256:<hex>` wire string and not by arrival.
    #[test]
    fn heads_are_ordered_by_the_decoded_event_id_token() {
        let ops = vec![
            first(0xcc, json!("c")),
            first(0x11, json!("a")),
            first(0x77, json!("b")),
        ];
        let heads = cas_heads(&ops).expect("three heads");
        let order: Vec<&Hash> = heads.iter().map(|head| &head.move_id).collect();
        assert_eq!(order, vec![&move_id(0x11), &move_id(0x77), &move_id(0xcc)]);
        for window in heads.windows(2) {
            let left = arkret_wire::EventId::from_event_digest(&window[0].move_id).unwrap();
            let right = arkret_wire::EventId::from_event_digest(&window[1].move_id).unwrap();
            assert!(left.token_bytes() < right.token_bytes());
        }
    }

    /// The old `"__unset__"` sentinel is an ordinary value on every family now.
    /// Nothing treats it as a free slot, and nothing treats it as unwritten.
    #[test]
    fn the_old_unset_sentinel_is_an_ordinary_value() {
        for target in [cell(), slot_cell()] {
            let ops = vec![first(1, json!("__unset__"))];
            assert_eq!(
                CasRegister.join(&target, &ops),
                CellState::Value(json!("__unset__"))
            );
        }
    }
}
