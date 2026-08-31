//! Executable state consumer for the RSVP `mv_register_cases` carried by
//! `fixtures/encoding-fixture.json`.

use arkret_schema_conformance::spec_json_artifact;
use arkret_state::lattice::{CellState, Lattice, MvRegister, SealedOp};
use arkret_wire::{CellRef, Hash, LatticeOp, LatticeOpType};
use serde_json::{Value, json};

const VECTOR_ID: &str = "ak.vector.calendar.rsvp_composite_subject.v1";

fn vector() -> Value {
    let fixture = spec_json_artifact("fixtures/encoding-fixture.json")
        .expect("embedded encoding fixture must load");
    fixture["vectors"]
        .as_array()
        .expect("encoding fixture must declare vectors")
        .iter()
        .find(|vector| vector["vector_id"] == VECTOR_ID)
        .unwrap_or_else(|| panic!("encoding fixture must declare {VECTOR_ID}"))
        .clone()
}

fn cell() -> CellRef {
    CellRef::new(
        "ak:cell:ak.component.calendar.rsvp.v1:LjvpAsw7qCPnXbATwtWyUYHAncyxVuNfGaCjpuF0968",
    )
    .unwrap()
}

fn set_status(move_byte: u8, status: &str) -> SealedOp {
    SealedOp::new(
        Hash::new(format!("sha256:{}", format!("{move_byte:02x}").repeat(32))).unwrap(),
        LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(json!(status)),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        },
    )
}

fn heads(state: CellState) -> Vec<String> {
    let mut values = match state {
        CellState::Value(value) => vec![value],
        CellState::Bottom(bottom) => bottom.head_ids,
    }
    .into_iter()
    .map(|value| {
        value
            .as_str()
            .expect("RSVP mv_register head must be a status string")
            .to_owned()
    })
    .collect::<Vec<_>>();
    values.sort();
    values
}

fn expected_heads(case: &Value) -> Vec<String> {
    let mut values = case["expected_heads"]
        .as_array()
        .expect("RSVP mv_register case must declare expected_heads")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("expected RSVP head must be a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    values.sort();
    values
}

#[test]
fn rsvp_mv_register_cases_execute_against_state_lattice() {
    for case in vector()["mv_register_cases"]
        .as_array()
        .expect("RSVP vector must declare mv_register_cases")
    {
        match case["name"].as_str().expect("case must declare name") {
            "causal_successor_dominates" => {
                // Seal/frontier processing removes causally dominated ops before
                // calling the lattice. Only the successor survives as a head.
                let successor = case["successor_status"].as_str().unwrap();
                assert_eq!(
                    heads(MvRegister.join(&cell(), &[set_status(2, successor)])),
                    expected_heads(case)
                );
            }
            "concurrent_statuses_expose_heads" => {
                let left = case["left_status"].as_str().unwrap();
                let right = case["right_status"].as_str().unwrap();
                let forward =
                    heads(MvRegister.join(&cell(), &[set_status(1, left), set_status(2, right)]));
                let reversed =
                    heads(MvRegister.join(&cell(), &[set_status(2, right), set_status(1, left)]));
                assert_eq!(forward, expected_heads(case));
                assert_eq!(reversed, forward);
                assert_eq!(case["hlc_swap_changes_result"], false);
            }
            name => panic!("unknown RSVP mv_register conformance case {name}"),
        }
    }
}
