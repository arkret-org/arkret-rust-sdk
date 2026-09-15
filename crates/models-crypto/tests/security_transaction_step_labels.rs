//! `SecurityTransactionStep` is the only place a security-transaction step is
//! named, and its wire spelling comes from a `rename_all` derive rather than
//! from the spec. That derive is the one thing standing between a variant
//! rename and a silently changed wire label, so the closed step orders are
//! compared here against the two schema enums that define them.

use arkret_wire::{
    PCR_POLICY_RECOVERY_STEP_ORDER, SECURITY_ROTATION_STEP_ORDER, SecurityTransactionStep,
};
use serde_json::Value;

fn schema_enum(fragment: &str) -> Vec<String> {
    let schema =
        arkret_schema_conformance::spec_json_artifact("schemas/security-transaction.schema.json")
            .expect("security transaction schema");
    schema
        .pointer(fragment)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{fragment} must be a closed enum array"))
        .iter()
        .map(|value| value.as_str().expect("step labels are strings").to_owned())
        .collect()
}

fn wire_labels(order: &[SecurityTransactionStep]) -> Vec<String> {
    order
        .iter()
        .map(|step| {
            serde_json::to_value(step)
                .expect("step serializes")
                .as_str()
                .expect("step serializes as text")
                .to_owned()
        })
        .collect()
}

#[test]
fn the_closed_step_orders_equal_their_schema_enums() {
    assert_eq!(
        wire_labels(&PCR_POLICY_RECOVERY_STEP_ORDER),
        schema_enum("/$defs/pcr_policy_recovery_step/enum")
    );
    assert_eq!(
        wire_labels(&SECURITY_ROTATION_STEP_ORDER),
        schema_enum("/$defs/security_rotation_step/enum")
    );
}

#[test]
fn only_the_two_terminal_steps_carry_a_client_attestation() {
    let attested = schema_enum("/$defs/client_step_attestation/properties/step/allOf/0/enum");
    let mut expected = PCR_POLICY_RECOVERY_STEP_ORDER
        .iter()
        .chain(SECURITY_ROTATION_STEP_ORDER.iter())
        .copied()
        .filter(|step| arkret_wire::SecurityTransaction::step_requires_client_attestation(*step))
        .collect::<Vec<_>>();
    expected.dedup();
    assert_eq!(wire_labels(&expected), attested);
}
