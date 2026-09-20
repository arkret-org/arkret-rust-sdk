//! The controller-gate functions are only usable if their argument type is too.
//!
//! `lib.rs` re-exports `sign_controller_account_gate_attestation` and
//! `verify_controller_account_gate_attestation` from
//! `arkret_signatures::agent_evidence`, but both take a
//! `ControllerAccountGateAttestation`, which lives in
//! `arkret_models_identity::agent_signer_evidence`. That module was missing
//! from the umbrella's otherwise alphabetical re-export list, between
//! `admin_grant` and `agent_signer_state`, so a crate depending only on
//! `arkret` could name the functions and not their parameter.
//!
//! This test names the portable attestation and operation-neutral domain items
//! through the umbrella, so the gap cannot reopen silently.

use arkret::{
    AgentAuthorizedSigningKey, AgentDetachedJws, AgentSigningPublicKey,
    CONTROLLER_ACCOUNT_GATE_MAX_VALIDITY_SECONDS, ControllerAccountEligibility,
    ControllerAccountGateAttestation, ControllerAccountGateBasis,
    ControllerAccountGateIssuanceInput, ControllerAccountGateIssuanceResult,
    ControllerAccountStatus, sign_controller_account_gate_attestation,
    verify_controller_account_gate_attestation,
};

#[test]
fn gate_argument_types_are_reachable_through_the_umbrella() {
    // Function items coerced to pointers: the parameter type has to resolve to
    // the same path the umbrella exports, or these do not type-check.
    let _sign: fn(&mut ControllerAccountGateAttestation, _) -> _ =
        sign_controller_account_gate_attestation;
    let _verify: fn(&ControllerAccountGateAttestation, _, _, _, _) -> _ =
        verify_controller_account_gate_attestation;

    fn nameable<T>() {}
    nameable::<AgentDetachedJws>();
    nameable::<AgentSigningPublicKey>();
    nameable::<AgentAuthorizedSigningKey>();
    nameable::<ControllerAccountGateBasis>();
    nameable::<ControllerAccountEligibility>();
    nameable::<ControllerAccountStatus>();
    nameable::<ControllerAccountGateIssuanceInput>();
    nameable::<ControllerAccountGateIssuanceResult>();

    assert_eq!(CONTROLLER_ACCOUNT_GATE_MAX_VALIDITY_SECONDS, 300);
}

#[test]
fn gate_schema_id_is_the_generated_registry_row_not_a_literal() {
    // The constant used to be hardcoded next to a comment claiming the Spec
    // registry had no row for it. It does.
    assert_eq!(
        ControllerAccountGateAttestation::SCHEMA_ID,
        arkret_wire::SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1,
    );
    assert_eq!(
        ControllerAccountGateAttestation::SCHEMA_ID,
        "ak.schema.controller_account_gate_attestation.v1",
    );
}
