use arkret_wire::{
    AuthoritySetPolicyKind, AuthoritySetSourceKind, BindingKind, OPERATION_ERROR_MAPPINGS,
    ServiceOperationId, TrackName, operation_error_mapping,
};

#[test]
fn generated_closed_registry_types_reject_unregistered_values() {
    assert_eq!(
        TrackName::ALL,
        &[TrackName::Discussion, TrackName::Synthesis]
    );
    assert_eq!(
        TrackName::from_wire("synthesis"),
        Some(TrackName::Synthesis)
    );
    assert_eq!(TrackName::from_wire("injected"), None);

    assert_eq!(
        BindingKind::ALL,
        &[
            BindingKind::HttpJson,
            BindingKind::Tus,
            BindingKind::Websocket,
        ]
    );
    assert_eq!(BindingKind::from_wire("injected"), None);

    assert_eq!(
        AuthoritySetPolicyKind::ALL,
        &[
            AuthoritySetPolicyKind::AccountAuthority,
            AuthoritySetPolicyKind::PrincipalControl,
            AuthoritySetPolicyKind::RealmAdmission,
        ]
    );
    assert_eq!(AuthoritySetPolicyKind::from_wire("injected"), None);
    assert_eq!(AuthoritySetSourceKind::from_wire("injected"), None);
}

#[test]
fn every_operation_has_a_generated_error_mapping() {
    assert_eq!(
        OPERATION_ERROR_MAPPINGS.len(),
        ServiceOperationId::ALL.len()
    );
    for (index, operation) in ServiceOperationId::ALL.iter().copied().enumerate() {
        let mapping = operation_error_mapping(operation);
        assert_eq!(mapping.operation, operation);
        assert_eq!(mapping, &OPERATION_ERROR_MAPPINGS[index]);
    }

    let handoff = operation_error_mapping(ServiceOperationId::GateAccountExchangeCreateHandoff);
    let identifiers: Vec<&str> = handoff
        .operation_specific
        .iter()
        .map(|entry| entry.as_str())
        .collect();
    assert_eq!(identifiers, ["proof_invalid", "duplicate_conflict"]);
}
