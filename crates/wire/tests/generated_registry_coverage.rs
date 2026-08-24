use arkret_wire::{AuthoritySetPolicyKind, AuthoritySetSourceKind, BindingKind, TrackName};

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
