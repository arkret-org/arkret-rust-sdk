use arkret_models_discovery::*;
use arkret_wire::{Did, ServiceKind, TrustDomainId, WebOrigin};
use url::Url;

fn description() -> ServiceDescribe {
    let mut value = ServiceDescribe::development(
        Did::new("did:webvh:z6mkfixture:station.example").unwrap(),
        TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
        ServiceKind::Station,
        vec!["ak.operation_bundle.station.describe.v1".into()],
        vec![TransportBinding::HttpJson {
            base_url: "https://station.example/".into(),
            extension_profile_required: (),
        }],
    );
    value.auth_metadata.account_authority = Some(AccountAuthority {
        origin: WebOrigin::new("https://auth.example").unwrap(),
        gate_account_base_url: "https://auth.example/_arkret/gate/account".into(),
        extra: Default::default(),
    });
    value.auth_metadata.methods = vec![AuthMethod {
        method: AuthMethodKind::Oidc,
        issuer_uri: Some("https://idp.example".into()),
        provider_uri: None,
        openid_configuration_url: Some(
            "https://idp.example/.well-known/openid-configuration".into(),
        ),
        client_id: Some("client".into()),
        scopes: vec!["openid".into(), "profile".into()],
        grant_exchange: AuthGrantExchange {
            kind: AuthGrantExchangeKind::AccountHandoff,
            extra: Default::default(),
        },
        extra: Default::default(),
    }];
    value
}

fn binding(value: &ServiceDescribe) -> Result<StationConnectionBinding, arkret_wire::WireError> {
    StationConnectionBinding::from_description(
        &Url::parse("https://station.example/").unwrap(),
        value,
        false,
    )
}

#[test]
fn selected_origin_accepts_split_authority_without_history_verifier() {
    let pin = binding(&description()).unwrap();
    let restored: StationConnectionBinding =
        serde_json::from_slice(&serde_json::to_vec(&pin).unwrap()).unwrap();
    pin.require_same(&restored).unwrap();
}

#[test]
fn preconfigured_identity_and_trust_domain_cannot_be_overwritten() {
    let mut pin = binding(&description()).unwrap();
    pin.service_id = arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkdifferent").unwrap();
    assert!(pin.require_same(&binding(&description()).unwrap()).is_err());
    pin = binding(&description()).unwrap();
    pin.trust_domain = TrustDomainId::new("ak:trust_domain:other").unwrap();
    assert!(pin.require_same(&binding(&description()).unwrap()).is_err());
}

#[test]
fn unchanged_station_does_not_authorize_changed_issuer_or_authority() {
    let pin = binding(&description()).unwrap();
    let mut changed = description();
    changed.auth_metadata.methods[0].issuer_uri = Some("https://attacker.example".into());
    assert!(pin.require_same(&binding(&changed).unwrap()).is_err());
    changed = description();
    changed
        .auth_metadata
        .account_authority
        .as_mut()
        .unwrap()
        .gate_account_base_url = "https://auth.example/other".into();
    assert!(pin.require_same(&binding(&changed).unwrap()).is_err());
}

#[test]
fn method_order_extensions_and_resolution_version_are_not_identity_changes() {
    let pin = binding(&description()).unwrap();
    let mut changed = description();
    changed.auth_metadata.methods[0].scopes.reverse();
    changed
        .auth_metadata
        .methods
        .push(changed.auth_metadata.methods[0].clone());
    changed.auth_metadata.methods.reverse();
    changed.auth_metadata.extra =
        arkret_wire::XExtensionMap::new([("x_note".to_owned(), serde_json::json!("new"))].into())
            .unwrap();
    changed.service_resolution.version_id = "2".into();
    pin.require_same(&binding(&changed).unwrap()).unwrap();
}

#[test]
fn mismatched_route_and_authority_origin_are_rejected() {
    let mut changed = description();
    if let TransportBinding::HttpJson { base_url, .. } = &mut changed.transport_bindings[0] {
        *base_url = "https://attacker.example/".into();
    }
    assert!(binding(&changed).is_err());
    changed = description();
    changed
        .auth_metadata
        .account_authority
        .as_mut()
        .unwrap()
        .origin = WebOrigin::new("https://other.example").unwrap();
    assert!(binding(&changed).is_err());
}

#[test]
fn missing_authority_never_falls_back_to_origin() {
    let mut changed = description();
    changed
        .auth_metadata
        .account_authority
        .as_mut()
        .unwrap()
        .gate_account_base_url
        .clear();
    assert!(binding(&changed).is_err());
    changed.auth_metadata.account_authority = None;
    assert!(binding(&changed).is_err());
}

#[test]
fn development_http_exception_requires_explicit_loopback() {
    assert!(validate_connection_url(&Url::parse("http://127.0.0.1/").unwrap(), false).is_err());
    validate_connection_url(&Url::parse("http://127.0.0.1/").unwrap(), true).unwrap();
    for url in [
        "http://example.com/",
        "https://user:password@example.com/",
        "https://example.com/?token=secret",
    ] {
        assert!(validate_connection_url(&Url::parse(url).unwrap(), true).is_err());
    }
}
