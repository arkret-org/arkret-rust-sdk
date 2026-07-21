use serde_json::json;

use super::super::*;

#[test]
fn directory_search_realms_request_uses_source_realm_id() {
    let source_realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let request = DirectorySearchRealmsRequestBody {
        query: Some("release".to_owned()),
        organization_did: None,
        source_realm_id: Some(source_realm_id.clone()),
        requester: None,
        proof_challenge: Some("challenge-1".to_owned()),
        claim_presentations: Vec::new(),
        cursor: None,
        limit: Some(20),
    };
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["source_realm_id"], source_realm_id.as_str());
    assert_eq!(value["proof_challenge"], "challenge-1");
    assert!(value.get("proofs").is_none());
    assert!(value.get("parent_space_id").is_none());

    let parsed: DirectorySearchRealmsRequestBody = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.source_realm_id, Some(source_realm_id));
    assert_eq!(parsed.proof_challenge.as_deref(), Some("challenge-1"));
    assert!(parsed.claim_presentations.is_empty());
}

#[test]
fn session_login_outcome_uses_typed_wire_fields() {
    let value = json!({
        "session_credential": "sx_token",
        "token_type": "Bearer",
        "actor": "did:webvh:z6mkfixture:alice.example",
        "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
        "expires_at": "2026-04-28T12:00:00.000Z"
    });
    let outcome: crate::SessionLoginOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(
        outcome.actor.as_str(),
        "did:webvh:z6mkfixture:alice.example"
    );
    assert_eq!(
        outcome.device_id.as_str(),
        "ak:device:01964137-0000-7000-8000-000000000001"
    );

    let serialized = serde_json::to_value(outcome).unwrap();
    assert_eq!(serialized["token_type"], "Bearer");
    assert_eq!(serialized["actor"], "did:webvh:z6mkfixture:alice.example");
    assert_eq!(
        serialized["device_id"],
        "ak:device:01964137-0000-7000-8000-000000000001"
    );
}

#[test]
fn did_validation_rejects_handles() {
    assert!(Did::new("did:webvh:z6mkfixture:alice.example").is_ok());
    assert!(Did::new("alice.example").is_err());
}

#[test]
fn did_validation_accepts_uuid_method() {
    assert!(Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").is_ok());
}

#[test]
fn device_id_accepts_protocol_device_forms() {
    assert!(DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").is_ok());
    assert!(DeviceId::new("ak:device:01904100-0000-7000-8000-8b3ad8ecac70").is_ok());
    assert!(DeviceId::new("device-1").is_err());
}

#[test]
fn actor_profile_rejects_unknown_fields_and_accepts_schema_statuses() {
    let value = json!({
        "id": "ak:actor_profile:01904100-0000-7000-8000-aaaaaaaaaaaa",
        "schema": ACTOR_PROFILE_SCHEMA,
        "principal_id": "did:webvh:z6mkfixture:ghost.example",
        "actor_kind": "integration",
        "display_name": "Ghost",
        "status": "locked",
        "accountable_principal_ids": ["did:webvh:z6mkfixture:owner.example"],
        "profile_fields": {
            "managed_by_applet": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        },
        "created_at": "2026-04-30T00:00:00.000Z",
        "updated_by": "did:webvh:z6mkfixture:owner.example",
        "updated_at": "2026-04-30T00:01:00.000Z"
    });
    let profile: ActorProfile = serde_json::from_value(value).unwrap();
    assert_eq!(profile.status, Some(ActorStatus::Locked));
    assert_eq!(profile.actor_kind, ActorKind::Integration);

    let bad = json!({
        "id": "ak:actor_profile:01904100-0000-7000-8000-aaaaaaaaaaaa",
        "schema": ACTOR_PROFILE_SCHEMA,
        "principal_id": "did:webvh:z6mkfixture:ghost.example",
        "actor_kind": "integration",
        "display_name": "Ghost",
        "created_at": "2026-04-30T00:00:00.000Z",
        "managed_by_applet": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
    });
    assert!(serde_json::from_value::<ActorProfile>(bad).is_err());
}

#[test]
fn server_description_checks_protocol_version() {
    let desc = ServiceDescribe {
        service_id: Did::new("did:webvh:z6mkfixture:svc.example").unwrap(),
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        service_type: ServiceType::PrincipalServer,
        protocol_version: "1.0".to_owned(),
        supported_profiles: vec![],
        supported_features: vec![],
        supported_operations: vec![],
        supported_bindings: vec![],
        auth_metadata: AuthMetadata::minimal("development"),
        limits: ServerLimits::default(),
        plaintext_visibility: PlaintextVisibility::none(),
        privacy_derivation: None,
        receive_policy_constraints: None,
        implemented_features: vec![],
        claimed_profiles: vec![],
        verified_profiles: vec![],
        experimental_features: vec![],
        compat_surfaces: vec![],
        development_mode: false,
        rate_limit_policy: Some(RateLimitPolicy::unspecified()),
        rate_limit_policy_id: None,
        egress_network_policy: Some(EgressNetworkPolicy::deny_private_defaults()),
        resource_types: vec![],
        discovery_profiles: vec![],
        restricted_query_proof: None,
        ingest_modes: vec![],
        accept_policy_kind: None,
        accept_policy_ref: None,
        default_ttl_seconds: None,
        max_ttl_seconds: None,
        revalidation_grace_seconds: None,
        accepted_resource_kinds: vec![],
        accepted_did_methods: vec![],
        takedown_contact: None,
        rate_limits: None,
        supported_reducer_profiles: vec![],
        supported_schema_profiles: vec![],
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        reducer_profile: None,
        last_materialized_at: None,
    };
    assert!(desc.supports_arkret_v1());
}
