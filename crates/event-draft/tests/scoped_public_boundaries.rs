use arkret_event_draft::{EventContentDraft, EventSpec, TypedEventDraft};
use arkret_models_collaboration::events_payloads::RealmOrganizationPayload;
use arkret_models_collaboration::events_payloads::agent::{
    AgentActionApprovePayload, AgentActionRejectPayload, AgentActionRequestPayload,
    AgentDraftProposePayload, AgentKeyAuthorizePayload, AgentKeyRevokePayload,
    AgentKeySupersession,
};
use arkret_wire::{
    AccountId, ActorId, DidCoreId, EventId, NonEmptyString, RealmId, ScopeRef, event_spec,
};
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

fn scope() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap(),
    }
}
fn actor() -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ))
}
fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 12, 0, 0, 0).unwrap()
}
fn event() -> EventId {
    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [7; 32])
}
fn scoped<K: EventSpec>(payload: K::Payload, mutate: impl Fn(&mut K::Payload, &str))
where
    K::Payload: Clone,
{
    check::<K>(payload, mutate, false);
}
fn check<K: EventSpec>(
    payload: K::Payload,
    mutate: impl Fn(&mut K::Payload, &str),
    key_profile: bool,
) where
    K::Payload: Clone,
{
    let literals = if key_profile {
        vec![
            "runtime-key".into(),
            "a".repeat(256),
            String::new(),
            "ak:key:invalid".into(),
            "a".repeat(257),
            "runtime\n".into(),
        ]
    } else {
        vec![
            " ".into(),
            "é".into(),
            "🦀".repeat(256),
            String::new(),
            "ak:handle:invalid".into(),
            "🦀".repeat(257),
        ]
    };
    for literal in literals {
        let mut candidate = payload.clone();
        mutate(&mut candidate, &literal);
        let valid = if key_profile {
            arkret_wire::AgentKeyId::new(literal.clone()).is_ok()
        } else {
            arkret_wire::validate_bounded_non_typed_identifier(&literal, 256).is_ok()
        };
        let expected = serde_json::to_value(&candidate).unwrap();
        let draft = TypedEventDraft::<K>::new(scope(), actor(), candidate.clone());
        assert_eq!(draft.is_ok(), valid, "{} {literal:?}", K::KIND_STR);
        let replacement = EventContentDraft::<K>::new(scope(), actor(), now())
            .unwrap()
            .intent()
            .clone()
            .with_typed_payload::<K>(candidate);
        assert_eq!(replacement.is_ok(), valid, "{} {literal:?}", K::KIND_STR);
        if valid {
            assert_eq!(
                serde_json::to_value(draft.unwrap().into_intent(now()).unwrap()).unwrap()["payload"],
                expected
            );
        }
    }
}
fn base() -> Value {
    json!({"agent_id":"ak:did_core:web:agent.example","controller_account_id":{"principal_id":"ak:did_core:web:controller.example","station_id":"ak:did_core:web:station.example"},"proposed_action":"ak.message.create","target":{"kind":"service_operation","operation_id":"ak.self.session.command.issue.v1"},"created_at":"2026-11-12T00:00:00.000Z","expires_at":"2026-11-13T00:00:00.000Z"})
}
#[test]
fn agent_action_and_draft_handles_cannot_bypass_serde_via_typed_authoring() {
    let hash = format!("sha256:{}", "a".repeat(64));
    let mut value = base();
    value["draft_id"] = json!("valid");
    value["content_digest"] = json!(hash);
    value["content_handoff"] = json!({"scheme":"ak.hpke_x25519_aead_chacha20poly1305.v1","recipients":[{"recipient_device_id":"ak:device:01904100-0000-7000-8000-000000000008","recipient_hpke_key_digest":hash,"enc":"AA","ciphertext":"AA","ciphertext_digest":hash}]});
    scoped::<event_spec::AgentDraftPropose>(
        serde_json::from_value::<AgentDraftProposePayload>(value).unwrap(),
        |p, s| p.draft_id = s.into(),
    );
    let mut value = base();
    value["request_id"] = json!("valid");
    value["request_canonical_digest"] = json!(hash);
    let request: AgentActionRequestPayload = serde_json::from_value(value).unwrap();
    scoped::<event_spec::AgentActionRequest>(request.clone(), |p, s| p.request_id = s.into());
    scoped::<event_spec::AgentActionRequest>(request, |p, s| p.draft_id = Some(s.into()));
    let mut value = base();
    value
        .as_object_mut()
        .unwrap()
        .remove("controller_account_id");
    value.as_object_mut().unwrap().remove("created_at");
    value["approval_id"] = json!("valid");
    value["approved_event_id"] = json!(event());
    value["approval_nonce"] = json!("nonce");
    let approve: AgentActionApprovePayload = serde_json::from_value(value).unwrap();
    scoped::<event_spec::AgentActionApprove>(approve.clone(), |p, s| p.approval_id = s.into());
    scoped::<event_spec::AgentActionApprove>(approve.clone(), |p, s| p.request_id = Some(s.into()));
    scoped::<event_spec::AgentActionApprove>(approve, |p, s| p.draft_id = Some(s.into()));
    let reject:AgentActionRejectPayload=serde_json::from_value(json!({"rejection_id":"valid","request_id":"valid","agent_id":"ak:did_core:web:agent.example","rejected_at":"2026-11-12T00:00:00.000Z"})).unwrap();
    scoped::<event_spec::AgentActionReject>(reject.clone(), |p, s| p.rejection_id = s.into());
    scoped::<event_spec::AgentActionReject>(reject, |p, s| p.request_id = s.into());
}
#[test]
fn agent_key_selectors_cannot_bypass_serde_via_typed_authoring() {
    let authorize:AgentKeyAuthorizePayload=serde_json::from_value(json!({"agent_id":"ak:did_core:web:agent.example","key_id":"valid","verification_method":"did:web:agent.example#key","public_key":{"kty":"OKP","kid":"did:web:agent.example#key","algorithm":"Ed25519","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"accountable_principal_id":"ak:did_core:web:controller.example","agent_key_scope":{"actions":["ak.message.create"],"resources":[{"kind":"realm","realm_id":scope().realm_id()}]},"audience":["ak:did_core:web:station.example"],"issued_at":"2026-11-12T00:00:00.000Z","approval_evidence":{"kind":"approval_event"}})).unwrap();
    // NonEmptyString itself cannot represent empty; other invalid profiles can.
    check::<event_spec::AgentKeyAuthorize>(
        authorize.clone(),
        |p, s| p.key_id = NonEmptyString::new(if s.is_empty() { "ak:invalid" } else { s }).unwrap(),
        true,
    );
    check::<event_spec::AgentKeyAuthorize>(
        authorize,
        |p, s| {
            p.supersedes = vec![AgentKeySupersession {
                key_id: NonEmptyString::new(if s.is_empty() { "ak:invalid" } else { s }).unwrap(),
                authorized_event_ref: event(),
            }]
        },
        true,
    );
    let revoke:AgentKeyRevokePayload=serde_json::from_value(json!({"agent_id":"ak:did_core:web:agent.example","key_id":"valid","revoked_by":"ak:did_core:web:controller.example","revoked_at":"2026-11-12T00:00:00.000Z"})).unwrap();
    check::<event_spec::AgentKeyRevoke>(
        revoke,
        |p, s| p.key_id = NonEmptyString::new(if s.is_empty() { "ak:invalid" } else { s }).unwrap(),
        true,
    );
}
#[test]
fn organization_statement_handles_cannot_bypass_serde_via_typed_authoring() {
    let payload:RealmOrganizationPayload=serde_json::from_value(json!({"statement_id":"valid","realm_id":scope().realm_id(),"organization_id":"ak:did_core:web:org.example","relationship":"owner","status":"active","control_scopes":["official_badge"],"issued_at":"2026-11-12T00:00:00.000Z","authorization":{"issuer_id":"ak:did_core:web:org.example","issuer_role":"organization","verification_method":"did:web:org.example#key","signed_at":"2026-11-12T00:00:00.000Z","proof":"placeholder"}})).unwrap();
    scoped::<event_spec::RealmOrganization>(payload.clone(), |p, s| p.statement_id = s.into());
    scoped::<event_spec::RealmOrganization>(payload.clone(), |p, s| {
        p.supersedes_statement_id = Some(s.into())
    });
    scoped::<event_spec::RealmOrganization>(payload, |p, s| {
        p.revokes_statement_id = Some(s.into())
    });
}

fn both_entrypoints<K: EventSpec>(payload: K::Payload, valid: bool)
where
    K::Payload: Clone,
{
    assert_eq!(
        TypedEventDraft::<K>::new(scope(), actor(), payload.clone()).is_ok(),
        valid
    );
    assert_eq!(
        EventContentDraft::<K>::new(scope(), actor(), now())
            .unwrap()
            .intent()
            .clone()
            .with_typed_payload::<K>(payload)
            .is_ok(),
        valid
    );
}
#[test]
fn media_configuration_and_roster_markers_apply_their_existing_validators() {
    use arkret_models_collaboration::events_payloads::RealmMediaServicePayload;
    use arkret_models_collaboration::events_payloads::call::{CallRosterDelta, CallStatePayload};
    let service:RealmMediaServicePayload=serde_json::from_value(json!({"value":{"service_id":"ak:did_core:web:media.example","modes":["sfu"],"foci":[{"focus_id":"valid","focus_kind":"livekit","token_endpoint":"https://media.example/token","connect_url":"wss://media.example/rtc"}]}})).unwrap();
    scoped::<event_spec::RealmMediaService>(service, |p, s| {
        p.value.foci[0].focus_id =
            NonEmptyString::new(if s.is_empty() { "ak:invalid" } else { s }).unwrap()
    });
    let call_id = arkret_wire::CallId::from_event_id(&event());
    let payload:CallStatePayload=serde_json::from_value(json!({"call_id":call_id,"roster_delta":{"op":"join","participant":{"actor_id":actor(),"device_id":"ak:device:01904100-0000-7000-8000-000000000008","focus_id":"valid","participant_id":"ak:rtc_participant:01904100-0000-7000-8000-000000000009","participant_binding":{"expires_at":"2026-11-13T00:00:00.000Z","issuer_kid":"did:web:media.example#key","signature":"placeholder"},"media":{"audio":true,"video":true,"screen":false}}}})).unwrap();
    for literal in [
        " ".to_owned(),
        "é".to_owned(),
        "🦀".repeat(64),
        String::new(),
        "ak:focus:invalid".into(),
        "🦀".repeat(65),
    ] {
        let mut value = payload.clone();
        let Some(CallRosterDelta::Join { participant }) = &mut value.roster_delta else {
            panic!("join")
        };
        participant.focus_id = Some(literal.clone());
        both_entrypoints::<event_spec::CallState>(
            value,
            arkret_wire::validate_bounded_non_typed_identifier(&literal, 64).is_ok(),
        );
    }
}
#[test]
fn capability_grant_marker_validates_all_constraint_identifiers_before_authoring() {
    use arkret_models_collaboration::events_payloads::CapabilityGrantPayload;
    let grant:CapabilityGrantPayload=serde_json::from_value(json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":scope().realm_id(),"issuer_id":actor(),"subject":actor(),"actions":["ak.message.create"],"resources":[{"kind":"realm","realm_id":scope().realm_id()}],"constraints":[{"constraint_kind":"temporal","effect":"allow"}],"issued_at":"2026-11-12T00:00:00.000Z","issuer_authority_refs":[{"kind":"realm_root","realm_id":scope().realm_id(),"authority_event_ref":event(),"authority_generation":"0"}]}})).unwrap();
    scoped::<event_spec::CapabilityGrant>(grant.clone(), |p, s| {
        p.grant.constraints[0].constraint_id = Some(s.into())
    });
    scoped::<event_spec::CapabilityGrant>(grant, |p, s| {
        p.grant.constraints[0].allowed_session_ids = vec![s.into()]
    });
}
