use arkret_models_collaboration::events_payloads::agent::{
    AgentDraftAccountDataValue, AgentDraftContentHandoffPlaintext,
};
use arkret_models_collaboration::events_payloads::preview::PreviewPolicyPayloadValueToken;
use arkret_models_collaboration::governance::realm_governance::{
    RealmLinkDirection, RealmLinkKind, RealmLinkListQuery,
};
use arkret_wire::{EventId, RealmPolicyActionId};
use serde_json::{Value, json};

fn plaintext() -> Value {
    json!({
        "schema":"ak.schema.agent_draft_content_handoff_plaintext.v1",
        "draft_id":" ", "agent_id":"ak:did_core:web:agent.example",
        "content":{"arbitrary":[true,null,123]},
        "content_digest":format!("sha256:{}", "a".repeat(64)),
        "expires_at":"2026-11-13T00:00:00.000Z", "created_at":"2026-11-12T00:00:00.000Z"
    })
}

#[test]
fn private_draft_plaintexts_have_closed_actual_serde_and_unicode_handle_bounds() {
    let mut body = plaintext();
    for literal in [" ".to_owned(), "🦀".repeat(256)] {
        body["draft_id"] = json!(literal);
        let parsed: AgentDraftContentHandoffPlaintext =
            serde_json::from_value(body.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), body);
    }
    for literal in [
        String::new(),
        "ak:draft:unregistered".into(),
        "🦀".repeat(257),
    ] {
        body["draft_id"] = json!(literal);
        assert!(serde_json::from_value::<AgentDraftContentHandoffPlaintext>(body.clone()).is_err());
    }
    let mut account = plaintext();
    account["schema"] = json!("ak.schema.agent_draft.v1");
    account["proposed_action"] = json!("ak.message.send");
    account["target"] =
        json!({"kind":"service_operation","operation_id":"ak.self.session.command.issue.v1"});
    account["source_pending_event_id"] = json!(EventId::from_digest(
        arkret_wire::canonical::DigestSuite::Sha256,
        [4; 32]
    ));
    account["workflow_state"] = json!("proposed");
    let parsed: AgentDraftAccountDataValue = serde_json::from_value(account.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), account);
    account["draft_id"] = json!("🦀".repeat(257));
    assert!(serde_json::from_value::<AgentDraftAccountDataValue>(account).is_err());
    let mut extra = plaintext();
    extra["extra"] = json!(1);
    assert!(serde_json::from_value::<AgentDraftContentHandoffPlaintext>(extra).is_err());
    let mut wrong = plaintext();
    wrong["schema"] = json!("ak.schema.agent_draft.v1");
    assert!(serde_json::from_value::<AgentDraftContentHandoffPlaintext>(wrong).is_err());
}

#[test]
fn realm_action_names_keep_scope_profile_without_trimming() {
    for literal in [" ".to_owned(), "🦀".repeat(256)] {
        assert_eq!(
            RealmPolicyActionId::new(literal.clone()).unwrap().as_str(),
            literal
        );
    }
    for literal in [String::new(), "ak:policy:bad".into(), "🦀".repeat(257)] {
        assert!(RealmPolicyActionId::new(literal).is_err());
    }
}

#[test]
fn realm_link_query_is_closed_before_parameter_extraction_and_uses_new_filter() {
    let query = RealmLinkListQuery::from_query_pairs([
        ("direction", "outbound"),
        ("allowed_link_kinds", "governed_by,mirror_of"),
    ])
    .unwrap();
    assert_eq!(query.direction, RealmLinkDirection::Outbound);
    assert_eq!(
        query.allowed_link_kinds,
        Some(vec![RealmLinkKind::GovernedBy, RealmLinkKind::MirrorOf])
    );
    assert_eq!(
        query.to_query_pairs().unwrap()[1],
        ("allowed_link_kinds", "governed_by,mirror_of".into())
    );
    for pairs in [
        vec![("link_kind_allow", "governed_by")],
        vec![
            ("allowed_link_kinds", "governed_by"),
            ("link_kind_allow", "mirror_of"),
        ],
        vec![
            ("allowed_link_kinds", "governed_by"),
            ("allowed_link_kinds", "mirror_of"),
        ],
        vec![("direction", "outbound"), ("direction", "inbound")],
        vec![("direction", "out")],
        vec![("allowed_link_kinds", "")],
        vec![("allowed_link_kinds", "unknown")],
        vec![("allowed_link_kinds", "governed_by,")],
        vec![("extra", "true")],
    ] {
        assert!(RealmLinkListQuery::from_query_pairs(pairs).is_err());
    }
    assert_eq!(
        RealmLinkListQuery::from_query_pairs(Vec::<(&str, &str)>::new())
            .unwrap()
            .direction,
        RealmLinkDirection::Both
    );
}

#[test]
fn preview_binding_obligation_rejects_false_and_old_names_at_serde_boundary() {
    let token: PreviewPolicyPayloadValueToken = serde_json::from_value(
        json!({"token_required":false,"target_digest_binding_required":true}),
    )
    .unwrap();
    token.validate().unwrap();
    for invalid in [
        json!({"required":true}),
        json!({"bind_target_digest":true}),
        json!({"target_digest_binding_required":false}),
        json!({"target_digest_binding_required":null}),
        json!({"token_required":null}),
        json!({"token_required":true,"required":true}),
    ] {
        assert!(serde_json::from_value::<PreviewPolicyPayloadValueToken>(invalid).is_err());
    }
}

#[test]
fn agent_key_actual_event_state_and_supersession_serde_share_the_terminal() {
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyAuthorizePayload, AgentKeyRevokePayload, AgentKeySupersession,
    };
    use arkret_models_collaboration::governance::agent_artifacts::AgentKeyAuthorizationState;
    use arkret_wire::{CurrentSelector, RealmId};
    let event_id = EventId::from_digest(arkret_wire::canonical::DigestSuite::Sha256, [8; 32]);
    let realm_id = RealmId::from_event_id(&event_id);
    let method = format!("did:web:agent.example#{}", "runtime".repeat(50));
    assert!(method.chars().count() > 256);
    let key_bytes = ed25519_dalek::SigningKey::from_bytes(&[8; 32])
        .verifying_key()
        .to_bytes();
    let public_key = json!({"kty":"OKP","kid":method,"algorithm":"Ed25519","key":arkret_canonical::base64url_encode(key_bytes)});
    let authorize = json!({
        "agent_id":"ak:did_core:web:agent.example","key_id":"runtime-key",
        "verification_method":method,"public_key":public_key,
        "accountable_principal_id":"ak:did_core:web:controller.example",
        "agent_key_scope":{"actions":["ak.message.create"],"resources":[{"kind":"realm","realm_id":realm_id}]},
        "audience":["station.example"],"issued_at":"2026-11-12T00:00:00.000Z",
        "approval_evidence":{"kind":"approval_event"}
    });
    let revoke = json!({"agent_id":"ak:did_core:web:agent.example","key_id":"runtime-key","revoked_by":"ak:did_core:web:controller.example","revoked_at":"2026-11-12T00:00:00.000Z"});
    let state = json!({"key_id":"runtime-key","verification_method":method,"authorized_event_ref":event_id});
    let supersession = json!({"key_id":"runtime-key","authorized_event_ref":event_id});
    let selector = json!({"kind":"agent_key","agent_id":"ak:did_core:web:agent.example","agent_key_id":"runtime-key"});
    for literal in [
        "runtime-key".to_owned(),
        "a".repeat(256),
        format!("did:web:{}#k", "é".repeat(246)),
    ] {
        let mut body = authorize.clone();
        body["key_id"] = json!(literal);
        let parsed: AgentKeyAuthorizePayload = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.key_id.as_str(), literal);
        assert_eq!(parsed.verification_method.as_str(), method);
        assert_eq!(parsed.public_key.kid.as_str(), method);
        let mut body = revoke.clone();
        body["key_id"] = json!(literal);
        assert!(serde_json::from_value::<AgentKeyRevokePayload>(body).is_ok());
        let mut body = state.clone();
        body["key_id"] = json!(literal);
        assert!(serde_json::from_value::<AgentKeyAuthorizationState>(body).is_ok());
        let mut body = supersession.clone();
        body["key_id"] = json!(literal);
        assert!(serde_json::from_value::<AgentKeySupersession>(body).is_ok());
        let mut body = selector.clone();
        body["agent_key_id"] = json!(literal);
        assert!(serde_json::from_value::<CurrentSelector>(body).is_ok());
    }
    for literal in [
        json!(""),
        json!("ak:key:example"),
        json!("a".repeat(257)),
        json!(format!("did:web:{}#k", "é".repeat(247))),
        json!(" "),
        json!("runtime\n"),
        json!("did:web:example#key\n"),
        Value::Null,
    ] {
        let mut body = authorize.clone();
        body["key_id"] = literal.clone();
        assert!(serde_json::from_value::<AgentKeyAuthorizePayload>(body).is_err());
        let mut body = revoke.clone();
        body["key_id"] = literal.clone();
        assert!(serde_json::from_value::<AgentKeyRevokePayload>(body).is_err());
        let mut body = state.clone();
        body["key_id"] = literal.clone();
        assert!(serde_json::from_value::<AgentKeyAuthorizationState>(body).is_err());
        let mut body = supersession.clone();
        body["key_id"] = literal.clone();
        assert!(serde_json::from_value::<AgentKeySupersession>(body).is_err());
        let mut body = selector.clone();
        body["agent_key_id"] = literal;
        assert!(serde_json::from_value::<CurrentSelector>(body).is_err());
    }
}
