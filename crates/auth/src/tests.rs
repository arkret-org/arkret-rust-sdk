use arkret_wire::{DidCoreId, DidFullId};

use super::helpers::sha256_hex;
use super::*;

fn did(name: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture{name}")).unwrap()
}

fn device(id: &str) -> DeviceId {
    let mut acc = 0xcbf29ce484222325u64;
    for byte in id.bytes() {
        acc = (acc ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    DeviceId::new(format!(
        "ak:device:01904100-0000-7000-8000-{:012x}",
        acc & 0x0000_ffff_ffff_ffff
    ))
    .unwrap()
}

fn session_grant_payload(now: DateTime<Utc>, device_id: &DeviceId) -> SessionGrantPayload {
    use arkret_models_identity::{
        CanonicalSessionPublicJwk, SESSION_GRANT_CREDENTIAL_KIND, SessionGrantCnf,
        SessionGrantCredentialClass, SessionGrantDeviceBinding, SessionGrantIssuanceNonce,
    };

    let mut claims = SignedSessionGrantClaims {
        kind: SESSION_GRANT_CREDENTIAL_KIND.to_owned(),
        grant_id: arkret_wire::SessionGrantId::from_issuance_digest([0; 32]),
        issuer: did("coauth"),
        issuance_nonce: SessionGrantIssuanceNonce::from_bytes([0x33; 32]),
        subject: did("alice"),
        session_public_key: CanonicalSessionPublicJwk::new(
            r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .unwrap(),
        audience: did("soland"),
        scopes: vec!["ak.self.account.read.viewer".to_owned()],
        not_before: now,
        expires_at: now + Duration::minutes(10),
        session_id: "browser-session-1".to_owned(),
        cnf: SessionGrantCnf {
            jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        },
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: arkret_models_identity::SessionGrantHolderBinding::HumanDevice {
            device_binding: device_id.to_string(),
        },
        device_binding: Some(SessionGrantDeviceBinding {
            device_id: device_id.clone(),
            authorization_event_id: arkret_wire::EventId::new(
                "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g",
            )
            .unwrap(),
            model_generation_ref: 1,
        }),
        proof_kind: None,
        scope_details: None,
    };
    claims.grant_id = claims.recomputed_grant_id().unwrap();
    SessionGrantPayload { claims }
}

fn session_grant_notification(
    now: DateTime<Utc>,
    request_id: &str,
) -> PrincipalSessionGrantNotification {
    let device_id = device("desktop");
    let payload = session_grant_payload(now, &device_id);
    let mut record = SessionGrant::new(payload, "signed.jwt.value")
        .unwrap()
        .into_record();
    record.revoke(now + Duration::minutes(1), "logout");

    PrincipalSessionGrantNotification {
        request_id: request_id.to_owned(),
        kind: SessionGrantNotificationKind::Revoked,
        record,
        admin_actor: Some(did("admin")),
        reason: Some("logout".to_owned()),
    }
}

#[test]
fn json_web_key_set_accepts_typed_public_keys_and_rejects_ambiguous_input() {
    let jwks = serde_json::json!({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "key_ops": ["verify"],
                "alg": "RS256",
                "kid": "rsa-2026-07",
                "n": "AQAB",
                "e": "AQAB"
            },
            {
                "kty": "OKP",
                "use": "sig",
                "alg": "Ed25519",
                "kid": "ed25519-2026-07",
                "crv": "Ed25519",
                "x": "AQAB"
            }
        ]
    });
    let parsed: arkret_signatures::JsonWebKeySet = serde_json::from_value(jwks.clone()).unwrap();
    assert_eq!(parsed.keys().len(), 2);
    assert_eq!(serde_json::to_value(parsed).unwrap(), jwks);

    let missing_rsa_exponent = serde_json::json!({
        "keys": [{ "kty": "RSA", "n": "AQAB" }]
    });
    assert!(
        serde_json::from_value::<arkret_signatures::JsonWebKeySet>(missing_rsa_exponent).is_err()
    );

    let symmetric_key = serde_json::json!({
        "keys": [{ "kty": "oct", "k": "AQAB" }]
    });
    assert!(serde_json::from_value::<arkret_signatures::JsonWebKeySet>(symmetric_key).is_err());

    let unknown_member = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "n": "AQAB",
            "e": "AQAB",
            "legacy_key_material": "opaque"
        }]
    });
    assert!(serde_json::from_value::<arkret_signatures::JsonWebKeySet>(unknown_member).is_err());

    let duplicate_kid = serde_json::json!({
        "keys": [
            { "kty": "RSA", "kid": "duplicate", "n": "AQAB", "e": "AQAB" },
            { "kty": "OKP", "kid": "duplicate", "crv": "Ed25519", "x": "AQAB" }
        ]
    });
    assert!(serde_json::from_value::<arkret_signatures::JsonWebKeySet>(duplicate_kid).is_err());

    let legacy_nested_value = serde_json::json!({ "keys": { "keys": [] } });
    assert!(
        serde_json::from_value::<arkret_signatures::JsonWebKeySet>(legacy_nested_value).is_err()
    );
}

#[test]
fn auth_password_hash_is_salted_argon2id() {
    let mut auth = AuthManager::default();
    let user = auth
        .register_password_user("alice", "secret", did("alice"))
        .unwrap();
    // Built-in hashing now produces a salted Argon2id PHC string, not a
    // bare SHA-256 hex digest.
    assert!(user.password_hash.starts_with("$argon2id$"));
    assert!(
        auth.login_password("alice", "secret", device("desktop"))
            .is_ok()
    );
    assert!(
        auth.login_password("alice", "wrong", device("desktop"))
            .is_err()
    );
}

#[test]
fn auth_account_state_defaults_fail_closed() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    // Unknown accounts fail closed as suspended until registration.
    assert_eq!(auth.account_state(&alice), AccountAuthState::Suspended);
    auth.register_password_user("alice", "secret", alice.clone())
        .unwrap();
    assert_eq!(auth.account_state(&alice), AccountAuthState::Active);
}

#[test]
fn session_grant_contract_redacts_and_notifies_principal_servers() {
    let now = Utc::now();
    let device_id = device("desktop");
    let payload = session_grant_payload(now, &device_id);
    payload.validate().unwrap();
    let binding = payload.principal_binding().unwrap();
    assert_eq!(binding.principal_id, did("alice"));
    assert_eq!(binding.device_id, device_id);

    let signer = |payload: &SessionGrantPayload| {
        payload.validate()?;
        Ok(format!("signed.{}.jwt", payload.claims.grant_id))
    };
    let issued = issue_session_grant_with_signer(payload.clone(), &signer).unwrap();
    let verifier = |grant_jwt: &str| {
        Ok(SessionGrantVerification {
            payload: payload.clone(),
            grant_hash: sha256_hex(grant_jwt.as_bytes()),
            verified: grant_jwt.starts_with("signed."),
        })
    };
    let verified = verify_session_grant_with_verifier(&issued.grant_jwt, &verifier).unwrap();
    assert_eq!(verified.grant_hash, issued.grant_hash);

    let grant = SessionGrant::new(payload, "signed.jwt.value").unwrap();
    assert!(!format!("{grant:?}").contains("signed.jwt.value"));
    let mut record = grant.into_record();
    assert!(record.active(now));
    let successor = arkret_wire::SessionGrantId::from_issuance_digest([0x55; 32]);
    record.supersede(now + Duration::seconds(30), successor.clone());
    assert!(!record.active(now));
    assert_eq!(record.successor_session_grant_id, Some(successor));
    // Build the revoke projection used by the remainder of this
    // notification adapter test.
    record.revoke(now + Duration::minutes(1), "logout");

    let notification = PrincipalSessionGrantNotification {
        request_id: "request-1".to_owned(),
        kind: SessionGrantNotificationKind::Revoked,
        record,
        admin_actor: Some(did("admin")),
        reason: Some("logout".to_owned()),
    };
    notification.validate().unwrap();

    let notifier = |notification: &PrincipalSessionGrantNotification| {
        notification.validate()?;
        Ok(PrincipalSessionGrantNotificationOutcome {
            accepted: true,
            audit_id: Some("audit-1".to_owned()),
            retry_after_ms: None,
        })
    };
    let response = notifier.notify_session_grant(&notification).unwrap();
    assert!(response.accepted);

    let mut outbox = MemorySessionGrantOutbox::default();
    outbox.enqueue(notification, now).unwrap();
    assert_eq!(outbox.due(now).len(), 1);
    let policy = SessionGrantRetryPolicy {
        initial_backoff_ms: 10,
        max_backoff_ms: 100,
        max_attempts: 2,
    };
    let mut entry = outbox.entries().next().unwrap().clone();
    entry.record_failure("temporary", now, policy);
    assert_eq!(entry.state, SessionGrantOutboxState::Failed);
    entry.record_failure("still failing", now, policy);
    assert_eq!(entry.state, SessionGrantOutboxState::DeadLettered);
}

#[derive(Default)]
struct MockPgSessionGrantOutbox {
    rows: Vec<SessionGrantOutboxEntry>,
    writes: Vec<String>,
}

impl SessionGrantOutbox for MockPgSessionGrantOutbox {
    fn enqueue(
        &mut self,
        notification: PrincipalSessionGrantNotification,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.writes
            .push(format!("insert:{}", notification.request_id));
        self.rows
            .push(SessionGrantOutboxEntry::new(notification, now)?);
        Ok(())
    }

    fn due(&self, now: DateTime<Utc>) -> Result<Vec<SessionGrantOutboxEntry>> {
        Ok(self
            .rows
            .iter()
            .filter(|entry| entry.due(now))
            .cloned()
            .collect())
    }

    fn entries(&self) -> Result<Vec<SessionGrantOutboxEntry>> {
        Ok(self.rows.clone())
    }

    fn record_delivery(&mut self, request_id: &str) -> Result<bool> {
        let Some(entry) = self
            .rows
            .iter_mut()
            .find(|entry| entry.notification.request_id == request_id)
        else {
            return Ok(false);
        };
        self.writes.push(format!("delivered:{request_id}"));
        entry.record_delivery();
        Ok(true)
    }

    fn record_failure(
        &mut self,
        request_id: &str,
        error: String,
        now: DateTime<Utc>,
        policy: SessionGrantRetryPolicy,
    ) -> Result<bool> {
        let Some(entry) = self
            .rows
            .iter_mut()
            .find(|entry| entry.notification.request_id == request_id)
        else {
            return Ok(false);
        };
        self.writes.push(format!("failure:{request_id}:{error}"));
        entry.record_failure(error, now, policy);
        Ok(true)
    }
}

#[test]
fn session_grant_outbox_slot_accepts_memory_and_pg_like_backends() {
    let now = Utc::now();
    let policy = SessionGrantRetryPolicy {
        initial_backoff_ms: 10,
        max_backoff_ms: 100,
        max_attempts: 2,
    };

    let mut memory = SessionGrantOutboxSlot::memory();
    memory
        .enqueue(session_grant_notification(now, "memory-1"), now)
        .unwrap();
    assert_eq!(memory.due(now).unwrap().len(), 1);
    assert!(memory.record_delivery("memory-1").unwrap());
    assert_eq!(memory.due(now).unwrap().len(), 0);

    let mut pg = SessionGrantOutboxSlot::new(Box::<MockPgSessionGrantOutbox>::default());
    pg.enqueue(session_grant_notification(now, "pg-1"), now)
        .unwrap();
    assert_eq!(pg.due(now).unwrap().len(), 1);
    assert!(
        pg.record_failure("pg-1", "serialization_failure", now, policy)
            .unwrap()
    );
    let entry = pg.entries().unwrap().pop().unwrap();
    assert_eq!(entry.state, SessionGrantOutboxState::Failed);
    assert_eq!(entry.attempts, 1);
}

#[test]
fn device_scope_helpers_accept_only_arkret_scope() {
    let device = device("phone");
    let scope = arkret_device_scope(&device);
    assert_eq!(device_id_from_scope_token(&scope).unwrap(), device);
    assert_eq!(
        primary_device_id_from_scopes(["openid", scope.as_str()]).unwrap(),
        device
    );

    assert!(device_id_from_scope_token("urn:matrix:client:device:dev_phone").is_none());
}

#[test]
fn auth_validates_progressive_disclosure_claims_fail_closed() {
    let alice = did("alice");
    let issuer = did("issuer");
    let org = did("org");
    let guardian = did("guardian");
    let controller = DidFullId::new("did:webvh:z6mkfixturecontroller:controller.example").unwrap();
    let request = PresentationRequestBody {
        request_id: "presentation-1".to_owned(),
        subject: alice.clone(),
        audience: "arkret-auth".to_owned(),
        nonce: "nonce".to_owned(),
        policy: ClaimDisclosurePolicy {
            policy_id: "policy-1".to_owned(),
            requirements: vec![
                ClaimDisclosureRequirement {
                    claim_kind: AuthClaimKind::VerifiedHandle.as_str().to_owned(),
                    trusted_issuers: vec![issuer.clone()],
                    reveal_fields: vec!["handle".to_owned()],
                    required: true,
                },
                ClaimDisclosureRequirement {
                    claim_kind: AuthClaimKind::OrganizationMembership.as_str().to_owned(),
                    trusted_issuers: vec![issuer.clone()],
                    reveal_fields: vec!["organization".to_owned()],
                    required: true,
                },
                ClaimDisclosureRequirement {
                    claim_kind: AuthClaimKind::GuardianController.as_str().to_owned(),
                    trusted_issuers: vec![issuer.clone()],
                    reveal_fields: vec!["guardian".to_owned(), "controller".to_owned()],
                    required: true,
                },
            ],
            max_age: Some(Duration::days(1)),
            fail_closed: true,
        },
        created_at: Utc::now(),
        verifier_service_id: None,
        represented_org: None,
        verifier_authority_chain: Vec::new(),
    };
    let mut handle =
        PresentedClaim::verified_handle("claim-handle", alice.clone(), issuer.clone(), "alice");
    handle.issued_at = Utc::now();
    let membership = PresentedClaim::organization_membership(
        "claim-org",
        alice.clone(),
        issuer.clone(),
        org.clone(),
        vec!["writer".to_owned()],
    );
    let guardian_controller = PresentedClaim::guardian_controller(
        "claim-guardian",
        alice.clone(),
        issuer.clone(),
        guardian.clone(),
        controller.clone(),
    );

    let accepted = validate_presentation(
        &request,
        &[
            handle.clone(),
            membership.clone(),
            guardian_controller.clone(),
        ],
        &BTreeSet::new(),
        Utc::now(),
    );
    assert!(accepted.accepted);
    assert_eq!(
        accepted.disclosed_claims[0].value(),
        &serde_json::from_value(serde_json::json!({"handle": "alice"})).unwrap()
    );
    assert_eq!(
        accepted.disclosed_claims[1].value(),
        &serde_json::from_value(serde_json::json!({
            "organization": org
        }))
        .unwrap()
    );
    assert_eq!(
        accepted.disclosed_claims[2].value(),
        &serde_json::from_value(serde_json::json!({
            "guardian": guardian,
            "controller": controller
        }))
        .unwrap()
    );
    let boundary = DisclosureProofAdapterBoundary {
        format: DisclosureProofFormat::SdJwt,
        holder: alice,
        issuer,
        audience: request.audience.clone(),
        nonce: request.nonce.clone(),
        domain: Some("arkret-auth".to_owned()),
        encoded_presentation: "compact.sd-jwt".to_owned(),
    };
    boundary
        .validate_request_binding(&request, Some("arkret-auth"))
        .unwrap();
    let verified = verify_presentation_with_adapter(
        &request,
        &boundary,
        &[
            handle.clone(),
            membership.clone(),
            guardian_controller.clone(),
        ],
        &BTreeSet::new(),
        Utc::now(),
        Some("arkret-auth"),
        |proof| {
            if proof.encoded_presentation == "compact.sd-jwt" {
                Ok(())
            } else {
                Err(Error::Protocol("unexpected presentation".to_owned()))
            }
        },
    )
    .unwrap();
    assert!(verified.accepted);
    assert!(
        verify_presentation_with_adapter(
            &request,
            &boundary,
            &[handle.clone(), membership, guardian_controller],
            &BTreeSet::new(),
            Utc::now(),
            Some("arkret-auth"),
            |_| Err(Error::Protocol("bad proof".to_owned())),
        )
        .is_err()
    );
    let mut wrong_audience = boundary;
    wrong_audience.audience = "other-audience".to_owned();
    assert!(
        wrong_audience
            .validate_request_binding(&request, Some("arkret-auth"))
            .is_err()
    );

    let rejected = validate_presentation(
        &request,
        &[handle],
        &BTreeSet::from(["claim-handle".to_owned()]),
        Utc::now(),
    );
    assert!(!rejected.accepted);
    assert!(
        rejected
            .rejected_claims
            .iter()
            .any(|claim| claim.reason == "claim is revoked")
    );
}

#[test]
fn auth_redacts_secrets_in_debug_output() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    let user = auth
        .register_password_user("alice", "secret", alice.clone())
        .unwrap();
    let session = auth
        .login_password("alice", "secret", device("desktop"))
        .unwrap();

    assert!(!format!("{user:?}").contains(&user.password_hash));
    assert!(!format!("{session:?}").contains(&session.session_credential));
    assert!(!format!("{session:?}").contains(&session.renewal_credential));
}

#[test]
fn presented_claim_omitted_optional_timestamps_round_trip() {
    let value = serde_json::json!({
        "claim_id": "claim-1",
        "subject": did("subject"),
        "issuer": did("issuer"),
        "claim_kind": "verified_handle",
        "value": {"display": "alice"},
        "issued_at": "2026-08-18T00:00:00.000Z",
    });

    let claim: PresentedClaim = serde_json::from_value(value).unwrap();
    assert_eq!(claim.refreshed_at, None);
    assert_eq!(claim.expires_at, None);
    assert_eq!(claim.revoked_at, None);

    let serialized = serde_json::to_value(&claim).unwrap();
    let object = serialized.as_object().unwrap();
    assert!(!object.contains_key("refreshed_at"));
    assert!(!object.contains_key("expires_at"));
    assert!(!object.contains_key("revoked_at"));
}

#[test]
fn session_grant_record_omitted_revoked_at_round_trip() {
    let now: DateTime<Utc> = "2026-08-18T00:00:00.000Z".parse().unwrap();
    let record = SessionGrantRecord {
        payload: session_grant_payload(now, &device("laptop")),
        grant_hash: "sha256:grant".to_owned(),
        created_at: now,
        state: SessionGrantProjectionState::Active,
        revoked_at: None,
        revoke_reason: None,
        successor_session_grant_id: None,
    };

    let serialized = serde_json::to_value(&record).unwrap();
    assert!(!serialized.as_object().unwrap().contains_key("revoked_at"));

    let restored: SessionGrantRecord = serde_json::from_value(serialized).unwrap();
    assert_eq!(restored, record);
}

#[test]
fn renewal_credential_metadata_omitted_revoked_at_round_trip() {
    let now: DateTime<Utc> = "2026-08-18T00:00:00.000Z".parse().unwrap();
    let metadata = RenewalCredentialMetadata {
        session_id: "session-1".to_owned(),
        user_id: did("alice"),
        device_id: device("desktop"),
        session_credential_hash: "sha256:session".to_owned(),
        renewal_credential_hash: "sha256:renewal".to_owned(),
        issued_at: now,
        expires_at: now,
        revoked_at: None,
    };

    let serialized = serde_json::to_value(&metadata).unwrap();
    assert!(!serialized.as_object().unwrap().contains_key("revoked_at"));

    let restored: RenewalCredentialMetadata = serde_json::from_value(serialized).unwrap();
    assert_eq!(restored, metadata);
}
