use super::helpers::sha256_hex;
use super::*;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn device(id: &str) -> DeviceId {
    let mut acc = 0xcbf29ce484222325u64;
    for byte in id.bytes() {
        acc = (acc ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    DeviceId::new(format!("cx:device:01904100-0000-7000-8000-{:012x}", acc & 0x0000_ffff_ffff_ffff))
        .unwrap()
}

fn deny_password_login(ctx: &AuthRateLimitContext) -> Result<()> {
    if ctx.action == AuthRateLimitAction::PasswordLogin {
        Err(Error::Protocol("rate limited".to_owned()))
    } else {
        Ok(())
    }
}

#[test]
fn auth_handles_password_mfa_and_sessions() {
    let alice = did("alice");
    let mut auth = AuthManager::new(1);
    auth.register_password_user("alice", "secret", alice.clone()).unwrap();
    auth.enable_mfa("alice").unwrap();
    assert!(auth.login_password("alice", "secret", device("1")).is_err());

    let mfa = auth.issue_mfa(alice.clone());
    auth.verify_mfa(&alice, &mfa.code).unwrap();
    let first = auth.login_password("alice", "secret", device("1")).unwrap();
    let second = auth.login_password("alice", "secret", device("2")).unwrap();

    assert_eq!(auth.active_sessions(&alice).len(), 1);
    let binding = auth.session_principal_binding(&second.session_id).unwrap();
    assert_eq!(binding.principal_id, alice);
    assert!(auth.refresh_session(&second.session_id, &second.refresh_token).is_ok());
    assert!(auth.refresh_session(&first.session_id, &first.refresh_token).is_err());
    auth.revoke_session(&second.session_id).unwrap();
    assert!(auth.active_sessions(&alice).is_empty());
}

#[test]
fn auth_handles_oidc_and_passkeys() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    auth.set_account_state(alice.clone(), AccountAuthState::Active);
    let oidc = auth.start_oidc("https://issuer.example", "client", "https://app/cb", "state");
    assert!(oidc.authorization_url.contains("response_type=code"));
    assert!(auth.complete_oidc(alice.clone(), device("oidc")).is_ok());

    let challenge = auth.start_passkey(alice.clone());
    let response = sha256_hex(challenge.challenge.as_bytes());
    let session = auth.verify_passkey(&alice, &response, device("passkey")).unwrap();
    assert_eq!(session.user_id, alice);
}

#[test]
fn auth_uses_provider_password_verifier() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    auth.register_password_hash("alice", "$argon2id$hash", alice.clone()).unwrap();

    let verifier = |request: &PasswordVerificationReqBody| {
        assert_eq!(request.username, "alice");
        assert_eq!(request.user_id, alice);
        assert_eq!(request.password_hash, "$argon2id$hash");
        assert_eq!(request.algorithm, PasswordHashAlgorithm::Argon2id);
        Ok(PasswordVerification { verified: request.password == "secret", rehash_needed: false })
    };

    let session = auth
        .login_password_with_verifier(
            "alice",
            "secret",
            PasswordHashAlgorithm::Argon2id,
            device("password-provider"),
            &verifier,
        )
        .unwrap();
    assert_eq!(session.user_id, did("alice"));

    assert!(
        auth.login_password_with_verifier(
            "alice",
            "wrong",
            PasswordHashAlgorithm::Argon2id,
            device("password-provider-2"),
            &verifier,
        )
        .is_err()
    );
}

#[test]
fn auth_uses_provider_oidc_verifier_with_metadata_and_jwks() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    auth.set_account_state(alice.clone(), AccountAuthState::Active);
    let request = OidcVerificationReqBody {
        issuer_metadata: OidcIssuerMetadata {
            issuer: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/authorize".to_owned(),
            token_endpoint: "https://issuer.example/token".to_owned(),
            jwks_uri: "https://issuer.example/jwks".to_owned(),
        },
        jwks: OidcJwks { keys: serde_json::json!({ "keys": [] }) },
        client_id: "client".to_owned(),
        expected_nonce: Some("nonce".to_owned()),
        credential: OidcCredential::IdToken { id_token: "token".to_owned() },
    };
    let verifier = |request: &OidcVerificationReqBody| {
        assert_eq!(request.issuer_metadata.jwks_uri, "https://issuer.example/jwks");
        Ok(OidcVerifiedIdentity {
            user_id: alice.clone(),
            issuer: request.issuer_metadata.issuer.clone(),
            subject: "sub-123".to_owned(),
            email: Some("alice@example.com".to_owned()),
            email_verified: true,
            expires_at: Some(Utc::now() + Duration::minutes(5)),
        })
    };

    let session =
        auth.complete_oidc_with_verifier(request, device("oidc-provider"), &verifier).unwrap();
    assert_eq!(session.user_id, alice);
}

#[test]
fn auth_uses_provider_passkey_verifier() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    auth.set_account_state(alice.clone(), AccountAuthState::Active);
    let challenge = auth.start_passkey(alice.clone());
    let response = WebAuthnPasskeyResBody {
        credential_id: "credential-1".to_owned(),
        client_data_json: br#"{"type":"webauthn.get"}"#.to_vec(),
        authenticator_data: vec![1, 2, 3],
        signature: vec![4, 5, 6],
        user_handle: None,
    };
    let verifier = |request: &PasskeyVerificationReqBody| {
        assert_eq!(request.challenge.challenge, challenge.challenge);
        assert_eq!(request.origin, "https://app.example");
        assert_eq!(request.relying_party_id, "app.example");
        Ok(PasskeyVerification {
            verified: true,
            user_id: request.user_id.clone(),
            credential_id: request.response.credential_id.clone(),
        })
    };

    let session = auth
        .verify_passkey_with_verifier(
            &alice,
            response,
            "https://app.example",
            "app.example",
            device("passkey-provider"),
            &verifier,
        )
        .unwrap();
    assert_eq!(session.user_id, alice);
}

#[test]
fn auth_models_account_recovery_methods() {
    let mut auth = AuthManager::default();
    let verification_method = "did:web:alice.example#key-1";
    let request = auth
        .start_recovery(
            did("alice"),
            AccountRecoveryMethod::DidProof { verification_method: verification_method.to_owned() },
        )
        .unwrap();
    assert!(request.request_id.starts_with("recovery_"));
    assert!(request.completed_at.is_none());

    let completed = auth
        .complete_recovery(&request.request_id, &sha256_hex(verification_method.as_bytes()))
        .unwrap();
    assert!(completed.completed_at.is_some());
    assert!(auth.complete_recovery(&request.request_id, "wrong").is_err());
}

#[test]
fn auth_exports_safe_state_and_enforces_device_binding_and_account_state() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    assert_eq!(auth.account_state(&alice), AccountAuthState::Suspended);
    auth.register_password_user("alice", "secret", alice.clone()).unwrap();

    let session = auth.login_password("alice", "secret", device("desktop")).unwrap();
    auth.validate_session(&session.session_id, &session.access_token, &device("desktop")).unwrap();
    assert!(
        auth.validate_session(&session.session_id, &session.access_token, &device("phone"))
            .is_err()
    );

    let snapshot = auth.export_state();
    assert_eq!(snapshot.sessions.len(), 1);
    assert!(!serde_json::to_string(&snapshot).unwrap().contains(&session.refresh_token));

    let mut restored = AuthManager::default();
    restored.import_state(snapshot).unwrap();
    restored
        .validate_session(&session.session_id, &session.access_token, &device("desktop"))
        .unwrap();
    restored.set_account_state(alice, AccountAuthState::Locked);
    assert!(restored.refresh_session(&session.session_id, &session.refresh_token).is_err());
}

#[test]
fn session_grant_contract_redacts_and_notifies_principal_servers() {
    let now = Utc::now();
    let payload = SessionGrantPayload {
        issuer: did("coauth"),
        subject: did("alice"),
        principal_id: did("alice"),
        device_id: device("desktop"),
        audience: vec!["did:web:soland.example".to_owned()],
        scopes: vec!["urn:contrix:principal-server:session.bind".to_owned()],
        session_id: "browser-session-1".to_owned(),
        grant_jti: "grant-1".to_owned(),
        issued_at: now,
        expires_at: now + Duration::minutes(10),
        revocation_ref: "https://coauth.example/api/admin/v1/session-grants/grant-1".to_owned(),
        session_public_key: Some("session-public-key".to_owned()),
    };
    payload.validate().unwrap();
    let binding = payload.principal_binding();
    assert_eq!(binding.device_id, device("desktop"));

    let signer = |payload: &SessionGrantPayload| {
        payload.validate()?;
        Ok(format!("signed.{}.jwt", payload.grant_jti))
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
        Ok(PrincipalSessionGrantNotificationResBody {
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
    let policy =
        SessionGrantRetryPolicy { initial_backoff_ms: 10, max_backoff_ms: 100, max_attempts: 2 };
    let mut entry = outbox.entries().next().unwrap().clone();
    entry.record_failure("temporary", now, policy);
    assert_eq!(entry.state, SessionGrantOutboxState::Failed);
    entry.record_failure("still failing", now, policy);
    assert_eq!(entry.state, SessionGrantOutboxState::DeadLettered);
}

#[test]
fn device_scope_helpers_accept_only_contrix_scope() {
    let device = device("phone");
    let scope = contrix_device_scope(&device);
    assert_eq!(device_id_from_scope_token(&scope).unwrap(), device);
    assert_eq!(primary_device_id_from_scopes(["openid", scope.as_str()]).unwrap(), device);

    assert!(device_id_from_scope_token("urn:matrix:client:device:dev_phone").is_none());
}

#[test]
fn auth_validates_progressive_disclosure_claims_fail_closed() {
    let alice = did("alice");
    let issuer = did("issuer");
    let org = did("org");
    let guardian = did("guardian");
    let controller = did("controller");
    let request = PresentationReqBody {
        request_id: "presentation-1".to_owned(),
        subject: alice.clone(),
        audience: "contrix-auth".to_owned(),
        nonce: "nonce".to_owned(),
        policy: DisclosurePolicy {
            policy_id: "policy-1".to_owned(),
            requirements: vec![
                ClaimDisclosureRequirement {
                    claim_type: AuthClaimType::VerifiedHandle.as_str().to_owned(),
                    trusted_issuers: vec![issuer.clone()],
                    reveal_fields: vec!["handle".to_owned()],
                    required: true,
                },
                ClaimDisclosureRequirement {
                    claim_type: AuthClaimType::OrganizationMembership.as_str().to_owned(),
                    trusted_issuers: vec![issuer.clone()],
                    reveal_fields: vec!["organization".to_owned()],
                    required: true,
                },
                ClaimDisclosureRequirement {
                    claim_type: AuthClaimType::GuardianController.as_str().to_owned(),
                    trusted_issuers: vec![issuer.clone()],
                    reveal_fields: vec!["guardian".to_owned(), "controller".to_owned()],
                    required: true,
                },
            ],
            max_age: Some(Duration::days(1)),
            fail_closed: true,
        },
        created_at: Utc::now(),
        verifier_did: None,
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
        org,
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
        &[handle.clone(), membership, guardian_controller],
        &BTreeSet::new(),
        Utc::now(),
    );
    assert!(accepted.accepted);
    assert_eq!(accepted.disclosed_claims[0].value, serde_json::json!({"handle": "alice"}));
    assert_eq!(
        accepted.disclosed_claims[1].value,
        serde_json::json!({"organization": "did:web:org.example"})
    );
    assert_eq!(
        accepted.disclosed_claims[2].value,
        serde_json::json!({
            "guardian": guardian,
            "controller": controller
        })
    );
    let boundary = DisclosureProofAdapterBoundary {
        format: DisclosureProofFormat::SdJwt,
        holder: alice,
        issuer,
        audience: request.audience.clone(),
        nonce: request.nonce.clone(),
        domain: Some("contrix-auth".to_owned()),
        encoded_presentation: "compact.sd-jwt".to_owned(),
    };
    boundary.validate_request_binding(&request, Some("contrix-auth")).unwrap();
    let mut wrong_audience = boundary;
    wrong_audience.audience = "other-audience".to_owned();
    assert!(wrong_audience.validate_request_binding(&request, Some("contrix-auth")).is_err());

    let rejected = validate_presentation(
        &request,
        &[handle],
        &BTreeSet::from(["claim-handle".to_owned()]),
        Utc::now(),
    );
    assert!(!rejected.accepted);
    assert!(rejected.rejected_claims.iter().any(|claim| claim.reason == "claim is revoked"));
}

#[test]
fn auth_uses_provider_did_proof_verifier_for_recovery() {
    let alice = did("alice");
    let verification_method = "did:web:alice.example#key-1";
    let mut auth = AuthManager::default();
    let request = auth
        .start_recovery(
            alice.clone(),
            AccountRecoveryMethod::DidProof { verification_method: verification_method.to_owned() },
        )
        .unwrap();
    let document = DidDocument::new(alice.clone(), verification_method, "public-key");
    let proof = Proof {
        kind: "did-proof".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: verification_method.to_owned(),
        payload_hash: crate::Hash::new(format!("sha256:{}", sha256_hex(b"payload"))).unwrap(),
        created_at: Utc::now(),
        domain: Some("contrix-auth".to_owned()),
        audience: None,
        jws: "signed-proof".to_owned(),
    };
    let verifier = |request: &DidProofVerificationReqBody| {
        assert_eq!(request.subject, alice);
        assert_eq!(request.public_key, "public-key");
        assert_eq!(request.proof.jws, "signed-proof");
        Ok(DidProofVerification {
            verified: true,
            subject: request.subject.clone(),
            verification_method: request.verification_method.clone(),
        })
    };

    let completed = auth
        .complete_recovery_with_did_verifier(&request.request_id, document, proof, &verifier)
        .unwrap();
    assert!(completed.completed_at.is_some());
}

#[test]
fn auth_redacts_secrets_in_debug_output() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    let user = auth.register_password_user("alice", "secret", alice.clone()).unwrap();
    let session = auth.login_password("alice", "secret", device("desktop")).unwrap();
    let challenge = auth.issue_mfa(alice);

    assert!(!format!("{user:?}").contains(&user.password_hash));
    assert!(!format!("{session:?}").contains(&session.access_token));
    assert!(!format!("{session:?}").contains(&session.refresh_token));
    assert!(!format!("{challenge:?}").contains(&challenge.code));
}

#[test]
fn auth_rate_limit_hook_can_deny_login() {
    let alice = did("alice");
    let mut auth = AuthManager::default().with_rate_limit_hook(deny_password_login);
    auth.register_password_user("alice", "secret", alice).unwrap();

    let err = auth.login_password("alice", "secret", device("desktop")).unwrap_err();
    assert!(err.to_string().contains("rate limited"));
}
