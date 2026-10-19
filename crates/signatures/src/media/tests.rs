use arkret_models_collaboration::objects::media::CallMediaParticipantBinding;
use ed25519_dalek::{Signer, SigningKey};

use super::*;

const ISSUER_KID: &str = "did:webvh:z6mkfixturemedia:media.example#media-token";

fn did(name: &str) -> Did {
    Did::new(format!("did:webvh:z6mkfixture{name}:{name}.example")).unwrap()
}

fn actor(name: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture{name}")).unwrap()
}

fn issuer_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// Anchor set carrying the issuer verifying key under [`ISSUER_KID`].
fn anchors_with_issuer_key(key: &SigningKey) -> MediaServiceAnchors {
    MediaServiceAnchors::new([(actor("media"), did("media"))])
        .unwrap()
        .with_keys([(ISSUER_KID.to_owned(), key.verifying_key())])
        .unwrap()
}

fn token_request() -> CallMediaTokenExchangeRequestBody {
    call_media_token_exchange(
        RealmId::new("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs").unwrap(),
        CallId::new("ak:call:AVxshP1cCAeTx94DZvt3ODhEjNR9Da4hbdzLBzwPU-T1").unwrap(),
        ActorId::service(actor("alice")),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
        "fra-1",
        arkret_models_collaboration::call_invitation::CallMediaJoinContext::Voluntary(
            arkret_models_collaboration::call_invitation::CallVoluntaryJoinContext {
                kind:
                    arkret_models_collaboration::call_invitation::CallVoluntaryJoinKind::Voluntary,
                created_at: arkret_canonical::canonical::normalize_timestamp_canonical(Utc::now()),
                expires_at: arkret_canonical::canonical::normalize_timestamp_canonical(
                    Utc::now() + chrono::Duration::seconds(30),
                ),
                nonce: arkret_canonical::base64url_encode([18u8; 32]),
                proof: arkret_models_collaboration::call_invitation::CallVoluntaryJoinProof {
                    verification_method: "did:webvh:z6mkfixturealice:alice.example#device"
                        .to_owned(),
                    jws: "test-unused-intent-proof".to_owned(),
                },
            },
        ),
    )
}

/// Build an unsigned outcome (placeholder signatures); callers sign it via
/// [`sign_outcome`] after any field tampering.
fn token_outcome(
    request: &CallMediaTokenExchangeRequestBody,
    expires_at: DateTime<Utc>,
) -> CallMediaTokenExchangeOutcome {
    let identity = "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000".to_owned();
    CallMediaTokenExchangeOutcome {
        realm_id: request.realm_id.clone(),
        call_id: request.call_id.clone(),
        actor_id: request.actor_id.clone(),
        device_id: request.device_id.clone(),
        focus_id: request.focus_id.clone(),
        backend_kind: MediaBackendKind::Livekit,
        connect_url: "wss://livekit-fra.example.com".to_owned(),
        backend_token: MediaBackendToken::Opaque("opaque-backend-token".to_owned()),
        participant_id: identity,
        participant_binding: CallMediaParticipantBinding {
            sig: String::new(),
            issuer_kid: arkret_wire::DidUrl::new(ISSUER_KID).unwrap(),
            expires_at,
        },
        expires_at,
        media: request.invitation_media(),
    }
}

/// Sign the participant binding over the spec signing_input with `key`,
/// mutating `outcome` in place. Call this AFTER any tampering so the
/// signature covers the (possibly tampered) authoritative fields.
fn sign_outcome(outcome: &mut CallMediaTokenExchangeOutcome, key: &SigningKey) {
    let input =
        participant_binding_signing_input(&ParticipantBindingContext::from_outcome(outcome))
            .unwrap();
    outcome.participant_binding.sig =
        arkret_canonical::base64url::base64url_encode(key.sign(&input).to_bytes());
}

/// A fully signed, verifiable outcome over the request and issuer key.
fn signed_outcome(
    request: &CallMediaTokenExchangeRequestBody,
    key: &SigningKey,
    expires_at: DateTime<Utc>,
) -> CallMediaTokenExchangeOutcome {
    let mut outcome = token_outcome(request, expires_at);
    sign_outcome(&mut outcome, key);
    outcome
}

#[test]
fn normative_current_bindings_verify_original_keys_and_reject_tuple_substitution() {
    use arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue;
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/call-current-fixture.json")
            .expect("pinned Call fixture must be available");
    let realm = serde_json::from_value(fixture["request_context"]["realm_id"].clone()).unwrap();
    let call = serde_json::from_value(fixture["request_context"]["call_id"].clone()).unwrap();
    for checkpoint in fixture["checkpoints"].as_array().unwrap() {
        for row in checkpoint["current_state_entries"].as_array().unwrap() {
            if row["selector"]["kind"] != "call_roster" {
                continue;
            }
            let roster: CallRosterCurrentValue =
                serde_json::from_value(row["value"].clone()).unwrap();
            verify_call_roster_bindings(&realm, &call, &roster).unwrap();
            if roster.entries.is_empty() {
                continue;
            }
            let original = serde_json::to_value(&roster).unwrap();
            for (pointer, value) in [
                (
                    "/entries/0/participant_signing_key/public_key_b64u",
                    serde_json::json!(arkret_canonical::base64url_encode([42; 32])),
                ),
                (
                    "/entries/0/value/participant/actor_id/account_id/station_id",
                    serde_json::json!("ak:did_core:web:other.example"),
                ),
                (
                    "/entries/0/value/participant/device_id",
                    serde_json::json!("ak:device:01964137-0000-7000-8000-000000000099"),
                ),
                (
                    "/entries/0/value/participant/participant_id",
                    serde_json::json!("ak:rtc_participant:01964137-0000-7000-8000-000000000099"),
                ),
                (
                    "/entries/0/value/participant/focus_id",
                    serde_json::json!("wrong-focus"),
                ),
                (
                    "/entries/0/value/participant/media/screen",
                    serde_json::json!(true),
                ),
                (
                    "/entries/0/value/participant/participant_binding/expires_at",
                    serde_json::json!("2026-09-20T01:00:00.000Z"),
                ),
                (
                    "/entries/0/value/participant/participant_binding/issuer_kid",
                    serde_json::json!("did:web:media.example#wrong"),
                ),
            ] {
                let mut changed = original.clone();
                *changed.pointer_mut(pointer).unwrap() = value;
                let roster = serde_json::from_value(changed).unwrap();
                assert!(
                    verify_call_roster_bindings(&realm, &call, &roster).is_err(),
                    "{pointer}"
                );
            }
            let wrong_call = CallId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [99; 32],
            ));
            assert!(verify_call_roster_bindings(&realm, &wrong_call, &roster).is_err());
        }
    }
}

#[test]
fn media_token_outcome_roundtrips_and_verifies() {
    let request = token_request();
    let key = issuer_key();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::minutes(5);
    let outcome = signed_outcome(&request, &key, expires_at);

    // Wire roundtrip: request + outcome survive a JSON round-trip.
    let request_json = serde_json::to_string(&request).unwrap();
    let request_back: CallMediaTokenExchangeRequestBody =
        serde_json::from_str(&request_json).unwrap();
    assert_eq!(request_back.focus_id, "fra-1");
    let outcome_json = serde_json::to_string(&outcome).unwrap();
    let outcome_back: CallMediaTokenExchangeOutcome = serde_json::from_str(&outcome_json).unwrap();
    assert_eq!(outcome_back.participant_id, outcome.participant_id);

    let anchors = anchors_with_issuer_key(&key);
    let verified = verify_call_media_token_outcome(&request, &outcome, &anchors, now).unwrap();
    assert_eq!(verified.issuer_did, did("media"));
    assert_eq!(verified.participant_id, outcome.participant_id);

    // Anchor: the signing input is label-prefixed (`media-service-binding.md`
    // §3). coland's cross-implementation lock asserts byte equality against
    // this same function.
    let signing_input =
        participant_binding_signing_input(&ParticipantBindingContext::from_outcome(&outcome))
            .unwrap();
    assert!(signing_input.starts_with(b"ak.media.participant_binding.v1\x00"));
}

#[test]
fn media_token_outcome_rejects_backend_shape_mismatch() {
    let request = token_request();
    let key = issuer_key();
    let now = Utc::now();
    let outcome = signed_outcome(&request, &key, now + chrono::Duration::minutes(5));
    let mut wire = serde_json::to_value(outcome).unwrap();

    wire["backend_kind"] = serde_json::json!("arkret_native");
    assert!(serde_json::from_value::<CallMediaTokenExchangeOutcome>(wire.clone()).is_err());

    wire["backend_token"] = serde_json::json!({
        "kid": ISSUER_KID,
        "payload": {
            "call_id": request.call_id,
            "focus_id": request.focus_id,
            "participant_id": "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000",
            "issued_at": "2026-08-16T00:00:00.000Z",
            "expires_at": "2026-08-16T00:05:00.000Z",
            "media": {"audio": true, "video": true, "screen": false}
        },
        "sig": "AA",
        "signature_algorithm": "Ed25519"
    });
    assert!(serde_json::from_value::<CallMediaTokenExchangeOutcome>(wire).is_ok());
}

#[test]
fn media_token_rejects_unanchored_issuer() {
    let request = token_request();
    let key = issuer_key();
    let now = Utc::now();
    let outcome = signed_outcome(&request, &key, now + chrono::Duration::minutes(5));

    // Issuer DID not in the anchor set.
    let anchors = MediaServiceAnchors::new([(actor("other"), did("other"))]).unwrap();
    assert!(
        anchors
            .clone()
            .with_keys([(ISSUER_KID.to_owned(), key.verifying_key())])
            .is_err()
    );
    let err = verify_call_media_token_outcome(&request, &outcome, &anchors, now).unwrap_err();
    assert!(err.to_string().contains("token_issuer_unauthorised"));

    // Empty anchor set is fail-closed.
    let empty = MediaServiceAnchors::default();
    assert!(verify_call_media_token_outcome(&request, &outcome, &empty, now).is_err());
}

#[test]
fn media_token_verifies_signatures_and_rejects_tampering() {
    let request = token_request();
    let key = issuer_key();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::minutes(5);
    let anchors = anchors_with_issuer_key(&key);

    // A correctly signed outcome verifies.
    let good = signed_outcome(&request, &key, expires_at);
    assert!(verify_call_media_token_outcome(&request, &good, &anchors, now).is_ok());

    // Anchor DID present but no verifying key registered → fail closed.
    let keyless = MediaServiceAnchors::new([(actor("media"), did("media"))]).unwrap();
    let err = verify_call_media_token_outcome(&request, &good, &keyless, now).unwrap_err();
    assert!(err.to_string().contains("token_issuer_unauthorised"));

    // A different issuer key produces a signature that does not verify.
    let other = SigningKey::from_bytes(&[22u8; 32]);
    let wrong_key = signed_outcome(&request, &other, expires_at);
    let err = verify_call_media_token_outcome(&request, &wrong_key, &anchors, now).unwrap_err();
    assert!(err.to_string().contains("token_issuer_unauthorised"));

    // Tamper each of the nine authoritative fields AFTER signing → the
    // recomputed signing_input no longer matches the signature.
    // participant_id has one carrier; changing it invalidates the signature.
    let mut t_identity = signed_outcome(&request, &key, expires_at);

    t_identity.participant_id = "ak:rtc_participant:tampered".to_owned();
    assert!(
        verify_call_media_token_outcome(&request, &t_identity, &anchors, now)
            .unwrap_err()
            .to_string()
            .contains("token_issuer_unauthorised")
    );

    // expires_at: re-sign would change it; here we move it within TTL but
    // do NOT re-sign, so the signature over the old expires_at fails.
    let mut t_expiry = signed_outcome(&request, &key, expires_at);
    t_expiry.participant_binding.expires_at = expires_at - chrono::Duration::seconds(30);
    t_expiry.expires_at = t_expiry.participant_binding.expires_at;
    assert!(
        verify_call_media_token_outcome(&request, &t_expiry, &anchors, now)
            .unwrap_err()
            .to_string()
            .contains("token_issuer_unauthorised")
    );

    // A binding signed by a non-anchored key fails as token_issuer_unauthorised.
    let mut t_sig = signed_outcome(&request, &key, expires_at);
    t_sig.participant_binding.sig = signed_outcome(&request, &other, expires_at)
        .participant_binding
        .sig;
    let err = verify_call_media_token_outcome(&request, &t_sig, &anchors, now).unwrap_err();
    assert!(err.to_string().contains("token_issuer_unauthorised"));
    assert!(err.to_string().contains("participant_binding"));
}

#[test]
fn media_token_rejects_ttl_over_ceiling_and_tuple_mismatch() {
    let request = token_request();
    let key = issuer_key();
    let now = Utc::now();
    let anchors = anchors_with_issuer_key(&key);

    // TTL over 600s ceiling.
    let long = signed_outcome(&request, &key, now + chrono::Duration::minutes(20));
    assert!(verify_call_media_token_outcome(&request, &long, &anchors, now).is_err());

    // Focus mismatch in the binding tuple (re-signed so the failure is the
    // structural tuple check, not the signature).
    let mut tampered = token_outcome(&request, now + chrono::Duration::minutes(5));
    tampered.focus_id = "fra-2".to_owned();
    sign_outcome(&mut tampered, &key);
    let err = verify_call_media_token_outcome(&request, &tampered, &anchors, now).unwrap_err();
    assert!(err.to_string().contains("participant_binding_invalid"));

    // Tampering the sole participant_id carrier invalidates the signature.
    let mut id_mismatch = signed_outcome(&request, &key, now + chrono::Duration::minutes(5));
    id_mismatch.participant_id = "ak:rtc_participant:elsewhere".to_owned();
    assert!(verify_call_media_token_outcome(&request, &id_mismatch, &anchors, now).is_err());
}
#[test]
fn complete_account_device_and_media_are_directly_signed() {
    let mut request = token_request();
    request.actor_id = ActorId::account(arkret_wire::AccountId::new(
        actor("alice"),
        actor("station_a"),
    ));
    let key = issuer_key();
    let now = Utc::now();
    let anchors = anchors_with_issuer_key(&key);
    let accepted = signed_outcome(&request, &key, now + chrono::Duration::minutes(5));
    verify_call_media_token_outcome(&request, &accepted, &anchors, now).unwrap();
    let mut wrong_request = request.clone();
    wrong_request.actor_id = ActorId::account(arkret_wire::AccountId::new(
        actor("alice"),
        actor("station_b"),
    ));
    let mut changed = accepted.clone();
    changed.actor_id = wrong_request.actor_id.clone();
    assert!(verify_call_media_token_outcome(&wrong_request, &changed, &anchors, now).is_err());
    let mut media = accepted.clone();
    media.media.screen = true;
    assert!(verify_call_media_token_outcome(&request, &media, &anchors, now).is_err());
    let mut device = accepted;
    device.device_id = DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000a").unwrap();
    wrong_request = request;
    wrong_request.device_id = device.device_id.clone();
    assert!(verify_call_media_token_outcome(&wrong_request, &device, &anchors, now).is_err());
}

#[test]
fn compact_binding_rejects_retired_fields_and_preserves_exact_account() {
    let mut request = token_request();
    request.actor_id = ActorId::account(arkret_wire::AccountId::new(
        actor("alice"),
        actor("station_a"),
    ));
    let key = issuer_key();
    let now = Utc::now();
    let outcome = signed_outcome(&request, &key, now + chrono::Duration::minutes(5));
    let anchors = anchors_with_issuer_key(&key);
    verify_call_media_token_outcome(&request, &outcome, &anchors, now).unwrap();
    let compact = serde_json::to_value(&outcome.participant_binding).unwrap();
    assert_eq!(compact.as_object().unwrap().len(), 3);
    assert!(compact.get("subject_binding_digest").is_none());
    for field in [
        "subject_binding_digest",
        "scheme",
        "issued_at",
        "realm_id",
        "call_id",
        "focus_id",
        "actor_id",
        "device_id",
        "participant_id",
    ] {
        let mut old = compact.clone();
        old[field] = serde_json::json!("retired");
        assert!(serde_json::from_value::<CallMediaParticipantBinding>(old).is_err());
    }
    request.actor_id = ActorId::account(arkret_wire::AccountId::new(
        actor("alice"),
        actor("station_b"),
    ));
    assert!(verify_call_media_token_outcome(&request, &outcome, &anchors, now).is_err());
}

#[test]
fn token_ttl_ceiling_does_not_round_down_fractional_seconds() {
    let now = Utc::now();
    assert!(validate_token_ttl(now, now + chrono::Duration::milliseconds(600001)).is_err());
    assert!(validate_token_ttl(now, now + chrono::Duration::milliseconds(1)).is_ok());
}
