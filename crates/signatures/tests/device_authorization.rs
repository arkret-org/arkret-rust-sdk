#![cfg(feature = "collaboration")]

use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_signatures::{
    verify_device_authorize_possession, verify_realm_device_authorize_possession,
};
use arkret_wire::{AccountId, ActorId, DidCoreId, RealmActorId};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

#[test]
fn device_possession_canonical_milliseconds_verify_after_wire_roundtrip() {
    let key = SigningKey::from_bytes(&[141; 32]);
    let account = AccountId::new(
        DidCoreId::new("ak:did_core:webvh:z6mkcontroller").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkstation").unwrap(),
    );
    let scopes =
        arkret_schema_conformance::spec_json_artifact("fixtures/applet-device-scope-fixture.json")
            .unwrap();
    let realm = serde_json::from_value(scopes["cases"][0]["scope"]["realm_id"].clone()).unwrap();
    let actor = ActorId::realm(RealmActorId::new(realm, account.principal_id.clone()));
    for branch in [
        "registration_anchor",
        "pcr_recovery",
        "realm_managed_delegation",
    ] {
        for expiry in ["2026-09-17T00:00:00.000Z", "2026-09-17T00:00:00.123Z"] {
            let mut value = json!({
                "device_id":"ak:device:01964137-0000-7000-8000-000000000001",
                "device_public_key_did":format!("did:key:{}", arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())),
                "hpke_key":"z6LSdevicehpke", "algorithms":["Ed25519"], "device_key_algorithm":"Ed25519",
                "authorized_by":account.principal_id, "not_before":"2026-09-16T00:00:00.000Z", "expires_at":expiry,
                "authorization_binding_kind":branch, "authorized_generation_ref":1, "device_signature":"AA"
            });
            let managed = branch == "realm_managed_delegation";
            if managed {
                value["applet_id"] = json!("ak:applet:01964137-0000-7000-8000-000000000002");
                value["scopes"] = scopes["cases"][0]["scopes"].clone();
                value["expected_control_revision"] = json!({"commit_id":arkret_wire::RealmCommitId::from_digest([42;32]),"stream_position":0});
                value["expected_device_revision"] = Value::Null;
            } else if branch == "pcr_recovery" {
                value["authorized_generation_ref"] = json!(2);
                value["recovery_session_id"] =
                    json!("ak:recovery_session:01964137-0000-7000-8000-000000000003");
            }
            let mut payload: DeviceAuthorizePayload = serde_json::from_value(value).unwrap();
            if expiry.ends_with(".123Z") {
                payload.expires_at = Some(Some("2026-09-17T00:00:00.123456789Z".parse().unwrap()));
            }
            let input = if managed {
                payload
                    .realm_device_possession_signature_input(&actor)
                    .unwrap()
            } else {
                payload.device_possession_signature_input(&account).unwrap()
            };
            let body: Value =
                serde_json::from_slice(input.splitn(2, |byte| *byte == b'\n').nth(1).unwrap())
                    .unwrap();
            assert_eq!(body["not_before"], "2026-09-16T00:00:00.000Z");
            assert_eq!(body["expires_at"], expiry);
            payload.device_signature = serde_json::from_value(json!(
                arkret_canonical::base64url_encode(key.sign(&input).to_bytes())
            ))
            .unwrap();
            let wire = serde_json::to_value(payload).unwrap();
            assert_eq!(wire["not_before"], body["not_before"]);
            assert_eq!(wire["expires_at"], body["expires_at"]);
            let mut received: DeviceAuthorizePayload = serde_json::from_value(wire).unwrap();
            if managed {
                verify_realm_device_authorize_possession(&received, &actor).unwrap();
            } else {
                verify_device_authorize_possession(&received, &account).unwrap();
            }
            received.expires_at = Some(Some(
                received.expires_at.flatten().unwrap() + chrono::Duration::milliseconds(1),
            ));
            if managed {
                assert!(verify_realm_device_authorize_possession(&received, &actor).is_err());
            } else {
                assert!(verify_device_authorize_possession(&received, &account).is_err());
            }
        }
    }
}
