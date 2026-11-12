#![cfg(not(target_arch = "wasm32"))]
use arkret_http_client::{Client, Error};
use arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody;
use arkret_models_crypto::keys::KeysUploadRequestBody;
use arkret_wire::NonEmptyString;
use serde_json::json;
#[tokio::test]
async fn invalid_programmatic_scalars_are_rejected_before_network_io() {
    let client = Client::builder(url::Url::parse("http://127.0.0.1:1").unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap();
    let mut token:CallMediaTokenExchangeRequestBody=serde_json::from_value(json!({"realm_id":"ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir","call_id":"ak:call:AVxshP1cCAeTx94DZvt3ODhEjNR9Da4hbdzLBzwPU-T1","actor_id":arkret_wire::ActorId::account(arkret_wire::AccountId::new(arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap())),"device_id":"ak:device:01904100-0000-7000-8000-000000000008","focus_id":"valid","join_context":{"kind":"voluntary","created_at":"2026-11-12T00:00:00.000Z","expires_at":"2026-11-12T00:00:30.000Z","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","proof":{"verification_method":"did:web:alice.example#key","jws":"placeholder"}}})).unwrap();
    for literal in [String::new(), "ak:focus:invalid".into(), "🦀".repeat(65)] {
        token.focus_id = literal;
        assert!(matches!(
            client.media_token_exchange(&token).await,
            Err(Error::Wire(_))
        ));
    }
    for fallback in [false, true] {
        let mut upload:KeysUploadRequestBody=serde_json::from_value(json!({"device_id":"ak:device:01904100-0000-7000-8000-000000000008","device_signature":{"kid":"did:web:alice.example#key","signature":"c2ln"},"one_time_keys":{"algorithm":{"key":"YWJj","algorithm":"Ed25519","signature":{"kid":"did:web:alice.example#key","signature":"c2ln"},"key_id":"valid"}}})).unwrap();
        if fallback {
            upload.fallback_keys = std::mem::take(&mut upload.one_time_keys);
        }
        let map = if fallback {
            &mut upload.fallback_keys
        } else {
            &mut upload.one_time_keys
        };
        map.values_mut().next().unwrap().key_id = Some(NonEmptyString::new("ak:invalid").unwrap());
        assert!(matches!(
            client.keys_upload(&upload).await,
            Err(Error::Wire(_))
        ));
    }
}
