//! Signed ICE protocol material; no TURN allocation or live service admission.

use anyhow::Result;
use arkret_models_collaboration::objects::media::{
    MediaIceConfigOutcome, MediaIceConfigRequestBody, MediaIceConfigSignature, MediaIceServer,
    MediaIceSignatureAlgorithm,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer as _;

use crate::service_identity::ServiceIdentityFixture;

/// Structural signing material only: the fixed public TURN tag and placeholder
/// credential provide no privacy, live issuance, allocation or admission evidence.
pub fn signed_config(
    request: &MediaIceConfigRequestBody,
    authority: &ServiceIdentityFixture,
    issued_at: DateTime<Utc>,
) -> Result<MediaIceConfigOutcome> {
    let mut outcome = MediaIceConfigOutcome {
        realm_id: request.realm_id.clone(),
        call_id: request.call_id.clone(),
        actor_id: request.actor_id.clone(),
        device_id: request.device_id.clone(),
        ice_servers: vec![
            MediaIceServer {
                urls: vec!["stun:stun.server.local:3478".into()],
                username: None,
                credential: None,
                credential_type: None,
            },
            MediaIceServer {
                urls: vec!["turn:turn.server.local:3478?transport=udp".into()],
                username: Some(format!(
                    "{}:{}",
                    issued_at.timestamp() + 600,
                    "fixture_only_not_private"
                )),
                credential: Some("fixture-turn-credential".into()),
                credential_type: None,
            },
        ],
        ttl_seconds: 600,
        refresh_lead_seconds: 150,
        issued_at,
        turn_required: false,
        constraints: None,
        next_retry_at: None,
        signature: MediaIceConfigSignature {
            kid: authority.verification_method.to_string(),
            signature_algorithm: MediaIceSignatureAlgorithm::Ed25519,
            sig: String::new(),
        },
        extensions: Default::default(),
    };
    outcome.signature.sig = arkret_canonical::base64url_encode(
        authority
            .signing_key
            .sign(&outcome.signature_input()?)
            .to_bytes(),
    );
    let anchors = arkret_signatures::media::MediaServiceAnchors::new([(
        authority.service_id.clone(),
        authority.history.did.clone(),
    )])?
    .with_keys([(
        authority.verification_method.to_string(),
        authority.signing_key.verifying_key(),
    )])?;
    arkret_signatures::media::verify_ice_config_outcome(&outcome, &anchors)?;
    Ok(outcome)
}
