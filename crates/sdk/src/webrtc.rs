//! Fail-closed verification for media-service ICE configuration.

use arkret_canonical::base64url::base64url_decode;
use arkret_models_collaboration::objects::media::{
    MediaIceConfigOutcome, MediaIceServer, MediaIceSignatureAlgorithm, MediaIceSignatureInput,
};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::media::MediaServiceAnchors;
use crate::{Did, Error, RealmId, Result};

/// Strongly-typed ICE configuration parsed from a verified
/// [`MediaIceConfigOutcome`] (`webrtc-signaling.md` §4 / §4.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceConfig {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    /// STUN / TURN servers offered for this call leg.
    pub ice_servers: Vec<MediaIceServer>,
    /// Credential lifetime in seconds.
    pub ttl_seconds: u32,
    /// Refresh lead — clients SHOULD re-fetch once remaining ≤ this (always
    /// `< ttl_seconds` per §4.1).
    pub refresh_lead_seconds: u32,
    /// `true` when the caller MUST relay through TURN (no host/srflx).
    pub force_turn: bool,
    /// The media-service DID that signed the config (from `signature.kid`).
    pub issuer_did: Did,
}

impl IceConfig {
    /// TURN servers only.
    pub fn turn_servers(&self) -> impl Iterator<Item = &MediaIceServer> {
        self.ice_servers.iter().filter(|server| server.is_turn())
    }

    /// STUN servers only.
    pub fn stun_servers(&self) -> impl Iterator<Item = &MediaIceServer> {
        self.ice_servers.iter().filter(|server| server.is_stun())
    }
}

fn validate_ice_server_credential_privacy(server: &MediaIceServer) -> Result<()> {
    const FORBIDDEN_PREFIXES: &[&str] = &[
        "did:web:",
        "did:plc:",
        "did:key:",
        "did:webvh:",
        "did:webs:",
        "did:keri:",
    ];
    for value in [&server.username, &server.credential].into_iter().flatten() {
        if FORBIDDEN_PREFIXES
            .iter()
            .any(|prefix| value.contains(prefix))
        {
            return Err(Error::Protocol(
                "ICE server credential leaks a DID; use a Realm-scoped pairwise pseudonym"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn ice_config_canonical_payload(outcome: &MediaIceConfigOutcome) -> Result<Vec<u8>> {
    outcome.canonical_signature_payload().map_err(|err| {
        Error::Protocol(format!("ice_config_denied: canonicalization failed: {err}"))
    })
}

fn ice_config_signing_input(outcome: &MediaIceConfigOutcome) -> Result<Vec<u8>> {
    outcome.signature_input().map_err(|err| {
        Error::Protocol(format!(
            "ice_config_denied: transcript construction failed: {err}"
        ))
    })
}

fn verify_ice_config_signature(
    outcome: &MediaIceConfigOutcome,
    anchors: &MediaServiceAnchors,
    kid: &str,
) -> Result<()> {
    if outcome.signature.alg != MediaIceSignatureAlgorithm::EdDsa {
        return Err(Error::Protocol(
            "ice_config_denied: unsupported signature algorithm".to_owned(),
        ));
    }
    if outcome.signature.signature_input != MediaIceSignatureInput::IceConfigV1 {
        return Err(Error::Protocol(
            "ice_config_denied: unsupported signature input".to_owned(),
        ));
    }
    let canonical = ice_config_canonical_payload(outcome)?;
    let expected_digest = crate::Hash::new(arkret_canonical::sha256_digest(&canonical))?;
    if outcome.signature.payload_digest != expected_digest {
        return Err(Error::Protocol(
            "ice_config_denied: payload digest mismatch".to_owned(),
        ));
    }
    let sig_b64 = &outcome.signature.sig;
    let key = anchors.verifying_key(kid).ok_or_else(|| {
        Error::Protocol(format!(
            "ice_config_denied: no verifying key registered for ICE config kid {kid}"
        ))
    })?;
    let sig_bytes = base64url_decode(sig_b64).map_err(|err| {
        Error::Protocol(format!(
            "ice_config_denied: signature.sig is not base64url: {err}"
        ))
    })?;
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::Protocol(format!(
            "ice_config_denied: signature.sig must be 64 bytes, got {}",
            sig_bytes.len()
        ))
    })?;
    let signature = Signature::from_bytes(&sig_array);
    let signing_input = ice_config_signing_input(outcome)?;
    if key.verify_strict(&signing_input, &signature).is_ok() {
        return Ok(());
    }
    Err(Error::Protocol(
        "ice_config_denied: signature.sig verification failed".to_owned(),
    ))
}

/// Verify an ICE config response and project it into a strongly-typed
/// [`IceConfig`] (`webrtc-signaling.md` §4 client rules).
///
/// Checks (fail closed):
/// - the top-level `signature.kid` resolves to an anchored media-service DID;
/// - `refresh_lead_seconds < ttl_seconds` and `ttl_seconds > 0`;
/// - `signature.sig` verifies as EdDSA(ed25519) over the canonical transcript;
/// - every TURN credential passes the pairwise-pseudonym privacy guard.
pub fn verify_ice_config_outcome(
    outcome: &MediaIceConfigOutcome,
    anchors: &MediaServiceAnchors,
) -> Result<IceConfig> {
    let kid = outcome.signature.kid.clone();
    if kid.is_empty() {
        return Err(Error::Protocol(
            "ice_config_denied: signature missing kid".to_owned(),
        ));
    }
    let issuer_did = kid.split('#').next().unwrap_or(&kid).to_owned();
    if anchors.is_empty() || !anchors.contains(&issuer_did) {
        return Err(Error::Protocol(format!(
            "ice_config_denied: signature issuer {issuer_did} not in realm media_service anchors"
        )));
    }
    if outcome.ttl_seconds == 0 || outcome.refresh_lead_seconds >= outcome.ttl_seconds {
        return Err(Error::Protocol(
            "ice_config_denied: refresh_lead_seconds must be below a positive ttl_seconds"
                .to_owned(),
        ));
    }
    verify_ice_config_signature(outcome, anchors, &kid)?;

    if outcome.bucket_seconds == 0 {
        return Err(Error::Protocol(
            "ice_config_denied: bucket_seconds must be positive".to_owned(),
        ));
    }
    let bucket = i64::from(outcome.bucket_seconds);
    let expected_bucket_secs = outcome.issued_at.timestamp().div_euclid(bucket) * bucket;
    if outcome.issued_at_bucket.timestamp() != expected_bucket_secs
        || outcome.issued_at_bucket.timestamp_subsec_nanos() != 0
    {
        return Err(Error::Protocol(
            "ice_config_denied: issued_at_bucket must equal floor(issued_at / bucket_seconds)"
                .to_owned(),
        ));
    }

    for server in &outcome.ice_servers {
        if server.urls.is_empty() {
            return Err(Error::Protocol(
                "ice_config_denied: ice server entry has no urls".to_owned(),
            ));
        }
        validate_ice_server_credential_privacy(server)?;
    }

    Ok(IceConfig {
        realm_id: outcome.realm_id.clone(),
        call_id: outcome.call_id.clone(),
        actor_id: outcome.actor_id.clone(),
        ice_servers: outcome.ice_servers.clone(),
        ttl_seconds: outcome.ttl_seconds,
        refresh_lead_seconds: outcome.refresh_lead_seconds,
        force_turn: outcome.force_turn,
        issuer_did: Did::new(issuer_did)?,
    })
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::objects::media::{
        MediaIceConfigSignature, MediaIceSignatureAlgorithm, MediaIceSignatureInput,
    };
    use arkret_wire::XExtensionMap;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap()
    }

    const MEDIA_KID: &str = "did:webvh:z6mkfixture:media.example#notary-key";

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn anchors_with_issuer_key(key: &SigningKey) -> MediaServiceAnchors {
        MediaServiceAnchors::new([did("media")])
            .with_keys([(MEDIA_KID.to_owned(), key.verifying_key())])
    }

    fn sign_ice_outcome(
        mut outcome: MediaIceConfigOutcome,
        kid: &str,
        key: &SigningKey,
    ) -> MediaIceConfigOutcome {
        let canonical = ice_config_canonical_payload(&outcome).unwrap();
        let signing_input = ice_config_signing_input(&outcome).unwrap();
        outcome.signature = MediaIceConfigSignature {
            kid: kid.to_owned(),
            alg: MediaIceSignatureAlgorithm::EdDsa,
            signature_input: MediaIceSignatureInput::IceConfigV1,
            payload_digest: crate::Hash::new(arkret_canonical::sha256_digest(&canonical)).unwrap(),
            sig: arkret_canonical::base64url_encode(key.sign(&signing_input).to_bytes()),
        };
        outcome
    }

    fn signed_ice_outcome(kid: &str, key: &SigningKey) -> MediaIceConfigOutcome {
        sign_ice_outcome(ice_outcome(kid), kid, key)
    }

    fn ice_outcome(kid: &str) -> MediaIceConfigOutcome {
        MediaIceConfigOutcome {
            realm_id: realm(),
            call_id: "ak:call:0196441c-0000-7000-8000-000000000000".to_owned(),
            actor_id: did("alice"),
            device_id: crate::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005")
                .unwrap(),
            ice_servers: vec![
                MediaIceServer {
                    urls: vec!["stun:stun.example.com".to_owned()],
                    username: None,
                    credential: None,
                    credential_type: None,
                },
                MediaIceServer {
                    urls: vec!["turn:turn.example.com".to_owned()],
                    username: Some("1718000000:rand".to_owned()),
                    credential: Some("secret".to_owned()),
                    credential_type: None,
                },
            ],
            ttl_seconds: 300,
            refresh_lead_seconds: 60,
            issued_at: "2026-05-27T12:29:56.000Z".parse().unwrap(),
            issued_at_bucket: "2026-05-27T12:25:00.000Z".parse().unwrap(),
            bucket_seconds: 300,
            expires_at: None,
            force_turn: false,
            constraints: None,
            next_retry_at: None,
            signature: MediaIceConfigSignature {
                kid: kid.to_owned(),
                alg: MediaIceSignatureAlgorithm::EdDsa,
                signature_input: MediaIceSignatureInput::IceConfigV1,
                payload_digest: crate::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                sig: "AAAA".to_owned(),
            },
            extensions: XExtensionMap::default(),
        }
    }

    #[test]
    fn ice_config_verifies_parses_and_classifies_servers() {
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let outcome = signed_ice_outcome(MEDIA_KID, &key);
        let config = verify_ice_config_outcome(&outcome, &anchors).unwrap();
        assert_eq!(config.issuer_did, did("media"));
        assert_eq!(config.ttl_seconds, 300);
        assert_eq!(config.stun_servers().count(), 1);
        assert_eq!(config.turn_servers().count(), 1);
        assert!(!config.force_turn);
    }

    #[test]
    fn ice_config_rejects_unanchored_issuer_and_bad_ttl() {
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let stranger = signed_ice_outcome("did:webvh:z6mkfixture:evil.example#notary-key", &key);
        let err = verify_ice_config_outcome(&stranger, &anchors).unwrap_err();
        assert!(err.to_string().contains("ice_config_denied"));

        let mut bad_ttl = signed_ice_outcome(MEDIA_KID, &key);
        bad_ttl.refresh_lead_seconds = bad_ttl.ttl_seconds;
        assert!(verify_ice_config_outcome(&bad_ttl, &anchors).is_err());

        let mut bad_digest = signed_ice_outcome(MEDIA_KID, &key);
        bad_digest.signature.payload_digest =
            crate::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        assert!(verify_ice_config_outcome(&bad_digest, &anchors).is_err());
    }

    #[test]
    fn ice_config_rejects_turn_credential_leaking_did() {
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let mut leaky = ice_outcome(MEDIA_KID);
        leaky.ice_servers[1].username = Some("did:webvh:z6mkfixture:alice.example".to_owned());
        let leaky = sign_ice_outcome(leaky, MEDIA_KID, &key);
        assert!(verify_ice_config_outcome(&leaky, &anchors).is_err());
    }

    #[test]
    fn ice_config_rejects_missing_or_bad_signature() {
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);

        let mut missing_sig = ice_outcome(MEDIA_KID);
        missing_sig.signature.sig.clear();
        assert!(verify_ice_config_outcome(&missing_sig, &anchors).is_err());

        let mut tampered = signed_ice_outcome(MEDIA_KID, &key);
        tampered.ttl_seconds += 1;
        assert!(verify_ice_config_outcome(&tampered, &anchors).is_err());

        let no_key = MediaServiceAnchors::new([did("media")]);
        let signed = signed_ice_outcome(MEDIA_KID, &key);
        assert!(verify_ice_config_outcome(&signed, &no_key).is_err());
    }
}
