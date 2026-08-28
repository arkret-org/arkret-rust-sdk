//! `challenge_dpop_session_v1` proof for `ak.profile.binding.websocket.v1`
//! (`zh/sync/websocket-binding.md` §3.1).
//!
//! The proof reuses RFC 9449's JOSE shape, `ath`, `nonce` and holder-key rules,
//! but it travels in an Arkret `authenticate` application frame, so its
//! `htm` is [`WEBSOCKET_AUTH_METHOD_TOKEN`] and its `htu` is a `wss` URI. The
//! generic HTTP DPoP verifier in [`crate::dpop`] MUST NOT accept either — it
//! canonicalises `htu` through a `http`/`https`-only gate, which is exactly
//! what keeps the two contexts separate. This module is the only entry point
//! that accepts the application context, and it never relaxes the HTTP one.
//!
//! `connection_id` and the socket `Origin` deliberately do **not** appear as
//! private claims: they are bound indirectly through the server-side
//! [`WebSocketChallengeRecord`] the service wrote before sending `challenge`.

use arkret_wire::websocket_binding::{
    WEBSOCKET_AUTH_METHOD_TOKEN, WebSocketChallengeRecord, WebSocketDpopClaims, WebSocketDpopProof,
    WebSocketDpopProtectedHeader, WebSocketDpopPublicJwk, WebSocketReplayLedgerKey,
    canonical_http_origin, validate_websocket_base_url, validate_websocket_session_grant,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{Error, Result};

/// Inputs of one `authenticate` proof.
#[derive(Clone, Debug)]
pub struct WebSocketAuthProofRequest<'a> {
    /// The discovery `base_url`, verbatim. It becomes `htu`.
    pub base_url: &'a str,
    /// The opaque session grant this connection authenticates with.
    pub session_grant: &'a str,
    /// The `nonce` of the challenge being answered.
    pub nonce: &'a str,
    /// Proof `iat`; MUST fall inside the challenge window.
    pub issued_at: DateTime<Utc>,
    /// Fresh per-proof identifier with ≥96 bits of entropy.
    pub jti: &'a str,
}

/// A built proof plus the values the caller has to echo elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketAuthProof {
    pub compact_jws: String,
    pub jkt: String,
    pub protected: WebSocketDpopProtectedHeader,
    pub claims: WebSocketDpopClaims,
}

/// `ath` of a session grant: `BASE64URL_NOPAD(SHA-256(ASCII(session_grant)))`,
/// with no `sha256:` prefix and no normalisation of the input.
pub fn websocket_session_grant_hash(session_grant: &str) -> String {
    arkret_canonical::canonical::sha256_base64url(session_grant.as_bytes())
}

/// Build the compact JWS carried by `authenticate.dpop_proof`.
pub fn build_websocket_auth_proof(
    request: &WebSocketAuthProofRequest<'_>,
    signing_key: &SigningKey,
) -> Result<WebSocketAuthProof> {
    validate_websocket_base_url(request.base_url)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    validate_websocket_session_grant(request.session_grant)
        .map_err(|error| Error::Protocol(error.to_string()))?;

    let public_jwk = WebSocketDpopPublicJwk::new(arkret_canonical::base64url_encode(
        signing_key.verifying_key().to_bytes(),
    ));
    let protected = WebSocketDpopProtectedHeader::new(public_jwk);
    let claims = WebSocketDpopClaims {
        jti: request.jti.to_owned(),
        htm: WEBSOCKET_AUTH_METHOD_TOKEN.to_owned(),
        htu: request.base_url.to_owned(),
        iat: request.issued_at.timestamp(),
        ath: websocket_session_grant_hash(request.session_grant),
        nonce: request.nonce.to_owned(),
    };
    let proof = WebSocketDpopProof {
        protected: protected.clone(),
        claims: claims.clone(),
    };
    proof
        .validate()
        .map_err(|error| Error::Protocol(error.to_string()))?;

    // §3.1 — both segments are RFC 8785 JCS UTF-8 bytes.
    let protected_b64 = arkret_canonical::base64url_encode(
        arkret_canonical::canonical::canonical_json_bytes(&serde_json::to_value(&protected)?)?,
    );
    let claims_b64 = arkret_canonical::base64url_encode(
        arkret_canonical::canonical::canonical_json_bytes(&serde_json::to_value(&claims)?)?,
    );
    let signing_input = format!("{protected_b64}.{claims_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let compact_jws = format!(
        "{signing_input}.{}",
        arkret_canonical::base64url_encode(signature.to_bytes())
    );
    let jkt = websocket_holder_thumbprint(&protected.jwk)?;

    Ok(WebSocketAuthProof {
        compact_jws,
        jkt,
        protected,
        claims,
    })
}

/// RFC 7638 JWK thumbprint of the holder key, in the fixed `{crv,kty,x}` form.
pub fn websocket_holder_thumbprint(jwk: &WebSocketDpopPublicJwk) -> Result<String> {
    jwk.validate()
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let thumbprint_object = serde_json::json!({
        "crv": "Ed25519",
        "kty": "OKP",
        "x": jwk.x,
    });
    let bytes = arkret_canonical::canonical::canonical_json_bytes(&thumbprint_object)?;
    Ok(arkret_canonical::canonical::sha256_base64url(bytes))
}

/// Everything the service needs to decide one `authenticate` frame.
#[derive(Clone, Debug)]
pub struct WebSocketAuthVerificationRequest<'a> {
    /// `authenticate.dpop_proof`.
    pub compact_jws: &'a str,
    /// `authenticate.connection_id`.
    pub connection_id: &'a str,
    /// `authenticate.session_grant`, verbatim.
    pub session_grant: &'a str,
    /// The current socket's `Origin` header value, verbatim.
    pub socket_origin: &'a str,
    /// The stored single-use challenge addressed by `(connection_id, nonce)`.
    pub challenge: &'a WebSocketChallengeRecord,
    /// `cnf.jkt` of the presented session grant.
    pub grant_cnf_jkt: &'a str,
    /// Whether the replay ledger already holds `(cnf.jkt, jti, context)`.
    pub replay_ledger_hit: bool,
    pub now: DateTime<Utc>,
}

/// Why one `authenticate` frame failed. Every variant closes the connection
/// with [`arkret_wire::websocket_binding::WebSocketCloseCode::PolicyViolation`];
/// the distinction exists for audit, never for a client-visible hint.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WebSocketAuthError {
    #[error("the authentication proof is not a compact JWS")]
    Malformed,
    #[error("an authentication proof segment is not RFC 8785 JCS JSON")]
    NonCanonicalSegment,
    #[error("the authentication proof header or claim set is not the closed shape")]
    InvalidShape,
    #[error("the authentication proof signature is invalid")]
    SignatureInvalid,
    #[error("the authentication proof htm is not the WebSocket application method token")]
    MethodMismatch,
    #[error("the authentication proof htu does not equal the challenge base_url")]
    TargetUriMismatch,
    #[error("the authentication proof nonce does not equal the challenge nonce")]
    NonceMismatch,
    #[error("the authenticate connection_id does not equal the challenge connection_id")]
    ConnectionIdMismatch,
    #[error("the socket Origin does not equal the challenge origin")]
    OriginMismatch,
    #[error("the challenge is expired, unknown or already consumed")]
    ChallengeUnusable,
    #[error("the authentication proof iat is outside the challenge window")]
    IssuedAtOutOfRange,
    #[error("the session_grant is not a 1..16384 byte visible ASCII token")]
    InvalidSessionGrant,
    #[error("ath does not equal the hash of the presented session_grant")]
    AccessTokenHashMismatch,
    #[error("the holder key thumbprint does not equal the grant cnf.jkt")]
    HolderKeyMismatch,
    #[error("the authentication proof was already used")]
    Replayed,
}

/// A successfully verified `authenticate` frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedWebSocketAuth {
    pub jkt: String,
    pub proof: WebSocketDpopProof,
    /// Write this in the same atomic step that marks the challenge consumed.
    pub replay_ledger_key: WebSocketReplayLedgerKey,
}

/// Verify one `authenticate` frame against its stored challenge.
///
/// The order is the normative one: bind the proof to the challenge record
/// first (`connection_id`, `nonce`, Origin, `htu`), then the grant-facing
/// checks (`ath`, holder thumbprint). No failure may consume the challenge or
/// establish a partial session — the caller consumes it only on `Ok`.
pub fn verify_websocket_auth_proof(
    request: &WebSocketAuthVerificationRequest<'_>,
) -> std::result::Result<VerifiedWebSocketAuth, WebSocketAuthError> {
    let mut parts = request.compact_jws.split('.');
    let (Some(protected_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(WebSocketAuthError::Malformed);
    };

    let protected: WebSocketDpopProtectedHeader = decode_jcs_segment(protected_b64)?;
    let claims: WebSocketDpopClaims = decode_jcs_segment(claims_b64)?;
    let proof = WebSocketDpopProof { protected, claims };
    proof
        .validate()
        .map_err(|_| WebSocketAuthError::InvalidShape)?;

    // Signature before any state lookup: an unsigned blob must not be able to
    // probe challenge state.
    let key_bytes: [u8; 32] = arkret_canonical::base64url_decode(&proof.protected.jwk.x)
        .map_err(|_| WebSocketAuthError::InvalidShape)?
        .try_into()
        .map_err(|_| WebSocketAuthError::InvalidShape)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| WebSocketAuthError::InvalidShape)?;
    let signature_bytes: [u8; 64] = arkret_canonical::base64url_decode(signature_b64)
        .map_err(|_| WebSocketAuthError::SignatureInvalid)?
        .try_into()
        .map_err(|_| WebSocketAuthError::SignatureInvalid)?;
    verifying_key
        .verify(
            format!("{protected_b64}.{claims_b64}").as_bytes(),
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| WebSocketAuthError::SignatureInvalid)?;

    if proof.claims.htm != WEBSOCKET_AUTH_METHOD_TOKEN {
        return Err(WebSocketAuthError::MethodMismatch);
    }
    if request.connection_id != request.challenge.connection_id {
        return Err(WebSocketAuthError::ConnectionIdMismatch);
    }
    if proof.claims.nonce != request.challenge.nonce {
        return Err(WebSocketAuthError::NonceMismatch);
    }
    let socket_origin = canonical_http_origin(request.socket_origin)
        .map_err(|_| WebSocketAuthError::OriginMismatch)?;
    if socket_origin != request.challenge.canonical_origin.as_str() {
        return Err(WebSocketAuthError::OriginMismatch);
    }
    if proof.claims.htu != request.challenge.canonical_base_url {
        return Err(WebSocketAuthError::TargetUriMismatch);
    }

    request
        .challenge
        .validate()
        .map_err(|_| WebSocketAuthError::ChallengeUnusable)?;
    if !request.challenge.is_open_at(request.now) {
        return Err(WebSocketAuthError::ChallengeUnusable);
    }
    let issued_at = DateTime::<Utc>::from_timestamp(proof.claims.iat, 0)
        .ok_or(WebSocketAuthError::IssuedAtOutOfRange)?;
    if issued_at < request.challenge.issued_at || issued_at > request.challenge.expires_at {
        return Err(WebSocketAuthError::IssuedAtOutOfRange);
    }

    validate_websocket_session_grant(request.session_grant)
        .map_err(|_| WebSocketAuthError::InvalidSessionGrant)?;
    if proof.claims.ath != websocket_session_grant_hash(request.session_grant) {
        return Err(WebSocketAuthError::AccessTokenHashMismatch);
    }

    let jkt = websocket_holder_thumbprint(&proof.protected.jwk)
        .map_err(|_| WebSocketAuthError::InvalidShape)?;
    if jkt != request.grant_cnf_jkt {
        return Err(WebSocketAuthError::HolderKeyMismatch);
    }
    if request.replay_ledger_hit {
        return Err(WebSocketAuthError::Replayed);
    }

    let replay_ledger_key = WebSocketReplayLedgerKey::new(jkt.clone(), proof.claims.jti.clone());
    Ok(VerifiedWebSocketAuth {
        jkt,
        proof,
        replay_ledger_key,
    })
}

/// Decode one base64url JWS segment as RFC 8785 JCS JSON.
///
/// `parse_canonical_json` is the right gate here: it rejects duplicate members
/// **and** any byte form other than the canonical serialization, which is what
/// §3.1 requires of both segments. The typed target is
/// `deny_unknown_fields`, so `kid`, `x5*` and private JWK members fail too.
fn decode_jcs_segment<T>(segment: &str) -> std::result::Result<T, WebSocketAuthError>
where
    T: serde::de::DeserializeOwned,
{
    let bytes =
        arkret_canonical::base64url_decode(segment).map_err(|_| WebSocketAuthError::Malformed)?;
    let value = arkret_canonical::canonical::parse_canonical_json(&bytes)
        .map_err(|_| WebSocketAuthError::NonCanonicalSegment)?;
    serde_json::from_value(value).map_err(|_| WebSocketAuthError::InvalidShape)
}

#[cfg(test)]
mod tests {
    use arkret_wire::DomainSeparationId;
    use chrono::TimeZone;

    use super::*;

    const BASE_URL: &str = "wss://server.example/_arkret/ws";
    const ORIGIN: &str = "https://app.example";
    const CONNECTION_ID: &str = "Y29ubmVjdGlvbi0wMTIzNDU2Nzg5YWJjZGVm";
    const NONCE: &str = "bm9uY2UtMDEyMzQ1Njc4OWFiY2RlZg";
    const SESSION_GRANT: &str = "ak.session.grant.fixture.websocket.v1";
    const JTI: &str = "d3MtYXV0aC1qdGktMDAwMQ";
    const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const EXPECTED_JWS: &str = "eyJhbGciOiJFZDI1NTE5IiwiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiMTFxWUFZS3hDcmZWU183VHlXUUhPZzdoY3ZQYXBpTWxyd0lhYVBjSFVSbyJ9LCJ0eXAiOiJkcG9wK2p3dCJ9.eyJhdGgiOiJOcGpyakRMaENkX0xWdjRkNWExeXltV0YzUUlaNTU0ejJ5cGlyM0pmekNvIiwiaHRtIjoiQVJLUkVULVdFQlNPQ0tFVC1BVVRIIiwiaHR1Ijoid3NzOi8vc2VydmVyLmV4YW1wbGUvX2Fya3JldC93cyIsImlhdCI6MTc4NTI4MzIwMCwianRpIjoiZDNNdFlYVjBhQzFxZEdrdE1EQXdNUSIsIm5vbmNlIjoiYm05dVkyVXRNREV5TXpRMU5qYzRPV0ZpWTJSbFpnIn0.06JR_Dq7w8g1hs8GYFavd2woUkq1c0ICwetNcBNL0dToJgrTPY_-aBvURkgiiObCk-o7WFgD3xKkmzMfHDedCw";

    fn signing_key() -> SigningKey {
        let mut seed = [0_u8; 32];
        hex_decode(SEED_HEX, &mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn hex_decode(input: &str, out: &mut [u8]) {
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).expect("hex seed");
        }
    }

    fn challenge() -> WebSocketChallengeRecord {
        WebSocketChallengeRecord {
            connection_id: CONNECTION_ID.to_owned(),
            nonce: NONCE.to_owned(),
            canonical_origin: arkret_wire::WebOrigin::new(ORIGIN).unwrap(),
            canonical_base_url: BASE_URL.to_owned(),
            issued_at: Utc.timestamp_opt(1_785_283_200, 0).unwrap(),
            expires_at: Utc.timestamp_opt(1_785_283_205, 0).unwrap(),
            consumed: false,
        }
    }

    fn built() -> WebSocketAuthProof {
        build_websocket_auth_proof(
            &WebSocketAuthProofRequest {
                base_url: BASE_URL,
                session_grant: SESSION_GRANT,
                nonce: NONCE,
                issued_at: Utc.timestamp_opt(1_785_283_200, 0).unwrap(),
                jti: JTI,
            },
            &signing_key(),
        )
        .expect("the fixture proof builds")
    }

    fn verification<'a>(
        proof: &'a str,
        challenge: &'a WebSocketChallengeRecord,
    ) -> WebSocketAuthVerificationRequest<'a> {
        WebSocketAuthVerificationRequest {
            compact_jws: proof,
            connection_id: CONNECTION_ID,
            session_grant: SESSION_GRANT,
            socket_origin: ORIGIN,
            challenge,
            grant_cnf_jkt: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
            replay_ledger_hit: false,
            now: Utc.timestamp_opt(1_785_283_201, 0).unwrap(),
        }
    }

    #[test]
    fn the_builder_reproduces_the_registered_known_answer() {
        let proof = built();
        assert_eq!(proof.compact_jws, EXPECTED_JWS);
        assert_eq!(proof.jkt, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
        assert_eq!(
            proof.claims.ath,
            "NpjrjDLhCd_LVv4d5a1yymWF3QIZ554z2ypir3JfzCo"
        );
    }

    #[test]
    fn the_known_answer_verifies_against_its_challenge() {
        let challenge = challenge();
        let verified = verify_websocket_auth_proof(&verification(EXPECTED_JWS, &challenge))
            .expect("the KAT verifies");
        assert_eq!(
            verified.replay_ledger_key.as_triple(),
            [
                "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
                JTI,
                DomainSeparationId::WEBSOCKET_AUTH_V1,
            ]
        );
    }

    #[test]
    fn the_http_dpop_verifier_never_accepts_this_context() {
        let error = crate::dpop::verify_dpop_proof(&crate::dpop::DpopVerificationRequest {
            proof_jwt: EXPECTED_JWS,
            method: WEBSOCKET_AUTH_METHOD_TOKEN,
            htu: BASE_URL,
            access_token: Some(SESSION_GRANT),
            expected_nonce: None,
            now: Utc.timestamp_opt(1_785_283_201, 0).unwrap(),
            max_age: chrono::Duration::seconds(300),
            max_future_skew: chrono::Duration::seconds(30),
        })
        .expect_err("a wss htu must never reach the HTTP DPoP validator");
        assert_eq!(error, crate::dpop::DpopVerificationError::InvalidTargetUri);
    }

    #[test]
    fn a_consumed_or_expired_challenge_fails_closed() {
        let mut consumed = challenge();
        consumed.consumed = true;
        assert_eq!(
            verify_websocket_auth_proof(&verification(EXPECTED_JWS, &consumed)),
            Err(WebSocketAuthError::ChallengeUnusable)
        );

        let challenge = challenge();
        let mut expired = verification(EXPECTED_JWS, &challenge);
        expired.now = Utc.timestamp_opt(1_785_283_206, 0).unwrap();
        assert_eq!(
            verify_websocket_auth_proof(&expired),
            Err(WebSocketAuthError::ChallengeUnusable)
        );
    }

    #[test]
    fn every_binding_input_is_checked() {
        let challenge = challenge();

        let mut wrong_connection = verification(EXPECTED_JWS, &challenge);
        wrong_connection.connection_id = "b3RoZXItY29ubmVjdGlvbi0wMTIzNDU2Nw";
        assert_eq!(
            verify_websocket_auth_proof(&wrong_connection),
            Err(WebSocketAuthError::ConnectionIdMismatch)
        );

        let mut wrong_origin = verification(EXPECTED_JWS, &challenge);
        wrong_origin.socket_origin = "https://evil.example";
        assert_eq!(
            verify_websocket_auth_proof(&wrong_origin),
            Err(WebSocketAuthError::OriginMismatch)
        );

        let mut wrong_grant = verification(EXPECTED_JWS, &challenge);
        wrong_grant.session_grant = "ak.session.grant.other";
        assert_eq!(
            verify_websocket_auth_proof(&wrong_grant),
            Err(WebSocketAuthError::AccessTokenHashMismatch)
        );

        let mut wrong_holder = verification(EXPECTED_JWS, &challenge);
        wrong_holder.grant_cnf_jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            verify_websocket_auth_proof(&wrong_holder),
            Err(WebSocketAuthError::HolderKeyMismatch)
        );

        let mut replayed = verification(EXPECTED_JWS, &challenge);
        replayed.replay_ledger_hit = true;
        assert_eq!(
            verify_websocket_auth_proof(&replayed),
            Err(WebSocketAuthError::Replayed)
        );
    }

    #[test]
    fn a_resigned_mutation_is_still_rejected() {
        let key = signing_key();
        let challenge = challenge();
        let mutations: [(&str, serde_json::Value); 4] = [
            (
                "htu",
                serde_json::json!("https://server.example/_arkret/ws"),
            ),
            ("htm", serde_json::json!("GET")),
            (
                "ath",
                serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
            ("nonce", serde_json::json!("d3Jvbmctbm9uY2UtMDEyMzQ1Njc4OQ")),
        ];
        for (claim, replacement) in mutations {
            let jws = resign_with_claim(&key, claim, replacement, None);
            verify_websocket_auth_proof(&verification(&jws, &challenge))
                .expect_err(&format!("a resigned {claim} mutation must fail"));
        }
        // An extra member is not part of the closed claim set even when signed.
        let jws = resign_with_claim(
            &key,
            "connection_id",
            serde_json::json!(CONNECTION_ID),
            Some("connection_id"),
        );
        assert_eq!(
            verify_websocket_auth_proof(&verification(&jws, &challenge)),
            Err(WebSocketAuthError::InvalidShape)
        );
    }

    fn resign_with_claim(
        key: &SigningKey,
        claim: &str,
        replacement: serde_json::Value,
        add_as_new: Option<&str>,
    ) -> String {
        let proof = built();
        let mut claims = serde_json::to_value(&proof.claims).expect("claims serialize");
        let object = claims.as_object_mut().expect("claims are an object");
        match add_as_new {
            Some(name) => {
                object.insert(name.to_owned(), replacement);
            }
            None => {
                object.insert(claim.to_owned(), replacement);
            }
        }
        let protected_b64 = arkret_canonical::base64url_encode(
            arkret_canonical::canonical::canonical_json_bytes(
                &serde_json::to_value(&proof.protected).expect("header serialize"),
            )
            .expect("canonical header"),
        );
        let claims_b64 = arkret_canonical::base64url_encode(
            arkret_canonical::canonical::canonical_json_bytes(&claims).expect("canonical claims"),
        );
        let signing_input = format!("{protected_b64}.{claims_b64}");
        format!(
            "{signing_input}.{}",
            arkret_canonical::base64url_encode(key.sign(signing_input.as_bytes()).to_bytes())
        )
    }
}
