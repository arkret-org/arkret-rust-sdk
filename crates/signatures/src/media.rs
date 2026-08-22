//! Call-media request construction and fail-closed signature verification.

use std::collections::BTreeMap;

use arkret_canonical::base64url::base64url_decode;
use arkret_canonical::canonical::canonical_json_bytes;
use arkret_models_collaboration::events_payloads::call::ParticipantBinding;
pub use arkret_models_collaboration::objects::media::MediaBackendKind;
use arkret_models_collaboration::objects::media::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
    MediaBackendToken,
};
use arkret_wire::DidCoreId;
/// Fixed ASCII domain-separation label that prefixes the participant-binding
/// signing input (`media-service-binding.md` §3). Equals the v1 binding
/// `scheme` byte-for-byte; a single `0x00` separates it from the canonical
/// JSON of the seven authoritative fields.
use arkret_wire::{CallId, DeviceId, DidFullId, RealmId};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;

use crate::{Error, Result};

#[path = "media_ice.rs"]
mod ice;
pub use ice::{IceConfig, verify_ice_config_outcome};

// ─── AKP-0010 (R3 spec-sync 2026-05-27) — media token exchange ────────────

/// Validate that `expires_at - now` is within the spec TTL ceiling
/// ([`MEDIA_TOKEN_TTL_MAX_SECS`](arkret_wire::MEDIA_TOKEN_TTL_MAX_SECS)).
/// Returns `Ok(())` when the TTL is within bounds, otherwise a
/// `participant_binding_invalid` protocol error.
pub fn validate_token_ttl(now: DateTime<Utc>, expires_at: DateTime<Utc>) -> Result<()> {
    let remaining = (expires_at - now).num_seconds();
    if remaining <= 0 {
        return Err(Error::Protocol(
            "participant_binding_invalid: token already expired".to_owned(),
        ));
    }
    if (remaining as u64) > arkret_wire::MEDIA_TOKEN_TTL_MAX_SECS {
        return Err(Error::Protocol(
            "participant_binding_invalid: token TTL exceeds 600s ceiling".to_owned(),
        ));
    }
    Ok(())
}

/// Client helper that builds a `ak.self.call.media.exchange.issue_token` request body.
///
/// The reqwest-backed transport (`arkret_http_client::Client::media_token_exchange`)
/// POSTs this body to `/_arkret/self/rtc/token` and returns the raw
/// [`CallMediaTokenExchangeOutcome`]. Callers MUST then pass the response through
/// [`verify_call_media_token_outcome`], which anchors `participant_binding.issuer_kid`
/// to the current
/// `ak.realm.media_service.service_id` ([`MediaServiceAnchors`]), enforces the
/// ≤ 600s TTL ([`validate_token_ttl`]), and checks the binding six-tuple against
/// this request. Focus backend labels are rejected up front by
/// [`MediaBackendKind`] deserialization: the registry is closed, so an
/// unrecognized label never reaches this helper.
pub fn call_media_token_exchange(
    realm_id: RealmId,
    call_id: CallId,
    actor_id: DidCoreId,
    device_id: DeviceId,
    focus_id: impl Into<String>,
) -> CallMediaTokenExchangeRequestBody {
    CallMediaTokenExchangeRequestBody {
        realm_id,
        call_id,
        actor_id,
        device_id,
        focus_id: focus_id.into(),
        capability_refs: Vec::new(),
        desired_media: None,
    }
}

/// Verified media-service routes anchored by the current epoch's core
/// `ak.realm.media_service.service_id`, together with each route's current full
/// DID and the ed25519 keys published by that exact DID version.
///
/// Token issuer `kid`s MUST resolve to one of these DIDs, otherwise the client
/// rejects the token with `token_issuer_unauthorised`. The SDK is a pure
/// verification library and performs no DID resolution itself: the caller
/// resolves the media-service service DID document and supplies the
/// `kid -> ed25519 public key` map via [`with_keys`](Self::with_keys) /
/// [`insert_key`](Self::insert_key). [`verify_call_media_token_outcome`] looks
/// up the binding's `issuer_kid` in this map to
/// verify the Ed25519 signatures; a missing key or a failed signature is rejected
/// with `token_issuer_unauthorised`.
#[derive(Clone, Debug, Default)]
pub struct MediaServiceAnchors {
    routes: BTreeMap<DidCoreId, DidFullId>,
    /// Issuer verifying keys keyed by their full `kid` (`did:...#fragment`).
    keys: BTreeMap<String, VerifyingKey>,
}

impl MediaServiceAnchors {
    /// Build an anchor set from verified `(service core, current full DID)` routes.
    ///
    /// The returned set carries no verifying keys; callers MUST add them with
    /// [`with_keys`](Self::with_keys) / [`insert_key`](Self::insert_key) before
    /// passing it to [`verify_call_media_token_outcome`], otherwise signature
    /// verification fails closed with `token_issuer_unauthorised`.
    pub fn new(routes: impl IntoIterator<Item = (DidCoreId, DidFullId)>) -> Result<Self> {
        let mut verified_routes = BTreeMap::new();
        for (service_id, full_id) in routes {
            if arkret_wire::project_full_id_to_core_id(&full_id)? != service_id {
                return Err(Error::Protocol(
                    "media service route full DID does not project to service_id".to_owned(),
                ));
            }
            if verified_routes.insert(service_id, full_id).is_some() {
                return Err(Error::Protocol(
                    "media service route set contains a duplicate service_id".to_owned(),
                ));
            }
        }
        Ok(Self {
            routes: verified_routes,
            keys: BTreeMap::new(),
        })
    }

    /// Register an issuer verifying key under its full `kid`
    /// (`did:...#fragment`). Returns `self` for builder-style chaining.
    pub fn with_keys(
        mut self,
        keys: impl IntoIterator<Item = (String, VerifyingKey)>,
    ) -> Result<Self> {
        for (kid, key) in keys {
            self.insert_key(kid, key)?;
        }
        Ok(self)
    }

    /// Register a single issuer verifying key under its full `kid`.
    pub fn insert_key(&mut self, kid: impl Into<String>, key: VerifyingKey) -> Result<()> {
        let kid = kid.into();
        if !kid.contains('#') || !self.contains(did_from_kid(&kid)) {
            return Err(Error::Protocol(
                "media service key kid is outside the verified current service routes".to_owned(),
            ));
        }
        self.keys.insert(kid, key);
        Ok(())
    }

    /// True when `did` (a bare DID, no `#fragment`) is anchored.
    pub fn contains(&self, did: &str) -> bool {
        self.routes.values().any(|full_id| full_id.as_str() == did)
    }

    /// Look up the verifying key for a full `kid` (`did:...#fragment`).
    pub(crate) fn verifying_key(&self, kid: &str) -> Option<&VerifyingKey> {
        self.keys.get(kid)
    }

    /// True when the anchor set is empty (no media service declared); callers
    /// MUST treat this as fail-closed for issuer anchoring.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Outcome of verifying a [`CallMediaTokenExchangeOutcome`] against the request
/// and the realm media-service anchors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallMediaTokenVerification {
    /// The anchored media-service DID that issued the participant binding.
    pub issuer_did: DidFullId,
    /// The verified participant identity (SFU-local handle).
    pub participant_identity: String,
}

/// Extract the bare DID from a `kid` of the form `did:...#fragment`.
fn did_from_kid(kid: &str) -> &str {
    kid.split('#').next().unwrap_or(kid)
}

/// The seven authoritative fields the participant binding signature covers
/// (`media-service-binding.md` §3). Serialized via canonical JSON, which sorts
/// keys, so the on-wire signing bytes are stable regardless of declaration
/// order. Unsigned metadata (`scheme` / `issuer_kid` / `issued_at`) MUST NOT
/// appear here.
#[derive(Serialize)]
struct ParticipantBindingSigningFields<'a> {
    actor_id: &'a DidCoreId,
    call_id: &'a CallId,
    device_id: &'a DeviceId,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    focus_id: &'a str,
    participant_identity: &'a str,
    realm_id: &'a RealmId,
}

/// Rebuild the normative `signing_input` for a participant binding:
///
/// ```text
/// "ak.media.participant_binding.v1" || 0x00 ||
/// canonical_json({ actor_id, call_id, device_id, expires_at,
///                  focus_id, participant_identity, realm_id })
/// ```
///
/// The first segment is the fixed ASCII label, then a single `0x00`, then the
/// canonical JSON of exactly the seven authoritative fields. Implementations
/// MUST NOT introduce a private domain prefix or fold metadata into the input.
///
/// This is `pub` so issuers (e.g. soland) can lock their construction against
/// the SDK verifier byte-for-byte: the bytes returned here are exactly what
/// `participant_binding.sig` covers, so a
/// cross-implementation test can assert the issuer's signing input equals this.
pub fn participant_binding_signing_input(binding: &CallMediaParticipantBinding) -> Result<Vec<u8>> {
    let fields = ParticipantBindingSigningFields {
        actor_id: &binding.actor_id,
        call_id: &binding.call_id,
        device_id: &binding.device_id,
        expires_at: binding.expires_at,
        focus_id: &binding.focus_id,
        participant_identity: &binding.participant_identity,
        realm_id: &binding.realm_id,
    };
    let mut input = Vec::new();
    input.extend_from_slice(ParticipantBinding::SCHEMA.as_bytes());
    input.push(0x00);
    input.extend_from_slice(&canonical_json_bytes(&fields)?);
    Ok(input)
}

/// Verify an Ed25519(ed25519) signature `sig_b64` (base64url, no padding) over
/// `signing_input` using the verifying key registered under `kid` in `anchors`.
/// Any missing key, malformed signature or failed verification surfaces as
/// `token_issuer_unauthorised` (`media-service-binding.md` §3 default path).
fn verify_issuer_signature(
    anchors: &MediaServiceAnchors,
    kid: &str,
    sig_b64: &str,
    signing_input: &[u8],
    what: &str,
) -> Result<()> {
    let key = anchors.verifying_key(kid).ok_or_else(|| {
        Error::Protocol(format!(
            "{}: no verifying key registered for {what} kid {kid}",
            arkret_wire::ReasonCode::TOKEN_ISSUER_UNAUTHORISED
        ))
    })?;
    let sig_bytes = base64url_decode(sig_b64).map_err(|err| {
        Error::Protocol(format!(
            "{}: {what} signature is not base64url: {err}",
            arkret_wire::ReasonCode::TOKEN_ISSUER_UNAUTHORISED
        ))
    })?;
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::Protocol(format!(
            "{}: {what} signature must be 64 bytes, got {}",
            arkret_wire::ReasonCode::TOKEN_ISSUER_UNAUTHORISED,
            sig_bytes.len()
        ))
    })?;
    let signature = Signature::from_bytes(&sig_array);
    key.verify_strict(signing_input, &signature).map_err(|err| {
        Error::Protocol(format!(
            "{}: {what} signature verification failed: {err}",
            arkret_wire::ReasonCode::TOKEN_ISSUER_UNAUTHORISED
        ))
    })
}

/// Verify a media token-exchange response against the issuing request and the
/// realm media-service anchors (`media-service-binding.md` §3 client rules).
///
/// Checks performed (all fail closed):
/// - required fields present (`connect_url`, `backend_token`, `participant_identity`,
///   `participant_binding.sig`, `issuer_kid`);
/// - `participant_binding.issuer_kid` resolves to an anchored `ak.realm.media_service.service_id` →
///   else `token_issuer_unauthorised`;
/// - the binding's `(realm_id, call_id, focus_id, actor_id, device_id)` six-tuple matches the
///   request and `participant_identity` matches the top-level one;
/// - the binding's `expires_at` is after its `issued_at`;
/// - TTL ≤ 600s and not already expired (via [`validate_token_ttl`]);
/// - `participant_binding.sig` verifies as Ed25519(ed25519) signatures over the normative
///   `signing_input` ([`participant_binding_signing_input`]) under the issuer verifying keys in
///   `anchors`. Per `media-service-binding.md` §3 the default verification path MUST verify both
///   signatures; either failing — or a missing key — rejects with `token_issuer_unauthorised`.
///   Because the signature covers the seven authoritative fields, tampering with any of them fails
///   verification.
///
/// The caller resolves the media-service service DID document and supplies the
/// `kid -> ed25519 public key` map through [`MediaServiceAnchors::with_keys`] /
/// [`MediaServiceAnchors::insert_key`]; this helper performs no DID resolution.
pub fn verify_call_media_token_outcome(
    request: &CallMediaTokenExchangeRequestBody,
    outcome: &CallMediaTokenExchangeOutcome,
    anchors: &MediaServiceAnchors,
    now: DateTime<Utc>,
) -> Result<CallMediaTokenVerification> {
    let binding = &outcome.participant_binding;

    if outcome.connect_url.trim().is_empty()
        || matches!(&outcome.backend_token, MediaBackendToken::Opaque(token) if token.trim().is_empty())
        || outcome.participant_identity.trim().is_empty()
        || binding.sig.trim().is_empty()
        || binding.issuer_kid.trim().is_empty()
    {
        return Err(Error::Protocol(
            "participant_binding_invalid: token response missing required fields".to_owned(),
        ));
    }

    if binding.scheme != ParticipantBinding::SCHEMA {
        return Err(Error::Protocol(format!(
            "participant_binding_invalid: unexpected scheme {:?}",
            binding.scheme
        )));
    }

    // Issuer DID anchoring — the binding issuer MUST resolve to an anchored
    // service_id.
    let issuer_did = did_from_kid(&binding.issuer_kid);
    if anchors.is_empty() || !anchors.contains(issuer_did) {
        return Err(Error::Protocol(format!(
            "token_issuer_unauthorised: participant_binding issuer {issuer_did} not in realm media_service anchors"
        )));
    }

    // Six-tuple binding MUST match the request the client made.
    if binding.realm_id != request.realm_id
        || binding.call_id != request.call_id
        || binding.focus_id != request.focus_id
        || binding.actor_id != request.actor_id
        || binding.device_id != request.device_id
    {
        return Err(Error::Protocol(
            "participant_binding_invalid: binding tuple does not match the request".to_owned(),
        ));
    }
    if binding.participant_identity != outcome.participant_identity {
        return Err(Error::Protocol(
            "participant_binding_invalid: participant_identity mismatch between binding and outcome"
                .to_owned(),
        ));
    }

    // The binding's issued_at MUST precede its expiry (a non-positive TTL
    // window is a malformed binding).
    if binding.expires_at <= binding.issued_at {
        return Err(Error::Protocol(
            "participant_binding_invalid: binding expires_at not after issued_at".to_owned(),
        ));
    }

    // TTL ceiling — both the binding and the outcome expiry MUST be ≤ 600s.
    validate_token_ttl(now, binding.expires_at)?;
    validate_token_ttl(now, outcome.expires_at)?;

    // Verification path (spec §3): the participant binding signature is the
    // single issuer assertion over the seven-tuple signing_input. A failing
    // signature — or a key the anchors do not publish — is
    // `token_issuer_unauthorised`.
    let signing_input = participant_binding_signing_input(binding)?;
    verify_issuer_signature(
        anchors,
        &binding.issuer_kid,
        &binding.sig,
        &signing_input,
        "participant_binding",
    )?;

    Ok(CallMediaTokenVerification {
        issuer_did: DidFullId::new(issuer_did.to_owned())?,
        participant_identity: outcome.participant_identity.clone(),
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const ISSUER_KID: &str = "did:webvh:z6mkfixturemedia:media.example#media-token";

    fn did(name: &str) -> DidFullId {
        DidFullId::new(format!("did:webvh:z6mkfixture{name}:{name}.example")).unwrap()
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
            actor("alice"),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
            "fra-1",
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
            focus_id: request.focus_id.clone(),
            backend_kind: MediaBackendKind::Livekit,
            connect_url: "wss://livekit-fra.example.com".to_owned(),
            backend_token: MediaBackendToken::Opaque("opaque-backend-token".to_owned()),
            participant_identity: identity.clone(),
            participant_binding: CallMediaParticipantBinding {
                scheme: ParticipantBinding::SCHEMA.to_owned(),
                sig: String::new(),
                issuer_kid: arkret_wire::DidUrl::new(ISSUER_KID).unwrap(),
                realm_id: request.realm_id.clone(),
                call_id: request.call_id.clone(),
                focus_id: request.focus_id.clone(),
                actor_id: request.actor_id.clone(),
                device_id: request.device_id.clone(),
                participant_identity: identity,
                issued_at: expires_at - chrono::Duration::minutes(5),
                expires_at,
            },
            expires_at,
        }
    }

    /// Sign the participant binding over the spec signing_input with `key`,
    /// mutating `outcome` in place. Call this AFTER any tampering so the
    /// signature covers the (possibly tampered) authoritative fields.
    fn sign_outcome(outcome: &mut CallMediaTokenExchangeOutcome, key: &SigningKey) {
        let input = participant_binding_signing_input(&outcome.participant_binding).unwrap();
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
        let outcome_back: CallMediaTokenExchangeOutcome =
            serde_json::from_str(&outcome_json).unwrap();
        assert_eq!(
            outcome_back.participant_identity,
            outcome.participant_identity
        );

        let anchors = anchors_with_issuer_key(&key);
        let verified = verify_call_media_token_outcome(&request, &outcome, &anchors, now).unwrap();
        assert_eq!(verified.issuer_did, did("media"));
        assert_eq!(verified.participant_identity, outcome.participant_identity);

        // Anchor: the signing input is label-prefixed (`media-service-binding.md`
        // §3). soland's cross-implementation lock asserts byte equality against
        // this same function.
        let signing_input =
            participant_binding_signing_input(&outcome.participant_binding).unwrap();
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
                "participant_identity": "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000",
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

        // Tamper each of the seven authoritative fields AFTER signing → the
        // recomputed signing_input no longer matches the signature.
        // participant_identity: also update the top-level field so the
        // structural cross-check passes and the failure is signature-only.
        let mut t_identity = signed_outcome(&request, &key, expires_at);
        t_identity.participant_binding.participant_identity =
            "ak:rtc_participant:tampered".to_owned();
        t_identity.participant_identity = "ak:rtc_participant:tampered".to_owned();
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
        tampered.participant_binding.focus_id = "fra-2".to_owned();
        sign_outcome(&mut tampered, &key);
        let err = verify_call_media_token_outcome(&request, &tampered, &anchors, now).unwrap_err();
        assert!(err.to_string().contains("participant_binding_invalid"));

        // participant_identity mismatch between binding and outcome.
        let mut id_mismatch = signed_outcome(&request, &key, now + chrono::Duration::minutes(5));
        id_mismatch.participant_identity = "ak:rtc_participant:elsewhere".to_owned();
        assert!(verify_call_media_token_outcome(&request, &id_mismatch, &anchors, now).is_err());
    }
}
