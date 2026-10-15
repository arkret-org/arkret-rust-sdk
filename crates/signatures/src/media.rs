//! Call-media request construction and fail-closed signature verification.

use std::collections::BTreeMap;

use arkret_canonical::base64url::base64url_decode;
use arkret_canonical::canonical::canonical_json_bytes;
use arkret_models_collaboration::events_payloads::call::ParticipantBinding;
pub use arkret_models_collaboration::objects::media::MediaBackendKind;
use arkret_models_collaboration::objects::media::{
    CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody, MediaBackendToken,
};
use arkret_wire::{ActorId, CallId, DeviceId, Did, DidCoreId, RealmId};
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
    let remaining = expires_at - now;
    if remaining <= chrono::Duration::zero() {
        return Err(Error::Protocol(
            "participant_binding_invalid: token already expired".to_owned(),
        ));
    }
    if remaining > chrono::Duration::seconds(arkret_wire::MEDIA_TOKEN_TTL_MAX_SECS as i64) {
        return Err(Error::Protocol(
            "participant_binding_invalid: token TTL exceeds 600s ceiling".to_owned(),
        ));
    }
    Ok(())
}

/// Client helper that builds a `ak.self.call.media.exchange.issue_token.v1` request body.
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
    actor_id: ActorId,
    device_id: DeviceId,
    focus_id: impl Into<String>,
    join_context: arkret_models_collaboration::call_invitation::CallMediaJoinContext,
) -> CallMediaTokenExchangeRequestBody {
    CallMediaTokenExchangeRequestBody {
        realm_id,
        call_id,
        actor_id,
        device_id,
        focus_id: focus_id.into(),
        capability_refs: Vec::new(),
        desired_media: None,
        join_context,
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
    routes: BTreeMap<DidCoreId, Did>,
    /// Issuer verifying keys keyed by their full `kid` (`did:...#fragment`).
    keys: BTreeMap<String, VerifyingKey>,
}

impl MediaServiceAnchors {
    /// Build an anchor set from verified `(service core, current DID)` routes.
    ///
    /// The returned set carries no verifying keys; callers MUST add them with
    /// [`with_keys`](Self::with_keys) / [`insert_key`](Self::insert_key) before
    /// passing it to [`verify_call_media_token_outcome`], otherwise signature
    /// verification fails closed with `token_issuer_unauthorised`.
    pub fn new(routes: impl IntoIterator<Item = (DidCoreId, Did)>) -> Result<Self> {
        let mut verified_routes = BTreeMap::new();
        for (service_id, did) in routes {
            if arkret_wire::project_did_to_core_id(&did)? != service_id {
                return Err(Error::Protocol(
                    "media service route DID does not project to service_id".to_owned(),
                ));
            }
            if verified_routes.insert(service_id, did).is_some() {
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
        self.routes
            .values()
            .any(|route_did| route_did.as_str() == did)
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
    pub issuer_did: Did,
    /// The verified participant identity (SFU-local handle).
    pub participant_id: String,
}

/// Extract the bare DID from a `kid` of the form `did:...#fragment`.
fn did_from_kid(kid: &str) -> &str {
    kid.split('#').next().unwrap_or(kid)
}

/// The ten authoritative fields the participant binding signature covers
/// (`media-service-binding.md` §3). Serialized via canonical JSON, which sorts
/// keys, so the on-wire signing bytes are stable regardless of declaration
/// order. Coordinates come from the exact enclosing carrier. Only the
/// compact binding supplies expiry, issuer method and the private-receipt commitment; media comes
/// from the exact issued range.
#[derive(Serialize)]
pub struct ParticipantBindingContext<'a> {
    pub actor_id: &'a DidCoreId,
    pub call_id: &'a CallId,
    pub device_id: &'a DeviceId,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub focus_id: &'a str,
    pub participant_id: &'a str,
    pub realm_id: &'a RealmId,
    pub issuer_kid: &'a str,
    pub subject_binding_digest: &'a str,
    pub media: arkret_models_collaboration::call_invitation::CallInvitationMedia,
}

/// Rebuild the normative `signing_input` for a participant binding:
///
/// ```text
/// "ak.media.participant_binding.v1" || 0x00 ||
/// canonical_json({ actor_id, call_id, device_id, expires_at,
///                  focus_id, participant_id, realm_id, media, issuer_kid, subject_binding_digest })
/// ```
///
/// The first segment is the fixed ASCII label, then a single `0x00`, then the
/// canonical JSON of exactly the ten authoritative fields. Implementations
/// MUST NOT introduce a private domain prefix or fold metadata into the input.
///
/// This is `pub` so issuers (e.g. coland) can lock their construction against
/// the SDK verifier byte-for-byte: the bytes returned here are exactly what
/// `participant_binding.sig` covers, so a
/// cross-implementation test can assert the issuer's signing input equals this.
impl<'a> ParticipantBindingContext<'a> {
    pub fn from_outcome(outcome: &'a CallMediaTokenExchangeOutcome) -> Self {
        Self {
            actor_id: &outcome.roster_identity.actor_id,
            call_id: &outcome.call_id,
            device_id: &outcome.roster_identity.device_id,
            expires_at: outcome.participant_binding.expires_at,
            focus_id: &outcome.focus_id,
            participant_id: &outcome.participant_id,
            realm_id: &outcome.realm_id,
            issuer_kid: outcome.participant_binding.issuer_kid.as_str(),
            subject_binding_digest: &outcome.participant_binding.subject_binding_digest,
            media: outcome.subject_binding.media.clone(),
        }
    }
}

pub fn participant_binding_signing_input(
    fields: &ParticipantBindingContext<'_>,
) -> Result<Vec<u8>> {
    let mut input = Vec::new();
    input.extend_from_slice(ParticipantBinding::SCHEMA.as_bytes());
    input.push(0x00);
    input.extend_from_slice(&canonical_json_bytes(fields)?);
    Ok(input)
}

/// Verifier-produced evidence for one exact roster join and its anchored issuer.
/// It has no wire representation and cannot be fabricated by a producer DTO.
#[derive(Clone, Debug)]
pub struct VerifiedCallParticipant {
    event_digest: String,
    service_id: DidCoreId,
}

impl VerifiedCallParticipant {
    pub fn verify(
        event: &arkret_wire::Event,
        service_id: &DidCoreId,
        public_key: &crate::PublicKeyMaterial,
    ) -> Result<Option<Self>> {
        if event.kind != arkret_wire::EventKind::CallState {
            return Ok(None);
        }
        let payload: arkret_models_collaboration::events_payloads::call::CallStatePayload =
            serde_json::from_value(
                serde_json::to_value(&event.payload).map_err(|e| Error::Protocol(e.to_string()))?,
            )
            .map_err(|e| Error::Protocol(e.to_string()))?;
        let Some(arkret_models_collaboration::events_payloads::call::CallRosterDelta::Join {
            participant,
        }) = payload.roster_delta
        else {
            return Ok(None);
        };
        let Some(binding) = &participant.participant_binding else {
            return Ok(None);
        };
        let issuer = arkret_wire::project_did_to_core_id(&Did::new(did_from_kid(
            binding.issuer_kid.as_str(),
        ))?)?;
        if &issuer != service_id || binding.expires_at <= event.created_at {
            return Err(Error::Protocol(
                "participant_binding_invalid: issuer or binding window differs".to_owned(),
            ));
        }
        let device = DeviceId::new(participant.device_id.clone())?;
        let context = ParticipantBindingContext {
            actor_id: &participant.actor_id,
            call_id: &payload.call_id,
            device_id: &device,
            expires_at: binding.expires_at,
            focus_id: participant
                .focus_id
                .as_deref()
                .ok_or_else(|| Error::Protocol("participant focus is missing".to_owned()))?,
            participant_id: participant
                .participant_id
                .as_deref()
                .ok_or_else(|| Error::Protocol("participant ID is missing".to_owned()))?,
            realm_id: &event.realm_id,
            issuer_kid: binding.issuer_kid.as_str(),
            subject_binding_digest: &binding.subject_binding_digest,
            media: participant
                .signed_media()
                .map_err(|e| Error::Protocol(e.to_string()))?,
        };
        if !crate::proof::verify_detached_ed25519_signature(
            public_key,
            &participant_binding_signing_input(&context)?,
            &binding.sig,
        ) {
            return Err(Error::Protocol(
                "participant_binding_invalid: anonymous tuple signature differs".to_owned(),
            ));
        }
        Ok(Some(Self {
            event_digest: arkret_models_collaboration::call_invitation::canonical_request_digest(
                event,
            )?,
            service_id: service_id.clone(),
        }))
    }

    pub fn binds(&self, event: &arkret_wire::Event, current_service: &DidCoreId) -> bool {
        &self.service_id == current_service
            && arkret_models_collaboration::call_invitation::canonical_request_digest(event)
                .is_ok_and(|digest| digest == self.event_digest)
    }
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
/// - required fields present (`connect_url`, `backend_token`, `participant_id`,
///   `participant_binding.sig`, `issuer_kid`);
/// - `participant_binding.issuer_kid` resolves to an anchored `ak.realm.media_service.service_id` →
///   else `token_issuer_unauthorised`;
/// - the binding's `(realm_id, call_id, focus_id, actor_id, device_id)` six-tuple matches the
///   request and `participant_id` matches the top-level one;
/// - TTL ≤ 600s and not already expired (via [`validate_token_ttl`]);
/// - `participant_binding.sig` verifies as Ed25519(ed25519) signatures over the normative
///   `signing_input` ([`participant_binding_signing_input`]) under the issuer verifying keys in
///   `anchors`. A failed signature or missing key rejects with `token_issuer_unauthorised`. Because
///   the signature covers the ten authoritative fields, tampering with any of them fails
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
        || outcome.participant_id.trim().is_empty()
        || binding.sig.trim().is_empty()
        || binding.issuer_kid.trim().is_empty()
    {
        return Err(Error::Protocol(
            "participant_binding_invalid: token response missing required fields".to_owned(),
        ));
    }

    // Issuer DID anchoring — the binding issuer MUST resolve to an anchored
    // service_id.
    let issuer_did = did_from_kid(&binding.issuer_kid);
    if anchors.is_empty() || !anchors.contains(issuer_did) {
        return Err(Error::Protocol(format!(
            "token_issuer_unauthorised: participant_binding issuer {issuer_did} not in realm media_service anchors"
        )));
    }

    if outcome.realm_id != request.realm_id
        || outcome.call_id != request.call_id
        || outcome.focus_id != request.focus_id
        || outcome.actor_id != request.actor_id
        || outcome.device_id != request.device_id
        || outcome.expires_at != binding.expires_at
        || outcome.roster_identity.device_id == request.device_id
        || &outcome.roster_identity.actor_id == request.actor_id.signing_principal_id()
    {
        return Err(Error::Protocol(
            "participant_binding_invalid: outcome tuple does not match the exact request"
                .to_owned(),
        ));
    }

    // TTL ceiling — both the binding and the outcome expiry MUST be ≤ 600s.
    validate_token_ttl(now, binding.expires_at)?;
    validate_token_ttl(now, outcome.expires_at)?;

    // Verification path (spec §3): the participant binding signature is the
    // single issuer assertion over the ten-field tuple signing_input. A failing
    // signature — or a key the anchors do not publish — is
    // `token_issuer_unauthorised`.
    let signing_input =
        participant_binding_signing_input(&ParticipantBindingContext::from_outcome(outcome))?;
    verify_issuer_signature(
        anchors,
        &binding.issuer_kid,
        &binding.sig,
        &signing_input,
        "participant_binding",
    )?;

    let receipt = &outcome.subject_binding;
    let media = request
        .desired_media
        .as_ref()
        .map(
            |m| arkret_models_collaboration::call_invitation::CallInvitationMedia {
                audio: m.audio.unwrap_or(true),
                video: m.video.unwrap_or(true),
                screen: m.screen.unwrap_or(false),
            },
        )
        .unwrap_or(
            arkret_models_collaboration::call_invitation::CallInvitationMedia {
                audio: true,
                video: true,
                screen: false,
            },
        );
    if receipt.realm_id != request.realm_id
        || receipt.call_id != request.call_id
        || receipt.subject_actor_id != request.actor_id
        || receipt.subject_device_id != request.device_id
        || receipt.roster_identity != outcome.roster_identity
        || receipt.focus_id != request.focus_id
        || receipt.participant_id != outcome.participant_id
        || receipt.media != media
        || receipt.issuer_kid != binding.issuer_kid
        || receipt.expires_at != binding.expires_at
        || binding.subject_binding_digest
            != arkret_models_collaboration::call_invitation::canonical_request_digest(receipt)?
    {
        return Err(Error::Protocol(
            "participant_binding_invalid: private subject receipt differs from exact exchange"
                .to_owned(),
        ));
    }
    verify_issuer_signature(
        anchors,
        receipt.issuer_kid.as_str(),
        &receipt.sig,
        &receipt.signature_input()?,
        "subject_binding",
    )?;

    Ok(CallMediaTokenVerification {
        issuer_did: Did::new(issuer_did.to_owned())?,
        participant_id: outcome.participant_id.clone(),
    })
}

#[cfg(test)]
mod tests {
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
            arkret_models_collaboration::call_invitation::CallMediaJoinContext::Voluntary(arkret_models_collaboration::call_invitation::CallVoluntaryJoinContext {
                kind:arkret_models_collaboration::call_invitation::CallVoluntaryJoinKind::Voluntary,
                created_at:arkret_canonical::canonical::normalize_timestamp_canonical(Utc::now()),expires_at:arkret_canonical::canonical::normalize_timestamp_canonical(Utc::now()+chrono::Duration::seconds(30)),
                nonce:arkret_canonical::base64url_encode([18u8;32]),proof:arkret_models_collaboration::call_invitation::CallVoluntaryJoinProof {verification_method:"did:webvh:z6mkfixturealice:alice.example#device".to_owned(),jws:"test-unused-intent-proof".to_owned()},
            }),
        )
    }

    /// Build an unsigned outcome (placeholder signatures); callers sign it via
    /// [`sign_outcome`] after any field tampering.
    fn token_outcome(
        request: &CallMediaTokenExchangeRequestBody,
        expires_at: DateTime<Utc>,
    ) -> CallMediaTokenExchangeOutcome {
        let identity = "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000".to_owned();
        let roster_identity =
            arkret_models_collaboration::call_invitation::CallMediaRosterIdentity {
                actor_id: DidCoreId::new(format!(
                    "ak:did_core:key:{}",
                    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                        SigningKey::from_bytes(&[99u8; 32])
                            .verifying_key()
                            .as_bytes()
                    )
                ))
                .unwrap(),
                device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000009").unwrap(),
            };
        let subject_binding =
            arkret_models_collaboration::call_invitation::CallMediaSubjectBinding {
                realm_id: request.realm_id.clone(),
                call_id: request.call_id.clone(),
                subject_actor_id: request.actor_id.clone(),
                subject_device_id: request.device_id.clone(),
                roster_identity: roster_identity.clone(),
                focus_id: request.focus_id.clone(),
                participant_id: identity.clone(),
                media: arkret_models_collaboration::call_invitation::CallInvitationMedia {
                    audio: true,
                    video: true,
                    screen: false,
                },
                nonce: arkret_canonical::base64url_encode([47u8; 32]),
                expires_at,
                issuer_kid: arkret_wire::DidUrl::new(ISSUER_KID).unwrap(),
                sig: String::new(),
            };
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
                subject_binding_digest: String::new(),
                issuer_kid: arkret_wire::DidUrl::new(ISSUER_KID).unwrap(),
                expires_at,
            },
            expires_at,
            roster_identity,
            subject_binding,
        }
    }

    /// Sign the participant binding over the spec signing_input with `key`,
    /// mutating `outcome` in place. Call this AFTER any tampering so the
    /// signature covers the (possibly tampered) authoritative fields.
    fn sign_outcome(outcome: &mut CallMediaTokenExchangeOutcome, key: &SigningKey) {
        outcome.subject_binding.sig = arkret_canonical::base64url_encode(
            key.sign(&outcome.subject_binding.signature_input().unwrap())
                .to_bytes(),
        );
        outcome.participant_binding.subject_binding_digest =
            arkret_models_collaboration::call_invitation::canonical_request_digest(
                &outcome.subject_binding,
            )
            .unwrap();
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

        // Tamper each of the ten authoritative fields AFTER signing → the
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
    fn private_receipt_and_public_media_commitment_cannot_be_reassigned() {
        let request = token_request();
        let key = issuer_key();
        let now = Utc::now();
        let anchors = anchors_with_issuer_key(&key);
        let accepted = signed_outcome(&request, &key, now + chrono::Duration::minutes(5));
        let mut wrong_subject = request.clone();
        wrong_subject.actor_id = ActorId::service(actor("other"));
        let mut forged = accepted.clone();
        forged.actor_id = wrong_subject.actor_id.clone();
        forged.subject_binding.subject_actor_id = wrong_subject.actor_id.clone();
        // Even possession of this issuer key cannot change the private mapping
        // while retaining the exact already-accepted public commitment.
        forged.subject_binding.sig = arkret_canonical::base64url_encode(
            key.sign(&forged.subject_binding.signature_input().unwrap())
                .to_bytes(),
        );
        assert!(
            verify_call_media_token_outcome(&wrong_subject, &forged, &anchors, now)
                .unwrap_err()
                .to_string()
                .contains("participant_binding_invalid")
        );
        let mut media = accepted.clone();
        media.subject_binding.media.screen = true;
        assert!(
            verify_call_media_token_outcome(&request, &media, &anchors, now)
                .unwrap_err()
                .to_string()
                .contains("token_issuer_unauthorised")
        );
        let mut alias = accepted.clone();
        alias.roster_identity.device_id =
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000a").unwrap();
        assert!(verify_call_media_token_outcome(&request, &alias, &anchors, now).is_err());
        let mut nonce = accepted.clone();
        nonce.subject_binding.nonce = arkret_canonical::base64url_encode([48u8; 32]);
        assert!(verify_call_media_token_outcome(&request, &nonce, &anchors, now).is_err());
        let mut named = accepted;
        let alternate = "did:webvh:z6mkfixturemedia:media.example#alternate";
        let mut same_key = anchors;
        same_key.insert_key(alternate, key.verifying_key()).unwrap();
        named.participant_binding.issuer_kid = arkret_wire::DidUrl::new(alternate).unwrap();
        assert!(
            verify_call_media_token_outcome(&request, &named, &same_key, now)
                .unwrap_err()
                .to_string()
                .contains("token_issuer_unauthorised")
        );
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
        assert_eq!(compact.as_object().unwrap().len(), 4);
        assert!(compact.get("subject_binding_digest").is_some());
        for field in [
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
}
