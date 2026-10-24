//! Call-media request construction and fail-closed signature verification.

use std::collections::BTreeMap;

use arkret_canonical::base64url::base64url_decode;
use arkret_canonical::canonical::canonical_json_bytes;
use arkret_models_collaboration::events_payloads::call::ParticipantBinding;
pub use arkret_models_collaboration::objects::media::MediaBackendKind;
use arkret_models_collaboration::objects::media::{
    CallMediaTokenExchangeRequestBody, CallMediaTokenExchangeResponseBody, MediaBackendToken,
};
use arkret_wire::{ActorId, CallId, DeviceId, Did, DidCoreId, RealmId};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;

use crate::{Error, Result};

#[path = "media_ice.rs"]
mod ice;
pub use ice::{IceConfig, verify_ice_config_outcome};

// AKP-0010 media token exchange.

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
/// [`CallMediaTokenExchangeResponseBody`]. Callers MUST then pass the response through
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

/// Outcome of verifying a [`CallMediaTokenExchangeResponseBody`] against the request
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

/// The nine authoritative fields the participant binding signature covers
/// (`media-service-binding.md` §3). Serialized via canonical JSON, which sorts
/// keys, so the on-wire signing bytes are stable regardless of declaration
/// order. Coordinates come from the exact enclosing carrier. Only the
/// compact binding supplies expiry and issuer method; media comes
/// from the exact issued range.
#[derive(Serialize)]
pub struct ParticipantBindingContext<'a> {
    pub actor_id: &'a ActorId,
    pub call_id: &'a CallId,
    pub device_id: &'a DeviceId,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub focus_id: &'a str,
    pub participant_id: &'a str,
    pub realm_id: &'a RealmId,
    pub issuer_kid: &'a str,
    pub media: arkret_models_collaboration::call_invitation::CallInvitationMedia,
}

/// Rebuild the normative `signing_input` for a participant binding:
///
/// ```text
/// "ak.media.participant_binding.v1" || 0x00 ||
/// canonical_json({ actor_id, call_id, device_id, expires_at,
///                  focus_id, participant_id, realm_id, media, issuer_kid })
/// ```
///
/// The first segment is the fixed ASCII label, then a single `0x00`, then the
/// canonical JSON of exactly the nine authoritative fields. Implementations
/// MUST NOT introduce a private domain prefix or fold metadata into the input.
///
/// This is `pub` so issuers (e.g. coland) can lock their construction against
/// the SDK verifier byte-for-byte: the bytes returned here are exactly what
/// `participant_binding.signature` covers, so a
/// cross-implementation test can assert the issuer's signing input equals this.
impl<'a> ParticipantBindingContext<'a> {
    pub fn from_outcome(outcome: &'a CallMediaTokenExchangeResponseBody) -> Self {
        Self {
            actor_id: &outcome.actor_id,
            call_id: &outcome.call_id,
            device_id: &outcome.device_id,
            expires_at: outcome.participant_binding.expires_at,
            focus_id: &outcome.focus_id,
            participant_id: &outcome.participant_id,
            realm_id: &outcome.realm_id,
            issuer_kid: outcome.participant_binding.issuer_kid.as_str(),
            media: outcome.media.clone(),
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
    issuer_key: [u8; 32],
    issuer_history: Option<arkret_models_identity::AuthenticatedServiceResolution>,
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
            media: participant
                .signed_media()
                .map_err(|e| Error::Protocol(e.to_string()))?,
        };
        if !crate::proof::verify_detached_ed25519_signature(
            public_key,
            &participant_binding_signing_input(&context)?,
            &binding.signature,
        ) {
            return Err(Error::Protocol(
                "participant_binding_invalid: complete participant tuple signature differs"
                    .to_owned(),
            ));
        }
        Ok(Some(Self {
            event_digest: arkret_models_collaboration::call_invitation::canonical_request_digest(
                event,
            )?,
            service_id: service_id.clone(),
            issuer_key: public_key.ed25519_bytes()?,
            issuer_history: None,
        }))
    }

    pub fn binds(&self, event: &arkret_wire::Event, current_service: &DidCoreId) -> bool {
        &self.service_id == current_service
            && arkret_models_collaboration::call_invitation::canonical_request_digest(event)
                .is_ok_and(|digest| digest == self.event_digest)
    }

    /// Retain the resolved native evidence for independent verification at the
    /// accepting Commit time. Attaching it does not assert that it is valid.
    pub fn with_issuer_history(
        mut self,
        history: arkret_models_identity::AuthenticatedServiceResolution,
    ) -> Self {
        self.issuer_history = Some(history);
        self
    }

    pub fn issuer_history(
        &self,
    ) -> Option<&arkret_models_identity::AuthenticatedServiceResolution> {
        self.issuer_history.as_ref()
    }

    pub fn signing_key_for(
        &self,
        event: &arkret_wire::Event,
    ) -> Result<arkret_models_collaboration::events_payloads::call::CallParticipantSigningKey> {
        if arkret_models_collaboration::call_invitation::canonical_request_digest(event)?
            != self.event_digest
        {
            return Err(Error::Protocol(
                "participant signing key belongs to a different Event".to_owned(),
            ));
        }
        Ok(
            arkret_models_collaboration::events_payloads::call::CallParticipantSigningKey {
                public_key_base64url: arkret_canonical::base64url_encode(self.issuer_key),
            },
        )
    }
}

/// Verify original participant bindings using keys authenticated by the enclosing
/// own-Station result. Native issuer authority remains the Station's obligation.
pub fn verify_call_roster_bindings(
    realm: &RealmId,
    call: &CallId,
    roster: &arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue,
) -> Result<()> {
    use arkret_models_collaboration::events_payloads::call::CallRosterDelta;
    for entry in &roster.entries {
        let CallRosterDelta::Join { participant } = &entry.value else {
            return Err(Error::Protocol("Call roster entry is not a join".into()));
        };
        match (
            &participant.participant_binding,
            &entry.participant_signing_key,
        ) {
            (None, None) => continue,
            (Some(binding), Some(key)) => {
                if binding.expires_at <= entry.source_commit.committed_at
                    || entry.source_commit.realm_id != *realm
                {
                    return Err(Error::Protocol(
                        "Call participant original window or Realm differs".into(),
                    ));
                }
                let device = DeviceId::new(participant.device_id.clone())?;
                let context = ParticipantBindingContext {
                    actor_id: &participant.actor_id,
                    call_id: call,
                    device_id: &device,
                    expires_at: binding.expires_at,
                    issuer_kid: binding.issuer_kid.as_str(),
                    focus_id: participant.focus_id.as_deref().ok_or_else(|| {
                        Error::Protocol("Call participant focus is missing".into())
                    })?,
                    participant_id: participant
                        .participant_id
                        .as_deref()
                        .ok_or_else(|| Error::Protocol("Call participant ID is missing".into()))?,
                    realm_id: realm,
                    media: participant
                        .signed_media()
                        .map_err(|e| Error::Protocol(e.to_string()))?,
                };
                let public = crate::PublicKeyMaterial::Ed25519Raw {
                    bytes: base64url_decode(&key.public_key_base64url)?,
                };
                if !crate::proof::verify_detached_ed25519_signature(
                    &public,
                    &participant_binding_signing_input(&context)?,
                    &binding.signature,
                ) {
                    return Err(Error::Protocol(
                        "Call participant original binding signature differs".into(),
                    ));
                }
            }
            _ => {
                return Err(Error::Protocol(
                    "Call participant historical issuer key is absent or unexpected".into(),
                ));
            }
        }
    }
    Ok(())
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
///   `participant_binding.signature`, `issuer_kid`);
/// - `participant_binding.issuer_kid` resolves to an anchored `ak.realm.media_service.service_id`
///   otherwise `token_issuer_unauthorised`;
/// - the binding's `(realm_id, call_id, focus_id, actor_id, device_id)` six-tuple matches the
///   request and `participant_id` matches the top-level one;
/// - TTL ≤ 600s and not already expired (via [`validate_token_ttl`]);
/// - `participant_binding.signature` verifies as Ed25519(ed25519) signatures over the normative
///   `signing_input` ([`participant_binding_signing_input`]) under the issuer verifying keys in
///   `anchors`. A failed signature or missing key rejects with `token_issuer_unauthorised`. Because
///   the signature covers the nine authoritative fields, tampering with any of them fails
///   verification.
///
/// The caller resolves the media-service service DID document and supplies the
/// `kid -> ed25519 public key` map through [`MediaServiceAnchors::with_keys`] /
/// [`MediaServiceAnchors::insert_key`]; this helper performs no DID resolution.
pub fn verify_call_media_token_outcome(
    request: &CallMediaTokenExchangeRequestBody,
    outcome: &CallMediaTokenExchangeResponseBody,
    anchors: &MediaServiceAnchors,
    now: DateTime<Utc>,
) -> Result<CallMediaTokenVerification> {
    let binding = &outcome.participant_binding;

    if outcome.connect_url.trim().is_empty()
        || matches!(&outcome.backend_token, MediaBackendToken::Opaque(token) if token.trim().is_empty())
        || outcome.participant_id.trim().is_empty()
        || binding.signature.trim().is_empty()
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
    // single issuer assertion over the nine-field tuple signing_input. A failing
    // signature — or a key the anchors do not publish — is
    // `token_issuer_unauthorised`.
    let signing_input =
        participant_binding_signing_input(&ParticipantBindingContext::from_outcome(outcome))?;
    verify_issuer_signature(
        anchors,
        &binding.issuer_kid,
        &binding.signature,
        &signing_input,
        "participant_binding",
    )?;

    if outcome.media != request.invitation_media() {
        return Err(Error::Protocol(
            "participant_binding_invalid: signed issued media differs from the request".to_owned(),
        ));
    }

    Ok(CallMediaTokenVerification {
        issuer_did: Did::new(issuer_did.to_owned())?,
        participant_id: outcome.participant_id.clone(),
    })
}

#[cfg(test)]
#[path = "media/tests.rs"]
mod tests;
