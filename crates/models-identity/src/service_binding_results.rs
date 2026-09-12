//! Own-Station verified service binding results
//! (`sync/server-trusted-results.md` §5.8 and §5.9).
//!
//! These are two deliberately separate results, not one generic service blob:
//!
//! - the genesis notary binding is a *signing preparation input* for a Realm that does not exist
//!   yet. It has no scope and no validity window, because the descriptors it carries become
//!   immutable historical Seal-signer truth the moment the genesis is accepted.
//! - the media service binding is *Realm scoped*. It is anchored by one joined Realm's currently
//!   accepted `ak.component.realm.media_service.v1` cell and carries a reuse window of at most 300
//!   seconds.
//!
//! Neither result authorizes anything: the caller still authors and signs its
//! own genesis, and media key release, plaintext visibility and backend token
//! checks stay exactly where they were.

use arkret_wire::{
    AccountId, ActorId, Did, DidCoreId, DidUrl, ErrorCode, NotaryValue, RealmId, ReasonCode,
    RequestId, Result, ServiceKind, WireError,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::identity_resolution::ServiceResolutionProjection;

/// Canonical byte budget of either direction of both service binding results.
pub const SERVICE_BINDING_RESULT_MAX_BYTES: usize = 65_536;
/// Upper bound of the media route and signing key reuse window.
pub const MEDIA_SERVICE_BINDING_MAX_REUSE_SECONDS: i64 = 300;

fn binding_error(code: ErrorCode, message: &str) -> WireError {
    WireError::ProtocolCode {
        code,
        message: message.to_owned(),
    }
}

fn binding_bytes(value: &impl Serialize, request: bool) -> Result<()> {
    if arkret_canonical::canonical_json_bytes(value)?.len() > SERVICE_BINDING_RESULT_MAX_BYTES {
        return Err(binding_error(
            if request {
                ErrorCode::PayloadTooLarge
            } else {
                ErrorCode::LimitExceeded
            },
            "service binding result exceeds its canonical byte budget",
        ));
    }
    Ok(())
}

/// Realm purposes whose founding notary is a Station service identity.
///
/// Identity-control genesis (`principal_control`, `agent_control`,
/// `applet_managed_control`) fixes its own signer from accepted identity rules
/// and is deliberately absent from this value space.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisNotaryPurpose {
    Collaboration,
    DirectConversation,
}

/// Body of `ak.self.genesis_notary.read.resolve.v1`
/// (`POST /_arkret/self/genesis-notary/query`).
///
/// No candidate service id, DID or endpoint is accepted from the caller: the
/// account pair is the authenticated session account and its serving Station.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisNotaryRequestBody {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub intended_purpose: GenesisNotaryPurpose,
}

impl GenesisNotaryRequestBody {
    pub fn validate(&self) -> Result<()> {
        binding_bytes(self, true)?;
        self.account_id.validate()
    }
}

/// Success body of `ak.self.genesis_notary.read.resolve.v1`.
///
/// `notary` is copied verbatim into `payload.object.notary`; the caller still
/// authors and signs the `ak.realm.create` Event itself. This result is scoped
/// to the invocation and is not an authorization lease.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisNotaryOutcome {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub intended_purpose: GenesisNotaryPurpose,
    pub notary: NotaryValue,
}

impl GenesisNotaryOutcome {
    pub fn validate(&self) -> Result<()> {
        binding_bytes(self, false)?;
        self.account_id.validate()?;
        self.notary.validate()?;
        if !matches!(self.notary.signer.actor_id, ActorId::Service { .. }) {
            return Err(binding_error(
                ErrorCode::SchemaViolation,
                "a founding notary descriptor for this purpose must be a service actor",
            ));
        }
        Ok(())
    }

    /// Bind the result to the exact request and the purpose the caller is about
    /// to freeze into its genesis. A late result for another creation intent
    /// must never be installed.
    pub fn validate_for_request(&self, request: &GenesisNotaryRequestBody) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id
            || self.account_id != request.account_id
            || self.intended_purpose != request.intended_purpose
        {
            return Err(binding_error(
                ErrorCode::StateMismatch,
                "genesis notary result differs from the exact request, account or purpose",
            ));
        }
        Ok(())
    }
}

/// One accepted assertion-capable Ed25519 signing key of the anchored media
/// service.
///
/// It is public verification material for `participant_binding` and ICE config
/// signatures. It releases no media key and grants no plaintext visibility.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSigningKey {
    pub verification_method: DidUrl,
    pub public_key_b64u: String,
}

impl ServiceSigningKey {
    /// The controller DID of `verification_method`, without its fragment.
    pub fn controller(&self) -> Result<Did> {
        let (controller, _) = self
            .verification_method
            .as_str()
            .split_once('#')
            .ok_or_else(|| {
                binding_error(
                    ErrorCode::SchemaViolation,
                    "service signing key verification_method has no fragment",
                )
            })?;
        Ok(Did::new(controller.to_owned())?)
    }

    pub fn validate(&self) -> Result<()> {
        let decoded = arkret_canonical::base64url::base64url_decode(&self.public_key_b64u)
            .map_err(|_| {
                binding_error(
                    ErrorCode::SchemaViolation,
                    "service signing key is not canonical unpadded base64url",
                )
            })?;
        if decoded.len() != 32
            || arkret_canonical::base64url::base64url_encode(&decoded) != self.public_key_b64u
        {
            return Err(binding_error(
                ErrorCode::SchemaViolation,
                "service signing key must encode exactly 32 Ed25519 public-key bytes",
            ));
        }
        self.controller().map(|_| ())
    }
}

/// Body of `ak.self.media_service_binding.read.resolve.v1`
/// (`POST /_arkret/self/media-service-bindings/query`).
///
/// Caller-supplied service ids, DIDs, base URLs, candidate origins and method
/// evidence are deliberately absent: the service identity comes only from the
/// Realm's currently accepted cell.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaServiceBindingRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
}

impl MediaServiceBindingRequestBody {
    pub fn validate(&self) -> Result<()> {
        binding_bytes(self, true)
    }
}

/// Success body of `ak.self.media_service_binding.read.resolve.v1`.
///
/// It carries no method history evidence, witness record, normalized DID
/// Document, describe body or third-party attestation closure. `expires_at`
/// bounds route and key reuse only; it extends no backend token, TURN
/// credential or participant binding TTL.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaServiceBindingOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub route: ServiceResolutionProjection,
    pub signing_keys: Vec<ServiceSigningKey>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl MediaServiceBindingOutcome {
    pub fn validate(&self) -> Result<()> {
        binding_bytes(self, false)?;
        self.route.validate()?;
        if self.route.service_kind != ServiceKind::MediaService.as_str() {
            return Err(binding_error(
                ErrorCode::SchemaViolation,
                "media service binding route must project the media_service kind",
            ));
        }
        if self.signing_keys.is_empty() || self.signing_keys.len() > 16 {
            return Err(binding_error(
                ErrorCode::SchemaViolation,
                "media service binding carries 1..16 signing keys and is never truncated",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for key in &self.signing_keys {
            key.validate()?;
            if !seen.insert(&key.verification_method) {
                return Err(binding_error(
                    ErrorCode::SchemaViolation,
                    "media service binding signing keys must be unique by verification_method",
                ));
            }
            if key.controller()? != self.route.did {
                return Err(binding_error(
                    ErrorCode::SchemaViolation,
                    "media service signing key is controlled by another DID than the route",
                ));
            }
        }
        if self.expires_at <= self.observed_at
            || self.expires_at - self.observed_at
                > Duration::seconds(MEDIA_SERVICE_BINDING_MAX_REUSE_SECONDS)
        {
            return Err(binding_error(
                ErrorCode::SchemaViolation,
                "media service binding reuse window must be positive and at most 300 seconds",
            ));
        }
        Ok(())
    }

    /// Bind the result to the exact request, then to the media service the
    /// caller has already installed from the Realm cell.
    ///
    /// A route whose `service_id` differs from the accepted cell value is
    /// fail-closed: the caller must not adopt it.
    pub fn validate_for_request(
        &self,
        request: &MediaServiceBindingRequestBody,
        accepted_service_id: &DidCoreId,
    ) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id || self.realm_id != request.realm_id {
            return Err(binding_error(
                ErrorCode::StateMismatch,
                "media service binding result differs from the exact request or Realm",
            ));
        }
        if &self.route.service_id != accepted_service_id {
            // Fail closed under the registered reason code rather than adopting
            // a route the Realm cell does not currently anchor.
            return Err(binding_error(
                ErrorCode::StateMismatch,
                &format!(
                    "{}: media service binding route is not the currently accepted media service",
                    ReasonCode::MEDIA_SERVICE_BINDING_UNCOVERED
                ),
            ));
        }
        Ok(())
    }

    /// Whether the route and signing keys may still be reused at `now`.
    #[must_use]
    pub fn is_reusable_at(&self, now: DateTime<Utc>) -> bool {
        self.observed_at <= now && now < self.expires_at
    }

    /// Whether an issued token or ICE config signature `kid` is one of the
    /// service keys this result anchors.
    #[must_use]
    pub fn anchors_issuer(&self, issuer_kid: &DidUrl) -> bool {
        self.signing_keys
            .iter()
            .any(|key| &key.verification_method == issuer_kid)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Hash, NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor};

    use super::*;

    fn account() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn request_id() -> RequestId {
        RequestId::new("ak:request:01970000-0000-7000-8000-000000000041").unwrap()
    }

    fn service_signer() -> NotarySignerDescriptor {
        NotarySignerDescriptor {
            actor_id: ActorId::service(DidCoreId::new("ak:did_core:web:notary.example").unwrap()),
            verification_method: DidUrl::new("did:web:notary.example#notary-key-1").unwrap(),
            key_kind: NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: "WnA82IwABQeTR4DCdDNIbwpCZAbc6nFs1BaTzKuN3Gs".to_owned(),
            frozen_public_key_digest: Hash::new(
                "sha256:a6022dfca46e307e79cf859f5c23fbc6487277471d0d5c21bbd5b92286c80c83",
            )
            .unwrap(),
        }
    }

    fn notary_outcome() -> GenesisNotaryOutcome {
        GenesisNotaryOutcome {
            request_id: request_id(),
            account_id: account(),
            intended_purpose: GenesisNotaryPurpose::Collaboration,
            notary: NotaryValue::new(service_signer(), 0).unwrap(),
        }
    }

    #[test]
    fn genesis_notary_binds_the_exact_request_and_purpose() {
        let request = GenesisNotaryRequestBody {
            request_id: request_id(),
            account_id: account(),
            intended_purpose: GenesisNotaryPurpose::Collaboration,
        };
        let outcome = notary_outcome();
        outcome.validate_for_request(&request).unwrap();

        let other_purpose = GenesisNotaryRequestBody {
            intended_purpose: GenesisNotaryPurpose::DirectConversation,
            ..request
        };
        assert!(outcome.validate_for_request(&other_purpose).is_err());
    }

    #[test]
    fn genesis_notary_rejects_a_non_service_founding_signer() {
        let mut outcome = notary_outcome();
        let mut signer = service_signer();
        signer.actor_id = ActorId::account(account());
        signer.verification_method = DidUrl::new("did:web:alice.example#notary-key-1").unwrap();
        outcome.notary = NotaryValue::new(signer, 0).unwrap();
        assert!(outcome.validate().is_err());
    }

    fn media_outcome() -> MediaServiceBindingOutcome {
        MediaServiceBindingOutcome {
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000042").unwrap(),
            realm_id: RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5")
                .unwrap(),
            route: ServiceResolutionProjection {
                service_id: DidCoreId::new("ak:did_core:web:media.example").unwrap(),
                service_kind: ServiceKind::MediaService.as_str().to_owned(),
                did: Did::new("did:web:media.example").unwrap(),
                method_history_head: format!("sha256:{}", "11".repeat(32)),
                version_id: "1-abc".to_owned(),
                resolution_event_ref: format!("did-web-document-sha256:{}", "11".repeat(32)),
                base_url: "https://media.example/".to_owned(),
            },
            signing_keys: vec![ServiceSigningKey {
                verification_method: DidUrl::new("did:web:media.example#media-key-1").unwrap(),
                public_key_b64u: "WnA82IwABQeTR4DCdDNIbwpCZAbc6nFs1BaTzKuN3Gs".to_owned(),
            }],
            observed_at: "2026-09-10T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-09-10T00:05:00.000Z".parse().unwrap(),
        }
    }

    #[test]
    fn media_binding_accepts_a_complete_result_and_bounds_its_window() {
        let outcome = media_outcome();
        outcome.validate().unwrap();
        assert!(outcome.is_reusable_at("2026-09-10T00:04:59.000Z".parse().unwrap()));
        assert!(!outcome.is_reusable_at("2026-09-10T00:05:00.000Z".parse().unwrap()));
        assert!(outcome.anchors_issuer(&DidUrl::new("did:web:media.example#media-key-1").unwrap()));
        assert!(!outcome.anchors_issuer(&DidUrl::new("did:web:media.example#other").unwrap()));

        let mut too_long = media_outcome();
        too_long.expires_at = "2026-09-10T00:05:01.000Z".parse().unwrap();
        assert!(too_long.validate().is_err());
    }

    #[test]
    fn media_binding_rejects_a_signing_key_controlled_by_another_did() {
        let mut outcome = media_outcome();
        outcome.signing_keys[0].verification_method =
            DidUrl::new("did:web:attacker.example#media-key-1").unwrap();
        assert!(outcome.validate().is_err());
    }

    #[test]
    fn media_binding_fails_closed_against_a_different_accepted_service() {
        let outcome = media_outcome();
        let request = MediaServiceBindingRequestBody {
            request_id: outcome.request_id.clone(),
            realm_id: outcome.realm_id.clone(),
        };
        outcome
            .validate_for_request(
                &request,
                &DidCoreId::new("ak:did_core:web:media.example").unwrap(),
            )
            .unwrap();
        let error = outcome
            .validate_for_request(
                &request,
                &DidCoreId::new("ak:did_core:web:other-media.example").unwrap(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("accepted media service"));
    }
}
