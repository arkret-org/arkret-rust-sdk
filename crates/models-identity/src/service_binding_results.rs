//! Own-Station projection of the currently assigned Realm media service.
//!
//! The route is anchored by an exact committed assignment Event and the
//! current Realm-stream revision. It is a bounded routing cache, not a second
//! authority or a portable authorization credential.

use arkret_wire::{
    Did, DidCoreId, DidUrl, ErrorCode, RealmId, ReasonCode, RequestId, Result, ServiceKind,
    WireError,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::identity_resolution::ServiceResolutionProjection;

pub const SERVICE_BINDING_RESULT_MAX_BYTES: usize = 65_536;
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSigningKey {
    pub verification_method: DidUrl,
    pub public_key_base64url: String,
}

impl ServiceSigningKey {
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
        let decoded = arkret_canonical::base64url::base64url_decode(&self.public_key_base64url)
            .map_err(|_| {
                binding_error(
                    ErrorCode::SchemaViolation,
                    "service signing key is not canonical unpadded base64url",
                )
            })?;
        if decoded.len() != 32
            || arkret_canonical::base64url::base64url_encode(&decoded) != self.public_key_base64url
        {
            return Err(binding_error(
                ErrorCode::SchemaViolation,
                "service signing key must encode exactly 32 Ed25519 public-key bytes",
            ));
        }
        self.controller().map(|_| ())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaServiceBindingRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
}

impl MediaServiceBindingRequestBody {
    pub fn validate(&self) -> Result<()> {
        binding_bytes(self, true)?;
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaServiceBindingResponseBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub route: ServiceResolutionProjection,
    pub signing_keys: Vec<ServiceSigningKey>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl MediaServiceBindingResponseBody {
    pub fn validate(&self) -> Result<()> {
        binding_bytes(self, false)?;
        self.route.validate()?;
        if ![
            ServiceKind::Station.as_str(),
            ServiceKind::MediaService.as_str(),
        ]
        .contains(&self.route.service_kind.as_str())
        {
            return Err(binding_error(
                ErrorCode::SchemaViolation,
                "media issuer must retain its verified station or media_service role",
            ));
        }
        if self.signing_keys.is_empty() || self.signing_keys.len() > 16 {
            return Err(binding_error(
                ErrorCode::SchemaViolation,
                "media service binding carries 1..16 signing keys",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for key in &self.signing_keys {
            key.validate()?;
            if !seen.insert(&key.verification_method) || key.controller()? != self.route.did {
                return Err(binding_error(
                    ErrorCode::SchemaViolation,
                    "media service signing keys must be unique and controlled by the route DID",
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
                "media service result differs from the exact request",
            ));
        }
        if &self.route.service_id != accepted_service_id {
            return Err(binding_error(
                ErrorCode::StateMismatch,
                &format!(
                    "{}: media service route is not the currently accepted assignment",
                    ReasonCode::MEDIA_SERVICE_BINDING_UNCOVERED
                ),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn is_reusable_at(&self, now: DateTime<Utc>) -> bool {
        self.observed_at <= now && now < self.expires_at
    }

    #[must_use]
    pub fn anchors_issuer(&self, issuer_kid: &DidUrl) -> bool {
        self.signing_keys
            .iter()
            .any(|key| &key.verification_method == issuer_kid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn media_binding_uses_the_registered_closed_shape_and_actual_issuer_role() {
        let request = MediaServiceBindingRequestBody {
            request_id: RequestId::new_v7_at(1_740_000_000_000),
            realm_id: RealmId::new("ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM")
                .unwrap(),
        };
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire.as_object().unwrap().len(), 2);
        let mut extra = wire;
        extra["account_id"] = serde_json::json!({});
        assert!(serde_json::from_value::<MediaServiceBindingRequestBody>(extra).is_err());
        let did = Did::new("did:web:issuer.example").unwrap();
        let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
        let mut outcome = MediaServiceBindingResponseBody {
            request_id: request.request_id.clone(),
            realm_id: request.realm_id.clone(),
            route: ServiceResolutionProjection {
                service_id: arkret_wire::project_did_to_core_id(&did).unwrap(),
                service_kind: "station".into(),
                did: did.clone(),
                method_history_head: format!("sha256:{}", "1".repeat(64)),
                version_id: "1-fixture".into(),
                resolution_event_ref: format!("did-web-document-sha256:{}", "1".repeat(64)),
                base_url: "https://issuer.example/".into(),
            },
            signing_keys: vec![ServiceSigningKey {
                verification_method: DidUrl::new("did:web:issuer.example#assertion").unwrap(),
                public_key_base64url: arkret_canonical::base64url_encode([7; 32]),
            }],
            observed_at: now,
            expires_at: now + Duration::seconds(300),
        };
        outcome
            .validate_for_request(&request, &outcome.route.service_id)
            .unwrap();
        assert_eq!(
            serde_json::to_value(&outcome)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            6
        );
        for field in ["account_id", "assignment_ref", "revision"] {
            let mut changed = serde_json::to_value(&outcome).unwrap();
            changed[field] = serde_json::json!({});
            assert!(
                serde_json::from_value::<MediaServiceBindingResponseBody>(changed).is_err(),
                "{field}"
            );
        }
        outcome.route.service_kind = "push_gateway".into();
        assert!(outcome.validate().is_err());
        outcome.route.service_kind = "station".into();
        outcome.signing_keys[0].verification_method =
            DidUrl::new("did:web:other.example#assertion").unwrap();
        assert!(outcome.validate().is_err());
    }
}
