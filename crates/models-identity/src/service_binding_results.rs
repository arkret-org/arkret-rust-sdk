//! Own-Station projection of the currently assigned Realm media service.
//!
//! The Station anchors the route in the Realm's accepted current result.
//! The response is a bounded routing cache, not a second
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

impl MediaServiceBindingRequestBody {
    pub fn validate(&self) -> Result<()> {
        binding_bytes(self, true)
    }
}

impl MediaServiceBindingOutcome {
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
                "media issuer route must retain its verified station or media_service kind",
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

include!("generated/service_binding_results_contracts.rs");
