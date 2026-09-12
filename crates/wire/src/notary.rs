//! Closed Realm notary configuration and frozen signer descriptors.

use serde::{Deserialize, Serialize};

use crate::{ActorId, Did, DidUrl, Hash, Result, WireError};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotaryKeyKind {
    Ed25519Raw32,
    P256Sec1Compressed33,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotaryJoseAlgorithm {
    Ed25519,
    ES256,
}

impl NotaryJoseAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::ES256 => "ES256",
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarySignerDescriptor {
    pub actor_id: ActorId,
    pub verification_method: DidUrl,
    pub key_kind: NotaryKeyKind,
    pub jose_algorithm: NotaryJoseAlgorithm,
    pub frozen_public_key_b64u: String,
    pub frozen_public_key_digest: Hash,
}

impl NotarySignerDescriptor {
    pub fn validate(&self) -> Result<()> {
        let controller = self
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| {
                WireError::Protocol("notary verification_method has no fragment".to_owned())
            })?;
        let controller = Did::new(controller.to_owned())?;
        if crate::project_did_to_core_id(&controller)? != *self.actor_id.signing_principal_id() {
            return Err(WireError::Protocol(
                "notary verification_method controller does not match actor_id".to_owned(),
            ));
        }
        let (expected_algorithm, expected_len) = match self.key_kind {
            NotaryKeyKind::Ed25519Raw32 => (NotaryJoseAlgorithm::Ed25519, 43),
            NotaryKeyKind::P256Sec1Compressed33 => (NotaryJoseAlgorithm::ES256, 44),
        };
        if self.jose_algorithm != expected_algorithm {
            return Err(WireError::Protocol(
                "notary signer key_kind and jose_algorithm do not match".to_owned(),
            ));
        }
        if self.frozen_public_key_b64u.len() != expected_len
            || !self
                .frozen_public_key_b64u
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(WireError::Protocol(
                "notary signer frozen_public_key_b64u has invalid canonical length or alphabet"
                    .to_owned(),
            ));
        }
        if !self
            .frozen_public_key_digest
            .as_ref()
            .starts_with("sha256:")
        {
            return Err(WireError::Protocol(
                "notary signer frozen_public_key_digest must use sha256".to_owned(),
            ));
        }
        let public_key = crate::base64url::base64url_decode(&self.frozen_public_key_b64u)
            .map_err(|error| WireError::Protocol(format!("invalid frozen notary key: {error}")))?;
        let expected_decoded_len = match self.key_kind {
            NotaryKeyKind::Ed25519Raw32 => 32,
            NotaryKeyKind::P256Sec1Compressed33 => 33,
        };
        if crate::base64url::base64url_encode(&public_key) != self.frozen_public_key_b64u
            || public_key.len() != expected_decoded_len
            || (!matches!(self.key_kind, NotaryKeyKind::Ed25519Raw32)
                && !public_key
                    .first()
                    .is_some_and(|byte| matches!(*byte, 0x02 | 0x03)))
        {
            return Err(WireError::Protocol(
                "notary signer frozen public key has invalid encoded key shape".to_owned(),
            ));
        }
        let expected_digest = Hash::new(crate::canonical::sha256_digest(public_key))?;
        if self.frozen_public_key_digest != expected_digest {
            return Err(WireError::Protocol(
                "notary signer frozen_public_key_digest does not match frozen_public_key_b64u"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryValue {
    pub signer: NotarySignerDescriptor,
    pub max_clock_error_ms: u32,
}

impl NotaryValue {
    pub fn new(signer: NotarySignerDescriptor, max_clock_error_ms: u32) -> Result<Self> {
        let value = Self {
            signer,
            max_clock_error_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_clock_error_ms > 60_000 {
            return Err(WireError::Protocol(
                "notary max_clock_error_ms exceeds 60000".to_owned(),
            ));
        }
        self.signer.validate()
    }

    pub fn signer_descriptor(
        &self,
        verification_method: &DidUrl,
    ) -> Option<&NotarySignerDescriptor> {
        (&self.signer.verification_method == verification_method).then_some(&self.signer)
    }
}
