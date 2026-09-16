//! Closed Realm authority-signer configuration and frozen signer descriptors.
//!
//! The Realm authority is the governance Station that signs `RealmCommit`; a
//! closed Realm freezes its single verification method and public key here so
//! no key rotation can widen the accepted signer set.

use serde::{Deserialize, Serialize};

use crate::{ActorId, Did, DidUrl, Hash, Result, WireError};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmAuthoritySignerKeyKind {
    Ed25519Raw32,
    P256Sec1Compressed33,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RealmAuthorityJoseAlgorithm {
    Ed25519,
    ES256,
}

impl RealmAuthorityJoseAlgorithm {
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
pub struct RealmAuthoritySignerDescriptor {
    pub actor_id: ActorId,
    pub verification_method: DidUrl,
    pub key_kind: RealmAuthoritySignerKeyKind,
    pub jose_algorithm: RealmAuthorityJoseAlgorithm,
    pub frozen_public_key_b64u: String,
}

impl RealmAuthoritySignerDescriptor {
    /// Local fingerprint derived from the sole frozen public key bytes.
    pub fn frozen_public_key_digest(&self) -> Result<Hash> {
        self.validate()?;
        let bytes =
            crate::base64url::base64url_decode(&self.frozen_public_key_b64u).map_err(|error| {
                WireError::Protocol(format!(
                    "invalid frozen realm-authority signer key: {error}"
                ))
            })?;
        Ok(Hash::new(crate::canonical::sha256_digest(bytes))?)
    }

    pub fn validate(&self) -> Result<()> {
        let controller = self
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| {
                WireError::Protocol(
                    "realm-authority signer verification_method has no fragment".to_owned(),
                )
            })?;
        let controller = Did::new(controller.to_owned())?;
        if crate::project_did_to_core_id(&controller)? != *self.actor_id.signing_principal_id() {
            return Err(WireError::Protocol(
                "realm-authority signer verification_method controller does not match actor_id"
                    .to_owned(),
            ));
        }
        let (expected_algorithm, expected_len) = match self.key_kind {
            RealmAuthoritySignerKeyKind::Ed25519Raw32 => (RealmAuthorityJoseAlgorithm::Ed25519, 43),
            RealmAuthoritySignerKeyKind::P256Sec1Compressed33 => {
                (RealmAuthorityJoseAlgorithm::ES256, 44)
            }
        };
        if self.jose_algorithm != expected_algorithm {
            return Err(WireError::Protocol(
                "realm-authority signer key_kind and jose_algorithm do not match".to_owned(),
            ));
        }
        if self.frozen_public_key_b64u.len() != expected_len
            || !self
                .frozen_public_key_b64u
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(WireError::Protocol(
                "realm-authority signer frozen_public_key_b64u has invalid canonical length or alphabet"
                    .to_owned(),
            ));
        }
        let public_key =
            crate::base64url::base64url_decode(&self.frozen_public_key_b64u).map_err(|error| {
                WireError::Protocol(format!(
                    "invalid frozen realm-authority signer key: {error}"
                ))
            })?;
        let expected_decoded_len = match self.key_kind {
            RealmAuthoritySignerKeyKind::Ed25519Raw32 => 32,
            RealmAuthoritySignerKeyKind::P256Sec1Compressed33 => 33,
        };
        if crate::base64url::base64url_encode(&public_key) != self.frozen_public_key_b64u
            || public_key.len() != expected_decoded_len
            || (!matches!(self.key_kind, RealmAuthoritySignerKeyKind::Ed25519Raw32)
                && !public_key
                    .first()
                    .is_some_and(|byte| matches!(*byte, 0x02 | 0x03)))
        {
            return Err(WireError::Protocol(
                "realm-authority signer frozen public key has invalid encoded key shape".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthoritySignerValue {
    pub signer: RealmAuthoritySignerDescriptor,
    pub max_clock_error_ms: u32,
}

impl RealmAuthoritySignerValue {
    pub fn new(signer: RealmAuthoritySignerDescriptor, max_clock_error_ms: u32) -> Result<Self> {
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
                "realm-authority signer max_clock_error_ms exceeds 60000".to_owned(),
            ));
        }
        self.signer.validate()
    }

    pub fn signer_descriptor(
        &self,
        verification_method: &DidUrl,
    ) -> Option<&RealmAuthoritySignerDescriptor> {
        (&self.signer.verification_method == verification_method).then_some(&self.signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_key_fingerprint_is_derived_and_rejected_as_wire_input() {
        let key = [7_u8; 32];
        let descriptor = RealmAuthoritySignerDescriptor {
            actor_id: ActorId::service(
                crate::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ),
            verification_method: DidUrl::new("did:web:station.example#realm-authority").unwrap(),
            key_kind: RealmAuthoritySignerKeyKind::Ed25519Raw32,
            jose_algorithm: RealmAuthorityJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: crate::base64url::base64url_encode(key),
        };
        descriptor.validate().unwrap();
        assert_eq!(
            descriptor.frozen_public_key_digest().unwrap().as_str(),
            crate::canonical::sha256_digest(key)
        );
        let mut value = serde_json::to_value(&descriptor).unwrap();
        assert!(value.get("frozen_public_key_digest").is_none());
        value["frozen_public_key_digest"] =
            serde_json::to_value(descriptor.frozen_public_key_digest().unwrap()).unwrap();
        assert!(serde_json::from_value::<RealmAuthoritySignerDescriptor>(value).is_err());
    }
}
