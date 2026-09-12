//! Closed Realm notary configuration and frozen signer descriptors.

use std::collections::BTreeSet;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotaryKind {
    Quorum,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryValue {
    pub kind: NotaryKind,
    pub signers: Vec<NotarySignerDescriptor>,
    pub fault_tolerance: u32,
    pub max_clock_error_ms: u32,
}

impl NotaryValue {
    pub fn new(
        signers: Vec<NotarySignerDescriptor>,
        fault_tolerance: u32,
        max_clock_error_ms: u32,
    ) -> Result<Self> {
        let value = Self {
            kind: NotaryKind::Quorum,
            signers,
            fault_tolerance,
            max_clock_error_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.signers.is_empty() || self.signers.len() > 256 {
            return Err(WireError::Protocol(
                "quorum notary requires 1..=256 signers".to_owned(),
            ));
        }
        if self.fault_tolerance > 85 || self.signers.len() != 3 * self.fault_tolerance as usize + 1
        {
            return Err(WireError::Protocol(
                "quorum notary requires n = 3 * fault_tolerance + 1".to_owned(),
            ));
        }
        if self.max_clock_error_ms > 60_000 {
            return Err(WireError::Protocol(
                "quorum notary max_clock_error_ms exceeds 60000".to_owned(),
            ));
        }
        validate_descriptor_set(&self.signers)
    }

    #[must_use]
    pub const fn quorum_size(&self) -> usize {
        2 * self.fault_tolerance as usize + 1
    }

    #[must_use]
    pub fn authorizes_seal_delta(
        &self,
        _present_signers: &BTreeSet<DidUrl>,
        _delta_kinds: &[crate::EventKind],
    ) -> bool {
        true
    }

    pub fn proposal_quorum_met(&self, present_signers: &BTreeSet<DidUrl>) -> bool {
        present_signers.len() >= self.quorum_size()
            && present_signers.iter().all(|method| {
                self.signers
                    .iter()
                    .any(|member| &member.verification_method == method)
            })
    }

    /// Every registered descriptor, primary slots first then recovery slots.
    ///
    /// The two sets are never interchangeable at authorization time, but a
    /// caller that must check a property of the complete configuration - such as
    /// the founding-notary rule that every slot is a `service` actor - has to
    /// see their union.
    pub fn descriptors(&self) -> Vec<&NotarySignerDescriptor> {
        self.signers.iter().collect()
    }

    pub fn signer_descriptor(
        &self,
        verification_method: &DidUrl,
    ) -> Option<&NotarySignerDescriptor> {
        self.signers
            .iter()
            .find(|member| &member.verification_method == verification_method)
    }
}

fn validate_descriptor_set(primary: &[NotarySignerDescriptor]) -> Result<()> {
    let mut actors = BTreeSet::new();
    let mut methods = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for descriptor in primary {
        descriptor.validate()?;
        if !actors.insert(descriptor.actor_id.clone())
            || !methods.insert(descriptor.verification_method.clone())
            || !digests.insert(descriptor.frozen_public_key_digest.clone())
        {
            return Err(WireError::Protocol(
                "notary signer descriptors must be unique by actor_id, verification_method, and frozen_public_key_digest"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}
