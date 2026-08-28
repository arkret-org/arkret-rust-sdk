//! Closed Realm notary configuration and frozen signer descriptors.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Did, DidCoreId, DidUrl, Hash, Result, WireError};

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
    pub actor_id: DidCoreId,
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
        if crate::project_did_to_core_id(&controller)? != self.actor_id {
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
pub enum ForensicAttribution {
    QuorumIntersection,
    Waived,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NotaryValue {
    SingleSigner {
        signer: NotarySignerDescriptor,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        recovery_notary_signer_descriptors: Vec<NotarySignerDescriptor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controller_organization_id: Option<DidCoreId>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        recovery_controller_organization_ids: Vec<DidCoreId>,
    },
    Threshold {
        notary_signer_descriptors: Vec<NotarySignerDescriptor>,
        threshold: u32,
        forensic_attribution: ForensicAttribution,
    },
    OpenSet {
        notary_signer_descriptors: Vec<NotarySignerDescriptor>,
    },
    Mixed {
        signer: NotarySignerDescriptor,
        recovery_notary_signer_descriptors: Vec<NotarySignerDescriptor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controller_organization_id: Option<DidCoreId>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        recovery_controller_organization_ids: Vec<DidCoreId>,
    },
}

impl NotaryValue {
    pub fn single_signer(signer: NotarySignerDescriptor) -> Self {
        Self::SingleSigner {
            signer,
            recovery_notary_signer_descriptors: Vec::new(),
            controller_organization_id: None,
            recovery_controller_organization_ids: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let (primary, recovery) = match self {
            Self::SingleSigner {
                signer,
                recovery_notary_signer_descriptors,
                controller_organization_id,
                recovery_controller_organization_ids,
            } => {
                if controller_organization_id.is_some()
                    && (recovery_notary_signer_descriptors.is_empty()
                        || recovery_controller_organization_ids.is_empty())
                {
                    return Err(WireError::Protocol(
                        "organization-controlled single_signer requires recovery members and recovery controller organizations"
                            .to_owned(),
                    ));
                }
                validate_unique_organizations(recovery_controller_organization_ids)?;
                (
                    std::slice::from_ref(signer),
                    recovery_notary_signer_descriptors.as_slice(),
                )
            }
            Self::Threshold {
                notary_signer_descriptors,
                threshold,
                forensic_attribution,
            } => {
                if notary_signer_descriptors.is_empty()
                    || *threshold == 0
                    || *threshold as usize > notary_signer_descriptors.len()
                {
                    return Err(WireError::Protocol(
                        "threshold notary requires 1 <= threshold <= members.len()".to_owned(),
                    ));
                }
                let intersection = 2 * (*threshold as usize) > notary_signer_descriptors.len();
                if intersection
                    != matches!(
                        forensic_attribution,
                        ForensicAttribution::QuorumIntersection
                    )
                {
                    return Err(WireError::Protocol(
                        "threshold forensic_attribution does not match quorum arithmetic"
                            .to_owned(),
                    ));
                }
                (notary_signer_descriptors.as_slice(), &[][..])
            }
            Self::OpenSet {
                notary_signer_descriptors,
            } => {
                if notary_signer_descriptors.is_empty() {
                    return Err(WireError::Protocol(
                        "open_set notary requires at least one member".to_owned(),
                    ));
                }
                (notary_signer_descriptors.as_slice(), &[][..])
            }
            Self::Mixed {
                signer,
                recovery_notary_signer_descriptors,
                controller_organization_id,
                recovery_controller_organization_ids,
            } => {
                if recovery_notary_signer_descriptors.is_empty() {
                    return Err(WireError::Protocol(
                        "mixed notary requires at least one recovery member".to_owned(),
                    ));
                }
                if controller_organization_id.is_some()
                    && recovery_controller_organization_ids.is_empty()
                {
                    return Err(WireError::Protocol(
                        "organization-controlled mixed notary requires recovery controller organizations"
                            .to_owned(),
                    ));
                }
                validate_unique_organizations(recovery_controller_organization_ids)?;
                (
                    std::slice::from_ref(signer),
                    recovery_notary_signer_descriptors.as_slice(),
                )
            }
        };
        validate_descriptor_set(primary, recovery)
    }

    pub fn proposal_quorum_met(&self, signers: &BTreeSet<DidUrl>) -> bool {
        match self {
            Self::SingleSigner { signer, .. } => {
                signers.len() == 1 && signers.contains(&signer.verification_method)
            }
            Self::Threshold {
                notary_signer_descriptors,
                threshold,
                ..
            } => {
                signers.len() >= *threshold as usize
                    && signers.iter().all(|method| {
                        notary_signer_descriptors
                            .iter()
                            .any(|member| &member.verification_method == method)
                    })
            }
            Self::OpenSet {
                notary_signer_descriptors,
            } => {
                signers.len() == 1
                    && signers.iter().all(|method| {
                        notary_signer_descriptors
                            .iter()
                            .any(|member| &member.verification_method == method)
                    })
            }
            Self::Mixed {
                signer,
                recovery_notary_signer_descriptors,
                ..
            } => {
                (signers.len() == 1 && signers.contains(&signer.verification_method))
                    || (signers.len() == recovery_notary_signer_descriptors.len()
                        && signers.iter().all(|method| {
                            recovery_notary_signer_descriptors
                                .iter()
                                .any(|member| &member.verification_method == method)
                        }))
            }
        }
    }

    pub fn signer_descriptor(
        &self,
        verification_method: &DidUrl,
    ) -> Option<&NotarySignerDescriptor> {
        match self {
            Self::SingleSigner {
                signer,
                recovery_notary_signer_descriptors,
                ..
            }
            | Self::Mixed {
                signer,
                recovery_notary_signer_descriptors,
                ..
            } => (&signer.verification_method == verification_method)
                .then_some(signer)
                .or_else(|| {
                    recovery_notary_signer_descriptors
                        .iter()
                        .find(|member| &member.verification_method == verification_method)
                }),
            Self::Threshold {
                notary_signer_descriptors,
                ..
            }
            | Self::OpenSet {
                notary_signer_descriptors,
            } => notary_signer_descriptors
                .iter()
                .find(|member| &member.verification_method == verification_method),
        }
    }
}

fn validate_unique_organizations(organizations: &[DidCoreId]) -> Result<()> {
    let mut unique = BTreeSet::new();
    if organizations
        .iter()
        .any(|organization| !unique.insert(organization))
    {
        return Err(WireError::Protocol(
            "notary recovery controller organizations must be unique".to_owned(),
        ));
    }
    Ok(())
}

fn validate_descriptor_set(
    primary: &[NotarySignerDescriptor],
    recovery: &[NotarySignerDescriptor],
) -> Result<()> {
    let mut actors = BTreeSet::new();
    let mut methods = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for descriptor in primary.iter().chain(recovery) {
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
