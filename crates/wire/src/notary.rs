//! Closed Realm notary configuration and frozen signer descriptors.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{ActorId, Did, DidCoreId, DidUrl, Hash, Result, WireError};

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
        recovery_signers: Vec<NotarySignerDescriptor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controller_organization_id: Option<DidCoreId>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        recovery_controller_organization_ids: Vec<DidCoreId>,
    },
    Threshold {
        signers: Vec<NotarySignerDescriptor>,
        threshold: u32,
        forensic_attribution: ForensicAttribution,
    },
    OpenSet {
        signers: Vec<NotarySignerDescriptor>,
    },
    Mixed {
        signer: NotarySignerDescriptor,
        recovery_signers: Vec<NotarySignerDescriptor>,
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
            recovery_signers: Vec::new(),
            controller_organization_id: None,
            recovery_controller_organization_ids: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let (primary, recovery) = match self {
            Self::SingleSigner {
                signer,
                recovery_signers,
                controller_organization_id,
                recovery_controller_organization_ids,
            } => {
                if controller_organization_id.is_some()
                    && (recovery_signers.is_empty()
                        || recovery_controller_organization_ids.is_empty())
                {
                    return Err(WireError::Protocol(
                        "organization-controlled single_signer requires recovery members and recovery controller organizations"
                            .to_owned(),
                    ));
                }
                validate_unique_organizations(recovery_controller_organization_ids)?;
                (std::slice::from_ref(signer), recovery_signers.as_slice())
            }
            Self::Threshold {
                signers,
                threshold,
                forensic_attribution,
            } => {
                if signers.is_empty() || *threshold == 0 || *threshold as usize > signers.len() {
                    return Err(WireError::Protocol(
                        "threshold notary requires 1 <= threshold <= members.len()".to_owned(),
                    ));
                }
                let intersection = 2 * (*threshold as usize) > signers.len();
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
                (signers.as_slice(), &[][..])
            }
            Self::OpenSet { signers } => {
                if signers.is_empty() {
                    return Err(WireError::Protocol(
                        "open_set notary requires at least one member".to_owned(),
                    ));
                }
                (signers.as_slice(), &[][..])
            }
            Self::Mixed {
                signer,
                recovery_signers,
                controller_organization_id,
                recovery_controller_organization_ids,
            } => {
                if recovery_signers.is_empty() {
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
                (std::slice::from_ref(signer), recovery_signers.as_slice())
            }
        };
        validate_descriptor_set(primary, recovery)
    }

    /// Whether this signer set is the registered recovery set rather than the
    /// primary one.
    ///
    /// The two are not interchangeable: a recovery descriptor only becomes
    /// usable under the closed exceptions in
    /// `event-auth-state-resolution.md` section 6.3 step 2b.
    #[must_use]
    pub fn signers_are_recovery_set(&self, present_signers: &BTreeSet<DidUrl>) -> bool {
        let recovery = match self {
            Self::SingleSigner {
                signer,
                recovery_signers,
                ..
            }
            | Self::Mixed {
                signer,
                recovery_signers,
                ..
            } => {
                if present_signers.len() == 1
                    && present_signers.contains(&signer.verification_method)
                {
                    return false;
                }
                recovery_signers
            }
            Self::Threshold { .. } | Self::OpenSet { .. } => return false,
        };
        !recovery.is_empty()
            && present_signers.len() == recovery.len()
            && present_signers.iter().all(|method| {
                recovery
                    .iter()
                    .any(|member| &member.verification_method == method)
            })
    }

    /// Whether a Seal signed by `present_signers` may cover exactly these
    /// `delta[]` Event kinds.
    ///
    /// A recovery-signed Seal that adjudicates a fork must adjudicate nothing
    /// else. Letting a recovery signer attach an ordinary membership,
    /// capability or policy Move to the same Seal would turn the narrow
    /// fork-resolution exception into a general signing authority
    /// (`event-auth-state-resolution.md` section 6.3 step 2b).
    #[must_use]
    pub fn authorizes_seal_delta(
        &self,
        present_signers: &BTreeSet<DidUrl>,
        delta_kinds: &[crate::EventKind],
    ) -> bool {
        if !self.signers_are_recovery_set(present_signers) {
            return true;
        }
        !delta_kinds.contains(&crate::EventKind::ForkResolution)
            || delta_kinds
                .iter()
                .all(|kind| *kind == crate::EventKind::ForkResolution)
    }

    pub fn proposal_quorum_met(&self, present_signers: &BTreeSet<DidUrl>) -> bool {
        match self {
            Self::SingleSigner { signer, .. } => {
                present_signers.len() == 1 && present_signers.contains(&signer.verification_method)
            }
            Self::Threshold {
                signers, threshold, ..
            } => {
                present_signers.len() >= *threshold as usize
                    && present_signers.iter().all(|method| {
                        signers
                            .iter()
                            .any(|member| &member.verification_method == method)
                    })
            }
            Self::OpenSet { signers } => {
                present_signers.len() == 1
                    && present_signers.iter().all(|method| {
                        signers
                            .iter()
                            .any(|member| &member.verification_method == method)
                    })
            }
            Self::Mixed {
                signer,
                recovery_signers,
                ..
            } => {
                (present_signers.len() == 1
                    && present_signers.contains(&signer.verification_method))
                    || (present_signers.len() == recovery_signers.len()
                        && present_signers.iter().all(|method| {
                            recovery_signers
                                .iter()
                                .any(|member| &member.verification_method == method)
                        }))
            }
        }
    }

    /// Every registered descriptor, primary slots first then recovery slots.
    ///
    /// The two sets are never interchangeable at authorization time, but a
    /// caller that must check a property of the complete configuration - such as
    /// the founding-notary rule that every slot is a `service` actor - has to
    /// see their union.
    pub fn descriptors(&self) -> Vec<&NotarySignerDescriptor> {
        match self {
            Self::SingleSigner {
                signer,
                recovery_signers,
                ..
            }
            | Self::Mixed {
                signer,
                recovery_signers,
                ..
            } => std::iter::once(signer).chain(recovery_signers).collect(),
            Self::Threshold { signers, .. } | Self::OpenSet { signers } => signers.iter().collect(),
        }
    }

    pub fn signer_descriptor(
        &self,
        verification_method: &DidUrl,
    ) -> Option<&NotarySignerDescriptor> {
        match self {
            Self::SingleSigner {
                signer,
                recovery_signers,
                ..
            }
            | Self::Mixed {
                signer,
                recovery_signers,
                ..
            } => (&signer.verification_method == verification_method)
                .then_some(signer)
                .or_else(|| {
                    recovery_signers
                        .iter()
                        .find(|member| &member.verification_method == verification_method)
                }),
            Self::Threshold { signers, .. } | Self::OpenSet { signers } => signers
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::EventKind;

    fn signer() -> NotarySignerDescriptor {
        serde_json::from_value(json!({
            "actor_id": {
                "kind": "service",
                "service_id": "ak:did_core:web:notary.example"
            },
            "verification_method": "did:web:notary.example#notary-key-1",
            "key_kind": "ed25519_raw32",
            "jose_algorithm": "Ed25519",
            "frozen_public_key_b64u": "WnA82IwABQeTR4DCdDNIbwpCZAbc6nFs1BaTzKuN3Gs",
            "frozen_public_key_digest": "sha256:a6022dfca46e307e79cf859f5c23fbc6487277471d0d5c21bbd5b92286c80c83"
        }))
        .unwrap()
    }

    fn recovery_signer() -> NotarySignerDescriptor {
        serde_json::from_value(json!({
            "actor_id": {
                "kind": "service",
                "service_id": "ak:did_core:web:recovery.example"
            },
            "verification_method": "did:web:recovery.example#recovery-key-1",
            "key_kind": "ed25519_raw32",
            "jose_algorithm": "Ed25519",
            "frozen_public_key_b64u": "MOoNKcCXaSPUUFBH8CxrFcYcMDLTQmpsL6BBpjqTIWs",
            "frozen_public_key_digest": "sha256:2d2e5b0dbb56dcbc75ad6dfef26eb0d75f8b48c34c8fdb6dbba8bce6f5f7b7d7"
        }))
        .unwrap()
    }

    fn mixed_notary() -> NotaryValue {
        NotaryValue::Mixed {
            signer: signer(),
            recovery_signers: vec![recovery_signer()],
            controller_organization_id: None,
            recovery_controller_organization_ids: Vec::new(),
        }
    }

    #[test]
    fn a_recovery_signed_fork_resolution_seal_may_cover_nothing_else() {
        let notary = mixed_notary();
        let primary = BTreeSet::from([signer().verification_method]);
        let recovery = BTreeSet::from([recovery_signer().verification_method]);
        assert!(!notary.signers_are_recovery_set(&primary));
        assert!(notary.signers_are_recovery_set(&recovery));

        // The narrow section 6.3.2 exception is per Seal: a recovery signer that
        // could attach an ordinary Move to a fork-resolution Seal would hold a
        // general signing authority, not a recovery one.
        assert!(notary.authorizes_seal_delta(
            &recovery,
            &[EventKind::ForkResolution, EventKind::ForkResolution]
        ));
        assert!(!notary.authorizes_seal_delta(
            &recovery,
            &[EventKind::ForkResolution, EventKind::MemberState]
        ));

        // Section 9.5 cell recovery keeps its own recovery Seal; the rule closes
        // fork-resolution Seals, it does not forbid every recovery Seal.
        assert!(notary.authorizes_seal_delta(&recovery, &[EventKind::ConflictRecovery]));

        // The primary descriptor is untouched by this rule.
        assert!(notary.authorizes_seal_delta(
            &primary,
            &[EventKind::ForkResolution, EventKind::MemberState]
        ));
    }

    #[test]
    fn open_set_accepts_a_non_empty_descriptor_set() {
        NotaryValue::OpenSet {
            signers: vec![signer()],
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn open_set_rejects_an_empty_descriptor_set() {
        let error = NotaryValue::OpenSet {
            signers: Vec::new(),
        }
        .validate()
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("open_set notary requires at least one member")
        );
    }

    #[test]
    fn notary_value_uses_the_schema_owned_collection_names() {
        let value = serde_json::to_value(NotaryValue::Threshold {
            signers: vec![signer()],
            threshold: 1,
            forensic_attribution: ForensicAttribution::QuorumIntersection,
        })
        .unwrap();

        assert!(value.get("signers").is_some());
        assert_eq!(value.as_object().unwrap().len(), 4);
    }
}
