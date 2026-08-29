//! Directory HTTP request/outcome DTO counterparts.
//!
//! The private-contact-discovery shapes in this module mirror
//! `directory-operations.schema.json` and deliberately keep validation that
//! depends on the advertised `ServiceDescribe.private_contact_discovery`
//! configuration next to the wire types.

use std::fmt;

use arkret_wire::{BatchId, Result, WireError};
use chrono::{DateTime, Utc};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use serde::{Deserialize, Deserializer, Serialize};
use voprf::{EvaluationElement, Group, Proof, Ristretto255, VoprfClient};

use crate::service_description::{
    PrivateContactDiscovery, PrivateContactDiscoveryCiphersuite,
    PrivateContactDiscoveryHandoffStubsMode, PrivateContactDiscoveryProfile, ServiceDescribe,
};

/// Transparent wrapper over `ServiceDescribe` for
/// `ak.gate.service.read.describe` (Principal Server) Salvo OpenAPI bindings.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerDescribeOutcome(pub ServiceDescribe);

macro_rules! canonical_base64url_wire_string {
    ($name:ident, $validator:ident) => {
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                $validator(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = WireError;

            fn try_from(value: String) -> Result<Self> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn decode_canonical_base64url(value: &str, expected_len: usize, label: &str) -> Result<Vec<u8>> {
    let decoded = arkret_canonical::base64url_decode(value)
        .map_err(|_| WireError::Protocol(format!("{label} must be canonical base64url")))?;
    if decoded.len() != expected_len || arkret_canonical::base64url_encode(&decoded) != value {
        return Err(WireError::Protocol(format!(
            "{label} must encode exactly {expected_len} bytes"
        )));
    }
    Ok(decoded)
}

fn validate_ristretto255_element(value: &str) -> Result<()> {
    let decoded = decode_canonical_base64url(value, 32, "PSI ristretto255 element")?;
    let encoded: [u8; 32] = decoded.try_into().expect("length checked above");
    let point = CompressedRistretto(encoded).decompress().ok_or_else(|| {
        WireError::Protocol("PSI ristretto255 element is not a valid group encoding".to_owned())
    })?;
    if point == curve25519_dalek::RistrettoPoint::identity() {
        return Err(WireError::Protocol(
            "PSI ristretto255 element must not be the identity".to_owned(),
        ));
    }
    Ok(())
}

fn validate_voprf_proof(value: &str) -> Result<()> {
    let decoded = decode_canonical_base64url(value, 64, "PSI VOPRF proof")?;
    let (scalars, remainder) = decoded.as_chunks::<32>();
    debug_assert!(remainder.is_empty());
    for scalar in scalars {
        if !bool::from(Scalar::from_canonical_bytes(*scalar).is_some()) {
            return Err(WireError::Protocol(
                "PSI VOPRF proof contains a non-canonical scalar".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_derived_prefix_16(value: &str) -> Result<()> {
    decode_canonical_base64url(value, 16, "PSI derived prefix").map(|_| ())
}

canonical_base64url_wire_string!(PsiRistretto255Element, validate_ristretto255_element);
canonical_base64url_wire_string!(PsiVoprfProof, validate_voprf_proof);
canonical_base64url_wire_string!(PsiDerivedPrefix16, validate_derived_prefix_16);

/// Validated `sha256:` commitment used by a non-dummy handoff stub.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PsiHandoffStateDigest(String);

impl PsiHandoffStateDigest {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 71
            || !value.starts_with("sha256:")
            || !value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WireError::Protocol(
                "PSI handoff state_digest must be sha256 plus 64 lowercase hex digits".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PsiHandoffStateDigest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// ASCII-SP-only padding used to make a PSI entity body hit its advertised
/// exact byte bucket.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PsiResponsePadding(String);

impl PsiResponsePadding {
    pub const MAX_LEN: usize = 262_144;

    pub fn spaces(count: usize) -> Result<Self> {
        if count > Self::MAX_LEN {
            return Err(WireError::Protocol(
                "PSI response padding exceeds the largest response bucket".to_owned(),
            ));
        }
        Ok(Self(" ".repeat(count)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for PsiResponsePadding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() > Self::MAX_LEN || !value.bytes().all(|byte| byte == b' ') {
            return Err(serde::de::Error::custom(
                "PSI response padding must contain at most 262144 ASCII spaces",
            ));
        }
        Ok(Self(value))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteConsentHandoffKind {
    Invite,
    Consent,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteConsentScope {
    Invite,
    DirectMessage,
    VoiceCall,
    VideoCall,
    Presence,
    Any,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteConsentState {
    GrantActive,
    Revoked,
    NoConsent,
    Unknown,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteConsentNextStep {
    RequestConsent,
    OpenInviteStrand,
    NoAction,
    TryLater,
}

/// Minimal, non-credential handoff metadata permitted beside a PSI match bit.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteConsentHandoffStub {
    pub kind: InviteConsentHandoffKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_scope: Option<InviteConsentScope>,
    pub state: InviteConsentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<PsiHandoffStateDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step: Option<InviteConsentNextStep>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

impl InviteConsentHandoffStub {
    /// The one response-invariant value used for every unmatched or
    /// per-target-denied position when `handoff_stubs_mode="always"`.
    pub fn dummy() -> Self {
        Self {
            kind: InviteConsentHandoffKind::Consent,
            consent_scope: None,
            state: InviteConsentState::Unknown,
            state_digest: None,
            next_step: Some(InviteConsentNextStep::NoAction),
            expires_at: None,
        }
    }
}

fn verify_batched_voprf_proof(
    blinded_elements: &[PsiRistretto255Element],
    evaluated_elements: &[PsiRistretto255Element],
    proof: &PsiVoprfProof,
    public_key: &str,
) -> Result<()> {
    let public_key = decode_canonical_base64url(public_key, 32, "PSI VOPRF public key")?;
    let public_key = Ristretto255::deserialize_elem(&public_key)
        .map_err(|_| WireError::Protocol("invalid PSI VOPRF public key".to_owned()))?;
    let proof_bytes = decode_canonical_base64url(proof.as_str(), 64, "PSI VOPRF proof")?;
    let proof = Proof::<Ristretto255>::deserialize(&proof_bytes)
        .map_err(|_| WireError::Protocol("invalid PSI VOPRF proof encoding".to_owned()))?;

    let clients = blinded_elements
        .iter()
        .map(|element| {
            let element =
                decode_canonical_base64url(element.as_str(), 32, "PSI VOPRF blinded element")?;
            // `VoprfClient` has no public proof-only verifier. Its documented
            // serialization is (blind || blindedElement), and verification is
            // independent of the blind, so scalar one reconstructs exactly the
            // public transcript without retaining the request's secret blind.
            let mut serialized_client = [0_u8; 64];
            serialized_client[0] = 1;
            serialized_client[32..].copy_from_slice(&element);
            VoprfClient::<Ristretto255>::deserialize(&serialized_client)
                .map_err(|_| WireError::Protocol("invalid PSI VOPRF blinded element".to_owned()))
        })
        .collect::<Result<Vec<_>>>()?;
    let evaluations = evaluated_elements
        .iter()
        .map(|element| {
            let element =
                decode_canonical_base64url(element.as_str(), 32, "PSI VOPRF evaluated element")?;
            EvaluationElement::<Ristretto255>::deserialize(&element)
                .map_err(|_| WireError::Protocol("invalid PSI VOPRF evaluated element".to_owned()))
        })
        .collect::<Result<Vec<_>>>()?;
    let dummy_inputs = vec![[0_u8]; clients.len()];

    let _ = VoprfClient::<Ristretto255>::batch_finalize(
        &dummy_inputs,
        &clients,
        &evaluations,
        &proof,
        public_key,
    )
    .map_err(|_| {
        WireError::Protocol(
            "PSI response failed RFC 9497 single batched DLEQ verification".to_owned(),
        )
    })?;
    Ok(())
}

/// Two-round RFC 9497 modeVOPRF request for
/// `ak.find.directory.read.private_contact_discovery.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryPrivateContactDiscoveryRequestBody {
    Blind {
        profile: PrivateContactDiscoveryProfile,
        batch_id: BatchId,
        ciphersuite: PrivateContactDiscoveryCiphersuite,
        key_epoch: u64,
        blinded_elements: Vec<PsiRistretto255Element>,
    },
    Match {
        profile: PrivateContactDiscoveryProfile,
        batch_id: BatchId,
        key_epoch: u64,
        derived_prefixes: Vec<PsiDerivedPrefix16>,
    },
}

impl DirectoryPrivateContactDiscoveryRequestBody {
    pub fn profile(&self) -> PrivateContactDiscoveryProfile {
        match self {
            Self::Blind { profile, .. } | Self::Match { profile, .. } => *profile,
        }
    }

    pub fn batch_id(&self) -> &BatchId {
        match self {
            Self::Blind { batch_id, .. } | Self::Match { batch_id, .. } => batch_id,
        }
    }

    pub fn key_epoch(&self) -> u64 {
        match self {
            Self::Blind { key_epoch, .. } | Self::Match { key_epoch, .. } => *key_epoch,
        }
    }

    pub fn item_count(&self) -> usize {
        match self {
            Self::Blind {
                blinded_elements, ..
            } => blinded_elements.len(),
            Self::Match {
                derived_prefixes, ..
            } => derived_prefixes.len(),
        }
    }

    pub fn validate_against(&self, configuration: &PrivateContactDiscovery) -> Result<()> {
        configuration.validate()?;
        if self.profile() != configuration.profile
            || self.key_epoch() != configuration.key_epoch
            || self.item_count() != usize::from(configuration.batch_item_count)
            || matches!(
                self,
                Self::Blind { ciphersuite, .. } if *ciphersuite != configuration.ciphersuite
            )
        {
            return Err(WireError::Protocol(
                "private-contact-discovery request does not match the advertised configuration"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Fixed-shape response for the corresponding private-discovery round.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryPrivateContactDiscoveryOutcome {
    Blind {
        profile: PrivateContactDiscoveryProfile,
        batch_id: BatchId,
        ciphersuite: PrivateContactDiscoveryCiphersuite,
        key_epoch: u64,
        evaluated_elements: Vec<PsiRistretto255Element>,
        evaluation_proofs: [PsiVoprfProof; 1],
        derived_prefix_bytes: u8,
        padding: PsiResponsePadding,
    },
    Match {
        profile: PrivateContactDiscoveryProfile,
        batch_id: BatchId,
        key_epoch: u64,
        hit_bitmap: Vec<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handoff_stubs: Option<Vec<InviteConsentHandoffStub>>,
        padding: PsiResponsePadding,
    },
}

impl DirectoryPrivateContactDiscoveryOutcome {
    pub fn item_count(&self) -> usize {
        match self {
            Self::Blind {
                evaluated_elements, ..
            } => evaluated_elements.len(),
            Self::Match { hit_bitmap, .. } => hit_bitmap.len(),
        }
    }

    pub fn padding(&self) -> &PsiResponsePadding {
        match self {
            Self::Blind { padding, .. } | Self::Match { padding, .. } => padding,
        }
    }

    fn padding_mut(&mut self) -> &mut PsiResponsePadding {
        match self {
            Self::Blind { padding, .. } | Self::Match { padding, .. } => padding,
        }
    }

    fn response_bucket(&self, configuration: &PrivateContactDiscovery) -> u32 {
        match self {
            Self::Blind { .. } => configuration.blind_response_bucket_bytes,
            Self::Match { .. } => configuration.match_response_bucket_bytes,
        }
    }

    /// Pad this concrete success outcome to the phase's advertised RFC 8785
    /// JCS entity-body bucket.
    ///
    /// This does not attest that Describe selected the smallest legal bucket:
    /// that requires the provider's maximal success projection and every
    /// allowed phase-specific Class B problem projection, which are outside
    /// this models-only success DTO.
    pub fn pad_to_advertised_bucket(
        mut self,
        configuration: &PrivateContactDiscovery,
    ) -> Result<Self> {
        configuration.validate()?;
        *self.padding_mut() = PsiResponsePadding::default();
        let unpadded_len = arkret_canonical::canonical_json_bytes(&self)
            .map_err(|error| WireError::Protocol(format!("cannot encode PSI outcome: {error}")))?
            .len();
        let bucket = self.response_bucket(configuration) as usize;
        let padding_len = bucket.checked_sub(unpadded_len).ok_or_else(|| {
            WireError::Protocol(
                "PSI outcome does not fit the advertised response bucket".to_owned(),
            )
        })?;
        *self.padding_mut() = PsiResponsePadding::spaces(padding_len)?;
        Ok(self)
    }

    pub fn validate_against_request(
        &self,
        request: &DirectoryPrivateContactDiscoveryRequestBody,
        configuration: &PrivateContactDiscovery,
    ) -> Result<()> {
        request.validate_against(configuration)?;
        let common_matches = match (self, request) {
            (
                Self::Blind {
                    profile,
                    batch_id,
                    ciphersuite,
                    key_epoch,
                    evaluated_elements,
                    derived_prefix_bytes,
                    evaluation_proofs,
                    ..
                },
                DirectoryPrivateContactDiscoveryRequestBody::Blind {
                    batch_id: request_batch_id,
                    blinded_elements,
                    ..
                },
            ) => {
                let shape_matches = *profile == configuration.profile
                    && batch_id == request_batch_id
                    && *ciphersuite == configuration.ciphersuite
                    && *key_epoch == configuration.key_epoch
                    && evaluated_elements.len() == blinded_elements.len()
                    && *derived_prefix_bytes == configuration.derived_prefix_bytes;
                if shape_matches {
                    verify_batched_voprf_proof(
                        blinded_elements,
                        evaluated_elements,
                        &evaluation_proofs[0],
                        &configuration.public_key,
                    )?;
                }
                shape_matches
            }
            (
                Self::Match {
                    profile,
                    batch_id,
                    key_epoch,
                    hit_bitmap,
                    handoff_stubs,
                    ..
                },
                DirectoryPrivateContactDiscoveryRequestBody::Match {
                    batch_id: request_batch_id,
                    derived_prefixes,
                    ..
                },
            ) => {
                let handoff_shape_matches = match configuration.handoff_stubs_mode {
                    PrivateContactDiscoveryHandoffStubsMode::Always => {
                        handoff_stubs.as_ref().is_some_and(|stubs| {
                            stubs.len() == hit_bitmap.len()
                                && hit_bitmap.iter().zip(stubs).all(|(hit, stub)| {
                                    *hit || stub == &InviteConsentHandoffStub::dummy()
                                })
                        })
                    }
                    PrivateContactDiscoveryHandoffStubsMode::Never => handoff_stubs.is_none(),
                };
                *profile == configuration.profile
                    && batch_id == request_batch_id
                    && *key_epoch == configuration.key_epoch
                    && hit_bitmap.len() == derived_prefixes.len()
                    && handoff_shape_matches
            }
            _ => false,
        };
        if !common_matches || self.item_count() != usize::from(configuration.batch_item_count) {
            return Err(WireError::Protocol(
                "private-contact-discovery outcome does not match its request/configuration"
                    .to_owned(),
            ));
        }

        let encoded_len = arkret_canonical::canonical_json_bytes(self)
            .map_err(|error| WireError::Protocol(format!("cannot encode PSI outcome: {error}")))?
            .len();
        if encoded_len != self.response_bucket(configuration) as usize {
            return Err(WireError::Protocol(
                "PSI outcome does not have the advertised exact entity-body length".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod private_contact_discovery_tests {
    use serde_json::json;

    use super::*;
    use crate::service_description::{AntiEnumerationDelay, AntiEnumerationDelayDistribution};

    const VALID_POINT: &str = "hj8zDMGhJZ7VpZmKI6z9N_tDUaeTpbPAkLZC3cQ5uUU";

    fn configuration(mode: PrivateContactDiscoveryHandoffStubsMode) -> PrivateContactDiscovery {
        PrivateContactDiscovery::new(
            "yAPizGsF_BUGRUm1kgZZykp3ssym8E9rNXAJM1R2rU4",
            14,
            1,
            mode,
            4096,
            4096,
            3600,
            1,
            86_400,
            AntiEnumerationDelay {
                minimum_ms: 100,
                jitter_ms: 50,
                distribution: AntiEnumerationDelayDistribution::Uniform,
            },
        )
    }

    #[test]
    fn private_contact_request_is_closed_typed_and_configuration_bound() {
        let request: DirectoryPrivateContactDiscoveryRequestBody = serde_json::from_value(json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "blind",
            "batch_id": "ak:batch:01964137-0000-7000-8000-000000000777",
            "ciphersuite": "ristretto255-SHA512",
            "key_epoch": 14,
            "blinded_elements": [VALID_POINT]
        }))
        .expect("current-v1 blind request");
        request
            .validate_against(&configuration(
                PrivateContactDiscoveryHandoffStubsMode::Never,
            ))
            .unwrap();

        let mut old_token = serde_json::to_value(&request).unwrap();
        old_token["ciphersuite"] = json!("OPRF-ristretto255-SHA512");
        assert!(
            serde_json::from_value::<DirectoryPrivateContactDiscoveryRequestBody>(old_token)
                .is_err()
        );

        let mut wrong_count = serde_json::to_value(&request).unwrap();
        wrong_count["blinded_elements"] = json!([VALID_POINT, VALID_POINT]);
        let wrong_count =
            serde_json::from_value::<DirectoryPrivateContactDiscoveryRequestBody>(wrong_count)
                .unwrap();
        assert!(
            wrong_count
                .validate_against(&configuration(
                    PrivateContactDiscoveryHandoffStubsMode::Never
                ))
                .is_err()
        );
    }

    #[test]
    fn exact_padding_and_old_outcome_fields_are_enforced() {
        let request: DirectoryPrivateContactDiscoveryRequestBody = serde_json::from_value(json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "match",
            "batch_id": "ak:batch:01964137-0000-7000-8000-000000000777",
            "key_epoch": 14,
            "derived_prefixes": ["ABEiM0RVZneImaq7zN3u_w"]
        }))
        .unwrap();
        let outcome = DirectoryPrivateContactDiscoveryOutcome::Match {
            profile: PrivateContactDiscoveryProfile::V1,
            batch_id: request.batch_id().clone(),
            key_epoch: 14,
            hit_bitmap: vec![false],
            handoff_stubs: None,
            padding: PsiResponsePadding::default(),
        }
        .pad_to_advertised_bucket(&configuration(
            PrivateContactDiscoveryHandoffStubsMode::Never,
        ))
        .unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&outcome)
                .unwrap()
                .len(),
            4096
        );
        outcome
            .validate_against_request(
                &request,
                &configuration(PrivateContactDiscoveryHandoffStubsMode::Never),
            )
            .unwrap();

        let old_outcome = json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "match",
            "batch_id": "ak:batch:01964137-0000-7000-8000-000000000777",
            "key_epoch": 14,
            "hit_bitmap": [false],
            "padding_count": 4096
        });
        assert!(
            serde_json::from_value::<DirectoryPrivateContactDiscoveryOutcome>(old_outcome).is_err()
        );
    }

    #[test]
    fn ristretto_elements_and_proofs_reject_noncanonical_encodings() {
        assert!(
            PsiRistretto255Element::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err()
        );
        assert!(PsiRistretto255Element::new("not-base64url").is_err());
        assert!(PsiVoprfProof::new(arkret_canonical::base64url_encode([0xff; 64])).is_err());
        assert!(PsiResponsePadding::spaces(PsiResponsePadding::MAX_LEN + 1).is_err());
        assert!(serde_json::from_str::<PsiResponsePadding>("\" x\"").is_err());
    }

    #[test]
    fn state_digest_deserialization_and_unmatched_dummy_are_fail_closed() {
        assert!(
            serde_json::from_str::<PsiHandoffStateDigest>(
                "\"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\""
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<PsiHandoffStateDigest>(
                "\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
            )
            .is_ok()
        );

        let request: DirectoryPrivateContactDiscoveryRequestBody = serde_json::from_value(json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "match",
            "batch_id": "ak:batch:01964137-0000-7000-8000-000000000777",
            "key_epoch": 14,
            "derived_prefixes": ["ABEiM0RVZneImaq7zN3u_w"]
        }))
        .unwrap();
        let mut non_dummy = InviteConsentHandoffStub::dummy();
        non_dummy.kind = InviteConsentHandoffKind::Invite;
        let outcome = DirectoryPrivateContactDiscoveryOutcome::Match {
            profile: PrivateContactDiscoveryProfile::V1,
            batch_id: request.batch_id().clone(),
            key_epoch: 14,
            hit_bitmap: vec![false],
            handoff_stubs: Some(vec![non_dummy]),
            padding: PsiResponsePadding::default(),
        }
        .pad_to_advertised_bucket(&configuration(
            PrivateContactDiscoveryHandoffStubsMode::Always,
        ))
        .unwrap();
        assert!(
            outcome
                .validate_against_request(
                    &request,
                    &configuration(PrivateContactDiscoveryHandoffStubsMode::Always),
                )
                .is_err()
        );
    }
}
