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
/// `ak.gate.service.read.describe` (Station) Salvo OpenAPI bindings.
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

/// PSI round whose success and Class B responses share one exact entity-body
/// bucket and anti-enumeration delay class.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PsiResponsePhase {
    Blind,
    Match,
}

/// Closed canonical error vocabulary admitted on the PSI Class B surface.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PsiClassBProblemType {
    #[serde(rename = "https://arkret.org/problems/policy_denied")]
    PolicyDenied,
    #[serde(rename = "https://arkret.org/problems/duplicate_conflict")]
    DuplicateConflict,
    #[serde(rename = "https://arkret.org/problems/psi_batch_unavailable")]
    PsiBatchUnavailable,
    #[serde(rename = "https://arkret.org/problems/psi_quota_exhausted")]
    PsiQuotaExhausted,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PsiPaddedProblemTitle {
    #[serde(rename = "Psi quota exhausted")]
    PsiQuotaExhausted,
    #[serde(rename = "Policy denied")]
    PolicyDenied,
    #[serde(rename = "Duplicate conflict")]
    DuplicateConflict,
    #[serde(rename = "Psi batch unavailable")]
    PsiBatchUnavailable,
}

impl PsiClassBProblemType {
    pub const fn status(self) -> u16 {
        match self {
            Self::PolicyDenied => 403,
            Self::DuplicateConflict => 409,
            Self::PsiBatchUnavailable => 410,
            Self::PsiQuotaExhausted => 429,
        }
    }

    pub const fn canonical_title(self) -> &'static str {
        match self {
            Self::PolicyDenied => "Policy denied",
            Self::DuplicateConflict => "Duplicate conflict",
            Self::PsiBatchUnavailable => "Psi batch unavailable",
            Self::PsiQuotaExhausted => "Psi quota exhausted",
        }
    }

    pub const fn title(self) -> PsiPaddedProblemTitle {
        match self {
            Self::PolicyDenied => PsiPaddedProblemTitle::PolicyDenied,
            Self::DuplicateConflict => PsiPaddedProblemTitle::DuplicateConflict,
            Self::PsiBatchUnavailable => PsiPaddedProblemTitle::PsiBatchUnavailable,
            Self::PsiQuotaExhausted => PsiPaddedProblemTitle::PsiQuotaExhausted,
        }
    }

    pub const fn is_allowed_in(self, phase: PsiResponsePhase) -> bool {
        match self {
            Self::PolicyDenied | Self::DuplicateConflict => true,
            Self::PsiBatchUnavailable => matches!(phase, PsiResponsePhase::Match),
            Self::PsiQuotaExhausted => matches!(phase, PsiResponsePhase::Blind),
        }
    }
}

/// Closed RFC 9457 Problem Details body for PSI request-level (Class B)
/// failures. `padding` is the only extension member.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PsiPaddedProblem {
    #[serde(rename = "type")]
    pub problem_type: PsiClassBProblemType,
    pub title: PsiPaddedProblemTitle,
    pub status: u16,
    pub detail: String,
    pub instance: String,
    pub padding: PsiResponsePadding,
}

impl PsiPaddedProblem {
    pub const DETAIL_MAX_CHARS: usize = 256;
    pub const INSTANCE_MAX_CHARS: usize = 128;

    pub fn new(
        problem_type: PsiClassBProblemType,
        detail: impl Into<String>,
        instance: impl Into<String>,
    ) -> Result<Self> {
        let problem = Self {
            problem_type,
            title: problem_type.title(),
            status: problem_type.status(),
            detail: detail.into(),
            instance: instance.into(),
            padding: PsiResponsePadding::default(),
        };
        problem.validate()?;
        Ok(problem)
    }

    pub fn validate(&self) -> Result<()> {
        if self.status != self.problem_type.status()
            || self.title != self.problem_type.title()
            || self.detail.is_empty()
            || self.detail.chars().count() > Self::DETAIL_MAX_CHARS
            || !is_uri_reference(&self.instance)
            || self.instance.chars().count() > Self::INSTANCE_MAX_CHARS
        {
            return Err(WireError::Protocol(
                "invalid PSI Class B RFC 9457 problem".to_owned(),
            ));
        }
        arkret_canonical::canonical_json_bytes(self).map_err(|error| {
            WireError::Protocol(format!(
                "cannot canonically encode PSI Class B problem: {error}"
            ))
        })?;
        Ok(())
    }

    pub fn validate_for_phase(&self, phase: PsiResponsePhase) -> Result<()> {
        self.validate()?;
        if !self.problem_type.is_allowed_in(phase) {
            return Err(WireError::Protocol(
                "PSI Class B problem is not allowed in this response phase".to_owned(),
            ));
        }
        Ok(())
    }

    /// Pad this concrete Class B problem to the phase bucket selected by the
    /// validated Describe configuration.
    pub fn pad_to_advertised_bucket(
        mut self,
        phase: PsiResponsePhase,
        configuration: &PrivateContactDiscovery,
    ) -> Result<Self> {
        configuration.validate()?;
        self.validate_for_phase(phase)?;
        self.padding = PsiResponsePadding::default();
        let unpadded_len = arkret_canonical::canonical_json_bytes(&self)
            .map_err(|error| WireError::Protocol(format!("cannot encode PSI problem: {error}")))?
            .len();
        let bucket = configuration.response_bucket(phase) as usize;
        let padding_len = bucket.checked_sub(unpadded_len).ok_or_else(|| {
            WireError::Protocol(
                "PSI Class B problem does not fit the advertised response bucket".to_owned(),
            )
        })?;
        self.padding = PsiResponsePadding::spaces(padding_len)?;
        Ok(self)
    }

    pub fn validate_for_phase_and_bucket(
        &self,
        phase: PsiResponsePhase,
        configuration: &PrivateContactDiscovery,
    ) -> Result<()> {
        configuration.validate()?;
        self.validate_for_phase(phase)?;
        let encoded_len = arkret_canonical::canonical_json_bytes(self)
            .map_err(|error| WireError::Protocol(format!("cannot encode PSI problem: {error}")))?
            .len();
        if encoded_len != configuration.response_bucket(phase) as usize {
            return Err(WireError::Protocol(
                "PSI Class B problem does not have the advertised exact entity-body length"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

fn is_uri_reference(value: &str) -> bool {
    if value.is_empty()
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\')
    {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else if bytes[index].is_ascii_alphanumeric()
            || matches!(
                bytes[index],
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'#'
                    | b'['
                    | b']'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
            )
        {
            index += 1;
        } else {
            return false;
        }
    }
    let base = url::Url::parse("https://arkret.invalid/")
        .expect("hard-coded PSI URI-reference validation base is valid");
    url::Url::options()
        .base_url(Some(&base))
        .parse(value)
        .is_ok()
}

impl<'de> Deserialize<'de> for PsiPaddedProblem {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawPsiPaddedProblem {
            #[serde(rename = "type")]
            problem_type: PsiClassBProblemType,
            title: PsiPaddedProblemTitle,
            status: u16,
            detail: String,
            instance: String,
            padding: PsiResponsePadding,
        }

        let raw = RawPsiPaddedProblem::deserialize(deserializer)?;
        let problem = Self {
            problem_type: raw.problem_type,
            title: raw.title,
            status: raw.status,
            detail: raw.detail,
            instance: raw.instance,
            padding: raw.padding,
        };
        problem.validate().map_err(serde::de::Error::custom)?;
        Ok(problem)
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
                Self::Blind { ciphersuite, .. }
                    if *ciphersuite != PrivateContactDiscovery::CIPHERSUITE
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
                    && *ciphersuite == PrivateContactDiscovery::CIPHERSUITE
                    && *key_epoch == configuration.key_epoch
                    && evaluated_elements.len() == blinded_elements.len()
                    && *derived_prefix_bytes == PrivateContactDiscovery::DERIVED_PREFIX_BYTES;
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

/// Recomputed lower-bound evidence for the two phase-specific PSI response
/// buckets advertised by a concrete Describe configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PsiResponseBucketPlan {
    pub blind_max_unpadded_bytes: usize,
    pub match_max_unpadded_bytes: usize,
    pub blind_bucket_bytes: u32,
    pub match_bucket_bytes: u32,
}

impl PrivateContactDiscovery {
    pub const fn response_bucket(&self, phase: PsiResponsePhase) -> u32 {
        match phase {
            PsiResponsePhase::Blind => self.blind_response_bucket_bytes,
            PsiResponsePhase::Match => self.match_response_bucket_bytes,
        }
    }

    /// Recompute the smallest allowed response bucket from the maximal legal
    /// success and every phase-admitted Class B problem with `padding=""`.
    pub fn required_response_bucket_plan(&self) -> Result<PsiResponseBucketPlan> {
        let blind_success = self.maximal_blind_success_unpadded_bytes()?;
        let match_success = self.maximal_match_success_unpadded_bytes()?;
        let blind_problem = maximal_problem_unpadded_bytes(PsiResponsePhase::Blind)?;
        let match_problem = maximal_problem_unpadded_bytes(PsiResponsePhase::Match)?;
        let blind_max_unpadded_bytes = blind_success.max(blind_problem);
        let match_max_unpadded_bytes = match_success.max(match_problem);
        Ok(PsiResponseBucketPlan {
            blind_max_unpadded_bytes,
            match_max_unpadded_bytes,
            blind_bucket_bytes: smallest_response_bucket(blind_max_unpadded_bytes)?,
            match_bucket_bytes: smallest_response_bucket(match_max_unpadded_bytes)?,
        })
    }

    pub(crate) fn validate_response_bucket_plan(&self) -> Result<()> {
        let plan = self.required_response_bucket_plan()?;
        if self.blind_response_bucket_bytes != plan.blind_bucket_bytes
            || self.match_response_bucket_bytes != plan.match_bucket_bytes
        {
            return Err(WireError::Protocol(format!(
                "private_contact_discovery response buckets are not minimal: expected blind={} match={}",
                plan.blind_bucket_bytes, plan.match_bucket_bytes
            )));
        }
        Ok(())
    }

    fn maximal_blind_success_unpadded_bytes(&self) -> Result<usize> {
        // RFC 9497 Appendix A.1.2.3 modeVOPRF ristretto255-SHA512 KAT
        // encodings. Using validated wire values here prevents the maximal
        // projection from quietly relying on an invalid group element/proof.
        let evaluated_element =
            PsiRistretto255Element::new("qo-gSHZNViOGhnlAL_YQjSUhiE-hOM1_nHZpqaAUJn4")?;
        let evaluation_proof = PsiVoprfProof::new(
            "zCA5EBddeGkn7rROqEcygEeJLd-FkOcjw3IFy3RgCwpatTN8jrTOrgSUws-JUp3PlFcu0mdHPVZ67tarhz3uCA",
        )?;
        let body = serde_json::json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "blind",
            "batch_id": "ak:batch:ffffffff-ffff-7fff-bfff-ffffffffffff",
            "ciphersuite": "ristretto255-SHA512",
            "key_epoch": self.key_epoch,
            "evaluated_elements": vec![evaluated_element.as_str(); usize::from(self.batch_item_count)],
            "evaluation_proofs": [evaluation_proof.as_str()],
            "derived_prefix_bytes": 16,
            "padding": "",
        });
        canonical_value_len(&body, "maximal PSI blind success")
    }

    fn maximal_match_success_unpadded_bytes(&self) -> Result<usize> {
        let mut body = serde_json::json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "match",
            "batch_id": "ak:batch:ffffffff-ffff-7fff-bfff-ffffffffffff",
            "key_epoch": self.key_epoch,
            "hit_bitmap": vec![false; usize::from(self.batch_item_count)],
            "padding": "",
        });
        if self.handoff_stubs_mode == PrivateContactDiscoveryHandoffStubsMode::Always {
            body.as_object_mut()
                .expect("maximal match projection is an object")
                .insert(
                    "hit_bitmap".to_owned(),
                    serde_json::Value::Array(vec![
                        serde_json::Value::Bool(true);
                        usize::from(self.batch_item_count)
                    ]),
                );
            let maximal_stub = serde_json::json!({
                "kind": "consent",
                "consent_scope": "voice_call",
                "state": "grant_active",
                "state_digest": format!("sha256:{}", "f".repeat(64)),
                "next_step": "open_invite_strand",
                "expires_at": "9999-12-31T23:59:59.999Z",
            });
            body.as_object_mut()
                .expect("maximal match projection is an object")
                .insert(
                    "handoff_stubs".to_owned(),
                    serde_json::Value::Array(vec![
                        maximal_stub;
                        usize::from(self.batch_item_count)
                    ]),
                );
        }
        canonical_value_len(&body, "maximal PSI match success")
    }
}

fn maximal_problem_unpadded_bytes(phase: PsiResponsePhase) -> Result<usize> {
    [
        PsiClassBProblemType::PolicyDenied,
        PsiClassBProblemType::DuplicateConflict,
        PsiClassBProblemType::PsiBatchUnavailable,
        PsiClassBProblemType::PsiQuotaExhausted,
    ]
    .into_iter()
    .filter(|problem_type| problem_type.is_allowed_in(phase))
    .map(|problem_type| {
        let problem = PsiPaddedProblem::new(
            problem_type,
            "\u{1}".repeat(PsiPaddedProblem::DETAIL_MAX_CHARS),
            format!(
                "ak:request:{}",
                "a".repeat(PsiPaddedProblem::INSTANCE_MAX_CHARS - "ak:request:".len())
            ),
        )?;
        arkret_canonical::canonical_json_bytes(&problem)
            .map(|body| body.len())
            .map_err(|error| {
                WireError::Protocol(format!("cannot encode maximal PSI problem: {error}"))
            })
    })
    .try_fold(0, |maximum, length| {
        length.map(|length| maximum.max(length))
    })
}

fn canonical_value_len(value: &serde_json::Value, label: &str) -> Result<usize> {
    arkret_canonical::canonical_json_value_bytes(value)
        .map(|body| body.len())
        .map_err(|error| WireError::Protocol(format!("cannot encode {label}: {error}")))
}

fn smallest_response_bucket(unpadded_len: usize) -> Result<u32> {
    PrivateContactDiscovery::RESPONSE_SIZE_BUCKETS_BYTES
        .into_iter()
        .find(|bucket| (*bucket as usize) >= unpadded_len)
        .ok_or_else(|| {
            WireError::Protocol(
                "maximal PSI response does not fit the largest response bucket".to_owned(),
            )
        })
}

#[cfg(test)]
mod private_contact_discovery_tests {
    use serde_json::json;

    use super::*;
    use crate::service_description::AntiEnumerationDelay;

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

    #[test]
    fn class_b_problem_is_closed_phase_bound_and_exactly_padded() {
        let configuration = configuration(PrivateContactDiscoveryHandoffStubsMode::Never);
        let problem = PsiPaddedProblem::new(
            PsiClassBProblemType::PsiQuotaExhausted,
            "psi quota exhausted for this device in the current quota window",
            "ak:request:0196429a-0000-7000-8000-0000000000aa",
        )
        .unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_string(&problem).unwrap(),
            r#"{"detail":"psi quota exhausted for this device in the current quota window","instance":"ak:request:0196429a-0000-7000-8000-0000000000aa","padding":"","status":429,"title":"Psi quota exhausted","type":"https://arkret.org/problems/psi_quota_exhausted"}"#
        );
        assert!(problem.validate_for_phase(PsiResponsePhase::Match).is_err());
        assert!(PsiClassBProblemType::PolicyDenied.is_allowed_in(PsiResponsePhase::Blind));
        assert!(PsiClassBProblemType::PolicyDenied.is_allowed_in(PsiResponsePhase::Match));
        assert!(PsiClassBProblemType::DuplicateConflict.is_allowed_in(PsiResponsePhase::Blind));
        assert!(PsiClassBProblemType::DuplicateConflict.is_allowed_in(PsiResponsePhase::Match));
        assert!(PsiClassBProblemType::PsiQuotaExhausted.is_allowed_in(PsiResponsePhase::Blind));
        assert!(!PsiClassBProblemType::PsiQuotaExhausted.is_allowed_in(PsiResponsePhase::Match));
        assert!(!PsiClassBProblemType::PsiBatchUnavailable.is_allowed_in(PsiResponsePhase::Blind));
        assert!(PsiClassBProblemType::PsiBatchUnavailable.is_allowed_in(PsiResponsePhase::Match));

        let problem = problem
            .pad_to_advertised_bucket(PsiResponsePhase::Blind, &configuration)
            .unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&problem)
                .unwrap()
                .len(),
            4096
        );
        problem
            .validate_for_phase_and_bucket(PsiResponsePhase::Blind, &configuration)
            .unwrap();

        let mismatched_status = json!({
            "type": "https://arkret.org/problems/psi_quota_exhausted",
            "title": "Psi quota exhausted",
            "status": 403,
            "detail": "quota",
            "instance": "ak:request:0196429a-0000-7000-8000-0000000000aa",
            "padding": ""
        });
        assert!(serde_json::from_value::<PsiPaddedProblem>(mismatched_status).is_err());
        let unknown_member = json!({
            "type": "https://arkret.org/problems/policy_denied",
            "title": "Policy denied",
            "status": 403,
            "detail": "policy",
            "instance": "ak:request:0196429a-0000-7000-8000-0000000000aa",
            "padding": "",
            "request_id": "forbidden-fallback"
        });
        assert!(serde_json::from_value::<PsiPaddedProblem>(unknown_member).is_err());
        let mismatched_title = json!({
            "type": "https://arkret.org/problems/policy_denied",
            "title": "Psi quota exhausted",
            "status": 403,
            "detail": "policy",
            "instance": "ak:request:0196429a-0000-7000-8000-0000000000aa",
            "padding": ""
        });
        assert!(serde_json::from_value::<PsiPaddedProblem>(mismatched_title).is_err());
        let invalid_instance = json!({
            "type": "https://arkret.org/problems/policy_denied",
            "title": "Policy denied",
            "status": 403,
            "detail": "policy",
            "instance": "not a URI reference",
            "padding": ""
        });
        assert!(serde_json::from_value::<PsiPaddedProblem>(invalid_instance).is_err());
        for invalid in ["ak:request:%zz", "ak:request:bad|character"] {
            let invalid_instance = json!({
                "type": "https://arkret.org/problems/policy_denied",
                "title": "Policy denied",
                "status": 403,
                "detail": "policy",
                "instance": invalid,
                "padding": ""
            });
            assert!(serde_json::from_value::<PsiPaddedProblem>(invalid_instance).is_err());
        }
        let overlong_detail = json!({
            "type": "https://arkret.org/problems/policy_denied",
            "title": "Policy denied",
            "status": 403,
            "detail": "x".repeat(PsiPaddedProblem::DETAIL_MAX_CHARS + 1),
            "instance": "ak:request:0196429a-0000-7000-8000-0000000000aa",
            "padding": ""
        });
        assert!(serde_json::from_value::<PsiPaddedProblem>(overlong_detail).is_err());
        let overlong_instance = json!({
            "type": "https://arkret.org/problems/policy_denied",
            "title": "Policy denied",
            "status": 403,
            "detail": "policy",
            "instance": format!("ak:request:{}", "a".repeat(118)),
            "padding": ""
        });
        assert!(serde_json::from_value::<PsiPaddedProblem>(overlong_instance).is_err());
    }

    #[test]
    fn maximal_projection_bucket_plan_is_phase_specific_and_minimal() {
        let small = configuration(PrivateContactDiscoveryHandoffStubsMode::Always);
        let small_plan = small.required_response_bucket_plan().unwrap();
        assert_eq!(
            maximal_problem_unpadded_bytes(PsiResponsePhase::Blind).unwrap(),
            1_804
        );
        assert_eq!(
            maximal_problem_unpadded_bytes(PsiResponsePhase::Match).unwrap(),
            1_808
        );
        assert_eq!(small_plan.blind_max_unpadded_bytes, 1_804);
        assert_eq!(small_plan.match_max_unpadded_bytes, 1_808);
        assert_eq!(small_plan.blind_bucket_bytes, 4096);
        assert_eq!(small_plan.match_bucket_bytes, 4096);

        let mut medium = configuration(PrivateContactDiscoveryHandoffStubsMode::Never);
        medium.batch_item_count = 256;
        medium.blind_response_bucket_bytes = 16_384;
        medium.match_response_bucket_bytes = 4_096;
        let medium_plan = medium.required_response_bucket_plan().unwrap();
        assert_eq!(medium_plan.blind_bucket_bytes, 16_384);
        assert_eq!(medium_plan.match_bucket_bytes, 4_096);
        medium.validate().unwrap();

        let mut maximal = configuration(PrivateContactDiscoveryHandoffStubsMode::Always);
        maximal.batch_item_count = 1024;
        maximal.blind_response_bucket_bytes = 65_536;
        maximal.match_response_bucket_bytes = 262_144;
        let maximal_plan = maximal.required_response_bucket_plan().unwrap();
        assert_eq!(maximal_plan.blind_max_unpadded_bytes, 47_448);
        assert_eq!(maximal_plan.match_max_unpadded_bytes, 247_989);
        assert_eq!(maximal_plan.blind_bucket_bytes, 65_536);
        assert_eq!(maximal_plan.match_bucket_bytes, 262_144);
        maximal.validate().unwrap();

        maximal.match_response_bucket_bytes = 65_536;
        assert!(maximal.validate().is_err());
    }
}
