//! Structured attestation evidence for audited E2EE and audit agents.

use super::*;
/// Attestation chain item format identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AttestationChainFormat {
    X509Der,

    CoseCbor,

    EpidQuote,

    TdxQuote,

    SnpReport,

    Tpm2Quote,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AttestationChainItem {
    pub format: AttestationChainFormat,

    pub bytes_b64u: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
}
/// Platform family identifier for attestation evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AttestationPlatformFamily {
    TeeSgx,

    TeeTdx,

    TeeSevSnp,

    Tpm2,

    HsmPkcs11,

    NitroEnclave,
    /// Conformance-fixture-only — MUST be rejected by deployments declaring
    /// `attested_hardware` assurance.
    SoftwareTestOnly,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AttestationPlatform {
    pub family: AttestationPlatformFamily,

    pub vendor: String,

    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AttestationMeasurement {
    pub code_digest: Hash,

    pub policy_version: String,
    /// Optional REPORTDATA-equivalent that binds the attestation to the
    /// Audit Agent's MLS leaf public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_data: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AttestationKey {
    pub alg: String,

    pub public_key_b64u: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AttestationValidity {
    pub not_before: DateTime<Utc>,

    pub expires_at: DateTime<Utc>,
}
/// Revocation check method for the attestation chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AttestationRevocationMethod {
    SgxPccsCrl,

    TdxPcsCrl,

    Ocsp,

    VendorSpecific,

    NoneSupported,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AttestationRevocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<AttestationRevocationMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_check_before: Option<DateTime<Utc>>,
}
/// Audit purpose declared by this attestation evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AuditPurpose {
    ComplianceLawfulAccess,

    RegulatoryRecordKeeping,

    IncidentInvestigation,

    InternalPolicyAudit,
}
/// `ck.schema.attestation_evidence.v1` structured evidence carrier.
///
/// Used at Audit Agent join time and by the reducer when validating the
/// current audit release-session model (`ck.audit.applet_binding` + audit
/// session lifecycle). The former `ck.audit.epoch_key_destruction` standing
/// audit kind was removed (`removed-event-kinds.json`) and replaced by that
/// model — see `crates/core/src/events/kinds.rs` and
/// zh/crypto-media/audited-e2ee.md §2 (attested_hardware binding).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AttestationEvidence {
    pub evidence_id: String,

    pub audit_agent_principal_id: Did,

    pub service_did: Did,

    pub platform: AttestationPlatform,

    pub measurement: AttestationMeasurement,

    pub attestation_chain: Vec<AttestationChainItem>,

    pub attestation_key: AttestationKey,

    pub verification_method: String,

    pub validity: AttestationValidity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<AttestationRevocation>,

    pub operator_did: Did,

    pub audit_purpose: AuditPurpose,

    pub audit_policy_version_digest: Hash,

    pub created_at: DateTime<Utc>,

    pub proofs: Vec<Value>,
}

impl AttestationEvidence {
    pub const SCHEMA: &'static str = "ak.schema.attestation_evidence.v1";
}
