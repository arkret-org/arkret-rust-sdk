//! Structured attestation evidence for audited E2EE and audit agents.

use arkret_wire::{DidCoreId, DidUrl, Hash, Proof, RealmId, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
/// Attestation chain item format identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct AttestationChainItem {
    pub format: AttestationChainFormat,

    pub bytes_b64u: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub issued_at: Option<DateTime<Utc>>,
}
/// Platform family identifier for attestation evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct AttestationPlatform {
    pub family: AttestationPlatformFamily,

    pub vendor: String,

    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationMeasurement {
    pub code_digest: Hash,

    pub policy_version: String,
    /// Optional REPORTDATA-equivalent that binds the attestation to the
    /// Audit Agent's MLS leaf public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_data: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationKey {
    pub algorithm: String,

    pub public_key_b64u: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationValidity {
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,

    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}
/// Revocation check method for the attestation chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRevocationMethod {
    SgxPccsCrl,

    TdxPcsCrl,

    Ocsp,

    VendorSpecific,

    NoneSupported,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRevocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<AttestationRevocationMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub last_checked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub next_check_before: Option<DateTime<Utc>>,
}
/// Audit purpose declared by this attestation evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPurpose {
    ComplianceLawfulAccess,

    RegulatoryRecordKeeping,

    IncidentInvestigation,

    InternalPolicyAudit,
}
/// `ak.schema.audit_release_attestation.v1` structured evidence carrier.
///
/// Used at Audit Agent join time and by the reducer when validating the
/// current audit release-session model (`ak.audit.applet_binding` + audit
/// session lifecycle). The former `ak.audit.epoch_key_destruction` standing
/// audit kind was removed (`removed-event-kinds.json`) and replaced by that
/// model — see `crates/wire/src/generated/event_kinds.rs` and
/// zh/crypto-media/audited-e2ee.md §2 (attested_hardware binding).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReleaseAttestation {
    pub attestation_id: String,

    pub realm_id: RealmId,

    pub audit_service_actor_id: DidCoreId,

    pub service_id: DidCoreId,

    pub platform: AttestationPlatform,

    pub measurement: AttestationMeasurement,

    pub attestation_chain: Vec<AttestationChainItem>,

    pub attestation_key: AttestationKey,

    pub verification_method: DidUrl,

    pub validity: AttestationValidity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<AttestationRevocation>,

    pub operator_principal_id: DidCoreId,

    pub audit_purpose: AuditPurpose,

    pub audit_policy_version_digest: Hash,

    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,

    pub proofs: Vec<Proof>,
}

impl AuditReleaseAttestation {
    pub const SCHEMA: &'static str = SchemaId::AUDIT_RELEASE_ATTESTATION_V1;
}
