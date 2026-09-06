use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, AttestationId, Base64UrlString, DidCoreId, DidUrl, EventId, Hash, NonEmptyString,
    PayloadProof, ProfileId, RealmId, ReasonCode, ReceiptId, Result, SchemaId, TrustDomainId,
    WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Plaintext,
    Audit,
    Erasure,
    Backup,
    #[serde(rename = "e2ee_late_recovery")]
    E2EELateRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPolicyAccessPayload {
    pub realm_id: RealmId,
    pub actor: DidCoreId,
    pub access_kind: AccessKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
}

impl AuditPolicyAccessPayload {
    pub fn validate_minimal(&self) -> Result<()> {
        match (self.access_kind, &self.late_recovery_original_event_id) {
            (AccessKind::E2EELateRecovery, None) => Err(WireError::Protocol("ak.audit.policy_access access_kind=e2ee_late_recovery requires late_recovery_original_event_id (schema_violation)".to_owned())),
            (kind, Some(_)) if !matches!(kind, AccessKind::E2EELateRecovery) => {
                Err(WireError::Protocol("ak.audit.policy_access late_recovery_original_event_id is only valid for access_kind=e2ee_late_recovery (schema_violation)".to_owned()))
            }
            _ => Ok(()),
        }
    }
}

/// Audit assurance class (encryption-and-audit.md §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAssurance {
    AttestedHardware,
    DisclosedPolicy,
}

/// Absolute hard ceiling on the `ak.profile.e2ee_relaxed.v1` send-pause
/// relaxation window, in milliseconds. Round R2/R3 (2026-05-20).
/// Implementations MUST reject any `relaxed_window_ms` exceeding this
/// value with `relaxed_window_exceeds_ceiling`.
pub const ABSOLUTE_HARD_CEILING_MS: u32 = 300_000;

/// Round R2/R3 — validate a relaxed-window value against the absolute hard
/// ceiling. Returns `Err(ReasonCode::RELAXED_WINDOW_EXCEEDS_CEILING)` when
/// `ms > ABSOLUTE_HARD_CEILING_MS`.
pub fn validate_relaxed_window_ms(ms: u32) -> std::result::Result<(), &'static str> {
    if ms > ABSOLUTE_HARD_CEILING_MS {
        return Err(ReasonCode::RELAXED_WINDOW_EXCEEDS_CEILING);
    }
    Ok(())
}

impl AuditAssurance {
    pub fn profile_id(self) -> &'static str {
        match self {
            AuditAssurance::AttestedHardware => ProfileId::ATTESTED_AUDIT_E2EE_V1,
            AuditAssurance::DisclosedPolicy => ProfileId::DISCLOSED_AUDIT_E2EE_V1,
        }
    }
}

/// Issuer role for a Read-Your-Writes audit receipt
/// (`audit-ryw-receipt.schema.json`).
///
/// `events_api` is the originating Events API node; `witness` is an
/// independent log; `peer_node` is another Station replica.
/// Receipt independence is derived from the verified
/// [`AuditRywWitnessAttestation`] rather than a producer-authored class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RywIssuerRole {
    EventsApi,
    Witness,
    PeerNode,
}

/// Per-actor frontier entry referenced by the RYW receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RywActorFrontierEntry {
    pub actor_seq: u64,
    pub event_id: EventId,
}

/// Frontier reference inside an RYW receipt
/// (`audit-ryw-receipt.schema.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RywFrontier {
    pub realm_frontier: Vec<EventId>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        with = "crate::event_sync::actor_sequence_bounds_map"
    )]
    pub actor_frontier: BTreeMap<ActorId, RywActorFrontierEntry>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRywWitnessAttestation {
    pub witnesses: Vec<AuditRywWitness>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRywWitness {
    pub witness_id: DidCoreId,
    pub verification_method: DidUrl,
    pub controlling_organization_id: DidCoreId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub attested_at: Option<DateTime<Utc>>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditRywRecoveryReasonCode {
    #[serde(rename = "late_key_arrival")]
    LateKeyArrival,
}

/// `ak.audit.ryw_receipt` event payload
/// (`audit-ryw-receipt.schema.json`).
///
/// Issued by an Events API node, witness, or peer Station to
/// confirm a `ak.audit.accessed` envelope reached `accepted`. The Audit
/// Agent MUST gate plaintext release on receiving a receipt that meets
/// the Realm's declared `audit_assurance`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRywReceipt {
    pub receipt_id: ReceiptId,
    pub schema: String,
    pub issuer_id: DidCoreId,
    pub issuer_role: RywIssuerRole,
    pub audit_event_id: EventId,
    pub realm_id: RealmId,
    /// REQUIRED trust domain
    /// binding. Mixed into the canonical `audit_policy_version_digest`
    /// 4-tuple so receipts cannot be replayed across deployments.
    pub trust_domain: TrustDomainId,
    pub realm_operator_organization_id: DidCoreId,
    pub audit_actor_id: ActorId,
    pub frontier: RywFrontier,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    pub witness_attestation: AuditRywWitnessAttestation,
    pub audit_assurance_class: AuditAssurance,
    pub audit_policy_version_digest: Hash,
    pub proofs: Vec<PayloadProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_reason_code: Option<AuditRywRecoveryReasonCode>,
}

impl AuditRywReceipt {
    pub const SCHEMA: &'static str = SchemaId::AUDIT_RYW_RECEIPT_V1;
}

/// Attestation platform family (`audit-release-attestation.schema.json`).
///
/// `SoftwareTestOnly` exists for conformance fixtures and is rejected outright
/// by a deployment declaring `attested_hardware`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAttestationPlatformFamily {
    #[serde(rename = "tee_sgx")]
    TeeSgx,
    #[serde(rename = "tee_tdx")]
    TeeTdx,
    #[serde(rename = "tee_sev_snp")]
    TeeSevSnp,
    #[serde(rename = "tpm_2")]
    Tpm2,
    #[serde(rename = "hsm_pkcs11")]
    HsmPkcs11,
    NitroEnclave,
    SoftwareTestOnly,
}

impl AuditAttestationPlatformFamily {
    /// Whether this family may back an `attested_hardware` release at all.
    pub const fn is_hardware_backed(self) -> bool {
        !matches!(self, Self::SoftwareTestOnly)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAttestationPlatform {
    pub family: AuditAttestationPlatformFamily,
    pub vendor: NonEmptyString,
    pub model: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAttestationMeasurement {
    pub code_digest: Hash,
    pub policy_version: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_data: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAttestationChainFormat {
    X509Der,
    CoseCbor,
    EpidQuote,
    TdxQuote,
    SnpReport,
    Tpm2Quote,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAttestationChainEntry {
    pub format: AuditAttestationChainFormat,
    pub bytes_b64u: Base64UrlString,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub issued_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAttestationKeyAlgorithm {
    Ed25519,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAttestationKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub algorithm: AuditAttestationKeyAlgorithm,
    pub public_key_b64u: Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAttestationValidity {
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAttestationRevocationMethod {
    SgxPccsCrl,
    TdxPcsCrl,
    Ocsp,
    VendorSpecific,
    NoneSupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAttestationRevocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<AuditAttestationRevocationMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub last_checked_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub next_check_before: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPurpose {
    ComplianceLawfulAccess,
    RegulatoryRecordKeeping,
    IncidentInvestigation,
    InternalPolicyAudit,
}

/// `ak.schema.audit_release_attestation.v1`
/// (`audit-release-attestation.schema.json`), carried inline on every
/// `ak.audit.release` under an `attested_hardware` binding.
///
/// This is the evidence `audited-e2ee.md` §6 verifies: its trust root,
/// validity window and measurement are checked against the binding's
/// [`AuditAttestationPolicy`] (`audit_release_attestation_invalid`), and its
/// identity fields against the active binding and accepted authorize
/// (`audit_release_attestation_mismatch`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReleaseAttestation {
    pub attestation_id: AttestationId,
    pub realm_id: RealmId,
    pub audit_actor_id: ActorId,
    pub service_id: DidCoreId,
    pub platform: AuditAttestationPlatform,
    pub measurement: AuditAttestationMeasurement,
    pub attestation_chains: Vec<AuditAttestationChainEntry>,
    pub attestation_key: AuditAttestationKey,
    pub verification_method: DidUrl,
    pub validity: AuditAttestationValidity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<AuditAttestationRevocation>,
    pub operator_id: DidCoreId,
    pub audit_purpose: AuditPurpose,
    pub audit_policy_version_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<PayloadProof>,
}

impl AuditReleaseAttestation {
    pub const SCHEMA: &'static str = SchemaId::AUDIT_RELEASE_ATTESTATION_V1;

    /// Longest evidence window `audited-e2ee.md` §6 allows under
    /// `attested_hardware`; Realm policy may cap it lower but never higher.
    pub const MAX_VALIDITY: chrono::TimeDelta = chrono::TimeDelta::days(90);

    /// The chain root is the last entry: leaf, then intermediates, then the
    /// vendor root the Realm's trust root list is compared against.
    pub fn chain_root(&self) -> Option<&AuditAttestationChainEntry> {
        self.attestation_chains.last()
    }

    /// `sha256` over the decoded root certificate bytes, in the digest form
    /// `attestation_policy.trust_root_digests[]` uses.
    pub fn chain_root_digest(&self) -> Result<Hash> {
        let root = self.chain_root().ok_or_else(|| {
            WireError::Protocol("attestation_chains must carry at least the root".to_owned())
        })?;
        let bytes = arkret_canonical::base64url_decode(root.bytes_b64u.as_str())
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        Hash::new(arkret_canonical::sha256_digest(bytes)).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn actors() -> [ActorId; 3] {
        let principal = DidCoreId::new("ak:did_core:web:auditor.example").unwrap();
        [
            ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
            )),
            ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
            )),
            ActorId::service(principal),
        ]
    }

    fn frontier() -> RywFrontier {
        let event_id =
            EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        RywFrontier {
            realm_frontier: vec![event_id.clone()],
            actor_frontier: actors()
                .into_iter()
                .enumerate()
                .map(|(index, actor)| {
                    (
                        actor,
                        RywActorFrontierEntry {
                            actor_seq: index as u64,
                            event_id: event_id.clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn audit_ryw_receipt_and_frontier_preserve_full_actor_schema() {
        let registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
            .unwrap()
            .expect("spec schema registry");
        let digest = format!("sha256:{}", "0".repeat(64));
        let frontier = frontier();
        for actor in actors() {
            let value = json!({
                "receipt_id":"ak:receipt:019a6aa0-0000-7000-8000-000000000000",
                "schema":AuditRywReceipt::SCHEMA,
                "issuer_id":"ak:did_core:web:station-a.example",
                "issuer_role":"events_api",
                "audit_event_id":"ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "realm_id":"ak:realm:Af5xbAMRUJoaDWcTzj2s9sJIxCGFCD2cO1gheRFGhJSi",
                "trust_domain":"ak:trust_domain:fixture",
                "realm_operator_organization_id":"ak:did_core:web:operator.example",
                "audit_actor_id":actor,
                "frontier":frontier,
                "observed_at":"2026-07-22T10:05:00.000Z",
                "witness_attestation":{"witnesses":[{
                    "witness_id":"ak:did_core:web:witness.example",
                    "verification_method":"did:web:witness.example#key-1",
                    "controlling_organization_id":"ak:did_core:web:witness-operator.example"
                }]},
                "audit_assurance_class":"attested_hardware",
                "audit_policy_version_digest":digest,
                "proofs":[{
                    "kind":"detached_jws",
                    "verification_method":"did:web:station-a.example#key-1",
                    "payload_digest":digest,
                    "created_at":"2026-07-22T10:05:00.000Z",
                    "jws":"a..b"
                }]
            });
            registry
                .validate_value(AuditRywReceipt::SCHEMA, &value)
                .unwrap();
            let encoded = serde_json::to_string(&value).unwrap();
            let decoded: AuditRywReceipt = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded.audit_actor_id, actor);
            assert_eq!(decoded.frontier, frontier);
            assert_eq!(decoded.frontier.actor_frontier.len(), 3);
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
            let mut event_proof = value.clone();
            let proof = event_proof["proofs"][0].as_object_mut().unwrap();
            let digest = proof.remove("payload_digest").unwrap();
            proof.insert("event_digest".to_owned(), digest);
            assert!(
                registry
                    .validate_value(AuditRywReceipt::SCHEMA, &event_proof)
                    .is_err()
            );
            assert!(serde_json::from_value::<AuditRywReceipt>(event_proof).is_err());
        }
        let wire = serde_json::to_value(&frontier).unwrap();
        for actor in actors() {
            let key = actor.canonical_key().unwrap();
            assert!(wire["actor_frontier"].get(&key).is_some());
        }
    }

    #[test]
    fn audit_ryw_frontier_rejects_ambiguous_actor_map_keys() {
        let actor = actors().into_iter().next().unwrap();
        let canonical = actor.canonical_key().unwrap();
        let entry =
            r#"{"actor_seq":1,"event_id":"ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let make_wire = |key: &str| {
            format!(
                "{{\"realm_frontier\":[],\"actor_frontier\":{{{}:{entry}}}}}",
                serde_json::to_string(key).unwrap(),
            )
        };
        for key in [
            actor.signing_principal_id().to_string(),
            format!(" {canonical}"),
            serde_json::to_string_pretty(&actor).unwrap(),
            r#"{"kind":"service","kind":"service","service_id":"ak:did_core:web:auditor.example"}"#
                .to_owned(),
            r#"{"kind":"hosted_principal","principal_id":"ak:did_core:web:auditor.example"}"#
                .to_owned(),
        ] {
            assert!(
                serde_json::from_str::<RywFrontier>(&make_wire(&key)).is_err(),
                "{key}"
            );
        }
        let key = serde_json::to_string(&canonical).unwrap();
        let duplicate =
            format!("{{\"realm_frontier\":[],\"actor_frontier\":{{{key}:{entry},{key}:{entry}}}}}");
        assert!(serde_json::from_str::<RywFrontier>(&duplicate).is_err());
        let empty: RywFrontier = serde_json::from_value(json!({"realm_frontier":[]})).unwrap();
        assert!(empty.actor_frontier.is_empty());
        assert_eq!(
            serde_json::to_value(empty).unwrap(),
            json!({"realm_frontier":[]})
        );
    }
}
