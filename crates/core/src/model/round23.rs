//! Round R2/R3 (2026-05-20, spec 8b7978d) wire-additions.
//!
//! - `EphemeralEnvelope` — broadcast ephemeral signal carrier
//!   (`cx.schema.ephemeral_envelope.v1`); used for `cx.call.signal`,
//!   `cx.presence`, `cx.typing`, `cx.receipt.read`. These MUST NOT enter
//!   reducer state, advance Anchor frontier, or be submitted via
//!   `cx.events.submit`.
//! - `ModerationAppealPayload` — `oneOf` of the four
//!   `cx.moderation.appeal.*` payload variants (submit / review / decision
//!   / close) (`cx.schema.moderation_appeal.v1`).
//! - `AttestationEvidence` — `cx.schema.attestation_evidence.v1` structured
//!   remote-attestation evidence carrier for Audit Agents joining under
//!   `cx.profile.attested_audit.e2ee.v1`.
//! - Updated `CrossSigningResetPayload` carrying `trust_domain` +
//!   `reset_event_id` (Round R2/R3 wire-break: required fields).
//! - `IdentityLinkCacheEntry` carrying `policy_frontier_digest` (Round R2/R3).

use super::*;
use crate::events::{
    MODERATION_APPEAL_CLOSE, MODERATION_APPEAL_DECISION, MODERATION_APPEAL_REVIEW,
    MODERATION_APPEAL_SUBMIT,
};
use crate::{ERROR_CODE_INVALID_PARAM, ERROR_CODE_SCHEMA_VIOLATION};

/// Absolute hard ceiling on `expires_at - sent_at` for an ephemeral signal,
/// in milliseconds. Per `schemas/ephemeral-envelope.schema.json`:
/// "Signals with expires_at > sent_at + 5 minutes MUST be dropped by
/// receivers (`invalid_param`)." Five minutes = 300_000 ms. Round R2/R3.
pub const EPHEMERAL_ABSOLUTE_HARD_CEILING_MS: u32 = 300_000;

/// Broadcast ephemeral envelope (`cx.schema.ephemeral_envelope.v1`).
///
/// Wire shape for the four broadcast ephemeral signal kinds — `cx.presence`,
/// `cx.typing`, `cx.receipt.read`, `cx.call.signal`. Carried on dedicated
/// ephemeral channels (sync subscribe live stream, presence/typing fanout,
/// call signaling channel) and dropped at TTL. Point-to-point to-device
/// signals (`cx.key.verification.*`) use the device message schema instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EphemeralEnvelope {
    /// Ephemeral signal kind. MUST be one of the four broadcast forms.
    pub kind: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Kind-specific signal payload. Schema per kind is defined by the
    /// producing module; MUST NOT carry mutable governance state.
    pub payload: Value,
    /// Optional detached signature over canonical envelope bytes
    /// (excluding `proof` itself). REQUIRED for `cx.call.signal` in E2EE
    /// Realms; RECOMMENDED for `cx.receipt.read`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl EphemeralEnvelope {
    pub const SCHEMA: &'static str = "cx.schema.ephemeral_envelope.v1";

    /// Construct with validation. Rejects:
    /// - non-ephemeral `kind`
    /// - `expires_at - sent_at > EPHEMERAL_ABSOLUTE_HARD_CEILING_MS` (5 min)
    /// - `expires_at <= sent_at`
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: impl Into<String>,
        realm_id: RealmId,
        actor_id: Did,
        device_id: Option<DeviceId>,
        sent_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        payload: Value,
        proof: Option<Value>,
    ) -> Result<Self> {
        let kind = kind.into();
        if !matches!(
            kind.as_str(),
            "cx.call.signal" | "cx.presence" | "cx.typing" | "cx.receipt.read"
        ) {
            return Err(Error::Protocol(format!(
                "ephemeral envelope kind {kind:?} not in {{cx.call.signal, cx.presence, cx.typing, cx.receipt.read}}"
            )));
        }
        if expires_at <= sent_at {
            return Err(Error::Protocol(
                "ephemeral envelope expires_at must be strictly after sent_at".to_owned(),
            ));
        }
        let window_ms = expires_at.signed_duration_since(sent_at).num_milliseconds();
        if window_ms < 0 || (window_ms as u64) > EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64 {
            return Err(Error::Protocol(format!(
                "ephemeral envelope window {window_ms}ms exceeds absolute hard ceiling \
                 {EPHEMERAL_ABSOLUTE_HARD_CEILING_MS}ms ({ERROR_CODE_INVALID_PARAM})"
            )));
        }
        Ok(Self { kind, realm_id, actor_id, device_id, sent_at, expires_at, payload, proof })
    }
}

/// Verdict on a moderation appeal (decision payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum AppealVerdict {
    /// Original decision stands.
    Uphold,
    /// Original decision reversed; MUST be paired in the same Anchor batch
    /// with `cx.moderation.decision.lift` referencing the original decision.
    Overturn,
    /// Original decision adjusted; `modify_decision_ref` MUST point to a new
    /// `cx.moderation.decision` event in the same batch.
    Modify,
}

/// Who may decrypt / read appeal evidence narrative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AppealEvidenceVisibility {
    AppellantOnly,
    ReviewersOnly,
    RealmAdmins,
    RealmMembers,
}

/// `cx.moderation.appeal.submit` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppealSubmitPayload {
    pub appeal_id: TypedAppealId,
    pub realm_id: RealmId,
    pub decision_ref: EventId,
    pub target_ref: String,
    pub appellant: Did,
    pub reason_text_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_visibility: Option<AppealEvidenceVisibility>,
    pub created_at: DateTime<Utc>,
}

/// `cx.moderation.appeal.review` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppealReviewPayload {
    pub appeal_id: TypedAppealId,
    pub reviewer: Did,
    pub reviewed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_ref: Option<String>,
}

/// `cx.moderation.appeal.decision` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppealDecisionPayload {
    pub appeal_id: TypedAppealId,
    pub reviewer: Did,
    pub verdict: AppealVerdict,
    pub reason_text_ref: String,
    /// Required iff `verdict == Modify`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modify_decision_ref: Option<EventId>,
    pub decided_at: DateTime<Utc>,
}

/// `cx.moderation.appeal.close` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppealClosePayload {
    pub appeal_id: TypedAppealId,
    pub closed_at: DateTime<Utc>,
    #[serde(default)]
    pub auto_closed: bool,
}

/// `cx.schema.moderation_appeal.v1` payload — `oneOf` of the four variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum ModerationAppealPayload {
    Submit(AppealSubmitPayload),
    Review(AppealReviewPayload),
    Decision(AppealDecisionPayload),
    Close(AppealClosePayload),
}

impl ModerationAppealPayload {
    pub const SCHEMA: &'static str = "cx.schema.moderation_appeal.v1";

    /// Companion event kind this payload variant is submitted on.
    pub fn event_kind(&self) -> &'static str {
        match self {
            ModerationAppealPayload::Submit(_) => MODERATION_APPEAL_SUBMIT,
            ModerationAppealPayload::Review(_) => MODERATION_APPEAL_REVIEW,
            ModerationAppealPayload::Decision(_) => MODERATION_APPEAL_DECISION,
            ModerationAppealPayload::Close(_) => MODERATION_APPEAL_CLOSE,
        }
    }

    /// Returns the appeal_id this payload refers to.
    pub fn appeal_id(&self) -> &TypedAppealId {
        match self {
            ModerationAppealPayload::Submit(p) => &p.appeal_id,
            ModerationAppealPayload::Review(p) => &p.appeal_id,
            ModerationAppealPayload::Decision(p) => &p.appeal_id,
            ModerationAppealPayload::Close(p) => &p.appeal_id,
        }
    }

    /// Reject `Decision(Uphold/Overturn)` with `modify_decision_ref` set, and
    /// `Decision(Modify)` without `modify_decision_ref`.
    pub fn validate_minimal(&self) -> Result<()> {
        if let ModerationAppealPayload::Decision(p) = self {
            match (p.verdict, &p.modify_decision_ref) {
                (AppealVerdict::Modify, None) => {
                    return Err(Error::Protocol(format!(
                        "moderation appeal decision verdict=modify requires modify_decision_ref \
                         ({ERROR_CODE_SCHEMA_VIOLATION})"
                    )));
                }
                (AppealVerdict::Uphold | AppealVerdict::Overturn, Some(_)) => {
                    return Err(Error::Protocol(format!(
                        "moderation appeal decision verdict={:?} MUST NOT include \
                         modify_decision_ref ({ERROR_CODE_SCHEMA_VIOLATION})",
                        p.verdict
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

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
    pub not_after: DateTime<Utc>,
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

/// `cx.schema.attestation_evidence.v1` structured evidence carrier.
///
/// Used at Audit Agent join time and by the reducer when validating
/// `cx.audit.epoch_key_destruction`. See zh/crypto-media/audited-e2ee.md §2
/// (attested_hardware binding) and §3.1.1.2 (epoch key destruction).
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
    pub const SCHEMA: &'static str = "cx.schema.attestation_evidence.v1";
}

/// Compute the canonical-JSON SHA-256 of the four policy-frontier fields
/// that gate identity link routing. Round R2/R3.
///
/// Used by `IdentityLinkCacheEntry.policy_frontier_digest` to invalidate
/// cached identity-link routing decisions when any of these four governance
/// inputs change. Canonicalisation per RFC 8785 JCS over the JSON object
/// `{disclosure_policy, history_visibility, identity_disclosure_profile,
/// minimal_metadata_mode}`.
pub fn compute_policy_frontier_digest(
    disclosure_policy: &Value,
    history_visibility: &Value,
    identity_disclosure_profile: &Value,
    minimal_metadata_mode: &Value,
) -> Result<[u8; 32]> {
    let canonical = canonical::canonical_json_bytes(&serde_json::json!({
        "disclosure_policy": disclosure_policy,
        "history_visibility": history_visibility,
        "identity_disclosure_profile": identity_disclosure_profile,
        "minimal_metadata_mode": minimal_metadata_mode,
    }))?;
    let digest = Sha256::digest(&canonical);
    Ok(digest.into())
}

/// Cached projection of an identity-link routing decision.
///
/// Round R2/R3 — adds `policy_frontier_digest` so consumers can detect
/// when the four governance inputs (`disclosure_policy`,
/// `history_visibility`, `identity_disclosure_profile`,
/// `minimal_metadata_mode`) have shifted at the policy frontier and the
/// cached link must be re-derived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityLinkCacheEntry {
    pub pairwise_did: Did,
    pub principal_did: Did,
    pub device_id: DeviceId,
    pub space_id: SpaceId,
    pub mls_epoch: u64,
    /// SHA-256 of canonical JSON over the four policy-frontier inputs.
    /// See [`compute_policy_frontier_digest`].
    #[serde(with = "serde_bytes_32_hex")]
    pub policy_frontier_digest: [u8; 32],
    pub effective_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

mod serde_bytes_32_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
    pub fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
        hex.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(D::Error::custom("policy_frontier_digest hex must be 64 chars"));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk).map_err(D::Error::custom)?;
            out[i] = u8::from_str_radix(pair, 16).map_err(D::Error::custom)?;
        }
        Ok(out)
    }
}

/// Round R2/R3 (2026-05-20) — typed payload for `cx.cross_signing.reset`.
///
/// Wire-breaking: `trust_domain` and `reset_event_id` are now required.
/// `trust_domain` enters every proof's canonical transcript so the same
/// proof bytes cannot be replayed from deployment A into deployment B.
/// `reset_event_id` MUST equal the enclosing `Event.event_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CrossSigningResetPayload {
    pub trust_domain: TypedTrustDomainId,
    pub reset_event_id: EventId,
    pub principal_id: Did,
    pub previous_generation: u64,
    pub new_generation: u64,
    pub reset_reason: String,
    /// One of `principal_signing` / `recovery_unlock` / `device_quorum` /
    /// `trusted_recovery_service`. Validated in the proof verification
    /// path (see zh/crypto-media/device-lifecycle.md §14.4).
    pub proof: Value,
    pub issued_at: DateTime<Utc>,
}

impl CrossSigningResetPayload {
    pub const SCHEMA: &'static str = "cx.schema.cross_signing_reset.v1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn realm() -> RealmId {
        RealmId::new("cx:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn did() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    #[test]
    fn ephemeral_envelope_rejects_window_over_ceiling() {
        let now = Utc::now();
        let bad = EphemeralEnvelope::new(
            "cx.presence",
            realm(),
            did(),
            None,
            now,
            now + Duration::milliseconds(EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as i64 + 1),
            serde_json::json!({"status":"online"}),
            None,
        );
        assert!(bad.is_err());
    }

    #[test]
    fn ephemeral_envelope_accepts_window_at_ceiling() {
        let now = Utc::now();
        let ok = EphemeralEnvelope::new(
            "cx.presence",
            realm(),
            did(),
            None,
            now,
            now + Duration::milliseconds(EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as i64),
            serde_json::json!({"status":"online"}),
            None,
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn ephemeral_envelope_rejects_non_ephemeral_kind() {
        let now = Utc::now();
        assert!(
            EphemeralEnvelope::new(
                "cx.message.create",
                realm(),
                did(),
                None,
                now,
                now + Duration::seconds(30),
                serde_json::json!({}),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn moderation_appeal_decision_modify_requires_ref() {
        let p = ModerationAppealPayload::Decision(AppealDecisionPayload {
            appeal_id: TypedAppealId::new("cx:appeal:01904100-0000-7000-8000-000000000001")
                .unwrap(),
            reviewer: did(),
            verdict: AppealVerdict::Modify,
            reason_text_ref: "blob:reason".to_owned(),
            modify_decision_ref: None,
            decided_at: Utc::now(),
        });
        assert!(p.validate_minimal().is_err());
    }

    #[test]
    fn moderation_appeal_decision_uphold_rejects_modify_ref() {
        let p = ModerationAppealPayload::Decision(AppealDecisionPayload {
            appeal_id: TypedAppealId::new("cx:appeal:01904100-0000-7000-8000-000000000001")
                .unwrap(),
            reviewer: did(),
            verdict: AppealVerdict::Uphold,
            reason_text_ref: "blob:reason".to_owned(),
            modify_decision_ref: Some(
                EventId::new("cx:event:01904100-0000-7000-8000-000000000002").unwrap(),
            ),
            decided_at: Utc::now(),
        });
        assert!(p.validate_minimal().is_err());
    }

    #[test]
    fn policy_frontier_digest_is_deterministic() {
        let h1 = compute_policy_frontier_digest(
            &serde_json::json!({"mode": "strict"}),
            &serde_json::json!("members_only"),
            &serde_json::json!({"profile": "default"}),
            &serde_json::json!(false),
        )
        .unwrap();
        let h2 = compute_policy_frontier_digest(
            &serde_json::json!({"mode": "strict"}),
            &serde_json::json!("members_only"),
            &serde_json::json!({"profile": "default"}),
            &serde_json::json!(false),
        )
        .unwrap();
        assert_eq!(h1, h2);
        let h3 = compute_policy_frontier_digest(
            &serde_json::json!({"mode": "strict"}),
            &serde_json::json!("members_only"),
            &serde_json::json!({"profile": "default"}),
            &serde_json::json!(true),
        )
        .unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn trust_domain_id_validates_scope() {
        assert!(TypedTrustDomainId::new("cx:trust_domain:example.net").is_ok());
        assert!(TypedTrustDomainId::new("cx:trust_domain:Example").is_err());
        assert!(TypedTrustDomainId::new("cx:trust_domain:").is_err());
        let too_long = format!("cx:trust_domain:{}", "a".repeat(129));
        assert!(TypedTrustDomainId::new(too_long).is_err());
    }
}
