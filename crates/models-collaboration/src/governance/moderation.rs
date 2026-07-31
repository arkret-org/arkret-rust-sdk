//! Moderation report wire DTOs.

use std::collections::BTreeMap;

use arkret_wire::constants::MODERATION_REPORT_SCHEMA;
use arkret_wire::{Did, Hash, RealmId, ScopeRef};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::moderation::FrankingProof;

fn now_utc_canonical() -> DateTime<Utc> {
    arkret_canonical::normalize_timestamp_canonical(Utc::now())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModerationEvidencePackage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_digest: Option<Hash>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ModerationReportOutcome {
    pub report_id: String,
    pub status: String,
    /// DIDs the report was routed to. Per
    /// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`
    /// this is an array of DID strings (the schema is closed), matching the
    /// `routed_to | did[]` shape in `content-moderation.md` /
    /// `service-http-binding.md`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_to: Vec<Did>,
}

/// Moderation action (moderation.md §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationAction {
    DenyJoin,
    DenyInvite,
    DenyWrite,
    QuarantineMessage,
    RequireReview,
    RedactOnAccept,
    ShadowCollapse,
}

/// `ak.self.moderation.command.report` request body. Embeds the
/// `FrankingProof` artifacts type owned by `events_payloads::moderation`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ModerationReportRequestBody {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
    pub target_ref: String,
    pub report_reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub evidence_package: Option<ModerationEvidencePackage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<FrankingProof>,
}

/// Moderation report (moderation.md §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModerationReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub report_id: String,
    pub realm_id: RealmId,
    pub target_ref: String,
    pub report_reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<ModerationFrankingProof>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl ModerationReport {
    pub fn new(
        id: impl Into<String>,
        realm_id: RealmId,
        target_ref: impl Into<String>,
        report_reason_code: impl Into<String>,
        reporter: Did,
    ) -> Self {
        Self {
            schema: Some(MODERATION_REPORT_SCHEMA.to_owned()),
            report_id: id.into(),
            realm_id,
            target_ref: target_ref.into(),
            report_reason_code: report_reason_code.into(),
            description: None,
            reporter,
            evidence_refs: Vec::new(),
            franking_proof: None,
            created_at: now_utc_canonical(),
        }
    }
}

/// Moderation franking proof for E2EE content (moderation.md §3.4).
///
/// `franking_tag` MUST be a key-bound MAC of the reported ciphertext that
/// only the reporter could have produced; spec leaves the algorithm open
/// per profile — this struct just carries the wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModerationFrankingProof {
    pub algorithm: String,
    pub franking_tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
}
