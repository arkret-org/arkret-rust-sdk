//! Moderation event payloads.

use arkret_wire::{
    DidCoreId, DidUrl, EventId, Hash, ObjectRef, RealmId, Result, ScopeRef, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ModerationEvidencePackage {
    pub target_refs: Vec<ObjectRef>,
    pub encryption: String,
    pub recipient_public_key_ref: DidUrl,
    pub encrypted_to_kid: DidUrl,
    pub ciphertext: String,
    pub ciphertext_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_digest: Option<Hash>,
    pub reporter_signature: String,
}

impl ModerationEvidencePackage {
    pub fn validate_for_target(&self, target_ref: &str) -> Result<()> {
        if self.target_refs.len() != 1
            || self.target_refs[0] != target_ref
            || self.encryption.trim().is_empty()
            || self.ciphertext.is_empty()
            || self.reporter_signature.trim().is_empty()
            || self.recipient_public_key_ref != self.encrypted_to_kid
        {
            return Err(WireError::Protocol(
                "moderation evidence does not bind the target and recipient".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Service receipt for one observed Event. Its durable existence is proven by
/// resolving the Event's exact [`arkret_wire::CommittedEventRef`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FrankingProof {
    pub realm_id: RealmId,
    pub event_id: EventId,
    pub received_by: DidCoreId,
    pub verification_method: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub replay_nonce: String,
    pub signature: String,
}

impl FrankingProof {
    pub const SIGNATURE_DOMAIN: &'static str = "ak.franking_proof.signature.v1";

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let unsigned = arkret_canonical::unsigned_value(self, &["signature"])?;
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "context": Self::SIGNATURE_DOMAIN,
            "proof": unsigned,
        }))
        .map_err(Into::into)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionLiftPayload {
    pub target_ref: ObjectRef,
    pub decision_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionPayload {
    pub target_ref: ObjectRef,
    pub decision: String,
    pub issuer_id: DidCoreId,
    pub request_canonical_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationReportPayload {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
    pub target_ref: ObjectRef,
    pub report_reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ModerationReportProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_provider_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_package: Option<ModerationEvidencePackage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<FrankingProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationReportProvenance {
    #[serde(rename = "self")]
    SelfAuthored,
    MimiFacade,
}

impl ModerationReportPayload {
    pub fn validate_self_endpoint(
        &self,
        actor_id: &DidCoreId,
    ) -> std::result::Result<(), &'static str> {
        if actor_id != &self.reporter_id
            || self.provenance == Some(ModerationReportProvenance::MimiFacade)
            || self.source_provider_id.is_some()
        {
            return Err("self moderation report must be directly authored by its reporter");
        }
        Ok(())
    }
}
