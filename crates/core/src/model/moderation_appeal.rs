//! Moderation appeal event payloads.

use super::*;
use crate::ERROR_CODE_SCHEMA_VIOLATION;
use crate::events::{
    MODERATION_APPEAL_CLOSE, MODERATION_APPEAL_DECISION, MODERATION_APPEAL_REVIEW,
    MODERATION_APPEAL_SUBMIT,
};

/// Verdict on a moderation appeal (decision payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AppealVerdict {
    /// Original decision stands.
    Uphold,
    /// Original decision reversed; MUST be paired in the same Anchor batch
    /// with `ck.moderation.decision.lift` referencing the original decision.
    Overturn,
    /// Original decision adjusted; `modify_decision_ref` MUST point to a new
    /// `ck.moderation.decision` event in the same batch.
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

/// `ck.moderation.appeal.submit` payload.
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

/// `ck.moderation.appeal.review` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppealReviewPayload {
    pub appeal_id: TypedAppealId,
    pub reviewer: Did,
    pub reviewed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_ref: Option<String>,
}

/// `ck.moderation.appeal.decision` payload.
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

/// `ck.moderation.appeal.close` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppealClosePayload {
    pub appeal_id: TypedAppealId,
    pub closed_at: DateTime<Utc>,
    #[serde(default)]
    pub auto_closed: bool,
}

/// `ck.schema.moderation_appeal.v1` payload — `oneOf` of the four variants.
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
    pub const SCHEMA: &'static str = "ck.schema.moderation_appeal.v1";

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
