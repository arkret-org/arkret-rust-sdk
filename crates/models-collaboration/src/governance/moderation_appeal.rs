//! Moderation appeal event payloads.

use arkret_wire::{Did, Error, EventId, EventKind, RealmId, Result, SchemaId, TypedAppealId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
/// Verdict on a moderation appeal (decision payload).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealVerdict {
    /// Original decision stands.
    Uphold,
    /// Original decision reversed; MUST be paired in the same Seal batch
    /// with `ak.moderation.decision.lift` referencing the original decision.
    Overturn,
    /// Original decision adjusted; `modify_decision_ref` MUST point to a new
    /// `ak.moderation.decision` event in the same batch.
    Modify,
}

/// Who may decrypt / read appeal evidence narrative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealEvidenceVisibility {
    AppellantOnly,
    ReviewersOnly,
    RealmAdmins,
    RealmMembers,
}

/// `ak.moderation.appeal.submit` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppealSubmitPayload {
    pub realm_id: RealmId,
    pub decision_ref: EventId,
    pub target_ref: String,
    pub appellant: Did,
    pub reason_text_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_visibility: Option<AppealEvidenceVisibility>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// `ak.moderation.appeal.review` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppealReviewPayload {
    pub appeal_id: TypedAppealId,
    pub realm_id: RealmId,
    pub reviewer: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub reviewed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_ref: Option<String>,
}

/// `ak.moderation.appeal.decision` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppealDecisionPayload {
    pub appeal_id: TypedAppealId,
    pub realm_id: RealmId,
    pub reviewer: Did,
    pub verdict: AppealVerdict,
    pub reason_text_ref: String,
    /// Required iff `verdict == Modify`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modify_decision_ref: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub decided_at: DateTime<Utc>,
}

/// `ak.moderation.appeal.close` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppealClosePayload {
    pub appeal_id: TypedAppealId,
    pub realm_id: RealmId,
    pub closer: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub closed_at: DateTime<Utc>,
    #[serde(default)]
    pub auto_closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
}

/// Closed in-memory union of the four moderation appeal payloads.
///
/// Wire decoding is selected by the event-kind marker and targets the
/// corresponding concrete payload type. The union deliberately has no
/// untagged `Deserialize` implementation, so callers cannot recover the
/// discriminator by trial-deserializing payload shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModerationAppealPayload {
    Submit(AppealSubmitPayload),
    Review(AppealReviewPayload),
    Decision(AppealDecisionPayload),
    Close(AppealClosePayload),
}

impl ModerationAppealPayload {
    pub const SCHEMA: &'static str = SchemaId::MODERATION_APPEAL_V1;
    /// Companion event kind this payload variant is submitted on.
    pub const fn event_kind(&self) -> EventKind {
        match self {
            ModerationAppealPayload::Submit(_) => EventKind::ModerationAppealSubmit,
            ModerationAppealPayload::Review(_) => EventKind::ModerationAppealReview,
            ModerationAppealPayload::Decision(_) => EventKind::ModerationAppealDecision,
            ModerationAppealPayload::Close(_) => EventKind::ModerationAppealClose,
        }
    }

    /// Returns the carried appeal id for a transition targeting an existing
    /// appeal. A submit creates the appeal whose id is
    /// `TypedAppealId::from_event_id(submit_event.event_id)`, so its payload
    /// deliberately carries no `appeal_id`.
    pub fn appeal_id(&self) -> Option<&TypedAppealId> {
        match self {
            ModerationAppealPayload::Submit(_) => None,
            ModerationAppealPayload::Review(p) => Some(&p.appeal_id),
            ModerationAppealPayload::Decision(p) => Some(&p.appeal_id),
            ModerationAppealPayload::Close(p) => Some(&p.appeal_id),
        }
    }

    /// Reject `Decision(Uphold/Overturn)` with `modify_decision_ref` set, and
    /// `Decision(Modify)` without `modify_decision_ref`.
    pub fn validate_minimal(&self) -> Result<()> {
        if let ModerationAppealPayload::Decision(p) = self {
            match (p.verdict, &p.modify_decision_ref) {
                (AppealVerdict::Modify, None) => {
                    return Err(Error::Protocol(
                        "moderation appeal decision verdict=modify requires modify_decision_ref \
                         (schema_violation)"
                            .to_owned(),
                    ));
                }
                (AppealVerdict::Uphold | AppealVerdict::Overturn, Some(_)) => {
                    return Err(Error::Protocol(format!(
                        "moderation appeal decision verdict={:?} MUST NOT include \
                         modify_decision_ref (schema_violation)",
                        p.verdict
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
