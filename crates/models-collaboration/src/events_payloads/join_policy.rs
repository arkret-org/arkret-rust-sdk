//! Join-policy event payloads.

use std::num::NonZeroU64;

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/join_policy_payload`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicyQuestionAnswerKind {
    Text,
    SingleChoice,
    MultiChoice,
    Boolean,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinPolicyQuestionChoice {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinPolicyQuestion {
    pub question_id: String,
    pub prompt_canonical: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_locales: Option<BTreeMap<String, String>>,
    pub answer_kind: JoinPolicyQuestionAnswerKind,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_chars: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<JoinPolicyQuestionChoice>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_reject_if_choice_in: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosed_in_directory: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinPolicyPayloadGatesItem {
    pub gate_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_resolve: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_did_methods: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_principal_dids: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_principal_dids: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub questions: Option<Vec<JoinPolicyQuestion>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicyDirectoryChallengeKind {
    Captcha,
    Pow,
    AttestedHuman,
    IdpOidc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinPolicyDirectoryHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_review_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_review_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_kinds_displayed: Option<Vec<JoinPolicyDirectoryChallengeKind>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinPolicyPayload {
    pub gates: Vec<JoinPolicyPayloadGatesItem>,
    pub combinator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_capability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_quorum: Option<JoinReviewerQuorum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_ttl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_after_reject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_open_applications_per_actor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applicant_visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_hint: Option<JoinPolicyDirectoryHint>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinReviewerQuorumPreset {
    Any,
    Majority,
    All,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinReviewerQuorumMembers {
    pub threshold: NonZeroU64,
    pub reviewers: Vec<Did>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JoinReviewerQuorum {
    Preset(JoinReviewerQuorumPreset),
    Members(JoinReviewerQuorumMembers),
}
