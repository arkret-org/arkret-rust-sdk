//! Arkret push surface models and helpers.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;


#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRule {
    pub rule_id: String,
    pub kind: PushRuleKind,
    #[serde(default = "default_push_rule_enabled")]
    pub enabled: bool,
    #[serde(deserialize_with = "deserialize_push_rule_locus")]
    pub evaluation_locus: String,
    #[serde(default)]
    pub conditions: Vec<PushCondition>,
    #[serde(default)]
    pub actions: Vec<PushRuleAction>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushRuleKind {
    Override,
    Content,
    Underride,
}

impl PushRuleKind {
    pub const EVALUATION_ORDER: [Self; 3] = [Self::Override, Self::Content, Self::Underride];
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushRuleAction {
    Notify,
    DontNotify,
    SoundDefault,
    SoundCritical,
    Highlight,
}

impl PushRuleAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::DontNotify => "dont_notify",
            Self::SoundDefault => "sound_default",
            Self::SoundCritical => "sound_critical",
            Self::Highlight => "highlight",
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushCondition {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRulesConfig {
    #[serde(default)]
    pub rules: Vec<PushRule>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DndDocument {
    pub dnd: DndSettings,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DndSettings {
    pub enabled: bool,
    pub schedule: DndSchedule,
    pub exceptions: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DndSchedule {
    pub timezone: String,
    pub tzdb_version: String,
    pub all_day: bool,
    pub periods: Vec<DndPeriod>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DndPeriod {
    pub start: String,
    pub end: String,
}

fn deserialize_push_rule_locus<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == "client" {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "unsupported_feature: v1 push rules require evaluation_locus=client",
        ))
    }
}

fn default_push_rule_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_rules_reject_server_evaluation_locus() {
        let error = serde_json::from_value::<PushRule>(serde_json::json!({
            "rule_id": "server-message",
            "kind": "underride",
            "enabled": true,
            "evaluation_locus": "server",
            "conditions": [],
            "actions": ["notify"]
        }))
        .unwrap_err()
        .to_string();
        assert!(error.contains("unsupported_feature"));

        let client: PushRule = serde_json::from_value(serde_json::json!({
            "rule_id": "client-message",
            "kind": "underride",
            "enabled": true,
            "evaluation_locus": "client",
            "conditions": [],
            "actions": ["notify"]
        }))
        .unwrap();
        assert_eq!(client.evaluation_locus, "client");

        for (field, value) in [("kind", "future"), ("actions", "future")] {
            let mut document = serde_json::json!({
                "rule_id": "closed-enum",
                "kind": "underride",
                "enabled": true,
                "evaluation_locus": "client",
                "conditions": [],
                "actions": ["notify"]
            });
            if field == "kind" {
                document[field] = serde_json::json!(value);
            } else {
                document[field] = serde_json::json!([value]);
            }
            assert!(serde_json::from_value::<PushRule>(document).is_err());
        }

        let missing_locus = serde_json::json!({
            "rule_id": "missing-locus",
            "kind": "underride",
            "enabled": true,
            "conditions": [],
            "actions": ["notify"]
        });
        assert!(serde_json::from_value::<PushRule>(missing_locus).is_err());
    }
}
