//! Typed diagnostic for an explicitly registered cross-Cell inconsistency.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CellRef, EventId, SchemaId};

/// One identity-preserving diagnostic candidate. Equal values written by
/// distinct Events remain distinct candidates.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalHead {
    pub event_id: EventId,
    pub value: Value,
}

/// The only registered cross-Cell domain diagnostic kind.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BottomKind {
    Conflict,
}

/// Non-authoritative projection diagnostic. Rejected, pending, quarantined,
/// and sequenced security outcomes are represented by their own result types.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bottom {
    pub kind: BottomKind,
    pub cell_ids: Vec<CellRef>,
    pub heads: Vec<CausalHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub escalated_at: Option<DateTime<Utc>>,
}

impl Bottom {
    pub const SCHEMA: &'static str = SchemaId::BOTTOM_V1;

    #[must_use]
    pub fn conflict(cell_ids: Vec<CellRef>, heads: Vec<CausalHead>) -> Self {
        Self {
            kind: BottomKind::Conflict,
            cell_ids,
            heads,
            escalated_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(value: &str) -> CellRef {
        CellRef::new(value.to_owned()).unwrap()
    }

    fn event(byte: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
    }

    #[test]
    fn conflict_preserves_equal_values_under_distinct_event_ids() {
        let bottom = Bottom::conflict(
            vec![cell("ak:cell:ak.component.realm.policy.v1:x")],
            vec![
                CausalHead {
                    event_id: event(0x44),
                    value: Value::String("open".to_owned()),
                },
                CausalHead {
                    event_id: event(0x55),
                    value: Value::String("open".to_owned()),
                },
            ],
        );

        let encoded = serde_json::to_string(&bottom).unwrap();
        assert!(!encoded.contains("event_ids"));
        assert!(!encoded.contains("seal_view"));
        assert!(!encoded.contains("details"));
        assert_eq!(serde_json::from_str::<Bottom>(&encoded).unwrap(), bottom);
    }

    #[test]
    fn unknown_bottom_kind_is_rejected() {
        let raw = serde_json::json!({
            "kind": "missing_dependency",
            "cell_ids": ["ak:cell:ak.component.realm.policy.v1:x"],
            "heads": []
        });
        assert!(serde_json::from_value::<Bottom>(raw).is_err());
    }
}
