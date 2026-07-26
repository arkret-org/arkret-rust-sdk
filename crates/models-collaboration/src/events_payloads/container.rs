//! Container-order event payloads.

use std::collections::BTreeSet;

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/container_move_item_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerMoveItemPayload {
    pub item_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_container_ref: Option<ObjectRef>,
    pub container_ref: ObjectRef,
    pub relation_kind: String,
    pub rank: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_position_digest: Option<Hash>,
}

impl ContainerMoveItemPayload {
    pub fn validate(&self) -> Result<()> {
        validate_container_relation_kind(&self.relation_kind)?;
        validate_container_rank(&self.rank)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRebalancePosition {
    pub item_ref: ObjectRef,
    pub rank: String,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/container_rebalance_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRebalancePayload {
    pub container_ref: ObjectRef,
    pub relation_kind: String,
    pub positions: Vec<ContainerRebalancePosition>,
    pub expected_order_digest: Hash,
}

impl ContainerRebalancePayload {
    pub const MAX_POSITIONS: usize = 10_000;

    pub fn validate(&self) -> Result<()> {
        validate_container_relation_kind(&self.relation_kind)?;
        if self.positions.is_empty() || self.positions.len() > Self::MAX_POSITIONS {
            return Err(Error::Protocol(
                "container rebalance positions length must be 1..=10000 (schema_violation)"
                    .to_owned(),
            ));
        }
        let mut item_refs = BTreeSet::new();
        let mut ranks = BTreeSet::new();
        for position in &self.positions {
            validate_container_rank(&position.rank)?;
            if !item_refs.insert(position.item_ref.as_str()) {
                return Err(Error::Protocol(
                    "container rebalance item_ref values must be unique (schema_violation)"
                        .to_owned(),
                ));
            }
            if !ranks.insert(position.rank.as_str()) {
                return Err(Error::Protocol(
                    "container rebalance rank values must be unique (schema_violation)".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn validate_container_relation_kind(value: &str) -> Result<()> {
    if (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Ok(())
    } else {
        Err(Error::Protocol(
            "container relation_kind must match ^[a-z][a-z0-9_]{0,63}$ (schema_violation)"
                .to_owned(),
        ))
    }
}

fn validate_container_rank(value: &str) -> Result<()> {
    if (1..=128).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(Error::Protocol(
            "container rank must match ^[0-9A-Za-z]{1,128}$ (schema_violation)".to_owned(),
        ))
    }
}

#[cfg(test)]
mod container_order_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn move_item_rejects_retired_shape_and_invalid_rank() {
        let current = json!({
            "item_ref": "ak:strand:01904100-0000-7000-8000-000000000001",
            "container_ref": "ak:space:01904100-0000-7000-8000-000000000002",
            "relation_kind": "contains",
            "rank": "A0"
        });
        let payload: ContainerMoveItemPayload = serde_json::from_value(current).unwrap();
        payload.validate().unwrap();

        let retired = json!({
            "source_ref": "ak:space:01904100-0000-7000-8000-000000000002",
            "target_ref": "ak:strand:01904100-0000-7000-8000-000000000001",
            "container_ref": "ak:space:01904100-0000-7000-8000-000000000002",
            "rank": "A0"
        });
        assert!(serde_json::from_value::<ContainerMoveItemPayload>(retired).is_err());

        let mut invalid = payload;
        invalid.rank = "A-0".to_owned();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rebalance_rejects_duplicate_items_and_ranks() {
        let mut payload = ContainerRebalancePayload {
            container_ref: "ak:space:01904100-0000-7000-8000-000000000002".to_owned(),
            relation_kind: "contains".to_owned(),
            positions: vec![
                ContainerRebalancePosition {
                    item_ref: "ak:strand:01904100-0000-7000-8000-000000000001".to_owned(),
                    rank: "A0".to_owned(),
                },
                ContainerRebalancePosition {
                    item_ref: "ak:strand:01904100-0000-7000-8000-000000000003".to_owned(),
                    rank: "B0".to_owned(),
                },
            ],
            expected_order_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        };
        payload.validate().unwrap();

        payload.positions[1].item_ref = payload.positions[0].item_ref.clone();
        assert!(payload.validate().is_err());
        payload.positions[1].item_ref = "ak:strand:01904100-0000-7000-8000-000000000003".to_owned();
        payload.positions[1].rank = payload.positions[0].rank.clone();
        assert!(payload.validate().is_err());
    }
}
