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
            return Err(WireError::Protocol(
                "container rebalance positions length must be 1..=10000 (schema_violation)"
                    .to_owned(),
            ));
        }
        let mut item_refs = BTreeSet::new();
        let mut ranks = BTreeSet::new();
        for position in &self.positions {
            validate_container_rank(&position.rank)?;
            if !item_refs.insert(position.item_ref.as_str()) {
                return Err(WireError::Protocol(
                    "container rebalance item_ref values must be unique (schema_violation)"
                        .to_owned(),
                ));
            }
            if !ranks.insert(position.rank.as_str()) {
                return Err(WireError::Protocol(
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
        Err(WireError::Protocol(
            "container relation_kind must match ^[a-z][a-z0-9_]{0,63}$ (schema_violation)"
                .to_owned(),
        ))
    }
}

fn validate_container_rank(value: &str) -> Result<()> {
    if (1..=128).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(WireError::Protocol(
            "container rank must match ^[0-9A-Za-z]{1,128}$ (schema_violation)".to_owned(),
        ))
    }
}
