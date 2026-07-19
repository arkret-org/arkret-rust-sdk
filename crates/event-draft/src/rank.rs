//! LexoRank-style rank interval arithmetic for container ordering drafts.

use serde::{Deserialize, Serialize};

use crate::{EventDraftError, Result};

const RANK_ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const RANK_MAX_LEN: usize = 128;

pub fn rank_between(before: Option<&str>, after: Option<&str>) -> Result<String> {
    let left = before.unwrap_or("");
    let right = after.unwrap_or("");
    validate_rank_boundary(left)?;
    validate_rank_boundary(right)?;
    if !left.is_empty() && !right.is_empty() && left >= right {
        return Err(EventDraftError::Protocol(format!(
            "invalid rank interval '{left}'..'{right}'"
        )));
    }

    let mut prefix = String::new();
    let mut index = 0;
    while prefix.len() < RANK_MAX_LEN {
        let low = left
            .as_bytes()
            .get(index)
            .map(|byte| rank_value(*byte).expect("validated rank boundary"))
            .unwrap_or(-1);
        let high = if right.is_empty() {
            RANK_ALPHABET.len() as i16
        } else {
            right
                .as_bytes()
                .get(index)
                .map(|byte| rank_value(*byte).expect("validated rank boundary"))
                .unwrap_or(RANK_ALPHABET.len() as i16)
        };
        if high - low > 1 {
            let midpoint = ((low + high) / 2) as usize;
            prefix.push(RANK_ALPHABET[midpoint] as char);
            return Ok(prefix);
        }
        if let Some(byte) = left.as_bytes().get(index) {
            prefix.push(*byte as char);
        } else {
            prefix.push(RANK_ALPHABET[0] as char);
            if !right.is_empty() && prefix == right {
                return Err(EventDraftError::Protocol(
                    "rank interval is exhausted".to_owned(),
                ));
            }
            return Ok(prefix);
        }
        index += 1;
    }
    Err(EventDraftError::Protocol(
        "rank interval is exhausted".to_owned(),
    ))
}

pub fn rank_exhausted(before: Option<&str>, after: Option<&str>) -> Result<bool> {
    match rank_between(before, after) {
        Ok(_) => Ok(false),
        Err(EventDraftError::Protocol(message)) if message == "rank interval is exhausted" => {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ContainerRebalanceAssignment {
    pub object_ref: String,
    pub rank: String,
}

pub fn container_rebalance_assignments(
    object_refs: &[String],
) -> Result<Vec<ContainerRebalanceAssignment>> {
    if object_refs.is_empty() {
        return Ok(Vec::new());
    }
    let count = object_refs.len() as u128;
    let denominator = count + 1;
    let required_capacity = denominator.checked_mul(2).ok_or_else(|| {
        EventDraftError::Protocol("too many container assignments to rebalance".to_owned())
    })?;
    let mut width = 0usize;
    let mut capacity = 1u128;
    while capacity < required_capacity {
        width += 1;
        if width > RANK_MAX_LEN {
            return Err(EventDraftError::Protocol(
                "too many container assignments to rebalance".to_owned(),
            ));
        }
        capacity = capacity
            .checked_mul(RANK_ALPHABET.len() as u128)
            .ok_or_else(|| {
                EventDraftError::Protocol("too many container assignments to rebalance".to_owned())
            })?;
    }
    object_refs
        .iter()
        .enumerate()
        .map(|(index, object_ref)| {
            let rank_number = (index as u128 + 1)
                .checked_mul(capacity)
                .map(|product| product / denominator)
                .ok_or_else(|| {
                    EventDraftError::Protocol(
                        "too many container assignments to rebalance".to_owned(),
                    )
                })?;
            Ok(ContainerRebalanceAssignment {
                object_ref: object_ref.clone(),
                rank: format_rank_number(rank_number, width),
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn validate_rank_boundary(rank: &str) -> Result<()> {
    if rank.len() > RANK_MAX_LEN || !rank.bytes().all(|byte| rank_value(byte).is_some()) {
        return Err(EventDraftError::Protocol(format!("invalid rank '{rank}'")));
    }
    Ok(())
}

fn rank_value(byte: u8) -> Option<i16> {
    RANK_ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as i16)
}

fn format_rank_number(mut value: u128, width: usize) -> String {
    let mut output = vec![RANK_ALPHABET[0]; width];
    for byte in output.iter_mut().rev() {
        *byte = RANK_ALPHABET[(value % RANK_ALPHABET.len() as u128) as usize];
        value /= RANK_ALPHABET.len() as u128;
    }
    String::from_utf8(output).expect("rank alphabet is valid UTF-8")
}
