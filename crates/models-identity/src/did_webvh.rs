//! Shared did:webvh method-native wire values.

use arkret_wire::{Result, WireError};
use serde_json::{Value, json};

/// The closed did:webvh v1.0 witness policy carried by
/// `parameters.witness`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DidWebvhWitnessPolicy {
    pub threshold: usize,
    pub witnesses: Vec<String>,
}

impl DidWebvhWitnessPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.threshold == 0 || self.threshold > self.witnesses.len() {
            return Err(WireError::Protocol(
                "witness threshold must be within 1..=witnesses.length".to_owned(),
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        for witness in &self.witnesses {
            let key = witness
                .strip_prefix("did:key:")
                .ok_or_else(|| WireError::Protocol("witness id must be a did:key".to_owned()))?;
            if key.is_empty() || key.contains('#') || key.contains(':') {
                return Err(WireError::Protocol(
                    "witness id must be a canonical did:key without a fragment".to_owned(),
                ));
            }
            arkret_canonical::decode_ed25519_multibase(key).map_err(|error| {
                WireError::Protocol(format!(
                    "witness did:key is not a decodable Ed25519 key: {error}"
                ))
            })?;
            if !unique.insert(witness) {
                return Err(WireError::Protocol("witness ids must be unique".to_owned()));
            }
        }
        Ok(())
    }

    pub fn parameter_value(&self) -> Result<Value> {
        self.validate()?;
        Ok(json!({
            "threshold": self.threshold,
            "witnesses": self
                .witnesses
                .iter()
                .map(|id| json!({"id": id}))
                .collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_parameter_is_closed_and_canonical() {
        let policy = DidWebvhWitnessPolicy {
            threshold: 1,
            witnesses: vec!["did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned()],
        };
        assert_eq!(
            policy.parameter_value().unwrap(),
            json!({
                "threshold": 1,
                "witnesses": [{
                    "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
                }],
            })
        );
    }
}
