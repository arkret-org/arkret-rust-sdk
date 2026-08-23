//! Realm genesis intent entropy.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::base64url::{base64url_decode, base64url_encode};
use crate::{Result, WireError};

/// Canonical unpadded Base64URL encoding of exactly 32 CSPRNG octets.
///
/// This value is scoped to event-derived Realm creation intents. It has no
/// replay, ordering, freshness, authorization, idempotency-key, or winner
/// semantics. Every Realm, including a Principal Control Realm, is identified
/// by retyping its accepted create Event id.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GenesisSalt(String);

impl GenesisSalt {
    pub const OCTETS: usize = 32;
    pub const ENCODED_LEN: usize = 43;

    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; Self::OCTETS];
        getrandom::fill(&mut bytes).map_err(|error| {
            WireError::Protocol(format!(
                "generate Realm genesis salt from OS CSPRNG: {error}"
            ))
        })?;
        Ok(Self(base64url_encode(bytes)))
    }

    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != Self::ENCODED_LEN || value.contains('=') {
            return Err(WireError::Protocol(
                "genesis_salt must be 43-character unpadded Base64URL".to_owned(),
            ));
        }
        let decoded = base64url_decode(&value).map_err(|_| {
            WireError::Protocol("genesis_salt is not canonical Base64URL".to_owned())
        })?;
        if decoded.len() != Self::OCTETS || base64url_encode(&decoded) != value {
            return Err(WireError::Protocol(
                "genesis_salt must decode to exactly 32 octets canonically".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for GenesisSalt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("GenesisSalt").field(&self.0).finish()
    }
}

impl fmt::Display for GenesisSalt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for GenesisSalt {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GenesisSalt {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_known_answer_round_trips() {
        let value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(GenesisSalt::new(value).unwrap().as_str(), value);
    }

    #[test]
    fn generated_salts_are_canonical_and_distinct() {
        let first = GenesisSalt::generate().unwrap();
        let second = GenesisSalt::generate().unwrap();
        assert_eq!(first.as_str().len(), GenesisSalt::ENCODED_LEN);
        assert_ne!(first, second);
        assert_eq!(GenesisSalt::new(first.to_string()).unwrap(), first);
    }

    #[test]
    fn rejects_padding_alphabet_and_wrong_lengths() {
        for value in [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "",
        ] {
            assert!(GenesisSalt::new(value).is_err(), "accepted {value:?}");
        }
    }
}
