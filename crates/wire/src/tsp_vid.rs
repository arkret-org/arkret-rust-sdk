use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{Did, Result, WireError};

macro_rules! tsp_vid_string {
    ($name:ident, $validator:ident, $message:literal) => {
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !$validator(&value) {
                    return Err(WireError::Protocol($message.to_owned()));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn is_keri_aid(value: &str) -> bool {
    static PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{44,128}$").expect("valid TSP KERI AID regex"));
    PATTERN.is_match(value)
}

fn is_urn(value: &str) -> bool {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^urn:[a-z0-9][a-z0-9-]{0,31}:[^\s?#]+$").expect("valid TSP URN regex")
    });
    value.chars().count() <= 2048 && PATTERN.is_match(value)
}

fn is_x509_identifier(value: &str) -> bool {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^urn:x509:sha256:[0-9a-f]{64}$").expect("valid TSP X.509 identifier regex")
    });
    PATTERN.is_match(value)
}

tsp_vid_string!(TspKeriAid, is_keri_aid, "invalid TSP KERI AID");
tsp_vid_string!(TspUrn, is_urn, "invalid TSP URN");
tsp_vid_string!(
    TspX509Identifier,
    is_x509_identifier,
    "invalid TSP X.509 identifier"
);

/// Closed Trust Spanning Protocol verifiable identifier.
///
/// Each identifier is externally tagged because DID, KERI, generic URN and
/// X.509 identifier spaces have different validation and resolution rules.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum TspVid {
    Did(Did),
    KeriAid(TspKeriAid),
    Urn(TspUrn),
    X509(TspX509Identifier),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_each_registered_vid_kind() {
        for value in [
            json!({"kind": "did", "value": "did:web:verifier.example"}),
            json!({"kind": "keri_aid", "value": "A".repeat(44)}),
            json!({"kind": "urn", "value": "urn:example:verifier"}),
            json!({
                "kind": "x509",
                "value": format!("urn:x509:sha256:{}", "a".repeat(64))
            }),
        ] {
            serde_json::from_value::<TspVid>(value).expect("registered TSP VID");
        }
    }

    #[test]
    fn rejects_legacy_strings_and_cross_kind_values() {
        assert!(serde_json::from_value::<TspVid>(json!("did:web:verifier.example")).is_err());
        assert!(
            serde_json::from_value::<TspVid>(json!({
                "kind": "did",
                "value": "urn:example:verifier"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<TspVid>(json!({
                "kind": "x509",
                "value": format!("urn:x509:sha256:{}", "A".repeat(64))
            }))
            .is_err()
        );
    }
}
