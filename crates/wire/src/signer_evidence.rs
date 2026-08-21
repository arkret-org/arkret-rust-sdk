//! Content-addressed signer-evidence locator.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{Error, Hash, Result};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
pub struct SignerEvidenceRef(String);

impl SignerEvidenceRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let Some(digest) = value.strip_prefix("ak:signer_evidence:sha256:") else {
            return Err(Error::Protocol(
                "invalid signer evidence reference".to_owned(),
            ));
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(Error::Protocol(
                "invalid signer evidence reference".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn content_digest(&self) -> Result<Hash> {
        Ok(Hash::new(
            self.0
                .strip_prefix("ak:signer_evidence:")
                .expect("validated signer evidence ref")
                .to_owned(),
        )?)
    }
}

impl Serialize for SignerEvidenceRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignerEvidenceRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl AsRef<str> for SignerEvidenceRef {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
