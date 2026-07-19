//! Strongly typed JSON Web Key and JSON Web Key Set models.

use std::collections::BTreeSet;

use arkret_wire::{Base64UrlString, NonEmptyString};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JsonWebKeyUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JsonWebKeyOperation {
    #[serde(rename = "sign")]
    Sign,
    #[serde(rename = "verify")]
    Verify,
    #[serde(rename = "encrypt")]
    Encrypt,
    #[serde(rename = "decrypt")]
    Decrypt,
    #[serde(rename = "wrapKey")]
    WrapKey,
    #[serde(rename = "unwrapKey")]
    UnwrapKey,
    #[serde(rename = "deriveKey")]
    DeriveKey,
    #[serde(rename = "deriveBits")]
    DeriveBits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty", deny_unknown_fields)]
pub enum JsonWebKey {
    #[serde(rename = "RSA")]
    Rsa {
        #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
        public_key_use: Option<JsonWebKeyUse>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        key_ops: Vec<JsonWebKeyOperation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alg: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kid: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x5u: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        x5c: Vec<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x5t: Option<Base64UrlString>,
        #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
        x5t_s256: Option<Base64UrlString>,
        n: Base64UrlString,
        e: Base64UrlString,
    },
    #[serde(rename = "EC")]
    Ec {
        #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
        public_key_use: Option<JsonWebKeyUse>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        key_ops: Vec<JsonWebKeyOperation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alg: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kid: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x5u: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        x5c: Vec<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x5t: Option<Base64UrlString>,
        #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
        x5t_s256: Option<Base64UrlString>,
        crv: NonEmptyString,
        x: Base64UrlString,
        y: Base64UrlString,
    },
    #[serde(rename = "OKP")]
    Okp {
        #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
        public_key_use: Option<JsonWebKeyUse>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        key_ops: Vec<JsonWebKeyOperation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alg: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kid: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x5u: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        x5c: Vec<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x5t: Option<Base64UrlString>,
        #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
        x5t_s256: Option<Base64UrlString>,
        crv: NonEmptyString,
        x: Base64UrlString,
    },
}

impl JsonWebKey {
    pub fn ed25519(x: Base64UrlString) -> Self {
        Self::Okp {
            public_key_use: None,
            key_ops: Vec::new(),
            alg: None,
            kid: None,
            x5u: None,
            x5c: Vec::new(),
            x5t: None,
            x5t_s256: None,
            crv: NonEmptyString::new("Ed25519").expect("Ed25519 is non-empty"),
            x,
        }
    }

    pub fn from_ed25519_verifying_key(verifying_key: &ed25519_dalek::VerifyingKey) -> Self {
        Self::ed25519(
            Base64UrlString::new(arkret_canonical::base64url_encode(verifying_key.to_bytes()))
                .expect("base64url encoding produces a valid JSON Web Key coordinate"),
        )
    }

    pub fn kid(&self) -> Option<&NonEmptyString> {
        match self {
            Self::Rsa { kid, .. } | Self::Ec { kid, .. } | Self::Okp { kid, .. } => kid.as_ref(),
        }
    }

    pub fn ed25519_x_for_verification(&self) -> Option<&Base64UrlString> {
        let Self::Okp {
            public_key_use,
            key_ops,
            alg,
            crv,
            x,
            ..
        } = self
        else {
            return None;
        };
        if crv.as_str() != "Ed25519"
            || *public_key_use == Some(JsonWebKeyUse::Encryption)
            || (!key_ops.is_empty() && !key_ops.contains(&JsonWebKeyOperation::Verify))
            || alg
                .as_ref()
                .is_some_and(|algorithm| algorithm.as_str() != "EdDSA")
        {
            return None;
        }
        Some(x)
    }

    pub fn ed25519_thumbprint_members(&self) -> Option<(&str, &Base64UrlString)> {
        let Self::Okp { crv, x, .. } = self else {
            return None;
        };
        (crv.as_str() == "Ed25519").then_some((crv.as_str(), x))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonWebKeySetWire {
    keys: Vec<JsonWebKey>,
}

impl<'de> Deserialize<'de> for JsonWebKeySet {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = JsonWebKeySetWire::deserialize(deserializer)?;
        Self::new(wire.keys).map_err(serde::de::Error::custom)
    }
}

impl JsonWebKeySet {
    pub fn new(keys: Vec<JsonWebKey>) -> Result<Self> {
        let mut key_ids = BTreeSet::new();
        for key_id in keys.iter().filter_map(JsonWebKey::kid) {
            if !key_ids.insert(key_id.as_str()) {
                return Err(Error::Protocol(format!(
                    "JSON Web Key Set contains duplicate kid: {key_id}"
                )));
            }
        }
        Ok(Self { keys })
    }

    pub fn keys(&self) -> &[JsonWebKey] {
        &self.keys
    }
}
