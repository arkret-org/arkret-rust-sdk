//! Runtime platform wire shapes shared by SDK and FFI crates.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Browser HTTP request body shape for WASM transports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmHttpRequestBody {
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl WasmHttpRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.method.trim().is_empty() {
            return Err(Error::Protocol(
                "WASM HTTP method must not be empty".to_owned(),
            ));
        }
        if !(self.url.starts_with("https://") || self.url.starts_with("http://localhost")) {
            return Err(Error::Protocol(
                "WASM HTTP URL must be HTTPS or localhost".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Browser HTTP response body shape returned by WASM transports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmHttpResponseBody {
    pub status: u16,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
