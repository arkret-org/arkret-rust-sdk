//! Explicit deployment trust roots shared by native HTTP discovery transports.

#[cfg(feature = "tls-rustls")]
use crate::Error;
use crate::Result;

#[cfg(all(not(target_arch = "wasm32"), feature = "tls-rustls"))]
pub(crate) fn apply_explicit_tls_roots(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder> {
    arkret_egress_reqwest::apply_explicit_tls_roots(builder).map_err(Error::Protocol)
}

#[cfg(not(all(not(target_arch = "wasm32"), feature = "tls-rustls")))]
pub(crate) fn apply_explicit_tls_roots(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder> {
    Ok(builder)
}
