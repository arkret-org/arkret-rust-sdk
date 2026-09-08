//! Explicit deployment trust roots shared by native HTTP discovery transports.

#[cfg(feature = "tls-rustls")]
use crate::Error;
use crate::Result;

#[cfg(all(not(target_arch = "wasm32"), feature = "tls-rustls"))]
pub(crate) fn apply_explicit_tls_roots(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder> {
    let Some(path) = std::env::var_os("SSL_CERT_FILE") else {
        return Ok(builder);
    };
    let path = std::path::PathBuf::from(path);
    let pem = std::fs::read(&path).map_err(|error| {
        Error::Protocol(format!(
            "failed to read SSL_CERT_FILE {}: {error}",
            path.display()
        ))
    })?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
        Error::Protocol(format!(
            "SSL_CERT_FILE {} contains no valid PEM certificate: {error}",
            path.display()
        ))
    })?;
    // SSL_CERT_FILE is an explicit trust-store override. Keep hostname
    // verification enabled, but avoid the platform verifier so ephemeral and
    // private deployment roots are evaluated consistently by rustls/webpki.
    Ok(builder.tls_backend_rustls().tls_certs_only(certificates))
}

#[cfg(not(all(not(target_arch = "wasm32"), feature = "tls-rustls")))]
pub(crate) fn apply_explicit_tls_roots(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder> {
    Ok(builder)
}
