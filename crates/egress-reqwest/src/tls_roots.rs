//! Process-local deployment roots for native reqwest transports.

/// Honor an explicit SSL_CERT_FILE without changing global operating-system trust.
///
/// With no explicit path this returns the original builder. With native rustls
/// enabled, the same PEM parser and rustls/webpki backend retain certificate-chain
/// and hostname verification. The application selects its cryptography provider.
pub fn apply_explicit_tls_roots(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder, String> {
    let Some(path) = std::env::var_os("SSL_CERT_FILE") else {
        return Ok(builder);
    };
    let path = std::path::PathBuf::from(path);
    let pem = std::fs::read(&path)
        .map_err(|error| format!("failed to read SSL_CERT_FILE {}: {error}", path.display()))?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
        format!(
            "SSL_CERT_FILE {} contains no valid PEM certificate: {error}",
            path.display()
        )
    })?;
    // SSL_CERT_FILE is an explicit trust-store override. Keep hostname
    // verification enabled, but avoid the platform verifier so ephemeral and
    // private deployment roots are evaluated consistently by rustls/webpki.
    Ok(builder.tls_backend_rustls().tls_certs_only(certificates))
}
