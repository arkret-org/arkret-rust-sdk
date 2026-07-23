//! Shared operations and deployment-health DTOs.
//!
//! These are product/ops contracts rather than signed protocol objects. Keep
//! them here when multiple services and admin clients need the same wire shape.

use serde::{Deserialize, Serialize};

/// Non-sensitive production hardening checklist snapshot.
///
/// Services expose this on `/health` and their describe surfaces so admin
/// clients can aggregate deployment posture without scraping service-specific
/// config. Fields are coarse by design and must not contain paths, hosts, token
/// tails, or other secrets.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HardeningStatus {
    #[serde(default)]
    pub development_mode: bool,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(default)]
    pub pq_hybrid_tls_required_group: String,
    #[serde(default)]
    pub pq_hybrid_tls_probe_artifact: String,
    #[serde(default)]
    pub pq_hybrid_tls_probe_verified: bool,
    #[serde(default)]
    pub csp_header_configured: bool,
    #[serde(default)]
    pub cors_strict: bool,
    #[serde(default)]
    pub secret_manager_in_use: bool,
    #[serde(default)]
    pub log_redaction_enabled: bool,
    #[serde(default)]
    pub admin_auth_mode: String,
    #[serde(default)]
    pub rate_limit_enabled: bool,
    #[serde(default)]
    pub provider_credential_rotation: String,
    #[serde(default)]
    pub checklist_score: u32,
    #[serde(default)]
    pub checklist_max: u32,
    #[serde(default)]
    pub warnings: Vec<String>,
}
