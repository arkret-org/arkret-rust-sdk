//! Profile and audit wire model shim.
//!
//! The strand-track profiles, Morph object, identity-link binding,
//! audit RYW receipts, moderation report, federation actor validation
//! class, the `AccountStatus` projection family, and the
//! erasure-receipt family migrated to `arkret-models-collaboration`
//! (re-exported below).

pub use arkret_models_collaboration::governance::audit::{
    ABSOLUTE_HARD_CEILING_MS, AuditAssurance, AuditRywReceipt,
    E2EE_RELAXED_INCOMPATIBLE_COMPLIANCE_PROFILES, PROFILE_E2EE_RELAXED, ReceiptIndependence,
    RywActorFrontierEntry, RywFrontier, RywIssuerRole, is_e2ee_relaxed_compatible_with_compliance,
    validate_relaxed_window_ms,
};
pub use arkret_models_collaboration::governance::erasure::*;
pub use arkret_models_collaboration::objects::account_status::{
    AccountStatus, AccountStatusProjection, AccountStatusProjectionCandidate,
    AccountStatusProjectionRejected, AccountStatusTransitionRejection,
    project_account_status_heads,
};
pub use arkret_models_collaboration::objects::profiles::*;
