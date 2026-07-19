//! Interop schema artifact counterparts retained by `arkret-core`.
//!
//! The MIMI interop and media artifact shapes migrated to
//! `arkret-models-collaboration` (re-exported below). [`MimiOperations`]
//! stays because it aggregates the core HTTP request/outcome body DTOs.

pub use arkret_models_collaboration::objects::interop::*;

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MimiOperations {
    MimiKeyMaterialRequestBody(crate::MimiKeyMaterialRequestBody),
    MimiKeyMaterialOutcome(crate::MimiKeyMaterialOutcome),
    MimiRoomUpdateRequestBody(crate::MimiRoomUpdateRequestBody),
    MimiRoomUpdateOutcome(crate::MimiRoomUpdateOutcome),
    MimiNotifyRequestBody(crate::MimiNotifyRequestBody),
    MimiNotifyOutcome(crate::MimiNotifyOutcome),
    MimiSubmitMessageRequestBody(crate::MimiSubmitMessageRequestBody),
    MimiSubmitMessageOutcome(crate::MimiSubmitMessageOutcome),
    MimiGroupInfoOutcome(crate::MimiGroupInfoOutcome),
    MimiRequestConsentRequestBody(crate::MimiRequestConsentRequestBody),
    MimiRequestConsentOutcome(crate::MimiRequestConsentOutcome),
    MimiUpdateConsentRequestBody(crate::MimiUpdateConsentRequestBody),
    MimiUpdateConsentOutcome(crate::MimiUpdateConsentOutcome),
    MimiIdentifierQueryRequestBody(crate::MimiIdentifierQueryRequestBody),
    MimiIdentifierQueryOutcome(crate::MimiIdentifierQueryOutcome),
    MimiReportAbuseRequestBody(crate::MimiReportAbuseRequestBody),
    MimiReportAbuseOutcome(crate::MimiReportAbuseOutcome),
    MimiProxyDownloadRequestBody(crate::MimiProxyDownloadRequestBody),
    MimiProxyDownloadOutcome(crate::MimiProxyDownloadOutcome),
}
