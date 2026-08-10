use arkret_canonical::serde_helpers::optional_canonical_timestamp;
use arkret_identifiers::{Did, EventId, RealmId, ServiceId};
use arkret_models_identity::handle::Handle;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::handle_claim::HandleClaim;
use crate::governance::invite_addressing::PrincipalLocator;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerContactAddress {
    pub subject_id: Did,
    pub recipient_service_id: ServiceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_kind: Option<String>,
}

/// Current Contact introduction evidence. Contact acceptance is directional
/// and is not coupled to a Consent grant.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactIntroductionEvidence {
    LocatorRef {
        principal_locator: PrincipalLocator,
    },
    SharedRealm {
        realm_id: RealmId,
        requester_member_ref: EventId,
        target_member_ref: EventId,
    },
    HandleClaim {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        handle: Handle,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        handle_claim: Box<HandleClaim>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolved_by: Option<Did>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "optional_canonical_timestamp"
        )]
        resolved_at: Option<DateTime<Utc>>,
    },
    SamePrincipalServer,
    ExplicitAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_contact_keeps_subject_resolution_material_separate_from_service_core() {
        let value = serde_json::json!({
            "subject_id": "did:webvh:z6mkSubject:subject.example",
            "recipient_service_id": "ak:did_core:webvh:z6mkService",
            "recipient_service_kind": "principal_server"
        });
        let address: PeerContactAddress = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            address.subject_id.as_str(),
            "did:webvh:z6mkSubject:subject.example"
        );
        assert_eq!(
            address.recipient_service_id.as_str(),
            "ak:did_core:webvh:z6mkService"
        );
        assert_eq!(serde_json::to_value(address).unwrap(), value);
    }
}
