use arkret_canonical::serde_helpers::optional_canonical_timestamp;
use arkret_identifiers::{DidCoreId, EventId, RealmId};
use arkret_models_identity::handle::Handle;
use arkret_models_identity::{HandleClaim, RouteAssistance, ServiceResolutionCarrier};
use arkret_wire::PrincipalAuthorityKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::invite_addressing::PrincipalLocator;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerContactAddress {
    pub subject_id: DidCoreId,
    pub principal_authority: PrincipalAuthorityKey,
    pub recipient_service_id: DidCoreId,
    pub service_resolution: ServiceResolutionCarrier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_assistance: Option<RouteAssistance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_kind: Option<String>,
}

impl PeerContactAddress {
    pub const RECIPIENT_SERVICE_KIND: &'static str = "principal_server";

    pub fn principal_server(
        subject_id: DidCoreId,
        principal_authority: PrincipalAuthorityKey,
        recipient_service_id: DidCoreId,
        service_resolution: ServiceResolutionCarrier,
    ) -> Self {
        Self {
            subject_id,
            principal_authority,
            recipient_service_id,
            service_resolution,
            route_assistance: None,
            recipient_service_kind: None,
        }
    }

    /// Validate transport shape and exact stable service binding only.
    ///
    /// A carrier URL, route-assistance notice, or mirror hint is discovery
    /// material, never authorization. Consumers must independently verify the
    /// fetched/supplied signed resolution record before routing.
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        self.service_resolution
            .validate_shape(&self.recipient_service_id)?;
        if self.principal_authority.principal_id != self.subject_id
            || self.principal_authority.principal_server_id != self.recipient_service_id
        {
            return Err(arkret_wire::WireError::Protocol(
                "Contact address principal authority pair does not bind subject and recipient service"
                    .to_owned(),
            ));
        }
        if let ServiceResolutionCarrier::Inline { inline } = &self.service_resolution {
            let projected = arkret_wire::project_full_id_to_core_id(&inline.record.full_id)?;
            if projected != self.recipient_service_id
                || inline.record.service_kind != Self::RECIPIENT_SERVICE_KIND
            {
                return Err(arkret_wire::WireError::Protocol(
                    "Contact inline service resolution does not bind the recipient Principal Server"
                        .to_owned(),
                ));
            }
        }
        if let Some(route_assistance) = &self.route_assistance {
            route_assistance.validate_shape()?;
        }
        if self
            .recipient_service_kind
            .as_deref()
            .is_some_and(|kind| kind != Self::RECIPIENT_SERVICE_KIND)
        {
            return Err(arkret_wire::WireError::Protocol(
                "contact_address.recipient_service_kind MUST be principal_server".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Current Contact introduction evidence. Contact acceptance is directional
/// and is not coupled to a Consent grant.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[allow(clippy::large_enum_variant)]
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
        resolved_by: Option<DidCoreId>,
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

    fn authority() -> PrincipalAuthorityKey {
        PrincipalAuthorityKey::new(
            DidCoreId::new("ak:did_core:webvh:z6mkSubject").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkService").unwrap(),
        )
    }

    #[test]
    fn peer_contact_address_binds_subject_and_service_cores_to_resolution_carrier() {
        let principal_authority = authority();
        let value = serde_json::json!({
            "subject_id": "ak:did_core:webvh:z6mkSubject",
            "principal_authority": principal_authority,
            "recipient_service_id": "ak:did_core:webvh:z6mkService",
            "service_resolution": {
                "current_record_url": "https://service.example/_arkret/open/services/ak%3Adid_core%3Awebvh%3Az6mkService/resolution"
            },
            "recipient_service_kind": "principal_server"
        });
        let address: PeerContactAddress = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(address.subject_id.as_str(), "ak:did_core:webvh:z6mkSubject");
        assert_eq!(
            address.recipient_service_id.as_str(),
            "ak:did_core:webvh:z6mkService"
        );
        address.validate_shape().unwrap();
        assert_eq!(serde_json::to_value(address).unwrap(), value);
    }

    #[test]
    fn peer_contact_address_rejects_full_subject_and_wrong_service_kind() {
        let full_subject = serde_json::json!({
            "subject_id": "did:webvh:z6mkSubject:subject.example",
            "principal_authority": authority(),
            "recipient_service_id": "ak:did_core:webvh:z6mkService",
            "service_resolution": {
                "current_record_url": "https://service.example/_arkret/open/services/ak%3Adid_core%3Awebvh%3Az6mkService/resolution"
            }
        });
        assert!(serde_json::from_value::<PeerContactAddress>(full_subject).is_err());

        let wrong_kind: PeerContactAddress = serde_json::from_value(serde_json::json!({
            "subject_id": "ak:did_core:webvh:z6mkSubject",
            "principal_authority": authority(),
            "recipient_service_id": "ak:did_core:webvh:z6mkService",
            "service_resolution": {
                "current_record_url": "https://service.example/_arkret/open/services/ak%3Adid_core%3Awebvh%3Az6mkService/resolution"
            },
            "recipient_service_kind": "relay"
        }))
        .unwrap();
        assert!(wrong_kind.validate_shape().is_err());
    }
}
