use arkret_canonical::serde_helpers::optional_canonical_timestamp;
use arkret_identifiers::{DidCoreId, EventId, RealmId};
use arkret_models_identity::handle::Handle;
use arkret_models_identity::{HandleClaim, RouteAssistance, ServiceResolutionCarrier};
#[cfg(test)]
use arkret_wire::AccountId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::contact_operations::ContactPeer;
use crate::governance::invite_addressing::PrincipalLocator;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerContactAddress {
    pub recipient: ContactPeer,
    pub service_resolution: ServiceResolutionCarrier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_assistance: Option<RouteAssistance>,
}

impl PeerContactAddress {
    pub const RECIPIENT_SERVICE_KIND: &'static str = "station";

    pub fn for_recipient(
        recipient: ContactPeer,
        service_resolution: ServiceResolutionCarrier,
    ) -> Self {
        Self {
            recipient,
            service_resolution,
            route_assistance: None,
        }
    }

    pub fn delivery_station_id(&self) -> &DidCoreId {
        self.recipient.delivery_station_id()
    }

    /// Validate transport shape and exact stable service binding only.
    ///
    /// A carrier URL, route-assistance notice, or mirror hint is discovery
    /// material, never authorization. Consumers must independently verify the
    /// fetched/supplied signed resolution record before routing.
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        let delivery_station_id = self.delivery_station_id();
        self.service_resolution
            .validate_shape(delivery_station_id)?;
        if let ServiceResolutionCarrier::Inline { inline } = &self.service_resolution {
            let projected =
                arkret_wire::project_did_to_core_id(&inline.normalized_did_document.id)?;
            if projected != *delivery_station_id
                || inline.service_kind != Self::RECIPIENT_SERVICE_KIND
            {
                return Err(arkret_wire::WireError::Protocol(
                    "Contact inline service resolution does not bind the recipient Station"
                        .to_owned(),
                ));
            }
        }
        if let Some(route_assistance) = &self.route_assistance {
            route_assistance.validate_shape()?;
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
    SameStation,
    ExplicitAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkSubject").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkService").unwrap(),
        )
    }

    #[test]
    fn peer_contact_address_binds_subject_and_service_cores_to_resolution_carrier() {
        let account_id = authority();
        let value = serde_json::json!({
            "recipient": {"kind": "human", "account_id": account_id},
            "service_resolution": {
                "resolution_url": "https://service.example/_arkret/open/services/ak%3Adid_core%3Awebvh%3Az6mkService/resolution"
            }
        });
        let address: PeerContactAddress = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            address.delivery_station_id().as_str(),
            "ak:did_core:webvh:z6mkService"
        );
        address.validate_shape().unwrap();
        assert_eq!(serde_json::to_value(address).unwrap(), value);
    }

    #[test]
    fn peer_contact_address_rejects_old_split_identity_and_wrong_resolution() {
        let old_split_identity = serde_json::json!({
            "subject_id": "did:webvh:z6mkSubject:subject.example",
            "account_id": authority(),
            "recipient_id": "ak:did_core:webvh:z6mkService",
            "service_resolution": {
                "resolution_url": "https://service.example/_arkret/open/services/ak%3Adid_core%3Awebvh%3Az6mkService/resolution"
            }
        });
        assert!(serde_json::from_value::<PeerContactAddress>(old_split_identity).is_err());

        let wrong_station: PeerContactAddress = serde_json::from_value(serde_json::json!({
            "recipient": {"kind": "human", "account_id": authority()},
            "service_resolution": {
                "resolution_url": "https://service.example/_arkret/open/services/ak%3Adid_core%3Awebvh%3Az6mkOther/resolution"
            }
        }))
        .unwrap();
        assert!(wrong_station.validate_shape().is_err());
    }
}
