use super::*;

pub const PEER_CONTACT_DELIVERY_REQUEST_SCHEMA: &str = "ck.schema.peer_contact_delivery_request.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerContactAddress {
    pub subject_id: Did,
    pub recipient_service_did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum PeerContactFactKind {
    #[serde(rename = "ck.contact.requested")]
    Requested,
    #[serde(rename = "ck.contact.accepted")]
    Accepted,
    #[serde(rename = "ck.contact.rejected")]
    Rejected,
    #[serde(rename = "ck.contact.tombstoned")]
    Tombstoned,
}

impl PeerContactFactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "ck.contact.requested",
            Self::Accepted => "ck.contact.accepted",
            Self::Rejected => "ck.contact.rejected",
            Self::Tombstoned => "ck.contact.tombstoned",
        }
    }

    pub fn from_wire(value: &str) -> Result<Self> {
        match value {
            "ck.contact.requested" => Ok(Self::Requested),
            "ck.contact.accepted" => Ok(Self::Accepted),
            "ck.contact.rejected" => Ok(Self::Rejected),
            "ck.contact.tombstoned" => Ok(Self::Tombstoned),
            _ => Err(Error::Protocol(format!(
                "unsupported peer_contact_delivery_request.fact_kind: {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerContactDeliveryRequest {
    pub schema: String,
    pub contact_event: Event,
    pub contact_address: PeerContactAddress,
    pub fact_kind: PeerContactFactKind,
    pub idempotency_key: String,
}

impl PeerContactDeliveryRequest {
    pub fn new(
        contact_event: Event,
        contact_address: PeerContactAddress,
        fact_kind: PeerContactFactKind,
        idempotency_key: impl Into<String>,
    ) -> Self {
        Self {
            schema: PEER_CONTACT_DELIVERY_REQUEST_SCHEMA.to_owned(),
            contact_event,
            contact_address,
            fact_kind,
            idempotency_key: idempotency_key.into(),
        }
    }

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != PEER_CONTACT_DELIVERY_REQUEST_SCHEMA {
            return Err(Error::Protocol(
                "peer_contact_delivery_request.schema mismatch".to_owned(),
            ));
        }
        if let Some(recipient_service_type) = self.contact_address.recipient_service_type.as_deref()
            && recipient_service_type != "principal_server"
        {
            return Err(Error::Protocol(
                "peer_contact_delivery_request.contact_address.recipient_service_type must be principal_server"
                    .to_owned(),
            ));
        }
        if self.contact_event.kind.as_str() != self.fact_kind.as_str() {
            return Err(Error::Protocol(
                "peer_contact_delivery_request.fact_kind must equal contact_event.kind".to_owned(),
            ));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(Error::Protocol(
                "peer_contact_delivery_request.idempotency_key must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}
