use super::*;
use crate::serde_helpers::{
    deserialize_optional_canonical_timestamp, serialize_optional_canonical_timestamp,
};

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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContactIntroductionEvidence {
    LocatorRef {
        principal_locator: PrincipalLocator,
    },
    ConsentGrant {
        consent_grant_ref: EventId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consent_id: Option<String>,
    },
    SharedRealm {
        realm_id: RealmId,
        requester_member_ref: EventId,
        target_member_ref: EventId,
    },
    HandleClaim {
        handle: Handle,
        handle_claim: Box<HandleClaim>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolved_by: Option<Did>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            serialize_with = "serialize_optional_canonical_timestamp",
            deserialize_with = "deserialize_optional_canonical_timestamp"
        )]
        resolved_at: Option<DateTime<Utc>>,
    },
    SamePrincipalServer,
    ExplicitAddress,
}

impl ContactIntroductionEvidence {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LocatorRef { .. } => "locator_ref",
            Self::ConsentGrant { .. } => "consent_grant",
            Self::SharedRealm { .. } => "shared_realm",
            Self::HandleClaim { .. } => "handle_claim",
            Self::SamePrincipalServer => "same_principal_server",
            Self::ExplicitAddress => "explicit_address",
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduction_evidence: Option<ContactIntroductionEvidence>,
    pub idempotency_key: String,
}

impl PeerContactDeliveryRequest {
    pub fn new(
        contact_event: Event,
        contact_address: PeerContactAddress,
        fact_kind: PeerContactFactKind,
        introduction_evidence: Option<ContactIntroductionEvidence>,
        idempotency_key: impl Into<String>,
    ) -> Self {
        Self {
            schema: PEER_CONTACT_DELIVERY_REQUEST_SCHEMA.to_owned(),
            contact_event,
            contact_address,
            fact_kind,
            introduction_evidence,
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
        if self.fact_kind == PeerContactFactKind::Requested && self.introduction_evidence.is_none()
        {
            return Err(Error::Protocol(
                "peer_contact_delivery_request.introduction_evidence is required for ck.contact.requested"
                    .to_owned(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value).unwrap()
    }

    fn event(kind: &str) -> Event {
        serde_json::from_value(serde_json::json!({
            "event_id": "ck:event:01904100-0000-7000-8000-79a90338768b",
            "kind": kind,
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 1,
            "created_at": "2026-06-07T10:00:00Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {},
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn requested_requires_introduction_evidence() {
        let request = PeerContactDeliveryRequest::new(
            event("ck.contact.requested"),
            PeerContactAddress {
                subject_id: did("did:webvh:z6mkfixture:bob.example"),
                recipient_service_did: did("did:webvh:z6mkfixture:bob.example"),
                recipient_service_type: None,
            },
            PeerContactFactKind::Requested,
            None,
            "contact-1",
        );
        assert!(request.validate_minimal().is_err());

        let request = PeerContactDeliveryRequest {
            introduction_evidence: Some(ContactIntroductionEvidence::ExplicitAddress),
            ..request
        };
        request.validate_minimal().unwrap();
    }

    #[test]
    fn handle_claim_contact_evidence_roundtrips() {
        let handle = Handle::parse("alice:example.com").unwrap();
        let claim = HandleClaim {
            handle: Some(handle.clone()),
            subject: Some(did("did:webvh:z6mkfixture:alice.example")),
            binding_state: Some(HandleBindingState::Verified),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            proofs: vec![PayloadProof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: "did:webvh:z6mkfixture:issuer.example#key-1".to_owned(),
                payload_digest: Hash::new(format!("sha256:{}", "4".repeat(64))).unwrap(),
                created_at: Utc::now(),
                domain: None,
                audience: None,
                jws: "header..sig".to_owned(),
            }],
            ..Default::default()
        };
        let evidence = ContactIntroductionEvidence::HandleClaim {
            handle,
            handle_claim: Box::new(claim),
            resolved_by: Some(did("did:webvh:z6mkfixture:directory.example")),
            resolved_at: None,
        };
        assert_eq!(evidence.kind(), "handle_claim");
        let value = serde_json::to_value(&evidence).unwrap();
        assert_eq!(value["kind"], "handle_claim");
        assert!(serde_json::from_value::<ContactIntroductionEvidence>(value).is_ok());
    }
}
