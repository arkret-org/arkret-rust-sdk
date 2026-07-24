use arkret_canonical::serde_helpers::{
    deserialize_optional_canonical_timestamp, serialize_optional_canonical_timestamp,
};
use arkret_identifiers::{Did, EventId, RealmId};
use arkret_models_identity::handle::Handle;
use arkret_wire::{Error, Event, FederatedDeviceSigningKeyEvidence, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::handle_claim::HandleClaim;
use crate::governance::invite_addressing::PrincipalLocator;

pub const PEER_CONTACT_DELIVERY_REQUEST_SCHEMA: &str = "ak.schema.peer_contact_delivery_request.v1";
pub const MAX_PEER_CONTACT_SIGNER_KEY_EVIDENCE: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerContactAddress {
    pub subject_id: Did,
    pub recipient_service_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerContactFactKind {
    #[serde(rename = "ak.contact.requested")]
    Requested,
    #[serde(rename = "ak.contact.accepted")]
    Accepted,
    #[serde(rename = "ak.contact.rejected")]
    Rejected,
    #[serde(rename = "ak.contact.tombstoned")]
    Tombstoned,
    #[serde(rename = "ak.direct_conversation.bound")]
    DirectConversationBound,
}

impl PeerContactFactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "ak.contact.requested",
            Self::Accepted => "ak.contact.accepted",
            Self::Rejected => "ak.contact.rejected",
            Self::Tombstoned => "ak.contact.tombstoned",
            Self::DirectConversationBound => "ak.direct_conversation.bound",
        }
    }

    pub fn from_wire(value: &str) -> Result<Self> {
        match value {
            "ak.contact.requested" => Ok(Self::Requested),
            "ak.contact.accepted" => Ok(Self::Accepted),
            "ak.contact.rejected" => Ok(Self::Rejected),
            "ak.contact.tombstoned" => Ok(Self::Tombstoned),
            "ak.direct_conversation.bound" => Ok(Self::DirectConversationBound),
            _ => Err(Error::Protocol(format!(
                "unsupported peer_contact_delivery_request.fact_kind: {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        handle: Handle,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
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
#[serde(deny_unknown_fields)]
pub struct PeerContactDeliveryRequest {
    pub schema: String,
    pub contact_event: Event,
    pub contact_address: PeerContactAddress,
    pub fact_kind: PeerContactFactKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduction_evidence: Option<ContactIntroductionEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signer_key_evidence: Vec<FederatedDeviceSigningKeyEvidence>,
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
            signer_key_evidence: Vec::new(),
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
                "peer_contact_delivery_request.introduction_evidence is required for ak.contact.requested"
                    .to_owned(),
            ));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(Error::Protocol(
                "peer_contact_delivery_request.idempotency_key must not be empty".to_owned(),
            ));
        }
        if self.signer_key_evidence.len() > MAX_PEER_CONTACT_SIGNER_KEY_EVIDENCE {
            return Err(Error::Protocol(
                "peer contact signer_key_evidence exceeds the v1 limit".to_owned(),
            ));
        }
        for evidence in &self.signer_key_evidence {
            evidence.validate_shape()?;
            if !evidence.matches_event_proof(&self.contact_event, &evidence.verification_method) {
                return Err(Error::Protocol(
                    "peer contact signer evidence does not match contact_event proof".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::Hash;
    use arkret_models_identity::handle::HandleBindingState;
    use arkret_wire::PayloadProof;

    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value).unwrap()
    }

    fn event(kind: &str) -> Event {
        serde_json::from_value(serde_json::json!({
            "event_id": "ak:event:01904100-0000-7000-8000-79a90338768b",
            "kind": kind,
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 1,
            "created_at": "2026-06-07T10:00:00.000Z",
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
            event("ak.contact.requested"),
            PeerContactAddress {
                subject_id: did("did:webvh:z6mkfixture:bob.example"),
                recipient_service_id: did("did:webvh:z6mkfixture:bob.example"),
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
                proof_purpose: None,
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
