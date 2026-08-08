//! Identity/account HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json` / `agent-operations.schema.json`):
//! the account logout / device-enroll / OIDC-callback request bodies and the
//! transparent identity-describe outcome wrappers used by the Salvo OpenAPI
//! bindings. Pure identity/account wire shapes; validation and dispatch live
//! with the auth and server behavior crates.

use arkret_wire::{
    DeviceAuthorizeEventPreimage, DeviceId, Did, Error, Event, EventId, Hash, ProtocolOpaqueId,
    Result,
};
use serde::{Deserialize, Serialize};

use crate::identity::{
    DidOperationSubmitOutcome, DidOperationSubmitRequestBody, IdentityDescription,
    IdentityDocumentView, IdentityLogListOutcome, IdentityReceiptListOutcome,
};

/// `ak.gate.account.command.logout` request (Principal Server device logout).
/// Empty body — the session bearer identifies the device session to terminate.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountLogoutRequestBody {}

/// `ak.gate.account.command.logout` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountLogoutOutcome {
    pub ok: bool,
    pub revoked: bool,
}

/// Request body for `ak.gate.account.command.enroll_device`
/// (`POST /_arkret/gate/account/device-enroll`). The authenticated session
/// submits the complete proof-free `ak.device.authorize` Event fixed by the
/// founding client. The enrollment authority may only append its proof. Mirrors
/// `agent-operations.schema.json#/$defs/account_device_enroll_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeviceEnrollRequestBody {
    pub device_id: DeviceId,
    pub authorize_event_preimage: DeviceAuthorizeEventPreimage,
}

impl AccountDeviceEnrollRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.authorize_event_preimage.validate()?;
        let preimage = &self.authorize_event_preimage;
        let authority_binding = preimage
            .payload
            .get("enrollment_authority_binding")
            .and_then(serde_json::Value::as_object);
        if preimage
            .payload
            .get("device_id")
            .and_then(serde_json::Value::as_str)
            != Some(self.device_id.as_str())
            || preimage
                .payload
                .get("principal_id")
                .and_then(serde_json::Value::as_str)
                != Some(preimage.actor_id.as_str())
            || preimage
                .payload
                .get("authorized_by")
                .and_then(serde_json::Value::as_str)
                != Some(preimage.actor_id.as_str())
            || authority_binding
                .and_then(|binding| binding.get("kind"))
                .and_then(serde_json::Value::as_str)
                != Some("service_attested")
            || authority_binding
                .and_then(|binding| binding.get("authority_did"))
                .and_then(serde_json::Value::as_str)
                != Some(preimage.executed_by.as_str())
            || authority_binding
                .and_then(|binding| binding.get("authorization_ref"))
                .and_then(serde_json::Value::as_str)
                != Some(preimage.authorization_ref.as_str())
        {
            return Err(Error::Protocol(
                "device enroll request has inconsistent device, principal, or authority bindings"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(self)?,
        ))?)
    }
}

/// Outcome for `ak.gate.account.command.enroll_device`. The account authority
/// does not contact the Principal Server; the caller submits `authorized_event`
/// verbatim to `POST /_arkret/self/events`. Mirrors
/// `agent-operations.schema.json#/$defs/account_device_enroll_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeviceEnrollOutcome {
    pub bootstrap_transaction_id: ProtocolOpaqueId,
    pub principal_id: Did,
    pub device_id: DeviceId,
    /// Enrollment authority DID (= `executed_by` /
    /// `enrollment_authority_binding.authority_did`).
    pub authority_did: Did,
    /// Fully-signed `service_attested` `ak.device.authorize` Event envelope.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub authorized_event: Event,
    pub authorized_event_id: EventId,
    pub authorized_event_digest: Hash,
    pub outcome_digest: Hash,
}

impl AccountDeviceEnrollOutcome {
    /// Recompute the durable response identity over the closed outcome with the
    /// self-referential `outcome_digest` field removed.
    pub fn recompute_outcome_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("device enroll outcome serializes as an object")
            .remove("outcome_digest");
        Ok(Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&value)?,
        ))?)
    }

    /// Ensure the authority returned the caller-fixed Event with only its proof appended.
    pub fn validate_against(&self, request: &AccountDeviceEnrollRequestBody) -> Result<()> {
        request.validate()?;
        if self.device_id != request.device_id
            || self.principal_id != request.authorize_event_preimage.actor_id
            || self.authorized_event.event_id != request.authorize_event_preimage.event_id
            || self.authorized_event_id != request.authorize_event_preimage.event_id
            || self.authorized_event.proofs.len() != 1
            || self.authorized_event.executed_by.as_ref() != Some(&self.authority_did)
            || self.authorized_event_digest.as_str() != self.authorized_event.event_digest()?
        {
            return Err(Error::Protocol(
                "device enroll outcome does not bind the requested Event identity".to_owned(),
            ));
        }
        if self.outcome_digest != self.recompute_outcome_digest()? {
            return Err(Error::Protocol(
                "device enroll outcome digest does not match the canonical response".to_owned(),
            ));
        }
        let mut proof_free = self.authorized_event.clone();
        proof_free.proofs.clear();
        let returned_preimage = DeviceAuthorizeEventPreimage::try_from(proof_free)?;
        if returned_preimage != request.authorize_event_preimage {
            return Err(Error::Protocol(
                "device enroll authority rewrote the client-authored Event preimage".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountOidcCallbackRequestBody {
    pub state: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityDescribeOutcome(pub IdentityDescription);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityDocumentViewOutcome(pub IdentityDocumentView);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityLogResultBody(pub IdentityLogListOutcome);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentitySubmitDidOperationRequestBody(pub DidOperationSubmitRequestBody);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentitySubmitDidOperationOutcome(pub DidOperationSubmitOutcome);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityReceiptsResultBody(pub IdentityReceiptListOutcome);

#[cfg(test)]
mod tests {
    use arkret_wire::{DidUrl, Proof};
    use serde_json::json;

    use super::{AccountDeviceEnrollOutcome, AccountDeviceEnrollRequestBody};

    fn founding_request() -> serde_json::Value {
        arkret_schema::embedded_json_artifact("fixtures/device-bootstrap-fixture.json")
            .unwrap()["enroll_request"]
            .clone()
    }

    #[test]
    fn device_enroll_fixture_is_canonical_and_closed() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/device-bootstrap-fixture.json")
                .unwrap();
        let request: AccountDeviceEnrollRequestBody =
            serde_json::from_value(founding_request()).expect("founding request");
        request.validate().unwrap();
        assert_eq!(
            request.canonical_request_digest().unwrap().as_str(),
            fixture["canonical_request"]["expected_digest"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            request.authorize_event_preimage.event_id.as_str(),
            fixture["event_identity"]["expected_event_id"]
                .as_str()
                .unwrap()
        );
        let serialized = serde_json::to_value(&request).unwrap();
        assert_eq!(serialized, founding_request());
        assert!(
            serialized["authorize_event_preimage"]
                .get("proofs")
                .is_none()
        );

        let mut later = founding_request();
        later["authorize_event_preimage"]["actor_seq"] = json!(2);
        let invalid: AccountDeviceEnrollRequestBody = serde_json::from_value(later).unwrap();
        assert!(invalid.validate().is_err());

        let mut unknown = founding_request();
        unknown["derived_digest"] = json!(format!("sha256:{}", "a".repeat(64)));
        assert!(serde_json::from_value::<AccountDeviceEnrollRequestBody>(unknown).is_err());
    }

    #[test]
    fn device_enroll_outcome_allows_only_one_appended_authority_proof() {
        let request: AccountDeviceEnrollRequestBody =
            serde_json::from_value(founding_request()).unwrap();
        let mut authorized_event = request.authorize_event_preimage.clone().into_event();
        let digest = authorized_event.event_digest().unwrap();
        authorized_event.proofs.push(Proof {
            kind: "DataIntegrityProof".to_owned(),
            verification_method: DidUrl::new(format!(
                "{}#enrollment-key-1",
                request.authorize_event_preimage.executed_by
            ))
            .unwrap(),
            event_digest: arkret_wire::Hash::new(digest.clone()).unwrap(),
            created_at: request.authorize_event_preimage.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZERTQSJ9..fixture".to_owned(),
        });
        let mut outcome = AccountDeviceEnrollOutcome {
            bootstrap_transaction_id: arkret_wire::ProtocolOpaqueId::new("bootstrap-1").unwrap(),
            principal_id: request.authorize_event_preimage.actor_id.clone(),
            device_id: request.device_id.clone(),
            authority_did: request.authorize_event_preimage.executed_by.clone(),
            authorized_event,
            authorized_event_id: request.authorize_event_preimage.event_id.clone(),
            authorized_event_digest: arkret_wire::Hash::new(digest).unwrap(),
            outcome_digest: arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        };
        outcome.outcome_digest = outcome.recompute_outcome_digest().unwrap();
        outcome.validate_against(&request).unwrap();

        let mut wrong_outcome_digest = outcome.clone();
        wrong_outcome_digest.outcome_digest =
            arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        assert!(wrong_outcome_digest.validate_against(&request).is_err());

        let mut rewritten = outcome.clone();
        rewritten.authorized_event.payload.insert(
            "hpke_key".to_owned(),
            json!("z6LSdifferentHpkeKey111111111111111111111111111111"),
        );
        assert!(rewritten.validate_against(&request).is_err());

        let mut extra_proof = outcome;
        extra_proof
            .authorized_event
            .proofs
            .push(extra_proof.authorized_event.proofs[0].clone());
        assert!(extra_proof.validate_against(&request).is_err());
    }
}
