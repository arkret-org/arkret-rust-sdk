//! Account-Authority-to-Station Principal Control Realm genesis relay.
//!
//! The outer service signature authenticates transport only. Content
//! authorization is exclusively the frozen registration anchor, the
//! identity-root control proof and the two Event proofs carried by the atomic
//! genesis unit.

use arkret_models_identity::{
    IdentityCreationControlProof, PCR_GENESIS_UNIT_KINDS, PrincipalRegistrationAnchor,
};
use arkret_wire::{
    DeviceId, Did, DidCoreId, EventBatchReceipt, Hash, IdempotencyKey, PcrGenesisUnit, RealmId,
    RegistrationDidEvidence, Result, WireError, canonical, project_did_to_core_id,
};
use serde::{Deserialize, Serialize};

use crate::events_payloads::event_wire::decode_payload_after_kind_validation;
use crate::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    RealmCreatePayload, RealmPurpose, device_authorize_payload_digest,
    validate_root_anchored_authorize_payload_digest,
};

// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/pcr_genesis_submit_request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrGenesisSubmitRequestBody {
    pub account_authority_id: DidCoreId,
    pub principal_id: DidCoreId,
    pub did: Did,
    pub pcr_realm_id: RealmId,
    pub did_version_id: String,
    pub control_key_digest: Hash,
    pub idempotency_key: IdempotencyKey,
    pub registration_request_digest: Hash,
    pub principal_registration_anchor: PrincipalRegistrationAnchor,
    pub registration_did_evidence: RegistrationDidEvidence,
    pub identity_creation_control_proof: IdentityCreationControlProof,
    pub genesis_unit: PcrGenesisUnit,
}

impl PcrGenesisSubmitRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.identity_creation_control_proof.validate_shape()?;
        self.principal_registration_anchor.validate()?;
        self.registration_did_evidence.validate_shape()?;
        self.genesis_unit.validate_ordered_envelopes()?;

        let proof = &self.identity_creation_control_proof;
        let create = self.genesis_unit.create();
        let authorize = self.genesis_unit.founding_authorize();
        create.validate_proof_bindings_with_digest_suite(canonical::DigestSuite::Sha256)?;
        authorize.validate_proof_bindings_with_digest_suite(canonical::DigestSuite::Sha256)?;
        if self.principal_id != proof.principal_id
            || self.did != proof.did
            || project_did_to_core_id(&self.did)? != self.principal_id
            || self.pcr_realm_id != proof.pcr_realm_id
            || self.did_version_id != proof.did_version_id
            || self.control_key_digest != proof.control_key_digest
            || self.principal_registration_anchor.did() != &self.did
            || proof.proof_kind.registration_anchor_kind()
                != self.principal_registration_anchor.anchor_kind()
            || self.principal_registration_anchor.canonical_digest()?
                != proof.registration_anchor_digest
            || self.registration_did_evidence.principal_id != self.principal_id
            || self.registration_did_evidence.did != self.did
            || self.registration_did_evidence.version_id != self.did_version_id
            || self.registration_did_evidence.method_history_head
                != self
                    .principal_registration_anchor
                    .declared_method_history_head()?
                    .as_str()
            || self.registration_did_evidence.control_key_digest != self.control_key_digest
            || proof.genesis_unit_kinds != PCR_GENESIS_UNIT_KINDS
            || create.actor_id.signing_principal_id() != &self.principal_id
            || create.realm_id != self.pcr_realm_id
            || authorize.actor_id.signing_principal_id() != &self.principal_id
            || authorize.realm_id != self.pcr_realm_id
        {
            return Err(WireError::Protocol(
                "PCR genesis relay identity binding mismatch".to_owned(),
            ));
        }

        let create_payload_digest = Hash::new(canonical::canonical_sha256(&create.payload)?)?;
        let authorize_payload_value =
            serde_json::Value::Object(authorize.payload.clone().into_iter().collect());
        let authorize_payload_digest = device_authorize_payload_digest(
            &authorize_payload_value,
            canonical::DigestSuite::Sha256,
        )?;
        if create_payload_digest != proof.realm_create_payload_digest
            || authorize_payload_digest != proof.founding_authorize_payload_digest
        {
            return Err(WireError::Protocol(
                "PCR genesis relay payload digest does not match identity creation proof"
                    .to_owned(),
            ));
        }

        let create_payload: RealmCreatePayload = decode_payload_after_kind_validation(create)?;
        let descriptor = create_payload
            .object
            .founding_device_descriptor
            .as_ref()
            .ok_or_else(|| {
                WireError::Protocol("PCR genesis omits founding device descriptor".to_owned())
            })?;
        if create_payload.object.purpose != RealmPurpose::PrincipalControl
            || descriptor.founding_authorize_payload_digest != authorize_payload_digest
        {
            return Err(WireError::Protocol(
                "PCR genesis descriptor does not commit to the founding authorize payload"
                    .to_owned(),
            ));
        }
        validate_root_anchored_authorize_payload_digest(
            &descriptor.founding_authorize_payload_digest,
            &authorize_payload_value,
            canonical::DigestSuite::Sha256,
        )?;
        let authorize_payload: DeviceAuthorizePayload =
            decode_payload_after_kind_validation(authorize)?;
        let expected_authorize_verification_method =
            format!("{}#{}", proof.did, descriptor.device_id);
        let authorized_by_root = matches!(
            &authorize_payload.authorized_by,
            DeviceOrPrincipalRef::Principal(principal_id)
                if principal_id == &proof.principal_id
        );
        let create_proof = create.producer_proof.as_ref();
        let authorize_proof = authorize.producer_proof.as_ref();
        if authorize_payload.authorization_binding_kind
            != DeviceAuthorizationBindingKind::RegistrationAnchor
            || !authorized_by_root
            || descriptor.device_id != authorize_payload.device_id
            || descriptor.device_public_key_did != authorize_payload.device_public_key_did
            || descriptor.hpke_key != authorize_payload.hpke_key
            || descriptor.algorithms != authorize_payload.algorithms
            || create_proof.is_none_or(|proof| !proof.verification_method.starts_with("did:key:"))
            || authorize_proof.is_none_or(|proof| {
                proof.verification_method.as_str() != expected_authorize_verification_method
            })
        {
            return Err(WireError::Protocol(
                "PCR genesis descriptor and founding device authorization disagree".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.validate()?;
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }
}

// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/pcr_genesis_submit_outcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrGenesisSubmitOutcome {
    pub principal_id: DidCoreId,
    pub pcr_realm_id: RealmId,
    pub accepted_device_id: DeviceId,
    pub resolution: arkret_models_identity::PrincipalResolutionProjection,
    pub receipt: EventBatchReceipt,
}

impl PcrGenesisSubmitOutcome {
    pub fn validate_against(&self, request: &PcrGenesisSubmitRequestBody) -> Result<()> {
        request.validate()?;
        let scope = self.receipt.pcr_genesis_scope()?;
        let create_payload: RealmCreatePayload =
            decode_payload_after_kind_validation(request.genesis_unit.create())?;
        let descriptor = create_payload
            .object
            .founding_device_descriptor
            .ok_or_else(|| {
                WireError::Protocol("PCR genesis omits founding device descriptor".to_owned())
            })?;
        let receipt_event_id = |kind: &str| {
            self.receipt
                .events
                .iter()
                .find(|item| item.kind.as_str() == kind)
                .map(|item| &item.event_id)
        };
        if self.principal_id != request.principal_id
            || self.pcr_realm_id != request.pcr_realm_id
            || self.accepted_device_id != descriptor.device_id
            || scope.principal_id != request.principal_id
            || scope.realm_id != request.pcr_realm_id
            || scope.audience_id.as_core_id() != request.account_authority_id.as_core_id()
            || scope.did_version_id != request.did_version_id
            || scope.control_key_digest != request.control_key_digest
            || scope.registration_evidence_digest
                != request.registration_did_evidence.canonical_digest()?
            || scope.accepted_device_id != descriptor.device_id
            || scope.device_key_digest != descriptor.device_key_digest()?
            || scope.hpke_key_digest != descriptor.hpke_key_digest()?
            || receipt_event_id(arkret_wire::event_kind_str::REALM_CREATE)
                != Some(&request.genesis_unit.create().event_id)
            || receipt_event_id(arkret_wire::event_kind_str::DEVICE_AUTHORIZE)
                != Some(&request.genesis_unit.founding_authorize().event_id)
        {
            return Err(WireError::Protocol(
                "PCR genesis accepted receipt does not match the submitted unit".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn pcr_genesis_submit_request_body_is_closed() {
        assert!(
            serde_json::from_value::<PcrGenesisSubmitRequestBody>(json!({})).is_err(),
            "every relay member is required"
        );
        assert!(
            serde_json::from_value::<PcrGenesisSubmitRequestBody>(json!({
                "account_authority_id": "ak:did_core:web:authority.example",
                "unexpected_member": true
            }))
            .is_err(),
            "the relay body is a closed object"
        );
    }

    #[test]
    fn pcr_genesis_submit_outcome_requires_the_resolution_projection() {
        assert!(
            serde_json::from_value::<PcrGenesisSubmitOutcome>(json!({
                "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
                "pcr_realm_id": "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
                "accepted_device_id": "ak:device:0198ff00-0000-7000-8000-000000000001",
                "receipt": {}
            }))
            .is_err(),
            "resolution must not become optional"
        );
    }

    #[test]
    fn pcr_genesis_unit_kinds_are_the_closed_ordered_pair() {
        assert_eq!(
            serde_json::to_value(PCR_GENESIS_UNIT_KINDS).unwrap(),
            json!(["ak.realm.create", "ak.device.authorize"])
        );
    }
}
