use arkret_models_identity::{
    DidOperationSubmitRequestBody, IdentityCreationControlProof, PCR_GENESIS_UNIT_KINDS,
};
use arkret_wire::{
    DeviceId, DidCoreId, DidFullId, EventBatchReceipt, Hash, IdempotencyKey, PcrGenesisUnit,
    RealmId, RegistrationDidEvidence, Result, WireError, canonical, project_full_id_to_core_id,
};
use serde::{Deserialize, Serialize};

use crate::events_payloads::event_wire::decode_payload_after_kind_validation;
use crate::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    RealmCreatePayload, RealmPurpose, device_authorize_payload_digest,
    validate_root_anchored_authorize_payload_digest,
};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrGenesisSubmitRequestBody {
    pub account_authority_id: DidCoreId,
    pub principal_id: DidCoreId,
    pub full_id: DidFullId,
    pub pcr_realm_id: RealmId,
    pub idempotency_key: IdempotencyKey,
    pub registration_request_digest: Hash,
    pub did_version_id: String,
    pub log_head_digest: Hash,
    pub control_key_digest: Hash,
    pub registration_did_operation: DidOperationSubmitRequestBody,
    pub registration_did_evidence: RegistrationDidEvidence,
    pub identity_creation_control_proof: IdentityCreationControlProof,
    pub genesis_unit: PcrGenesisUnit,
}

impl PcrGenesisSubmitRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.identity_creation_control_proof.validate_shape()?;
        self.registration_did_operation.validate()?;
        self.registration_did_evidence.validate_shape()?;
        self.genesis_unit.validate_ordered_envelopes()?;

        let proof = &self.identity_creation_control_proof;
        let create = self.genesis_unit.create();
        let authorize = self.genesis_unit.founding_authorize();
        create.validate_proof_bindings_with_digest_suite(canonical::DigestSuite::Sha256)?;
        authorize.validate_proof_bindings_with_digest_suite(canonical::DigestSuite::Sha256)?;
        if self.principal_id != proof.principal_id
            || self.full_id != proof.full_id
            || project_full_id_to_core_id(&self.full_id)? != self.principal_id
            || self.pcr_realm_id != proof.pcr_realm_id
            || self.did_version_id != proof.did_version_id
            || self.log_head_digest != proof.log_head_digest
            || self.control_key_digest != proof.control_key_digest
            || self.registration_did_operation.did != self.full_id
            || Hash::new(canonical::canonical_sha256(
                &self.registration_did_operation,
            )?)? != proof.operation_digest
            || self.registration_did_evidence.principal_id != self.principal_id
            || self.registration_did_evidence.full_id != self.full_id
            || self.registration_did_evidence.version_id != self.did_version_id
            || self.registration_did_evidence.method_history_head != self.log_head_digest.as_str()
            || self.registration_did_evidence.control_key_digest != self.control_key_digest
            || proof.genesis_unit_kinds != PCR_GENESIS_UNIT_KINDS
            || create.actor_id != self.principal_id.clone()
            || create.realm_id != self.pcr_realm_id
            || authorize.actor_id != self.principal_id.clone()
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
            format!("{}#{}", proof.full_id, descriptor.device_id);
        let authorized_by_root = matches!(
            &authorize_payload.authorized_by,
            DeviceOrPrincipalRef::Principal(principal_id)
                if principal_id == &proof.principal_id
        );
        if authorize_payload.authorization_binding_kind
            != DeviceAuthorizationBindingKind::RegistrationAnchor
            || !authorized_by_root
            || descriptor.device_id != authorize_payload.device_id
            || descriptor.device_public_key != authorize_payload.device_public_key
            || descriptor.hpke_key != authorize_payload.hpke_key
            || descriptor.algorithms != authorize_payload.algorithms
            || create.proofs.len() != 1
            || !create.proofs[0]
                .as_producer()
                .is_some_and(|proof| proof.verification_method.starts_with("did:key:"))
            || authorize.proofs.len() != 1
            || authorize.proofs[0].as_producer().is_none_or(|proof| {
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrGenesisSubmitOutcome {
    pub principal_id: DidCoreId,
    pub pcr_realm_id: RealmId,
    pub accepted_device_id: DeviceId,
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
            || scope.audience.as_core_id() != request.account_authority_id.as_core_id()
            || scope.did_version_id != request.did_version_id
            || scope.log_head_digest != request.log_head_digest
            || scope.control_key_digest != request.control_key_digest
            || scope.registration_evidence_digest
                != request.registration_did_evidence.canonical_digest()?
            || scope.accepted_device_id != descriptor.device_id
            || scope.device_key_digest != descriptor.device_key_digest
            || scope.hpke_key_digest != descriptor.hpke_key_digest
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
