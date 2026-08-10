use arkret_models_identity::{IdentityCreationControlProof, PCR_GENESIS_UNIT_KINDS};
use arkret_wire::{
    ActorId, CoreId, DeviceId, Did, Error, EventBatchReceipt, Hash, IdempotencyKey, PcrGenesisUnit,
    RealmId, Result, canonical,
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
    pub account_authority_id: Did,
    pub principal_id: CoreId,
    pub pcr_realm_id: RealmId,
    pub idempotency_key: IdempotencyKey,
    pub registration_request_digest: Hash,
    pub did_version_id: String,
    pub log_head_digest: Hash,
    pub control_key_digest: Hash,
    pub identity_creation_control_proof: IdentityCreationControlProof,
    pub genesis_unit: PcrGenesisUnit,
}

impl PcrGenesisSubmitRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.identity_creation_control_proof.validate_shape()?;
        self.genesis_unit.validate_ordered_envelopes()?;

        let proof = &self.identity_creation_control_proof;
        let create = self.genesis_unit.create();
        let authorize = self.genesis_unit.founding_authorize();
        create.validate_proof_bindings()?;
        authorize.validate_proof_bindings()?;
        if self.principal_id != proof.principal_id
            || self.pcr_realm_id != proof.pcr_realm_id
            || self.did_version_id != proof.did_version_id
            || self.log_head_digest != proof.log_head_digest
            || self.control_key_digest != proof.control_key_digest
            || proof.genesis_unit_kinds != PCR_GENESIS_UNIT_KINDS
            || create.actor_id != ActorId::from(self.principal_id.clone())
            || create.realm_id != self.pcr_realm_id
            || authorize.actor_id != ActorId::from(self.principal_id.clone())
            || authorize.realm_id != self.pcr_realm_id
        {
            return Err(Error::Protocol(
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
            return Err(Error::Protocol(
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
                Error::Protocol("PCR genesis omits founding device descriptor".to_owned())
            })?;
        if create_payload.object.purpose != RealmPurpose::PrincipalControl
            || descriptor.founding_authorize_payload_digest != authorize_payload_digest
        {
            return Err(Error::Protocol(
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
            DeviceOrPrincipalRef::Did(did) if did == &proof.full_id
        );
        if authorize_payload.authorization_binding_kind
            != DeviceAuthorizationBindingKind::RootAnchored
            || !authorized_by_root
            || descriptor.device_id != authorize_payload.device_id
            || descriptor.device_public_key != authorize_payload.device_public_key
            || descriptor.hpke_key != authorize_payload.hpke_key
            || descriptor.algorithms != authorize_payload.algorithms
            || create.proofs.len() != 1
            || !create.proofs[0].verification_method.starts_with("did:key:")
            || authorize.proofs.len() != 1
            || authorize.proofs[0].verification_method.as_str()
                != expected_authorize_verification_method
        {
            return Err(Error::Protocol(
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
    pub principal_id: CoreId,
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
                Error::Protocol("PCR genesis omits founding device descriptor".to_owned())
            })?;
        let create_digest = Hash::new(request.genesis_unit.create().event_digest()?)?;
        let authorize_digest =
            Hash::new(request.genesis_unit.founding_authorize().event_digest()?)?;
        if self.principal_id != request.principal_id
            || self.pcr_realm_id != request.pcr_realm_id
            || self.accepted_device_id != descriptor.device_id
            || scope.principal_id != request.identity_creation_control_proof.full_id
            || scope.realm_id != request.pcr_realm_id
            || scope.audience != request.account_authority_id
            || scope.did_version_id != request.did_version_id
            || scope.log_head_digest != request.log_head_digest
            || scope.control_key_digest != request.control_key_digest
            || scope.accepted_device_id != descriptor.device_id
            || scope.device_key_digest != descriptor.device_key_digest
            || scope.hpke_key_digest != descriptor.hpke_key_digest
            || scope.create_digest != create_digest
            || scope.founding_authorize_digest != authorize_digest
        {
            return Err(Error::Protocol(
                "PCR genesis accepted receipt does not match the submitted unit".to_owned(),
            ));
        }
        Ok(())
    }
}
