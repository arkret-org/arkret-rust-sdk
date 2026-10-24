//! Cryptographic verification of exact, private Realm actor material.
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_models_integration::{
    RealmActorMaterial, RealmActorMaterialRequestBody, RealmActorMaterialResponseBody,
};
use arkret_wire::{ActorId, DetachedSignatureContext};
use chrono::{DateTime, Utc};

use crate::{IdentityError, RealmAuthorityKeyDirectory, Result, VerifiedRealmAuthority};

/// Holding this value proves the response binding and Station signature, not write permission.
pub struct VerifiedRealmActorMaterial(RealmActorMaterialResponseBody);
impl VerifiedRealmActorMaterial {
    pub fn material(&self) -> &RealmActorMaterialResponseBody {
        &self.0
    }
    pub fn into_material(self) -> RealmActorMaterialResponseBody {
        self.0
    }
}

pub fn verify_realm_actor_material(
    material: RealmActorMaterialResponseBody,
    request: &RealmActorMaterialRequestBody,
    requester: &ActorId,
    authority: &VerifiedRealmAuthority,
    resolution: &AuthenticatedServiceResolution,
    keys: &dyn RealmAuthorityKeyDirectory,
    now: DateTime<Utc>,
) -> Result<VerifiedRealmActorMaterial> {
    material.validate_for_request(request, requester, now)?;
    let invalid = || {
        IdentityError::Protocol(
            "Realm material issuer differs from verified current governance".into(),
        )
    };
    if &material.realm_id != authority.realm_id()
        || resolution.service_kind != "station"
        || &resolution.service_id != authority.current_service_id()
        || !authority
            .binds_current_authority(material.governance_generation, &material.authority_ref)
    {
        return Err(invalid());
    }
    let document = crate::authenticated_service_document_at(
        resolution,
        authority.current_service_id(),
        material.issued_at,
    )?;
    crate::validate_verification_method_relationship(
        &document,
        &material.signature.verification_method,
        &document.id,
        crate::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let key = crate::public_key_material_from_document(
        &document,
        &material.signature.verification_method,
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let unsigned = arkret_canonical::unsigned_value(&material, &["signature"])?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &material.signature,
        &unsigned,
        DetachedSignatureContext::RealmActorMaterial,
        &key,
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    if let RealmActorMaterial::Event {
        event,
        commit,
        producer_signer_fact,
    } = &material.material
    {
        let full = arkret_wire::CommittedEventFullView {
            event: event.clone(),
            commit: commit.clone(),
        };
        crate::account_device_signer_evidence::verify_historical_producer_committed_event(
            &full,
            producer_signer_fact,
            authority,
            keys,
            event.event_id.digest_suite_code().digest_suite(),
        )?;
    }
    Ok(VerifiedRealmActorMaterial(material))
}
