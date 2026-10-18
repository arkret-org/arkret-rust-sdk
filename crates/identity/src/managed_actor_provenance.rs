//! Verify private originals for a managed Account Device's first authority forward.

use std::collections::BTreeMap;

use arkret_canonical::DigestSuite;
use arkret_models_collaboration::authority_commit::{
    ForwardManagedActorProvenance, ManagedAccountabilitySelector, ManagedProfileSelector,
    PeerAuthorityForwardEventRequest, PeerAuthorityForwardMlsRequest,
    authority_forward_body_digest,
};
use arkret_models_collaboration::events_payloads::{
    ActorProfileCreatePayload, RealmCreatePayload, RealmPurpose,
};
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityGrantStatus,
};
use arkret_models_identity::{AuthenticatedServiceResolution, ForwardAccountDeviceSignerEvidence};
use arkret_models_integration::{AppletManagedActorProvisionPayload, AppletManagedActorRole};
use arkret_signatures::detached_object::verify_detached_object_signature;
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_wire::{
    AccountId, ActorId, ActorKind, ActorProfileId, AppletId, AuthorizationRef,
    DetachedSignatureContext, Did, DidCoreId, DidUrl, ErrorCode, Event, RealmCommit, RealmId,
    ScopeRef, WireError,
};
use chrono::{DateTime, Utc};

use crate::{
    DidVerificationRelationship, ProducerVerificationContext, RealmAuthorityKeyDirectory, Result,
    VerifiedProducerEvent, VerifiedRealmAuthority,
};

/// Inputs selected independently from authenticated transport and the governor's actual
/// registration.
pub struct ManagedForwardVerificationContext<'a> {
    pub source_service_id: &'a DidCoreId,
    pub destination_service_id: &'a DidCoreId,
    pub applet_id: &'a AppletId,
    pub applet_service_id: &'a DidCoreId,
    pub digest_suite: DigestSuite,
    pub now: DateTime<Utc>,
    pub authorities: &'a BTreeMap<RealmId, VerifiedRealmAuthority>,
    pub authority_keys: &'a dyn RealmAuthorityKeyDirectory,
}

/// Authenticated immutable source. It does not grant membership, installation or an action.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedManagedActorProvenance {
    original: ForwardManagedActorProvenance,
    account: AccountId,
    role: AppletManagedActorRole,
    source_time: DateTime<Utc>,
    event_id: arkret_wire::EventId,
    forward_body_digest: arkret_wire::Hash,
}

impl VerifiedManagedActorProvenance {
    pub fn original(&self) -> &ForwardManagedActorProvenance {
        &self.original
    }
    pub fn account(&self) -> &AccountId {
        &self.account
    }
    pub fn role(&self) -> AppletManagedActorRole {
        self.role
    }
    pub fn source_time(&self) -> DateTime<Utc> {
        self.source_time
    }

    /// A private verified token cannot be moved to another Event or another
    /// forward body when a consumer carries it into its accepting transaction.
    pub fn ensure_target(
        &self,
        event: &Event,
        forward_body_digest: &arkret_wire::Hash,
    ) -> Result<()> {
        if event.event_id != self.event_id
            || event.actor_id.as_account_id() != Some(&self.account)
            || forward_body_digest != &self.forward_body_digest
        {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "managed source token belongs to another Event or forward body",
            ));
        }
        Ok(())
    }

    /// Invoke again at the effect boundary; earlier verification cannot extend the source lease.
    pub fn ensure_live(&self, now: DateTime<Utc>) -> Result<()> {
        if now < self.source_time || now >= self.original.current.expires_at {
            return Err(rejected(
                ErrorCode::DeviceUnauthorized,
                "managed identity source expired or is from a future cut",
            ));
        }
        Ok(())
    }
}

pub fn verify_forwarded_managed_event_request(
    request: &PeerAuthorityForwardEventRequest,
    context: &ManagedForwardVerificationContext<'_>,
) -> Result<VerifiedManagedActorProvenance> {
    request.validate()?;
    let source = request
        .producer_managed_provenance
        .as_ref()
        .ok_or_else(|| {
            rejected(
                ErrorCode::SchemaViolation,
                "managed Device requires original provenance",
            )
        })?;
    let device = request.producer_device_evidence.as_ref().ok_or_else(|| {
        rejected(
            ErrorCode::SchemaViolation,
            "managed provenance requires Device evidence",
        )
    })?;
    verify(
        source,
        device,
        &request.event_submission.event,
        &authority_forward_body_digest(request)?,
        context,
    )
}

pub fn verify_forwarded_managed_mls_request(
    request: &PeerAuthorityForwardMlsRequest,
    context: &ManagedForwardVerificationContext<'_>,
) -> Result<VerifiedManagedActorProvenance> {
    request.validate()?;
    let source = request
        .producer_managed_provenance
        .as_ref()
        .ok_or_else(|| {
            rejected(
                ErrorCode::SchemaViolation,
                "managed Device requires original provenance",
            )
        })?;
    let device = request.producer_device_evidence.as_ref().ok_or_else(|| {
        rejected(
            ErrorCode::SchemaViolation,
            "managed provenance requires Device evidence",
        )
    })?;
    verify(
        source,
        device,
        &request.mls_submission.commit_event,
        &authority_forward_body_digest(request)?,
        context,
    )
}

fn verify(
    source: &ForwardManagedActorProvenance,
    device: &ForwardAccountDeviceSignerEvidence,
    event: &Event,
    body_digest: &arkret_wire::Hash,
    context: &ManagedForwardVerificationContext<'_>,
) -> Result<VerifiedManagedActorProvenance> {
    source.validate()?;
    let producer = crate::account_device_signer_evidence::verify_forwarded_account_device_producer(
        device,
        event,
        context.source_service_id,
        context.destination_service_id,
        body_digest,
        context.digest_suite,
        context.now,
    )?;
    let account = producer.account_id;
    let originals = &source.creation;
    let provision = &originals.provision.event;
    if !matches!(
        &provision.scope_ref,
        ScopeRef::Realm { realm_id } | ScopeRef::Circle { realm_id, .. }
            if realm_id == &provision.realm_id
    ) {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed creation requires its original Realm or Circle installation scope",
        ));
    }
    let payload: AppletManagedActorProvisionPayload = decode(provision)?;
    payload.validate()?;
    verify_applet_managed_initial_resolution(&payload, originals.provision.commit.committed_at)?;
    if payload.actor_id != ActorId::account(account.clone())
        || &payload.applet_id != context.applet_id
        || &payload.service_id != context.applet_service_id
        || event.applet_id.as_ref() != Some(context.applet_id)
        || event.actor_id != payload.actor_id
        || event.executed_by.is_some()
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed originals differ from the actual Account, Applet or registration Service",
        ));
    }
    let service_actor = ActorId::service(payload.service_id.clone());
    let authorization = AuthorizationRef::from(payload.applet_authority_ref.clone());
    let core = &device.device_projection_attestation.attestation;
    if core.authorization_window.expires_at.is_none() {
        return Err(rejected(
            ErrorCode::DeviceUnauthorized,
            "managed Device authorization requires its original finite window",
        ));
    }
    for original in originals.entries() {
        let item = &original.event;
        if item.actual_signer() != &service_actor
            || item.applet_id.as_ref() != Some(&payload.applet_id)
            || item.authorization_ref.as_ref() != Some(&authorization)
            || item.created_at != provision.created_at
            || original.commit.committed_at > core.attested_at
            || original.commit.committed_at < item.created_at
        {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "managed creation mixes original signers, bindings or acceptance cuts",
            ));
        }
        // The authenticated accepting Commit selects this original's digest suite;
        // a later business Realm may use a different suite.
        verify_original_commit(
            &original.commit,
            &device.service_resolution,
            &account.station_id,
        )?;
        let original_suite =
            arkret_canonical::digest_suite(original.commit.event_ref.digest_suite_code().as_str())?;
        let proof = item.producer_proof.as_ref().ok_or_else(|| {
            rejected(
                ErrorCode::SignatureInvalid,
                "managed original lacks producer proof",
            )
        })?;
        let key = service_key(
            &source.service_resolution,
            &payload.service_id,
            &proof.verification_method,
            item.created_at,
        )?;
        VerifiedProducerEvent::verify(
            item.clone(),
            &ProducerVerificationContext {
                actor: service_actor.clone(),
                verification_method: proof.verification_method.clone(),
                public_key: key,
                digest_suite: original_suite,
            },
        )?;
    }
    if provision.actor_id != service_actor || provision.executed_by.is_some() {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "provision was not authored by its original Service",
        ));
    }
    let genesis = &originals.pcr_genesis.event;
    let genesis_payload: RealmCreatePayload = decode(genesis)?;
    genesis_payload.object.validate()?;
    let pcr = RealmId::from_event_id(&genesis.event_id);
    let inception = &originals.pcr_genesis.commit;
    let initial_profile = &originals.profile.commit;
    let original_root =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
    if inception.governance_generation != 0
        || inception.authority_ref != original_root
        || initial_profile.governance_generation != 0
        || initial_profile.authority_ref != original_root
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed creation does not bind its original generation-zero authority",
        ));
    }
    initial_profile.validate_successor_of(inception)?;
    originals
        .accountability
        .commit
        .validate_successor_of(&originals.provision.commit)?;
    if genesis.actor_id != payload.actor_id
        || genesis.executed_by.as_ref() != Some(&service_actor)
        || genesis.scope_ref != ScopeRef::RealmGenesis
        || genesis_payload.object.purpose != RealmPurpose::AppletManagedControl
        || genesis_payload.object.governance_station_id != account.station_id
        || genesis_payload.object.initial_resolution.as_ref() != Some(&payload.initial_resolution)
        || !exact_ref(
            genesis,
            "applet_managed_actor_provision",
            &provision.event_id,
        )
        || core.event_authorization.authorization_ref.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: pcr.clone(),
            })
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed PCR genesis or original Device PCR does not bind provision",
        ));
    }
    let accountability = &originals.accountability.event;
    let endorsement: AccountabilityGrantPayload = decode(accountability)?;
    endorsement.validate_lifecycle_at(originals.accountability.commit.committed_at)?;
    if accountability.realm_id != provision.realm_id
        || accountability.scope_ref != provision.scope_ref
        || accountability.actor_id != service_actor
        || accountability.executed_by.is_some()
        || endorsement.issuer_id != payload.service_id
        || endorsement.subject_id != account.principal_id
        || !exact_ref(
            accountability,
            "applet_managed_actor_provision",
            &provision.event_id,
        )
        || endorsement.grant_status != AccountabilityGrantStatus::Active
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed accountability does not bind original issuer, subject and provision",
        ));
    }
    endorsement.proof.validate()?;
    let outer_method = &accountability
        .producer_proof
        .as_ref()
        .expect("verified original")
        .verification_method;
    if endorsement.proof.kind != arkret_wire::proof_kind::DETACHED_JWS
        || &endorsement.proof.verification_method != outer_method
        || endorsement.proof.created_at != accountability.created_at
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "accountability inner proof differs from its original Service method",
        ));
    }
    let key = service_key(
        &source.service_resolution,
        &payload.service_id,
        outer_method,
        accountability.created_at,
    )?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &endorsement.proof.jws,
            &endorsement.canonical_proof_binding_bytes()?,
            &key,
        )
        .map_err(|e| rejected(ErrorCode::SignatureInvalid, &e.to_string()))?;
    let profile = &originals.profile.event;
    let definition: ActorProfileCreatePayload = decode(profile)?;
    definition.object.validate()?;
    let actor_kind = match payload.actor_role {
        AppletManagedActorRole::Bot => ActorKind::Bot,
        AppletManagedActorRole::Ghost => ActorKind::Integration,
    };
    if profile.actor_id != payload.actor_id
        || profile.executed_by.as_ref() != Some(&service_actor)
        || profile.realm_id != pcr
        || profile.scope_ref
            != (ScopeRef::Realm {
                realm_id: pcr.clone(),
            })
        || !exact_ref(profile, "accountability", &accountability.event_id)
        || definition.object.principal_id != account.principal_id
        || definition.object.actor_kind != actor_kind
        || definition.object.accountable_principal_ids.as_slice() != [payload.service_id.clone()]
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed Profile differs from original role or accountability",
        ));
    }
    let profile_id = ActorProfileId::from_event_id(&profile.event_id);
    let current = &source.current.profile;
    let source_cut = &core.event_authorization;
    if current.commit.stream_position > source_cut.revision.stream_position
        || current.commit.governance_generation > source_cut.governance_generation
        || (current.commit.stream_position == source_cut.revision.stream_position
            && (current.commit.commit_id != source_cut.revision.commit_id
                || current.commit.governance_generation != source_cut.governance_generation))
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed Profile current is outside the exact Device PCR cut",
        ));
    }
    let value = &current.result.value;
    let ManagedProfileSelector::ActorProfile { actor_profile_id } = &current.result.selector;
    let expected_applet = serde_json::to_value(&payload.applet_id)?;
    let expected_external = payload
        .external_ref
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    for fields in [&definition.object.profile_fields, &value.profile_fields] {
        if fields.get("managed_by_applet") != Some(&expected_applet)
            || fields.get("external_ref") != expected_external.as_ref()
        {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "managed Profile Applet or Ghost external tuple differs",
            ));
        }
    }
    if current.realm_id != pcr
        || actor_profile_id != &profile_id
        || value.id.as_ref() != Some(&profile_id)
        || value.realm_id.as_ref() != Some(&pcr)
        || value.principal_id != account.principal_id
        || value.actor_kind != actor_kind
        || value.created_at != profile.created_at
        || value.accountable_principal_ids.as_slice() != [payload.service_id.clone()]
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "current managed Profile does not bind its immutable creation",
        ));
    }
    let current = &source.current.accountability;
    let value = &current.result.value;
    let scopes = endorsement.accountability_scope.normalized_set()?;
    let ManagedAccountabilitySelector::IdentityAccountability {
        issuer_id,
        subject_id,
        accountability_scope,
    } = &current.result.selector;
    if current.realm_id != accountability.realm_id
        || issuer_id != &endorsement.issuer_id
        || subject_id != &endorsement.subject_id
        || accountability_scope != &scopes
        || value.issuer_id != endorsement.issuer_id
        || value.subject_id != endorsement.subject_id
        || value.accountability_scope != scopes
        || value.grant_status != AccountabilityGrantStatus::Active
        || core.attested_at < value.not_before
        || context.now < value.not_before
        || value.expires_at.is_some_and(|end| context.now >= end)
    {
        return Err(rejected(
            ErrorCode::DeviceUnauthorized,
            "current accountability is not the original exact active endorsement",
        ));
    }
    for commit in [
        &source.current.profile.commit,
        &source.current.accountability.commit,
    ] {
        let authority = context.authorities.get(&commit.realm_id).ok_or_else(|| {
            rejected(
                ErrorCode::TemporarilyUnavailable,
                "managed current covering authority is unavailable",
            )
        })?;
        authority
            .verify_commit(commit, context.authority_keys)
            .map_err(|e| rejected(ErrorCode::SignatureInvalid, &e.to_string()))?;
        if commit.committed_at > core.attested_at
            || commit.committed_at < originals.pcr_genesis.commit.committed_at
        {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "managed current Commit is outside the frozen source cut",
            ));
        }
    }
    if source.current.expires_at > core.expires_at
        || core
            .authorization_window
            .expires_at
            .is_some_and(|end| source.current.expires_at > end)
        || source
            .current
            .accountability
            .result
            .value
            .expires_at
            .is_some_and(|end| source.current.expires_at > end)
    {
        return Err(rejected(
            ErrorCode::DeviceUnauthorized,
            "managed source exceeds its Device or actual current endorsement expiry ceiling",
        ));
    }
    let verified = VerifiedManagedActorProvenance {
        original: source.clone(),
        account,
        role: payload.actor_role,
        source_time: core.attested_at,
        event_id: event.event_id.clone(),
        forward_body_digest: body_digest.clone(),
    };
    verified.ensure_live(context.now)?;
    Ok(verified)
}

fn verify_original_commit(
    commit: &RealmCommit,
    resolution: &AuthenticatedServiceResolution,
    host: &DidCoreId,
) -> Result<()> {
    if commit.signature.created_at != commit.committed_at {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "original Commit signature time differs from acceptance",
        ));
    }
    let key = service_key(
        resolution,
        host,
        &commit.signature.verification_method,
        commit.signature.created_at,
    )?;
    verify_detached_object_signature(
        &commit.signature,
        &arkret_canonical::unsigned_value(commit, &["signature"])?,
        DetachedSignatureContext::RealmCommit,
        &key,
    )?;
    Ok(())
}

/// Original Service signatures never substitute for the Principal's native
/// self-certifying chain, witness thresholds or effective inception version.
pub fn verify_applet_managed_initial_resolution(
    payload: &AppletManagedActorProvisionPayload,
    accepted_at: DateTime<Utc>,
) -> Result<crate::DidDocument> {
    payload.validate()?;
    let did = &payload.initial_resolution.did;
    let (receipt, entries, witnesses) = payload.method_history_evidence.webvh_material();
    let mut log_bytes = Vec::new();
    for entry in entries {
        log_bytes.extend(arkret_canonical::canonical_json_bytes(entry)?);
        log_bytes.push(b'\n');
    }
    let witness_bytes = arkret_canonical::canonical_json_bytes(witnesses)?;
    let verified =
        crate::verify_did_webvh_v1_chain_and_witness_bytes(did, &log_bytes, Some(&witness_bytes))
            .map_err(|error| {
            rejected(
                ErrorCode::SignatureInvalid,
                &format!("managed Principal native history does not verify: {error}",),
            )
        })?;
    let terminal = verified.log.raw_entries.last().ok_or_else(|| {
        rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal native history has no terminal entry",
        )
    })?;
    if verified.log.head_version_id != payload.initial_resolution.version_id
        || arkret_canonical::canonical_sha256(terminal)?
            != payload.initial_resolution.method_history_head
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal native terminal differs from its original resolution",
        ));
    }
    let effective = arkret_signatures::webvh::validate_webvh_history_at(did, entries, accepted_at)
        .map_err(|error| {
            rejected(
                ErrorCode::SignatureInvalid,
                &format!("managed Principal original effective history does not verify: {error}",),
            )
        })?;
    // Managed Principals carry an independent operational controller. Human
    // identity-anchor document restrictions do not apply, but no history root
    // may appear in any of their operational DID documents.
    let roots = entries
        .iter()
        .filter_map(|entry| {
            entry
                .pointer("/parameters/updateKeys")
                .and_then(serde_json::Value::as_array)
        })
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    for entry in entries {
        let state = entry.get("state").ok_or_else(|| {
            rejected(
                ErrorCode::SignatureInvalid,
                "managed Principal history omits its document",
            )
        })?;
        let document: crate::DidDocument = serde_json::from_value(state.clone())?;
        document.validate()?;
        let encoded = serde_json::to_string(state)?;
        if roots.iter().any(|root| encoded.contains(root)) {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "managed Principal operational document exposes a history root",
            ));
        }
    }
    if effective.version_id != payload.initial_resolution.version_id {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal initial resolution was not effective at its original acceptance",
        ));
    }
    let document: crate::DidDocument = serde_json::from_value(verified.log.head_state)?;
    if arkret_models_identity::normalized_did_document_digest(&document)? != receipt.document_digest
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal method receipt names a different original document",
        ));
    }
    let first = verified.log.entries.first().ok_or_else(|| {
        rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal native history has no inception",
        )
    })?;
    let complete = arkret_models_identity::ResolutionMethodEvidenceBoundary {
        from_method_history_head: arkret_canonical::canonical_sha256(&entries[0])?,
        from_version_id: first.version_id.clone(),
        to_method_history_head: payload.initial_resolution.method_history_head.clone(),
        to_version_id: payload.initial_resolution.version_id.clone(),
    };
    crate::service_resolution_evidence::verify_webvh_history(
        did,
        &document,
        &complete,
        receipt,
        entries,
        witnesses,
        &payload.initial_resolution.method_history_head,
        &payload.initial_resolution.version_id,
    )
    .map_err(|error| {
        rejected(
            ErrorCode::SignatureInvalid,
            &format!("managed Principal original method receipt does not verify: {error}",),
        )
    })?;
    Ok(document)
}

fn service_key(
    resolution: &AuthenticatedServiceResolution,
    expected: &DidCoreId,
    method: &DidUrl,
    at: DateTime<Utc>,
) -> Result<PublicKeyMaterial> {
    let did = method
        .as_str()
        .split_once('#')
        .ok_or_else(|| {
            rejected(
                ErrorCode::SignatureInvalid,
                "Service proof lacks method fragment",
            )
        })?
        .0;
    if arkret_wire::project_did_to_core_id(&Did::new(did.to_owned())?)? != *expected {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "Service method belongs to another original signer",
        ));
    }
    let document = crate::authenticated_service_document_at(resolution, expected, at)?;
    crate::validate_verification_method_relationship(
        &document,
        method,
        &document.id,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|e| rejected(ErrorCode::SignatureInvalid, &e.to_string()))?;
    crate::public_key_material_from_document(&document, method)
        .map_err(|e| rejected(ErrorCode::SignatureInvalid, &e.to_string()))
}

fn exact_ref(event: &Event, role: &str, id: &arkret_wire::EventId) -> bool {
    let mut refs = event
        .semantic_refs
        .iter()
        .filter(|reference| reference.role == role);
    refs.next()
        .is_some_and(|reference| reference.critical && reference.id == id.as_str())
        && refs.next().is_none()
}

fn decode<T: serde::de::DeserializeOwned>(event: &Event) -> Result<T> {
    Ok(serde_json::from_value(serde_json::to_value(
        &event.payload,
    )?)?)
}

fn rejected(code: ErrorCode, message: &str) -> crate::IdentityError {
    WireError::ProtocolCode {
        code,
        message: message.into(),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
    use arkret_signatures::detached_object::sign_detached_object;
    use arkret_signatures::webvh::{
        ServiceRegistrationInceptionInput, prepare_service_registration_inception,
    };
    use arkret_wire::{EventId, RealmCommitAuthorityRef, RealmCommitId, ServiceKind};
    use chrono::{Duration, TimeZone};
    use ed25519_dalek::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    fn signed_source() -> (AuthenticatedServiceResolution, DidCoreId, RealmCommit) {
        let at = Utc.with_ymd_and_hms(2026, 10, 18, 0, 0, 0).unwrap();
        let mut rng = ChaCha20Rng::from_seed([147; 32]);
        let registration = ServiceRegistrationKey::new(
            ServiceKind::Station,
            CanonicalServiceUrl::new("https://provenance.arkret.org/").unwrap(),
        )
        .unwrap();
        let inception = prepare_service_registration_inception(
            &mut rng,
            &ServiceRegistrationInceptionInput {
                provider_endpoint: &"https://identity.arkret.org/".parse().unwrap(),
                registration_key: &registration,
                also_known_as: &[],
                version_time: at,
                did_key_fragment: None,
            },
        )
        .unwrap();
        let host =
            arkret_wire::project_did_to_core_id(&Did::new(inception.did.clone()).unwrap()).unwrap();
        let resolution = crate::build_authenticated_webvh_service_resolution(
            host.clone(),
            "station".into(),
            serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
            vec![inception.log_entry.clone()],
            vec![],
            at + Duration::seconds(10),
        )
        .unwrap();
        let key = SigningKey::from_bytes(&inception.did_key_seed);
        let method = DidUrl::new(inception.did_key_id.clone()).unwrap();
        let event = EventId::from_digest(DigestSuite::Sha256, [171; 32]);
        let realm = RealmId::from_event_id(&event);
        let committed_at = at + Duration::seconds(5);
        let signature = sign_detached_object(
            &serde_json::json!({}),
            DetachedSignatureContext::RealmCommit,
            method.clone(),
            committed_at,
            &key,
        )
        .unwrap();
        let mut commit = RealmCommit {
            commit_id: RealmCommitId::from_digest([0; 32]),
            realm_id: realm.clone(),
            stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id: realm },
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: event.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(event),
            committed_at,
            producer_signer_fact_digest: None,
            signature,
        };
        commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            commit.canonical_id_bytes().unwrap(),
        ));
        commit.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            method,
            committed_at,
            &key,
        )
        .unwrap();
        (resolution, host, commit)
    }

    #[test]
    fn original_acceptance_requires_real_source_history_and_exact_signed_bytes() {
        let (resolution, host, commit) = signed_source();
        verify_original_commit(&commit, &resolution, &host).unwrap();
        let mut changed = commit.clone();
        changed.governance_generation += 1;
        assert!(verify_original_commit(&changed, &resolution, &host).is_err());
        assert!(
            verify_original_commit(
                &commit,
                &resolution,
                &DidCoreId::new("ak:did_core:web:other.arkret.org").unwrap()
            )
            .is_err()
        );
        let mut incomplete = resolution;
        let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            log_entries, ..
        } = &mut incomplete.method_history_evidence
        else {
            unreachable!()
        };
        log_entries.clear();
        assert!(verify_original_commit(&commit, &incomplete, &host).is_err());
    }
}
