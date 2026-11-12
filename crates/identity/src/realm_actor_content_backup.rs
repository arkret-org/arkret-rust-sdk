//! Native backup identity bindings. The document passed here must be the
//! independently accepted method-native original, not a newly resolved DID.

use arkret_models_crypto::RealmActorContentBackupRecipient;
use arkret_wire::ActorId;

use crate::{DidDocument, IdentityError, Result};

/// Check both the full target Actor and its independently accepted original
/// document. This stronger contract is distinct from the document-only API.
pub fn validate_realm_actor_content_backup_recipient_for_actor(
    actor: &ActorId,
    recipient: &RealmActorContentBackupRecipient,
    accepted_document: &DidDocument,
) -> Result<()> {
    let actor = actor.as_realm_actor_id().ok_or_else(|| {
        IdentityError::Protocol("native archive recipient requires a Realm actor".into())
    })?;
    if arkret_wire::project_did_to_core_id(&accepted_document.id)? != actor.principal_id {
        return Err(IdentityError::Protocol(
            "archive document belongs to another Actor".into(),
        ));
    }
    validate_recipient_document(recipient, accepted_document)
}

pub(crate) fn validate_recipient_document(
    recipient: &RealmActorContentBackupRecipient,
    accepted_document: &DidDocument,
) -> Result<()> {
    let invalid = || {
        IdentityError::Protocol(
            "native archive descriptor differs from its accepted X25519 keyAgreement original"
                .into(),
        )
    };
    recipient.validate()?;
    crate::validate_verification_method_relationship(
        accepted_document,
        &recipient.key_agreement_ref,
        &accepted_document.id,
        crate::DidVerificationRelationship::KeyAgreement,
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let normalized = arkret_models_identity::normalized_did_document(accepted_document)?;
    let absolute = |reference: &str| {
        if reference.starts_with('#') {
            format!("{}{reference}", accepted_document.id)
        } else {
            reference.to_owned()
        }
    };
    let selected = recipient.key_agreement_ref.as_str();
    let method = normalized["verification_methods"]
        .as_array()
        .and_then(|methods| {
            methods.iter().find(|method| {
                method
                    .get("verification_method")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|method| absolute(method) == selected)
            })
        })
        .ok_or_else(invalid)?;
    if method["controller_did"].as_str() != Some(accepted_document.id.as_str()) {
        return Err(invalid());
    }
    let material = &method["public_key_material"];
    let public = if let Some(multibase) = material
        .get("publicKeyMultibase")
        .and_then(serde_json::Value::as_str)
    {
        let bytes = arkret_canonical::decode_multibase_base58btc(multibase)?;
        if bytes.len() != 34 || bytes[..2] != [0xec, 0x01] {
            return Err(invalid());
        }
        bytes[2..].to_vec()
    } else if let Some(jwk) = material.get("publicKeyJwk") {
        if jwk["kty"] != "OKP" || jwk["crv"] != "X25519" || jwk.get("d").is_some() {
            return Err(invalid());
        }
        arkret_canonical::base64url_decode(jwk["x"].as_str().ok_or_else(invalid)?)?
    } else {
        return Err(invalid());
    };
    if public.len() != 32
        || arkret_canonical::base64url_encode(public) != recipient.public_key_base64url
    {
        return Err(invalid());
    }
    Ok(())
}

/// Verify a Manager's full immutable source against independently established
/// governance. This is historical packet provenance, not current Manager,
/// membership, history access or publication permission. No network resolver
/// or present-day Device directory participates.
pub fn verify_realm_actor_content_backup_source(
    packet: &arkret_models_crypto::KeyBackup,
    source: &arkret_models_integration::RealmActorContentBackupSource,
    authority: &crate::VerifiedRealmAuthority,
) -> Result<()> {
    use arkret_wire::{CommittedEventFullView, DetachedSignatureContext, RealmAuthorityTransition};
    let invalid = |message: &str| IdentityError::Protocol(message.into());
    let admission = &source.admission;
    if &admission.realm_actor_id.realm_id != authority.realm_id()
        || authority.authority_service_at(admission.governance_generation)
            != Some(&admission.service_id)
        || !authority.authorizes_issuer_at(
            &admission.service_id,
            Some(&admission.authority_ref),
            admission.accepted_at,
        )
    {
        return Err(invalid(
            "native admission issuer does not belong to its original governance tenure",
        ));
    }

    let history = &source.governance_history;
    let mut resolutions = vec![&history.genesis_resolution, &source.origin_resolution];
    for transition in &history.authority_transitions {
        resolutions.push(&transition.from_resolution);
        resolutions.push(&transition.to_resolution);
    }
    let mut keys = crate::RealmAuthorityKeyMap::new();
    let mut pin = |signature: &arkret_wire::DetachedObjectSignature| -> Result<()> {
        let did = crate::verification_method_did(signature.verification_method.as_str())?;
        let issuer = arkret_wire::project_did_to_core_id(&did)?;
        let mut selected = None;
        for resolution in &resolutions {
            if resolution.service_id != issuer {
                continue;
            }
            let Ok(document) =
                crate::authenticated_service_document_at(resolution, &issuer, signature.created_at)
            else {
                continue;
            };
            if crate::validate_verification_method_relationship(
                &document,
                &signature.verification_method,
                &document.id,
                crate::DidVerificationRelationship::AssertionMethod,
            )
            .is_err()
            {
                continue;
            }
            let key =
                crate::public_key_material_from_document(&document, &signature.verification_method)
                    .map_err(|error| invalid(&error.to_string()))?;
            if selected.as_ref().is_some_and(|previous| previous != &key) {
                return Err(invalid(
                    "immutable native source has conflicting historical Service keys",
                ));
            }
            selected = Some(key);
        }
        let key = selected.ok_or_else(|| {
            invalid("immutable native source lacks its original historical Service method")
        })?;
        keys.insert_at(&signature.verification_method, signature.created_at, key);
        Ok(())
    };
    pin(&history.genesis.commit.signature)?;
    pin(&source.device_authorization.commit.signature)?;
    pin(&admission.signature)?;
    for transition in &history.authority_transitions {
        pin(&transition.original.commit.signature)?;
        pin(&transition.handoff.old_authority_signature)?;
        pin(&transition.handoff.new_authority_acceptance_signature)?;
    }
    let verify_original = |event: &arkret_wire::Event,
                           commit: &arkret_wire::RealmCommit,
                           fact: Option<
        &arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
    >|
     -> Result<()> {
        let fact = fact.ok_or_else(|| {
            invalid(
                "original producer provenance is unavailable; no self-consistency-only fallback",
            )
        })?;
        crate::account_device_signer_evidence::verify_historical_producer_committed_event(
            &CommittedEventFullView {
                event: event.clone(),
                commit: commit.clone(),
            },
            fact,
            authority,
            &keys,
            event.event_id.digest_suite_code().digest_suite(),
        )
    };
    let genesis = &history.genesis;
    if genesis.event.kind != arkret_wire::EventKind::RealmCreate
        || arkret_wire::RealmId::from_event_id(&genesis.event.event_id)
            != admission.realm_actor_id.realm_id
        || genesis.commit.stream_position != 0
        || genesis.commit.previous_commit_ref.is_some()
        || genesis.commit.governance_generation != 0
        || history.authority_transitions.len() as u64 != admission.governance_generation
    {
        return Err(invalid(
            "native archive governance source is not the exact complete genesis-to-admission history",
        ));
    }
    verify_original(
        &genesis.event,
        &genesis.commit,
        genesis.producer_signer_fact.as_ref(),
    )?;
    for (index, transition) in history.authority_transitions.iter().enumerate() {
        let handoff = &transition.handoff;
        RealmAuthorityTransition {
            change_event: transition.original.event.clone(),
            change_commit: transition.original.commit.clone(),
            handoff: handoff.clone(),
        }
        .validate_shape()?;
        if handoff.from_generation != index as u64
            || handoff.to_generation != index as u64 + 1
            || authority.authority_service_at(handoff.from_generation)
                != Some(&handoff.from_service_id)
            || authority.authority_service_at(handoff.to_generation) != Some(&handoff.to_service_id)
            || !authority.authorizes_issuer_at(
                &handoff.to_service_id,
                Some(&arkret_wire::RealmCommitAuthorityRef::Handoff(
                    handoff.handoff_id.clone(),
                )),
                handoff.new_authority_acceptance_signature.created_at,
            )
        {
            return Err(invalid(
                "native archive handoff does not belong to the independently verified chain",
            ));
        }
        verify_original(
            &transition.original.event,
            &transition.original.commit,
            transition.original.producer_signer_fact.as_ref(),
        )?;
        let unsigned = arkret_canonical::unsigned_value(
            handoff,
            &[
                "old_authority_signature",
                "new_authority_acceptance_signature",
            ],
        )?;
        for (signature, context) in [
            (
                &handoff.old_authority_signature,
                DetachedSignatureContext::RealmAuthorityHandoffOld,
            ),
            (
                &handoff.new_authority_acceptance_signature,
                DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            ),
        ] {
            let key = crate::RealmAuthorityKeyDirectory::public_key_at(
                &keys,
                &signature.verification_method,
                signature.created_at,
            )
            .ok_or_else(|| invalid("original handoff signer is unavailable"))?;
            arkret_signatures::detached_object::verify_detached_object_signature(
                signature, &unsigned, context, &key,
            )
            .map_err(|error| invalid(&error.to_string()))?;
        }
    }
    let authorization = &source.device_authorization;
    verify_original(
        &authorization.event,
        &authorization.commit,
        Some(&authorization.producer_signer_fact),
    )?;
    if authorization.event.kind != arkret_wire::EventKind::DeviceAuthorize
        || authorization.event.actor_id.as_realm_actor_id() != Some(&admission.realm_actor_id)
        || authorization.event.event_id != admission.device_authorize_ref.event_id
        || authorization.commit.commit_id != admission.device_authorize_ref.commit_id
        || authorization.commit.stream_ref != admission.device_authorize_ref.stream_ref
        || authorization.commit.stream_position != admission.device_authorize_ref.stream_position
        || authorization.event.payload.get("device_id")
            != Some(&serde_json::to_value(&admission.device_id)?)
        || authorization
            .event
            .payload
            .get("authorized_generation_ref")
            .and_then(serde_json::Value::as_u64)
            != Some(admission.device_generation)
    {
        return Err(invalid(
            "native receipt author does not match its immutable Device authorization",
        ));
    }
    let device_did = authorization
        .event
        .payload
        .get("device_public_key_did")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("original Device authorization lacks its public key"))?;
    let expected = format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &arkret_canonical::base64url_decode(&admission.device_public_key_base64url)?
                .as_slice()
                .try_into()
                .map_err(|_| invalid("native original Device public key is not 32 bytes"))?
        )
    );
    if device_did != expected {
        return Err(invalid(
            "native receipt original public key differs from original authorization",
        ));
    }
    if !authorization
        .event
        .payload
        .get("scopes")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|scopes| {
            scopes.iter().any(|scope| {
                scope.get("effective_scope") == Some(&serde_json::json!(admission.effective_scope))
                    && scope
                        .get("actions")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|actions| {
                            actions.iter().any(|action| {
                                action.as_str() == Some("ak.self.keys.backups.resource.replace.v1")
                            })
                        })
            })
        })
    {
        return Err(invalid(
            "original Device authorization did not authorize PUT in this exact scope",
        ));
    }
    let issuer_key = crate::RealmAuthorityKeyDirectory::public_key_at(
        &keys,
        &admission.signature.verification_method,
        admission.signature.created_at,
    )
    .ok_or_else(|| invalid("native admission historical issuer is unavailable"))?;
    arkret_signatures::realm_actor_content_backup::verify_realm_actor_content_backup_admission_signature(admission, &issuer_key)
        .map_err(|error| invalid(&error.to_string()))?;
    arkret_signatures::realm_actor_content_backup::verify_realm_actor_backup_packet(
        packet, admission,
    )
    .map_err(|error| invalid(&error.to_string()))
}

/// Verify every entry of the complete archive manifest. `keys` is the
/// deployment's independently pinned historical authority/Service directory;
/// it must not resolve a receipt's arbitrary hint to a present-day key.
pub fn verify_realm_actor_archive_inventory(
    manifest: &arkret_models_integration::RealmActorArchiveInventoryManifest,
    authority: &crate::VerifiedRealmAuthority,
    keys: &dyn crate::RealmAuthorityKeyDirectory,
) -> Result<()> {
    use arkret_models_integration::*;
    let invalid = |message: &str| IdentityError::Protocol(message.into());
    manifest.validate_order()?;
    if &manifest.realm_actor_id.realm_id != authority.realm_id() {
        return Err(invalid("archive manifest belongs to another Realm"));
    }
    let actor = ActorId::Realm {
        realm_actor_id: manifest.realm_actor_id.clone(),
    };
    let verify_original = |original: &RealmActorBackupEventMaterial| -> Result<()> {
        crate::account_device_signer_evidence::verify_historical_producer_committed_event(
            &arkret_wire::CommittedEventFullView {
                event: original.event.clone(),
                commit: original.commit.clone(),
            },
            &original.producer_signer_fact,
            authority,
            keys,
            original.event.event_id.digest_suite_code().digest_suite(),
        )
    };
    let matches_ref = |original: &RealmActorBackupEventMaterial,
                       reference: &arkret_wire::CommittedEventRef| {
        original.event.event_id == reference.event_id
            && original.commit.commit_id == reference.commit_id
            && original.commit.stream_ref == reference.stream_ref
            && original.commit.stream_position == reference.stream_position
    };
    for entry in &manifest.entries {
        match entry {
            RealmActorArchiveInventoryEntry::Backup(entry) => {
                if entry.backup.actor_id != actor {
                    return Err(invalid("archive first-PUT packet belongs to another actor"));
                }
                verify_realm_actor_content_backup_source(
                    &entry.backup,
                    &entry.native_source,
                    authority,
                )?;
            }
            RealmActorArchiveInventoryEntry::Series(entry) => {
                verify_original(&entry.source)?;
                let record = &entry.record;
                if !matches_ref(&entry.source, &entry.source_ref)
                    || entry.source.event.kind != arkret_wire::EventKind::KeyBackupActiveSeries
                    || serde_json::to_value(&entry.source.event.payload)?
                        != serde_json::to_value(record)?
                    || record.actor_id != actor
                    || record.effective_scope.as_ref() != Some(&entry.effective_scope)
                {
                    return Err(invalid(
                        "archive series differs from its complete accepted original",
                    ));
                }
                arkret_models_collaboration::events_payloads::validate_key_backup_active_series_record(record)
                    .map_err(|error| invalid(&error.to_string()))?;
                // The accepted Fact has already passed the original governance
                // Commit digest and producer JWS checks above. Reuse its exact
                // same-method Service key without contaminating governor keys.
                let fact_key = match &entry.source.producer_signer_fact {
                    arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::RealmRecoveryService(fact)
                        if fact.verification_method == record.signature_proof.verification_method
                            && fact.actor_id == entry.source.event.actor_id
                            && fact.target_actor_id == actor => Some(arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                                bytes: arkret_canonical::base64url_decode(fact.public_key_base64url.as_str())?,
                            }),
                    _ => None,
                };
                let key = fact_key
                    .or_else(|| {
                        keys.public_key_at(
                            &record.signature_proof.verification_method,
                            record.issued_at,
                        )
                    })
                    .ok_or_else(|| invalid("archive series original Service key is unavailable"))?;
                arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
                    &record.signing_payload_bytes()?,
                    record.signature_proof.signature.as_str(),
                    &key,
                )
                .map_err(|error| invalid(&error.to_string()))?;
            }
            RealmActorArchiveInventoryEntry::Recipient(entry) => {
                verify_original(&entry.declaration)?;
                if !matches_ref(&entry.declaration, &entry.recipient_ref) {
                    return Err(invalid("archive recipient declaration coordinates differ"));
                }
                let event = &entry.declaration.event;
                let descriptor = &entry.content_backup_recipient;
                match event.kind {
                    arkret_wire::EventKind::RealmActorCreate => {
                        let payload: RealmActorCreatePayload =
                            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                        if payload.actor_id != actor
                            || &payload.recovery.content_backup_recipient != descriptor
                            || entry.recovery_begin.is_some()
                        {
                            return Err(invalid(
                                "archive recipient differs from its original creation",
                            ));
                        }
                        crate::verify_realm_actor_initial_resolution(
                            &payload,
                            entry.declaration.commit.committed_at,
                        )?;
                    }
                    arkret_wire::EventKind::RealmActorManagerChange => {
                        let payload: RealmActorManagerChangePayload =
                            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                        if event.actor_id != actor
                            || &payload.next_content_backup_recipient != descriptor
                            || entry.recovery_begin.is_some()
                        {
                            return Err(invalid(
                                "archive recipient differs from its original manager transfer",
                            ));
                        }
                        let (receipt, entries, witnesses) =
                            payload.method_history_evidence.webvh_material();
                        let mut log = Vec::new();
                        for entry in entries {
                            log.extend(arkret_canonical::canonical_json_bytes(entry)?);
                            log.push(b'\n');
                        }
                        let verified = crate::verify_did_webvh_v1_chain_and_witness_bytes(
                            &payload.next_resolution.did,
                            &log,
                            Some(&arkret_canonical::canonical_json_bytes(witnesses)?),
                        )
                        .map_err(|error| invalid(&error.to_string()))?;
                        if verified.log.head_version_id != payload.next_resolution.version_id
                            || entries
                                .last()
                                .map(arkret_canonical::canonical_sha256)
                                .transpose()?
                                .as_deref()
                                != Some(payload.next_resolution.method_history_head.as_str())
                        {
                            return Err(invalid(
                                "archive recipient native history terminal differs",
                            ));
                        }
                        let document: DidDocument =
                            serde_json::from_value(verified.log.head_state)?;
                        if arkret_models_identity::normalized_did_document_digest(&document)?
                            != receipt.document_digest
                        {
                            return Err(invalid(
                                "archive recipient native receipt names another original document",
                            ));
                        }
                        validate_realm_actor_content_backup_recipient_for_actor(
                            &actor, descriptor, &document,
                        )?;
                    }
                    arkret_wire::EventKind::RealmActorControlReset => {
                        let payload: RealmActorControlResetPayload =
                            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                        let begin = entry.recovery_begin.as_ref().ok_or_else(|| invalid("reset archive recipient requires its one exact accepted begin original"))?;
                        verify_original(begin)?;
                        if !matches_ref(begin, &payload.recovery_begin_ref)
                            || begin.event.kind != arkret_wire::EventKind::RealmActorRecoveryBegin
                        {
                            return Err(invalid("reset archive recipient begin original differs"));
                        }
                        let intent: RealmActorRecoveryBeginPayload =
                            serde_json::from_value(serde_json::to_value(&begin.event.payload)?)?;
                        if payload.target_actor_id != actor
                            || intent.target_actor_id != actor
                            || intent.next_content_backup_recipient.as_ref() != Some(descriptor)
                        {
                            return Err(invalid(
                                "reset does not install this exact replacement archive recipient",
                            ));
                        }
                        crate::verify_realm_actor_recovery_publication(
                            &intent,
                            &payload.published_method_history_evidence,
                            entry.declaration.commit.committed_at,
                        )?;
                    }
                    _ => {
                        return Err(invalid(
                            "archive recipient is not an accepted native declaration",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
