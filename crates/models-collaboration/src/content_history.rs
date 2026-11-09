//! Original owning-Station recovery proof; never a current routing source.

use arkret_models_crypto::{
    ContentBackupSourceAttestation, ContentEndpoint, ContentRecoveryBinding,
    ContentRecoverySourceAttestation,
};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::{Event, EventKind, Hash, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authority_commit::HistoricalProducerSignerFact;

include!("generated/content_history_contracts.rs");

impl ContentBackupSource {
    /// Byte binding after independent original producer and typed-slot projection.
    /// This does not verify the Service method history, signature or storage.
    pub fn validate_submission_binding(
        &self,
        event: &Event,
        actual_producer: &ContentEndpoint,
        destination: &arkret_wire::DidCoreId,
        registered_protections_digest: &Hash,
    ) -> Result<()> {
        let source = &self.attestation;
        source.validate()?;
        let account = actual_producer.actor_id.as_account_id().ok_or_else(|| {
            WireError::Protocol("backup source requires an actual Account producer".to_owned())
        })?;
        if self.origin_resolution.service_id != account.station_id
            || self.origin_resolution.service_kind != "station"
        {
            return Err(WireError::Protocol(
                "backup source is not the actual owning Station".to_owned(),
            ));
        }
        source.validate_original_binding(
            event,
            actual_producer,
            destination,
            registered_protections_digest,
        )
    }
}

/// Candidate integrity only. Native admission independently enforces complete
/// registered-slot coverage, issuer qualification, signature and destination.
pub(crate) fn validate_backup_source_candidates(
    events: &[&Event],
    sources: Option<&[ContentBackupSource]>,
) -> Result<()> {
    let Some(sources) = sources else {
        return Ok(());
    };
    if sources.is_empty() || sources.len() > events.len() || sources.len() > 2 {
        return Err(WireError::Protocol(
            "invalid number of original backup sources".to_owned(),
        ));
    }
    let mut next = 0;
    for source in sources {
        source.attestation.validate()?;
        let offset = events[next..]
            .iter()
            .position(|e| e.event_id == source.attestation.event_ref)
            .ok_or_else(|| {
                WireError::Protocol("extra, duplicate or unordered backup source".to_owned())
            })?;
        let event = events[next + offset];
        next += offset + 1;
        let declared = &source.attestation;
        let account = declared
            .producer
            .actor_id
            .as_account_id()
            .expect("validated Account producer");
        if declared.event_original_digest.as_str() != arkret_canonical::canonical_sha256(event)?
            || declared.effective_scope != event.scope_ref
            || &declared.producer.actor_id != event.executed_by.as_ref().unwrap_or(&event.actor_id)
            || source.origin_resolution.service_id != account.station_id
            || source.origin_resolution.service_kind != "station"
        {
            return Err(WireError::Protocol(
                "backup-source candidate differs from original bytes".to_owned(),
            ));
        }
    }
    Ok(())
}

/// The original client carrier rejects source; only the owning Station emits this peer form.
pub type PeerMlsCommitSubmission = arkret_wire::MlsCommitSubmission<ContentRecoverySource>;

#[derive(Serialize)]
struct UnsignedRecoverySourceAttestation<'a> {
    event_ref: &'a arkret_wire::EventId,
    replacement: &'a ContentEndpoint,
    effective_scope: &'a arkret_wire::ScopeRef,
    base_group_state_ref: &'a arkret_wire::EventId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    previous_epoch: u64,
    inventory_digest: &'a Hash,
    verification_method: &'a arkret_wire::DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    attested_at: &'a DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: &'a DateTime<Utc>,
}

impl ContentRecoverySource {
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let ContentRecoverySourceAttestation {
            event_ref,
            replacement,
            effective_scope,
            base_group_state_ref,
            previous_epoch,
            inventory_digest,
            verification_method,
            attested_at,
            expires_at,
            signature: _,
        } = &self.attestation;
        let value = UnsignedRecoverySourceAttestation {
            event_ref,
            replacement,
            effective_scope,
            base_group_state_ref,
            previous_epoch: *previous_epoch,
            inventory_digest,
            verification_method,
            attested_at,
            expires_at,
        };
        let mut bytes = b"ak.mls.recovery_source.v1\n".to_vec();
        bytes.extend(arkret_canonical::canonical_json_bytes(&value)?);
        Ok(bytes)
    }

    /// Byte binding at forwarding time. Native authority, original service
    /// signature and the accepting clock remain separate mandatory checks.
    pub fn validate_submission_binding(&self, event: &Event) -> Result<()> {
        let source = &self.attestation;
        let account = event.actual_signer().as_account_id().ok_or_else(|| {
            WireError::Protocol(
                "recovery source requires the original actual Account signer".to_owned(),
            )
        })?;
        let binding: ContentRecoveryBinding = serde_json::from_value(
            event
                .payload
                .get("recovery_binding")
                .cloned()
                .ok_or_else(|| WireError::Protocol("missing recovery binding".to_owned()))?,
        )?;
        binding.validate()?;
        if event.kind != EventKind::MlsCommit
            || self.origin_resolution.service_id != account.station_id
            || self.origin_resolution.service_kind != "station"
            || source.event_ref != event.event_id
            || source.replacement != binding.replacement
            || &source.replacement.actor_id != event.actual_signer()
            || source.effective_scope != event.scope_ref
            || source.base_group_state_ref != binding.base_group_state_ref
            || event.payload.get("base_group_state_ref")
                != Some(&serde_json::to_value(&source.base_group_state_ref)?)
            || event
                .payload
                .get("previous_epoch")
                .and_then(serde_json::Value::as_str)
                != Some(source.previous_epoch.to_string().as_str())
            || source.previous_epoch != binding.expected_epoch
            || source.inventory_digest != binding.inventory_digest
            || source.expires_at - source.attested_at > chrono::Duration::seconds(300)
            || source.expires_at <= source.attested_at
            || event
                .producer_proof
                .as_ref()
                .map(|proof| &proof.verification_method)
                != Some(&source.verification_method)
        {
            return Err(WireError::Protocol(
                "recovery source differs from exact original submission binding".to_owned(),
            ));
        }
        Ok(())
    }

    /// Original-time byte binding; native historical authority and signature are independent.
    pub fn validate_original_binding(
        &self,
        event: &Event,
        committed_at: DateTime<Utc>,
        fact: &HistoricalProducerSignerFact,
    ) -> Result<()> {
        self.validate_submission_binding(event)?;
        let source = &self.attestation;
        if source.attested_at > committed_at || source.expires_at <= committed_at {
            return Err(WireError::Protocol(
                "recovery source was not fresh at original acceptance".into(),
            ));
        }
        let (actor, method, authorization, accepted_at) = match fact {
            HistoricalProducerSignerFact::AccountDevice(f) => {
                f.validate_event_binding(event, event.event_id.digest_suite_code().digest_suite())?;
                if source.replacement.endpoint
                    != (arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                        device_id: f.device_id.clone(),
                    })
                {
                    return Err(WireError::Protocol(
                        "recovery source Device mismatch".to_owned(),
                    ));
                }
                (
                    &f.actor,
                    &f.verification_method,
                    &f.key.authorization_ref.event_id,
                    f.accepted_at,
                )
            }
            HistoricalProducerSignerFact::AgentRuntime(f) => {
                f.validate_event_binding(event, event.event_id.digest_suite_code().digest_suite())?;
                if source.replacement.endpoint
                    != (arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                        verification_method: f.verification_method.clone(),
                    })
                {
                    return Err(WireError::Protocol(
                        "Agent recovery source cannot use a Device endpoint".to_owned(),
                    ));
                }
                (
                    &f.actor_id,
                    &f.verification_method,
                    &f.authorization_event_ref,
                    f.accepted_at,
                )
            }
            _ => {
                return Err(WireError::Protocol(
                    "unsupported recovery source producer".to_owned(),
                ));
            }
        };
        // The producer fact authenticates the Event signing key. The accepted
        // RFC recovery path independently binds the replacement leaf key.
        if actor != &source.replacement.actor_id
            || method != &source.verification_method
            || authorization != &source.replacement.authorization_event_ref
            || accepted_at != committed_at
            || fact.event_id() != &event.event_id
        {
            return Err(WireError::Protocol(
                "original signer fact differs from origin endpoint proof".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn original_fact_digest(fact: &HistoricalProducerSignerFact) -> Result<Hash> {
        fact.digest()
    }
}
