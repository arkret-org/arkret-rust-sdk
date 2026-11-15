//! Recording keys bound to actual installed RFC 9420 epoch material, and a
//! synchronous local writer fence. Network/current authority is supplied by the
//! SDK facade; this lower layer never treats a caller boolean as authority.

use std::sync::{Arc, Mutex, MutexGuard};

use arkret_canonical::canonical::DigestSuite;
use arkret_crypto::call_recording::{RecordingStreamEncoder, RecordingStreamOutput};
use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::events_payloads::call::{
    CallRecordingArtifact, CallRecordingEncryptionContext, CallRecordingStartPayload,
    RecordingCaptureKind,
};
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialRequestBody, MlsGroupStateMaterialResponseBody,
};
use arkret_models_crypto::{EncryptedAttachmentKeyRef, MlsCommitPayload};
use arkret_wire::{
    CommittedEventFullView, Event, EventId, EventKind, MlsGroupId, MlsGroupValue, ScopeRef,
};

use crate::{ArkretMlsGroup, MlsError as Error, MlsPublicGroupTracker, Result};

/// Local codec choices, independent of the original signed Start fields.
/// This is not a wire descriptor and carries no authority or MLS source claim.
pub struct RecordingStreamParameters {
    pub segment_bytes: u32,
    pub media_type: String,
    pub digest_suite: DigestSuite,
}

/// A private-field local capability for exact installed MLS material. It proves
/// RFC state equality, not authority acceptance by itself. The facade combines
/// this with bound current results and independently verified original receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledRecordingEpoch {
    scope: ScopeRef,
    genesis: EventId,
    state: EventId,
    group_id: MlsGroupId,
    epoch: u64,
    context: Vec<u8>,
    tree: Vec<u8>,
}

impl InstalledRecordingEpoch {
    /// The enclosing authority and producer signatures must already be verified
    /// by the caller. This function additionally checks the exact content refs,
    /// native current coordinates and real local RFC GroupContext/tree.
    pub fn verify_installed_material(
        group: &ArkretMlsGroup,
        current: &MlsGroupValue,
        genesis: &CommittedEventFullView,
        state: &CommittedEventFullView,
        request: &MlsGroupStateMaterialRequestBody,
        material: &MlsGroupStateMaterialResponseBody,
    ) -> Result<Self> {
        genesis.validate_shape()?;
        state.validate_shape()?;
        if !group.is_active()
            || &current.effective_scope != group.scope()
            || current.genesis_event_ref != genesis.event.event_id
            || current.current_mls_commit_event_ref != state.event.event_id
            || current.epoch != group.epoch()
            || current.cipher_suite.as_str() != group.group_ciphersuite_canonical_id()?
            || current.covered_key_access_revision != current.current_key_access_revision
            || genesis.event.kind != EventKind::MlsGenesis
            || genesis.event.scope_ref != current.effective_scope
            || state.event.scope_ref != current.effective_scope
            || genesis.event.realm_id != state.event.realm_id
            || current.effective_scope.realm_id_opt() != Some(&state.event.realm_id)
        {
            return Err(protocol(
                "recording source differs from actual current installed MLS state",
            ));
        }
        let genesis_payload: MlsGenesisPayload =
            serde_json::from_value(serde_json::to_value(&genesis.event.payload)?)?;
        genesis_payload.validate()?;
        if genesis_payload.effective_scope() != &current.effective_scope
            || genesis_payload.mls_group_id()? != group.group_id()
            || genesis_payload.cipher_suite != current.cipher_suite
        {
            return Err(protocol(
                "recording immutable MLS Genesis differs from current group",
            ));
        }
        let (binding, group_info_ref, tree_ref) = match state.event.kind {
            EventKind::MlsGenesis if state.event.event_id == genesis.event.event_id => (
                genesis_payload.governance_binding,
                genesis_payload.group_info_ref,
                genesis_payload.ratchet_tree_ref,
            ),
            EventKind::MlsCommit => {
                let payload: MlsCommitPayload =
                    serde_json::from_value(serde_json::to_value(&state.event.payload)?)?;
                payload.validate()?;
                (
                    payload.governance_binding().clone(),
                    payload.group_info_ref().clone(),
                    payload.ratchet_tree_ref().clone(),
                )
            }
            _ => {
                return Err(protocol(
                    "recording Q must identify the original MLS Genesis or Commit",
                ));
            }
        };
        if binding.effective_scope() != &current.effective_scope
            || binding.next_epoch() != current.epoch
            || binding.key_access_revision() != current.covered_key_access_revision
            || binding.mls_group_id()? != group.group_id()
            || request.effective_scope != current.effective_scope
            || request.group_state_event_id != state.event.event_id
            || request.epoch != current.epoch
            || request.mls_group_id != group.group_id()
            || request.group_info_ref != group_info_ref
            || request.ratchet_tree_ref != tree_ref
            || current.public_tree_ref != tree_ref
        {
            return Err(protocol(
                "recording material selectors differ from accepted Q",
            ));
        }
        group.verify_installed_historical_base(state, &state.event.event_id)?;
        let bytes = material.validate_for_request(request)?;
        let published = MlsPublicGroupTracker::from_external(
            &bytes.group_info_bytes,
            &bytes.ratchet_tree_bytes,
            group.group_id().as_str(),
            current.epoch,
        )?;
        if published.governance_binding()? != binding {
            return Err(protocol(
                "recording public material has a different authenticated governance binding",
            ));
        }
        let (local_info, local_tree) = group.public_group_state_bytes()?;
        let local = MlsPublicGroupTracker::from_external(
            &local_info,
            &local_tree,
            group.group_id().as_str(),
            group.epoch(),
        )?;
        local.verify_publication(&bytes.group_info_bytes, &bytes.ratchet_tree_bytes)?;
        Ok(Self {
            scope: current.effective_scope.clone(),
            genesis: current.genesis_event_ref.clone(),
            state: state.event.event_id.clone(),
            group_id: group.group_id(),
            epoch: current.epoch,
            context: published.group_context_bytes()?,
            tree: published.ratchet_tree_bytes()?,
        })
    }

    pub fn effective_scope(&self) -> &ScopeRef {
        &self.scope
    }
    pub fn genesis_event_ref(&self) -> &EventId {
        &self.genesis
    }
    pub fn group_state_event_ref(&self) -> &EventId {
        &self.state
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn require_installed(&self, group: &ArkretMlsGroup) -> Result<()> {
        if !group.is_active()
            || group.scope() != &self.scope
            || group.group_id() != self.group_id
            || group.epoch() != self.epoch
        {
            return Err(protocol(
                "recording epoch capability no longer matches the installed group",
            ));
        }
        let (info, tree) = group.public_group_state_bytes()?;
        let local =
            MlsPublicGroupTracker::from_external(&info, &tree, self.group_id.as_str(), self.epoch)?;
        if local.group_context_bytes()? != self.context || local.ratchet_tree_bytes()? != self.tree
        {
            return Err(protocol("recording epoch capability has stale RFC state"));
        }
        Ok(())
    }

    pub fn require_key_ref(&self, key_ref: &EncryptedAttachmentKeyRef) -> Result<()> {
        if key_ref.group_state_ref.event_id()? != self.state {
            return Err(protocol(
                "recording key_ref does not resolve to exact accepted Q",
            ));
        }
        Ok(())
    }

    /// A previously authorized original epoch remains the key source of its old
    /// segment. This never substitutes today's epoch or an attachment/history
    /// content root. The host independently enforces the existing history-read
    /// gate before restoring any old member-held private MLS state.
    pub fn decrypt_recording(
        &self,
        group: &ArkretMlsGroup,
        start_event_id: &EventId,
        start: &CallRecordingStartPayload,
        artifact: &CallRecordingArtifact,
        ciphertext: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.require_installed(group)?;
        self.require_key_ref(&artifact.encryption.key_ref)?;
        artifact
            .encryption
            .validate_start_binding(start_event_id, start)?;
        if self.scope.realm_id_opt() != Some(&artifact.realm_id) {
            return Err(protocol(
                "recording artifact belongs to another effective Realm",
            ));
        }
        let exported =
            crate::exporter_kdf::derive_rtc_recording_key(group, &artifact.encryption.context)?;
        let key = zeroize::Zeroizing::new(
            <[u8; 32]>::try_from(exported.as_slice())
                .map_err(|_| protocol("recording exporter returned wrong key size"))?,
        );
        Ok(arkret_crypto::call_recording::decrypt_recording(
            &key, artifact, ciphertext,
        )?)
    }
}

struct FenceState {
    generation: u64,
    latest: InstalledRecordingEpoch,
    enabled: bool,
}

/// Every host epoch-key install and new-epoch plaintext delivery must use this
/// same instance. Merely notifying a recorder asynchronously is insufficient.
/// The codec cannot prove that a host actually routes all lifecycle hooks here.
#[derive(Clone)]
pub struct RecordingEpochFence {
    state: Arc<Mutex<FenceState>>,
}

impl RecordingEpochFence {
    pub fn new(source: &InstalledRecordingEpoch) -> Self {
        Self {
            state: Arc::new(Mutex::new(FenceState {
                generation: 0,
                latest: source.clone(),
                enabled: true,
            })),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, FenceState>> {
        self.state
            .lock()
            .map_err(|_| protocol("recording writer fence poisoned"))
    }

    /// Stop all old writers before executing the actual synchronous key-install
    /// hook. Failure leaves capture disabled. Never bump a remote timestamp.
    pub fn with_epoch_install<T>(&self, install: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut state = self.lock()?;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| protocol("recording writer generation overflow"))?;
        state.enabled = false;
        install()
    }

    /// Called only after installation and requalification of the real new group.
    /// Even reinstalling the same epoch never re-enables an old writer token.
    pub fn adopt_installed_epoch(
        &self,
        group: &ArkretMlsGroup,
        source: &InstalledRecordingEpoch,
    ) -> Result<()> {
        let mut state = self.lock()?;
        source.require_installed(group)?;
        if source.scope != state.latest.scope
            || source.genesis != state.latest.genesis
            || source.epoch < state.latest.epoch
            || (source.epoch == state.latest.epoch && source != &state.latest)
        {
            return Err(protocol(
                "recording writer fence cannot adopt a different group or roll back epoch",
            ));
        }
        state.latest = source.clone();
        state.enabled = true;
        Ok(())
    }

    /// Use the same fence around actual plaintext delivery, not a later recorder
    /// notification. The callback must not recursively acquire this fence.
    pub fn with_media_delivery<T>(
        &self,
        group: &ArkretMlsGroup,
        source: &InstalledRecordingEpoch,
        deliver: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let state = self.lock()?;
        source.require_installed(group)?;
        if !state.enabled || &state.latest != source {
            return Err(protocol(
                "recording media source is not enabled at this writer fence",
            ));
        }
        deliver()
    }

    /// Lifecycle/revocation/qualification changes stop capture without generating
    /// a synthetic Stop Event. The host still uses the real native Stop/newStart.
    pub fn stop_capture(&self) -> Result<()> {
        let mut state = self.lock()?;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| protocol("recording writer generation overflow"))?;
        state.enabled = false;
        Ok(())
    }

    pub fn begin_recording(
        &self,
        group: &ArkretMlsGroup,
        source: &InstalledRecordingEpoch,
        start_event: &Event,
        focus_id: String,
        parameters: RecordingStreamParameters,
    ) -> Result<FencedRecordingWriter> {
        let state = self.lock()?;
        source.require_installed(group)?;
        if start_event.kind != EventKind::CallRecordingStart
            || start_event.scope_ref != source.scope
            || source.scope.realm_id_opt() != Some(&start_event.realm_id)
        {
            return Err(protocol(
                "recording Start has another kind or effective scope",
            ));
        }
        start_event.verify_event_id_matches_content_with_digest_suite(
            start_event.realm_id.digest_suite_code().digest_suite(),
        )?;
        let start: CallRecordingStartPayload =
            serde_json::from_value(serde_json::to_value(&start_event.payload)?)?;
        start.validate().map_err(protocol)?;
        let key_ref = start
            .capture_metadata
            .key_ref
            .as_ref()
            .ok_or_else(|| protocol("recording Start did not freeze Q"))?;
        source.require_key_ref(key_ref)?;
        if !state.enabled
            || &state.latest != source
            || start.capture_kind != RecordingCaptureKind::Recording
        {
            return Err(protocol(
                "recording Start differs from enabled original source",
            ));
        }
        // The focus is a separate accepted Call-source input, not an MLS
        // property. Every other Context member comes from the original Event.
        let context = CallRecordingEncryptionContext {
            realm_id: start_event.realm_id.clone(),
            call_id: start.call_id.clone(),
            focus_id,
            recording_id: start.recording_id.clone(),
            media_service_id: start.recording_agent_id.clone(),
            recording_start_event_id: start_event.event_id.clone(),
        };
        let exported = crate::exporter_kdf::derive_rtc_recording_key(group, &context)?;
        let key = zeroize::Zeroizing::new(
            <[u8; 32]>::try_from(exported.as_slice())
                .map_err(|_| protocol("recording exporter returned wrong key size"))?,
        );
        let encoder = RecordingStreamEncoder::fresh(
            *key,
            context,
            key_ref.clone(),
            parameters.segment_bytes,
            parameters.media_type,
            parameters.digest_suite,
        )?;
        encoder
            .encryption()
            .validate_start_binding(&start_event.event_id, &start)?;
        Ok(FencedRecordingWriter {
            fence: self.clone(),
            generation: state.generation,
            source: source.clone(),
            encoder,
        })
    }
}

/// A writer cannot admit plaintext after its fence's epoch-install invalidation.
/// Its already buffered old-epoch tail may still be finished and published later.
pub struct FencedRecordingWriter {
    fence: RecordingEpochFence,
    generation: u64,
    source: InstalledRecordingEpoch,
    encoder: RecordingStreamEncoder,
}

impl FencedRecordingWriter {
    pub fn encryption(
        &self,
    ) -> &arkret_models_collaboration::events_payloads::call::CallRecordingEncryption {
        self.encoder.encryption()
    }

    pub fn push_to(
        &mut self,
        plaintext: &[u8],
        emit: impl FnMut(&[u8]) -> arkret_crypto::Result<()>,
    ) -> Result<()> {
        let state = self.fence.lock()?;
        if !state.enabled || state.generation != self.generation || state.latest != self.source {
            return Err(protocol(
                "old recording writer stopped before epoch-key installation",
            ));
        }
        self.encoder.push_to(plaintext, emit)?;
        Ok(())
    }

    pub fn finish(
        self,
        emit: impl FnMut(&[u8]) -> arkret_crypto::Result<()>,
    ) -> Result<RecordingStreamOutput> {
        Ok(self.encoder.finish(emit)?)
    }
}

fn protocol(message: &str) -> Error {
    Error::Protocol(message.to_owned())
}

#[cfg(test)]
mod tests;
