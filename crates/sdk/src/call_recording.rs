//! Own-Station-bound current MLS source for recording. The wire protocol lives
//! in the model crates; this adapter only joins existing verified effects.

use arkret_http_client::own_station_results::BoundOwnStationResponse;
use arkret_identity::{VerifiedProducerEvent, VerifiedRealmCommit};
use arkret_mls::ArkretMlsGroup;
use arkret_mls::call_recording::{
    FencedRecordingWriter, InstalledRecordingEpoch, RecordingEpochFence,
};
use arkret_models_collaboration::events_payloads::call::{
    CallRecordingEncryptionContext, CallRecordingStartPayload,
};
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialResponseBody, MlsMemberGroupStateMaterialReadRequestBody,
};
use arkret_wire::{
    CommittedEventFullView, CurrentSelector, CurrentState, EventKind, MlsGroupValue, RealmId,
    RealmStateSnapshot, WireError,
};

use crate::DigestSuite;

/// No deserializer or unchecked constructor. A wire MlsGroupValue or an arbitrary
/// key_ref cannot be promoted to this local authority capability.
pub struct BoundRecordingSource {
    current: BoundOwnStationResponse<RealmId, RealmStateSnapshot>,
    material: BoundOwnStationResponse<
        MlsMemberGroupStateMaterialReadRequestBody,
        MlsGroupStateMaterialResponseBody,
    >,
    installed: InstalledRecordingEpoch,
}

impl BoundRecordingSource {
    /// Join native current winning state, both original producer/authority
    /// signatures, authorized raw public material and actual local RFC state.
    /// This does not fetch unavailable history or treat a Welcome as authority.
    pub fn bind(
        group: &ArkretMlsGroup,
        current: BoundOwnStationResponse<RealmId, RealmStateSnapshot>,
        material: BoundOwnStationResponse<
            MlsMemberGroupStateMaterialReadRequestBody,
            MlsGroupStateMaterialResponseBody,
        >,
        genesis_producer: &VerifiedProducerEvent,
        genesis_commit: &VerifiedRealmCommit,
        state_producer: &VerifiedProducerEvent,
        state_commit: &VerifiedRealmCommit,
    ) -> Result<Self, WireError> {
        if current.session() != material.session() {
            return Err(protocol(
                "recording current and material belong to different live sessions",
            ));
        }
        let snapshot = current.value().map_err(protocol)?;
        snapshot.require_full_recovery()?;
        if &snapshot.realm_id != current.request()
            || group.scope().realm_id_opt() != Some(current.request())
            || material.request().caller_actor_id != group.local_actor_id().clone()
        {
            return Err(protocol(
                "recording source request differs from real group scope or local endpoint",
            ));
        }
        let mut matches = snapshot.current_state_entries.iter().filter_map(|row| {
            let CurrentState::Value {
                selector,
                source_stream_ref,
                value,
                ..
            } = row;
            match selector {
                CurrentSelector::MlsGroup { scope_ref } if scope_ref == group.scope() => {
                    Some((source_stream_ref, value))
                }
                _ => None,
            }
        });
        let (stream, value) = matches
            .next()
            .ok_or_else(|| protocol("current winning MLS source unavailable"))?;
        if matches.next().is_some()
            || stream != &arkret_wire::CommitStreamRef::from_scope(group.scope(), None)?
        {
            return Err(protocol(
                "recording current has duplicate or wrong-stream MLS source",
            ));
        }
        let value: MlsGroupValue = serde_json::from_value(value.clone())?;
        if material.request().target_commit_event_ref != value.current_mls_commit_event_ref
            || material.request().target_epoch != value.epoch
        {
            return Err(protocol(
                "recording member material target differs from current winning Q",
            ));
        }
        let genesis = joined_original(genesis_producer, genesis_commit)?;
        let state = joined_original(state_producer, state_commit)?;
        let installed = InstalledRecordingEpoch::verify_installed_material(
            group,
            &value,
            &genesis,
            &state,
            &material.request().as_peer_request(),
            material.value().map_err(protocol)?,
        )
        .map_err(protocol)?;
        // Re-read the opaque carriers after all work; a replaced local session
        // cannot mint a source from already-returned references.
        current.value().map_err(protocol)?;
        material.value().map_err(protocol)?;
        Ok(Self {
            current,
            material,
            installed,
        })
    }

    pub fn installed_epoch(&self) -> Result<&InstalledRecordingEpoch, WireError> {
        self.current.value().map_err(protocol)?;
        self.material.value().map_err(protocol)?;
        Ok(&self.installed)
    }

    pub fn new_writer_fence(&self) -> Result<RecordingEpochFence, WireError> {
        Ok(RecordingEpochFence::new(self.installed_epoch()?))
    }

    /// Start must be the actual accepted, signed original. Its raw Q is frozen
    /// unchanged into the encoder's descriptor; equivalent ref spellings cannot
    /// replace it. Capture permission/Service provenance remain native gates.
    pub fn begin_recording(
        &self,
        group: &ArkretMlsGroup,
        fence: &RecordingEpochFence,
        start_producer: &VerifiedProducerEvent,
        start_commit: &VerifiedRealmCommit,
        context: CallRecordingEncryptionContext,
        segment_bytes: u32,
        media_type: String,
        suite: DigestSuite,
    ) -> Result<FencedRecordingWriter, WireError> {
        let installed = self.installed_epoch()?;
        let start = joined_original(start_producer, start_commit)?;
        if start.event.kind != EventKind::CallRecordingStart
            || &start.event.scope_ref != installed.effective_scope()
            || start.event.realm_id != context.realm_id
        {
            return Err(protocol(
                "recording writer requires original accepted Start in the same effective scope",
            ));
        }
        let payload: CallRecordingStartPayload =
            serde_json::from_value(serde_json::to_value(&start.event.payload)?)?;
        fence
            .begin_recording(
                group,
                installed,
                &start.event.event_id,
                &payload,
                context,
                segment_bytes,
                media_type,
                suite,
            )
            .map_err(protocol)
    }
}

fn joined_original(
    event: &VerifiedProducerEvent,
    commit: &VerifiedRealmCommit,
) -> Result<CommittedEventFullView, WireError> {
    let full = CommittedEventFullView {
        event: event.event().clone(),
        commit: commit.commit().clone(),
    };
    full.validate_shape()?;
    Ok(full)
}

fn protocol(error: impl std::fmt::Display) -> WireError {
    WireError::Protocol(error.to_string())
}
