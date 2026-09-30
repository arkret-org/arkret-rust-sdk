//! Private managed-runtime resolution update closure.
//! Mirrors applet-edge-operations.schema.json's closed update evidence carrier.
use arkret_models_identity::{AuthenticatedServiceResolution, ResolutionMethodHistoryEvidence};
use arkret_wire::{Event, EventKind, RealmCommit, Result, ScopeRef, WireError};
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedActorResolutionUpdateEvidence {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub resolution_event: Event,
    pub commits: Vec<RealmCommit>,
    pub method_history_evidence: ResolutionMethodHistoryEvidence,
    pub attester_resolution: AuthenticatedServiceResolution,
}

impl ManagedActorResolutionUpdateEvidence {
    /// Structural checks only. The runtime must additionally verify the
    /// retained anchor, native history, historical Station signatures and its
    /// separately prepared local private-key material before installation.
    pub fn validate_shape(&self) -> Result<()> {
        self.method_history_evidence.validate_shape()?;
        let event = &self.resolution_event;
        if event.kind != EventKind::IdentityResolutionUpdate
            || !matches!(&event.scope_ref,ScopeRef::Realm{realm_id} if realm_id==&event.realm_id)
            || event
                .actor_id
                .as_account_id()
                .is_none_or(|account| account.station_id != self.attester_resolution.service_id)
        {
            return Err(WireError::Protocol(
                "managed resolution update has another Event kind, stream or Account Station"
                    .into(),
            ));
        }
        let mut previous: Option<&RealmCommit> = None;
        for commit in &self.commits {
            commit.validate_shape()?;
            if commit.realm_id != event.realm_id
                || !matches!(&commit.stream_ref,arkret_wire::CommitStreamRef::Realm{realm_id} if realm_id==&event.realm_id)
            {
                return Err(WireError::Protocol(
                    "managed resolution lineage crosses PCR Realms".into(),
                ));
            }
            if let Some(prior) = previous {
                if commit.stream_ref != prior.stream_ref
                    || commit.previous_commit_ref.as_ref() != Some(&prior.commit_id)
                    || prior.stream_position.checked_add(1) != Some(commit.stream_position)
                {
                    return Err(WireError::Protocol(
                        "managed resolution lineage is not consecutive".into(),
                    ));
                }
            }
            previous = Some(commit);
        }
        if previous.is_none_or(|commit| commit.event_ref != event.event_id) {
            return Err(WireError::Protocol(
                "managed resolution lineage does not accept its resolution Event".into(),
            ));
        }
        Ok(())
    }
}
