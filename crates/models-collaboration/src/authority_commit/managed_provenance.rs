//! Private first-forward originals; never a member-history or replication carrier.

use arkret_models_identity::{ActorProfile, AuthenticatedServiceResolution};
use arkret_wire::{
    AccountabilityScopeSet, ActorProfileId, CommitStreamRef, CurrentRevision, DidCoreId, ErrorCode,
    Event, EventKind, RealmCommit, RealmId, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::accountability::AccountabilityProjection;

/// Counterpart: `authority-commit-operations.schema.json#/$defs/managed_creation_accepted_event`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCreationAcceptedEvent {
    pub event: Event,
    pub commit: RealmCommit,
}

/// Counterpart: `authority-commit-operations.schema.json#/$defs/managed_creation_originals`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCreationOriginals {
    pub provision: ManagedCreationAcceptedEvent,
    pub pcr_genesis: ManagedCreationAcceptedEvent,
    pub accountability: ManagedCreationAcceptedEvent,
    pub profile: ManagedCreationAcceptedEvent,
}

impl ManagedCreationOriginals {
    pub fn entries(&self) -> [&ManagedCreationAcceptedEvent; 4] {
        [
            &self.provision,
            &self.pcr_genesis,
            &self.accountability,
            &self.profile,
        ]
    }

    /// Content/coordinate checks only; historical signatures need independent verification.
    pub fn validate(&self) -> Result<()> {
        for (original, kind) in self.entries().into_iter().zip([
            EventKind::AppletManagedActorProvision,
            EventKind::RealmCreate,
            EventKind::IdentityAccountabilityGrant,
            EventKind::ProfileCreate,
        ]) {
            let event = &original.event;
            let commit = &original.commit;
            event.validate_for_submit_structural()?;
            commit.verify_commit_id_matches_content()?;
            if event.kind != kind
                || commit.event_ref != event.event_id
                || commit.realm_id != event.realm_id
                || commit.stream_ref
                    != CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))?
            {
                return Err(malformed(
                    "managed creation original kind or Commit binding differs",
                ));
            }
        }
        let genesis = &self.pcr_genesis;
        if genesis.event.realm_id != RealmId::from_event_id(&genesis.event.event_id)
            || genesis.commit.stream_position != 0
            || self
                .entries()
                .iter()
                .any(|item| item.commit.committed_at != genesis.commit.committed_at)
        {
            return Err(malformed(
                "managed creation requires original inception and one acceptance time",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedProfileSelector {
    ActorProfile { actor_profile_id: ActorProfileId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedAccountabilitySelector {
    IdentityAccountability {
        issuer_id: DidCoreId,
        subject_id: DidCoreId,
        accountability_scope: AccountabilityScopeSet,
    },
}

/// Registered typed-current shape, with a family-specific selector and value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedIdentityProjection<S, V> {
    pub selector: S,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: V,
}

/// Counterpart: `authority-commit-operations.schema.json#/$defs/managed_profile_current`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedProfileCurrent {
    pub realm_id: RealmId,
    pub result: ManagedIdentityProjection<ManagedProfileSelector, ActorProfile>,
    pub commit: RealmCommit,
}

/// Counterpart: `authority-commit-operations.schema.json#/$defs/managed_accountability_current`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedAccountabilityCurrent {
    pub realm_id: RealmId,
    pub result: ManagedIdentityProjection<ManagedAccountabilitySelector, AccountabilityProjection>,
    pub commit: RealmCommit,
}

/// Counterpart: `authority-commit-operations.schema.json#/$defs/managed_identity_current`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedIdentityCurrent {
    pub profile: ManagedProfileCurrent,
    pub accountability: ManagedAccountabilityCurrent,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Counterpart: `authority-commit-operations.schema.json#/$defs/forward_managed_actor_provenance`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardManagedActorProvenance {
    pub creation: ManagedCreationOriginals,
    pub service_resolution: AuthenticatedServiceResolution,
    pub current: ManagedIdentityCurrent,
}

impl ForwardManagedActorProvenance {
    pub const MAX_CANONICAL_BYTES: usize = 1_048_576;

    /// Structural gate only; this cannot grant a role, liveness or business authority.
    pub fn validate(&self) -> Result<()> {
        if arkret_canonical::canonical_json_bytes(self)?.len() > Self::MAX_CANONICAL_BYTES {
            return Err(WireError::ProtocolCode {
                code: ErrorCode::PayloadTooLarge,
                message: "managed forward provenance exceeds its canonical byte budget".into(),
            });
        }
        self.creation.validate()?;
        let profile = &self.current.profile;
        let accountability = &self.current.accountability;
        validate_current(
            &profile.realm_id,
            &profile.result.source_stream_ref,
            &profile.result.revision,
            &profile.commit,
        )?;
        if profile.result.source_stream_ref
            != (CommitStreamRef::Realm {
                realm_id: profile.realm_id.clone(),
            })
        {
            return Err(malformed(
                "managed Profile current requires its exact PCR Realm stream",
            ));
        }
        validate_current(
            &accountability.realm_id,
            &accountability.result.source_stream_ref,
            &accountability.result.revision,
            &accountability.commit,
        )?;
        profile.result.value.validate_display_members()?;
        Ok(())
    }
}

fn validate_current(
    realm: &RealmId,
    stream: &CommitStreamRef,
    revision: &CurrentRevision,
    commit: &RealmCommit,
) -> Result<()> {
    commit.verify_commit_id_matches_content()?;
    if &commit.realm_id != realm
        || stream.realm_id() != realm
        || stream != &commit.stream_ref
        || revision.commit_id != commit.commit_id
        || revision.stream_position != commit.stream_position
    {
        return Err(malformed(
            "managed current result differs from its exact covering Commit",
        ));
    }
    Ok(())
}

fn malformed(message: &str) -> WireError {
    WireError::ProtocolCode {
        code: ErrorCode::SchemaViolation,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn whole_device_evidence_is_excluded_but_private_originals_are_digest_bound() {
        let body = json!({
            "branch": "authority_forward",
            "event_submission": {"event": "unchanged-original"},
            "producer_device_evidence": {"attestation": "first", "event_authorization": "old"},
            "producer_managed_provenance": {"creation": {"profile": "original"}}
        });
        let mut expected = body.clone();
        expected
            .as_object_mut()
            .unwrap()
            .remove("producer_device_evidence");
        let digest = super::super::authority_forward_body_digest(&body).unwrap();
        assert_eq!(
            digest.as_str(),
            arkret_canonical::canonical_sha256(&expected).unwrap()
        );
        let mut refreshed_device = body.clone();
        refreshed_device["producer_device_evidence"] =
            json!({"attestation": "fresh", "event_authorization": "new"});
        assert_eq!(
            digest,
            super::super::authority_forward_body_digest(&refreshed_device).unwrap()
        );
        let mut changed_original = body.clone();
        changed_original["producer_managed_provenance"]["creation"]["profile"] =
            json!("substituted");
        assert_ne!(
            digest,
            super::super::authority_forward_body_digest(&changed_original).unwrap()
        );
        let mut wrong_exclusion = body;
        wrong_exclusion["producer_device_evidence"]
            .as_object_mut()
            .unwrap()
            .remove("event_authorization");
        assert_ne!(
            digest.as_str(),
            arkret_canonical::canonical_sha256(&wrong_exclusion).unwrap()
        );
    }

    #[test]
    fn private_current_selectors_cannot_change_families_or_grow_members() {
        let id = ActorProfileId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [13; 32],
        ));
        let selector = json!({"kind":"actor_profile", "actor_profile_id": id});
        assert!(serde_json::from_value::<ManagedProfileSelector>(selector.clone()).is_ok());
        let mut wrong = selector;
        wrong["kind"] = json!("member_state");
        assert!(serde_json::from_value::<ManagedProfileSelector>(wrong).is_err());
        let extra = json!({"kind":"actor_profile", "actor_profile_id": id, "actor_role":"bot"});
        assert!(serde_json::from_value::<ManagedProfileSelector>(extra).is_err());
    }
}
