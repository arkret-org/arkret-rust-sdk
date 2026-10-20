//! Realm-owned Applet identities and control transactions.

use arkret_wire::{DetachedSignatureContext, Result, ScopeRef, WireError};

#[path = "generated/realm_actor_contracts.rs"]
mod contracts;
pub use contracts::*;

impl RealmActorControlHttpMetadata {
    pub const HEADER: &'static str = "Arkret-Realm-Actor-Control";

    pub fn validate(&self) -> Result<()> {
        self.actor_id.validate()?;
        let actor = self
            .actor_id
            .as_realm_actor_id()
            .ok_or_else(|| WireError::Protocol("control metadata requires a Realm actor".into()))?;
        if self.control_ref.stream_ref.scope_ref()
            != (ScopeRef::RealmControl {
                realm_id: actor.realm_id.clone(),
            })
            || !(22..=128).contains(&self.nonce.len())
            || !self
                .nonce
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(WireError::Protocol(
                "invalid Realm control reference or nonce".into(),
            ));
        }
        Ok(())
    }

    pub fn to_header_value(&self) -> Result<String> {
        self.validate()?;
        Ok(arkret_canonical::base64url_encode(
            arkret_canonical::canonical_json_bytes(self)?,
        ))
    }

    pub fn from_header_value(value: &str) -> Result<Self> {
        if value.len() > 8192 {
            return Err(WireError::Protocol(
                "Realm control metadata is too large".into(),
            ));
        }
        let bytes = arkret_canonical::base64url_decode(value)?;
        let metadata: Self = serde_json::from_slice(&bytes)?;
        if metadata.to_header_value()? != value {
            return Err(WireError::Protocol(
                "Realm control metadata is not canonical".into(),
            ));
        }
        Ok(metadata)
    }
}

impl RealmActorCreatePayload {
    pub const SCHEMA: &'static str = "ak.schema.realm_actor_create.v1";

    pub fn validate(&self) -> Result<()> {
        self.actor_id.validate()?;
        let actor = self.actor_id.as_realm_actor_id().ok_or_else(|| {
            WireError::Protocol("Realm actor creation requires a full Realm ActorId".into())
        })?;
        self.method_history_evidence.validate_shape()?;
        let boundary = self.method_history_evidence.boundary();
        let signature = &self.control_signature;
        if self.schema != Self::SCHEMA
            || actor.principal_id == self.service_id
            || self.creation_scope.realm_id_opt() != Some(&actor.realm_id)
            || !matches!(
                &self.creation_scope,
                ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
            )
            || !(22..=128).contains(&self.request_id.len())
            || !self
                .request_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            || (self.actor_role == RealmActorCreatePayloadActorRole::Ghost)
                != self.external_ref.is_some()
            || !self.recovery.enabled
            || arkret_wire::project_did_to_core_id(&self.initial_resolution.did)?
                != actor.principal_id
            || boundary.to_method_history_head != self.initial_resolution.method_history_head
            || boundary.to_version_id != self.initial_resolution.version_id
            || signature.context != DetachedSignatureContext::RealmActorCreation
            || signature.verification_method != self.control_method_kid
            || signature.created_at >= self.expires_at
        {
            return Err(WireError::Protocol(
                "Realm actor creation bindings are inconsistent".into(),
            ));
        }
        if let Some(external) = &self.external_ref {
            let mut protocol = external.protocol.bytes();
            if !protocol.next().is_some_and(|c| c.is_ascii_lowercase())
                || external.protocol.len() > 64
                || !protocol
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.-".contains(&c))
                || external.instance_id.trim().is_empty()
                || external.external_id.trim().is_empty()
            {
                return Err(WireError::Protocol(
                    "Ghost external tuple is invalid".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn creation_transcript(&self) -> RealmActorCreationTranscript {
        RealmActorCreationTranscript {
            schema: self.schema.clone(),
            actor_id: self.actor_id.clone(),
            applet_id: self.applet_id.clone(),
            service_id: self.service_id.clone(),
            actor_role: match self.actor_role {
                RealmActorCreatePayloadActorRole::Bot => RealmActorCreationTranscriptActorRole::Bot,
                RealmActorCreatePayloadActorRole::Ghost => {
                    RealmActorCreationTranscriptActorRole::Ghost
                }
            },
            request_id: self.request_id.clone(),
            creation_scope: self.creation_scope.clone(),
            registration_ref: self.registration_ref.clone(),
            creation_authorization_ref: self.creation_authorization_ref.clone(),
            initial_resolution: self.initial_resolution.clone(),
            method_history_evidence: self.method_history_evidence.clone(),
            control_method_kid: self.control_method_kid.clone(),
            expires_at: self.expires_at,
            external_ref: self.external_ref.clone(),
            recovery: RealmActorCreationTranscriptRecovery {
                kind: RealmActorCreationTranscriptRecoveryKind::ManagerNative,
                enabled: self.recovery.enabled,
            },
        }
    }
}

/// Derive only the creation writers from the actual accepting Commit.
/// Authentication, permission and uniqueness belong to the accepting transaction.
pub fn realm_actor_creation_current_rows(
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> Result<Vec<arkret_wire::TypedCurrentRow>> {
    use arkret_wire::{
        ActorId, CommitStreamRef, CurrentRevision, CurrentSelector, EventKind,
        RealmActorStatusGate, TypedCurrentRow,
    };
    let invalid = || WireError::Protocol("Realm actor creation and accepting Commit differ".into());
    let candidate: RealmActorCreatePayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    candidate.validate()?;
    let actor = &candidate.actor_id;
    let owner = actor.as_realm_actor_id().ok_or_else(invalid)?;
    let stream = CommitStreamRef::RealmControl {
        realm_id: owner.realm_id.clone(),
    };
    if event.kind != EventKind::RealmActorCreate
        || event.realm_id != owner.realm_id
        || event.scope_ref
            != (ScopeRef::RealmControl {
                realm_id: owner.realm_id.clone(),
            })
        || commit.realm_id != owner.realm_id
        || commit.stream_ref != stream
        || commit.event_ref != event.event_id
        || event.actor_id != ActorId::service(candidate.service_id.clone())
        || event.executed_by.is_some()
        || event.applet_id.as_ref() != Some(&candidate.applet_id)
        || event.authorization_ref.as_deref() != Some(candidate.creation_authorization_ref.as_str())
    {
        return Err(invalid());
    }
    let accepted = arkret_wire::CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: stream.clone(),
        stream_position: commit.stream_position,
    };
    let resolution = arkret_models_identity::PrincipalResolutionProjection {
        did: candidate.initial_resolution.did.clone(),
        method_history_head: candidate.initial_resolution.method_history_head.clone(),
        version_id: candidate.initial_resolution.version_id.clone(),
        resolution_event_ref: event.event_id.to_string(),
        updated_at: event.created_at,
    };
    let rows = vec![
        (
            CurrentSelector::RealmActorIdentity {
                actor_id: actor.clone(),
            },
            serde_json::json!({"applet_id":candidate.applet_id,"actor_role":candidate.actor_role,"creation_service_id":candidate.service_id,"creation_ref":accepted}),
        ),
        (
            CurrentSelector::RealmActorControl {
                actor_id: actor.clone(),
            },
            serde_json::json!({"resolution":resolution,"control_method_kid":candidate.control_method_kid}),
        ),
        (
            CurrentSelector::RealmActorManager {
                actor_id: actor.clone(),
            },
            serde_json::json!({"service_id":candidate.service_id,"registration_ref":candidate.registration_ref,"binding_ref":accepted}),
        ),
        (
            CurrentSelector::RealmActorStatus {
                actor_id: actor.clone(),
                gate: RealmActorStatusGate::Owner,
            },
            serde_json::json!("active"),
        ),
        (
            CurrentSelector::RealmActorStatus {
                actor_id: actor.clone(),
                gate: RealmActorStatusGate::Governance,
            },
            serde_json::json!("active"),
        ),
        (
            CurrentSelector::RealmActorDeviceGeneration {
                actor_id: actor.clone(),
            },
            serde_json::json!({"current_device_generation_ref":1}),
        ),
        (
            CurrentSelector::RealmActorRecovery {
                actor_id: actor.clone(),
            },
            serde_json::json!({"kind":"manager_native","enabled":true,"pending":null}),
        ),
    ];
    Ok(rows
        .into_iter()
        .map(|(selector, value)| TypedCurrentRow::Value {
            selector,
            source_stream_ref: stream.clone(),
            revision: CurrentRevision {
                commit_id: commit.commit_id.clone(),
                stream_position: commit.stream_position,
            },
            value,
        })
        .collect())
}

impl RealmActorDeviceAuthorizationValue {
    /// Derive the exact current value from its original accepted authorization.
    /// The accepting transaction supplies the Commit separately.
    pub fn from_event(event: &arkret_wire::Event) -> Result<Self> {
        use arkret_models_collaboration::events_payloads::{
            DeviceAuthorizationScopes, DeviceAuthorizePayload,
        };
        let actor = event
            .actor_id
            .as_realm_actor_id()
            .ok_or_else(|| WireError::Protocol("Realm Device requires complete owner".into()))?;
        let payload: DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
        payload.realm_device_possession_signature_input(&event.actor_id)?;
        if event.kind != arkret_wire::EventKind::DeviceAuthorize
            || event.executed_by.is_some()
            || event.authorization_ref.is_some()
            || event.applet_id != payload.applet_id
            || event.realm_id != actor.realm_id
            || event.scope_ref
                != (ScopeRef::RealmControl {
                    realm_id: actor.realm_id.clone(),
                })
        {
            return Err(WireError::Protocol(
                "Realm Device original envelope differs".into(),
            ));
        }
        let Some(DeviceAuthorizationScopes::AppletManaged(scopes)) = payload.scopes else {
            return Err(WireError::Protocol("Realm Device scopes absent".into()));
        };
        Ok(Self {
            device_public_key_did: payload.device_public_key_did.to_string(),
            hpke_key: payload.hpke_key.to_string(),
            algorithms: payload
                .algorithms
                .into_iter()
                .map(|v| v.to_string())
                .collect(),
            device_key_algorithm: payload.device_key_algorithm.to_string(),
            authorized_by: actor.principal_id.clone(),
            authorization_binding_kind: payload.authorization_binding_kind,
            authorized_generation_ref: payload.authorized_generation_ref,
            not_before: payload.not_before,
            expires_at: payload
                .expires_at
                .flatten()
                .ok_or_else(|| WireError::Protocol("Realm Device finite expiry absent".into()))?,
            scopes,
            applet_id: payload
                .applet_id
                .ok_or_else(|| WireError::Protocol("Realm Device Applet absent".into()))?,
            device_signature: payload.device_signature,
            device_authorize_event_id: event.event_id.clone(),
        })
    }
}
