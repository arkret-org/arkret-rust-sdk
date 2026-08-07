use arkret_state::lattice::LatticeKind as SdkLatticeKind;
use arkret_wire::SchemaId;
use serde_json::Value;

use super::types::*;

// ────────────────────────── Helper macros ──────────────────────────

macro_rules! singleton_lattice {
    ($struct_name:ident, $cell_family:expr, $lattice:expr, $bottom:expr, $criticality:expr) => {
        singleton_lattice!(
            $struct_name,
            $cell_family,
            $lattice,
            $bottom,
            $criticality,
            &[]
        );
    };
    (
        $struct_name:ident,
        $cell_family:expr,
        $lattice:expr,
        $bottom:expr,
        $criticality:expr,
        $event_kinds:expr
    ) => {
        pub struct $struct_name;
        impl $struct_name {
            pub const CELL_FAMILY: &'static str = $cell_family;
        }
        impl LatticeKind for $struct_name {
            fn cell_family(&self) -> &'static str {
                Self::CELL_FAMILY
            }
            fn lattice(&self) -> SdkLatticeKind {
                $lattice
            }
            fn bottom_policy(&self) -> BottomPolicy {
                $bottom
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: Self::CELL_FAMILY,
                    component_version: 1,
                    criticality: $criticality,
                }
            }
            fn subject_for_effect(
                &self,
                _effect_payload: &Value,
            ) -> Result<Option<String>, LatticeKindError> {
                Ok(None)
            }
            fn event_kinds(&self) -> &'static [&'static str] {
                $event_kinds
            }
        }
    };
}

macro_rules! per_subject_lattice {
    (
        $struct_name:ident,
        $cell_family:expr,
        $lattice:expr,
        $bottom:expr,
        $criticality:expr,
        $subject_field:expr
    ) => {
        per_subject_lattice!(
            $struct_name,
            $cell_family,
            $lattice,
            $bottom,
            $criticality,
            $subject_field,
            &[]
        );
    };
    (
        $struct_name:ident,
        $cell_family:expr,
        $lattice:expr,
        $bottom:expr,
        $criticality:expr,
        $subject_field:expr,
        $event_kinds:expr
    ) => {
        pub struct $struct_name;
        impl $struct_name {
            pub const CELL_FAMILY: &'static str = $cell_family;
        }
        impl LatticeKind for $struct_name {
            fn cell_family(&self) -> &'static str {
                Self::CELL_FAMILY
            }
            fn lattice(&self) -> SdkLatticeKind {
                $lattice
            }
            fn bottom_policy(&self) -> BottomPolicy {
                $bottom
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: Self::CELL_FAMILY,
                    component_version: 1,
                    criticality: $criticality,
                }
            }
            fn subject_for_effect(
                &self,
                effect_payload: &Value,
            ) -> Result<Option<String>, LatticeKindError> {
                effect_payload
                    .get($subject_field)
                    .and_then(Value::as_str)
                    .map(|s| Some(s.to_owned()))
                    .ok_or(LatticeKindError::MissingSubjectField {
                        cell_family: Self::CELL_FAMILY,
                        field: $subject_field,
                    })
            }
            fn event_kinds(&self) -> &'static [&'static str] {
                $event_kinds
            }
        }
    };
}

// ────────────────────────── OrSet families ──────────────────────────

per_subject_lattice!(
    ConsentGrant,
    arkret_wire::CellFamilyId::CONSENT_GRANT_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "consent_id",
    &["ak.consent.grant", "ak.consent.revoke"]
);

per_subject_lattice!(
    ModerationState,
    arkret_wire::CellFamilyId::MODERATION_STATE_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Expose,
    Criticality::Required,
    "target_ref",
    &["ak.moderation.decision", "ak.moderation.decision.lift"]
);

per_subject_lattice!(
    CapabilityGrant,
    arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "grant_id",
    &["ak.capability.grant", "ak.capability.revoke"]
);

per_subject_lattice!(
    CapabilityDerived,
    arkret_wire::CellFamilyId::CAPABILITY_DERIVED_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "grant_id",
    &["ak.capability.derived"]
);

per_subject_lattice!(
    SessionGrant,
    arkret_wire::CellFamilyId::SESSION_GRANT_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "session_id",
    &["ak.session.grant"]
);

per_subject_lattice!(
    DeviceAuthorized,
    arkret_wire::CellFamilyId::DEVICE_AUTHORIZATION_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "device_id",
    &["ak.device.authorize", "ak.device.revoke"]
);

per_subject_lattice!(
    DeviceListUpdate,
    arkret_wire::CellFamilyId::DEVICE_LIST_UPDATE_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "owner_did",
    &["ak.device.list_update"]
);

pub struct AgentKey;
impl LatticeKind for AgentKey {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::AGENT_KEY_V1
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrSet
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::AGENT_KEY_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let agent_id = effect_payload
            .get("agent_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::AGENT_KEY_V1,
                field: "agent_id",
            })?;
        let key_id = effect_payload.get("key_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::AGENT_KEY_V1,
                field: "key_id",
            },
        )?;
        arkret_wire::composite_subject(&[agent_id, key_id])
            .map(Some)
            .map_err(|error| LatticeKindError::InvalidCompositeSubject {
                cell_family: arkret_wire::CellFamilyId::AGENT_KEY_V1,
                reason: error.to_string(),
            })
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.agent.key.authorize", "ak.agent.key.revoke"]
    }
}

pub struct KeyBackupActiveSeries;

impl KeyBackupActiveSeries {
    pub const SCHEMA: &'static str = SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1;
}

impl LatticeKind for KeyBackupActiveSeries {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let actor_id = effect_payload
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1,
                field: "actor_id",
            })?;
        let backup_kind = effect_payload
            .get("backup_kind")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1,
                field: "backup_kind",
            })?;
        Ok(Some(format!("{actor_id}::{backup_kind}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.key_backup.active_series"]
    }
}

// ────────────────────────── CasRegister families ──────────────────────────

per_subject_lattice!(
    AppletRegistration,
    arkret_wire::CellFamilyId::APPLET_REGISTRATION_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "applet_id",
    &["ak.applet.registration"]
);

singleton_lattice!(
    CircleTombstone,
    arkret_wire::CellFamilyId::CIRCLE_TOMBSTONE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.circle.tombstone"]
);

per_subject_lattice!(
    StrandPosition,
    arkret_wire::CellFamilyId::STRAND_POSITION_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "strand_id",
    &["ak.strand.move", "ak.strand.reorder"]
);

per_subject_lattice!(
    StrandStage,
    arkret_wire::CellFamilyId::STRAND_STAGE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "strand_id",
    &["ak.strand.stage.set"]
);

per_subject_lattice!(
    MorphStage,
    arkret_wire::CellFamilyId::MORPH_STAGE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "morph_id",
    &["ak.morph.stage.set"]
);

// Strand notification subscription cell, keyed by (strand_id, watcher_actor_id).
// Spec: arkret-spec/spec/v1/zh/models/strand-and-message.md §8.
// SDK's subject derivation composes both keys into a single string so the
// existing per-subject lattice infra (single Option<String>) works without
// growing tuple support; the cell store still treats each (strand, actor)
// pair as an independent slot.
pub struct StrandWatch;
impl LatticeKind for StrandWatch {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::STRAND_WATCH_V1
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::STRAND_WATCH_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let strand_id = effect_payload
            .get("strand_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::STRAND_WATCH_V1,
                field: "strand_id",
            })?;
        let watcher_actor_id = effect_payload
            .get("watcher_actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::STRAND_WATCH_V1,
                field: "watcher_actor_id",
            })?;
        Ok(Some(format!("{strand_id}::{watcher_actor_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.strand.watch.set"]
    }
}

per_subject_lattice!(
    CrossSigningPublish,
    arkret_wire::CellFamilyId::CROSS_SIGNING_PUBLISH_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "principal_id",
    &["ak.cross_signing.publish"]
);

singleton_lattice!(
    NotaryCell,
    arkret_wire::CellFamilyId::NOTARY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

pub struct IdentityAccountability;
impl LatticeKind for IdentityAccountability {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::IDENTITY_ACCOUNTABILITY_V1
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::IDENTITY_ACCOUNTABILITY_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }

    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let payload = serde_json::from_value::<
            arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload,
        >(effect_payload.clone())
        .map_err(|error| LatticeKindError::InvalidCompositeSubject {
            cell_family: self.cell_family(),
            reason: error.to_string(),
        })?;
        payload.cell_subject().map(Some).map_err(|error| {
            LatticeKindError::InvalidCompositeSubject {
                cell_family: self.cell_family(),
                reason: error.to_string(),
            }
        })
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.identity.accountability_grant"]
    }
}

singleton_lattice!(
    MlsEpoch,
    arkret_wire::CellFamilyId::MLS_EPOCH_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

per_subject_lattice!(
    CallSummary,
    arkret_wire::CellFamilyId::CALL_SUMMARY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "call_id",
    &["ak.call.summary"]
);

per_subject_lattice!(
    CallFocus,
    arkret_wire::CellFamilyId::CALL_FOCUS_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "call_id",
    &["ak.call.state"]
);

per_subject_lattice!(
    CallModeration,
    arkret_wire::CellFamilyId::CALL_MODERATION_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Inert,
    Criticality::Required,
    "call_id",
    &["ak.call.state"]
);

per_subject_lattice!(
    CallRoster,
    arkret_wire::CellFamilyId::CALL_ROSTER_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Inert,
    Criticality::Required,
    "call_id",
    &["ak.call.state"]
);

fn call_capture_subject(
    effect_payload: &Value,
    transition_field: &'static str,
    cell_family: &'static str,
) -> Result<Option<String>, LatticeKindError> {
    let call_id = effect_payload
        .get("call_id")
        .and_then(Value::as_str)
        .ok_or(LatticeKindError::MissingSubjectField {
            cell_family,
            field: "call_id",
        })?;
    let recording_id = effect_payload
        .get("recording_id")
        .or_else(|| {
            effect_payload
                .get(transition_field)
                .and_then(|transition| transition.get("recording_id"))
        })
        .and_then(Value::as_str)
        .ok_or(LatticeKindError::MissingSubjectField {
            cell_family,
            field: "recording_id",
        })?;
    arkret_wire::composite_subject(&[call_id, recording_id])
        .map(Some)
        .map_err(|error| LatticeKindError::InvalidCompositeSubject {
            cell_family,
            reason: error.to_string(),
        })
}

pub struct CallRecording;

impl LatticeKind for CallRecording {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::CALL_RECORDING_V1
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::Fsm
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: self.cell_family(),
            component_version: 1,
            criticality: Criticality::Required,
        }
    }

    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        call_capture_subject(effect_payload, "recording_transition", self.cell_family())
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.call.recording.start", "ak.call.state"]
    }
}

pub struct CallTranscript;

impl LatticeKind for CallTranscript {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::CALL_TRANSCRIPT_V1
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::Fsm
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: self.cell_family(),
            component_version: 1,
            criticality: Criticality::Required,
        }
    }

    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        call_capture_subject(effect_payload, "transcript_transition", self.cell_family())
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.call.recording.start", "ak.call.state"]
    }
}

pub struct CallRecordingResult;

impl LatticeKind for CallRecordingResult {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::CALL_RECORDING_RESULT_V1
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: self.cell_family(),
            component_version: 1,
            criticality: Criticality::Required,
        }
    }

    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        call_capture_subject(effect_payload, "recording_transition", self.cell_family())
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.call.recording.start", "ak.call.state"]
    }
}

pub struct CallTranscriptResult;

impl LatticeKind for CallTranscriptResult {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::CALL_TRANSCRIPT_RESULT_V1
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: self.cell_family(),
            component_version: 1,
            criticality: Criticality::Required,
        }
    }

    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        call_capture_subject(effect_payload, "transcript_transition", self.cell_family())
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.call.recording.start", "ak.call.state"]
    }
}

pub struct CallMuteOverride;

impl LatticeKind for CallMuteOverride {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::CALL_MUTE_OVERRIDE_V1
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: self.cell_family(),
            component_version: 1,
            criticality: Criticality::Required,
        }
    }

    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let call_id = effect_payload
            .get("call_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: self.cell_family(),
                field: "call_id",
            })?;
        let mute =
            effect_payload
                .get("mute_override")
                .ok_or(LatticeKindError::MissingSubjectField {
                    cell_family: self.cell_family(),
                    field: "mute_override",
                })?;
        let actor_id = mute.get("actor_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: self.cell_family(),
                field: "mute_override.actor_id",
            },
        )?;
        let device_id = mute.get("device_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: self.cell_family(),
                field: "mute_override.device_id",
            },
        )?;
        arkret_wire::composite_subject(&[call_id, actor_id, device_id])
            .map(Some)
            .map_err(|error| LatticeKindError::InvalidCompositeSubject {
                cell_family: self.cell_family(),
                reason: error.to_string(),
            })
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.call.state"]
    }
}

// ────────────────────────── Fsm families ──────────────────────────

per_subject_lattice!(
    MemberState,
    arkret_wire::CellFamilyId::MEMBER_STATE_V1,
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "actor_id",
    &["ak.member.state"]
);

pub struct InviteLifecycle;
impl LatticeKind for InviteLifecycle {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::INVITE_LIFECYCLE_V1
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::Fsm
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::INVITE_LIFECYCLE_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }

    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        effect_payload
            .get("invite_id")
            .and_then(Value::as_str)
            .or_else(|| {
                effect_payload
                    .get("invite")
                    .and_then(|invite| invite.get("id"))
                    .and_then(Value::as_str)
            })
            .map(|subject| Some(subject.to_owned()))
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::INVITE_LIFECYCLE_V1,
                field: "invite_id or invite.id",
            })
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &[
            "ak.invite.create",
            "ak.invite.cancel",
            "ak.invite.accept",
            "ak.invite.third_party",
            "ak.invite.claim",
            "ak.invite.revoke",
        ]
    }
}

per_subject_lattice!(
    AgentStatus,
    arkret_wire::CellFamilyId::AGENT_STATUS_V1,
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "agent_id",
    &[
        "ak.self.agent.pause",
        "ak.self.agent.resume",
        "ak.self.agent.deactivate"
    ]
);

per_subject_lattice!(
    AuditBinding,
    arkret_wire::CellFamilyId::AUDIT_BINDING_V1,
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "binding_id",
    &["ak.audit.applet_binding"]
);

per_subject_lattice!(
    AuditSession,
    arkret_wire::CellFamilyId::AUDIT_SESSION_V1,
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "session_id",
    &[
        "ak.audit.session.request",
        "ak.audit.session.authorize",
        "ak.audit.session.notice",
        "ak.audit.session.close"
    ]
);

per_subject_lattice!(
    CallState,
    arkret_wire::CellFamilyId::CALL_STATE_V1,
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "call_id",
    &["ak.call.state"]
);

pub struct RealmLink;
impl LatticeKind for RealmLink {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::REALM_LINK_V1
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::Fsm
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::REALM_LINK_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }

    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let target_realm_id = effect_payload
            .get("target_realm_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::REALM_LINK_V1,
                field: "target_realm_id",
            })?;
        let link_kind = effect_payload
            .get("link_kind")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::REALM_LINK_V1,
                field: "link_kind",
            })?;
        arkret_wire::composite_subject(&[target_realm_id, link_kind])
            .map(Some)
            .map_err(|error| LatticeKindError::InvalidCompositeSubject {
                cell_family: arkret_wire::CellFamilyId::REALM_LINK_V1,
                reason: error.to_string(),
            })
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.realm.link"]
    }
}

pub struct CircleMember;
impl LatticeKind for CircleMember {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let circle_id = effect_payload
            .get("circle_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1,
                field: "circle_id",
            })?;
        let actor_id = effect_payload
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1,
                field: "actor_id",
            })?;
        Ok(Some(format!("{circle_id}::{actor_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.circle.member.state"]
    }
}

// ────────────────────────── OrderedLog families ──────────────────────────

per_subject_lattice!(
    AuditRelease,
    arkret_wire::CellFamilyId::AUDIT_RELEASE_V1,
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    "session_id",
    &["ak.audit.release"]
);

singleton_lattice!(
    CircleCreate,
    arkret_wire::CellFamilyId::CIRCLE_CREATE_V1,
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Inert,
    Criticality::Required,
    &["ak.circle.create"]
);

singleton_lattice!(
    SidecarCreate,
    arkret_wire::CellFamilyId::SIDECAR_CREATE_V1,
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Inert,
    Criticality::Required,
    &["ak.sidecar.create"]
);

// `ak.space.parent` is a CAS register keyed by the child Space ID.
per_subject_lattice!(
    SpaceParent,
    arkret_wire::CellFamilyId::SPACE_PARENT_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "space_id",
    &["ak.space.parent"]
);

per_subject_lattice!(
    AccountStatus,
    arkret_wire::CellFamilyId::ACCOUNT_STATUS_V1,
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "account_id",
    &["ak.account.status"]
);

per_subject_lattice!(
    PolicyRule,
    arkret_wire::CellFamilyId::POLICY_RULE_V1,
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "rule_id",
    &["ak.policy.rule"]
);

per_subject_lattice!(
    CrossSigningReset,
    arkret_wire::CellFamilyId::CROSS_SIGNING_RESET_V1,
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    "principal_id",
    &["ak.cross_signing.reset"]
);

/// Lattice marker for the `ak.component.member.identity.v1` cell family.
/// Named `MemberIdentityLattice` (not `MemberIdentity`) to avoid colliding
/// with the wire object `models::MemberIdentity`.
pub struct MemberIdentityLattice;
impl LatticeKind for MemberIdentityLattice {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::MEMBER_IDENTITY_V1
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrderedLog
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Expose
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::MEMBER_IDENTITY_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let realm_id = effect_payload
            .get("realm_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::MEMBER_IDENTITY_V1,
                field: "realm_id",
            })?;
        let actor_id = effect_payload
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::MEMBER_IDENTITY_V1,
                field: "actor_id",
            })?;
        let segment = effect_payload
            .get("segment")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::MEMBER_IDENTITY_V1,
                field: "segment",
            })?;
        Ok(Some(format!("{realm_id}::{actor_id}::{segment}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.member.identity.update"]
    }
}

pub struct ContactFactLog;
impl LatticeKind for ContactFactLog {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::CONTACT_FACT_LOG_V1
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrderedLog
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Expose
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::CONTACT_FACT_LOG_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        effect_payload
            .get("target")
            .or_else(|| effect_payload.get("requester"))
            .or_else(|| effect_payload.get("peer"))
            .and_then(Value::as_str)
            .map(|s| Some(s.to_owned()))
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::CONTACT_FACT_LOG_V1,
                field: "target/requester/peer",
            })
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &[
            "ak.contact.requested",
            "ak.contact.accepted",
            "ak.contact.rejected",
            "ak.contact.tombstoned",
        ]
    }
}

// contract-registry `ak.direct_conversation.bound`: `lattice = or_set`,
// `bottom = inert`, `concurrency_class = merge_safe`. The element key is
// `(binding_digest, envelope.actor_id)` — both participants endorsing the same
// coordinates are compatible adds that MUST NOT join to bottom
// (`contact-and-direct-conversation.md` §8.3). The previous `OrderedLog` /
// `Expose` pair contradicted the generated `SPEC_LATTICE_BINDINGS` entry.
per_subject_lattice!(
    DirectConversationBinding,
    arkret_wire::CellFamilyId::DIRECT_CONVERSATION_BINDING_V1,
    SdkLatticeKind::OrSet,
    BottomPolicy::Inert,
    Criticality::Required,
    "pair_key",
    &["ak.direct_conversation.bound"]
);

// ────────────────────────── MvRegister families ──────────────────────────

per_subject_lattice!(
    ProfileCreate,
    arkret_wire::CellFamilyId::PROFILE_CREATE_V1,
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "actor_id",
    &["ak.profile.create", "ak.profile.update"]
);

pub struct AgentSelectorClaim;

impl AgentSelectorClaim {
    pub const SCHEMA: &'static str = SchemaId::AGENT_SELECTOR_CLAIM_V1;
}

impl LatticeKind for AgentSelectorClaim {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::AGENT_SELECTOR_CLAIM_V1
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::MvRegister
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Expose
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::AGENT_SELECTOR_CLAIM_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }

    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let controller_subject = effect_payload
            .get("controller_subject")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: self.cell_family(),
                field: "controller_subject",
            })?;
        let agent_slug = effect_payload
            .get("agent_slug")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: self.cell_family(),
                field: "agent_slug",
            })?;
        arkret_wire::composite_subject(&[controller_subject, agent_slug])
            .map(Some)
            .map_err(|error| LatticeKindError::InvalidCompositeSubject {
                cell_family: self.cell_family(),
                reason: error.to_string(),
            })
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.agent.selector_claim"]
    }
}

per_subject_lattice!(
    ViewCreate,
    arkret_wire::CellFamilyId::VIEW_CREATE_V1,
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["ak.view.create"]
);

per_subject_lattice!(
    ViewUpdate,
    arkret_wire::CellFamilyId::VIEW_UPDATE_V1,
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["ak.view.update"]
);

per_subject_lattice!(
    ViewReconcile,
    arkret_wire::CellFamilyId::VIEW_RECONCILE_V1,
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["ak.view.reconcile"]
);

per_subject_lattice!(
    MimiRoomBinding,
    arkret_wire::CellFamilyId::MIMI_ROOM_BINDING_V1,
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "room_id",
    &["ak.mimi.room_binding"]
);

// ─────────── Realm families ───────────

// ── Realm CasRegister/Reject singleton families ──

per_subject_lattice!(
    PolicyDefinition,
    arkret_wire::CellFamilyId::POLICY_DEFINITION_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "policy_id",
    &["ak.policy.set"]
);

singleton_lattice!(
    RealmPolicy,
    arkret_wire::CellFamilyId::REALM_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.policy"]
);

// Per-Realm metadata cell. `ak.realm.create` seeds it as its first registered
// effect and `ak.realm.update` writes every later value, so it MUST exist in
// the genesis `state_root` leaf set (models/realm-and-space.md section 2.5,
// authz/event-auth-state-resolution.md section 6.2.1).
singleton_lattice!(
    RealmMetadata,
    arkret_wire::CellFamilyId::REALM_METADATA_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.create", "ak.realm.update"]
);

singleton_lattice!(
    RealmReadReceiptPolicy,
    arkret_wire::CellFamilyId::REALM_READ_RECEIPT_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.read_receipt_policy"]
);

singleton_lattice!(
    RealmHistoryVisibility,
    arkret_wire::CellFamilyId::REALM_HISTORY_VISIBILITY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.history_visibility"]
);

singleton_lattice!(
    RealmJoinRule,
    arkret_wire::CellFamilyId::REALM_JOIN_RULE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.join_rule"]
);

singleton_lattice!(
    RealmDiscovery,
    arkret_wire::CellFamilyId::REALM_DISCOVERY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.discovery"]
);

// `ak.realm.organization` declares a tuple `cell_subject`:
// `(organization_id = payload.organization_id, relationship = payload.relationship)`.
// It is NOT a singleton keyed by realm_id; distinct (organization_id, relationship)
// pairs must form independent CAS register cells so they cannot overwrite each other.
pub struct RealmOrganization;
impl LatticeKind for RealmOrganization {
    fn cell_family(&self) -> &'static str {
        arkret_wire::CellFamilyId::REALM_ORGANIZATION_V1
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: arkret_wire::CellFamilyId::REALM_ORGANIZATION_V1,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let organization_id = effect_payload
            .get("organization_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::REALM_ORGANIZATION_V1,
                field: "organization_id",
            })?;
        let relationship = effect_payload
            .get("relationship")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: arkret_wire::CellFamilyId::REALM_ORGANIZATION_V1,
                field: "relationship",
            })?;
        Ok(Some(format!("{organization_id}::{relationship}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.realm.organization"]
    }
}

singleton_lattice!(
    RealmArchive,
    arkret_wire::CellFamilyId::REALM_ARCHIVE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.archive"]
);

singleton_lattice!(
    RealmFreeze,
    arkret_wire::CellFamilyId::REALM_FREEZE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.freeze"]
);

singleton_lattice!(
    RealmTombstone,
    arkret_wire::CellFamilyId::REALM_TOMBSTONE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.tombstone"]
);

singleton_lattice!(
    RealmDestroy,
    arkret_wire::CellFamilyId::REALM_DESTROY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.destroy"]
);

singleton_lattice!(
    RealmModerationPolicy,
    arkret_wire::CellFamilyId::REALM_MODERATION_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.moderation_policy"]
);

singleton_lattice!(
    RealmHistorySharingPolicy,
    arkret_wire::CellFamilyId::REALM_HISTORY_SHARING_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.history_sharing_policy"]
);

singleton_lattice!(
    RealmPreviewPolicy,
    arkret_wire::CellFamilyId::REALM_PREVIEW_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.preview_policy"]
);

singleton_lattice!(
    RealmAssetPrivacyPolicy,
    arkret_wire::CellFamilyId::REALM_ASSET_PRIVACY_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.asset_privacy_policy"]
);

singleton_lattice!(
    RealmPolicyBundle,
    arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.policy_bundle"]
);

singleton_lattice!(
    RealmPolicyServer,
    arkret_wire::CellFamilyId::REALM_POLICY_SERVER_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.policy_server"]
);

singleton_lattice!(
    RealmAlias,
    arkret_wire::CellFamilyId::REALM_ALIAS_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.alias"]
);

singleton_lattice!(
    RealmPlaintextVisibleServices,
    arkret_wire::CellFamilyId::REALM_PLAINTEXT_VISIBLE_SERVICES_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.plaintext_visible_services"]
);

singleton_lattice!(
    RealmMediaService,
    arkret_wire::CellFamilyId::REALM_MEDIA_SERVICE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.media_service"]
);

singleton_lattice!(
    RealmSchema,
    arkret_wire::CellFamilyId::REALM_SCHEMA_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.schema"]
);

singleton_lattice!(
    RealmDeliveryBindingPolicy,
    arkret_wire::CellFamilyId::REALM_DELIVERY_BINDING_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.delivery_binding_policy"]
);

singleton_lattice!(
    RealmDisappearingPolicy,
    arkret_wire::CellFamilyId::REALM_DISAPPEARING_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.disappearing_policy"]
);

singleton_lattice!(
    RealmSearchPolicy,
    arkret_wire::CellFamilyId::REALM_SEARCH_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.search_policy"]
);

// ── Realm CasRegister/Reject per-subject families ──

per_subject_lattice!(
    RealmInheritancePolicy,
    arkret_wire::CellFamilyId::REALM_INHERITANCE_POLICY_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "source_realm_id",
    &["ak.realm.inheritance_policy"]
);

singleton_lattice!(
    RealmReducerProfile,
    arkret_wire::CellFamilyId::REALM_REDUCER_PROFILE_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.upgrade"]
);

// ── Realm ordered-log families ──

singleton_lattice!(
    RealmCreate,
    arkret_wire::CellFamilyId::REALM_CREATE_V1,
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Inert,
    Criticality::Required,
    &["ak.realm.create"]
);

// `ak.strand.create` writes the strand object cell
// (contract-registry `cell_writes`: lattice `mv_register`, bottom `expose`).
// Without this registration a governance proof over a realm whose accepted
// history carries a drafted strand-create cell (e.g. the direct-conversation
// materialization) fails with `no lattice registered for governance cell`.
singleton_lattice!(
    StrandObject,
    arkret_wire::CellFamilyId::STRAND_OBJECT_V1,
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    &["ak.strand.create"]
);

// ── New Strand facet families (per-subject by Strand id) ──

pub struct StrandMetadata;
impl StrandMetadata {
    pub const CELL_FAMILY: &'static str = arkret_wire::CellFamilyId::STRAND_METADATA_V1;
}
impl LatticeKind for StrandMetadata {
    fn cell_family(&self) -> &'static str {
        Self::CELL_FAMILY
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: Self::CELL_FAMILY,
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        effect_payload
            .get("target_ref")
            .or_else(|| effect_payload.get("strand_id"))
            .and_then(Value::as_str)
            .map(|s| Some(s.to_owned()))
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: Self::CELL_FAMILY,
                field: "target_ref",
            })
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.strand.update"]
    }
}

per_subject_lattice!(
    StrandTracks,
    arkret_wire::CellFamilyId::STRAND_TRACKS_V1,
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "strand_id",
    &["ak.strand.tracks.update"]
);
