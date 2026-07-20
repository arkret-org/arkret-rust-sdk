use arkret_state::lattice::LatticeKind as SdkLatticeKind;
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
        impl LatticeKind for $struct_name {
            fn cell_family(&self) -> &'static str {
                $cell_family
            }
            fn lattice(&self) -> SdkLatticeKind {
                $lattice
            }
            fn bottom_policy(&self) -> BottomPolicy {
                $bottom
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: $cell_family,
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
        impl LatticeKind for $struct_name {
            fn cell_family(&self) -> &'static str {
                $cell_family
            }
            fn lattice(&self) -> SdkLatticeKind {
                $lattice
            }
            fn bottom_policy(&self) -> BottomPolicy {
                $bottom
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: $cell_family,
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
                        cell_family: $cell_family,
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
    "ak.component.consent.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "consent_id",
    &["ak.consent.grant", "ak.consent.revoke"]
);

per_subject_lattice!(
    CapabilityGrant,
    "ak.component.capability.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "grant_id",
    &["ak.capability.grant", "ak.capability.revoke"]
);

per_subject_lattice!(
    CapabilityDelegate,
    "ak.component.capability.delegate.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "grant_id",
    &["ak.capability.delegate"]
);

per_subject_lattice!(
    CapabilityDerived,
    "ak.component.capability.derived.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "grant_id",
    &["ak.capability.derived"]
);

per_subject_lattice!(
    SessionGrant,
    "ak.component.session.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "session_id",
    &["ak.session.grant"]
);

per_subject_lattice!(
    DeviceAuthorized,
    "ak.component.device.authorization.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "device_id",
    &["ak.device.authorize", "ak.device.revoke"]
);

per_subject_lattice!(
    DeviceListUpdate,
    "ak.component.device.list_update.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "owner_did",
    &["ak.device.list_update"]
);

pub struct DevicePushRoute;
impl LatticeKind for DevicePushRoute {
    fn cell_family(&self) -> &'static str {
        "ak.component.device.push_route.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.device.push_route.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let recipient_service_id = effect_payload
            .get("recipient_service_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.device.push_route.v1",
                field: "recipient_service_id",
            })?;
        let principal_id = effect_payload
            .get("principal_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.device.push_route.v1",
                field: "principal_id",
            })?;
        let device_id = effect_payload
            .get("device_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.device.push_route.v1",
                field: "device_id",
            })?;
        let push_route = effect_payload
            .get("push_route")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.device.push_route.v1",
                field: "push_route",
            })?;
        Ok(Some(format!(
            "{recipient_service_id}::{principal_id}::{device_id}::{push_route}"
        )))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.device.push_route"]
    }
}

pub struct AgentKey;
impl LatticeKind for AgentKey {
    fn cell_family(&self) -> &'static str {
        "ak.component.agent.key.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrSet
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.agent.key.v1",
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
                cell_family: "ak.component.agent.key.v1",
                field: "agent_id",
            })?;
        let key_id = effect_payload.get("key_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.agent.key.v1",
                field: "key_id",
            },
        )?;
        Ok(Some(format!("{agent_id}::{key_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.agent.key.authorize", "ak.agent.key.revoke"]
    }
}

pub struct KeyBackupActiveSeries;
impl LatticeKind for KeyBackupActiveSeries {
    fn cell_family(&self) -> &'static str {
        "ak.component.key_backup.active_series.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.key_backup.active_series.v1",
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
                cell_family: "ak.component.key_backup.active_series.v1",
                field: "actor_id",
            })?;
        let backup_class = effect_payload
            .get("backup_class")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.key_backup.active_series.v1",
                field: "backup_class",
            })?;
        Ok(Some(format!("{actor_id}::{backup_class}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.key_backup.active_series"]
    }
}

singleton_lattice!(
    CoveredSeals,
    "ak.component.covered_seals.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required
);

// ────────────────────────── CasRegister families ──────────────────────────

singleton_lattice!(
    CircleTombstone,
    "ak.component.circle.tombstone.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.circle.tombstone"]
);

per_subject_lattice!(
    StrandPosition,
    "ak.component.strand.position.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "strand_id",
    &["ak.strand.move", "ak.strand.reorder"]
);

per_subject_lattice!(
    StrandStage,
    "ak.component.strand.stage.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "strand_id",
    &["ak.strand.stage.set"]
);

per_subject_lattice!(
    MorphStage,
    "ak.component.morph.stage.v1",
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
        "ak.component.strand.watch.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.strand.watch.v1",
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
                cell_family: "ak.component.strand.watch.v1",
                field: "strand_id",
            })?;
        let watcher_actor_id = effect_payload
            .get("watcher_actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.strand.watch.v1",
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
    "ak.component.cross_signing.publish.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "principal_id",
    &["ak.cross_signing.publish"]
);

singleton_lattice!(
    NotaryCell,
    "ak.component.notary.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

singleton_lattice!(
    MlsEpoch,
    "ak.component.mls.epoch.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

per_subject_lattice!(
    CallSummary,
    "ak.component.call.summary.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "call_id",
    &["ak.call.summary"]
);

// ────────────────────────── Fsm families ──────────────────────────

per_subject_lattice!(
    MemberState,
    "ak.component.member.state.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "actor_id",
    &["ak.member.state"]
);

per_subject_lattice!(
    AgentStatus,
    "ak.component.agent.status.v1",
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
    "ak.component.audit.binding.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "binding_id",
    &["ak.audit.applet_binding"]
);

per_subject_lattice!(
    AuditSession,
    "ak.component.audit.session.v1",
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
    "ak.component.call.state.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "call_id",
    &["ak.call.state"]
);

pub struct RealmLink;
impl LatticeKind for RealmLink {
    fn cell_family(&self) -> &'static str {
        "ak.component.realm.link.v1"
    }

    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::Fsm
    }

    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.realm.link.v1",
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
                cell_family: "ak.component.realm.link.v1",
                field: "target_realm_id",
            })?;
        let link_kind = effect_payload
            .get("link_kind")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.realm.link.v1",
                field: "link_kind",
            })?;
        arkret_wire::composite_subject(&[target_realm_id, link_kind])
            .map(Some)
            .map_err(|error| LatticeKindError::InvalidCompositeSubject {
                cell_family: "ak.component.realm.link.v1",
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
        "ak.component.circle.member.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.circle.member.v1",
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
                cell_family: "ak.component.circle.member.v1",
                field: "circle_id",
            })?;
        let actor_id = effect_payload
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.circle.member.v1",
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
    "ak.component.audit.release.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    "session_id",
    &["ak.audit.release"]
);

singleton_lattice!(
    CircleCreate,
    "ak.component.circle.create.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["ak.circle.create"]
);

// `ak.space.parent` is a CAS register keyed by the child Space ID.
per_subject_lattice!(
    SpaceParent,
    "ak.component.space.parent.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "space_id",
    &["ak.space.parent"]
);

per_subject_lattice!(
    AccountStatus,
    "ak.component.account.status.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "account_id",
    &["ak.account.status"]
);

per_subject_lattice!(
    PolicyRule,
    "ak.component.policy.rule.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "rule_id",
    &["ak.policy.rule"]
);

per_subject_lattice!(
    CrossSigningReset,
    "ak.component.cross_signing.reset.v1",
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
        "ak.component.member.identity.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrderedLog
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Expose
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.member.identity.v1",
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
                cell_family: "ak.component.member.identity.v1",
                field: "realm_id",
            })?;
        let actor_id = effect_payload
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.member.identity.v1",
                field: "actor_id",
            })?;
        let segment = effect_payload
            .get("segment")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.member.identity.v1",
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
        "ak.component.contact.fact_log.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrderedLog
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Expose
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.contact.fact_log.v1",
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
                cell_family: "ak.component.contact.fact_log.v1",
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

per_subject_lattice!(
    DirectConversationBinding,
    "ak.component.direct_conversation.binding.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "pair_key",
    &["ak.direct_conversation.bound"]
);

// ────────────────────────── MvRegister families ──────────────────────────

per_subject_lattice!(
    ProfileCreate,
    "ak.component.profile.create.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "actor_id",
    &["ak.profile.create", "ak.profile.update"]
);

per_subject_lattice!(
    ViewCreate,
    "ak.component.view.create.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["ak.view.create"]
);

per_subject_lattice!(
    ViewUpdate,
    "ak.component.view.update.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["ak.view.update"]
);

per_subject_lattice!(
    ViewReconcile,
    "ak.component.view.reconcile.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["ak.view.reconcile"]
);

per_subject_lattice!(
    MimiRoomBinding,
    "ak.component.mimi.room_binding.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "room_id",
    &["ak.mimi.room_binding"]
);

// ─────────── Realm families ───────────

// ── Realm CasRegister/Reject singleton families ──

singleton_lattice!(
    RealmPolicy,
    "ak.component.realm.policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.policy"]
);

singleton_lattice!(
    RealmReadReceiptPolicy,
    "ak.component.realm.read_receipt_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.read_receipt_policy"]
);

singleton_lattice!(
    RealmHistoryVisibility,
    "ak.component.realm.history_visibility.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.history_visibility"]
);

singleton_lattice!(
    RealmJoinRule,
    "ak.component.realm.join_rule.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.join_rule"]
);

singleton_lattice!(
    RealmDiscovery,
    "ak.component.realm.discovery.v1",
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
        "ak.component.realm.organization.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.realm.organization.v1",
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
                cell_family: "ak.component.realm.organization.v1",
                field: "organization_id",
            })?;
        let relationship = effect_payload
            .get("relationship")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ak.component.realm.organization.v1",
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
    "ak.component.realm.archive.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.archive"]
);

singleton_lattice!(
    RealmFreeze,
    "ak.component.realm.freeze.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.freeze"]
);

singleton_lattice!(
    RealmTombstone,
    "ak.component.realm.tombstone.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.tombstone"]
);

singleton_lattice!(
    RealmDestroy,
    "ak.component.realm.destroy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.destroy"]
);

singleton_lattice!(
    RealmModerationPolicy,
    "ak.component.realm.moderation_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.moderation_policy"]
);

singleton_lattice!(
    RealmHistorySharingPolicy,
    "ak.component.realm.history_sharing_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.history_sharing_policy"]
);

singleton_lattice!(
    RealmPreviewPolicy,
    "ak.component.realm.preview_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.preview_policy"]
);

singleton_lattice!(
    RealmAssetPrivacyPolicy,
    "ak.component.realm.asset_privacy_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.asset_privacy_policy"]
);

singleton_lattice!(
    RealmPolicyComponents,
    "ak.component.realm.policy_components.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.policy_components"]
);

singleton_lattice!(
    RealmPolicyServer,
    "ak.component.realm.policy_server.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.policy_server"]
);

singleton_lattice!(
    RealmPlaintextVisibleServices,
    "ak.component.realm.plaintext_visible_services.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.plaintext_visible_services"]
);

singleton_lattice!(
    RealmMediaService,
    "ak.component.realm.media_service.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.media_service"]
);

singleton_lattice!(
    RealmSchema,
    "ak.component.realm.schema.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.schema"]
);

singleton_lattice!(
    RealmDeliveryBindingPolicy,
    "ak.component.realm.delivery_binding_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.delivery_binding_policy"]
);

singleton_lattice!(
    RealmDisappearingPolicy,
    "ak.component.realm.disappearing_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.disappearing_policy"]
);

singleton_lattice!(
    RealmSearchPolicy,
    "ak.component.realm.search_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ak.realm.search_policy"]
);

// ── Realm CasRegister/Reject per-subject families ──

per_subject_lattice!(
    RealmInheritancePolicy,
    "ak.component.realm.inheritance_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "source_realm_id",
    &["ak.realm.inheritance_policy"]
);

per_subject_lattice!(
    RealmUpgrade,
    "ak.component.realm.upgrade.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "target_reducer_profile",
    &["ak.realm.upgrade"]
);

// ── Realm OrderedLog/Expose families ──

singleton_lattice!(
    RealmCreate,
    "ak.component.realm.create.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["ak.realm.create"]
);

// ── New Strand facet families (per-subject by Strand id) ──

pub struct StrandMetadata;
impl LatticeKind for StrandMetadata {
    fn cell_family(&self) -> &'static str {
        "ak.component.strand.metadata.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ak.component.strand.metadata.v1",
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
                cell_family: "ak.component.strand.metadata.v1",
                field: "target_ref",
            })
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ak.strand.update"]
    }
}

per_subject_lattice!(
    StrandTracks,
    "ak.component.strand.tracks.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "strand_id",
    &["ak.strand.tracks.update"]
);
