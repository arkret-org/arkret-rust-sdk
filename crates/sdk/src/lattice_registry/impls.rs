use serde_json::Value;

use super::types::*;
use crate::lattice::LatticeKind as SdkLatticeKind;

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
    "ck.component.consent.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "consent_id",
    &["ck.consent.grant", "ck.consent.revoke"]
);

per_subject_lattice!(
    CapabilityGrant,
    "ck.component.capability.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "grant_id",
    &["ck.capability.grant", "ck.capability.revoke"]
);

per_subject_lattice!(
    CapabilityDelegate,
    "ck.component.capability.delegate.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "grant_id",
    &["ck.capability.delegate"]
);

per_subject_lattice!(
    CapabilityDerived,
    "ck.component.capability.derived.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "grant_id",
    &["ck.capability.derived"]
);

per_subject_lattice!(
    SessionGrant,
    "ck.component.session.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "session_id",
    &["ck.session.grant"]
);

per_subject_lattice!(
    DeviceAuthorized,
    "ck.component.device.authorization.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "device_id",
    &["ck.device.authorize", "ck.device.revoke"]
);

per_subject_lattice!(
    DeviceListUpdate,
    "ck.component.device.list_update.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "owner_did",
    &["ck.device.list_update"]
);

pub struct DevicePushRoute;
impl LatticeKind for DevicePushRoute {
    fn cell_family(&self) -> &'static str {
        "ck.component.device.push_route.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.device.push_route.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let recipient_service_did = effect_payload
            .get("recipient_service_did")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.device.push_route.v1",
                field: "recipient_service_did",
            })?;
        let principal_id = effect_payload
            .get("principal_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.device.push_route.v1",
                field: "principal_id",
            })?;
        let device_id = effect_payload
            .get("device_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.device.push_route.v1",
                field: "device_id",
            })?;
        let push_route = effect_payload
            .get("push_route")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.device.push_route.v1",
                field: "push_route",
            })?;
        Ok(Some(format!(
            "{recipient_service_did}::{principal_id}::{device_id}::{push_route}"
        )))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ck.device.push_route"]
    }
}

pub struct AgentKey;
impl LatticeKind for AgentKey {
    fn cell_family(&self) -> &'static str {
        "ck.component.agent.key.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrSet
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.agent.key.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let agent_principal_id = effect_payload
            .get("agent_principal_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.agent.key.v1",
                field: "agent_principal_id",
            })?;
        let key_id = effect_payload.get("key_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.agent.key.v1",
                field: "key_id",
            },
        )?;
        Ok(Some(format!("{agent_principal_id}::{key_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &[
            "ck.agent.key.authorize",
            "ck.agent.key.revoke",
            "ck.agent.key.rotate",
        ]
    }
}

pub struct KeyBackupActiveSeries;
impl LatticeKind for KeyBackupActiveSeries {
    fn cell_family(&self) -> &'static str {
        "ck.component.key_backup.active_series.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.key_backup.active_series.v1",
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
                cell_family: "ck.component.key_backup.active_series.v1",
                field: "actor_id",
            })?;
        let backup_class = effect_payload
            .get("backup_class")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.key_backup.active_series.v1",
                field: "backup_class",
            })?;
        Ok(Some(format!("{actor_id}::{backup_class}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ck.key_backup.active_series"]
    }
}

singleton_lattice!(
    CoveredSeals,
    "ck.component.covered_seals.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required
);

// ────────────────────────── CasRegister families ──────────────────────────

singleton_lattice!(
    CircleTombstone,
    "ck.component.circle.tombstone.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.circle.tombstone"]
);

per_subject_lattice!(
    StrandPosition,
    "ck.component.strand.position.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "strand_id",
    &["ck.strand.move", "ck.strand.reorder"]
);

per_subject_lattice!(
    StrandStage,
    "ck.component.strand.stage.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "strand_id",
    &["ck.strand.stage.set"]
);

per_subject_lattice!(
    MorphStage,
    "ck.component.morph.stage.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "morph_id",
    &["ck.morph.stage.set"]
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
        "ck.component.strand.watch.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.strand.watch.v1",
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
                cell_family: "ck.component.strand.watch.v1",
                field: "strand_id",
            })?;
        let watcher_actor_id = effect_payload
            .get("watcher_actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.strand.watch.v1",
                field: "watcher_actor_id",
            })?;
        Ok(Some(format!("{strand_id}::{watcher_actor_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ck.strand.watch.set"]
    }
}

per_subject_lattice!(
    CrossSigningPublish,
    "ck.component.cross_signing.publish.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "principal_id",
    &["ck.cross_signing.publish"]
);

singleton_lattice!(
    NotaryCell,
    "ck.component.notary.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

singleton_lattice!(
    MlsEpoch,
    "ck.component.mls.epoch.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

per_subject_lattice!(
    CallSummary,
    "ck.component.call.summary.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "call_id",
    &["ck.call.summary"]
);

// ────────────────────────── Fsm families ──────────────────────────

per_subject_lattice!(
    MemberState,
    "ck.component.member.state.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "actor_id",
    &["ck.member.state"]
);

per_subject_lattice!(
    AgentStatus,
    "ck.component.agent.status.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "agent_principal_id",
    &[
        "ck.self.agent.pause",
        "ck.self.agent.resume",
        "ck.self.agent.deactivate"
    ]
);

per_subject_lattice!(
    CallState,
    "ck.component.call.state.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "call_id",
    &["ck.call.state"]
);

pub struct CircleMember;
impl LatticeKind for CircleMember {
    fn cell_family(&self) -> &'static str {
        "ck.component.circle.member.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.circle.member.v1",
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
                cell_family: "ck.component.circle.member.v1",
                field: "circle_id",
            })?;
        let actor_id = effect_payload
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.circle.member.v1",
                field: "actor_id",
            })?;
        Ok(Some(format!("{circle_id}::{actor_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ck.circle.member.state"]
    }
}

// ────────────────────────── OrderedLog families ──────────────────────────

singleton_lattice!(
    CircleCreate,
    "ck.component.circle.create.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["ck.circle.create"]
);

// `ck.space.parent` is a CAS register keyed by the child Space ID.
per_subject_lattice!(
    SpaceParent,
    "ck.component.space.parent.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "space_id",
    &["ck.space.parent"]
);

per_subject_lattice!(
    AccountStatus,
    "ck.component.account.status.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "account_id",
    &["ck.account.status"]
);

per_subject_lattice!(
    PolicyRule,
    "ck.component.policy.rule.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "rule_id",
    &["ck.policy.rule"]
);

per_subject_lattice!(
    CrossSigningReset,
    "ck.component.cross_signing.reset.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    "principal_id",
    &["ck.cross_signing.reset"]
);

/// Lattice marker for the `ck.component.member.identity.v1` cell family.
/// Named `MemberIdentityLattice` (not `MemberIdentity`) to avoid colliding
/// with the wire object `models::MemberIdentity`.
pub struct MemberIdentityLattice;
impl LatticeKind for MemberIdentityLattice {
    fn cell_family(&self) -> &'static str {
        "ck.component.member.identity.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrderedLog
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Expose
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.member.identity.v1",
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
                cell_family: "ck.component.member.identity.v1",
                field: "realm_id",
            })?;
        let actor_id = effect_payload
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.member.identity.v1",
                field: "actor_id",
            })?;
        let segment = effect_payload
            .get("segment")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.member.identity.v1",
                field: "segment",
            })?;
        Ok(Some(format!("{realm_id}::{actor_id}::{segment}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ck.member.identity.update"]
    }
}

pub struct ContactFactLog;
impl LatticeKind for ContactFactLog {
    fn cell_family(&self) -> &'static str {
        "ck.component.contact.fact_log.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrderedLog
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Expose
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.contact.fact_log.v1",
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
                cell_family: "ck.component.contact.fact_log.v1",
                field: "target/requester/peer",
            })
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &[
            "ck.contact.requested",
            "ck.contact.accepted",
            "ck.contact.rejected",
            "ck.contact.tombstoned",
        ]
    }
}

per_subject_lattice!(
    DirectConversationBinding,
    "ck.component.direct_conversation.binding.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "pair_key",
    &["ck.direct_conversation.bound"]
);

// ────────────────────────── MvRegister families ──────────────────────────

per_subject_lattice!(
    ProfileCreate,
    "ck.component.profile.create.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "actor_id",
    &["ck.profile.create", "ck.profile.update"]
);

per_subject_lattice!(
    ViewCreate,
    "ck.component.view.create.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["ck.view.create"]
);

per_subject_lattice!(
    ViewUpdate,
    "ck.component.view.update.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["ck.view.update"]
);

per_subject_lattice!(
    ViewReconcile,
    "ck.component.view.reconcile.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["ck.view.reconcile"]
);

per_subject_lattice!(
    MimiRoomBinding,
    "ck.component.mimi.room_binding.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "room_id",
    &["ck.mimi.room_binding"]
);

// ─────────── Realm families ───────────

// ── Realm CasRegister/Reject singleton families ──

singleton_lattice!(
    RealmPolicy,
    "ck.component.realm.policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.policy"]
);

singleton_lattice!(
    RealmReadReceiptPolicy,
    "ck.component.realm.read_receipt_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.read_receipt_policy"]
);

singleton_lattice!(
    RealmHistoryVisibility,
    "ck.component.realm.history_visibility.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.history_visibility"]
);

singleton_lattice!(
    RealmJoinRule,
    "ck.component.realm.join_rule.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.join_rule"]
);

singleton_lattice!(
    RealmDiscovery,
    "ck.component.realm.discovery.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.discovery"]
);

// `ck.realm.organization` declares a tuple `cell_subject`:
// `(organization_id = payload.organization_id, relationship = payload.relationship)`.
// It is NOT a singleton keyed by realm_id; distinct (organization_id, relationship)
// pairs must form independent CAS register cells so they cannot overwrite each other.
pub struct RealmOrganization;
impl LatticeKind for RealmOrganization {
    fn cell_family(&self) -> &'static str {
        "ck.component.realm.organization.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.realm.organization.v1",
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
                cell_family: "ck.component.realm.organization.v1",
                field: "organization_id",
            })?;
        let relationship = effect_payload
            .get("relationship")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.realm.organization.v1",
                field: "relationship",
            })?;
        Ok(Some(format!("{organization_id}::{relationship}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ck.realm.organization"]
    }
}

singleton_lattice!(
    RealmArchive,
    "ck.component.realm.archive.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.archive"]
);

singleton_lattice!(
    RealmFreeze,
    "ck.component.realm.freeze.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.freeze"]
);

singleton_lattice!(
    RealmTombstone,
    "ck.component.realm.tombstone.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.tombstone"]
);

singleton_lattice!(
    RealmDestroy,
    "ck.component.realm.destroy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.destroy"]
);

singleton_lattice!(
    RealmModerationPolicy,
    "ck.component.realm.moderation_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.moderation_policy"]
);

singleton_lattice!(
    RealmHistorySharingPolicy,
    "ck.component.realm.history_sharing_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.history_sharing_policy"]
);

singleton_lattice!(
    RealmPreviewPolicy,
    "ck.component.realm.preview_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.preview_policy"]
);

singleton_lattice!(
    RealmAssetPrivacyPolicy,
    "ck.component.realm.asset_privacy_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.asset_privacy_policy"]
);

singleton_lattice!(
    RealmPolicyComponents,
    "ck.component.realm.policy_components.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.policy_components"]
);

singleton_lattice!(
    RealmPolicyServer,
    "ck.component.realm.policy_server.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.policy_server"]
);

singleton_lattice!(
    RealmPlaintextVisibleServices,
    "ck.component.realm.plaintext_visible_services.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.plaintext_visible_services"]
);

singleton_lattice!(
    RealmMediaService,
    "ck.component.realm.media_service.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.media_service"]
);

singleton_lattice!(
    RealmSchema,
    "ck.component.realm.schema.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.schema"]
);

singleton_lattice!(
    RealmDeliveryBindingPolicy,
    "ck.component.realm.delivery_binding_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.delivery_binding_policy"]
);

singleton_lattice!(
    RealmDisappearingPolicy,
    "ck.component.realm.disappearing_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.disappearing_policy"]
);

singleton_lattice!(
    RealmSearchPolicy,
    "ck.component.realm.search_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.search_policy"]
);

// ── Realm CasRegister/Reject per-subject families ──

per_subject_lattice!(
    RealmInheritancePolicy,
    "ck.component.realm.inheritance_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "source_realm_id",
    &["ck.realm.inheritance_policy"]
);

per_subject_lattice!(
    RealmUpgrade,
    "ck.component.realm.upgrade.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "target_reducer_profile",
    &["ck.realm.upgrade"]
);

// ── Realm OrderedLog/Expose families ──

singleton_lattice!(
    RealmCreate,
    "ck.component.realm.create.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["ck.realm.create"]
);

singleton_lattice!(
    RealmLink,
    "ck.component.realm.link.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["ck.realm.link"]
);

// ── New Strand facet families (per-subject by Strand id) ──

pub struct StrandMetadata;
impl LatticeKind for StrandMetadata {
    fn cell_family(&self) -> &'static str {
        "ck.component.strand.metadata.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.strand.metadata.v1",
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
                cell_family: "ck.component.strand.metadata.v1",
                field: "target_ref",
            })
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ck.strand.update"]
    }
}

per_subject_lattice!(
    StrandTracks,
    "ck.component.strand.tracks.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "strand_id",
    &["ck.strand.tracks.update"]
);
