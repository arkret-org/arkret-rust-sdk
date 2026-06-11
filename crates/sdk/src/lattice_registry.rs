//! Cell-family lattice registry + spec-normative cell-family bindings.
//!
//! Per-cell-family [`LatticeKind`] runtime (one impl per `cell_family`
//! declared in the spec event-kind-registry) plus a [`LatticeRegistry`]
//! that pre-registers every spec-normative family via
//! [`default_lattice_registry`].
//!
//! Naming note: this module's [`LatticeKind`] is the *trait* declaring
//! which lattice algebra owns a given `cell_family`; the SDK's
//! [`crate::lattice::LatticeKind`] is the *enum* listing the six
//! normative algebras themselves. Impls below dispatch a `cell_family`
//! → `crate::lattice::LatticeKind` enum mapping plus a typed
//! subject-derivation function.
//!
//! Coverage (mirrors soland `reducer::lattice_kinds`):
//! - **OrSet** (causal add/remove): consent.grant, capability.grant / delegate / derived,
//!   session.grant, device.authorized, device.list_update, agent.key, covered_seals (MLS).
//! - **CasRegister** (last-writer-wins, conflict→Bottom): realm.policy, realm.read_receipt_policy,
//!   realm.history_visibility, realm.join_rule, realm.discovery, realm.organization, realm.upgrade,
//!   flow.position, flow.stage, morph.stage, space.parent, device.push_route, notary (Move/Seal
//!   authority cell), mls_epoch.
//! - **Fsm** (legal transitions only): member.state, agent.status.
//! - **OrderedLog** (per-issuer monotonic append): account.status, policy.rule,
//!   cross_signing.reset, contact.fact_log, direct_conversation.binding.
//! - **MvRegister** (concurrent multi-value): profile.create, view.create / update / reconcile,
//!   mimi.room_binding.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::lattice::LatticeKind as SdkLatticeKind;
use crate::state_res::{BottomMode, MemoryCellRegistry};

/// Cell-cardinality declared by a [`LatticeKind`] — corresponds to the
/// cokret-spec event-kind-registry's `cell_subject` shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateCardinality {
    /// One projection slot per `(space_id, cell_family)`. Subject empty.
    Singleton,
    /// One projection slot per `(space_id, cell_family, subject)`; subject
    /// is derived from the typed effect-payload field declared in the spec
    /// registry's `cell_subject`.
    PerSubject,
    /// Not a state-bearing event — no slot, no subject.
    None,
}

/// Receiver behaviour when an unknown component_type/version is seen
/// (matches the `criticality` field in the cokret-spec registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Criticality {
    /// MUST fail closed (schema_violation / soft_fail / quarantine
    /// depending on context).
    Required,
    /// MAY warn and skip; do not advance reducer state for this event.
    Optional,
    /// Silently drop; do not advance reducer state.
    Ignore,
}

/// Stable identification of the logical cell this [`LatticeKind`] drives.
/// Multiple kinds operating on the same cell (paired kinds, e.g.
/// `ck.capability.grant` + `ck.capability.revoke`) MUST share
/// `component_type` so the receiver treats them as supersedes on the
/// same cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentDescriptor {
    /// Stable URI in the `ck.component.<facet-path>.v<n>` namespace.
    pub component_type: &'static str,
    /// Monotonic version within the same `component_type`.
    pub component_version: u32,
    /// Receiver behaviour for unknown component_type/version.
    pub criticality: Criticality,
}

/// Bottom-handling policy for a cell family.
///
/// - `Reject`: when the Lattice's `join` returns a structured `Bottom`, the receiver MUST
///   quarantine the resolved cell and emit `bottom_diagnostics` events. Lattice queries on this
///   cell return `bottom` rather than choosing a winner. This is the v1 default for safety-critical
///   cells (capability, consent, notary).
/// - `Expose`: callers are expected to render the multi-value set directly (e.g. UI shows "two
///   concurrent edits, please reconcile" rather than blocking). Suitable for advisory cells (Flow
///   titles, user profile fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BottomPolicy {
    Reject,
    Expose,
}

impl BottomPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Expose => "expose",
        }
    }

    /// Translate to the SDK state-res `BottomMode` that the
    /// `CellRegistry` uses to drive Move/Seal receive-pipeline
    /// bottom handling. The two are 1:1 by design.
    pub fn to_sdk_bottom_mode(self) -> BottomMode {
        match self {
            Self::Reject => BottomMode::Reject,
            Self::Expose => BottomMode::Expose,
        }
    }
}

/// Errors a [`LatticeKind`] can raise during subject derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LatticeKindError {
    /// The Move's effects[] is missing the typed field used to derive the
    /// cell subject (e.g. `payload.flow_id` for a flow-position cell).
    MissingSubjectField {
        cell_family: &'static str,
        field: &'static str,
    },
    /// The cell_family declared by a Move effect doesn't match this
    /// `LatticeKind`. The dispatcher MUST route to a different impl.
    UnknownCellFamily {
        observed: String,
        declared: &'static str,
    },
}

impl std::fmt::Display for LatticeKindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSubjectField { cell_family, field } => {
                write!(
                    f,
                    "{cell_family} requires effect field `{field}` for cell subject"
                )
            }
            Self::UnknownCellFamily { observed, declared } => {
                write!(
                    f,
                    "cell_family `{observed}` is not handled by this LatticeKind ({declared})"
                )
            }
        }
    }
}

impl std::error::Error for LatticeKindError {}

/// One canonical Cokret cell-family implementation.
///
/// Each impl owns one `cell_family` (e.g. `ck.component.consent.v1`),
/// declares the lattice algebra that resolves it (one of the six
/// spec-normative lattices from [`crate::lattice::LatticeKind`]), and
/// exposes subject-derivation + post-resolution validation hooks.
/// Move/Seal receive pipeline iterates sealed Moves, groups effects
/// by `(cell_family, cell_subject)`, and dispatches to the matching
/// `LatticeKind` for per-cell `Lattice::join`.
pub trait LatticeKind: Send + Sync {
    /// Stable cell-family id. Move effects route to this `LatticeKind`
    /// when the effect's `cell` ref has this family path.
    fn cell_family(&self) -> &'static str;

    /// Which of the six normative lattices drives this family. The SDK's
    /// `crate::lattice` module provides the runtime impl.
    fn lattice(&self) -> SdkLatticeKind;

    /// `reject` → quarantine on Bottom (default, safety-critical cells);
    /// `expose` → render multi-value directly (advisory cells).
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    /// Component metadata for extension handling.
    fn component(&self) -> ComponentDescriptor;

    /// Derive the cell subject from a Move effect's typed fields.
    fn subject_for_effect(
        &self,
        _effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        Ok(None)
    }

    /// Durable Cokret event kinds whose projection feeds this cell
    /// family. Empty by default — only kinds with a 1:N event-kind →
    /// cell-family mapping declare it.
    fn event_kinds(&self) -> &'static [&'static str] {
        &[]
    }
}

/// Canonical-cell-family registry. Holds one `Box<dyn LatticeKind>` per
/// registered `cell_family` string; lookup is `O(log n)` over a
/// `BTreeMap`. The inverted `event_kind → cell_family` index is built
/// from each impl's [`LatticeKind::event_kinds`] declaration.
#[derive(Default)]
pub struct LatticeRegistry {
    families: BTreeMap<&'static str, Box<dyn LatticeKind>>,
    event_kind_index: BTreeMap<&'static str, &'static str>,
}

impl LatticeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a cell-family impl. Subsequent inserts on the same
    /// family id replace the existing impl (last-write-wins).
    pub fn register<K>(&mut self, kind: K)
    where
        K: LatticeKind + 'static,
    {
        let family = kind.cell_family();
        for ek in kind.event_kinds() {
            self.event_kind_index.insert(*ek, family);
        }
        self.families.insert(family, Box::new(kind));
    }

    pub fn lookup(&self, cell_family: &str) -> Option<&dyn LatticeKind> {
        self.families.get(cell_family).map(|boxed| boxed.as_ref())
    }

    pub fn lookup_for_event_kind(&self, event_kind: &str) -> Option<&dyn LatticeKind> {
        let family = self.event_kind_index.get(event_kind)?;
        self.lookup(family)
    }

    pub fn event_kind_mappings(&self) -> usize {
        self.event_kind_index.len()
    }

    pub fn len(&self) -> usize {
        self.families.len()
    }

    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }
}

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
    "capability_id",
    &["ck.capability.grant", "ck.capability.revoke"]
);

per_subject_lattice!(
    CapabilityDelegate,
    "ck.component.capability.delegate.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "capability_id",
    &["ck.capability.delegate"]
);

per_subject_lattice!(
    CapabilityDerived,
    "ck.component.capability.derived.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "capability_id",
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
    CoveredFrontier,
    "ck.component.mls.covered_seals.v1",
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
    FlowPosition,
    "ck.component.flow.position.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "flow_id",
    &["ck.flow.move", "ck.flow.reorder"]
);

per_subject_lattice!(
    FlowStage,
    "ck.component.flow.stage.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "flow_id",
    &["ck.flow.stage.set"]
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

// Flow notification subscription cell, keyed by (flow_id, watcher_actor_id).
// Spec: cokret-spec/spec/v1/zh/models/flow-and-message.md §8.
// SDK's subject derivation composes both keys into a single string so the
// existing per-subject lattice infra (single Option<String>) works without
// growing tuple support; the cell store still treats each (flow, actor)
// pair as an independent slot.
pub struct FlowWatch;
impl LatticeKind for FlowWatch {
    fn cell_family(&self) -> &'static str {
        "ck.component.flow.watch.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.flow.watch.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let flow_id = effect_payload
            .get("flow_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.flow.watch.v1",
                field: "flow_id",
            })?;
        let watcher_actor_id = effect_payload
            .get("watcher_actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.flow.watch.v1",
                field: "watcher_actor_id",
            })?;
        Ok(Some(format!("{flow_id}::{watcher_actor_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ck.flow.watch.set"]
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
/// with the wire object `model::MemberIdentity`.
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

singleton_lattice!(
    RealmOrganization,
    "ck.component.realm.organization.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["ck.realm.organization"]
);

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

// ── New Flow facet families (per-subject by Flow id) ──

pub struct FlowMetadata;
impl LatticeKind for FlowMetadata {
    fn cell_family(&self) -> &'static str {
        "ck.component.flow.metadata.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "ck.component.flow.metadata.v1",
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
            .or_else(|| effect_payload.get("flow_id"))
            .and_then(Value::as_str)
            .map(|s| Some(s.to_owned()))
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "ck.component.flow.metadata.v1",
                field: "target_ref",
            })
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["ck.flow.update"]
    }
}

per_subject_lattice!(
    FlowTracks,
    "ck.component.flow.tracks.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "flow_id",
    &["ck.flow.tracks.update"]
);

// ───────────────────────── Factory ─────────────────────────

/// Build a [`LatticeRegistry`] pre-populated with every spec-normative
/// cell family covered by this module. Downstream Move/Seal receive
/// pipelines call this once at boot. Lifted from soland so all
/// consumers (soland, yougen Move pre-check, cotest fixtures) share
/// one canonical registry.
///
/// Coverage target: all spec-declared cell families in
/// `event-kind-registry.json`.
pub fn default_lattice_registry() -> LatticeRegistry {
    let mut registry = LatticeRegistry::new();

    // OrSet
    registry.register(ConsentGrant);
    registry.register(CapabilityGrant);
    registry.register(CapabilityDelegate);
    registry.register(CapabilityDerived);
    registry.register(SessionGrant);
    registry.register(DeviceAuthorized);
    registry.register(DeviceListUpdate);
    registry.register(DevicePushRoute);
    registry.register(AgentKey);
    registry.register(CoveredFrontier);
    registry.register(KeyBackupActiveSeries);

    // CasRegister
    registry.register(CircleTombstone);
    registry.register(CircleMember);
    registry.register(FlowPosition);
    registry.register(FlowStage);
    registry.register(MorphStage);
    registry.register(FlowWatch);
    registry.register(CrossSigningPublish);
    registry.register(NotaryCell);
    registry.register(MlsEpoch);

    // Fsm
    registry.register(MemberState);
    registry.register(AgentStatus);

    // OrderedLog
    registry.register(CircleCreate);
    registry.register(SpaceParent);
    registry.register(AccountStatus);
    registry.register(PolicyRule);
    registry.register(CrossSigningReset);
    registry.register(MemberIdentityLattice);
    registry.register(ContactFactLog);
    registry.register(DirectConversationBinding);

    // MvRegister
    registry.register(ProfileCreate);
    registry.register(ViewCreate);
    registry.register(ViewUpdate);
    registry.register(ViewReconcile);
    registry.register(MimiRoomBinding);

    registry.register(RealmPolicy);
    registry.register(RealmReadReceiptPolicy);
    registry.register(RealmHistoryVisibility);
    registry.register(RealmJoinRule);
    registry.register(RealmDiscovery);
    registry.register(RealmOrganization);
    registry.register(RealmArchive);
    registry.register(RealmFreeze);
    registry.register(RealmTombstone);
    registry.register(RealmDestroy);
    registry.register(RealmModerationPolicy);
    registry.register(RealmHistorySharingPolicy);
    registry.register(RealmPreviewPolicy);
    registry.register(RealmAssetPrivacyPolicy);
    registry.register(RealmPolicyComponents);
    registry.register(RealmPolicyServer);
    registry.register(RealmPlaintextVisibleServices);
    registry.register(RealmMediaService);
    registry.register(RealmSchema);
    registry.register(RealmDeliveryBindingPolicy);
    registry.register(RealmDisappearingPolicy);
    registry.register(RealmSearchPolicy);
    registry.register(RealmInheritancePolicy);
    registry.register(RealmUpgrade);
    registry.register(RealmCreate);
    registry.register(RealmLink);
    registry.register(FlowMetadata);
    registry.register(FlowTracks);

    registry
}

/// One-shot list of `(cell_family, sdk_lattice_kind, sdk_bottom_mode)`
/// used to bulk-register the SDK's [`MemoryCellRegistry`] so the
/// Move/Seal receive pipeline (`apply_seal` / `verify_move`)
/// resolves every spec-declared cell family correctly. The list mirrors
/// [`default_lattice_registry`] one-to-one.
pub fn lattice_bindings_for_sdk_registry() -> Vec<(&'static str, SdkLatticeKind, BottomMode)> {
    let registry = default_lattice_registry();
    const FAMILIES: &[&str] = &[
        // OrSet
        "ck.component.consent.grant.v1",
        "ck.component.capability.grant.v1",
        "ck.component.capability.delegate.v1",
        "ck.component.capability.derived.v1",
        "ck.component.session.grant.v1",
        "ck.component.device.authorization.v1",
        "ck.component.device.list_update.v1",
        "ck.component.device.push_route.v1",
        "ck.component.agent.key.v1",
        "ck.component.mls.covered_seals.v1",
        "ck.component.key_backup.active_series.v1",
        // CasRegister
        "ck.component.circle.tombstone.v1",
        "ck.component.circle.member.v1",
        "ck.component.flow.position.v1",
        "ck.component.flow.stage.v1",
        "ck.component.morph.stage.v1",
        "ck.component.flow.watch.v1",
        "ck.component.cross_signing.publish.v1",
        "ck.component.notary.v1",
        "ck.component.mls.epoch.v1",
        // Fsm
        "ck.component.member.state.v1",
        "ck.component.agent.status.v1",
        // OrderedLog
        "ck.component.circle.create.v1",
        "ck.component.space.parent.v1",
        "ck.component.account.status.v1",
        "ck.component.policy.rule.v1",
        "ck.component.cross_signing.reset.v1",
        "ck.component.member.identity.v1",
        "ck.component.contact.fact_log.v1",
        "ck.component.direct_conversation.binding.v1",
        // MvRegister
        "ck.component.profile.create.v1",
        "ck.component.view.create.v1",
        "ck.component.view.update.v1",
        "ck.component.view.reconcile.v1",
        "ck.component.mimi.room_binding.v1",
        // Realm + spec-new flow facet families.
        "ck.component.realm.policy.v1",
        "ck.component.realm.read_receipt_policy.v1",
        "ck.component.realm.history_visibility.v1",
        "ck.component.realm.join_rule.v1",
        "ck.component.realm.discovery.v1",
        "ck.component.realm.organization.v1",
        "ck.component.realm.archive.v1",
        "ck.component.realm.freeze.v1",
        "ck.component.realm.tombstone.v1",
        "ck.component.realm.destroy.v1",
        "ck.component.realm.moderation_policy.v1",
        "ck.component.realm.history_sharing_policy.v1",
        "ck.component.realm.preview_policy.v1",
        "ck.component.realm.asset_privacy_policy.v1",
        "ck.component.realm.policy_components.v1",
        "ck.component.realm.policy_server.v1",
        "ck.component.realm.plaintext_visible_services.v1",
        "ck.component.realm.media_service.v1",
        "ck.component.realm.schema.v1",
        "ck.component.realm.delivery_binding_policy.v1",
        "ck.component.realm.disappearing_policy.v1",
        "ck.component.realm.search_policy.v1",
        "ck.component.realm.inheritance_policy.v1",
        "ck.component.realm.upgrade.v1",
        "ck.component.realm.create.v1",
        "ck.component.realm.link.v1",
        "ck.component.flow.metadata.v1",
        "ck.component.flow.tracks.v1",
    ];
    FAMILIES
        .iter()
        .map(|family| {
            let kind = registry
                .lookup(family)
                .unwrap_or_else(|| panic!("default_lattice_registry missing {family}"));
            (
                *family,
                kind.lattice(),
                kind.bottom_policy().to_sdk_bottom_mode(),
            )
        })
        .collect()
}

/// Build a fresh [`MemoryCellRegistry`] populated with every
/// spec-declared cell family. Move/Seal receive pipeline
/// (`verify_move` / `apply_seal`) uses this to resolve
/// `(family → Lattice)` for every effect.
///
/// FSM families need their transition tables set via `register_fsm`; the
/// spec-normative membership FSM table is encoded inline below.
pub fn build_sdk_cell_registry() -> MemoryCellRegistry {
    use serde_json::json;

    let mut sdk_registry = MemoryCellRegistry::new();
    for (family, kind, bottom_mode) in lattice_bindings_for_sdk_registry() {
        if matches!(kind, SdkLatticeKind::Fsm) {
            continue;
        }
        sdk_registry.register(family, kind, bottom_mode);
    }
    sdk_registry.register_fsm(
        "ck.component.member.state.v1",
        Some(json!("invite")),
        vec![
            (json!("invite"), json!("join")),
            (json!("invite"), json!("leave")),
            (json!("knock"), json!("join")),
            (json!("knock"), json!("leave")),
            (json!("join"), json!("leave")),
            (json!("join"), json!("ban")),
            (json!("leave"), json!("invite")),
            (json!("leave"), json!("knock")),
            (json!("ban"), json!("invite")),
            (json!("ban"), json!("knock")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ck.component.agent.status.v1",
        None,
        vec![
            (json!("active"), json!("paused")),
            (json!("paused"), json!("active")),
            (json!("pending_runtime_key"), json!("deactivated")),
            (json!("active"), json!("deactivated")),
            (json!("paused"), json!("deactivated")),
            (json!("pairing_expired"), json!("deactivated")),
        ],
        BottomMode::Reject,
    );
    sdk_registry
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn default_registry_covers_at_least_all_spec_normative_cell_families() {
        let registry = default_lattice_registry();
        // Spec event-kind-registry has 40+ unique `cell_family` strings;
        // this registry should cover them all.
        assert!(
            registry.len() >= 40,
            "expected ≥40 cell families registered, got {}",
            registry.len()
        );
    }

    #[test]
    fn default_registry_kind_count_matches_expected_total() {
        // The registry covers the 60 cell families declared by
        // event-kind-registry plus the three reducer-local seal/MLS
        // families (`notary`, `mls.epoch`, `mls.covered_seals`).
        let registry = default_lattice_registry();
        assert_eq!(registry.len(), 63);
    }

    #[test]
    fn consent_grant_has_or_set_lattice_and_consent_id_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.consent.grant.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let payload = json!({"consent_id": "cnt:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("cnt:01HXYZ"));
    }

    #[test]
    fn member_state_uses_fsm_lattice_with_actor_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.member.state.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::Fsm);
        let payload = json!({"actor_id": "did:example:alice"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("did:example:alice"));
    }

    #[test]
    fn realm_policy_is_singleton_cas_register() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.realm.policy.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn notary_cell_is_singleton_cas_register_and_required() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.notary.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let comp = kind.component();
        assert_eq!(comp.criticality, Criticality::Required);
        assert_eq!(comp.component_type, "ck.component.notary.v1");
    }

    #[test]
    fn covered_seals_is_singleton_or_set() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup("ck.component.mls.covered_seals.v1")
            .unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn mv_register_families_have_expose_bottom() {
        let registry = default_lattice_registry();
        for family in [
            "ck.component.profile.create.v1",
            "ck.component.view.create.v1",
            "ck.component.view.update.v1",
            "ck.component.view.reconcile.v1",
            "ck.component.mimi.room_binding.v1",
        ] {
            let kind = registry
                .lookup(family)
                .unwrap_or_else(|| panic!("missing impl for {family}"));
            assert_eq!(kind.lattice(), SdkLatticeKind::MvRegister);
            assert_eq!(
                kind.bottom_policy(),
                BottomPolicy::Expose,
                "{family} should expose multi-value via UX, not reject"
            );
        }
    }

    #[test]
    fn ordered_log_families_have_per_issuer_subject_or_singleton() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.realm.create.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        let kind = registry.lookup("ck.component.account.status.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        let payload = json!({"account_id": "act:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("act:01HXYZ"));
    }

    #[test]
    fn missing_subject_field_surfaces_typed_error() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.flow.position.v1").unwrap();
        let err = kind
            .subject_for_effect(&json!({"unrelated": "x"}))
            .unwrap_err();
        match err {
            LatticeKindError::MissingSubjectField { cell_family, field } => {
                assert_eq!(cell_family, "ck.component.flow.position.v1");
                assert_eq!(field, "flow_id");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn event_kind_index_resolves_consent_grant_and_revoke() {
        let registry = default_lattice_registry();
        let grant = registry
            .lookup_for_event_kind("ck.consent.grant")
            .expect("ck.consent.grant should map to consent.grant.v1 cell");
        assert_eq!(grant.cell_family(), "ck.component.consent.grant.v1");
        let revoke = registry
            .lookup_for_event_kind("ck.consent.revoke")
            .expect("ck.consent.revoke shares the consent.grant.v1 cell (or-set rm)");
        assert_eq!(revoke.cell_family(), "ck.component.consent.grant.v1");
    }

    #[test]
    fn lattice_kind_error_display_is_stable() {
        let err = LatticeKindError::MissingSubjectField {
            cell_family: "ck.component.flow.position.v1",
            field: "flow_id",
        };
        let msg = format!("{err}");
        assert!(msg.contains("ck.component.flow.position.v1"));
        assert!(msg.contains("flow_id"));
    }
}
