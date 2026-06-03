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
//! - **OrSet** (causal add/remove): consent.grant, capability.grant /
//!   delegate / derived, session.grant, device.authorized,
//!   device.list_update, agent.key, covered_frontier (MLS).
//! - **CasRegister** (last-writer-wins, conflict→Bottom): space.policy,
//!   space.read_receipt_policy, space.history_visibility,
//!   space.join_rule, space.discovery, space.organization,
//!   realm.upgrade, flow.position, flow.stage, morph.stage, space.parent,
//!   anchorer (Move/Anchor authority cell), mls_epoch.
//! - **Fsm** (legal transitions only): member.state, agent.status.
//!   
//! - **OrderedLog** (per-issuer monotonic append): space.create,
//!   space.child, space.parent, account.status, policy.rule,
//!   cross_signing.reset.
//! - **MvRegister** (concurrent multi-value): profile.create,
//!   view.create / update / reconcile, mimi.room_binding.

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
/// `cx.capability.grant` + `cx.capability.revoke`) MUST share
/// `component_type` so the receiver treats them as supersedes on the
/// same cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentDescriptor {
    /// Stable URI in the `cx.component.<facet-path>.v<n>` namespace.
    pub component_type: &'static str,
    /// Monotonic version within the same `component_type`.
    pub component_version: u32,
    /// Receiver behaviour for unknown component_type/version.
    pub criticality: Criticality,
}

/// Bottom-handling policy for a cell family.
///
/// - `Reject`: when the Lattice's `join` returns a structured `Bottom`,
///   the receiver MUST quarantine the resolved cell and emit
///   `bottom_diagnostics` events. Lattice queries on this cell return
///   `bottom` rather than choosing a winner. This is the v1 default for
///   safety-critical cells (capability, consent, anchorer).
/// - `Expose`: callers are expected to render the multi-value set
///   directly (e.g. UI shows "two concurrent edits, please reconcile"
///   rather than blocking). Suitable for advisory cells (Flow titles,
///   user profile fields).
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
    /// `CellRegistry` uses to drive Move/Anchor receive-pipeline
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
    MissingSubjectField { cell_family: &'static str, field: &'static str },
    /// The cell_family declared by a Move effect doesn't match this
    /// `LatticeKind`. The dispatcher MUST route to a different impl.
    UnknownCellFamily { observed: String, declared: &'static str },
}

impl std::fmt::Display for LatticeKindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSubjectField { cell_family, field } => {
                write!(f, "{cell_family} requires effect field `{field}` for cell subject")
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
/// Each impl owns one `cell_family` (e.g. `cx.component.consent.v1`),
/// declares the lattice algebra that resolves it (one of the six
/// spec-normative lattices from [`crate::lattice::LatticeKind`]), and
/// exposes subject-derivation + post-resolution validation hooks.
/// Move/Anchor receive pipeline iterates anchored Moves, groups effects
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
        singleton_lattice!($struct_name, $cell_family, $lattice, $bottom, $criticality, &[]);
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
    "cx.component.consent.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "consent_id",
    &["cx.consent.grant", "cx.consent.revoke"]
);

per_subject_lattice!(
    CapabilityGrant,
    "cx.component.capability.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "capability_id",
    &["cx.capability.grant", "cx.capability.revoke"]
);

per_subject_lattice!(
    CapabilityDelegate,
    "cx.component.capability.delegate.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "capability_id",
    &["cx.capability.delegate"]
);

per_subject_lattice!(
    CapabilityDerived,
    "cx.component.capability.derived.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "capability_id",
    &["cx.capability.derived"]
);

per_subject_lattice!(
    SessionGrant,
    "cx.component.session.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "session_id",
    &["cx.session.grant"]
);

per_subject_lattice!(
    DeviceAuthorized,
    "cx.component.device.authorization.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "device_id",
    &["cx.device.authorize", "cx.device.revoke"]
);

per_subject_lattice!(
    DeviceListUpdate,
    "cx.component.device.list_update.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "owner_did",
    &["cx.device.list_update"]
);

pub struct AgentKey;
impl LatticeKind for AgentKey {
    fn cell_family(&self) -> &'static str {
        "cx.component.agent.key.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrSet
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "cx.component.agent.key.v1",
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
            cell_family: "cx.component.agent.key.v1",
            field: "agent_principal_id",
        })?;
        let key_id = effect_payload.get("key_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "cx.component.agent.key.v1",
                field: "key_id",
            },
        )?;
        Ok(Some(format!("{agent_principal_id}::{key_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["cx.agent.key.authorize", "cx.agent.key.revoke", "cx.agent.key.rotate"]
    }
}

singleton_lattice!(
    CoveredFrontier,
    "cx.component.mls.covered_frontier.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required
);

// ────────────────────────── CasRegister families ──────────────────────────

singleton_lattice!(
    SpacePolicy,
    "cx.component.space.policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.policy"]
);

singleton_lattice!(
    SpaceReadReceiptPolicyLattice,
    "cx.component.space.read_receipt_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.read_receipt_policy"]
);

singleton_lattice!(
    SpaceHistoryVisibility,
    "cx.component.space.history_visibility.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.history_visibility"]
);

singleton_lattice!(
    SpaceJoinRule,
    "cx.component.space.join_rule.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.join_rule"]
);

singleton_lattice!(
    SpaceDiscovery,
    "cx.component.space.discovery.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.discovery"]
);

singleton_lattice!(
    SpaceOrganization,
    "cx.component.space.organization.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.organization", "cx.realm.update"]
);

singleton_lattice!(
    SpaceUpgrade,
    "cx.component.space.upgrade.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.upgrade"]
);

singleton_lattice!(
    SpaceArchive,
    "cx.component.space.archive.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.archive"]
);

singleton_lattice!(
    SpaceFreeze,
    "cx.component.space.freeze.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.freeze"]
);

singleton_lattice!(
    SpaceTombstone,
    "cx.component.space.tombstone.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.tombstone"]
);

singleton_lattice!(
    SpaceDestroy,
    "cx.component.space.destroy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.destroy"]
);

singleton_lattice!(
    CircleTombstone,
    "cx.component.circle.tombstone.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.circle.tombstone"]
);

singleton_lattice!(
    SpaceModerationPolicy,
    "cx.component.space.moderation_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.moderation_policy"]
);

singleton_lattice!(
    SpaceHistorySharingPolicy,
    "cx.component.space.history_sharing_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.history_sharing_policy"]
);

singleton_lattice!(
    SpaceAssetPrivacyPolicy,
    "cx.component.space.asset_privacy_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.asset_privacy_policy"]
);

singleton_lattice!(
    SpacePolicyComponents,
    "cx.component.space.policy_components.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.policy_components"]
);

singleton_lattice!(
    SpacePolicyServer,
    "cx.component.space.policy_server.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.policy_server"]
);

singleton_lattice!(
    SpacePlaintextVisibleServices,
    "cx.component.space.plaintext_visible_services.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.plaintext_visible_services"]
);

singleton_lattice!(
    SpaceMediaService,
    "cx.component.space.media_service.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.media_service"]
);

singleton_lattice!(
    SpaceSchema,
    "cx.component.space.schema.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.schema"]
);

singleton_lattice!(
    SpaceInheritancePolicy,
    "cx.component.space.inheritance_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.inheritance_policy"]
);

per_subject_lattice!(
    FlowPosition,
    "cx.component.flow.position.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "flow_id",
    &["cx.flow.move", "cx.flow.reorder"]
);

per_subject_lattice!(
    FlowStage,
    "cx.component.flow.stage.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "flow_id",
    &["cx.flow.stage.set"]
);

per_subject_lattice!(
    MorphStage,
    "cx.component.morph.stage.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "morph_id",
    &["cx.morph.stage.set"]
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
        "cx.component.flow.watch.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "cx.component.flow.watch.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let flow_id = effect_payload.get("flow_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "cx.component.flow.watch.v1",
                field: "flow_id",
            },
        )?;
        let watcher_actor_id = effect_payload
            .get("watcher_actor_id")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: "cx.component.flow.watch.v1",
                field: "watcher_actor_id",
            })?;
        Ok(Some(format!("{flow_id}::{watcher_actor_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["cx.flow.watch.set"]
    }
}

per_subject_lattice!(
    CrossSigningPublish,
    "cx.component.cross_signing.publish.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "principal_id",
    &["cx.cross_signing.publish"]
);

singleton_lattice!(
    AnchorerCell,
    "cx.component.anchorer.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

singleton_lattice!(
    MlsEpoch,
    "cx.component.mls.epoch.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

// ────────────────────────── Fsm families ──────────────────────────

per_subject_lattice!(
    MemberState,
    "cx.component.member.state.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "actor_id",
    &["cx.member.state"]
);

per_subject_lattice!(
    AgentStatus,
    "cx.component.agent.status.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "agent_principal_id",
    &["cx.agent.pause", "cx.agent.resume", "cx.agent.deactivate"]
);

pub struct CircleMember;
impl LatticeKind for CircleMember {
    fn cell_family(&self) -> &'static str {
        "cx.component.circle.member.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "cx.component.circle.member.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let circle_id = effect_payload.get("circle_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "cx.component.circle.member.v1",
                field: "circle_id",
            },
        )?;
        let actor_id = effect_payload.get("actor_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "cx.component.circle.member.v1",
                field: "actor_id",
            },
        )?;
        Ok(Some(format!("{circle_id}::{actor_id}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["cx.circle.member.state"]
    }
}

// ────────────────────────── OrderedLog families ──────────────────────────

singleton_lattice!(
    SpaceCreate,
    "cx.component.space.create.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["cx.space.create"]
);

singleton_lattice!(
    SpaceChild,
    "cx.component.space.child.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["cx.space.child"]
);

singleton_lattice!(
    CircleCreate,
    "cx.component.circle.create.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["cx.circle.create"]
);

// R1.2 — spec event-kind registry declares `cx.component.space.parent.v1`
// as `cas-register/reject` keyed by `payload.space_id`. The legacy
// `OrderedLog` declaration here predates the registry rev and was caught
// by `artifact_cell_family_lattice_and_bottom_drift_test`.
per_subject_lattice!(
    SpaceParent,
    "cx.component.space.parent.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "space_id",
    &["cx.space.parent"]
);

per_subject_lattice!(
    AccountStatus,
    "cx.component.account.status.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "account_id",
    &["cx.account.status"]
);

per_subject_lattice!(
    PolicyRule,
    "cx.component.policy.rule.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    "rule_id",
    &["cx.policy.rule"]
);

per_subject_lattice!(
    CrossSigningReset,
    "cx.component.cross_signing.reset.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    "principal_id",
    &["cx.cross_signing.reset"]
);

pub struct MemberIdentity;
impl LatticeKind for MemberIdentity {
    fn cell_family(&self) -> &'static str {
        "cx.component.member.identity.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::OrderedLog
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Expose
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "cx.component.member.identity.v1",
            component_version: 1,
            criticality: Criticality::Required,
        }
    }
    fn subject_for_effect(
        &self,
        effect_payload: &Value,
    ) -> Result<Option<String>, LatticeKindError> {
        let realm_id = effect_payload.get("realm_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "cx.component.member.identity.v1",
                field: "realm_id",
            },
        )?;
        let actor_id = effect_payload.get("actor_id").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "cx.component.member.identity.v1",
                field: "actor_id",
            },
        )?;
        let segment = effect_payload.get("segment").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "cx.component.member.identity.v1",
                field: "segment",
            },
        )?;
        Ok(Some(format!("{realm_id}::{actor_id}::{segment}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["cx.member.identity.update"]
    }
}

// ────────────────────────── MvRegister families ──────────────────────────

per_subject_lattice!(
    ProfileCreate,
    "cx.component.profile.create.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "actor_id",
    &["cx.profile.create", "cx.profile.update"]
);

per_subject_lattice!(
    ViewCreate,
    "cx.component.view.create.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["cx.view.create"]
);

per_subject_lattice!(
    ViewUpdate,
    "cx.component.view.update.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["cx.view.update"]
);

per_subject_lattice!(
    ViewReconcile,
    "cx.component.view.reconcile.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["cx.view.reconcile"]
);

per_subject_lattice!(
    MimiRoomBinding,
    "cx.component.mimi.room_binding.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "room_id",
    &["cx.mimi.room_binding"]
);

// ─────────── Realm-rename + spec-new families (R1.2) ───────────
//
// The spec event-kind registry has renamed the realm-scoped policy /
// lifecycle cell families from `cx.component.space.*` to
// `cx.component.realm.*` (per `cokret-spec/spec/v1/zh/models/realm-and-space.md`).
// Two brand-new flow-shape families (`cx.component.flow.metadata.v1`,
// `cx.component.flow.tracks.v1`) and one cross-realm linking family
// (`cx.component.realm.link.v1`) also landed in the same rev.
//
// These impls are registered AFTER the legacy `Space*` impls in
// `default_lattice_registry()` so the event_kind index — which is
// last-write-wins — resolves `cx.realm.<facet>` to the new
// `cx.component.realm.<facet>.v1` family. The old `Space*` impls stay
// registered for back-compat with existing soland reducer cell IDs
// (`ck:cell:cx.component.space.policy.v1:<space_id>` etc.) until those
// reducer paths follow the rename.

// ── Realm CasRegister/Reject singleton families ──

singleton_lattice!(
    RealmPolicy,
    "cx.component.realm.policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.policy"]
);

singleton_lattice!(
    RealmReadReceiptPolicy,
    "cx.component.realm.read_receipt_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.read_receipt_policy"]
);

singleton_lattice!(
    RealmHistoryVisibility,
    "cx.component.realm.history_visibility.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.history_visibility"]
);

singleton_lattice!(
    RealmJoinRule,
    "cx.component.realm.join_rule.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.join_rule"]
);

singleton_lattice!(
    RealmDiscovery,
    "cx.component.realm.discovery.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.discovery"]
);

singleton_lattice!(
    RealmOrganization,
    "cx.component.realm.organization.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.organization"]
);

singleton_lattice!(
    RealmArchive,
    "cx.component.realm.archive.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.archive"]
);

singleton_lattice!(
    RealmFreeze,
    "cx.component.realm.freeze.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.freeze"]
);

singleton_lattice!(
    RealmTombstone,
    "cx.component.realm.tombstone.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.tombstone"]
);

singleton_lattice!(
    RealmDestroy,
    "cx.component.realm.destroy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.destroy"]
);

singleton_lattice!(
    RealmModerationPolicy,
    "cx.component.realm.moderation_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.moderation_policy"]
);

singleton_lattice!(
    RealmHistorySharingPolicy,
    "cx.component.realm.history_sharing_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.history_sharing_policy"]
);

singleton_lattice!(
    RealmPreviewPolicy,
    "cx.component.realm.preview_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.preview_policy"]
);

singleton_lattice!(
    RealmAssetPrivacyPolicy,
    "cx.component.realm.asset_privacy_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.asset_privacy_policy"]
);

singleton_lattice!(
    RealmPolicyComponents,
    "cx.component.realm.policy_components.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.policy_components"]
);

singleton_lattice!(
    RealmPolicyServer,
    "cx.component.realm.policy_server.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.policy_server"]
);

singleton_lattice!(
    RealmPlaintextVisibleServices,
    "cx.component.realm.plaintext_visible_services.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.plaintext_visible_services"]
);

singleton_lattice!(
    RealmMediaService,
    "cx.component.realm.media_service.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.media_service"]
);

singleton_lattice!(
    RealmSchema,
    "cx.component.realm.schema.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.schema"]
);

singleton_lattice!(
    RealmDeliveryBindingPolicy,
    "cx.component.realm.delivery_binding_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.realm.delivery_binding_policy"]
);

// ── Realm CasRegister/Reject per-subject families ──

per_subject_lattice!(
    RealmInheritancePolicy,
    "cx.component.realm.inheritance_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "source_realm_id",
    &["cx.realm.inheritance_policy"]
);

per_subject_lattice!(
    RealmUpgrade,
    "cx.component.realm.upgrade.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "target_reducer_profile",
    &["cx.realm.upgrade"]
);

// ── Realm OrderedLog/Expose families ──

singleton_lattice!(
    RealmCreate,
    "cx.component.realm.create.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["cx.realm.create"]
);

singleton_lattice!(
    RealmLink,
    "cx.component.realm.link.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
    &["cx.realm.link"]
);

// ── New Flow facet families (per-subject by Flow id) ──

pub struct FlowMetadata;
impl LatticeKind for FlowMetadata {
    fn cell_family(&self) -> &'static str {
        "cx.component.flow.metadata.v1"
    }
    fn lattice(&self) -> SdkLatticeKind {
        SdkLatticeKind::CasRegister
    }
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }
    fn component(&self) -> ComponentDescriptor {
        ComponentDescriptor {
            component_type: "cx.component.flow.metadata.v1",
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
                cell_family: "cx.component.flow.metadata.v1",
                field: "target_ref",
            })
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["cx.flow.update"]
    }
}

per_subject_lattice!(
    FlowTracks,
    "cx.component.flow.tracks.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "flow_id",
    &["cx.flow.tracks.update"]
);

// ───────────────────────── Factory ─────────────────────────

/// Build a [`LatticeRegistry`] pre-populated with every spec-normative
/// cell family covered by this module. Downstream Move/Anchor receive
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
    registry.register(AgentKey);
    registry.register(CoveredFrontier);

    // CasRegister
    registry.register(SpacePolicy);
    registry.register(SpaceReadReceiptPolicyLattice);
    registry.register(SpaceHistoryVisibility);
    registry.register(SpaceJoinRule);
    registry.register(SpaceDiscovery);
    registry.register(SpaceOrganization);
    registry.register(SpaceUpgrade);
    registry.register(SpaceArchive);
    registry.register(SpaceFreeze);
    registry.register(SpaceTombstone);
    registry.register(SpaceDestroy);
    registry.register(CircleTombstone);
    registry.register(CircleMember);
    registry.register(SpaceModerationPolicy);
    registry.register(SpaceHistorySharingPolicy);
    registry.register(SpaceAssetPrivacyPolicy);
    registry.register(SpacePolicyComponents);
    registry.register(SpacePolicyServer);
    registry.register(SpacePlaintextVisibleServices);
    registry.register(SpaceMediaService);
    registry.register(SpaceSchema);
    registry.register(SpaceInheritancePolicy);
    registry.register(FlowPosition);
    registry.register(FlowStage);
    registry.register(MorphStage);
    registry.register(FlowWatch);
    registry.register(CrossSigningPublish);
    registry.register(AnchorerCell);
    registry.register(MlsEpoch);

    // Fsm
    registry.register(MemberState);
    registry.register(AgentStatus);

    // OrderedLog
    registry.register(SpaceCreate);
    registry.register(SpaceChild);
    registry.register(CircleCreate);
    registry.register(SpaceParent);
    registry.register(AccountStatus);
    registry.register(PolicyRule);
    registry.register(CrossSigningReset);
    registry.register(MemberIdentity);

    // MvRegister
    registry.register(ProfileCreate);
    registry.register(ViewCreate);
    registry.register(ViewUpdate);
    registry.register(ViewReconcile);
    registry.register(MimiRoomBinding);

    // R1.2 — Realm-rename families. Registered after the legacy `Space*`
    // impls so the event_kind index (last-write-wins) resolves
    // `cx.realm.<facet>` events to the new `cx.component.realm.<facet>.v1`
    // families per the spec event-kind-registry.
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
/// Move/Anchor receive pipeline (`apply_anchor` / `verify_move`)
/// resolves every spec-declared cell family correctly. The list mirrors
/// [`default_lattice_registry`] one-to-one.
pub fn lattice_bindings_for_sdk_registry() -> Vec<(&'static str, SdkLatticeKind, BottomMode)> {
    let registry = default_lattice_registry();
    const FAMILIES: &[&str] = &[
        // OrSet
        "cx.component.consent.grant.v1",
        "cx.component.capability.grant.v1",
        "cx.component.capability.delegate.v1",
        "cx.component.capability.derived.v1",
        "cx.component.session.grant.v1",
        "cx.component.device.authorization.v1",
        "cx.component.device.list_update.v1",
        "cx.component.agent.key.v1",
        "cx.component.mls.covered_frontier.v1",
        // CasRegister
        "cx.component.space.policy.v1",
        "cx.component.space.read_receipt_policy.v1",
        "cx.component.space.history_visibility.v1",
        "cx.component.space.join_rule.v1",
        "cx.component.space.discovery.v1",
        "cx.component.space.organization.v1",
        "cx.component.space.upgrade.v1",
        "cx.component.space.archive.v1",
        "cx.component.space.freeze.v1",
        "cx.component.space.tombstone.v1",
        "cx.component.space.destroy.v1",
        "cx.component.circle.tombstone.v1",
        "cx.component.circle.member.v1",
        "cx.component.space.moderation_policy.v1",
        "cx.component.space.history_sharing_policy.v1",
        "cx.component.space.asset_privacy_policy.v1",
        "cx.component.space.policy_components.v1",
        "cx.component.space.policy_server.v1",
        "cx.component.space.plaintext_visible_services.v1",
        "cx.component.space.media_service.v1",
        "cx.component.space.schema.v1",
        "cx.component.space.inheritance_policy.v1",
        "cx.component.flow.position.v1",
        "cx.component.flow.stage.v1",
        "cx.component.morph.stage.v1",
        "cx.component.flow.watch.v1",
        "cx.component.cross_signing.publish.v1",
        "cx.component.anchorer.v1",
        "cx.component.mls.epoch.v1",
        // Fsm
        "cx.component.member.state.v1",
        "cx.component.agent.status.v1",
        // OrderedLog
        "cx.component.space.create.v1",
        "cx.component.space.child.v1",
        "cx.component.circle.create.v1",
        "cx.component.space.parent.v1",
        "cx.component.account.status.v1",
        "cx.component.policy.rule.v1",
        "cx.component.cross_signing.reset.v1",
        "cx.component.member.identity.v1",
        // MvRegister
        "cx.component.profile.create.v1",
        "cx.component.view.create.v1",
        "cx.component.view.update.v1",
        "cx.component.view.reconcile.v1",
        "cx.component.mimi.room_binding.v1",
        // R1.2 — Realm-rename + spec-new flow facet families.
        "cx.component.realm.policy.v1",
        "cx.component.realm.read_receipt_policy.v1",
        "cx.component.realm.history_visibility.v1",
        "cx.component.realm.join_rule.v1",
        "cx.component.realm.discovery.v1",
        "cx.component.realm.organization.v1",
        "cx.component.realm.archive.v1",
        "cx.component.realm.freeze.v1",
        "cx.component.realm.tombstone.v1",
        "cx.component.realm.destroy.v1",
        "cx.component.realm.moderation_policy.v1",
        "cx.component.realm.history_sharing_policy.v1",
        "cx.component.realm.preview_policy.v1",
        "cx.component.realm.asset_privacy_policy.v1",
        "cx.component.realm.policy_components.v1",
        "cx.component.realm.policy_server.v1",
        "cx.component.realm.plaintext_visible_services.v1",
        "cx.component.realm.media_service.v1",
        "cx.component.realm.schema.v1",
        "cx.component.realm.delivery_binding_policy.v1",
        "cx.component.realm.inheritance_policy.v1",
        "cx.component.realm.upgrade.v1",
        "cx.component.realm.create.v1",
        "cx.component.realm.link.v1",
        "cx.component.flow.metadata.v1",
        "cx.component.flow.tracks.v1",
    ];
    FAMILIES
        .iter()
        .map(|family| {
            let kind = registry
                .lookup(family)
                .unwrap_or_else(|| panic!("default_lattice_registry missing {family}"));
            (*family, kind.lattice(), kind.bottom_policy().to_sdk_bottom_mode())
        })
        .collect()
}

/// Build a fresh [`MemoryCellRegistry`] populated with every
/// spec-declared cell family. Move/Anchor receive pipeline
/// (`verify_move` / `apply_anchor`) uses this to resolve
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
        "cx.component.member.state.v1",
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
        "cx.component.agent.status.v1",
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
        // Sanity-check that the move from soland preserved every
        // family. Bumped to 75 after R1.2 — the spec event-kind registry
        // renamed `cx.component.space.*` realm-policy families to
        // `cx.component.realm.*` and added `cx.component.flow.metadata.v1`,
        // `cx.component.flow.tracks.v1`, `cx.component.realm.link.v1`,
        // `cx.component.realm.create.v1`, `cx.component.realm.destroy.v1`,
        // `cx.component.realm.delivery_binding_policy.v1`. We keep the
        // legacy `Space*` impls registered for reducer back-compat, so
        // 49 (legacy) + 28 (new realm/flow/morph/agent) - 4 withdrawn
        // agent extension vectors families, plus agent status, Circle, and
        // member identity cells, plus preview policy = 79.
        // Bump this number deliberately when the spec event-kind
        // registry grows a new cell_family.
        let registry = default_lattice_registry();
        assert_eq!(registry.len(), 79);
    }

    #[test]
    fn consent_grant_has_or_set_lattice_and_consent_id_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.consent.grant.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let payload = json!({"consent_id": "cnt:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("cnt:01HXYZ"));
    }

    #[test]
    fn member_state_uses_fsm_lattice_with_actor_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.member.state.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::Fsm);
        let payload = json!({"actor_id": "did:example:alice"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("did:example:alice"));
    }

    #[test]
    fn space_policy_is_singleton_cas_register() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.space.policy.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn anchorer_cell_is_singleton_cas_register_and_required() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.anchorer.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let comp = kind.component();
        assert_eq!(comp.criticality, Criticality::Required);
        assert_eq!(comp.component_type, "cx.component.anchorer.v1");
    }

    #[test]
    fn covered_frontier_is_singleton_or_set() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.mls.covered_frontier.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn mv_register_families_have_expose_bottom() {
        let registry = default_lattice_registry();
        for family in [
            "cx.component.profile.create.v1",
            "cx.component.view.create.v1",
            "cx.component.view.update.v1",
            "cx.component.view.reconcile.v1",
            "cx.component.mimi.room_binding.v1",
        ] {
            let kind =
                registry.lookup(family).unwrap_or_else(|| panic!("missing impl for {family}"));
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
        let kind = registry.lookup("cx.component.space.create.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        let kind = registry.lookup("cx.component.account.status.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        let payload = json!({"account_id": "act:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("act:01HXYZ"));
    }

    #[test]
    fn missing_subject_field_surfaces_typed_error() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.flow.position.v1").unwrap();
        let err = kind.subject_for_effect(&json!({"unrelated": "x"})).unwrap_err();
        match err {
            LatticeKindError::MissingSubjectField { cell_family, field } => {
                assert_eq!(cell_family, "cx.component.flow.position.v1");
                assert_eq!(field, "flow_id");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn event_kind_index_resolves_consent_grant_and_revoke() {
        let registry = default_lattice_registry();
        let grant = registry
            .lookup_for_event_kind("cx.consent.grant")
            .expect("cx.consent.grant should map to consent.grant.v1 cell");
        assert_eq!(grant.cell_family(), "cx.component.consent.grant.v1");
        let revoke = registry
            .lookup_for_event_kind("cx.consent.revoke")
            .expect("cx.consent.revoke shares the consent.grant.v1 cell (or-set rm)");
        assert_eq!(revoke.cell_family(), "cx.component.consent.grant.v1");
    }

    #[test]
    fn lattice_kind_error_display_is_stable() {
        let err = LatticeKindError::MissingSubjectField {
            cell_family: "cx.component.flow.position.v1",
            field: "flow_id",
        };
        let msg = format!("{err}");
        assert!(msg.contains("cx.component.flow.position.v1"));
        assert!(msg.contains("flow_id"));
    }
}
