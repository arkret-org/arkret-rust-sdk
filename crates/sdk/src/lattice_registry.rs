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
//!   device.list_update, covered_frontier (MLS).
//! - **CasRegister** (last-writer-wins, conflict→Bottom): space.policy,
//!   space.read_receipt_policy, space.history_visibility,
//!   space.join_rule, space.discovery, space.organization,
//!   space.upgrade, flow.position, place.parent, anchorer (Move/Anchor
//!   authority cell), mls_epoch, agent_workspace.reservation.
//! - **Fsm** (legal transitions only): member.state,
//!   agent_task.{execution_state, transparency, source_authority}.
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
/// contrix-spec event-kind-registry's `cell_subject` shape.
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
/// (matches the `criticality` field in the contrix-spec registry).
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

/// One canonical Contrix cell-family implementation.
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

    /// Durable Contrix event kinds whose projection feeds this cell
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
    "cx.component.device.authorized.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "device_id",
    &["cx.device.authorized", "cx.device.revoked"]
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
    &["cx.space.read_receipt_policy"]
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
    &["cx.space.upgrade"]
);

singleton_lattice!(
    SpaceArchive,
    "cx.component.space.archive.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.archive"]
);

singleton_lattice!(
    SpaceFreeze,
    "cx.component.space.freeze.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.freeze"]
);

singleton_lattice!(
    SpaceTombstone,
    "cx.component.space.tombstone.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.tombstone"]
);

singleton_lattice!(
    SpaceDestroy,
    "cx.component.space.destroy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.destroy"]
);

singleton_lattice!(
    SpaceModerationPolicy,
    "cx.component.space.moderation_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.moderation_policy"]
);

singleton_lattice!(
    SpaceHistorySharingPolicy,
    "cx.component.space.history_sharing_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.history_sharing_policy"]
);

singleton_lattice!(
    SpaceAssetPrivacyPolicy,
    "cx.component.space.asset_privacy_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.asset_privacy_policy"]
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
    &["cx.space.plaintext_visible_services"]
);

singleton_lattice!(
    SpaceMediaService,
    "cx.component.space.media_service.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.media_service"]
);

singleton_lattice!(
    SpaceSchema,
    "cx.component.space.schema.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.schema"]
);

singleton_lattice!(
    SpaceInheritancePolicy,
    "cx.component.space.inheritance_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.inheritance_policy"]
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

// Flow notification subscription cell, keyed by (flow_id, actor_did).
// Spec: contrix-spec/spec/v1/zh/models/flow-and-message.md §8.
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
        let actor_did = effect_payload.get("actor_did").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: "cx.component.flow.watch.v1",
                field: "actor_did",
            },
        )?;
        Ok(Some(format!("{flow_id}::{actor_did}")))
    }
    fn event_kinds(&self) -> &'static [&'static str] {
        &["cx.flow.watch.set"]
    }
}

per_subject_lattice!(
    PlaceParent,
    "cx.component.place.parent.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "place_id",
    &["cx.place.parent"]
);

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
    AgentTaskExecutionState,
    "cx.component.agent_task.execution_state.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "task_id",
    &["cx.agent_task.create", "cx.agent_task.execution.transition", "cx.agent_task.cancel"]
);

per_subject_lattice!(
    AgentTaskTransparency,
    "cx.component.agent_task.transparency.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "task_id",
    &["cx.agent_task.create", "cx.agent_task.transparency.transition"]
);

per_subject_lattice!(
    AgentTaskSourceAuthority,
    "cx.component.agent_task.source_authority.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "task_id",
    &["cx.agent_task.create", "cx.agent_task.source_authority.transition"]
);

// `cx.profile.agent_workspace.v1` — reservation cells (cas-register).
// Schema declares initial_value="__unset__" (spec PR 1.1, see
// event-auth-state-resolution.md §5.3.3). The spec registry exposes one
// family and multiplexes mirror_space_by_source / mirror_flow_by_source
// through a composite subject: (cell_namespace, cell_namespace_subject).
pub struct AgentWorkspaceReservation;
impl LatticeKind for AgentWorkspaceReservation {
    fn cell_family(&self) -> &'static str {
        "cx.component.agent_workspace.reservation.v1"
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
        let cell_namespace = effect_payload.get("cell_namespace").and_then(Value::as_str).ok_or(
            LatticeKindError::MissingSubjectField {
                cell_family: self.cell_family(),
                field: "cell_namespace",
            },
        )?;
        let cell_namespace_subject = effect_payload
            .get("cell_namespace_subject")
            .and_then(Value::as_str)
            .ok_or(LatticeKindError::MissingSubjectField {
                cell_family: self.cell_family(),
                field: "cell_namespace_subject",
            })?;
        Ok(Some(format!("{cell_namespace}:{cell_namespace_subject}")))
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &[
            "cx.agent_workspace.reservation.set",
            "cx.agent_workspace.reservation.recover",
            "cx.agent_workspace.reservation.cleanup",
        ]
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
    SpaceParent,
    "cx.component.space.parent.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Expose,
    Criticality::Required,
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
    registry.register(FlowWatch);
    registry.register(PlaceParent);
    registry.register(CrossSigningPublish);
    registry.register(AnchorerCell);
    registry.register(MlsEpoch);
    registry.register(AgentWorkspaceReservation);

    // Fsm
    registry.register(MemberState);
    registry.register(AgentTaskExecutionState);
    registry.register(AgentTaskTransparency);
    registry.register(AgentTaskSourceAuthority);

    // OrderedLog
    registry.register(SpaceCreate);
    registry.register(SpaceChild);
    registry.register(SpaceParent);
    registry.register(AccountStatus);
    registry.register(PolicyRule);
    registry.register(CrossSigningReset);

    // MvRegister
    registry.register(ProfileCreate);
    registry.register(ViewCreate);
    registry.register(ViewUpdate);
    registry.register(ViewReconcile);
    registry.register(MimiRoomBinding);

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
        "cx.component.device.authorized.v1",
        "cx.component.device.list_update.v1",
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
        "cx.component.flow.watch.v1",
        "cx.component.place.parent.v1",
        "cx.component.cross_signing.publish.v1",
        "cx.component.anchorer.v1",
        "cx.component.mls.epoch.v1",
        "cx.component.agent_workspace.reservation.v1",
        // Fsm
        "cx.component.member.state.v1",
        "cx.component.agent_task.execution_state.v1",
        "cx.component.agent_task.transparency.v1",
        "cx.component.agent_task.source_authority.v1",
        // OrderedLog
        "cx.component.space.create.v1",
        "cx.component.space.child.v1",
        "cx.component.space.parent.v1",
        "cx.component.account.status.v1",
        "cx.component.policy.rule.v1",
        "cx.component.cross_signing.reset.v1",
        // MvRegister
        "cx.component.profile.create.v1",
        "cx.component.view.create.v1",
        "cx.component.view.update.v1",
        "cx.component.view.reconcile.v1",
        "cx.component.mimi.room_binding.v1",
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
/// spec-normative membership and agent-task FSM tables are encoded
/// inline below.
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
        "cx.component.agent_task.execution_state.v1",
        None,
        vec![
            (json!("pending_source_stub"), json!("active")),
            (json!("pending_source_stub"), json!("cancelled_stub_rejected")),
            (json!("pending_source_stub"), json!("cancelled_orphan")),
            (json!("pending_source_stub"), json!("cancelled_by_controller")),
            (json!("active"), json!("completed")),
            (json!("active"), json!("cancelled_by_controller")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "cx.component.agent_task.transparency.v1",
        None,
        vec![(json!("ok"), json!("lost")), (json!("lost"), json!("reconfirmed_after_loss"))],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "cx.component.agent_task.source_authority.v1",
        None,
        vec![
            (json!("ok"), json!("revoked")),
            (json!("revoked"), json!("reconfirmed_after_revoke")),
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
        // family. Locked at 49 to catch silent additions/removals;
        // bump this number deliberately when the spec event-kind
        // registry grows a new cell_family.
        let registry = default_lattice_registry();
        assert_eq!(registry.len(), 50);
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
    fn agent_workspace_reservation_uses_unified_family() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup("cx.component.agent_workspace.reservation.v1")
            .expect("unified agent workspace reservation family should be registered");
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let subject = kind
            .subject_for_effect(&json!({
                "cell_namespace": "mirror_space_by_source",
                "cell_namespace_subject": "cx:space:source"
            }))
            .unwrap();
        assert_eq!(subject.as_deref(), Some("mirror_space_by_source:cx:space:source"));
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
