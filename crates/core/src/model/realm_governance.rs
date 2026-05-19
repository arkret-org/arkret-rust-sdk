//! Realm governance typed payloads introduced by the R1.2 Realm/Space
//! reversal (spec rounds R2 / R3).
//!
//! These types model the three new wire payloads that compose the
//! cross-Realm governance surface:
//!
//! - [`RealmLink`] — `cx.realm.link` payload. Typed link between two
//!   Realm boundaries, one of eight canonical [`RealmLinkKind`] values.
//! - [`RealmInheritancePolicy`] — `cx.realm.inheritance_policy` payload.
//!   Declares which policy names + capability bundles a child Realm
//!   inherits from a parent Realm, capped by `max_depth`.
//! - [`CapabilityDerived`] — `cx.capability.derived` payload. Records a
//!   capability that was derived by composing a parent Realm's grant
//!   with a child Realm's inheritance declaration.
//!
//! All three are wire-shape-only typed structs at this stage; the full
//! derive evaluation lives in the reducer's audit pipeline (TODO(realm-rework)).

use super::*;

/// Canonical link_kind values for `cx.realm.link`. The eight values
/// enumerate the typed cross-Realm relations the spec recognises post
/// R1.2 (Realm/Space reversal); link payloads MUST carry exactly one of
/// these. Wire form is snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmLinkKind {
    /// Target Realm is the governing authority for source Realm.
    GovernedBy,
    /// Source Realm may be discovered by members of target Realm.
    DiscoverableFrom,
    /// Source Realm accepts join requests from target Realm's
    /// authenticated members.
    JoinGateFrom,
    /// Source Realm inherits policy from target Realm (paired with a
    /// `cx.realm.inheritance_policy` declaration).
    InheritsPolicyFrom,
    /// Source Realm is a confidential extension (sub-Realm with stricter
    /// confidentiality envelope) of the target Realm.
    ConfidentialExtensionOf,
    /// Source Realm mirrors target Realm's content for replication /
    /// disaster-recovery purposes.
    MirrorOf,
    /// Source Realm was split off from target Realm (governance fork).
    SplitFrom,
    /// Source Realm fully replaces target Realm (terminal: target is
    /// tombstoned in favour of source).
    Replaces,
}

impl RealmLinkKind {
    /// Stable string form used in cell_subject keys and wire payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GovernedBy => "governed_by",
            Self::DiscoverableFrom => "discoverable_from",
            Self::JoinGateFrom => "join_gate_from",
            Self::InheritsPolicyFrom => "inherits_policy_from",
            Self::ConfidentialExtensionOf => "confidential_extension_of",
            Self::MirrorOf => "mirror_of",
            Self::SplitFrom => "split_from",
            Self::Replaces => "replaces",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "governed_by" => Self::GovernedBy,
            "discoverable_from" => Self::DiscoverableFrom,
            "join_gate_from" => Self::JoinGateFrom,
            "inherits_policy_from" => Self::InheritsPolicyFrom,
            "confidential_extension_of" => Self::ConfidentialExtensionOf,
            "mirror_of" => Self::MirrorOf,
            "split_from" => Self::SplitFrom,
            "replaces" => Self::Replaces,
            _ => return None,
        })
    }

    /// The full enumeration of canonical kinds; useful for tests and
    /// admin tooling.
    pub fn all() -> &'static [RealmLinkKind] {
        &[
            Self::GovernedBy,
            Self::DiscoverableFrom,
            Self::JoinGateFrom,
            Self::InheritsPolicyFrom,
            Self::ConfidentialExtensionOf,
            Self::MirrorOf,
            Self::SplitFrom,
            Self::Replaces,
        ]
    }
}

/// Lifecycle status of a `cx.realm.link`. The link cell is `or_set`-keyed
/// by `(source_realm_id, target_realm_id, link_kind)`; status flips this
/// triple from `active` to `rejected` or `tombstoned` without producing
/// a new key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmLinkStatus {
    Active,
    Rejected,
    Tombstoned,
}

impl RealmLinkStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rejected => "rejected",
            Self::Tombstoned => "tombstoned",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "active" => Self::Active,
            "rejected" => Self::Rejected,
            "tombstoned" => Self::Tombstoned,
            _ => return None,
        })
    }
}

/// Typed payload for the `cx.realm.link` event.
///
/// Cell family: `cx.component.realm.link.v1` (or_set lattice). Cell
/// subject key: `(realm_id, target_realm_id, link_kind)`. The reducer
/// resolves status flips by retaining the latest status per triple.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmLinkPayload {
    /// Target Realm id (the link's "to" side). `source_realm_id` is the
    /// envelope `space_id` and is therefore implicit.
    pub target_realm_id: RealmId,
    pub link_kind: RealmLinkKind,
    #[serde(default = "default_link_status")]
    pub status: RealmLinkStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional opaque commitment / proof reference linking this edge to
    /// an external attestation (e.g. governance approval, sub-Realm split
    /// transcript). Free-form per spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
}

fn default_link_status() -> RealmLinkStatus {
    RealmLinkStatus::Active
}

/// Direction filter used by the realm-link query API to scope the
/// returned edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmLinkDirection {
    /// Edges where this Realm is the source — `realm_id == realm_id`.
    Outbound,
    /// Edges where this Realm is the target — `target_realm_id == realm_id`.
    Inbound,
    /// Both directions concatenated.
    #[default]
    Both,
}

impl RealmLinkDirection {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "outbound" => Self::Outbound,
            "inbound" => Self::Inbound,
            "both" => Self::Both,
            _ => return None,
        })
    }
}

/// Typed payload for the `cx.realm.inheritance_policy` event.
///
/// Cell family: `cx.component.realm.inheritance_policy.v1` (cas-register).
/// Declares which policy names and capability bundles a Realm inherits
/// from a parent (source) Realm. The reducer rejects payloads with
/// `max_depth > 1` (the wire spec currently caps inheritance at depth 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmInheritancePolicy {
    /// Parent Realm whose policies / capabilities are being inherited.
    pub source_realm_id: RealmId,
    /// List of policy names (free-form strings per spec; reducer does no
    /// enum enforcement) inherited from `source_realm_id`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_policies: Vec<String>,
    /// Capability bundle identifiers inherited from `source_realm_id`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_capability_bundles: Vec<String>,
    /// Maximum inheritance depth. Wire spec currently caps this at 1;
    /// the reducer rejects payloads with `max_depth > 1`.
    #[serde(default = "default_inheritance_max_depth")]
    pub max_depth: u32,
}

fn default_inheritance_max_depth() -> u32 {
    1
}

impl RealmInheritancePolicy {
    /// Cap on `max_depth` enforced by the wire validator + soland
    /// reducer at this stage. Composite inheritance (depth>1) is TODO.
    pub const MAX_DEPTH_CAP: u32 = 1;

    pub fn validate(&self) -> Result<()> {
        if self.max_depth == 0 {
            return Err(Error::Protocol(
                "realm.inheritance_policy.max_depth MUST be >= 1".to_owned(),
            ));
        }
        if self.max_depth > Self::MAX_DEPTH_CAP {
            return Err(Error::Protocol(format!(
                "realm.inheritance_policy.max_depth must be <= {} (current wire cap)",
                Self::MAX_DEPTH_CAP
            )));
        }
        Ok(())
    }
}

/// Typed payload for the `cx.capability.derived` event.
///
/// Cell family: `cx.component.capability.derived.v1` (cas-register keyed
/// by `capability_id`). Records a capability that was derived from
/// composing a parent Realm grant (`source_grant_ref`) with a child
/// Realm's inheritance declaration (`source_realm_inheritance_policy_ref`).
///
/// The full derive evaluation (verify the source grant, replay the
/// inheritance policy, project the resulting bundle) lives in the
/// reducer's audit pipeline and is currently TODO(realm-rework). At
/// schema level the soland reducer accepts the payload + projects the
/// cell so downstream consumers can introspect it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CapabilityDerived {
    pub capability_id: CapabilityId,
    pub source_grant_ref: EventRef,
    pub source_realm_inheritance_policy_ref: EventRef,
    /// Causal frontier (free-form string per spec event-kind-registry)
    /// that the derived capability is anchored against. Reducer treats
    /// this opaquely.
    pub causal_frontier: String,
    /// Optional declarative shape of the derived capability bundle.
    /// Reducer projects it through but doesn't introspect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_link_kind_roundtrip_covers_all_eight() {
        for kind in RealmLinkKind::all() {
            let s = kind.as_str();
            let parsed = RealmLinkKind::parse(s).unwrap_or_else(|| panic!("parse {s}"));
            assert_eq!(parsed, *kind);
        }
        // Total count: spec pins exactly eight canonical kinds.
        assert_eq!(RealmLinkKind::all().len(), 8);
    }

    #[test]
    fn realm_link_status_default_is_active() {
        let payload: RealmLinkPayload = serde_json::from_value(serde_json::json!({
            "target_realm_id": "cx:realm:01904100-0000-7000-8000-cfc039892036",
            "link_kind": "governed_by",
        }))
        .unwrap();
        assert_eq!(payload.status, RealmLinkStatus::Active);
    }

    #[test]
    fn realm_link_payload_serde_roundtrip() {
        let payload = RealmLinkPayload {
            target_realm_id: RealmId::new("cx:realm:01904100-0000-7000-8000-cfc039892036").unwrap(),
            link_kind: RealmLinkKind::JoinGateFrom,
            status: RealmLinkStatus::Active,
            label: Some("compliance gate".to_owned()),
            commitment: Some("cx:event:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned()),
        };
        let v = serde_json::to_value(&payload).unwrap();
        let back: RealmLinkPayload = serde_json::from_value(v).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn realm_inheritance_policy_validate_rejects_excessive_depth() {
        let bad = RealmInheritancePolicy {
            source_realm_id: RealmId::new("cx:realm:01904100-0000-7000-8000-cfc039892036").unwrap(),
            allowed_policies: vec!["join_policy.v1".to_owned()],
            allowed_capability_bundles: vec!["bundle.admin.v1".to_owned()],
            max_depth: 2,
        };
        assert!(bad.validate().is_err());

        let good = RealmInheritancePolicy {
            source_realm_id: RealmId::new("cx:realm:01904100-0000-7000-8000-cfc039892036").unwrap(),
            allowed_policies: vec!["join_policy.v1".to_owned()],
            allowed_capability_bundles: vec!["bundle.admin.v1".to_owned()],
            max_depth: 1,
        };
        assert!(good.validate().is_ok());
    }

    #[test]
    fn capability_derived_serde_roundtrip() {
        let cap = CapabilityDerived {
            capability_id: CapabilityId::new("cx:capability:01904100-0000-7000-8000-bbbbbbbbbbbb")
                .unwrap(),
            source_grant_ref: EventRef::new(
                "cx:event:01904100-0000-7000-8000-cccccccccccc".to_owned(),
                "authorized_by".to_owned(),
            ),
            source_realm_inheritance_policy_ref: EventRef::new(
                "cx:event:01904100-0000-7000-8000-dddddddddddd".to_owned(),
                "inherits_from".to_owned(),
            ),
            causal_frontier: "cx:frontier:02000000".to_owned(),
            bundle: Some(serde_json::json!({"capabilities": ["read", "write"]})),
        };
        let v = serde_json::to_value(&cap).unwrap();
        let back: CapabilityDerived = serde_json::from_value(v).unwrap();
        assert_eq!(back, cap);
    }
}
