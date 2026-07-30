use serde::{Deserialize, Serialize};

pub use crate::generated::EventWireScope;
pub use crate::generated::event_kinds::{
    CbaEffectPlane, EVENT_KIND_COUNT, EventKind, EventRegistryCategory, cba_cell_family_plane,
};

/// Object-only schema id; this is not an Event.kind.
pub const RECEIPT_OBJECT_KINDS: &[&str] = &["ak.event_batch_receipt"];

pub fn is_ephemeral_kind(kind: &str) -> bool {
    EventKind::try_new(kind).is_some_and(|kind| kind.wire_scope() == EventWireScope::EphemeralEvent)
}

pub fn is_receipt_object_only(kind: &str) -> bool {
    RECEIPT_OBJECT_KINDS.contains(&kind)
}

pub fn event_payload_schema_ref(kind: &str) -> Option<&'static str> {
    EventKind::try_new(kind).and_then(|kind| {
        kind.descriptor()
            .and_then(|descriptor| descriptor.payload_schema_ref)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmLifecycleState {
    Active,
    Frozen,
    Archived,
    Tombstoned,
    Destroyed,
}

pub fn is_terminal_realm_state(state: RealmLifecycleState) -> bool {
    matches!(state, RealmLifecycleState::Destroyed)
}

pub fn is_reducer_input_event_kind(kind: &str) -> bool {
    EventKind::try_new(kind).is_some_and(|kind| kind.is_reducer_input())
}

pub fn event_wire_scope(kind: &str) -> EventWireScope {
    EventKind::try_new(kind)
        .and_then(|kind| kind.descriptor().map(|descriptor| descriptor.wire_scope))
        .unwrap_or(EventWireScope::Custom)
}

/// Broad class for routing, indexing and UI projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventProductClass {
    Account,
    Actor,
    Agent,
    Applet,
    Audit,
    Authz,
    Call,
    /// AKP-0007 (spec b7d35be) — Circle lifecycle / membership events.
    Circle,
    Consent,
    /// AKP-0015 contact enhancement — contact-request lifecycle and the
    /// direct-conversation Realm binding it produces.
    Contact,
    Device,
    E2ee,
    Strand,
    Handle,
    Identity,
    Invite,
    Membership,
    Message,
    Mimi,
    Moderation,
    Morph,
    Organization,
    Pin,
    Policy,
    Profile,
    Read,
    Realm,
    Relation,
    Schema,
    Sidecar,
    Sovereign,
    Space,
    /// Governance state resolution — currently only the `⊥` conflict recovery
    /// of `event-auth-state-resolution.md` §9.5.
    State,
    View,
    Custom(String),
}

pub fn is_standard_event_kind(kind: &str) -> bool {
    EventKind::try_new(kind).is_some()
}

/// Classify a protocol event kind without deserializing its content.
pub fn event_product_class(kind: &EventKind) -> EventProductClass {
    match kind {
        EventKind::AccountBlocklist | EventKind::AccountStatus | EventKind::AccountDataSet => {
            EventProductClass::Account
        }
        EventKind::ActorDiscovery => EventProductClass::Actor,
        EventKind::StateConflictRecovery => EventProductClass::State,
        EventKind::AgentActionApprove
        | EventKind::AgentActionReject
        | EventKind::AgentActionRequest
        | EventKind::SelfAgentDeactivate
        | EventKind::AgentDraftPropose
        | EventKind::AgentKeyAuthorize
        | EventKind::AgentKeyRevoke
        | EventKind::SelfAgentPause
        | EventKind::SelfAgentResume
        | EventKind::AgentSelectorClaim => EventProductClass::Agent,
        EventKind::SidecarCreate | EventKind::AgentSidecarExchangeControl => {
            EventProductClass::Sidecar
        }
        EventKind::AppletBridgeError
        | EventKind::AppletDiscovery
        | EventKind::AppletRegistration => EventProductClass::Applet,
        EventKind::AttestationRangeCompleteness
        | EventKind::AuditAccessed
        | EventKind::AuditAppletBinding
        | EventKind::AuditErasureReceipt
        | EventKind::AuditRelease
        | EventKind::AuditRywReceipt
        | EventKind::AuditSessionAuthorize
        | EventKind::AuditSessionClose
        | EventKind::AuditSessionNotice
        | EventKind::AuditSessionRequest => EventProductClass::Audit,
        EventKind::CapabilityDelegate
        | EventKind::CapabilityDerived
        | EventKind::CapabilityGrant
        | EventKind::CapabilityRevoke
        | EventKind::SessionGrant => EventProductClass::Authz,
        EventKind::CallRecordingStart | EventKind::CallState | EventKind::CallSummary => {
            EventProductClass::Call
        }
        EventKind::CircleCreate
        | EventKind::CircleUpdate
        | EventKind::CircleArchive
        | EventKind::CircleRestore
        | EventKind::CircleTombstone
        | EventKind::CircleMemberState
        | EventKind::CircleSealCommit => EventProductClass::Circle,
        EventKind::ConsentGrant | EventKind::ConsentRevoke => EventProductClass::Consent,
        EventKind::ContactRequested
        | EventKind::ContactAccepted
        | EventKind::ContactRejected
        | EventKind::ContactTombstoned
        | EventKind::DirectConversationBound => EventProductClass::Contact,
        EventKind::DeviceAuthorize
        | EventKind::CrossSigningPublish
        | EventKind::CrossSigningReset
        | EventKind::DeviceListUpdate
        | EventKind::DevicePushRoute
        | EventKind::DeviceReanchor
        | EventKind::DeviceRevoke
        | EventKind::KeyBackupActiveSeries => EventProductClass::Device,
        EventKind::MlsCommit
        | EventKind::MlsCommitFailed
        | EventKind::MlsGenesis
        | EventKind::MlsKeypackage
        | EventKind::MlsProposal
        | EventKind::MlsWelcome
        | EventKind::RealmKeyShare
        | EventKind::RealmKeyShareAudit
        | EventKind::RealmKeyWithheld => EventProductClass::E2ee,
        EventKind::StrandArchive
        | EventKind::StrandCreate
        | EventKind::StrandMove
        | EventKind::StrandReorder
        | EventKind::StrandRestore
        | EventKind::StrandStageSet
        | EventKind::StrandTracksUpdate
        | EventKind::StrandUpdate
        | EventKind::StrandWatchSet => EventProductClass::Strand,
        EventKind::HandleDiscovery => EventProductClass::Handle,
        EventKind::DidProof
        | EventKind::IdentityAccountabilityGrant
        | EventKind::IdentityDisclosurePolicy
        | EventKind::IdentityDisclosureReceipt
        | EventKind::IdentityPresentationRequest
        | EventKind::IdentityPresentationResponse => EventProductClass::Identity,
        EventKind::InviteAccept
        | EventKind::InviteCancel
        | EventKind::InviteClaim
        | EventKind::InviteCreate
        | EventKind::InviteRevoke
        | EventKind::InviteThirdParty => EventProductClass::Invite,
        EventKind::MemberIdentityUpdate | EventKind::MemberState => EventProductClass::Membership,
        EventKind::MessageCreate
        | EventKind::MessageRedact
        | EventKind::MessageRevise
        | EventKind::ReactionAdd
        | EventKind::ReactionRemove
        | EventKind::Redaction => EventProductClass::Message,
        EventKind::MimiRoomBinding => EventProductClass::Mimi,
        EventKind::ModerationAppealClose
        | EventKind::ModerationAppealDecision
        | EventKind::ModerationAppealReview
        | EventKind::ModerationAppealSubmit
        | EventKind::ModerationDecision
        | EventKind::ModerationDecisionLift
        | EventKind::ModerationFrankingProof
        | EventKind::SelfModerationReport => EventProductClass::Moderation,
        EventKind::MorphArchive
        | EventKind::MorphCreate
        | EventKind::MorphRestore
        | EventKind::MorphSchemaMigrate
        | EventKind::MorphStageSet
        | EventKind::MorphUpdate => EventProductClass::Morph,
        EventKind::OrganizationDiscovery | EventKind::OrganizationModerationPolicy => {
            EventProductClass::Organization
        }
        EventKind::PinAdd | EventKind::PinRemove | EventKind::PinReorder => EventProductClass::Pin,
        EventKind::PolicyAction | EventKind::PolicyRule | EventKind::PolicySet => {
            EventProductClass::Policy
        }
        EventKind::ProfileCreate | EventKind::ProfileRealmOverride | EventKind::ProfileUpdate => {
            EventProductClass::Profile
        }
        EventKind::ReadCursorAdvance => EventProductClass::Read,
        EventKind::RealmArchive
        | EventKind::RealmAssetPrivacyPolicy
        | EventKind::RealmCreate
        | EventKind::RealmDeliveryBindingPolicy
        | EventKind::RealmDisappearingPolicy
        | EventKind::RealmDestroy
        | EventKind::RealmDiscovery
        | EventKind::RealmFreeze
        | EventKind::RealmAlias
        | EventKind::RealmHistorySharingPolicy
        | EventKind::RealmHistoryVisibility
        | EventKind::RealmInheritancePolicy
        | EventKind::RealmJoinRule
        | EventKind::RealmSetDefaultStrand
        | EventKind::RealmNotary
        | EventKind::RealmDigestSuiteTransition
        | EventKind::RealmLink
        | EventKind::RealmMediaService
        | EventKind::RealmModerationPolicy
        | EventKind::RealmOrganization
        | EventKind::RealmPlaintextVisibleServices
        | EventKind::RealmPolicy
        | EventKind::RealmPolicyBundle
        | EventKind::RealmPolicyServer
        | EventKind::RealmPreviewPolicy
        | EventKind::RealmReadReceiptPolicy
        | EventKind::RealmSchema
        | EventKind::RealmSearchPolicy
        | EventKind::RealmTombstone
        | EventKind::RealmUpdate
        | EventKind::RealmUpgrade
        | EventKind::NotaryFaultCensorship
        | EventKind::NotaryFaultEquivocation => EventProductClass::Realm,
        EventKind::ContainerMoveItem
        | EventKind::ContainerRebalance
        | EventKind::RelationCreate
        | EventKind::RelationTombstone
        | EventKind::RelationUpdate => EventProductClass::Relation,
        EventKind::RsvpSet => EventProductClass::Strand,
        EventKind::SchemaDefine | EventKind::SchemaUpdate => EventProductClass::Schema,
        EventKind::SovereignDidPolicy => EventProductClass::Sovereign,
        EventKind::SpaceArchive
        | EventKind::SpaceCreate
        | EventKind::SpaceParent
        | EventKind::SpaceRestore
        | EventKind::SpaceTombstone
        | EventKind::SpaceUpdate => EventProductClass::Space,
        EventKind::ViewCreate | EventKind::ViewReconcile | EventKind::ViewUpdate => {
            EventProductClass::View
        }
        EventKind::Unknown(raw) => EventProductClass::Custom(raw.clone()),
    }
}

/// Classify a raw boundary value while preserving unknown values.
pub fn event_product_class_from_wire(kind: &str) -> EventProductClass {
    event_product_class(&EventKind::from_wire(kind))
}

pub fn is_audit_kind(kind: &str) -> bool {
    kind.starts_with("ak.audit.")
}

pub fn is_redaction_kind(kind: &str) -> bool {
    matches!(kind, EventKind::MESSAGE_REDACT | EventKind::REDACTION)
}

pub fn is_membership_kind(kind: &str) -> bool {
    matches!(
        event_product_class_from_wire(kind),
        EventProductClass::Membership
    )
}

pub fn is_invite_kind(kind: &str) -> bool {
    matches!(
        event_product_class_from_wire(kind),
        EventProductClass::Invite
    )
}

pub fn is_realm_lifecycle_kind(kind: &str) -> bool {
    matches!(
        kind,
        EventKind::REALM_CREATE
            | EventKind::REALM_UPDATE
            | EventKind::REALM_ARCHIVE
            | EventKind::REALM_FREEZE
            | EventKind::REALM_DESTROY
            | EventKind::REALM_TOMBSTONE
    )
}

pub fn is_pin_kind(kind: &str) -> bool {
    matches!(event_product_class_from_wire(kind), EventProductClass::Pin)
}

pub fn is_space_lifecycle_kind(kind: &str) -> bool {
    matches!(
        kind,
        EventKind::SPACE_ARCHIVE | EventKind::SPACE_RESTORE | EventKind::SPACE_TOMBSTONE
    )
}

pub fn is_strand_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, EventKind::STRAND_ARCHIVE | EventKind::STRAND_RESTORE)
}

pub fn is_morph_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, EventKind::MORPH_ARCHIVE | EventKind::MORPH_RESTORE)
}

pub fn is_strand_tracks_kind(kind: &str) -> bool {
    matches!(kind, EventKind::STRAND_TRACKS_UPDATE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_active_spec_event_kinds() {
        assert!(is_standard_event_kind(EventKind::MESSAGE_CREATE));
        assert_eq!(
            EventKind::MessageCreate.product_class(),
            EventProductClass::Message
        );
        assert_eq!(
            EventKind::RealmCreate.product_class(),
            EventProductClass::Realm
        );
        assert_eq!(
            EventKind::SpaceCreate.product_class(),
            EventProductClass::Space
        );
        assert!(is_invite_kind(EventKind::INVITE_CREATE));
        assert!(is_membership_kind(EventKind::MEMBER_STATE));
        assert!(is_pin_kind(EventKind::PIN_ADD));
        assert!(is_audit_kind(EventKind::AUDIT_RYW_RECEIPT));
        assert!(is_redaction_kind(EventKind::REDACTION));
        assert!(is_realm_lifecycle_kind(EventKind::REALM_TOMBSTONE));
        assert!(is_space_lifecycle_kind(EventKind::SPACE_ARCHIVE));
        assert!(is_strand_lifecycle_kind(EventKind::STRAND_ARCHIVE));
        assert!(is_morph_lifecycle_kind(EventKind::MORPH_ARCHIVE));
        assert!(is_strand_tracks_kind(EventKind::STRAND_TRACKS_UPDATE));
        assert_eq!(
            EventKind::CallState.product_class(),
            EventProductClass::Call
        );
        assert_eq!(
            event_product_class_from_wire("vendor.example.widget"),
            EventProductClass::Custom("vendor.example.widget".to_owned())
        );
        assert_eq!(
            EventKind::RealmNotary.product_class(),
            EventProductClass::Realm
        );
        assert_eq!(
            EventKind::RealmDigestSuiteTransition.product_class(),
            EventProductClass::Realm
        );
    }

    #[test]
    fn event_kind_namespaced_value_round_trips() {
        let kind = EventKind::try_new(EventKind::MESSAGE_CREATE).expect("registered event kind");
        assert_eq!(kind.as_str(), EventKind::MESSAGE_CREATE);
        assert_eq!(kind.product_class(), EventProductClass::Message);
        assert!(kind.is_reducer_input());
    }

    #[test]
    fn event_kind_try_new_rejects_vendor_kinds() {
        assert!(EventKind::try_new(EventKind::MESSAGE_CREATE).is_some());
        assert!(EventKind::try_new("vendor.example.widget").is_none());
        assert!(EventKind::try_new("").is_none());
    }

    #[test]
    fn event_kind_serde_preserves_unknown() {
        let kind = EventKind::MessageCreate;
        let json_text = serde_json::to_string(&kind).unwrap();
        assert_eq!(json_text, format!(r#""{}""#, EventKind::MESSAGE_CREATE));
        assert_eq!(serde_json::from_str::<EventKind>(&json_text).unwrap(), kind);

        let parsed: EventKind = serde_json::from_str(r#""ak.future.kind""#).unwrap();
        assert_eq!(parsed, EventKind::Unknown("ak.future.kind".to_owned()));
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            r#""ak.future.kind""#
        );
    }

    #[test]
    fn generated_event_kind_surface_is_complete() {
        assert_eq!(
            crate::generated::REGISTERED_EVENT_KINDS.len(),
            EVENT_KIND_COUNT
        );
        for descriptor in crate::generated::EVENT_KIND_DESCRIPTORS {
            let parsed = EventKind::from_wire(descriptor.kind);
            assert!(parsed.is_standard());
            assert_eq!(parsed.descriptor(), Some(descriptor));
        }
    }
}
