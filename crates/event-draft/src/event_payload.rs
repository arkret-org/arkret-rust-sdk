//! Typed read-only projections over the payload-agnostic wire [`Event`].

use arkret_models_collaboration::agent_operations::AgentSidecarExchangeControlPayload;
use arkret_models_collaboration::contact_operations::ContactScopeUpdatePayload;
use arkret_models_collaboration::events_payloads::agent::{
    AgentActionApprovePayload, AgentActionRejectPayload, AgentActionRequestPayload,
    AgentDeactivatePayload, AgentDraftProposePayload, AgentKeyAuthorizePayload,
    AgentKeyRevokePayload, AgentPausePayload, AgentProvisionPayload, AgentResumePayload,
};
use arkret_models_collaboration::events_payloads::audit::{
    AuditAccessedPayload, AuditAppletBindingCreatePayload, AuditAppletBindingStatePayload,
    AuditPayload, AuditReleasePayload, AuditSessionAuthorizePayload, AuditSessionClosePayload,
    AuditSessionNoticePayload, AuditSessionRequestPayload,
};
use arkret_models_collaboration::events_payloads::call::{
    CallCreatePayload, CallRecordingStartPayload, CallStatePayload, CallSummaryPayload,
};
use arkret_models_collaboration::events_payloads::*;
use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_collaboration::governance::erasure::ErasureReceipt;
use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InviteCancelPayload, InviteClaimPayload, InviteCreatePayload,
    InviteRevokePayload, InviteThirdPartyCreatePayload, MembershipPayload, RelationCreatePayload,
};
use arkret_models_collaboration::governance::moderation_appeal::{
    AppealClosePayload, AppealDecisionPayload, AppealReviewPayload, AppealSubmitPayload,
};
use arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload;
use arkret_models_collaboration::governance::realm_governance::{
    CapabilityDerived, RealmAliasPayload, RealmLinkPayload, RealmPolicyServerPayload,
};
use arkret_models_collaboration::governance::realm_lifecycle::{
    HistoryVisibilityPayload, ObjectLifecyclePayload, RealmArchivePayload, RealmDestroyPayload,
    RealmTombstonePayload,
};
use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
use arkret_models_collaboration::object_lifecycle::{
    SpaceObjectTombstonePayload, SpaceStateTransitionPayload,
};
use arkret_models_collaboration::objects::productivity::{
    AccountBlocklistPayload, PinAddPayload, PinRemovePayload, PinReorderPayload, RsvpSetPayload,
};
use arkret_models_collaboration::objects::read_receipts::ReadCursor;
use arkret_models_collaboration::sidecar_operations::SidecarContextAttachPayload;
use arkret_models_collaboration::sync_frames::snapshot::RangeCompletenessAttestation;
use arkret_models_crypto::MlsCommitPayload;
use arkret_models_identity::claim_presentation::AgentSelectorClaim;
use arkret_models_identity::delivery_binding::DevicePushRoutePayload;
use arkret_models_identity::identity_resolution::PrincipalResolutionUpdatePayload;
use arkret_models_identity::member_identity::MemberIdentityUpdatePayload;
use arkret_models_integration::applet_audit_payload::{
    AppletBridgeErrorPayload, AppletRegistrationPayload,
};
use arkret_wire::{Error, Event, Result, event_spec};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum MessageEventPayload {
    Create(MessageCreatePayload),
    Revise(MessageRevisePayload),
    Redact(MessageRedactPayload),
    ReactionAdd(ReactionPayload),
    ReactionRemove(ReactionPayload),
}

mod sealed {
    pub trait Sealed {}
}

/// Type-level binding from one active standard Event kind to its SDK payload.
pub trait EventSpec: sealed::Sealed + 'static {
    const KIND: arkret_wire::EventKind;
    const KIND_STR: &'static str;
    type Payload: Serialize + DeserializeOwned;

    fn validate_payload(_payload: &Self::Payload) -> Result<()> {
        Ok(())
    }
}

/// One SDK-owned type binding from a standard Event kind to a Rust payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventPayloadBinding {
    pub kind: arkret_wire::EventKind,
    pub payload_type: &'static str,
}

/// Phase-1 ratchet for active kinds whose dedicated SDK payload binding has
/// not landed yet. This number may only decrease; a new registry kind changes
/// the computed gap and fails the binding coverage test.
pub const EVENT_SPECS_WITHOUT_TYPED_BINDING_COUNT: usize = 0;

/// Active kinds whose dedicated Rust payload model has not landed yet.
///
/// Entries may only be removed. A newly registered kind is first caught by
/// [`EVENT_SPECS_WITHOUT_TYPED_BINDING_COUNT`] and requires an explicit type
/// and binding decision rather than silently joining this list.
pub const EVENT_KINDS_WITHOUT_RUST_PAYLOAD: &[arkret_wire::EventKind] = &[];

macro_rules! event_payload_accessors {
    ($($marker:ty => ($name:ident, $ty:ty $(, $validate:expr)?)),+ $(,)?) => {
        pub const EVENT_PAYLOAD_BINDINGS: &[EventPayloadBinding] = &[
            $(EventPayloadBinding {
                kind: <$marker>::KIND,
                payload_type: stringify!($ty),
            },)+
        ];

        $(
            impl sealed::Sealed for $marker {}

            impl EventSpec for $marker {
                const KIND: arkret_wire::EventKind = <$marker>::KIND;
                const KIND_STR: &'static str = <$marker>::KIND_STR;
                type Payload = $ty;

                fn validate_payload(payload: &Self::Payload) -> Result<()> {
                    let _ = payload;
                    $(($validate)(payload)?;)?
                    Ok(())
                }
            }
        )+

        /// Strongly typed, read-only payload projections for a wire [`Event`].
        pub trait EventPayloadExt {
            fn typed_payload<K: EventSpec>(&self) -> Result<K::Payload>;
            $(fn $name(&self) -> Result<$ty>;)+
            fn as_message_event_payload(&self) -> Result<MessageEventPayload>;
        }

        impl EventPayloadExt for Event {
            fn typed_payload<K: EventSpec>(&self) -> Result<K::Payload> {
                if self.kind != K::KIND {
                    return Err(Error::PayloadKindMismatch {
                        expected: K::KIND_STR,
                        actual: self.kind.as_str().to_owned(),
                    });
                }
                let payload = serde_json::from_value(Value::Object(
                    self.payload.clone().into_iter().collect(),
                ))
                .map_err(|source| Error::PayloadInvalid {
                    kind: K::KIND_STR,
                    reason: source.to_string(),
                })?;
                K::validate_payload(&payload).map_err(|error| Error::PayloadInvalid {
                    kind: K::KIND_STR,
                    reason: error.to_string(),
                })?;
                Ok(payload)
            }

            $(
                fn $name(&self) -> Result<$ty> {
                    self.typed_payload::<$marker>()
                }
            )+

            fn as_message_event_payload(&self) -> Result<MessageEventPayload> {
                match &self.kind {
                    arkret_wire::EventKind::MessageCreate => Ok(MessageEventPayload::Create(self.as_message_create()?)),
                    arkret_wire::EventKind::MessageRevise => Ok(MessageEventPayload::Revise(self.as_message_revise()?)),
                    arkret_wire::EventKind::MessageRedact => Ok(MessageEventPayload::Redact(self.as_message_redact()?)),
                    arkret_wire::EventKind::ReactionAdd => Ok(MessageEventPayload::ReactionAdd(self.as_reaction_add()?)),
                    arkret_wire::EventKind::ReactionRemove => Ok(MessageEventPayload::ReactionRemove(self.as_reaction_remove()?)),
                    _ => Err(Error::Protocol(format!(
                        "event is not a message timeline payload: {}",
                        self.kind.as_str()
                    ))),
                }
            }
        }
    };
}

event_payload_accessors! {
    event_spec::IdentityResolutionUpdate => (as_identity_resolution_update, PrincipalResolutionUpdatePayload),
    event_spec::RealmCreate => (as_realm_create, RealmCreatePayload, |payload: &RealmCreatePayload| payload.object.validate()),
    event_spec::RealmProfile => (as_realm_profile, RealmProfile),
    event_spec::RealmAlias => (as_realm_alias, RealmAliasPayload),
    event_spec::RealmUpgrade => (as_realm_upgrade, RealmUpgradeStatePayload),
    event_spec::RealmOrganization => (as_realm_organization, RealmOrganizationPayload),
    event_spec::RealmLink => (as_realm_link, RealmLinkPayload),
    event_spec::RealmPolicy => (as_realm_policy, StatePayload),
    event_spec::RealmJoinRule => (as_realm_join_rule, StatePayload),
    event_spec::RealmHistoryVisibility => (as_realm_history_visibility, HistoryVisibilityPayload),
    event_spec::RealmDiscovery => (as_realm_discovery, StatePayload),
    event_spec::RealmPreviewPolicy => (as_realm_preview_policy, PreviewPolicyPayload),
    event_spec::RealmSearchPolicy => (as_realm_search_policy, RealmSearchPolicyPayload),
    event_spec::RealmSetDefaultStrand => (as_realm_set_default_strand, RealmSetDefaultStrandPayload),
    event_spec::RealmNotary => (as_realm_notary, RealmNotaryPayload, RealmNotaryPayload::validate),
    event_spec::RealmDigestSuiteTransition => (as_realm_digest_suite_transition, RealmDigestSuiteTransitionPayload, RealmDigestSuiteTransitionPayload::validate),
    event_spec::RealmPolicyServer => (as_realm_policy_server, RealmPolicyServerPayload),
    event_spec::RealmPolicyBundle => (as_realm_policy_bundle, RealmPolicyBundlePayload),
    event_spec::RealmHistorySharingPolicy => (as_realm_history_sharing_policy, HistorySharingPolicyPayload),
    event_spec::RealmDeliveryBindingPolicy => (as_realm_delivery_binding_policy, RealmDeliveryBindingPolicyPayload),
    event_spec::RealmAssetPrivacyPolicy => (as_realm_asset_privacy_policy, StatePayload),
    event_spec::RealmReadReceiptPolicy => (as_realm_read_receipt_policy, ReadReceiptPolicyPayload),
    event_spec::RealmModerationPolicy => (as_realm_moderation_policy, StatePayload),
    event_spec::RealmPlaintextVisibleServices => (as_realm_plaintext_visible_services, PlaintextVisibleServicesPayload),
    event_spec::RealmMediaService => (as_realm_media_service, StatePayload),
    event_spec::RealmSchema => (as_realm_schema, StatePayload),
    event_spec::RealmInheritancePolicy => (as_realm_inheritance_policy, RealmInheritancePolicyPayload),
    event_spec::RealmArchive => (as_realm_archive, RealmArchivePayload),
    event_spec::RealmFreeze => (as_realm_freeze, RealmFreezePayload),
    event_spec::RealmTombstone => (as_realm_tombstone, RealmTombstonePayload),
    event_spec::RealmDestroy => (as_realm_destroy, RealmDestroyPayload),
    event_spec::CircleCreate => (as_circle_create, CircleCreatePayload),
    event_spec::SidecarCreate => (as_sidecar_create, SidecarCreatePayload),
    event_spec::SidecarContextAttach => (as_sidecar_context_attach, SidecarContextAttachPayload, SidecarContextAttachPayload::validate),
    event_spec::CircleUpdate => (as_circle_update, CirclePatchPayload),
    event_spec::CircleArchive => (as_circle_archive, ObjectLifecyclePayload),
    event_spec::CircleRestore => (as_circle_restore, ObjectLifecyclePayload),
    event_spec::CircleTombstone => (as_circle_tombstone, ObjectLifecyclePayload),
    event_spec::CircleMemberState => (as_circle_member_state, CircleMemberStatePayload),
    event_spec::CircleSealCommit => (as_circle_seal_commit, CircleSealCommitPayload),
    event_spec::OrganizationDiscovery => (as_organization_discovery, OrganizationDiscoveryStatePayload),
    event_spec::ActorDiscovery => (as_actor_discovery, ResourceDiscoveryStatePayload),
    event_spec::AppletDiscovery => (as_applet_discovery, ResourceDiscoveryStatePayload),
    event_spec::HandleDiscovery => (as_handle_discovery, ResourceDiscoveryStatePayload),
    event_spec::OrganizationModerationPolicy => (as_organization_moderation_policy, OrganizationModerationPolicyStatePayload),
    event_spec::IdentityDisclosurePolicy => (as_identity_disclosure_policy, IdentityDisclosurePolicyStatePayload),
    event_spec::IdentityDisclosureReceipt => (as_identity_disclosure_receipt, IdentityDisclosureReceiptStatePayload),
    event_spec::IdentityPresentationRequest => (as_identity_presentation_request, IdentityPresentationRequestStatePayload),
    event_spec::IdentityPresentationResponse => (as_identity_presentation_response, IdentityPresentationResponseStatePayload),
    event_spec::IdentityAccountabilityGrant => (as_identity_accountability_grant, AccountabilityGrantPayload),
    event_spec::SchemaDefine => (as_schema_define, SchemaDefineStatePayload),
    event_spec::SchemaUpdate => (as_schema_update, SchemaUpdateStatePayload),
    event_spec::PolicySet => (as_policy_set, PolicySetStatePayload),
    event_spec::PolicyRule => (as_policy_rule, PolicyRuleStatePayload),
    event_spec::PolicyAction => (as_policy_action, PolicyActionStatePayload),
    event_spec::ConflictRecovery => (as_state_conflict_recovery, StateConflictRecoveryPayload),
    event_spec::NotaryFaultEquivocation => (as_notary_fault_equivocation, NotaryFaultEquivocationPayload),
    event_spec::NotaryFaultCensorship => (as_notary_fault_censorship, NotaryFaultCensorshipPayload),
    event_spec::MemberState => (as_member_state, MembershipPayload),
    event_spec::MemberIdentityUpdate => (as_member_identity_update, MemberIdentityUpdatePayload),
    event_spec::MessageCreate => (as_message_create, MessageCreatePayload),
    event_spec::MessageRevise => (as_message_revise, MessageRevisePayload),
    event_spec::MessageRedact => (as_message_redact, MessageRedactPayload),
    event_spec::ReactionAdd => (as_reaction_add, ReactionPayload),
    event_spec::ReactionRemove => (as_reaction_remove, ReactionPayload),
    event_spec::StrandCreate => (as_strand_create, StrandCreatePayload),
    event_spec::StrandUpdate => (as_strand_update, StrandPatchPayload),
    event_spec::StrandArchive => (as_strand_archive, ObjectLifecyclePayload),
    event_spec::StrandRestore => (as_strand_restore, ObjectLifecyclePayload),
    event_spec::StrandStageSet => (as_strand_stage_set, StrandStageSetPayload),
    event_spec::StrandTracksUpdate => (as_strand_tracks_update, StrandPatchPayload),
    event_spec::StrandMove => (as_strand_move, StrandMovePayload),
    event_spec::StrandReorder => (as_strand_reorder, StrandReorderPayload),
    event_spec::StrandWatchSet => (as_strand_watch_set, StrandWatchSetPayload),
    event_spec::SpaceCreate => (as_space_create, SpaceCreatePayload),
    event_spec::SpaceUpdate => (as_space_update, SpacePatchPayload),
    event_spec::SpaceParent => (as_space_parent, SpaceParentPayload),
    event_spec::SpaceArchive => (as_space_archive, SpaceStateTransitionPayload),
    event_spec::SpaceRestore => (as_space_restore, SpaceStateTransitionPayload),
    event_spec::SpaceTombstone => (as_space_tombstone, SpaceObjectTombstonePayload),
    event_spec::AgentSidecarExchangeControl => (as_agent_sidecar_exchange_control, AgentSidecarExchangeControlPayload),
    event_spec::RsvpSet => (as_rsvp_set, RsvpSetPayload),
    event_spec::PinAdd => (as_pin_add, PinAddPayload),
    event_spec::PinRemove => (as_pin_remove, PinRemovePayload),
    event_spec::PinReorder => (as_pin_reorder, PinReorderPayload),
    event_spec::Redaction => (as_redaction, CrossObjectRedactionPayload),
    event_spec::MorphCreate => (as_morph_create, MorphCreatePayload),
    event_spec::MorphUpdate => (as_morph_update, MorphUpdatePayload, MorphUpdatePayload::validate),
    event_spec::MorphArchive => (as_morph_archive, ObjectLifecyclePayload),
    event_spec::MorphRestore => (as_morph_restore, ObjectLifecyclePayload),
    event_spec::MorphSchemaMigrate => (as_morph_schema_migrate, MorphSchemaMigratePayload),
    event_spec::MorphStageSet => (as_morph_stage_set, MorphStageSetPayload),
    event_spec::RelationCreate => (as_relation_create, RelationCreatePayload),
    event_spec::RelationUpdate => (as_relation_update, RelationUpdatePayload),
    event_spec::RelationTombstone => (as_relation_tombstone, RelationTombstonePayload),
    event_spec::ContainerMoveItem => (as_container_move_item, ContainerMoveItemPayload, ContainerMoveItemPayload::validate),
    event_spec::ContainerRebalance => (as_container_rebalance, ContainerRebalancePayload, ContainerRebalancePayload::validate),
    event_spec::ViewCreate => (as_view_create, ViewPayload),
    event_spec::ViewUpdate => (as_view_update, ViewPayload),
    event_spec::ViewReconcile => (as_view_reconcile, ViewReconcilePayload),
    event_spec::AgentKeyAuthorize => (as_agent_key_authorize, AgentKeyAuthorizePayload),
    event_spec::AgentKeyRevoke => (as_agent_key_revoke, AgentKeyRevokePayload),
    event_spec::AgentProvision => (as_agent_provision, AgentProvisionPayload, AgentProvisionPayload::validate),
    event_spec::AgentSelectorClaim => (as_agent_selector_claim, AgentSelectorClaim),
    event_spec::SelfAgentPause => (as_self_agent_pause, AgentPausePayload),
    event_spec::SelfAgentResume => (as_self_agent_resume, AgentResumePayload),
    event_spec::SelfAgentDeactivate => (as_self_agent_deactivate, AgentDeactivatePayload),
    event_spec::AgentDraftPropose => (as_agent_draft_propose, AgentDraftProposePayload),
    event_spec::AgentActionRequest => (as_agent_action_request, AgentActionRequestPayload),
    event_spec::AgentActionApprove => (as_agent_action_approve, AgentActionApprovePayload),
    event_spec::AgentActionReject => (as_agent_action_reject, AgentActionRejectPayload),
    event_spec::CapabilityGrant => (as_capability_grant, CapabilityGrantPayload),
    event_spec::CapabilityRevoke => (as_capability_revoke, CapabilityRevokePayload),
    event_spec::CapabilityDerived => (as_capability_derived, CapabilityDerived),
    event_spec::ConsentGrant => (as_consent_grant, ConsentGrantPayload),
    event_spec::ConsentRevoke => (as_consent_revoke, ConsentRevokePayload),
    event_spec::ContactRequested => (as_contact_requested, ContactRequestedPayload),
    event_spec::ContactAccepted => (as_contact_accepted, ContactAcceptedPayload),
    event_spec::ContactRejected => (as_contact_rejected, ContactRejectedPayload),
    event_spec::ContactTombstone => (as_contact_tombstoned, ContactTombstonedPayload),
    event_spec::ContactScopeUpdate => (as_contact_scope_update, ContactScopeUpdatePayload),
    event_spec::DirectConversationBound => (as_direct_conversation_bound, DirectConversationBoundPayload),
    event_spec::DirectConversationMlsGenerationActivate => (as_direct_conversation_mls_generation_activate, DirectConversationMlsGenerationActivatePayload),
    event_spec::AccountBlocklist => (as_account_blocklist, AccountBlocklistPayload),
    event_spec::AccountDataSet => (as_account_data_set, AccountDataSetPayload),
    event_spec::ProfileCreate => (as_profile_create, ActorProfileCreatePayload),
    event_spec::ProfileUpdate => (as_profile_update, ActorProfileUpdatePayload),
    event_spec::ProfileRealmOverride => (as_profile_realm_override, ProfileRealmOverridePayload),
    event_spec::DeviceAuthorize => (as_device_authorize, DeviceAuthorizePayload, |payload: &DeviceAuthorizePayload| payload.validate_wire_constraints().map_err(|reason| Error::Protocol(reason.to_owned()))),
    event_spec::DeviceReanchor => (as_device_reanchor, DeviceReanchorPayload, |payload: &DeviceReanchorPayload| payload.validate().map_err(|reason| Error::Protocol(reason.to_owned()))),
    event_spec::DeviceRevoke => (as_device_revoke, DeviceRevokePayload),
    event_spec::DeviceListUpdate => (as_device_list_update, DeviceListUpdatePayload),
    event_spec::KeyBackupActiveSeries => (as_key_backup_active_series, KeyBackupActiveSeriesPayload),
    event_spec::DevicePushRoute => (as_device_push_route, DevicePushRoutePayload),
    event_spec::MlsProposal => (as_mls_proposal, MlsProposalPayload),
    event_spec::MlsGenesis => (as_mls_genesis, MlsGenesisPayload),
    event_spec::MlsCommit => (as_mls_commit, MlsCommitPayload),
    event_spec::MlsCommitFailed => (as_mls_commit_failed, MlsCommitFailedPayload),
    event_spec::MlsWelcome => (as_mls_welcome, MlsWelcomePayload),
    event_spec::MlsKeypackage => (as_mls_keypackage, MlsKeypackagePayload),
    event_spec::RealmKeyShare => (as_realm_key_share, RealmKeySharePayload),
    event_spec::RealmKeyWithheld => (as_realm_key_withheld, RealmKeyWithheldPayload),
    event_spec::RealmKeyShareAudit => (as_realm_key_share_audit, RealmKeyShareAuditPayload),
    event_spec::AuditAccessed => (as_audit_accessed, AuditAccessedPayload),
    event_spec::AuditAppletBindingCreate => (as_audit_applet_binding_create, AuditAppletBindingCreatePayload),
    event_spec::AuditAppletBindingState => (as_audit_applet_binding_state, AuditAppletBindingStatePayload),
    event_spec::AuditSessionRequest => (as_audit_session_request, AuditSessionRequestPayload),
    event_spec::AuditSessionAuthorize => (as_audit_session_authorize, AuditSessionAuthorizePayload),
    event_spec::AuditSessionNotice => (as_audit_session_notice, AuditSessionNoticePayload),
    event_spec::AuditRelease => (as_audit_release, AuditReleasePayload),
    event_spec::AuditSessionClose => (as_audit_session_close, AuditSessionClosePayload),
    event_spec::AuditRywReceipt => (as_audit_ryw_receipt, AuditPayload),
    event_spec::AuditErasureReceipt => (as_audit_erasure_receipt, ErasureReceipt),
    event_spec::AttestationRangeCompleteness => (as_range_completeness_attestation, RangeCompletenessAttestation),
    event_spec::SelfModerationReport => (as_self_moderation_report, ModerationReportPayload),
    event_spec::ModerationFrankingProof => (as_moderation_franking_proof, FrankingProof),
    event_spec::ModerationDecision => (as_moderation_decision, ModerationDecisionPayload),
    event_spec::ModerationDecisionLift => (as_moderation_decision_lift, ModerationDecisionLiftPayload),
    event_spec::ModerationAppealSubmit => (as_moderation_appeal_submit, AppealSubmitPayload),
    event_spec::ModerationAppealReview => (as_moderation_appeal_review, AppealReviewPayload),
    event_spec::ModerationAppealDecision => (as_moderation_appeal_decision, AppealDecisionPayload),
    event_spec::ModerationAppealClose => (as_moderation_appeal_close, AppealClosePayload),
    event_spec::ReadCursorAdvance => (as_read_cursor_advance, ReadCursor),
    event_spec::InviteCreate => (as_invite_create, InviteCreatePayload),
    event_spec::InviteCancel => (as_invite_cancel, InviteCancelPayload),
    event_spec::InviteAccept => (as_invite_accept, InviteAcceptPayload),
    event_spec::InviteThirdParty => (as_invite_third_party, InviteThirdPartyCreatePayload),
    event_spec::InviteClaim => (as_invite_claim, InviteClaimPayload),
    event_spec::InviteRevoke => (as_invite_revoke, InviteRevokePayload),
    event_spec::AppletBridgeError => (as_applet_bridge_error, AppletBridgeErrorPayload),
    event_spec::AppletRegistration => (as_applet_registration, AppletRegistrationPayload),
    event_spec::MimiRoomBinding => (as_mimi_room_binding, MimiRoomBindingPayload),
    event_spec::CallCreate => (as_call_create, CallCreatePayload),
    event_spec::CallState => (as_call_state, CallStatePayload),
    event_spec::CallRecordingStart => (as_call_recording_start, CallRecordingStartPayload),
    event_spec::CallSummary => (as_call_summary, CallSummaryPayload),
    event_spec::SovereignDidPolicy => (as_sovereign_did_policy, SovereignDidPolicyStatePayload),
    event_spec::RealmOwnerTransfer => (as_realm_owner_transfer, RealmOwnerTransferPayload),
    event_spec::RealmAuthorityReset => (as_realm_authority_reset, RealmAuthorityResetPayload),
    event_spec::RealmAuthorityBasisUpdate => (as_realm_authority_basis_update, RealmAuthorityBasisUpdatePayload),
    event_spec::CapabilityRelinquish => (as_capability_relinquish, CapabilityRelinquishPayload),
}

/// Marker-checked payload projection for reducer-resolved state records.
///
/// The resolved record remains an erased storage/projection boundary, while
/// domain readers must name the exact Event marker before accessing content.
pub trait ResolvedStateEventPayloadExt {
    fn typed_payload<K: EventSpec>(&self) -> Result<K::Payload>;
}

impl ResolvedStateEventPayloadExt for arkret_models_collaboration::ResolvedStateEvent {
    fn typed_payload<K: EventSpec>(&self) -> Result<K::Payload> {
        if self.kind != K::KIND {
            return Err(Error::PayloadKindMismatch {
                expected: K::KIND_STR,
                actual: self.kind.as_str().to_owned(),
            });
        }
        let payload = serde_json::from_value(self.content.clone()).map_err(|source| {
            Error::PayloadInvalid {
                kind: K::KIND_STR,
                reason: source.to_string(),
            }
        })?;
        K::validate_payload(&payload).map_err(|error| Error::PayloadInvalid {
            kind: K::KIND_STR,
            reason: error.to_string(),
        })?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_wire::{
        DidCoreId, EventId, EventKind, EventRequirements, Hlc, MessageId, RealmId, ScopeRef,
        StrandId,
    };
    use serde_json::json;

    use super::*;

    fn event_id(seed: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
    }

    fn realm() -> RealmId {
        RealmId::from_event_id(&event_id(0x65))
    }

    fn scope() -> ScopeRef {
        ScopeRef::Realm { realm_id: realm() }
    }

    fn alice() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn base_event() -> Event {
        let strand_id = StrandId::from_event_id(&event_id(0x6c));
        Event {
            event_id: event_id(0xa0),
            kind: EventKind::MessageCreate,
            realm_id: realm(),
            scope_ref: scope(),
            actor_id: alice(),
            principal_server_id: alice(),
            actor_seq: 1,
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            hlc: Some(Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()),
            prev_refs: Vec::new(),
            refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            redacts: None,
            payload: serde_json::from_value(json!({
                "strand_id": strand_id,
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }))
            .unwrap(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            causal_refs: Vec::new(),
            proofs: Vec::new(),
        }
    }

    #[test]
    fn payload_accessor_parses_plain_message_payload() {
        let event = base_event();
        let payload = event.as_message_create().unwrap();

        assert_eq!(payload.strand_id, StrandId::from_event_id(&event_id(0x6c)));
        assert_eq!(payload.track_name, "discussion");
        assert_eq!(
            payload
                .content
                .as_ref()
                .map(|content| content.body.as_str()),
            Some("hello")
        );
        assert!(payload.encrypted_content.is_none());
    }

    #[test]
    fn message_event_payload_classifies_message_and_reaction_kinds() {
        let mut revise = base_event();
        revise.kind = EventKind::MessageRevise;
        let message_id = MessageId::from_event_id(&event_id(1));
        revise.payload = serde_json::from_value(json!({
            "message_id": message_id,
            "content": {"kind": "ak.content.text", "body": "hello revised"},
            "reason": "typo"
        }))
        .unwrap();
        assert!(matches!(
            revise.as_message_event_payload().unwrap(),
            MessageEventPayload::Revise(_)
        ));

        let mut reaction = base_event();
        reaction.kind = EventKind::ReactionAdd;
        let target_ref = event_id(0x99);
        reaction.payload = serde_json::from_value(json!({
            "target_ref": target_ref,
            "key": "+1"
        }))
        .unwrap();

        match reaction.as_message_event_payload().unwrap() {
            MessageEventPayload::ReactionAdd(payload) => assert_eq!(payload.key, "+1"),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn payload_accessor_parses_encrypted_message_payload() {
        let mut event = base_event();
        let strand_id = StrandId::from_event_id(&event_id(0x6c));
        let realm_id = realm();
        let scope_digest = arkret_models_crypto::encrypted_envelope_scope_digest(
            &ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            &realm_id,
        )
        .unwrap();
        let group_state_ref = event_id(4);
        event.payload = serde_json::from_value(json!({
            "strand_id": strand_id,
            "track_name": "discussion",
            "encrypted_content": {
                "scheme": "mls_rfc9420",
                "version": "1.0",
                "group_id": "AA",
                "epoch": 1,
                "content_type": "application/vnd.arkret.message+json",
                "ciphertext": "b3BhcXVl",
                "aad_visibility_event_id_kind": "hidden",
                "aad": {
                    "realm_id": realm_id,
                    "scope_digest": scope_digest,
                    "event_kind": event_spec::MessageCreate::KIND_STR
                },
                "key_ref": {
                    "algorithm": "MLS",
                    "group_state_ref": group_state_ref
                },
                "payload_digest": format!("sha256:{}", "a".repeat(64)),
                "aad_digest": format!("sha256:{}", "b".repeat(64))
            }
        }))
        .unwrap();

        let payload = event.typed_payload::<event_spec::MessageCreate>().unwrap();
        assert!(payload.content.is_none());
        assert_eq!(
            payload
                .encrypted_content
                .as_ref()
                .map(|content| content.ciphertext.as_str()),
            Some("b3BhcXVl")
        );
    }

    #[test]
    fn typed_payload_rejects_kind_mismatch() {
        let error = base_event()
            .typed_payload::<event_spec::StrandCreate>()
            .unwrap_err();

        assert!(matches!(
            error,
            Error::PayloadKindMismatch {
                expected: event_spec::StrandCreate::KIND_STR,
                actual,
            } if actual == event_spec::MessageCreate::KIND_STR
        ));
    }

    #[test]
    fn payload_accessor_rejects_missing_required_field() {
        let mut event = base_event();
        let strand_id = StrandId::from_event_id(&event_id(0x6c));
        event.payload = serde_json::from_value(json!({
            "strand_id": strand_id,
            "content": {"kind": "ak.content.text", "body": "hello"}
        }))
        .unwrap();

        let error = event
            .typed_payload::<event_spec::MessageCreate>()
            .unwrap_err();
        assert!(matches!(
            error,
            Error::PayloadInvalid {
                kind: event_spec::MessageCreate::KIND_STR,
                ..
            }
        ));
    }

    #[test]
    fn payload_accessor_does_not_change_digest_input() {
        let event = base_event();
        let digest = event.event_digest().unwrap();

        let _payload = event.as_message_create().unwrap();

        assert_eq!(event.event_digest().unwrap(), digest);
        assert_eq!(event.payload["content"]["body"], "hello");
    }

    #[test]
    fn event_payload_binding_gap_is_an_explicit_decreasing_ratchet() {
        let kinds = EVENT_PAYLOAD_BINDINGS
            .iter()
            .map(|binding| binding.kind.clone())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(kinds.len(), EVENT_PAYLOAD_BINDINGS.len());
        assert_eq!(
            arkret_wire::EVENT_KIND_COUNT - EVENT_PAYLOAD_BINDINGS.len(),
            EVENT_SPECS_WITHOUT_TYPED_BINDING_COUNT,
            "a standard kind was added or a payload binding changed without updating the explicit gap ratchet"
        );
        let mut payload_type_by_schema_ref = BTreeMap::new();
        for binding in EVENT_PAYLOAD_BINDINGS {
            let descriptor = binding
                .kind
                .descriptor()
                .unwrap_or_else(|| panic!("binding uses unknown kind {}", binding.kind));
            let schema_ref = descriptor.payload_schema_ref.unwrap_or_else(|| {
                panic!(
                    "binding kind {} has no explicit payload schema ref",
                    binding.kind
                )
            });
            if let Some(existing) =
                payload_type_by_schema_ref.insert(schema_ref, binding.payload_type)
            {
                assert_eq!(
                    existing, binding.payload_type,
                    "kinds sharing payload schema ref {schema_ref} use different Rust payload types"
                );
            }
        }

        let missing_types = EVENT_KINDS_WITHOUT_RUST_PAYLOAD
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(missing_types.len(), EVENT_KINDS_WITHOUT_RUST_PAYLOAD.len());
        assert!(
            missing_types.is_disjoint(&kinds),
            "a kind with a typed binding remains in EVENT_KINDS_WITHOUT_RUST_PAYLOAD"
        );
        for kind in missing_types {
            assert!(
                kind.descriptor()
                    .is_some_and(|descriptor| descriptor.payload_schema_ref.is_some()),
                "missing-payload ratchet contains unknown or unbound kind {kind}"
            );
        }
    }
}
