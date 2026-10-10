//! Typed read-only projections over the payload-agnostic wire [`Event`].

use arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload;
use arkret_models_collaboration::contact_operations::ContactScopeUpdatePayload;
use arkret_models_collaboration::events_payloads::agent::{
    AgentActionApprovePayload, AgentActionRejectPayload, AgentActionRequestPayload,
    AgentDeactivatePayload, AgentDraftProposePayload, AgentKeyAuthorizePayload,
    AgentKeyRevokePayload, AgentPausePayload, AgentProvisionPayload, AgentResumePayload,
};
use arkret_models_collaboration::events_payloads::audit::AuditAccessedPayload;
use arkret_models_collaboration::events_payloads::call::{
    CallCreatePayload, CallRecordingStartPayload, CallStatePayload,
};
use arkret_models_collaboration::events_payloads::*;
use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_collaboration::governance::erasure::ErasureReceipt;
use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InviteCancelPayload, InviteClaimPayload, InviteCreatePayload,
    InviteRevokePayload, InviteThirdPartyCreatePayload, MembershipPayload,
};
use arkret_models_collaboration::governance::operation_wire::PolicySetStatePayload;
use arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload;
use arkret_models_collaboration::governance::realm_governance::{
    RealmAliasPayload, RealmLinkPayload,
};
use arkret_models_collaboration::governance::realm_lifecycle::{
    CircleHistoryAccessPayload, HistoryAccessPayload, ObjectLifecyclePayload, RealmArchivePayload,
    RealmAssetPrivacyPolicyPayload, RealmDestroyPayload, RealmDiscoveryPayload,
    RealmJoinRulePayload, RealmSchemaPayload, RealmTombstonePayload,
};
use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
use arkret_models_collaboration::object_lifecycle::{
    SpaceObjectTombstonePayload, SpaceStateTransitionPayload,
};
use arkret_models_collaboration::objects::productivity::{
    PinAddPayload, PinRemovePayload, PinReorderPayload, RsvpSetPayload,
};
use arkret_models_collaboration::objects::read_receipts::ReadCursor;
use arkret_models_crypto::MlsCommitPayload;
use arkret_models_identity::device_push_route::DevicePushRoutePayload;
use arkret_models_identity::identity_resolution::PrincipalResolutionUpdatePayload;
use arkret_models_identity::member_identity::MemberIdentityUpdatePayload;
use arkret_models_integration::applet::{
    AppletManagedActorProvisionPayload, AppletRegistrationPayload,
};
use arkret_models_integration::applet_audit_payload::AppletBridgeErrorPayload;
use arkret_wire::{Event, Result, WireError, event_spec};
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

        /// Validate an erased standard Event payload through its generated
        /// kind-to-Rust-type dispatch. The wire payload is never interpreted
        /// through a bundled JSON Schema at runtime.
        pub fn validate_event_payload(
            kind: &arkret_wire::EventKind,
            payload: &Value,
        ) -> Result<()> {
            arkret_wire::forbidden_wire::validate_event_payload_forbidden_fields(kind, payload)?;
            $(
                if *kind == <$marker>::KIND {
                    let typed: <$marker as EventSpec>::Payload =
                        serde_json::from_value(payload.clone()).map_err(|source| {
                            WireError::PayloadInvalid {
                                kind: <$marker>::KIND_STR,
                                reason: source.to_string(),
                            }
                        })?;
                    <$marker as EventSpec>::validate_payload(&typed).map_err(|error| {
                        WireError::PayloadInvalid {
                            kind: <$marker>::KIND_STR,
                            reason: error.to_string(),
                        }
                    })?;
                    return Ok(());
                }
            )+
            Err(WireError::Protocol(format!(
                "event kind {} has no typed payload binding",
                kind.as_str()
            )))
        }

        /// Strongly typed, read-only payload projections for a wire [`Event`].
        pub trait EventPayloadExt {
            fn typed_payload<K: EventSpec>(&self) -> Result<K::Payload>;
            $(fn $name(&self) -> Result<$ty>;)+
            fn as_message_event_payload(&self) -> Result<MessageEventPayload>;
        }

        impl EventPayloadExt for Event {
            fn typed_payload<K: EventSpec>(&self) -> Result<K::Payload> {
                if self.kind != K::KIND {
                    return Err(WireError::PayloadKindMismatch {
                        expected: K::KIND_STR,
                        actual: self.kind.as_str().to_owned(),
                    });
                }
                let payload = serde_json::from_value(Value::Object(
                    self.payload.clone().into_iter().collect(),
                ))
                .map_err(|source| WireError::PayloadInvalid {
                    kind: K::KIND_STR,
                    reason: source.to_string(),
                })?;
                K::validate_payload(&payload).map_err(|error| WireError::PayloadInvalid {
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
                    _ => Err(WireError::Protocol(format!(
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
    event_spec::RealmGovernanceStationChange => (as_realm_governance_station_change, RealmGovernanceStationChangePayload),
    event_spec::RealmAuthorityReset => (as_realm_authority_reset, RealmAuthorityResetPayload),
    event_spec::DirectConversationBound => (as_direct_conversation_bound, DirectConversationBoundPayload, DirectConversationBoundPayload::validate_shape),
    event_spec::RealmProfile => (as_realm_profile, RealmProfile),
    event_spec::RealmAlias => (as_realm_alias, RealmAliasPayload),
    event_spec::RealmOrganization => (as_realm_organization, RealmOrganizationPayload),
    event_spec::RealmLink => (as_realm_link, RealmLinkPayload),
    event_spec::RealmJoinRule => (as_realm_join_rule, RealmJoinRulePayload),
    event_spec::RealmHistoryAccess => (as_realm_history_access, HistoryAccessPayload, HistoryAccessPayload::validate),
    event_spec::RealmDiscovery => (as_realm_discovery, RealmDiscoveryPayload),
    event_spec::RealmPreviewPolicy => (as_realm_preview_policy, PreviewPolicyPayload),
    event_spec::RealmSearchPolicy => (as_realm_search_policy, RealmSearchPolicyPayload),
    event_spec::RealmSetDefaultStrand => (as_realm_set_default_strand, RealmSetDefaultStrandPayload),
    event_spec::RealmPolicyBundle => (as_realm_policy_bundle, RealmPolicyBundlePayload),
    event_spec::RealmAssetPrivacyPolicy => (as_realm_asset_privacy_policy, RealmAssetPrivacyPolicyPayload),
    event_spec::RealmReadReceiptPolicy => (as_realm_read_receipt_policy, ReadReceiptPolicyPayload, ReadReceiptPolicyPayload::validate),
    event_spec::RealmPlaintextVisibleServices => (as_realm_plaintext_visible_services, PlaintextVisibleServicesPayload),
    event_spec::RealmMediaService => (as_realm_media_service, RealmMediaServicePayload),
    event_spec::RealmSchema => (as_realm_schema, RealmSchemaPayload),
    event_spec::RealmArchive => (as_realm_archive, RealmArchivePayload),
    event_spec::RealmRestore => (as_realm_restore, RealmArchivePayload),
    event_spec::RealmFreeze => (as_realm_freeze, RealmFreezePayload),
    event_spec::RealmUnfreeze => (as_realm_unfreeze, RealmFreezePayload),
    event_spec::RealmTombstone => (as_realm_tombstone, RealmTombstonePayload),
    event_spec::RealmDestroy => (as_realm_destroy, RealmDestroyPayload),
    event_spec::CircleCreate => (as_circle_create, CircleCreatePayload),
    event_spec::SidecarCreate => (as_sidecar_create, SidecarCreatePayload),
    event_spec::SidecarContextAttach => (as_sidecar_context_attach, SidecarContextAttachPayload, SidecarContextAttachPayload::validate),
    event_spec::AgentSidecarExchangeControl => (as_agent_sidecar_exchange_control, AgentSidecarExchangeControlPayload),
    event_spec::CircleUpdate => (as_circle_update, CirclePatchPayload),
    event_spec::CircleHistoryAccess => (as_circle_history_access, CircleHistoryAccessPayload, CircleHistoryAccessPayload::validate),
    event_spec::CircleArchive => (as_circle_archive, ObjectLifecyclePayload),
    event_spec::CircleRestore => (as_circle_restore, ObjectLifecyclePayload),
    event_spec::CircleTombstone => (as_circle_tombstone, ObjectLifecyclePayload),
    event_spec::CircleMemberState => (as_circle_member_state, CircleMemberStatePayload, CircleMemberStatePayload::validate),
    event_spec::IdentityAccountabilityGrant => (as_identity_accountability_grant, AccountabilityGrantPayload),
    event_spec::MemberState => (as_member_state, MembershipPayload),
    event_spec::MemberIdentityUpdate => (as_member_identity_update, MemberIdentityUpdatePayload),
    event_spec::MessageCreate => (as_message_create, MessageCreatePayload, MessageCreatePayload::validate_poll_response_heads),
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
    event_spec::AgentInteractionSet => (as_agent_interaction_set, AgentInteractionSetPayload),
    event_spec::StrandWatchSet => (as_strand_watch_set, StrandWatchSetPayload),
    event_spec::SpaceCreate => (as_space_create, SpaceCreatePayload),
    event_spec::SpaceUpdate => (as_space_update, SpacePatchPayload, SpacePatchPayload::validate),
    event_spec::SpaceParent => (as_space_parent, SpaceParentPayload),
    event_spec::SpaceArchive => (as_space_archive, SpaceStateTransitionPayload),
    event_spec::SpaceRestore => (as_space_restore, SpaceStateTransitionPayload),
    event_spec::SpaceTombstone => (as_space_tombstone, SpaceObjectTombstonePayload),
    event_spec::RsvpSet => (as_rsvp_set, RsvpSetPayload),
    event_spec::PinAdd => (as_pin_add, PinAddPayload),
    event_spec::PinRemove => (as_pin_remove, PinRemovePayload),
    event_spec::PinReorder => (as_pin_reorder, PinReorderPayload),
    event_spec::Redaction => (as_redaction, CrossObjectRedactionPayload),
    event_spec::MorphCreate => (as_morph_create, MorphCreatePayload),
    event_spec::MorphUpdate => (as_morph_update, MorphUpdatePayload, MorphUpdatePayload::validate),
    event_spec::MorphArchive => (as_morph_archive, ObjectLifecyclePayload),
    event_spec::MorphRestore => (as_morph_restore, ObjectLifecyclePayload),
    event_spec::MorphStageSet => (as_morph_stage_set, MorphStageSetPayload),
    event_spec::RelationCreate => (as_relation_create, RelationCreatePayload),
    event_spec::RelationUpdate => (as_relation_update, RelationUpdatePayload),
    event_spec::RelationTombstone => (as_relation_tombstone, RelationTombstonePayload),
    event_spec::ViewCreate => (as_view_create, ViewCreatePayload, ViewCreatePayload::validate),
    event_spec::ViewUpdate => (as_view_update, ViewUpdatePayload, ViewUpdatePayload::validate),
    event_spec::ViewReconcile => (as_view_reconcile, ViewReconcilePayload, ViewReconcilePayload::validate),
    event_spec::AgentKeyAuthorize => (as_agent_key_authorize, AgentKeyAuthorizePayload),
    event_spec::AgentKeyRevoke => (as_agent_key_revoke, AgentKeyRevokePayload),
    event_spec::AgentProvision => (as_agent_provision, AgentProvisionPayload, AgentProvisionPayload::validate),
    event_spec::SelfAgentPause => (as_self_agent_pause, AgentPausePayload),
    event_spec::SelfAgentResume => (as_self_agent_resume, AgentResumePayload),
    event_spec::SelfAgentDeactivate => (as_self_agent_deactivate, AgentDeactivatePayload),
    event_spec::AgentDraftPropose => (as_agent_draft_propose, AgentDraftProposePayload),
    event_spec::AgentActionRequest => (as_agent_action_request, AgentActionRequestPayload),
    event_spec::AgentActionApprove => (as_agent_action_approve, AgentActionApprovePayload),
    event_spec::AgentActionReject => (as_agent_action_reject, AgentActionRejectPayload),
    event_spec::CapabilityGrant => (as_capability_grant, CapabilityGrantPayload),
    event_spec::CapabilityRevoke => (as_capability_revoke, CapabilityRevokePayload),
    event_spec::ConsentGrant => (as_consent_grant, ConsentGrantPayload),
    event_spec::ConsentRevoke => (as_consent_revoke, ConsentRevokePayload),
    event_spec::ContactRequested => (as_contact_requested, ContactRequestedPayload),
    event_spec::ContactAccepted => (as_contact_accepted, ContactAcceptedPayload),
    event_spec::ContactRejected => (as_contact_rejected, ContactRejectedPayload),
    event_spec::ContactTombstone => (as_contact_tombstoned, ContactTombstonedPayload),
    event_spec::ContactScopeUpdate => (as_contact_scope_update, ContactScopeUpdatePayload),
    event_spec::AccountDataSet => (as_account_data_set, AccountDataSetPayload),
    event_spec::ProfileCreate => (as_profile_create, ActorProfileCreatePayload),
    event_spec::ProfileUpdate => (as_profile_update, ActorProfileUpdatePayload),
    event_spec::ProfileRealmOverride => (as_profile_realm_override, ProfileRealmOverridePayload),
    event_spec::KeyBackupActiveSeries => (as_key_backup_active_series, KeyBackupActiveSeries),
    event_spec::DeviceAuthorize => (as_device_authorize, DeviceAuthorizePayload, |payload: &DeviceAuthorizePayload| payload.validate_wire_constraints().map_err(|reason| WireError::Protocol(reason.to_owned()))),
    event_spec::DeviceReanchor => (as_device_reanchor, DeviceReanchorPayload, DeviceReanchorPayload::validate),
    event_spec::DeviceRevoke => (as_device_revoke, DeviceRevokePayload, DeviceRevokePayload::validate),
    event_spec::DevicePushRoute => (as_device_push_route, DevicePushRoutePayload),
    event_spec::MlsGenesis => (as_mls_genesis, MlsGenesisPayload, MlsGenesisPayload::validate),
    event_spec::MlsCommit => (as_mls_commit, MlsCommitPayload, MlsCommitPayload::validate),
    event_spec::AuditAccessed => (as_audit_accessed, AuditAccessedPayload),
    event_spec::AuditErasureReceipt => (as_audit_erasure_receipt, ErasureReceipt),
    event_spec::SelfModerationReport => (as_self_moderation_report, ModerationReportPayload),
    event_spec::ModerationFrankingProof => (as_moderation_franking_proof, FrankingProof),
    event_spec::ModerationDecision => (as_moderation_decision, ModerationDecisionPayload),
    event_spec::ModerationDecisionLift => (as_moderation_decision_lift, ModerationDecisionLiftPayload),
    event_spec::ReadCursorAdvance => (as_read_cursor_advance, ReadCursor),
    event_spec::InviteCreate => (as_invite_create, InviteCreatePayload),
    event_spec::InviteCancel => (as_invite_cancel, InviteCancelPayload),
    event_spec::InviteAccept => (as_invite_accept, InviteAcceptPayload, InviteAcceptPayload::validate),
    event_spec::InviteThirdParty => (as_invite_third_party, InviteThirdPartyCreatePayload),
    event_spec::InviteClaim => (as_invite_claim, InviteClaimPayload),
    event_spec::InviteRevoke => (as_invite_revoke, InviteRevokePayload, InviteRevokePayload::validate),
    event_spec::AppletBridgeError => (as_applet_bridge_error, AppletBridgeErrorPayload),
    event_spec::AppletRegistration => (as_applet_registration, AppletRegistrationPayload),
    event_spec::AppletManagedActorProvision => (as_applet_managed_actor_provision, AppletManagedActorProvisionPayload, AppletManagedActorProvisionPayload::validate),
    event_spec::MimiRoomBinding => (as_mimi_room_binding, MimiRoomBindingPayload),
    event_spec::CallCreate => (as_call_create, CallCreatePayload),
    event_spec::CallState => (as_call_state, CallStatePayload),
    event_spec::CallRecordingStart => (as_call_recording_start, CallRecordingStartPayload),
    event_spec::RealmOwnerTransfer => (as_realm_owner_transfer, RealmOwnerTransferPayload),
    event_spec::CapabilityRelinquish => (as_capability_relinquish, CapabilityRelinquishPayload),
    event_spec::PolicySet => (as_policy_set, PolicySetStatePayload, PolicySetStatePayload::validate),
    event_spec::PolicyAction => (as_policy_action, PolicyActionStatePayload, PolicyActionStatePayload::validate),
    event_spec::AppletDiscovery => (as_applet_discovery, AppletDiscoveryStatePayload, AppletDiscoveryStatePayload::validate),
    event_spec::OrganizationModerationPolicy => (as_organization_moderation_policy, OrganizationModerationPolicyStatePayload, |payload: &OrganizationModerationPolicyStatePayload| payload.value.validate()),
    event_spec::SchemaDefine => (as_schema_define, SchemaDefineStatePayload, SchemaDefineStatePayload::validate),
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidCoreId, EventId, EventKind, MessageId, RealmId, ScopeRef, StrandId};
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
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(alice(), alice())),
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            semantic_refs: Vec::new(),
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
            producer_proof: None,
        }
    }

    #[test]
    fn view_payload_accessors_enforce_their_distinct_write_shapes() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../arkret-spec/spec/v1/artifacts/fixtures/view-write-contract-fixture.json"
        ))
        .unwrap();
        let instance = |name: &str| {
            fixture["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == name)
                .unwrap()["instance"]
                .clone()
        };
        let mut event = base_event();
        event.kind = EventKind::ViewCreate;
        event.payload = serde_json::from_value(json!({"definition": {}})).unwrap();
        assert!(event.as_view_create().is_err());
        event.payload =
            serde_json::from_value(instance("create_payload_accepts_the_author_definition"))
                .unwrap();
        assert!(event.as_view_create().is_ok());

        event.kind = EventKind::ViewUpdate;
        assert!(event.as_view_update().is_err());
        event.payload = serde_json::from_value(json!({
            "view_id": "ak:view:AaiFHUI8GObKlPqeNvnl4E37L9moM-J0DjA4_UN9FvhR",
            "patch": {"title": {"$op": "set", "value": "Updated"}}
        }))
        .unwrap();
        assert!(event.as_view_update().is_ok());

        event.kind = EventKind::ViewReconcile;
        assert!(event.as_view_reconcile().is_err());
        event.payload =
            serde_json::from_value(instance("reconcile_payload_accepts_the_author_definition"))
                .unwrap();
        assert!(event.as_view_reconcile().is_ok());
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
        let group_state_ref = event_id(4);
        event.payload = serde_json::from_value(json!({
            "strand_id": strand_id,
            "track_name": "discussion",
            "encrypted_content": {
                "version": "1.0",
                "content_type": "application/vnd.arkret.message+json",
                "encryption_context": {
                    "epoch": 1,
                    "group_state_ref": group_state_ref
                },
                "ciphertext": "b3BhcXVl",
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
            WireError::PayloadKindMismatch {
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
            WireError::PayloadInvalid {
                kind: event_spec::MessageCreate::KIND_STR,
                ..
            }
        ));
    }

    #[test]
    fn payload_accessor_does_not_change_digest_input() {
        let event = base_event();
        let digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();

        let _payload = event.as_message_create().unwrap();

        assert_eq!(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            digest
        );
        assert_eq!(event.payload["content"]["body"], "hello");
    }

    fn device_authorize_payload_value() -> Value {
        json!({
            "device_id": "ak:device:0198ff00-0000-7000-8000-000000000001",
            "device_public_key_did": "did:key:z6MkfixtureDeviceKey",
            "hpke_key": "z6LSfixtureHpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1"],
            "device_key_algorithm": "Ed25519",
            "authorized_by": "ak:did_core:webvh:z6mkfixture:alice.example",
            "authorized_generation_ref": 1,
            "not_before": "2026-04-26T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "cGVuZGluZw"
        })
    }

    #[test]
    fn device_authorize_binds_its_typed_payload() {
        let mut event = base_event();
        event.kind = EventKind::DeviceAuthorize;
        event.payload = serde_json::from_value(device_authorize_payload_value()).unwrap();

        let payload = event.as_device_authorize().unwrap();
        assert_eq!(
            payload.device_id.as_str(),
            "ak:device:0198ff00-0000-7000-8000-000000000001"
        );
        assert_eq!(
            payload.authorization_binding_kind,
            DeviceAuthorizationBindingKind::RegistrationAnchor
        );
        assert!(payload.pairing_challenge_transcript_digest.is_none());
        validate_event_payload(
            &EventKind::DeviceAuthorize,
            &Value::Object(event.payload.into_iter().collect()),
        )
        .unwrap();
    }

    #[test]
    fn device_authorize_rejects_a_binding_kind_that_contradicts_its_anchor() {
        // `accepted_device` is the only branch that carries a pairing
        // challenge transcript, and it anchors on a device rather than a
        // principal; the registration-anchor fixture therefore fails the
        // payload's own wire constraints instead of parsing.
        let mut payload = device_authorize_payload_value();
        payload.as_object_mut().unwrap().insert(
            "authorization_binding_kind".to_owned(),
            json!("accepted_device"),
        );

        let mut event = base_event();
        event.kind = EventKind::DeviceAuthorize;
        event.payload = serde_json::from_value(payload).unwrap();

        let error = event.as_device_authorize().unwrap_err();
        assert!(matches!(
            error,
            WireError::PayloadInvalid {
                kind: event_spec::DeviceAuthorize::KIND_STR,
                ..
            }
        ));
    }

    #[test]
    fn device_revoke_binds_its_typed_payload() {
        let mut event = base_event();
        event.kind = EventKind::DeviceRevoke;
        event.payload = serde_json::from_value(json!({
            "device_id": "ak:device:0198ff00-0000-7000-8000-000000000001",
            "revoked_by": "ak:did_core:webvh:z6mkcontroller",
            "revoked_at": "2026-09-16T00:00:00.000Z",
            "reason": "device_lost"
        }))
        .unwrap();

        let payload = event.as_device_revoke().unwrap();
        assert_eq!(
            payload.device_id.as_str(),
            "ak:device:0198ff00-0000-7000-8000-000000000001"
        );
        assert_eq!(payload.reason.as_str(), "device_lost");
        assert!(payload.proof.is_none());
        validate_event_payload(
            &EventKind::DeviceRevoke,
            &Value::Object(event.payload.into_iter().collect()),
        )
        .unwrap();
    }

    #[test]
    fn realm_authority_reset_binds_only_the_formal_closed_payload() {
        let mut event = base_event();
        event.kind = EventKind::RealmAuthorityReset;
        event.payload = serde_json::from_value(json!({
            "realm_id": "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
            "expected_state_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .unwrap();

        let typed = event.as_realm_authority_reset().unwrap();
        assert_eq!(
            typed.realm_id.as_str(),
            "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5"
        );
        validate_event_payload(
            &EventKind::RealmAuthorityReset,
            &Value::Object(event.payload.clone().into_iter().collect()),
        )
        .unwrap();

        event
            .payload
            .insert("destructive_confirmation".to_owned(), json!("forbidden"));
        assert!(event.as_realm_authority_reset().is_err());
    }

    #[test]
    fn device_revoke_rejects_a_self_revoking_authority() {
        let mut event = base_event();
        event.kind = EventKind::DeviceRevoke;
        event.payload = serde_json::from_value(json!({
            "device_id": "ak:device:0198ff00-0000-7000-8000-000000000001",
            "revoked_by": "ak:device:0198ff00-0000-7000-8000-000000000001",
            "revoked_at": "2026-09-16T00:00:00.000Z",
            "reason": "device_lost"
        }))
        .unwrap();

        let error = event.as_device_revoke().unwrap_err();
        assert!(matches!(
            error,
            WireError::PayloadInvalid {
                kind: event_spec::DeviceRevoke::KIND_STR,
                ..
            }
        ));
    }

    #[test]
    fn every_active_standard_event_kind_has_a_typed_payload_binding() {
        let bound = EVENT_PAYLOAD_BINDINGS
            .iter()
            .map(|binding| binding.kind.clone())
            .collect::<std::collections::HashSet<_>>();
        let unbound = EventKind::ALL
            .iter()
            .filter(|kind| !bound.contains(*kind))
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        assert!(
            unbound.is_empty(),
            "active Event kinds without an SDK payload binding: {unbound:?}"
        );
    }

    #[test]
    fn active_event_payload_bindings_are_unique_and_schema_backed() {
        let kinds = EVENT_PAYLOAD_BINDINGS
            .iter()
            .map(|binding| binding.kind.clone())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(kinds.len(), EVENT_PAYLOAD_BINDINGS.len());
        let mut payload_type_by_schema_ref = std::collections::BTreeMap::new();
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
    }
}
