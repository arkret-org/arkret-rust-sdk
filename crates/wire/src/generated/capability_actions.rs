//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-10-03.1;
//! sha256=da17e87f85640ef75b59ff112d8b749ab33e27ef12209858ab5deb7c67b7c23b Entries: registered=146

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum CapabilityActionId {
    AgentActionApprove,
    AgentActionReject,
    AgentActionRequest,
    AgentDraftPropose,
    AgentKeyAuthorize,
    AgentKeyRevoke,
    AgentSidecarExchangeControl,
    AgentSidecarPublish,
    AgentSidecarWrite,
    AppletBridgeError,
    AppletGhostProvision,
    AppletInvoke,
    ApprovalVote,
    AuditAccessed,
    AuditExport,
    AuditQuery,
    CallJoin,
    CallModerate,
    CallRecord,
    CallScreenShare,
    CallSignalSend,
    CallTranscribe,
    CapabilityGrant,
    CapabilityRelinquish,
    CapabilityRevoke,
    CircleAudit,
    CircleCreate,
    CircleManage,
    CircleMemberAdd,
    CircleMemberAddOthers,
    CircleMemberManage,
    ConsentGrant,
    ConsentRevoke,
    ContactScopeUpdate,
    EventRead,
    InviteAccept,
    InviteCancel,
    InviteClaim,
    InviteCreate,
    InviteRevoke,
    InviteThirdParty,
    MemberCompensateLeave,
    MemberCompensateRemove,
    MemberLeaveOwn,
    MemberRejoinOwn,
    MessageCreate,
    MessageMentionBroadcast,
    MessageRedact,
    MessageRedactOwn,
    MessageRevise,
    MessageReviseOwn,
    MessageStreamSend,
    MlsCommit,
    MlsGenesis,
    ModerationDecision,
    ModerationDecisionLift,
    MorphArchive,
    MorphCreate,
    MorphRead,
    MorphRestore,
    MorphStageSet,
    MorphUpdate,
    NotificationAck,
    NotificationRead,
    ObjectArchive,
    ObjectRead,
    ObjectReadContent,
    ObjectReadHistory,
    ObjectReadMetadata,
    ObjectRestore,
    ObjectStageSet,
    PinAdd,
    PinRemove,
    PinReorder,
    PolicyAction,
    PolicyManage,
    PolicySet,
    PresenceBroadcast,
    ReactionAdd,
    ReactionRemove,
    ReadCursorAdvance,
    RealmAdmin,
    RealmAlias,
    RealmArchive,
    RealmAuthorityReset,
    RealmCreate,
    RealmDestroy,
    RealmDiscover,
    RealmFreeze,
    RealmGovernanceStationChange,
    RealmLink,
    RealmMediaService,
    RealmNotificationAudit,
    RealmOwner,
    RealmOwnerTransfer,
    RealmPlaintextVisibleServices,
    RealmPreviewPolicy,
    RealmProfile,
    RealmSearchPolicy,
    RealmSetDefaultStrand,
    RealmTombstone,
    ReceiptBroadcast,
    RelationCreate,
    RelationTombstone,
    RelationUpdate,
    RsvpSet,
    SchemaDefine,
    SelfAccountReadDescribeV1,
    SelfAccountStreamSubscribeV1,
    SelfAgentCommandDeactivateV1,
    SelfAgentCommandPauseV1,
    SelfAgentCommandProvisionV1,
    SelfAgentCommandRenewPairingV1,
    SelfAgentCommandResumeV1,
    SelfAgentParticipationResourceReplaceV1,
    SelfAgentSidecarCommandEnsureV1,
    SelfBlobCommandPresignV1,
    SelfBlobResourceGetV1,
    SelfBlobResourceHeadV1,
    SelfBlobUploadCreateV1,
    SelfCommittedEventReadScanV1,
    SelfCommittedEventStreamSubscribeV1,
    SelfRealmStateSnapshotReadByRefV1,
    SelfRealmStateSnapshotReadManifestHeadV1,
    SpaceArchive,
    SpaceCreate,
    SpaceParent,
    SpaceRestore,
    SpaceTombstone,
    SpaceUpdate,
    StrandAdmin,
    StrandArchive,
    StrandCreate,
    StrandMove,
    StrandRead,
    StrandReorder,
    StrandRestore,
    StrandStageSet,
    StrandTracksUpdate,
    StrandUpdate,
    StrandWatchSet,
    StrandWatchSetOthers,
    TypingBroadcast,
    ViewCreate,
    ViewReconcile,
    ViewUpdate,
}

impl CapabilityActionId {
    pub const ALL: &'static [Self] = &[
        Self::AgentActionApprove,
        Self::AgentActionReject,
        Self::AgentActionRequest,
        Self::AgentDraftPropose,
        Self::AgentKeyAuthorize,
        Self::AgentKeyRevoke,
        Self::AgentSidecarExchangeControl,
        Self::AgentSidecarPublish,
        Self::AgentSidecarWrite,
        Self::AppletBridgeError,
        Self::AppletGhostProvision,
        Self::AppletInvoke,
        Self::ApprovalVote,
        Self::AuditAccessed,
        Self::AuditExport,
        Self::AuditQuery,
        Self::CallJoin,
        Self::CallModerate,
        Self::CallRecord,
        Self::CallScreenShare,
        Self::CallSignalSend,
        Self::CallTranscribe,
        Self::CapabilityGrant,
        Self::CapabilityRelinquish,
        Self::CapabilityRevoke,
        Self::CircleAudit,
        Self::CircleCreate,
        Self::CircleManage,
        Self::CircleMemberAdd,
        Self::CircleMemberAddOthers,
        Self::CircleMemberManage,
        Self::ConsentGrant,
        Self::ConsentRevoke,
        Self::ContactScopeUpdate,
        Self::EventRead,
        Self::InviteAccept,
        Self::InviteCancel,
        Self::InviteClaim,
        Self::InviteCreate,
        Self::InviteRevoke,
        Self::InviteThirdParty,
        Self::MemberCompensateLeave,
        Self::MemberCompensateRemove,
        Self::MemberLeaveOwn,
        Self::MemberRejoinOwn,
        Self::MessageCreate,
        Self::MessageMentionBroadcast,
        Self::MessageRedact,
        Self::MessageRedactOwn,
        Self::MessageRevise,
        Self::MessageReviseOwn,
        Self::MessageStreamSend,
        Self::MlsCommit,
        Self::MlsGenesis,
        Self::ModerationDecision,
        Self::ModerationDecisionLift,
        Self::MorphArchive,
        Self::MorphCreate,
        Self::MorphRead,
        Self::MorphRestore,
        Self::MorphStageSet,
        Self::MorphUpdate,
        Self::NotificationAck,
        Self::NotificationRead,
        Self::ObjectArchive,
        Self::ObjectRead,
        Self::ObjectReadContent,
        Self::ObjectReadHistory,
        Self::ObjectReadMetadata,
        Self::ObjectRestore,
        Self::ObjectStageSet,
        Self::PinAdd,
        Self::PinRemove,
        Self::PinReorder,
        Self::PolicyAction,
        Self::PolicyManage,
        Self::PolicySet,
        Self::PresenceBroadcast,
        Self::ReactionAdd,
        Self::ReactionRemove,
        Self::ReadCursorAdvance,
        Self::RealmAdmin,
        Self::RealmAlias,
        Self::RealmArchive,
        Self::RealmAuthorityReset,
        Self::RealmCreate,
        Self::RealmDestroy,
        Self::RealmDiscover,
        Self::RealmFreeze,
        Self::RealmGovernanceStationChange,
        Self::RealmLink,
        Self::RealmMediaService,
        Self::RealmNotificationAudit,
        Self::RealmOwner,
        Self::RealmOwnerTransfer,
        Self::RealmPlaintextVisibleServices,
        Self::RealmPreviewPolicy,
        Self::RealmProfile,
        Self::RealmSearchPolicy,
        Self::RealmSetDefaultStrand,
        Self::RealmTombstone,
        Self::ReceiptBroadcast,
        Self::RelationCreate,
        Self::RelationTombstone,
        Self::RelationUpdate,
        Self::RsvpSet,
        Self::SchemaDefine,
        Self::SelfAccountReadDescribeV1,
        Self::SelfAccountStreamSubscribeV1,
        Self::SelfAgentCommandDeactivateV1,
        Self::SelfAgentCommandPauseV1,
        Self::SelfAgentCommandProvisionV1,
        Self::SelfAgentCommandRenewPairingV1,
        Self::SelfAgentCommandResumeV1,
        Self::SelfAgentParticipationResourceReplaceV1,
        Self::SelfAgentSidecarCommandEnsureV1,
        Self::SelfBlobCommandPresignV1,
        Self::SelfBlobResourceGetV1,
        Self::SelfBlobResourceHeadV1,
        Self::SelfBlobUploadCreateV1,
        Self::SelfCommittedEventReadScanV1,
        Self::SelfCommittedEventStreamSubscribeV1,
        Self::SelfRealmStateSnapshotReadByRefV1,
        Self::SelfRealmStateSnapshotReadManifestHeadV1,
        Self::SpaceArchive,
        Self::SpaceCreate,
        Self::SpaceParent,
        Self::SpaceRestore,
        Self::SpaceTombstone,
        Self::SpaceUpdate,
        Self::StrandAdmin,
        Self::StrandArchive,
        Self::StrandCreate,
        Self::StrandMove,
        Self::StrandRead,
        Self::StrandReorder,
        Self::StrandRestore,
        Self::StrandStageSet,
        Self::StrandTracksUpdate,
        Self::StrandUpdate,
        Self::StrandWatchSet,
        Self::StrandWatchSetOthers,
        Self::TypingBroadcast,
        Self::ViewCreate,
        Self::ViewReconcile,
        Self::ViewUpdate,
    ];

    pub const AGENT_ACTION_APPROVE: &'static str = "ak.agent.action_approve";
    pub const AGENT_ACTION_REJECT: &'static str = "ak.agent.action_reject";
    pub const AGENT_ACTION_REQUEST: &'static str = "ak.agent.action_request";
    pub const AGENT_DRAFT_PROPOSE: &'static str = "ak.agent.draft.propose";
    pub const AGENT_KEY_AUTHORIZE: &'static str = "ak.agent.key.authorize";
    pub const AGENT_KEY_REVOKE: &'static str = "ak.agent.key.revoke";
    pub const AGENT_SIDECAR_EXCHANGE_CONTROL: &'static str = "ak.agent.sidecar.exchange.control";
    pub const AGENT_SIDECAR_PUBLISH: &'static str = "ak.agent.sidecar.publish";
    pub const AGENT_SIDECAR_WRITE: &'static str = "ak.agent.sidecar.write";
    pub const APPLET_BRIDGE_ERROR: &'static str = "ak.applet.bridge_error";
    pub const APPLET_GHOST_PROVISION: &'static str = "ak.applet.ghost.provision";
    pub const APPLET_INVOKE: &'static str = "ak.applet.invoke";
    pub const APPROVAL_VOTE: &'static str = "ak.approval.vote";
    pub const AUDIT_ACCESSED: &'static str = "ak.audit.accessed";
    pub const AUDIT_EXPORT: &'static str = "ak.audit.export";
    pub const AUDIT_QUERY: &'static str = "ak.audit.query";
    pub const CALL_JOIN: &'static str = "ak.call.join";
    pub const CALL_MODERATE: &'static str = "ak.call.moderate";
    pub const CALL_RECORD: &'static str = "ak.call.record";
    pub const CALL_SCREEN_SHARE: &'static str = "ak.call.screen_share";
    pub const CALL_SIGNAL_SEND: &'static str = "ak.call.signal.send";
    pub const CALL_TRANSCRIBE: &'static str = "ak.call.transcribe";
    pub const CAPABILITY_GRANT: &'static str = "ak.capability.grant";
    pub const CAPABILITY_RELINQUISH: &'static str = "ak.capability.relinquish";
    pub const CAPABILITY_REVOKE: &'static str = "ak.capability.revoke";
    pub const CIRCLE_AUDIT: &'static str = "ak.circle.audit";
    pub const CIRCLE_CREATE: &'static str = "ak.circle.create";
    pub const CIRCLE_MANAGE: &'static str = "ak.circle.manage";
    pub const CIRCLE_MEMBER_ADD: &'static str = "ak.circle.member.add";
    pub const CIRCLE_MEMBER_ADD_OTHERS: &'static str = "ak.circle.member.add.others";
    pub const CIRCLE_MEMBER_MANAGE: &'static str = "ak.circle.member.manage";
    pub const CONSENT_GRANT: &'static str = "ak.consent.grant";
    pub const CONSENT_REVOKE: &'static str = "ak.consent.revoke";
    pub const CONTACT_SCOPE_UPDATE: &'static str = "ak.contact.scope.update";
    pub const EVENT_READ: &'static str = "ak.event.read";
    pub const INVITE_ACCEPT: &'static str = "ak.invite.accept";
    pub const INVITE_CANCEL: &'static str = "ak.invite.cancel";
    pub const INVITE_CLAIM: &'static str = "ak.invite.claim";
    pub const INVITE_CREATE: &'static str = "ak.invite.create";
    pub const INVITE_REVOKE: &'static str = "ak.invite.revoke";
    pub const INVITE_THIRD_PARTY: &'static str = "ak.invite.third_party";
    pub const MEMBER_COMPENSATE_LEAVE: &'static str = "ak.member.compensate.leave";
    pub const MEMBER_COMPENSATE_REMOVE: &'static str = "ak.member.compensate.remove";
    pub const MEMBER_LEAVE_OWN: &'static str = "ak.member.leave.own";
    pub const MEMBER_REJOIN_OWN: &'static str = "ak.member.rejoin.own";
    pub const MESSAGE_CREATE: &'static str = "ak.message.create";
    pub const MESSAGE_MENTION_BROADCAST: &'static str = "ak.message.mention.broadcast";
    pub const MESSAGE_REDACT: &'static str = "ak.message.redact";
    pub const MESSAGE_REDACT_OWN: &'static str = "ak.message.redact.own";
    pub const MESSAGE_REVISE: &'static str = "ak.message.revise";
    pub const MESSAGE_REVISE_OWN: &'static str = "ak.message.revise.own";
    pub const MESSAGE_STREAM_SEND: &'static str = "ak.message.stream.send";
    pub const MLS_COMMIT: &'static str = "ak.mls.commit";
    pub const MLS_GENESIS: &'static str = "ak.mls.genesis";
    pub const MODERATION_DECISION: &'static str = "ak.moderation.decision";
    pub const MODERATION_DECISION_LIFT: &'static str = "ak.moderation.decision.lift";
    pub const MORPH_ARCHIVE: &'static str = "ak.morph.archive";
    pub const MORPH_CREATE: &'static str = "ak.morph.create";
    pub const MORPH_READ: &'static str = "ak.morph.read";
    pub const MORPH_RESTORE: &'static str = "ak.morph.restore";
    pub const MORPH_STAGE_SET: &'static str = "ak.morph.stage.set";
    pub const MORPH_UPDATE: &'static str = "ak.morph.update";
    pub const NOTIFICATION_ACK: &'static str = "ak.notification.ack";
    pub const NOTIFICATION_READ: &'static str = "ak.notification.read";
    pub const OBJECT_ARCHIVE: &'static str = "ak.object.archive";
    pub const OBJECT_READ: &'static str = "ak.object.read";
    pub const OBJECT_READ_CONTENT: &'static str = "ak.object.read_content";
    pub const OBJECT_READ_HISTORY: &'static str = "ak.object.read_history";
    pub const OBJECT_READ_METADATA: &'static str = "ak.object.read_metadata";
    pub const OBJECT_RESTORE: &'static str = "ak.object.restore";
    pub const OBJECT_STAGE_SET: &'static str = "ak.object.stage.set";
    pub const PIN_ADD: &'static str = "ak.pin.add";
    pub const PIN_REMOVE: &'static str = "ak.pin.remove";
    pub const PIN_REORDER: &'static str = "ak.pin.reorder";
    pub const POLICY_ACTION: &'static str = "ak.policy.action";
    pub const POLICY_MANAGE: &'static str = "ak.policy.manage";
    pub const POLICY_SET: &'static str = "ak.policy.set";
    pub const PRESENCE_BROADCAST: &'static str = "ak.presence.broadcast";
    pub const REACTION_ADD: &'static str = "ak.reaction.add";
    pub const REACTION_REMOVE: &'static str = "ak.reaction.remove";
    pub const READ_CURSOR_ADVANCE: &'static str = "ak.read_cursor.advance";
    pub const REALM_ADMIN: &'static str = "ak.realm.admin";
    pub const REALM_ALIAS: &'static str = "ak.realm.alias";
    pub const REALM_ARCHIVE: &'static str = "ak.realm.archive";
    pub const REALM_AUTHORITY_RESET: &'static str = "ak.realm.authority.reset";
    pub const REALM_CREATE: &'static str = "ak.realm.create";
    pub const REALM_DESTROY: &'static str = "ak.realm.destroy";
    pub const REALM_DISCOVER: &'static str = "ak.realm.discover";
    pub const REALM_FREEZE: &'static str = "ak.realm.freeze";
    pub const REALM_GOVERNANCE_STATION_CHANGE: &'static str = "ak.realm.governance_station.change";
    pub const REALM_LINK: &'static str = "ak.realm.link";
    pub const REALM_MEDIA_SERVICE: &'static str = "ak.realm.media_service";
    pub const REALM_NOTIFICATION_AUDIT: &'static str = "ak.realm.notification.audit";
    pub const REALM_OWNER: &'static str = "ak.realm.owner";
    pub const REALM_OWNER_TRANSFER: &'static str = "ak.realm.owner.transfer";
    pub const REALM_PLAINTEXT_VISIBLE_SERVICES: &'static str =
        "ak.realm.plaintext_visible_services";
    pub const REALM_PREVIEW_POLICY: &'static str = "ak.realm.preview_policy";
    pub const REALM_PROFILE: &'static str = "ak.realm.profile";
    pub const REALM_SEARCH_POLICY: &'static str = "ak.realm.search_policy";
    pub const REALM_SET_DEFAULT_STRAND: &'static str = "ak.realm.set_default_strand";
    pub const REALM_TOMBSTONE: &'static str = "ak.realm.tombstone";
    pub const RECEIPT_BROADCAST: &'static str = "ak.receipt.broadcast";
    pub const RELATION_CREATE: &'static str = "ak.relation.create";
    pub const RELATION_TOMBSTONE: &'static str = "ak.relation.tombstone";
    pub const RELATION_UPDATE: &'static str = "ak.relation.update";
    pub const RSVP_SET: &'static str = "ak.rsvp.set";
    pub const SCHEMA_DEFINE: &'static str = "ak.schema.define";
    pub const SELF_ACCOUNT_READ_DESCRIBE_V1: &'static str = "ak.self.account.read.describe.v1";
    pub const SELF_ACCOUNT_STREAM_SUBSCRIBE_V1: &'static str =
        "ak.self.account.stream.subscribe.v1";
    pub const SELF_AGENT_COMMAND_DEACTIVATE_V1: &'static str =
        "ak.self.agent.command.deactivate.v1";
    pub const SELF_AGENT_COMMAND_PAUSE_V1: &'static str = "ak.self.agent.command.pause.v1";
    pub const SELF_AGENT_COMMAND_PROVISION_V1: &'static str = "ak.self.agent.command.provision.v1";
    pub const SELF_AGENT_COMMAND_RENEW_PAIRING_V1: &'static str =
        "ak.self.agent.command.renew_pairing.v1";
    pub const SELF_AGENT_COMMAND_RESUME_V1: &'static str = "ak.self.agent.command.resume.v1";
    pub const SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE_V1: &'static str =
        "ak.self.agent.participation.resource.replace.v1";
    pub const SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1: &'static str =
        "ak.self.agent.sidecar.command.ensure.v1";
    pub const SELF_BLOB_COMMAND_PRESIGN_V1: &'static str = "ak.self.blob.command.presign.v1";
    pub const SELF_BLOB_RESOURCE_GET_V1: &'static str = "ak.self.blob.resource.get.v1";
    pub const SELF_BLOB_RESOURCE_HEAD_V1: &'static str = "ak.self.blob.resource.head.v1";
    pub const SELF_BLOB_UPLOAD_CREATE_V1: &'static str = "ak.self.blob.upload.create.v1";
    pub const SELF_COMMITTED_EVENT_READ_SCAN_V1: &'static str =
        "ak.self.committed_event.read.scan.v1";
    pub const SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1: &'static str =
        "ak.self.committed_event.stream.subscribe.v1";
    pub const SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1: &'static str =
        "ak.self.realm_state_snapshot.read.by_ref.v1";
    pub const SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1: &'static str =
        "ak.self.realm_state_snapshot.read.manifest_head.v1";
    pub const SPACE_ARCHIVE: &'static str = "ak.space.archive";
    pub const SPACE_CREATE: &'static str = "ak.space.create";
    pub const SPACE_PARENT: &'static str = "ak.space.parent";
    pub const SPACE_RESTORE: &'static str = "ak.space.restore";
    pub const SPACE_TOMBSTONE: &'static str = "ak.space.tombstone";
    pub const SPACE_UPDATE: &'static str = "ak.space.update";
    pub const STRAND_ADMIN: &'static str = "ak.strand.admin";
    pub const STRAND_ARCHIVE: &'static str = "ak.strand.archive";
    pub const STRAND_CREATE: &'static str = "ak.strand.create";
    pub const STRAND_MOVE: &'static str = "ak.strand.move";
    pub const STRAND_READ: &'static str = "ak.strand.read";
    pub const STRAND_REORDER: &'static str = "ak.strand.reorder";
    pub const STRAND_RESTORE: &'static str = "ak.strand.restore";
    pub const STRAND_STAGE_SET: &'static str = "ak.strand.stage.set";
    pub const STRAND_TRACKS_UPDATE: &'static str = "ak.strand.tracks.update";
    pub const STRAND_UPDATE: &'static str = "ak.strand.update";
    pub const STRAND_WATCH_SET: &'static str = "ak.strand.watch.set";
    pub const STRAND_WATCH_SET_OTHERS: &'static str = "ak.strand.watch.set.others";
    pub const TYPING_BROADCAST: &'static str = "ak.typing.broadcast";
    pub const VIEW_CREATE: &'static str = "ak.view.create";
    pub const VIEW_RECONCILE: &'static str = "ak.view.reconcile";
    pub const VIEW_UPDATE: &'static str = "ak.view.update";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentActionApprove => Self::AGENT_ACTION_APPROVE,
            Self::AgentActionReject => Self::AGENT_ACTION_REJECT,
            Self::AgentActionRequest => Self::AGENT_ACTION_REQUEST,
            Self::AgentDraftPropose => Self::AGENT_DRAFT_PROPOSE,
            Self::AgentKeyAuthorize => Self::AGENT_KEY_AUTHORIZE,
            Self::AgentKeyRevoke => Self::AGENT_KEY_REVOKE,
            Self::AgentSidecarExchangeControl => Self::AGENT_SIDECAR_EXCHANGE_CONTROL,
            Self::AgentSidecarPublish => Self::AGENT_SIDECAR_PUBLISH,
            Self::AgentSidecarWrite => Self::AGENT_SIDECAR_WRITE,
            Self::AppletBridgeError => Self::APPLET_BRIDGE_ERROR,
            Self::AppletGhostProvision => Self::APPLET_GHOST_PROVISION,
            Self::AppletInvoke => Self::APPLET_INVOKE,
            Self::ApprovalVote => Self::APPROVAL_VOTE,
            Self::AuditAccessed => Self::AUDIT_ACCESSED,
            Self::AuditExport => Self::AUDIT_EXPORT,
            Self::AuditQuery => Self::AUDIT_QUERY,
            Self::CallJoin => Self::CALL_JOIN,
            Self::CallModerate => Self::CALL_MODERATE,
            Self::CallRecord => Self::CALL_RECORD,
            Self::CallScreenShare => Self::CALL_SCREEN_SHARE,
            Self::CallSignalSend => Self::CALL_SIGNAL_SEND,
            Self::CallTranscribe => Self::CALL_TRANSCRIBE,
            Self::CapabilityGrant => Self::CAPABILITY_GRANT,
            Self::CapabilityRelinquish => Self::CAPABILITY_RELINQUISH,
            Self::CapabilityRevoke => Self::CAPABILITY_REVOKE,
            Self::CircleAudit => Self::CIRCLE_AUDIT,
            Self::CircleCreate => Self::CIRCLE_CREATE,
            Self::CircleManage => Self::CIRCLE_MANAGE,
            Self::CircleMemberAdd => Self::CIRCLE_MEMBER_ADD,
            Self::CircleMemberAddOthers => Self::CIRCLE_MEMBER_ADD_OTHERS,
            Self::CircleMemberManage => Self::CIRCLE_MEMBER_MANAGE,
            Self::ConsentGrant => Self::CONSENT_GRANT,
            Self::ConsentRevoke => Self::CONSENT_REVOKE,
            Self::ContactScopeUpdate => Self::CONTACT_SCOPE_UPDATE,
            Self::EventRead => Self::EVENT_READ,
            Self::InviteAccept => Self::INVITE_ACCEPT,
            Self::InviteCancel => Self::INVITE_CANCEL,
            Self::InviteClaim => Self::INVITE_CLAIM,
            Self::InviteCreate => Self::INVITE_CREATE,
            Self::InviteRevoke => Self::INVITE_REVOKE,
            Self::InviteThirdParty => Self::INVITE_THIRD_PARTY,
            Self::MemberCompensateLeave => Self::MEMBER_COMPENSATE_LEAVE,
            Self::MemberCompensateRemove => Self::MEMBER_COMPENSATE_REMOVE,
            Self::MemberLeaveOwn => Self::MEMBER_LEAVE_OWN,
            Self::MemberRejoinOwn => Self::MEMBER_REJOIN_OWN,
            Self::MessageCreate => Self::MESSAGE_CREATE,
            Self::MessageMentionBroadcast => Self::MESSAGE_MENTION_BROADCAST,
            Self::MessageRedact => Self::MESSAGE_REDACT,
            Self::MessageRedactOwn => Self::MESSAGE_REDACT_OWN,
            Self::MessageRevise => Self::MESSAGE_REVISE,
            Self::MessageReviseOwn => Self::MESSAGE_REVISE_OWN,
            Self::MessageStreamSend => Self::MESSAGE_STREAM_SEND,
            Self::MlsCommit => Self::MLS_COMMIT,
            Self::MlsGenesis => Self::MLS_GENESIS,
            Self::ModerationDecision => Self::MODERATION_DECISION,
            Self::ModerationDecisionLift => Self::MODERATION_DECISION_LIFT,
            Self::MorphArchive => Self::MORPH_ARCHIVE,
            Self::MorphCreate => Self::MORPH_CREATE,
            Self::MorphRead => Self::MORPH_READ,
            Self::MorphRestore => Self::MORPH_RESTORE,
            Self::MorphStageSet => Self::MORPH_STAGE_SET,
            Self::MorphUpdate => Self::MORPH_UPDATE,
            Self::NotificationAck => Self::NOTIFICATION_ACK,
            Self::NotificationRead => Self::NOTIFICATION_READ,
            Self::ObjectArchive => Self::OBJECT_ARCHIVE,
            Self::ObjectRead => Self::OBJECT_READ,
            Self::ObjectReadContent => Self::OBJECT_READ_CONTENT,
            Self::ObjectReadHistory => Self::OBJECT_READ_HISTORY,
            Self::ObjectReadMetadata => Self::OBJECT_READ_METADATA,
            Self::ObjectRestore => Self::OBJECT_RESTORE,
            Self::ObjectStageSet => Self::OBJECT_STAGE_SET,
            Self::PinAdd => Self::PIN_ADD,
            Self::PinRemove => Self::PIN_REMOVE,
            Self::PinReorder => Self::PIN_REORDER,
            Self::PolicyAction => Self::POLICY_ACTION,
            Self::PolicyManage => Self::POLICY_MANAGE,
            Self::PolicySet => Self::POLICY_SET,
            Self::PresenceBroadcast => Self::PRESENCE_BROADCAST,
            Self::ReactionAdd => Self::REACTION_ADD,
            Self::ReactionRemove => Self::REACTION_REMOVE,
            Self::ReadCursorAdvance => Self::READ_CURSOR_ADVANCE,
            Self::RealmAdmin => Self::REALM_ADMIN,
            Self::RealmAlias => Self::REALM_ALIAS,
            Self::RealmArchive => Self::REALM_ARCHIVE,
            Self::RealmAuthorityReset => Self::REALM_AUTHORITY_RESET,
            Self::RealmCreate => Self::REALM_CREATE,
            Self::RealmDestroy => Self::REALM_DESTROY,
            Self::RealmDiscover => Self::REALM_DISCOVER,
            Self::RealmFreeze => Self::REALM_FREEZE,
            Self::RealmGovernanceStationChange => Self::REALM_GOVERNANCE_STATION_CHANGE,
            Self::RealmLink => Self::REALM_LINK,
            Self::RealmMediaService => Self::REALM_MEDIA_SERVICE,
            Self::RealmNotificationAudit => Self::REALM_NOTIFICATION_AUDIT,
            Self::RealmOwner => Self::REALM_OWNER,
            Self::RealmOwnerTransfer => Self::REALM_OWNER_TRANSFER,
            Self::RealmPlaintextVisibleServices => Self::REALM_PLAINTEXT_VISIBLE_SERVICES,
            Self::RealmPreviewPolicy => Self::REALM_PREVIEW_POLICY,
            Self::RealmProfile => Self::REALM_PROFILE,
            Self::RealmSearchPolicy => Self::REALM_SEARCH_POLICY,
            Self::RealmSetDefaultStrand => Self::REALM_SET_DEFAULT_STRAND,
            Self::RealmTombstone => Self::REALM_TOMBSTONE,
            Self::ReceiptBroadcast => Self::RECEIPT_BROADCAST,
            Self::RelationCreate => Self::RELATION_CREATE,
            Self::RelationTombstone => Self::RELATION_TOMBSTONE,
            Self::RelationUpdate => Self::RELATION_UPDATE,
            Self::RsvpSet => Self::RSVP_SET,
            Self::SchemaDefine => Self::SCHEMA_DEFINE,
            Self::SelfAccountReadDescribeV1 => Self::SELF_ACCOUNT_READ_DESCRIBE_V1,
            Self::SelfAccountStreamSubscribeV1 => Self::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1,
            Self::SelfAgentCommandDeactivateV1 => Self::SELF_AGENT_COMMAND_DEACTIVATE_V1,
            Self::SelfAgentCommandPauseV1 => Self::SELF_AGENT_COMMAND_PAUSE_V1,
            Self::SelfAgentCommandProvisionV1 => Self::SELF_AGENT_COMMAND_PROVISION_V1,
            Self::SelfAgentCommandRenewPairingV1 => Self::SELF_AGENT_COMMAND_RENEW_PAIRING_V1,
            Self::SelfAgentCommandResumeV1 => Self::SELF_AGENT_COMMAND_RESUME_V1,
            Self::SelfAgentParticipationResourceReplaceV1 => {
                Self::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE_V1
            }
            Self::SelfAgentSidecarCommandEnsureV1 => Self::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1,
            Self::SelfBlobCommandPresignV1 => Self::SELF_BLOB_COMMAND_PRESIGN_V1,
            Self::SelfBlobResourceGetV1 => Self::SELF_BLOB_RESOURCE_GET_V1,
            Self::SelfBlobResourceHeadV1 => Self::SELF_BLOB_RESOURCE_HEAD_V1,
            Self::SelfBlobUploadCreateV1 => Self::SELF_BLOB_UPLOAD_CREATE_V1,
            Self::SelfCommittedEventReadScanV1 => Self::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            Self::SelfCommittedEventStreamSubscribeV1 => {
                Self::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1
            }
            Self::SelfRealmStateSnapshotReadByRefV1 => {
                Self::SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1
            }
            Self::SelfRealmStateSnapshotReadManifestHeadV1 => {
                Self::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1
            }
            Self::SpaceArchive => Self::SPACE_ARCHIVE,
            Self::SpaceCreate => Self::SPACE_CREATE,
            Self::SpaceParent => Self::SPACE_PARENT,
            Self::SpaceRestore => Self::SPACE_RESTORE,
            Self::SpaceTombstone => Self::SPACE_TOMBSTONE,
            Self::SpaceUpdate => Self::SPACE_UPDATE,
            Self::StrandAdmin => Self::STRAND_ADMIN,
            Self::StrandArchive => Self::STRAND_ARCHIVE,
            Self::StrandCreate => Self::STRAND_CREATE,
            Self::StrandMove => Self::STRAND_MOVE,
            Self::StrandRead => Self::STRAND_READ,
            Self::StrandReorder => Self::STRAND_REORDER,
            Self::StrandRestore => Self::STRAND_RESTORE,
            Self::StrandStageSet => Self::STRAND_STAGE_SET,
            Self::StrandTracksUpdate => Self::STRAND_TRACKS_UPDATE,
            Self::StrandUpdate => Self::STRAND_UPDATE,
            Self::StrandWatchSet => Self::STRAND_WATCH_SET,
            Self::StrandWatchSetOthers => Self::STRAND_WATCH_SET_OTHERS,
            Self::TypingBroadcast => Self::TYPING_BROADCAST,
            Self::ViewCreate => Self::VIEW_CREATE,
            Self::ViewReconcile => Self::VIEW_RECONCILE,
            Self::ViewUpdate => Self::VIEW_UPDATE,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::AGENT_ACTION_APPROVE => Some(Self::AgentActionApprove),
            Self::AGENT_ACTION_REJECT => Some(Self::AgentActionReject),
            Self::AGENT_ACTION_REQUEST => Some(Self::AgentActionRequest),
            Self::AGENT_DRAFT_PROPOSE => Some(Self::AgentDraftPropose),
            Self::AGENT_KEY_AUTHORIZE => Some(Self::AgentKeyAuthorize),
            Self::AGENT_KEY_REVOKE => Some(Self::AgentKeyRevoke),
            Self::AGENT_SIDECAR_EXCHANGE_CONTROL => Some(Self::AgentSidecarExchangeControl),
            Self::AGENT_SIDECAR_PUBLISH => Some(Self::AgentSidecarPublish),
            Self::AGENT_SIDECAR_WRITE => Some(Self::AgentSidecarWrite),
            Self::APPLET_BRIDGE_ERROR => Some(Self::AppletBridgeError),
            Self::APPLET_GHOST_PROVISION => Some(Self::AppletGhostProvision),
            Self::APPLET_INVOKE => Some(Self::AppletInvoke),
            Self::APPROVAL_VOTE => Some(Self::ApprovalVote),
            Self::AUDIT_ACCESSED => Some(Self::AuditAccessed),
            Self::AUDIT_EXPORT => Some(Self::AuditExport),
            Self::AUDIT_QUERY => Some(Self::AuditQuery),
            Self::CALL_JOIN => Some(Self::CallJoin),
            Self::CALL_MODERATE => Some(Self::CallModerate),
            Self::CALL_RECORD => Some(Self::CallRecord),
            Self::CALL_SCREEN_SHARE => Some(Self::CallScreenShare),
            Self::CALL_SIGNAL_SEND => Some(Self::CallSignalSend),
            Self::CALL_TRANSCRIBE => Some(Self::CallTranscribe),
            Self::CAPABILITY_GRANT => Some(Self::CapabilityGrant),
            Self::CAPABILITY_RELINQUISH => Some(Self::CapabilityRelinquish),
            Self::CAPABILITY_REVOKE => Some(Self::CapabilityRevoke),
            Self::CIRCLE_AUDIT => Some(Self::CircleAudit),
            Self::CIRCLE_CREATE => Some(Self::CircleCreate),
            Self::CIRCLE_MANAGE => Some(Self::CircleManage),
            Self::CIRCLE_MEMBER_ADD => Some(Self::CircleMemberAdd),
            Self::CIRCLE_MEMBER_ADD_OTHERS => Some(Self::CircleMemberAddOthers),
            Self::CIRCLE_MEMBER_MANAGE => Some(Self::CircleMemberManage),
            Self::CONSENT_GRANT => Some(Self::ConsentGrant),
            Self::CONSENT_REVOKE => Some(Self::ConsentRevoke),
            Self::CONTACT_SCOPE_UPDATE => Some(Self::ContactScopeUpdate),
            Self::EVENT_READ => Some(Self::EventRead),
            Self::INVITE_ACCEPT => Some(Self::InviteAccept),
            Self::INVITE_CANCEL => Some(Self::InviteCancel),
            Self::INVITE_CLAIM => Some(Self::InviteClaim),
            Self::INVITE_CREATE => Some(Self::InviteCreate),
            Self::INVITE_REVOKE => Some(Self::InviteRevoke),
            Self::INVITE_THIRD_PARTY => Some(Self::InviteThirdParty),
            Self::MEMBER_COMPENSATE_LEAVE => Some(Self::MemberCompensateLeave),
            Self::MEMBER_COMPENSATE_REMOVE => Some(Self::MemberCompensateRemove),
            Self::MEMBER_LEAVE_OWN => Some(Self::MemberLeaveOwn),
            Self::MEMBER_REJOIN_OWN => Some(Self::MemberRejoinOwn),
            Self::MESSAGE_CREATE => Some(Self::MessageCreate),
            Self::MESSAGE_MENTION_BROADCAST => Some(Self::MessageMentionBroadcast),
            Self::MESSAGE_REDACT => Some(Self::MessageRedact),
            Self::MESSAGE_REDACT_OWN => Some(Self::MessageRedactOwn),
            Self::MESSAGE_REVISE => Some(Self::MessageRevise),
            Self::MESSAGE_REVISE_OWN => Some(Self::MessageReviseOwn),
            Self::MESSAGE_STREAM_SEND => Some(Self::MessageStreamSend),
            Self::MLS_COMMIT => Some(Self::MlsCommit),
            Self::MLS_GENESIS => Some(Self::MlsGenesis),
            Self::MODERATION_DECISION => Some(Self::ModerationDecision),
            Self::MODERATION_DECISION_LIFT => Some(Self::ModerationDecisionLift),
            Self::MORPH_ARCHIVE => Some(Self::MorphArchive),
            Self::MORPH_CREATE => Some(Self::MorphCreate),
            Self::MORPH_READ => Some(Self::MorphRead),
            Self::MORPH_RESTORE => Some(Self::MorphRestore),
            Self::MORPH_STAGE_SET => Some(Self::MorphStageSet),
            Self::MORPH_UPDATE => Some(Self::MorphUpdate),
            Self::NOTIFICATION_ACK => Some(Self::NotificationAck),
            Self::NOTIFICATION_READ => Some(Self::NotificationRead),
            Self::OBJECT_ARCHIVE => Some(Self::ObjectArchive),
            Self::OBJECT_READ => Some(Self::ObjectRead),
            Self::OBJECT_READ_CONTENT => Some(Self::ObjectReadContent),
            Self::OBJECT_READ_HISTORY => Some(Self::ObjectReadHistory),
            Self::OBJECT_READ_METADATA => Some(Self::ObjectReadMetadata),
            Self::OBJECT_RESTORE => Some(Self::ObjectRestore),
            Self::OBJECT_STAGE_SET => Some(Self::ObjectStageSet),
            Self::PIN_ADD => Some(Self::PinAdd),
            Self::PIN_REMOVE => Some(Self::PinRemove),
            Self::PIN_REORDER => Some(Self::PinReorder),
            Self::POLICY_ACTION => Some(Self::PolicyAction),
            Self::POLICY_MANAGE => Some(Self::PolicyManage),
            Self::POLICY_SET => Some(Self::PolicySet),
            Self::PRESENCE_BROADCAST => Some(Self::PresenceBroadcast),
            Self::REACTION_ADD => Some(Self::ReactionAdd),
            Self::REACTION_REMOVE => Some(Self::ReactionRemove),
            Self::READ_CURSOR_ADVANCE => Some(Self::ReadCursorAdvance),
            Self::REALM_ADMIN => Some(Self::RealmAdmin),
            Self::REALM_ALIAS => Some(Self::RealmAlias),
            Self::REALM_ARCHIVE => Some(Self::RealmArchive),
            Self::REALM_AUTHORITY_RESET => Some(Self::RealmAuthorityReset),
            Self::REALM_CREATE => Some(Self::RealmCreate),
            Self::REALM_DESTROY => Some(Self::RealmDestroy),
            Self::REALM_DISCOVER => Some(Self::RealmDiscover),
            Self::REALM_FREEZE => Some(Self::RealmFreeze),
            Self::REALM_GOVERNANCE_STATION_CHANGE => Some(Self::RealmGovernanceStationChange),
            Self::REALM_LINK => Some(Self::RealmLink),
            Self::REALM_MEDIA_SERVICE => Some(Self::RealmMediaService),
            Self::REALM_NOTIFICATION_AUDIT => Some(Self::RealmNotificationAudit),
            Self::REALM_OWNER => Some(Self::RealmOwner),
            Self::REALM_OWNER_TRANSFER => Some(Self::RealmOwnerTransfer),
            Self::REALM_PLAINTEXT_VISIBLE_SERVICES => Some(Self::RealmPlaintextVisibleServices),
            Self::REALM_PREVIEW_POLICY => Some(Self::RealmPreviewPolicy),
            Self::REALM_PROFILE => Some(Self::RealmProfile),
            Self::REALM_SEARCH_POLICY => Some(Self::RealmSearchPolicy),
            Self::REALM_SET_DEFAULT_STRAND => Some(Self::RealmSetDefaultStrand),
            Self::REALM_TOMBSTONE => Some(Self::RealmTombstone),
            Self::RECEIPT_BROADCAST => Some(Self::ReceiptBroadcast),
            Self::RELATION_CREATE => Some(Self::RelationCreate),
            Self::RELATION_TOMBSTONE => Some(Self::RelationTombstone),
            Self::RELATION_UPDATE => Some(Self::RelationUpdate),
            Self::RSVP_SET => Some(Self::RsvpSet),
            Self::SCHEMA_DEFINE => Some(Self::SchemaDefine),
            Self::SELF_ACCOUNT_READ_DESCRIBE_V1 => Some(Self::SelfAccountReadDescribeV1),
            Self::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1 => Some(Self::SelfAccountStreamSubscribeV1),
            Self::SELF_AGENT_COMMAND_DEACTIVATE_V1 => Some(Self::SelfAgentCommandDeactivateV1),
            Self::SELF_AGENT_COMMAND_PAUSE_V1 => Some(Self::SelfAgentCommandPauseV1),
            Self::SELF_AGENT_COMMAND_PROVISION_V1 => Some(Self::SelfAgentCommandProvisionV1),
            Self::SELF_AGENT_COMMAND_RENEW_PAIRING_V1 => Some(Self::SelfAgentCommandRenewPairingV1),
            Self::SELF_AGENT_COMMAND_RESUME_V1 => Some(Self::SelfAgentCommandResumeV1),
            Self::SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE_V1 => {
                Some(Self::SelfAgentParticipationResourceReplaceV1)
            }
            Self::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1 => {
                Some(Self::SelfAgentSidecarCommandEnsureV1)
            }
            Self::SELF_BLOB_COMMAND_PRESIGN_V1 => Some(Self::SelfBlobCommandPresignV1),
            Self::SELF_BLOB_RESOURCE_GET_V1 => Some(Self::SelfBlobResourceGetV1),
            Self::SELF_BLOB_RESOURCE_HEAD_V1 => Some(Self::SelfBlobResourceHeadV1),
            Self::SELF_BLOB_UPLOAD_CREATE_V1 => Some(Self::SelfBlobUploadCreateV1),
            Self::SELF_COMMITTED_EVENT_READ_SCAN_V1 => Some(Self::SelfCommittedEventReadScanV1),
            Self::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1 => {
                Some(Self::SelfCommittedEventStreamSubscribeV1)
            }
            Self::SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1 => {
                Some(Self::SelfRealmStateSnapshotReadByRefV1)
            }
            Self::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1 => {
                Some(Self::SelfRealmStateSnapshotReadManifestHeadV1)
            }
            Self::SPACE_ARCHIVE => Some(Self::SpaceArchive),
            Self::SPACE_CREATE => Some(Self::SpaceCreate),
            Self::SPACE_PARENT => Some(Self::SpaceParent),
            Self::SPACE_RESTORE => Some(Self::SpaceRestore),
            Self::SPACE_TOMBSTONE => Some(Self::SpaceTombstone),
            Self::SPACE_UPDATE => Some(Self::SpaceUpdate),
            Self::STRAND_ADMIN => Some(Self::StrandAdmin),
            Self::STRAND_ARCHIVE => Some(Self::StrandArchive),
            Self::STRAND_CREATE => Some(Self::StrandCreate),
            Self::STRAND_MOVE => Some(Self::StrandMove),
            Self::STRAND_READ => Some(Self::StrandRead),
            Self::STRAND_REORDER => Some(Self::StrandReorder),
            Self::STRAND_RESTORE => Some(Self::StrandRestore),
            Self::STRAND_STAGE_SET => Some(Self::StrandStageSet),
            Self::STRAND_TRACKS_UPDATE => Some(Self::StrandTracksUpdate),
            Self::STRAND_UPDATE => Some(Self::StrandUpdate),
            Self::STRAND_WATCH_SET => Some(Self::StrandWatchSet),
            Self::STRAND_WATCH_SET_OTHERS => Some(Self::StrandWatchSetOthers),
            Self::TYPING_BROADCAST => Some(Self::TypingBroadcast),
            Self::VIEW_CREATE => Some(Self::ViewCreate),
            Self::VIEW_RECONCILE => Some(Self::ViewReconcile),
            Self::VIEW_UPDATE => Some(Self::ViewUpdate),
            _ => None,
        }
    }
}

impl std::fmt::Display for CapabilityActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for CapabilityActionId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CapabilityActionId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown capability action id: {raw}")))
    }
}
