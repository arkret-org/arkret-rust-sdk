//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/capability-action-registry.json; version=2026-07-20;
//! sha256=dcba96da280fe85a2b71fa708ce1264670807e3ee0018f6d38a6df700f2ec01b Entries: registered=154

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
    AgentSelectorClaim,
    AgentSidecarExchangeControl,
    AgentSidecarPublish,
    AgentSidecarWrite,
    ApprovalVote,
    AuditAccessed,
    AuditAppletBinding,
    AuditExport,
    AuditQuery,
    AuditRelease,
    AuditSessionAuthorize,
    AuditSessionClose,
    AuditSessionNotice,
    AuditSessionRequest,
    CallJoin,
    CallModerate,
    CallRecord,
    CallScreenShare,
    CallSignalSend,
    CallTranscribe,
    CapabilityDelegate,
    CapabilityDerived,
    CapabilityGrant,
    CapabilityRevoke,
    CircleAudit,
    CircleCreate,
    CircleManage,
    CircleMemberAdd,
    CircleMemberAddOthers,
    CircleMemberManage,
    ContainerMoveItem,
    ContainerRebalance,
    EventRead,
    InviteAccept,
    InviteCancel,
    InviteClaim,
    InviteCreate,
    InviteRevoke,
    InviteThirdParty,
    MessageCreate,
    MessageMentionBroadcast,
    MessageRedact,
    MessageRedactOwn,
    MessageRevise,
    MessageReviseOwn,
    MlsCommit,
    MlsGenesis,
    MlsKeypackage,
    MlsProposal,
    MlsWelcome,
    ModerationAppealReview,
    ModerationAppealSubmit,
    ModerationDecision,
    ModerationDecisionLift,
    MorphArchive,
    MorphCreate,
    MorphRead,
    MorphRestore,
    MorphSchemaMigrate,
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
    PolicyRule,
    PolicySet,
    PresenceBroadcast,
    ReactionAdd,
    ReactionRemove,
    ReadCursorAdvance,
    RealmAdmin,
    RealmArchive,
    RealmCreate,
    RealmDestroy,
    RealmDisappearingPolicy,
    RealmDiscover,
    RealmFreeze,
    RealmJoinReview,
    RealmLink,
    RealmMediaService,
    RealmModerationPolicy,
    RealmNotificationAudit,
    RealmPlaintextVisibleServices,
    RealmPreviewPolicy,
    RealmSearchPolicy,
    RealmSetDefaultStrand,
    RealmTombstone,
    RealmUpdate,
    RealmUpgrade,
    RealmKeyShare,
    ReceiptBroadcast,
    RelationCreate,
    RelationTombstone,
    RelationUpdate,
    RsvpSet,
    SchemaDefine,
    SchemaUpdate,
    SelfAccountQueryDescribe,
    SelfAccountStreamSubscribe,
    SelfAgentCommandDeactivate,
    SelfAgentCommandPause,
    SelfAgentCommandProvision,
    SelfAgentCommandRenewPairing,
    SelfAgentCommandResume,
    SelfAgentGrantCommandAttach,
    SelfAgentGrantResourceDelete,
    SelfAgentParticipationResourceReplace,
    SelfAgentSidecarCommandEnsure,
    SelfBlobCommandPresign,
    SelfBlobResourceGet,
    SelfBlobResourceHead,
    SelfBlobUploadCreate,
    SelfEventsQueryScan,
    SelfEventsStreamSubscribe,
    SelfSnapshotQueryManifestHead,
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
        Self::AgentSelectorClaim,
        Self::AgentSidecarExchangeControl,
        Self::AgentSidecarPublish,
        Self::AgentSidecarWrite,
        Self::ApprovalVote,
        Self::AuditAccessed,
        Self::AuditAppletBinding,
        Self::AuditExport,
        Self::AuditQuery,
        Self::AuditRelease,
        Self::AuditSessionAuthorize,
        Self::AuditSessionClose,
        Self::AuditSessionNotice,
        Self::AuditSessionRequest,
        Self::CallJoin,
        Self::CallModerate,
        Self::CallRecord,
        Self::CallScreenShare,
        Self::CallSignalSend,
        Self::CallTranscribe,
        Self::CapabilityDelegate,
        Self::CapabilityDerived,
        Self::CapabilityGrant,
        Self::CapabilityRevoke,
        Self::CircleAudit,
        Self::CircleCreate,
        Self::CircleManage,
        Self::CircleMemberAdd,
        Self::CircleMemberAddOthers,
        Self::CircleMemberManage,
        Self::ContainerMoveItem,
        Self::ContainerRebalance,
        Self::EventRead,
        Self::InviteAccept,
        Self::InviteCancel,
        Self::InviteClaim,
        Self::InviteCreate,
        Self::InviteRevoke,
        Self::InviteThirdParty,
        Self::MessageCreate,
        Self::MessageMentionBroadcast,
        Self::MessageRedact,
        Self::MessageRedactOwn,
        Self::MessageRevise,
        Self::MessageReviseOwn,
        Self::MlsCommit,
        Self::MlsGenesis,
        Self::MlsKeypackage,
        Self::MlsProposal,
        Self::MlsWelcome,
        Self::ModerationAppealReview,
        Self::ModerationAppealSubmit,
        Self::ModerationDecision,
        Self::ModerationDecisionLift,
        Self::MorphArchive,
        Self::MorphCreate,
        Self::MorphRead,
        Self::MorphRestore,
        Self::MorphSchemaMigrate,
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
        Self::PolicyRule,
        Self::PolicySet,
        Self::PresenceBroadcast,
        Self::ReactionAdd,
        Self::ReactionRemove,
        Self::ReadCursorAdvance,
        Self::RealmAdmin,
        Self::RealmArchive,
        Self::RealmCreate,
        Self::RealmDestroy,
        Self::RealmDisappearingPolicy,
        Self::RealmDiscover,
        Self::RealmFreeze,
        Self::RealmJoinReview,
        Self::RealmLink,
        Self::RealmMediaService,
        Self::RealmModerationPolicy,
        Self::RealmNotificationAudit,
        Self::RealmPlaintextVisibleServices,
        Self::RealmPreviewPolicy,
        Self::RealmSearchPolicy,
        Self::RealmSetDefaultStrand,
        Self::RealmTombstone,
        Self::RealmUpdate,
        Self::RealmUpgrade,
        Self::RealmKeyShare,
        Self::ReceiptBroadcast,
        Self::RelationCreate,
        Self::RelationTombstone,
        Self::RelationUpdate,
        Self::RsvpSet,
        Self::SchemaDefine,
        Self::SchemaUpdate,
        Self::SelfAccountQueryDescribe,
        Self::SelfAccountStreamSubscribe,
        Self::SelfAgentCommandDeactivate,
        Self::SelfAgentCommandPause,
        Self::SelfAgentCommandProvision,
        Self::SelfAgentCommandRenewPairing,
        Self::SelfAgentCommandResume,
        Self::SelfAgentGrantCommandAttach,
        Self::SelfAgentGrantResourceDelete,
        Self::SelfAgentParticipationResourceReplace,
        Self::SelfAgentSidecarCommandEnsure,
        Self::SelfBlobCommandPresign,
        Self::SelfBlobResourceGet,
        Self::SelfBlobResourceHead,
        Self::SelfBlobUploadCreate,
        Self::SelfEventsQueryScan,
        Self::SelfEventsStreamSubscribe,
        Self::SelfSnapshotQueryManifestHead,
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
    pub const AGENT_SELECTOR_CLAIM: &'static str = "ak.agent.selector_claim";
    pub const AGENT_SIDECAR_EXCHANGE_CONTROL: &'static str = "ak.agent.sidecar.exchange.control";
    pub const AGENT_SIDECAR_PUBLISH: &'static str = "ak.agent.sidecar.publish";
    pub const AGENT_SIDECAR_WRITE: &'static str = "ak.agent.sidecar.write";
    pub const APPROVAL_VOTE: &'static str = "ak.approval.vote";
    pub const AUDIT_ACCESSED: &'static str = "ak.audit.accessed";
    pub const AUDIT_APPLET_BINDING: &'static str = "ak.audit.applet_binding";
    pub const AUDIT_EXPORT: &'static str = "ak.audit.export";
    pub const AUDIT_QUERY: &'static str = "ak.audit.query";
    pub const AUDIT_RELEASE: &'static str = "ak.audit.release";
    pub const AUDIT_SESSION_AUTHORIZE: &'static str = "ak.audit.session.authorize";
    pub const AUDIT_SESSION_CLOSE: &'static str = "ak.audit.session.close";
    pub const AUDIT_SESSION_NOTICE: &'static str = "ak.audit.session.notice";
    pub const AUDIT_SESSION_REQUEST: &'static str = "ak.audit.session.request";
    pub const CALL_JOIN: &'static str = "ak.call.join";
    pub const CALL_MODERATE: &'static str = "ak.call.moderate";
    pub const CALL_RECORD: &'static str = "ak.call.record";
    pub const CALL_SCREEN_SHARE: &'static str = "ak.call.screen_share";
    pub const CALL_SIGNAL_SEND: &'static str = "ak.call.signal.send";
    pub const CALL_TRANSCRIBE: &'static str = "ak.call.transcribe";
    pub const CAPABILITY_DELEGATE: &'static str = "ak.capability.delegate";
    pub const CAPABILITY_DERIVED: &'static str = "ak.capability.derived";
    pub const CAPABILITY_GRANT: &'static str = "ak.capability.grant";
    pub const CAPABILITY_REVOKE: &'static str = "ak.capability.revoke";
    pub const CIRCLE_AUDIT: &'static str = "ak.circle.audit";
    pub const CIRCLE_CREATE: &'static str = "ak.circle.create";
    pub const CIRCLE_MANAGE: &'static str = "ak.circle.manage";
    pub const CIRCLE_MEMBER_ADD: &'static str = "ak.circle.member.add";
    pub const CIRCLE_MEMBER_ADD_OTHERS: &'static str = "ak.circle.member.add.others";
    pub const CIRCLE_MEMBER_MANAGE: &'static str = "ak.circle.member.manage";
    pub const CONTAINER_MOVE_ITEM: &'static str = "ak.container.move_item";
    pub const CONTAINER_REBALANCE: &'static str = "ak.container.rebalance";
    pub const EVENT_READ: &'static str = "ak.event.read";
    pub const INVITE_ACCEPT: &'static str = "ak.invite.accept";
    pub const INVITE_CANCEL: &'static str = "ak.invite.cancel";
    pub const INVITE_CLAIM: &'static str = "ak.invite.claim";
    pub const INVITE_CREATE: &'static str = "ak.invite.create";
    pub const INVITE_REVOKE: &'static str = "ak.invite.revoke";
    pub const INVITE_THIRD_PARTY: &'static str = "ak.invite.third_party";
    pub const MESSAGE_CREATE: &'static str = "ak.message.create";
    pub const MESSAGE_MENTION_BROADCAST: &'static str = "ak.message.mention.broadcast";
    pub const MESSAGE_REDACT: &'static str = "ak.message.redact";
    pub const MESSAGE_REDACT_OWN: &'static str = "ak.message.redact.own";
    pub const MESSAGE_REVISE: &'static str = "ak.message.revise";
    pub const MESSAGE_REVISE_OWN: &'static str = "ak.message.revise.own";
    pub const MLS_COMMIT: &'static str = "ak.mls.commit";
    pub const MLS_GENESIS: &'static str = "ak.mls.genesis";
    pub const MLS_KEYPACKAGE: &'static str = "ak.mls.keypackage";
    pub const MLS_PROPOSAL: &'static str = "ak.mls.proposal";
    pub const MLS_WELCOME: &'static str = "ak.mls.welcome";
    pub const MODERATION_APPEAL_REVIEW: &'static str = "ak.moderation.appeal.review";
    pub const MODERATION_APPEAL_SUBMIT: &'static str = "ak.moderation.appeal.submit";
    pub const MODERATION_DECISION: &'static str = "ak.moderation.decision";
    pub const MODERATION_DECISION_LIFT: &'static str = "ak.moderation.decision.lift";
    pub const MORPH_ARCHIVE: &'static str = "ak.morph.archive";
    pub const MORPH_CREATE: &'static str = "ak.morph.create";
    pub const MORPH_READ: &'static str = "ak.morph.read";
    pub const MORPH_RESTORE: &'static str = "ak.morph.restore";
    pub const MORPH_SCHEMA_MIGRATE: &'static str = "ak.morph.schema_migrate";
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
    pub const POLICY_RULE: &'static str = "ak.policy.rule";
    pub const POLICY_SET: &'static str = "ak.policy.set";
    pub const PRESENCE_BROADCAST: &'static str = "ak.presence.broadcast";
    pub const REACTION_ADD: &'static str = "ak.reaction.add";
    pub const REACTION_REMOVE: &'static str = "ak.reaction.remove";
    pub const READ_CURSOR_ADVANCE: &'static str = "ak.read_cursor.advance";
    pub const REALM_ADMIN: &'static str = "ak.realm.admin";
    pub const REALM_ARCHIVE: &'static str = "ak.realm.archive";
    pub const REALM_CREATE: &'static str = "ak.realm.create";
    pub const REALM_DESTROY: &'static str = "ak.realm.destroy";
    pub const REALM_DISAPPEARING_POLICY: &'static str = "ak.realm.disappearing_policy";
    pub const REALM_DISCOVER: &'static str = "ak.realm.discover";
    pub const REALM_FREEZE: &'static str = "ak.realm.freeze";
    pub const REALM_JOIN_REVIEW: &'static str = "ak.realm.join.review";
    pub const REALM_LINK: &'static str = "ak.realm.link";
    pub const REALM_MEDIA_SERVICE: &'static str = "ak.realm.media_service";
    pub const REALM_MODERATION_POLICY: &'static str = "ak.realm.moderation_policy";
    pub const REALM_NOTIFICATION_AUDIT: &'static str = "ak.realm.notification.audit";
    pub const REALM_PLAINTEXT_VISIBLE_SERVICES: &'static str =
        "ak.realm.plaintext_visible_services";
    pub const REALM_PREVIEW_POLICY: &'static str = "ak.realm.preview_policy";
    pub const REALM_SEARCH_POLICY: &'static str = "ak.realm.search_policy";
    pub const REALM_SET_DEFAULT_STRAND: &'static str = "ak.realm.set_default_strand";
    pub const REALM_TOMBSTONE: &'static str = "ak.realm.tombstone";
    pub const REALM_UPDATE: &'static str = "ak.realm.update";
    pub const REALM_UPGRADE: &'static str = "ak.realm.upgrade";
    pub const REALM_KEY_SHARE: &'static str = "ak.realm_key.share";
    pub const RECEIPT_BROADCAST: &'static str = "ak.receipt.broadcast";
    pub const RELATION_CREATE: &'static str = "ak.relation.create";
    pub const RELATION_TOMBSTONE: &'static str = "ak.relation.tombstone";
    pub const RELATION_UPDATE: &'static str = "ak.relation.update";
    pub const RSVP_SET: &'static str = "ak.rsvp.set";
    pub const SCHEMA_DEFINE: &'static str = "ak.schema.define";
    pub const SCHEMA_UPDATE: &'static str = "ak.schema.update";
    pub const SELF_ACCOUNT_QUERY_DESCRIBE: &'static str = "ak.self.account.query.describe";
    pub const SELF_ACCOUNT_STREAM_SUBSCRIBE: &'static str = "ak.self.account.stream.subscribe";
    pub const SELF_AGENT_COMMAND_DEACTIVATE: &'static str = "ak.self.agent.command.deactivate";
    pub const SELF_AGENT_COMMAND_PAUSE: &'static str = "ak.self.agent.command.pause";
    pub const SELF_AGENT_COMMAND_PROVISION: &'static str = "ak.self.agent.command.provision";
    pub const SELF_AGENT_COMMAND_RENEW_PAIRING: &'static str =
        "ak.self.agent.command.renew_pairing";
    pub const SELF_AGENT_COMMAND_RESUME: &'static str = "ak.self.agent.command.resume";
    pub const SELF_AGENT_GRANT_COMMAND_ATTACH: &'static str = "ak.self.agent.grant.command.attach";
    pub const SELF_AGENT_GRANT_RESOURCE_DELETE: &'static str =
        "ak.self.agent.grant.resource.delete";
    pub const SELF_AGENT_PARTICIPATION_RESOURCE_REPLACE: &'static str =
        "ak.self.agent.participation.resource.replace";
    pub const SELF_AGENT_SIDECAR_COMMAND_ENSURE: &'static str =
        "ak.self.agent.sidecar.command.ensure";
    pub const SELF_BLOB_COMMAND_PRESIGN: &'static str = "ak.self.blob.command.presign";
    pub const SELF_BLOB_RESOURCE_GET: &'static str = "ak.self.blob.resource.get";
    pub const SELF_BLOB_RESOURCE_HEAD: &'static str = "ak.self.blob.resource.head";
    pub const SELF_BLOB_UPLOAD_CREATE: &'static str = "ak.self.blob.upload.create";
    pub const SELF_EVENTS_QUERY_SCAN: &'static str = "ak.self.events.query.scan";
    pub const SELF_EVENTS_STREAM_SUBSCRIBE: &'static str = "ak.self.events.stream.subscribe";
    pub const SELF_SNAPSHOT_QUERY_MANIFEST_HEAD: &'static str =
        "ak.self.snapshot.query.manifest_head";
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
            Self::AgentActionApprove => "ak.agent.action_approve",
            Self::AgentActionReject => "ak.agent.action_reject",
            Self::AgentActionRequest => "ak.agent.action_request",
            Self::AgentDraftPropose => "ak.agent.draft.propose",
            Self::AgentKeyAuthorize => "ak.agent.key.authorize",
            Self::AgentKeyRevoke => "ak.agent.key.revoke",
            Self::AgentSelectorClaim => "ak.agent.selector_claim",
            Self::AgentSidecarExchangeControl => "ak.agent.sidecar.exchange.control",
            Self::AgentSidecarPublish => "ak.agent.sidecar.publish",
            Self::AgentSidecarWrite => "ak.agent.sidecar.write",
            Self::ApprovalVote => "ak.approval.vote",
            Self::AuditAccessed => "ak.audit.accessed",
            Self::AuditAppletBinding => "ak.audit.applet_binding",
            Self::AuditExport => "ak.audit.export",
            Self::AuditQuery => "ak.audit.query",
            Self::AuditRelease => "ak.audit.release",
            Self::AuditSessionAuthorize => "ak.audit.session.authorize",
            Self::AuditSessionClose => "ak.audit.session.close",
            Self::AuditSessionNotice => "ak.audit.session.notice",
            Self::AuditSessionRequest => "ak.audit.session.request",
            Self::CallJoin => "ak.call.join",
            Self::CallModerate => "ak.call.moderate",
            Self::CallRecord => "ak.call.record",
            Self::CallScreenShare => "ak.call.screen_share",
            Self::CallSignalSend => "ak.call.signal.send",
            Self::CallTranscribe => "ak.call.transcribe",
            Self::CapabilityDelegate => "ak.capability.delegate",
            Self::CapabilityDerived => "ak.capability.derived",
            Self::CapabilityGrant => "ak.capability.grant",
            Self::CapabilityRevoke => "ak.capability.revoke",
            Self::CircleAudit => "ak.circle.audit",
            Self::CircleCreate => "ak.circle.create",
            Self::CircleManage => "ak.circle.manage",
            Self::CircleMemberAdd => "ak.circle.member.add",
            Self::CircleMemberAddOthers => "ak.circle.member.add.others",
            Self::CircleMemberManage => "ak.circle.member.manage",
            Self::ContainerMoveItem => "ak.container.move_item",
            Self::ContainerRebalance => "ak.container.rebalance",
            Self::EventRead => "ak.event.read",
            Self::InviteAccept => "ak.invite.accept",
            Self::InviteCancel => "ak.invite.cancel",
            Self::InviteClaim => "ak.invite.claim",
            Self::InviteCreate => "ak.invite.create",
            Self::InviteRevoke => "ak.invite.revoke",
            Self::InviteThirdParty => "ak.invite.third_party",
            Self::MessageCreate => "ak.message.create",
            Self::MessageMentionBroadcast => "ak.message.mention.broadcast",
            Self::MessageRedact => "ak.message.redact",
            Self::MessageRedactOwn => "ak.message.redact.own",
            Self::MessageRevise => "ak.message.revise",
            Self::MessageReviseOwn => "ak.message.revise.own",
            Self::MlsCommit => "ak.mls.commit",
            Self::MlsGenesis => "ak.mls.genesis",
            Self::MlsKeypackage => "ak.mls.keypackage",
            Self::MlsProposal => "ak.mls.proposal",
            Self::MlsWelcome => "ak.mls.welcome",
            Self::ModerationAppealReview => "ak.moderation.appeal.review",
            Self::ModerationAppealSubmit => "ak.moderation.appeal.submit",
            Self::ModerationDecision => "ak.moderation.decision",
            Self::ModerationDecisionLift => "ak.moderation.decision.lift",
            Self::MorphArchive => "ak.morph.archive",
            Self::MorphCreate => "ak.morph.create",
            Self::MorphRead => "ak.morph.read",
            Self::MorphRestore => "ak.morph.restore",
            Self::MorphSchemaMigrate => "ak.morph.schema_migrate",
            Self::MorphStageSet => "ak.morph.stage.set",
            Self::MorphUpdate => "ak.morph.update",
            Self::NotificationAck => "ak.notification.ack",
            Self::NotificationRead => "ak.notification.read",
            Self::ObjectArchive => "ak.object.archive",
            Self::ObjectRead => "ak.object.read",
            Self::ObjectReadContent => "ak.object.read_content",
            Self::ObjectReadHistory => "ak.object.read_history",
            Self::ObjectReadMetadata => "ak.object.read_metadata",
            Self::ObjectRestore => "ak.object.restore",
            Self::ObjectStageSet => "ak.object.stage.set",
            Self::PinAdd => "ak.pin.add",
            Self::PinRemove => "ak.pin.remove",
            Self::PinReorder => "ak.pin.reorder",
            Self::PolicyAction => "ak.policy.action",
            Self::PolicyManage => "ak.policy.manage",
            Self::PolicyRule => "ak.policy.rule",
            Self::PolicySet => "ak.policy.set",
            Self::PresenceBroadcast => "ak.presence.broadcast",
            Self::ReactionAdd => "ak.reaction.add",
            Self::ReactionRemove => "ak.reaction.remove",
            Self::ReadCursorAdvance => "ak.read_cursor.advance",
            Self::RealmAdmin => "ak.realm.admin",
            Self::RealmArchive => "ak.realm.archive",
            Self::RealmCreate => "ak.realm.create",
            Self::RealmDestroy => "ak.realm.destroy",
            Self::RealmDisappearingPolicy => "ak.realm.disappearing_policy",
            Self::RealmDiscover => "ak.realm.discover",
            Self::RealmFreeze => "ak.realm.freeze",
            Self::RealmJoinReview => "ak.realm.join.review",
            Self::RealmLink => "ak.realm.link",
            Self::RealmMediaService => "ak.realm.media_service",
            Self::RealmModerationPolicy => "ak.realm.moderation_policy",
            Self::RealmNotificationAudit => "ak.realm.notification.audit",
            Self::RealmPlaintextVisibleServices => "ak.realm.plaintext_visible_services",
            Self::RealmPreviewPolicy => "ak.realm.preview_policy",
            Self::RealmSearchPolicy => "ak.realm.search_policy",
            Self::RealmSetDefaultStrand => "ak.realm.set_default_strand",
            Self::RealmTombstone => "ak.realm.tombstone",
            Self::RealmUpdate => "ak.realm.update",
            Self::RealmUpgrade => "ak.realm.upgrade",
            Self::RealmKeyShare => "ak.realm_key.share",
            Self::ReceiptBroadcast => "ak.receipt.broadcast",
            Self::RelationCreate => "ak.relation.create",
            Self::RelationTombstone => "ak.relation.tombstone",
            Self::RelationUpdate => "ak.relation.update",
            Self::RsvpSet => "ak.rsvp.set",
            Self::SchemaDefine => "ak.schema.define",
            Self::SchemaUpdate => "ak.schema.update",
            Self::SelfAccountQueryDescribe => "ak.self.account.query.describe",
            Self::SelfAccountStreamSubscribe => "ak.self.account.stream.subscribe",
            Self::SelfAgentCommandDeactivate => "ak.self.agent.command.deactivate",
            Self::SelfAgentCommandPause => "ak.self.agent.command.pause",
            Self::SelfAgentCommandProvision => "ak.self.agent.command.provision",
            Self::SelfAgentCommandRenewPairing => "ak.self.agent.command.renew_pairing",
            Self::SelfAgentCommandResume => "ak.self.agent.command.resume",
            Self::SelfAgentGrantCommandAttach => "ak.self.agent.grant.command.attach",
            Self::SelfAgentGrantResourceDelete => "ak.self.agent.grant.resource.delete",
            Self::SelfAgentParticipationResourceReplace => {
                "ak.self.agent.participation.resource.replace"
            }
            Self::SelfAgentSidecarCommandEnsure => "ak.self.agent.sidecar.command.ensure",
            Self::SelfBlobCommandPresign => "ak.self.blob.command.presign",
            Self::SelfBlobResourceGet => "ak.self.blob.resource.get",
            Self::SelfBlobResourceHead => "ak.self.blob.resource.head",
            Self::SelfBlobUploadCreate => "ak.self.blob.upload.create",
            Self::SelfEventsQueryScan => "ak.self.events.query.scan",
            Self::SelfEventsStreamSubscribe => "ak.self.events.stream.subscribe",
            Self::SelfSnapshotQueryManifestHead => "ak.self.snapshot.query.manifest_head",
            Self::SpaceArchive => "ak.space.archive",
            Self::SpaceCreate => "ak.space.create",
            Self::SpaceParent => "ak.space.parent",
            Self::SpaceRestore => "ak.space.restore",
            Self::SpaceTombstone => "ak.space.tombstone",
            Self::SpaceUpdate => "ak.space.update",
            Self::StrandAdmin => "ak.strand.admin",
            Self::StrandArchive => "ak.strand.archive",
            Self::StrandCreate => "ak.strand.create",
            Self::StrandMove => "ak.strand.move",
            Self::StrandRead => "ak.strand.read",
            Self::StrandReorder => "ak.strand.reorder",
            Self::StrandRestore => "ak.strand.restore",
            Self::StrandStageSet => "ak.strand.stage.set",
            Self::StrandTracksUpdate => "ak.strand.tracks.update",
            Self::StrandUpdate => "ak.strand.update",
            Self::StrandWatchSet => "ak.strand.watch.set",
            Self::StrandWatchSetOthers => "ak.strand.watch.set.others",
            Self::TypingBroadcast => "ak.typing.broadcast",
            Self::ViewCreate => "ak.view.create",
            Self::ViewReconcile => "ak.view.reconcile",
            Self::ViewUpdate => "ak.view.update",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "ak.agent.action_approve" => Some(Self::AgentActionApprove),
            "ak.agent.action_reject" => Some(Self::AgentActionReject),
            "ak.agent.action_request" => Some(Self::AgentActionRequest),
            "ak.agent.draft.propose" => Some(Self::AgentDraftPropose),
            "ak.agent.key.authorize" => Some(Self::AgentKeyAuthorize),
            "ak.agent.key.revoke" => Some(Self::AgentKeyRevoke),
            "ak.agent.selector_claim" => Some(Self::AgentSelectorClaim),
            "ak.agent.sidecar.exchange.control" => Some(Self::AgentSidecarExchangeControl),
            "ak.agent.sidecar.publish" => Some(Self::AgentSidecarPublish),
            "ak.agent.sidecar.write" => Some(Self::AgentSidecarWrite),
            "ak.approval.vote" => Some(Self::ApprovalVote),
            "ak.audit.accessed" => Some(Self::AuditAccessed),
            "ak.audit.applet_binding" => Some(Self::AuditAppletBinding),
            "ak.audit.export" => Some(Self::AuditExport),
            "ak.audit.query" => Some(Self::AuditQuery),
            "ak.audit.release" => Some(Self::AuditRelease),
            "ak.audit.session.authorize" => Some(Self::AuditSessionAuthorize),
            "ak.audit.session.close" => Some(Self::AuditSessionClose),
            "ak.audit.session.notice" => Some(Self::AuditSessionNotice),
            "ak.audit.session.request" => Some(Self::AuditSessionRequest),
            "ak.call.join" => Some(Self::CallJoin),
            "ak.call.moderate" => Some(Self::CallModerate),
            "ak.call.record" => Some(Self::CallRecord),
            "ak.call.screen_share" => Some(Self::CallScreenShare),
            "ak.call.signal.send" => Some(Self::CallSignalSend),
            "ak.call.transcribe" => Some(Self::CallTranscribe),
            "ak.capability.delegate" => Some(Self::CapabilityDelegate),
            "ak.capability.derived" => Some(Self::CapabilityDerived),
            "ak.capability.grant" => Some(Self::CapabilityGrant),
            "ak.capability.revoke" => Some(Self::CapabilityRevoke),
            "ak.circle.audit" => Some(Self::CircleAudit),
            "ak.circle.create" => Some(Self::CircleCreate),
            "ak.circle.manage" => Some(Self::CircleManage),
            "ak.circle.member.add" => Some(Self::CircleMemberAdd),
            "ak.circle.member.add.others" => Some(Self::CircleMemberAddOthers),
            "ak.circle.member.manage" => Some(Self::CircleMemberManage),
            "ak.container.move_item" => Some(Self::ContainerMoveItem),
            "ak.container.rebalance" => Some(Self::ContainerRebalance),
            "ak.event.read" => Some(Self::EventRead),
            "ak.invite.accept" => Some(Self::InviteAccept),
            "ak.invite.cancel" => Some(Self::InviteCancel),
            "ak.invite.claim" => Some(Self::InviteClaim),
            "ak.invite.create" => Some(Self::InviteCreate),
            "ak.invite.revoke" => Some(Self::InviteRevoke),
            "ak.invite.third_party" => Some(Self::InviteThirdParty),
            "ak.message.create" => Some(Self::MessageCreate),
            "ak.message.mention.broadcast" => Some(Self::MessageMentionBroadcast),
            "ak.message.redact" => Some(Self::MessageRedact),
            "ak.message.redact.own" => Some(Self::MessageRedactOwn),
            "ak.message.revise" => Some(Self::MessageRevise),
            "ak.message.revise.own" => Some(Self::MessageReviseOwn),
            "ak.mls.commit" => Some(Self::MlsCommit),
            "ak.mls.genesis" => Some(Self::MlsGenesis),
            "ak.mls.keypackage" => Some(Self::MlsKeypackage),
            "ak.mls.proposal" => Some(Self::MlsProposal),
            "ak.mls.welcome" => Some(Self::MlsWelcome),
            "ak.moderation.appeal.review" => Some(Self::ModerationAppealReview),
            "ak.moderation.appeal.submit" => Some(Self::ModerationAppealSubmit),
            "ak.moderation.decision" => Some(Self::ModerationDecision),
            "ak.moderation.decision.lift" => Some(Self::ModerationDecisionLift),
            "ak.morph.archive" => Some(Self::MorphArchive),
            "ak.morph.create" => Some(Self::MorphCreate),
            "ak.morph.read" => Some(Self::MorphRead),
            "ak.morph.restore" => Some(Self::MorphRestore),
            "ak.morph.schema_migrate" => Some(Self::MorphSchemaMigrate),
            "ak.morph.stage.set" => Some(Self::MorphStageSet),
            "ak.morph.update" => Some(Self::MorphUpdate),
            "ak.notification.ack" => Some(Self::NotificationAck),
            "ak.notification.read" => Some(Self::NotificationRead),
            "ak.object.archive" => Some(Self::ObjectArchive),
            "ak.object.read" => Some(Self::ObjectRead),
            "ak.object.read_content" => Some(Self::ObjectReadContent),
            "ak.object.read_history" => Some(Self::ObjectReadHistory),
            "ak.object.read_metadata" => Some(Self::ObjectReadMetadata),
            "ak.object.restore" => Some(Self::ObjectRestore),
            "ak.object.stage.set" => Some(Self::ObjectStageSet),
            "ak.pin.add" => Some(Self::PinAdd),
            "ak.pin.remove" => Some(Self::PinRemove),
            "ak.pin.reorder" => Some(Self::PinReorder),
            "ak.policy.action" => Some(Self::PolicyAction),
            "ak.policy.manage" => Some(Self::PolicyManage),
            "ak.policy.rule" => Some(Self::PolicyRule),
            "ak.policy.set" => Some(Self::PolicySet),
            "ak.presence.broadcast" => Some(Self::PresenceBroadcast),
            "ak.reaction.add" => Some(Self::ReactionAdd),
            "ak.reaction.remove" => Some(Self::ReactionRemove),
            "ak.read_cursor.advance" => Some(Self::ReadCursorAdvance),
            "ak.realm.admin" => Some(Self::RealmAdmin),
            "ak.realm.archive" => Some(Self::RealmArchive),
            "ak.realm.create" => Some(Self::RealmCreate),
            "ak.realm.destroy" => Some(Self::RealmDestroy),
            "ak.realm.disappearing_policy" => Some(Self::RealmDisappearingPolicy),
            "ak.realm.discover" => Some(Self::RealmDiscover),
            "ak.realm.freeze" => Some(Self::RealmFreeze),
            "ak.realm.join.review" => Some(Self::RealmJoinReview),
            "ak.realm.link" => Some(Self::RealmLink),
            "ak.realm.media_service" => Some(Self::RealmMediaService),
            "ak.realm.moderation_policy" => Some(Self::RealmModerationPolicy),
            "ak.realm.notification.audit" => Some(Self::RealmNotificationAudit),
            "ak.realm.plaintext_visible_services" => Some(Self::RealmPlaintextVisibleServices),
            "ak.realm.preview_policy" => Some(Self::RealmPreviewPolicy),
            "ak.realm.search_policy" => Some(Self::RealmSearchPolicy),
            "ak.realm.set_default_strand" => Some(Self::RealmSetDefaultStrand),
            "ak.realm.tombstone" => Some(Self::RealmTombstone),
            "ak.realm.update" => Some(Self::RealmUpdate),
            "ak.realm.upgrade" => Some(Self::RealmUpgrade),
            "ak.realm_key.share" => Some(Self::RealmKeyShare),
            "ak.receipt.broadcast" => Some(Self::ReceiptBroadcast),
            "ak.relation.create" => Some(Self::RelationCreate),
            "ak.relation.tombstone" => Some(Self::RelationTombstone),
            "ak.relation.update" => Some(Self::RelationUpdate),
            "ak.rsvp.set" => Some(Self::RsvpSet),
            "ak.schema.define" => Some(Self::SchemaDefine),
            "ak.schema.update" => Some(Self::SchemaUpdate),
            "ak.self.account.query.describe" => Some(Self::SelfAccountQueryDescribe),
            "ak.self.account.stream.subscribe" => Some(Self::SelfAccountStreamSubscribe),
            "ak.self.agent.command.deactivate" => Some(Self::SelfAgentCommandDeactivate),
            "ak.self.agent.command.pause" => Some(Self::SelfAgentCommandPause),
            "ak.self.agent.command.provision" => Some(Self::SelfAgentCommandProvision),
            "ak.self.agent.command.renew_pairing" => Some(Self::SelfAgentCommandRenewPairing),
            "ak.self.agent.command.resume" => Some(Self::SelfAgentCommandResume),
            "ak.self.agent.grant.command.attach" => Some(Self::SelfAgentGrantCommandAttach),
            "ak.self.agent.grant.resource.delete" => Some(Self::SelfAgentGrantResourceDelete),
            "ak.self.agent.participation.resource.replace" => {
                Some(Self::SelfAgentParticipationResourceReplace)
            }
            "ak.self.agent.sidecar.command.ensure" => Some(Self::SelfAgentSidecarCommandEnsure),
            "ak.self.blob.command.presign" => Some(Self::SelfBlobCommandPresign),
            "ak.self.blob.resource.get" => Some(Self::SelfBlobResourceGet),
            "ak.self.blob.resource.head" => Some(Self::SelfBlobResourceHead),
            "ak.self.blob.upload.create" => Some(Self::SelfBlobUploadCreate),
            "ak.self.events.query.scan" => Some(Self::SelfEventsQueryScan),
            "ak.self.events.stream.subscribe" => Some(Self::SelfEventsStreamSubscribe),
            "ak.self.snapshot.query.manifest_head" => Some(Self::SelfSnapshotQueryManifestHead),
            "ak.space.archive" => Some(Self::SpaceArchive),
            "ak.space.create" => Some(Self::SpaceCreate),
            "ak.space.parent" => Some(Self::SpaceParent),
            "ak.space.restore" => Some(Self::SpaceRestore),
            "ak.space.tombstone" => Some(Self::SpaceTombstone),
            "ak.space.update" => Some(Self::SpaceUpdate),
            "ak.strand.admin" => Some(Self::StrandAdmin),
            "ak.strand.archive" => Some(Self::StrandArchive),
            "ak.strand.create" => Some(Self::StrandCreate),
            "ak.strand.move" => Some(Self::StrandMove),
            "ak.strand.read" => Some(Self::StrandRead),
            "ak.strand.reorder" => Some(Self::StrandReorder),
            "ak.strand.restore" => Some(Self::StrandRestore),
            "ak.strand.stage.set" => Some(Self::StrandStageSet),
            "ak.strand.tracks.update" => Some(Self::StrandTracksUpdate),
            "ak.strand.update" => Some(Self::StrandUpdate),
            "ak.strand.watch.set" => Some(Self::StrandWatchSet),
            "ak.strand.watch.set.others" => Some(Self::StrandWatchSetOthers),
            "ak.typing.broadcast" => Some(Self::TypingBroadcast),
            "ak.view.create" => Some(Self::ViewCreate),
            "ak.view.reconcile" => Some(Self::ViewReconcile),
            "ak.view.update" => Some(Self::ViewUpdate),
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
