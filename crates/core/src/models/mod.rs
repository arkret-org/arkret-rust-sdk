use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub use arkret_identifiers::{
    ActorProfileId, AppletId, AttestationId, AuditBindingId, AuditReleaseId, AuditSessionId,
    BackupId, BackupSeriesId, BatchId, BlobId, BlobRef, BlockId, CallId, CapabilityId, ChunkId,
    CircleId, ClaimId, Cursor, DeviceId, DeviceMessageId, Did, EventId, FilterId, FrameId,
    FrankingProofId, GrantId, Hash, Hlc, InviteId, KeyEventId, MessageId, ModerationQueueItemId,
    MorphId, NotificationId, OperationId, PolicyId, PresentationId, ReadCursorId, RealmId,
    ReceiptId, RecoverySessionId, RelationId, ReportId, RequestId, RtcParticipantId, SnapshotId,
    SpaceId, StrandId, TransactionId, TypedAppealId, TypedTrustDomainId, ViewId,
    new_prefixed_uuid7,
};
pub use arkret_wire_base::{EvaluationClass, ServiceType, XExtensionMap};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{Error, Result, SealId, canonical};

mod account;
mod actor_profile;
mod agent;
mod agent_participation;
mod applet;
mod applet_install_plan;
mod artifacts;
mod attestation;
mod authorization;
mod blob;
mod circle;
mod conformance;
mod constants {
    pub use arkret_wire_base::constants::*;
}
mod cross_signing;
mod delivery_binding;
mod device_verification;
mod did_continuity;
mod direct_conversation;
mod directory;
mod ephemeral;
mod event_query;
mod event_sync;
mod events;
mod federation;
mod federation_wire;
mod governance_payloads;
mod handle;
mod history_visibility;
mod identity;
mod identity_link_cache;
mod invite_addressing;
mod key_backup;
mod keys;
mod media;
mod member_delivery_binding_candidate;
mod member_identity;
mod mention;
mod mimi;
mod mls_governance_proof;
mod mls_payloads;
mod moderation;
mod moderation_appeal;
mod moderation_queue;
mod object_address {
    pub use arkret_wire_base::object_address::*;
}
mod object_lifecycle;
mod operation;
mod operation_payloads;
mod patch;
mod peer_contact;
mod policy_check;
mod primitives {
    pub use arkret_wire_base::primitives::*;
}
mod problem_details {
    pub use arkret_wire_base::problem_details::*;
}
pub mod product;
mod productivity;
mod profiles;
mod push {
    pub use arkret_wire_edge::models_push::*;
}
mod queries;
mod query_projection;
mod realm;
mod realm_alias;
mod realm_governance;
mod registry;
mod relation;
mod resource_selector;
mod runtime_identity;
mod service_description {
    pub use arkret_wire_edge::service_description::*;
}
mod space;
mod strand;
mod sync;
#[cfg(test)]
mod tests;
mod third_party_invite;
#[cfg(test)]
mod wire_dto_tests;
#[cfg(test)]
mod wire_model_tests;
mod wire_strings;

pub use account::*;
pub use actor_profile::*;
pub use agent::*;
pub use agent_participation::*;
pub use applet::*;
pub use applet_install_plan::*;
pub use arkret_wire_edge::{
    AccessKind, AuditPolicyAccessPayload, InviteReceiveAction, PlaintextDataClassKind,
    ReceivePolicyConstraints, ReceivePolicySurface, UnknownInviteAction,
};
pub use artifacts::*;
pub use attestation::*;
pub use authorization::*;
pub use blob::*;
pub use circle::*;
pub use conformance::*;
pub use constants::*;
pub use cross_signing::*;
pub use delivery_binding::*;
pub use device_verification::*;
pub use did_continuity::*;
pub use direct_conversation::*;
pub use directory::*;
pub use ephemeral::*;
pub use event_query::*;
pub use event_sync::*;
pub use events::*;
pub use federation::*;
pub use federation_wire::*;
pub use governance_payloads::*;
pub use handle::*;
pub use history_visibility::*;
pub use identity::*;
pub use identity_link_cache::*;
pub use invite_addressing::*;
pub use key_backup::*;
pub use keys::*;
pub use media::*;
pub use member_delivery_binding_candidate::*;
pub use member_identity::*;
pub use mention::*;
pub use mimi::*;
pub use mls_governance_proof::*;
pub use mls_payloads::*;
pub use moderation::*;
pub use moderation_appeal::*;
pub use moderation_queue::*;
pub use object_address::*;
pub use object_lifecycle::*;
pub use operation::*;
pub use operation_payloads::*;
pub use patch::*;
pub use peer_contact::*;
pub use policy_check::*;
pub use primitives::{proof_kind, *};
pub use problem_details::*;
pub use product::*;
pub use productivity::*;
pub use profiles::*;
pub use push::*;
pub use queries::*;
pub use query_projection::*;
pub use realm::*;
pub use realm_alias::*;
pub use realm_governance::*;
pub use registry::*;
pub use relation::*;
pub use resource_selector::*;
pub use runtime_identity::*;
pub use service_description::*;
pub use space::*;
pub use strand::*;
pub use sync::*;

pub type EventSubmitEnvelope = Event;
pub type FacetName = Facet;
pub type ObjectRef = String;
pub type BooleanFilter = Filter;
pub type QueryFilter = Filter;
pub use third_party_invite::*;
pub use wire_strings::*;

fn is_false(value: &bool) -> bool {
    !*value
}
