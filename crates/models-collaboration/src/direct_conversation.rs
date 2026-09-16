//! Direct-conversation lookup over current authority projections.

use arkret_wire::{CommittedEventRef, Hash, RealmId, StrandId};
use serde::{Deserialize, Serialize};

use crate::contact_operations::ContactPeer;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationResolveRequestBody {
    pub peer: ContactPeer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationCoordinates {
    pub pair_key: Hash,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_ref: Option<CommittedEventRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectConversationResolveOutcome {
    CreationRequired,
    AwaitingAuthority {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
    Found {
        coordinates: DirectConversationCoordinates,
    },
    Suspended {
        coordinates: DirectConversationCoordinates,
        reason_code: String,
    },
    TemporarilyUnavailable {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
}
