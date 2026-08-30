//! Holder-private Station-written invite quarantine cells.

use arkret_wire::{AccountId, DidCoreId, EventId, Hash, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

crate::string_marker!(InviteQuarantineSchema, V1, "ak.schema.invite_quarantine.v1");
crate::string_marker!(InviteQuarantineStatus, PendingReview, "pending_review");
crate::string_marker!(InviteQuarantineScope, Invite, "invite");
crate::string_marker!(
    InviteQuarantineInvalidationReason,
    ConsentRevoke,
    "consent_revoke"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum InviteQuarantineIntroductionKind {
    LocatorRef,
    ConsentGrant,
    SharedRealm,
    HandleClaim,
    SameStation,
    ExplicitAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum InviteTrustTier {
    High,
    Discovery,
    Low,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum InviteQuarantineInvalidationScope {
    Invite,
    Any,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteQuarantineEntry {
    pub entry_digest: Hash,
    pub status: InviteQuarantineStatus,
    pub account_id: AccountId,
    pub source_peer_principal_id: DidCoreId,
    pub source_id: DidCoreId,
    pub consent_scope: InviteQuarantineScope,
    pub introduction_kind: InviteQuarantineIntroductionKind,
    pub effective_kind: InviteQuarantineIntroductionKind,
    pub trust_tier: InviteTrustTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_event_id: Option<EventId>,
    pub invite_event_digest: Hash,
    pub request_digest: Hash,
    pub idempotency_key_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteQuarantineInvalidation {
    pub reason: InviteQuarantineInvalidationReason,
    pub peer_principal_id: DidCoreId,
    pub consent_scope: InviteQuarantineInvalidationScope,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    pub removed_entries: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteQuarantine {
    pub schema: InviteQuarantineSchema,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub quarantine_entries: Vec<InviteQuarantineEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_invalidation: Option<InviteQuarantineInvalidation>,
}

impl InviteQuarantine {
    pub fn new(updated_at: DateTime<Utc>) -> Self {
        Self {
            schema: InviteQuarantineSchema::V1,
            updated_at,
            quarantine_entries: Vec::new(),
            last_invalidation: None,
        }
    }

    /// Check the cell against its authenticated holder, not an identity inferred
    /// from the first entry. An empty cell still belongs to one exact account.
    pub fn validate_holder(&self, account_id: &AccountId) -> Result<()> {
        account_id.validate()?;
        let mut digests = std::collections::BTreeSet::new();
        if self.quarantine_entries.len() > 200
            || self
                .quarantine_entries
                .windows(2)
                .any(|pair| pair[0].received_at > pair[1].received_at)
        {
            return Err(WireError::Protocol(
                "invite quarantine must contain at most 200 entries, oldest first".to_owned(),
            ));
        }
        for entry in &self.quarantine_entries {
            if &entry.account_id != account_id
                || entry.received_at >= entry.expires_at
                || entry.received_at > self.updated_at
                || entry.expires_at <= self.updated_at
                || !digests.insert(&entry.entry_digest)
            {
                return Err(WireError::Protocol(
                    "invite quarantine contains a foreign, duplicate, expired, or invalid entry"
                        .to_owned(),
                ));
            }
        }
        if self.last_invalidation.as_ref().is_some_and(|value| {
            !(1..=200).contains(&value.removed_entries) || value.revoked_at > self.updated_at
        }) {
            return Err(WireError::Protocol(
                "invalid invite quarantine revocation diagnostic".to_owned(),
            ));
        }
        Ok(())
    }
}
