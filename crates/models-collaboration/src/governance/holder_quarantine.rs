//! Holder-private Station-written quarantine cells.
//!
//! `ak.account.holder_quarantine` covers both deferred admission surfaces the
//! consent gate holds back — invite delivery and consent requests — so the
//! carrier is named for the holder, not for one of its two surfaces.

use arkret_wire::{AccountId, DidCoreId, EventId, Hash, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

crate::string_marker!(HolderQuarantineSchema, V1, "ak.schema.holder_quarantine.v1");
crate::string_marker!(HolderQuarantineStatus, PendingReview, "pending_review");
crate::string_marker!(HolderQuarantineScope, Invite, "invite");
crate::string_marker!(
    HolderQuarantineInvalidationReason,
    ConsentRevoke,
    "consent_revoke"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum HolderQuarantineIntroductionKind {
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
pub enum HolderQuarantineInvalidationScope {
    Invite,
    Any,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HolderQuarantineEntry {
    pub entry_digest: Hash,
    pub status: HolderQuarantineStatus,
    pub account_id: AccountId,
    pub source_peer_principal_id: DidCoreId,
    pub source_id: DidCoreId,
    pub consent_scope: HolderQuarantineScope,
    pub introduction_kind: HolderQuarantineIntroductionKind,
    pub effective_kind: HolderQuarantineIntroductionKind,
    pub trust_tier: InviteTrustTier,
    pub invite_event_id: EventId,
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
pub struct HolderQuarantineInvalidation {
    pub reason: HolderQuarantineInvalidationReason,
    pub peer_principal_id: DidCoreId,
    pub consent_scope: HolderQuarantineInvalidationScope,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    pub removed_entries: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HolderQuarantine {
    pub schema: HolderQuarantineSchema,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub quarantine_entries: Vec<HolderQuarantineEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_invalidation: Option<HolderQuarantineInvalidation>,
}

impl HolderQuarantine {
    pub fn new(updated_at: DateTime<Utc>) -> Self {
        Self {
            schema: HolderQuarantineSchema::V1,
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
