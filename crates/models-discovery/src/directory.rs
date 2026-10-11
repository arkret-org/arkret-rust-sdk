//! Public Realm Directory wire models.
//!
//! Directory results are discovery hints only. They never carry membership,
//! join, history, Event/RealmCommit, source-reference, or authority evidence.

use arkret_wire::{BlobRef, RealmId, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

fn invalid(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRealmMetadata {
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_locator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
}

impl PublicRealmMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.display_name.is_empty() || self.display_name.chars().count() > 128 {
            return Err(invalid(
                "public Realm display_name must contain 1..=128 characters",
            ));
        }
        if self
            .summary
            .as_ref()
            .is_some_and(|value| value.chars().count() > 512)
        {
            return Err(invalid("public Realm summary exceeds 512 characters"));
        }
        if self
            .public_locator
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 2048)
        {
            return Err(invalid(
                "public Realm locator must contain 1..=2048 characters",
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRealmDirectoryEntry {
    pub realm_id: RealmId,
    pub public_metadata: PublicRealmMetadata,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub indexed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl PublicRealmDirectoryEntry {
    pub fn validate(&self) -> Result<()> {
        self.public_metadata.validate()?;
        if self.expires_at <= self.indexed_at {
            return Err(invalid(
                "public Realm directory entry must expire after indexing",
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySearchRealmsRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl DirectorySearchRealmsRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self
            .query
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.chars().count() > 128)
            || self.limit.is_some_and(|value| value == 0 || value > 100)
            || self
                .cursor
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 2048)
        {
            return Err(invalid("invalid public Realm directory search selector"));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRealmSearchOutcome {
    pub realms: Vec<PublicRealmDirectoryEntry>,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl DirectoryRealmSearchOutcome {
    pub fn validate(&self) -> Result<()> {
        if self.realms.len() > 100
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 2048)
        {
            return Err(invalid("invalid public Realm directory search page"));
        }
        self.realms
            .iter()
            .try_for_each(PublicRealmDirectoryEntry::validate)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResolveRealmRequestBody {
    pub realm_id: RealmId,
}

pub type DirectoryRealmResolutionOutcome = PublicRealmDirectoryEntry;
