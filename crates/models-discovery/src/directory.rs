//! Public Realm Directory wire models.
//!
//! Directory results are discovery hints only. They never carry membership,
//! join, history, Event/RealmCommit, source-reference, or authority evidence.

use arkret_wire::{Result, WireError};

pub use crate::generated::directory::{
    DirectoryRealmSearchResponseBody, DirectoryResolveRealmRequestBody,
    DirectorySearchRealmsRequestBody, PublicRealmDirectoryEntry, PublicRealmMetadata,
};

fn invalid(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
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

impl DirectoryRealmSearchResponseBody {
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
