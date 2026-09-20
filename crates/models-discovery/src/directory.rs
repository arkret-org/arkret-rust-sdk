//! Public Realm Directory wire models.
//!
//! Directory results are discovery hints only. They never carry membership,
//! join, history, Event/RealmCommit, source-reference, or authority evidence.

use arkret_wire::{
    AnnounceId, AuditReasonText, BlobRef, DidCoreId, DidUrl, Hash, RealmId, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

fn invalid(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

fn validate_request_id(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value)
        .map_err(|_| invalid("Directory request_id must be a canonical UUID"))?;
    if parsed.hyphenated().to_string() != value || !(1..=8).contains(&parsed.get_version_num()) {
        return Err(invalid("Directory request_id must be a canonical UUID"));
    }
    Ok(())
}

fn is_base64url_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResolveRealmRequestBody {
    pub realm_id: RealmId,
}

pub type DirectoryRealmResolutionOutcome = PublicRealmDirectoryEntry;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicDiscoverability {
    #[serde(rename = "public")]
    Public,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectoryGovernanceProofKind {
    #[serde(rename = "detached_jws")]
    DetachedJws,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectoryGovernanceProofPurpose {
    #[serde(rename = "governance_authorization")]
    GovernanceAuthorization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryGovernanceProof {
    pub kind: DirectoryGovernanceProofKind,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub audience_id: DidCoreId,
    pub proof_purpose: DirectoryGovernanceProofPurpose,
    pub jws: String,
}

impl DirectoryGovernanceProof {
    pub fn validate_for_directory(&self, directory_id: &DidCoreId) -> Result<()> {
        let mut segments = self.jws.split('.');
        let protected = segments.next().unwrap_or_default();
        let payload = segments.next().unwrap_or_default();
        let signature = segments.next().unwrap_or_default();
        if &self.audience_id != directory_id
            || !is_base64url_segment(protected)
            || !payload.is_empty()
            || !is_base64url_segment(signature)
            || segments.next().is_some()
        {
            return Err(invalid("invalid Directory governance proof binding"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryAnnounceRequestBody {
    pub realm_id: RealmId,
    pub directory_id: DidCoreId,
    pub discoverability: PublicDiscoverability,
    pub public_metadata: PublicRealmMetadata,
    pub authority_generation: u64,
    pub request_id: String,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_announce_id: Option<AnnounceId>,
    pub governance_proof: DirectoryGovernanceProof,
}

impl DirectoryAnnounceRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.public_metadata.validate()?;
        self.governance_proof
            .validate_for_directory(&self.directory_id)?;
        validate_request_id(&self.request_id)?;
        if self.expires_at <= self.issued_at {
            return Err(invalid("Directory announcement must expire after issuance"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryAnnounceOutcome {
    pub announce_id: AnnounceId,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub indexed_at: DateTime<Utc>,
    pub effective_ttl_seconds: u64,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub next_revalidation_after: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryWithdrawRequestBody {
    pub realm_id: RealmId,
    pub directory_id: DidCoreId,
    pub authority_generation: u64,
    pub request_id: String,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    pub governance_proof: DirectoryGovernanceProof,
}

impl DirectoryWithdrawRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_request_id(&self.request_id)?;
        self.governance_proof
            .validate_for_directory(&self.directory_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryWithdrawOutcome {
    pub withdrawal_ref: String,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub acked_at: DateTime<Utc>,
}

impl DirectoryWithdrawOutcome {
    pub fn validate(&self) -> Result<()> {
        let suffix = self
            .withdrawal_ref
            .strip_prefix("withdrawal:")
            .ok_or_else(|| invalid("invalid Directory withdrawal_ref"))?;
        if suffix.is_empty()
            || suffix.len() > 128
            || !suffix.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
        {
            return Err(invalid("invalid Directory withdrawal_ref"));
        }
        Ok(())
    }
}
