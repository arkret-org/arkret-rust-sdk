//! Materialized Realm projection for the authority-commit protocol.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, BlobRef, DidCoreId, Discoverability, FederationPolicy, HistoryAccess, JoinRule,
    PolicyId, RealmId, SchemaId, SecurityClass, StrandId, TrustDomainId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PRINCIPAL_CONTROL_PURPOSE: &str = "principal_control";

/// Current Realm business projection. Commit ordering, finality, and Station
/// replacement live in `RealmCommit` / `RealmAuthorityBundle`, not in mirrored
/// reducer, digest-suite, or encryption-profile fields here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Realm {
    pub id: RealmId,
    pub schema: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_class: Option<SecurityClass>,
    pub trust_domain: TrustDomainId,
    pub governance_station_id: DidCoreId,
    pub authority_generation: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owning_organization_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_strand_id: Option<StrandId>,
    pub default_discoverability: Discoverability,
    pub default_join_rule: JoinRule,
    pub history_access: HistoryAccess,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Realm {
    pub const SCHEMA: &'static str = SchemaId::REALM_V1;

    pub fn new(
        id: RealmId,
        title: impl Into<String>,
        created_by: ActorId,
        trust_domain: TrustDomainId,
        governance_station_id: DidCoreId,
    ) -> Self {
        Self {
            id,
            schema: Self::SCHEMA.to_owned(),
            title: title.into(),
            summary: None,
            security_class: None,
            trust_domain,
            governance_station_id,
            authority_generation: 0,
            owning_organization_ids: Vec::new(),
            schema_refs: Vec::new(),
            fields: BTreeMap::new(),
            policy_id: None,
            preview_policy_id: None,
            default_strand_id: None,
            default_discoverability: Discoverability::InviteOnly,
            default_join_rule: JoinRule::Invite,
            history_access: HistoryAccess::SinceJoin,
            federation_policy: None,
            retention_policy_id: None,
            avatar_blob_ref: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
        }
    }
}
