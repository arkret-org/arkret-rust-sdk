//! Arkret federation wire frame contracts.
//!
//! Discovery (`.well-known/arkret-server`), HTTP message-signature input
//! transcripts, replay records, quarantine records, backfill / event-auth /
//! media query and outcome shapes. The transaction envelope (which embeds
//! the core HTTP transaction body and RFC 9421 signature envelope), the
//! in-memory replay store, and the delta batch aggregate stay in
//! `arkret-core`.

use std::collections::BTreeSet;

use arkret_identifiers::{Did, EventId, Hash, RealmId, TypedTrustDomainId};
use arkret_wire::event_envelope::Event;
use arkret_wire::{BlobRef, Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnownArkretServer {
    pub service_id: Did,
    pub base_url: String,
    pub protocol_versions: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<ServiceEndpointDescriptor>,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpointDescriptor {
    pub service_type: String,
    pub service_endpoint: String,
    #[serde(default)]
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMessageSignatureInput {
    pub method: String,
    pub target_uri: String,
    pub authority: String,
    pub content_digest: String,
    pub origin_service_id: Did,
    pub destination_service_id: Did,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    /// Optional federation trust-domain transcript fields. When present they
    /// MUST be included in the canonical HTTP message signature base.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_trust_domain: Option<TypedTrustDomainId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_trust_domain: Option<TypedTrustDomainId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationReplayRecord {
    pub transaction_id: String,
    pub content_digest: Hash,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub first_seen_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationReplayDecision {
    AcceptedNew,
    AcceptedDuplicate,
    QuarantinedConflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationQuarantineKind {
    DuplicateTransactionConflict,
    CommitFork,
    OperationFork,
    BadDigest,
    StaleCursor,
    UnauthorizedPull,
    BadSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationQuarantineRecord {
    pub kind: FederationQuarantineKind,
    pub object_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_digest: Option<Hash>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationBackfillAuthorization {
    pub requester_service_id: Did,
    pub realm_id: RealmId,
    pub history_visible: bool,
    pub service_delegated: bool,
    pub plaintext_visible_to_service: bool,
}

impl FederationBackfillAuthorization {
    /// Single authoritative backfill-pull authorization decision point: history
    /// MUST be visible AND the service MUST be delegated AND plaintext MUST be
    /// visible to the service (all three). SDK-SEC-03: the looser `allows_pull`
    /// (OR over delegation/plaintext) was removed to avoid a more-permissive
    /// alternate that could silently widen backfill access if a caller switched
    /// to it.
    pub fn is_authorized(&self) -> bool {
        self.history_visible && self.service_delegated && self.plaintext_visible_to_service
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyActorChallenge {
    pub actor_id: Did,
    pub origin_service_id: Did,
    pub destination_service_id: Did,
    pub challenge: String,
    pub purpose: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct VerifyActorChallengeSignature {
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationBackfillQuery {
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_event_id: Option<EventId>,
    pub limit: u32,
    pub authorization: FederationBackfillAuthorization,
}

impl FederationBackfillQuery {
    pub fn validate(&self) -> Result<()> {
        if self.limit == 0 {
            return Err(Error::Protocol(
                "federation backfill limit must be non-zero".to_owned(),
            ));
        }
        if !self.authorization.is_authorized() {
            return Err(Error::Protocol(
                "federation backfill is not authorized".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationBackfillOutcome {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state_events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationEventAuthQuery {
    pub realm_id: RealmId,
    pub event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationEventAuthOutcome {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_chain: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationMediaRequestBody {
    pub blob_ref: BlobRef,
    #[serde(default)]
    pub allow_remote_thumbnail: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationMediaOutcome {
    pub blob_ref: BlobRef,
    pub content_type: String,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    pub content_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

impl FederationMediaOutcome {
    pub fn validate(&self) -> Result<()> {
        if self.content_type.trim().is_empty() || self.size_bytes == 0 {
            Err(Error::Protocol(
                "federation media response requires content type and size".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn backfill_authorization_requires_all_visibility_flags() {
        let auth = FederationBackfillAuthorization {
            requester_service_id: did("a"),
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            history_visible: true,
            service_delegated: true,
            plaintext_visible_to_service: false,
        };
        assert!(!auth.is_authorized());
    }

    #[test]
    fn federation_backfill_keys_and_media_contracts_validate_fail_closed() {
        let authorized = FederationBackfillAuthorization {
            requester_service_id: did("a"),
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            history_visible: true,
            service_delegated: true,
            plaintext_visible_to_service: true,
        };
        FederationBackfillQuery {
            realm_id: authorized.realm_id.clone(),
            from_event_id: Some(
                EventId::new("ak:event:01904100-0000-7000-8000-0b94566027c1").unwrap(),
            ),
            limit: 10,
            authorization: authorized,
        }
        .validate()
        .unwrap();

        FederationMediaOutcome {
            blob_ref: BlobRef::from_bytes(b"media"),
            content_type: "image/png".to_owned(),
            size_bytes: 42,
            content_digest: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            redirect_url: None,
        }
        .validate()
        .unwrap();
    }
}
