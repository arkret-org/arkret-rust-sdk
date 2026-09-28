//! Closed MLS historical leaf authority and signed roster read carriers.

use std::collections::HashSet;

use arkret_models_crypto::{
    KeyOperationSignature, PeerKeyPackageClaimReceipt, PeerKeyPackagesClaimOutcome,
};
use arkret_wire::{
    ActorId, Base64UrlString, DidCoreId, EventId, Hash, KeypackageClaimId, MlsGroupId,
    MlsWelcomeDeliveryId, MlsWelcomeRecipientEndpoint, RealmId, ScopeRef,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::internal_prelude::{Result, WireError};

fn signing_bytes<T: Serialize>(value: &T, domain: &[u8]) -> Result<Vec<u8>> {
    let mut unsigned = serde_json::to_value(value)
        .map_err(|error| WireError::Protocol(format!("MLS roster signing body: {error}")))?;
    unsigned
        .as_object_mut()
        .and_then(|object| object.remove("signature"))
        .ok_or_else(|| WireError::Protocol("MLS roster signing body lacks signature".to_owned()))?;
    let canonical = arkret_canonical::canonical_json_bytes(&unsigned)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn validate_leaf_key(key: &Base64UrlString) -> Result<()> {
    let bytes = arkret_canonical::base64url::base64url_decode(key.as_str())
        .map_err(|_| WireError::Protocol("MLS leaf key is not base64url".to_owned()))?;
    if bytes.len() != 32 || arkret_canonical::base64url::base64url_encode(&bytes) != key.as_str() {
        return Err(WireError::Protocol(
            "MLS leaf key must be canonical Ed25519 public key bytes".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsAddAuthorityAttestation {
    pub attestor_station_id: DidCoreId,
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub genesis_event_ref: EventId,
    pub commit_event_ref: EventId,
    pub commit_stream_position: u64,
    pub epoch: u64,
    pub welcome_id: MlsWelcomeDeliveryId,
    pub claim_id: KeypackageClaimId,
    pub actor_id: ActorId,
    pub endpoint: MlsWelcomeRecipientEndpoint,
    pub authorization_event_ref: EventId,
    pub leaf_signature_key_b64u: Base64UrlString,
    pub claim_record_digest: Hash,
    pub claim_receipt: PeerKeyPackageClaimReceipt,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub attested_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

impl MlsAddAuthorityAttestation {
    pub fn validate_shape(&self) -> Result<()> {
        if self.effective_scope.realm_id_opt() != Some(&self.realm_id)
            || !matches!(
                &self.effective_scope,
                ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
            )
            || self.commit_stream_position == 0
            || self.epoch == 0
            || self.actor_id.route_service_id() != &self.attestor_station_id
            || !self.claim_record_digest.as_str().starts_with("sha256:")
        {
            return Err(WireError::Protocol(
                "MLS Add authority attestation selectors are inconsistent".to_owned(),
            ));
        }
        validate_leaf_key(&self.leaf_signature_key_b64u)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(self, b"ak.mls_add_authority_attestation.v1\n")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsAttestAddRequestBody {
    pub attestation: MlsAddAuthorityAttestation,
    pub claim_outcome: PeerKeyPackagesClaimOutcome,
}

impl MlsAttestAddRequestBody {
    pub fn validate_claim_binding(&self) -> Result<()> {
        self.attestation.validate_shape()?;
        if arkret_canonical::canonical_json_bytes(&self.attestation.claim_receipt)
            .map_err(|error| WireError::Protocol(error.to_string()))?
            != arkret_canonical::canonical_json_bytes(&self.claim_outcome.claim_receipt)
                .map_err(|error| WireError::Protocol(error.to_string()))?
            || self.claim_outcome.claim_request_id
                != self.claim_outcome.claim_receipt.claim_request_id
            || self.claim_outcome.claim_receipt.destination_id
                != self.attestation.attestor_station_id
        {
            return Err(WireError::Protocol(
                "MLS Add authority claim receipt does not match outcome".to_owned(),
            ));
        }
        let claims_digest = arkret_canonical::canonical_sha256(&self.claim_outcome.claims)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        if claims_digest != self.claim_outcome.claim_receipt.claims_digest.as_str() {
            return Err(WireError::Protocol(
                "MLS Add authority claim array digest mismatch".to_owned(),
            ));
        }
        let mut claim_ids = HashSet::new();
        if !self
            .claim_outcome
            .claims
            .iter()
            .all(|claim| claim_ids.insert(claim.claim_id.as_str()))
        {
            return Err(WireError::Protocol(
                "MLS Add authority claim outcome repeats a claim id".to_owned(),
            ));
        }
        let mut matching = self
            .claim_outcome
            .claims
            .iter()
            .filter(|claim| claim.claim_id == self.attestation.claim_id.as_str());
        let claim = matching
            .next()
            .ok_or_else(|| WireError::Protocol("MLS Add authority claim id missing".to_owned()))?;
        if matching.next().is_some() || claim.actor_id != self.attestation.actor_id {
            return Err(WireError::Protocol(
                "MLS Add authority claim id is duplicated or actor differs".to_owned(),
            ));
        }
        let endpoint_matches = match &self.attestation.endpoint {
            MlsWelcomeRecipientEndpoint::Device { device_id } => {
                claim.device_id.as_ref() == Some(device_id)
                    && claim.device_authorize_event_id.as_ref()
                        == Some(&self.attestation.authorization_event_ref)
            }
            MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method,
            } => {
                claim.agent_verification_method.as_ref() == Some(verification_method)
                    && claim.agent_key_authorize_event_id.as_ref()
                        == Some(&self.attestation.authorization_event_ref)
            }
        };
        if !endpoint_matches {
            return Err(WireError::Protocol(
                "MLS Add authority endpoint authorization differs from selected claim".to_owned(),
            ));
        }
        let claim_digest = arkret_canonical::canonical_sha256(claim)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        if claim_digest != self.attestation.claim_record_digest.as_str() {
            return Err(WireError::Protocol(
                "MLS Add authority selected claim digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsAttestAddOutcome {
    pub status: MlsAttestAddStatus,
    pub attestation_digest: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsAttestAddStatus {
    Installed,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsRosterAuthorityReadRequestBody {
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub genesis_event_ref: EventId,
    pub target_commit_event_ref: EventId,
    pub target_epoch: u64,
    pub caller_actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl MlsRosterAuthorityReadRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.effective_scope.realm_id_opt() != Some(&self.realm_id)
            || !matches!(
                &self.effective_scope,
                ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
            )
            || (self.target_epoch == 0 && self.target_commit_event_ref != self.genesis_event_ref)
            || self
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 1024)
        {
            return Err(WireError::Protocol(
                "MLS roster request selectors are inconsistent".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MlsRosterRecord {
    Genesis {
        genesis_event_ref: EventId,
        actor_id: ActorId,
        leaf_signature_key_b64u: Base64UrlString,
        endpoint: MlsWelcomeRecipientEndpoint,
        authorization_event_ref: EventId,
    },
    Add {
        commit_event_ref: EventId,
        consumed_proposal_ordinal: u64,
        sender_actor_id: ActorId,
        proposal_wire_b64u: Base64UrlString,
        attestation: MlsAddAuthorityAttestation,
    },
}

impl MlsRosterRecord {
    pub fn validate_shape(&self) -> Result<()> {
        if let Self::Add {
            proposal_wire_b64u,
            attestation,
            ..
        } = self
        {
            let proposal =
                arkret_canonical::base64url::base64url_decode(proposal_wire_b64u.as_str())
                    .map_err(|_| {
                        WireError::Protocol("MLS roster Proposal is not base64url".to_owned())
                    })?;
            if proposal.is_empty()
                || arkret_canonical::base64url::base64url_encode(&proposal)
                    != proposal_wire_b64u.as_str()
            {
                return Err(WireError::Protocol(
                    "MLS roster Proposal is not canonical TLS bytes".to_owned(),
                ));
            }
            attestation.validate_shape()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsRosterAuthorityManifest {
    pub governance_station_id: DidCoreId,
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub genesis_event_ref: EventId,
    pub target_commit_event_ref: EventId,
    pub target_epoch: u64,
    pub authority_head_commit_event_ref: EventId,
    pub caller_actor_id: ActorId,
    pub total_records: u64,
    pub page_count: u64,
    pub records_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

impl MlsRosterAuthorityManifest {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(self, b"ak.mls_roster_authority_manifest.v1\n")
    }

    pub fn validate_for_request(&self, request: &MlsRosterAuthorityReadRequestBody) -> Result<()> {
        request.validate()?;
        if self.realm_id != request.realm_id
            || self.effective_scope != request.effective_scope
            || self.mls_group_id != request.mls_group_id
            || self.genesis_event_ref != request.genesis_event_ref
            || self.target_commit_event_ref != request.target_commit_event_ref
            || self.target_epoch != request.target_epoch
            || self.caller_actor_id != request.caller_actor_id
            || self.total_records == 0
            || self.page_count != self.total_records.div_ceil(8)
            || (self.target_epoch == 0
                && (self.target_commit_event_ref != self.genesis_event_ref
                    || self.authority_head_commit_event_ref != self.genesis_event_ref))
            || !self.records_digest.as_str().starts_with("sha256:")
        {
            return Err(WireError::Protocol(
                "MLS roster manifest does not match the requested cut".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsRosterAuthorityReadOutcome {
    pub manifest: MlsRosterAuthorityManifest,
    pub page_index: u64,
    pub records: Vec<MlsRosterRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}
