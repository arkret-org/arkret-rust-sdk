//! Borrowed unsigned projections for original scope retirement and fresh delivery.
//! These are local signing inputs, never deserializable wire objects or proof of
//! native eligibility. They introduce no field/domain/formula or new authority.
use super::*;

#[derive(Serialize)]
#[serde(tag = "state")]
pub enum ContentScopeRetirementProofUnsigned<'a> {
    #[serde(rename = "removed")]
    Removed {
        replacement: &'a ContentEndpoint,
        inventory_digest: &'a arkret_wire::Hash,
        inventory_entry_digest: &'a arkret_wire::Hash,
        request_digest: &'a arkret_wire::Hash,
        effective_scope: &'a arkret_wire::ScopeRef,
        genesis_event_ref: &'a arkret_wire::EventId,
        governance_station_id: &'a arkret_wire::DidCoreId,
        governance_generation: u64,
        scope_cut: &'a arkret_wire::CommittedEventRef,
        group_state_ref: &'a arkret_wire::EventId,
        #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
        epoch: u64,
        nonce_base64url: &'a str,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        attested_at: chrono::DateTime<chrono::Utc>,
        verification_method: &'a arkret_wire::DidUrl,
        remaining_old_leaf_count: u32,
    },
    #[serde(rename = "terminated")]
    Terminated {
        replacement: &'a ContentEndpoint,
        inventory_digest: &'a arkret_wire::Hash,
        inventory_entry_digest: &'a arkret_wire::Hash,
        request_digest: &'a arkret_wire::Hash,
        effective_scope: &'a arkret_wire::ScopeRef,
        genesis_event_ref: &'a arkret_wire::EventId,
        governance_station_id: &'a arkret_wire::DidCoreId,
        governance_generation: u64,
        scope_cut: &'a arkret_wire::CommittedEventRef,
        group_state_ref: &'a arkret_wire::EventId,
        #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
        epoch: u64,
        nonce_base64url: &'a str,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        attested_at: chrono::DateTime<chrono::Utc>,
        verification_method: &'a arkret_wire::DidUrl,
        terminal_source_digest: &'a arkret_wire::Hash,
    },
}

impl<'a> From<&'a ContentScopeRetirementProof> for ContentScopeRetirementProofUnsigned<'a> {
    fn from(value: &'a ContentScopeRetirementProof) -> Self {
        match value {
            ContentScopeRetirementProof::Removed {
                replacement,
                inventory_digest,
                inventory_entry_digest,
                request_digest,
                effective_scope,
                genesis_event_ref,
                governance_station_id,
                governance_generation,
                scope_cut,
                group_state_ref,
                epoch,
                nonce_base64url,
                attested_at,
                verification_method,
                remaining_old_leaf_count,
                signature: _,
            } => Self::Removed {
                replacement,
                inventory_digest,
                inventory_entry_digest,
                request_digest,
                effective_scope,
                genesis_event_ref,
                governance_station_id,
                governance_generation: *governance_generation,
                scope_cut,
                group_state_ref,
                epoch: *epoch,
                nonce_base64url,
                attested_at: *attested_at,
                verification_method,
                remaining_old_leaf_count: *remaining_old_leaf_count,
            },
            ContentScopeRetirementProof::Terminated {
                replacement,
                inventory_digest,
                inventory_entry_digest,
                request_digest,
                effective_scope,
                genesis_event_ref,
                governance_station_id,
                governance_generation,
                scope_cut,
                group_state_ref,
                epoch,
                nonce_base64url,
                attested_at,
                verification_method,
                terminal_source_digest,
                signature: _,
            } => Self::Terminated {
                replacement,
                inventory_digest,
                inventory_entry_digest,
                request_digest,
                effective_scope,
                genesis_event_ref,
                governance_station_id,
                governance_generation: *governance_generation,
                scope_cut,
                group_state_ref,
                epoch: *epoch,
                nonce_base64url,
                attested_at: *attested_at,
                verification_method,
                terminal_source_digest,
            },
        }
    }
}

impl ContentScopeRetirementProofUnsigned<'_> {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        super::scope_cleanup::signing_bytes(b"ak.mls.scope_retirement.v1\n", self)
    }

    pub fn with_signature(
        self,
        signature: crate::KeyOperationSignature,
    ) -> Result<ContentScopeRetirementProof> {
        let value = match self {
            Self::Removed {
                replacement,
                inventory_digest,
                inventory_entry_digest,
                request_digest,
                effective_scope,
                genesis_event_ref,
                governance_station_id,
                governance_generation,
                scope_cut,
                group_state_ref,
                epoch,
                nonce_base64url,
                attested_at,
                verification_method,
                remaining_old_leaf_count,
            } => ContentScopeRetirementProof::Removed {
                replacement: replacement.clone(),
                inventory_digest: inventory_digest.clone(),
                inventory_entry_digest: inventory_entry_digest.clone(),
                request_digest: request_digest.clone(),
                effective_scope: effective_scope.clone(),
                genesis_event_ref: genesis_event_ref.clone(),
                governance_station_id: governance_station_id.clone(),
                governance_generation,
                scope_cut: scope_cut.clone(),
                group_state_ref: group_state_ref.clone(),
                epoch,
                nonce_base64url: nonce_base64url.to_owned(),
                attested_at,
                verification_method: verification_method.clone(),
                remaining_old_leaf_count,
                signature,
            },
            Self::Terminated {
                replacement,
                inventory_digest,
                inventory_entry_digest,
                request_digest,
                effective_scope,
                genesis_event_ref,
                governance_station_id,
                governance_generation,
                scope_cut,
                group_state_ref,
                epoch,
                nonce_base64url,
                attested_at,
                verification_method,
                terminal_source_digest,
            } => ContentScopeRetirementProof::Terminated {
                replacement: replacement.clone(),
                inventory_digest: inventory_digest.clone(),
                inventory_entry_digest: inventory_entry_digest.clone(),
                request_digest: request_digest.clone(),
                effective_scope: effective_scope.clone(),
                genesis_event_ref: genesis_event_ref.clone(),
                governance_station_id: governance_station_id.clone(),
                governance_generation,
                scope_cut: scope_cut.clone(),
                group_state_ref: group_state_ref.clone(),
                epoch,
                nonce_base64url: nonce_base64url.to_owned(),
                attested_at,
                verification_method: verification_method.clone(),
                terminal_source_digest: terminal_source_digest.clone(),
                signature,
            },
        };
        value.validate_shape()?;
        Ok(value)
    }
}

#[derive(Serialize)]
pub struct ContentScopeRetirementDeliveryUnsigned<'a> {
    pub request_digest: &'a arkret_wire::Hash,
    pub authorization_digest: &'a arkret_wire::Hash,
    pub proof_digest: &'a arkret_wire::Hash,
    pub recipient_service_id: &'a arkret_wire::DidCoreId,
    pub governance_station_id: &'a arkret_wire::DidCoreId,
    pub governance_generation: u64,
    pub nonce_base64url: &'a str,
    pub delivery_challenge_base64url: &'a str,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub attested_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub verification_method: &'a arkret_wire::DidUrl,
}

impl<'a> From<&'a ContentScopeRetirementDeliveryAttestation>
    for ContentScopeRetirementDeliveryUnsigned<'a>
{
    fn from(value: &'a ContentScopeRetirementDeliveryAttestation) -> Self {
        Self {
            request_digest: &value.request_digest,
            authorization_digest: &value.authorization_digest,
            proof_digest: &value.proof_digest,
            recipient_service_id: &value.recipient_service_id,
            governance_station_id: &value.governance_station_id,
            governance_generation: value.governance_generation,
            nonce_base64url: &value.nonce_base64url,
            delivery_challenge_base64url: &value.delivery_challenge_base64url,
            attested_at: value.attested_at,
            expires_at: value.expires_at,
            verification_method: &value.verification_method,
        }
    }
}
impl ContentScopeRetirementDeliveryUnsigned<'_> {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        super::scope_cleanup::signing_bytes(b"ak.mls.scope_retirement_delivery.v1\n", self)
    }
    pub fn with_signature(
        self,
        signature: crate::KeyOperationSignature,
    ) -> Result<ContentScopeRetirementDeliveryAttestation> {
        let value = ContentScopeRetirementDeliveryAttestation {
            request_digest: self.request_digest.clone(),
            authorization_digest: self.authorization_digest.clone(),
            proof_digest: self.proof_digest.clone(),
            recipient_service_id: self.recipient_service_id.clone(),
            governance_station_id: self.governance_station_id.clone(),
            governance_generation: self.governance_generation,
            nonce_base64url: self.nonce_base64url.to_owned(),
            delivery_challenge_base64url: self.delivery_challenge_base64url.to_owned(),
            attested_at: self.attested_at,
            expires_at: self.expires_at,
            verification_method: self.verification_method.clone(),
            signature,
        };
        value.validate_shape()?;
        Ok(value)
    }
}

#[cfg(test)]
#[path = "retirement_signing/tests.rs"]
mod tests;
