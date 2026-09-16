//! Closed request/response models for the public MLS group-state material query.

use arkret_canonical::base64url::base64url_decode;
use arkret_wire::{Base64UrlString, BlobRef, EventId, Hash, MlsGroupId, RealmId, ScopeRef};
use serde::{Deserialize, Serialize};

use crate::internal_prelude::{Result, WireError};

pub const MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES: u32 = 8 * 1024 * 1024;
pub const MLS_GROUP_STATE_MATERIAL_MIN_RESPONSE_BYTES: u32 = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MlsGroupStateMaterialRequestBody {
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub epoch: crate::events_payloads::mls::MlsGenesisEpoch,
    pub group_state_event_id: EventId,
    pub group_info_ref: BlobRef,
    pub ratchet_tree_ref: BlobRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u32>,
}

impl MlsGroupStateMaterialRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.effective_scope.realm_id() != &self.realm_id {
            return Err(WireError::Protocol(
                "MLS group-state material scope does not match realm_id".to_owned(),
            ));
        }
        material_digest_from_ref(&self.group_info_ref)?;
        material_digest_from_ref(&self.ratchet_tree_ref)?;
        if let Some(limit) = self.max_response_bytes
            && !(MLS_GROUP_STATE_MATERIAL_MIN_RESPONSE_BYTES
                ..=MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES)
                .contains(&limit)
        {
            return Err(WireError::Protocol(
                "MLS group-state material max_response_bytes is outside protocol bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MlsGroupStateMaterialOutcome {
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub epoch: crate::events_payloads::mls::MlsGenesisEpoch,
    pub group_state_event_id: EventId,
    pub group_info_ref: BlobRef,
    pub group_info_bytes_b64: Base64UrlString,
    pub ratchet_tree_ref: BlobRef,
    pub ratchet_tree_bytes_b64: Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedMlsGroupStateMaterial {
    pub group_info_bytes: Vec<u8>,
    pub ratchet_tree_bytes: Vec<u8>,
}

impl MlsGroupStateMaterialOutcome {
    /// Validate the exact request/response selector binding and both raw-byte
    /// content addresses before an RFC 9420 parser sees either byte string.
    pub fn validate_for_request(
        &self,
        request: &MlsGroupStateMaterialRequestBody,
    ) -> Result<ValidatedMlsGroupStateMaterial> {
        request.validate()?;
        if self.realm_id != request.realm_id
            || self.effective_scope != request.effective_scope
            || self.mls_group_id != request.mls_group_id
            || self.epoch != request.epoch
            || self.group_state_event_id != request.group_state_event_id
            || self.group_info_ref != request.group_info_ref
            || self.ratchet_tree_ref != request.ratchet_tree_ref
        {
            return Err(WireError::Protocol(
                "MLS group-state material response does not match request selectors".to_owned(),
            ));
        }

        let group_info_digest = material_digest_from_ref(&self.group_info_ref)?;
        let ratchet_tree_digest = material_digest_from_ref(&self.ratchet_tree_ref)?;
        let group_info_bytes = decode_and_validate_bytes(
            "group_info",
            &self.group_info_bytes_b64,
            &group_info_digest,
        )?;
        let ratchet_tree_bytes = decode_and_validate_bytes(
            "ratchet_tree",
            &self.ratchet_tree_bytes_b64,
            &ratchet_tree_digest,
        )?;
        let total = group_info_bytes
            .len()
            .checked_add(ratchet_tree_bytes.len())
            .ok_or_else(|| {
                WireError::Protocol("MLS group-state material size overflow".to_owned())
            })?;
        let limit = request
            .max_response_bytes
            .unwrap_or(MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES) as usize;
        if total > limit {
            return Err(WireError::Protocol(
                "MLS group-state material exceeds requested response bound".to_owned(),
            ));
        }
        Ok(ValidatedMlsGroupStateMaterial {
            group_info_bytes,
            ratchet_tree_bytes,
        })
    }
}

pub fn material_digest_from_ref(blob_ref: &BlobRef) -> Result<Hash> {
    let digest = blob_ref.as_str().strip_prefix("ak:blob:").ok_or_else(|| {
        WireError::Protocol("MLS material ref must be content-addressed".to_owned())
    })?;
    if !(digest.starts_with("sha256:") || digest.starts_with("blake3:")) {
        return Err(WireError::Protocol(
            "MLS material ref must use the Realm digest suite".to_owned(),
        ));
    }
    Ok(Hash::new(digest.to_owned())?)
}

fn decode_and_validate_bytes(
    field: &str,
    encoded: &Base64UrlString,
    expected_digest: &Hash,
) -> Result<Vec<u8>> {
    let bytes = base64url_decode(encoded.as_str()).map_err(|error| {
        WireError::Protocol(format!(
            "MLS {field} bytes are not unpadded base64url: {error}"
        ))
    })?;
    if arkret_canonical::canonical::verify_digest(&bytes, expected_digest.as_str()).is_err() {
        return Err(WireError::Protocol(format!(
            "MLS {field} raw-byte digest mismatch"
        )));
    }
    Ok(bytes)
}
