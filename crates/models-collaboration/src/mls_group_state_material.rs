//! Closed request/response models for the public MLS group-state material query.

use arkret_canonical::base64url::base64url_decode;
use arkret_wire::{Base64UrlString, BlobRef, EventId, Hash, MlsGroupId, RealmId, ScopeRef};
use serde::{Deserialize, Serialize};

use crate::internal_prelude::{Error, Result};

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
    pub group_info_digest: Hash,
    pub ratchet_tree_ref: BlobRef,
    pub ratchet_tree_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u32>,
}

impl MlsGroupStateMaterialRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.effective_scope.realm_id() != &self.realm_id {
            return Err(Error::Protocol(
                "MLS group-state material scope does not match realm_id".to_owned(),
            ));
        }
        validate_content_address(&self.group_info_ref, &self.group_info_digest)?;
        validate_content_address(&self.ratchet_tree_ref, &self.ratchet_tree_digest)?;
        if let Some(limit) = self.max_response_bytes
            && !(MLS_GROUP_STATE_MATERIAL_MIN_RESPONSE_BYTES
                ..=MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES)
                .contains(&limit)
        {
            return Err(Error::Protocol(
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
    pub group_info_digest: Hash,
    pub group_info_bytes_b64: Base64UrlString,
    pub ratchet_tree_ref: BlobRef,
    pub ratchet_tree_digest: Hash,
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
            || self.group_info_digest != request.group_info_digest
            || self.ratchet_tree_ref != request.ratchet_tree_ref
            || self.ratchet_tree_digest != request.ratchet_tree_digest
        {
            return Err(Error::Protocol(
                "MLS group-state material response does not match request selectors".to_owned(),
            ));
        }

        validate_content_address(&self.group_info_ref, &self.group_info_digest)?;
        validate_content_address(&self.ratchet_tree_ref, &self.ratchet_tree_digest)?;
        let group_info_bytes = decode_and_validate_bytes(
            "group_info",
            &self.group_info_bytes_b64,
            &self.group_info_digest,
        )?;
        let ratchet_tree_bytes = decode_and_validate_bytes(
            "ratchet_tree",
            &self.ratchet_tree_bytes_b64,
            &self.ratchet_tree_digest,
        )?;
        let total = group_info_bytes
            .len()
            .checked_add(ratchet_tree_bytes.len())
            .ok_or_else(|| Error::Protocol("MLS group-state material size overflow".to_owned()))?;
        let limit = request
            .max_response_bytes
            .unwrap_or(MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES) as usize;
        if total > limit {
            return Err(Error::Protocol(
                "MLS group-state material exceeds requested response bound".to_owned(),
            ));
        }
        Ok(ValidatedMlsGroupStateMaterial {
            group_info_bytes,
            ratchet_tree_bytes,
        })
    }
}

pub fn validate_content_address(blob_ref: &BlobRef, digest: &Hash) -> Result<()> {
    let embedded = blob_ref
        .as_str()
        .strip_prefix("ak:blob:sha256:")
        .ok_or_else(|| Error::Protocol("MLS material ref must use ak:blob:sha256".to_owned()))?;
    let explicit = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Protocol("MLS material digest must use sha256".to_owned()))?;
    if embedded != explicit {
        return Err(Error::Protocol(
            "MLS material content-addressed ref does not match explicit digest".to_owned(),
        ));
    }
    Ok(())
}

fn decode_and_validate_bytes(
    field: &str,
    encoded: &Base64UrlString,
    expected_digest: &Hash,
) -> Result<Vec<u8>> {
    let bytes = base64url_decode(encoded.as_str()).map_err(|error| {
        Error::Protocol(format!(
            "MLS {field} bytes are not unpadded base64url: {error}"
        ))
    })?;
    let actual = arkret_canonical::canonical::sha256_digest(&bytes);
    if actual != expected_digest.as_str() {
        return Err(Error::Protocol(format!(
            "MLS {field} raw-byte digest mismatch"
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_for(bytes: &[u8]) -> MlsGroupStateMaterialRequestBody {
        let digest = arkret_canonical::canonical::sha256_digest(bytes);
        let hex = digest.strip_prefix("sha256:").unwrap();
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
        MlsGroupStateMaterialRequestBody {
            realm_id: realm_id.clone(),
            effective_scope: ScopeRef::Realm { realm_id },
            mls_group_id: MlsGroupId::new("Z3JvdXAtMA").unwrap(),
            epoch: crate::events_payloads::mls::MlsGenesisEpoch,
            group_state_event_id: EventId::new("ak:event:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            group_info_ref: BlobRef::new(format!("ak:blob:sha256:{hex}")).unwrap(),
            group_info_digest: Hash::new(digest.clone()).unwrap(),
            ratchet_tree_ref: BlobRef::new(format!("ak:blob:sha256:{hex}")).unwrap(),
            ratchet_tree_digest: Hash::new(digest).unwrap(),
            max_response_bytes: Some(1024),
        }
    }

    #[test]
    fn content_address_requires_the_same_sha256() {
        let blob_ref = BlobRef::new(format!("ak:blob:sha256:{}", "a".repeat(64))).unwrap();
        let matching = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let mismatch = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        validate_content_address(&blob_ref, &matching).unwrap();
        assert!(validate_content_address(&blob_ref, &mismatch).is_err());
    }

    #[test]
    fn outcome_decodes_exact_bytes_only_after_all_bindings_match() {
        let bytes = b"public MLS material";
        let request = request_for(bytes);
        let outcome = MlsGroupStateMaterialOutcome {
            realm_id: request.realm_id.clone(),
            effective_scope: request.effective_scope.clone(),
            mls_group_id: request.mls_group_id.clone(),
            epoch: request.epoch,
            group_state_event_id: request.group_state_event_id.clone(),
            group_info_ref: request.group_info_ref.clone(),
            group_info_digest: request.group_info_digest.clone(),
            group_info_bytes_b64: Base64UrlString::new(
                arkret_canonical::base64url::base64url_encode(bytes),
            )
            .unwrap(),
            ratchet_tree_ref: request.ratchet_tree_ref.clone(),
            ratchet_tree_digest: request.ratchet_tree_digest.clone(),
            ratchet_tree_bytes_b64: Base64UrlString::new(
                arkret_canonical::base64url::base64url_encode(bytes),
            )
            .unwrap(),
        };

        let decoded = outcome.validate_for_request(&request).unwrap();
        assert_eq!(decoded.group_info_bytes, bytes);
        assert_eq!(decoded.ratchet_tree_bytes, bytes);

        let mut mismatched = outcome;
        mismatched.group_state_event_id =
            EventId::new("ak:event:01904100-0000-7000-8000-000000000003").unwrap();
        assert!(mismatched.validate_for_request(&request).is_err());
    }
}
