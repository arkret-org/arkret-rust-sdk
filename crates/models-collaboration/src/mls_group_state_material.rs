//! Closed request/response models for the public MLS group-state material query.

use arkret_canonical::base64url::base64url_decode;
use arkret_wire::{
    ActorId, Base64UrlString, BlobRef, EventId, Hash, MlsGroupId, RealmId, ScopeRef,
};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_actor_id: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_commit_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_epoch: Option<u64>,
    pub group_info_ref: BlobRef,
    pub ratchet_tree_ref: BlobRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u32>,
}

impl MlsGroupStateMaterialRequestBody {
    pub fn validate(&self) -> Result<()> {
        match &self.effective_scope {
            ScopeRef::Realm { realm_id } | ScopeRef::Circle { realm_id, .. }
                if realm_id == &self.realm_id => {}
            _ => {
                return Err(WireError::Protocol(
                    "MLS group-state material requires a matching Realm or Circle scope".to_owned(),
                ));
            }
        }
        match (
            &self.caller_actor_id,
            &self.target_commit_event_ref,
            self.target_epoch,
        ) {
            (None, None, None) => {}
            (Some(actor), Some(target_ref), Some(target_epoch)) => {
                actor.validate()?;
                if target_epoch == 0 && target_ref != &self.group_state_event_id {
                    return Err(WireError::Protocol(
                        "MLS epoch-zero target must name the Genesis Event".to_owned(),
                    ));
                }
            }
            _ => {
                return Err(WireError::Protocol(
                    "MLS member material selectors must appear together".to_owned(),
                ));
            }
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

/// Member-authenticated read through the caller's Account Station. All
/// selectors are forwarded unchanged to the governance Station.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MlsMemberGroupStateMaterialReadRequestBody {
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub epoch: crate::events_payloads::mls::MlsGenesisEpoch,
    pub group_state_event_id: EventId,
    pub caller_actor_id: ActorId,
    pub target_commit_event_ref: EventId,
    pub target_epoch: u64,
    pub group_info_ref: BlobRef,
    pub ratchet_tree_ref: BlobRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u32>,
}

impl MlsMemberGroupStateMaterialReadRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.as_peer_request().validate()
    }

    pub fn as_peer_request(&self) -> MlsGroupStateMaterialRequestBody {
        MlsGroupStateMaterialRequestBody {
            realm_id: self.realm_id.clone(),
            effective_scope: self.effective_scope.clone(),
            mls_group_id: self.mls_group_id.clone(),
            epoch: self.epoch,
            group_state_event_id: self.group_state_event_id.clone(),
            caller_actor_id: Some(self.caller_actor_id.clone()),
            target_commit_event_ref: Some(self.target_commit_event_ref.clone()),
            target_epoch: Some(self.target_epoch),
            group_info_ref: self.group_info_ref.clone(),
            ratchet_tree_ref: self.ratchet_tree_ref.clone(),
            max_response_bytes: self.max_response_bytes,
        }
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn member_request_json() -> serde_json::Value {
        json!({
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "effective_scope": {
                "kind": "realm",
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            },
            "mls_group_id": "QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4",
            "epoch": 0,
            "group_state_event_id": "ak:event:ARELvWOpF6BRhrks3DlbQy-9XIE6aAQQumDQp7fA4Ape",
            "caller_actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:bob.example",
                    "station_id": "ak:did_core:web:bob-station.example"
                }
            },
            "target_commit_event_ref": "ak:event:ARELvWOpF6BRhrks3DlbQy-9XIE6aAQQumDQp7fA4Ape",
            "target_epoch": 0,
            "group_info_ref": "ak:blob:sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "ratchet_tree_ref": "ak:blob:sha256:2222222222222222222222222222222222222222222222222222222222222222"
        })
    }

    #[test]
    fn member_material_requires_closed_exact_target_selectors() {
        let value = member_request_json();
        let request: MlsMemberGroupStateMaterialReadRequestBody =
            serde_json::from_value(value.clone()).unwrap();
        request.validate().unwrap();
        let forwarded = request.as_peer_request();
        forwarded.validate().unwrap();
        assert_eq!(
            forwarded.caller_actor_id.as_ref(),
            Some(&request.caller_actor_id)
        );

        let mut without_caller = value.clone();
        without_caller
            .as_object_mut()
            .unwrap()
            .remove("caller_actor_id");
        assert!(
            serde_json::from_value::<MlsMemberGroupStateMaterialReadRequestBody>(without_caller)
                .is_err()
        );

        let mut extra_field = value.clone();
        extra_field["unregistered_selector"] = json!(true);
        assert!(
            serde_json::from_value::<MlsMemberGroupStateMaterialReadRequestBody>(extra_field)
                .is_err()
        );

        let mut wrong_genesis_cut = value.clone();
        wrong_genesis_cut["target_commit_event_ref"] =
            json!("ak:event:AfZbqEPRJlRM-xYwGIXrxWkwgHYHegqlBXpFrtofzYJM");
        let wrong: MlsMemberGroupStateMaterialReadRequestBody =
            serde_json::from_value(wrong_genesis_cut).unwrap();
        assert!(wrong.validate().is_err());

        let mut incomplete_peer = forwarded;
        incomplete_peer.target_epoch = None;
        assert!(incomplete_peer.validate().is_err());

        let mut genesis_scope = value;
        genesis_scope["effective_scope"] = json!({ "kind": "realm_genesis" });
        let genesis: MlsMemberGroupStateMaterialReadRequestBody =
            serde_json::from_value(genesis_scope).unwrap();
        assert!(genesis.validate().is_err());
    }
}
