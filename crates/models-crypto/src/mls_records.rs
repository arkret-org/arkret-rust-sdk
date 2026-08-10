//! MLS record wire shapes: KeyPackage lifecycle + published-KeyPackage record,
//! and the provider-opaque MLS group-state snapshot record.
//!
//! These record shapes moved here so the MLS behavior layer can consume them
//! without depending on the higher crates that previously owned them:
//! `MlsKeyPackageState` from `arkret-models-collaboration`,
//! `MlsKeyPackageRecord` from the `arkret` umbrella, and `MlsGroupStateRecord` from the
//! SDK crypto store. The original owners keep re-export shims so downstream
//! paths are unchanged.

use std::collections::BTreeMap;

use arkret_wire::{
    DeviceId, DidCoreId, DidFullId, DidUrl, EventId, Hash, NonEmptyString, Proof, RealmId,
    project_full_id_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MlsEndpointIdentity {
    HumanDevice {
        principal_id: DidCoreId,
        device_id: DeviceId,
    },
    NativeAgentRuntime {
        agent_id: DidCoreId,
        verification_method: DidUrl,
        agent_key_authorize_event_id: EventId,
    },
}

impl MlsEndpointIdentity {
    pub fn human_device(principal_id: DidCoreId, device_id: DeviceId) -> Self {
        Self::HumanDevice {
            principal_id,
            device_id,
        }
    }

    pub fn native_agent_runtime(
        agent_id: DidCoreId,
        verification_method: DidUrl,
        agent_key_authorize_event_id: EventId,
    ) -> arkret_wire::Result<Self> {
        let (controller, fragment) =
            verification_method
                .as_str()
                .split_once('#')
                .ok_or_else(|| {
                    arkret_wire::Error::Protocol(
                        "Native Agent MLS verification method has no fragment".to_owned(),
                    )
                })?;
        if fragment.is_empty() {
            return Err(arkret_wire::Error::Protocol(
                "Native Agent MLS verification method has an empty fragment".to_owned(),
            ));
        }
        let controller = DidFullId::new(controller.to_owned())?;
        if project_full_id_to_core_id(&controller)?.as_str() != agent_id.as_str() {
            return Err(arkret_wire::Error::Protocol(
                "Native Agent MLS verification method controller mismatch".to_owned(),
            ));
        }
        Ok(Self::NativeAgentRuntime {
            agent_id,
            verification_method,
            agent_key_authorize_event_id,
        })
    }

    pub fn actor_id(&self) -> &DidCoreId {
        match self {
            Self::HumanDevice { principal_id, .. } => principal_id,
            Self::NativeAgentRuntime { agent_id, .. } => agent_id,
        }
    }

    pub fn human_device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::HumanDevice { device_id, .. } => Some(device_id),
            Self::NativeAgentRuntime { .. } => None,
        }
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        match self {
            Self::HumanDevice { .. } => Ok(()),
            Self::NativeAgentRuntime {
                agent_id,
                verification_method,
                agent_key_authorize_event_id,
            } => Self::native_agent_runtime(
                agent_id.clone(),
                verification_method.clone(),
                agent_key_authorize_event_id.clone(),
            )
            .map(|_| ()),
        }
    }
}

/// Client-local, encrypted-checkpoint state for a minimal-metadata Realm
/// author. This is deliberately not an HTTP/OpenAPI DTO and must never enter
/// an Event or service operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPairwiseAuthorState {
    pub realm_id: RealmId,
    pub pairwise_actor_id: DidCoreId,
    pub pairwise_full_id: DidFullId,
    pub verification_method: DidUrl,
    /// Opaque handle into the platform secure signer; never private material.
    pub local_signing_key_ref: NonEmptyString,
    pub mls_group_id: NonEmptyString,
    pub epoch: u64,
    pub accepted_group_state_ref: EventId,
    pub leaf_index: u32,
    /// Public Ed25519 LeafNode signature key bytes.
    pub leaf_signature_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmPairwiseAcceptedLeaf {
    pub leaf_index: u32,
    pub basic_credential_identity: Vec<u8>,
    pub signature_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmPairwiseAcceptedGroupState {
    pub realm_id: RealmId,
    pub mls_group_id: NonEmptyString,
    pub epoch: u64,
    pub accepted_group_state_ref: EventId,
    pub active_leaves: Vec<RealmPairwiseAcceptedLeaf>,
}

/// Durable, client-local uniqueness ledger. A key identity may be restored in
/// the same Realm, but none of its public identity components may be rebound
/// to another Realm.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPairwiseKeyScopeLedger {
    bindings: BTreeMap<String, RealmId>,
}

impl RealmPairwiseAuthorState {
    pub fn validate_against(
        &self,
        snapshot: &RealmPairwiseAcceptedGroupState,
    ) -> arkret_wire::Result<()> {
        if !self.pairwise_full_id.as_str().starts_with("did:key:") {
            return Err(arkret_wire::Error::Protocol(
                "pairwise author DidFullId must use did:key".to_owned(),
            ));
        }
        if project_full_id_to_core_id(&self.pairwise_full_id)? != self.pairwise_actor_id {
            return Err(arkret_wire::Error::Protocol(
                "pairwise DidFullId does not project to pairwise_actor_id".to_owned(),
            ));
        }
        let (method_base, method_fragment) = self
            .verification_method
            .as_str()
            .split_once('#')
            .ok_or_else(|| {
                arkret_wire::Error::Protocol(
                    "pairwise verification method has no fragment".to_owned(),
                )
            })?;
        if method_base != self.pairwise_full_id.as_str() {
            return Err(arkret_wire::Error::Protocol(
                "pairwise verification method base differs from pairwise_full_id".to_owned(),
            ));
        }
        let decoded = arkret_canonical::decode_multibase_base58btc(method_fragment)
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))?;
        let Some((codec, prefix_len)) = arkret_canonical::decode_multicodec_varint(&decoded) else {
            return Err(arkret_wire::Error::Protocol(
                "pairwise verification method has invalid multicodec prefix".to_owned(),
            ));
        };
        if codec != 0xed || decoded.get(prefix_len..) != Some(self.leaf_signature_key.as_slice()) {
            return Err(arkret_wire::Error::Protocol(
                "pairwise verification method key differs from LeafNode signature_key".to_owned(),
            ));
        }
        if self.realm_id != snapshot.realm_id
            || self.mls_group_id != snapshot.mls_group_id
            || self.epoch != snapshot.epoch
            || self.accepted_group_state_ref != snapshot.accepted_group_state_ref
        {
            return Err(arkret_wire::Error::Protocol(
                "pairwise author state does not name the exact accepted Realm MLS snapshot"
                    .to_owned(),
            ));
        }
        let matching = snapshot
            .active_leaves
            .iter()
            .filter(|leaf| leaf.leaf_index == self.leaf_index)
            .collect::<Vec<_>>();
        if matching.len() != 1
            || matching[0].basic_credential_identity.as_slice()
                != self.pairwise_actor_id.as_str().as_bytes()
            || matching[0].signature_key != self.leaf_signature_key
        {
            return Err(arkret_wire::Error::Protocol(
                "pairwise author is not the exact active BasicCredential leaf".to_owned(),
            ));
        }
        Ok(())
    }
}

impl RealmPairwiseKeyScopeLedger {
    pub fn validate_and_bind(
        &mut self,
        state: &RealmPairwiseAuthorState,
        snapshot: &RealmPairwiseAcceptedGroupState,
    ) -> arkret_wire::Result<()> {
        state.validate_against(snapshot)?;
        let identities = [
            format!("actor:{}", state.pairwise_actor_id),
            format!("full:{}", state.pairwise_full_id),
            format!("method:{}", state.verification_method),
            format!("key-ref:{}", state.local_signing_key_ref),
            format!("leaf-key:{}", hex::encode(&state.leaf_signature_key)),
        ];
        for identity in &identities {
            if self
                .bindings
                .get(identity)
                .is_some_and(|realm_id| realm_id != &state.realm_id)
            {
                return Err(arkret_wire::Error::Protocol(
                    "pairwise author key identity is already bound to another Realm".to_owned(),
                ));
            }
        }
        for identity in identities {
            self.bindings.insert(identity, state.realm_id.clone());
        }
        Ok(())
    }
}

/// Lifecycle of a published KeyPackage per `device-lifecycle.md` §2 /
/// `encryption-and-audit.md` §2.6. Once a KeyPackage is `claimed` it
/// MUST NOT be re-claimed; once `consumed` it MUST NOT return to
/// `published`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MlsKeyPackageState {
    #[default]
    Published,
    Claimed,
    Consumed,
    Revoked,
    Retired,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsKeyPackageRecord {
    /// Globally unique identifier (`ak:mls:kp:<uuid>`, RFC 9562 UUIDv7).
    pub keypackage_id: String,
    /// Exact MLS endpoint that owns the BasicCredential and LeafNode key.
    /// Human devices and Native Agent runtimes are mutually exclusive; callers
    /// must not infer one from the other or synthesize a placeholder device.
    pub endpoint: MlsEndpointIdentity,
    /// MLS KeyPackage material (base64url).
    pub key_package: String,
    /// Canonical hash of `key_package`.
    pub keypackage_ref: Hash,
    pub cipher_suites: Vec<String>,
    /// Content / MLS profile capabilities (e.g. `mimi.content.v1`).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Lifecycle state.
    #[serde(default)]
    pub state: MlsKeyPackageState,
    /// Bound `claim_id` once `state = claimed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<Proof>,
    /// Whether this is a reusable last-resort KeyPackage. Last-resort
    /// KeyPackages are NOT consumed on claim (the server keeps them
    /// claimable), so a member is always (re-)addable even after its
    /// single-use KeyPackages are exhausted. The init-key forward-secrecy
    /// trade-off is the standard MLS last-resort guarantee. The KeyPackage
    /// material MUST itself carry the OpenMLS `last_resort` extension (built
    /// via `mark_as_last_resort`) so the holder retains the init private key
    /// across repeated Welcome processing.
    #[serde(default)]
    pub last_resort: bool,
}

impl MlsKeyPackageRecord {
    /// Whether the record is currently usable for a Welcome.
    pub fn is_usable(&self) -> bool {
        !matches!(
            self.state,
            MlsKeyPackageState::Revoked
                | MlsKeyPackageState::Consumed
                | MlsKeyPackageState::Retired
        )
    }
}

#[cfg(test)]
mod tests {
    use super::MlsKeyPackageState;

    #[test]
    fn keypackage_wire_state_accepts_retired_and_rejects_expired() {
        let retired: MlsKeyPackageState = serde_json::from_str("\"retired\"").unwrap();
        assert_eq!(retired, MlsKeyPackageState::Retired);
        assert_eq!(serde_json::to_string(&retired).unwrap(), "\"retired\"");
        assert!(serde_json::from_str::<MlsKeyPackageState>("\"expired\"").is_err());
    }
}

/// Provider-opaque MLS group-state snapshot record.
///
/// Applications serialize provider-specific MLS state into
/// `serialized_state` while using the typed Arkret envelopes for KeyPackages,
/// Welcomes and Commits. The SDK crypto store keeps this layer independent
/// from OpenMLS internals.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsGroupStateRecord {
    pub group_id: String,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub epoch: u64,
    pub serialized_state: Vec<u8>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

// `serialized_state` is the full OpenMLS group snapshot (ratchet secrets +
// retained history secrets): render it redacted so a stray `{record:?}` in a
// log line can never leak decryptable key material.
impl std::fmt::Debug for MlsGroupStateRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsGroupStateRecord")
            .field("group_id", &self.group_id)
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("epoch", &self.epoch)
            .field(
                "serialized_state",
                &format_args!("<redacted {} bytes>", self.serialized_state.len()),
            )
            .field("updated_at", &self.updated_at)
            .finish()
    }
}
