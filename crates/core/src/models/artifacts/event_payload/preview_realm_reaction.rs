//! Preview-policy, profile-realm-override, reaction, read-receipt, realm, relation,
//! signature-material, space, state, and view payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{HistoryKeySource, RealmKeyWithheldReasonCode};
use crate::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/preview_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValueHistory {
    pub range: String,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_member_events: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValueToken {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_target_digest: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValue {
    pub mode: String,
    pub audiences: Vec<String>,
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<PreviewPolicyPayloadValueHistory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<PreviewPolicyPayloadValueToken>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayload {
    pub value: PreviewPolicyPayloadValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/profile_realm_override_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRealmOverridePayload {
    pub target_ref: String,
    pub target_realm_id: RealmId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// reaction_encrypted_payload_plaintext`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionEncryptedPayloadPlaintext {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_add_event_ids: Option<Vec<EventRef>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/reaction_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionPayload {
    pub target_ref: ObjectRef,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/read_receipt_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceiptPolicyPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_overrides_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_child_privacy_tightening_against_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_public_receipts_on_world_readable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_forced_public_world_readable_receipts: Option<bool>,
}

// `realm_archive_payload` now has a strong type:
// `models::operation_payloads::RealmArchivePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmCreatePayload {
    pub object: Realm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

// `realm_destroy_payload` now has a strong type:
// `models::operation_payloads::RealmDestroyPayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_disappearing_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDisappearingPolicyPayload {
    pub enabled: bool,
    pub max_ttl_ms: u64,
    pub allowed_triggers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_grace_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_realms: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_freeze_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmFreezePayload {
    pub frozen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_expires_at: Option<DateTime<Utc>>,
}

impl RealmFreezePayload {
    pub fn new(frozen: bool) -> Self {
        Self {
            frozen,
            reason: None,
            effective_at: None,
            freeze_expires_at: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        if !reason.trim().is_empty() {
            self.reason = Some(reason);
        }
        self
    }

    pub fn with_freeze_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.freeze_expires_at = Some(expires_at);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("realm freeze payload serialize: {err}")))
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_inheritance_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInheritancePolicyPayloadInherits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_bundles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_defaults: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInheritancePolicyPayload {
    pub source_realm_id: RealmId,
    pub inherits: RealmInheritancePolicyPayloadInherits,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<InheritancePolicyStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_scope`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyScope {
    pub effective_scope: Value,
    pub policy_digest: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_frontier_digest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<HistoryVisibilityValue>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/realm_key_request_scope`.
///
/// Request-flavoured scope: unlike [`RealmKeyScope`] (used by the durable
/// share), `policy_digest` is an OPTIONAL requester hint (the key source MUST
/// recompute effective policy) and `from_epoch` / `to_epoch` are REQUIRED (the
/// requester always names the epoch range it wants).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyRequestScope {
    pub effective_scope: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_frontier_digest: Option<Value>,
    pub from_epoch: u64,
    pub to_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<HistoryVisibilityValue>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/realm_key_request_content`.
///
/// Ephemeral `ck.realm_key.request` body: a device asks a provider to seal the
/// retained `history_secret[from..to]` for a Realm to its HPKE public key so it
/// can decrypt pre-join content. The sealed material rides back inside a
/// `ck.realm_key.share` `ciphertext`.
///
/// `requested_source_class` reuses the authoritative
/// [`crate::models::HistoryKeySource`] (defined in `history_visibility.rs`).
/// The direct request/share path is not allowed to request the
/// [`HistoryKeySource::KeyBackup`] class — backup-derived history keys are out
/// of scope here; [`RealmKeyRequestPayload::validate`] rejects it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyRequestPayload {
    pub key_scope: RealmKeyRequestScope,
    pub recipient_principal_id: Did,
    pub recipient_device_id: String,
    pub recipient_hpke_public_key: String,
    pub requested_source_class: HistoryKeySource,
    pub target_source_ref: String,
    pub target_principal_id: Did,
    pub created_at: DateTime<Utc>,
}

impl RealmKeyRequestPayload {
    /// Reject empty load-bearing fields and the out-of-scope `key_backup`
    /// source class before the request is shipped.
    pub fn validate(&self) -> Result<()> {
        if self.recipient_device_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ck.realm_key.request.recipient_device_id must not be empty".to_owned(),
            ));
        }
        if self.recipient_hpke_public_key.trim().is_empty() {
            return Err(Error::Protocol(
                "ck.realm_key.request.recipient_hpke_public_key must not be empty".to_owned(),
            ));
        }
        if self.requested_source_class == HistoryKeySource::KeyBackup {
            return Err(Error::Protocol(
                "ck.realm_key.request.requested_source_class must not be key_backup".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_audit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyShareAuditPayload {
    pub share_event_ref: EventRef,
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_principal_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_digest: Option<Hash>,
    pub recorded_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeySharePayload {
    pub recipient_principal_id: Did,
    pub recipient_device_id: String,
    pub sender_device_id: String,
    pub sender_device_signature: Value,
    pub key_scope: RealmKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_key_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RealmKeySharePayload {
    /// Canonical bytes the sender device MUST sign and place in
    /// `sender_device_signature` (device-lifecycle.md §13). Covers
    /// `sender_device_id`, recipient principal/device, `key_scope`,
    /// `ciphertext` / `encrypted_key_ref`, `aad_digest` and `created_at` —
    /// everything except the signature field itself. Signer and verifier MUST
    /// reconstruct it byte-identically; the to-device receiver verifies this
    /// independently of the durable Event-envelope signature.
    pub fn sender_signing_input(&self) -> Vec<u8> {
        let covered = serde_json::json!({
            "purpose": "ck.realm_key.share.sender_device_signature.v1",
            "sender_device_id": self.sender_device_id,
            "recipient_principal_id": self.recipient_principal_id,
            "recipient_device_id": self.recipient_device_id,
            "key_scope": self.key_scope,
            "ciphertext": self.ciphertext,
            "encrypted_key_ref": self.encrypted_key_ref,
            "aad_digest": self.aad_digest,
            "created_at": self.created_at,
        });
        crate::canonical::canonical_json_bytes(&covered).unwrap_or_default()
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_withheld_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyWithheldPayload {
    pub recipient_principal_id: Did,
    pub recipient_device_id: String,
    pub sender_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_scope: Option<RealmKeyScope>,
    pub withheld_reason_code: RealmKeyWithheldReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_search_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSearchPolicyPayload {
    pub enabled_profile_refs: Vec<String>,
    pub allowed_service_dids: Vec<Did>,
    pub data_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_retention_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_behavior: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leakage_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_rotation_cadence_ms: Option<u64>,
}

// `realm_tombstone_payload` now has a strong type:
// `models::operation_payloads::RealmTombstonePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

// `relation_create_payload` now has a strong type:
// `models::operation_payloads::RelationCreatePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_update_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationUpdatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/signature_material`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignatureMaterial {
    NonEmptyString(String),
    Variant1(BTreeMap<String, Value>),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceCreatePayload {
    pub object: Space,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_parent_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceParentPayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    pub expected_parent_space_id: Option<SpaceId>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacePatchPayload {
    pub space_id: SpaceId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_id: Option<ViewId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
}

#[cfg(test)]
mod realm_key_request_tests {
    use super::*;
    use serde_json::json;

    fn scope() -> RealmKeyScope {
        RealmKeyScope {
            effective_scope: json!({}),
            policy_digest: json!("sha256:00"),
            membership_frontier_digest: None,
            from_epoch: Some(0),
            to_epoch: Some(4),
            history_visibility: None,
        }
    }

    fn request_scope() -> RealmKeyRequestScope {
        RealmKeyRequestScope {
            effective_scope: json!({}),
            policy_digest: None,
            membership_frontier_digest: None,
            from_epoch: 0,
            to_epoch: 4,
            history_visibility: None,
        }
    }

    fn request(source: HistoryKeySource) -> RealmKeyRequestPayload {
        RealmKeyRequestPayload {
            key_scope: request_scope(),
            recipient_principal_id: Did::new(
                "did:webvh:example.test:users:01J0000000000000000000000A".to_owned(),
            )
            .unwrap(),
            recipient_device_id: "ck:device:01J0000000000000000000000B".to_owned(),
            recipient_hpke_public_key: "cHVia2V5".to_owned(),
            requested_source_class: source,
            target_source_ref: "ck:device:01J0000000000000000000000C".to_owned(),
            target_principal_id: Did::new(
                "did:webvh:example.test:users:01J0000000000000000000000D".to_owned(),
            )
            .unwrap(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn realm_key_request_round_trips_and_field_order_is_stable() {
        let payload = request(HistoryKeySource::VerifiedMemberDevice);
        payload.validate().unwrap();
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            value["requested_source_class"],
            json!("verified_member_device")
        );
        let parsed: RealmKeyRequestPayload = serde_json::from_value(value).unwrap();
        assert_eq!(
            parsed.recipient_device_id,
            payload.recipient_device_id
        );
        assert_eq!(parsed.target_source_ref, payload.target_source_ref);
    }

    #[test]
    fn realm_key_request_rejects_key_backup_and_empty_fields() {
        assert!(request(HistoryKeySource::KeyBackup).validate().is_err());

        let mut bad = request(HistoryKeySource::OwnDevice);
        bad.recipient_hpke_public_key = "   ".to_owned();
        assert!(bad.validate().is_err());
    }
}
