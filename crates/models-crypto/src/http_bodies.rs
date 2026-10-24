//! Key-package HTTP request/outcome DTO counterparts for the
//! `ak.self.keys.*` key-package operations
//! (`service-operation-dtos.schema.json`). Pure wire shapes; upload,
//! claim, and consumption behavior lives with the transport and server
//! crates.

use std::collections::BTreeSet;

use arkret_wire::{
    AccountId, ActorId, AuditReasonText, Base64UrlString, DeviceId, DidCoreId, DidUrl,
    DomainSeparationId, EventId, Hash, KeyPackageRef, KeypackageClaimId, MlsGroupId,
    MlsWelcomeDeliveryId, NonEmptyString, RealmId, StrandId,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::artifacts_keys::{
    Failure, KeyOperationSignature, KeyPackageClaimRecord, KeyPackageUploadEntry,
};
use crate::key_backup::KeyBackup;
use crate::keypackage_capabilities::{
    validate_advertised_keypackage_capabilities, validate_required_keypackage_capabilities,
};
use crate::mls_records::MlsKeyPackageRecord;

/// Counterpart for `keypackage-operations.schema.json#/$defs/keypackages_upload_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesUploadRequestBody {
    pub actor_id: ActorId,
    pub principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_authorize_event_id: Option<EventId>,
    pub keypackages: Vec<KeyPackageUploadEntry>,
    pub endpoint_signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<MlsGroupId>,
}

/// Canonical unsigned projection for
/// `ak.self.keys.keypackages.upload.create.v1`.
///
/// The request-level signature is absent by construction, so producers and
/// verifiers cannot accidentally sign different upload shapes.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesUploadFields {
    pub actor_id: ActorId,
    pub principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_authorize_event_id: Option<EventId>,
    pub keypackages: Vec<KeyPackageUploadEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<MlsGroupId>,
}

// A missing optional member stays absent. Explicit null cannot be collapsed
// into absence because the complete upload object is the signing transcript.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPackagesUploadWire {
    actor_id: ActorId,
    principal_id: DidCoreId,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    device_id: Option<DeviceId>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    agent_verification_method: Option<DidUrl>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    agent_key_authorize_event_id: Option<EventId>,
    keypackages: Vec<KeyPackageUploadEntry>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    endpoint_signature: Option<KeyOperationSignature>,
    #[serde(
        default,
        deserialize_with = "deserialize_upload_expiry_canonical_timestamp"
    )]
    expires_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    strand_id: Option<StrandId>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    mls_group_id: Option<MlsGroupId>,
}

// A missing Agent device selector defaults to an empty vector. A present
// selector must satisfy the schema before deserialization can erase presence.
pub(crate) fn deserialize_keypackage_unique_nonempty<'de, D, T>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Ord,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.is_empty() || values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(serde::de::Error::custom(
            "KeyPackage array must be non-empty and unique",
        ));
    }
    Ok(values)
}

pub(crate) fn deserialize_keypackage_positive_millis<'de, D>(
    deserializer: D,
) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let timeout = u64::deserialize(deserializer)?;
    if timeout == 0 {
        return Err(serde::de::Error::custom(
            "millisecond value must be positive when present",
        ));
    }
    Ok(Some(timeout))
}

fn deserialize_keypackage_nonempty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.is_empty() {
        return Err(serde::de::Error::custom(
            "KeyPackage array must be non-empty",
        ));
    }
    Ok(values)
}

pub(crate) fn deserialize_keypackage_string_list<'de, D>(
    deserializer: D,
) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = deserialize_keypackage_unique_nonempty::<D, NonEmptyString>(deserializer)?;
    Ok(values
        .into_iter()
        .map(|value| value.as_str().to_owned())
        .collect())
}

fn deserialize_keypackage_optional_string_list<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_keypackage_string_list(deserializer).map(Some)
}

fn deserialize_upload_expiry_canonical_timestamp<'de, D>(
    deserializer: D,
) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    arkret_canonical::serde_helpers::canonical_timestamp::deserialize(deserializer).map(Some)
}

impl KeyPackagesUploadWire {
    fn into_unsigned(self) -> KeyPackagesUploadFields {
        KeyPackagesUploadFields {
            actor_id: self.actor_id,
            principal_id: self.principal_id,
            device_id: self.device_id,
            agent_verification_method: self.agent_verification_method,
            agent_key_authorize_event_id: self.agent_key_authorize_event_id,
            keypackages: self.keypackages,
            expires_at: self.expires_at,
            strand_id: self.strand_id,
            mls_group_id: self.mls_group_id,
        }
    }
}

impl<'de> Deserialize<'de> for KeyPackagesUploadRequestBody {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut wire = KeyPackagesUploadWire::deserialize(deserializer)?;
        let signature = wire
            .endpoint_signature
            .take()
            .ok_or_else(|| serde::de::Error::missing_field("endpoint_signature"))?;
        let body = wire.into_unsigned().into_signed(signature);
        body.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(body)
    }
}

impl<'de> Deserialize<'de> for KeyPackagesUploadFields {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = KeyPackagesUploadWire::deserialize(deserializer)?;
        if wire.endpoint_signature.is_some() {
            return Err(serde::de::Error::custom(
                "unsigned upload forbids endpoint_signature",
            ));
        }
        let unsigned = wire.into_unsigned();
        unsigned
            .validate_shape()
            .map_err(serde::de::Error::custom)?;
        Ok(unsigned)
    }
}

impl KeyPackagesUploadRequestBody {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        self.unsigned().validate_shape()?;
        if self
            .agent_verification_method
            .as_ref()
            .is_some_and(|method| self.endpoint_signature.kid.as_str() != method.as_str())
        {
            return Err("Agent KeyPackage upload signer must match its endpoint method");
        }
        Ok(())
    }

    #[must_use]
    pub fn unsigned(&self) -> KeyPackagesUploadFields {
        KeyPackagesUploadFields {
            actor_id: self.actor_id.clone(),
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            agent_verification_method: self.agent_verification_method.clone(),
            agent_key_authorize_event_id: self.agent_key_authorize_event_id.clone(),
            keypackages: self.keypackages.clone(),
            expires_at: self.expires_at,
            strand_id: self.strand_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
        }
    }
}

impl KeyPackagesUploadFields {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        validate_keypackage_account_actor(&self.actor_id, &self.principal_id)?;
        if self.keypackages.is_empty() {
            return Err("KeyPackage upload requires at least one entry");
        }
        let mut identities = BTreeSet::new();
        for entry in &self.keypackages {
            crate::artifacts_keys::validate_mls_keypackage_identity(&entry.keypackage_id)?;
            if !identities.insert(entry.keypackage_id.as_str()) {
                return Err("KeyPackage upload requires unique KeyPackage identities");
            }
        }
        match (
            &self.device_id,
            &self.agent_verification_method,
            &self.agent_key_authorize_event_id,
        ) {
            (Some(_), None, None) | (None, Some(_), Some(_)) => Ok(()),
            _ => Err("KeyPackage upload must select exactly one Human-device or Agent endpoint"),
        }
    }

    #[must_use]
    pub fn into_signed(
        self,
        endpoint_signature: KeyOperationSignature,
    ) -> KeyPackagesUploadRequestBody {
        KeyPackagesUploadRequestBody {
            actor_id: self.actor_id,
            principal_id: self.principal_id,
            device_id: self.device_id,
            agent_verification_method: self.agent_verification_method,
            agent_key_authorize_event_id: self.agent_key_authorize_event_id,
            keypackages: self.keypackages,
            endpoint_signature,
            expires_at: self.expires_at,
            strand_id: self.strand_id,
            mls_group_id: self.mls_group_id,
        }
    }
}

/// Convert a persisted MLS KeyPackage record into the canonical typed upload
/// entry shared by ordinary devices and Agent runtimes.
///
/// Request ownership and signing-key authorization remain caller concerns;
/// this helper owns only the record-to-wire projection so digest, expiry, and
/// last-resort semantics cannot drift between clients.
pub fn mls_key_package_record_upload_entry(
    record: &MlsKeyPackageRecord,
) -> Result<KeyPackageUploadEntry, &'static str> {
    Ok(KeyPackageUploadEntry {
        keypackage_id: record.keypackage_id.clone(),
        keypackage_ref: record.keypackage_ref.as_str().to_owned(),
        keypackage: Base64UrlString::new(record.keypackage.clone())?,
        cipher_suites: record.cipher_suites.clone(),
        capabilities: record.capabilities.clone(),
        expires_at: record
            .expires_at
            .unwrap_or(record.created_at + Duration::days(7)),
        created_at: record.created_at,
        last_resort: record.last_resort.then_some(true),
    })
}

pub const KEYPACKAGES_UPLOAD_SIGNATURE_DOMAIN: &str = "ak.self.keys.keypackages.upload.create.v1\n";
pub const KEYPACKAGES_CONSUME_SIGNATURE_DOMAIN: &str =
    "ak.self.keys.keypackages.command.consume.v1\n";
pub const KEYPACKAGES_REVOKE_SIGNATURE_DOMAIN: &str =
    "ak.self.keys.keypackages.command.revoke.v1\n";

fn keypackage_signing_input<T: Serialize>(
    domain: &str,
    unsigned: &T,
) -> arkret_canonical::Result<Vec<u8>> {
    let canonical = arkret_canonical::canonical_json_bytes(unsigned)?;
    let mut input = Vec::with_capacity(domain.len() + canonical.len());
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(&canonical);
    Ok(input)
}

pub fn keypackages_upload_signing_input(
    unsigned: &KeyPackagesUploadFields,
) -> arkret_canonical::Result<Vec<u8>> {
    unsigned
        .validate_shape()
        .map_err(|error| arkret_canonical::CanonicalError::Protocol(error.to_owned()))?;
    keypackage_signing_input(KEYPACKAGES_UPLOAD_SIGNATURE_DOMAIN, unsigned)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesUploadResponseBody {
    pub accepted: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<Failure>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_keypackage_string_list"
    )]
    pub keypackage_refs: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerKeyPackageClaimPurpose {
    RealmMembership,
    DirectConversation,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerKeyPackageRequesterAuthorization {
    Device {
        verification_method: DidUrl,
        requester_device_id: DeviceId,
        device_authorize_event_id: EventId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        signed_at: DateTime<Utc>,
        signature: KeyOperationSignature,
    },
    RealmDevice {
        verification_method: DidUrl,
        requester_device_id: DeviceId,
        device_authorize_event_id: EventId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        signed_at: DateTime<Utc>,
        signature: KeyOperationSignature,
    },
    Agent {
        verification_method: DidUrl,
        requester_agent_id: DidCoreId,
        agent_key_authorize_event_id: EventId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        signed_at: DateTime<Utc>,
        signature: KeyOperationSignature,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimFields {
    pub claim_request_id: Base64UrlString,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_account_id: Option<AccountId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_actor_id: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub requester_account_id: Option<AccountId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub requester_actor_id: Option<ActorId>,
    pub intended_realm_id: RealmId,
    pub mls_group_id: MlsGroupId,
    pub claim_purpose: PeerKeyPackageClaimPurpose,
    #[serde(deserialize_with = "deserialize_keypackage_unique_nonempty")]
    pub required_capabilities: Vec<NonEmptyString>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_keypackage_unique_nonempty"
    )]
    pub target_device_ids: Vec<DeviceId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_keypackage_ref: Option<KeyPackageRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_agent_id: Option<DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_agent_verification_method: Option<DidUrl>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_agent_key_authorize_event_id: Option<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_keypackage_positive_millis"
    )]
    pub timeout_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub strand_id: Option<StrandId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub pair_key: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub last_resort_allowed: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesClaimServiceBinding {
    pub source_id: DidCoreId,
    pub destination_id: DidCoreId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimRequestBody {
    pub claim_request_id: Base64UrlString,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_account_id: Option<AccountId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_actor_id: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub requester_account_id: Option<AccountId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub requester_actor_id: Option<ActorId>,
    pub intended_realm_id: RealmId,
    pub mls_group_id: MlsGroupId,
    pub claim_purpose: PeerKeyPackageClaimPurpose,
    #[serde(deserialize_with = "deserialize_keypackage_unique_nonempty")]
    pub required_capabilities: Vec<NonEmptyString>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_keypackage_unique_nonempty"
    )]
    pub target_device_ids: Vec<DeviceId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_keypackage_ref: Option<KeyPackageRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_agent_id: Option<DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_agent_verification_method: Option<DidUrl>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_agent_key_authorize_event_id: Option<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_keypackage_positive_millis"
    )]
    pub timeout_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub strand_id: Option<StrandId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub pair_key: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub last_resort_allowed: Option<bool>,
    pub service_binding: KeyPackagesClaimServiceBinding,
    pub requester_authorization: PeerKeyPackageRequesterAuthorization,
}

impl PeerKeyPackagesClaimRequestBody {
    pub fn unsigned_request(&self) -> PeerKeyPackagesClaimFields {
        PeerKeyPackagesClaimFields {
            claim_request_id: self.claim_request_id.clone(),
            target_account_id: self.target_account_id.clone(),
            target_actor_id: self.target_actor_id.clone(),
            requester_account_id: self.requester_account_id.clone(),
            requester_actor_id: self.requester_actor_id.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
            claim_purpose: self.claim_purpose,
            required_capabilities: self.required_capabilities.clone(),
            expires_at: self.expires_at,
            target_device_ids: self.target_device_ids.clone(),
            target_keypackage_ref: self.target_keypackage_ref.clone(),
            target_agent_id: self.target_agent_id.clone(),
            target_agent_verification_method: self.target_agent_verification_method.clone(),
            target_agent_key_authorize_event_id: self.target_agent_key_authorize_event_id.clone(),
            timeout_ms: self.timeout_ms,
            strand_id: self.strand_id.clone(),
            pair_key: self.pair_key.clone(),
            last_resort_allowed: self.last_resort_allowed,
        }
    }

    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        validate_key_packages_claim_request_shape(
            &self.unsigned_request(),
            &self.requester_authorization,
        )
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesClaimRequestBody {
    pub claim_request_id: Base64UrlString,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_account_id: Option<AccountId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_actor_id: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub requester_account_id: Option<AccountId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub requester_actor_id: Option<ActorId>,
    pub intended_realm_id: RealmId,
    pub mls_group_id: MlsGroupId,
    pub claim_purpose: PeerKeyPackageClaimPurpose,
    #[serde(deserialize_with = "deserialize_keypackage_unique_nonempty")]
    pub required_capabilities: Vec<NonEmptyString>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_keypackage_unique_nonempty"
    )]
    pub target_device_ids: Vec<DeviceId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_keypackage_ref: Option<KeyPackageRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_agent_id: Option<DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_agent_verification_method: Option<DidUrl>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub target_agent_key_authorize_event_id: Option<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_keypackage_positive_millis"
    )]
    pub timeout_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub strand_id: Option<StrandId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub pair_key: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub last_resort_allowed: Option<bool>,
    pub service_binding: KeyPackagesClaimServiceBinding,
    pub requester_authorization: PeerKeyPackageRequesterAuthorization,
}

impl KeyPackagesClaimRequestBody {
    pub fn unsigned_request(&self) -> PeerKeyPackagesClaimFields {
        PeerKeyPackagesClaimFields {
            claim_request_id: self.claim_request_id.clone(),
            target_account_id: self.target_account_id.clone(),
            target_actor_id: self.target_actor_id.clone(),
            requester_account_id: self.requester_account_id.clone(),
            requester_actor_id: self.requester_actor_id.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
            claim_purpose: self.claim_purpose,
            required_capabilities: self.required_capabilities.clone(),
            expires_at: self.expires_at,
            target_device_ids: self.target_device_ids.clone(),
            target_keypackage_ref: self.target_keypackage_ref.clone(),
            target_agent_id: self.target_agent_id.clone(),
            target_agent_verification_method: self.target_agent_verification_method.clone(),
            target_agent_key_authorize_event_id: self.target_agent_key_authorize_event_id.clone(),
            timeout_ms: self.timeout_ms,
            strand_id: self.strand_id.clone(),
            pair_key: self.pair_key.clone(),
            last_resort_allowed: self.last_resort_allowed,
        }
    }

    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        validate_key_packages_claim_request_shape(
            &self.unsigned_request(),
            &self.requester_authorization,
        )
    }
}

impl From<&KeyPackagesClaimRequestBody> for PeerKeyPackagesClaimRequestBody {
    fn from(value: &KeyPackagesClaimRequestBody) -> Self {
        Self {
            claim_request_id: value.claim_request_id.clone(),
            target_account_id: value.target_account_id.clone(),
            target_actor_id: value.target_actor_id.clone(),
            requester_account_id: value.requester_account_id.clone(),
            requester_actor_id: value.requester_actor_id.clone(),
            intended_realm_id: value.intended_realm_id.clone(),
            mls_group_id: value.mls_group_id.clone(),
            claim_purpose: value.claim_purpose,
            required_capabilities: value.required_capabilities.clone(),
            expires_at: value.expires_at,
            target_device_ids: value.target_device_ids.clone(),
            target_keypackage_ref: value.target_keypackage_ref.clone(),
            target_agent_id: value.target_agent_id.clone(),
            target_agent_verification_method: value.target_agent_verification_method.clone(),
            target_agent_key_authorize_event_id: value.target_agent_key_authorize_event_id.clone(),
            timeout_ms: value.timeout_ms,
            strand_id: value.strand_id.clone(),
            pair_key: value.pair_key.clone(),
            last_resort_allowed: value.last_resort_allowed,
            service_binding: value.service_binding.clone(),
            requester_authorization: value.requester_authorization.clone(),
        }
    }
}

fn validate_key_packages_claim_request_shape(
    unsigned_request: &PeerKeyPackagesClaimFields,
    requester_authorization: &PeerKeyPackageRequesterAuthorization,
) -> Result<(), PeerKeyPackageClaimShapeError> {
    validate_peer_claim_fields(unsigned_request)?;
    match requester_authorization {
        PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            signature,
            ..
        } => {
            if unsigned_request.requester_account_id.is_none()
                || unsigned_request.requester_actor_id.is_some()
                || signature.kid.as_str() != verification_method.as_str()
            {
                return Err(PeerKeyPackageClaimShapeError::VerificationMethodMismatch);
            }
            let _ = (requester_device_id, device_authorize_event_id);
        }
        PeerKeyPackageRequesterAuthorization::RealmDevice {
            verification_method,
            signature,
            ..
        } => {
            if unsigned_request.requester_account_id.is_some()
                || !unsigned_request
                    .requester_actor_id
                    .as_ref()
                    .is_some_and(|actor| {
                        actor
                            .as_realm_actor_id()
                            .is_some_and(|id| id.realm_id == unsigned_request.intended_realm_id)
                    })
                || signature.kid.as_str() != verification_method.as_str()
            {
                return Err(PeerKeyPackageClaimShapeError::InvalidAuthorizationModel);
            }
        }
        PeerKeyPackageRequesterAuthorization::Agent {
            verification_method,
            requester_agent_id: _,
            agent_key_authorize_event_id,
            signature,
            ..
        } => {
            if unsigned_request.requester_account_id.is_some()
                || unsigned_request.requester_actor_id.is_some()
                || signature.kid.as_str() != verification_method.as_str()
            {
                return Err(PeerKeyPackageClaimShapeError::VerificationMethodMismatch);
            }
            let _ = agent_key_authorize_event_id;
        }
    }
    Ok(())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackageClaimReceipt {
    pub claim_request_id: Base64UrlString,
    pub request_digest: Hash,
    pub claims_digest: Hash,
    pub source_id: DidCoreId,
    pub destination_id: DidCoreId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub claim_authority_ref: Option<arkret_wire::RealmCommitAuthorityRef>,
    pub request: PeerKeyPackagesClaimFields,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub claimed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimResponseBody {
    pub claim_request_id: Base64UrlString,
    #[serde(deserialize_with = "deserialize_keypackage_nonempty")]
    pub claims: Vec<KeyPackageClaimRecord>,
    pub claim_receipt: PeerKeyPackageClaimReceipt,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesClaimResponseBody {
    pub claim_request_id: Base64UrlString,
    #[serde(deserialize_with = "deserialize_keypackage_nonempty")]
    pub claims: Vec<KeyPackageClaimRecord>,
    pub claim_receipt: PeerKeyPackageClaimReceipt,
}

impl KeyPackagesClaimResponseBody {
    /// Enforce the cross-field receipt/outcome bindings that JSON Schema
    /// cannot express by itself.
    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        validate_key_packages_claim_outcome_shape(
            &self.claim_request_id,
            &self.claims,
            &self.claim_receipt,
        )
    }
}

impl From<PeerKeyPackagesClaimResponseBody> for KeyPackagesClaimResponseBody {
    fn from(value: PeerKeyPackagesClaimResponseBody) -> Self {
        Self {
            claim_request_id: value.claim_request_id,
            claims: value.claims,
            claim_receipt: value.claim_receipt,
        }
    }
}

impl PeerKeyPackagesClaimResponseBody {
    /// Enforce the cross-field receipt/outcome bindings that JSON Schema
    /// cannot express by itself.
    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        validate_key_packages_claim_outcome_shape(
            &self.claim_request_id,
            &self.claims,
            &self.claim_receipt,
        )
    }
}

fn validate_key_packages_claim_outcome_shape(
    claim_request_id: &Base64UrlString,
    claims: &[KeyPackageClaimRecord],
    receipt: &PeerKeyPackageClaimReceipt,
) -> Result<(), PeerKeyPackageClaimShapeError> {
    if claims.is_empty()
        || claim_request_id != &receipt.claim_request_id
        || receipt.claim_request_id != receipt.request.claim_request_id
        || receipt.request.expires_at != receipt.expires_at
        || receipt.claimed_at >= receipt.expires_at
        || claims
            .iter()
            .any(|claim| claim.expires_at < receipt.expires_at)
    {
        return Err(PeerKeyPackageClaimShapeError::InvalidClaimOutcome);
    }
    for claim in claims {
        validate_target_claim_evidence(claim, receipt)?;
    }
    if receipt.request.target_keypackage_ref.is_some() && claims.len() != 1 {
        return Err(PeerKeyPackageClaimShapeError::InvalidClaimOutcome);
    }
    let claims_digest = arkret_canonical::canonical_sha256(&claims)
        .map_err(|_| PeerKeyPackageClaimShapeError::InvalidClaimOutcome)?;
    if receipt.claims_digest.as_str() != claims_digest {
        return Err(PeerKeyPackageClaimShapeError::InvalidClaimOutcome);
    }
    Ok(())
}

/// Owner read of one claim of the caller's own KeyPackage
/// (`ak.self.keys.keypackages.read.claim.v1`). The response is the
/// byte-identical original [`KeyPackagesClaimResponseBody`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesClaimQueryRequestBody {
    pub claim_id: KeypackageClaimId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimQueryRequestBody {
    pub claim_request_id: Base64UrlString,
    pub request_digest: Hash,
}

impl PeerKeyPackagesClaimQueryRequestBody {
    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        if !(22..=128).contains(&self.claim_request_id.as_str().len()) {
            return Err(PeerKeyPackageClaimShapeError::InvalidClaimRequestId);
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerKeyPackagesClaimQueryState {
    Unknown,
    Pending,
    Claimed,
    Consumed,
    ClaimFailed,
    Expired,
    Revoked,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPackageClaimTerminalState {
    NeverClaimed,
    Expired,
    Revoked,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageClaimTerminalReceipt {
    pub domain: NonEmptyString,
    pub claim_request_id: Base64UrlString,
    pub request_digest: Hash,
    pub terminal_state: KeyPackageClaimTerminalState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_keypackage_optional_string_list"
    )]
    pub keypackage_refs: Option<Vec<String>>,
    pub source_id: DidCoreId,
    pub destination_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub terminal_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

impl KeyPackageClaimTerminalReceipt {
    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        if self.domain.as_str() != DomainSeparationId::KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1
            || !(22..=128).contains(&self.claim_request_id.as_str().len())
            || self
                .signature
                .signature_algorithm
                .as_ref()
                .is_none_or(|algorithm| algorithm.as_str() != "Ed25519")
        {
            return Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome);
        }
        match (self.terminal_state, self.keypackage_refs.as_ref()) {
            (KeyPackageClaimTerminalState::NeverClaimed, None) => Ok(()),
            (
                KeyPackageClaimTerminalState::Expired | KeyPackageClaimTerminalState::Revoked,
                Some(references),
            ) if !references.is_empty()
                && references.iter().all(|reference| !reference.is_empty())
                && references.iter().collect::<BTreeSet<_>>().len() == references.len() =>
            {
                Ok(())
            }
            _ => Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome),
        }
    }

    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        signed_receipt_canonical_signing_bytes(self, self.domain.as_str())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimQueryResponseBody {
    pub claim_request_id: Base64UrlString,
    pub state: PeerKeyPackagesClaimQueryState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub claim_outcome: Option<PeerKeyPackagesClaimResponseBody>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub consume_receipt: Option<KeyPackageConsumeReceipt>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub terminal_receipt: Option<KeyPackageClaimTerminalReceipt>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_keypackage_positive_millis"
    )]
    pub retry_after_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub error_code: Option<PeerKeyPackageClaimErrorCode>,
}

impl PeerKeyPackagesClaimQueryResponseBody {
    /// Peer command uses the same closed durable view, except that it cannot
    /// return unknown after admitting a command identity.
    pub fn validate_command_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        self.validate_shape()?;
        if self.state == PeerKeyPackagesClaimQueryState::Unknown {
            return Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome);
        }
        Ok(())
    }
    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        if let Some(outcome) = &self.claim_outcome
            && (outcome.claim_request_id != self.claim_request_id
                || outcome.validate_shape().is_err())
        {
            return Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome);
        }
        if let Some(receipt) = &self.consume_receipt
            && (receipt.recipient_durable_receipt.claim_request_id != self.claim_request_id
                || receipt.validate_shape().is_err())
        {
            return Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome);
        }
        if let Some(receipt) = &self.terminal_receipt {
            let expected = match self.state {
                PeerKeyPackagesClaimQueryState::Expired => {
                    Some(KeyPackageClaimTerminalState::Expired)
                }
                PeerKeyPackagesClaimQueryState::Revoked => {
                    Some(KeyPackageClaimTerminalState::Revoked)
                }
                PeerKeyPackagesClaimQueryState::ClaimFailed => {
                    Some(KeyPackageClaimTerminalState::NeverClaimed)
                }
                _ => None,
            };
            if receipt.validate_shape().is_err()
                || receipt.claim_request_id != self.claim_request_id
                || expected != Some(receipt.terminal_state)
            {
                return Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome);
            }
        }
        match self.state {
            PeerKeyPackagesClaimQueryState::Pending
                if self.claim_outcome.is_none()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_none()
                    && self.retry_after_ms.is_some_and(|value| value > 0)
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Claimed
                if self.claim_outcome.is_some()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_none()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Consumed
                if self.claim_outcome.is_some()
                    && self.consume_receipt.is_some()
                    && self.terminal_receipt.is_none()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Expired | PeerKeyPackagesClaimQueryState::Revoked
                if self.claim_outcome.is_some()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_some()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::ClaimFailed
                if self.claim_outcome.is_none()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_some()
                    && self.retry_after_ms.is_none()
                    && self.error_code == Some(PeerKeyPackageClaimErrorCode::ClaimFailed) =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Unknown
                if self.claim_outcome.is_none()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_none()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            _ => Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerKeyPackageClaimErrorCode {
    #[serde(rename = "claim_failed")]
    ClaimFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PeerKeyPackageClaimShapeError {
    #[error("claim_request_id must encode at least 128 bits and be at most 128 characters")]
    InvalidClaimRequestId,
    #[error("required_capabilities must be non-empty and unique")]
    InvalidRequiredCapabilities,
    #[error("target_device_ids must be unique")]
    DuplicateTargetDevice,
    #[error("millisecond value must be positive when present")]
    InvalidTimeout,
    #[error("direct conversation claims require strand_id and pair_key and forbid last resort")]
    InvalidDirectConversationFields,
    #[error("requester authorization must select exactly one supported authority model")]
    InvalidAuthorizationModel,
    #[error("requester authorization signature kid must equal verification_method")]
    VerificationMethodMismatch,
    #[error("peer claim query outcome fields do not match its state")]
    InvalidQueryOutcome,
    #[error("peer claim outcome fields or receipt bindings are inconsistent")]
    InvalidClaimOutcome,
    #[error("requester signing key evidence does not match requester authorization")]
    SignerEvidenceMismatch,
    #[error("target signing key evidence does not match its claim record")]
    TargetSignerEvidenceMismatch,
}

/// Validate one returned claim against every target selector carried by the
/// signed request embedded in the destination receipt.
pub fn validate_target_claim_evidence(
    claim: &KeyPackageClaimRecord,
    receipt: &PeerKeyPackageClaimReceipt,
) -> Result<(), PeerKeyPackageClaimShapeError> {
    claim
        .validate_shape()
        .map_err(|_| PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch)?;
    let request = &receipt.request;
    if request
        .target_actor_id
        .as_ref()
        .is_some_and(|actor| actor != &claim.actor_id)
        || request
            .target_account_id
            .as_ref()
            .is_some_and(|account| claim.actor_id.as_account_id() != Some(account))
        || request.target_actor_id.is_some() != receipt.claim_authority_ref.is_some()
    {
        return Err(PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch);
    }
    let required_capabilities = request
        .required_capabilities
        .iter()
        .map(NonEmptyString::as_str)
        .collect::<Vec<_>>();
    let advertised_capabilities = claim
        .capabilities
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    validate_required_keypackage_capabilities(&required_capabilities, &advertised_capabilities)
        .map_err(|_| PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch)?;
    if request.target_principal_id().as_ref() != Some(&claim.principal_id)
        || request
            .target_keypackage_ref
            .as_ref()
            .is_some_and(|expected| expected.as_str() != claim.keypackage_ref)
        || request.required_capabilities.iter().any(|required| {
            !claim
                .capabilities
                .iter()
                .any(|actual| actual == required.as_str())
        })
        || request.last_resort_allowed != Some(true) && claim.last_resort == Some(true)
    {
        return Err(PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch);
    }
    match (
        &claim.device_authorize_event_id,
        &claim.agent_key_authorize_event_id,
    ) {
        (Some(_), None) => {
            if claim.device_id.is_none()
                || claim
                    .device_id
                    .as_ref()
                    .is_some_and(|device| !request.target_device_ids.contains(device))
                || request.target_device_ids.is_empty()
                || request.target_agent_id.is_some()
                || request.target_agent_verification_method.is_some()
                || request.target_agent_key_authorize_event_id.is_some()
                || claim.agent_id.is_some()
                || claim.agent_verification_method.is_some()
            {
                return Err(PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch);
            }
        }
        (None, Some(_)) => {
            if claim.agent_id.as_ref().map(DidCoreId::as_core_id)
                != Some(claim.principal_id.as_core_id())
                || claim.agent_id.as_ref() != request.target_agent_id.as_ref()
                || claim.agent_verification_method.as_ref()
                    != request.target_agent_verification_method.as_ref()
                || claim.agent_key_authorize_event_id.as_ref()
                    != request.target_agent_key_authorize_event_id.as_ref()
                || !request.target_device_ids.is_empty()
                || claim.device_id.is_some()
                || claim.agent_verification_method.as_ref().is_none()
            {
                return Err(PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch);
            }
        }
        _ => return Err(PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch),
    }
    Ok(())
}

fn validate_peer_claim_fields(
    request: &PeerKeyPackagesClaimFields,
) -> Result<(), PeerKeyPackageClaimShapeError> {
    if !(22..=128).contains(&request.claim_request_id.as_str().len()) {
        return Err(PeerKeyPackageClaimShapeError::InvalidClaimRequestId);
    }
    if request.timeout_ms == Some(0) {
        return Err(PeerKeyPackageClaimShapeError::InvalidTimeout);
    }
    let capabilities = request
        .required_capabilities
        .iter()
        .map(NonEmptyString::as_str)
        .collect::<BTreeSet<_>>();
    let canonical_capabilities = request
        .required_capabilities
        .iter()
        .map(NonEmptyString::as_str)
        .collect::<Vec<_>>();
    if capabilities.is_empty()
        || capabilities.len() != request.required_capabilities.len()
        || validate_advertised_keypackage_capabilities(&canonical_capabilities).is_err()
        || canonical_capabilities
            .iter()
            .any(|capability| !crate::is_active_keypackage_capability(capability))
    {
        return Err(PeerKeyPackageClaimShapeError::InvalidRequiredCapabilities);
    }
    let target_devices = request
        .target_device_ids
        .iter()
        .map(DeviceId::as_str)
        .collect::<BTreeSet<_>>();
    if target_devices.len() != request.target_device_ids.len() {
        return Err(PeerKeyPackageClaimShapeError::DuplicateTargetDevice);
    }
    if request.claim_purpose == PeerKeyPackageClaimPurpose::DirectConversation
        && (request.strand_id.is_none()
            || request.pair_key.is_none()
            || request.last_resort_allowed == Some(true))
    {
        return Err(PeerKeyPackageClaimShapeError::InvalidDirectConversationFields);
    }
    let human_target = request.target_actor_id.is_none()
        && request.target_account_id.is_some()
        && !request.target_device_ids.is_empty()
        && request.target_agent_id.is_none()
        && request.target_agent_verification_method.is_none()
        && request.target_agent_key_authorize_event_id.is_none();
    let agent_target = request.target_actor_id.is_none()
        && request.target_account_id.is_none()
        && request.target_device_ids.is_empty()
        && request.target_agent_id.is_some()
        && request.target_agent_verification_method.is_some()
        && request.target_agent_key_authorize_event_id.is_some();
    let realm_target = request.target_account_id.is_none()
        && request.target_actor_id.as_ref().is_some_and(|actor| {
            actor.validate().is_ok()
                && actor
                    .as_realm_actor_id()
                    .is_some_and(|id| id.realm_id == request.intended_realm_id)
        })
        && !request.target_device_ids.is_empty()
        && request.target_agent_id.is_none()
        && request.target_agent_verification_method.is_none()
        && request.target_agent_key_authorize_event_id.is_none();
    if request.requester_actor_id.as_ref().is_some_and(|actor| {
        actor.validate().is_err()
            || actor
                .as_realm_actor_id()
                .is_none_or(|id| id.realm_id != request.intended_realm_id)
    }) || request.requester_actor_id.is_some() && request.requester_account_id.is_some()
        || (realm_target || request.requester_actor_id.is_some())
            && request.claim_purpose != PeerKeyPackageClaimPurpose::RealmMembership
    {
        return Err(PeerKeyPackageClaimShapeError::InvalidAuthorizationModel);
    }
    if [human_target, agent_target, realm_target]
        .into_iter()
        .filter(|selected| *selected)
        .count()
        != 1
        || request.target_keypackage_ref.is_some()
            && (request.last_resort_allowed == Some(true)
                || (human_target || realm_target) && request.target_device_ids.len() != 1)
    {
        return Err(PeerKeyPackageClaimShapeError::InvalidDirectConversationFields);
    }
    Ok(())
}

fn validate_keypackage_account_actor(
    actor_id: &ActorId,
    principal_id: &DidCoreId,
) -> Result<(), &'static str> {
    actor_id
        .validate()
        .map_err(|_| "KeyPackage actor_id is invalid")?;
    if actor_id.as_account_id().is_none() && actor_id.as_realm_actor_id().is_none() {
        return Err("Device KeyPackage requires an Account or Realm actor");
    }
    if actor_id.signing_principal_id() != principal_id {
        return Err("KeyPackage actor_id principal differs from principal_id");
    }
    Ok(())
}

impl PeerKeyPackagesClaimFields {
    /// Validate the unsigned selectors before authoring or consuming a claim.
    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        validate_peer_claim_fields(self)
    }

    pub fn target_principal_id(&self) -> Option<DidCoreId> {
        self.target_account_id
            .as_ref()
            .map(|account| account.principal_id.clone())
            .or_else(|| {
                self.target_actor_id
                    .as_ref()
                    .map(|actor| actor.signing_principal_id().clone())
            })
            .or_else(|| self.target_agent_id.clone())
    }

    pub fn requester_principal_id(
        &self,
        authorization: &PeerKeyPackageRequesterAuthorization,
    ) -> Option<DidCoreId> {
        match authorization {
            PeerKeyPackageRequesterAuthorization::Device { .. } => self
                .requester_account_id
                .as_ref()
                .map(|account| account.principal_id.clone()),
            PeerKeyPackageRequesterAuthorization::RealmDevice { .. } => self
                .requester_actor_id
                .as_ref()
                .map(|actor| actor.signing_principal_id().clone()),
            PeerKeyPackageRequesterAuthorization::Agent {
                requester_agent_id, ..
            } => Some(requester_agent_id.clone()),
        }
    }
}

#[derive(Serialize)]
struct PeerKeyPackageAuthorizationTranscript<'a> {
    authorization: PeerKeyPackageAuthorizationMetadata<'a>,
    request: &'a PeerKeyPackagesClaimFields,
    service_binding: &'a KeyPackagesClaimServiceBinding,
}

#[derive(Serialize)]
struct PeerKeyPackageAuthorizationMetadata<'a> {
    kind: &'static str,
    verification_method: &'a DidUrl,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_device_id: Option<&'a DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_authorize_event_id: Option<&'a EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_agent_id: Option<&'a DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_key_authorize_event_id: Option<&'a EventId>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    signed_at: DateTime<Utc>,
}

pub fn keypackage_claim_authorization_signing_bytes(
    request: &PeerKeyPackagesClaimFields,
    service_binding: &KeyPackagesClaimServiceBinding,
    authorization: &PeerKeyPackageRequesterAuthorization,
) -> arkret_canonical::Result<Vec<u8>> {
    let metadata = match authorization {
        PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            signed_at,
            ..
        } => PeerKeyPackageAuthorizationMetadata {
            kind: "device",
            verification_method,
            requester_device_id: Some(requester_device_id),
            device_authorize_event_id: Some(device_authorize_event_id),
            requester_agent_id: None,
            agent_key_authorize_event_id: None,
            signed_at: *signed_at,
        },
        PeerKeyPackageRequesterAuthorization::RealmDevice {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            signed_at,
            ..
        } => PeerKeyPackageAuthorizationMetadata {
            kind: "realm_device",
            verification_method,
            requester_device_id: Some(requester_device_id),
            device_authorize_event_id: Some(device_authorize_event_id),
            requester_agent_id: None,
            agent_key_authorize_event_id: None,
            signed_at: *signed_at,
        },
        PeerKeyPackageRequesterAuthorization::Agent {
            verification_method,
            requester_agent_id,
            agent_key_authorize_event_id,
            signed_at,
            ..
        } => PeerKeyPackageAuthorizationMetadata {
            kind: "agent",
            verification_method,
            requester_device_id: None,
            device_authorize_event_id: None,
            requester_agent_id: Some(requester_agent_id),
            agent_key_authorize_event_id: Some(agent_key_authorize_event_id),
            signed_at: *signed_at,
        },
    };
    let transcript = PeerKeyPackageAuthorizationTranscript {
        authorization: metadata,
        request,
        service_binding,
    };
    let canonical = arkret_canonical::canonical_json_bytes(&transcript)?;
    let mut bytes = b"ak.keypackage-claim-authorization-v1\n".to_vec();
    bytes.extend(canonical);
    Ok(bytes)
}

#[derive(Serialize)]
struct PeerKeyPackageClaimReceiptUnsigned<'a> {
    claim_request_id: &'a Base64UrlString,
    request_digest: &'a Hash,
    claims_digest: &'a Hash,
    source_id: &'a DidCoreId,
    destination_id: &'a DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_authority_ref: &'a Option<arkret_wire::RealmCommitAuthorityRef>,
    request: &'a PeerKeyPackagesClaimFields,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    claimed_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
}

pub fn peer_keypackage_claim_receipt_signing_bytes(
    receipt: &PeerKeyPackageClaimReceipt,
) -> arkret_canonical::Result<Vec<u8>> {
    let unsigned = PeerKeyPackageClaimReceiptUnsigned {
        claim_request_id: &receipt.claim_request_id,
        request_digest: &receipt.request_digest,
        claims_digest: &receipt.claims_digest,
        source_id: &receipt.source_id,
        destination_id: &receipt.destination_id,
        claim_authority_ref: &receipt.claim_authority_ref,
        request: &receipt.request,
        claimed_at: receipt.claimed_at,
        expires_at: receipt.expires_at,
    };
    let canonical = arkret_canonical::canonical_json_bytes(&unsigned)?;
    let mut bytes = b"ak.peer-keypackage-claim-receipt-v1\n".to_vec();
    bytes.extend(canonical);
    Ok(bytes)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug)]
pub struct RecipientMlsDurableReceipt {
    pub domain: NonEmptyString,
    pub claim_request_id: Base64UrlString,
    pub keypackage_ref: NonEmptyString,
    pub recipient: RecipientMlsDurableSigner,
    pub recipient_id: DidCoreId,
    pub realm_id: RealmId,
    pub mls_group_id: MlsGroupId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub mls_epoch: u64,
    /// The delivery is not an Event and has no independent RealmCommit
    /// (`keypackage-operations.schema.json#/$defs/recipient_mls_durable_receipt`).
    pub welcome_ref: MlsWelcomeDeliveryId,
    pub welcome_digest: Hash,
    pub durable_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RecipientMlsDurableSigner {
    RealmDevice {
        recipient_actor_id: ActorId,
        recipient_device_id: DeviceId,
        device_verification_method: DidUrl,
    },
    Device {
        recipient_account_id: AccountId,
        recipient_device_id: DeviceId,
        device_verification_method: DidUrl,
    },
    Agent {
        recipient_agent_id: DidCoreId,
        recipient_agent_verification_method: DidUrl,
        agent_key_authorize_event_id: EventId,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientMlsDurableReceiptWire {
    domain: NonEmptyString,
    claim_request_id: Base64UrlString,

    keypackage_ref: NonEmptyString,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    recipient_account_id: Option<AccountId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    recipient_actor_id: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    recipient_device_id: Option<DeviceId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    device_verification_method: Option<DidUrl>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    recipient_agent_id: Option<DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    recipient_agent_verification_method: Option<DidUrl>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    agent_key_authorize_event_id: Option<EventId>,
    recipient_id: DidCoreId,
    realm_id: RealmId,
    mls_group_id: MlsGroupId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    mls_epoch: u64,
    welcome_ref: MlsWelcomeDeliveryId,
    welcome_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    durable_at: DateTime<Utc>,
    signature: KeyOperationSignature,
}

impl Serialize for RecipientMlsDurableReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (
            recipient_actor_id,
            recipient_account_id,
            recipient_device_id,
            device_verification_method,
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        ) = match &self.recipient {
            RecipientMlsDurableSigner::RealmDevice {
                recipient_actor_id,
                recipient_device_id,
                device_verification_method,
            } => (
                Some(recipient_actor_id.clone()),
                None,
                Some(recipient_device_id.clone()),
                Some(device_verification_method.clone()),
                None,
                None,
                None,
            ),
            RecipientMlsDurableSigner::Device {
                recipient_account_id,
                recipient_device_id,
                device_verification_method,
            } => (
                None,
                Some(recipient_account_id.clone()),
                Some(recipient_device_id.clone()),
                Some(device_verification_method.clone()),
                None,
                None,
                None,
            ),
            RecipientMlsDurableSigner::Agent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            } => (
                None,
                None,
                None,
                None,
                Some(recipient_agent_id.clone()),
                Some(recipient_agent_verification_method.clone()),
                Some(agent_key_authorize_event_id.clone()),
            ),
        };
        RecipientMlsDurableReceiptWire {
            domain: self.domain.clone(),
            claim_request_id: self.claim_request_id.clone(),
            keypackage_ref: self.keypackage_ref.clone(),
            recipient_account_id,
            recipient_actor_id,
            recipient_device_id,
            device_verification_method,
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
            recipient_id: self.recipient_id.clone(),
            realm_id: self.realm_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
            mls_epoch: self.mls_epoch,
            welcome_ref: self.welcome_ref.clone(),
            welcome_digest: self.welcome_digest.clone(),
            durable_at: self.durable_at,
            signature: self.signature.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RecipientMlsDurableReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RecipientMlsDurableReceiptWire::deserialize(deserializer)?;
        let recipient = match (
            wire.recipient_actor_id,
            wire.recipient_account_id,
            wire.recipient_device_id,
            wire.device_verification_method,
            wire.recipient_agent_id,
            wire.recipient_agent_verification_method,
            wire.agent_key_authorize_event_id,
        ) {
            (None, Some(account_id), Some(device_id), Some(method), None, None, None) => {
                RecipientMlsDurableSigner::Device {
                    recipient_account_id: account_id,
                    recipient_device_id: device_id,
                    device_verification_method: method,
                }
            }
            (None, None, None, None, Some(agent_id), Some(method), Some(event_id)) => {
                RecipientMlsDurableSigner::Agent {
                    recipient_agent_id: agent_id,
                    recipient_agent_verification_method: method,
                    agent_key_authorize_event_id: event_id,
                }
            }
            (Some(actor_id), None, Some(device_id), Some(method), None, None, None) => {
                RecipientMlsDurableSigner::RealmDevice {
                    recipient_actor_id: actor_id,
                    recipient_device_id: device_id,
                    device_verification_method: method,
                }
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "recipient durable receipt must select exactly one device or Agent signer",
                ));
            }
        };
        let receipt = Self {
            domain: wire.domain,
            claim_request_id: wire.claim_request_id,
            keypackage_ref: wire.keypackage_ref,
            recipient,
            recipient_id: wire.recipient_id,
            realm_id: wire.realm_id,
            mls_group_id: wire.mls_group_id,
            mls_epoch: wire.mls_epoch,
            welcome_ref: wire.welcome_ref,
            welcome_digest: wire.welcome_digest,
            durable_at: wire.durable_at,
            signature: wire.signature,
        };
        receipt.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(receipt)
    }
}

impl RecipientMlsDurableReceipt {
    pub fn recipient_principal_id(&self) -> Option<DidCoreId> {
        match &self.recipient {
            RecipientMlsDurableSigner::RealmDevice {
                recipient_actor_id, ..
            } => Some(recipient_actor_id.signing_principal_id().clone()),
            RecipientMlsDurableSigner::Device {
                recipient_account_id,
                ..
            } => Some(recipient_account_id.principal_id.clone()),
            RecipientMlsDurableSigner::Agent {
                recipient_agent_id, ..
            } => Some(recipient_agent_id.clone()),
        }
    }

    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        signed_receipt_canonical_signing_bytes(self, self.domain.as_str())
    }

    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.domain.as_str() != DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1 {
            return Err("recipient durable receipt domain mismatch");
        }
        match &self.recipient {
            RecipientMlsDurableSigner::RealmDevice {
                recipient_actor_id,
                device_verification_method,
                ..
            } => {
                if recipient_actor_id
                    .as_realm_actor_id()
                    .is_none_or(|actor| actor.realm_id != self.realm_id)
                    || recipient_actor_id.validate().is_err()
                    || self.signature.kid.as_str() != device_verification_method.as_str()
                {
                    return Err("Realm recipient durable receipt identity or key binding differs");
                }
            }
            RecipientMlsDurableSigner::Device {
                device_verification_method,
                ..
            } => {
                if self.signature.kid.as_str() != device_verification_method.as_str() {
                    return Err("recipient device receipt signature kid mismatch");
                }
            }
            RecipientMlsDurableSigner::Agent {
                recipient_agent_id: _,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            } => {
                if self.signature.kid.as_str() != recipient_agent_verification_method.as_str() {
                    return Err("recipient Agent durable receipt binding mismatch");
                }
                let _ = agent_key_authorize_event_id;
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesConsumeRequestBody {
    pub claim_id: KeypackageClaimId,
    pub recipient_durable_receipt: RecipientMlsDurableReceipt,
    pub signature: KeyOperationSignature,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesConsumeFields {
    pub claim_id: KeypackageClaimId,
    pub recipient_durable_receipt: RecipientMlsDurableReceipt,
}

impl KeyPackagesConsumeRequestBody {
    #[must_use]
    pub fn unsigned(&self) -> KeyPackagesConsumeFields {
        KeyPackagesConsumeFields {
            claim_id: self.claim_id.clone(),
            recipient_durable_receipt: self.recipient_durable_receipt.clone(),
        }
    }

    pub fn validate_shape(&self) -> Result<(), &'static str> {
        let unsigned = self.unsigned();
        unsigned.validate_shape()?;
        let expected_method = match &self.recipient_durable_receipt.recipient {
            RecipientMlsDurableSigner::Device {
                device_verification_method,
                ..
            }
            | RecipientMlsDurableSigner::RealmDevice {
                device_verification_method,
                ..
            } => device_verification_method,
            RecipientMlsDurableSigner::Agent {
                recipient_agent_verification_method,
                ..
            } => recipient_agent_verification_method,
        };
        if self.signature.kid.as_str() != expected_method.as_str() {
            return Err("KeyPackage consume signature kid differs from durable recipient signer");
        }
        Ok(())
    }
}

impl KeyPackagesConsumeFields {
    #[must_use]
    pub fn into_signed(self, signature: KeyOperationSignature) -> KeyPackagesConsumeRequestBody {
        KeyPackagesConsumeRequestBody {
            claim_id: self.claim_id,
            recipient_durable_receipt: self.recipient_durable_receipt,
            signature,
        }
    }
}

impl KeyPackagesConsumeFields {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        self.recipient_durable_receipt.validate_shape()
    }
}

pub fn keypackages_consume_signing_input(
    unsigned: &KeyPackagesConsumeFields,
) -> arkret_canonical::Result<Vec<u8>> {
    keypackage_signing_input(KEYPACKAGES_CONSUME_SIGNATURE_DOMAIN, unsigned)
}

/// Recovery identity covers the complete signed command, including the outer
/// signature. This is distinct from the unsigned signature transcript.
pub fn keypackages_consume_request_digest(
    body: &KeyPackagesConsumeRequestBody,
) -> arkret_canonical::Result<String> {
    arkret_canonical::canonical_sha256(body)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageConsumeReceipt {
    pub domain: NonEmptyString,
    pub request_digest: Hash,
    pub claim_id: KeypackageClaimId,
    pub recipient_durable_receipt: RecipientMlsDurableReceipt,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub consumed_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

impl KeyPackageConsumeReceipt {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        signed_receipt_canonical_signing_bytes(self, self.domain.as_str())
    }

    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.domain.as_str() != DomainSeparationId::KEYPACKAGE_CONSUME_RECEIPT_V1 {
            return Err("KeyPackage consume receipt domain mismatch");
        }
        self.recipient_durable_receipt.validate_shape()?;
        Ok(())
    }
}

fn signed_receipt_canonical_signing_bytes(
    value: &impl Serialize,
    domain: &str,
) -> arkret_canonical::Result<Vec<u8>> {
    let mut unsigned = serde_json::to_value(value)?;
    let object = unsigned.as_object_mut().ok_or_else(|| {
        arkret_canonical::CanonicalError::Protocol(
            "signed receipt must serialize as an object".to_owned(),
        )
    })?;
    object.remove("signature");
    keypackage_signing_input(&format!("{domain}\n"), &unsigned)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesConsumeResponseBody {
    pub consume_receipt: KeyPackageConsumeReceipt,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesRevokeRequestBody {
    #[serde(deserialize_with = "deserialize_keypackage_string_list")]
    pub keypackage_refs: Vec<String>,
    pub device_id: DeviceId,
    pub signature: KeyOperationSignature,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub reason: Option<AuditReasonText>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesRevokeFields {
    #[serde(deserialize_with = "deserialize_keypackage_string_list")]
    pub keypackage_refs: Vec<String>,
    pub device_id: DeviceId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub reason: Option<AuditReasonText>,
}

impl KeyPackagesRevokeRequestBody {
    #[must_use]
    pub fn unsigned(&self) -> KeyPackagesRevokeFields {
        KeyPackagesRevokeFields {
            keypackage_refs: self.keypackage_refs.clone(),
            device_id: self.device_id.clone(),
            reason: self.reason.clone(),
        }
    }
}

impl KeyPackagesRevokeFields {
    #[must_use]
    pub fn into_signed(self, signature: KeyOperationSignature) -> KeyPackagesRevokeRequestBody {
        KeyPackagesRevokeRequestBody {
            keypackage_refs: self.keypackage_refs,
            device_id: self.device_id,
            signature,
            reason: self.reason,
        }
    }
}

pub fn keypackages_revoke_signing_input(
    unsigned: &KeyPackagesRevokeFields,
) -> arkret_canonical::Result<Vec<u8>> {
    keypackage_signing_input(KEYPACKAGES_REVOKE_SIGNATURE_DOMAIN, unsigned)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesRevokeResponseBody {
    pub revoked: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
}

/// Transparent wrapper over `KeyBackup` for the `ak.self.keys.command.put_backup`
/// request body Salvo OpenAPI bindings.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeysBackupsPutRequestBody(pub KeyBackup);
