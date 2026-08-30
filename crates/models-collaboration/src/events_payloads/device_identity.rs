//! Device-authorization and identity-binding payloads.

use std::collections::BTreeSet;
use std::fmt;

use arkret_wire::DidCoreId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::internal_prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceAuthorizationBindingKind {
    RegistrationAnchor,
    PcrRecovery,
    AcceptedDevice,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizePayload {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub device_public_key_did: NonEmptyString,
    /// Device HPKE public key used for secret/key envelope sealing. Services
    /// MUST NOT substitute this value in projection.
    pub hpke_key: NonEmptyString,
    /// Canonical sorted (UTF-8 bytewise) unique algorithm ids supported by
    /// this device. Enters the device trust binding transcript together with
    /// `device_public_key_did` and `hpke_key`.
    pub algorithms: Vec<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key_algorithm: Option<NonEmptyString>,
    pub authorized_by: DeviceOrPrincipalRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<NonEmptyString>>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub authorization_binding_kind: DeviceAuthorizationBindingKind,
    pub device_signature: SignatureMaterial,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_session_id: Option<RecoverySessionId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceAuthorizePayloadWire {
    principal_id: DidCoreId,
    device_id: DeviceId,
    device_public_key_did: NonEmptyString,
    hpke_key: NonEmptyString,
    algorithms: Vec<NonEmptyString>,
    #[serde(default)]
    device_key_algorithm: Option<NonEmptyString>,
    authorized_by: DeviceOrPrincipalRef,
    #[serde(default)]
    scopes: Option<Vec<NonEmptyString>>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    not_before: DateTime<Utc>,
    #[serde(default)]
    expires_at: Option<Option<DateTime<Utc>>>,
    authorization_binding_kind: DeviceAuthorizationBindingKind,
    device_signature: SignatureMaterial,
    #[serde(default)]
    recovery_session_id: Option<RecoverySessionId>,
}

impl<'de> Deserialize<'de> for DeviceAuthorizePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceAuthorizePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            principal_id: wire.principal_id,
            device_id: wire.device_id,
            device_public_key_did: wire.device_public_key_did,
            hpke_key: wire.hpke_key,
            algorithms: wire.algorithms,
            device_key_algorithm: wire.device_key_algorithm,
            authorized_by: wire.authorized_by,
            scopes: wire.scopes,
            not_before: wire.not_before,
            expires_at: wire.expires_at,
            authorization_binding_kind: wire.authorization_binding_kind,
            device_signature: wire.device_signature,
            recovery_session_id: wire.recovery_session_id,
        };
        payload
            .validate_wire_constraints()
            .map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl DeviceAuthorizePayload {
    /// Enforce the `device-lifecycle.md` §5.2 canonical-form MUST on
    /// `algorithms`: non-empty, UTF-8 bytewise ascending, no duplicates. The
    /// producer MUST write the same canonical array that enters the
    /// `ak-device-trust-bind-v1` signing input.
    pub fn validate_canonical_algorithms(&self) -> std::result::Result<(), &'static str> {
        UnsignedDeviceAuthorizePayload::from_signed(self).validate_canonical_algorithms()
    }

    pub fn validate_wire_constraints(&self) -> std::result::Result<(), &'static str> {
        UnsignedDeviceAuthorizePayload::from_signed(self).validate_wire_constraints()
    }

    /// Canonical signing input for
    /// `ak.device.authorize.payload.device_signature`.
    ///
    /// The signature proves possession of the private key corresponding to
    /// `device_public_key_did`; authorization is independently established by the
    /// root anchor or an accepted device.
    pub fn device_possession_signature_input(&self) -> Result<Vec<u8>> {
        UnsignedDeviceAuthorizePayload::from_signed(self).device_possession_signature_input()
    }
}

/// Device-authorization payload before the device possession signature exists.
/// The type is deliberately not serializable.
#[derive(Clone, Debug)]
pub struct UnsignedDeviceAuthorizePayload {
    principal_id: DidCoreId,
    device_id: DeviceId,
    device_public_key_did: NonEmptyString,
    hpke_key: NonEmptyString,
    algorithms: Vec<NonEmptyString>,
    device_key_algorithm: Option<NonEmptyString>,
    authorized_by: DeviceOrPrincipalRef,
    scopes: Option<Vec<NonEmptyString>>,
    not_before: DateTime<Utc>,
    expires_at: Option<Option<DateTime<Utc>>>,
    authorization_binding_kind: DeviceAuthorizationBindingKind,
    recovery_session_id: Option<RecoverySessionId>,
}

impl UnsignedDeviceAuthorizePayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal_id: DidCoreId,
        device_id: DeviceId,
        device_public_key_did: NonEmptyString,
        hpke_key: NonEmptyString,
        algorithms: Vec<NonEmptyString>,
        device_key_algorithm: Option<NonEmptyString>,
        authorized_by: DeviceOrPrincipalRef,
        scopes: Option<Vec<NonEmptyString>>,
        not_before: DateTime<Utc>,
        expires_at: Option<Option<DateTime<Utc>>>,
        authorization_binding_kind: DeviceAuthorizationBindingKind,
        recovery_session_id: Option<RecoverySessionId>,
    ) -> Result<Self> {
        let payload = Self {
            principal_id,
            device_id,
            device_public_key_did,
            hpke_key,
            algorithms,
            device_key_algorithm,
            authorized_by,
            scopes,
            not_before,
            expires_at,
            authorization_binding_kind,
            recovery_session_id,
        };
        payload
            .validate_wire_constraints()
            .map_err(|reason| WireError::Protocol(reason.to_owned()))?;
        Ok(payload)
    }

    fn from_signed(payload: &DeviceAuthorizePayload) -> Self {
        Self {
            principal_id: payload.principal_id.clone(),
            device_id: payload.device_id.clone(),
            device_public_key_did: payload.device_public_key_did.clone(),
            hpke_key: payload.hpke_key.clone(),
            algorithms: payload.algorithms.clone(),
            device_key_algorithm: payload.device_key_algorithm.clone(),
            authorized_by: payload.authorized_by.clone(),
            scopes: payload.scopes.clone(),
            not_before: payload.not_before,
            expires_at: payload.expires_at,
            authorization_binding_kind: payload.authorization_binding_kind,
            recovery_session_id: payload.recovery_session_id.clone(),
        }
    }

    pub fn validate_canonical_algorithms(&self) -> std::result::Result<(), &'static str> {
        if self.algorithms.is_empty() {
            return Err("device_authorize_algorithms_empty");
        }
        if self
            .algorithms
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err("device_authorize_algorithms_not_canonical");
        }
        Ok(())
    }

    pub fn validate_wire_constraints(&self) -> std::result::Result<(), &'static str> {
        self.validate_canonical_algorithms()?;
        match (&self.authorization_binding_kind, &self.authorized_by) {
            (
                DeviceAuthorizationBindingKind::RegistrationAnchor,
                DeviceOrPrincipalRef::Principal(principal_id),
            ) if principal_id == &self.principal_id && self.recovery_session_id.is_none() => {}
            (
                DeviceAuthorizationBindingKind::PcrRecovery,
                DeviceOrPrincipalRef::Principal(principal_id),
            ) if principal_id == &self.principal_id && self.recovery_session_id.is_some() => {}
            (DeviceAuthorizationBindingKind::AcceptedDevice, DeviceOrPrincipalRef::DeviceId(_))
                if self.recovery_session_id.is_none() => {}
            _ => return Err("device_authorize_authorization_binding_mismatch"),
        }
        if let Some(scopes) = &self.scopes
            && (scopes.is_empty() || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len())
        {
            return Err("device_authorize_scopes_must_be_non_empty_and_unique");
        }
        Ok(())
    }

    pub fn device_possession_signature_input(&self) -> Result<Vec<u8>> {
        self.validate_wire_constraints()
            .map_err(|reason| WireError::Protocol(reason.to_owned()))?;
        let device_key_algorithm = self.device_key_algorithm.as_deref().ok_or_else(|| {
            WireError::Protocol("device_authorize_device_key_algorithm_required".to_owned())
        })?;
        if device_key_algorithm != "Ed25519" {
            return Err(WireError::Protocol(
                "device_authorize_device_key_algorithm_unsupported".to_owned(),
            ));
        }
        let authorized_by = match &self.authorized_by {
            DeviceOrPrincipalRef::DeviceId(device_id) => device_id.as_str(),
            DeviceOrPrincipalRef::Principal(principal_id) => principal_id.as_str(),
        };
        let mut scopes = self.scopes.clone();
        if let Some(scopes) = &mut scopes {
            scopes.sort_unstable();
            scopes.dedup();
        }
        let expires_at = self.expires_at.as_ref().and_then(|value| value.as_ref());
        let recovery_session_id = self.recovery_session_id.as_ref().map(|id| id.as_str());
        let body = serde_json::json!({
            "principal_id": self.principal_id.as_str(),
            "device_id": self.device_id.as_str(),
            "device_public_key_did": self.device_public_key_did.as_str(),
            "hpke_key": self.hpke_key.as_str(),
            "algorithms": &self.algorithms,
            "device_key_algorithm": device_key_algorithm,
            "authorized_by": authorized_by,
            "not_before": self.not_before,
            "expires_at": expires_at,
            "scopes": scopes,
            "recovery_session_id": recovery_session_id,
            "authorization_binding_kind": self.authorization_binding_kind,
        });
        let mut out = match self.authorization_binding_kind {
            DeviceAuthorizationBindingKind::RegistrationAnchor => {
                binding_contexts::DEVICE_AUTHORIZE_POSSESSION_PREFIX.to_vec()
            }
            DeviceAuthorizationBindingKind::PcrRecovery => {
                binding_contexts::DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PREFIX.to_vec()
            }
            DeviceAuthorizationBindingKind::AcceptedDevice => {
                return Err(WireError::Protocol(
                    "accepted_device possession uses the pairing challenge attestation transcript"
                        .to_owned(),
                ));
            }
        };
        out.extend_from_slice(&canonical::canonical_json_bytes(&body)?);
        Ok(out)
    }

    pub fn attach_signature(self, signature: Base64UrlString) -> Result<DeviceAuthorizePayload> {
        let signature = NonEmptyString::new(signature.into_string())
            .map_err(|reason| WireError::Protocol(reason.to_owned()))?;
        Ok(DeviceAuthorizePayload {
            principal_id: self.principal_id,
            device_id: self.device_id,
            device_public_key_did: self.device_public_key_did,
            hpke_key: self.hpke_key,
            algorithms: self.algorithms,
            device_key_algorithm: self.device_key_algorithm,
            authorized_by: self.authorized_by,
            scopes: self.scopes,
            not_before: self.not_before,
            expires_at: self.expires_at,
            authorization_binding_kind: self.authorization_binding_kind,
            device_signature: SignatureMaterial::NonEmptyString(signature),
            recovery_session_id: self.recovery_session_id,
        })
    }
}

/// Canonical digest of an `ak.device.authorize` payload as it appears on the
/// wire.
///
/// This is the value a root-anchored re-entry commits to through
/// [`DeviceReanchorPayload::replacement_authorize_payload_digest`]. The
/// re-anchor cannot commit to the authorize Event id or envelope digest because
/// that Event's `prev_refs` names the re-anchor, and every `event_id` derives
/// from its own signed content — the two would be preimages of each other.
/// Committing to the payload keeps the binding one-directional while still
/// fixing which device is authorized.
///
/// It takes the wire `payload` object rather than [`DeviceAuthorizePayload`] on
/// purpose: the producer and the verifier must hash the same bytes, and a
/// parse-then-reserialize round trip is one normalization away from disagreeing.
pub fn device_authorize_payload_digest(
    payload: &Value,
    digest_suite: canonical::DigestSuite,
) -> Result<Hash> {
    let bytes = canonical::canonical_json_bytes(payload)?;
    Ok(Hash::new(canonical::digest(digest_suite, &bytes))?)
}

/// Canonical digest for a locally constructed, typed
/// [`DeviceAuthorizePayload`].
///
/// Producers should use this entry point so an untyped JSON value cannot be
/// substituted while constructing a root commitment. Verifiers that already
/// received wire JSON must continue to use [`device_authorize_payload_digest`]
/// to hash the exact admitted payload object without a parse/reserialize
/// round-trip.
pub fn typed_device_authorize_payload_digest(
    payload: &DeviceAuthorizePayload,
    digest_suite: canonical::DigestSuite,
) -> Result<Hash> {
    payload
        .validate_wire_constraints()
        .map_err(|reason| WireError::Protocol(reason.to_owned()))?;
    let bytes = canonical::canonical_json_bytes(payload)?;
    Ok(Hash::new(canonical::digest(digest_suite, &bytes))?)
}

pub fn validate_root_anchored_authorize_payload_digest(
    committed_digest: &Hash,
    payload: &Value,
    digest_suite: canonical::DigestSuite,
) -> Result<()> {
    let authorize: DeviceAuthorizePayload = serde_json::from_value(payload.clone())?;
    if !matches!(
        authorize.authorization_binding_kind,
        DeviceAuthorizationBindingKind::RegistrationAnchor
            | DeviceAuthorizationBindingKind::PcrRecovery
    ) {
        return Err(WireError::Protocol(
            "root-anchored unit requires a registration_anchor or pcr_recovery binding".to_owned(),
        ));
    }
    if device_authorize_payload_digest(payload, digest_suite)? != *committed_digest {
        return Err(WireError::Protocol(
            "root-anchored authorize payload digest mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Closed PCR-policy recovery payload for `ak.device.reanchor`.
///
/// The replacement binding commits to the authorize payload digest, never to
/// that Event's id or envelope digest: the authorize envelope carries this
/// Event's `event_id` in `prev_refs`, and every `event_id` is a function of its
/// own signed content, so an id or envelope binding would make the two Events
/// preimages of each other. See `key-management.md` §5.0.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAuthorityKind {
    PcrPolicy,
    DidRoot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReanchorPayload {
    pub principal_id: DidCoreId,
    pub principal_server_id: DidCoreId,
    pub recovery_authority_kind: RecoveryAuthorityKind,
    pub recovery_policy_id: PolicyId,
    pub recovery_policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub previous_device_generation: u64,
    pub new_device_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_root_evidence_digest: Option<Hash>,
    pub pre_fence_seal_frontier: Option<DeviceReanchorPreFenceSealFrontier>,
    pub replacement_authorize_payload_digest: Hash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceReanchorPayloadWire {
    principal_id: DidCoreId,
    principal_server_id: DidCoreId,
    recovery_authority_kind: RecoveryAuthorityKind,
    recovery_policy_id: PolicyId,
    recovery_policy_version: u64,
    recovery_session_id: RecoverySessionId,
    previous_device_generation: u64,
    new_device_generation: u64,
    #[serde(default)]
    did_root_evidence_digest: Option<Hash>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pre_fence_seal_frontier: Option<DeviceReanchorPreFenceSealFrontier>,
    replacement_authorize_payload_digest: Hash,
}

fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl<'de> Deserialize<'de> for DeviceReanchorPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceReanchorPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            principal_id: wire.principal_id,
            principal_server_id: wire.principal_server_id,
            recovery_authority_kind: wire.recovery_authority_kind,
            recovery_policy_id: wire.recovery_policy_id,
            recovery_policy_version: wire.recovery_policy_version,
            recovery_session_id: wire.recovery_session_id,
            previous_device_generation: wire.previous_device_generation,
            new_device_generation: wire.new_device_generation,
            did_root_evidence_digest: wire.did_root_evidence_digest,
            pre_fence_seal_frontier: wire.pre_fence_seal_frontier,
            replacement_authorize_payload_digest: wire.replacement_authorize_payload_digest,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl DeviceReanchorPayload {
    pub const SCHEMA: &'static str = SchemaId::DEVICE_REANCHOR_V1;

    pub fn principal_authority(&self) -> AccountId {
        AccountId::new(self.principal_id.clone(), self.principal_server_id.clone())
    }

    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.recovery_policy_version == 0
            || self.previous_device_generation == 0
            || self.new_device_generation != self.previous_device_generation.saturating_add(1)
        {
            return Err(
                "device reanchor policy version and generations must be positive immediate successors",
            );
        }
        match (
            self.recovery_authority_kind,
            self.did_root_evidence_digest.is_some(),
        ) {
            (RecoveryAuthorityKind::DidRoot, true) | (RecoveryAuthorityKind::PcrPolicy, false) => {}
            _ => {
                return Err(
                    "device reanchor did_root_evidence_digest must exist exactly for did_root authority",
                );
            }
        }
        if let Some(basis) = &self.pre_fence_seal_frontier
            && basis.validate_protocol_bounds().is_err()
        {
            return Err(
                "device reanchor pre_fence_seal_frontier leaves must be non-empty, unique, canonically \
                 ordered and at most 64",
            );
        }
        Ok(())
    }
}

/// Validate the special first Seal after a B-model recovery re-anchor when the
/// accepted pre-fence Seal frontier is explicitly null. Generic Seal validation still
/// applies; this helper requires the business delta to cover the re-anchor and
/// its replacement device authorization while permitting other pending Control
/// Moves admitted by the contextual Seal rules.
///
/// Both envelope digests are caller-supplied: the re-anchor payload binds the
/// replacement by payload digest, so the authorize envelope digest exists only
/// once both Events are formed.
pub fn validate_device_reanchor_recovery_first_seal(
    payload: &DeviceReanchorPayload,
    predecessor_refs: &[SealId],
    delta: &[Hash],
    reanchor_digest: &Hash,
    replacement_authorize_digest: &Hash,
) -> Result<()> {
    if payload.pre_fence_seal_frontier.is_some() {
        return Err(WireError::Protocol(
            "device reanchor recovery-first Seal requires pre_fence_seal_frontier=null".to_owned(),
        ));
    }
    if !predecessor_refs.is_empty() {
        return Err(WireError::Protocol(
            "device reanchor recovery-first Seal must have predecessor_refs=[]".to_owned(),
        ));
    }
    if delta
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(WireError::Protocol(
            "device reanchor recovery-first Seal delta must be canonical sorted and duplicate-free"
                .to_owned(),
        ));
    }
    if !delta
        .iter()
        .any(|digest| digest.as_str() == reanchor_digest.as_str())
        || !delta
            .iter()
            .any(|digest| digest.as_str() == replacement_authorize_digest.as_str())
    {
        return Err(WireError::Protocol(
            "device reanchor recovery-first Seal delta must cover reanchor and replacement authorize"
                .to_owned(),
        ));
    }
    Ok(())
}

use arkret_wire::SchemaId;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_list_update_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceListUpdatePayload {
    pub principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_ids: Option<Vec<DeviceId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_ids: Option<Vec<DeviceId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_list_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceListUpdatePayloadWire {
    principal_id: DidCoreId,
    #[serde(default)]
    changed_ids: Option<Vec<DeviceId>>,
    #[serde(default)]
    left_ids: Option<Vec<DeviceId>>,
    #[serde(default)]
    device_list_digest: Option<Hash>,
    #[serde(default)]
    stream_id: Option<NonEmptyString>,
    #[serde(default)]
    #[serde(
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    updated_at: Option<DateTime<Utc>>,
}

impl<'de> Deserialize<'de> for DeviceListUpdatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceListUpdatePayloadWire::deserialize(deserializer)?;
        if wire.changed_ids.is_none()
            && wire.left_ids.is_none()
            && wire.device_list_digest.is_none()
        {
            return Err(serde::de::Error::custom(
                "device list update requires changed, left, or device_list_digest",
            ));
        }
        for (name, devices) in [
            ("changed_ids", &wire.changed_ids),
            ("left_ids", &wire.left_ids),
        ] {
            if let Some(devices) = devices
                && (devices.is_empty()
                    || devices.iter().collect::<BTreeSet<_>>().len() != devices.len())
            {
                return Err(serde::de::Error::custom(format!(
                    "device list update {name} must be non-empty and unique"
                )));
            }
        }
        Ok(Self {
            principal_id: wire.principal_id,
            changed_ids: wire.changed_ids,
            left_ids: wire.left_ids,
            device_list_digest: wire.device_list_digest,
            stream_id: wire.stream_id,
            updated_at: wire.updated_at,
        })
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_or_principal_ref`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceOrPrincipalRef {
    DeviceId(DeviceId),
    Principal(DidCoreId),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokePayload {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub revoked_by: DeviceOrPrincipalRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    pub reason: DeviceRevocationReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignatureMaterial>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DeviceRevocationReason(String);

impl DeviceRevocationReason {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, &'static str> {
        let value = value.into();
        let mut characters = value.chars();
        let Some(first) = characters.next() else {
            return Err("device revocation reason must not be empty");
        };
        if value.len() > 64
            || !first.is_ascii_lowercase()
            || !characters.all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
        {
            return Err("device revocation reason must match ^[a-z][a-z0-9_]{0,63}$");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceRevocationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DeviceRevocationReason {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The binding does not enforce uniqueness: at most one Direct Conversation Realm can exist per
/// pair because only the derived founder may author the founding unit. This payload is the
/// participant-visible endorsement of coordinates and of the first exact-pair MLS generation.
///
/// It carries no `binding_state`, no `supersedes_binding_ref` and no permanent `mls_group_id`: the
/// binding is written once and never retired, and participant authority always reads the *current*
/// active MLS generation rather than the founding group.
pub struct DirectConversationBoundPayload {
    pub pair_key: Hash,
    pub unordered_participant_ids: Vec<ActorId>,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
    pub authorization_basis: DirectConversationAuthorizationBasis,
    /// `generation 1` activation Event: the first exact-pair active MLS generation.
    pub initial_exact_pair_group_state_ref: EventId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl DirectConversationBoundPayload {
    pub fn validate_pair_key(&self, trust_domain: TrustDomainId) -> Result<()> {
        self.authorization_basis.validate_shape()?;
        let [left, right]: [ActorId; 2] = self
            .unordered_participant_ids
            .clone()
            .try_into()
            .map_err(|_| {
                WireError::Protocol("direct conversation requires two participants".to_owned())
            })?;
        let expected = direct_conversation_pair_key(
            trust_domain,
            DirectConversationPairKeyParticipant::unmapped(left),
            DirectConversationPairKeyParticipant::unmapped(right),
        )?;
        if self.pair_key != expected {
            return Err(WireError::Protocol(
                "direct conversation pair_key mismatch (schema_violation)".to_owned(),
            ));
        }
        Ok(())
    }

    /// Receiver-derived semantic digest from
    /// `contact-and-direct-conversation.md` §8.3.
    ///
    /// The digest is not a wire field. It normalizes the two unordered sets,
    /// excludes `created_at` and Event envelope context, then hashes the
    /// closed binding object under the registered v1 domain separator.
    pub fn binding_digest(&self) -> Result<Hash> {
        self.authorization_basis.validate_shape()?;
        if self.unordered_participant_ids.len() != 2 {
            return Err(WireError::Protocol(
                "direct conversation requires two participants".to_owned(),
            ));
        }

        let mut participants = self.unordered_participant_ids.clone();
        participants.sort();
        let mut event_refs = self
            .authorization_basis
            .event_refs
            .iter()
            .map(EventId::as_str)
            .collect::<Vec<_>>();
        event_refs.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

        let binding_object = serde_json::json!({
            "pair_key": self.pair_key.as_str(),
            "unordered_participant_ids": participants,
            "realm_id": self.realm_id.as_str(),
            "main_strand_id": self.main_strand_id.as_str(),
            "founding_unit_digest": self.founding_unit_digest.as_str(),
            "authorization_basis": {
                "kind": self.authorization_basis.kind,
                "event_refs": event_refs,
            },
            "initial_exact_pair_group_state_ref": self.initial_exact_pair_group_state_ref.as_str(),
        });
        let canonical = arkret_canonical::canonical_json_bytes(&binding_object)?;
        let mut preimage = b"ak.direct-conversation.binding-digest.v1\n".to_vec();
        preimage.extend_from_slice(&canonical);
        Ok(Hash::new(arkret_canonical::sha256_digest(&preimage))?)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn device_authorize_value() -> Value {
        json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "device_public_key_did": "z6MkDeviceKey",
            "hpke_key": "z6LSHpkeKey",
            "algorithms": [
                "ak.hpke_x25519_aead_chacha20poly1305.v1",
                "ak.mls.v1"
            ],
            "device_key_algorithm": "Ed25519",
            "authorized_by": "ak:did_core:webvh:z6mkfixture",
            "not_before": "2026-05-30T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "c2ln"
        })
    }

    #[test]
    fn device_authorize_binding_kind_is_closed_and_matches_authorizer() {
        let root: DeviceAuthorizePayload =
            serde_json::from_value(device_authorize_value()).unwrap();
        root.validate_wire_constraints().unwrap();

        let mut accepted = device_authorize_value();
        accepted["authorization_binding_kind"] = json!("accepted_device");
        accepted["authorized_by"] = json!("ak:device:01904100-0000-7000-8000-000000000002");
        serde_json::from_value::<DeviceAuthorizePayload>(accepted).unwrap();

        let mut recovery = device_authorize_value();
        recovery["authorization_binding_kind"] = json!("pcr_recovery");
        recovery["recovery_session_id"] =
            json!("ak:recovery_session:01904100-0000-7000-8000-000000000003");
        serde_json::from_value::<DeviceAuthorizePayload>(recovery).unwrap();

        let mut mismatch = device_authorize_value();
        mismatch["authorization_binding_kind"] = json!("accepted_device");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(mismatch).is_err());
    }

    #[test]
    fn possession_input_binds_authorization_kind() {
        let payload: DeviceAuthorizePayload =
            serde_json::from_value(device_authorize_value()).unwrap();
        let input =
            String::from_utf8(payload.device_possession_signature_input().unwrap()).unwrap();
        assert!(
            input
                .as_bytes()
                .starts_with(binding_contexts::DEVICE_AUTHORIZE_POSSESSION_PREFIX)
        );
        assert!(input.contains("\"authorization_binding_kind\":\"registration_anchor\""));

        let mut recovery = device_authorize_value();
        recovery["authorization_binding_kind"] = json!("pcr_recovery");
        recovery["recovery_session_id"] =
            json!("ak:recovery_session:01904100-0000-7000-8000-000000000003");
        let recovery: DeviceAuthorizePayload = serde_json::from_value(recovery).unwrap();
        let recovery_input = recovery.device_possession_signature_input().unwrap();
        assert!(
            recovery_input
                .starts_with(binding_contexts::DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PREFIX)
        );
    }

    #[test]
    fn root_anchor_digest_verifier_rejects_kind_and_payload_mutation() {
        let value = device_authorize_value();
        let digest =
            device_authorize_payload_digest(&value, canonical::DigestSuite::Sha256).unwrap();
        let typed: DeviceAuthorizePayload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            typed_device_authorize_payload_digest(&typed, canonical::DigestSuite::Sha256).unwrap(),
            digest
        );
        validate_root_anchored_authorize_payload_digest(
            &digest,
            &value,
            canonical::DigestSuite::Sha256,
        )
        .unwrap();

        let mut mutated = value.clone();
        mutated["hpke_key"] = json!("z6LSMutated");
        assert!(
            validate_root_anchored_authorize_payload_digest(
                &digest,
                &mutated,
                canonical::DigestSuite::Sha256,
            )
            .is_err()
        );

        let mut wrong_kind = value;
        wrong_kind["authorization_binding_kind"] = json!("accepted_device");
        wrong_kind["authorized_by"] = json!("ak:device:01904100-0000-7000-8000-000000000002");
        assert!(
            validate_root_anchored_authorize_payload_digest(
                &digest,
                &wrong_kind,
                canonical::DigestSuite::Sha256,
            )
            .is_err()
        );
    }

    #[test]
    fn device_authorize_deserialization_enforces_required_signature_and_canonical_lists() {
        let mut missing_signature = device_authorize_value();
        missing_signature
            .as_object_mut()
            .unwrap()
            .remove("device_signature");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(missing_signature).is_err());

        let mut unsorted_algorithms = device_authorize_value();
        unsorted_algorithms["algorithms"] = json!(["ak.mls.v1", "ak.hpke.v1"]);
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(unsorted_algorithms).is_err());

        let mut duplicate_scopes = device_authorize_value();
        duplicate_scopes["scopes"] = json!(["read", "read"]);
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(duplicate_scopes).is_err());
    }

    #[test]
    fn device_or_principal_ref_rejects_unknown_string() {
        assert!(
            serde_json::from_value::<DeviceOrPrincipalRef>(json!("neither-a-device-id-nor-a-did"))
                .is_err()
        );
    }

    #[test]
    fn device_or_principal_ref_accepts_device_id_and_did_key() {
        serde_json::from_value::<DeviceOrPrincipalRef>(json!(
            "ak:device:01904100-0000-7000-8000-000000000001"
        ))
        .unwrap();
        serde_json::from_value::<DeviceOrPrincipalRef>(json!(
            "ak:did_core:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw"
        ))
        .unwrap();
    }

    #[test]
    fn device_list_update_enforces_any_of_and_set_constraints() {
        let principal_id = "ak:did_core:webvh:z6mkfixturealice";
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id,
                "changed_ids": []
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id,
                "left_ids": [
                    "ak:device:01904100-0000-7000-8000-000000000001",
                    "ak:device:01904100-0000-7000-8000-000000000001"
                ]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id,
                "device_list_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }))
            .is_ok()
        );
    }

    #[test]
    fn device_revocation_reason_enforces_schema_slug() {
        assert!(DeviceRevocationReason::new("device_lost").is_ok());
        assert!(DeviceRevocationReason::new("").is_err());
        assert!(DeviceRevocationReason::new("DeviceLost").is_err());
        assert!(DeviceRevocationReason::new("device-lost").is_err());
        assert!(DeviceRevocationReason::new(format!("a{}", "b".repeat(64))).is_err());
    }

    #[test]
    fn device_reanchor_enforces_exact_authority_generation_cas_and_basis() {
        let valid = json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "principal_server_id": "ak:did_core:web:principal.example",
            "recovery_authority_kind": "pcr_policy",
            "recovery_policy_id": "ak:policy:01904100-0000-7000-8000-000000000001",
            "recovery_policy_version": 1,
            "recovery_session_id": "ak:recovery_session:01904100-0000-7000-8000-000000000002",
            "previous_device_generation": 1,
            "new_device_generation": 2,
            "pre_fence_seal_frontier": null,
            "replacement_authorize_payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        let payload: DeviceReanchorPayload = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(payload.new_device_generation, 2);
        let reanchor_digest = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let authorize_digest = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        let delta = vec![
            Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            Hash::new(reanchor_digest.as_str().to_owned()).unwrap(),
            Hash::new(authorize_digest.as_str().to_owned()).unwrap(),
        ];
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[],
                &delta,
                &reanchor_digest,
                &authorize_digest
            )
            .is_ok()
        );
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[SealId::new(format!("ak:seal:sha256:{}", "2".repeat(64))).unwrap()],
                &delta,
                &reanchor_digest,
                &authorize_digest
            )
            .is_err()
        );
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[],
                &delta[..2],
                &reanchor_digest,
                &authorize_digest
            )
            .is_err()
        );
        let missing_reanchor = vec![delta[0].clone(), delta[2].clone()];
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[],
                &missing_reanchor,
                &reanchor_digest,
                &authorize_digest
            )
            .is_err()
        );
        let duplicate = vec![delta[1].clone(), delta[1].clone(), delta[2].clone()];
        assert!(
            validate_device_reanchor_recovery_first_seal(
                &payload,
                &[],
                &duplicate,
                &reanchor_digest,
                &authorize_digest
            )
            .is_err()
        );

        let mut carries_event_id = valid.clone();
        carries_event_id["replacement_authorize_event_id"] =
            json!("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19");
        assert!(serde_json::from_value::<DeviceReanchorPayload>(carries_event_id).is_err());

        let mut missing_required_nullable = valid.clone();
        missing_required_nullable
            .as_object_mut()
            .unwrap()
            .remove("pre_fence_seal_frontier");
        assert!(
            serde_json::from_value::<DeviceReanchorPayload>(missing_required_nullable).is_err()
        );

        let mut mismatched = valid.clone();
        mismatched["new_device_generation"] = json!(3);
        assert!(serde_json::from_value::<DeviceReanchorPayload>(mismatched).is_err());

        let mut zero_policy_version = valid.clone();
        zero_policy_version["recovery_policy_version"] = json!(0);
        assert!(serde_json::from_value::<DeviceReanchorPayload>(zero_policy_version).is_err());

        let mut unexpected_did_root_evidence = valid;
        unexpected_did_root_evidence["did_root_evidence_digest"] =
            json!(format!("sha256:{}", "f".repeat(64)));
        assert!(
            serde_json::from_value::<DeviceReanchorPayload>(unexpected_did_root_evidence).is_err()
        );
    }

    /// The non-null `pre_fence_seal_frontier` branch.
    ///
    /// It went unexercised long enough for the type to lose both roots: every
    /// fixture in this repo and in `arkret-spec` used `pre_fence_seal_frontier: null`,
    /// which is the shape a brand-new principal with no accepted Seal produces,
    /// so nothing ever round-tripped the only shape that carries them.
    #[test]
    fn device_reanchor_pre_fence_seal_frontier_round_trips_both_frontier_roots() {
        let wire = json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "principal_server_id": "ak:did_core:web:principal.example",
            "recovery_authority_kind": "pcr_policy",
            "recovery_policy_id": "ak:policy:01904100-0000-7000-8000-000000000001",
            "recovery_policy_version": 1,
            "recovery_session_id": "ak:recovery_session:01904100-0000-7000-8000-000000000002",
            "previous_device_generation": 1,
            "new_device_generation": 2,
            "pre_fence_seal_frontier": {
                "leaves": [
                    format!("ak:seal:sha256:{}", "a".repeat(64)),
                    format!("ak:seal:sha256:{}", "b".repeat(64)),
                ],
                "control_event_set_root": format!("sha256:{}", "c".repeat(64)),
                "state_root": format!("sha256:{}", "d".repeat(64)),
            },
            "replacement_authorize_payload_digest": format!("sha256:{}", "e".repeat(64))
        });
        let payload: DeviceReanchorPayload = serde_json::from_value(wire.clone()).unwrap();
        let basis = payload.pre_fence_seal_frontier.as_ref().unwrap();
        assert_eq!(basis.leaves.len(), 2);
        assert_eq!(
            basis.control_event_set_root.as_str(),
            format!("sha256:{}", "c".repeat(64))
        );
        assert_eq!(
            basis.state_root.as_str(),
            format!("sha256:{}", "d".repeat(64))
        );
        assert_eq!(serde_json::to_value(&payload).unwrap(), wire);

        // Both roots are required, not optional decoration.
        for dropped in ["control_event_set_root", "state_root"] {
            let mut missing = wire.clone();
            missing["pre_fence_seal_frontier"]
                .as_object_mut()
                .unwrap()
                .remove(dropped);
            assert!(
                serde_json::from_value::<DeviceReanchorPayload>(missing).is_err(),
                "pre_fence_seal_frontier must reject a frontier missing {dropped}"
            );
        }

        // Leaf bounds still come from the one SealBasis implementation.
        let mut unsorted = wire;
        unsorted["pre_fence_seal_frontier"]["leaves"] = json!([
            format!("ak:seal:sha256:{}", "b".repeat(64)),
            format!("ak:seal:sha256:{}", "a".repeat(64)),
        ]);
        assert!(serde_json::from_value::<DeviceReanchorPayload>(unsorted).is_err());
    }

    #[test]
    fn direct_conversation_binding_digest_matches_registered_kat_and_normalizes_sets() {
        let payload = json!({
            "pair_key": "sha256:e8c24c1badc48eefa472a1700e87a6597a95aedfab8cbe3173f1622b9ad427b5",
            "unordered_participant_ids": [
                "ak:did_core:webvh:z6mkfixturebob",
                "ak:did_core:webvh:z6mkfixturealice"
            ],
            "realm_id": "ak:realm:AVYxXzYx_KzaGx7X62doksaQR0ISkneyOwwF1k6ExHKy",
            "main_strand_id": "ak:strand:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo",
            "founding_unit_digest": format!("sha256:{}", "b".repeat(64)),
            "authorization_basis": {
                "kind": "accepted_contact",
                "event_refs": [
                    "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
                    "ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N"
                ]
            },
            "initial_exact_pair_group_state_ref": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "created_at": "2026-08-07T12:34:56.000Z"
        });
        let mut parsed: DirectConversationBoundPayload = serde_json::from_value(payload).unwrap();
        let expected = "sha256:f0a12a2e712ad2de56f6a6f3ef7dc5dbe1b0e078f6ce5439b7c206d30a23c67c";
        assert_eq!(parsed.binding_digest().unwrap().as_str(), expected);

        parsed.unordered_participant_ids.reverse();
        parsed.authorization_basis.event_refs.reverse();
        parsed.created_at = DateTime::parse_from_rfc3339("2027-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed.binding_digest().unwrap().as_str(), expected);
    }
}
