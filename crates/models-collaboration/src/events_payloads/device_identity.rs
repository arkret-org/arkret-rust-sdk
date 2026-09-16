//! Device authorization payload and possession-proof binding.

use std::collections::BTreeSet;

use arkret_wire::{
    AccountId, AppletId, DeviceId, DidCoreId, DomainSeparationId, Event, EventKind, Hash,
    NonEmptyString, RecoverySessionId, Result, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::SignatureMaterial;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAuthorizationBindingKind {
    RegistrationAnchor,
    PcrRecovery,
    AcceptedDevice,
    AppletManagedDelegation,
}

impl DeviceAuthorizationBindingKind {
    pub const fn possession_proof_context(self) -> &'static str {
        match self {
            Self::RegistrationAnchor => "ak.device_authorize_possession_proof.v1",
            Self::PcrRecovery => "ak.device_authorize_recovery_possession_proof.v1",
            Self::AcceptedDevice => {
                DomainSeparationId::DEVICE_AUTHORIZE_ACCEPTED_DEVICE_POSSESSION_PROOF_V1
            }
            Self::AppletManagedDelegation => {
                "ak.device_authorize_applet_managed_possession_proof.v1"
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceOrPrincipalRef {
    DeviceId(DeviceId),
    Principal(DidCoreId),
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizePayload {
    pub device_id: DeviceId,
    pub device_public_key_did: NonEmptyString,
    pub hpke_key: NonEmptyString,
    pub algorithms: Vec<NonEmptyString>,
    pub device_key_algorithm: NonEmptyString,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_challenge_transcript_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceAuthorizePayloadWire {
    device_id: DeviceId,
    device_public_key_did: NonEmptyString,
    hpke_key: NonEmptyString,
    algorithms: Vec<NonEmptyString>,
    device_key_algorithm: NonEmptyString,
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
    #[serde(default)]
    pairing_challenge_transcript_digest: Option<Hash>,
    #[serde(default)]
    applet_id: Option<AppletId>,
}

impl<'de> Deserialize<'de> for DeviceAuthorizePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceAuthorizePayloadWire::deserialize(deserializer)?;
        let payload = Self {
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
            pairing_challenge_transcript_digest: wire.pairing_challenge_transcript_digest,
            applet_id: wire.applet_id,
        };
        payload
            .validate_wire_constraints()
            .map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl DeviceAuthorizePayload {
    pub fn validate_wire_constraints(&self) -> std::result::Result<(), &'static str> {
        if self.device_key_algorithm.as_str() != "Ed25519" {
            return Err("device_authorize_device_key_algorithm_unsupported");
        }
        if self.algorithms.is_empty()
            || self
                .algorithms
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err("device_authorize_algorithms_not_canonical");
        }
        if (self.authorization_binding_kind == DeviceAuthorizationBindingKind::AcceptedDevice)
            != self.pairing_challenge_transcript_digest.is_some()
        {
            return Err("device_authorize_pairing_challenge_binding_mismatch");
        }
        match (&self.authorization_binding_kind, &self.authorized_by) {
            (
                DeviceAuthorizationBindingKind::RegistrationAnchor,
                DeviceOrPrincipalRef::Principal(_),
            ) if self.recovery_session_id.is_none() => {}
            (DeviceAuthorizationBindingKind::PcrRecovery, DeviceOrPrincipalRef::Principal(_))
                if self.recovery_session_id.is_some() => {}
            (DeviceAuthorizationBindingKind::AcceptedDevice, DeviceOrPrincipalRef::DeviceId(_))
                if self.recovery_session_id.is_none() => {}
            (
                DeviceAuthorizationBindingKind::AppletManagedDelegation,
                DeviceOrPrincipalRef::Principal(_),
            ) if self.recovery_session_id.is_none() => {}
            _ => return Err("device_authorize_authorization_binding_mismatch"),
        }
        let applet_branch = self.authorization_binding_kind
            == DeviceAuthorizationBindingKind::AppletManagedDelegation;
        if applet_branch != self.applet_id.is_some() {
            return Err("device_authorize_applet_binding_mismatch");
        }
        if applet_branch && (!matches!(self.expires_at, Some(Some(_))) || self.scopes.is_none()) {
            return Err("device_authorize_applet_managed_delegation_requires_bounds");
        }
        if let Some(scopes) = &self.scopes
            && (scopes.is_empty() || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len())
        {
            return Err("device_authorize_scopes_must_be_non_empty_and_unique");
        }
        Ok(())
    }

    pub fn device_possession_signature_input(
        &self,
        subject_account_id: &AccountId,
    ) -> Result<Vec<u8>> {
        self.validate_wire_constraints()
            .map_err(|reason| WireError::Protocol(reason.into()))?;
        let authorized_by = match &self.authorized_by {
            DeviceOrPrincipalRef::DeviceId(id) => id.as_str(),
            DeviceOrPrincipalRef::Principal(id) => id.as_str(),
        };
        if self.authorization_binding_kind
            == DeviceAuthorizationBindingKind::AppletManagedDelegation
            && authorized_by != subject_account_id.principal_id.as_str()
        {
            return Err(WireError::Protocol(
                "device_authorize_applet_managed_delegation_requires_self_anchor".into(),
            ));
        }
        if self.authorization_binding_kind == DeviceAuthorizationBindingKind::AcceptedDevice {
            let digest = self
                .pairing_challenge_transcript_digest
                .as_ref()
                .expect("validated");
            return crate::device_pairing::device_pairing_target_proof_signing_input(
                subject_account_id,
                &self.algorithms,
                self.device_id.as_str(),
                self.device_public_key_did.as_str(),
                self.hpke_key.as_str(),
                digest.as_str(),
            );
        }
        let expires_at = self.expires_at.as_ref().and_then(|value| value.as_ref());
        let mut body = serde_json::json!({
            "account_id": subject_account_id,
            "device_id": self.device_id.as_str(),
            "device_public_key_did": self.device_public_key_did.as_str(),
            "hpke_key": self.hpke_key.as_str(),
            "algorithms": self.algorithms,
            "device_key_algorithm": self.device_key_algorithm,
            "authorized_by": authorized_by,
            "not_before": self.not_before,
            "expires_at": expires_at,
            "scopes": self.scopes,
            "recovery_session_id": self.recovery_session_id,
            "authorization_binding_kind": self.authorization_binding_kind,
        });
        if let Some(applet_id) = &self.applet_id {
            body.as_object_mut()
                .expect("device authorization transcript is an object")
                .insert(
                    "applet_id".into(),
                    Value::String(applet_id.as_str().to_owned()),
                );
        }
        let context = self.authorization_binding_kind.possession_proof_context();
        let mut bytes = Vec::with_capacity(context.len() + 1);
        bytes.extend_from_slice(context.as_bytes());
        bytes.push(b'\n');
        bytes.extend(canonical::canonical_json_bytes(&body)?);
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceAuthorizePayloadError {
    UnexpectedKind(String),
    InvalidPayload(String),
}

impl std::fmt::Display for DeviceAuthorizePayloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedKind(kind) => write!(
                formatter,
                "event kind must be ak.device.authorize, got {kind}"
            ),
            Self::InvalidPayload(reason) => write!(
                formatter,
                "ak.device.authorize payload is invalid: {reason}"
            ),
        }
    }
}

impl std::error::Error for DeviceAuthorizePayloadError {}

impl TryFrom<&Event> for DeviceAuthorizePayload {
    type Error = DeviceAuthorizePayloadError;

    fn try_from(event: &Event) -> std::result::Result<Self, Self::Error> {
        if event.kind != EventKind::DeviceAuthorize {
            return Err(DeviceAuthorizePayloadError::UnexpectedKind(
                event.kind.as_str().to_owned(),
            ));
        }
        serde_path_to_error::deserialize(Value::Object(event.payload.clone().into_iter().collect()))
            .map_err(|error| DeviceAuthorizePayloadError::InvalidPayload(error.to_string()))
    }
}

/// Canonical digest of an `ak.device.authorize` payload as it appears on the
/// wire.
///
/// This is the value a root-anchored unit commits to. A root commitment cannot
/// name the authorize Event id or envelope digest, because every `event_id`
/// derives from its own signed content and the committing Event is referenced
/// from the authorize envelope — the two would be preimages of each other.
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

/// Verify that a root-anchored commitment names this exact authorize payload.
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
