//! Device authorization payload and possession-proof binding.

use std::collections::BTreeSet;

use arkret_models_crypto::RecoveryAuthorityKind;
use arkret_wire::{
    AccountId, AppletId, DeviceId, DidCoreId, DomainSeparationId, Event, EventKind, Hash,
    NonEmptyString, PolicyId, RecoverySessionId, Result, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::SignatureMaterial;

/// Counterpart for
/// `event-payload.schema.json#/$defs/device_reanchor_payload`.
///
/// The payload fixes the account-local recovery decision and the exact
/// replacement authorization payload. Ordering and commit identifiers are
/// assigned later by the governance Station, so no `RealmCommit` or producer
/// ordering coordinate is accepted here.
// Field declaration order is byte-for-byte the properties order of
// event-payload.schema.json#/$defs/device_reanchor_payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReanchorPayload {
    pub account_id: AccountId,
    pub recovery_authority_kind: RecoveryAuthorityKind,
    pub recovery_policy_id: PolicyId,
    pub recovery_policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub previous_device_generation: u64,
    pub new_device_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_root_evidence_digest: Option<Hash>,
    pub replacement_authorize_payload_digest: Hash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceReanchorPayloadWire {
    account_id: AccountId,
    recovery_authority_kind: RecoveryAuthorityKind,
    recovery_policy_id: PolicyId,
    recovery_policy_version: u64,
    recovery_session_id: RecoverySessionId,
    previous_device_generation: u64,
    new_device_generation: u64,
    #[serde(default)]
    did_root_evidence_digest: Option<Hash>,
    replacement_authorize_payload_digest: Hash,
}

impl<'de> Deserialize<'de> for DeviceReanchorPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceReanchorPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            account_id: wire.account_id,
            recovery_authority_kind: wire.recovery_authority_kind,
            recovery_policy_id: wire.recovery_policy_id,
            recovery_policy_version: wire.recovery_policy_version,
            recovery_session_id: wire.recovery_session_id,
            previous_device_generation: wire.previous_device_generation,
            new_device_generation: wire.new_device_generation,
            did_root_evidence_digest: wire.did_root_evidence_digest,
            replacement_authorize_payload_digest: wire.replacement_authorize_payload_digest,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl DeviceReanchorPayload {
    pub fn validate(&self) -> Result<()> {
        if self.recovery_policy_version == 0 {
            return Err(WireError::Protocol(
                "device reanchor recovery_policy_version must be at least 1".to_owned(),
            ));
        }
        if self.previous_device_generation == 0
            || Some(self.new_device_generation) != self.previous_device_generation.checked_add(1)
        {
            return Err(WireError::Protocol(
                "device reanchor generation must be one immediate monotonic successor".to_owned(),
            ));
        }
        if (self.recovery_authority_kind == RecoveryAuthorityKind::DidRoot)
            != self.did_root_evidence_digest.is_some()
        {
            return Err(WireError::Protocol(
                "device reanchor did_root evidence presence must match recovery authority kind"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod device_reanchor_tests {
    use arkret_schema_conformance::event_payload_validator_catalog;
    use serde_json::json;

    use super::*;

    fn payload_value(authority_kind: &str) -> Value {
        let mut value = json!({
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkholder",
                "station_id": "ak:did_core:web:station.example"
            },
            "recovery_authority_kind": authority_kind,
            "recovery_policy_id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
            "recovery_policy_version": 3,
            "recovery_session_id": "ak:recovery_session:0198ff00-0000-7000-8000-00000000000c",
            "previous_device_generation": 7,
            "new_device_generation": 8,
            "replacement_authorize_payload_digest": format!("sha256:{}", "a".repeat(64))
        });
        if authority_kind == "did_root" {
            value.as_object_mut().unwrap().insert(
                "did_root_evidence_digest".to_owned(),
                json!(format!("sha256:{}", "b".repeat(64))),
            );
        }
        value
    }

    #[test]
    fn payload_round_trips_and_matches_the_registered_schema() {
        for authority_kind in ["pcr_policy", "did_root"] {
            let value = payload_value(authority_kind);
            event_payload_validator_catalog()
                .unwrap()
                .validate_payload("ak.device.reanchor", &value)
                .unwrap();
            let payload: DeviceReanchorPayload = serde_json::from_value(value.clone()).unwrap();
            payload.validate().unwrap();
            assert_eq!(serde_json::to_value(payload).unwrap(), value);
        }
    }

    #[test]
    fn payload_requires_exactly_one_monotonic_generation_step() {
        for (previous, next) in [(0, 1), (7, 7), (7, 9), (u64::MAX, u64::MAX)] {
            let mut value = payload_value("pcr_policy");
            value["previous_device_generation"] = json!(previous);
            value["new_device_generation"] = json!(next);
            assert!(serde_json::from_value::<DeviceReanchorPayload>(value).is_err());
        }
    }

    #[test]
    fn did_root_evidence_is_closed_by_the_authority_branch() {
        let mut pcr_with_did_root_evidence = payload_value("pcr_policy");
        pcr_with_did_root_evidence.as_object_mut().unwrap().insert(
            "did_root_evidence_digest".to_owned(),
            json!(format!("sha256:{}", "b".repeat(64))),
        );
        assert!(
            serde_json::from_value::<DeviceReanchorPayload>(pcr_with_did_root_evidence).is_err()
        );

        let mut did_root_without_evidence = payload_value("did_root");
        did_root_without_evidence
            .as_object_mut()
            .unwrap()
            .remove("did_root_evidence_digest");
        assert!(
            serde_json::from_value::<DeviceReanchorPayload>(did_root_without_evidence).is_err()
        );
    }

    #[test]
    fn unknown_or_missing_members_are_rejected() {
        for member in [
            "account_id",
            "recovery_authority_kind",
            "recovery_policy_id",
            "recovery_policy_version",
            "recovery_session_id",
            "previous_device_generation",
            "new_device_generation",
            "replacement_authorize_payload_digest",
        ] {
            let mut value = payload_value("pcr_policy");
            value.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<DeviceReanchorPayload>(value).is_err(),
                "{member} must be required"
            );
        }

        let mut value = payload_value("pcr_policy");
        value["realm_commit_id"] = json!(format!("sha256:{}", "c".repeat(64)));
        assert!(serde_json::from_value::<DeviceReanchorPayload>(value).is_err());
    }
}

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
    /// PCR-local device generation accepted by the governing Station. This is
    /// never a DID `versionId`.
    pub authorized_generation_ref: u64,
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
    authorized_generation_ref: u64,
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
            authorized_generation_ref: wire.authorized_generation_ref,
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
        if self.authorized_generation_ref == 0 {
            return Err("device_authorize_generation_ref_must_be_positive");
        }
        if self.authorization_binding_kind == DeviceAuthorizationBindingKind::RegistrationAnchor
            && self.authorized_generation_ref != 1
        {
            return Err("device_authorize_registration_generation_ref_must_be_one");
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
            "authorized_generation_ref": self.authorized_generation_ref,
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

/// Registered revocation reason of `ak.device.revoke`.
///
/// `event-payload.schema.json#/$defs/device_revoke_payload` constrains the
/// member to `^[a-z][a-z0-9_]{0,63}$`. The newtype keeps that pattern on the
/// deserialization path so an unconstrained `String` can never reach a signed
/// payload.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DeviceRevocationReason(String);

impl DeviceRevocationReason {
    pub const MAX_BYTES: usize = 64;

    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let mut characters = value.chars();
        let Some(first) = characters.next() else {
            return Err(WireError::Protocol(
                "device revocation reason must not be empty".to_owned(),
            ));
        };
        if value.len() > Self::MAX_BYTES
            || !first.is_ascii_lowercase()
            || !characters.all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
        {
            return Err(WireError::Protocol(
                "device revocation reason must match ^[a-z][a-z0-9_]{0,63}$".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeviceRevocationReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DeviceRevocationReason {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Counterpart for
/// `event-payload.schema.json#/$defs/device_revoke_payload`.
///
/// The revoked subject account is derived exclusively from the Event envelope
/// `actor_id`, so the payload carries no `principal_id` mirror. It likewise
/// carries no checkpoint, generation or pending-selector member: the permanent
/// cutoff is the accepted `RealmCommit` covering this Event, and the
/// `revocation_pending` record for the reducer-derived authorization and
/// generation is created by first durable acceptance, never self-reported by
/// the producer.
// Field declaration order is byte-for-byte the properties order of
// event-payload.schema.json#/$defs/device_revoke_payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokePayload {
    pub device_id: DeviceId,
    pub revoked_by: DeviceOrPrincipalRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    pub reason: DeviceRevocationReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignatureMaterial>,
}

impl DeviceRevokePayload {
    /// The subject of a revocation is the envelope author, so a payload that
    /// names a device the author does not control is refused before it is
    /// authored rather than after it is committed.
    pub fn validate(&self) -> Result<()> {
        if let DeviceOrPrincipalRef::DeviceId(revoking_device) = &self.revoked_by
            && *revoking_device == self.device_id
        {
            return Err(WireError::Protocol(
                "ak.device.revoke must not name the revoked device as its own revoking authority"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod device_authorize_tests {
    use serde_json::{Value, json};

    use super::*;

    fn registration_payload_value() -> Value {
        json!({
            "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
            "device_public_key_did": "did:key:z6Mki3devicepublickey",
            "hpke_key": "z6LSdevicehpke",
            "algorithms": ["Ed25519", "HPKE-X25519-HKDF-SHA256-AES128GCM"],
            "device_key_algorithm": "Ed25519",
            "authorized_by": "ak:did_core:webvh:z6mkcontroller",
            "not_before": "2026-09-16T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "authorized_generation_ref": 1,
            "device_signature": "c2lnbmF0dXJl"
        })
    }

    #[test]
    fn generation_ref_round_trips_and_enters_the_possession_transcript() {
        let payload: DeviceAuthorizePayload =
            serde_json::from_value(registration_payload_value()).unwrap();
        assert_eq!(payload.authorized_generation_ref, 1);
        assert_eq!(
            serde_json::to_value(&payload).unwrap(),
            registration_payload_value()
        );

        let account_id = AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkcontroller").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkstation").unwrap(),
        );
        let transcript = payload
            .device_possession_signature_input(&account_id)
            .unwrap();
        let (_, body) =
            transcript.split_at(transcript.iter().position(|byte| *byte == b'\n').unwrap() + 1);
        let body: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(body["authorized_generation_ref"], json!(1));
    }

    #[test]
    fn generation_ref_is_required_positive_and_registration_is_one() {
        let mut missing = registration_payload_value();
        missing
            .as_object_mut()
            .unwrap()
            .remove("authorized_generation_ref");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(missing).is_err());

        for invalid in [0, 2] {
            let mut payload = registration_payload_value();
            payload
                .as_object_mut()
                .unwrap()
                .insert("authorized_generation_ref".to_owned(), json!(invalid));
            assert!(
                serde_json::from_value::<DeviceAuthorizePayload>(payload).is_err(),
                "registration generation {invalid} must fail closed"
            );
        }
    }
}

#[cfg(test)]
mod device_revoke_tests {
    use serde_json::json;

    use super::*;

    const DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
    const OTHER_DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000002";

    fn payload_value() -> Value {
        json!({
            "device_id": DEVICE,
            "revoked_by": "ak:did_core:webvh:z6mkcontroller",
            "revoked_at": "2026-09-16T00:00:00.000Z",
            "reason": "device_lost",
            "proof": "ak.proof.detached"
        })
    }

    #[test]
    fn payload_round_trips_in_schema_property_order() {
        let payload: DeviceRevokePayload = serde_json::from_value(payload_value()).unwrap();
        assert_eq!(payload.device_id.as_str(), DEVICE);
        assert_eq!(payload.reason.as_str(), "device_lost");
        payload.validate().unwrap();
        assert_eq!(serde_json::to_value(&payload).unwrap(), payload_value());
    }

    #[test]
    fn proof_is_the_only_optional_member() {
        for member in ["device_id", "revoked_by", "revoked_at", "reason"] {
            let mut missing = payload_value();
            missing.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<DeviceRevokePayload>(missing).is_err(),
                "{member} must be required"
            );
        }
        let mut without_proof = payload_value();
        without_proof.as_object_mut().unwrap().remove("proof");
        let payload: DeviceRevokePayload = serde_json::from_value(without_proof.clone()).unwrap();
        assert!(payload.proof.is_none());
        assert_eq!(serde_json::to_value(&payload).unwrap(), without_proof);
    }

    #[test]
    fn the_payload_never_mirrors_a_principal_id() {
        let mut mirrored = payload_value();
        mirrored.as_object_mut().unwrap().insert(
            "principal_id".to_owned(),
            json!("ak:did_core:webvh:z6mksubject"),
        );
        assert!(serde_json::from_value::<DeviceRevokePayload>(mirrored).is_err());
    }

    #[test]
    fn no_checkpoint_or_generation_member_is_accepted() {
        for member in ["generation", "checkpoint", "revocation_pending"] {
            let mut extended = payload_value();
            extended
                .as_object_mut()
                .unwrap()
                .insert(member.to_owned(), json!(1));
            assert!(
                serde_json::from_value::<DeviceRevokePayload>(extended).is_err(),
                "{member} is reducer-derived and must not be producer-supplied"
            );
        }
    }

    #[test]
    fn reason_follows_the_registered_pattern() {
        for accepted in ["a", "device_lost", "k9_rotated", &"a".repeat(64)] {
            DeviceRevocationReason::new(accepted).unwrap();
        }
        for refused in [
            "",
            "Device_lost",
            "9lost",
            "device-lost",
            "device lost",
            "device.lost",
            &"a".repeat(65),
        ] {
            assert!(
                DeviceRevocationReason::new(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
        let mut invalid = payload_value();
        invalid
            .as_object_mut()
            .unwrap()
            .insert("reason".to_owned(), json!("Device Lost"));
        assert!(serde_json::from_value::<DeviceRevokePayload>(invalid).is_err());
    }

    #[test]
    fn a_device_cannot_be_its_own_revoking_authority() {
        let mut self_revoking = payload_value();
        self_revoking
            .as_object_mut()
            .unwrap()
            .insert("revoked_by".to_owned(), json!(DEVICE));
        let payload: DeviceRevokePayload = serde_json::from_value(self_revoking).unwrap();
        assert!(payload.validate().is_err());

        let mut peer_revoking = payload_value();
        peer_revoking
            .as_object_mut()
            .unwrap()
            .insert("revoked_by".to_owned(), json!(OTHER_DEVICE));
        let payload: DeviceRevokePayload = serde_json::from_value(peer_revoking).unwrap();
        payload.validate().unwrap();
    }

    #[test]
    fn revoked_at_must_be_a_canonical_timestamp() {
        let mut loose = payload_value();
        loose
            .as_object_mut()
            .unwrap()
            .insert("revoked_at".to_owned(), json!("2026-09-16T00:00:00Z"));
        assert!(serde_json::from_value::<DeviceRevokePayload>(loose).is_err());
    }
}
