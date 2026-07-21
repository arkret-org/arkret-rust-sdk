//! Cross-signing reset payloads and canonical proof helpers.

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use arkret_canonical::binding_contexts;
use arkret_wire::{DeviceId, Did, Error, EventId, Hash, Result, TypedTrustDomainId, canonical};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::artifacts_device_identity::CrossSigningResetProof;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CrossSigningResetReason {
    Rotation,
    Compromise,
    DeviceLoss,
    PolicyRequired,
}

impl CrossSigningResetReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rotation => "rotation",
            Self::Compromise => "compromise",
            Self::DeviceLoss => "device_loss",
            Self::PolicyRequired => "policy_required",
        }
    }

    fn requires_revoked_devices(self) -> bool {
        matches!(self, Self::Compromise | Self::DeviceLoss)
    }
}

/// Typed payload for `ak.cross_signing.reset`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CrossSigningResetPayload {
    trust_domain: TypedTrustDomainId,
    reset_event_id: EventId,
    principal_id: Did,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = u64)))]
    previous_generation: NonZeroU64,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = u64)))]
    new_generation: NonZeroU64,
    #[serde(rename = "reset_reason_code")]
    reset_reason: CrossSigningResetReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_device_ids: Option<Vec<DeviceId>>,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    proof: CrossSigningResetProof,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    issued_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossSigningResetPayloadWire {
    trust_domain: TypedTrustDomainId,
    reset_event_id: EventId,
    principal_id: Did,
    previous_generation: NonZeroU64,
    new_generation: NonZeroU64,
    #[serde(rename = "reset_reason_code")]
    reset_reason: CrossSigningResetReason,
    #[serde(default)]
    revoked_device_ids: Option<Vec<DeviceId>>,
    proof: CrossSigningResetProof,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    issued_at: DateTime<Utc>,
}

impl<'de> Deserialize<'de> for CrossSigningResetPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CrossSigningResetPayloadWire::deserialize(deserializer)?;
        Self::new(
            wire.trust_domain,
            wire.reset_event_id,
            wire.principal_id,
            wire.previous_generation,
            wire.new_generation,
            wire.reset_reason,
            wire.revoked_device_ids,
            wire.proof,
            wire.issued_at,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl CrossSigningResetPayload {
    pub const SCHEMA: &'static str = "ak.schema.cross_signing_reset.v1";

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trust_domain: TypedTrustDomainId,
        reset_event_id: EventId,
        principal_id: Did,
        previous_generation: NonZeroU64,
        new_generation: NonZeroU64,
        reset_reason: CrossSigningResetReason,
        revoked_device_ids: Option<Vec<DeviceId>>,
        proof: CrossSigningResetProof,
        issued_at: DateTime<Utc>,
    ) -> Result<Self> {
        let payload = Self {
            trust_domain,
            reset_event_id,
            principal_id,
            previous_generation,
            new_generation,
            reset_reason,
            revoked_device_ids,
            proof,
            issued_at,
        };
        payload.validate_structure()?;
        Ok(payload)
    }

    pub fn trust_domain(&self) -> &TypedTrustDomainId {
        &self.trust_domain
    }

    pub fn reset_event_id(&self) -> &EventId {
        &self.reset_event_id
    }

    pub fn principal_id(&self) -> &Did {
        &self.principal_id
    }

    pub fn previous_generation(&self) -> u64 {
        self.previous_generation.get()
    }

    pub fn new_generation(&self) -> u64 {
        self.new_generation.get()
    }

    pub fn reset_reason(&self) -> CrossSigningResetReason {
        self.reset_reason
    }

    pub fn revoked_device_ids(&self) -> Option<&[DeviceId]> {
        self.revoked_device_ids.as_deref()
    }

    pub fn proof(&self) -> &CrossSigningResetProof {
        &self.proof
    }

    pub fn issued_at(&self) -> &DateTime<Utc> {
        &self.issued_at
    }

    pub fn validate_structure(&self) -> Result<()> {
        let expected_generation = self
            .previous_generation
            .get()
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("cross-signing reset generation overflow".to_owned()))?;
        if self.new_generation.get() != expected_generation {
            return Err(Error::Protocol(
                "cross-signing reset new_generation must equal previous_generation + 1".to_owned(),
            ));
        }

        match &self.revoked_device_ids {
            Some(device_ids) => {
                if device_ids.is_empty() {
                    return Err(Error::Protocol(
                        "cross-signing reset revoked_device_ids must not be empty".to_owned(),
                    ));
                }
                let mut unique = BTreeSet::new();
                if device_ids
                    .iter()
                    .any(|device_id| !unique.insert(device_id.as_str()))
                {
                    return Err(Error::Protocol(
                        "cross-signing reset revoked_device_ids must be unique".to_owned(),
                    ));
                }
            }
            None if self.reset_reason.requires_revoked_devices() => {
                return Err(Error::Protocol(
                    "compromise and device_loss resets require revoked_device_ids".to_owned(),
                ));
            }
            None => {}
        }

        if let CrossSigningResetProof::DeviceQuorum {
            threshold,
            signatures,
        } = &self.proof
        {
            if signatures.is_empty() {
                return Err(Error::Protocol(
                    "device_quorum reset proof requires at least one signature".to_owned(),
                ));
            }
            if (signatures.len() as u64) < threshold.get() {
                return Err(Error::Protocol(format!(
                    "device_quorum reset proof has {} signature(s) below declared threshold {}",
                    signatures.len(),
                    threshold.get()
                )));
            }
            let mut unique = BTreeSet::new();
            if signatures
                .iter()
                .any(|signature| !unique.insert(signature.device_id.as_str()))
            {
                return Err(Error::Protocol(
                    "device_quorum reset proof device_id values must be unique".to_owned(),
                ));
            }
        }

        Ok(())
    }

    fn reset_proof_kind(&self) -> &'static str {
        match &self.proof {
            CrossSigningResetProof::PrincipalSigning { .. } => "principal_signing",
            CrossSigningResetProof::RecoveryUnlock { .. } => "recovery_unlock",
            CrossSigningResetProof::DeviceQuorum { .. } => "device_quorum",
            CrossSigningResetProof::TrustedRecoveryService { .. } => "trusted_recovery_service",
        }
    }

    fn reset_proof_body(&self, include_unlock_commitment: bool) -> Value {
        match &self.proof {
            CrossSigningResetProof::PrincipalSigning {
                verification_method,
                alg,
                ..
            } => json!({
                "verification_method": verification_method,
                "alg": alg,
            }),
            CrossSigningResetProof::RecoveryUnlock {
                recovery_session_id,
                recovery_secret_ref,
                unlock_commitment,
                alg,
                ..
            } => {
                let mut body = json!({
                    "recovery_session_id": recovery_session_id,
                    "recovery_secret_ref": recovery_secret_ref,
                    "alg": alg,
                });
                if include_unlock_commitment && let Some(object) = body.as_object_mut() {
                    object.insert(
                        "unlock_commitment".to_owned(),
                        Value::String(unlock_commitment.as_str().to_owned()),
                    );
                }
                body
            }
            CrossSigningResetProof::DeviceQuorum {
                threshold,
                signatures,
            } => {
                let signatures = signatures
                    .iter()
                    .map(|signature| {
                        json!({
                            "device_id": signature.device_id,
                            "verification_method": signature.verification_method,
                            "alg": signature.alg,
                        })
                    })
                    .collect::<Vec<_>>();
                json!({
                    "threshold": threshold,
                    "signatures": signatures,
                })
            }
            CrossSigningResetProof::TrustedRecoveryService {
                recovery_session_id,
                service_id,
                verification_method,
                alg,
                attestation_ref,
                ..
            } => {
                let mut body = json!({
                    "recovery_session_id": recovery_session_id,
                    "service_id": service_id,
                    "verification_method": verification_method,
                    "alg": alg,
                });
                if let Some(attestation_ref) = attestation_ref
                    && let Some(object) = body.as_object_mut()
                {
                    object.insert(
                        "attestation_ref".to_owned(),
                        Value::String(attestation_ref.as_str().to_owned()),
                    );
                }
                body
            }
        }
    }

    fn reset_signing_body(&self, include_unlock_commitment: bool) -> Value {
        json!({
            "trust_domain": self.trust_domain,
            "reset_event_id": self.reset_event_id,
            "principal_id": self.principal_id,
            "previous_generation": self.previous_generation,
            "new_generation": self.new_generation,
            "reset_reason_code": self.reset_reason,
            "issued_at": self.issued_at,
            "proof_kind": self.reset_proof_kind(),
            "proof_body": self.reset_proof_body(include_unlock_commitment),
        })
    }

    pub fn reset_signing_input(&self) -> Result<Vec<u8>> {
        let mut out = binding_contexts::CROSS_SIGNING_RESET_PREFIX.to_vec();
        out.extend_from_slice(&canonical::canonical_json_bytes(
            &self.reset_signing_body(true),
        )?);
        Ok(out)
    }

    pub fn recovery_unlock_binding_input(&self) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(
            &self.reset_signing_body(false),
        )?)
    }

    pub fn recovery_unlock_commitment(&self) -> Result<Hash> {
        let CrossSigningResetProof::RecoveryUnlock {
            recovery_secret_ref,
            ..
        } = &self.proof
        else {
            return Err(Error::Protocol(
                "recovery_unlock_commitment requires recovery_unlock proof".to_owned(),
            ));
        };
        let binding_input = self.recovery_unlock_binding_input()?;
        let digest = canonical::sha256_digest_from_slices(&[
            binding_contexts::CROSS_SIGNING_RESET_UNLOCK_BINDING_PREFIX,
            recovery_secret_ref.as_bytes(),
            &binding_input,
        ]);
        Hash::new(digest).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal_reset() -> Value {
        json!({
            "trust_domain": "ak:trust_domain:example.net",
            "reset_event_id": "ak:event:01964137-0000-7000-8000-0000000000aa",
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason_code": "rotation",
            "proof": {
                "kind": "principal_signing",
                "verification_method": "did:webvh:z6mkfixture:alice.example#did-control",
                "alg": "EdDSA",
                "signature": "AAAA"
            },
            "issued_at": "2026-05-30T00:00:00.000Z"
        })
    }

    #[test]
    fn reset_payload_deserialization_enforces_closed_strong_shape() {
        let payload: CrossSigningResetPayload =
            serde_json::from_value(principal_reset()).expect("valid reset payload");
        assert_eq!(payload.previous_generation(), 1);
        assert_eq!(payload.new_generation(), 2);

        let mut invalid_reason = principal_reset();
        invalid_reason["reset_reason_code"] = json!("lost phone");
        assert!(serde_json::from_value::<CrossSigningResetPayload>(invalid_reason).is_err());

        let mut unknown = principal_reset();
        unknown["legacy"] = json!(true);
        assert!(serde_json::from_value::<CrossSigningResetPayload>(unknown).is_err());
    }

    #[test]
    fn compromise_reset_requires_unique_revoked_devices() {
        let mut missing = principal_reset();
        missing["reset_reason_code"] = json!("compromise");
        assert!(serde_json::from_value::<CrossSigningResetPayload>(missing).is_err());

        let mut duplicate = principal_reset();
        duplicate["reset_reason_code"] = json!("device_loss");
        duplicate["revoked_device_ids"] = json!([
            "ak:device:01904100-0000-7000-8000-000000000001",
            "ak:device:01904100-0000-7000-8000-000000000001"
        ]);
        assert!(serde_json::from_value::<CrossSigningResetPayload>(duplicate).is_err());
    }

    #[test]
    fn reset_signing_input_excludes_signature_material() {
        let payload: CrossSigningResetPayload =
            serde_json::from_value(principal_reset()).expect("valid reset payload");
        let base = payload
            .reset_signing_input()
            .expect("canonical reset input");

        let mut changed = principal_reset();
        changed["proof"]["signature"] = json!("BBBB");
        let changed: CrossSigningResetPayload =
            serde_json::from_value(changed).expect("valid changed signature");
        assert_eq!(base, changed.reset_signing_input().unwrap());
    }

    #[test]
    fn device_quorum_threshold_matches_schema_minimum() {
        let mut payload = principal_reset();
        payload["proof"] = json!({
            "kind": "device_quorum",
            "threshold": 1,
            "signatures": [{
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "verification_method": "did:webvh:z6mkfixture:alice.example#device-1",
                "alg": "EdDSA",
                "signature": "AAAA"
            }]
        });
        assert!(serde_json::from_value::<CrossSigningResetPayload>(payload).is_err());
    }
}
