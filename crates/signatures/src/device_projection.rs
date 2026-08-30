//! Origin-Station device projection attestation
//! (`crypto-media/device-lifecycle.md` §8.2).
//!
//! `ak.self.keys.read.lookup.v1` is a relationship-gated **cross principal**
//! surface. Its prose used to require the receiver to replay a PCR
//! authorization chain from an identity-root anchored genesis receipt, while
//! the schema carried no genesis receipt, no chain and no Seal — so the stated
//! verification closure was not executable on the wire, and the only way to
//! make it executable would have been to publish an account's internal
//! governance log to every third party that happens to share a Realm with it.
//!
//! v1 resolves that the other way round: the origin Station signs the
//! exact device projection, and that signature is the whole closure. PCR
//! material stays behind `ak.self.identity.read.resolution_audit.v1`.

use arkret_models_crypto::{
    DeviceProjectionAttestation, DeviceProjectionAttestationCore, DeviceStatus,
};
use arkret_wire::{Base64UrlString, Did, DidCoreId, DidUrl, ProtocolSignature};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

/// Sign one device projection attestation.
///
/// `verification_method` MUST be a key of the origin Station named in
/// `core.station_id`; the binding is re-checked on the verify side, so
/// a mis-signed attestation fails there rather than being trusted here.
pub fn sign_device_projection_attestation(
    core: DeviceProjectionAttestationCore,
    verification_method: DidUrl,
    signing_key: &SigningKey,
) -> arkret_wire::Result<DeviceProjectionAttestation> {
    if core.attested_at >= core.expires_at {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation is not a positive validity window".to_owned(),
        ));
    }
    // The schema pins `device_status` to `active`: this surface attests usable
    // devices only, and a revoked one is omitted rather than reported. Refusing
    // to sign anything else keeps the Rust type from being the one place that
    // could mint a row the wire contract forbids.
    if core.device_status != DeviceStatus::Active {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation may only attest an active device".to_owned(),
        ));
    }
    let created_at = core.attested_at;
    let mut attestation = DeviceProjectionAttestation {
        proof: ProtocolSignature {
            verification_method,
            created_at,
            jws: base64_value("AA".to_owned())?,
        },
        attestation: core,
    };
    let bytes = attestation.proof_signing_bytes()?;
    attestation.proof.jws = base64_value(arkret_canonical::base64url_encode(
        signing_key.sign(&bytes).to_bytes(),
    ))?;
    Ok(attestation)
}

/// Verify one device projection attestation against the origin Principal
/// Server's key.
///
/// The caller supplies the already-resolved key: this surface never resolves a
/// DID per row, which is what makes the §8.3 hot path free of online lookups.
/// What is enforced here is the part a caller must not be able to skip — the
/// proof controller projects **exactly** onto `station_id`, the proof
/// timestamp equals the attested instant, the attestation has not expired, and
/// the signature covers the registered transcript.
pub fn verify_device_projection_attestation(
    attestation: &DeviceProjectionAttestation,
    station_key: &VerifyingKey,
    now: DateTime<Utc>,
) -> arkret_wire::Result<()> {
    let core = &attestation.attestation;
    let controller = proof_controller(&attestation.proof.verification_method)?;
    if controller != core.station_id {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation proof controller is not the origin Station".to_owned(),
        ));
    }
    if attestation.proof.created_at != core.attested_at {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation proof timestamp mismatch".to_owned(),
        ));
    }
    if core.attested_at >= core.expires_at {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation is not a positive validity window".to_owned(),
        ));
    }
    if now >= core.expires_at {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation is expired".to_owned(),
        ));
    }
    let signature_bytes = arkret_canonical::base64url_decode(attestation.proof.jws.as_str())
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    station_key
        .verify(&attestation.proof_signing_bytes()?, &signature)
        .map_err(|_| {
            arkret_wire::WireError::Protocol(
                "invalid device projection attestation proof".to_owned(),
            )
        })
}

fn proof_controller(verification_method: &DidUrl) -> arkret_wire::Result<DidCoreId> {
    let (bare, _) = verification_method
        .as_str()
        .rsplit_once('#')
        .ok_or_else(|| {
            arkret_wire::WireError::Protocol(
                "device projection attestation verification method has no fragment".to_owned(),
            )
        })?;
    let did = Did::new(bare.to_owned())
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    arkret_wire::project_did_to_core_id(&did)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
}

fn base64_value(value: String) -> arkret_wire::Result<Base64UrlString> {
    Base64UrlString::new(value).map_err(|error| arkret_wire::WireError::Protocol(error.to_owned()))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DeviceId, DidKey, EventId, NonEmptyString};
    use chrono::TimeZone as _;

    use super::*;

    fn core() -> DeviceProjectionAttestationCore {
        let attested_at = Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap();
        DeviceProjectionAttestationCore {
            principal_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            station_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            device_signing_key_did: DidKey::new(
                "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x",
            )
            .unwrap(),
            hpke_key: NonEmptyString::new("hpke-1").unwrap(),
            device_authorize_event_id: EventId::new(
                "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
            )
            .unwrap(),
            authorized_generation_ref: 7,
            device_status: DeviceStatus::Active,
            attested_at,
            expires_at: attested_at + chrono::Duration::minutes(10),
        }
    }

    fn verification_method() -> DidUrl {
        DidUrl::new("did:webvh:z6mkfixtureps:ps.example#signing-1").unwrap()
    }

    #[test]
    fn a_signed_attestation_round_trips_and_rejects_tampering() {
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let now = core().attested_at;
        let attestation =
            sign_device_projection_attestation(core(), verification_method(), &signing_key)
                .unwrap();
        verify_device_projection_attestation(&attestation, &signing_key.verifying_key(), now)
            .expect("valid attestation");

        let mut tampered = attestation;
        tampered.attestation.authorized_generation_ref = 8;
        assert!(
            verify_device_projection_attestation(&tampered, &signing_key.verifying_key(), now)
                .is_err(),
            "a rewritten generation must break the signature"
        );
    }

    /// A signature made by some other service is not evidence about this
    /// account's device, however valid it is on its own terms.
    #[test]
    fn a_foreign_controller_is_rejected_before_the_signature_matters() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let now = core().attested_at;
        let attestation = sign_device_projection_attestation(
            core(),
            DidUrl::new("did:webvh:z6mkattacker:attacker.example#signing-1").unwrap(),
            &signing_key,
        )
        .unwrap();
        assert!(
            verify_device_projection_attestation(&attestation, &signing_key.verifying_key(), now)
                .is_err()
        );
    }

    /// The wire contract pins `device_status` to `active`; the Rust enum can
    /// spell `revoked`, so the producer refuses rather than minting a row the
    /// schema forbids.
    #[test]
    fn a_non_active_device_is_never_attested() {
        let signing_key = SigningKey::from_bytes(&[14_u8; 32]);
        let mut revoked = core();
        revoked.device_status = DeviceStatus::Revoked;
        assert!(
            sign_device_projection_attestation(revoked, verification_method(), &signing_key)
                .is_err()
        );
    }

    #[test]
    fn an_expired_attestation_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
        let core = core();
        let expires_at = core.expires_at;
        let attestation =
            sign_device_projection_attestation(core, verification_method(), &signing_key).unwrap();
        assert!(
            verify_device_projection_attestation(
                &attestation,
                &signing_key.verifying_key(),
                expires_at
            )
            .is_err(),
            "a cache must not extend the hard freshness bound"
        );
    }
}
