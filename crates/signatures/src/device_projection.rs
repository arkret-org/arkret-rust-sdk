//! Origin-Station device projection attestation
//! (`crypto-media/device-lifecycle.md` §8.2).
//!
//! `ak.self.keys.read.lookup.v1` is a relationship-gated **cross principal**
//! surface. Its prose used to require the receiver to replay a PCR
//! authorization chain from an identity-root anchored genesis receipt, while
//! the schema carried no genesis receipt or replayable chain, so the stated
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
use arkret_wire::{Did, DidCoreId, DidUrl, ProtocolSignature};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial, sign_ed25519_detached_jws};

/// Sign one device projection attestation.
///
/// `verification_method` MUST be a key of the origin Station named in
/// `core.account_id.station_id`; the binding is re-checked on the verify side, so
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
    if core.attested_at < core.authorization_window.not_before
        || core
            .authorization_window
            .expires_at
            .is_some_and(|expiry| core.attested_at >= expiry || core.expires_at > expiry)
    {
        return Err(arkret_wire::WireError::Protocol(
            "device projection cache window exceeds the original authorization window".to_owned(),
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
            jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
        },
        attestation: core,
    };
    let bytes = attestation.proof_signing_bytes()?;
    attestation.proof.jws = sign_ed25519_detached_jws(signing_key, &bytes)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    Ok(attestation)
}

/// Verify one device projection attestation against the origin Station's key.
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
    if controller != core.account_id.station_id {
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
    if core.attested_at < core.authorization_window.not_before
        || core
            .authorization_window
            .expires_at
            .is_some_and(|expiry| core.attested_at >= expiry || core.expires_at > expiry)
    {
        return Err(arkret_wire::WireError::Protocol(
            "device projection cache window exceeds the original authorization window".to_owned(),
        ));
    }
    if now >= core.expires_at {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation is expired".to_owned(),
        ));
    }
    if core.device_status != DeviceStatus::Active {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation may only attest an active device".to_owned(),
        ));
    }
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &attestation.proof.jws,
            &attestation.proof_signing_bytes()?,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: station_key.to_bytes().to_vec(),
            },
        )
        .map_err(|_| {
            arkret_wire::WireError::Protocol(
                "invalid device projection attestation proof".to_owned(),
            )
        })
}

pub fn sign_forward_device_projection_attestation(
    core: arkret_models_crypto::ForwardDeviceProjectionAttestationCore,
    verification_method: DidUrl,
    signing_key: &SigningKey,
) -> arkret_wire::Result<arkret_models_crypto::ForwardDeviceProjectionAttestation> {
    core.validate_event_authorization()?;
    if core.attested_at >= core.expires_at {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation is not a positive validity window".to_owned(),
        ));
    }
    if core.attested_at < core.authorization_window.not_before
        || core
            .authorization_window
            .expires_at
            .is_some_and(|expiry| core.attested_at >= expiry || core.expires_at > expiry)
    {
        return Err(arkret_wire::WireError::Protocol(
            "device projection cache window exceeds the original authorization window".to_owned(),
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
    let mut attestation = arkret_models_crypto::ForwardDeviceProjectionAttestation {
        proof: ProtocolSignature {
            verification_method,
            created_at,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
        },
        attestation: core,
    };
    let bytes = attestation.proof_signing_bytes()?;
    attestation.proof.jws = sign_ed25519_detached_jws(signing_key, &bytes)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    Ok(attestation)
}

/// Verify one device projection attestation against the origin Station's key.
///
/// The caller supplies the already-resolved key: this surface never resolves a
/// DID per row, which is what makes the §8.3 hot path free of online lookups.
/// What is enforced here is the part a caller must not be able to skip — the
/// proof controller projects **exactly** onto `station_id`, the proof
/// timestamp equals the attested instant, the attestation has not expired, and
/// the signature covers the registered transcript.
pub fn verify_forward_device_projection_attestation(
    attestation: &arkret_models_crypto::ForwardDeviceProjectionAttestation,
    station_key: &VerifyingKey,
    now: DateTime<Utc>,
) -> arkret_wire::Result<()> {
    let core = &attestation.attestation;
    core.validate_event_authorization()?;
    let controller = proof_controller(&attestation.proof.verification_method)?;
    if controller != core.account_id.station_id {
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
    if core.attested_at < core.authorization_window.not_before
        || core
            .authorization_window
            .expires_at
            .is_some_and(|expiry| core.attested_at >= expiry || core.expires_at > expiry)
    {
        return Err(arkret_wire::WireError::Protocol(
            "device projection cache window exceeds the original authorization window".to_owned(),
        ));
    }
    if now >= core.expires_at {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation is expired".to_owned(),
        ));
    }
    if core.device_status != DeviceStatus::Active {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation may only attest an active device".to_owned(),
        ));
    }
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &attestation.proof.jws,
            &attestation.proof_signing_bytes()?,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: station_key.to_bytes().to_vec(),
            },
        )
        .map_err(|_| {
            arkret_wire::WireError::Protocol(
                "invalid device projection attestation proof".to_owned(),
            )
        })
}

/// Device evidence verified while its current-query cache window was valid.
/// This authenticates a historical authorization fact, not permission to publish.
/// Callers must still evaluate all applicable verified authorization closures.
#[derive(Clone, Debug)]
pub struct VerifiedDeviceProjection {
    core: DeviceProjectionAttestationCore,
}

impl VerifiedDeviceProjection {
    pub fn authorization(&self) -> &DeviceProjectionAttestationCore {
        &self.core
    }

    /// Check the original device grant at the signed publication time. The
    /// attestation's freshness deadline is deliberately not a grant expiry.
    pub fn validate_publication_time(&self, signed_at: DateTime<Utc>) -> arkret_wire::Result<()> {
        let window = &self.core.authorization_window;
        if signed_at < window.not_before
            || window.expires_at.is_some_and(|expiry| signed_at >= expiry)
        {
            return Err(arkret_wire::WireError::Protocol(
                "ordinary publication is outside the authenticated device authorization window"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authenticate evidence at its actual observation time for later ordinary use.
/// The resulting value retains the verified grant independently of cache TTL;
/// it cannot bypass authorization closures, realm membership or event proof checks.
pub fn authenticate_device_projection_for_caching(
    attestation: &DeviceProjectionAttestation,
    station_key: &VerifyingKey,
    observed_at: DateTime<Utc>,
) -> arkret_wire::Result<VerifiedDeviceProjection> {
    if observed_at < attestation.attestation.attested_at {
        return Err(arkret_wire::WireError::Protocol(
            "device evidence predates its attestation".to_owned(),
        ));
    }
    verify_device_projection_attestation(attestation, station_key, observed_at)?;
    Ok(VerifiedDeviceProjection {
        core: attestation.attestation.clone(),
    })
}

pub fn verify_device_projection_with_key_material(
    attestation: &DeviceProjectionAttestation,
    station_key: &PublicKeyMaterial,
    at: DateTime<Utc>,
) -> arkret_wire::Result<()> {
    if at < attestation.attestation.attested_at {
        return Err(arkret_wire::WireError::Protocol(
            "device projection attestation is not yet effective".to_owned(),
        ));
    }
    let bytes = station_key
        .ed25519_bytes()
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    verify_device_projection_attestation(attestation, &key, at)
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

#[cfg(test)]
mod tests {
    use arkret_wire::{DeviceId, DidKey, EventId, NonEmptyString};
    use chrono::TimeZone as _;

    use super::*;

    fn core() -> DeviceProjectionAttestationCore {
        let attested_at = Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap();
        DeviceProjectionAttestationCore {
            account_id: arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            ),
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
            authorization_window: arkret_models_crypto::DeviceAuthorizationWindow {
                not_before: attested_at,
                expires_at: None,
            },
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

        let mut tampered = attestation.clone();
        tampered.attestation.authorized_generation_ref = 8;
        assert!(
            verify_device_projection_attestation(&tampered, &signing_key.verifying_key(), now)
                .is_err(),
            "a rewritten generation must break the signature"
        );
        let mut foreign_account = attestation.clone();
        foreign_account.attestation.account_id.station_id =
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        assert!(
            verify_device_projection_attestation(
                &foreign_account,
                &signing_key.verifying_key(),
                now
            )
            .is_err()
        );
        let mut foreign_principal = attestation;
        foreign_principal.attestation.account_id.principal_id =
            DidCoreId::new("ak:did_core:web:other-principal.example").unwrap();
        assert!(
            verify_device_projection_attestation(
                &foreign_principal,
                &signing_key.verifying_key(),
                now
            )
            .is_err()
        );
    }

    #[test]
    fn cached_device_evidence_keeps_the_original_grant_window() {
        let key = SigningKey::from_bytes(&[21; 32]);
        let mut core = core();
        let observed_at = core.attested_at;
        let grant_expiry = observed_at + chrono::Duration::hours(1);
        core.authorization_window.expires_at = Some(grant_expiry);
        let signed = sign_device_projection_attestation(core, verification_method(), &key).unwrap();
        let cached =
            authenticate_device_projection_for_caching(&signed, &key.verifying_key(), observed_at)
                .unwrap();
        let after_cache = observed_at + chrono::Duration::minutes(20);
        assert!(
            verify_device_projection_attestation(&signed, &key.verifying_key(), after_cache)
                .is_err()
        );
        cached.validate_publication_time(after_cache).unwrap();
        assert!(cached.validate_publication_time(grant_expiry).is_err());
        assert!(
            cached
                .validate_publication_time(observed_at - chrono::Duration::seconds(1))
                .is_err()
        );
        let mut tampered = signed;
        tampered.attestation.authorization_window.expires_at = None;
        assert!(
            authenticate_device_projection_for_caching(
                &tampered,
                &key.verifying_key(),
                observed_at
            )
            .is_err()
        );
    }

    #[test]
    fn device_cache_cannot_extend_or_precede_the_original_grant() {
        let key = SigningKey::from_bytes(&[22; 32]);
        let mut outside = core();
        outside.authorization_window.expires_at =
            Some(outside.expires_at - chrono::Duration::seconds(1));
        assert!(sign_device_projection_attestation(outside, verification_method(), &key).is_err());
        let mut future = core();
        future.authorization_window.not_before = future.attested_at + chrono::Duration::seconds(1);
        assert!(sign_device_projection_attestation(future, verification_method(), &key).is_err());
        let mut absent = serde_json::to_value(core()).unwrap();
        absent["authorization_window"]
            .as_object_mut()
            .unwrap()
            .remove("expires_at");
        assert!(serde_json::from_value::<DeviceProjectionAttestationCore>(absent).is_err());
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

    #[test]
    fn historical_device_proof_uses_signed_time_and_exact_station_key() {
        let signing_key = SigningKey::from_bytes(&[15_u8; 32]);
        let core = core();
        let at = core.attested_at;
        let expiry = core.expires_at;
        let attestation =
            sign_device_projection_attestation(core, verification_method(), &signing_key).unwrap();
        let material = PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        verify_device_projection_with_key_material(&attestation, &material, at).unwrap();
        assert!(
            verify_device_projection_with_key_material(
                &attestation,
                &material,
                at - chrono::Duration::seconds(1)
            )
            .is_err()
        );
        assert!(
            verify_device_projection_with_key_material(&attestation, &material, expiry).is_err()
        );
        let foreign_key = PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[16_u8; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        assert!(
            verify_device_projection_with_key_material(&attestation, &foreign_key, at).is_err()
        );
        // Replaying later uses the immutable response's signing instant, not wall time.
        verify_device_projection_with_key_material(&attestation, &material, at).unwrap();
    }
    #[test]
    fn directory_proof_rejects_true_core_only_signature() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let core = core();
        let mut signed =
            sign_device_projection_attestation(core.clone(), verification_method(), &key).unwrap();
        verify_device_projection_attestation(&signed, &key.verifying_key(), core.attested_at)
            .unwrap();
        let mut transcript: serde_json::Value =
            serde_json::from_slice(&signed.proof_signing_bytes().unwrap()).unwrap();
        transcript["payload_digest"] = serde_json::json!(
            arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&core).unwrap()).unwrap()
        );
        signed.proof.jws = sign_ed25519_detached_jws(
            &key,
            &arkret_canonical::canonical_json_bytes(&transcript).unwrap(),
        )
        .unwrap();
        assert!(
            verify_device_projection_attestation(&signed, &key.verifying_key(), core.attested_at)
                .is_err()
        );
    }
}
