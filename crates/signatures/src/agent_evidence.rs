//! Account Authority signing and independent verification of the controller
//! lifecycle gate an Agent Authority carries inside portable signer evidence.
//!
//! The gate is not an Event and not a `RealmCommit` witness: it is a short
//! lived, Account Authority-owned assertion about one controller principal,
//! signed under its own domain separation label so it can never be replayed as
//! any other object. Verifying it is a consumer obligation, not the issuer's,
//! so the verifier here re-checks the closed shape, the expected identities,
//! the DID projection of the signing method, the validity window and only then
//! the detached proof.

use arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation;
use arkret_wire::{Did, DidCoreId, NonEmptyString, project_did_to_core_id};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;

use crate::{
    Ed25519DetachedJwsVerifier, Error, PublicKeyMaterial, Result, sign_ed25519_detached_jws,
};

/// Finish an Account Authority controller gate with the canonical Ed25519
/// detached JWS every independent evidence verifier expects.
///
/// The signing bytes come from the attestation itself
/// ([`ControllerAccountGateAttestation::signing_bytes`]): the domain label, a
/// newline, then the JCS bytes of the object with `proof.jws` removed. Every
/// other closed member, `proof.kind` included, stays covered.
pub fn sign_controller_account_gate_attestation(
    attestation: &mut ControllerAccountGateAttestation,
    signing_key: &SigningKey,
) -> Result<()> {
    attestation.validate()?;
    let bytes = attestation.signing_bytes()?;
    let jws = sign_ed25519_detached_jws(signing_key, &bytes)?;
    attestation.proof.jws = NonEmptyString::new(jws)
        .map_err(|error| Error::Protocol(format!("controller gate proof is empty: {error}")))?;
    Ok(())
}

/// Independently verify the Account Authority-owned gate before an Agent PCR
/// includes it in portable evidence, or before a consumer acts on it.
///
/// `expected_principal_id` and `expected_authority_id` are supplied by the
/// caller from facts it already trusts. A gate that names its own authority is
/// worthless, so the method's DID must also project to the authority the
/// caller named.
pub fn verify_controller_account_gate_attestation(
    attestation: &ControllerAccountGateAttestation,
    expected_principal_id: &DidCoreId,
    expected_authority_id: &DidCoreId,
    authority_public_key: &PublicKeyMaterial,
    now: DateTime<Utc>,
) -> Result<()> {
    attestation.validate()?;
    if &attestation.principal_id != expected_principal_id {
        return Err(Error::Protocol(
            "controller gate names another controller principal".to_owned(),
        ));
    }
    if &attestation.authority_id != expected_authority_id {
        return Err(Error::Protocol(
            "controller gate names another Account Authority".to_owned(),
        ));
    }
    if gate_method_authority(attestation)? != attestation.authority_id {
        return Err(Error::Protocol(
            "controller gate signing method does not project to its authority".to_owned(),
        ));
    }
    if !attestation.is_valid_at(now) {
        return Err(Error::Protocol(
            "controller gate is outside its validity window".to_owned(),
        ));
    }
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            attestation.proof.jws.as_str(),
            &attestation.signing_bytes()?,
            authority_public_key,
        )
        .map(|_| ())
        .map_err(|error| Error::Protocol(format!("controller gate signature is invalid: {error}")))
}

/// The service the gate's `verification_method` belongs to, projected through
/// the registered DID adapter rather than parsed as text.
fn gate_method_authority(attestation: &ControllerAccountGateAttestation) -> Result<DidCoreId> {
    let controller = attestation
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            Error::Protocol("controller gate verification_method needs a fragment".to_owned())
        })?;
    Ok(project_did_to_core_id(&Did::new(controller.to_owned())?)?)
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::agent_signer_evidence::{
        AgentDetachedJws, ControllerAccountEligibility, ControllerAccountGateBasis,
        ControllerAccountStatus,
    };
    use arkret_wire::{DidUrl, Hash, proof_kind};

    use super::*;

    fn digest(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn principal() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:controller.example").unwrap()
    }

    fn authority() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:authority.example").unwrap()
    }

    fn unsigned() -> ControllerAccountGateAttestation {
        ControllerAccountGateAttestation {
            schema: NonEmptyString::new(ControllerAccountGateAttestation::SCHEMA_ID.to_owned())
                .unwrap(),
            principal_id: principal(),
            eligibility: ControllerAccountEligibility::Active,
            status: ControllerAccountStatus::Active,
            basis: ControllerAccountGateBasis::AccountBindingDefault {
                binding_version: 7,
                binding_receipt_digest: digest(0x11),
            },
            basis_digest: digest(0x22),
            authority_id: authority(),
            verification_method: DidUrl::new("did:web:authority.example#account-authority")
                .unwrap(),
            issued_at: "2026-09-16T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-09-16T00:05:00.000Z".parse().unwrap(),
            proof: AgentDetachedJws {
                kind: NonEmptyString::new(proof_kind::DETACHED_JWS.to_owned()).unwrap(),
                jws: NonEmptyString::new("unsigned".to_owned()).unwrap(),
            },
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public(signing_key: &SigningKey) -> PublicKeyMaterial {
        PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        }
    }

    fn inside_window() -> DateTime<Utc> {
        "2026-09-16T00:02:00.000Z".parse().unwrap()
    }

    #[test]
    fn a_signed_gate_verifies_against_its_named_identities() {
        let signing_key = key(41);
        let mut gate = unsigned();
        sign_controller_account_gate_attestation(&mut gate, &signing_key).unwrap();

        verify_controller_account_gate_attestation(
            &gate,
            &principal(),
            &authority(),
            &public(&signing_key),
            inside_window(),
        )
        .unwrap();
    }

    #[test]
    fn a_gate_for_another_controller_is_refused() {
        let signing_key = key(43);
        let mut gate = unsigned();
        sign_controller_account_gate_attestation(&mut gate, &signing_key).unwrap();

        let error = verify_controller_account_gate_attestation(
            &gate,
            &DidCoreId::new("ak:did_core:web:someone-else.example").unwrap(),
            &authority(),
            &public(&signing_key),
            inside_window(),
        )
        .expect_err("a foreign controller must fail closed");
        assert!(
            error.to_string().contains("controller principal"),
            "{error}"
        );
    }

    /// A gate whose signing method belongs to a different service cannot pass
    /// even when the carried `authority_id` is the expected one.
    #[test]
    fn a_method_from_another_service_is_refused() {
        let signing_key = key(47);
        let mut gate = unsigned();
        gate.verification_method = DidUrl::new("did:web:other.example#account-authority").unwrap();
        sign_controller_account_gate_attestation(&mut gate, &signing_key).unwrap();

        let error = verify_controller_account_gate_attestation(
            &gate,
            &principal(),
            &authority(),
            &public(&signing_key),
            inside_window(),
        )
        .expect_err("a foreign signing method must fail closed");
        assert!(error.to_string().contains("project"), "{error}");
    }

    #[test]
    fn an_expired_gate_is_refused() {
        let signing_key = key(53);
        let mut gate = unsigned();
        sign_controller_account_gate_attestation(&mut gate, &signing_key).unwrap();

        for instant in [
            "2026-09-15T23:59:59.000Z".parse::<DateTime<Utc>>().unwrap(),
            "2026-09-16T00:05:00.000Z".parse::<DateTime<Utc>>().unwrap(),
        ] {
            let error = verify_controller_account_gate_attestation(
                &gate,
                &principal(),
                &authority(),
                &public(&signing_key),
                instant,
            )
            .expect_err("a gate outside its window must fail closed");
            assert!(error.to_string().contains("validity window"), "{error}");
        }
    }

    #[test]
    fn a_gate_does_not_survive_a_basis_mutation() {
        let signing_key = key(59);
        let mut gate = unsigned();
        sign_controller_account_gate_attestation(&mut gate, &signing_key).unwrap();
        gate.basis_digest = digest(0x33);

        assert!(
            verify_controller_account_gate_attestation(
                &gate,
                &principal(),
                &authority(),
                &public(&signing_key),
                inside_window(),
            )
            .is_err()
        );
    }

    /// `proof.kind` is inside the signed bytes, so re-labelling the proof
    /// breaks the signature rather than silently changing its meaning.
    #[test]
    fn the_proof_kind_is_covered_by_the_signature() {
        let signing_key = key(61);
        let mut gate = unsigned();
        sign_controller_account_gate_attestation(&mut gate, &signing_key).unwrap();
        gate.proof.kind = NonEmptyString::new("data_integrity".to_owned()).unwrap();

        assert!(
            verify_controller_account_gate_attestation(
                &gate,
                &principal(),
                &authority(),
                &public(&signing_key),
                inside_window(),
            )
            .is_err()
        );
    }

    #[test]
    fn another_authority_key_does_not_verify() {
        let signing_key = key(67);
        let mut gate = unsigned();
        sign_controller_account_gate_attestation(&mut gate, &signing_key).unwrap();

        assert!(
            verify_controller_account_gate_attestation(
                &gate,
                &principal(),
                &authority(),
                &public(&key(71)),
                inside_window(),
            )
            .is_err()
        );
    }

    /// The issuer refuses to put a signature on a shape a consumer would then
    /// have to reject: an over-long window never becomes signed bytes.
    #[test]
    fn an_over_long_window_is_never_signed() {
        let mut gate = unsigned();
        gate.expires_at = "2026-09-16T00:06:00.000Z".parse().unwrap();
        assert!(sign_controller_account_gate_attestation(&mut gate, &key(73)).is_err());
    }
}
