//! Frozen-configuration signature verification for Seal conclusions.

use arkret_models_collaboration::{
    SealConclusionCertificate, SealConclusionSet, SealConclusionStatement,
    SealConfigurationHandoffCertificate, SealConfigurationHandoffStatement,
};
use arkret_wire::{EventId, NotaryValue, PayloadSigner, RealmId, Result, SealSignature, WireError};

use crate::verify_frozen_notary_detached_jws;

pub fn sign_seal_conclusion<S: PayloadSigner + ?Sized>(
    statement: SealConclusionStatement,
    signers: &[&S],
) -> Result<SealConclusionCertificate> {
    let payload = statement.signing_payload_bytes()?;
    let signatures = sign_fixed_sha256_payload(&payload, signers)?;
    let certificate = SealConclusionCertificate {
        statement,
        signatures,
    };
    certificate.validate_structural()?;
    Ok(certificate)
}

pub fn sign_seal_configuration_handoff<S: PayloadSigner + ?Sized>(
    statement: SealConfigurationHandoffStatement,
    signers: &[&S],
) -> Result<SealConfigurationHandoffCertificate> {
    let payload = statement.signing_payload_bytes()?;
    let signatures = sign_fixed_sha256_payload(&payload, signers)?;
    let certificate = SealConfigurationHandoffCertificate {
        statement,
        signatures,
    };
    certificate.validate_structural()?;
    Ok(certificate)
}

fn sign_fixed_sha256_payload<S: PayloadSigner + ?Sized>(
    payload: &[u8],
    signers: &[&S],
) -> Result<Vec<SealSignature>> {
    if signers.is_empty() {
        return Err(WireError::Protocol(
            "Seal conclusion certificate requires at least one signer".to_owned(),
        ));
    }
    let mut signatures = signers
        .iter()
        .map(|signer| {
            signer
                .sign_notary_payload_with_digest_suite(
                    payload,
                    arkret_canonical::DigestSuite::Sha256,
                )
                .map(SealSignature::from)
        })
        .collect::<Result<Vec<_>>>()?;
    signatures.sort_by(|left, right| left.verification_method.cmp(&right.verification_method));
    Ok(signatures)
}

pub fn verify_seal_conclusion_quorum_signatures(
    certificate: &SealConclusionCertificate,
    configuration: &NotaryValue,
) -> Result<()> {
    certificate.validate_quorum_with(configuration, |signature, descriptor, payload| {
        verify_frozen_notary_detached_jws(signature, descriptor, payload)
    })
}

pub fn verify_seal_configuration_handoff_quorum_signatures(
    certificate: &SealConfigurationHandoffCertificate,
    old_configuration: &NotaryValue,
) -> Result<()> {
    certificate.validate_quorum_with(old_configuration, |signature, descriptor, payload| {
        verify_frozen_notary_detached_jws(signature, descriptor, payload)
    })
}

/// Verifies the certificate chain from an independently trusted configuration.
///
/// Callers still verify the target/authority Seal ancestry, authorization for
/// every selector, and every returned registered Cell value against local
/// accepted history. This helper only proves the frozen quorum lineage and
/// signatures.
pub fn verify_seal_conclusion_set_quorum_chain(
    set: &SealConclusionSet,
    realm_id: &RealmId,
    trusted_configuration_ref: &EventId,
    trusted_configuration: &NotaryValue,
) -> Result<NotaryValue> {
    set.validate_structural()?;
    trusted_configuration.validate()?;
    let mut current_ref = trusted_configuration_ref.clone();
    let mut current = trusted_configuration.clone();
    for handoff in &set.configuration_handoffs {
        if &handoff.statement.realm_id != realm_id
            || handoff.statement.configuration_ref != current_ref
        {
            return Err(WireError::Protocol(
                "Seal configuration handoff is not the next trusted Realm configuration".to_owned(),
            ));
        }
        verify_seal_configuration_handoff_quorum_signatures(handoff, &current)?;
        current_ref = handoff.statement.next_configuration_ref.clone();
        current = handoff.statement.next_configuration.clone();
    }
    for conclusion in &set.conclusions {
        if &conclusion.statement.realm_id != realm_id
            || conclusion.statement.configuration_ref != current_ref
        {
            return Err(WireError::Protocol(
                "Seal conclusion is not signed by the terminal trusted configuration".to_owned(),
            ));
        }
        verify_seal_conclusion_quorum_signatures(conclusion, &current)?;
    }
    Ok(current)
}
