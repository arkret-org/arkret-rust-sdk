//! Frozen-configuration signature verification for Seal conclusions.

use arkret_wire::{
    EventId, NotaryValue, PayloadSigner, RealmId, Result, SealConclusionCertificate,
    SealConclusionSet, SealConclusionStatement, SealConfigurationHandoffCertificate,
    SealConfigurationHandoffStatement, SealSignature, WireError,
};

use crate::verify_frozen_notary_detached_jws;

pub fn sign_seal_conclusion<S: PayloadSigner + ?Sized>(
    statement: SealConclusionStatement,
    signer: &S,
) -> Result<SealConclusionCertificate> {
    let payload = statement.signing_payload_bytes()?;
    let signature = sign_fixed_sha256_payload(&payload, signer)?;
    let certificate = SealConclusionCertificate {
        statement,
        signature,
    };
    certificate.validate_structural()?;
    Ok(certificate)
}

pub fn sign_seal_configuration_handoff<S: PayloadSigner + ?Sized>(
    statement: SealConfigurationHandoffStatement,
    signer: &S,
) -> Result<SealConfigurationHandoffCertificate> {
    let payload = statement.signing_payload_bytes()?;
    let signature = sign_fixed_sha256_payload(&payload, signer)?;
    let certificate = SealConfigurationHandoffCertificate {
        statement,
        signature,
    };
    certificate.validate_structural()?;
    Ok(certificate)
}

fn sign_fixed_sha256_payload<S: PayloadSigner + ?Sized>(
    payload: &[u8],
    signer: &S,
) -> Result<SealSignature> {
    signer
        .sign_notary_payload_with_digest_suite(payload, arkret_canonical::DigestSuite::Sha256)
        .map(SealSignature::from)
}

pub fn verify_seal_conclusion_signature(
    certificate: &SealConclusionCertificate,
    configuration: &NotaryValue,
) -> Result<()> {
    certificate.validate_authority_with(configuration, |signature, descriptor, payload| {
        verify_frozen_notary_detached_jws(signature, descriptor, payload)
    })
}

pub fn verify_seal_configuration_handoff_signature(
    certificate: &SealConfigurationHandoffCertificate,
    old_configuration: &NotaryValue,
) -> Result<()> {
    certificate.validate_authority_with(old_configuration, |signature, descriptor, payload| {
        verify_frozen_notary_detached_jws(signature, descriptor, payload)
    })
}

/// Verifies the certificate chain from an independently trusted configuration.
///
/// Callers still bind the exact queries, validate registered Cell semantics,
/// enforce current disclosure/action authorization, and reject conflicts with
/// durable trusted state. The authority attests the target's confirmed ancestry;
/// a consumer does not replay the historical state machine.
pub fn verify_seal_conclusion_set_authority_chain(
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
        verify_seal_configuration_handoff_signature(handoff, &current)?;
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
        verify_seal_conclusion_signature(conclusion, &current)?;
    }
    Ok(current)
}

/// Authenticated partial facts, deliberately not a state-machine checkpoint.
/// There is no deserialization or voting/GC conversion for this type.
#[derive(Clone, Debug)]
pub struct VerifiedSealConclusionFacts {
    realm_id: RealmId,
    certificates: Vec<SealConclusionCertificate>,
}

impl VerifiedSealConclusionFacts {
    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    pub fn result(
        &self,
        target: &arkret_wire::SealId,
        selector: &arkret_wire::SealConclusionSelector,
    ) -> Option<&arkret_wire::SealConclusionOutcome> {
        self.certificates
            .iter()
            .filter(|certificate| &certificate.statement.target_seal_ref == target)
            .flat_map(|certificate| &certificate.statement.results)
            .find(|result| &result.selector() == selector)
    }

    /// Retain these certificates atomically with the consuming local result.
    pub fn certificates(&self) -> &[SealConclusionCertificate] {
        &self.certificates
    }
}

/// Authenticate every requested fact without replaying unrelated history.
///
/// `required_queries` must be derived locally from the registered operation,
/// never copied from an untrusted sparse response. `validate_fact` enforces
/// registered Cell/value semantics and rejects known conflicting durable facts.
/// Current read/action authorization remains a per-delivery caller obligation.
pub fn verify_seal_conclusion_facts<F>(
    set: &SealConclusionSet,
    realm_id: &RealmId,
    trusted_configuration_ref: &EventId,
    trusted_configuration: &NotaryValue,
    required_queries: &[arkret_wire::SealConclusionQuery],
    mut validate_fact: F,
) -> Result<VerifiedSealConclusionFacts>
where
    F: FnMut(&arkret_wire::SealId, &arkret_wire::SealConclusionOutcome) -> Result<()>,
{
    if required_queries.is_empty()
        || required_queries.len() > arkret_wire::MAX_SEAL_CONCLUSION_QUERIES
    {
        return Err(WireError::Protocol(
            "fact consumption requires 1..=128 exact queries".to_owned(),
        ));
    }
    verify_seal_conclusion_set_authority_chain(
        set,
        realm_id,
        trusted_configuration_ref,
        trusted_configuration,
    )?;
    if set.conclusions.len() != required_queries.len() {
        return Err(WireError::Protocol(
            "conclusion set does not cover every-and-only required queries".to_owned(),
        ));
    }
    let mut matched = std::collections::BTreeSet::new();
    let mut facts = std::collections::BTreeMap::new();
    for query in required_queries {
        query.validate_structural()?;
        let index = set
            .conclusions
            .iter()
            .position(|certificate| certificate.statement.matches_query(query))
            .ok_or_else(|| {
                WireError::Protocol("required conclusion query is missing".to_owned())
            })?;
        if !matched.insert(index) {
            return Err(WireError::Protocol(
                "a certificate cannot account for duplicate queries".to_owned(),
            ));
        }
        for result in &set.conclusions[index].statement.results {
            let key = (
                query.target_seal_ref.clone(),
                arkret_canonical::canonical_json_bytes(&result.selector())?,
            );
            let value = arkret_canonical::canonical_json_bytes(result)?;
            if facts
                .insert(key, value.clone())
                .is_some_and(|previous| previous != value)
            {
                return Err(WireError::Protocol(
                    "authority conclusions contradict at the same target and selector".to_owned(),
                ));
            }
            validate_fact(&query.target_seal_ref, result)?;
        }
    }
    Ok(VerifiedSealConclusionFacts {
        realm_id: realm_id.clone(),
        certificates: set.conclusions.clone(),
    })
}

#[cfg(test)]
mod tests;
