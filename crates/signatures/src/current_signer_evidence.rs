//! Origin-Station signature for request-bound current signer evidence.

use arkret_models_collaboration::{
    CurrentSignerEvidenceQueryOutcome, CurrentSignerEvidenceResponseCore,
};
use arkret_wire::{Base64UrlString, Did, DidUrl, ProtocolSignature, WireError};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

pub fn sign_current_signer_evidence_outcome(
    response: CurrentSignerEvidenceResponseCore,
    verification_method: DidUrl,
    signing_key: &SigningKey,
) -> arkret_wire::Result<CurrentSignerEvidenceQueryOutcome> {
    let created_at = response.issued_at;
    let mut outcome = CurrentSignerEvidenceQueryOutcome {
        response,
        proof: ProtocolSignature {
            verification_method,
            created_at,
            jws: Base64UrlString::new("AA".to_owned())
                .map_err(|error| WireError::Protocol(error.to_owned()))?,
        },
    };
    outcome.proof.jws = Base64UrlString::new(arkret_canonical::base64url_encode(
        signing_key.sign(&outcome.proof_signing_bytes()?).to_bytes(),
    ))
    .map_err(|error| WireError::Protocol(error.to_owned()))?;
    Ok(outcome)
}

pub fn verify_current_signer_evidence_outcome(
    outcome: &CurrentSignerEvidenceQueryOutcome,
    issuer_key: &VerifyingKey,
    now: DateTime<Utc>,
) -> arkret_wire::Result<()> {
    let did_text = outcome
        .proof
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(did, _)| did)
        .ok_or_else(|| WireError::Protocol("evidence proof method has no fragment".to_owned()))?;
    let did = Did::new(did_text.to_owned())?;
    if arkret_wire::project_did_to_core_id(&did)? != outcome.response.issuer_id {
        return Err(WireError::Protocol(
            "current signer evidence proof controller is not issuer_id".to_owned(),
        ));
    }
    if outcome.proof.created_at != outcome.response.issued_at || now >= outcome.response.expires_at
    {
        return Err(WireError::Protocol(
            "current signer evidence proof is outside its signed window".to_owned(),
        ));
    }
    let signature = Signature::from_slice(&arkret_canonical::base64url_decode(
        outcome.proof.jws.as_str(),
    )?)
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    issuer_key
        .verify(&outcome.proof_signing_bytes()?, &signature)
        .map_err(|_| WireError::Protocol("current signer evidence signature is invalid".to_owned()))
}
