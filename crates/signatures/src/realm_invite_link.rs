//! Possession proofs for client-generated Realm invite credentials.

use arkret_models_collaboration::governance::realm_invite_link::{
    RealmInviteLinkProof, RealmInviteLinkProofAlgorithm, RealmInviteLinkSecret,
    realm_invite_link_proof_bytes,
};
use arkret_wire::{AccountId, Hash, RealmId, RealmInviteLinkId, RequestId};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// Only the public key is published in the creation Event.
pub fn realm_invite_link_public_key(secret: &RealmInviteLinkSecret) -> String {
    arkret_canonical::base64url_encode(
        SigningKey::from_bytes(secret.seed_bytes())
            .verifying_key()
            .as_bytes(),
    )
}

/// Reject noncanonical encodings, invalid points and weak invitation keys.
pub fn validate_realm_invite_link_public_key(public_key: &str) -> arkret_wire::Result<()> {
    public_key_value(public_key).map(|_| ())
}

fn public_key_value(public_key: &str) -> arkret_wire::Result<VerifyingKey> {
    let invalid =
        || arkret_wire::WireError::Protocol("invalid Realm invite link public key".into());
    let bytes = arkret_canonical::base64url_decode(public_key).map_err(|_| invalid())?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| invalid())?;
    if arkret_canonical::base64url_encode(bytes) != public_key {
        return Err(invalid());
    }
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid())?;
    if key.is_weak() {
        return Err(invalid());
    }
    Ok(key)
}

/// Sign either the acceptance or the independently scoped preview transcript locally.
pub fn sign_realm_invite_link_proof(
    secret: &RealmInviteLinkSecret,
    realm_id: &RealmId,
    link_id: &RealmInviteLinkId,
    account: &AccountId,
    request: &RequestId,
    accepting: bool,
) -> arkret_wire::Result<RealmInviteLinkProof> {
    let bytes = realm_invite_link_proof_bytes(realm_id, link_id, account, request, accepting)?;
    let signature = SigningKey::from_bytes(secret.seed_bytes()).sign(&bytes);
    Ok(RealmInviteLinkProof {
        signature_algorithm: RealmInviteLinkProofAlgorithm::Ed25519,
        transcript_digest: Hash::new(arkret_canonical::sha256_digest(&bytes))?,
        signature: arkret_canonical::base64url_encode(signature.to_bytes()),
    })
}

/// The caller must obtain the public key from the accepted creation source at the governing cut.
pub fn verify_realm_invite_link_proof(
    public_key: &str,
    proof: &RealmInviteLinkProof,
    realm_id: &RealmId,
    link_id: &RealmInviteLinkId,
    account: &AccountId,
    request: &RequestId,
    accepting: bool,
) -> arkret_wire::Result<()> {
    let invalid =
        || arkret_wire::WireError::Protocol("invalid Realm invite link possession proof".into());
    let bytes = realm_invite_link_proof_bytes(realm_id, link_id, account, request, accepting)?;
    proof.validate_transcript(&bytes)?;
    let key = public_key_value(public_key)?;
    let signature = arkret_canonical::base64url_decode(&proof.signature).map_err(|_| invalid())?;
    let signature = ed25519_dalek::Signature::from_slice(&signature).map_err(|_| invalid())?;
    key.verify_strict(&bytes, &signature).map_err(|_| invalid())
}
