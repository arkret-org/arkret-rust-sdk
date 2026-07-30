//! Byte-exact RFC 9420 exporter helpers shared by clients and conformance KATs.

use arkret_crypto::{
    AEAD_NONCE_EXPORTER_LABEL, AeadNonceContext, aead_nonce_prefix_len,
    aead_sender_nonce_context_bytes,
};
use arkret_wire::{Did, RealmId};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::group::mls_kdf_label;
use crate::{MlsError as Error, Result};

const MLS_EXPORTED_LABEL: &str = "exported";
const MLS_HASH_LEN: usize = 32;
pub const MENTION_ROUTING_EXPORTER_LABEL: &str = "arkret-mention-routing-v1";

fn expand_with_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| Error::Crypto("MLS exporter secret is too short".to_owned()))?;
    let info = mls_kdf_label(length, label, context)?;
    let mut output = Zeroizing::new(vec![0u8; length]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| Error::Crypto("MLS ExpandWithLabel failed".to_owned()))?;
    Ok(output)
}

/// Evaluate RFC 9420 `MLS-Exporter` from an epoch exporter secret.
pub fn mls_exporter_from_secret(
    exporter_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if exporter_secret.len() < MLS_HASH_LEN || label.is_empty() || length == 0 {
        return Err(Error::Crypto(
            "MLS exporter requires a 32-byte secret, non-empty label, and output".to_owned(),
        ));
    }
    let derived = expand_with_label(exporter_secret, label, &[], MLS_HASH_LEN)?;
    let context_hash = Sha256::digest(context);
    expand_with_label(&derived, MLS_EXPORTED_LABEL, &context_hash, length)
}

pub fn derive_signal_exporter_key(
    exporter_secret: &[u8],
    realm_id: &RealmId,
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let history_secret = mls_exporter_from_secret(
        exporter_secret,
        arkret_wire::ExporterLabelId::HISTORY_V1,
        realm_id.as_str().as_bytes(),
        MLS_HASH_LEN,
    )?;
    expand_with_label(
        &history_secret,
        arkret_wire::ExporterLabelId::SIGNAL_V1,
        &[],
        key_len,
    )
}

pub fn derive_sender_nonce_prefix(
    exporter_secret: &[u8],
    context: &AeadNonceContext,
    nonce_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let context = aead_sender_nonce_context_bytes(context)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    let prefix_len =
        aead_nonce_prefix_len(nonce_len).map_err(|error| Error::Crypto(error.to_string()))?;
    mls_exporter_from_secret(
        exporter_secret,
        AEAD_NONCE_EXPORTER_LABEL,
        &context,
        prefix_len,
    )
}

pub fn derive_mention_routing_key(
    exporter_secret: &[u8],
    realm_id: &RealmId,
) -> Result<Zeroizing<Vec<u8>>> {
    mls_exporter_from_secret(
        exporter_secret,
        MENTION_ROUTING_EXPORTER_LABEL,
        realm_id.as_str().as_bytes(),
        MLS_HASH_LEN,
    )
}

pub fn mention_routing_hmac(
    exporter_secret: &[u8],
    realm_id: &RealmId,
    mentioned_did: &Did,
) -> Result<[u8; MLS_HASH_LEN]> {
    let key = derive_mention_routing_key(exporter_secret, realm_id)?;
    mention_routing_hmac_from_key(&key, mentioned_did)
}

pub fn mention_routing_hmac_from_key(
    routing_key: &[u8],
    mentioned_did: &Did,
) -> Result<[u8; MLS_HASH_LEN]> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(routing_key)
        .map_err(|_| Error::Crypto("mention routing HMAC key is invalid".to_owned()))?;
    mac.update(mentioned_did.as_str().as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn registered_private_kdf_vectors_match_byte_for_byte() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/arkret-private-kdf-fixture.json")
                .unwrap();
        let secret = (0u8..32).collect::<Vec<_>>();
        let realm_id = RealmId::new("ak:realm:019a7360-0000-7000-8000-000000000000").unwrap();

        let signal = derive_signal_exporter_key(&secret, &realm_id, 16).unwrap();
        assert_eq!(
            hex(&signal),
            fixture["cases"][2]["expected"]["signal_key_hex"]
                .as_str()
                .unwrap()
        );

        let mention_key = derive_mention_routing_key(&secret, &realm_id).unwrap();
        assert_eq!(
            hex(&mention_key),
            fixture["cases"][4]["expected"]["routing_hmac_key_hex"]
                .as_str()
                .unwrap()
        );
        let did = Did::new("did:webvh:z6MkhAlice:example.com").unwrap();
        assert_eq!(
            hex(&mention_routing_hmac(&secret, &realm_id, &did).unwrap()),
            fixture["cases"][4]["expected"]["routing_tag_hex"]
                .as_str()
                .unwrap()
        );
    }
}
