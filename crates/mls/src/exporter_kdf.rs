//! Byte-exact RFC 9420 exporter helpers shared by clients and conformance KATs.

use arkret_wire::{DeviceId, Did, RealmId, canonical};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{MlsError as Error, Result};

const MLS_HASH_LEN: usize = arkret_crypto::mls_exporter::MLS_HASH_LEN;
pub const MENTION_ROUTING_EXPORTER_LABEL: &str = "arkret-mention-routing-v1";

fn expand_with_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let output = arkret_crypto::mls_exporter::mls_expand_with_label(secret, label, context, length)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    Ok(Zeroizing::new(output))
}

/// Evaluate RFC 9420 `MLS-Exporter` from an epoch exporter secret.
pub fn mls_exporter_from_secret(
    exporter_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        arkret_crypto::mls_exporter::mls_exporter_from_secret(
            exporter_secret,
            label,
            context,
            length,
        )
        .map_err(|error| Error::Crypto(error.to_string()))?,
    ))
}

pub fn derive_signal_exporter_key(
    exporter_secret: &[u8],
    realm_id: &RealmId,
    sender_device_id: &DeviceId,
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let history_secret = mls_exporter_from_secret(
        exporter_secret,
        arkret_wire::ExporterLabelId::HISTORY_V1,
        realm_id.as_str().as_bytes(),
        MLS_HASH_LEN,
    )?;
    derive_signal_key_from_history_secret(&history_secret, sender_device_id, key_len)
}

pub(crate) fn derive_signal_key_from_history_secret(
    history_secret: &[u8],
    sender_device_id: &DeviceId,
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let context = canonical::canonical_json_bytes(&serde_json::json!({
        "sender_device_id": sender_device_id,
    }))?;
    expand_with_label(
        history_secret,
        arkret_wire::ExporterLabelId::SIGNAL_V1,
        &context,
        key_len,
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
    use serde_json::Value;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn fixture_case(name: &str) -> Value {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/arkret-private-kdf-fixture.json")
                .unwrap();
        fixture["cases"]
            .as_array()
            .expect("kdf fixture must carry cases")
            .iter()
            .find(|case| case["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("kdf fixture missing case {name}"))
            .clone()
    }

    fn case_exporter_secret(case: &Value) -> Vec<u8> {
        let hex = case["input"]["exporter_secret_hex"]
            .as_str()
            .expect("case must declare an exporter secret");
        (0..hex.len() / 2)
            .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn signal_exporter_key_matches_the_registered_vector() {
        let case = fixture_case("signal_exporter_key_sha256_aes128gcm");
        let secret = case_exporter_secret(&case);
        let realm_id = RealmId::new(case["input"]["realm_id_utf8"].as_str().unwrap()).unwrap();
        let sender_device_id =
            DeviceId::new(case["input"]["sender_device_id"].as_str().unwrap()).unwrap();
        let key_len = usize::try_from(case["input"]["aead_nk"].as_u64().unwrap()).unwrap();

        let signal =
            derive_signal_exporter_key(&secret, &realm_id, &sender_device_id, key_len).unwrap();

        assert_eq!(
            hex(&signal),
            case["expected"]["signal_key_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn mention_routing_hmac_matches_the_registered_vector() {
        let case = fixture_case("mention_routing_hmac_did");
        let secret = case_exporter_secret(&case);
        let realm_id = RealmId::new(case["input"]["realm_id_utf8"].as_str().unwrap()).unwrap();
        let did = Did::new(case["input"]["mentioned_did_utf8"].as_str().unwrap()).unwrap();
        assert_eq!(
            MENTION_ROUTING_EXPORTER_LABEL,
            case["input"]["exporter_label"].as_str().unwrap()
        );

        let mention_key = derive_mention_routing_key(&secret, &realm_id).unwrap();
        assert_eq!(
            hex(&mention_key),
            case["expected"]["routing_hmac_key_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex(&mention_routing_hmac(&secret, &realm_id, &did).unwrap()),
            case["expected"]["routing_tag_hex"].as_str().unwrap()
        );
    }
}
