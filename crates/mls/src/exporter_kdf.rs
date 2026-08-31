//! Byte-exact RFC 9420 exporter helpers shared by clients and conformance KATs.

use arkret_wire::RealmId;
use zeroize::Zeroizing;

use crate::{MlsError as Error, Result};

const MLS_HASH_LEN: usize = arkret_crypto::mls_exporter::MLS_HASH_LEN;

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
    verified_sender_domain: &[u8],
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let history_secret = mls_exporter_from_secret(
        exporter_secret,
        arkret_wire::ExporterLabelId::HISTORY_V1,
        realm_id.as_str().as_bytes(),
        MLS_HASH_LEN,
    )?;
    derive_signal_key_from_history_secret(&history_secret, verified_sender_domain, key_len)
}

pub(crate) fn derive_signal_key_from_history_secret(
    history_secret: &[u8],
    verified_sender_domain: &[u8],
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if verified_sender_domain.is_empty() {
        return Err(Error::Protocol(
            "signal sender domain must not be empty".to_owned(),
        ));
    }
    expand_with_label(
        history_secret,
        arkret_wire::ExporterLabelId::SIGNAL_V1,
        verified_sender_domain,
        key_len,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn fixture_case(name: &str) -> Value {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/arkret-private-kdf-fixture.json",
        )
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
        let sender_domain = case["input"]["verified_sender_domain_utf8"]
            .as_str()
            .unwrap()
            .as_bytes();
        let key_len = usize::try_from(case["input"]["aead_nk"].as_u64().unwrap()).unwrap();

        let signal =
            derive_signal_exporter_key(&secret, &realm_id, sender_domain, key_len).unwrap();

        assert_eq!(
            hex(&signal),
            case["expected"]["signal_key_hex"].as_str().unwrap()
        );
    }
}
