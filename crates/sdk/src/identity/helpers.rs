use super::*;

pub(super) fn split_domain_handle(handle: &str) -> Result<(String, String)> {
    let normalized = normalize_handle(handle);
    let Some((local, domain)) = normalized.split_once('@') else {
        return Err(Error::Protocol("handle proof requires local@domain form".to_owned()));
    };
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || local.contains('/')
        || domain.contains('/')
        || domain.contains("..")
    {
        return Err(Error::Protocol("invalid domain handle".to_owned()));
    }
    Ok((local.to_owned(), domain.to_owned()))
}

pub(super) fn normalize_handle(handle: &str) -> String {
    handle.trim().trim_start_matches('@').to_lowercase()
}

pub(super) fn did_web_document_url(did: &Did) -> Option<String> {
    if did.method() != "web" {
        return None;
    }
    let method_id = did.as_str().strip_prefix("did:web:")?;
    if method_id.is_empty() || method_id.contains("//") || method_id.contains('?') {
        return None;
    }
    let parts = method_id.split(':').collect::<Vec<_>>();
    let host = parts.first()?;
    if host.is_empty() || !host.contains('.') || host.contains('/') {
        return None;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
    {
        return None;
    }
    if parts.len() == 1 {
        return Some(format!("https://{host}/.well-known/did.json"));
    }
    if parts[1..].iter().any(|part| part.is_empty() || part.contains('/') || part.contains("..")) {
        return None;
    }
    Some(format!("https://{host}/{}/did.json", parts[1..].join("/")))
}

pub(super) fn is_allowed_did_web_content_type(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    matches!(media_type.as_str(), "application/did+json" | "application/json")
}

pub(super) fn did_webvh_parts(did: &Did) -> Option<(String, String, Option<u16>, Vec<String>)> {
    let method_id = did.as_str().strip_prefix("did:webvh:")?;
    let mut parts = method_id.split(':');
    let scid = parts.next()?.to_owned();
    if scid.is_empty() {
        return None;
    }
    let host_raw = parts.next()?;
    if host_raw.is_empty() {
        return None;
    }
    let (host, port) = if let Some(idx) = host_raw.find("%3A").or_else(|| host_raw.find("%3a")) {
        let host = host_raw[..idx].to_owned();
        let port_str = &host_raw[idx + 3..];
        let port = port_str.parse::<u16>().ok()?;
        (host, Some(port))
    } else {
        (host_raw.to_owned(), None)
    };
    let path = parts.map(ToOwned::to_owned).collect::<Vec<_>>();
    if path
        .iter()
        .any(|segment| segment.is_empty() || segment.contains('/') || segment.contains(".."))
    {
        return None;
    }
    Some((scid, host, port, path))
}

pub(super) fn did_webvh_scid(did: &Did) -> Option<String> {
    did_webvh_parts(did).map(|(scid, _, _, _)| scid)
}

pub(super) fn did_webvh_document_url(did: &Did) -> Option<String> {
    did_webvh_url(did, "did.json")
}

pub(super) fn did_webvh_log_url(did: &Did) -> Option<String> {
    did_webvh_url(did, "did.jsonl")
}

pub(super) fn did_webvh_url(did: &Did, leaf: &str) -> Option<String> {
    let (_, host, port, path) = did_webvh_parts(did)?;
    if !host.contains('.') {
        return None;
    }
    let authority = match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    if path.is_empty() {
        Some(format!("https://{authority}/.well-known/{leaf}"))
    } else {
        Some(format!("https://{authority}/{}/{leaf}", path.join("/")))
    }
}

pub(super) fn did_key_material(did: &Did) -> Option<String> {
    let method_id = did.as_str().strip_prefix("did:key:")?;
    let encoded = method_id.strip_prefix('z')?;
    let decoded = decode_base58btc(encoded)?;
    if !is_supported_did_key_multicodec(&decoded) {
        return None;
    }
    Some(method_id.to_owned())
}

pub(super) fn decode_base58btc(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }
    let mut output = Vec::<u8>::new();
    for byte in input.bytes() {
        let mut carry = base58btc_value(byte)?;
        for item in output.iter_mut().rev() {
            let value = u32::from(*item) * 58 + carry;
            *item = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            output.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading_zeroes = input.bytes().take_while(|byte| *byte == b'1').count();
    for _ in 0..leading_zeroes {
        output.insert(0, 0);
    }
    Some(output)
}

pub(super) fn base58btc_value(byte: u8) -> Option<u32> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    ALPHABET.iter().position(|candidate| *candidate == byte).map(|index| index as u32)
}

pub(super) fn is_supported_did_key_multicodec(bytes: &[u8]) -> bool {
    let Some((code, offset)) = decode_multicodec_varint(bytes) else {
        return false;
    };
    let key = &bytes[offset..];
    match code {
        0xec | 0xed => key.len() == 32,           // X25519-pub / Ed25519-pub
        0xe7 | 0x1200 => key.len() == 33,         // secp256k1-pub / P-256-pub
        0x1201 => key.len() == 49,                // P-384-pub
        0x1202 => (66..=67).contains(&key.len()), // P-521-pub
        0x1205 => key.len() >= 64,                // RSA-pub
        _ => false,
    }
}

pub(super) fn decode_multicodec_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

pub(super) fn operation_payload(operation: &DidKeyLogOperation) -> String {
    match operation {
        DidKeyLogOperation::Inception { verification_keys, recovery_keys } => {
            format!(
                "inception|{}|{}",
                key_set_payload(verification_keys),
                key_set_payload(recovery_keys)
            )
        }
        DidKeyLogOperation::Rotate { verification_keys } => {
            format!("rotate|{}", key_set_payload(verification_keys))
        }
        DidKeyLogOperation::Recover { verification_keys, recovery_keys } => {
            format!(
                "recover|{}|{}",
                key_set_payload(verification_keys),
                key_set_payload(recovery_keys)
            )
        }
        DidKeyLogOperation::Deactivate => "deactivate".to_owned(),
    }
}

pub(super) fn key_set_payload(keys: &BTreeMap<String, String>) -> String {
    keys.iter().map(|(id, key)| format!("{id}={key}")).collect::<Vec<_>>().join(",")
}

pub(super) fn ensure_key_set(name: &str, keys: &BTreeMap<String, String>) -> Result<()> {
    if keys.is_empty() {
        return Err(Error::Protocol(format!("{name} key set is empty")));
    }
    if keys.iter().any(|(id, key)| id.trim().is_empty() || key.trim().is_empty()) {
        return Err(Error::Protocol(format!("{name} key set has an empty key")));
    }
    Ok(())
}

pub(super) fn ensure_active(state: &VerifiedDidKeyLog) -> Result<()> {
    if state.deactivated {
        return Err(Error::Protocol("DID is deactivated".to_owned()));
    }
    Ok(())
}

pub(super) fn verify_did_key_log_proof(
    entry: &DidKeyLogEntry,
    signer_public_key: &str,
) -> Result<()> {
    let expected = did_key_log_proof(
        entry.sequence,
        &entry.did,
        entry.previous_hash.as_deref(),
        &entry.operation,
        &entry.signer,
        entry.created_at,
        signer_public_key,
    );
    if entry.proof != expected {
        return Err(Error::Protocol("invalid DID key log proof".to_owned()));
    }
    Ok(())
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
