use crate::{CapabilityActionId, DomainSeparationId};

pub const PROTOCOL_VERSION: &str = "1.0";

/// Classify a protocol-family bootstrap discriminator before a v1-specific
/// response is interpreted.
pub fn protocol_version_bootstrap_error(value: &str) -> Option<crate::ErrorCode> {
    if value == PROTOCOL_VERSION {
        return None;
    }
    if is_canonical_protocol_version(value) {
        Some(crate::ErrorCode::UnsupportedProtocolVersion)
    } else {
        Some(crate::ErrorCode::SchemaViolation)
    }
}

/// Shared serde bootstrap gate for every public typed carrier that exposes a
/// protocol-family discriminator. Keeping this in `arkret-wire` prevents a
/// new DTO from silently interpreting v1 fields before version selection.
pub fn deserialize_protocol_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    if let Some(code) = protocol_version_bootstrap_error(&value) {
        return Err(serde::de::Error::custom(format!(
            "{}: protocol_version {value} does not match Arkret {PROTOCOL_VERSION}",
            code.as_str()
        )));
    }
    Ok(value)
}

fn is_canonical_protocol_version(value: &str) -> bool {
    let Some((major, minor)) = value.split_once('.') else {
        return false;
    };
    !minor.contains('.') && canonical_decimal(major) && canonical_decimal(minor)
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

pub const BUILT_IN_CONFORMANCE_FIXTURES_VERSION: &str = "arkret-sdk-builtin-v1";

/// AEAD profile id used by every Arkret payload envelope that seals with
/// XChaCha20-Poly1305 (account data, key vaults, file transfer).
pub const AEAD_PROFILE_XCHACHA20_POLY1305_V1: &str = crate::AeadProfileId::XCHACHA20_POLY1305_V1;
/// HPKE suite id (RFC 9180 base mode) used by secret share, key backup, and
/// file-transfer key envelopes.
pub const HPKE_SUITE_X25519_CHACHA20POLY1305_V1: &str =
    crate::HpkeSuiteId::X25519_AEAD_CHACHA20POLY1305_V1;
/// Whole-file blob AEAD scheme id.
pub const BLOB_SCHEME_WHOLE_FILE_AEAD_V1: &str = "ak.blob.whole_file_aead.v1";
/// Chunked streaming blob AEAD scheme id (STREAM / OAE2).
pub const BLOB_SCHEME_STREAM_AEAD_V1: &str = "ak.blob.stream_aead.v1";
/// HPKE `info` string bound into every device-to-device secret share.
/// Wire `kind` of a device-to-device secret request.
pub const SECRET_REQUEST_KIND: &str = "ak.secret.request";
/// Wire `kind` of a sealed device-to-device secret response.
pub const SECRET_SEND_KIND: &str = "ak.secret.send";
/// `signature.type` of a signed identity recovery policy.
pub const RECOVERY_POLICY_SIGNATURE_TYPE: &str =
    DomainSeparationId::IDENTITY_RECOVERY_POLICY_SIGNATURE_V1;

/// AKP-0007 capability action list (6 actions). Useful for downstream
/// services that want to iterate the Circle-management surface.
///
/// `ak.circle.manage`, `ak.circle.member.manage`, `ak.circle.member.add.others`
/// and `ak.circle.audit` declare `required_constraints=["allowed_circle_ids"]`;
/// unconstrained Realm-wide grants for those actions MUST be rejected.
pub const CIRCLE_CAPABILITY_ACTIONS: &[&str] = &[
    CapabilityActionId::CIRCLE_CREATE,
    CapabilityActionId::CIRCLE_MANAGE,
    CapabilityActionId::CIRCLE_MEMBER_ADD,
    CapabilityActionId::CIRCLE_MEMBER_MANAGE,
    CapabilityActionId::CIRCLE_MEMBER_ADD_OTHERS,
    CapabilityActionId::CIRCLE_AUDIT,
];

/// AKP-0010 — maximum TTL bound for media tokens (600 seconds). Tokens
/// MUST be rejected when `expires_at - now > 600s`. SHOULD floor: 300s.
pub const MEDIA_TOKEN_TTL_MAX_SECS: u64 = 600;
/// AKP-0010 — SHOULD-bound (recommended) TTL for media tokens.
pub const MEDIA_TOKEN_TTL_SHOULD_SECS: u64 = 300;

/// Federation S2S HTTP message-signature headers.
/// MUST be present on every cross-trust-domain federation request and
/// MUST be included in the canonical signing transcript so a sender from
/// trust domain A cannot replay the same signed bytes into trust domain B.
pub const HEADER_SOURCE_TRUST_DOMAIN: &str = "Source-Trust-Domain";
pub const HEADER_DESTINATION_TRUST_DOMAIN: &str = "Destination-Trust-Domain";

#[cfg(test)]
mod protocol_version_tests {
    use super::*;

    #[test]
    fn bootstrap_discriminator_separates_unsupported_from_malformed() {
        assert_eq!(protocol_version_bootstrap_error("1.0"), None);
        assert_eq!(
            protocol_version_bootstrap_error("2.0"),
            Some(crate::ErrorCode::UnsupportedProtocolVersion)
        );
        for malformed in ["1", "1.0.0", "01.0", "1.00", "", "v1"] {
            assert_eq!(
                protocol_version_bootstrap_error(malformed),
                Some(crate::ErrorCode::SchemaViolation)
            );
        }
    }
}
