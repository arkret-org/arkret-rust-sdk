//! Arkret v1 KeyPackage application-capability registry surface.

use std::sync::OnceLock;

use regex::Regex;

pub const ARKRET_CONTENT_V1: &str = "ak.content.v1";
pub const MIMI_CONTENT_V1: &str = "mimi.content.v1";
pub const ACTIVE_KEYPACKAGE_CAPABILITIES: &[&str] = &[ARKRET_CONTENT_V1, MIMI_CONTENT_V1];
pub const REQUIRED_ARKRET_GROUP_CAPABILITIES: &[&str] = &[ARKRET_CONTENT_V1];

pub const MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE: u16 = 0xF1C1;
pub const MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE: u16 = 0xF1C2;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyPackageCapabilityError {
    #[error("KeyPackage capability identifiers must match the v1 registered identifier shape")]
    InvalidIdentifier,
    #[error("KeyPackage capabilities must be UTF-8 byte-lexicographically sorted and unique")]
    NonCanonicalOrder,
    #[error("required KeyPackage capabilities must be active registered values")]
    UnsupportedRequiredCapability,
    #[error("required KeyPackage capabilities are not a subset of advertised capabilities")]
    MissingRequiredCapability,
    #[error("KeyPackage capability extension is not deterministic CBOR")]
    InvalidExtensionEncoding,
}

pub fn is_well_formed_keypackage_capability(value: &str) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN
        .get_or_init(|| {
            Regex::new(r"^(?:ak|[a-z][a-z0-9-]{0,31})(?:\.[a-z][a-z0-9_-]{0,63})+\.v1$")
                .expect("KeyPackage capability regex is valid")
        })
        .is_match(value)
        && value.len() <= 128
}

pub fn is_active_keypackage_capability(value: &str) -> bool {
    ACTIVE_KEYPACKAGE_CAPABILITIES.contains(&value)
}

pub fn validate_advertised_keypackage_capabilities(
    capabilities: &[&str],
) -> Result<(), KeyPackageCapabilityError> {
    if capabilities.is_empty()
        || capabilities.len() > 64
        || capabilities
            .iter()
            .any(|value| !is_well_formed_keypackage_capability(value))
    {
        return Err(KeyPackageCapabilityError::InvalidIdentifier);
    }
    if capabilities
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(KeyPackageCapabilityError::NonCanonicalOrder);
    }
    Ok(())
}

pub fn validate_required_keypackage_capabilities(
    required: &[&str],
    advertised: &[&str],
) -> Result<(), KeyPackageCapabilityError> {
    validate_advertised_keypackage_capabilities(required)?;
    validate_advertised_keypackage_capabilities(advertised)?;
    if required
        .iter()
        .any(|value| !is_active_keypackage_capability(value))
    {
        return Err(KeyPackageCapabilityError::UnsupportedRequiredCapability);
    }
    if required.iter().any(|value| !advertised.contains(value)) {
        return Err(KeyPackageCapabilityError::MissingRequiredCapability);
    }
    Ok(())
}

pub fn encode_keypackage_capability_extension(
    capabilities: &[&str],
) -> Result<Vec<u8>, KeyPackageCapabilityError> {
    validate_advertised_keypackage_capabilities(capabilities)?;
    if capabilities.len() > 64 {
        return Err(KeyPackageCapabilityError::InvalidExtensionEncoding);
    }
    let mut encoded = Vec::new();
    encode_cbor_head(4, capabilities.len() as u64, &mut encoded);
    for capability in capabilities {
        encode_cbor_head(3, capability.len() as u64, &mut encoded);
        encoded.extend_from_slice(capability.as_bytes());
    }
    Ok(encoded)
}

pub fn decode_keypackage_capability_extension(
    encoded: &[u8],
) -> Result<Vec<String>, KeyPackageCapabilityError> {
    let mut offset = 0;
    let count = decode_cbor_head(encoded, &mut offset, 4)?;
    if !(1..=64).contains(&count) {
        return Err(KeyPackageCapabilityError::InvalidExtensionEncoding);
    }
    let mut capabilities = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let length = decode_cbor_head(encoded, &mut offset, 3)?;
        let length = usize::try_from(length)
            .map_err(|_| KeyPackageCapabilityError::InvalidExtensionEncoding)?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= encoded.len())
            .ok_or(KeyPackageCapabilityError::InvalidExtensionEncoding)?;
        let capability = std::str::from_utf8(&encoded[offset..end])
            .map_err(|_| KeyPackageCapabilityError::InvalidExtensionEncoding)?
            .to_owned();
        capabilities.push(capability);
        offset = end;
    }
    if offset != encoded.len() {
        return Err(KeyPackageCapabilityError::InvalidExtensionEncoding);
    }
    let borrowed = capabilities.iter().map(String::as_str).collect::<Vec<_>>();
    validate_advertised_keypackage_capabilities(&borrowed)?;
    if encode_keypackage_capability_extension(&borrowed)? != encoded {
        return Err(KeyPackageCapabilityError::InvalidExtensionEncoding);
    }
    Ok(capabilities)
}

fn encode_cbor_head(major: u8, value: u64, encoded: &mut Vec<u8>) {
    let major = major << 5;
    match value {
        0..=23 => encoded.push(major | value as u8),
        24..=0xff => encoded.extend_from_slice(&[major | 24, value as u8]),
        0x100..=0xffff => {
            encoded.push(major | 25);
            encoded.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            encoded.push(major | 26);
            encoded.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            encoded.push(major | 27);
            encoded.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decode_cbor_head(
    encoded: &[u8],
    offset: &mut usize,
    expected_major: u8,
) -> Result<u64, KeyPackageCapabilityError> {
    let first = *encoded
        .get(*offset)
        .ok_or(KeyPackageCapabilityError::InvalidExtensionEncoding)?;
    *offset += 1;
    if first >> 5 != expected_major {
        return Err(KeyPackageCapabilityError::InvalidExtensionEncoding);
    }
    let additional = first & 0x1f;
    let (value, width) = match additional {
        value @ 0..=23 => (u64::from(value), 0),
        24 => (read_uint(encoded, offset, 1)?, 1),
        25 => (read_uint(encoded, offset, 2)?, 2),
        26 => (read_uint(encoded, offset, 4)?, 4),
        27 => (read_uint(encoded, offset, 8)?, 8),
        _ => return Err(KeyPackageCapabilityError::InvalidExtensionEncoding),
    };
    let canonical = match width {
        0 => value <= 23,
        1 => (24..=0xff).contains(&value),
        2 => (0x100..=0xffff).contains(&value),
        4 => (0x1_0000..=0xffff_ffff).contains(&value),
        8 => value > 0xffff_ffff,
        _ => false,
    };
    if !canonical {
        return Err(KeyPackageCapabilityError::InvalidExtensionEncoding);
    }
    Ok(value)
}

fn read_uint(
    encoded: &[u8],
    offset: &mut usize,
    width: usize,
) -> Result<u64, KeyPackageCapabilityError> {
    let end = offset
        .checked_add(width)
        .filter(|end| *end <= encoded.len())
        .ok_or(KeyPackageCapabilityError::InvalidExtensionEncoding)?;
    let mut value = 0u64;
    for byte in &encoded[*offset..end] {
        value = (value << 8) | u64::from(*byte);
    }
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_registry_preserves_well_formed_unknown_but_never_requires_it() {
        let advertised = [ARKRET_CONTENT_V1, "example.content.v1"];
        assert!(validate_advertised_keypackage_capabilities(&advertised).is_ok());
        assert_eq!(
            validate_required_keypackage_capabilities(&["example.content.v1"], &advertised),
            Err(KeyPackageCapabilityError::UnsupportedRequiredCapability)
        );
    }

    #[test]
    fn canonical_order_and_subset_are_enforced() {
        assert_eq!(
            validate_advertised_keypackage_capabilities(&[MIMI_CONTENT_V1, ARKRET_CONTENT_V1]),
            Err(KeyPackageCapabilityError::NonCanonicalOrder)
        );
        let oversized = (0..65)
            .map(|index| format!("example.content_{index:02}.v1"))
            .collect::<Vec<_>>();
        let oversized = oversized.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            validate_advertised_keypackage_capabilities(&oversized),
            Err(KeyPackageCapabilityError::InvalidIdentifier)
        );
        assert_eq!(
            validate_required_keypackage_capabilities(
                &[ARKRET_CONTENT_V1, MIMI_CONTENT_V1],
                &[ARKRET_CONTENT_V1],
            ),
            Err(KeyPackageCapabilityError::MissingRequiredCapability)
        );
    }

    #[test]
    fn deterministic_cbor_round_trip_rejects_noncanonical_forms() {
        let encoded =
            encode_keypackage_capability_extension(&[ARKRET_CONTENT_V1, MIMI_CONTENT_V1]).unwrap();
        assert_eq!(
            decode_keypackage_capability_extension(&encoded).unwrap(),
            [ARKRET_CONTENT_V1.to_owned(), MIMI_CONTENT_V1.to_owned()]
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_keypackage_capability_extension(&trailing),
            Err(KeyPackageCapabilityError::InvalidExtensionEncoding)
        );
        assert_eq!(
            decode_keypackage_capability_extension(&[0x9f, 0xff]),
            Err(KeyPackageCapabilityError::InvalidExtensionEncoding)
        );
    }
}
