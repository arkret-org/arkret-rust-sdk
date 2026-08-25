//! Arkret v1 Unicode and external-domain string profiles.

use precis_profiles::UsernameCaseMapped;
use precis_profiles::precis_core::profile::Profile;
use unicode_normalization::{UnicodeNormalization, is_nfc};

use crate::{Result, WireError};

pub const HANDLE_LOCALPART_MAX_CODE_POINTS: usize = 128;
pub const AGENT_SLUG_MAX_CODE_POINTS: usize = 64;
pub const DOMAIN_MAX_ASCII_OCTETS: usize = 253;

pub fn prepare_handle_localpart(input: &str) -> Result<String> {
    prepare_human_identifier(input, HANDLE_LOCALPART_MAX_CODE_POINTS)
}

pub fn validate_canonical_handle_localpart(input: &str) -> Result<()> {
    validate_canonical_human_identifier(input, HANDLE_LOCALPART_MAX_CODE_POINTS)
}

pub fn prepare_agent_slug(input: &str) -> Result<String> {
    prepare_human_identifier(input, AGENT_SLUG_MAX_CODE_POINTS)
}

pub fn validate_canonical_agent_slug(input: &str) -> Result<()> {
    validate_canonical_human_identifier(input, AGENT_SLUG_MAX_CODE_POINTS)
}

pub fn prepare_human_identifier(input: &str, max_code_points: usize) -> Result<String> {
    let prepared = UsernameCaseMapped::new()
        .enforce(input)
        .map_err(|error| {
            WireError::Protocol(format!("human identifier PRECIS failure: {error:?}"))
        })?
        .into_owned();
    validate_human_identifier_shape(&prepared, max_code_points)?;
    Ok(prepared)
}

pub fn validate_canonical_human_identifier(input: &str, max_code_points: usize) -> Result<()> {
    let prepared = prepare_human_identifier(input, max_code_points)?;
    if prepared != input {
        return Err(WireError::Protocol(
            "human identifier is not in canonical prepared form".to_owned(),
        ));
    }
    Ok(())
}

fn validate_human_identifier_shape(value: &str, max_code_points: usize) -> Result<()> {
    if value.is_empty() || value.chars().count() > max_code_points {
        return Err(WireError::Protocol(
            "human identifier length is outside the profile bounds".to_owned(),
        ));
    }
    if value.chars().any(|character| {
        character.is_whitespace()
            || character.is_control()
            || matches!(character, ':' | '@' | '/' | '#' | '?' | '\\')
            || is_bidi_format_control(character)
            || character == '\u{FEFF}'
    }) {
        return Err(WireError::Protocol(
            "human identifier contains a forbidden structural or control character".to_owned(),
        ));
    }
    Ok(())
}

pub fn prepare_idna_domain(input: &str) -> Result<String> {
    if input.is_empty() || input != input.trim() || input.ends_with('.') {
        return Err(WireError::Protocol(
            "domain is empty, padded, or has a trailing dot".to_owned(),
        ));
    }
    let ascii = idna::domain_to_ascii_strict(input)
        .map_err(|_| WireError::Protocol("domain fails the Arkret UTS #46 profile".to_owned()))?;
    if ascii.len() > DOMAIN_MAX_ASCII_OCTETS || ascii.split('.').count() < 2 {
        return Err(WireError::Protocol(
            "domain must contain at least two labels within DNS length limits".to_owned(),
        ));
    }
    let (unicode, unicode_result) = idna::domain_to_unicode(&ascii);
    unicode_result
        .map_err(|_| WireError::Protocol("domain A-label cannot be decoded safely".to_owned()))?;
    let roundtrip = idna::domain_to_ascii_strict(&unicode)
        .map_err(|_| WireError::Protocol("domain fails the U-label round trip".to_owned()))?;
    if roundtrip != ascii {
        return Err(WireError::Protocol(
            "domain A-label round trip mismatch".to_owned(),
        ));
    }
    Ok(ascii)
}

pub fn validate_canonical_idna_domain(input: &str) -> Result<()> {
    if !input.is_ascii() || input.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(WireError::Protocol(
            "canonical domain must be a lowercase ASCII A-label".to_owned(),
        ));
    }
    if prepare_idna_domain(input)? != input {
        return Err(WireError::Protocol("domain is not canonical".to_owned()));
    }
    Ok(())
}

/// Validate the canonical `<prepared-localpart>:<lowercase-A-label-domain>` wire form.
pub fn validate_canonical_handle(input: &str) -> Result<()> {
    let (localpart, domain) = input
        .split_once(':')
        .ok_or_else(|| WireError::Protocol("canonical handle must contain ':'".to_owned()))?;
    if domain.contains(':') {
        return Err(WireError::Protocol(
            "canonical handle contains more than one ':' separator".to_owned(),
        ));
    }
    validate_canonical_handle_localpart(localpart)?;
    validate_canonical_idna_domain(domain)
}

/// Validate the canonical RFC 7565 `acct:` spelling used for Arkret handle aliases.
pub fn validate_canonical_acct_uri(input: &str) -> Result<()> {
    let body = input
        .strip_prefix("acct:")
        .ok_or_else(|| WireError::Protocol("acct URI must start with 'acct:'".to_owned()))?;
    let (encoded_localpart, domain) = body
        .rsplit_once('@')
        .ok_or_else(|| WireError::Protocol("acct URI must contain '@'".to_owned()))?;
    if encoded_localpart.is_empty() || domain.contains('@') {
        return Err(WireError::Protocol(
            "acct URI must contain one non-empty localpart and one host".to_owned(),
        ));
    }
    let localpart = decode_acct_localpart(encoded_localpart)?;
    validate_canonical_handle_localpart(&localpart)?;
    validate_canonical_idna_domain(domain)
}

pub fn human_identifier_skeleton(value: &str) -> Result<String> {
    validate_canonical_handle_localpart(value)?;
    Ok(unicode_security::skeleton(value).collect())
}

pub fn validate_single_line_display_text(value: &str, max_code_points: usize) -> Result<()> {
    validate_nfc_and_code_points(value, max_code_points)?;
    if value.chars().all(char::is_whitespace)
        || value.chars().any(|character| {
            character.is_control() || is_bidi_format_control(character) || character == '\u{FEFF}'
        })
    {
        return Err(WireError::Protocol(
            "single-line display text contains only whitespace or a forbidden control".to_owned(),
        ));
    }
    Ok(())
}

/// Return the deterministic holder-local skeleton used for impersonation
/// warnings.
pub fn display_confusable_skeleton_v1(value: &str) -> Result<String> {
    validate_single_line_display_text(value, 512)?;
    let prepared: String = value
        .chars()
        .filter(|character| !is_registered_default_ignorable(*character))
        .nfkc()
        .collect();
    Ok(unicode_security::skeleton(&prepared).nfd().collect())
}

fn is_registered_default_ignorable(character: char) -> bool {
    matches!(
        character as u32,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFF0..=0xFFF8
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

pub fn validate_short_text(value: &str, max_code_points: usize) -> Result<()> {
    validate_nfc_and_code_points(value, max_code_points)?;
    if value.chars().any(|character| {
        (character.is_control() && character != '\n')
            || is_bidi_embedding_or_override(character)
            || character == '\u{FEFF}'
    }) {
        return Err(WireError::Protocol(
            "short text contains a forbidden control character".to_owned(),
        ));
    }
    Ok(())
}

/// Validate the unbounded portion of the Arkret content-text profile.
///
/// Field-specific schemas remain responsible for their own code-point and
/// UTF-8 byte limits. Empty content is allowed by the shared schema profile.
pub fn validate_content_text(value: &str) -> Result<()> {
    if !is_nfc(value)
        || value.chars().any(|character| {
            (character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
                || character == '\u{FEFF}'
        })
    {
        return Err(WireError::Protocol(
            "content text is non-NFC or contains a forbidden control character".to_owned(),
        ));
    }
    Ok(())
}

fn decode_acct_localpart(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(WireError::Protocol(
                "acct URI contains a truncated percent escape".to_owned(),
            ));
        }
        let high = decode_upper_hex(bytes[index + 1])?;
        let low = decode_upper_hex(bytes[index + 2])?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| WireError::Protocol("acct URI localpart is not valid UTF-8".to_owned()))
}

fn decode_upper_hex(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(WireError::Protocol(
            "acct URI percent escapes must use uppercase hexadecimal".to_owned(),
        )),
    }
}

fn validate_nfc_and_code_points(value: &str, max_code_points: usize) -> Result<()> {
    if value.is_empty() || !is_nfc(value) || value.chars().count() > max_code_points {
        return Err(WireError::Protocol(
            "text is empty, non-NFC, or outside the profile bounds".to_owned(),
        ));
    }
    Ok(())
}

fn is_bidi_embedding_or_override(character: char) -> bool {
    matches!(character as u32, 0x202A..=0x202E)
}

fn is_bidi_format_control(character: char) -> bool {
    is_bidi_embedding_or_override(character) || matches!(character as u32, 0x2066..=0x2069)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_internationalized_identifier_and_width() {
        assert_eq!(prepare_handle_localpart("小明").unwrap(), "小明");
        assert_eq!(prepare_handle_localpart("ＡＬＩＣＥ").unwrap(), "alice");
        assert_eq!(prepare_agent_slug("总结助手").unwrap(), "总结助手");
    }

    #[test]
    fn canonical_receiver_rejects_rewritable_input() {
        assert!(validate_canonical_handle_localpart("ＡＬＩＣＥ").is_err());
        assert!(validate_canonical_handle_localpart("e\u{301}xample").is_err());
        assert!(validate_canonical_agent_slug("Bad/Slug").is_err());
    }

    #[test]
    fn idna_profile_converts_and_round_trips() {
        assert_eq!(
            prepare_idna_domain("domain.中国").unwrap(),
            "domain.xn--fiqs8s"
        );
        validate_canonical_idna_domain("domain.xn--fiqs8s").unwrap();
        assert!(validate_canonical_idna_domain("domain.中国").is_err());
        assert!(prepare_idna_domain("example.com.").is_err());
        assert!(prepare_idna_domain("xn--a.example").is_err());
    }

    #[test]
    fn display_text_accepts_multilingual_content_and_rejects_controls() {
        validate_single_line_display_text("中文标题 🚀 / R&D（第二阶段）", 256).unwrap();
        assert!(validate_single_line_display_text("   ", 256).is_err());
        assert!(validate_single_line_display_text("line\nbreak", 256).is_err());
        assert!(validate_single_line_display_text("x\u{202E}y", 256).is_err());
    }

    #[test]
    fn canonical_handle_and_acct_profiles_share_identifier_validation() {
        validate_canonical_handle("小明:domain.xn--fiqs8s").unwrap();
        validate_canonical_acct_uri("acct:%E5%B0%8F%E6%98%8E@domain.xn--fiqs8s").unwrap();
        assert!(validate_canonical_handle("ＡＬＩＣＥ:example.com").is_err());
        assert!(validate_canonical_acct_uri("acct:Alice@example.com").is_err());
        assert!(validate_canonical_acct_uri("acct:%e5%B0%8F@example.com").is_err());
    }

    #[test]
    fn content_text_requires_nfc_and_rejects_unsafe_controls() {
        validate_content_text("line one\nline two\tvalue").unwrap();
        assert!(validate_content_text("e\u{301}").is_err());
        assert!(validate_content_text("before\u{0000}after").is_err());
    }

    #[test]
    fn skeleton_is_derived_and_not_canonicalization() {
        let latin = human_identifier_skeleton("paypal").unwrap();
        let cyrillic = human_identifier_skeleton("раураl").unwrap();
        assert_eq!(latin, cyrillic);
        assert_ne!("paypal", "раураl");
    }
}
