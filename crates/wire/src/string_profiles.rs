//! Arkret v1 Unicode and external-domain string profiles.

use precis_profiles::UsernameCaseMapped;
use precis_profiles::precis_core::profile::Profile;
use unicode_normalization::is_nfc;
use unicode_security::{RestrictionLevel, RestrictionLevelDetection};

use crate::{Error, Result};

pub const HANDLE_LOCALPART_MAX_CODE_POINTS: usize = 128;
pub const HANDLE_LOCALPART_MAX_UTF8_OCTETS: usize = 512;
pub const AGENT_SLUG_MAX_CODE_POINTS: usize = 64;
pub const AGENT_SLUG_MAX_UTF8_OCTETS: usize = 256;
pub const DOMAIN_MAX_ASCII_OCTETS: usize = 253;
pub const DISPLAY_TEXT_MAX_UTF8_OCTETS: usize = 1024;
pub const LONG_DISPLAY_TEXT_MAX_UTF8_OCTETS: usize = 2048;

pub fn prepare_handle_localpart(input: &str) -> Result<String> {
    prepare_human_identifier(
        input,
        HANDLE_LOCALPART_MAX_CODE_POINTS,
        HANDLE_LOCALPART_MAX_UTF8_OCTETS,
    )
}

pub fn validate_canonical_handle_localpart(input: &str) -> Result<()> {
    validate_canonical_human_identifier(
        input,
        HANDLE_LOCALPART_MAX_CODE_POINTS,
        HANDLE_LOCALPART_MAX_UTF8_OCTETS,
    )
}

pub fn prepare_agent_slug(input: &str) -> Result<String> {
    prepare_human_identifier(
        input,
        AGENT_SLUG_MAX_CODE_POINTS,
        AGENT_SLUG_MAX_UTF8_OCTETS,
    )
}

pub fn validate_canonical_agent_slug(input: &str) -> Result<()> {
    validate_canonical_human_identifier(
        input,
        AGENT_SLUG_MAX_CODE_POINTS,
        AGENT_SLUG_MAX_UTF8_OCTETS,
    )
}

pub fn prepare_human_identifier(
    input: &str,
    max_code_points: usize,
    max_utf8_octets: usize,
) -> Result<String> {
    let prepared = UsernameCaseMapped::new()
        .enforce(input)
        .map_err(|error| Error::Protocol(format!("human identifier PRECIS failure: {error:?}")))?
        .into_owned();
    validate_human_identifier_shape(&prepared, max_code_points, max_utf8_octets)?;
    Ok(prepared)
}

pub fn validate_canonical_human_identifier(
    input: &str,
    max_code_points: usize,
    max_utf8_octets: usize,
) -> Result<()> {
    let prepared = prepare_human_identifier(input, max_code_points, max_utf8_octets)?;
    if prepared != input {
        return Err(Error::Protocol(
            "human identifier is not in canonical prepared form".to_owned(),
        ));
    }
    Ok(())
}

fn validate_human_identifier_shape(
    value: &str,
    max_code_points: usize,
    max_utf8_octets: usize,
) -> Result<()> {
    if value.is_empty() || value.chars().count() > max_code_points || value.len() > max_utf8_octets
    {
        return Err(Error::Protocol(
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
        return Err(Error::Protocol(
            "human identifier contains a forbidden structural or control character".to_owned(),
        ));
    }
    Ok(())
}

pub fn prepare_idna_domain(input: &str) -> Result<String> {
    if input.is_empty() || input != input.trim() || input.ends_with('.') {
        return Err(Error::Protocol(
            "domain is empty, padded, or has a trailing dot".to_owned(),
        ));
    }
    let ascii = idna::domain_to_ascii_strict(input)
        .map_err(|_| Error::Protocol("domain fails the Arkret UTS #46 profile".to_owned()))?;
    if ascii.len() > DOMAIN_MAX_ASCII_OCTETS || ascii.split('.').count() < 2 {
        return Err(Error::Protocol(
            "domain must contain at least two labels within DNS length limits".to_owned(),
        ));
    }
    let (unicode, unicode_result) = idna::domain_to_unicode(&ascii);
    unicode_result
        .map_err(|_| Error::Protocol("domain A-label cannot be decoded safely".to_owned()))?;
    let roundtrip = idna::domain_to_ascii_strict(&unicode)
        .map_err(|_| Error::Protocol("domain fails the U-label round trip".to_owned()))?;
    if roundtrip != ascii {
        return Err(Error::Protocol(
            "domain A-label round trip mismatch".to_owned(),
        ));
    }
    Ok(ascii)
}

pub fn validate_canonical_idna_domain(input: &str) -> Result<()> {
    if !input.is_ascii() || input.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(Error::Protocol(
            "canonical domain must be a lowercase ASCII A-label".to_owned(),
        ));
    }
    if prepare_idna_domain(input)? != input {
        return Err(Error::Protocol("domain is not canonical".to_owned()));
    }
    Ok(())
}

pub fn human_identifier_skeleton(value: &str) -> Result<String> {
    validate_canonical_handle_localpart(value)?;
    Ok(unicode_security::skeleton(value).collect())
}

pub fn validate_highly_restrictive_registration_identifier(value: &str) -> Result<()> {
    validate_canonical_handle_localpart(value)?;
    if !value.check_restriction_level(RestrictionLevel::HighlyRestrictive) {
        return Err(Error::Protocol(
            "human identifier exceeds the UTS #39 Highly Restrictive registration policy"
                .to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_single_line_display_text(
    value: &str,
    max_code_points: usize,
    max_utf8_octets: usize,
) -> Result<()> {
    validate_nfc_and_length(value, max_code_points, max_utf8_octets)?;
    if value.chars().all(char::is_whitespace)
        || value.chars().any(|character| {
            character.is_control() || is_bidi_format_control(character) || character == '\u{FEFF}'
        })
    {
        return Err(Error::Protocol(
            "single-line display text contains only whitespace or a forbidden control".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_short_text(
    value: &str,
    max_code_points: usize,
    max_utf8_octets: usize,
) -> Result<()> {
    validate_nfc_and_length(value, max_code_points, max_utf8_octets)?;
    if value.chars().any(|character| {
        (character.is_control() && character != '\n')
            || is_bidi_embedding_or_override(character)
            || character == '\u{FEFF}'
    }) {
        return Err(Error::Protocol(
            "short text contains a forbidden control character".to_owned(),
        ));
    }
    Ok(())
}

fn validate_nfc_and_length(
    value: &str,
    max_code_points: usize,
    max_utf8_octets: usize,
) -> Result<()> {
    if value.is_empty()
        || !is_nfc(value)
        || value.chars().count() > max_code_points
        || value.len() > max_utf8_octets
    {
        return Err(Error::Protocol(
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
        validate_single_line_display_text(
            "中文标题 🚀 / R&D（第二阶段）",
            256,
            DISPLAY_TEXT_MAX_UTF8_OCTETS,
        )
        .unwrap();
        assert!(validate_single_line_display_text("   ", 256, 1024).is_err());
        assert!(validate_single_line_display_text("line\nbreak", 256, 1024).is_err());
        assert!(validate_single_line_display_text("x\u{202E}y", 256, 1024).is_err());
    }

    #[test]
    fn skeleton_is_derived_and_not_canonicalization() {
        let latin = human_identifier_skeleton("paypal").unwrap();
        let cyrillic = human_identifier_skeleton("раураl").unwrap();
        assert_eq!(latin, cyrillic);
        assert_ne!("paypal", "раураl");
    }
}
