//! Shared bound for the opaque server-issued private invite locator.
//!
//! The same credential is written into the holder-private
//! `ak.account.invite_delivery` entry, copied verbatim into a pre-join preview
//! target, and forwarded once to the exact inviter Station. Every schema that
//! carries it spells the same `minLength: 1` / `maxLength: 512`, so the check
//! is defined once here rather than re-derived at each call site.

use crate::{Result, WireError};

/// Registered `maxLength` of `invite_token` across every schema that carries
/// it.
pub const INVITE_TOKEN_MAX_CHARS: usize = 512;

/// Validate one `invite_token` against the registered bounds.
///
/// `context` names the carrier so a rejection says which member failed; the
/// token itself is never included, because it is holder-private and error
/// text reaches logs.
pub fn validate_invite_token(context: &str, value: &str) -> Result<()> {
    let length = value.chars().count();
    if length == 0 || length > INVITE_TOKEN_MAX_CHARS {
        return Err(WireError::Protocol(format!(
            "{context} invite_token must be 1..={INVITE_TOKEN_MAX_CHARS} characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{INVITE_TOKEN_MAX_CHARS, validate_invite_token};

    #[test]
    fn empty_and_overlong_tokens_are_rejected() {
        assert!(validate_invite_token("test", "").is_err());
        assert!(validate_invite_token("test", &"t".repeat(INVITE_TOKEN_MAX_CHARS)).is_ok());
        assert!(validate_invite_token("test", &"t".repeat(INVITE_TOKEN_MAX_CHARS + 1)).is_err());
    }

    #[test]
    fn the_bound_counts_characters_not_bytes() {
        assert!(validate_invite_token("test", &"é".repeat(INVITE_TOKEN_MAX_CHARS)).is_ok());
    }

    #[test]
    fn a_rejection_never_quotes_the_token() {
        let secret = "s".repeat(INVITE_TOKEN_MAX_CHARS + 1);
        let error = validate_invite_token("test", &secret).expect_err("overlong token is rejected");
        assert!(!error.to_string().contains(&secret));
    }
}
