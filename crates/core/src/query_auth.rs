//! Canonical detection of authentication material in URL query parameters.

/// Query parameter names that can carry authentication or signing material.
///
/// Arkret protected endpoints reject these names case-insensitively. Values
/// must be carried in headers or typed request bodies instead.
pub const QUERY_AUTH_PARAMETER_NAMES: &[&str] = &[
    "access_token",
    "api_key",
    "api_token",
    "auth",
    "auth_token",
    "authorization",
    "bearer",
    "device_proof",
    "id_token",
    "key",
    "password",
    "proof",
    "refresh_token",
    "secret",
    "service_signature",
    "session",
    "session_token",
    "signature",
    "token",
];

/// Return whether a decoded query parameter name is reserved for auth material.
pub fn is_query_auth_parameter(name: &str) -> bool {
    QUERY_AUTH_PARAMETER_NAMES
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// Parse an encoded query string and detect auth-material parameter names.
pub fn contains_query_auth_material(query: &str) -> bool {
    url::form_urlencoded::parse(query.as_bytes())
        .any(|(name, _)| is_query_auth_parameter(name.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_case_and_percent_encoded_names_without_substring_false_positives() {
        assert!(contains_query_auth_material("foo=1&Access_Token=secret"));
        assert!(contains_query_auth_material("sign%61ture=secret"));
        assert!(!contains_query_auth_material(
            "oauth=metadata&tokenized=true"
        ));
    }
}
