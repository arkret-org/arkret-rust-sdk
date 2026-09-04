//! Framework-independent parsing for the HTTP `Authorization` header.

use std::fmt;

/// Authorization schemes used by Arkret HTTP bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationScheme {
    Bearer,
    Dpop,
}

impl AuthorizationScheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::Dpop => "DPoP",
        }
    }
}

/// A validated scheme and non-empty credential borrowed from a header value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationCredential<'a> {
    scheme: AuthorizationScheme,
    credential: &'a str,
}

impl<'a> AuthorizationCredential<'a> {
    pub const fn scheme(self) -> AuthorizationScheme {
        self.scheme
    }

    pub const fn credential(self) -> &'a str {
        self.credential
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationHeaderError {
    MissingSchemeSeparator,
    UnsupportedScheme,
    EmptyCredential,
    InvalidWhitespace,
}

impl fmt::Display for AuthorizationHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingSchemeSeparator => {
                "authorization header must contain a scheme and credential"
            }
            Self::UnsupportedScheme => "authorization scheme is not supported",
            Self::EmptyCredential => "authorization credential must not be empty",
            Self::InvalidWhitespace => "authorization header must use one ASCII space separator",
        })
    }
}

impl std::error::Error for AuthorizationHeaderError {}

/// Parse an Arkret authorization header without depending on an HTTP framework.
///
/// The scheme is ASCII case-insensitive as required by HTTP authentication;
/// the single-space separator remains strict so a credential is never parsed
/// ambiguously.
pub fn parse_authorization(
    value: &str,
) -> Result<AuthorizationCredential<'_>, AuthorizationHeaderError> {
    let (scheme, credential) = value
        .split_once(' ')
        .ok_or(AuthorizationHeaderError::MissingSchemeSeparator)?;
    if credential.is_empty() {
        return Err(AuthorizationHeaderError::EmptyCredential);
    }
    if credential.starts_with(char::is_whitespace) || credential.contains(char::is_whitespace) {
        return Err(AuthorizationHeaderError::InvalidWhitespace);
    }
    let scheme = if scheme.eq_ignore_ascii_case("Bearer") {
        AuthorizationScheme::Bearer
    } else if scheme.eq_ignore_ascii_case("DPoP") {
        AuthorizationScheme::Dpop
    } else {
        return Err(AuthorizationHeaderError::UnsupportedScheme);
    };
    Ok(AuthorizationCredential { scheme, credential })
}

/// Extract a credential only when the presented scheme is the expected one.
pub fn authorization_credential(value: &str, expected: AuthorizationScheme) -> Option<&str> {
    parse_authorization(value)
        .ok()
        .filter(|authorization| authorization.scheme() == expected)
        .map(AuthorizationCredential::credential)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_schemes_without_interchanging_them() {
        let bearer = parse_authorization("Bearer access-token").unwrap();
        assert_eq!(bearer.scheme(), AuthorizationScheme::Bearer);
        assert_eq!(bearer.credential(), "access-token");
        assert_eq!(
            authorization_credential("DPoP session-grant", AuthorizationScheme::Dpop),
            Some("session-grant")
        );
        assert_eq!(
            authorization_credential("DPoP session-grant", AuthorizationScheme::Bearer),
            None
        );
    }

    #[test]
    fn rejects_ambiguous_or_empty_headers() {
        for value in [
            "Bearer",
            "Bearer ",
            "Bearer  token",
            "Basic token",
            "DPoP token trailing",
        ] {
            assert!(parse_authorization(value).is_err(), "accepted {value:?}");
        }
        assert_eq!(
            parse_authorization("bearer token").unwrap().scheme(),
            AuthorizationScheme::Bearer
        );
    }
}
