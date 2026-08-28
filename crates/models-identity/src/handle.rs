use std::fmt;

use arkret_wire::{
    DidCoreId, Result, WireError, human_identifier_skeleton, prepare_handle_localpart,
    prepare_idna_domain, validate_canonical_handle_localpart, validate_canonical_idna_domain,
};
use serde::{Deserialize, Serialize};

/// Canonical Arkret handle string.
///
/// Wire form: `<prepared-localpart>:<lowercase-A-label-domain>`.
///
/// `acct:<localpart>@<domain>` remains an interop alias only and lives in
/// `HandleClaim::handle_aliases`; the `@` mention sigil is not part of
/// this field.
///
/// Spec source: `string-profiles.schema.json#/$defs/canonical_handle`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Handle {
    canonical: String,
    localpart: String,
    domain: String,
}

impl Handle {
    /// Parse and validate an already-canonical wire handle.
    pub fn parse(input: &str) -> Result<Self> {
        let (localpart, domain) = input
            .split_once(':')
            .ok_or_else(|| WireError::Protocol(format!("handle missing ':<domain>': {input}")))?;
        if domain.contains(':') {
            return Err(WireError::Protocol(format!(
                "handle has too many ':' separators: {input}"
            )));
        }
        validate_canonical_handle_localpart(localpart)?;
        validate_canonical_idna_domain(domain)?;
        Ok(Self {
            canonical: input.to_owned(),
            localpart: localpart.to_owned(),
            domain: domain.to_owned(),
        })
    }

    /// Prepare a user-entered display/input form into canonical wire form.
    pub fn prepare(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let body = trimmed.strip_prefix('@').unwrap_or(trimmed);
        let (local, domain) = if let Some(parts) = body.rsplit_once('@') {
            parts
        } else {
            body.split_once(':').ok_or_else(|| {
                WireError::Protocol(format!("handle input missing domain separator: {input}"))
            })?
        };
        let localpart = prepare_handle_localpart(local)?;
        let domain = prepare_idna_domain(domain)?;
        Self::parse(&format!("{localpart}:{domain}"))
    }

    /// Build from `acct:<local>@<domain>` interop form. The result is the
    /// canonical handle; the original `acct:` string is intended to be
    /// carried separately as a handle alias.
    pub fn from_acct(acct: &str) -> Result<Self> {
        let rest = acct.strip_prefix("acct:").ok_or_else(|| {
            WireError::Protocol(format!("acct uri must start with acct:: {acct}"))
        })?;
        let (local, domain) = rest
            .rsplit_once('@')
            .ok_or_else(|| WireError::Protocol(format!("acct uri must contain @: {acct}")))?;
        let local = percent_decode_utf8(local)?;
        let localpart = prepare_handle_localpart(&local)?;
        let domain = prepare_idna_domain(domain)?;
        Self::parse(&format!("{localpart}:{domain}"))
    }

    /// Canonical wire form `<localpart>:<domain>`.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn localpart(&self) -> &str {
        &self.localpart
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Display form `@<localpart>:<domain>` favoured for UI surfaces.
    pub fn display(&self) -> String {
        format!("@{}:{}", self.localpart, self.domain)
    }

    /// Interop form for `handle_aliases[]` cross-publication.
    pub fn to_acct(&self) -> String {
        format!(
            "acct:{}@{}",
            percent_encode_acct_userpart(&self.localpart),
            self.domain
        )
    }

    /// UTS #39 skeleton for authority-local registration collision indexes.
    pub fn registration_skeleton(&self) -> Result<String> {
        human_identifier_skeleton(&self.localpart)
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl TryFrom<String> for Handle {
    type Error = WireError;
    fn try_from(value: String) -> Result<Self> {
        Handle::parse(&value)
    }
}

impl From<Handle> for String {
    fn from(value: Handle) -> Self {
        value.canonical
    }
}

fn percent_encode_acct_userpart(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-' | b'+') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn percent_decode_utf8(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3).ok_or_else(|| {
                WireError::Protocol("acct URI contains truncated percent encoding".to_owned())
            })?;
            let hex = std::str::from_utf8(hex).map_err(|_| {
                WireError::Protocol("acct URI percent encoding is invalid".to_owned())
            })?;
            decoded.push(u8::from_str_radix(hex, 16).map_err(|_| {
                WireError::Protocol("acct URI percent encoding is invalid".to_owned())
            })?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| WireError::Protocol("acct URI userpart is not valid UTF-8".to_owned()))
}

/// R3.2 — `ak.schema.handle_claim.v1.subject` validator.
///
/// The handle claim subject MUST be a holder/principal `did_core_id`, not a
/// server-local account id, service identity, administrative identifier, or
/// generic resource id. The type boundary rejects DIDs and non-core
/// identifiers; deployment-specific role admission remains the issuer's job.
///
/// On rejection returns [`WireError::Protocol`] carrying the
/// `handle_claim_subject_not_principal_did` wire code prefix.
pub fn validate_handle_claim_subject(subject: &DidCoreId) -> Result<()> {
    let s = subject.as_str();
    if !s.starts_with("ak:did_core:") {
        return Err(WireError::Protocol(format!(
            "handle_claim_subject_not_principal_did: subject must be a DID core id ({s})"
        )));
    }
    Ok(())
}

/// Default visibility for a handle claim disclosure boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleVisibility {
    Public,
    Restricted,
    Private,
}

/// Binding-state machine for the handle claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleBindingState {
    Pending,
    Verified,
    Revoked,
    Expired,
}

/// Protocol kind of handle claim (`claim_kind` in the wire schema).
///
/// R3.5 wire-breaking: the draft-era `claim_kind` / `class` discriminators
/// are forbidden. The draft-era `service_handle` value is removed.
/// Service-readable names / resource labels need their own service /
/// resource schema; organization-assigned user / principal handles use
/// `organization_handle`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleClaimKind {
    HandleBinding,
    OrganizationHandle,
}

/// `binding_source` accepted on a handle claim hint. Excludes
/// `did_document_default` — handle claims MUST commit to a concrete
/// recipient service when ferrying a builder payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleHintBindingSource {
    Explicit,
    Invite,
    JoinPolicy,
    OrganizationPolicy,
    RealmPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_handle() {
        let h = Handle::parse("alice:example.com").unwrap();
        assert_eq!(h.localpart(), "alice");
        assert_eq!(h.domain(), "example.com");
        assert_eq!(h.canonical(), "alice:example.com");
    }

    #[test]
    fn prepares_display_input_but_canonical_parse_rejects_rewrites() {
        let h = Handle::prepare("@ＡＬＩＣＥ:Example.COM").unwrap();
        assert_eq!(h.canonical(), "alice:example.com");
        assert!(Handle::parse("Alice:example.com").is_err());
        assert!(Handle::parse("alice:Example.COM").is_err());
    }

    #[test]
    fn rejects_bare_host_and_uri_form() {
        // `<localpart>:<domain>` requires a localpart segment AND a
        // multi-label domain (`example.com`, not `example`).
        assert!(Handle::parse("example.com").is_err());
        assert!(Handle::parse("alice:example").is_err());
        // arkret:// URI form is no longer accepted (R3.1 wire rename).
        assert!(Handle::parse("arkret://example.com/users/alice").is_err());
        // acct: alias must be routed through `from_acct`.
        assert!(Handle::parse("acct:alice@example.com").is_err());
    }

    #[test]
    fn rejects_port_and_accepts_unicode_localpart() {
        assert!(Handle::parse("alice:example.com:8443").is_err());
        let h = Handle::parse("小明:domain.xn--fiqs8s").unwrap();
        assert_eq!(h.display(), "@小明:domain.xn--fiqs8s");
    }

    #[test]
    fn from_acct_normalises_to_canonical() {
        let h = Handle::from_acct("acct:Bob@example.com").unwrap();
        assert_eq!(h.canonical(), "bob:example.com");
        assert_eq!(h.to_acct(), "acct:bob@example.com");
        let unicode = Handle::from_acct("acct:%E5%B0%8F%E6%98%8E@domain.xn--fiqs8s").unwrap();
        assert_eq!(unicode.canonical(), "小明:domain.xn--fiqs8s");
        assert_eq!(
            unicode.to_acct(),
            "acct:%E5%B0%8F%E6%98%8E@domain.xn--fiqs8s"
        );
    }
}
