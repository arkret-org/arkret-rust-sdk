use std::fmt;

use arkret_wire::{Did, Error, Result};
use serde::{Deserialize, Serialize};

/// Canonical Arkret handle string.
///
/// R3.1 wire form: `<localpart>:<domain>(:<port>)?` with lowercase
/// `localpart`. The previous `arkret://<domain>/users/<localpart>` URI
/// form has been retired (arkret-spec @ 7157ee8 — 2026-05-27).
///
/// `acct:<localpart>@<domain>` remains an interop alias only and lives in
/// [`HandleClaim::handle_aliases`]; the `@` mention sigil is not part of
/// this field.
///
/// Spec source: `handle-claim.schema.json#/properties/handle`
/// (commit 7157ee8).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(try_from = "String", into = "String")]
pub struct Handle {
    canonical: String,
    localpart: String,
    domain: String,
    port: Option<u16>,
}

impl Handle {
    /// Parse a canonical `<localpart>:<domain>(:<port>)?` handle.
    /// Lowercases both the localpart and domain.
    pub fn parse(input: &str) -> Result<Self> {
        let mut parts = input.split(':');
        let local = parts
            .next()
            .ok_or_else(|| Error::Protocol(format!("handle is empty: {input}")))?;
        let domain_part = parts
            .next()
            .ok_or_else(|| Error::Protocol(format!("handle missing ':<domain>': {input}")))?;
        let port_part = parts.next();
        if parts.next().is_some() {
            return Err(Error::Protocol(format!(
                "handle has too many ':' separators: {input}"
            )));
        }
        if local.is_empty() {
            return Err(Error::Protocol(format!(
                "handle localpart is empty: {input}"
            )));
        }
        let localpart = local.to_ascii_lowercase();
        if !is_valid_localpart(&localpart) {
            return Err(Error::Protocol(format!(
                "handle localpart invalid: {input}"
            )));
        }
        let domain = domain_part.to_ascii_lowercase();
        if !is_valid_domain(&domain) {
            return Err(Error::Protocol(format!("handle domain invalid: {input}")));
        }
        let port = match port_part {
            Some(p) => Some(
                p.parse::<u16>()
                    .map_err(|_| Error::Protocol(format!("handle port invalid: {input}")))?,
            ),
            None => None,
        };
        let canonical = match port {
            Some(p) => format!("{localpart}:{domain}:{p}"),
            None => format!("{localpart}:{domain}"),
        };
        Ok(Self {
            canonical,
            localpart,
            domain,
            port,
        })
    }

    /// Build from `acct:<local>@<domain>` interop form. The result is the
    /// canonical handle; the original `acct:` string is intended to be
    /// carried separately as a handle alias.
    pub fn from_acct(acct: &str) -> Result<Self> {
        let rest = acct
            .strip_prefix("acct:")
            .ok_or_else(|| Error::Protocol(format!("acct uri must start with acct:: {acct}")))?;
        let (local, domain) = rest
            .rsplit_once('@')
            .ok_or_else(|| Error::Protocol(format!("acct uri must contain @: {acct}")))?;
        let synthesized = format!("{}:{}", local.to_ascii_lowercase(), domain);
        Self::parse(&synthesized)
    }

    /// Canonical wire form `<localpart>:<domain>(:<port>)?`.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn localpart(&self) -> &str {
        &self.localpart
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Display form `@<localpart>:<domain>` favoured for UI surfaces.
    pub fn display(&self) -> String {
        match self.port {
            Some(p) => format!("@{}:{}:{}", self.localpart, self.domain, p),
            None => format!("@{}:{}", self.localpart, self.domain),
        }
    }

    /// Interop form for `handle_aliases[]` cross-publication.
    pub fn to_acct(&self) -> String {
        match self.port {
            Some(p) => format!("acct:{}@{}:{}", self.localpart, self.domain, p),
            None => format!("acct:{}@{}", self.localpart, self.domain),
        }
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl TryFrom<String> for Handle {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        Handle::parse(&value)
    }
}

impl From<Handle> for String {
    fn from(value: Handle) -> Self {
        value.canonical
    }
}

fn is_valid_localpart(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    s.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '+' | '~' | '-')
    })
}

/// AKP R3 spec-sync (2026-05-27) — wire-level handle normalize check.
///
/// Performs the operations that a registrar / claim reducer MUST run
/// before accepting a candidate localpart:
///
/// 1. Reject zero-width / bidi controls before any display processing.
/// 2. Enforce the v1 canonical ASCII localpart alphabet.
/// 3. Reject common non-ASCII Latin lookalikes with the `handle_homograph_forbidden` wire code.
///
/// On rejection returns [`Error::Protocol`] carrying the
/// `handle_homograph_forbidden` wire code prefix so downstream HTTP
/// adapters can map straight to the registry error.
pub fn normalize_handle_localpart(input: &str) -> Result<String> {
    normalize_localpart_with_code(input, "handle_homograph_forbidden")
}

/// Shared localpart normalize used by BOTH handle and realm-alias registrars
/// (object-addressing.md §3.3 reuses identity-handles.md §17 discipline).
///
/// `code` is the wire error-code prefix carried on rejection — pass
/// `handle_homograph_forbidden` for handles, `realm_alias_homograph_forbidden`
/// for realm aliases — so downstream HTTP adapters map straight to the right
/// registry error. Steps: length bound → zero-width / bidi reject → canonical
/// ASCII alphabet → confusable-codepoint reject → lowercase.
pub fn normalize_localpart_with_code(input: &str, code: &str) -> Result<String> {
    if input.is_empty() || input.len() > 128 {
        return Err(Error::Protocol(format!(
            "{code}: localpart length out of range ({input:?})"
        )));
    }

    // Reject zero-width characters and bidi controls outright.
    for ch in input.chars() {
        let cp = ch as u32;
        if matches!(
            cp,
            0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0xFEFF
        ) {
            return Err(Error::Protocol(format!(
                "{code}: zero-width / bidi control rejected ({input:?})"
            )));
        }
    }

    if input.chars().any(|c| !is_valid_localpart_char(c)) {
        return Err(Error::Protocol(format!(
            "{code}: localpart outside canonical ASCII alphabet ({input:?})"
        )));
    }

    for ch in input.chars() {
        if !ch.is_ascii() && minimal_confusable_for(ch).is_some() {
            return Err(Error::Protocol(format!(
                "{code}: confusable codepoint ({input:?})"
            )));
        }
    }

    Ok(input.to_lowercase())
}

fn is_valid_localpart_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '-')
}

/// UTS#39-inspired high-risk lookup retained for diagnostics and tests.
fn minimal_confusable_for(ch: char) -> Option<char> {
    Some(match ch {
        // Cyrillic lookalikes.
        'а' => 'a',
        'е' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'у' => 'y',
        'х' => 'x',
        'А' => 'A',
        'В' => 'B',
        'Е' => 'E',
        'К' => 'K',
        'М' => 'M',
        'Н' => 'H',
        'О' => 'O',
        'Р' => 'P',
        'С' => 'C',
        'Т' => 'T',
        'Х' => 'X',
        // Greek lookalikes.
        'α' => 'a',
        'ο' => 'o',
        'ρ' => 'p',
        'ν' => 'v',
        'Α' => 'A',
        'Β' => 'B',
        'Ε' => 'E',
        'Ζ' => 'Z',
        'Η' => 'H',
        'Ι' => 'I',
        'Κ' => 'K',
        'Μ' => 'M',
        'Ν' => 'N',
        'Ο' => 'O',
        'Ρ' => 'P',
        'Τ' => 'T',
        'Υ' => 'Y',
        'Χ' => 'X',
        _ => return None,
    })
}

#[cfg(test)]
mod handle_normalize_tests {
    use super::*;

    #[test]
    fn pure_ascii_normalizes() {
        assert_eq!(normalize_handle_localpart("alice").unwrap(), "alice");
    }

    #[test]
    fn cyrillic_lookalike_is_rejected() {
        // "alicе" with Cyrillic 'е' (U+0435).
        let result = normalize_handle_localpart("alic\u{0435}");
        assert!(result.is_err());
    }

    #[test]
    fn zero_width_is_rejected() {
        let result = normalize_handle_localpart("ali\u{200B}ce");
        assert!(result.is_err());
    }

    #[test]
    fn mixed_script_is_rejected() {
        let result = normalize_handle_localpart("aliceα");
        assert!(result.is_err());
    }

    #[test]
    fn all_non_ascii_localpart_is_rejected() {
        let result = normalize_handle_localpart("\u{0430}\u{043B}\u{0438}\u{0441}\u{0430}");
        assert!(result.is_err());
    }
}

pub fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // R3.1 schema: at least 2 dot-separated labels, each label is
    // `[a-z0-9]([a-z0-9-]*[a-z0-9])?`.
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        if label.is_empty() {
            return false;
        }
        let bytes = label.as_bytes();
        let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
        let last_ok =
            bytes[bytes.len() - 1].is_ascii_lowercase() || bytes[bytes.len() - 1].is_ascii_digit();
        first_ok
            && last_ok
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

/// R3.2 — `ak.schema.handle_claim.v1.subject` validator.
///
/// The handle claim subject MUST be a holder / principal DID. It is NOT a
/// Realm `actor_id` (`ak:actor:`), a server-local `account_id`
/// (`ak:account:`), a service DID, an administrative identifier, or a
/// generic resource id. We accept any `did:<method>:...` and reject the
/// typed-id prefixes; a deployment-specific "is this a service DID"
/// distinction is left to the issuer, but the typed-id rejection here
/// catches the structural misuse the spec calls out.
///
/// On rejection returns [`Error::Protocol`] carrying the
/// `handle_claim_subject_not_principal_did` wire code prefix.
pub fn validate_handle_claim_subject(subject: &Did) -> Result<()> {
    let s = subject.as_str();
    if s.starts_with("ak:actor:") || s.starts_with("ak:account:") {
        return Err(Error::Protocol(format!(
            "handle_claim_subject_not_principal_did: subject must be a holder/principal DID, \
             not a typed id ({s})"
        )));
    }
    if !s.starts_with("did:") {
        return Err(Error::Protocol(format!(
            "handle_claim_subject_not_principal_did: subject must be a DID ({s})"
        )));
    }
    Ok(())
}

/// Default visibility for a handle claim disclosure boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleVisibility {
    Public,
    Restricted,
    Private,
}

/// Binding-state machine for the handle claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleBindingState {
    Pending,
    Verified,
    Revoked,
    Expired,
}

/// Protocol kind of handle claim (`claim_kind` in the wire schema).
///
/// R3.5 wire-breaking: the draft-era `claim_type` / `class` discriminators
/// are forbidden. The draft-era `service_handle` value is removed.
/// Service-readable names / resource labels need their own service /
/// resource schema; organization-assigned user / principal handles use
/// `organization_handle`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleClaimKind {
    HandleBinding,
    OrganizationHandle,
}

/// `binding_source` accepted on a handle claim hint. Excludes
/// `did_document_default` — handle claims MUST commit to a concrete
/// recipient service when ferrying a builder payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleHintBindingSource {
    Explicit,
    Invite,
    JoinPolicy,
    OrganizationPolicy,
    RealmPolicy,
}

/// Canonical handle claim shape — matches `handle-claim.schema.json`.
pub const HANDLE_CLAIM_SCHEMA: &str = "ak.schema.handle_claim.v1";

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
    fn lowercases_localpart() {
        let h = Handle::parse("Alice:example.com").unwrap();
        assert_eq!(h.localpart(), "alice");
        assert_eq!(h.canonical(), "alice:example.com");
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
    fn accepts_optional_port() {
        let h = Handle::parse("alice:example.com:8443").unwrap();
        assert_eq!(h.port(), Some(8443));
        assert_eq!(h.canonical(), "alice:example.com:8443");
    }

    #[test]
    fn from_acct_normalises_to_canonical() {
        let h = Handle::from_acct("acct:Bob@example.com").unwrap();
        assert_eq!(h.canonical(), "bob:example.com");
        assert_eq!(h.to_acct(), "acct:bob@example.com");
    }
}
