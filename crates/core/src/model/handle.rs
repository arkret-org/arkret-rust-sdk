use std::fmt;

use super::*;

/// Canonical Contrix handle string.
///
/// R3.1 wire form: `<localpart>:<domain>(:<port>)?` with lowercase
/// `localpart`. The previous `contrix://<domain>/users/<localpart>` URI
/// form has been retired (contrix-spec @ 7157ee8 — 2026-05-27).
///
/// `acct:<localpart>@<domain>` remains an interop alias only and lives in
/// [`HandleClaim::handle_aliases`]; the `@` mention sigil is not part of
/// this field.
///
/// Spec source: `handle-claim.schema.json#/properties/handle`
/// (commit 7157ee8).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
        let local =
            parts.next().ok_or_else(|| Error::Protocol(format!("handle is empty: {input}")))?;
        let domain_part = parts
            .next()
            .ok_or_else(|| Error::Protocol(format!("handle missing ':<domain>': {input}")))?;
        let port_part = parts.next();
        if parts.next().is_some() {
            return Err(Error::Protocol(format!("handle has too many ':' separators: {input}")));
        }
        if local.is_empty() {
            return Err(Error::Protocol(format!("handle localpart is empty: {input}")));
        }
        let localpart = local.to_ascii_lowercase();
        if !is_valid_localpart(&localpart) {
            return Err(Error::Protocol(format!("handle localpart invalid: {input}")));
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
        Ok(Self { canonical, localpart, domain, port })
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

/// CXP R3 spec-sync (2026-05-27) — wire-level handle normalize check.
///
/// Performs the operations that a registrar / claim reducer MUST run
/// before accepting a candidate localpart:
///
/// 1. Apply Unicode NFC normalization (idempotent for ASCII).
/// 2. Reject mixed-script labels (Latin mixed with non-Latin scripts).
/// 3. Reject obvious homograph substitutions through a minimal
///    confusable skeleton — currently the ASCII-confusable subset; the
///    full UTS#39 skeleton table lands in R3.1.
///
/// On rejection returns [`Error::Protocol`] carrying the
/// `handle_homograph_forbidden` wire code prefix so downstream HTTP
/// adapters can map straight to the registry error.
//
// TODO(R3.1): swap the minimal skeleton table for the full UTS#39
// `confusables.txt` mapping (add `unicode-skeleton` crate or embed the
// table). Until then, only the high-frequency Latin-vs-Cyrillic-vs-Greek
// substitutions below are caught — sufficient for the wire-level guard
// to refuse the most common attacks (cyrillic 'а', greek 'ο', etc.).
pub fn normalize_handle_localpart(input: &str) -> Result<String> {
    // 1. Trim NFC-equivalent control / zero-width payloads. The full
    //    NFC pass is deferred (no `unicode-normalization` dep yet); for
    //    ASCII the normalized form equals the input.
    if input.is_empty() || input.len() > 128 {
        return Err(Error::Protocol(format!(
            "handle_homograph_forbidden: localpart length out of range ({input:?})"
        )));
    }

    // 2. Reject zero-width characters and bidi controls outright.
    for ch in input.chars() {
        let cp = ch as u32;
        if matches!(
            cp,
            0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0xFEFF
        ) {
            return Err(Error::Protocol(format!(
                "handle_homograph_forbidden: zero-width / bidi control rejected ({input:?})"
            )));
        }
    }

    // 3. Script-mixed check: if any character is non-ASCII while at
    //    least one ASCII letter is present, fail closed. This is the
    //    R3 wire-level minimum; the full UTS#39 mixed-script detector
    //    needs a script-property table (deferred).
    let has_ascii_letter = input.chars().any(|c| c.is_ascii_alphabetic());
    let has_non_ascii_letter = input.chars().any(|c| !c.is_ascii() && c.is_alphabetic());
    if has_ascii_letter && has_non_ascii_letter {
        return Err(Error::Protocol(format!(
            "handle_homograph_forbidden: script-mixed localpart ({input:?})"
        )));
    }

    // 4. Minimal confusable skeleton check for the highest-risk
    //    substitutions (Cyrillic / Greek look-alikes of ASCII letters).
    for ch in input.chars() {
        if !ch.is_ascii() && minimal_confusable_for(ch).is_some() {
            return Err(Error::Protocol(format!(
                "handle_homograph_forbidden: confusable codepoint ({input:?})"
            )));
        }
    }

    Ok(input.to_lowercase())
}

/// Minimal UTS#39 confusable lookup. Returns the ASCII look-alike for a
/// known high-risk codepoint, or [`None`] when the character is not in
/// the minimal table. The full table is loaded in R3.1.
fn minimal_confusable_for(ch: char) -> Option<char> {
    Some(match ch {
        // Cyrillic look-alikes.
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
        // Greek look-alikes.
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
}

fn is_valid_domain(s: &str) -> bool {
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
            && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

/// R3.2 — `cx.schema.handle_claim.v1.subject` validator.
///
/// The handle claim subject MUST be a holder / principal DID. It is NOT a
/// Realm `actor_id` (`cx:actor:`), a server-local `account_id`
/// (`cx:account:`), a service DID, an administrative identifier, or a
/// generic resource id. We accept any `did:<method>:...` and reject the
/// typed-id prefixes; a deployment-specific "is this a service DID"
/// distinction is left to the issuer, but the typed-id rejection here
/// catches the structural misuse the spec calls out.
///
/// On rejection returns [`Error::Protocol`] carrying the
/// `handle_claim_subject_not_principal_did` wire code prefix.
pub fn validate_handle_claim_subject(subject: &Did) -> Result<()> {
    let s = subject.as_str();
    if s.starts_with("cx:actor:") || s.starts_with("cx:account:") {
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleVisibility {
    Public,
    Restricted,
    Private,
}

/// Binding-state machine for the handle claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleBindingState {
    Pending,
    Challenged,
    Verified,
    Revoked,
}

/// Class of handle being asserted (`claim_type` in the wire schema).
///
/// R3.2 wire-breaking: the draft-era `service_handle` value is removed.
/// Service-readable names / resource labels need their own service /
/// resource schema; organization-assigned user / principal handles use
/// `organization_handle`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleClass {
    UserHandle,
    OrganizationHandle,
}

/// Builder-side member delivery binding offered by a handle claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeliveryBindingHint {
    pub recipient_service_did: Did,
    #[serde(default = "default_hint_recipient_service_type")]
    pub recipient_service_type: RecipientServiceType,
    pub binding_source: HandleHintBindingSource,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub delivery_modes: BTreeSet<DeliveryMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
}

fn default_hint_recipient_service_type() -> RecipientServiceType {
    RecipientServiceType::PrincipalServer
}

/// `binding_source` accepted on a handle claim hint. Excludes
/// `did_document_default` — handle claims MUST commit to a concrete
/// recipient service when ferrying a builder payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleHintBindingSource {
    Explicit,
    Invite,
    JoinPolicy,
    OrganizationPolicy,
    RealmPolicy,
}

/// Canonical handle claim shape — matches `handle-claim.schema.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct HandleClaim {
    /// Canonical handle `<localpart>:<domain>`. R3.1 wire rename from
    /// the prior `handle_uri` field name (contrix-spec @ 7157ee8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<Handle>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_service_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_state: Option<HandleBindingState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<HandleClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<HandleVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claim_scope: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_delivery_binding: Option<DeliveryBindingHint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
}

impl HandleClaim {
    /// Enforce schema `allOf` conditional required fields:
    ///   - `binding_state=verified` ⇒ `handle` + `expires_at`
    ///   - `member_delivery_binding` present ⇒ `handle` + `audience` +
    ///     `expires_at`, and binding_source != did_document_default
    ///     (enforced by the [`HandleHintBindingSource`] type itself).
    pub fn validate(&self) -> Result<()> {
        if matches!(self.binding_state, Some(HandleBindingState::Verified)) {
            if self.handle.is_none() {
                return Err(Error::Protocol("binding_state=verified requires handle".to_owned()));
            }
            if self.expires_at.is_none() {
                return Err(Error::Protocol(
                    "binding_state=verified requires expires_at".to_owned(),
                ));
            }
        }
        if self.member_delivery_binding.is_some()
            && (self.handle.is_none() || self.audience.is_none() || self.expires_at.is_none())
        {
            return Err(Error::Protocol(
                "member_delivery_binding present requires handle, audience, expires_at".to_owned(),
            ));
        }
        if let Some(subject) = &self.subject {
            validate_handle_claim_subject(subject)?;
        }
        Ok(())
    }

    /// Canonical handle wire form, if any. R3.1 helper exported so
    /// soland / yougen / cotest all agree on the bytes used for
    /// signature / digest transcripts.
    pub fn handle_canonical(&self) -> Option<&str> {
        self.handle.as_ref().map(Handle::canonical)
    }
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
        // contrix:// URI form is no longer accepted (R3.1 wire rename).
        assert!(Handle::parse("contrix://example.com/users/alice").is_err());
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

    #[test]
    fn verified_requires_handle_and_expires() {
        let claim =
            HandleClaim { binding_state: Some(HandleBindingState::Verified), ..Default::default() };
        assert!(claim.validate().is_err());
    }

    #[test]
    fn member_delivery_binding_requires_audience() {
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_service_did: Did::new("did:web:rs.example".to_owned()).unwrap(),
                recipient_service_type: RecipientServiceType::PrincipalServer,
                binding_source: HandleHintBindingSource::Explicit,
                delivery_modes: BTreeSet::new(),
                service_acceptance_ref: None,
                policy_ref: None,
            }),
            expires_at: Some(Utc::now()),
            ..Default::default()
        };
        assert!(claim.validate().is_err());
    }
}
