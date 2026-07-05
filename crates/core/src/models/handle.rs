use std::fmt;

use super::*;

/// Canonical Cokret handle string.
///
/// R3.1 wire form: `<localpart>:<domain>(:<port>)?` with lowercase
/// `localpart`. The previous `cokret://<domain>/users/<localpart>` URI
/// form has been retired (cokret-spec @ 7157ee8 — 2026-05-27).
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

pub(crate) fn is_valid_localpart(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    s.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '+' | '~' | '-')
    })
}

/// CKP R3 spec-sync (2026-05-27) — wire-level handle normalize check.
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
pub(crate) fn normalize_localpart_with_code(input: &str, code: &str) -> Result<String> {
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

pub(crate) fn is_valid_domain(s: &str) -> bool {
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

/// R3.2 — `ck.schema.handle_claim.v1.subject` validator.
///
/// The handle claim subject MUST be a holder / principal DID. It is NOT a
/// Realm `actor_id` (`ck:actor:`), a server-local `account_id`
/// (`ck:account:`), a service DID, an administrative identifier, or a
/// generic resource id. We accept any `did:<method>:...` and reject the
/// typed-id prefixes; a deployment-specific "is this a service DID"
/// distinction is left to the issuer, but the typed-id rejection here
/// catches the structural misuse the spec calls out.
///
/// On rejection returns [`Error::Protocol`] carrying the
/// `handle_claim_subject_not_principal_did` wire code prefix.
pub fn validate_handle_claim_subject(subject: &Did) -> Result<()> {
    let s = subject.as_str();
    if s.starts_with("ck:actor:") || s.starts_with("ck:account:") {
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleClaimKind {
    HandleBinding,
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
    pub policy_event_ref: Option<String>,
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
pub const HANDLE_CLAIM_SCHEMA: &str = "ck.schema.handle_claim.v1";

fn default_handle_claim_schema() -> String {
    HANDLE_CLAIM_SCHEMA.to_owned()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct HandleClaim {
    #[serde(default = "default_handle_claim_schema")]
    pub schema: String,
    /// Canonical handle `<localpart>:<domain>`. R3.1 wire rename from
    /// the prior `handle_uri` field name (cokret-spec @ 7157ee8).
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
    pub claim_kind: Option<HandleClaimKind>,
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
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
}

impl Default for HandleClaim {
    fn default() -> Self {
        Self {
            schema: default_handle_claim_schema(),
            handle: None,
            handle_aliases: Vec::new(),
            subject: None,
            issuer: None,
            issuer_service_did: None,
            binding_state: None,
            claim_kind: None,
            visibility: None,
            audience: None,
            challenge: None,
            claim_scope: BTreeMap::new(),
            member_delivery_binding: None,
            claims: Vec::new(),
            created_at: None,
            expires_at: None,
            verified_at: None,
            source_refs: Vec::new(),
            proofs: Vec::new(),
        }
    }
}

impl HandleClaim {
    /// Enforce schema `allOf` conditional required fields:
    ///   - `binding_state=verified` ⇒ `handle` + `expires_at`
    ///   - `member_delivery_binding` present ⇒ `handle` + `audience` + `expires_at`, and
    ///     binding_source != did_document_default (enforced by the [`HandleHintBindingSource`] type
    ///     itself).
    pub fn validate(&self) -> Result<()> {
        if matches!(self.binding_state, Some(HandleBindingState::Verified)) {
            if self.handle.is_none() {
                return Err(Error::Protocol(
                    "binding_state=verified requires handle".to_owned(),
                ));
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

    /// Validate a handle claim before it is consumed as a remote directory or
    /// Principal Server resolution result.
    pub fn validate_remote_resolution(
        &self,
        expected_audience: Option<&str>,
        expected_recipient_service_did: Option<&Did>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        if self.schema != HANDLE_CLAIM_SCHEMA {
            return Err(Error::Protocol("handle claim schema mismatch".to_owned()));
        }
        if self.handle.is_none() {
            return Err(Error::Protocol("handle claim requires handle".to_owned()));
        }
        if self.subject.is_none() {
            return Err(Error::Protocol("handle claim requires subject".to_owned()));
        }
        if self.issuer.as_deref().is_none_or(str::is_empty) {
            return Err(Error::Protocol("handle claim requires issuer".to_owned()));
        }
        if self.binding_state != Some(HandleBindingState::Verified) {
            return Err(Error::Protocol("handle claim must be verified".to_owned()));
        }
        let expires_at = self
            .expires_at
            .ok_or_else(|| Error::Protocol("handle claim requires expires_at".to_owned()))?;
        if expires_at <= now {
            return Err(Error::Protocol("handle claim expired".to_owned()));
        }
        if self.proofs.is_empty() {
            return Err(Error::Protocol("handle claim requires proof".to_owned()));
        }
        if let Some(expected_audience) = expected_audience {
            match self.audience.as_deref() {
                Some(audience) if audience == expected_audience => {}
                _ => {
                    return Err(Error::Protocol("handle claim audience mismatch".to_owned()));
                }
            }
        }
        if let Some(expected_recipient_service_did) = expected_recipient_service_did {
            match self.member_delivery_binding.as_ref() {
                Some(binding)
                    if &binding.recipient_service_did == expected_recipient_service_did => {}
                Some(_) => {
                    return Err(Error::Protocol(
                        "handle claim delivery binding mismatch".to_owned(),
                    ));
                }
                None => {
                    return Err(Error::Protocol(
                        "handle claim requires member_delivery_binding".to_owned(),
                    ));
                }
            }
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

    fn placeholder_payload_proof() -> PayloadProof {
        PayloadProof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:issuer.example#key-1".to_owned(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
            jws: "placeholder".to_owned(),
        }
    }

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
        // cokret:// URI form is no longer accepted (R3.1 wire rename).
        assert!(Handle::parse("cokret://example.com/users/alice").is_err());
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
        let claim = HandleClaim {
            binding_state: Some(HandleBindingState::Verified),
            ..Default::default()
        };
        assert!(claim.validate().is_err());
    }

    #[test]
    fn member_delivery_binding_requires_audience() {
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_service_did: Did::new("did:webvh:z6mkfixture:rs.example".to_owned())
                    .unwrap(),
                recipient_service_type: RecipientServiceType::PrincipalServer,
                binding_source: HandleHintBindingSource::Explicit,
                delivery_modes: BTreeSet::new(),
                service_acceptance_ref: None,
                policy_event_ref: None,
            }),
            expires_at: Some(Utc::now()),
            ..Default::default()
        };
        assert!(claim.validate().is_err());
    }

    #[test]
    fn handle_claim_serializes_current_wire_names_only() {
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            subject: Some(Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap()),
            issuer: Some("did:webvh:z6mkfixture:issuer.example".to_owned()),
            binding_state: Some(HandleBindingState::Verified),
            claim_kind: Some(HandleClaimKind::HandleBinding),
            created_at: Some(Utc::now()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            proofs: vec![placeholder_payload_proof()],
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_service_did: Did::new("did:webvh:z6mkfixture:rs.example".to_owned())
                    .unwrap(),
                recipient_service_type: RecipientServiceType::PrincipalServer,
                binding_source: HandleHintBindingSource::OrganizationPolicy,
                delivery_modes: BTreeSet::from([DeliveryMode::Events]),
                service_acceptance_ref: Some(
                    "ck:event:01890000-0000-7000-8000-000000000001".to_owned(),
                ),
                policy_event_ref: Some("ck:event:01890000-0000-7000-8000-000000000002".to_owned()),
            }),
            ..Default::default()
        };

        let value = serde_json::to_value(&claim).unwrap();
        assert_eq!(value["claim_kind"], "handle_binding");
        assert!(value.get("class").is_none());
        assert!(value.get("claim_type").is_none());
        assert!(value.get("issued_at").is_none());
        assert!(value["created_at"].is_string());
        assert_eq!(
            value["member_delivery_binding"]["policy_event_ref"],
            "ck:event:01890000-0000-7000-8000-000000000002"
        );
        assert!(value["member_delivery_binding"].get("policy_ref").is_none());
    }

    #[test]
    fn remote_resolution_requires_proof_audience_and_delivery_binding() {
        let audience = "ck:realm:01904100-0000-7000-8000-000000000001";
        let recipient = Did::new("did:webvh:z6mkfixture:rs.example".to_owned()).unwrap();
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            subject: Some(Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap()),
            issuer: Some("did:webvh:z6mkfixture:issuer.example".to_owned()),
            binding_state: Some(HandleBindingState::Verified),
            audience: Some(audience.to_owned()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_service_did: recipient.clone(),
                recipient_service_type: RecipientServiceType::PrincipalServer,
                binding_source: HandleHintBindingSource::OrganizationPolicy,
                delivery_modes: BTreeSet::from([DeliveryMode::Events]),
                service_acceptance_ref: None,
                policy_event_ref: None,
            }),
            proofs: vec![placeholder_payload_proof()],
            ..Default::default()
        };

        assert!(
            claim
                .validate_remote_resolution(Some(audience), Some(&recipient), Utc::now())
                .is_ok()
        );
        assert!(
            claim
                .validate_remote_resolution(
                    Some("did:webvh:z6mkfixture:other.example"),
                    Some(&recipient),
                    Utc::now(),
                )
                .is_err()
        );
        let mut unsigned = claim;
        unsigned.proofs.clear();
        assert!(
            unsigned
                .validate_remote_resolution(Some(audience), Some(&recipient), Utc::now())
                .is_err()
        );
    }
}
