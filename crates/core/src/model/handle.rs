use std::fmt;

use super::*;

/// Canonical Contrix-native handle URI.
///
/// Wire form: `contrix://<domain>(:<port>)?/users/<localpart>` with
/// lowercase `localpart`. Self-hosted single-user deployments use the
/// same shape; there is no bare-host or `acct:` canonical variant.
/// `acct:<localpart>@<domain>` is interop-only and lives in
/// [`HandleClaim::handle_aliases`].
///
/// Spec source: `handle-claim.schema.json#/$defs/handle_uri`
/// (commit 0a5ab85, 2026-05-19).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(try_from = "String", into = "String")]
pub struct HandleUri {
    canonical: String,
    localpart: String,
    domain: String,
    port: Option<u16>,
}

impl HandleUri {
    /// Parse a canonical `contrix://` handle URI. Lowercases the localpart.
    pub fn parse(input: &str) -> Result<Self> {
        let rest = input.strip_prefix("contrix://").ok_or_else(|| {
            Error::Protocol(format!("handle uri must start with contrix://: {input}"))
        })?;
        let (authority, path) = rest.split_once("/users/").ok_or_else(|| {
            Error::Protocol(format!("handle uri must contain /users/ path: {input}"))
        })?;
        if path.is_empty() {
            return Err(Error::Protocol(format!("handle uri localpart is empty: {input}")));
        }
        if path.contains('/') {
            return Err(Error::Protocol(format!(
                "handle uri localpart must not contain '/': {input}"
            )));
        }
        let localpart = path.to_ascii_lowercase();
        if !is_valid_localpart(&localpart) {
            return Err(Error::Protocol(format!("handle uri localpart invalid: {input}")));
        }
        let (domain, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                let port: u16 = port
                    .parse()
                    .map_err(|_| Error::Protocol(format!("handle uri port invalid: {input}")))?;
                (host.to_ascii_lowercase(), Some(port))
            }
            _ => (authority.to_ascii_lowercase(), None),
        };
        if !is_valid_domain(&domain) {
            return Err(Error::Protocol(format!("handle uri domain invalid: {input}")));
        }
        let canonical = match port {
            Some(p) => format!("contrix://{domain}:{p}/users/{localpart}"),
            None => format!("contrix://{domain}/users/{localpart}"),
        };
        Ok(Self { canonical, localpart, domain, port })
    }

    /// Build from `acct:<local>@<domain>` interop form. The result is the
    /// canonical `contrix://` URI; the original `acct:` string is intended
    /// to be carried separately as a handle alias.
    pub fn from_acct(acct: &str) -> Result<Self> {
        let rest = acct
            .strip_prefix("acct:")
            .ok_or_else(|| Error::Protocol(format!("acct uri must start with acct:: {acct}")))?;
        let (local, domain) = rest
            .rsplit_once('@')
            .ok_or_else(|| Error::Protocol(format!("acct uri must contain @: {acct}")))?;
        let synthesized = format!("contrix://{}/users/{}", domain, local.to_ascii_lowercase());
        Self::parse(&synthesized)
    }

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

impl fmt::Display for HandleUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl TryFrom<String> for HandleUri {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        HandleUri::parse(&value)
    }
}

impl From<HandleUri> for String {
    fn from(value: HandleUri) -> Self {
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

fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
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

/// Class of handle being asserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandleClass {
    UserHandle,
    OrganizationHandle,
    ServiceHandle,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct HandleClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_uri: Option<HandleUri>,
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
    pub service_acceptance_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
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
    ///   - `binding_state=verified` ⇒ `handle_uri` + `expires_at`
    ///   - `member_delivery_binding` present ⇒ `handle_uri` + `audience` +
    ///     `expires_at`, and binding_source != did_document_default
    ///     (enforced by the [`HandleHintBindingSource`] type itself).
    pub fn validate(&self) -> Result<()> {
        if matches!(self.binding_state, Some(HandleBindingState::Verified)) {
            if self.handle_uri.is_none() {
                return Err(Error::Protocol(
                    "binding_state=verified requires handle_uri".to_owned(),
                ));
            }
            if self.expires_at.is_none() {
                return Err(Error::Protocol(
                    "binding_state=verified requires expires_at".to_owned(),
                ));
            }
        }
        if self.member_delivery_binding.is_some() {
            if self.handle_uri.is_none() || self.audience.is_none() || self.expires_at.is_none() {
                return Err(Error::Protocol(
                    "member_delivery_binding present requires handle_uri, audience, expires_at"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_uri() {
        let h = HandleUri::parse("contrix://example.com/users/alice").unwrap();
        assert_eq!(h.localpart(), "alice");
        assert_eq!(h.domain(), "example.com");
        assert_eq!(h.canonical(), "contrix://example.com/users/alice");
    }

    #[test]
    fn lowercases_localpart() {
        let h = HandleUri::parse("contrix://example.com/users/Alice").unwrap();
        assert_eq!(h.localpart(), "alice");
        assert_eq!(h.canonical(), "contrix://example.com/users/alice");
    }

    #[test]
    fn rejects_bare_host() {
        assert!(HandleUri::parse("contrix://example.com").is_err());
        assert!(HandleUri::parse("user:domain").is_err());
        assert!(HandleUri::parse("acct:alice@example.com").is_err());
    }

    #[test]
    fn from_acct_normalises_to_canonical() {
        let h = HandleUri::from_acct("acct:Bob@example.com").unwrap();
        assert_eq!(h.canonical(), "contrix://example.com/users/bob");
        assert_eq!(h.to_acct(), "acct:bob@example.com");
    }

    #[test]
    fn verified_requires_uri_and_expires() {
        let claim =
            HandleClaim { binding_state: Some(HandleBindingState::Verified), ..Default::default() };
        assert!(claim.validate().is_err());
    }

    #[test]
    fn member_delivery_binding_requires_audience() {
        let claim = HandleClaim {
            handle_uri: Some(HandleUri::parse("contrix://example.com/users/alice").unwrap()),
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

impl Default for HandleClaim {
    fn default() -> Self {
        Self {
            handle_uri: None,
            handle_aliases: Vec::new(),
            subject: None,
            issuer: None,
            issuer_service_did: None,
            binding_state: None,
            class: None,
            visibility: None,
            audience: None,
            challenge: None,
            claim_scope: BTreeMap::new(),
            service_acceptance_ref: None,
            policy_ref: None,
            member_delivery_binding: None,
            claims: Vec::new(),
            issued_at: None,
            expires_at: None,
            verified_at: None,
            source_refs: Vec::new(),
            proofs: Vec::new(),
        }
    }
}
