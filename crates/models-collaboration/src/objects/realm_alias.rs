//! Realm alias — human-readable address for a Realm.
//!
//! Spec source: `discovery/object-addressing.md` §3.3 (canonical grammar shared
//! with handle `identity/identity-handles.md` §3.1/§17).
//!
//! A realm alias is the realm-side counterpart of a user
//! [`Handle`](arkret_models_identity::handle::Handle):
//!
//! * Canonical wire form is `<prepared-localpart>:<lowercase-A-label-domain>` — the same grammar as
//!   a handle. The canonical form carries no sigil.
//! * The `#` share / mention sigil (`#general:acme.example`) is a display + input-routing
//!   affordance only; it is stripped before the wire form, exactly as the handle `@` sigil is.
//! * Realm alias and handle occupy DISJOINT namespaces — a realm alias resolves via `resolve_realm`
//!   to a `ak:realm:<44-char-token>`, a handle resolves via `resolve_handle` to a holder/principal
//!   DID. The same `<localpart>:<domain>` MAY therefore be both a handle and a realm alias; the
//!   protocol does NOT require global uniqueness across the two namespaces.
//!
//! A realm alias has no port form; exactly one `:` separates localpart and domain.

use std::fmt;

use arkret_wire::{
    Result, WireError, prepare_handle_localpart, prepare_idna_domain,
    validate_canonical_handle_localpart, validate_canonical_idna_domain,
};
use serde::{Deserialize, Serialize};

/// Canonical Arkret realm alias string `<localpart>:<domain>`.
///
/// See the module docs for the namespace / sigil discipline. Construct via
/// [`RealmAlias::parse`] (canonical input) or [`RealmAlias::parse_display`]
/// (tolerates a leading `#` share sigil).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RealmAlias {
    canonical: String,
    localpart: String,
    domain: String,
}

impl RealmAlias {
    /// Parse an already-canonical `<localpart>:<domain>` realm alias.
    ///
    /// Rejects: the `#` / `@` sigils (they are not in the localpart alphabet),
    /// a port suffix (`a:b.c:8443` — realm alias has no port form), a bare host
    /// (`general` — missing `:<domain>`), and a single-label domain
    /// (`a:example` — domain needs ≥2 labels).
    pub fn parse(input: &str) -> Result<Self> {
        let mut parts = input.split(':');
        let local = parts
            .next()
            .ok_or_else(|| WireError::Protocol(format!("realm alias is empty: {input}")))?;
        let domain_part = parts.next().ok_or_else(|| {
            WireError::Protocol(format!("realm alias missing ':<domain>': {input}"))
        })?;
        if parts.next().is_some() {
            // Exactly one ':'; canonical human addresses never carry a port.
            return Err(WireError::Protocol(format!(
                "realm alias has too many ':' separators (no port form): {input}"
            )));
        }
        validate_canonical_handle_localpart(local)?;
        validate_canonical_idna_domain(domain_part)?;
        Ok(Self {
            canonical: input.to_owned(),
            localpart: local.to_owned(),
            domain: domain_part.to_owned(),
        })
    }

    /// Prepare a user-entered alias under a known issuing authority domain.
    ///
    /// Accepts a bare localpart (`general`) or a display / canonical form
    /// (`#general:acme.example`, `general:acme.example`). A full form naming a
    /// different domain is rejected: only the issuing authority may create
    /// aliases beneath its own domain, and silently rebinding the domain would
    /// mint an alias the authority never authorized.
    pub fn prepare_under_authority(input: &str, authority_domain: &str) -> Result<Self> {
        let trimmed = input.trim();
        let body = trimmed.strip_prefix('#').unwrap_or(trimmed).trim();
        let authority = prepare_idna_domain(authority_domain)?;
        let alias = if body.contains(':') {
            Self::prepare(body)?
        } else {
            Self::prepare(&format!("{body}:{authority}"))?
        };
        if alias.domain() != authority {
            return Err(WireError::Protocol(format!(
                "realm alias domain {} is not the issuing authority domain {authority}",
                alias.domain()
            )));
        }
        Ok(alias)
    }

    /// Prepare a user-entered alias into canonical wire form.
    pub fn prepare(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let body = trimmed.strip_prefix('#').unwrap_or(trimmed);
        let (local, domain) = body.split_once(':').ok_or_else(|| {
            WireError::Protocol(format!("realm alias missing ':<domain>': {input}"))
        })?;
        let localpart = prepare_handle_localpart(local)?;
        let domain = prepare_idna_domain(domain)?;
        Self::parse(&format!("{localpart}:{domain}"))
    }

    /// Parse from a display / share form, tolerating a single leading `#`
    /// share sigil and surrounding whitespace. The `#` is stripped before
    /// canonical parsing (it is never part of the wire form).
    pub fn parse_display(input: &str) -> Result<Self> {
        Self::prepare(input)
    }

    /// Canonical wire form `<localpart>:<domain>` (no sigil).
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn localpart(&self) -> &str {
        &self.localpart
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Derive the realm-alias issuing authority domain operated by a service
    /// DID, so a client and its Station agree on the exact bytes.
    ///
    /// The alias `<domain>` is the issuing authority, and a Realm's own
    /// authority signature is not evidence that a foreign domain authorized
    /// the claim
    /// (`discovery/object-addressing.md` §3.3). A deployment therefore issues
    /// aliases only beneath its own authority domain, which is the DID's host:
    ///
    /// * `did:web:<host>[:<path>…]` — the host is the first method-specific segment. `did:web`
    ///   percent-encodes a port as `%3A`, so a bare `:` always starts a path segment and is never
    ///   part of the host.
    /// * `did:webvh:<scid>:<host>[:<path>…]` — the SCID precedes the host.
    pub fn authority_domain_for_service(service_id: &str) -> Result<String> {
        let mut segments = service_id.split(':');
        if segments.next() != Some("did") {
            return Err(WireError::Protocol(format!(
                "realm alias authority is not a DID: {service_id}"
            )));
        }
        let method = segments
            .next()
            .filter(|method| !method.is_empty())
            .ok_or_else(|| {
                WireError::Protocol(format!(
                    "realm alias authority DID has no method: {service_id}"
                ))
            })?;
        let host = match method {
            "web" => segments.next(),
            // The SCID is method-specific data preceding the host.
            "webvh" => segments.nth(1),
            _ => {
                return Err(WireError::Protocol(format!(
                    "realm alias authority DID method {method} declares no host: {service_id}"
                )));
            }
        }
        .filter(|host| !host.is_empty())
        .ok_or_else(|| {
            WireError::Protocol(format!(
                "realm alias authority DID has no host: {service_id}"
            ))
        })?;
        // A did:web port is percent-encoded; an alias authority is host-only.
        let host = host.split_once("%3A").map_or(host, |(host, _)| host);
        prepare_idna_domain(host)
    }

    /// Display / share form `#<localpart>:<domain>` favoured for UI surfaces —
    /// the realm-side counterpart of
    /// [`Handle::display`](arkret_models_identity::handle::Handle::display) (`@<localpart>:
    /// <domain>`).
    pub fn display(&self) -> String {
        format!("#{}", self.canonical)
    }
}

impl fmt::Display for RealmAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl TryFrom<String> for RealmAlias {
    type Error = WireError;
    fn try_from(value: String) -> Result<Self> {
        RealmAlias::parse(&value)
    }
}

impl From<RealmAlias> for String {
    fn from(value: RealmAlias) -> Self {
        value.canonical
    }
}
