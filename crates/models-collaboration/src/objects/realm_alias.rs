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
//!   to a `ak:realm:<uuid>`, a handle resolves via `resolve_handle` to a holder/principal DID. The
//!   same `<localpart>:<domain>` MAY therefore be both a handle and a realm alias; the protocol
//!   does NOT require global uniqueness across the two namespaces.
//!
//! A realm alias has no port form; exactly one `:` separates localpart and domain.

use std::fmt;

use arkret_wire::{
    Error, Result, prepare_handle_localpart, prepare_idna_domain,
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
            .ok_or_else(|| Error::Protocol(format!("realm alias is empty: {input}")))?;
        let domain_part = parts
            .next()
            .ok_or_else(|| Error::Protocol(format!("realm alias missing ':<domain>': {input}")))?;
        if parts.next().is_some() {
            // Exactly one ':'; canonical human addresses never carry a port.
            return Err(Error::Protocol(format!(
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

    /// Prepare a user-entered alias into canonical wire form.
    pub fn prepare(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let body = trimmed.strip_prefix('#').unwrap_or(trimmed);
        let (local, domain) = body
            .split_once(':')
            .ok_or_else(|| Error::Protocol(format!("realm alias missing ':<domain>': {input}")))?;
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
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        RealmAlias::parse(&value)
    }
}

impl From<RealmAlias> for String {
    fn from(value: RealmAlias) -> Self {
        value.canonical
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::handle::Handle;

    use super::*;

    #[test]
    fn parses_canonical_alias() {
        let a = RealmAlias::parse("general:acme.example").unwrap();
        assert_eq!(a.localpart(), "general");
        assert_eq!(a.domain(), "acme.example");
        assert_eq!(a.canonical(), "general:acme.example");
    }

    #[test]
    fn preparation_lowercases_segments() {
        let a = RealmAlias::prepare("General:Acme.Example").unwrap();
        assert_eq!(a.canonical(), "general:acme.example");
        assert!(RealmAlias::parse("General:Acme.Example").is_err());
    }

    #[test]
    fn display_carries_hash_sigil() {
        let a = RealmAlias::parse("general:acme.example").unwrap();
        assert_eq!(a.display(), "#general:acme.example");
    }

    #[test]
    fn parse_display_strips_hash_sigil() {
        let a = RealmAlias::parse_display("#general:acme.example").unwrap();
        assert_eq!(a.canonical(), "general:acme.example");
        // Bare canonical (no sigil) is also accepted.
        let b = RealmAlias::parse_display("  general:acme.example  ").unwrap();
        assert_eq!(b.canonical(), "general:acme.example");
    }

    #[test]
    fn rejects_sigil_in_canonical_parse() {
        // `#`/`@` are not in the localpart alphabet, so canonical parse rejects
        // them — sigils only enter via parse_display.
        assert!(RealmAlias::parse("#general:acme.example").is_err());
        assert!(RealmAlias::parse("@general:acme.example").is_err());
    }

    #[test]
    fn rejects_bare_host_and_single_label_domain() {
        // Bare host (no localpart:domain split).
        assert!(RealmAlias::parse("general").is_err());
        // Single-label domain.
        assert!(RealmAlias::parse("general:example").is_err());
        // Empty localpart.
        assert!(RealmAlias::parse(":acme.example").is_err());
    }

    #[test]
    fn rejects_port_form() {
        // Realm aliases and handles have no port form.
        assert!(RealmAlias::parse("general:acme.example:8443").is_err());
    }

    #[test]
    fn accepts_internationalized_localpart() {
        let alias = RealmAlias::parse("项目:acme.example").unwrap();
        assert_eq!(alias.display(), "#项目:acme.example");
    }

    #[test]
    fn serde_roundtrip_via_string() {
        let a = RealmAlias::parse("team.eng:acme.example").unwrap();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"team.eng:acme.example\"");
        let back: RealmAlias = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn shares_grammar_with_handle_but_distinct_namespace() {
        // The SAME string is a valid handle AND a valid realm alias — the two
        // occupy disjoint namespaces (object-addressing.md §3.3), so their
        // canonical forms coincide while resolving to different object kinds.
        let alias = RealmAlias::parse("support:acme.example").unwrap();
        let handle = Handle::parse("support:acme.example").unwrap();
        assert_eq!(alias.canonical(), handle.canonical());
        // Display sigils differ: `#` for realm alias, `@` for handle.
        assert_eq!(alias.display(), "#support:acme.example");
        assert_eq!(handle.display(), "@support:acme.example");
    }
}
