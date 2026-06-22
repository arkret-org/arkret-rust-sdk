//! Realm alias — human-readable address for a Realm.
//!
//! Spec source: `discovery/object-addressing.md` §3.3 (canonical grammar shared
//! with handle `identity/identity-handles.md` §3.1/§17).
//!
//! A realm alias is the realm-side counterpart of a user [`Handle`](super::Handle):
//!
//! * Canonical wire form is `<localpart>:<domain>` — the SAME grammar as a handle (lowercase ASCII
//!   localpart, ≥2-label domain). The canonical form carries NO sigil.
//! * The `#` share / mention sigil (`#general:acme.example`) is a display + input-routing
//!   affordance only; it is stripped before the wire form, exactly as the handle `@` sigil is.
//! * Realm alias and handle occupy DISJOINT namespaces — a realm alias resolves via `resolve_realm`
//!   to a `ck:realm:<uuid>`, a handle resolves via `resolve_handle` to a holder/principal DID. The
//!   same `<localpart>:<domain>` MAY therefore be both a handle and a realm alias; the protocol
//!   does NOT require global uniqueness across the two namespaces.
//!
//! Unlike [`Handle`](super::Handle), a realm alias has NO port form: it is a
//! Directory-resolved label, not a service address, so exactly one `:` separates
//! localpart and domain.

use std::fmt;

use super::handle::{is_valid_domain, normalize_localpart_with_code};
use super::*;

/// Wire error-code prefix carried when a realm alias fails the homograph /
/// confusable / mixed-script discipline (object-addressing.md §3.3). Mirrors
/// the handle `handle_homograph_forbidden` code and is registered in
/// `error-code-registry.json`.
pub const REALM_ALIAS_HOMOGRAPH_FORBIDDEN: &str = "realm_alias_homograph_forbidden";

/// Canonical Cokret realm alias string `<localpart>:<domain>`.
///
/// See the module docs for the namespace / sigil discipline. Construct via
/// [`RealmAlias::parse`] (canonical input) or [`RealmAlias::parse_display`]
/// (tolerates a leading `#` share sigil).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(try_from = "String", into = "String")]
pub struct RealmAlias {
    canonical: String,
    localpart: String,
    domain: String,
}

impl RealmAlias {
    /// Parse a canonical `<localpart>:<domain>` realm alias. Lowercases both
    /// segments and runs the shared localpart confusable / alphabet normalize.
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
            // Exactly one ':' — no port form (unlike handle).
            return Err(Error::Protocol(format!(
                "realm alias has too many ':' separators (no port form): {input}"
            )));
        }
        // Shares the handle localpart discipline: rejects zero-width / bidi /
        // confusable / out-of-alphabet, lowercases, bounds length. Carries the
        // realm-alias wire error code on rejection.
        let localpart = normalize_localpart_with_code(local, REALM_ALIAS_HOMOGRAPH_FORBIDDEN)?;
        let domain = domain_part.to_ascii_lowercase();
        if !is_valid_domain(&domain) {
            return Err(Error::Protocol(format!(
                "realm alias domain invalid: {input}"
            )));
        }
        let canonical = format!("{localpart}:{domain}");
        Ok(Self {
            canonical,
            localpart,
            domain,
        })
    }

    /// Parse from a display / share form, tolerating a single leading `#`
    /// share sigil and surrounding whitespace. The `#` is stripped before
    /// canonical parsing (it is never part of the wire form).
    pub fn parse_display(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let body = trimmed.strip_prefix('#').unwrap_or(trimmed);
        Self::parse(body)
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
    /// the realm-side counterpart of [`Handle::display`](super::Handle::display)
    /// (`@<localpart>:<domain>`).
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
    use super::*;

    #[test]
    fn parses_canonical_alias() {
        let a = RealmAlias::parse("general:acme.example").unwrap();
        assert_eq!(a.localpart(), "general");
        assert_eq!(a.domain(), "acme.example");
        assert_eq!(a.canonical(), "general:acme.example");
    }

    #[test]
    fn lowercases_segments() {
        let a = RealmAlias::parse("General:Acme.Example").unwrap();
        assert_eq!(a.canonical(), "general:acme.example");
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
        // Realm alias has NO port form (unlike handle).
        assert!(RealmAlias::parse("general:acme.example:8443").is_err());
    }

    #[test]
    fn rejects_confusable_localpart() {
        // Cyrillic 'е' (U+0435) in the localpart.
        assert!(RealmAlias::parse("gen\u{0435}ral:acme.example").is_err());
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
