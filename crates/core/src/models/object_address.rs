//! R3.3 (CKP-0011, arkret-spec @ cced4b8) — client-agnostic shareable object
//! addressing grammar + invite-token target binding.
//!
//! A shareable address points at a Realm, a Strand inside a Realm, or a Message
//! inside a Strand. Three envelopes share ONE grammar:
//!
//! * logical id `ck:<kind>:<uuid>` — opaque, never carries via/action/token.
//! * `web+arkret:` URI scheme: `web+arkret:realm/<realm>/strand/<strand>/m/<msg>?action=view`
//! * HTTPS landing: `https://<landing>/#realm/.../strand/...?action=...` — everything AFTER the `#`
//!   is the SAME grammar as the `web+arkret:` form (strip the `https://<host>/#` shell, then reuse
//!   the same parser).
//!
//! ## Normative grammar rules
//! * PATH carries identity: keyword + bare uuid (the `ck:<kind>:` sigil is stripped). Hierarchy is
//!   fixed `realm/<r>` ⊃ `strand/<f>` ⊃ `m/<msg>`. The message seal keyword is exactly `m/`.
//! * The `<realm>` segment: a UUIDv7 textual form is a `realm_id`; otherwise it is an ALIAS
//!   (domain-style). `<strand>` and `<msg>` segments accept ONLY a bare uuid.
//! * Strand/Message addresses MUST carry `realm/<r>`. A global strand_id is never guessed. Retired
//!   `via` query hints are ignored.
//! * Unknown path keyword, wrong order, or a missing intermediate level fails closed. v1 legal
//!   keywords are ONLY `realm` / `strand` / `m`; an unknown keyword is always fail-closed
//!   (forward-compat, no fork).
//!
//! ## QUERY hints (never identity)
//! * `action=<view|join|reply>` — default `view`; pure UI hint, MUST NOT escalate permissions.
//! * `lt=<reference|invite|preview>` — omitted == `reference`.
//! * `tok=<opaque-token>` — present iff `lt=invite` or `lt=preview`.
//!
//! ## Token target binding (security-critical)
//! An `invite` token's signed payload MUST carry a [`TargetDescriptor`]. Its
//! digest [`target_digest`] covers ONLY the identity tuple + `link_type` and
//! NEVER `action` / `tok` / `lt`. Consequence: refreshing UI hints
//! does not invalidate the token, but switching to a different
//! Strand/Message necessarily changes the digest, so a token cannot be replayed
//! across objects (scope-confusion defence). See [`verify_token_target`].

use cokret_identifiers::is_lowercase_uuidv7;
use serde::{Deserialize, Serialize};

use crate::{Error, Result, canonical};

/// `web+arkret:` URI scheme prefix.
pub const WEB_ARKRET_SCHEME: &str = "web+arkret:";

/// Link type carried by an address. `reference` is the default and carries no
/// authorization; `invite` carries membership/join material; `preview` carries
/// only policy-limited pre-join preview authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum LinkType {
    Reference,
    Invite,
    Preview,
}

impl LinkType {
    /// Parse an `lt=` query value. Omitted/unknown values collapse to the
    /// strictest [`LinkType::Reference`] (fail-closed, never escalate).
    pub fn from_query(value: Option<&str>) -> Self {
        match value {
            Some("invite") => LinkType::Invite,
            Some("preview") => LinkType::Preview,
            // "reference", omitted, or anything else collapses to the
            // strictest reference.
            _ => LinkType::Reference,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            LinkType::Reference => "reference",
            LinkType::Invite => "invite",
            LinkType::Preview => "preview",
        }
    }
}

/// UI action hint. Pure presentation; MUST NOT escalate permissions. Default
/// [`AddressAction::View`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AddressAction {
    View,
    Join,
    Reply,
}

impl AddressAction {
    /// Parse an `action=` query value. Omitted/unknown → [`AddressAction::View`].
    pub fn from_query(value: Option<&str>) -> Self {
        match value {
            Some("join") => AddressAction::Join,
            Some("reply") => AddressAction::Reply,
            _ => AddressAction::View,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            AddressAction::View => "view",
            AddressAction::Join => "join",
            AddressAction::Reply => "reply",
        }
    }
}

/// The realm path segment: a UUIDv7 textual form resolves to a `realm_id`;
/// anything else (domain-style / contains `.`) is an opaque ALIAS that a
/// server must resolve to a canonical `realm_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmRef {
    /// Bare lowercase UUIDv7 (sigil-stripped `ck:realm:` identity).
    RealmId(String),
    /// Domain-style alias requiring server-side resolution.
    Alias(String),
}

impl RealmRef {
    /// Classify a `<realm>` path segment per the UUIDv7-vs-alias rule.
    pub fn parse(segment: &str) -> Self {
        if is_lowercase_uuidv7(segment) {
            RealmRef::RealmId(segment.to_owned())
        } else {
            RealmRef::Alias(segment.to_owned())
        }
    }

    /// The raw path-segment form (bare uuid or alias string) used when
    /// re-serializing the address.
    pub fn path_segment(&self) -> &str {
        match self {
            RealmRef::RealmId(value) | RealmRef::Alias(value) => value,
        }
    }
}

/// A parsed shareable address. `strand` / `message` are bare uuid strings (the
/// `ck:<kind>:` sigil is stripped on the wire).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedAddress {
    pub realm: RealmRef,
    /// Bare strand uuid; `Some` for strand + message targets.
    pub strand: Option<String>,
    /// Bare message uuid; `Some` only for message targets.
    pub message: Option<String>,
    pub action: AddressAction,
    pub link_type: LinkType,
    /// Opaque invite / preview token; present iff `link_type == Invite` or
    /// `link_type == Preview`.
    pub token: Option<String>,
}

impl ParsedAddress {
    /// The resolved [`TargetKind`](crate::models::TargetKind)-equivalent class.
    pub fn is_realm(&self) -> bool {
        self.strand.is_none()
    }

    pub fn is_strand(&self) -> bool {
        self.strand.is_some() && self.message.is_none()
    }

    pub fn is_message(&self) -> bool {
        self.message.is_some()
    }
}

fn protocol_err(reason: &str) -> Error {
    Error::Protocol(format!("object_address: {reason}"))
}

/// Split an address string into its `(path, query)` halves after stripping the
/// envelope shell. Accepts the `web+arkret:` scheme and the HTTPS-fragment
/// landing form. Returns the raw path (no leading `/`) and the raw query (no
/// leading `?`), both percent-encoded as received.
fn strip_shell(input: &str) -> Result<(String, String)> {
    let body = if let Some(rest) = input.strip_prefix(WEB_ARKRET_SCHEME) {
        // `web+arkret:realm/...` — opaque-path URI, no `//` authority.
        rest.trim_start_matches('/').to_owned()
    } else if input.starts_with("https://") || input.starts_with("http://") {
        // HTTPS landing: everything AFTER the first `#` is the same grammar.
        // A percent-encoded whole fragment is a non-canonical landing URL and
        // is rejected by the shared grammar parser instead of being guessed.
        let (_, fragment) = input
            .split_once('#')
            .ok_or_else(|| protocol_err("https landing missing '#' fragment"))?;
        fragment.trim_start_matches('/').to_owned()
    } else {
        return Err(protocol_err(
            "unrecognized address envelope (expected web+arkret: or https://.../#)",
        ));
    };

    let (path, query) = match body.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (body, String::new()),
    };
    if path.is_empty() {
        return Err(protocol_err("empty address path"));
    }
    Ok((path, query))
}

/// Parse the PATH half into the identity tuple, enforcing the fixed hierarchy
/// and fail-closed keyword rules.
fn parse_path(path: &str) -> Result<(RealmRef, Option<String>, Option<String>)> {
    let mut segments = path.split('/').filter(|s| !s.is_empty());

    // Level 0 MUST be `realm/<r>`.
    match segments.next() {
        Some("realm") => {}
        Some(other) => {
            return Err(protocol_err(&format!(
                "path must start with 'realm/'; got unknown/misordered keyword '{other}'"
            )));
        }
        None => return Err(protocol_err("empty path")),
    }
    let realm_seg = segments
        .next()
        .ok_or_else(|| protocol_err("missing realm identifier after 'realm/'"))?;
    if realm_seg == "strand" || realm_seg == "m" || realm_seg == "realm" {
        return Err(protocol_err(
            "missing realm identifier (found keyword in id slot)",
        ));
    }
    let realm = RealmRef::parse(realm_seg);

    // Optional level 1 `strand/<f>`.
    let mut strand = None;
    let mut message = None;
    match segments.next() {
        None => {}
        Some("strand") => {
            let strand_seg = segments
                .next()
                .ok_or_else(|| protocol_err("missing strand identifier after 'strand/'"))?;
            if !is_lowercase_uuidv7(strand_seg) {
                return Err(protocol_err(
                    "strand segment must be a bare lowercase uuidv7",
                ));
            }
            strand = Some(strand_seg.to_owned());

            // Optional level 2 `m/<msg>`.
            match segments.next() {
                None => {}
                Some("m") => {
                    let msg_seg = segments
                        .next()
                        .ok_or_else(|| protocol_err("missing message identifier after 'm/'"))?;
                    if !is_lowercase_uuidv7(msg_seg) {
                        return Err(protocol_err(
                            "message segment must be a bare lowercase uuidv7",
                        ));
                    }
                    message = Some(msg_seg.to_owned());
                }
                Some(other) => {
                    return Err(protocol_err(&format!(
                        "after strand, only 'm/' is legal; got '{other}' (unknown keyword / wrong order)"
                    )));
                }
            }
        }
        // `m/<msg>` without an intermediate `strand/` is a missing-level error.
        Some("m") => {
            return Err(protocol_err(
                "message seal 'm/' requires an intermediate 'strand/' level",
            ));
        }
        Some(other) => {
            return Err(protocol_err(&format!(
                "after realm, only 'strand/' is legal; got '{other}' (unknown keyword / wrong order)"
            )));
        }
    }

    // Any trailing segments are illegal (e.g. a 4th level, or a stray keyword).
    if segments.next().is_some() {
        return Err(protocol_err(
            "trailing path segments beyond realm/strand/m hierarchy",
        ));
    }

    Ok((realm, strand, message))
}

/// Minimal `application/x-www-form-urlencoded` query decoder for the hint set.
/// Valid `%XX` octets are decoded; malformed or truncated percent sequences are
/// left literal so link rewriters cannot change parsing by dropping bytes.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 3 <= bytes.len() => {
                let hex = |b: u8| -> Option<u8> {
                    match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    }
                };
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(query: &str) -> (AddressAction, LinkType, Option<String>) {
    let mut action_raw: Option<String> = None;
    let mut lt_raw: Option<String> = None;
    let mut tok: Option<String> = None;

    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, percent_decode(v)),
            None => (pair, String::new()),
        };
        match key {
            "action" => action_raw = Some(value),
            "lt" => lt_raw = Some(value),
            "tok" if !value.is_empty() => tok = Some(value),
            // `via` is retired as a client-derived routing hint. Empty tok,
            // unknown query keys (forward-compat for new hints), and
            // never-identity-bearing extras are ignored.
            _ => {}
        }
    }

    let action = AddressAction::from_query(action_raw.as_deref());
    let link_type = LinkType::from_query(lt_raw.as_deref());
    // `tok` is meaningful iff `lt=invite|preview`; drop a stray token on a
    // reference link so it can never be mistaken for authorization.
    let tok = if matches!(link_type, LinkType::Invite | LinkType::Preview) {
        tok
    } else {
        None
    };
    (action, link_type, tok)
}

/// Parse a shareable object address from EITHER the `web+arkret:` URI form or
/// the HTTPS-landing fragment form into a [`ParsedAddress`].
///
/// Fails closed on: unrecognized envelope, unknown/misordered path keyword, a
/// missing intermediate hierarchy level, a non-uuid strand/message segment, or a
/// Strand/Message address missing `realm/<r>`.
pub fn parse_address(input: &str) -> Result<ParsedAddress> {
    let (path, query) = strip_shell(input)?;
    let (realm, strand, message) = parse_path(&path)?;
    let (action, link_type, token) = parse_query(&query);

    Ok(ParsedAddress {
        realm,
        strand,
        message,
        action,
        link_type,
        token,
    })
}

/// Build a canonical `web+arkret:` address from its parts. `action` is emitted
/// only when non-default; `lt`/`tok` are emitted
/// only for invite / preview links.
pub fn build_address(parsed: &ParsedAddress) -> String {
    let mut out = String::from(WEB_ARKRET_SCHEME);
    out.push_str("realm/");
    out.push_str(parsed.realm.path_segment());
    if let Some(strand) = &parsed.strand {
        out.push_str("/strand/");
        out.push_str(strand);
        if let Some(message) = &parsed.message {
            out.push_str("/m/");
            out.push_str(message);
        }
    }

    out.push_str(&build_query(parsed));
    out
}

/// Build an HTTPS landing URL. The target + token live in the fragment, which
/// reuses the canonical `web+arkret:` grammar (sans scheme).
///
/// The caller supplies the deployment-owned landing URL. This helper appends
/// the canonical fragment grammar unchanged; accepted ids and query atoms are
/// ASCII-safe.
pub fn build_https_landing(landing: &str, parsed: &ParsedAddress) -> String {
    let host = landing.trim_end_matches('/');
    let mut fragment = String::from("realm/");
    fragment.push_str(parsed.realm.path_segment());
    if let Some(strand) = &parsed.strand {
        fragment.push_str("/strand/");
        fragment.push_str(strand);
        if let Some(message) = &parsed.message {
            fragment.push_str("/m/");
            fragment.push_str(message);
        }
    }
    fragment.push_str(&build_query(parsed));
    format!("{host}/#{fragment}")
}

/// Build the shared `?action=...&lt=...&tok=...` query suffix.
fn build_query(parsed: &ParsedAddress) -> String {
    let mut parts: Vec<String> = Vec::new();
    if parsed.action != AddressAction::View {
        parts.push(format!("action={}", parsed.action.as_str()));
    }
    if matches!(parsed.link_type, LinkType::Invite | LinkType::Preview) {
        parts.push(format!("lt={}", parsed.link_type.as_str()));
        if let Some(token) = &parsed.token {
            parts.push(format!("tok={token}"));
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

/// Wrap a bare uuid (or already-typed id) into a canonical `ck:<kind>:<uuid>`
/// identifier. Idempotent if the input already carries the prefix.
fn typed_id(prefix: &str, bare: &str) -> String {
    if bare.starts_with(prefix) {
        bare.to_owned()
    } else {
        format!("{prefix}{bare}")
    }
}

/// The canonical signed-payload target descriptor bound into an `invite` token.
///
/// Field presence is exact: `realm_id` + `link_type` always present; `strand_id`
/// only for strand/message targets; `message_id` only for message targets. Absent
/// hierarchy fields are OMITTED ENTIRELY (never serialized as `null`) so the
/// canonical-JSON digest does not drift. VALUES are typed canonical ids
/// (`ck:realm:<uuid>` etc.), never the bare path uuid or an alias string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct TargetDescriptor {
    pub realm_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    pub link_type: LinkType,
}

impl TargetDescriptor {
    /// Build a descriptor from a [`ParsedAddress`], rebuilding the bare path
    /// uuids into typed canonical ids.
    ///
    /// If the address used an ALIAS for the realm, `realm_id` is initialized to
    /// the alias string and MUST be replaced with the server-resolved canonical
    /// id via [`Self::set_realm_id`] before the descriptor is signed or its
    /// digest is computed — the digest is meaningless over an alias.
    pub fn from_parsed(parsed: &ParsedAddress) -> Self {
        let realm_id = match &parsed.realm {
            RealmRef::RealmId(uuid) => typed_id("ak:realm:", uuid),
            // Alias targets need directory resolution before signing. Keep the
            // alias placeholder here, then inject the canonical id via
            // `set_realm_id` before digesting/signing.
            RealmRef::Alias(alias) => alias.clone(),
        };
        TargetDescriptor {
            realm_id,
            strand_id: parsed.strand.as_deref().map(|f| typed_id("ak:strand:", f)),
            message_id: parsed
                .message
                .as_deref()
                .map(|m| typed_id("ak:message:", m)),
            link_type: parsed.link_type,
        }
    }

    /// Inject the server-resolved canonical `ck:realm:<uuid>` id (used when the
    /// address arrived as an alias). Idempotent prefix handling.
    pub fn set_realm_id(&mut self, realm_id: impl Into<String>) {
        let realm_id = realm_id.into();
        self.realm_id = typed_id("ak:realm:", &realm_id);
    }
}

/// `target_digest = "sha256:" + hex(sha256(JCS(target_descriptor)))`, computed
/// via the shared canonicalizer [`crate::canonical::canonical_sha256`].
///
/// The digest covers ONLY the identity tuple + `link_type`. It MUST NOT include
/// `via` / `action` / `tok` / `lt` or any query hint — those live outside the
/// descriptor entirely, so refreshing routing hints or changing the UI action
/// does NOT invalidate a token, while switching Strand/Message DOES.
pub fn target_digest(descriptor: &TargetDescriptor) -> Result<String> {
    canonical::canonical_sha256(descriptor)
}

/// Recompute the digest of `address` (under `effective_link_type`) and compare
/// it byte-for-byte against the digest of the token's signed descriptor.
///
/// This is the scope-confusion defence: a token minted for object A will fail
/// against an address that resolves to a different object B because the
/// identity tuple in the recomputed descriptor differs.
///
/// NOTE: this binds the *target* only; verifying the token's signature /
/// expiry / issuer is the caller's responsibility. When the address used an
/// alias, the caller MUST resolve and inject the realm_id (see
/// [`TargetDescriptor::set_realm_id`]) into the address-derived descriptor
/// before calling, or pass an address that already carries a uuid realm.
pub fn verify_token_target(
    token_descriptor: &TargetDescriptor,
    address: &ParsedAddress,
    effective_link_type: LinkType,
) -> bool {
    let mut expected = TargetDescriptor::from_parsed(address);
    // The token binds a specific link_type; compare under the effective one
    // rather than whatever the (untrusted) address query claimed.
    expected.link_type = effective_link_type;

    // If the address still carries an alias realm, we cannot honestly compare
    // identity — fail closed.
    if !expected.realm_id.starts_with("ak:realm:") {
        return false;
    }

    match (target_digest(token_descriptor), target_digest(&expected)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: &str = "01904100-0000-7000-8000-0000000000aa";
    const F: &str = "01904100-0000-7000-8000-0000000000bb";
    const F2: &str = "01904100-0000-7000-8000-0000000000cc";
    const M: &str = "01904100-0000-7000-8000-0000000000dd";
    const VIA: &str = "did:webvh:z6mkfixture:relay.example";

    fn realm_addr() -> ParsedAddress {
        ParsedAddress {
            realm: RealmRef::RealmId(R.to_owned()),
            strand: None,
            message: None,
            action: AddressAction::View,
            link_type: LinkType::Reference,
            token: None,
        }
    }

    #[test]
    fn parse_realm_address_uuid() {
        let parsed = parse_address(&format!("web+arkret:realm/{R}")).unwrap();
        assert_eq!(parsed.realm, RealmRef::RealmId(R.to_owned()));
        assert!(parsed.is_realm());
        assert_eq!(parsed.link_type, LinkType::Reference);
        assert_eq!(parsed.action, AddressAction::View);
    }

    #[test]
    fn parse_realm_address_alias() {
        let parsed = parse_address("web+arkret:realm/team.example.com").unwrap();
        assert_eq!(parsed.realm, RealmRef::Alias("team.example.com".to_owned()));
    }

    #[test]
    fn parse_strand_and_message_addresses() {
        let strand = parse_address(&format!("web+arkret:realm/{R}/strand/{F}")).unwrap();
        assert!(strand.is_strand());
        assert_eq!(strand.strand.as_deref(), Some(F));

        let msg = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}/m/{M}?action=reply"
        ))
        .unwrap();
        assert!(msg.is_message());
        assert_eq!(msg.message.as_deref(), Some(M));
        assert_eq!(msg.action, AddressAction::Reply);
    }

    #[test]
    fn retired_via_hint_is_ignored() {
        let parsed = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via=did:webvh:z6mkfixture:a&via=did:webvh:z6mkfixture:b"
        ))
        .unwrap();
        assert!(parsed.is_strand());
    }

    #[test]
    fn query_percent_decode_handles_complete_and_truncated_octets() {
        let parsed = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?lt=preview&tok=a%2Fb%25c%2"
        ))
        .unwrap();
        assert_eq!(parsed.token.as_deref(), Some("a/b%c%2"));
    }

    // ── Round-trip equivalence ──────────────────────────────────────────────

    #[test]
    fn web_cokret_roundtrip() {
        let parsed = parse_address(&format!("web+arkret:realm/{R}/strand/{F}/m/{M}")).unwrap();
        let rebuilt = build_address(&parsed);
        let reparsed = parse_address(&rebuilt).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn https_landing_equivalence() {
        let parsed =
            parse_address(&format!("web+arkret:realm/{R}/strand/{F}?action=join")).unwrap();
        let landing = build_https_landing("https://share.arkret.example", &parsed);
        assert!(landing.starts_with("https://share.arkret.example/#realm/"));
        // Everything after `#` is the same grammar → reparse yields the same
        // ParsedAddress as the web+arkret: form.
        let reparsed = parse_address(&landing).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn invite_link_roundtrip_carries_token() {
        let parsed = ParsedAddress {
            realm: RealmRef::RealmId(R.to_owned()),
            strand: Some(F.to_owned()),
            message: None,
            action: AddressAction::View,
            link_type: LinkType::Invite,
            token: Some("opaque-tok-123".to_owned()),
        };
        let built = build_address(&parsed);
        assert!(built.contains("lt=invite"));
        assert!(built.contains("tok=opaque-tok-123"));
        let reparsed = parse_address(&built).unwrap();
        assert_eq!(reparsed.link_type, LinkType::Invite);
        assert_eq!(reparsed.token.as_deref(), Some("opaque-tok-123"));
    }

    // ── Fail-closed cases ───────────────────────────────────────────────────

    #[test]
    fn unknown_keyword_fails_closed() {
        assert!(parse_address(&format!("web+arkret:space/{R}")).is_err());
        assert!(parse_address(&format!("web+arkret:realm/{R}/thread/{F}?via={VIA}")).is_err());
    }

    #[test]
    fn strand_or_message_without_via_is_valid() {
        assert!(parse_address(&format!("web+arkret:realm/{R}/strand/{F}")).is_ok());
        assert!(parse_address(&format!("web+arkret:realm/{R}/strand/{F}/m/{M}")).is_ok());
    }

    #[test]
    fn missing_intermediate_level_fails_closed() {
        // `m/` without a `strand/` level.
        assert!(parse_address(&format!("web+arkret:realm/{R}/m/{M}?via={VIA}")).is_err());
    }

    #[test]
    fn wrong_order_fails_closed() {
        assert!(parse_address(&format!("web+arkret:strand/{F}/realm/{R}?via={VIA}")).is_err());
    }

    #[test]
    fn non_uuid_strand_segment_fails_closed() {
        assert!(
            parse_address(&format!("web+arkret:realm/{R}/strand/not-a-uuid?via={VIA}")).is_err()
        );
    }

    #[test]
    fn https_without_fragment_fails_closed() {
        assert!(parse_address(&format!("https://share.example/realm/{R}")).is_err());
    }

    #[test]
    fn preview_link_type_round_trips_token() {
        let parsed = parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=preview")).unwrap();
        assert_eq!(parsed.link_type, LinkType::Preview);
        assert_eq!(parsed.token, None);
        let parsed2 = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?lt=preview&tok=xyz"
        ))
        .unwrap();
        assert_eq!(parsed2.link_type, LinkType::Preview);
        assert_eq!(parsed2.token.as_deref(), Some("xyz"));
    }

    // ── target_digest stability & scope confusion ───────────────────────────

    #[test]
    fn descriptor_uses_typed_ids_and_omits_absent_levels() {
        let parsed = realm_addr();
        let desc = TargetDescriptor::from_parsed(&parsed);
        assert_eq!(desc.realm_id, format!("ak:realm:{R}"));
        assert_eq!(desc.strand_id, None);
        assert_eq!(desc.message_id, None);
        // Absent levels MUST be omitted, not null.
        let json = serde_json::to_string(&desc).unwrap();
        assert!(!json.contains("null"));
        assert!(!json.contains("strand_id"));
        assert!(!json.contains("message_id"));
    }

    #[test]
    fn target_digest_ignores_via_action_tok_lt() {
        let base = parse_address(&format!("web+arkret:realm/{R}/strand/{F}")).unwrap();
        let hinted = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via=did:webvh:z6mkfixture:a&via=did:webvh:z6mkfixture:b&action=join"
        ))
        .unwrap();
        let d1 = target_digest(&TargetDescriptor::from_parsed(&base)).unwrap();
        let d2 = target_digest(&TargetDescriptor::from_parsed(&hinted)).unwrap();
        assert_eq!(d1, d2, "hints (via/action) must not change the digest");
        assert!(d1.starts_with("sha256:"));
    }

    #[test]
    fn target_digest_changes_when_object_changes() {
        let strand_a = parse_address(&format!("web+arkret:realm/{R}/strand/{F}")).unwrap();
        let strand_b = parse_address(&format!("web+arkret:realm/{R}/strand/{F2}")).unwrap();
        let msg = parse_address(&format!("web+arkret:realm/{R}/strand/{F}/m/{M}")).unwrap();
        let d_a = target_digest(&TargetDescriptor::from_parsed(&strand_a)).unwrap();
        let d_b = target_digest(&TargetDescriptor::from_parsed(&strand_b)).unwrap();
        let d_m = target_digest(&TargetDescriptor::from_parsed(&msg)).unwrap();
        assert_ne!(d_a, d_b, "switching strand must change the digest");
        assert_ne!(d_a, d_m, "promoting strand→message must change the digest");
    }

    #[test]
    fn verify_token_target_accepts_matching_object() {
        // Token minted for strand A (invite link).
        let addr_a =
            parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=invite&tok=t")).unwrap();
        let token_desc = {
            let mut d = TargetDescriptor::from_parsed(&addr_a);
            d.link_type = LinkType::Invite;
            d
        };
        assert!(verify_token_target(&token_desc, &addr_a, LinkType::Invite));
    }

    #[test]
    fn verify_token_target_rejects_scope_confusion_replay() {
        // Token minted for object A.
        let addr_a =
            parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=invite&tok=t")).unwrap();
        let token_desc = {
            let mut d = TargetDescriptor::from_parsed(&addr_a);
            d.link_type = LinkType::Invite;
            d
        };
        // Replayed onto a different object B (different strand).
        let addr_b =
            parse_address(&format!("web+arkret:realm/{R}/strand/{F2}?lt=invite&tok=t")).unwrap();
        assert!(
            !verify_token_target(&token_desc, &addr_b, LinkType::Invite),
            "A-object token must not validate against a B address"
        );
    }

    #[test]
    fn verify_token_target_fails_closed_on_alias_realm() {
        let alias_addr = parse_address(&format!(
            "web+arkret:realm/team.example.com/strand/{F}?lt=invite&tok=t"
        ))
        .unwrap();
        let token_desc = {
            let mut d = TargetDescriptor::from_parsed(&alias_addr);
            d.link_type = LinkType::Invite;
            d
        };
        // Without an injected canonical realm_id, comparison MUST fail closed.
        assert!(!verify_token_target(
            &token_desc,
            &alias_addr,
            LinkType::Invite
        ));
    }
}
