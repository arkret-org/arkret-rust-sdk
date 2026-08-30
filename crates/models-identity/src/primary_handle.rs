//! R3.2 (arkret-spec @ b56cab1) — §3.2.1 primary handle selection,
//! `claim_digest(c)`, and §3.8.2 mention rendering.
//!
//! These helpers are shared across inkson / sodmin / soland / cotest so
//! every implementation agrees on the deterministic primary-handle
//! selection and the canonical claim digest. The DID-Document
//! `metadata.primary_handle` lookup (`holder_primary_handle_at_as_of`) is
//! injected via [`DidDocumentSnapshotResolver`] so the algorithm stays a
//! pure function of its inputs.
//!
//! This module is wasm-safe: it depends only on the identity-domain wire
//! shapes ([`Handle`], [`HandleClaim`], [`HandleBindingState`]) plus the
//! `arkret-wire` primitives (`Did`/`Error`/`Result`) and `arkret-canonical`
//! (JCS canonicalization + sha256), and pulls in no client / keystore /
//! salvo / MLS native-only dependency. The umbrella `arkret` crate re-exports
//! these symbols from `arkret::identity`, while wasm-only consumers (e.g.
//! sodmin) depend on this authoritative implementation directly instead of
//! mirroring the algorithm by hand.

use arkret_canonical::canonical;
use arkret_wire::{AccountId, DidCoreId, Result, WireError};
use chrono::{DateTime, Utc};

use crate::{Handle, HandleBindingState, HandleClaim};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleIssuerAuthorityClass {
    DomainAuthority,
    DelegatedIssuer,
    DirectoryMirror,
}

impl HandleIssuerAuthorityClass {
    fn priority(self) -> u8 {
        match self {
            Self::DomainAuthority => 0,
            Self::DelegatedIssuer => 1,
            Self::DirectoryMirror => 2,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleIssuerPolicyEntry {
    pub issuer_id: DidCoreId,
    pub authorized_handle_domains: Vec<String>,
    pub issuer_class: HandleIssuerAuthorityClass,
}

/// Hook that resolves the holder's preferred handle from the subject DID
/// Document `metadata.primary_handle` at a given `as_of`. Implementations
/// that resolve historical DID Document versions (e.g. `did:webvh`) MUST
/// return the value effective at `as_of`.
pub trait DidDocumentSnapshotResolver {
    fn resolve_metadata_primary_handle(
        &self,
        subject: &DidCoreId,
        as_of: &DateTime<Utc>,
    ) -> Result<Option<String>>;
}

/// Test/offline resolver: never returns a holder preference.
///
/// Production callers that support DID Document `metadata.primary_handle`
/// MUST inject a real [`DidDocumentSnapshotResolver`]. Using this resolver in
/// production deliberately disables the holder-flagged priority layer and
/// falls through to audience-match / most-recent selection.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHolderPreferenceResolver;

impl DidDocumentSnapshotResolver for NoHolderPreferenceResolver {
    fn resolve_metadata_primary_handle(
        &self,
        _subject: &DidCoreId,
        _as_of: &DateTime<Utc>,
    ) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Deterministic six-tuple input to [`select_primary_handle`].
///
/// `account_id` is the exact account being resolved. Candidate filtering
/// compares the complete pair; a matching principal on another server is a
/// different account.
pub struct PrimaryHandleSelectInput<'a> {
    pub account_id: &'a AccountId,
    /// Current resolution context — target Realm id or inviting service
    /// DID — matched against `claim.audience`. `None` means no audience
    /// constraint applies.
    pub context: Option<&'a str>,
    pub claim_set_snapshot: &'a [HandleClaim],
    /// Realm policy `handle_issuer_policies` in trust order. Claims whose issuer
    /// is absent or whose handle domain is outside the entry's declared scope
    /// are dropped in Step 0.
    pub handle_issuer_policies: &'a [HandleIssuerPolicyEntry],
    /// `metadata.primary_handle` value at `resolution_as_of` (already
    /// materialised from the DID Document snapshot). `None` skips the
    /// holder-flagged layer.
    pub holder_primary_handle_at_as_of: Option<&'a str>,
    pub resolution_as_of: DateTime<Utc>,
}

/// §3.2.1 — select the deterministic primary handle claim for a subject in
/// a context. Returns `None` when the candidate set is empty (the caller
/// MUST then follow the §3.8.2 unresolved fallback path).
pub fn select_primary_handle(input: &PrimaryHandleSelectInput<'_>) -> Option<HandleClaim> {
    // Step 0 — candidate pre-filter.
    let candidates: Vec<&HandleClaim> = input
        .claim_set_snapshot
        .iter()
        .filter(|c| candidate_passes_step0(c, input))
        .collect();
    if candidates.is_empty() {
        return None;
    }

    // Step 1 — priority layers.
    let layer: Vec<&HandleClaim> = {
        let audience_matched: Vec<&HandleClaim> = candidates
            .iter()
            .copied()
            .filter(|c| matches_audience(c, input.context))
            .collect();
        if !audience_matched.is_empty() {
            audience_matched
        } else {
            let holder_flagged: Vec<&HandleClaim> = candidates
                .iter()
                .copied()
                .filter(|c| holder_flagged(c, input.holder_primary_handle_at_as_of))
                .collect();
            if !holder_flagged.is_empty() {
                holder_flagged
            } else {
                // most-recent: all candidates compete on created_at.
                candidates.clone()
            }
        }
    };

    // Step 2 — deterministic tie-breaker.
    let winner = layer.into_iter().reduce(|best, candidate| {
        if tie_break_prefers(candidate, best, input.handle_issuer_policies) {
            candidate
        } else {
            best
        }
    })?;
    Some(winner.clone())
}

/// Convenience: run [`select_primary_handle`] and return only the
/// canonical handle string of the winning claim (if any). Admin / UI
/// views that just need "the handle to show" use this.
pub fn select_primary_handle_string(input: &PrimaryHandleSelectInput<'_>) -> Option<String> {
    select_primary_handle(input).map(|c| c.handle.canonical().to_owned())
}

fn candidate_passes_step0(c: &HandleClaim, input: &PrimaryHandleSelectInput<'_>) -> bool {
    if &c.subject_account_id != input.account_id {
        return false;
    }
    if c.binding_state != HandleBindingState::Verified {
        return false;
    }
    // created_at MUST be <= resolution_as_of. `created_at` is schema-required,
    // so it is always present on a parsed claim.
    if c.created_at > input.resolution_as_of {
        return false;
    }
    // expires_at MUST be > resolution_as_of.
    match c.expires_at {
        Some(expiry) if expiry > input.resolution_as_of => {}
        _ => return false,
    }
    // issuer trust filter (mandatory pre-filter).
    match policy_entry(c, input.handle_issuer_policies) {
        Some(_) => {}
        _ => return false,
    }
    // audience scope filter: present audience must equal context.
    if let Some(aud) = &c.audience {
        match input.context {
            Some(ctx) if ctx == aud => {}
            _ => return false,
        }
    }
    true
}

fn matches_audience(c: &HandleClaim, context: Option<&str>) -> bool {
    matches!((c.audience.as_deref(), context), (Some(a), Some(ctx)) if a == ctx)
}

fn holder_flagged(c: &HandleClaim, holder_primary: Option<&str>) -> bool {
    holder_primary.is_some_and(|preferred| c.handle.canonical() == preferred)
}

/// Returns `true` if `candidate` should win over `best` per the Step 2
/// tie-breaker ordering: authority class → handle_issuer_policies position →
/// created_at (later wins) → `claim_digest` (lexicographically smaller
/// wins).
fn tie_break_prefers(
    candidate: &HandleClaim,
    best: &HandleClaim,
    handle_issuer_policies: &[HandleIssuerPolicyEntry],
) -> bool {
    let cand_entry = policy_entry(candidate, handle_issuer_policies);
    let best_entry = policy_entry(best, handle_issuer_policies);
    let cand_class = cand_entry.map_or(u8::MAX, |(_, entry)| entry.issuer_class.priority());
    let best_class = best_entry.map_or(u8::MAX, |(_, entry)| entry.issuer_class.priority());
    if cand_class != best_class {
        return cand_class < best_class;
    }
    let cand_pos = cand_entry.map_or(usize::MAX, |(position, _)| position);
    let best_pos = best_entry.map_or(usize::MAX, |(position, _)| position);
    if cand_pos != best_pos {
        return cand_pos < best_pos;
    }
    let cand_created = candidate.created_at;
    let best_created = best.created_at;
    if cand_created != best_created {
        return cand_created > best_created;
    }
    match (claim_digest(candidate), claim_digest(best)) {
        (Ok(cd), Ok(bd)) => cd < bd,
        _ => false,
    }
}

fn policy_entry<'a>(
    claim: &HandleClaim,
    policy: &'a [HandleIssuerPolicyEntry],
) -> Option<(usize, &'a HandleIssuerPolicyEntry)> {
    let issuer = &claim.issuer_id;
    let handle = &claim.handle;
    policy
        .iter()
        .enumerate()
        .find(|(_, entry)| handle_issuer_policy_entry_authorizes(entry, issuer, handle))
}

/// Return whether one Realm handle-issuer policy entry authorizes this exact
/// issuer and canonical handle domain.
///
/// Directory and UI implementations use this same helper as primary-handle
/// selection so wildcard label-boundary handling cannot drift across layers.
pub fn handle_issuer_policy_entry_authorizes(
    entry: &HandleIssuerPolicyEntry,
    issuer: &DidCoreId,
    handle: &Handle,
) -> bool {
    entry.issuer_id == *issuer
        && entry
            .authorized_handle_domains
            .iter()
            .any(|pattern| domain_matches(pattern, handle.domain()))
}

fn domain_matches(pattern: &str, domain: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.';
    }
    domain == pattern
}

/// §3.2.1 — `claim_digest(c) = sha256:hex(sha256(JCS(semantic_projection(c))))`.
///
/// `semantic_projection` keeps only the canonical semantic fields and
/// excludes `proofs`, `verified_at`, `challenge` and any non-semantic
/// hint. Unordered-collection arrays (`handle_aliases`, `source_refs`,
/// are sorted before canonicalization; `claims` keeps issuer order (order is semantic).
pub fn claim_digest(claim: &HandleClaim) -> Result<String> {
    let mut value = serde_json::to_value(claim)
        .map_err(|e| WireError::Protocol(format!("claim_digest serialize: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        // Exclude non-semantic / hint fields.
        obj.remove("proofs");
        obj.remove("verified_at");
        obj.remove("challenge");
        // Sort unordered-collection arrays.
        sort_string_array(obj.get_mut("handle_aliases"));
        sort_string_array(obj.get_mut("source_refs"));
    }
    let bytes = canonical::canonical_json_bytes(&value)
        .map_err(|e| WireError::Protocol(format!("claim_digest canonicalize: {e}")))?;
    Ok(canonical::sha256_digest(bytes))
}

fn sort_string_array(slot: Option<&mut serde_json::Value>) {
    if let Some(serde_json::Value::Array(items)) = slot {
        items.sort_by(|a, b| {
            a.as_str()
                .unwrap_or_default()
                .cmp(b.as_str().unwrap_or_default())
        });
    }
}

/// Outcome of [`render_mention`], carrying the rendered label plus the
/// visual-degradation tier the UI MUST surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MentionRender {
    /// Resolved to a verified primary handle.
    Verified { handle: Handle },
    /// Served from a stale local cache (degraded).
    Cached { handle: Handle },
    /// Only the captured display name is available (degraded).
    NameOnly { name: String },
    /// Nothing resolved; UI shows a truncated exact account label (degraded).
    Unresolved { truncated_account_id: String },
}

/// §3.8.2 — render a mention from its authoritative exact account id.
///
/// `realm_scoped_claims` is the Realm-scoped projection snapshot
/// (effective MemberIdentity + roster handle-claim evidence). When the
/// projection yields a verified primary handle, that wins. Otherwise the
/// caller-supplied `cached_handle` / `display_name_at_time` drive the
/// degraded fallback ladder. `handle_at_time` is intentionally NOT used
/// as the current display value — it is audit metadata only.
pub fn render_mention(
    selection: &PrimaryHandleSelectInput<'_>,
    cached_handle: Option<&Handle>,
    display_name_at_time: Option<&str>,
) -> MentionRender {
    if let Some(claim) = select_primary_handle(selection) {
        return MentionRender::Verified {
            handle: claim.handle,
        };
    }
    if let Some(handle) = cached_handle {
        return MentionRender::Cached {
            handle: handle.clone(),
        };
    }
    if let Some(name) = display_name_at_time {
        return MentionRender::NameOnly {
            name: name.to_owned(),
        };
    }
    MentionRender::Unresolved {
        truncated_account_id: truncate_account_id(selection.account_id),
    }
}

/// Visual-degradation tier the UI MUST surface when rendering a subject.
/// Lighter-weight sibling of [`MentionRender`] for history / mention
/// surfaces that only need a label string (no cached-handle ladder).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectRender {
    /// Resolved to a verified primary handle via §3.2.1.
    Verified(String),
    /// Served from a captured display name (degraded).
    NameOnly(String),
    /// Nothing resolved; UI shows a truncated DID (degraded).
    Unresolved(String),
}

/// §3.8.2 — render an account from its authoritative `account_id`,
/// degrading through display name then a truncated exact-account label.
/// `display_name_at_time` is audit metadata used purely for the degraded
/// label.
pub fn render_subject(
    input: &PrimaryHandleSelectInput<'_>,
    display_name_at_time: Option<&str>,
) -> SubjectRender {
    if let Some(handle) = select_primary_handle_string(input) {
        return SubjectRender::Verified(handle);
    }
    if let Some(name) = display_name_at_time {
        return SubjectRender::NameOnly(name.to_owned());
    }
    SubjectRender::Unresolved(truncate_account_id(input.account_id))
}

fn truncate_account_id(account_id: &AccountId) -> String {
    truncate_did(&format!(
        "{}@{}",
        account_id.principal_id.as_str(),
        account_id.station_id.as_str()
    ))
}

fn truncate_did(did: &str) -> String {
    if did.chars().count() <= 16 {
        return did.to_owned();
    }
    let head: String = did.chars().take(10).collect();
    let tail_rev: Vec<char> = did.chars().rev().take(3).collect();
    let tail: String = tail_rev.into_iter().rev().collect();
    format!("{head}\u{2026}{tail}")
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidUrl, Hash, PayloadProof};

    use super::*;

    fn issuer(s: &str) -> DidCoreId {
        DidCoreId::new(s).unwrap()
    }

    fn issuer_policy(issuer_did: &str, domain: &str) -> HandleIssuerPolicyEntry {
        HandleIssuerPolicyEntry {
            issuer_id: issuer(issuer_did),
            authorized_handle_domains: vec![domain.to_owned()],
            issuer_class: HandleIssuerAuthorityClass::DomainAuthority,
        }
    }

    fn verified_claim(
        handle: &str,
        issuer_did: &str,
        created: DateTime<Utc>,
        expires: DateTime<Utc>,
        audience: Option<&str>,
    ) -> HandleClaim {
        HandleClaim {
            schema: HandleClaim::SCHEMA.to_owned(),
            handle: Handle::parse(handle).unwrap(),
            handle_aliases: Vec::new(),
            subject_account_id: subject(),
            issuer_id: DidCoreId::new(issuer_did).unwrap(),
            vouching_id: None,
            binding_state: HandleBindingState::Verified,
            claim_kind: None,
            visibility: None,
            audience: audience.map(str::to_owned),
            challenge: None,
            claim_scope: Default::default(),
            claims: Vec::new(),
            created_at: created,
            expires_at: Some(expires),
            verified_at: None,
            source_refs: Vec::new(),
            proofs: Vec::new(),
        }
    }

    fn subject() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver").unwrap(),
        )
    }

    fn placeholder_payload_proof() -> PayloadProof {
        PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:issuer.example#key-1").unwrap(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "placeholder".to_owned(),
        }
    }

    #[test]
    fn empty_candidate_set_returns_none() {
        let s = subject();
        let input = PrimaryHandleSelectInput {
            account_id: &s,
            context: None,
            claim_set_snapshot: &[],
            handle_issuer_policies: &[],
            holder_primary_handle_at_as_of: None,
            resolution_as_of: Utc::now(),
        };
        assert!(select_primary_handle(&input).is_none());
    }

    #[test]
    fn audience_match_wins_over_most_recent() {
        let now = Utc::now();
        let earlier = now - chrono::Duration::hours(2);
        let later = now - chrono::Duration::hours(1);
        let expires = now + chrono::Duration::days(30);
        let acc = vec![
            issuer_policy("ak:did_core:webvh:z6mkfixtureacme", "acme.example"),
            issuer_policy("ak:did_core:webvh:z6mkfixtureother", "other.example"),
        ];
        let s = subject();
        // older claim with matching audience vs newer claim without.
        let matching = verified_claim(
            "alice:acme.example",
            "ak:did_core:webvh:z6mkfixtureacme",
            earlier,
            expires,
            Some("ak:realm:r1"),
        );
        let newer = verified_claim(
            "alice:other.example",
            "ak:did_core:webvh:z6mkfixtureother",
            later,
            expires,
            None,
        );
        let snapshot = vec![newer, matching];
        let input = PrimaryHandleSelectInput {
            account_id: &s,
            context: Some("ak:realm:r1"),
            claim_set_snapshot: &snapshot,
            handle_issuer_policies: &acc,
            holder_primary_handle_at_as_of: None,
            resolution_as_of: now,
        };
        let chosen = select_primary_handle(&input).unwrap();
        assert_eq!(chosen.handle.canonical(), "alice:acme.example");
    }

    #[test]
    fn issuer_not_in_accepted_is_dropped() {
        let now = Utc::now();
        let expires = now + chrono::Duration::days(30);
        let s = subject();
        let claim = verified_claim(
            "alice:rogue.example",
            "ak:did_core:webvh:z6mkfixturerogue",
            now - chrono::Duration::hours(1),
            expires,
            None,
        );
        let snapshot = vec![claim];
        let input = PrimaryHandleSelectInput {
            account_id: &s,
            context: None,
            claim_set_snapshot: &snapshot,
            handle_issuer_policies: &[issuer_policy(
                "ak:did_core:webvh:z6mkfixtureacme",
                "acme.example",
            )],
            holder_primary_handle_at_as_of: None,
            resolution_as_of: now,
        };
        assert!(select_primary_handle(&input).is_none());
    }

    #[test]
    fn issuer_is_not_authorized_outside_its_declared_handle_domain() {
        let now = Utc::now();
        let snapshot = vec![verified_claim(
            "alice:rogue.example",
            "ak:did_core:webvh:z6mkfixtureacme",
            now - chrono::Duration::hours(1),
            now + chrono::Duration::days(30),
            None,
        )];
        let policy = vec![issuer_policy(
            "ak:did_core:webvh:z6mkfixtureacme",
            "acme.example",
        )];
        let s = subject();
        assert!(
            select_primary_handle(&PrimaryHandleSelectInput {
                account_id: &s,
                context: None,
                claim_set_snapshot: &snapshot,
                handle_issuer_policies: &policy,
                holder_primary_handle_at_as_of: None,
                resolution_as_of: now,
            })
            .is_none()
        );
    }

    #[test]
    fn claim_digest_stable_under_hint_mutation() {
        let now = Utc::now();
        let expires = now + chrono::Duration::days(30);
        let mut a = verified_claim(
            "alice:acme.example",
            "ak:did_core:webvh:z6mkfixtureacme",
            now,
            expires,
            None,
        );
        let mut b = a.clone();
        // Mutating non-semantic hint fields MUST NOT change the digest.
        a.verified_at = Some(now);
        a.challenge = Some("nonce-1".to_owned());
        a.proofs = vec![placeholder_payload_proof()];
        b.verified_at = Some(now - chrono::Duration::hours(5));
        b.challenge = Some("nonce-2".to_owned());
        b.proofs = vec![];
        assert_eq!(claim_digest(&a).unwrap(), claim_digest(&b).unwrap());
    }

    #[test]
    fn render_falls_back_to_name_then_did() {
        let s = subject();
        let input = PrimaryHandleSelectInput {
            account_id: &s,
            context: None,
            claim_set_snapshot: &[],
            handle_issuer_policies: &[],
            holder_primary_handle_at_as_of: None,
            resolution_as_of: Utc::now(),
        };
        // No claims, no cache → NameOnly when display name present.
        let r = render_mention(&input, None, Some("Alice Zhang"));
        assert_eq!(
            r,
            MentionRender::NameOnly {
                name: "Alice Zhang".to_owned()
            }
        );
        // Nothing at all → Unresolved.
        let r2 = render_mention(&input, None, None);
        assert!(matches!(r2, MentionRender::Unresolved { .. }));
    }

    #[test]
    fn render_subject_degrades_through_name_then_truncated_did() {
        let s = AccountId::new(
            DidCoreId::new("ak:did_core:webvh:averylongsubjectidentifier").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver").unwrap(),
        );
        let input = PrimaryHandleSelectInput {
            account_id: &s,
            context: None,
            claim_set_snapshot: &[],
            handle_issuer_policies: &[],
            holder_primary_handle_at_as_of: None,
            resolution_as_of: Utc::now(),
        };
        let named = render_subject(&input, Some("Alice"));
        assert_eq!(named, SubjectRender::NameOnly("Alice".to_owned()));
        match render_subject(&input, None) {
            SubjectRender::Unresolved(label) => assert!(label.contains('\u{2026}')),
            other => panic!("expected Unresolved, got {other:?}"),
        }
    }
}
