//! R3.2 (cokret-spec @ b56cab1) — §3.2.1 primary handle selection,
//! `claim_digest(c)`, and §3.8.2 mention rendering.
//!
//! These helpers are shared across yougen / sodmin / soland / cotest so
//! every implementation agrees on the deterministic primary-handle
//! selection and the canonical claim digest. The DID-Document
//! `metadata.primary_handle` lookup (`holder_primary_handle_at_as_of`) is
//! injected via [`DidDocumentSnapshotResolver`] so the algorithm stays a
//! pure function of its inputs.
//!
//! This module is wasm-safe: it depends only on `cokret-core` primitives
//! (`canonical`, `models::{Handle, HandleClaim, HandleBindingState}`,
//! `Did`/`Error`/`Result`) and pulls in no client / keystore / salvo / MLS
//! native-only dependency. The umbrella `cokret` crate re-exports these
//! symbols from `cokret::identity` so existing SDK callers are unaffected,
//! and wasm-only consumers (e.g. sodmin) depend on this authoritative
//! implementation directly instead of mirroring the algorithm by hand.

use chrono::{DateTime, Utc};

use crate::models::{Handle, HandleBindingState, HandleClaim};
use crate::{Did, Error, Result, canonical};

/// Hook that resolves the holder's preferred handle from the subject DID
/// Document `metadata.primary_handle` at a given `as_of`. Implementations
/// that resolve historical DID Document versions (e.g. `did:webvh`) MUST
/// return the value effective at `as_of`.
pub trait DidDocumentSnapshotResolver {
    fn resolve_metadata_primary_handle(
        &self,
        subject: &Did,
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
        _subject: &Did,
        _as_of: &DateTime<Utc>,
    ) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Deterministic six-tuple input to [`select_primary_handle`].
///
/// `subject_id` is the holder/principal DID being resolved (authoritative
/// attribution key — never a Realm `actor_id`). It is carried as `&str`
/// because the selection algorithm never keys on it; it is read only by
/// the §3.8.2 render helpers for the degraded truncated-subject label,
/// which must tolerate any opaque subject string the caller holds.
pub struct PrimaryHandleSelectInput<'a> {
    pub subject_id: &'a str,
    /// Current resolution context — target Realm id or inviting service
    /// DID — matched against `claim.audience`. `None` means no audience
    /// constraint applies.
    pub context: Option<&'a str>,
    pub claim_set_snapshot: &'a [HandleClaim],
    /// Realm policy `accepted_issuers` in trust order (earlier == more
    /// trusted). Claims whose issuer is absent from this list are dropped
    /// in Step 0.
    pub accepted_issuers: &'a [String],
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
        if tie_break_prefers(candidate, best, input.accepted_issuers) {
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
    select_primary_handle(input).and_then(|c| c.handle.map(|h| h.canonical().to_owned()))
}

fn candidate_passes_step0(c: &HandleClaim, input: &PrimaryHandleSelectInput<'_>) -> bool {
    if !matches!(c.binding_state, Some(HandleBindingState::Verified)) {
        return false;
    }
    // created_at MUST be <= resolution_as_of.
    match c.created_at {
        Some(created) if created <= input.resolution_as_of => {}
        _ => return false,
    }
    // expires_at MUST be > resolution_as_of.
    match c.expires_at {
        Some(expiry) if expiry > input.resolution_as_of => {}
        _ => return false,
    }
    // issuer trust filter (mandatory pre-filter).
    match &c.issuer {
        Some(issuer) if input.accepted_issuers.iter().any(|i| i == issuer) => {}
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
    match (c.handle.as_ref(), holder_primary) {
        (Some(handle), Some(pref)) => handle.canonical() == pref,
        _ => false,
    }
}

/// Returns `true` if `candidate` should win over `best` per the Step 2
/// tie-breaker ordering: accepted_issuers position (earlier wins) →
/// created_at (later wins) → `claim_digest` (lexicographically smaller
/// wins).
fn tie_break_prefers(
    candidate: &HandleClaim,
    best: &HandleClaim,
    accepted_issuers: &[String],
) -> bool {
    let cand_pos = issuer_position(candidate, accepted_issuers);
    let best_pos = issuer_position(best, accepted_issuers);
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

fn issuer_position(c: &HandleClaim, accepted_issuers: &[String]) -> usize {
    match &c.issuer {
        Some(issuer) => accepted_issuers
            .iter()
            .position(|i| i == issuer)
            .unwrap_or(usize::MAX),
        None => usize::MAX,
    }
}

/// §3.2.1 — `claim_digest(c) = sha256:hex(sha256(JCS(semantic_projection(c))))`.
///
/// `semantic_projection` keeps only the canonical semantic fields and
/// excludes `proofs`, `verified_at`, `challenge` and any non-semantic
/// hint. Unordered-collection arrays (`handle_aliases`, `source_refs`,
/// `member_delivery_binding.delivery_modes`) are sorted before
/// canonicalization; `claims` keeps issuer order (order is semantic).
pub fn claim_digest(claim: &HandleClaim) -> Result<String> {
    let mut value = serde_json::to_value(claim)
        .map_err(|e| Error::Protocol(format!("claim_digest serialize: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        // Exclude non-semantic / hint fields.
        obj.remove("proofs");
        obj.remove("verified_at");
        obj.remove("challenge");
        // Sort unordered-collection arrays.
        sort_string_array(obj.get_mut("handle_aliases"));
        sort_string_array(obj.get_mut("source_refs"));
        if let Some(mdb) = obj
            .get_mut("member_delivery_binding")
            .and_then(|v| v.as_object_mut())
        {
            sort_string_array(mdb.get_mut("delivery_modes"));
        }
    }
    let bytes = canonical::canonical_json_bytes(&value)
        .map_err(|e| Error::Protocol(format!("claim_digest canonicalize: {e}")))?;
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
    /// Nothing resolved; UI shows a truncated DID (degraded).
    Unresolved { truncated_did: String },
}

/// §3.8.2 — render a mention from its authoritative `subject_id`.
///
/// `realm_scoped_claims` is the Realm-scoped projection snapshot
/// (effective MemberIdentity + roster handle-claim evidence). When the
/// projection yields a verified primary handle, that wins. Otherwise the
/// caller-supplied `cached_handle` / `display_name_at_time` drive the
/// degraded fallback ladder. `handle_at_time` is intentionally NOT used
/// as the current display value — it is audit metadata only.
pub fn render_mention(
    subject_id: &Did,
    selection: &PrimaryHandleSelectInput<'_>,
    cached_handle: Option<&Handle>,
    display_name_at_time: Option<&str>,
) -> MentionRender {
    if let Some(claim) = select_primary_handle(selection)
        && let Some(handle) = claim.handle
    {
        return MentionRender::Verified { handle };
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
        truncated_did: truncate_did(subject_id.as_str()),
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

/// §3.8.2 — render a subject from its authoritative `subject_id`,
/// degrading through display name then truncated DID. `subject_id` (via
/// `input.subject_id`) is the only authoritative attribution field;
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
    SubjectRender::Unresolved(truncate_did(input.subject_id))
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
    use super::*;
    use crate::models::Handle;

    fn issuer(s: &str) -> String {
        s.to_owned()
    }

    fn verified_claim(
        handle: &str,
        issuer_did: &str,
        created: DateTime<Utc>,
        expires: DateTime<Utc>,
        audience: Option<&str>,
    ) -> HandleClaim {
        HandleClaim {
            handle: Some(Handle::parse(handle).unwrap()),
            subject: Some(Did::new("did:web:alice.example".to_owned()).unwrap()),
            issuer: Some(issuer_did.to_owned()),
            binding_state: Some(HandleBindingState::Verified),
            audience: audience.map(str::to_owned),
            created_at: Some(created),
            expires_at: Some(expires),
            ..Default::default()
        }
    }

    fn subject() -> Did {
        Did::new("did:web:alice.example".to_owned()).unwrap()
    }

    #[test]
    fn empty_candidate_set_returns_none() {
        let s = subject();
        let input = PrimaryHandleSelectInput {
            subject_id: s.as_str(),
            context: None,
            claim_set_snapshot: &[],
            accepted_issuers: &[],
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
            issuer("did:web:acme.example"),
            issuer("did:web:other.example"),
        ];
        let s = subject();
        // older claim with matching audience vs newer claim without.
        let matching = verified_claim(
            "alice:acme.example",
            "did:web:acme.example",
            earlier,
            expires,
            Some("ck:realm:r1"),
        );
        let newer = verified_claim(
            "alice:other.example",
            "did:web:other.example",
            later,
            expires,
            None,
        );
        let snapshot = vec![newer, matching];
        let input = PrimaryHandleSelectInput {
            subject_id: s.as_str(),
            context: Some("ck:realm:r1"),
            claim_set_snapshot: &snapshot,
            accepted_issuers: &acc,
            holder_primary_handle_at_as_of: None,
            resolution_as_of: now,
        };
        let chosen = select_primary_handle(&input).unwrap();
        assert_eq!(chosen.handle.unwrap().canonical(), "alice:acme.example");
    }

    #[test]
    fn issuer_not_in_accepted_is_dropped() {
        let now = Utc::now();
        let expires = now + chrono::Duration::days(30);
        let s = subject();
        let claim = verified_claim(
            "alice:rogue.example",
            "did:web:rogue.example",
            now - chrono::Duration::hours(1),
            expires,
            None,
        );
        let snapshot = vec![claim];
        let input = PrimaryHandleSelectInput {
            subject_id: s.as_str(),
            context: None,
            claim_set_snapshot: &snapshot,
            accepted_issuers: &[issuer("did:web:acme.example")],
            holder_primary_handle_at_as_of: None,
            resolution_as_of: now,
        };
        assert!(select_primary_handle(&input).is_none());
    }

    #[test]
    fn claim_digest_stable_under_hint_mutation() {
        let now = Utc::now();
        let expires = now + chrono::Duration::days(30);
        let mut a = verified_claim(
            "alice:acme.example",
            "did:web:acme.example",
            now,
            expires,
            None,
        );
        let mut b = a.clone();
        // Mutating non-semantic hint fields MUST NOT change the digest.
        a.verified_at = Some(now);
        a.challenge = Some("nonce-1".to_owned());
        a.proofs = vec![serde_json::json!({"kind": "detached_jws"})];
        b.verified_at = Some(now - chrono::Duration::hours(5));
        b.challenge = Some("nonce-2".to_owned());
        b.proofs = vec![];
        assert_eq!(claim_digest(&a).unwrap(), claim_digest(&b).unwrap());
    }

    #[test]
    fn render_falls_back_to_name_then_did() {
        let s = subject();
        let input = PrimaryHandleSelectInput {
            subject_id: s.as_str(),
            context: None,
            claim_set_snapshot: &[],
            accepted_issuers: &[],
            holder_primary_handle_at_as_of: None,
            resolution_as_of: Utc::now(),
        };
        // No claims, no cache → NameOnly when display name present.
        let r = render_mention(&s, &input, None, Some("Alice Zhang"));
        assert_eq!(
            r,
            MentionRender::NameOnly {
                name: "Alice Zhang".to_owned()
            }
        );
        // Nothing at all → Unresolved.
        let r2 = render_mention(&s, &input, None, None);
        assert!(matches!(r2, MentionRender::Unresolved { .. }));
    }

    #[test]
    fn render_subject_degrades_through_name_then_truncated_did() {
        let s = Did::new("did:web:averylongsubjectidentifier.example".to_owned()).unwrap();
        let input = PrimaryHandleSelectInput {
            subject_id: s.as_str(),
            context: None,
            claim_set_snapshot: &[],
            accepted_issuers: &[],
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
