//! Canonical computation of the two `did-usage-and-verification.md` §5 digest
//! fields — `policy_digest` and `evidence_digest`.
//!
//! # Why this module exists
//!
//! §5 mandates both fields but defines **no algorithm** for either. Five
//! services therefore grew five incompatible implementations
//! (`arkret-work/review/spec-open/2026-07-31-binding-digest-fields-have-no-canonical-computation.
//! md`). Two failure modes are worth naming, because this module is shaped to make
//! both unrepresentable:
//!
//! 1. **Same input, different digest.** Two repos digested the *same five fields* of the *same*
//!    [`ResolverPolicy`] through the *same* canonical encoder and still disagreed, because one
//!    wrote `"fail_closed"` by hand and the other wrote `format!("{:?}", fail_mode)` →
//!    `"FailClosed"`. Here the encoding is explicit and comes from [`ResolverFailMode::as_str`]; no
//!    [`Debug`] output ever reaches a digest.
//! 2. **Evidence that carries no evidence.** One repo's `evidence_digest` was a constant plus the
//!    DID; another set `evidence_digest = document_digest` verbatim. Both satisfied a "records an
//!    evidence digest" acceptance criterion while committing to nothing. [`EvidenceEnvelope`]
//!    always binds `document_digest` **and** `policy_digest`, so the degenerate cases are no longer
//!    reachable through this API.
//!
//! # Layering: interoperable core, deployment-local extensions
//!
//! A single fixed field list cannot work — deployments legitimately differ
//! (one gates on `development_mode`, another on a delegated resolver endpoint
//! and a document size cap). Both digests therefore have a **closed core** the
//! SDK owns and an **open extension map** the deployment owns:
//!
//! | digest | core (SDK) | extensions (deployment) |
//! | --- | --- | --- |
//! | [`policy_digest`] | every [`ResolverPolicy`] field + [`POLICY_DIGEST_VERSION`] | `deployment` object |
//! | [`EvidenceEnvelope::digest`] | `document_digest`, `policy_digest`, `method_proofs` + [`EVIDENCE_DIGEST_VERSION`] | `method` object |
//!
//! Two deployments with equal policies and empty extensions produce the **same**
//! `policy_digest`; any extension change still changes it, so §5's "policy
//! revision invalidates affected bindings" keeps holding structurally (the
//! digest is a [`VerifiedDidBindingKey`](crate::VerifiedDidBindingKey)
//! dimension, so a changed digest makes old acceptances unreachable).
//!
//! # Operator kill switch
//!
//! [`POLICY_DIGEST_VERSION`] retires every binding across all repos when the SDK
//! encoding changes. For a *deployment-local* one-step retirement without an SDK
//! release, use [`PolicyDigestInput::with_deployment_epoch`].

use std::collections::BTreeMap;

use arkret_canonical::canonical;
use arkret_wire::Hash;
use serde_json::{Map, Value};

use crate::binding::{BindingError, document_canonical_digest};
use crate::{DidDocument, ResolverPolicy};

// ============================================================================
// Version constants
// ============================================================================

/// Version tag folded into every [`policy_digest`].
///
/// Bumping it changes every `policy_digest`, which changes every
/// [`VerifiedDidBindingKey`](crate::VerifiedDidBindingKey), which retires every
/// stored acceptance in one step. Bump it whenever the canonical encoding below
/// changes in any way — adding a core field, renaming one, or changing a token.
pub const POLICY_DIGEST_VERSION: &str = "ak.did.resolver_policy.v1";

/// Version tag folded into every [`EvidenceEnvelope`] digest.
pub const EVIDENCE_DIGEST_VERSION: &str = "ak.did.binding_evidence.v1";

// ============================================================================
// Errors
// ============================================================================

/// Failures of a canonical digest computation.
///
/// Deliberately a `Result` rather than a silent fallback: two of the five
/// pre-existing implementations degraded a canonicalization failure into
/// `unwrap_or_default()` (hashing empty bytes) or `expect()` (a panic on a code
/// path a peer can reach). Neither is acceptable for a value that keys a trust
/// store.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DigestError {
    /// The canonical JSON encoding failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    /// The computed digest is not a valid [`Hash`].
    #[error("computed digest is invalid: {0}")]
    InvalidDigest(String),
}

impl From<DigestError> for BindingError {
    fn from(error: DigestError) -> Self {
        match error {
            DigestError::Canonicalization(reason) => Self::Canonicalization(reason),
            DigestError::InvalidDigest(reason) => Self::InvalidDigest(reason),
        }
    }
}

fn digest_of(value: &Value) -> Result<Hash, DigestError> {
    let bytes = canonical::canonical_json_bytes(value)
        .map_err(|error| DigestError::Canonicalization(error.to_string()))?;
    Hash::new(canonical::sha256_digest(bytes))
        .map_err(|error| DigestError::InvalidDigest(error.to_string()))
}

// ============================================================================
// Normalization
// ============================================================================

/// Normalize a DID method reference to the canonical `did:<method>:` prefix
/// form.
///
/// Accepts every spelling observed across the downstream repos — `"web"`,
/// `"did:web"`, `"did:web:"` — and maps all three onto `"did:web:"`, so a
/// deployment that stores bare method names and one that stores prefixes agree
/// on the digest. An empty / whitespace-only token normalizes to `"did:"` and is
/// kept (rather than silently dropped) so a misconfiguration stays visible in
/// the digest instead of being erased by it.
pub fn normalize_did_method_prefix(method: &str) -> String {
    let trimmed = method.trim();
    let prefixed = if trimmed.starts_with("did:") {
        trimmed.to_owned()
    } else {
        format!("did:{trimmed}")
    };
    if prefixed.ends_with(':') {
        prefixed
    } else {
        format!("{prefixed}:")
    }
}

/// Sort + dedup a normalized token list.
///
/// Reordering a config list is not a policy change and MUST NOT retire every
/// binding; adding or removing an entry is and MUST.
fn normalized_method_set(methods: &[String]) -> Vec<String> {
    let mut out = methods
        .iter()
        .map(|method| normalize_did_method_prefix(method))
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn trimmed_set(values: &[String]) -> Vec<String> {
    let mut out = values
        .iter()
        .map(|value| value.trim().to_owned())
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn string_array(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}

fn extension_object(extensions: &BTreeMap<String, Value>) -> Value {
    Value::Object(
        extensions
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Map<String, Value>>(),
    )
}

// ============================================================================
// policy_digest
// ============================================================================

/// Canonical input to [`policy_digest`]: the SDK-owned [`ResolverPolicy`] core
/// plus deployment-local dimensions.
///
/// ```
/// # use arkret_identity::binding_digest::PolicyDigestInput;
/// # use arkret_identity::ResolverPolicy;
/// let policy = ResolverPolicy::default();
/// let digest = PolicyDigestInput::new(&policy)
///     .with_extension("development_mode", false)
///     .with_extension("allow_private_networks", false)
///     .digest()
///     .expect("policy digest");
/// assert!(digest.as_str().starts_with("sha256:"));
/// ```
#[derive(Clone, Debug)]
pub struct PolicyDigestInput<'a> {
    resolver_policy: &'a ResolverPolicy,
    deployment_extensions: BTreeMap<String, Value>,
    deployment_epoch: Option<String>,
}

impl<'a> PolicyDigestInput<'a> {
    /// Digest input covering only the interoperable [`ResolverPolicy`] core.
    pub fn new(resolver_policy: &'a ResolverPolicy) -> Self {
        Self {
            resolver_policy,
            deployment_extensions: BTreeMap::new(),
            deployment_epoch: None,
        }
    }

    /// Add one deployment-local policy dimension.
    ///
    /// Every switch that can change whether a resolution is admissible belongs
    /// here — a private-network allowance, a delegated resolver endpoint, a
    /// document size cap, a development-mode flag. Anything omitted is a switch
    /// that can flip without retiring the bindings it affected.
    #[must_use]
    pub fn with_extension(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.deployment_extensions.insert(key.into(), value.into());
        self
    }

    /// Add several deployment-local dimensions at once.
    #[must_use]
    pub fn with_extensions(
        mut self,
        extensions: impl IntoIterator<Item = (String, Value)>,
    ) -> Self {
        self.deployment_extensions.extend(extensions);
        self
    }

    /// Set the operator-controlled epoch tag.
    ///
    /// This is the deployment-local counterpart of [`POLICY_DIGEST_VERSION`]:
    /// changing it retires every binding in this deployment in one step,
    /// without waiting for an SDK release. Use it for incident response
    /// ("distrust everything accepted before now"), not for routine config.
    #[must_use]
    pub fn with_deployment_epoch(mut self, epoch: impl Into<String>) -> Self {
        self.deployment_epoch = Some(epoch.into());
        self
    }

    /// The policy this input digests.
    pub fn resolver_policy(&self) -> &ResolverPolicy {
        self.resolver_policy
    }

    /// The deployment-local dimensions recorded so far.
    pub fn deployment_extensions(&self) -> &BTreeMap<String, Value> {
        &self.deployment_extensions
    }

    /// The canonical object this input digests.
    ///
    /// Exposed so a deployment can log or diff exactly what its digest commits
    /// to — the review entry's core complaint was that the inputs were
    /// invisible and therefore uncomparable across repos.
    pub fn canonical_value(&self) -> Value {
        let policy = self.resolver_policy;
        let mut object = Map::new();
        object.insert(
            "version".to_owned(),
            Value::String(POLICY_DIGEST_VERSION.to_owned()),
        );
        object.insert(
            "allowed_methods".to_owned(),
            string_array(normalized_method_set(&policy.allowed_methods)),
        );
        object.insert(
            "default_principal_method".to_owned(),
            match &policy.default_principal_method {
                Some(method) => Value::String(normalize_did_method_prefix(method)),
                None => Value::Null,
            },
        );
        object.insert(
            "trust_roots".to_owned(),
            string_array(trimmed_set(&policy.trust_roots)),
        );
        object.insert(
            "ttl_seconds".to_owned(),
            match policy.ttl {
                Some(ttl) => Value::from(ttl.num_seconds()),
                None => Value::Null,
            },
        );
        // Explicit closed token, never `format!("{:?}", ..)`.
        object.insert(
            "fail_mode".to_owned(),
            Value::String(policy.fail_mode.as_str().to_owned()),
        );
        object.insert(
            "deployment".to_owned(),
            extension_object(&self.deployment_extensions),
        );
        if let Some(epoch) = &self.deployment_epoch {
            object.insert("deployment_epoch".to_owned(), Value::String(epoch.clone()));
        }
        Value::Object(object)
    }

    /// SHA-256 over the canonical JSON encoding of [`Self::canonical_value`].
    pub fn digest(&self) -> Result<Hash, DigestError> {
        digest_of(&self.canonical_value())
    }
}

/// Canonical `policy_digest` of a [`ResolverPolicy`] with no deployment-local
/// dimensions.
///
/// Use [`PolicyDigestInput`] directly when the deployment has extra switches;
/// omitting a switch that gates admissibility means a change to it will not
/// retire the bindings it affected.
pub fn policy_digest(resolver_policy: &ResolverPolicy) -> Result<Hash, DigestError> {
    PolicyDigestInput::new(resolver_policy).digest()
}

// ============================================================================
// evidence envelope
// ============================================================================

/// Canonical evidence envelope behind a binding's `evidence_digest`
/// (`did-usage-and-verification.md` §5: "method evidence 与 resolver / Realm
/// policy 的绑定").
///
/// The core is three-part and method-agnostic:
///
/// | member | meaning |
/// | --- | --- |
/// | `document_digest` | the pinned document the acceptance rests on |
/// | `method_proofs` | the method-specific proof set (webvh log head + witness set, controller proof bundle...); `[]` for methods that publish none |
/// | `policy_digest` | the resolver / Realm policy in force |
///
/// A method with no proof set degrades to a commitment over
/// `document_digest` + `policy_digest` — which is *stronger* than either
/// pre-existing degenerate form, because a policy change now changes the
/// evidence digest too, and the value is no longer byte-identical to
/// `document_digest`.
///
/// `method` carries deployment / method-specific material (resolution source,
/// a locally verified binding flag, a service kind, a source key-state digest).
/// Anything that is not itself JSON — raw key bytes, for instance — should be
/// hashed first and carried as its digest string.
///
/// ```
/// # use arkret_identity::binding_digest::EvidenceEnvelope;
/// # use arkret_wire::Hash;
/// # let document_digest = Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
/// # let policy_digest = Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap();
/// let digest = EvidenceEnvelope::new(document_digest, policy_digest)
///     .with_extension("source", "shared_resolver_chain")
///     .digest()
///     .expect("evidence digest");
/// assert!(digest.as_str().starts_with("sha256:"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceEnvelope {
    document_digest: Hash,
    policy_digest: Hash,
    method_proofs: Vec<Value>,
    method_extensions: BTreeMap<String, Value>,
}

impl EvidenceEnvelope {
    /// Envelope over an already-computed document digest.
    pub fn new(document_digest: Hash, policy_digest: Hash) -> Self {
        Self {
            document_digest,
            policy_digest,
            method_proofs: Vec::new(),
            method_extensions: BTreeMap::new(),
        }
    }

    /// Envelope over a resolved document, computing the canonical document
    /// digest here so it cannot disagree with the one the binding pins.
    pub fn for_document(document: &DidDocument, policy_digest: Hash) -> Result<Self, DigestError> {
        let document_digest = document_canonical_digest(document).map_err(|error| match error {
            BindingError::InvalidDigest(reason) => DigestError::InvalidDigest(reason),
            other => DigestError::Canonicalization(other.to_string()),
        })?;
        Ok(Self::new(document_digest, policy_digest))
    }

    /// Append one method-specific proof.
    ///
    /// Order is preserved and significant: a proof set is a sequence (a webvh
    /// log chain is ordered), so this is not sorted behind the caller's back.
    #[must_use]
    pub fn with_method_proof(mut self, proof: impl Into<Value>) -> Self {
        self.method_proofs.push(proof.into());
        self
    }

    /// Append several method-specific proofs, preserving order.
    #[must_use]
    pub fn with_method_proofs(mut self, proofs: impl IntoIterator<Item = Value>) -> Self {
        self.method_proofs.extend(proofs);
        self
    }

    /// Add one method / deployment-specific evidence member.
    #[must_use]
    pub fn with_extension(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.method_extensions.insert(key.into(), value.into());
        self
    }

    /// Add several method / deployment-specific evidence members.
    #[must_use]
    pub fn with_extensions(
        mut self,
        extensions: impl IntoIterator<Item = (String, Value)>,
    ) -> Self {
        self.method_extensions.extend(extensions);
        self
    }

    /// The pinned document digest this envelope commits to.
    pub fn document_digest(&self) -> &Hash {
        &self.document_digest
    }

    /// The policy digest this envelope commits to.
    pub fn policy_digest(&self) -> &Hash {
        &self.policy_digest
    }

    /// The recorded method-specific proof set.
    pub fn method_proofs(&self) -> &[Value] {
        &self.method_proofs
    }

    /// The recorded method / deployment-specific members.
    pub fn method_extensions(&self) -> &BTreeMap<String, Value> {
        &self.method_extensions
    }

    /// The canonical object this envelope digests.
    ///
    /// Publishing this is what turns "an acceptance records an evidence digest"
    /// into a *checkable* claim: an auditor can recompute the digest from the
    /// envelope rather than trusting that the field is non-empty.
    pub fn canonical_value(&self) -> Value {
        let mut object = Map::new();
        object.insert(
            "version".to_owned(),
            Value::String(EVIDENCE_DIGEST_VERSION.to_owned()),
        );
        object.insert(
            "document_digest".to_owned(),
            Value::String(self.document_digest.as_str().to_owned()),
        );
        object.insert(
            "method_proofs".to_owned(),
            Value::Array(self.method_proofs.clone()),
        );
        object.insert(
            "policy_digest".to_owned(),
            Value::String(self.policy_digest.as_str().to_owned()),
        );
        object.insert(
            "method".to_owned(),
            extension_object(&self.method_extensions),
        );
        Value::Object(object)
    }

    /// SHA-256 over the canonical JSON encoding of [`Self::canonical_value`].
    pub fn digest(&self) -> Result<Hash, DigestError> {
        digest_of(&self.canonical_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResolverFailMode;

    fn hash(seed: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("valid hash")
    }

    fn document() -> DidDocument {
        let did = arkret_wire::Did::new(
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned(),
        )
        .expect("valid did");
        DidDocument::new(
            did.clone(),
            format!("{did}#k1"),
            "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        )
    }

    // -- policy digest --

    #[test]
    fn fail_mode_token_is_explicit_not_debug_derived() {
        // The concrete divergence the review entry named: one repo emitted the
        // snake_case token, another `format!("{:?}", ..)`, so one policy value
        // produced two digests.
        assert_eq!(ResolverFailMode::FailClosed.as_str(), "fail_closed");
        assert_eq!(
            ResolverFailMode::AllowCachedOnError.as_str(),
            "allow_cached_on_error"
        );
        assert_ne!(
            format!("{:?}", ResolverFailMode::FailClosed),
            ResolverFailMode::FailClosed.as_str(),
            "the Debug spelling must not be the canonical token"
        );
        let policy = ResolverPolicy::default();
        let value = PolicyDigestInput::new(&policy).canonical_value();
        assert_eq!(value["fail_mode"], Value::String("fail_closed".to_owned()));
    }

    #[test]
    fn equal_policies_with_no_extensions_agree_across_deployments() {
        let left = ResolverPolicy::default();
        let right = ResolverPolicy::default();
        assert_eq!(
            policy_digest(&left).expect("digest"),
            policy_digest(&right).expect("digest"),
            "identical policies must be cross-repo comparable"
        );
    }

    #[test]
    fn method_list_is_order_insensitive_but_membership_sensitive() {
        let mut reordered = ResolverPolicy::default();
        reordered.allowed_methods.reverse();
        assert_eq!(
            policy_digest(&ResolverPolicy::default()).expect("digest"),
            policy_digest(&reordered).expect("digest"),
            "reordering a config list is not a policy change"
        );

        let mut extra = ResolverPolicy::default();
        extra.allowed_methods.push("did:plc:".to_owned());
        assert_ne!(
            policy_digest(&ResolverPolicy::default()).expect("digest"),
            policy_digest(&extra).expect("digest"),
            "adding a method IS a policy change"
        );
    }

    #[test]
    fn method_spellings_normalize_to_one_token() {
        assert_eq!(normalize_did_method_prefix("web"), "did:web:");
        assert_eq!(normalize_did_method_prefix("did:web"), "did:web:");
        assert_eq!(normalize_did_method_prefix(" did:web: "), "did:web:");

        let mut bare = ResolverPolicy::default();
        bare.allowed_methods = vec!["webvh".to_owned(), "web".to_owned(), "key".to_owned()];
        let mut prefixed = ResolverPolicy::default();
        prefixed.allowed_methods = vec![
            "did:key:".to_owned(),
            "did:web:".to_owned(),
            "did:webvh:".to_owned(),
        ];
        assert_eq!(
            policy_digest(&bare).expect("digest"),
            policy_digest(&prefixed).expect("digest"),
        );
    }

    #[test]
    fn duplicate_methods_do_not_change_the_digest() {
        let mut duplicated = ResolverPolicy::default();
        duplicated.allowed_methods.push("did:web:".to_owned());
        assert_eq!(
            policy_digest(&ResolverPolicy::default()).expect("digest"),
            policy_digest(&duplicated).expect("digest"),
        );
    }

    #[test]
    fn every_resolver_policy_field_is_covered() {
        let base = ResolverPolicy::default();
        let baseline = policy_digest(&base).expect("digest");

        let mut methods = base.clone();
        methods.allowed_methods = vec!["did:key:".to_owned()];
        let mut principal = base.clone();
        principal.default_principal_method = Some("did:web:".to_owned());
        let mut roots = base.clone();
        roots.trust_roots = vec!["https://root.example".to_owned()];
        let mut ttl = base.clone();
        ttl.ttl = Some(chrono::Duration::days(1));
        let mut ttl_off = base.clone();
        ttl_off.ttl = None;
        let mut fail_mode = base.clone();
        fail_mode.fail_mode = ResolverFailMode::AllowCachedOnError;

        for (label, mutated) in [
            ("allowed_methods", methods),
            ("default_principal_method", principal),
            ("trust_roots", roots),
            ("ttl", ttl),
            ("ttl=None", ttl_off),
            ("fail_mode", fail_mode),
        ] {
            assert_ne!(
                baseline,
                policy_digest(&mutated).expect("digest"),
                "`{label}` must be part of the policy digest"
            );
        }
    }

    #[test]
    fn deployment_extensions_change_the_digest_and_do_not_collide_with_the_core() {
        let policy = ResolverPolicy::default();
        let bare = PolicyDigestInput::new(&policy).digest().expect("digest");
        let extended = PolicyDigestInput::new(&policy)
            .with_extension("development_mode", true)
            .digest()
            .expect("digest");
        let flipped = PolicyDigestInput::new(&policy)
            .with_extension("development_mode", false)
            .digest()
            .expect("digest");
        assert_ne!(bare, extended);
        assert_ne!(extended, flipped);

        // An extension may reuse a core field name without shadowing it: the
        // extensions live in their own `deployment` sub-object.
        let shadow = PolicyDigestInput::new(&policy)
            .with_extension("fail_mode", "allow_cached_on_error")
            .canonical_value();
        assert_eq!(shadow["fail_mode"], Value::String("fail_closed".to_owned()));
        assert_eq!(
            shadow["deployment"]["fail_mode"],
            Value::String("allow_cached_on_error".to_owned())
        );
    }

    #[test]
    fn extension_insertion_order_is_irrelevant() {
        let policy = ResolverPolicy::default();
        let forward = PolicyDigestInput::new(&policy)
            .with_extension("a", 1)
            .with_extension("b", 2)
            .digest()
            .expect("digest");
        let backward = PolicyDigestInput::new(&policy)
            .with_extension("b", 2)
            .with_extension("a", 1)
            .digest()
            .expect("digest");
        assert_eq!(forward, backward);
    }

    #[test]
    fn deployment_epoch_retires_every_binding_in_one_step() {
        let policy = ResolverPolicy::default();
        let before = PolicyDigestInput::new(&policy).digest().expect("digest");
        let after = PolicyDigestInput::new(&policy)
            .with_deployment_epoch("2026-07-31-incident")
            .digest()
            .expect("digest");
        assert_ne!(before, after);
    }

    #[test]
    fn policy_digest_version_is_folded_in() {
        let policy = ResolverPolicy::default();
        assert_eq!(
            PolicyDigestInput::new(&policy).canonical_value()["version"],
            Value::String(POLICY_DIGEST_VERSION.to_owned())
        );
    }

    // -- evidence envelope --

    #[test]
    fn evidence_digest_is_never_the_bare_document_digest() {
        // One pre-existing implementation set `evidence_digest = document_digest`
        // verbatim, so the field carried zero additional information.
        let document_digest = hash(0x11);
        let envelope = EvidenceEnvelope::new(document_digest.clone(), hash(0x22));
        assert_ne!(envelope.digest().expect("digest"), document_digest);
    }

    #[test]
    fn evidence_digest_binds_the_document_and_the_policy() {
        let base = EvidenceEnvelope::new(hash(0x11), hash(0x22))
            .digest()
            .expect("digest");
        let other_document = EvidenceEnvelope::new(hash(0x33), hash(0x22))
            .digest()
            .expect("digest");
        let other_policy = EvidenceEnvelope::new(hash(0x11), hash(0x44))
            .digest()
            .expect("digest");
        assert_ne!(base, other_document, "document digest must bind");
        assert_ne!(base, other_policy, "policy digest must bind");
    }

    #[test]
    fn evidence_digest_is_not_a_constant_of_the_did() {
        // The other degenerate pre-existing form was `f(did)` plus two hard-coded
        // strings: two different documents for the same DID produced one digest.
        let mut second = document();
        second.verification_methods.insert(
            "#key-2".to_owned(),
            "z6MkfixtureOtherKeyMaterialValue".to_owned(),
        );
        let policy = hash(0x22);
        let first_digest = EvidenceEnvelope::for_document(&document(), policy.clone())
            .expect("envelope")
            .digest()
            .expect("digest");
        let second_digest = EvidenceEnvelope::for_document(&second, policy)
            .expect("envelope")
            .digest()
            .expect("digest");
        assert_ne!(
            first_digest, second_digest,
            "two documents under one DID must not share an evidence digest"
        );
    }

    #[test]
    fn for_document_matches_the_binding_document_digest() {
        let document = document();
        let envelope = EvidenceEnvelope::for_document(&document, hash(0x22)).expect("envelope");
        assert_eq!(
            envelope.document_digest(),
            &document_canonical_digest(&document).expect("digest"),
        );
    }

    #[test]
    fn method_proofs_are_order_significant() {
        let left = EvidenceEnvelope::new(hash(0x11), hash(0x22))
            .with_method_proof(serde_json::json!({"log": 1}))
            .with_method_proof(serde_json::json!({"log": 2}))
            .digest()
            .expect("digest");
        let right = EvidenceEnvelope::new(hash(0x11), hash(0x22))
            .with_method_proof(serde_json::json!({"log": 2}))
            .with_method_proof(serde_json::json!({"log": 1}))
            .digest()
            .expect("digest");
        assert_ne!(left, right, "a log chain is a sequence, not a set");
    }

    #[test]
    fn method_extensions_bind_and_are_order_insensitive() {
        let base = EvidenceEnvelope::new(hash(0x11), hash(0x22));
        let bare = base.clone().digest().expect("digest");
        let sourced = base
            .clone()
            .with_extension("source", "shared_resolver_chain")
            .digest()
            .expect("digest");
        let other_source = base
            .clone()
            .with_extension("source", "did_key_local_decode")
            .digest()
            .expect("digest");
        assert_ne!(bare, sourced);
        assert_ne!(sourced, other_source);

        let forward = base
            .clone()
            .with_extension("a", 1)
            .with_extension("b", 2)
            .digest()
            .expect("digest");
        let backward = base
            .with_extension("b", 2)
            .with_extension("a", 1)
            .digest()
            .expect("digest");
        assert_eq!(forward, backward);
    }

    #[test]
    fn evidence_envelope_is_recomputable_from_its_canonical_value() {
        // The audit property: an evidence digest can be re-derived rather than
        // merely asserted to be non-empty.
        let envelope = EvidenceEnvelope::new(hash(0x11), hash(0x22))
            .with_method_proof(serde_json::json!({"witness": "w1"}))
            .with_extension("source", "shared_resolver_chain");
        let recomputed = digest_of(&envelope.canonical_value()).expect("digest");
        assert_eq!(envelope.digest().expect("digest"), recomputed);
    }

    #[test]
    fn evidence_version_is_folded_in() {
        let envelope = EvidenceEnvelope::new(hash(0x11), hash(0x22));
        assert_eq!(
            envelope.canonical_value()["version"],
            Value::String(EVIDENCE_DIGEST_VERSION.to_owned())
        );
    }

    // -- coverage of the five pre-existing input sets --

    #[test]
    fn covers_every_downstream_policy_input_set() {
        // teabay: accepted methods + allow_private_networks + development_mode
        let policy = ResolverPolicy::default();
        let teabay = PolicyDigestInput::new(&policy)
            .with_extension("allow_private_networks", false)
            .with_extension("development_mode", false);
        // coauth: deployment profile, delegated resolver, pairwise proof toggle,
        // loopback relaxation, document size cap.
        let coauth = PolicyDigestInput::new(&policy)
            .with_extension("deployment_profile", "organization")
            .with_extension("principal_method", "did:webvh:")
            .with_extension("delegated_resolver", Value::Null)
            .with_extension("proof_required_for_pairwise", true)
            .with_extension("resolver_allow_loopback", false)
            .with_extension("did_document_max_bytes", 262_144);
        // soland: trust domain + development mode + allow list.
        let soland = PolicyDigestInput::new(&policy)
            .with_extension("trust_domain", "ak:trust_domain:soland.local")
            .with_extension("development_mode", false);
        // bridges / inkson: the ResolverPolicy core alone.
        let core = PolicyDigestInput::new(&policy);

        let digests = [
            teabay.digest().expect("digest"),
            coauth.digest().expect("digest"),
            soland.digest().expect("digest"),
            core.digest().expect("digest"),
        ];
        for (index, left) in digests.iter().enumerate() {
            for right in digests.iter().skip(index + 1) {
                assert_ne!(
                    left, right,
                    "distinct deployment dimensions must yield distinct digests"
                );
            }
        }
    }

    #[test]
    fn covers_every_downstream_evidence_input_set() {
        let policy = hash(0x22);
        let document = document();

        // teabay: provenance members + a conditional service kind.
        let teabay = EvidenceEnvelope::for_document(&document, policy.clone())
            .expect("envelope")
            .with_extension("source", "principal_service_endpoint")
            .with_extension("purpose", "principal_service_endpoint")
            .with_extension("service_kind", "media")
            .digest()
            .expect("digest");
        // coauth: an opaque resolver-supplied method evidence subtree.
        let coauth = EvidenceEnvelope::for_document(&document, policy.clone())
            .expect("envelope")
            .with_method_proof(serde_json::json!({"witnesses": ["w1", "w2"], "log_head": "1-abc"}))
            .with_extension("source", "delegated_resolver")
            .with_extension("verified_local_binding", true)
            .with_extension("identity_fact_rejection", Value::Null)
            .digest()
            .expect("digest");
        // bridges: a source key-state digest, hashed to a string first.
        let bridges = EvidenceEnvelope::for_document(&document, policy.clone())
            .expect("envelope")
            .with_extension("source_key_state_digest", hash(0x66).as_str())
            .digest()
            .expect("digest");
        // inkson / soland: no method proof set at all.
        let plain = EvidenceEnvelope::for_document(&document, policy)
            .expect("envelope")
            .digest()
            .expect("digest");

        let digests = [teabay, coauth, bridges, plain];
        for (index, left) in digests.iter().enumerate() {
            for right in digests.iter().skip(index + 1) {
                assert_ne!(left, right);
            }
        }
    }
}
