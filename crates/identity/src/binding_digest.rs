//! The canonical `did-usage-and-verification.md` §5 binding contracts.
//!
//! §5 promises a *recomputable* binding: every digest field has a retained
//! canonical input object an auditor can re-hash. This module is the single
//! implementation of those objects, so the five services that used to invent
//! their own `evidence_digest` / `policy_digest` inputs now share one shape.
//!
//! | §5 field | canonical input | machine shape |
//! | --- | --- | --- |
//! | `document_digest` | the resolver's verified normalized document | §5.1, [`document_canonical_digest`](crate::document_canonical_digest) |
//! | `evidence_digest` | [`EvidenceReceipt`] | `did-binding-contracts.schema.json#/$defs/evidence_receipt` |
//! | `policy_digest` | [`ResolverPolicySnapshot`] | `#/$defs/resolver_policy_snapshot` |
//! | `evidence_dependencies` | [`EvidenceDependencies`] | `#/$defs/evidence_dependencies` |
//!
//! Two shapes are deliberately unrepresentable here:
//!
//! 1. **Evidence the caller made up.** [`EvidenceReceipt`] is built from what the resolver returned
//!    ([`ResolvedDid::method_evidence`](crate::ResolvedDid)), so a constant placeholder or a bare
//!    copy of `document_digest` cannot be produced through this API. A method that publishes no
//!    proofs degrades to an empty `method_proofs` array — the one normative degenerate form.
//! 2. **Language-native enum spellings.** Every token comes from a `&'static str` accessor; no
//!    `Debug` output reaches a digest. (`"FailClosed"` vs `"fail_closed"` is exactly how one policy
//!    value produced two digests.)
//!
//! `policy_digest` is deliberately **not** nested inside the evidence receipt: a
//! binding carries both digests side by side, and nesting would couple evidence
//! invalidation to policy rotation and double-count one dimension.

use arkret_canonical::canonical;
use arkret_wire::{DidFullId, Hash};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::binding::BindingError;
use crate::{ResolverFailMode, ResolverPolicy};

// ============================================================================
// Registered kinds
// ============================================================================

/// `kind` of the §5.2 canonical evidence receipt.
pub const EVIDENCE_RECEIPT_KIND: &str = "ak.did.binding_evidence.v1";

/// `kind` of the §5.3 canonical resolver policy snapshot.
pub const RESOLVER_POLICY_SNAPSHOT_KIND: &str = "ak.did.resolver_policy.v1";

/// The one resolver policy profile v1 registers; its `profile_policy` is the
/// empty object.
pub const BASE_RESOLVER_POLICY_PROFILE: &str = "ak.did_resolver_policy_profile.base.v1";

// ============================================================================
// Errors
// ============================================================================

/// Failures of a canonical §5 contract construction or digest computation.
///
/// Deliberately a `Result` rather than a silent fallback: a canonicalization
/// failure degraded into `unwrap_or_default()` hashes empty bytes, and a value
/// that keys a trust store must never be produced that way.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DigestError {
    /// The canonical JSON encoding failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    /// The computed digest is not a valid [`Hash`](struct@Hash).
    #[error("computed digest is invalid: {0}")]
    InvalidDigest(String),
    /// A closed set carried a duplicate entry.
    #[error("{collection} carries duplicate entry `{entry}`")]
    DuplicateEntry {
        collection: &'static str,
        entry: String,
    },
    /// A resolver policy cannot be declared as a canonical snapshot.
    #[error("resolver policy is not declarable: {0}")]
    UndeclarablePolicy(String),
}

impl From<DigestError> for BindingError {
    fn from(error: DigestError) -> Self {
        match error {
            DigestError::Canonicalization(reason) => Self::Canonicalization(reason),
            DigestError::InvalidDigest(reason) => Self::InvalidDigest(reason),
            other => Self::Canonicalization(other.to_string()),
        }
    }
}

fn digest_of(value: &Value) -> Result<Hash, DigestError> {
    let bytes = canonical::canonical_json_bytes(value)
        .map_err(|error| DigestError::Canonicalization(error.to_string()))?;
    Hash::new(canonical::sha256_digest(bytes))
        .map_err(|error| DigestError::InvalidDigest(error.to_string()))
}

/// Normalize a DID method reference to the canonical `did:<method>:` prefix
/// form.
///
/// Accepts every spelling observed across the downstream repos — `"web"`,
/// `"did:web"`, `"did:web:"` — and maps all three onto `"did:web:"`, so a
/// deployment that stores bare method names and one that stores prefixes agree
/// on the snapshot. An empty token normalizes to `"did:"` and is kept rather
/// than silently dropped, so a misconfiguration stays visible in the digest
/// instead of being erased by it.
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

fn sorted_unique(
    collection: &'static str,
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, DigestError> {
    let mut out: Vec<String> = values.into_iter().collect();
    out.sort();
    if let Some(duplicate) = out.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(DigestError::DuplicateEntry {
            collection,
            entry: duplicate[0].clone(),
        });
    }
    Ok(out)
}

fn string_array(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

// ============================================================================
// §5.2 evidence receipt
// ============================================================================

/// One witness row of a `did:webvh` log evidence proof.
///
/// These rows double as the selective-invalidation coordinates §5.6 requires:
/// a witness revocation names a `witness_did`, never a digest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebvhWitnessRow {
    pub witness_did: DidFullId,
    pub controlling_organization: DidFullId,
}

/// `did:webvh` method evidence row
/// (`did-binding-contracts.schema.json#/$defs/webvh_log_evidence`).
///
/// `witness_proofs_digest` commits to the canonical raw witness proof set, so
/// the receipt stays sensitive to any witness signature change even though the
/// signatures themselves are not carried inline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebvhLogEvidence {
    /// The verified webvh log head (`versionId` / entry-hash form) this binding
    /// pinned.
    pub history_head: String,
    /// Sorted by `witness_did` in UTF-8 byte order; duplicates are rejected.
    pub witnesses: Vec<WebvhWitnessRow>,
    pub witness_proofs_digest: Hash,
}

/// One registered method-evidence proof row.
///
/// v1 registers exactly one kind. An unregistered kind cannot be constructed,
/// which is how "unknown method evidence kind fails closed" is enforced at the
/// type level rather than at a runtime match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MethodEvidenceProof {
    WebvhLog(WebvhLogEvidence),
}

impl MethodEvidenceProof {
    /// The registered row kind token.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::WebvhLog(_) => "webvh_log",
        }
    }

    fn canonical_value(&self) -> Result<Value, DigestError> {
        match self {
            Self::WebvhLog(evidence) => {
                sorted_unique(
                    "webvh_log.witnesses",
                    evidence
                        .witnesses
                        .iter()
                        .map(|row| row.witness_did.as_str().to_owned()),
                )?;
                let mut rows: Vec<&WebvhWitnessRow> = evidence.witnesses.iter().collect();
                rows.sort_by(|left, right| {
                    left.witness_did.as_str().cmp(right.witness_did.as_str())
                });
                let mut object = Map::new();
                object.insert("kind".to_owned(), Value::String("webvh_log".to_owned()));
                object.insert(
                    "history_head".to_owned(),
                    Value::String(evidence.history_head.clone()),
                );
                object.insert(
                    "witnesses".to_owned(),
                    Value::Array(
                        rows.into_iter()
                            .map(|row| {
                                let mut witness = Map::new();
                                witness.insert(
                                    "witness_did".to_owned(),
                                    Value::String(row.witness_did.as_str().to_owned()),
                                );
                                witness.insert(
                                    "controlling_organization".to_owned(),
                                    Value::String(row.controlling_organization.as_str().to_owned()),
                                );
                                Value::Object(witness)
                            })
                            .collect(),
                    ),
                );
                object.insert(
                    "witness_proofs_digest".to_owned(),
                    Value::String(evidence.witness_proofs_digest.as_str().to_owned()),
                );
                Ok(Value::Object(object))
            }
        }
    }
}

/// What a resolver surfaced about the method backing a resolution, alongside
/// the document itself.
///
/// §5.2: webvh log heads, witness proof sets and consistency material exist only
/// in the resolver's hands and cannot be derived from a DID Document, so the
/// resolver contract carries them out. A method that publishes no proofs returns
/// [`MethodEvidence::none`], which is the normative degenerate form — not a
/// placeholder the caller invents.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodEvidence {
    /// Registered per-method proof rows; empty for proofless methods.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<MethodEvidenceProof>,
    /// The method history head pin, when the method exposes one. Surfacing it
    /// here is what lets §5.5 record `pinned` instead of `not_surfaced`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_head: Option<String>,
    /// The method version identifier pin, when the method exposes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
}

impl MethodEvidence {
    /// The evidence a proofless method (`did:key`, bare `did:web`) surfaces.
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether this method publishes verifiable evidence at all.
    ///
    /// §5.5 distinguishes `method_unsupported` (a legitimate terminal state)
    /// from `not_surfaced` (a resolver that failed to deliver evidence its
    /// method supports), and that distinction is exactly this predicate.
    pub fn is_proofless(&self) -> bool {
        self.proofs.is_empty()
    }
}

/// The §5.2 canonical evidence receipt whose digest is a binding's
/// `evidence_digest`.
///
/// The receipt itself MUST be retained: "auditable" means "recomputable", and an
/// auditor recomputes the digest from this object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReceipt {
    /// Canonical lowercase DID method token (`key`, `web`, `webvh`).
    pub method: String,
    /// The §5.1 digest of the resolver's verified normalized document
    /// projection — never the raw response bytes.
    pub document_digest: Hash,
    /// Closed per-method proof rows; empty for proofless methods.
    pub method_proofs: Vec<MethodEvidenceProof>,
}

impl EvidenceReceipt {
    /// Build the receipt from what the resolver returned.
    ///
    /// This is the only constructor, which is the point: `evidence_digest` can
    /// no longer be a value the caller made up before resolution happened.
    pub fn new(method: &str, document_digest: Hash, evidence: &MethodEvidence) -> Self {
        Self {
            method: method.trim().trim_start_matches("did:").to_lowercase(),
            document_digest,
            method_proofs: evidence.proofs.clone(),
        }
    }

    /// The canonical object this receipt digests.
    ///
    /// Proof rows are ordered by their own canonical encoding rather than by
    /// resolver return order, and exact duplicates are rejected: §5.2 forbids
    /// treating the resolver's ordering as the digest ordering.
    pub fn canonical_value(&self) -> Result<Value, DigestError> {
        let mut encoded = self
            .method_proofs
            .iter()
            .map(|proof| {
                let row = proof.canonical_value()?;
                canonical::canonical_json_string(&row)
                    .map_err(|error| DigestError::Canonicalization(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        encoded = sorted_unique("evidence_receipt.method_proofs", encoded)?;
        let rows = encoded
            .into_iter()
            .map(|row| {
                serde_json::from_str::<Value>(&row)
                    .map_err(|error| DigestError::Canonicalization(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut object = Map::new();
        object.insert(
            "kind".to_owned(),
            Value::String(EVIDENCE_RECEIPT_KIND.to_owned()),
        );
        object.insert("method".to_owned(), Value::String(self.method.clone()));
        object.insert(
            "document_digest".to_owned(),
            Value::String(self.document_digest.as_str().to_owned()),
        );
        object.insert("method_proofs".to_owned(), Value::Array(rows));
        Ok(Value::Object(object))
    }

    /// `"sha256:" + lowercase_hex(SHA-256(RFC8785_JCS(evidence_receipt)))`.
    pub fn digest(&self) -> Result<Hash, DigestError> {
        digest_of(&self.canonical_value()?)
    }

    /// The §5.6 dependency record mechanically extracted from this receipt.
    pub fn evidence_dependencies(&self) -> Result<EvidenceDependencies, DigestError> {
        EvidenceDependencies::from_receipt(self)
    }
}

// ============================================================================
// §5.6 evidence dependencies
// ============================================================================

/// The structured dependency record a binding carries so witness-level
/// invalidation can be selective
/// (`did-binding-contracts.schema.json#/$defs/evidence_dependencies`).
///
/// A witness revocation, an organization merge or a falsified consistency proof
/// arrives as a *coordinate* (witness DID, organization, log head), never as a
/// digest — digests are one-way, so `evidence_digest` cannot answer "which
/// bindings depend on witness X". This record can, and a store that declares
/// evidence-bearing methods MUST index it at least by witness DID.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDependencies {
    /// Sorted, deduplicated; empty for proofless methods.
    pub witness_dids: Vec<DidFullId>,
    /// Sorted, deduplicated; empty for proofless methods.
    pub witness_controlling_organizations: Vec<DidFullId>,
    /// Sorted, deduplicated; empty for proofless methods.
    pub history_heads: Vec<String>,
}

impl EvidenceDependencies {
    /// Extract the record from a receipt. Purely mechanical — there is no
    /// caller-supplied dimension, so the record cannot disagree with the
    /// evidence it indexes.
    pub fn from_receipt(receipt: &EvidenceReceipt) -> Result<Self, DigestError> {
        let mut witness_dids = Vec::new();
        let mut organizations = Vec::new();
        let mut history_heads = Vec::new();
        for proof in &receipt.method_proofs {
            match proof {
                MethodEvidenceProof::WebvhLog(evidence) => {
                    history_heads.push(evidence.history_head.clone());
                    for row in &evidence.witnesses {
                        witness_dids.push(row.witness_did.as_str().to_owned());
                        organizations.push(row.controlling_organization.as_str().to_owned());
                    }
                }
            }
        }
        Ok(Self {
            witness_dids: typed_dids(dedup_sorted(witness_dids))?,
            witness_controlling_organizations: typed_dids(dedup_sorted(organizations))?,
            history_heads: dedup_sorted(history_heads),
        })
    }

    /// Whether this record indexes nothing (a proofless method).
    pub fn is_empty(&self) -> bool {
        self.witness_dids.is_empty()
            && self.witness_controlling_organizations.is_empty()
            && self.history_heads.is_empty()
    }
}

fn dedup_sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn typed_dids(values: Vec<String>) -> Result<Vec<DidFullId>, DigestError> {
    values
        .into_iter()
        .map(|value| {
            DidFullId::new(value).map_err(|error| DigestError::Canonicalization(error.to_string()))
        })
        .collect()
}

// ============================================================================
// §5.3 resolver policy snapshot
// ============================================================================

/// The registered resolver policy profile that selects a snapshot's
/// `profile_policy` schema.
///
/// It is an enum rather than a free string plus an open map precisely because
/// §5.3 makes the profile a *schema discriminator*: unknown profiles, unknown
/// fields and missing registered fields all fail closed, which an
/// `BTreeMap<String, Value>` cannot express. A deployment with extra
/// admissibility dimensions registers a new profile — and gains a new variant
/// here — rather than smuggling keys through an open object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverPolicyProfile {
    /// `ak.did_resolver_policy_profile.base.v1`: `profile_policy` is `{}`.
    #[default]
    Base,
}

impl ResolverPolicyProfile {
    /// The registered profile id written into the snapshot.
    pub fn id(self) -> &'static str {
        match self {
            Self::Base => BASE_RESOLVER_POLICY_PROFILE,
        }
    }

    fn profile_policy(self) -> Value {
        match self {
            Self::Base => Value::Object(Map::new()),
        }
    }
}

/// The §5.3 canonical resolver policy snapshot whose digest is a binding's
/// `policy_digest`.
///
/// The three required members are the security core of *any* resolver policy —
/// which methods are accepted, how failures degrade, and which roots are
/// trusted — and MUST NOT be omitted. Everything a deployment adds beyond them
/// belongs to a registered profile's closed `profile_policy`; v1 registers only
/// the base profile, whose `profile_policy` is the empty object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverPolicySnapshot {
    profile: ResolverPolicyProfile,
    accepted_did_methods: Vec<String>,
    fail_mode: ResolverFailMode,
    trust_roots: Vec<String>,
}

impl ResolverPolicySnapshot {
    /// Declare a policy as a canonical snapshot.
    ///
    /// An empty `accepted_did_methods` list is rejected rather than encoded:
    /// "any method" is a fail-open configuration, and a snapshot that declared
    /// it would claim a security core it does not have.
    pub fn new(
        profile: ResolverPolicyProfile,
        accepted_did_methods: impl IntoIterator<Item = String>,
        fail_mode: ResolverFailMode,
        trust_roots: impl IntoIterator<Item = String>,
    ) -> Result<Self, DigestError> {
        let accepted_did_methods = sorted_unique(
            "resolver_policy_snapshot.accepted_did_methods",
            accepted_did_methods
                .into_iter()
                .map(|method| normalize_did_method_prefix(&method)),
        )?;
        if accepted_did_methods.is_empty() {
            return Err(DigestError::UndeclarablePolicy(
                "accepted_did_methods must not be empty; an unrestricted method list is fail-open"
                    .to_owned(),
            ));
        }
        Ok(Self {
            profile,
            accepted_did_methods,
            fail_mode,
            trust_roots: sorted_unique(
                "resolver_policy_snapshot.trust_roots",
                trust_roots.into_iter().map(|root| root.trim().to_owned()),
            )?,
        })
    }

    /// The profile whose closed schema validates `profile_policy`.
    pub fn profile(&self) -> ResolverPolicyProfile {
        self.profile
    }

    /// The normalized, sorted `did:<method>:` prefixes this policy accepts.
    pub fn accepted_did_methods(&self) -> &[String] {
        &self.accepted_did_methods
    }

    /// The declared failure-degradation behavior.
    pub fn fail_mode(&self) -> ResolverFailMode {
        self.fail_mode
    }

    /// The sorted, deduplicated trust roots.
    pub fn trust_roots(&self) -> &[String] {
        &self.trust_roots
    }

    /// The canonical object this snapshot digests.
    ///
    /// Publishing it is what turns "the deployment records a policy digest" into
    /// a checkable claim: an auditor recomputes the digest and verifies that any
    /// security-relevant configuration change necessarily changes it.
    pub fn canonical_value(&self) -> Value {
        let mut object = Map::new();
        object.insert(
            "kind".to_owned(),
            Value::String(RESOLVER_POLICY_SNAPSHOT_KIND.to_owned()),
        );
        object.insert(
            "policy_profile".to_owned(),
            Value::String(self.profile.id().to_owned()),
        );
        object.insert(
            "accepted_did_methods".to_owned(),
            string_array(&self.accepted_did_methods),
        );
        // Explicit registered token, never `format!("{:?}", ..)`.
        object.insert(
            "fail_mode".to_owned(),
            Value::String(self.fail_mode.as_str().to_owned()),
        );
        object.insert("trust_roots".to_owned(), string_array(&self.trust_roots));
        object.insert("profile_policy".to_owned(), self.profile.profile_policy());
        Value::Object(object)
    }

    /// `"sha256:" + lowercase_hex(SHA-256(RFC8785_JCS(policy_snapshot)))`.
    pub fn digest(&self) -> Result<Hash, DigestError> {
        digest_of(&self.canonical_value())
    }
}

impl Serialize for ResolverPolicySnapshot {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.canonical_value().serialize(serializer)
    }
}

impl ResolverPolicy {
    /// This policy as the §5.3 canonical snapshot under the base profile.
    ///
    /// The snapshot carries the three required security-core dimensions.
    /// `ttl` (the resolution cache lifetime, which §5 explicitly forbids from
    /// turning an ordinary request into a live resolution) and
    /// `default_principal_method` (a client-side defaulting convenience for
    /// method-less principal ids) are not admissibility dimensions of the base
    /// profile; a deployment that treats any additional switch as one MUST
    /// register its own profile with a closed `profile_policy` listing it.
    pub fn policy_snapshot(&self) -> Result<ResolverPolicySnapshot, DigestError> {
        ResolverPolicySnapshot::new(
            ResolverPolicyProfile::Base,
            self.allowed_methods.iter().cloned(),
            self.fail_mode,
            self.trust_roots.iter().cloned(),
        )
    }

    /// The §5.3 `policy_digest` of this policy.
    pub fn policy_digest(&self) -> Result<Hash, DigestError> {
        self.policy_snapshot()?.digest()
    }
}

/// The §5.3 `policy_digest` of a [`ResolverPolicy`].
pub fn policy_digest(resolver_policy: &ResolverPolicy) -> Result<Hash, DigestError> {
    resolver_policy.policy_digest()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("valid hash")
    }

    fn did(name: &str) -> DidFullId {
        DidFullId::new(format!("did:webvh:z6mkfixture:{name}.example")).expect("valid did")
    }

    fn webvh_evidence() -> MethodEvidence {
        MethodEvidence {
            proofs: vec![MethodEvidenceProof::WebvhLog(WebvhLogEvidence {
                history_head: "3-QmFixtureHead".to_owned(),
                witnesses: vec![
                    WebvhWitnessRow {
                        witness_did: did("witness-b"),
                        controlling_organization: did("org-2"),
                    },
                    WebvhWitnessRow {
                        witness_did: did("witness-a"),
                        controlling_organization: did("org-1"),
                    },
                ],
                witness_proofs_digest: hash(0x77),
            })],
            history_head: Some("3-QmFixtureHead".to_owned()),
            version_id: Some("3-QmFixtureHead".to_owned()),
        }
    }

    // -- policy snapshot --

    #[test]
    fn fail_mode_token_is_registered_not_debug_derived() {
        assert_eq!(ResolverFailMode::FailClosed.as_str(), "fail_closed");
        assert_ne!(
            format!("{:?}", ResolverFailMode::FailClosed),
            ResolverFailMode::FailClosed.as_str(),
            "the Debug spelling must not be the canonical token"
        );
        let snapshot = ResolverPolicy::default()
            .policy_snapshot()
            .expect("snapshot");
        assert_eq!(
            snapshot.canonical_value()["fail_mode"],
            Value::String("fail_closed".to_owned())
        );
    }

    #[test]
    fn snapshot_shape_matches_the_registered_contract() {
        let value = ResolverPolicy::default()
            .policy_snapshot()
            .expect("snapshot")
            .canonical_value();
        assert_eq!(
            value["kind"],
            Value::String(RESOLVER_POLICY_SNAPSHOT_KIND.to_owned())
        );
        assert_eq!(
            value["policy_profile"],
            Value::String(BASE_RESOLVER_POLICY_PROFILE.to_owned())
        );
        assert_eq!(value["profile_policy"], Value::Object(Map::new()));
        assert_eq!(
            value["accepted_did_methods"],
            serde_json::json!(["did:key:", "did:web:", "did:webvh:"]),
            "normalized, sorted, deduplicated"
        );
        assert_eq!(value["trust_roots"], serde_json::json!([]));
        assert_eq!(
            value.as_object().expect("object").len(),
            6,
            "the snapshot is closed: no member beyond the registered six"
        );
    }

    #[test]
    fn method_spellings_normalize_to_one_token() {
        assert_eq!(normalize_did_method_prefix("web"), "did:web:");
        assert_eq!(normalize_did_method_prefix("did:web"), "did:web:");
        assert_eq!(normalize_did_method_prefix(" did:web: "), "did:web:");

        let bare = ResolverPolicy {
            allowed_methods: vec!["webvh".to_owned(), "web".to_owned(), "key".to_owned()],
            ..Default::default()
        };
        assert_eq!(
            bare.policy_digest().expect("digest"),
            ResolverPolicy::default().policy_digest().expect("digest"),
        );
    }

    #[test]
    fn every_security_core_dimension_changes_the_digest() {
        let base = ResolverPolicy::default();
        let baseline = base.policy_digest().expect("digest");

        let mut methods = base.clone();
        methods.allowed_methods = vec!["did:key:".to_owned()];
        let mut roots = base.clone();
        roots.trust_roots = vec!["https://root.example".to_owned()];
        let mut fail_mode = base;
        fail_mode.fail_mode = ResolverFailMode::AllowCachedOnError;

        for (label, mutated) in [
            ("accepted_did_methods", methods),
            ("trust_roots", roots),
            ("fail_mode", fail_mode),
        ] {
            assert_ne!(
                baseline,
                mutated.policy_digest().expect("digest"),
                "`{label}` must be part of the policy digest"
            );
        }
    }

    #[test]
    fn a_fail_open_method_list_is_not_declarable() {
        let mut open = ResolverPolicy::default();
        open.allowed_methods.clear();
        assert!(matches!(
            open.policy_snapshot(),
            Err(DigestError::UndeclarablePolicy(_))
        ));
    }

    #[test]
    fn duplicate_methods_are_rejected_not_silently_merged() {
        let mut duplicated = ResolverPolicy::default();
        duplicated.allowed_methods.push("web".to_owned());
        assert!(matches!(
            duplicated.policy_snapshot(),
            Err(DigestError::DuplicateEntry { .. })
        ));
    }

    // -- evidence receipt --

    #[test]
    fn a_proofless_method_degrades_to_an_empty_proof_array() {
        let receipt = EvidenceReceipt::new("key", hash(0x11), &MethodEvidence::none());
        let value = receipt.canonical_value().expect("canonical");
        assert_eq!(value["method_proofs"], serde_json::json!([]));
        assert_eq!(
            value["kind"],
            Value::String(EVIDENCE_RECEIPT_KIND.to_owned())
        );
        assert_ne!(
            receipt.digest().expect("digest"),
            hash(0x11),
            "the receipt digest is never the bare document digest"
        );
    }

    #[test]
    fn the_receipt_binds_the_document_and_the_evidence() {
        let baseline = EvidenceReceipt::new("webvh", hash(0x11), &webvh_evidence())
            .digest()
            .expect("digest");
        let other_document = EvidenceReceipt::new("webvh", hash(0x33), &webvh_evidence())
            .digest()
            .expect("digest");
        assert_ne!(baseline, other_document, "document digest must bind");

        let mut tampered = webvh_evidence();
        let MethodEvidenceProof::WebvhLog(row) = &mut tampered.proofs[0];
        row.witness_proofs_digest = hash(0x99);
        let other_evidence = EvidenceReceipt::new("webvh", hash(0x11), &tampered)
            .digest()
            .expect("digest");
        assert_ne!(baseline, other_evidence, "witness proofs must bind");
    }

    #[test]
    fn witness_rows_are_sorted_not_taken_in_resolver_order() {
        let receipt = EvidenceReceipt::new("webvh", hash(0x11), &webvh_evidence());
        let value = receipt.canonical_value().expect("canonical");
        let witnesses = value["method_proofs"][0]["witnesses"]
            .as_array()
            .expect("array");
        assert_eq!(
            witnesses[0]["witness_did"],
            Value::String(did("witness-a").as_str().to_owned())
        );

        let mut reversed = webvh_evidence();
        let MethodEvidenceProof::WebvhLog(row) = &mut reversed.proofs[0];
        row.witnesses.reverse();
        assert_eq!(
            receipt.digest().expect("digest"),
            EvidenceReceipt::new("webvh", hash(0x11), &reversed)
                .digest()
                .expect("digest"),
            "resolver return order must not reach the digest"
        );
    }

    #[test]
    fn duplicate_witnesses_are_rejected() {
        let mut duplicated = webvh_evidence();
        let MethodEvidenceProof::WebvhLog(row) = &mut duplicated.proofs[0];
        let first = row.witnesses[0].clone();
        row.witnesses.push(first);
        assert!(matches!(
            EvidenceReceipt::new("webvh", hash(0x11), &duplicated).digest(),
            Err(DigestError::DuplicateEntry { .. })
        ));
    }

    #[test]
    fn the_method_token_is_the_bare_lowercase_method() {
        for spelling in ["webvh", "WEBVH", "did:webvh", " webvh "] {
            assert_eq!(
                EvidenceReceipt::new(spelling, hash(0x11), &MethodEvidence::none()).method,
                "webvh"
            );
        }
    }

    #[test]
    fn the_receipt_is_recomputable_from_its_canonical_value() {
        let receipt = EvidenceReceipt::new("webvh", hash(0x11), &webvh_evidence());
        let recomputed = digest_of(&receipt.canonical_value().expect("canonical")).expect("digest");
        assert_eq!(receipt.digest().expect("digest"), recomputed);
    }

    // -- evidence dependencies --

    #[test]
    fn dependencies_are_extracted_mechanically_and_sorted() {
        let receipt = EvidenceReceipt::new("webvh", hash(0x11), &webvh_evidence());
        let dependencies = receipt.evidence_dependencies().expect("dependencies");
        assert_eq!(
            dependencies.witness_dids,
            vec![did("witness-a"), did("witness-b")]
        );
        assert_eq!(
            dependencies.witness_controlling_organizations,
            vec![did("org-1"), did("org-2")]
        );
        assert_eq!(dependencies.history_heads, vec!["3-QmFixtureHead"]);
    }

    #[test]
    fn a_proofless_method_produces_the_empty_dependency_record() {
        let receipt = EvidenceReceipt::new("key", hash(0x11), &MethodEvidence::none());
        assert!(receipt.evidence_dependencies().expect("deps").is_empty());
    }
}
