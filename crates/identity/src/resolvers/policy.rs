use arkret_wire::Did;

use crate::*;

/// Policy controlling DID resolution per `identity-handles.md` §5 /
/// `device-lifecycle.md` §4.
///
/// `allowed_methods` and `default_principal_method` MUST be applied
/// before dispatching a resolver, so a misconfigured peer can't smuggle
/// a `did:bogus:` through. `trust_roots` is method-specific (e.g. for
/// `did:web` it's a list of accepted authorities; for `did:keri` it's
/// a list of witness DIDs). `ttl` bounds the cache lifetime; `fail_mode`
/// decides whether to return stale cache entries when the upstream is
/// unreachable.
#[derive(Clone, Debug)]
pub struct ResolverPolicy {
    /// DID method prefixes (e.g. `"did:web:"`, `"did:key:"`) the
    /// resolver is allowed to dispatch. An empty allow list means
    /// "any method"; that's only safe for trusted contexts.
    pub allowed_methods: Vec<String>,
    /// Default method prefix for principal IDs (`actor_id`). Resolution
    /// of an actor that doesn't carry its own method MUST use this.
    pub default_principal_method: Option<String>,
    /// Trust roots accepted for the active method. Interpretation is
    /// up to the underlying resolver implementation.
    pub trust_roots: Vec<String>,
    /// Maximum lifetime of a cached resolution. `None` disables caching.
    pub ttl: Option<chrono::Duration>,
    /// Fail-mode for upstream errors.
    pub fail_mode: ResolverFailMode,
}

/// Behavior when DID resolution fails (network outage, signature
/// mismatch, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ResolverFailMode {
    /// Refuse to use any cached state. Safest default.
    #[default]
    FailClosed,
    /// Allow returning a still-valid cache hit (within TTL) on
    /// transient upstream errors.
    AllowCachedOnError,
}

impl ResolverFailMode {
    /// Stable snake_case token for canonical encodings.
    ///
    /// Never derive this from [`Debug`]: `format!("{:?}", ResolverFailMode::FailClosed)`
    /// yields `"FailClosed"`, which is a Rust identifier, not a wire contract —
    /// renaming the variant would silently change every digest computed from it.
    /// `crate::binding_digest` uses this token, and downstream repos MUST use it
    /// instead of hand-writing their own mapping (that divergence is exactly what
    /// produced two incompatible `policy_digest` values for one policy value).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::AllowCachedOnError => "allow_cached_on_error",
        }
    }
}

impl std::fmt::Display for ResolverFailMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Default for ResolverPolicy {
    fn default() -> Self {
        // Default to the method set `identity-did.md` §5 requires a core
        // resolver to support (`did:webvh`, `did:web`, `did:key`) rather
        // than an empty allow list. An empty list means "any method"
        // (see `allowed_methods` docs); using it as the *default* made the
        // default-constructed resolver fail-open, permitting `did:bogus:`.
        // `did:webvh` is the default principal method per §3.1: a principal
        // `actor_id` that carries no method of its own resolves as `did:webvh`,
        // never silently as `did:web`.
        Self {
            allowed_methods: vec![
                "did:webvh:".to_owned(),
                "did:web:".to_owned(),
                "did:key:".to_owned(),
            ],
            default_principal_method: Some("did:webvh:".to_owned()),
            trust_roots: Vec::new(),
            ttl: Some(chrono::Duration::days(7)),
            fail_mode: ResolverFailMode::FailClosed,
        }
    }
}

impl ResolverPolicy {
    /// Whether `did` is permitted by `allowed_methods`.
    pub fn permits(&self, did: &Did) -> bool {
        if self.allowed_methods.is_empty() {
            return true;
        }
        let s = did.as_str();
        self.allowed_methods
            .iter()
            .any(|prefix| s.starts_with(prefix))
    }

    /// Validate `did` against the policy. Returns
    /// `Err(IdentityError::Protocol("unauthorized_method"))` when the method is
    /// not in the allow list.
    pub fn validate(&self, did: &Did) -> Result<()> {
        if self.permits(did) {
            Ok(())
        } else {
            Err(IdentityError::Protocol(format!(
                "unauthorized_method: '{}' not in resolver allow list",
                did.as_str()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_fail_closed_against_unknown_methods() {
        let policy = ResolverPolicy::default();
        // The spec-required triad is permitted...
        for did in [
            "did:webvh:scid:host:webvh:01",
            "did:webvh:z6mkfixture:example.com",
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        ] {
            let did = Did::new(did.to_owned()).expect("valid did");
            assert!(policy.permits(&did), "default must permit {did:?}");
        }
        // ...but an unknown method is rejected, not fail-open.
        let bogus = Did::new("did:bogus:whatever".to_owned()).expect("valid did syntax");
        assert!(!policy.permits(&bogus), "default must reject did:bogus:");
        assert!(policy.validate(&bogus).is_err());
        assert_eq!(
            policy.default_principal_method.as_deref(),
            Some("did:webvh:"),
            "default principal method must be did:webvh, never did:web"
        );
    }
}
