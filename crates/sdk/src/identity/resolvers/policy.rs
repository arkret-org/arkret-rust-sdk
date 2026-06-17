use crate::identity::*;

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

impl Default for ResolverPolicy {
    fn default() -> Self {
        Self {
            allowed_methods: Vec::new(),
            default_principal_method: None,
            trust_roots: Vec::new(),
            ttl: Some(chrono::Duration::minutes(15)),
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
    /// `Err(Error::Protocol("unauthorized_method"))` when the method is
    /// not in the allow list.
    pub fn validate(&self, did: &Did) -> Result<()> {
        if self.permits(did) {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "unauthorized_method: '{}' not in resolver allow list",
                did.as_str()
            )))
        }
    }
}
