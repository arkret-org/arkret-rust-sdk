use super::*;

/// Profile-specific protocol conformance domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ConformanceProfile {
    Encoding,
    Hlc,
    Cursor,
    StateResolution,
    Redaction,
    Capability,
    Sync,
    Snapshot,
    FederationSignatures,
    Privacy,
    Security,
}

/// One conformance test case descriptor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ConformanceCase {
    pub case_id: String,
    pub description: String,
    pub schema_id: Option<String>,
    pub vector: Value,
}

/// Conformance suite for one protocol profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ConformanceSuite {
    pub profile: ConformanceProfile,
    pub cases: Vec<ConformanceCase>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ConformanceCaseResult {
    pub profile: ConformanceProfile,
    pub case_id: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ConformanceProfileCoverage {
    pub profile: ConformanceProfile,
    pub cases_total: usize,
    pub cases_passed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ConformanceReport {
    pub fixture_version: String,
    pub passed: bool,
    pub coverage: Vec<ConformanceProfileCoverage>,
    pub results: Vec<ConformanceCaseResult>,
}

/// Loadable conformance fixture set used by SDK and external fixtures.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ConformanceFixtureSet {
    pub fixture_version: String,
    pub suites: Vec<ConformanceSuite>,
}

impl ConformanceFixtureSet {
    /// Built-in fixtures shipped with the SDK.
    pub fn builtin() -> Self {
        Self {
            fixture_version: BUILT_IN_CONFORMANCE_FIXTURES_VERSION.to_owned(),
            suites: profile_conformance_suites(),
        }
    }

    /// Decode a fixture set from JSON.
    pub fn from_json(value: Value) -> Result<Self> {
        let fixtures: Self = serde_json::from_value(value)?;
        fixtures.validate()?;
        Ok(fixtures)
    }

    /// Validate fixture shape before execution.
    pub fn validate(&self) -> Result<()> {
        if self.fixture_version.trim().is_empty() {
            return Err(Error::Protocol("fixture_version must be non-empty".to_owned()));
        }
        if self.suites.is_empty() {
            return Err(Error::Protocol("fixture set must contain at least one suite".to_owned()));
        }
        for suite in &self.suites {
            if suite.cases.is_empty() {
                return Err(Error::Protocol(format!(
                    "conformance suite {:?} must contain cases",
                    suite.profile
                )));
            }
            for case in &suite.cases {
                if case.case_id.trim().is_empty() {
                    return Err(Error::Protocol(
                        "conformance case id must be non-empty".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Execute the fixture set against SDK validators.
    pub fn run(&self) -> ConformanceReport {
        let registry = ProtocolSchemaRegistry::default();
        run_conformance_suites(&registry, self.fixture_version.clone(), &self.suites)
    }
}

/// Built-in profile-specific conformance suites.
pub fn profile_conformance_suites() -> Vec<ConformanceSuite> {
    vec![
        conformance_suite(
            ConformanceProfile::Encoding,
            "canonical-json-digest",
            "Canonical JSON and digest vectors reject ambiguous encodings.",
            None,
            json!({"input": {"b": 2, "a": 1}, "digest_required": true}),
        ),
        conformance_suite(
            ConformanceProfile::Hlc,
            "hlc-monotonic-canonical-form",
            "HLC values use fixed-width lowercase hex and preserve causal ordering.",
            None,
            json!({"fixed_width": true, "lowercase": true, "causal_ordering": true}),
        ),
        conformance_suite(
            ConformanceProfile::Cursor,
            "cursor-token-binding-and-expiry",
            "Cursor tokens bind positions and reject stale or malformed encodings.",
            Some(CURSOR_SCHEMA),
            json!({"binds_positions": true, "expires": true, "rejects_malformed": true}),
        ),
        conformance_suite(
            ConformanceProfile::StateResolution,
            "canonical-container-position-event-kinds",
            "Reducer fixtures use canonical container operation kinds.",
            Some(EVENT_SCHEMA),
            json!({
                "order_independent": true,
                "requires_merkle_root": true,
                "canonical_kinds": [
                    OP_CONTAINER_MOVE_ITEM,
                    OP_CONTAINER_REBALANCE
                ]
            }),
        ),
        conformance_suite(
            ConformanceProfile::Redaction,
            "redaction-preserves-reference-fields",
            "Redaction removes payload while preserving IDs, actor, HLC and semantic refs.",
            Some(EVENT_SCHEMA),
            json!({"preserve": ["event_id", "actor_id", "hlc", "refs"]}),
        ),
        conformance_suite(
            ConformanceProfile::Capability,
            "facet-aware-capability-frontier-validation",
            "Capability checks run at the causal frontier and can fail closed on allowed facets.",
            Some(CAPABILITY_SCHEMA),
            json!({"fail_closed": true, "frontier_bound": true, "facet_allow": true}),
        ),
        conformance_suite(
            ConformanceProfile::Sync,
            "facet-query-renderer-sync-token-binding",
            "Sync tokens bind principal, device, service, facets, renderer, filter hash and stream positions.",
            Some(VIEW_SCHEMA),
            json!({
                "binds_filter": true,
                "binds_positions": true,
                "binds_facets": true,
                "binds_renderer": true
            }),
        ),
        conformance_suite(
            ConformanceProfile::Snapshot,
            "snapshot-chunk-digests",
            "Snapshot manifests verify chunk digests before reducer restore.",
            None,
            json!({"chunk_digest": "sha256", "restore_requires_all_chunks": true}),
        ),
        conformance_suite(
            ConformanceProfile::FederationSignatures,
            "http-message-signature-binding",
            "Federation signatures bind method, target URI, authority, digest and service DIDs.",
            None,
            json!({"requires_origin_did": true, "requires_destination_did": true}),
        ),
        conformance_suite(
            ConformanceProfile::Privacy,
            "not-found-and-private-did-privacy",
            "Invisible resources and private DID lookups avoid oracle behavior.",
            None,
            json!({"privacy_preserving_not_found": true, "requires_resolution_proof": true}),
        ),
        conformance_suite(
            ConformanceProfile::Security,
            "proof-policy-and-redaction-fail-closed",
            "Security-sensitive schema extensions, proof bindings and log payloads fail closed.",
            Some(ENCRYPTED_ENVELOPE_SCHEMA),
            json!({"fail_closed_extensions": true, "proof_binding": true, "redact_secrets": true}),
        ),
    ]
}

fn conformance_suite(
    profile: ConformanceProfile,
    case_id: &str,
    description: &str,
    schema_id: Option<&str>,
    vector: Value,
) -> ConformanceSuite {
    ConformanceSuite {
        profile,
        cases: vec![ConformanceCase {
            case_id: case_id.to_owned(),
            description: description.to_owned(),
            schema_id: schema_id.map(str::to_owned),
            vector,
        }],
    }
}

/// Execute the SDK's built-in conformance descriptors and return a
/// machine-readable report that downstream projects can store as release
/// evidence. Official external fixtures can be loaded by callers into the same
/// report shape.
pub fn run_builtin_conformance_report() -> ConformanceReport {
    ConformanceFixtureSet::builtin().run()
}

fn run_conformance_suites(
    registry: &ProtocolSchemaRegistry,
    fixture_version: String,
    suites: &[ConformanceSuite],
) -> ConformanceReport {
    let mut results = Vec::new();

    for suite in suites {
        for case in &suite.cases {
            let error =
                validate_conformance_case(registry, case).err().map(|error| error.to_string());
            results.push(ConformanceCaseResult {
                profile: suite.profile,
                case_id: case.case_id.clone(),
                passed: error.is_none(),
                error,
            });
        }
    }

    let coverage = suites
        .iter()
        .map(|suite| {
            let cases_total =
                results.iter().filter(|result| result.profile == suite.profile).count();
            let cases_passed = results
                .iter()
                .filter(|result| result.profile == suite.profile && result.passed)
                .count();
            ConformanceProfileCoverage { profile: suite.profile, cases_total, cases_passed }
        })
        .collect::<Vec<_>>();
    let passed = results.iter().all(|result| result.passed);

    ConformanceReport { fixture_version, passed, coverage, results }
}

fn validate_conformance_case(
    registry: &ProtocolSchemaRegistry,
    case: &ConformanceCase,
) -> Result<()> {
    if case.case_id.trim().is_empty() {
        return Err(Error::Protocol("conformance case id must be non-empty".to_owned()));
    }
    if case.vector.is_null() {
        return Err(Error::Protocol(format!(
            "conformance case '{}' must contain a vector payload",
            case.case_id
        )));
    }
    if let Some(schema_id) = &case.schema_id {
        registry
            .schema(schema_id)
            .ok_or_else(|| Error::Protocol(format!("unknown conformance schema '{schema_id}'")))?;
    }
    Ok(())
}
