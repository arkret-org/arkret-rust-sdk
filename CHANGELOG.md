# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Starting with the local `1.0.0` freeze, breaking public API changes require a
major-version bump.

## [Unreleased]

## [1.0.0] - 2026-05-25

### Release Engineering

- Bumped all 11 workspace crates to `1.0.0` for the local freeze.
- Recorded local interop evidence in `docs/release-evidence-1.0.0.md` using
  cotest release-gate run `artifacts/runs/20260525-055932` from the sibling
  `cotest` checkout.
- Kept the release flow local-only: no crates.io publish, no GitHub release,
  and no release tag.
- Promoted
  `cargo semver-checks check-release --workspace --baseline-rev HEAD~1` to a
  blocking local CI gate for the 1.0 API surface.

### Release Engineering

- Release verification is local-only: the workflow validates package assembly
  with `cargo package --workspace --locked --no-verify` and does not publish
  crates, create GitHub releases, or push release tags.
- Release verification now uses the current `cargo deny check --config
  .deny.toml` invocation and runs `cargo audit --deny warnings` with explicit
  tracked exceptions for `RUSTSEC-2024-0384` and `RUSTSEC-2026-0124`, matching
  the documented OpenMLS/HPKE upstream dependency constraints.

### Round R4 — protocol review closures (wire-breaking) (2026-05-20)

Tracks contrix-spec range `2a4d39b..a77b9958e3c6535a39bf468d661a23ae5d38cb10`
(8 commits). See [`../_todos.md`](../_todos.md) "协议变更摘要" for the canonical
wire-breaking list.

- **Added** new `round4` module aggregating Round R4 types, constants, and
  validation helpers (re-exported from the umbrella `contrix` crate).
- **Added** types: `EventsSubscribeFrame` (8-kind enum: `event` / `frontier` /
  `heartbeat` / `catchup_complete` / `epoch_rotation` / `dropped{cursor}` /
  `resync_required` / `unauthorized`), `SnapshotBootstrap`, `EventsFrontierResponse`
  oneOf (`AccountClient` / `FederationPeer` / `AnonymousHealth` — the last
  forbids `receipts` / `signatures` at the type level), `PolicyCheckRequest` /
  `PolicyCheckResponse{bound_to{realm_id,actor,action,request_canonical_digest,
  policy_server_id}, signature}`, `FederationServiceBindingRef` (6 required
  fields), `EventsSubmitBatchRequest` / `EventsSubmitFederationRequest`,
  `ThirdPartyInvite{oob_code_kind ∈ OfflineToken|Lookup}`,
  `SpaceStateTransitionPayload` / `SpaceObjectTombstonePayload`,
  `AppletId = enum { Did | Cx }`.
- **BREAKING** DID regex tightened: `^did:[a-z0-9]+:[^\s]+$` (method-name
  segment no longer accepts `.` / `-` / `_` / `:`). Applied across all DID
  parsers, newtype validators, signature `kid` parsers, and schema-validation
  hooks. All fixtures swept.
- **BREAKING** `cx.call.signal` ephemeral envelope: `proof` is now required;
  `signal_type` enum widened from 6 to 13 values (adds `reject`, `mute_state`,
  `media_state`, `speaking`, `focus_join`, `focus_leave`, `error`); new helper
  `validate_signal_seq(prev, next, key=(realm,call,actor,device))` enforces
  per-(realm,call,actor,device) monotonic `seq`.
- **BREAKING** `cx.cross_signing.publish` CAS: `CrossSigningPublishPayload`
  gains required `expected_previous_generation: u64`; new
  `cross_signing_publish_cell_subject(principal_id, expected_previous_generation)
   -> CellSubject::Tuple`.
- **BREAKING** `compute_audit_policy_version_digest(realm_id, trust_domain,
  audit_disclosure, audit_assurance)` — old 2-arg signature removed; old
  receipts no longer verify.
- **BREAKING** `Realm` / `ServiceDescribe` / `AuditRywReceipt` gain required
  `trust_domain: TypedTrustDomainId`. `ServiceDescribe` v2 carries 17 required
  fields including `plaintext_visibility` / `claimed_profiles` /
  `verified_profiles` / `compat_surfaces` / `development_mode` and a
  `rate_limit` oneOf.
- **BREAKING** `ConsentRevokePayload` gains required
  `observed_dots: Vec<Dot>`; `AccessKind` gains `E2EELateRecovery` with
  required `late_recovery_original_event_id`.
- **Added** federation HTTP signature transcript now includes the three new
  S2S headers `Source-Trust-Domain` / `Destination-Trust-Domain` /
  `Request-Canonical-Digest` (re-exported constants
  `HEADER_SOURCE_TRUST_DOMAIN` / `HEADER_DESTINATION_TRUST_DOMAIN` /
  `HEADER_REQUEST_CANONICAL_DIGEST`).
- **Added** 3 new error code constants (`ERROR_CODE_DELIVERY_BINDING_STALE` /
  `_HANDED_OVER` / `_HISTORICAL_ONLY`) and 1 new capability action
  (`CAPABILITY_ACTION_MORPH_CREATE = "cx.morph.create"`, medium risk,
  required-constraints `[morph_type_allow]`).
- **Added** `cx:space:<uuidv7>` accepted in `object_ref`; flow cell-metadata
  helpers `flow_update_cell_subject(flow_id)` / `flow_tracks_patch_cell_subject(flow_id)`
  (cell-family `cx.component.flow.fields.v1`, CAS-register, bottom=reject).

### Added — Round R2/R3 spec round 2+3 cleanup (wire-breaking) (2026-05-20)

Tracks contrix-spec commits `f3c3bad..2a4d39b` (notably `8b7978d spec: round 2+3
cleanup`). All 17 new normative requirements landed in the SDK as type
signatures, schema-id constants, and validation helpers. See contrix-spec
`CHANGELOG.md` Round R2/R3 entries for the normative source.

- **Event kinds**: 4 new active `durable_event` kinds — `cx.moderation.appeal.submit`
  / `.review` / `.decision` / `.close` — extending the moderation flow.
  Helpers `is_ephemeral_kind` (recognises the 12 ephemeral wire kinds:
  `cx.call.signal`, `cx.presence`, `cx.typing`, `cx.receipt.read`, and the
  `cx.key.verification.*` family) and `is_receipt_object_only`
  (`cx.event_batch_receipt`).
- **Typed IDs**: `TypedAppealId` (`cx:appeal:<uuidv7>`) and
  `TypedTrustDomainId` (`cx:trust_domain:<scope>` with lowercase `[a-z0-9._:-]`
  max-128 scope validator).
- **Schemas**: `cx.schema.ephemeral_envelope.v1`,
  `cx.schema.moderation_appeal.v1`, `cx.schema.attestation_evidence.v1` added
  to `ARTIFACT_BACKED_SCHEMA_IDS`. The SDK reads the JSON Schema bodies
  directly from the spec artifacts directory at runtime; no in-source copy.
  `cursor.schema.json` (h.minLength=22), `cross-signing-reset.schema.json`
  (required `trust_domain` + `reset_event_id`) and `event-schema.json` (not
  branch reject 12 ephemeral kinds) update upstream.
- **Rust types**: `EphemeralEnvelope` with `EPHEMERAL_ABSOLUTE_HARD_CEILING_MS`
  (300_000 ms) enforced by the constructor; `ModerationAppealPayload` enum
  with 4 oneOf variants + `validate_minimal` for the verdict/modify_ref
  cross-check; `AttestationEvidence` mirroring all schema fields;
  `CrossSigningResetPayload` with required `trust_domain` and
  `reset_event_id` (wire-breaking); `IdentityLinkCacheEntry` carrying a
  32-byte `policy_frontier_digest`; helper
  `compute_policy_frontier_digest(disclosure_policy, history_visibility,
  identity_disclosure_profile, minimal_metadata_mode)`.
- **Anchor canonical bytes**: free-function shims `anchor_canonical_bytes`
  and `compute_anchor_id` exposing the existing body canonicalisation
  (excludes `id` and `anchorer_sig`); new
  `Anchor::validate_frontier_format` rejects the dropped
  `cx:event:<uuid>` frontier form (only `sha256:<hex>` etc are accepted).
- **Error codes** (15 new wire-level top codes): `relaxed_window_exceeds_ceiling`,
  `e2ee_relaxed_disallowed_in_compliance_profile`, `cross_domain_replay_rejected`,
  `reset_event_id_mismatch`, `appeal_overturn_missing_lift`,
  `appeal_self_review_forbidden`, `realm_terminal_state`,
  `audit_agent_attestation_mismatch`, `audit_purpose_mismatch`,
  `legal_hold_active`, `blob_redacted`,
  `media_plaintext_service_not_authorised`,
  `mls_governance_binding_stale`, `expired_invite_token`,
  `late_recovery_rejected_membership`. All wired into `KNOWN_ERROR_CODES`
  and `error_code_http_status`.
- **Capability actions**: `CAP_ACTION_MODERATION_APPEAL_SUBMIT` (low risk;
  any member may appeal) and `CAP_ACTION_MODERATION_APPEAL_REVIEW` (medium
  risk; gates the review / decision / close transitions).
- **`cx.profile.e2ee_relaxed.v1`**: `PROFILE_E2EE_RELAXED` constant +
  `ABSOLUTE_HARD_CEILING_MS = 300_000`; helpers
  `is_e2ee_relaxed_compatible_with_compliance` (rejects coexistence with
  attested or disclosed audit profiles) and `validate_relaxed_window_ms`.
- **Cursor handle**: `generate_cursor_handle()` yields ≥22 base64url chars
  (128-bit handle); `validate_cursor_handle` minLength raised to 22 per
  schema.
- **Realm lifecycle**: `is_terminal_realm_state(state) -> bool` returns
  `true` once `cx.realm.destroy` has been applied.

### Changed — Realm/Space terminology inversion (wire-breaking) (Round R1.x)

- Old `Space` (security boundary) → **Realm**, old `Place` (container) →
  **Space**. SDK public types, builders, and resolver paths are renamed
  end-to-end; legacy names remain reachable as serde aliases on incoming
  events for back-compat with older servers. New typed cells
  `cx.realm.link`, `cx.realm.inheritance_policy`, and
  `cx.capability.derived` model the boundary graph.

### Added — `authz::delegation` module (capability delegation chain check) (2026-05-18)

- **`contrix::authz::delegation`** — new SDK-rooted home for capability
  delegation primitives that were previously inlined in soland's
  `AuthzEngine`. Hosts: `Grant` (runtime in-memory form), `GrantConstraint`,
  `GrantRequest`, `DelegationError` enum (variants `ParentNotFound`,
  `ParentRevoked`, `ParentExpired`, `NotGrantHolder`, `ActionsNotHeld {
  offending: Vec<String> }`, `OverExpire`, `ResourceOutOfScope`), and the
  pure helpers `delegation_chain_intact`, `delegation_chain_intact_map`,
  `create_delegated_grant`, `revoke_with_cascade`, `grant_effective_expiry`,
  `is_grant_expired`, `resource_within`. All functions are pure (slice in,
  decision out) so yougen and sodmin admin can pre-validate grant requests
  client-side before submission — the existing soland HTTP handler keeps
  the server-side enforcement contract unchanged via re-exports
  (`pub use contrix_sdk::authz::delegation::{Grant, ...}`). Enforces
  capabilities.md §10 (delegation MUST NOT widen actions, resources, or
  expiry; non-holder MUST NOT re-delegate; chain breaks on any
  revoked/expired ancestor) plus the BFS cascade contract.
  Twelve new unit tests cover the happy path, parent-revoked, parent-expired,
  over-expire (both later child expiry and child-unset-while-parent-set),
  actions overreach (with stable-dedup of offending list), resource
  out-of-scope, non-holder, parent-not-found, three-level chain with middle
  revoke breaking both descendants, cascade BFS across a five-node tree
  (two middles, two leaves; leaf-cascade is empty), and stricter-wins
  selection between top-level `expires_at` and the temporal constraint
  inside `constraints[]`. Note: the runtime `Grant` in this module is a
  sibling of the wire-spec `CapabilityGrant` in `authz::grants` — the
  former carries a stringly-typed `resource` for fast in-memory check,
  the latter carries typed `ResourceSelector` entries for canonical
  events. SDK-4; SDK lib 444 → 456 tests; soland lib 218/218 unchanged.

### Added — `profile_requirements` codegen + validator (2026-05-18)

- **`contrix_core::generated::profile_requirements`** — new generated
  module exposing per-profile `ProfileRequirements`
  (`required_operations` / `required_event_kinds` / `required_schemas`
  / `required_constraint_kinds`) as a `LazyLock<BTreeMap<&'static
  str, ProfileRequirements>>` keyed by `profile_id`. Built from
  `contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json`
  by a new `tools/generate-sdk-profile-requirements.ps1` that mirrors
  the existing profile-ID constants generator. The module ships
  `validate_profile_requirements` (returns
  `ProfileRequirementsError::UnknownProfile` /
  `MissingRequirements { missing_operations, missing_event_kinds,
  missing_schemas }`) and a higher-level
  `profile_compliance_report` (`ProfileComplianceReport` with both
  satisfied + missing partitions, plus an `is_compliant()` helper).
  Consumed by `soland describe` / `yougen claim` / `cotest gate` so
  all three present the same compliance answer against the canonical
  artifact. Eight new tests gate the module: a drift test that
  re-parses the artifact and re-builds the requirement tuples in
  memory then compares against the committed file, a
  sorted-deduplicated invariant test (uses ordinal sort to match
  Rust's `str::cmp`), and validator + report behavioural tests.
  SDK-6.

### Added — `identity::binding` module (DID key binding proof verify, Ed25519V1) (2026-05-18)

- **`contrix::identity::binding`** — new SDK-rooted module hosting the
  pure-protocol DID key binding proof primitive that coauth (and any
  future consumer — yougen, cotest, starid) calls into for the
  cryptographic verify step. Exposes:
  - `BindingProofKind::Ed25519V1` (today; `WebAuthnCose` reserved).
  - `BindingProof { kind, payload, signature, public_key }` wire
    shape, `Serialize` / `Deserialize`.
  - `verify_binding_proof(&proof, expected_subject)` — single
    `Result<(), BindingError>` entry point. Checks payload-non-empty,
    public-key / signature length, expected-subject-substring, and
    Ed25519 verify. No I/O, no DID-doc resolve — composes under
    higher-level envelopes (e.g. coauth's `cx.did_binding.control_proof.v1`
    JWT) which extract `(payload, signature, public_key)` and delegate
    the final crypto check.
  - `derive_ed25519_from_seed(&[u8; 32]) -> SigningKey` — pure RFC 8032
    seed → key, no passkey / OIDC coupling.
  - `sign_binding_proof_ed25519` — symmetric counterpart for tests and
    signer-side callers.
  - `multicodec_ed25519_public_key(&VerifyingKey) -> String` and
    `multicodec_ed25519_from_bytes(&[u8; 32]) -> String` — emit the
    `z<base58btc(0xed01 || pubkey)>` form `did:key` and starid's
    `update_keys` slot consume. Lower-level `_from_bytes` variant
    serves opaque-32-byte-identifier callers (coauth's `passkey_derive`
    hashes a COSE key down to 32 bytes and wears the Ed25519-pub
    envelope per the v1 wire-up).
  - `decode_multicodec_ed25519` — inverse of the above; validates `z`
    prefix, `0xed 0x01` tag, and 34-byte envelope length.
  - `BindingError` — `Unsupported` / `EmptyPayload` /
    `PublicKeyLength` / `SignatureLength` / `SubjectMismatch` /
    `SignatureMismatch` / `InvalidMulticodec` variants; all
    deterministic from inputs.
  - 8 new unit tests covering sign-then-verify round trip, tampered
    signature, tampered payload, wrong subject, empty payload,
    wrong-length keys / sigs, multicodec round trip + `z6Mk` prefix,
    and multicodec decode rejection of three malformed-input families.
  Closes SDK-10 from `_claude_todos.md`. Coauth's
  `services::passkey_derive` swaps its inline multicodec encoder for
  `multicodec_ed25519_from_bytes` in the COAUTH-2 follow-up; no
  wire-byte changes (starid still accepts the same `z6Mk…` strings).

### Added — `jws::sign_jws_ed25519` symmetric signer (2026-05-18)

- **`contrix::jws::sign_jws_ed25519`** — new SDK-rooted detached
  Ed25519 JWS signer. Symmetric counterpart of the existing
  `verify_jws_ed25519`: a `verify` after a `sign` over the same
  `canonical_bytes` (with a resolver that returns the matching public
  key) always round-trips. Takes `(canonical_bytes, &SigningKey)` and
  emits the wire string
  `BASE64URL({"alg":"EdDSA"}) || ".." || BASE64URL(signature)` where
  `signature = Ed25519(BASE64URL(header) || "." || BASE64URL(canonical_bytes))`,
  matching RFC 7515 §3.2 detached form. Rejects empty payload bytes
  with the same reason the verify path does, so an "empty payload"
  caller fails fast at sign time. Five new tests cover the canonical
  shape (3 segments, empty payload segment, exact header bytes,
  64-byte signature), empty-payload rejection, ed25519 sign
  determinism, sign-then-verify round trip through a single-key stub
  resolver, and tampered-payload verify rejection. Soland's anchorer
  (`src/anchorer.rs::signature_for`) drops its inline JWS
  construction in favor of this helper so the wire bytes are produced
  by exactly one implementation. SDK-1 sign side; pairs with the
  earlier verify-side landing. Closes the SO-2 dependency from
  `_claude_todos.md`.

### Added — `canonical::canonical_digest` helper (2026-05-18)

- **`contrix::canonical::canonical_digest`** — new one-liner that takes
  already-canonicalized JSON bytes (e.g. produced via
  `canonical_json_bytes`) and returns the wire-form
  `sha256:<lowercase-hex>` digest used in event envelopes
  (`canonical_digest` field), anchors, and policy-check payloads
  (`request_canonical_digest`). Thin alias for `sha256_digest` kept
  distinct so the call-site intent ("this is the wire-form canonical
  digest") is self-documenting. Downstream services (soland
  `wire.rs:560,793,816` Move/Anchor `canonical_hash` and
  `request_canonical_digest` fields, plus yougen / floria / chime as
  they migrate) call this so the same canonical bytes produce
  byte-identical digest strings everywhere. SDK-2.

### Added — `agent_binding::verify_audit_binding_by_kind` dispatcher (2026-05-18)

- **`contrix::agent_binding::verify_audit_binding_by_kind`** — single
  SDK entry point for verifying `cx.agent.protocol_session.result`
  `audit_binding` blocks, dispatched by `binding_kind` so consumers
  don't have to re-implement the scheme switch. Routes `ed25519_v1`
  through the existing `verify_ed25519_audit_binding`; future schemes
  plug in here so yougen / floria / cotest all pick them up
  uniformly. New `AuditBindingVerifyOutcome` enum collapses the two
  Ed25519 `Malformed*` outcomes into one and adds dispatcher-level
  `Absent` / `Unsupported` states for the cases the scheme-specific
  verifier never sees. Lifts the dispatch logic that previously lived
  inline in yougen's `verify_agent_audit_binding`. SDK-5.

### Moved — `default_lattice_registry()` from soland to SDK (2026-05-18)

- **`contrix::lattice_registry`** — new SDK-rooted module owning the
  cell-family `LatticeKind` trait + `LatticeRegistry` plus the
  spec-normative cell-family bindings and the `default_lattice_registry`
  / `build_sdk_cell_registry` / `lattice_bindings_for_sdk_registry`
  factories. Lifted wholesale from `soland/src/reducer/{registry,
  lattice_kinds}.rs` so yougen Move pre-check and cotest fixtures share
  one canonical registry with soland's Move/Anchor receive pipeline (49
  spec-declared cell families covered). Soland's two modules become
  thin re-export shims; existing call sites
  (`crate::reducer::registry::LatticeKind`,
  `crate::reducer::lattice_kinds::default_lattice_registry()`,
  `build_sdk_cell_registry()`) keep working without changes. Artifact
  drift tests stay in soland (they consult `crate::artifacts::*`).
  Intentionally NOT feature-gated so principal-server style consumers
  pick it up without dragging in `full-surface`. SDK-8.

### Added — `jws` module (RFC 7515 detached Ed25519) (2026-05-18)

- **`contrix::jws`** — new SDK-rooted module consolidating the
  RFC 7515 detached Ed25519 JWS verifier that previously lived in
  `soland/src/jws_verify.rs`. Same wire bytes / same accept-reject
  decision, now shared across every consumer (yougen, floria, cotest,
  teabay, soland) so they all hit the same `Ok(()) / Err(reason)` for
  the same `(canonical_bytes, jws, verification_method, issuer,
  resolver)` tuple. Surfaces: `verify_jws_ed25519` (full pipeline:
  shape + alg=EdDSA + DID resolve + ed25519-dalek verify, takes
  `&dyn DidResolver` so callers pick the method chain),
  `resolve_ed25519_pubkey` (DID URL → `VerifyingKey`, fragment-fallback
  + single-key shortcut for did:key documents),
  `verify_replay_window` / `verify_replay_window_at` (HLC freshness
  bounding, injectable wall-clock for tests),
  `verify_replay_window_for_move` / `verify_replay_window_for_move_at`
  (per-cell-family override picking the tightest applicable window),
  `effective_window_for_move`, `physical_millis_from_hlc`. All error
  paths return `Result<_, String>` with descriptive reasons. No new
  workspace deps — reuses `ed25519-dalek`, `base64`, `chrono`,
  `serde_json` already in `crates/sdk`, and the existing
  `identity::helpers::decode_base58btc` for multibase decoding. Gated
  on `full-surface` because it consumes `identity::DidResolver`.
  Soland's `jws_verify` is now a thin `AppState` → `&dyn DidResolver`
  adapter over this module.

### Added — `http_signature` module (RFC 9421) (2026-05-18)

- **`contrix::http_signature`** — new HTTP-framework-agnostic
  module that consolidates the RFC 9421 HTTP Message Signature
  logic previously duplicated in `floria/src/auth.rs` (verifier)
  and `chime/src/push/signing.rs` (signer). Surfaces:
  `SignatureInput` + `parse_signature_input` (header parser, no
  panic on unknown components or missing params),
  `SignedRequestParts` (method / target-uri / authority / path /
  headers / optional body-digest projection — works for Salvo,
  reqwest, hyper, etc.), `canonical_message` (emits the RFC 9421
  §2.5 signing-string bytes, including the bit-exact
  `@signature-params` line), `sign_message` / `verify_signature`
  (Ed25519 over those bytes, base64 standard alphabet for the
  `Signature` header), `ContentDigest` + `verify_content_digest`
  (RFC 9530 sha-256 / sha-512), and a discriminated
  `SignatureError` enum (12 variants — no stringly-typed errors).
  Wasm32-safe (only `ed25519-dalek` + `sha2` + `base64`, all
  already in the workspace). Consumers (floria, chime, soland
  fanout, future teabay middleware) will migrate in Lane E.

### Internal — typed `ConstraintParseError` for recurrence helpers (2026-05-18)

- **`contrix::authz::constraints`** — the recurrence parsing helpers
  (`recurrence_allows`, `recurrence_next_transition_after`,
  `parse_recurrence_zone`, `parse_recurrence_day`, `parse_recurrence_time`,
  `recurrence_frequency_allows`) now return `Result<_, ConstraintParseError>`
  instead of `Result<_, String>`. The new `pub(super) enum
  ConstraintParseError` has structured variants (`InvalidTimezone`,
  `InvalidDay`, `InvalidTime`, `InvalidFrequency`,
  `OutsideWeekdayRecurrence`, `OutsideWeekendRecurrence`,
  `OutsideRecurrenceDays`, `OutsideWindow`) so the engine can pattern
  match on failure kind instead of string-comparing. **Public API
  unchanged**: the engine boundary in `authz::engine::evaluate_constraint`
  renders the enum via `Display`, which preserves every existing deny
  reason byte-for-byte (e.g. `"unsupported recurrence timezone: UTC99"`,
  `"outside recurrence window"`, `"outside weekday recurrence: Sun"`).
  No compat shim — the enum is internal (`pub(super)`).

### Added — Applet / Agent protocol-session OP constants + registry (2026-05-16)

Round 13. Mirror of soland round 14f wire validator. The 9 sub-events
of the applet (`cx.applet.{registration,discovery,protocol_session.{start,status},bridge_error}`)
and agent (`cx.agent.{endpoint,protocol_session.{start,status,result}}`)
families were registered as event kinds in `crates/core/src/events/kinds.rs`
but had no `OP_*` aliases or `required_fields_for_operation_kind` entries
in `crates/core/src/model/`. This round adds both so downstream consumers
(soland, yougen, …) can validate submit payloads using the same registry
abstraction as the rest of the reducer-input event family.

- **`contrix-core`** — all changes in `crates/core/src/model/`:
  - `constants.rs`: new `OP_APPLET_BRIDGE_ERROR` / `OP_APPLET_DISCOVERY` /
    `OP_APPLET_PROTOCOL_SESSION_START` / `OP_APPLET_PROTOCOL_SESSION_STATUS`
    / `OP_APPLET_REGISTRATION` / `OP_AGENT_ENDPOINT` /
    `OP_AGENT_PROTOCOL_SESSION_RESULT` / `OP_AGENT_PROTOCOL_SESSION_START`
    / `OP_AGENT_PROTOCOL_SESSION_STATUS` constants (alphabetically
    grouped under new Applet protocol / Agent protocol section
    headers). Doc-comment makes explicit these are reducer-input
    EVENTS (registered in spec `event-kind-registry.json`), not RPC
    service operations — so they intentionally do NOT appear in
    `BUILT_IN_OPERATION_KINDS` (which mirrors `operation-registry.json`
    and is gated by `SpecArtifactBundle::drift_report`). Same convention
    as the lifecycle event ops (`OP_FLOW_CREATE`, `OP_FLOW_TRACK_*`, etc.)
    that have always been kept out of the built-in list.
  - `registry.rs::required_fields_for_operation_kind` gets 9 new arms:
    `OP_APPLET_REGISTRATION` → `[service_did, namespace]`
    `OP_APPLET_DISCOVERY` → `[service_did, manifest]`
    `OP_APPLET_PROTOCOL_SESSION_START` → `[applet_id, session_id]`
    `OP_APPLET_PROTOCOL_SESSION_STATUS` → `[session_id, status]`
    `OP_APPLET_BRIDGE_ERROR` → `[session_id, errcode]`
    `OP_AGENT_ENDPOINT` → `[agent_did, protocol]`
    `OP_AGENT_PROTOCOL_SESSION_START` → `[agent_did, session_id, capability_proof]`
    `OP_AGENT_PROTOCOL_SESSION_STATUS` → `[session_id, status]`
    `OP_AGENT_PROTOCOL_SESSION_RESULT` → `[session_id, result, audit_binding]`
    Mirrors soland round 14f `FLOW_TRACK_REQUIREMENTS` shape exactly.

- **`contrix` (sdk)** — no changes. These events don't affect
  client-side projection state (applet bridge state machine lives in
  the client app; agent session signing audit binding is verified at
  the agent endpoint). The reducer's `process_event_content` already
  falls through to the "Unknown event types do not affect the local
  reducer state" branch for them, which is correct.

- **Spec references**:
  - `extensions/applet-integration.md` event-kind-registry rows for
    the 5 applet sub-events.
  - `extensions/agent-integration.md` event-kind-registry rows for
    the 4 agent sub-events.
  - `event-kind-registry.json` artifact (already published).

- **Out of scope (follow-up)**:
  - **Resolver state for applet / agent sessions** — spec doesn't yet
    define a server-side state machine for protocol sessions; both
    families are session-scoped (start → status* → terminal) with the
    state living at the applet / agent endpoint itself. If spec adds
    canonical session state tracking, SDK reducer can mirror that.

### Added — `cx.flow.track.*` reducer handlers (2026-05-16)

Round 12. SDK previously declared the four `cx.flow.track.*` event-kind
constants (`FLOW_TRACK_DISABLE` / `FLOW_TRACK_ENABLE` /
`FLOW_TRACK_SET_PRIMARY` / `FLOW_TRACK_UPDATE`) in
`crates/core/src/events/kinds.rs` but had no `OP_*` operation constants,
no operation-registry required-fields entries, and no resolver
dispatcher branches — events landed and dispatched as "Unknown event
type" no-ops. This round wires the full reducer surface so client-side
state machines correctly maintain `Flow.tracks` from the event log.

- **`contrix-core`**:
  - `crates/core/src/model/constants.rs`: new `OP_FLOW_TRACK_DISABLE` /
    `OP_FLOW_TRACK_ENABLE` / `OP_FLOW_TRACK_SET_PRIMARY` /
    `OP_FLOW_TRACK_UPDATE` constants (alphabetically grouped under the
    Flow header, after `OP_FLOW_REORDER`).
  - `crates/core/src/model/registry.rs::required_fields_for_operation_kind`
    new arms: `OP_FLOW_TRACK_DISABLE | OP_FLOW_TRACK_ENABLE |
    OP_FLOW_TRACK_SET_PRIMARY` → `[flow_id, track_id]`;
    `OP_FLOW_TRACK_UPDATE` → `[flow_id, track_id, patch]`.

- **`contrix` (sdk)**:
  - `crates/sdk/src/resolver/mod.rs`: re-export the four new `OP_*` from
    the `model::*` use list.
  - `crates/sdk/src/resolver/state.rs`:
    - `process_event_content` dispatcher gets four new arms calling new
      helpers `enable_flow_track` / `disable_flow_track` /
      `update_flow_track` / `set_primary_flow_track`.
    - New helper `extract_flow_track_id` reads `track_id` (fallback
      `track_name`) from event content; returns `Err(Protocol("flow
      track event requires track_id"))` if absent — same convention as
      the existing `extract_flow_id` / `extract_morph_id` helpers.
    - All four track helpers enforce the spec common-fields.md §5.1
      "update on non-active object MUST fail" rule: parent Flow's
      `state` MUST be `Some(ObjectState::Active)`; otherwise
      `failed_precondition` with `flow_not_active` and the reducer
      makes no mutations. Unknown Flow tolerated (causal / backfill —
      same convention as `restore_*` and `archive_*` guards).
    - `enable_flow_track`: validate track name against
      `validate_flow_track_name`, then `tracks.entry(track_id)
      .or_insert_with(FlowTrackConfig::default)` — re-enable is a
      no-op on the config but still bumps `updated_at` for audit.
    - `disable_flow_track`: `tracks.remove(track_id)`; unknown track
      tolerated.
    - `update_flow_track`: reads `patch` object from event content;
      merges `is_primary` / `profile` / `template` / `fields`. Unknown
      track is created (matches existing `update_flow` upsert
      behaviour for new fields).
    - `set_primary_flow_track`: clears `is_primary` on every track,
      then sets it on the named one. Validates track exists in the
      Flow's tracks map; if absent, the primary swap is a no-op (causal
      tolerance) but `updated_at` still advances.
  - Five resolver tests added in `crates/sdk/src/resolver/tests.rs`:
    `flow_track_enable_inserts_into_tracks_map`,
    `flow_track_disable_removes_from_tracks_map`,
    `flow_track_update_patches_track_config`,
    `flow_track_set_primary_clears_others_and_marks_named`,
    `flow_track_event_rejected_when_flow_archived`.

- **Spec references**:
  - Spec event-kind-registry: `cx.flow.track.{enable,disable,update,set_primary}`
    (`category: flow`, `wire_scope: durable_event`, `reducer_input: true`).
  - `common-fields.md §5.1` final paragraph — update on non-active
    object MUST fail.

- **Out of scope (follow-up)**:
  - **soland canonical registry + wire validator** — soland's
    server-side admission (`event_log::submit_event`) currently treats
    `cx.flow.track.*` as opaque envelopes (canonical-kind registry
    doesn't recognise them). soland round 14d adds the canonical
    registration + state-machine preflight in parallel with this round.
  - **Place tracks** — Place doesn't have a `tracks` field; Flow is
    the only canonical object with sub-event-managed track membership.

### Tightened — `cx.redaction` flips Flow / Morph subject state (2026-05-16)

Completes spec `common-fields.md §5.1` redaction row for Flow / Morph.
Round 10 closed the archive / tombstone / update source-state matrix;
this round (round 11) extends `cx.redaction` so that targeting a Flow /
Morph object via the event content's `object_ref` field flips the
subject's projection state to `ObjectState::Redacted` (terminal). Until
this round, `redact_event` only cleared the target event's content while
the corresponding Flow / Morph subject's `state` remained `Active` —
soland round 14b had to add the same logic server-side to enforce the
spec rule, and SDK was the divergent side. Now the two are symmetric.

- **`contrix` (sdk)** — all changes in `crates/sdk/src/resolver/state.rs`:
  - New helper `redact_object_for_event(event)` extracts `object_ref`
    (fallback `target_object_ref`) from the redaction event's `content`.
    When that names a Flow / Morph subject (`cx:flow:` / `cx:morph:`),
    the helper validates `state ∈ {Active, Archived}` and flips it to
    `Redacted` along with `state_changed_at`, `updated_by`, `updated_at`.
    Terminal source (`Deleted` / `Redacted`) MUST `failed_precondition`
    with `flow_already_terminal` / `morph_already_terminal`. Unknown
    subject is tolerated (causal / backfill ordering — same convention
    as `restore_*` and `archive_*` guards).
  - `process_event_content` `cx.redaction` arm now invokes
    `redact_object_for_event` BEFORE `redact_event` clears the target
    event content. The state-machine guard runs first so a rejected
    redaction cannot leave the event partially redacted.
  - Place is intentionally excluded — `PlaceState` has no `Redacted`
    variant; spec routes Place removal through `cx.place.tombstone`
    only. Redactions naming a Place subject fall through to the
    "unknown subject" tolerance branch silently (Place isn't kept in
    `subjects` / `morphs`).
  - Four resolver tests added in `crates/sdk/src/resolver/tests.rs`:
    `redaction_with_flow_object_ref_flips_subject_to_redacted`,
    `redaction_with_morph_object_ref_flips_subject_to_redacted`,
    `redaction_against_already_redacted_flow_rejects`,
    `redaction_against_already_redacted_morph_rejects`. Each asserts
    the canonical reason code in the error AND that the failed
    reducer write left no side effects.

- **Spec references**:
  - `common-fields.md §5.1` redaction row — `cx.<kind>.redact` /
    `cx.redaction` source MUST be `active|archived`, target `redacted`,
    reject with `<kind>_already_terminal`.
  - `common-fields.md §5.1` "终态等价" — `tombstoned` / `deleted` /
    `redacted` are equivalent unrecoverable terminals.
  - Spec note "Place 没有 redacted" — Place removal goes through
    `cx.place.tombstone` instead of `cx.redaction`.

- **Out of scope (follow-up)**:
  - **un-redaction for Flow / Morph** — `cx.message.redact` supports
    a `redaction_value: null` un-redact path for messages. Flow /
    Morph `Redacted` is a terminal state by spec, so the current
    behaviour (no un-redact path) is correct; no SDK change needed.
  - **Place redaction via `cx.redaction`** — see above. Future spec
    tightening may add a dedicated `cx.place.redact` path; not in v1.

### Tightened — Archive / tombstone / update source-state guards (2026-05-16)

Completes spec `common-fields.md §5.1` canonical state-transition table
across all three lifecycle families (Flow / Morph / Place). Round 8 added
`*.restore` source-state guard for Place; round 9 mirrored that for Flow
and Morph; this round (round 10) closes the remaining matrix: archive on
non-active source, tombstone on a terminal source, and the §5.1 final
paragraph rule that `*.update` MUST fail on a non-active object (otherwise
edits would silently revive an archived/tombstoned object, conflicting
with `*.restore` semantics).

- **`contrix` (sdk)** — all changes in `crates/sdk/src/resolver/state.rs`:
  - `archive_flow` previously delegated unconditionally to
    `set_flow_state(Archived)`. It now validates
    `state == Some(ObjectState::Active)` first; non-Active source MUST
    `failed_precondition` with `flow_not_active`. Unknown Flow is
    tolerated (causal / backfill) — same as the restore guards.
  - `archive_morph` (a new helper; previously the dispatcher inlined
    `set_morph_state(Archived)`) and `archive_place` (a new helper;
    previously inlined `set_place_state(Archived)`) follow the same
    contract: `morph_not_active` / `place_not_active` on non-Active
    source; unknown object tolerated. The dispatcher
    (`process_event_content`) now routes through the named helpers.
  - `tombstone_place` is a new helper (previously inlined
    `set_place_state(Tombstoned)`). Per §5.1, `cx.<kind>.tombstone` is
    legal from `active` OR `archived`; reject `tombstoned` (terminal
    self-transition) with `place_already_terminal`. Note that `*.tombstone`
    events exist for Place only in the spec registry; Flow / Morph
    don't have dedicated tombstone events.
  - `update_flow`, `update_morph`, and `update_place` now reject when the
    target's current state is non-Active (per `common-fields.md §5.1`
    final paragraph). Reasons mirror archive: `flow_not_active`,
    `morph_not_active`, `place_not_active`. This is a behavioural
    tightening — prior code allowed updating archived objects, silently
    bypassing the canonical `*.restore` re-entry path.
  - Eight new resolver tests in `crates/sdk/src/resolver/tests.rs`:
    `place_archive_rejected_when_already_archived`,
    `place_archive_rejected_when_tombstoned`,
    `place_tombstone_rejected_when_already_terminal`,
    `flow_archive_rejected_when_already_archived`,
    `morph_archive_rejected_when_already_archived`,
    `place_update_rejected_when_archived`,
    `flow_update_rejected_when_archived`,
    `morph_update_rejected_when_archived`. Each asserts the canonical
    reason_code is present in the error AND that the failed reducer
    write left no side effects.

- **Spec references**:
  - `common-fields.md §5.1` — canonical state-transition table introducing
    the symmetric reason_code family: `<kind>_not_active` /
    `<kind>_not_archived` / `<kind>_already_terminal`.
  - `common-fields.md §5.1` final paragraph — `*.update` MUST fail on
    non-active object as an invariant.
  - `common-fields.md §5.1` "未知对象容忍" — unknown object is tolerated;
    only state checks on materialised objects run.

- **Out of scope (follow-up)**:
  - `cx.redaction` source-state guard for Flow / Morph / Message — spec
    §5.1 also covers `cx.<kind>.redact` / `cx.redaction` with the same
    `<kind>_already_terminal` semantics, but the redaction reducer path
    lives in a different code surface than the lifecycle dispatcher.

### Tightened — Flow / Morph restore state-machine guards (2026-05-15)

Completes the spec `common-fields.md §5` symmetry across all three lifecycle
families (Flow / Morph / Place). Prior to this round, only `cx.place.restore`
validated source state (added in the cx.place.restore round); `cx.flow.restore`
and `cx.morph.restore` unconditionally flipped state to Active regardless of
source. Spec is explicit: `*.restore` is the canonical `archived → active`
path, and `tombstoned` / `deleted` / `redacted` MUST NOT be restored. This
round pins that invariant in the reducer for Flow and Morph as well.

- **`contrix` (sdk)**:
  - `restore_flow` in `crates/sdk/src/resolver/state.rs` now validates
    `state == Some(ObjectState::Archived)` before delegating to
    `set_flow_state(Active)`. Source state Active / Deleted / Redacted /
    unset MUST `failed_precondition` with `flow_not_archived` and the
    reducer makes no mutations. Unknown Flow (causal / backfill not yet
    caught up) is tolerated — same policy as `restore_place`.
  - `OP_MORPH_RESTORE` dispatcher branch in the same file no longer
    routes directly to `set_morph_state(Active)`; it now calls a new
    `restore_morph` helper. Same contract as `restore_flow`: validate
    `state == Some(ObjectState::Archived)`, reject otherwise with
    `morph_not_archived`. Morph has no `state_changed_at` field so the
    success path is symmetric only on what Morph actually carries.
  - Four resolver tests added in `crates/sdk/src/resolver/tests.rs`:
    `flow_archive_then_restore_round_trip` (state transitions back to
    Active, `state_changed_at` matches the restore Event's `created_at`),
    `flow_restore_rejected_when_active` (verifies error contains
    `flow_not_archived` AND that the failed reducer write doesn't
    promote `state_changed_at`), `morph_archive_then_restore_round_trip`,
    and `morph_restore_rejected_when_active`. The "reject when
    tombstoned" path is logically equivalent to the "reject when active"
    path — both exercise the same `state != Some(Archived)` branch — so
    one rejection test per family covers the unit-level guard.

- **Spec references**:
  - `common-fields.md §5` — canonical state machine, `*.restore`
    semantics, `tombstoned / deleted / redacted MUST NOT 被 restore`.
  - `space-and-place.md §4.4` — the Place precedent this round mirrors.

- **Wire compat**: backward-compatible. New rejection paths only fire on
  inputs that were silently being miscategorized before (e.g. an
  attacker's attempt to restore a tombstoned Flow); well-behaved clients
  emit restore only after archive, which still works.

- **Out of scope (follow-up)**:
  - `cx.flow.archive` / `cx.morph.archive` / `cx.place.archive` /
    `cx.*.tombstone` themselves still don't validate source state. Spec
    doesn't have explicit MUST for those transitions — likely needs spec
    work first to nail down (e.g. is archive-of-tombstoned a
    `failed_precondition` or an idempotent no-op?). Separate PR.

### Added — `cx.place.restore` (2026-05-15)

Mirror the new `cx.place.restore` event kind landed in `../contrix-spec`
(Unreleased changelog entry "新增 `cx.place.restore` 修正 Place 生命周期对称性").
Previously the SDK had `cx.place.archive` / `cx.place.tombstone` but no way to
reverse archive — clients had no wire-legal path to unarchive a board / list,
and reducers had no spec-aligned state-machine entry. With this round the SDK
implements the canonical `archived -> active` transition end-to-end.

- **`contrix-core`**:
  - `events::PLACE_RESTORE` constant (`"cx.place.restore"`) added in
    `crates/core/src/events/kinds.rs`, inserted into the sorted
    `STANDARD_EVENT_KINDS` array (binary-searched by
    `is_standard_event_kind`) between `PLACE_PARENT` and `PLACE_TOMBSTONE`,
    and added to the `Place` arm of `classify_event_kind`.
  - `model::OP_PLACE_RESTORE` constant added in
    `crates/core/src/model/constants.rs` alongside `OP_PLACE_ARCHIVE` /
    `OP_PLACE_TOMBSTONE`; auto-re-exported via `pub use constants::*`.
  - `required_fields_for_operation_kind` (in `crates/core/src/model/registry.rs`)
    extends its existing `OP_PLACE_ARCHIVE | OP_PLACE_TOMBSTONE` arm to
    `OP_PLACE_ARCHIVE | OP_PLACE_RESTORE | OP_PLACE_TOMBSTONE` — restore
    requires the same single `place_id` field as archive.

- **`contrix` (sdk)**:
  - `Space::restore_place_operation(place_id)` constructs the spec-shaped
    `cx.place.restore` operation, mirroring `archive_place_operation`
    (same `OperationType::Update`, same `{ "place_id": ... }` payload).
  - Resolver `SpaceState::process_event_content` adds an `OP_PLACE_RESTORE`
    branch backed by a new `restore_place` reducer in
    `crates/sdk/src/resolver/state.rs`. The reducer validates current
    `state == Archived` per `contrix-spec` `space-and-place.md §4.4`; any
    other state (`Active`, `Tombstoned`, unset) MUST `failed_precondition`
    with `place_not_archived` and the reducer makes no mutations. Unknown
    Place (causal / backfill not yet caught up) is tolerated, matching the
    existing `set_place_state` policy.
  - Three resolver tests added in `crates/sdk/src/resolver/tests.rs`:
    `place_archive_then_restore_round_trip` (state transitions back to
    Active with correct `state_changed_at`),
    `place_restore_rejected_when_active`, and
    `place_restore_rejected_when_tombstoned`. Both rejection tests verify
    the error string contains `place_not_archived` and that the failing
    event does not mutate the Place state.

- **Spec references**:
  - `contrix-spec` event_kind_registry / capability_action_registry now
    list `cx.place.restore`.
  - `space-and-place.md §4.4` "Restore Place" subsection is the normative
    source for the reducer guard above.
  - `conformance-vectors.md §6.2-6.4` are the wire-level conformance
    vectors this SDK round satisfies.

- **Migration**: writers that previously had no wire path for unarchiving
  Places (or were emitting `cx.place.update` with a top-level `state`
  patch as a workaround) MUST switch to `cx.place.restore`. The reducer
  here enforces the new guard; downstream impls (soland, yougen) need to
  catch up separately — tracked in their own `_todos.md` files.

- **Out of scope (follow-up)**:
  - `cx.place.archive` / `cx.place.tombstone` themselves still don't
    validate the source state (a pre-existing gap not introduced here);
    same is true for `cx.flow.restore` / `cx.morph.restore`. Addressing
    that surface is a separate PR.

### Added — round 8 (2026-05-15): MAL-11 + snapshot v2 + per-admin signing

Three new SDK surfaces requested by the soland principal server.

- **MAL-11 anchor compaction primitives** in `contrix-core`:
  - New `AnchorKind` enum (`Normal` / `Compaction`) added to the
    `Anchor` struct as a `#[serde(default)]` field — `Normal` is
    omitted from the wire, so pre-MAL-11 envelopes deserialize as
    `Normal` and serialize byte-identically. `Compaction` participates
    in the canonical-bytes-for-id hash, so an attacker can't relabel a
    normal anchor as compaction without invalidating its id.
  - `Anchor::sign_single_kind` / `sign_threshold_kind` /
    `sign_multi_kind` companion methods accept an explicit
    `AnchorKind`. The non-`_kind` shortcuts default to `Normal` and
    remain source-compatible.
  - `AnchorStore::successors(space_id, anchor_id)` returns direct
    children — used by the compaction pipeline to find what to rewire
    when pruning.
  - `AnchorStore::prune_predecessor(space_id, anchor_id)` drops the
    named anchor and rewires its direct successors' `predecessor_refs`
    to bypass it (deduped against grandparents). Refuses to prune a
    leaf; refuses to prune if the anchor isn't in the store. Returns
    the list of rewired successor ids.
  - `MemoryAnchorStore` implements both new trait methods. Other
    backends inherit `Err(Backend("not implemented"))` defaults so
    they compile but fail-closed.
  - New `CompactionPolicy` + `PruneCandidate` + `PruneEligibility`
    types in `state::compaction`. Policy fields:
    `min_anchor_age_seconds` (default 7 days),
    `min_compaction_witnesses` (default 1), `preserve_genesis`
    (default true), `prune_only_singleton_successors` (default true).
- **Snapshot chunk v2 primitives** in `contrix-core::snapshot`:
  - `SnapshotChunker` — deterministic byte-range partitioning with
    configurable `target_chunk_bytes` (default 256 KiB).
  - `SnapshotChunk` — `{chunk_id, bytes, digest}` with base64-url
    wire encoding.
  - `SnapshotMerkleTree` — RFC 6962-style binary Merkle over chunk
    digests; `audit_path(leaf_index)` returns the sibling chain;
    stateless `SnapshotMerkleTree::verify` lets receivers verify a
    single chunk without rebuilding the tree.
  - `GeneratorProof` — generator's signed commitment to
    `(state_root, merkle_root, chunk_count, total_bytes, chunk_bytes)`.
    `body_digest` returns the canonical payload hash; receivers call
    `verify_payload_digest()` then run their own JWS verifier on
    `signature.jws`.
- **Per-admin signing key + session-grant introspection** in
  `contrix-core::admin_signer`:
  - `AdminKeyStore` wraps any `KeyStore` and addresses per-admin
    signing keys via canonical id
    `contrix:signer:admin:<application_id>:<did>`. `load_admin_key` /
    `store_admin_key` / `delete_admin_key` / `has_admin_key` /
    `list_admin_dids` all key off `Did`.
  - `SessionGrantIntrospection` is the typed view of an OAuth-style
    introspection response carrying `(principal_did, admin_scopes[],
    expires_at_unix, device_id, audit_context)`.
    `is_currently_active`, `has_admin_scope`, and `require_admin_scope`
    are convenience guards for handler code.
  - `admin_scopes` module exposes conventional scope strings
    (`ANCHORER_RECONFIGURE`, `ANCHOR_COMPACT`, `ANCHOR_PRUNE`,
    `BOTTOM_REPAIR`, `ADMIN_READ`, etc.).

### Test coverage

`contrix-core` lib tests: **298 → 342 passed** (rounds 6/7 baseline →
round 8, +44 new). Highlights:
- 6 new tests for `AnchorKind` (default, wire omission, canonical-id
  forgery defense, JSON round-trip, missing-field default).
- 4 new tests for `AnchorStore::successors` /
  `AnchorStore::prune_predecessor` (rewire, leaf rejection, dedup).
- 10 new tests for `CompactionPolicy` (per-flag rejection, eligibility
  composition, serde round-trip).
- 17 new tests for snapshot v2 (chunker determinism, Merkle round-trip
  at sizes 1/2/3/4/5/8/11, audit-path verify success + tamper
  rejection, GeneratorProof digest stability + serde round-trip).
- 13 new tests for `AdminKeyStore` + `SessionGrantIntrospection`
  (per-admin id format, isolation, list/sort, missing-key NotFound,
  introspection expiry + scope gating).

### Compat notes

- `Anchor` struct gained one required field (`kind: AnchorKind`).
  Source-compat: callers must initialize it (`AnchorKind::Normal`
  preserves prior behavior). Wire-compat: `Normal` round-trips
  byte-identically because of `skip_serializing_if`.
- All three new modules are additive; no other public API is changed.

## [0.7.0] – 2026-05-10 — wasm32 workspace closure + release hardening

This release closes the wasm32 build story for the entire workspace and is
the first release where `cargo build --target wasm32-unknown-unknown
--workspace --lib --locked` is fully green alongside the native
`774 / 0 / 0` lib test suite. No wire-level breaking changes vs `0.6.0`;
the bump is for the SDK API surface adjustments described below.

### Added

- **Per-target `openmls` feature gating** in `crates/sdk/Cargo.toml`. The
  workspace `openmls` dependency is now declared once for native (lean,
  no extra features) and once for `cfg(target_arch = "wasm32")` with the
  `js` feature enabled, which transitively activates
  `fluvio_wasm_timer` + `js-sys` so MLS group state machinery has a
  browser-compatible timer source.
- **`uuid` wasm32 randomness**: `crates/identifiers/Cargo.toml` declares
  a `cfg(target_arch = "wasm32")` block enabling `uuid`'s `js` feature
  plus `getrandom = { features = ["wasm_js"] }` and a renamed
  `getrandom_02 = { package = "getrandom", version = "0.2", features = ["js"] }`
  so both the v0.3 and v0.2 (transitive via `rand_core` from
  `ed25519-dalek`) lines wire to the wasm-bindgen RNG path. (C35.1)

### Changed

- **`contrix-client` `TransportConfig` is now per-target.** The native
  variant retains the full set of fields (`timeout`, `connect_timeout`,
  `pool_idle_timeout`, `pool_max_idle_per_host`, `tcp_nodelay`,
  `tcp_keepalive`, `http2_keep_alive_*`, `proxies`, `no_proxy`,
  `redirect`, `gzip`); on `cfg(target_arch = "wasm32")` it is a unit
  struct with no-op `is_default()` / `apply()` because the browser
  `fetch` transport governs those policies. The 13 corresponding
  builder methods (`timeout`, `connect_timeout`, `pool_*`, `tcp_*`,
  `http2_keep_alive_*`, `proxy`, `no_proxy`, `redirect`, `gzip`) are
  `#[cfg(not(target_arch = "wasm32"))]`. `RetryConfig` fields are
  annotated `cfg_attr(target_arch = "wasm32", allow(dead_code))`.
  (C36.0)
- **`Client::execute` is split per-target.** Native retains the retry
  loop driven by `tokio::time::sleep`; on wasm32 the body collapses to
  `validate_request_builder` + `builder.send().await` — embedders that
  want retry/backoff in the browser should layer it on top with
  `gloo-timers` since neither `tokio::time::sleep` nor
  `reqwest::Error::is_connect()` are available in that environment.
  (C36.0)
- **`crates/sdk/src/lib.rs::http_did_resolver` and the
  `AsyncSyncTransport` / `EventsSubscribeTransport` impls in
  `crates/sdk/src/sync_client.rs`** are `cfg`-gated to native targets.
  Their `Send`-bound `BoxSyncFuture` return types are incompatible with
  the wasm32 `reqwest::Response` (carries `JsValue` / `Closure` /
  `JsFuture`, all `!Send`); the underlying traits remain `pub` so
  downstream wasm crates can supply a `LocalBoxFuture`-style transport.
  (C36.0)
- **Crate version `0.6.0 → 0.7.0`** across the workspace (root
  `[workspace.dependencies]` plus the 23 member crates).

### Security / Maintenance

- **`rustls-webpki` bumped `0.103.3 → 0.103.13`** to clear
  `RUSTSEC-2026-0049`, `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, and
  `RUSTSEC-2026-0104` (CRL handling, name-constraint matching, and a
  reachable parser panic). Pulled in transitively via
  `reqwest -> hyper-rustls -> tokio-rustls -> rustls`.
- **`Cargo.lock` rolls** — futures family bumped to 0.3.32 to resolve a
  conflict between `multra`/`hyper`/`h2` and openmls's wasm `js`
  feature; new transitives `fluvio-wasm-timer 0.2.5`, `bitflags 1.3.2`,
  `instant 0.1.13`, `parking_lot 0.11`, `redox_syscall 0.2.16`,
  `winapi 0.3.9` appear on the wasm32 side only.
- **`.deny.toml`** advisory ignore list pruned: removed two stale
  entries (`RUSTSEC-2024-0436` paste, `RUSTSEC-2024-0388` derivative)
  that no longer match anything in the lock; added
  `RUSTSEC-2024-0384` (unmaintained `instant`, transitive via
  `openmls 0.8.1` → `fluvio-wasm-timer` on the wasm path; no upgrade
  available pending an openmls upstream bump). `cargo deny check` is
  green: `advisories ok, bans ok, licenses ok, sources ok`.

## [0.6.0] – 2026-05-10 — Spec sync (`contrix-spec` `f724863..48898bf`)

Wire-breaking spec alignment pass. v1 is unreleased so this is a hard
break with no compat shims, no `#[deprecated]` adapters, and no
legacy-form fallback in `Deserialize`.

### Breaking

- **`Flow.tracks` is now an object/map**, not an array.
  - `Flow.tracks: Vec<FlowTrack>` → `Flow.tracks: BTreeMap<String,
    FlowTrackConfig>`. The track name is the map key and is no longer
    carried as a struct field.
  - Renamed `FlowTrack` → `FlowTrackConfig` and dropped the `name`
    field. Custom `Deserialize` impl (which accepted bare-string and
    full-object forms) is removed; the struct now derives
    `Deserialize` directly.
  - Helper constructors return a `FlowTrackConfig` to be inserted
    under the canonical map key (`FLOW_TRACK_NAME_SYNTHESIS` /
    `FLOW_TRACK_NAME_DISCUSSION`):
    `FlowTrackConfig::synthesis()`, `FlowTrackConfig::discussion()`,
    `FlowTrackConfig::discussion_primary()`, plus the chainable
    `with_profile(..)` / `primary()` builders.
  - `FlowTrack::validate_name` (instance method) is replaced by the
    free function `validate_flow_track_name(name: &str)` that validates
    a candidate map key against `^[a-z][a-z0-9_]{0,63}$`.
  - `resolve_primary_track` signature is now
    `fn(&BTreeMap<String, FlowTrackConfig>, Option<&str>) ->
     Result<Option<(&String, &FlowTrackConfig)>>`. Same fail-closed
    rule when more than one track sets `is_primary=true`; fallback
    rules (synthesis-by-default, single-track, profile_default) match
    against the map key.
  - `Flow::discussion(..)` constructs the chat-style room form by
    inserting `FlowTrackConfig::synthesis()` and
    `FlowTrackConfig::discussion_primary()` under the canonical names.
- **`/device_messages` is now `POST` + `Idempotency-Key` header**.
  - Endpoint registry: `cx.device_messages.put` is `POST
    /api/v1/device_messages` (was `PUT
    /api/v1/device_messages/{txn_id}`).
  - `Client::send_device_messages(idempotency_key, request)` switches
    to `POST` and propagates the key via the `Idempotency-Key`
    request header.
  - `ToDeviceMessage` (in both `contrix_core::model` and
    `contrix_core::sync`) drops its `Option<String> txn_id` field —
    the wire envelope no longer carries it.
  - `OP_DEVICE_MESSAGES_PUT` required-fields list drops `txn_id`.
  - `DeviceMessageEnvelope` (`crates/sdk/src/devices.rs`) drops its
    `txn_id` field to match
    `device-message.schema.json`.
- **`/applet/transactions` is now `POST` + `Idempotency-Key` header**.
  - Endpoint registry: `cx.applet.transaction` is `POST
    /api/v1/applet/transactions` (was `PUT
    /api/v1/applet/transactions/{txn_id}`).
  - `Client::applet_transaction(idempotency_key, request)` switches to
    `POST` + `Idempotency-Key` header.
  - Server route table, OpenAPI document, conformance vectors, and
    Salvo router debug strings updated to the new shape.
- API endpoint headers list: both `cx.device_messages.put` and
  `cx.applet.transaction` declare a required `Idempotency-Key` header.

### Changed

- Crate version `0.5.2 → 0.6.0` across the workspace.

## [0.5.1] – 2026-05-09 — Platform `KeyStore` native backends

Round 23 of the SDK: turns the Round-22 `KeyStore` platform stubs into
real implementations behind per-target feature flags. `v1` wire is
unchanged; this is an additive SDK API release.

### Added

- **`MacOsKeychainKeyStore` (macOS Keychain Services)** behind the new
  `keystore-macos` feature, wired to the `security-framework` crate's
  generic-password APIs (`set_generic_password` / `get_generic_password`
  / `delete_generic_password` plus `ItemSearchOptions` for `list()`).
  Items live under service name `"contrix.<application_id>"`. 5 unit
  tests gated on `cfg(target_os = "macos")`.
- **`LinuxSecretServiceKeyStore` (D-Bus Secret Service)** behind the new
  `keystore-linux` feature, wired to the `secret-service` crate's
  blocking client. Items are tagged with `service` + `account`
  attributes for namespaced enumeration. 5 unit tests gated on
  `cfg(target_os = "linux")` plus `CONTRIX_TEST_LINUX_KEYSTORE=1` env
  guard for runtime D-Bus access.
- **`WindowsCredentialKeyStore` (Windows Credential Manager)** behind
  the new `keystore-windows` feature, wired to the `windows` crate's
  `Cred*W` family (`CredReadW` / `CredWriteW` / `CredDeleteW` /
  `CredEnumerateW`). Target name pattern
  `"contrix.<application_id>:<key_id>"`. 5 unit tests; on Windows CI
  these run live against the user's Credential Manager.
- **`KeyStoreError`** strongly-typed error enum (`Unsupported` /
  `NotFound` / `InvalidId` / `Backend`) convertible to
  `Error::Protocol`. Off-target / feature-disabled builds keep all
  three platform types visible (so downstream FFI / docs continue to
  compile cross-target) but their constructors return
  `KeyStoreError::Unsupported { reason }`.
- **`platform_default_keystore(application_id)`** helper that picks the
  matching native backend for the active target/feature combo and
  falls back to `InMemoryKeyStore` when none is available. Lets
  downstream apps do `let ks = platform_default_keystore("yougen");`
  without per-platform `cfg` blocks at the call site.
- Workspace `Cargo.toml` gains pinned versions for
  `security-framework = 3.5`, `secret-service = 5.0`, and
  `windows = 0.62`. Each is brought in only by its `target_os` via
  `[target.cfg(target_os = "...")]` blocks in `crates/core/Cargo.toml`,
  so cross-target builds don't pull unrelated platform crates.

### Changed

- Crate version `0.5.0 → 0.5.1` across the workspace; `v1` wire format
  unchanged. Public re-export at `contrix_core::{KeyStoreError,
  platform_default_keystore}`.

## [0.5.0] – 2026-05-09 — Move/Anchor signer surface + EventsQuery typed wrappers

This release completes round 21 of the SDK: the public Move/Anchor signer
trait, an Ed25519 backend for production signing, the `EventsQueryRequest`
/ `EventsQueryResponse` typed wrappers downstream agents (coauth / soland /
yougen) need for `cx.events.query`, and the workspace bump to 0.5.0
(folds C19.B follow-ups + completes signer surface). v1 wire is unchanged
from 0.4.0; this is an additive SDK API release.

### Added

- **`contrix-core::MoveSigner` trait + `UnsignedMove` builder** — public
  signer abstraction for Move/Anchor signing. `Move::sign(&unsigned, &signer)`
  produces a fully-signed Move whose `id` matches canonical bytes hash
  and `sig.payload_digest` matches the same canonical bytes. 8 unit tests.
- **`Anchor::sign_single` / `Anchor::sign_threshold` / `Anchor::sign_multi`**
  constructors that take a [`MoveSigner`] (or threshold proof bytes) +
  predecessor refs + frontier and produce a fully-signed [`Anchor`]
  with `id` derived from canonical bytes.
- **`contrix-signatures::Ed25519MoveSigner`** behind the new `signer`
  feature: wraps `ed25519_dalek::SigningKey`, exposes
  `new(signing_key, did, kid)` + `from_did_key_seed(seed)`, produces
  detached EdDSA JWS strings. Includes
  `verify_ed25519_move_signature` helper for round-trip vectors. 5
  unit tests.
- Re-exported at the top-level `contrix` crate root behind the
  `contrix/signer = ["contrix-signatures/signer"]` feature flag.
- **`contrix::EventsQueryRequest` / `EventsQueryResponse`** typed
  wrappers in `sync_client.rs` for `cx.events.query`. Multi-selector
  (`spaces[] ∪ actors[]`), `from` / `until` HLC bounds, `direction`
  (forward/backward), `limit`. `EventsQueryResponse` carries `events`,
  `next_cursor`, `prev_cursor`, `limited`. From/Into impls bridge with
  the existing `SyncBackfillResponse` wire shape soland accepts. 4 new
  unit tests.
- **`EventsSubscribeFrame::Frontier { cursor }` round-trip test** —
  rounds out the existing 9-variant frame deserializer (already had
  Event / CatchupComplete / Heartbeat / Dropped / EpochRotation /
  ResyncRequired / Unauthorized / Unknown coverage).

### Changed

- `EventsQueryDirection` now derives `Default` (= `Forward`) so
  `EventsQueryRequest` defaults match spec convention.
- All 23 workspace crates bumped 0.4.0 → 0.5.0; workspace dep table
  updated in lockstep.
- Pre-existing clippy `derivable_impls` warnings on
  `ReadReceiptDisclosure` / `ReadReceiptVisibility` cleaned up using
  `#[derive(Default)]` + `#[default]` markers.

### Test baseline

- `cargo build --workspace --all-features` clean.
- `cargo clippy --workspace --all-features --tests -- -D warnings` clean.
- `cargo test --workspace --lib --all-features` **728 passed / 0 failed
  / 0 ignored** (was 704 in 0.4.0; +24 new tests covering signer trait,
  Ed25519 backend, EventsQuery typed wrappers, and Frontier frame).

## [0.2.0] – 2026-05-08 — Move / Anchor / Lattice rebase ⚠ wire-breaking

This release rebases the SDK onto the Move/Anchor/Lattice three-primitive
state-convergence model introduced by `contrix-spec` 2026-05-08. The
v1 wire surface is **incompatible** with 0.1.0: `cx.consent.*` events,
the legacy `StateReducer` API, and the host-endorsement / writer-model
typed model are all gone. v1 was unreleased; no compat shim is provided.

### Added

- **`contrix-lattice` crate** — new independent crate providing the
  closed `Lattice` trait and six normative implementations
  (`or-set` / `mv-register` / `cas-register` / `fsm` / `counter` /
  `ordered-log`) plus `AnchoredOp` / `CellState` types. 55 unit tests.
- **`contrix-core::Move`** typed model with canonical-bytes id derivation
  (spec §3); 13 unit tests covering id round-trip / signature payload
  hash / SemanticRef default-skip / snake-case op enums.
- **`contrix-core::Anchor`** typed model with three signature shapes
  (`Single` / `Multi` / `Threshold`); 13 unit tests covering id
  round-trip + threshold below-quorum reject + wire `kind`
  discriminator.
- **`contrix-core::Bottom`** structured diagnostic typed model with six
  `BottomKind` variants matching `bottom.schema.json`.
- **`contrix-core::AnchorerValue`** four-variant typed enum
  (`SingleDid` / `Threshold` / `OpenSet` / `Mixed`); validates the
  anchorer cell's cas-register value shape per spec §4.4.
- **`contrix-core::CellId`** parser + `composite_subject` (base64url +
  sha256 hash form per encoding.md §9.5) + `composite_subject_pipe`
  diagnostic form.
- New typed identifiers: `MoveId` (`cx:move:sha256:<hex>`), `AnchorId`
  (`cx:anchor:sha256:<hex>`), `CellRef` (`cx:cell:<component>:<subject>`)
  with OpenAPI schemas.
- **`contrix-state-res` rewrite** — `MoveStore` / `AnchorStore` /
  `CellStore` / `CellRegistry` trait contracts + Memory backends +
  `verify_move` five-step pipeline + `apply_anchor` eight-step
  algorithm + `effective_anchor_view` pure function +
  `compute_state_root` (RFC 6962 Merkle, empty-list root locked to
  spec §4.2). 32 unit tests.
- **`contrix::consent`** rewritten as or-set Move builder per spec
  consent-model §3:
  `grant_effect` / `revoke_effect_with_precondition` /
  `evaluate_consent` / `require_consent_precondition`. Cell family
  `cx.component.consent.grant.v1`. Tag form
  `grant:<consent_id>:<peer>:<scope>` for deterministic dedupe.
- **`contrix::mls_move`** new module — MLS commit Move helpers per
  spec §10: `mls_commit_preconditions` / `mls_commit_effects` /
  `e2ee_message_precondition` / `covered_frontier_contains` plus
  cell families `cx.component.mls_epoch.v1` (cas-register, reject) /
  `cx.component.key_schedule.v1` (cas-register, reject) /
  `cx.component.covered_frontier.v1` (or-set, **expose**).
- `docs/move-anchor-runtime.md` — SDK-internal runtime architecture
  design (≈540 lines): module split, store trait contracts, verifier
  pipeline, `apply_anchor` walk-through, caching strategy (L0/L1/L2),
  user-facing projection vs cell effective state separation,
  CellRegistry loading, migration roadmap.

### Removed (wire-breaking)

- **Old `contrix-state-res` API**: `StateReducer`, `state_digest`,
  `is_state_event`, `subject_for_event`, `candidate_wins`,
  `ResolvedStateEvent`, `ConflictRecord`, `StateResolutionSnapshot`,
  `StateAuthority`, `evaluate_state_auth`, `BoardReducer` —
  ≈30 unit tests removed; replaced by 32 new tests on the new
  primitives.
- **Old `Proof` extensions**: `Proof::host_did`, `Proof::endorsed_at`,
  `proof_kind::HOST_ENDORSEMENT`. Move signatures use detached JWS
  exclusively now (signatures are anchorer-side concerns for
  multi/threshold flows, not Move-issuer concerns).
- **`SpaceWriterModel`** enum + `Space.space_writer_model` /
  `Space.space_host` fields + `derived_writer_model()` /
  `validate_writer_model()` helpers. Anchor authority is determined
  by the anchorer cell value, not a per-Space typed enum.
- **`crates/sdk/src/space_host.rs`** module deleted in entirety
  (`SpaceHostPayload` / `SpaceHostTransferPayload`).
- **Old `consent::ConsentState`** enum (`Granted` / `Revoked` /
  `Absent`) and the typed `ConsentGrantPayload` /
  `ConsentRevokePayload` envelopes. Effective consent is now derived
  from the consent cell's or-set join via `evaluate_consent`.
- All legacy `state_key` fields, `LegacyStateKey` errors, and
  `assert_no_legacy_state_key` helpers across the workspace.

### Changed

- `contrix-state-res` Cargo.toml gains `contrix-lattice`, `sha2`,
  `thiserror` deps to support the new runtime.
- `contrix-testing::state_resolution_vectors` rewritten to drive
  `apply_anchor` end-to-end. `StateResolutionVector` struct fields
  changed from `{name, winner_event_id, conflict_count}` to
  `{name, anchor, accepted_count, rejected_count, post_state_root}`
  to reflect the new "no per-cell winner" semantics.
- `MemoryCellRegistry` ships built-in bindings for nine cell
  families: `member.state` (FSM with membership transitions),
  `capability.grant` / `consent.grant` (or-set), `anchorer` /
  `space.policy` / `mls_epoch` / `key_schedule` (cas-register),
  `space.title` (mv-register, expose), `metric.counter` (counter),
  `audit.log` (ordered-log), `covered_frontier` (or-set, expose).
- 23-crate workspace bumped from `0.1.0` to `0.2.0`.

### Test baseline

- `cargo test --workspace --all-features`: **614 passed, 1
  pre-existing failure** (schema artifact-load test that requires
  spec workspace at a specific path; unrelated to this rebase).
- Net test delta vs 0.1.0: −≈35 (old state-res / consent /
  space-host tests removed) + 99 new (Move 13, Cell 10, Bottom 6,
  Anchor 13, AnchorerValue 10, Lattice 55, state-res 32, consent
  16, mls_move 11) = **+64 unit tests**.
- `cargo clippy --workspace --all-features --tests -- -D warnings`:
  clean.

### Migration

Downstream consumers MUST:

1. Replace `StateReducer::new(...).apply_events(events)` with
   `apply_anchor(anchor, &move_store, &anchor_store, &cell_store,
   &registry, verify_jws_closure)`.
2. Stop emitting `cx.consent.grant` / `cx.consent.revoke` event
   envelopes; build Moves whose effects come from
   `consent::grant_effect` / `consent::revoke_effect_with_precondition`
   instead.
3. Remove all references to `SpaceWriterModel` / `Space.space_host`.
   Anchor authority lookup goes through the anchorer cell.
4. For E2EE Spaces, attach `mls_move::e2ee_message_precondition` to
   message Moves; build MLS commit Moves with
   `mls_move::MlsCommitMoveSpec::build`.

See `docs/move-anchor-runtime.md` for the full architecture.

## [0.1.0-prep] (rolling work toward 0.2.0)

### Added

- `ClientBuilder` transport configuration: `connect_timeout`,
  `pool_idle_timeout`, `pool_max_idle_per_host`, `tcp_nodelay`,
  `tcp_keepalive`, `http2_keep_alive_interval`, `http2_keep_alive_timeout`,
  `http2_keep_alive_while_idle`, `proxy`, `no_proxy`, `redirect`, and
  `gzip`. See `crates/http-client/src/lib.rs`.
- `RedirectPolicy` enum (`None` / `Limited(usize)`) used by
  `ClientBuilder::redirect`.
- `SECURITY.md` describing supported versions, the responsible disclosure
  process and the project's response timeline.
- CI hardening: `cargo audit`, `cargo deny check`, `cargo doc --all-features`
  with `-D rustdoc::broken_intra_doc_links`, and a separate MSRV job.
- `RELEASING.md` enumerates the full 22-crate local package verification set
  in topological order and is now in lockstep with local release-gate evidence.

### Changed

- `ClientBuilder::build` now rejects calls that combine a pre-built
  `http_client(...)` with any transport-shaping option, instead of silently
  ignoring the option.
- Local package verification covers every workspace crate in dependency order,
  not just the umbrella `contrix` crate.
- `.github/workflows/ci.yml` corrects the publish dry-run package spec from
  `-p contrix-sdk` (which never matched any crate) to `-p contrix`.

## [0.1.0] – TBD

Initial release candidate for Contrix v1 SDK.

### Added

- Workspace of 22 focused crates plus an umbrella `contrix` crate
  re-exporting the public SDK surface (high-level state managers, sync
  client, MLS encryption, identity, federation, push, presence, …).
- Wire models for Space / Flow / Message / Morph / Relation / Event / View
  matching the Contrix v1 `data-structures.md` shape, including `FlowBranch`
  end-to-end migration and `Morph` as a canonical object.
- Canonical JSON encoder + SHA-256 digest helpers; signed payloads use this
  module so different clients compute identical hashes.
- HLC parsing and deterministic ordering, RFC 9421 / RFC 9530 transcript
  helpers, and replay/CommitFork detection.
- HTTP `contrix-client` with HTTPS-by-default, retry/backoff, idempotency,
  read-your-writes wait header support, and query-string-auth rejection.
- Framework-independent server endpoint registry plus optional Salvo
  adapter and OpenAPI integration. Every public model carries
  `salvo::oapi::ToSchema` under the `salvo` feature.
- MLS RFC 9420 group encryption based on OpenMLS, including `KeyPackage`,
  `Commit`, `Welcome` envelopes and `cx_app_state_ref` GroupContext
  extension.
- 42 canonical error code constants plus an `is_known_error_code` helper
  mirroring the spec's `error-code-registry.json`.
- Conformance vector library covering canonical-JSON, redaction, capability
  evaluation and sync-cursor binding (`crates/testing`).
- Authorization engine covering the 8 v1 constraint families
  (`temporal`, `field_access`, `type_restriction`, `scope_limitation`,
  `delegation_control`, `quota`, `claim_based`, `confidentiality`) with
  optional `subtype` discriminators, `ApprovalMode` quorum semantics +
  `ApprovalWorkflowMode` workflow stages, evaluation order
  (`deny → quarantine → require_review → allow`), and a `partial_auth_state`
  read-only marker.
- Push privacy validator that rejects raw-DID payloads outside an explicit
  `plaintext_visible_services` allowlist; TURN credential validator that
  rejects DID-bearing usernames/credentials.
- `MerkleProofStep` + `verify_snapshot_inclusion` for snapshot manifest
  inclusion proofs.
- Round-1 through Round-8 spec-alignment work (see commit history for
  the per-round task lists; the closed punch list is preserved in git).

### Security

- The `0.1.x` line targets functional parity for an external security
  review. See `SECURITY.md` for the disclosure process and
  `docs/security-audit.md` for current evidence.

[Unreleased]: https://github.com/contrix/contrix-rust-sdk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/contrix/contrix-rust-sdk/releases/tag/v0.1.0
