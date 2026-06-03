# SDK Architecture (v1 wire surfaces — R3 sync)

This page is a focused architectural reference for the **R3** sync of
`cokret-rust-sdk` against `cokret-spec @ b47ff6ec`. The umbrella architecture
at [`ARCHITECTURE.md`](../ARCHITECTURE.md) covers crate layering and the broad
client/server split; this document drills into the surfaces that R3 added or
re-shaped.

For day-to-day API entry points, see [`quick-start.md`](quick-start.md). For the
operator-facing API mapping see [`api-and-errors.md`](api-and-errors.md).

## v1 wire surfaces (R3) — agent_runtime + call.media + recovery

R3 introduced three coupled wire surfaces that the SDK now exposes as
first-class typed builders. They share three common invariants:

1. **All three are protected by an FSM lattice** — `cx.agent.{pause,resume,
   deactivate}` carry `lattice = fsm, bottom = reject`; recovery completion is
   driven by an idempotent `cx.recovery.session.complete` reducer; media tokens
   are bounded by a TTL gate (see [§Call media](#call-media-cxcallmediatoken_exchange)).
2. **All three reject on unknown enums** — `MediaBackendType::Unknown(_)`,
   `RecoveryProofKind` enum, agent state enum all use the canonical
   `unknown_focus_type` / `member_identity_unknown_segment` style reject
   helpers. Forward-compat is opt-in per profile, not implicit.
3. **All three are typed at the SDK boundary**, not parsed twice — the codec
   round-trips JCS-canonical bytes and the validator returns
   `Result<T, ServiceError>` rather than handing back `serde_json::Value`.

### Agent FSM (active / paused / deactivated)

The agent FSM is owned by soland's runtime cell `cx.component.agent_state.v1`.
The SDK models it as:

```rust
pub enum AgentState {
    Active,
    Paused,
    Deactivated, // terminal; only inert reads remain allowed
}
```

Transition matrix (informational — soland is canonical):

| from \ to    | Active | Paused | Deactivated |
|--------------|--------|--------|-------------|
| Active       |  —     |  pause |  deactivate |
| Paused       | resume |   —    |  deactivate |
| Deactivated  |  REJECT|  REJECT|     —       |

Operations:

- `ck.agent.pause` — `POST /agents/{agent_principal_id}/pause` — soft stop;
  outstanding tasks complete, no new tasks accepted.
- `ck.agent.resume` — `POST /agents/{agent_principal_id}/resume` — reverse of
  pause; rejected if state == Deactivated with `agent_deactivated`.
- `ck.agent.deactivate` — `POST /agents/{agent_principal_id}/deactivate` —
  terminal. The historical `/revoke` alias was dropped at R3. Validator
  ensures no callers reference `/revoke`.

Errors surfaced on this surface:

- `agent_paused` — write attempted against a paused agent principal.
- `agent_deactivated` — any write or resume against a deactivated agent.
- `pairing_request_expired` — `ck.account.agent_key_pair` window elapsed.
- `proof_invalid` — pairing proof bytes failed canonical-digest check.
- `verification_method_principal_mismatch` — DID resolved to a different
  principal than the pairing payload claims.
- `actor_kind_reducer_managed` — caller tried to mutate an actor whose state
  is reducer-owned (only reducer events may write).
- `sidecar_create_denied`, `approval_already_consumed` — sidecar thread /
  action-approval edge cases.

The SDK exposes `ck.agent.draft.propose`, `ck.agent.action_request`,
`ck.agent.action_approve`, `ck.agent.action_reject` as actor-private event
kinds (`reducer_input = false`). These are *not* part of the FSM lattice; they
ride on the agent's own actor stream.

### Call media (`ck.call.media.token_exchange`)

The call media surface lets a participant exchange a Cokret call grant for
a backend-specific media token (LiveKit, Mediasoup, Janus, Cokret-native,
MoQ relay). The SDK helper:

```rust
async fn call_media_token_exchange(
    realm_id: RealmId,
    call_id: CallId,
    actor_id: Did,
    device_id: DeviceId,
    focus_id: FocusId,
) -> Result<MediaTokenResponse, ServiceError>;
```

`MediaTokenResponse`:

```rust
pub struct MediaTokenResponse {
    pub backend_token: String,           // opaque to SDK; passes through to backend
    pub participant_identity: String,    // canonical: ck:participant:<realm>:<actor>:<device>:<call>
    pub participant_binding: ParticipantBinding,
    pub expires_at: Timestamp,           // <= 600s; SHOULD <= 300s
    pub service_signature: ServiceSignature, // includes rotating `kid`
    pub connect_url: Option<Url>,
}
```

`ParticipantBinding` (`scheme = "ck.media.participant_binding.v1"`) carries
`sig, issuer_kid, realm_id, call_id, focus_id, actor_id, device_id,
participant_identity, expires_at`. Verification checks:

1. `issuer_kid` resolves to a known media-token issuer (soland canonical,
   floria proxying allowed only when `ck.profile.media_service_binding.v1`
   declares so).
2. `expires_at <= now + 600s` (hard); SDK soft-warns if `> 300s`.
3. `participant_identity` matches the canonical join string.
4. `focus_id` is one of the foci advertised by `ck.realm.media_service`.

Errors:

- `focus_mismatch` — participant_binding focus_id differs from the realm's
  resolved focus.
- `unknown_focus_type` — `MediaBackendType::Unknown(_)` arm hit; reject helper
  surfaces this directly.
- `token_issuer_unauthorised` — `issuer_kid` not registered for this realm's
  media-service binding.
- `participant_binding_invalid` — canonical bytes failed signature verify.
- `participant_identity_unrecognised` — identity string does not parse.
- `session_focus_already_committed` — call already bound to a different focus.
- `e2ee_key_source_unauthorised` — backend tried to source SFrame keys outside
  the MLS-Exporter derivation.
- `recording_artifact_pipeline_bypassed` — recording artifact written without
  going through the canonical pipeline.
- `legacy_single_endpoint_media_service` — realm still advertises the v1.0
  `sfu_endpoint` shape; client must reject under R3.
- `focus_unavailable_for_client` — client doesn't ship the required backend
  profile (e.g. asked for Mediasoup but only ships LiveKit).

`MediaBackendType`:

```rust
pub enum MediaBackendType {
    LiveKit,
    Mediasoup,
    Janus,
    CokretNative,
    MoqRelay,
    Unknown(String),
}
```

`Unknown(String)` is preserved on decode so logs are useful, but every
operational call site invokes `MediaBackendType::reject_if_unknown()` before
trusting the value. The `cx.profile.media_service_binding.{livekit,
cokret_native}.v1` profile entries gate which arms a client will negotiate.

### Recovery (policy + receipt)

R3 lifts recovery from a soland-internal flow to a first-class wire surface.

`RecoveryPolicy`:

```rust
pub struct RecoveryPolicy {
    pub policy_id: Uuid,
    pub principal_id: Did,
    pub policy_version: u32,
    pub proof_kinds: Vec<RecoveryProofKind>,
    // body fields per spec/v1/artifacts/schemas/recovery-policy.schema.json
    pub body: RecoveryPolicyBody,
}
```

`RecoveryReceipt`:

```rust
pub struct RecoveryReceipt {
    pub receipt_id: Uuid,
    pub recovery_session_id: RecoverySessionId, // ck:recovery_session:<uuid>
    pub principal_id: Did,
    pub proof_summary: Vec<ProofSummaryEntry>,
    pub completion_timestamp: Timestamp,
}
```

`RecoveryProofKind`:

```rust
pub enum RecoveryProofKind {
    DeviceQuorum,
    RecoveryUnlock,
    TrustedRecoveryService,
    PrincipalSigning,
}
```

Identifier `RecoverySession` uses wire form `ck:recovery_session:<uuid>` and
lives in `cokret-identifiers`.

Round-trip validation matches the spec JSON-Schemas
(`recovery-policy.schema.json`, `recovery-receipt.schema.json`). Proof-witness
verification is currently a `TODO(R3.1)` stub — the SDK validates structure
and digest references but does not cryptographically verify each
`RecoveryProofKind` arm. Downstream services (soland) carry the canonical
verifier.

Error surfaced specifically on this lane:

- `recovery_witness_revoke_lagging` — a witness's revocation hasn't propagated
  inside the recovery freshness window.

## Profiles wired in R3

- `ck.profile.media_service_binding.v1` — generic media-service binding.
- `ck.profile.media_service_binding.livekit.v1`
- `ck.profile.media_service_binding.cokret_native.v1`
- `ck.profile.accountable_principals.strict_reject.v1` — see soland runbook for
  operational implications.
- `ck.profile.stateless_cursor.v1` — feature-gated `stateless_cursor` cargo
  feature; advertised separately from the stateful core wire path.

## Spec drift coverage (CI)

The `spec-drift` job in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (named
`spec artifact drift report` — also referred to as **`spec-drift-report`** in
plans) runs `cargo run --example spec_drift_report` against the latest
`cokret-spec` checkout and prints any event kinds, operations, or profiles
the SDK has not declared coverage for. It is informational
(`continue-on-error: true`), failing only on *hard* drift (entries the SDK
declares but the spec no longer ships).

R3's new event kinds (`ck.agent.draft.propose`, `ck.agent.action_request`,
`ck.agent.action_approve`, `ck.agent.action_reject`), new operation
(`ck.call.media.token_exchange`), and new profiles are all in the SDK's
declared-coverage set, so the drift report runs clean against
`cokret-spec @ b47ff6ec`.

If the spec-drift job is ever removed or its coverage list narrowed, the
runbook for adding it back is:

1. Add a `spec-drift` job to `.github/workflows/ci.yml` with
   `continue-on-error: true` initially.
2. Check out `cokret/cokret-spec` at the SDK's pinned spec SHA into a
   sibling path; set `COKRET_SPEC_ARTIFACTS` to its `spec/v1/artifacts`
   directory.
3. Invoke `cargo run --example spec_drift_report`. The example crate iterates
   `event-kinds.json`, `operations.json`, `profiles.json` and compares
   against `crates/core/src/events/kinds.rs`, the operation registry, and
   `crates/core/src/generated/profiles.rs::PROFILE_IDS`.
4. After a stable cycle, flip to `continue-on-error: false` so that *soft*
   drift (spec adds, SDK hasn't) is also a hard CI fail. Until then the job
   is intentionally advisory.
