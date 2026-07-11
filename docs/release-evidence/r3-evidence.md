# R3 Sync — Release Evidence

> Spec target: **arkret-spec @ `b47ff6ec`**
> SDK sync window: pre-R3.1 (handle rename / MemberIdentity work tracked
> separately under R3.1).
> Companion: [`release-evidence-1.0.0.md`](../release-evidence-1.0.0.md)
> covers the prior stable surface; this note layers the R3 deltas on top.

## SHA range

| Seal | Value |
|---|---|
| arkret-spec source | `b47ff6ec` |
| Local mirror | `D:/Works/arkret/spec-synced-b47ff6ec17cb53b6d94a65fbb86385b1075d5e52/` |
| SDK head at sync | `main` (no version bump) |

No `git tag` is cut for R3. The CHANGELOG carries a dated R3 entry rather
than a version stamp — see [`CHANGELOG.md`](../../CHANGELOG.md).

## Changes by surface

### Identifiers (`crates/identifiers/`)

- Added id-kind `RecoverySession` (wire form `ak:recovery_session:<uuid>`).
- Added id-kind / wire form for `CircleId` (`^ak:circle:[0-9a-f]{8}-...$`)
  to back `ResourceSelector::Circle(CircleId)`.

### Core wire models (`crates/core/`)

- `events/kinds.rs` — registered new agent event kinds
  (`ak.agent.draft.propose`, `ak.agent.action_request`,
  `ak.agent.action_approve`, `ak.agent.action_reject`) as actor-private
  events with `reducer_input = false`. Marked `ak.agent.{pause, resume,
  deactivate}` with `lattice = fsm, bottom = reject`.
- `model/call_media.rs` — `MediaTokenResponse`, `ParticipantBinding`,
  `MediaBackendType` (with `Unknown(String)` arm), TTL gate helper, and
  capability action enum entries `CallJoin`, `CallScreenShare`, `CallRecord`,
  `CallTranscribe`, `CallModerate`.
- `model/recovery.rs` — `RecoveryPolicy`, `RecoveryReceipt`,
  `RecoveryProofKind`; codec round-trip with schema-aligned validation guard
  (proof verification deferred — see TODO list below).
- `model/profile.rs` / `generated/profiles.rs` — added profile IDs
  `MediaServiceBinding`, `MediaServiceBindingLivekit`,
  `MediaServiceBindingArkretNative`, `AccountableToStrictReject`.
- `cursor/` — default parser is now stateful `{v, purpose, t, x, h}`;
  stateless cursor (`{v, purpose, t, s, d?, target?, x, _mac/_sig,
  issuer_kid}`) is feature-gated under `stateless_cursor` and advertised via
  `ak.profile.stateless_cursor.v1`.
- `model/selector.rs` — `ResourceSelector::Circle(CircleId)`; `object_ref`
  union updated.
- `model/account.rs` — `AccountDataSetPayload`, `AccountBlocklistPayload`
  payload structs and event-schema dispatcher routing.
- `model/handle.rs` — wire-level canonical normalize helper (NFC + UTS#39
  confusable skeleton + script-mixed reject); surfaces
  `handle_homograph_forbidden`. Full UTS#39 table deferred to R3.1.
- `errors.rs` — added 20 new error codes:
  `pairing_request_expired`, `proof_invalid`,
  `verification_method_principal_mismatch`, `agent_paused`,
  `agent_deactivated`, `approval_already_consumed`, `sidecar_create_denied`,
  `actor_kind_reducer_managed`, `focus_mismatch`, `unknown_focus_type`,
  `token_issuer_unauthorised`, `participant_binding_invalid`,
  `participant_identity_unrecognised`, `session_focus_already_committed`,
  `e2ee_key_source_unauthorised`, `recording_artifact_pipeline_bypassed`,
  `focus_unavailable_for_client`,
  `recovery_witness_revoke_lagging`, `handle_homograph_forbidden`.

### HTTP client (`crates/http-client/`)

- New helper `call_media_token_exchange(realm_id, call_id, actor_id,
  device_id, focus_id) -> MediaTokenResponse`.
- `ak.self.agent.command.deactivate` HTTP path is now
  `POST /agents/{agent_id}/deactivate`; the historical `/revoke`
  alias is gone. Grep gate in the completion checklist enforces this.

### Server (`crates/server/`)

- Operation registry adds `ak.self.call.media.exchange.issue_token`
  (`POST /rtc/token`, `CallMedia/TokenExchange`,
  `call.media.exchange.issue_token`) to the `core_personal` surface tier.
- Agent runtime tier surface declared:
  `[agent_key_pair, provision, list, get, pause, resume, deactivate,
  rotate_key, grant.attach, grant.detach, sidecar_thread.ensure]`.

## Tests added — by crate

| Crate | Tests |
|---|---|
| `crates/identifiers/` | `recovery_session_id::round_trip`, `circle_id::pattern_match`, `circle_id::reject_malformed` |
| `crates/core/` | `events::kinds::agent_event_kinds_registered`, `models::call_media::participant_binding_round_trip`, `models::call_media::token_ttl_gate_rejects_above_600s`, `models::call_media::backend_type_unknown_rejects`, `models::recovery::policy_round_trip`, `models::recovery::receipt_round_trip`, `models::handle::homograph_skeleton_rejects` |
| `crates/http-client/` | `call_media::token_exchange_request_shape` (mock transport), `agent::deactivate_path_no_revoke` (path-regression guard) |
| `crates/server/` | `registry::call_media_token_exchange_registered`, `registry::agent_runtime_tier_surface` |

Test runs are gated through the existing CI matrix on
`.github/workflows/ci.yml`; no new jobs were added for R3.

## TODO(R3.1) stubs

The following items are explicitly stubbed for the next sync. They compile
and surface canonical wire types but do not cryptographically validate the
underlying proofs / payloads. Downstream services (soland, coauth) carry
the canonical verifiers in R3 and are expected to reject anything the SDK's
relaxed validators would have let through.

- `crates/core/src/models/recovery.rs::verify_proof_witnesses` — proof
  arms (`DeviceQuorum`, `RecoveryUnlock`, `TrustedRecoveryService`,
  `PrincipalSigning`) currently structure-check only. R3.1 will wire the
  per-arm verifier table.
- `crates/core/src/models/handle.rs::uts39_full_skeleton_table` — minimal
  confusable skeleton ships in R3; full UTS#39 table import deferred.
- `crates/core/src/models/member_identity.rs` (R3.1) — `ak.member.identity.update`,
  `MemberIdentity` / `VerifiedHandle` shapes, effective-set computation,
  identity_state_digest helper. Tracked under R3.1 items HDLREN-* / MID-*
  in `_arkret-rust-sdk_todos.md`.
- `crates/core/src/errors.rs::operations_error_mapping_table` —
  per-operation error-code mapping table (`operations-error-mapping.json`
  v2026-05-27) deferred; HTTP-status mapping updated for new codes.

## CI / drift

The `spec-drift` job in `.github/workflows/ci.yml` (hard gate; named
`spec artifact drift report` and referred to as **`spec-drift-report`** in
the plan docs) was extended to cover the new event kinds, the new
`ak.self.call.media.exchange.issue_token` operation, and the new profiles. See
[`docs/architecture.md`](../architecture.md#spec-drift-coverage-ci) for the
coverage description and the "how to re-add this job" runbook.

## Completion gate snapshot

The completion gate from `_arkret-rust-sdk_todos.md`:

- `cargo check --workspace` — passes.
- `cargo clippy --workspace -- -D warnings` — passes.
- `cargo test --workspace` — happy paths pass; FSM and proof-witness
  stubs documented above.
- `grep -RIn "agent_id}/revoke\|sfu_endpoint\"\\s"` — returns zero.
