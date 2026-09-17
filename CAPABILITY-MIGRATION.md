# Authority-commit capability migration

`e309b047` removed 162 files and 164,976 lines in one step. Some of that was a
complete protocol unit leaving; some of it was product capability leaving with
it, which is why every downstream repository stopped compiling. This file is the
evidence ledger for that split: what survived, where it lives now, which test
proves it, and — for every removed unit — why the removal is safe.

A removed source file is acceptable only when its entire contract belongs to the
removed protocol machinery. Mixed modules are split and migrated, never dropped
whole.

The only source of truth is arkret-spec. Normative prose lives in
`spec/v1/zh`; machine-readable artifacts live in `spec/v1/artifacts`. Every row
below cites one of them.

## Protocol invariants every row is measured against

- A shared durable Event is submitted to the current governance Station, which
  produces an authority-signed RealmCommit. Only the RealmCommit carries
  `previous_commit_ref`, at the same stream position exactly `+1`, and it names
  exactly one `event_ref` (`realm-commit.schema.json`).
- Realm, each Circle and each Sidecar own independent commit streams. There is
  no global chain and no global position.
- The single submission DTO is `EventCommitSubmission { event }`
  (`crates/wire/src/authority_commit.rs`).
- Welcome is a producer-signed recipient delivery object
  (`ak:mls_welcome_delivery:<uuidv7>`), not an Event. The only shared MLS Events
  are `ak.mls.genesis` and `ak.mls.commit`; Proposals are inline; KeyPackages use
  a dedicated ledger.
- A scope is plaintext before its own accepted `ak.mls.genesis` and irreversibly
  standard RFC 9420 after it; the violation reason codes are
  `mls_activation_required` and `mls_activation_irreversible`.
- Producer Events carry no predecessor: `Event` has neither `actor_seq` nor
  `prev_refs`.

## Restored product capability

| Capability | Spec authority | Implementation | Behavior test |
| --- | --- | --- | --- |
| Account Authority status publication + issuer-ledger resolve, session revoke | `account-operations.schema.json#/$defs/account_status_publication{,_request_body,_outcome}`, `…/account_status_resolve_{request_body,outcome}`, `…/session_revoke_{request_body,outcome}` | `crates/models-collaboration/src/account_lifecycle.rs` | `account_lifecycle::tests` (7) |
| Account lifecycle authorization proof | `account-operations.schema.json#/$defs/account_lifecycle_proof` | `crates/models-identity/src/account.rs` (`AccountLifecycleProof`, `AccountLifecycleProofKind`, `SessionGrantAppletSelector`) | `account_lifecycle::tests::account_lifecycle_proof_*` |
| Holder-private consent self-management | `consent-operations.schema.json`; HTTP face `GET /_arkret/self/consent/results`, `GET /_arkret/self/consent/result` (`zh/sync/service-http-binding.md` L322-326) | `crates/models-collaboration/src/consent_operations.rs` | `consent_operations::tests` (4) |
| PCR genesis relay (`pcr_genesis_submit_*`) | `principal-operations.schema.json#/$defs/pcr_genesis_submit_{request,outcome}`, `…/pcr_genesis_unit` | `crates/models-collaboration/src/principal_operations.rs`, `PcrGenesisUnit` in `crates/wire/src/authority_commit.rs`, `PCR_GENESIS_UNIT_KINDS` in `crates/models-identity/src/account.rs` | `principal_operations::tests` (3) |
| Session grant introspection / auth-session logout | `service-operation-dtos.schema.json#/$defs/SessionGrantIntrospect{RequestBody,Outcome,Grant}`, `…/AuthSessionLogout{RequestBody,Outcome}`; ops `ak.gate.account.command.introspect_session_grant.v1`, `ak.gate.account.command.logout_auth_session.v1` | `crates/models-collaboration/src/session_grants.rs` | `session_grants::session_grant_introspection_tests` (3) |
| Device revocation gate | `device-revocation-state.schema.json` | `crates/wire/src/device_revocation.rs` | `device_revocation::tests` (16) |
| Controller-account gate attestation | `zh/identity/key-management.md` §3.7 area; `proof-context-registry.json` domain `ak.controller_account_gate.v1` | `crates/models-identity/src/agent_signer_evidence.rs` | `agent_signer_evidence::tests` (9), including `status == active` iff `eligibility == active` |
| Realm media service foci | `event-payload.schema.json#/$defs/media_service_focus`; `zh/crypto-media/media-service-binding.md` §2 | `crates/models-collaboration/src/events_payloads/realm.rs` (`MediaServiceFocus`, `RealmMediaServicePayload`) | `realm::tests` media-focus cases (7), including `focus_kind` fail-closed |
| Applet managed-actor four-Event authoring unit | `zh/identity/key-management.md` §3.6.3, `zh/extensions/applet-integration.md` §9.1, `applet-managed-actor.schema.json`, `applet-install-authoring.schema.json` | `crates/sdk/src/managed_actor_authoring.rs` | `crates/sdk/tests/applet_managed_actor_authoring.rs` (8) |
| Agent Realm-membership cascade | `agent-membership-cascade.schema.json`; `zh/models/actor.md` | `crates/models-collaboration/src/governance/agent_membership_cascade.rs` | `agent_membership_cascade::tests` (9) |
| Realm join bootstrap assembly | `realm-join-intake.schema.json#/$defs/peer_bootstrap_outcome`; `zh/governance/join-policy.md` L36 | `crates/models-collaboration/src/governance/realm_join_bootstrap.rs` | `realm_join_bootstrap::tests` (4) |
| Read-cursor position + causal relation | `read-cursor.schema.json#/$defs/position`; `zh/discovery/read-receipts.md` §6.5 | `crates/models-collaboration/src/objects/read_receipts.rs` | `read_receipts::read_cursor_tests` (8) |
| MIMI consent request / update | `mimi-operations.schema.json#/$defs/mimi_{request,update}_consent_request_body`; ops `ak.open.mimi.command.{request,update}_consent.v1`; proof contexts `ak.mimi_{request,update}_consent_request_proof.v1` | `crates/models-collaboration/src/mimi_operations.rs` | `mimi_operations::tests` (5) |
| Recovery policy + recovery session | `recovery-policy.schema.json`, `recovery-session.schema.json`, `high-risk-authority-proof.schema.json` | `crates/models-crypto/src/{recovery_policy,recovery_session,high_risk_authority_proof,authority_set_policy}.rs` | 28 tests across those modules |
| Agent Sidecar object, view state, exchange control/projection/binding, MLS context | `agent-sidecar*.schema.json`, `principal-operations.schema.json#/$defs/sidecar_*` | `crates/models-collaboration/src/agent_sidecar.rs`, rebuilt three-phase `sidecar_operations.rs` | 16 tests |
| Event read rows, redacted / reference-locked views, projection rows and pages | `service-operation-dtos.schema.json#/$defs/{EventReadRow,RedactedEventView,ReferenceLockedEventStub,EventView,Projection*Row,Projection*List}` | `crates/models-collaboration/src/event_query.rs`, `.../objects/query_projection.rs` | `event_read_row_tests`, `event_view_tests`, `projection_list_tests` |
| Event submit envelope + batch submission | `service-operation-dtos.schema.json#/$defs/{EventSubmitEnvelope,EventsSubmitBatchRequestBody}` | `crates/wire/src/event_submission.rs` | round-trip plus a test asserting a bare Event array is rejected |
| Recovery / Agent-refresh session grant branches | `service-operation-dtos.schema.json#/$defs/{RecoverySessionGrantRequest,AgentSessionGrantRefreshRequest,AgentSessionRefreshProof}` | `crates/models-collaboration/src/session_grant_bodies.rs` | module tests |
| `device_authorize_payload_digest` (single implementation) | `zh/crypto-media/device-lifecycle.md` §5.2/§5.4 | `crates/models-collaboration/src/events_payloads/device_identity.rs` | exercised through `principal_operations` and the PCR genesis relay |
| `event_spec::DeviceAuthorize` typed draft binding | `event-kind-registry.json` `payload_schema_ref` for `ak.device.authorize` | `crates/event-draft/src/event_payload.rs` | `device_authorize_binds_its_typed_payload` (+1 negative) |
| `derived_object_id_for_kind` | `zh/models/common-fields.md` §6.0; `id-kind-registry.json` `id_form=event_derived` | `crates/schema/src/derived_object_id.rs` | 3 tests including a 6-kind KAT |
| SDK facade surface | n/a (re-export layer) | `crates/sdk/src/lib.rs` | `cargo check --workspace --all-features` resolves every re-export; ambiguity is a hard compile error |

### Facade re-exports restored

`crates/sdk/src/lib.rs` again re-exports the product modules the umbrella had
stopped surfacing: `arkret_models_collaboration` (`account_lifecycle`,
`account_operations`, `account_status`, `agent_operations`, `agent_scope`,
`applet_installation_authority`, `consent_operations`, `contact_operations`,
`device_messages`, `device_pairing`, `mimi_operations`, `principal_operations`,
`session_grants`, `sidecar_operations`, `signal_operations`,
`governance::agent_membership_cascade`, `governance::realm_join_bootstrap`),
`arkret_models_crypto` (`encrypted_attachment`, `key_backup_operations`,
`keypackage_capabilities`, `secret_share`, `security_transaction`),
`arkret_models_identity` (`did_webvh`, `organization_registration`,
`primary_handle`), `arkret_models_discovery` (`verified_profiles`,
`websocket_binding`), `arkret_models_integration` (`push`, `push_vocab`),
`arkret_wire` (accepted-device possession, applet revoke mode, consent scope,
directory source-ref access, event receipt, extension manifest, ingress budget,
invite token, MLS transition digest, notary canonical value, object ref,
operation types, wasm platform bodies, recovery authority, request digest,
resource selector, evaluation class, Signal envelope family, WebSocket binding,
webvh parameters, wire presence), `arkret_http_client::service_resolution_fetcher`,
`arkret_event_draft` (`EVENT_PAYLOAD_BINDINGS`, `EventPayloadBinding`,
`EventAuthoringContext`, `local_operation_spec`) and `arkret_retry`
(newly added as an umbrella dependency).

## Removed as complete protocol units

Each entry is the whole unit, with no product type left inside it.

- **Seal, protocol-level Cell, Bottom, CBS, ControlProposal.** `wire/src/{seal,
  seal_conclusion,cell,cell_state,bottom,cbs,cbs_proof_bundle,control_proposal,
  signer}.rs`, `state/src/state/**`, `state/src/direct_traversal.rs`,
  `bootstrap/src/{projection,self_principal_seal}.rs`,
  `signatures/src/{frozen_notary,seal_conclusion}*`,
  `schema/src/event_cell_contract.rs`. Finality is now the authority-signed
  RealmCommit; no Seal, Cell or acknowledged control proposal exists on the wire.
- **Lattice registry and the five CRDT state models.** `crates/lattice-registry/**`,
  `state/src/state_model/**` (`causal_register`, `counter`, `domain_transition`,
  `or_set`, `ordered_log`, `sequenced_state`, `traits`),
  `state/src/resolver/**`, `state/src/consent.rs`,
  `state/benches/causal_register.rs`,
  `tools/spec-codegen/src/lattice_contracts.rs`,
  `tools/generate-sdk-state-model-bindings.py`, `tools/lint-cell-family-literals.py`.
  State is projected as typed current results with an `expected_revision`
  precondition; there is no generic reducer inventory left to generate.
- **Actor sequence, predecessor graph and generic frontier reconciliation.**
  `Event` lost `actor_seq` and `prev_refs`; `state/src/generated/mls_security_frontier.rs`,
  `state/src/mls_{cells,governance_proof}.rs`,
  `models-crypto/src/mls_governance_{proof,result}.rs`, `sdk/src/mls_governance.rs`,
  `sdk/src/control_projection.rs`, `tools/generate-mls-security-frontier.py`.
- **History key / RHRK and the history exporter.** `models-collaboration/src/history_key.rs`,
  `identity/src/history_recovery.rs`, `http-client/src/endpoints/history_key.rs`,
  `state/src/{history_authorization,history_backup,history_store,ordinary_history}*`,
  `sdk/src/{historical_producer,history_response,ordinary_history,device_authorization_history}*`,
  `wire/src/{history_secret,history_store,organization_recovery}.rs`,
  `wire/src/generated/history_store_limits.rs`,
  `signatures/tests/history_source_signing.rs`,
  `sdk/tests/history_response_receiver.rs`.
- **Audited E2EE.** `AuditAssurance`, `AuditRyw*`, `AuditReleaseAttestation`,
  `AuditAppletBinding*`, `AuditSession*`, `AttestationId`, `AuditBindingId`,
  `AuditReleaseId`, together with `RywFrontier`. No spec `$defs` remains for any
  of them; the stale registry rows are removed in `tools/schema_struct_registry.json`.
- **Reducer profile negotiation.** `wire/src/generated/{reducer_managed_paths,
  reducer_profiles}.rs`, `schema/src/generated/current_result_schemas.rs`,
  `tools/generate-current-result-schemas.py`. Service discovery advertises
  concrete operations and schemas instead.
- **Superseded, not lost:** `wire/src/security_transaction.rs` (now
  `models-crypto/src/security_transaction.rs`), `schema/src/prepared_event.rs`
  (now `models-collaboration::prepared_event_draft`),
  `schema/src/agent_runtime_scope.rs` (now
  `models-collaboration::agent_scope`), `models-crypto/src/serde_absence.rs`
  (folded into `arkret-canonical::serde_helpers`),
  `models-collaboration/src/applet_authoring.rs` (now
  `models-integration::applet_models`), `crypto/src/secret_share.rs` and
  `models-crypto/src/secret_share.rs` (already restored by `0ddafe1f`).

## Migrated mixed areas, with the evidence

- **Recovery keeps its atomic business transaction.** Completion binds the
  re-anchor Event and the replacement-device authorize Event to two
  *consecutive* `CommittedEventRef` values in one PCR Realm stream
  (`zh/crypto-media/device-lifecycle.md`, RecoveryTransaction termination:
  「reanchor Event 与 replacement-device authorize Event 必须分别取得同一 PCR
  stream 中连续的 `CommittedEventRef`」). Because one RealmCommit carries exactly
  one `event_ref`, the pair is two distinct commits and two distinct Events.
  `validate_recovery_commit_pair` now also rejects a shared `commit_id` or a
  shared `event_id`, and uses `checked_add` so a saturating stream position
  cannot fake adjacency. Tests:
  `recovery_authority::tests::recovery_commit_pair_{requires_consecutive_same_stream_commits,
  rejects_a_shared_commit_or_event,rejects_a_saturating_position}`.
  The attestation fields were also realigned to
  `recovery-authority.schema.json#/$defs/recovery_completion_attestation`:
  `reanchor_ref` → `reanchor_event_ref`, `device_authorization_ref` →
  `device_authorization_event_ref`, declaration order moved to the schema's
  `properties` order, and `IssueRecoveryCompletionGrantRequest` now carries
  `device_authorization_event_id` and checks the terminal receipt's
  `reanchor_event_id`.
- **Event authoring keeps its domain builders and submits
  `EventCommitSubmission { event }`.** `PcrGenesisUnit`, the applet managed-actor
  unit and the consent grant/revoke bodies all cross the submission boundary
  through that one DTO.
- **Capability revoke/relinquish moved from a cell head to a revision.**
  `CapabilityRevokePayload` dropped `grant_ref` and both payloads gained
  `expected_revision`, matching
  `event-payload.schema.json#/$defs/capability_{revoke,relinquish}_payload`.
- **`SidecarCreatePayload` is a deliberately empty closed object.**
  `event-payload.schema.json#/$defs/sidecar_create_payload` has `properties: {}`;
  `tools/schema_struct_gate.py` now recognises that shape instead of treating an
  empty property set as an unresolved pointer.
- **Prose no longer cites removed vocabulary.** The remaining `head_eq` and
  "release Move" doc comments in `crates/identifiers`,
  `crates/models-collaboration/src/events_payloads/strand.rs` and
  `crates/wire/src/problem_details.rs` now say `expected_revision` and
  "release Event".

## Deliberately NOT restored, with the evidence

- **Reusable current signer evidence** (`models-collaboration/src/current_signer_evidence.rs`).
  `signer-key-operations.schema.json` states the current-query face carries "No
  portable evidence or reusable current grant". Only the controller-account-gate
  family was taken out of that module.
- **Agent Sidecar `encryption_profile`.** `zh/models/sidecar.md` L61-63: the
  Sidecar's encryption activation point is its own accepted `ak.mls.genesis`, so
  neither `ak.sidecar.create` nor the materialized Sidecar object carries an
  encryption profile field. `agent-sidecar*.schema.json` confirm it.
- **`PayloadSigner::sign_notary_payload_with_digest_suite`.** "notary" has zero
  hits across `spec/v1`; the method's only baseline caller was
  `Seal::sign_with_signer` under domain `ak.seal.commit.v1`. Authority and
  recipient-delivery objects are signed through
  `detached-object-signature.schema.json` instead, whose context enum is closed
  and carries no digest-suite parameter.
- **`AgentMembershipCascadeFederationSubmission`.** It depended on
  `EventFederationSubmission` and `CbsProofBundle`; CBS is a removed unit.
- **History key request/response (RHRK).** Adjudicated removal; not restored.

## Open gaps handed to downstream

These are real spec `$defs` with no SDK counterpart yet. They are listed so a
downstream repository can see the boundary instead of hand-rolling a protocol
type locally.

- `service-operation-dtos.schema.json`: `DirectConversationFoundingAuthorityEvidence`,
  `DidWebvhIdentityMethodEvidence`.
- `account-subscribe-frame.schema.json` and `websocket-frame.schema.json`: the
  account-sync / client-sync / demand-sync / stream-trace and WebSocket session
  frame families (`models-collaboration/src/sync_frames/{account_sync,client_sync,
  demand_sync,stream_trace,websocket_binding,websocket_session}.rs` are still
  deleted).
- `http-client/src/endpoints/events.rs`: the Event stream / query / submit /
  snapshot client methods have no replacement in `crates/http-client/src/endpoints/`.
- `wire/src/offline_publication.rs`: `AuthorizationLease` and `IngressReceipt`
  are still normative (`zh/overview/glossary.md`, `zh/identity/security-transactions.md`
  L213), even though the lease *issue operation* is gone from the operation
  registry.
- `signatures/src/agent_evidence.rs`: no signer/verifier wrapper exists for the
  restored `ControllerAccountGateAttestation`, and the SDK has no helper that
  produces a `DetachedObjectSignature` at all.
- `mls/src/exporter_kdf.rs`: the RFC 9420 exporter helpers are gone while the
  RTC (`ak.rtc-*-key/v1`) and blob exporter labels remain registered.
- `models-collaboration/src/authenticated_signer_resolution_evidence.rs`
  counterpart for `authenticated-signer-resolution-evidence.schema.json`.
- `crates/models-collaboration/tests/**` and `crates/schema/tests/**`: the
  schema-conformance, DTO field-coverage and fixture/KAT consumers deleted by
  `e309b047` have not been re-pointed at the current artifacts.
- `service-operation-dtos.schema.json#/$defs/DidWebvhIdentityMethodEvidence` has
  no standalone Rust struct; it is the `IdentityMethodEvidence::DidWebvh`
  variant in `crates/models-identity/src/identity.rs`, whose field set and tag
  match the schema.
- `agent-operations.schema.json#/$defs/key_state` still declares
  `requested_scope`, `signer_resolution_evidence_ref` and
  `current_signer_evidence`, and explicitly says the object carries no
  `runtime_state`. `crates/models-collaboration/src/agent_operations.rs`
  `KeyState` has none of the first three, spells the required
  `controller_authorization_ref` as an optional `current_authorization_ref`, and
  does carry `runtime_state`.
- `agent-operations.schema.json#/$defs/agent_sidecar_view` requires
  `sidecar` / `desired_agent_ids` / `effective_agent_ids` / `mls_context` /
  `access_readiness` / `pending_access_reconciliations`; the `AgentSidecarView`
  and `AgentSidecarList` in `agent_operations.rs` still carry the older
  `sidecar_id` / `realm_id` / `sidecar_head` shape. Every type the spec shape
  needs now exists in `crates/models-collaboration/src/agent_sidecar.rs`.
- `crates/wire/src/authority_commit.rs` `PcrGenesisUnit` and
  `crates/models-identity/src/account.rs` `IdentityCreationEvents` are two
  carriers for the same ordered `ak.realm.create` + `ak.device.authorize` pair.
  Only `PcrGenesisUnit` has a spec `$defs` counterpart.
- `crates/models-identity/src/agent_signer_state.rs` `StationSigningKey` carries
  `authorization_ref: CommittedEventRef` plus a `revision`, while
  `signer-key-operations.schema.json#/$defs/station_signing_key` is closed over
  `actor` / `verification_method` / `public_key_b64u` / `authorization_ref:
  event_id`. `crates/wire/src/signal.rs` holds a second `StationSigningKey` that
  does match the schema.
- `tools/deny_unknown_inventory.json` still names 23 removed types and
  `tools/optional_timestamp_inventory.json` still names five deleted files
  (`models-collaboration/src/{http_bodies,session_grant_bodies}.rs`,
  `events_payloads/state.rs`, `state/src/consent.rs`, `wire/src/bottom.rs`).
  Neither file gates on those rows today, so they are stale evidence rather than
  a red gate.
- `docs/move-anchor-runtime.md` documented the removed Move / anchor / cell
  runtime end to end with no surviving implementation, and was deleted on
  2026-09-16.

## Verification gates

Run from the repository root; none of these may be satisfied by a reduced test
count or a green minimal workspace.

| Gate | Result on 2026-09-16 |
| --- | --- |
| `cargo check --workspace --all-features` | clean, zero warnings |
| `cargo check --workspace --all-features --all-targets` | clean, zero warnings |
| `cargo +nightly fmt` (repository-local; never the `--all` writing form, which reaches into sibling repositories) | applied, no residual diff |
| `cargo test --workspace --all-features --no-fail-fast` | 1501 passed, 0 failed |
| `python tools/schema_struct_gate.py` | pass (206 exact mappings, 23 exemptions) |
| `python tools/identity_type_audit.py` | pass |
| `python tools/lint-optional-timestamp-defaults.py` | pass |
| `python tools/lint-time-representations.py` | pass |
| `python tools/lint-event-derived-id-minting.py` | pass |
| `python tools/lint-event-preimage-authoring.py` | pass |
| `python tools/check-layering.py` | pass |
| `python tools/check-publish-order.py` | pass |
| `python tools/lint-type-names.py` | fail — 7 `*Result` / `*Candidate` names, all pre-existing at `36f73eb0` and all spec-derived DTO names |
| `./tools/sync-spec.ps1 -ArtifactsDir <arkret-spec>/spec/v1/artifacts -Check` | drift on one generated file (see below) |

`--no-fail-fast` is mandatory on the test run: the default fail-fast prints
neither the `---- ` lines nor a failure count when a test target fails to
compile.

### The remaining non-green gate

**`sync-spec.ps1 -Check`.** Drift is reported on exactly one file,
`crates/identifiers/src/generated/digest_suite_codes.rs`, and the drift is
metadata only: the generated body is byte-identical after the generator's own
formatting is normalised, and both sides report `Entries: active=2`. What changed
is the recorded input `sha256` of `registry/digest-suite-registry.json`
(`ed95ff0b…` checked in, `4d8bab90…` now) while the registry's own `version`
label stayed at `2026-09-16.7` — arkret-spec rewrote those bytes without bumping
the version. Re-running the writing sync would only rewrite the header hash, so
it is deliberately deferred until arkret-spec stops moving.

### `lint-type-names.py` offenders

All seven predate this work (verified against `36f73eb0`) and every one of them
is the name the spec itself gives the DTO, so renaming them in the SDK would
introduce exactly the kind of local divergence this migration is removing:
`TypedCurrentResult` and `StreamRow` (`crates/wire/src/authority_commit.rs`),
`SignerKeyQueryResult` (`crates/models-identity/src/signer_key_operations.rs`),
`DeviceMessageDeliveredResult` and `DeviceMessageUnknownResult`
(`crates/models-collaboration/src/device_messages.rs`, both spec `$defs` names),
`RealmJoinCandidate` (`crates/models-collaboration/src/governance/realm_join_intake.rs`)
and `AppletManagedActorAuthoringResult`
(`crates/models-integration/src/applet_models.rs`). Either the lint's R4 rule
needs a spec-named exemption list or the spec needs to rename these; the SDK is
not the right place to resolve it unilaterally.
