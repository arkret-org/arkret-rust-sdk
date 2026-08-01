# Regression review log

## 2026-08-01 — coverage promises were represented by hand-copied partial sets

- Surface: active schema coverage, closed registry vocabularies, operation error mappings, and
  typed protocol identifiers.
- Regression: the restored spec-drift job exposed 57 active schemas missing from the manual
  `SUPPORTED_SCHEMA_IDS`; the track enum omitted the active `synthesis` value; binding and
  authority vocabularies were duplicated by hand; the 218-row operation-to-error registry had no
  generated SDK surface; and two newly declared special-form ids remained plain strings in model
  DTOs. `ServiceRegistrationReceipt` additionally serialized the off-spec member `receipt_id`.
- Correction: schema coverage now means every active registry row has generated descriptors,
  an embedded artifact, and runtime loading, with live/generated sets compared in both directions.
  Closed track, binding, and authority values plus operation-error mappings are generated from the
  spec. `AppletInstallPlan.plan_id` and `ServiceRegistrationReceipt.registration_receipt_id` now
  use their typed ids; first-party consumers were migrated with no compatibility shim. The full
  adjudication and all 57 schema ids are recorded in
  `decisions/2026-08-01-sdk-spec-coverage-contract.md`.
- Verified by injection: synthetic active schema rows fail the drift report; incomplete operation
  mappings and unknown error codes fail generation; unknown closed-registry values fail parsing;
  legacy/invalid receipt and plan ids fail wire decoding. The live drift report, generation check,
  strict workspace clippy, full workspace tests, and required downstream compile gates all pass.
- Prevention dimension: a coverage gate must derive its claimed set from the artifact or
  declaration that creates the implementation surface. A second list maintained by memory is not
  an independent check; it is a second source of drift.

## 2026-08-01 — special-form id coverage claimed four kinds with no type behind them

- Surface: `arkret-schema::SUPPORTED_SPECIAL_FORM_ID_KINDS` and `arkret-identifiers`.
- Regression: the same hand-copied-list defect as the `SUPPORTED_ID_KINDS` entry below, running
  in the opposite direction. The constant declared 9 `special_forms` kinds; four of them —
  `mls`, `pseudonym`, `plan`, `service_registration_receipt` — had **zero** occurrences of their
  wire prefix anywhere in `arkret-identifiers`. The drift report was therefore asserting SDK
  support that did not exist, which is worse than no gate: it actively supplied a false guarantee.
  The uuid-side fix landed the same day covered only `id_kinds`, leaving `special_forms` as the
  symmetric hole.
- Detection: auditing what the just-added `id_kind_coverage` gate did *not* cover.
- Correction: `declare_special_form_id_kinds!` now emits `DECLARED_SPECIAL_FORM_ID_KINDS` from
  the same declarations the types are generated from, and `id_kind_coverage.rs` compares it with
  `SUPPORTED_SPECIAL_FORM_ID_KINDS` in both directions plus a populated-both-sides guard. The
  four claims were resolved by their registry status, not by editing the list to match:
  `mls` / `pseudonym` are `profile_extension` (validated by the E2EE profile, never SDK core) and
  were dropped; `plan` / `service_registration_receipt` are `active` and are now implemented by
  `PlanId` and `ServiceRegistrationReceiptId`, validating the registry wire forms
  `^ak:plan:[A-Za-z0-9_-]+$` and `^ak:service_registration_receipt:[0-9a-f]{64}$`.
- Verified by injection: adding `pseudonym` back to the constant, removing `cursor` from it, and
  transposing two types' `ID_KIND` each turn the gate red with a distinct message.
- Prevention dimension: closing a defect class on one surface does not close it on the surface
  next to it. When a fix is "derive the set from the declarations", the immediate follow-up
  question is which *other* hand-written sets feed the same gate — here, the answer was one line
  below the one that was fixed.

## 2026-08-01 — the profile-requirement gate compared candidate profiles against the active surface

- Surface: `SpecArtifactBundle::profile_requirement_drift`.
- Regression: the check compared every profile requirement against `REGISTERED_SCHEMA_IDS` /
  `REGISTERED_EVENT_KINDS` / `REGISTERED_OPERATION_IDS`, which the generator emits from the
  **active** registry surface only. `ak.profile.candidate.join_policy.v1` is itself a `candidate`
  profile requiring `ak.schema.join_policy_operations.v1`, the schema registry's only `candidate`
  row, and was reported as drift although neither side had drifted. Worse, the single message
  spelled three different conditions — dangling reference, SDK generation gap, spec status
  inversion — identically, so the report could not say which one had occurred.
- Detection: the first real run of `spec_drift_report`; the root cause was reachable only by
  reading both the profile's own `status` and the referenced entry's, neither of which the check
  looked at.
- Correction: the comparison now pairs the two statuses. Absent from the registry entirely, or
  active-but-ungenerated, stays a hard error whatever the profile's status; an **active** profile
  requiring a non-active entry became a *new* hard error with its own message; only the
  non-active-to-non-active pairing is exempt. A missing `status` field reads as active on both
  sides, so nothing is exempted by omission.
- Verified by injection: `crates/schema/tests/profile_requirement_pairing.rs` builds synthetic
  bundles that differ from the exempt pairing in exactly one status and asserts the gate still
  fires — including the case a careless fix would swallow (`candidate` profile, `active` schema).
- Prevention dimension: a gate that exempts a false positive must be pinned by the cases adjacent
  to it, not by the case it was written for. Only the neighbours distinguish "narrowed correctly"
  from "stopped checking".

## 2026-08-01 — `cargo clippy -D warnings` was already red at HEAD on orphaned doc comments

- Surface: workspace-wide; ~15 sites, e.g. `crates/wire/src/patch.rs:30`,
  `crates/schema/src/event_cell_contract.rs:416`, `crates/models-crypto/src/key_backup.rs:113`.
- Regression: a prior cleanup deleted items but left their `///` blocks behind, which then
  re-attached themselves to the next item with a blank line between. `clippy::empty_line_after_doc_comments`
  is `-D warnings` in this workspace, so the documented lint gate does not pass on `main`.
  Two effects compound: the CI lint step cannot be green, and the surviving comments now document
  the wrong item (`patch.rs` told the reader a path-length constant was a schema id).
- Correction: every orphaned comment and remaining workspace warning was resolved without
  suppressing the lint. `cargo clippy --workspace --all-features --all-targets -- -D warnings`
  now exits 0.
- Prevention dimension: same family as the CI entry below — a gate nobody has seen pass is not a
  gate. `-D warnings` in a config file proves nothing about the last time the command exited 0.

## 2026-08-01 — two CI gates invoked examples that were never in the repository

- Surface: `.github/workflows/ci.yml` jobs `rust` and `spec-drift`.
- Regression: the `rust` job ended with `cargo run --example export_openapi --features server`
  and `spec-drift` ended with `cargo run --example spec_drift_report`. Neither example has ever
  existed — the only example in the workspace is `crates/crypto/examples/dump_key_backup_kat.rs`.
  Both steps therefore failed at cargo target resolution, before executing anything. The
  consequence is not a noisy red build but the opposite: `SpecArtifactBundle::drift_report` — the
  declared hard gate over the `SUPPORTED_*` spec-coverage constants — had **never once run**, so
  those constants were free to drift for as long as they have existed.
- Detection: auditing which SDK types are spec-generated; the CI step referenced a target that
  could not be found anywhere in the tree.
- Correction: added `crates/schema/examples/spec_drift_report.rs` (env-var or embedded snapshot,
  non-zero exit on drift) and pinned the CI invocation to `-p arkret-schema`. Deleted the
  `export_openapi` step: no crate assembles an OpenAPI document, the `openapi` features only add
  `ToSchema` derives, and the SDK *consumes* the spec's OpenAPI as an embedded snapshot rather
  than producing one.
- First run of the restored gate found: 5 unlisted id kinds (fixed, below), 55 unlisted schemas
  and 2 event kinds with no payload validator (`ak.relation.tombstone`,
  `ak.moderation.franking_proof`), plus `ak.profile.candidate.join_policy.v1` requiring
  `ak.schema.join_policy_operations.v1`, which is absent from `REGISTERED_SCHEMA_IDS`. **The
  schema and payload-validator findings were subsequently closed**. The live count reached 57;
  every active schema is now generated and embedded under the written artifact-layer coverage
  contract, while payload carrier gaps were fixed in the spec. The manual schema list was deleted,
  so the resolution did not pad a second list to force the gate green.
- Prevention dimension: a CI step whose only observable behavior is its own exit code proves
  nothing about the gate it names. Any job asserting a hard gate must be shown failing on an
  injected violation at least once; a step that has never printed gate output is not evidence.

## 2026-08-01 — typed-id coverage was a hand-copied string list five kinds behind

- Surface: `arkret-schema::SUPPORTED_ID_KINDS` and `arkret-identifiers`.
- Regression: the constant that decides whether the SDK covers `id-kind-registry.json` was 47
  hand-written strings with nothing connecting it to the newtypes it claimed to describe. It had
  fallen behind on `authorization_lease`, `invite_locator`, `message_stream`,
  `recovery_authority_ticket` and `sidecar` — all five of which `arkret-identifiers` has shipped
  typed ids for all along. The mechanism: 53 separate `uuid_id_type!` calls expand to inherent
  associated `KIND_PREFIX` consts with no registry, so the set is unenumerable and the only way
  to state it was to retype it.
- Detection: the first real run of `spec_drift_report` (above).
- Correction: the calls now go through one `declare_uuid_id_kinds!` block that also emits
  `DECLARED_UUID_ID_KIND_PREFIXES`; `crates/schema/tests/id_kind_coverage.rs` compares that set
  with `SUPPORTED_ID_KINDS` in both directions, with a populated-both-sides guard so an emptied
  side cannot pass vacuously. The five missing kinds were added. `arkret-identifiers` sits below
  `arkret-wire` in the frozen layering and cannot read the generated descriptors itself, which is
  why the comparison lives in `arkret-schema` — the lowest crate that sees both sides.
- Prevention dimension: when a gate needs the set of things a macro declared, the macro must
  publish that set. A list that can only be kept correct by retyping it will drift, and the drift
  is invisible precisely because both copies look authoritative.

## 2026-08-01 — the HTTP client was the one spec-derived surface with no drift gate

- Surface: `arkret-http-client`.
- Regression: `crates/server/src/registry.rs` builds its routing table from
  `SERVICE_OPERATION_DESCRIPTORS`, so a spec path change moves the server automatically. The
  client spelled all ~115 distinct paths as string literals across 137 sites and referenced the
  generated descriptors **zero** times, and the crate had no `tests/` directory at all. A renamed
  path in `operation-registry.json` would regenerate the descriptors, keep the server correct,
  and leave the client silently issuing requests to endpoints the protocol no longer defines.
- Detection: cross-checking which crates consume the generated operation descriptors while
  auditing the spec-generation surface.
- Correction: `crates/http-client/tests/operation_path_coverage.rs` extracts every
  `"/_arkret/…"` literal from the client sources and requires each to normalise onto a registered
  `http_path`. Templates are compared shape-wise so `format!` with inline captures, positional
  arguments and plain literals all agree. Four non-endpoint literals are exempted individually
  with stated reasons, and a companion test deletes exemptions that stop appearing so the list
  cannot become a blanket suppression. All 115 current paths already matched — the defect was the
  absence of the gate, not the paths. The gate was verified by injecting a renamed path and
  confirming it fails.
- Prevention dimension: "the generated descriptors exist" is not the same as "the code uses
  them". When one side of a workspace derives a surface from a registry and another hardcodes it,
  the hardcoded side needs an explicit gate; symmetry of correctness today says nothing about
  symmetry after the next spec change.

## 2026-07-31 — `cargo clippy --fix` silently deleted a PartialEq impl from coverage

- Surface: `arkret-wire` `wire_strings.rs`, test
  `did_url_compares_against_string_types_in_both_directions`.
- Regression: the MSRV 1.97 cleanup ran `cargo clippy --fix` over the workspace. Clippy's
  `cmp_owned` rewrote `assert!(did_url != String::from(other))` to `assert!(did_url != other)`
  in both directions. Each rewritten line became a character-for-character duplicate of the
  `&str` assertion above it, so the `DidUrl`/`String` `PartialEq` impls the test exists to
  pin stopped being exercised at all. Clippy's own warning count went to zero and the test
  still passed, so nothing flagged the loss.
- Detection: human read of the diff — two visibly identical `assert!` lines in a row. No gate
  catches this: coverage is line-based and the lines still execute, just against the wrong impl.
- Correction: reverted both lines and put `#[allow(clippy::cmp_owned)]` on the test with the
  reason, since the owned operand *is* the subject under test.
- Prevention dimension: `--fix` output is a patch to review, never a result to accept on the
  strength of a clean warning count. Lints that "simplify" an expression (`cmp_owned`,
  `redundant_clone`, `useless_conversion`) are the dangerous class inside test bodies, where
  the discarded conversion is often the assertion's whole point. Review those hunks
  individually; a hunk that makes two adjacent assertions identical is the tell.
- Second finding from the same sweep, downstream: in `inkson`
  `views/chat/composer.rs`, `useless_conversion` rewrote a closure body inside a Leptos
  `view!` macro and left `api.sdk_http_client()})` on one line. The rewrite was semantically
  correct, but `rustfmt` does not format macro interiors, so the damage survived a clean
  `cargo fmt`. After running `--fix` on a repo with heavy macro usage, read the diff for
  collapsed delimiters — a formatter pass will not surface them.
- Cheap mechanical check that would have caught both: after `--fix`, diff each changed file
  against `HEAD` as sorted sets of trimmed non-blank lines. Pure reformatting and code motion
  cancel out, so what remains is exactly the lines whose *content* changed — the set worth
  reading by hand. That is how the 110-line `state/seal.rs` `items_after_test_module` move was
  confirmed to be a pure relocation.

## 2026-07-30 — generated FSM bindings still lacked executable transition semantics

- Surface: `arkret-lattice-registry` FSM construction used by Move/Seal verification.
- Regression: adding every spec-declared FSM family exposed several hand-maintained semantic gaps:
  audit and Realm-link creation states had no accepted first transition, Circle membership inherited
  Realm-only delivery-rebind self-transitions, last-resort KeyPackages could not remain published,
  and an absent provisioned Agent did not resolve to its normative `active` lifecycle state.
- Detection: trace the absent-cell `from` derivation through `verify_control_move`, then compare each
  FSM table with its normative lifecycle and conformance-vector text instead of checking only that
  the family resolved.
- Correction: encode the missing creation/initial transitions, keep the `join -> join` rebind only
  for Realm membership, permit the last-resort `published -> published` no-state-change operation,
  and register `active` as the implicit Agent lifecycle state.
- Prevention dimension: registry tests now exercise first writes and variant-specific transitions,
  in addition to exact family/lattice/bottom set equality.

## 2026-07-30 — executable lattice registry covered only a hand-picked subset

- Surface: `arkret-lattice-registry` and the Move/Seal `MemoryCellRegistry`.
- Regression: the spec declared 133 active cell families, while the executable factory registered
  84. The previous count assertion only pinned the hand-maintained subset and therefore stayed
  green as the spec added families.
- Detection: exact set comparison against `event-kind-registry.json` during the SDK code review.
- Correction: generate all family/lattice/bottom bindings from the active registry entries, remove
  the duplicate handwritten family list and its panic path, and compare the generated executable
  set with the embedded registry in both directions.
- Prevention dimension: the spec generation manifest owns the executable lattice-binding output;
  generation fails on incomplete, unsupported, or conflicting bindings, and the SDK test reports
  any missing or extra family without relying on a numeric threshold.

## 2026-07-30 — embedded artifacts and generated profile digests drifted independently

- Surface: `arkret-schema` embedded artifacts and `arkret-policy` generated reducer profile
  constants.
- Regression: the embedded artifact snapshot missed the latest capability fixture and reducer
  registry changes, while `profiles.rs` was two reducer-registry revisions behind. The existing
  remote drift gates were red on the main checkout.
- Detection: full artifact leaf comparison and the existing generation scripts' check modes.
- Correction: refresh all 265 embedded JSON artifacts and regenerate profile constants from the
  same current spec artifact tree.
- Prevention dimension: every spec synchronization must run both the embedded-artifact refresh and
  the manifest-owned generated-surface synchronization against one resolved artifact directory,
  followed by both check modes before commit.

## 2026-07-29 — anchor-unit validation rejected valid CAS preconditions

- Surface: `arkret-wire::Event::validate_for_submit_structural_in_context` and Soland's durable
  control-seal coordinator.
- Regression: `EventSubmitContext::AnchorUnit` required `preconditions[]` to be empty in addition
  to omitting `seal_ref`, `auth_context`, and `seal_basis`. The v1 spec exempts the closed anchor
  unit from a basis because no accepted Seal exists, but does not remove Control Move
  preconditions. Soland accepted Realm bootstrap batches and later rejected the same Events while
  constructing the genesis Seal, leaving the Realm permanently pending.
- Detection: `cotest` joint-full run `20260729-043955`; 34 direct
  `quorum_unreachable` failures plus dependent `frontier_unavailable` failures. Soland logs showed
  the coordinator rejecting accepted bootstrap Events as neither Data Events nor Control Moves.
- Required correction: allow preconditions in the closed `AnchorUnit` context, retain the
  fail-closed prohibition on all three CBA basis fields, and cover both standard-context rejection
  and anchor-context acceptance.
- Prevention dimension: every alternate Event submit context must be exercised at both initial
  admission and delayed/restarted Seal materialization; the same accepted bytes cannot be
  reinterpreted under a stricter structural gate.

## 2026-07-27 — stale operation discriminator assertion

- Surface: `arkret-event-draft/tests/operation_contract.rs`
- Regression: the protocol-wide naming migration changed the record classifier from `type` to `record_kind`, but the serialization contract test still asserted the removed `type` field.
- Detection: full targeted test run while implementing accountability scope-set subject derivation.
- Correction: assert `record_kind="operation"` and explicitly reject the stale `type` field.
- Prevention dimension: generated/model naming changes must include an all-target test run for every crate whose contract tests serialize the affected model.

## 2026-07-27 — active reducer cells missing from the lattice registry

- Surface: `arkret-lattice-registry`
- Regression: the generated contract registry declared
  `ak.component.identity.accountability.v1` and
  `ak.component.agent.selector_claim.v1`, but the executable registry exposed
  no bindings for those active cells.
- Detection: strict vector-registry and lattice round-trip coverage during the
  federation Seal closure review.
- Correction: register the canonical CAS and MV-register bindings, expose them
  through the public factory, and raise the binding-count regression guard from
  80 to 82.
- Prevention dimension: every active reducer-profile cell must round-trip
  through both the machine-readable contract and the executable factory.

## 2026-07-27 — key-backup KAT vector recorded a non-canonical nonce transcript

- Surface: `arkret-spec` `fixtures/key-backup-hardening-fixture.json`, case
  `passphrase_kdf_kat`; consumed by
  `arkret-crypto/tests/key_backup_kat_fixture.rs`.
- Regression: `intermediate.nonce_transcript_canonical_json` listed
  `backup_kind` before `backup_id`, which is not JCS key order, so it was not
  canonical JSON at all (`encoding.md` §2). The recorded
  `expected.nonce_hex` / `nonce_b64u` / `ciphertext_b64u` /
  `ciphertext_digest` matched neither the recorded transcript nor the canonical
  one, so the whole downstream chain of the vector was stale. Argon2id root
  key, all three HKDF subkeys, the AEAD AAD and the key commitment were
  unaffected and already matched the reference implementation.
- Detection: `passphrase_kdf_kat_reproduces_fixture_bytes` failed at the
  transcript assertion while clearing the workspace baseline.
- Correction: regenerated the transcript and its four downstream values from
  the reference implementation (`VaultBinding::nonce_transcript_canonical_bytes`
  → `derive_nonce` → `encrypt_vault_with_nonce_salt`), then re-ran
  `artifact_pipeline.py generate`, `check_fixture_digests.py --write-reference`,
  `artifact_pipeline.py check`, `lint_spec.py`, `release_gate.py` and
  `tools/refresh-embedded-artifacts.py`.
- Prevention dimension: any fixture field spelled `*_canonical_json` must be
  produced by the canonical encoder, never hand-edited; a KAT whose recorded
  transcript does not reproduce its own recorded output bytes is stale by
  construction.

## 2026-07-28 — generated Rust types refreshed without the embedded spec snapshot

- Surface: `arkret-schema` embedded artifacts.
- Regression: registry/type generation picked up the recovery receipt operation and new reason
  codes, but `embedded_artifacts.json` still carried the pre-change registry. Workspace tests
  failed on generated reason-code equality and live-spec snapshot equality.
- Detection: full SDK workspace test after rebasing all recovery work onto current `main`.
- Correction: run `tools/refresh-embedded-artifacts.py` against the same checked artifact tree and
  verify the 236 embedded JSON resources plus OpenAPI snapshot with the script's `--check` mode.
- Prevention dimension: spec-backed SDK generation is one atomic edit round: generated Rust,
  embedded JSON, embedded OpenAPI, and their equality tests must all use the same artifact tree.

## 2026-07-28 — closed enrollment union was only validated by an optional method call

- Surface: `AccountDeviceEnrollRequestBody`.
- Regression: the schema declares a closed founding/recovery union, but ordinary Serde
  deserialization can still construct a mixed or incomplete request and relies on each consumer
  remembering to call `validate()`/`mode()` afterward.
- Detection: wire-model self-review against the updated `agent-operations.schema.json`.
- Status: fixed by deleting the recovery branch and restoring the founding-only enrollment DTO.
  The future dedicated recovery authority operation must use an enum/validated deserializer that
  cannot represent the wrong branch.
- Prevention dimension: a protocol closed union should be enforced at construction and
  deserialization boundaries, not as a convention imposed on every downstream handler.

## 2026-07-29 — publication evidence used the Event-only proof wire

- Surface: `arkret-wire::AuthorizationLease` and `arkret-wire::IngressReceipt`.
- Regression: both non-Event signed objects exposed `Proof`, whose digest member is
  `event_digest`, although `offline-publication.schema.json` references the generic
  non-Event proof shape with `payload_digest`. The helper then signed a non-Event context while
  serializing an Event-only proof, producing wire that the normative schema rejects.
- Detection: implementing the Account Authority recovery outcome lease and comparing the SDK
  authoring path against the exact offline-publication schema.
- Correction: use `PayloadProof` throughout publication evidence, validate
  `payload_digest`, and migrate all SDK fixtures/helpers without aliases or dual decoding.
- Prevention dimension: every signed object family must test its serialized proof member names
  against its exact schema reference; Event proof helpers may never be reused by non-Event
  objects.

## 2026-07-30 — Realm frontier transport validation guessed the effective proposal policy

- Surface: `RealmSealFrontierView` and `ControlGovernanceHealth`.
- Regression: the account-client frontier carries proposal receipts and decision chains but not
  the Realm's exact decision policy. Its structural validator substituted
  `ControlProposalDecisionPolicy::protocol_maximum()` and performed exact-policy validation,
  rejecting a canonical 30s/90s receipt as though it were required to use the 24h/72h protocol
  ceilings.
- Detection: the real Inkson/Soland onboarding flow accepted and sealed the principal-control
  anchor, then failed locally while validating the returned Realm frontier.
- Correction: recover the effective receipt windows at the frontier boundary and require every
  receipt/decision chain to agree; authoritative admission and persistence still pass the full
  effective Realm policy explicitly.
- Prevention dimension: a protocol ceiling is a bound, never a substitute for an unresolved
  effective policy. DTOs that omit policy inputs must not pass `protocol_maximum()` to an
  exact-policy validator.

## 2026-08-01 — shared UI locale omitted its opt-in OpenAPI schema

- Surface: `arkret-locale::UiLocale` as embedded by `AccountHandoffOutcome`.
- Regression: `arkret-models-identity/openapi` derived `ToSchema` for the handoff outcome but did
  not enable or provide schema support for the newly shared locale enum, so current Soland and
  Inkson mains failed to compile with `UiLocale: ToSchema` missing.
- Correction: add an opt-in `arkret-locale/openapi` feature, derive `ToSchema` only under that
  feature, and forward it from `arkret-models-identity/openapi`. The locale crate's default graph
  remains dependency-free.
- Prevention dimension: every wire-model feature that derives a transitive schema must forward
  schema support to newly introduced field types; validate the feature combination directly.

## 2026-08-01 — authority controls retained the retired permission semantics

- Surface: policy constraint deserialization, child-grant authoring, and capability-frontier
  validation.
- Regression: `authority_regrant_allowed` still defaulted to `true`, the frontier walker followed
  only the first grant ref, and ordinary action evaluation compared absolute chain depth against
  the grant-local remaining-hop budget. This both widened omitted booleans and rejected valid
  multi-parent authority unions or valid uses of terminal child grants.
- Correction: the permission now defaults fail-closed to `false`; child issuance applies the
  parent constraint as a terminal-depth seal; frontier validation recursively walks every typed
  grant ref, validates union action/resource coverage and derived audit depth, and ordinary action
  evaluation no longer treats an issuance-only constraint as a business-action deny.
- Prevention dimension: remaining-hop budgets and absolute audit depth are distinct quantities;
  multi-parent protocol graphs require an explicit all-edge oracle and cannot be validated by a
  single `first()` walk.

## 2026-08-01 — payload-validator exceptions outlived their spec gaps

- Surface: `arkret-schema` active Event payload coverage gate.
- Regression: after the spec added closed payload validators for `ak.moderation.franking_proof`
  and `ak.relation.tombstone`, the SDK still listed both kinds as documented no-validator
  exceptions, making the drift gate fail against the current embedded registry.
- Correction: remove the two stale exceptions; only the actor-private
  `ak.read_cursor.advance` sibling-schema case remains.
- Prevention dimension: an exception inventory is bidirectional: it must fail when a new gap
  appears and when a formerly justified exception becomes obsolete.
