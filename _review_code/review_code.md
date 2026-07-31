# Regression review log

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
