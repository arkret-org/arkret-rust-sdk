# Regression review log

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
