# Regression review log

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
