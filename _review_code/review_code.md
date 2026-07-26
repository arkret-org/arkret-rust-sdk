# Regression review log

## 2026-07-27 — stale operation discriminator assertion

- Surface: `arkret-event-draft/tests/operation_contract.rs`
- Regression: the protocol-wide naming migration changed the record classifier from `type` to `record_kind`, but the serialization contract test still asserted the removed `type` field.
- Detection: full targeted test run while implementing accountability scope-set subject derivation.
- Correction: assert `record_kind="operation"` and explicitly reject the stale `type` field.
- Prevention dimension: generated/model naming changes must include an all-target test run for every crate whose contract tests serialize the affected model.
