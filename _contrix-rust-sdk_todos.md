# contrix-rust-sdk — Release-Readiness Tasks

> Parent plan: [`../_todos_all.md`](../_todos_all.md)
> Project role: base SDK; consumed by every downstream Rust project.
> Phase: **1 (blocking)**, with finishing touches in **5**.

## State at start (2026-05-24)

- 11 crates at version 0.7.0; resolver=3; MSRV 1.92.
- 1,001 unit tests pass; clippy/audit/deny/MSRV/docs/dry-publish/spec-drift all in CI.
- ~15 TODOs identified across core + sdk crates.
- No semver-checks, no codecov, no tests/ integration dir for the umbrella crate.
- Public API surface clean; realm-rework backward-compat aliases (`PlaceId`, `PLACE_SCHEMA`, `OP_PLACE_*`) still present.

## Phase 1 tasks (close before tagging 0.8.0-rc1)

### Critical TODOs (in code)
- [x] §1 `crates/sdk/src/auth/grants.rs:362` — make `SessionGrantOutbox` a trait with a default in-memory impl + a `Box<dyn>` slot so coauth/soland can plug a Pg-backed implementation. Tests: add an in-memory + a mock-pg test.
- [x] §2 `crates/core/src/cursor.rs:32` — replace the weak PRNG fallback with `getrandom` (and document panic on init failure).
- [x] §3 `crates/core/src/model/round23.rs:386` — wire identity-link cache invalidation into the link router.
- [x] §4 `crates/core/src/model/round4.rs:616,623` — finish `wire_shape` comment + snapshot bootstrap signing.
- [x] §5 `crates/core/src/state/verify.rs:111` — wire M8 capability typed model when soland lands the `cx.capability.grant` cell.
- [x] §6 `crates/sdk/src/resolver/state.rs:205` — rename `reduce_space_lifecycle_event` → `reduce_realm_lifecycle_event`.
- [x] §7 `crates/sdk/src/resolver/state.rs:300` — consume `cx.morph.create` per C47 Lane A4.
- [x] §8 `crates/sdk/src/device_message.rs:290` — implement `sign_move` (or document it as test-only and panic with a clearer message).
- [x] §9 `crates/core/src/events/kinds.rs:425,489` — sort `STANDARD_EVENT_KINDS` so `binary_search` is correct, drop the linear-scan fallback.

### Realm-rework alias removal (wire-breaking; coordinate with master plan Rule B)
- [x] §10 `crates/identifiers/src/lib.rs:252` — delete `PlaceId` alias and any re-export.
- [x] §11 `crates/core/src/model/constants.rs:14,90,130` — delete `PLACE_SCHEMA`, `OP_PLACE_*`, legacy `OP_SPACE_*` aliases.
- [x] §12 Sweep `grep -rni "PlaceId\|PLACE_SCHEMA\|OP_PLACE_" crates/` — expect zero hits after §10–§11.

### Engineering hygiene (master plan §5)
- [x] §13 Add `cargo semver-checks` to CI (non-blocking warning until 1.0, then `-D warnings`).
- [x] §14 Add codecov upload from the existing `tarpaulin.toml`-driven coverage run; aim for a badge in README; no hard threshold yet.
- [x] §15 Add an umbrella `contrix` crate end-to-end smoke test (build a client, sign a sample event, verify it).
- [x] §16 Bump MSRV to 1.92 explicitly in every crate's Cargo.toml (workspace already pins; verify per-crate has `rust-version` set).
- [x] §17 Add a pre-commit hook (`.githooks/pre-commit`) running fmt + clippy on touched crates; document in CONTRIBUTING.md.

### Public API + docs
- [x] §18 Audit `crates/sdk/src/lib.rs` re-exports — confirm no pre-rename symbols leak. Update `ARCHITECTURE.md` example to use only realm-* names.
- [x] §19 Refresh `docs/release-readiness.md` checklist for 0.8.0-rc1.
- [x] §20 Add a `MIGRATING-FROM-0.7.md` documenting alias removal.

### Tag
- [x] §21 Bump all 11 crates to `0.8.0-rc1`. `RELEASING.md` already encodes the order.
- [ ] §22 Run release package checks and the coordinated publish/tag path for `v0.8.0-rc1`. Full dependent `cargo publish --dry-run` requires preceding internal RC crates to already exist on crates.io.

## Phase 5 tasks (final 1.0)

- [ ] §23 External security review — per `SECURITY.md` and `README.md`, this is a hard gate.
- [ ] §24 Final interop evidence (link to cotest release-gate run from `docs/release-evidence-0.1.0.md` → rename to `release-evidence-1.0.0.md`).
- [ ] §25 Flip `cargo semver-checks` from warn to `-D warnings`.
- [ ] §26 Bump to 1.0.0, publish.

## Exit gate (phase 1)

All of:
1. §1-§22 closed.
2. CI green on all 4 feature variants (no-default, client, server, mls).
3. `cargo run --example spec_drift_report` reports zero drift vs `contrix-spec v1.0.0-rc1` artifacts.
4. `0.8.0-rc1` published.

## Notes

- Mobile FFI bindings remain unpublished — that's correct for 0.8.0. Plan them for 0.9 or 1.0 with a separate `RELEASING-FFI.md`.
- COSE support is out-of-scope for 1.0; reaffirm in `SECURITY.md`.
- TLS pinning in `http-client` is currently a documentation gap; either add a pinning extension trait or document the rationale in `docs/deployment.md`.
