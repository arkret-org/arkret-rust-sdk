# Release Evidence: 1.0.0

Date: 2026-05-25

Status: local `1.0.0` freeze evidence. No crates were published, no GitHub
release was created, and no release tag was pushed.

## Local Gates

The final package gate for this repository is:

```powershell
cargo fmt --all -- --check
cargo check --no-default-features
cargo check --no-default-features --features client
cargo check --no-default-features --features server
cargo check --no-default-features --features mls
cargo check --all-features
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
python tools\check-publish-order.py
cargo package --workspace --locked --no-verify
git diff --check
```

## Interop Evidence

cotest local release gate against soland:

- Command:
  `pwsh -NoProfile -File ..\cotest\scripts\run-cotest.ps1 -Profile release-gate -Runtime process -SkipJointSmokeGate`
- Result: success
- Passed: 28
- Failed: 0
- Summary:
  `D:\Works\cokret\cotest\artifacts\runs\20260525-055932\summary.md`
- Release gate:
  `D:\Works\cokret\cotest\artifacts\runs\20260525-055932\release-gate.md`

The gate covers protocol conformance fixtures, profile discovery, privacy
boundary checks, push-rule consistency, account/session edges, federation
replay, optional starid resolver discovery, session-grant introspection, and
yougen mock-vs-live soland parity.

## Security Evidence

- Local review packet: `docs/security-review-1.0.0.md`
- Internal checklist: `docs/security-audit.md`
- Feature safety API: `cokret::current_feature_safety_report().validate()`
- Semver gate: `.github/workflows/ci.yml` now treats
  `cargo semver-checks check-release --workspace --baseline-rev HEAD~1` as
  blocking. Local pre-commit validation used `--baseline-rev HEAD` so the
  dirty 1.0.0 working tree was compared against the committed 0.8.0-rc1
  baseline without querying crates.io.

## External Claims

This evidence file does not claim an external audit, crates.io publication, or
remote release. It records local readiness only.
