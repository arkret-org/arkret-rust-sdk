# Release Readiness

Current target: active Arkret v1 SDK `0.3.x` development line. Workspace crate
versions remain `0.3.0` until an explicit release cut.

This repository is ready for a local `0.3.x` release-candidate cut only when
these gates pass:

- `cargo +nightly fmt --all -- --check`
- `cargo check -p arkret`
- `cargo check --no-default-features`
- `cargo check -p arkret --no-default-features --features full-surface`
- `cargo check --no-default-features --features client`
- `cargo check --no-default-features --features server`
- `cargo check --no-default-features --features mls`
- `cargo check --all-features`
- `cargo clippy --all-features --all-targets -- -D warnings`
- `cargo test --all-features`
- `python tools/check-publish-order.py`
- `cargo package --workspace --locked --no-verify`
- `cargo doc --no-deps --all-features --workspace`
- `cargo deny check --config .deny.toml`
- `cargo audit --deny warnings --ignore RUSTSEC-2024-0384 --ignore RUSTSEC-2026-0124`
- `cargo run --example spec_drift_report`
- `cargo semver-checks check-release --workspace --baseline-rev HEAD~1` is a
  blocking CI gate for release-candidate API compatibility evidence. During
  pre-commit local validation, use `--baseline-rev HEAD` to compare the dirty
  working tree against the last committed local baseline.
- `cargo tarpaulin --config tarpaulin.toml --out Xml` uploads coverage to
  Codecov without a hard threshold.
- README and crate docs clearly state the local security-review packet and
  current interoperability evidence status.
- Local encryption helpers use authenticated encryption and no obsolete placeholder encryption remains.
- Mobile bindings stay unpublished until the runtime-facing FFI and callback
  contracts have real downstream consumers and release commitments.
- Basic interoperability smoke is recorded under `docs/` for `soland`,
  `starid`, `floria`, `chime`, and federation endpoints.
- The two `cargo audit` ignores are tracked upstream-dependency exceptions:
  `instant` is pulled through OpenMLS's wasm timer path, and
  `libcrux-chacha20poly1305` is present only through hpke-rs's optional
  libcrux backend while the SDK enables the RustCrypto HPKE backend.
- This local readiness workflow does not publish crates, create GitHub
  releases, or require release tags.

Security notes for the `0.3.x` development line:

- Back production MLS state with a platform key store and durable crypto store implementation.
- Run protocol conformance tests against at least one real server implementation.
