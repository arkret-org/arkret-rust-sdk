# Release Readiness

Current target: `0.8.0-rc1`.

This repository is ready for local `0.8.0-rc1` freeze only when these gates pass:

- `cargo fmt --all -- --check`
- `cargo check --no-default-features`
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
- `cargo semver-checks check-release --workspace` is a blocking CI gate for
  the 1.0 API freeze.
- `cargo tarpaulin --config tarpaulin.toml --out Xml` uploads coverage to
  Codecov without a hard threshold.
- README and crate docs clearly state the local security-review packet and
  current interoperability evidence status.
- Local encryption helpers use authenticated encryption and no obsolete placeholder encryption remains.
- Mobile bindings stay unpublished until the runtime-facing FFI and callback
  contracts have real downstream consumers and release commitments.
- Basic interoperability smoke is recorded in `docs/release-evidence-0.8.0-rc1.md`
  for `soland`, `starid`, `floria`, `chime`, and federation endpoints.
- The two `cargo audit` ignores are tracked upstream-dependency exceptions:
  `instant` is pulled through OpenMLS's wasm timer path, and
  `libcrux-chacha20poly1305` is present only through hpke-rs's optional
  libcrux backend while the SDK enables the RustCrypto HPKE backend.
- This local readiness workflow does not publish crates, create GitHub
  releases, or require release tags.

Security notes before a stable non-0.x release:

- Back production MLS state with a platform key store and durable crypto store implementation.
- Run protocol conformance tests against at least one real server implementation.
