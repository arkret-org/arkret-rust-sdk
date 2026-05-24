# Release Readiness

Current target: `0.8.0-rc1`.

This repository is ready for a public `0.8.0-rc1` release only when these gates pass:

- `cargo fmt --all -- --check`
- `cargo check --no-default-features`
- `cargo check --no-default-features --features client`
- `cargo check --no-default-features --features server`
- `cargo check --no-default-features --features mls`
- `cargo check --all-features`
- `cargo clippy --all-features --all-targets -- -D warnings`
- `cargo test --all-features`
- `cargo semver-checks check-release --workspace` runs in CI as a
  non-blocking warning until the 1.0 API freeze.
- `cargo tarpaulin --config tarpaulin.toml --out Xml` uploads coverage to
  Codecov without a hard threshold.
- README and crate docs clearly state the remaining external security review
  and current interoperability evidence status.
- Local encryption helpers use authenticated encryption and no obsolete placeholder encryption remains.
- Mobile bindings stay unpublished until the runtime-facing FFI and callback
  contracts have real downstream consumers and release commitments.
- Basic interoperability smoke is recorded in `docs/release-evidence-0.8.0-rc1.md`
  for `soland`, `starid`, `floria`, `chime`, and federation endpoints.

Security notes before a stable non-0.x release:

- Back production MLS state with a platform key store and durable crypto store implementation.
- Run protocol conformance tests against at least one real server implementation.
