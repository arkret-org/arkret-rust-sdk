# Release Readiness

Current target: `0.1.0`.

This repository is ready for a public `0.1.0` release only when these gates pass:

- `cargo fmt --all -- --check`
- `cargo check --no-default-features`
- `cargo check --no-default-features --features client`
- `cargo check --no-default-features --features server`
- `cargo check --no-default-features --features mls`
- `cargo check --all-features`
- `cargo clippy --all-features --all-targets -- -D warnings`
- `cargo test --all-features`
- The generated OpenAPI document from `cargo run --example export_openapi --features server` is reviewed against the Contrix spec.
- README and crate docs clearly state the remaining external security review
  and current interoperability evidence status.
- Local encryption helpers use authenticated encryption and no legacy placeholder encryption remains.
- Mobile bindings stay unpublished while `ffi_api_freeze_review()` reports
  `reviewed_but_unfrozen` or any publication blockers.
- `cargo semver-checks` is non-blocking for this rapid `0.1.x` bootstrap;
  breaking API updates are accepted until the stable API freeze.
- Basic interoperability smoke is recorded in `docs/release-evidence-0.1.0.md`
  for `soland`, `starid`, `floria`, `chime`, and federation endpoints.

Security notes before a stable non-0.x release:

- Back production MLS state with a platform key store and durable crypto store implementation.
- Run protocol conformance tests against at least one real server implementation.
