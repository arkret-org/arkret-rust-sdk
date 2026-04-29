# Release Evidence: 0.1.0

Date: 2026-04-29

Status: release-candidate evidence file. This tag remains a `0.1.x`
candidate until external security review and real server interoperability are
recorded.

## Local Gates

The release gate is complete only when every command below passes on the
candidate revision:

- [x] `cargo fmt --all -- --check`
- [x] `cargo check --no-default-features`
- [x] `cargo check --no-default-features --features client`
- [x] `cargo check --no-default-features --features server`
- [x] `cargo check --no-default-features --features mls`
- [x] `cargo check --all-features`
- [x] `cargo clippy --all-features --all-targets -- -D warnings`
- [x] `cargo test --all-features`
- [x] `cargo test --all-features --examples`
- [x] `cargo test --examples`
- [x] `cargo run --example export_openapi --features server`
- [x] `git diff --check`

## External Gates

- [ ] OpenAPI export reviewed against the Contrix spec.
- [ ] Real server interoperability recorded for login, repo write, sync, media,
  push and encrypted message flow.
- [ ] Federation push/pull smoke test recorded across two services.
- [ ] External security review recorded with issue dispositions.

## Exit Criteria

Alpha requires typed public APIs, durable native store contracts and basic
real-server sync evidence.

Beta requires multi-device crypto recovery, interop conformance and migration
tests.

Stable requires external audit, compatibility policy and semver API freeze.
