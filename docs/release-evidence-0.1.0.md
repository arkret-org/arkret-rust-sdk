# Release Evidence: 0.1.0

Date: 2026-04-30

Status: release-candidate evidence file. This tag remains a `0.1.x`
candidate until external security review is recorded. Semver compatibility
checks are intentionally skipped for this rapid `0.1.x` bootstrap because
breaking API updates are accepted.

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
- [x] `git diff --check`
- [x] `cargo semver-checks`: skipped on 2026-04-30 because the local cargo
  subcommand is unavailable and `0.1.x` breaking API updates are accepted.
## External Gates

- [x] Basic real-service interoperability smoke recorded:
  - `E:\Works\arkret\soland`: `cargo test --test http_api push_profile_and_moderation_contracts_work -- --nocapture`.
  - `E:\Works\arkret\soland`: `cargo test --test http_api account_contacts_and_space_lifecycle_workflow -- --nocapture`.
  - `E:\Works\arkret\starid`: `cargo test --test http_api`, 12 passed.
  - `E:\Works\arkret\floria`: `cargo test --lib --all-features service::tests -- --nocapture`, 32 passed.
  - `E:\Works\arkret\chime`: `cargo test --all-features`, 40 unit tests + 4 doctests passed, 1 doctest ignored.
- [x] Federation smoke recorded in `E:\Works\arkret\soland`:
  - `cargo test --test http_api federation_rejects_replayed_operations -- --nocapture`.
  - `cargo test --test http_api federation_transactions_are_idempotent_by_origin_and_body -- --nocapture`.
- [ ] External security review recorded with issue dispositions.

## Exit Criteria

Alpha requires typed public APIs, durable native store contracts and basic
real-server sync evidence.

Beta requires multi-device crypto recovery, interop conformance and migration
tests.

Stable requires external audit, compatibility policy and semver API freeze.
