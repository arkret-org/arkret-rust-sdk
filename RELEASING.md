# Local Release Readiness

The Arkret Rust SDK is a 30-crate Cargo workspace. This repository's release
readiness strand is local-only: it validates the coordinated crate set without
publishing to crates.io, creating GitHub releases, or pushing tags.

## Crate set and package order

These crates are packaged in dependency order so local package checks catch
workspace dependency and manifest drift:

```text
arkret-canonical
arkret-egress-policy
arkret-egress-reqwest
arkret-retry
arkret-identifiers
arkret-keystore
arkret-locale
arkret-wire
arkret-hlc
arkret-models-crypto
arkret-models-identity
arkret-schema
arkret-models-collaboration
arkret-models-discovery
arkret-models-integration
arkret-push-policy
arkret-event-draft
arkret-policy
arkret-state
arkret-signatures
arkret-auth
arkret-crypto
arkret-identity
arkret-mls
arkret-http-client
arkret-bootstrap
arkret-rate-limit
arkret-server
arkret
```

The order is generated from `cargo metadata --no-deps`. If any crate is added
or its dependency surface changes, regenerate it and update both this file and
the package-check workflow:

```sh
python tools/check-publish-order.py
python tools/check-publish-order.py --print
```

## Checklist

Run verification locally:

```sh
cargo +nightly fmt --all -- --check
cargo check -p arkret
cargo check --no-default-features
cargo check --no-default-features --features client
cargo check --no-default-features --features server
cargo check --no-default-features --features mls
cargo check --workspace --all-features
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
python tools/check-publish-order.py
cargo package --workspace --locked --no-verify
cargo doc --no-deps --all-features --workspace
cargo deny check --config .deny.toml
cargo audit --deny warnings --ignore RUSTSEC-2026-0124
cargo run -p arkret-schema --example spec_drift_report
```

Do not run `cargo publish`, do not create/push release tags, and do not create
GitHub releases as part of this local readiness workflow.

The `cargo audit` ignore is a tracked upstream-dependency exception for a
package that is present in `Cargo.lock` but has no current upstream upgrade
path: `RUSTSEC-2026-0124` is the optional `hpke-rs-libcrux` backend recorded in
the lockfile while Arkret uses the RustCrypto HPKE backend.

## Compatibility notes

Canonical digest behavior (`canonical` JSON encoder, signed payload shape,
AAD layout, redaction rules) is a local wire contract. Changing it requires an
explicit compatibility note in `CHANGELOG.md` and matching downstream updates.

The MSRV is pinned in `[workspace.package].rust-version`. Bumping it requires
a CHANGELOG entry and a CI run with the new pinned toolchain.
