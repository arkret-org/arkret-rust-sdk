# Release Source Packages

# Tag releases

Pushing a `v*` tag builds and publishes a GitHub Release after every required
build succeeds. `workflow_dispatch` builds the same artifacts without publishing
a release; use it before tagging. Existing source versions are not changed.

Sibling checkout revisions in the workflow are part of the release source set.
Before tagging, update those pins to a compatible tested set and commit any
required Cargo.lock changes. Do not replace pinned revisions with `main`. Each
archive includes `build-info.json` with the source commits and lockfile hash,
and a companion SHA-256 file. Verify it from the download directory with
`sha256sum --check ./*.sha256`.

Cross-repository private dependencies require `CI_REPO_TOKEN` with read access;
`GITHUB_TOKEN` only supplies the current repository's permissions. Publishing
uses the release job's `contents: write` permission.

The SDK release contains the publishable workspace `.crate` source archives;
it does not contain platform executables. Private conformance/test crates are
excluded. The workflow does not publish to crates.io; its unpublished dependency
set and Cargo git dependencies need a separate registry release plan.

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
cargo package --workspace --exclude arkret-schema-conformance --exclude arkret-test-kit --exclude-lockfile --locked --no-verify
cargo doc --no-deps --all-features --workspace
cargo deny check --config .deny.toml
cargo audit --deny warnings --ignore RUSTSEC-2026-0124
cargo run -p arkret-schema --example spec_drift_report
```

Local verification does not create tags or releases. Only a pushed `v*` tag
activates the GitHub Release job.

The `cargo audit` ignore is a tracked upstream-dependency exception for a
package that is present in `Cargo.lock` but has no current upstream upgrade
path: `RUSTSEC-2026-0124` is the optional `hpke-rs-libcrux` backend recorded in
the lockfile while Arkret uses the RustCrypto HPKE backend.

Local package checks produce source archives without a release lockfile. The
private conformance crates are not packaged, and schema/model test dependencies
form a development-only cycle. Cargo cannot resolve that cycle against crates.io
before the workspace has been published. This check still validates normalized
manifests and archive contents; native checks and tests validate the locked
workspace dependency graph separately.

## Compatibility notes

Canonical digest behavior (`canonical` JSON encoder, signed payload shape,
AAD layout, redaction rules) is a local wire contract. Changing it requires an
explicit compatibility note in `CHANGELOG.md` and matching downstream updates.

The MSRV is pinned in `[workspace.package].rust-version`. Bumping it requires
a CHANGELOG entry and a CI run with the new pinned toolchain.
