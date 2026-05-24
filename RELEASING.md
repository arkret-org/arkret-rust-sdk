# Releasing

The Contrix Rust SDK is a 11-crate Cargo workspace. The full crate set is
published in a single coordinated release (one version, one tag) so that
downstream callers can pin a single `contrix = "x.y.z"` and have all the
transitively-published crates line up.

## Crate set and publish order

These crates are published in dependency order. crates.io requires every
listed dependency to already exist on the registry before a dependent crate
can be published, so order matters and re-runs may need a small delay between
crates while the registry indexes the new version.

```text
contrix-identifiers
contrix-core
contrix-ffi
contrix-html
contrix-http-client
contrix-signatures
contrix-crypto
contrix-api
contrix-server
contrix-testing
contrix    # umbrella SDK; depends on every other crate above
```

The order is generated from `cargo metadata --no-deps`. If any crate is added
or its dependency surface changes, regenerate it and update both this file and
the `CRATES:` block in `.github/workflows/release-crates.yml`.

To validate the workflow list locally before tagging, run:

```sh
python tools/check-publish-order.py            # validate the workflow's order
python tools/check-publish-order.py --print    # print a fresh topological order
```

The validator confirms every crate in the workflow appears after its
workspace dependencies. Any valid topological order works — alphabetical
tie-breaking is informational, not a requirement.

## Checklist

1. Run verification:

   ```sh
   cargo fmt --all -- --check
   cargo check --workspace --all-features
   cargo clippy --all-features --all-targets -- -D warnings
   cargo test --all-features
   cargo doc --no-deps --all-features --workspace
   cargo deny --config .deny.toml check --all-features
   cargo audit --deny warnings
   ```

2. Confirm the public protocol surface is compatible with the current Contrix
   specification. Update `docs/release-evidence-<version>.md` with the
   interoperability run results.

3. Update the workspace version in `Cargo.toml` (or run `cargo release` —
   `release.toml` is configured with `shared-version = true` so every member
   moves together).

4. Update `CHANGELOG.md`: rename the `## [Unreleased]` heading to the new
   version + date, then start a fresh `## [Unreleased]` block.

5. Tag and push:

   ```sh
   git tag "v$(grep -m1 '^version =' crates/sdk/Cargo.toml | cut -d'\"' -f2)"
   git push origin --tags
   ```

   The `Release crates.io` GitHub Actions workflow watches `v*.*.*` tag pushes
   and publishes every crate above in order. The tag push is the single
   release trigger; do **not** run `cargo publish` manually unless rescuing a
   partial release.

6. Manual rescue (only if the workflow fails partway through): re-run from the
   first crate that did not publish. The workflow's loop tolerates "version
   already exists" responses, so it is safe to re-trigger via
   `workflow_dispatch` with `dry_run = false`.

## Compatibility notes

Do not publish a release that changes canonical digest behavior (`canonical`
JSON encoder, signed payload shape, AAD layout, redaction rules) without an
explicit compatibility note in `CHANGELOG.md` and a major-version bump.

The MSRV is pinned in `[workspace.package].rust-version`. Bumping it requires
a CHANGELOG entry and a CI run with the new pinned toolchain.
