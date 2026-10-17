# Dependency maintenance

The 2026-10-18 update checks every registry dependency declaration in the SDK
workspace, HTTP browser target, spec-codegen tool and fuzz harness against the
latest stable crates.io release. Workspace package versions remain unchanged.
Cargo.lock files are generated locally for verification and are never committed.
Each CI job resolves a fresh temporary lockfile before using --locked. Pre-release versions are not
introduced to replace stable dependencies.

## Intentional constraints

- `getrandom_02` remains on the latest 0.2 release. It unifies the WASM `js`
  feature for legacy transitive cryptography dependencies; replacing this alias
  with getrandom 0.4 would leave those actual 0.2 consumers unconfigured.
- `voprf` stays at 0.6.0-pre.1, the newest published pre-release already in use.
  The latest stable 0.5.0 would be a downgrade and uses an older crypto stack.
- `zbus` stays on the latest 5.x release, 5.19.0. The latest stable
  [`secret-service` 5.2.0](https://crates.io/crates/secret-service/5.2.0)
  requires zbus 5 and accepts its `Connection` in `connect_with_existing`.
  The keystore's mutation lease and Secret Service session share that connection;
  independently upgrading the direct zbus dependency to 6 would break the API.

## Advisory handling

The verified dependency resolution upgrades rustls to 0.23.46, fixing RUSTSEC-2026-0346 through
RUSTSEC-2026-0349, and replaces yanked chacha20 0.10.1 with 0.10.2.

RUSTSEC-2026-0370, RUSTSEC-2026-0371 and RUSTSEC-2026-0372 are upstream
maintenance notices: zvariant, zbus_names and zvariant_derive have been
[merged into zbus 6](https://github.com/z-galaxy/zbus/issues/2043).
They do not describe vulnerabilities. The exact notices are recorded in
`.deny.toml` because the latest Secret Service release still requires them.
Remove these three entries and migrate the whole connection/Secret Service
graph when that upstream library supports zbus 6. Vulnerability checks remain
enabled; no vulnerability advisory is ignored by this update.

The spec-codegen and fuzz packages declare the repository's Apache-2.0 license.
Auditing the separate fuzz workspace also registers the existing libfuzzer-sys
dependency's [NCSA license](https://spdx.org/licenses/NCSA.html), alongside its
MIT/Apache-2.0 Rust wrapper. The upstream libFuzzer notices remain in that
dependency; the fuzz harness is unpublished and outside the SDK workspace.
