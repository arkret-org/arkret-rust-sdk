# Dependency maintenance

The 2026-10-18 update checks every registry dependency declaration in the SDK
workspace, HTTP browser target, spec-codegen tool and fuzz harness against the
latest stable crates.io release. Workspace package versions remain unchanged.
The root Cargo.lock is tracked for reproducible workspace and tag-release
verification. Update it with targeted `cargo update -p <package> --precise
<version>` commands and retain the resulting advisory and test evidence.
The regular CI jobs also exercise fresh compatible dependency resolution before
using --locked; this does not replace auditing the tracked workspace lockfile.
The independent spec-codegen and fuzz lockfiles remain local verification
outputs. Pre-release versions are not introduced to replace stable dependencies.

## Intentional constraints

- `getrandom_02` remains on the latest 0.2 release. It unifies the WASM `js`
  feature for legacy transitive cryptography dependencies; replacing this alias
  with getrandom 0.4 would leave those actual 0.2 consumers unconfigured.
- `voprf` stays at 0.6.0-pre.1, the newest published pre-release already in use.
  The latest stable 0.5.0 would be a downgrade and uses an older crypto stack.
- `zbus` and `secret-service` migrate together to zbus 6. The Secret Service
  dependency uses the `arkret/zbus-6` branch of
  https://github.com/arkret-org/secret-service-rs, pinned by complete revision.
  Its upstream 5.2.0 package identity and licenses are retained. No third-party
  source is copied into the SDK. The mutation lease and Secret Service session
  still share one connection; the public KeyStore API stays synchronous.

## Advisory handling

The verified dependency resolution upgrades rustls to 0.23.46, fixing RUSTSEC-2026-0346 through
RUSTSEC-2026-0349, and replaces yanked chacha20 0.10.1 with 0.10.2.

The 2026-10-23 tracked workspace lockfile update resolves ctutils 0.4.4
(RUSTSEC-2026-0385), rustls-webpki 0.103.16 (RUSTSEC-2026-0382), and
webpki-root-certs 1.0.10 (RUSTSEC-2026-0383) within existing dependency
constraints. No workspace package versions or advisory exemptions change.

The OpenMLS fork now uses the `arkret/rustcrypto-constant-time` branch of
https://github.com/arkret-org/openmls, pinned to
`67e25df7f507ac62b27b75cf76981b99a83742a2`. Its hpke-rs 0.8 backend removes
the old libcrux-kem 0.0.9 dependency, resolving RUSTSEC-2026-0330 and
RUSTSEC-2026-0331. The credential and provider crates use p256/p384 0.14,
so the locked graph no longer retains crypto-bigint 0.5.5 affected by
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
The locked graph selects crypto-bigint 0.7.10 and tokio 1.54.1, also resolving
RUSTSEC-2026-0386. No advisory exemptions or workspace package versions change.
The fork retains the upstream licenses, documents its maintenance, and tests
P-256/P-384/Ed25519 signature generation, verification and tampering rejection.

RUSTSEC-2026-0370, RUSTSEC-2026-0371 and RUSTSEC-2026-0372 are upstream
maintenance notices: zvariant, zbus_names and zvariant_derive have been
[merged into zbus 6](https://github.com/z-galaxy/zbus/issues/2043).
The complete Secret Service/lease graph now uses zbus 6, so the three
maintenance-notice exemptions are removed from `.deny.toml`. The fork is an
explicit allowed Git source; unknown Git sources remain denied. Actual Linux
Secret Service contracts and process competition must pass when updating the
revision. See [KeyStore maintenance](../crates/keystore/README.md).

The spec-codegen and fuzz packages declare the repository's Apache-2.0 license.
Auditing the separate fuzz workspace also registers the existing libfuzzer-sys
dependency's [NCSA license](https://spdx.org/licenses/NCSA.html), alongside its
MIT/Apache-2.0 Rust wrapper. The upstream libFuzzer notices remain in that
dependency; the fuzz harness is unpublished and outside the SDK workspace.
