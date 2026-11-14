# arkret-keystore

Durable `KeyStore` backends for the Arkret v1 SDK.

This crate owns the pure storage contract (`KeyStore`, `KeyStoreError`, and
zeroizing `KeyBytes`), an encrypted-file backend, and OS-native backends behind
target-specific features. The `arkret` umbrella re-exports the public surface:

| Backend | Feature | `target_os` |
|---|---|---|
| `EncryptedFileKeyStore` | `keystore-encrypted-file` | native targets |
| `MacOsKeychainKeyStore` | `keystore-macos` | `macos` |
| `LinuxSecretServiceKeyStore` | `keystore-linux` | `linux` |
| `WindowsProtectedKeyStore` | `keystore-windows` | `windows` |

Each platform type still compiles on every target; off-target constructors
return `KeyStoreError::Unsupported`. Use `durable_platform_keystore` whenever
persistence is required; it fails closed if the target's durable backend was
not compiled or the host service is unavailable. The SDK does not provide an
in-memory fallback; tests that need a fake implement the small `KeyStore`
contract locally.

`EncryptedFileKeyStore` uses a caller-custodied random 32-byte master key,
HKDF-SHA256, and XChaCha20-Poly1305. Keep the master key outside the ciphertext
file's backup and access-control boundary. A stable sidecar lock and atomic
same-directory replacement make whole-map updates safe across processes.

## Linux dependency maintenance

The Secret Service transport comes from the `arkret/zbus-6` branch of
https://github.com/arkret-org/secret-service-rs, pinned to a complete Git revision
in the workspace manifest. The SDK keeps no third-party source copy. The fork
moves to zbus 6 and its integrated wire types; upstream package version and
license terms are unchanged. The public KeyStore API remains synchronous, with
zbus driving the internal async calls. Mutation leases still share the actual
Secret Service connection and close it explicitly on drop.

Use `tools/with-test-secret-service.sh` for the real Linux backend contracts and
explicit cross-process `secret_service_processes_converge_on_one_first_key`
test. Constructor-only or off-target tests do not validate Secret Service.

## Persistence and concurrency semantics

The backends are not semantically identical:

| Backend | Persistence | At-rest protection | Cross-process concurrency |
|---|---|---|---|
| `EncryptedFileKeyStore` | survives reboot with caller-custodied master key | XChaCha20-Poly1305 authenticated encryption | stable lock file + atomic same-directory replacement |
| `MacOsKeychainKeyStore` | survives logout and reboot (login keychain) | Keychain, unlocked with the login session | per-user stable OS lock serializes Keychain mutations |
| `LinuxSecretServiceKeyStore` | survives logout and reboot (default collection) | Secret Service daemon; the collection may lock on logout | namespaced D-Bus lease serializes SDK mutations |
| `WindowsProtectedKeyStore` | survives logout and reboot (current-user DPAPI) | XChaCha20-Poly1305 vault; 32-byte master key protected by user-profile DPAPI | stable lock files + atomic same-directory replacement |

`store` remains last-writer-wins. `create_if_absent` returns the committed
first value without replacing existing bytes, including invalid application
payloads. `compare_exchange` compares the complete committed bytes and replaces
only a matching value; absence and a present empty value are distinct. Successful
returns follow durable commit, and a mismatch leaves storage unchanged.
File and Windows stores serialize every mutation with their stable vault lock.
macOS uses a private per-user stable OS file lock shared by all SDK writers in
one Keychain service; the system account home is resolved independently of HOME and
TMPDIR, outside temporary-file cleanup. Linux holds a namespaced D-Bus lease on the actual Secret Service
connection. Process exit releases the OS lock or lease. Direct external writers
must not mutate the macOS or Linux namespace concurrently; ambiguous Secret
Service items fail closed. Custom import-only backends default to typed
`Unsupported` for first creation and compare exchange, without emulating them
using a separate load and store.

Licensed under Apache-2.0.
