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
| `MacOsKeychainKeyStore` | survives logout and reboot (login keychain) | Keychain, unlocked with the login session | atomic add-if-absent using Keychain uniqueness |
| `LinuxSecretServiceKeyStore` | survives logout and reboot (default collection) | Secret Service daemon; the collection may lock on logout | namespaced D-Bus lease serializes SDK mutations |
| `WindowsProtectedKeyStore` | survives logout and reboot (current-user DPAPI) | XChaCha20-Poly1305 vault; 32-byte master key protected by user-profile DPAPI | stable lock files + atomic same-directory replacement |

`store` remains last-writer-wins. `create_if_absent` atomically returns the
first committed value without replacing existing bytes, including corrupt
values. File and Windows stores use the existing stable vault lock; macOS uses
Keychain's unique `(service, account)` add operation. Linux holds an exclusive
D-Bus name on the same connection as its Secret Service session, queueing
cooperating SDK mutations and releasing ownership on disconnect/crash. Direct
external writers must not mutate the Linux namespace concurrently; duplicate
Secret Service items fail closed. This is first creation, not key rotation or
compare-and-swap; serialize explicit rotation/deletion at the application layer.
Custom import-only backends default to typed `Unsupported` for first creation.

Licensed under Apache-2.0.
