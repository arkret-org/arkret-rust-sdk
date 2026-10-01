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

## Persistence and concurrency semantics

The backends are not semantically identical:

| Backend | Persistence | At-rest protection | Cross-process concurrency |
|---|---|---|---|
| `EncryptedFileKeyStore` | survives reboot with caller-custodied master key | XChaCha20-Poly1305 authenticated encryption | stable lock file + atomic same-directory replacement |
| `MacOsKeychainKeyStore` | survives logout and reboot (login keychain) | Keychain, unlocked with the login session | Keychain serializes item ops; no SDK-level CAS |
| `LinuxSecretServiceKeyStore` | survives logout and reboot (default collection) | Secret Service daemon; the collection may lock on logout | D-Bus daemon serializes ops; no SDK-level CAS |
| `WindowsProtectedKeyStore` | survives logout and reboot (current-user DPAPI) | XChaCha20-Poly1305 vault; 32-byte master key protected by user-profile DPAPI | stable lock files + atomic same-directory replacement |

Every backend is last-writer-wins for `store` on the same id and provides no
compare-and-swap. The encrypted-file backend serializes whole-map updates;
OS-native backends rely on their platform service. Serialize semantic key
rotation at the application layer.

Licensed under Apache-2.0.
