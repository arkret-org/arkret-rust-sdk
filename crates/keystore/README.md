# arkret-keystore

Durable `KeyStore` backends for the Arkret v1 SDK.

The pure storage contract — the `KeyStore` trait, `KeyStoreError`, and the
dependency-free `InMemoryKeyStore` — lives in `arkret-core`. This crate adds
an encrypted-file backend plus OS-native backends that carry platform IO and
native dependencies, kept out of `arkret-core` so the core wire/model crate
stays light:

| Backend | Feature | `target_os` |
|---|---|---|
| `InMemoryKeyStore` (re-exported from `arkret-core`) | always available | any |
| `EncryptedFileKeyStore` | `keystore-encrypted-file` | native targets |
| `MacOsKeychainKeyStore` | `keystore-macos` | `macos` |
| `LinuxSecretServiceKeyStore` | `keystore-linux` | `linux` |
| `WindowsCredentialKeyStore` | `keystore-windows` | `windows` |

Each platform type still compiles on every target; off-target constructors
return `KeyStoreError::Unsupported`. Use `durable_platform_keystore` whenever
persistence is required; it fails closed if the target's durable backend was
not compiled. `platform_default_keystore_with_kind` is reserved for callers
that explicitly support an in-memory mode and inspect the returned
`BackendKind`.

`EncryptedFileKeyStore` uses a caller-custodied random 32-byte master key,
HKDF-SHA256, and XChaCha20-Poly1305. Keep the master key outside the ciphertext
file's backup and access-control boundary. A stable sidecar lock and atomic
same-directory replacement make whole-map updates safe across processes.

## Persistence and concurrency semantics

The backends are not semantically identical:

| Backend | Persistence | At-rest protection | Cross-process concurrency |
|---|---|---|---|
| `InMemoryKeyStore` | none — lost on process exit | none (process memory) | none (per-process map) |
| `EncryptedFileKeyStore` | survives reboot with caller-custodied master key | XChaCha20-Poly1305 authenticated encryption | stable lock file + atomic same-directory replacement |
| `MacOsKeychainKeyStore` | survives logout and reboot (login keychain) | Keychain, unlocked with the login session | Keychain serializes item ops; no SDK-level CAS |
| `LinuxSecretServiceKeyStore` | survives logout and reboot (default collection) | Secret Service daemon; the collection may lock on logout | D-Bus daemon serializes ops; no SDK-level CAS |
| `WindowsCredentialKeyStore` | survives logout and reboot (`CRED_PERSIST_LOCAL_MACHINE`) | DPAPI, scoped to the user profile | Win32 credential API serializes ops; no SDK-level CAS |

Every backend is last-writer-wins for `store` on the same id and provides no
compare-and-swap. The encrypted-file backend serializes whole-map updates;
OS-native backends rely on their platform service. Serialize semantic key
rotation at the application layer.

Licensed under Apache-2.0.
