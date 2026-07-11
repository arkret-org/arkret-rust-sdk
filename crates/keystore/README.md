# arkret-keystore

Platform-native `KeyStore` backends for the Arkret v1 SDK.

The pure storage contract — the `KeyStore` trait, `KeyStoreError`, and the
dependency-free `InMemoryKeyStore` — lives in `arkret-core`. This crate adds
the OS-native backends that carry platform IO and native OS dependencies,
kept out of `arkret-core` so the core wire/model crate stays light:

| Backend | Feature | `target_os` |
|---|---|---|
| `InMemoryKeyStore` (re-exported from `arkret-core`) | always available | any |
| `MacOsKeychainKeyStore` | `keystore-macos` | `macos` |
| `LinuxSecretServiceKeyStore` | `keystore-linux` | `linux` |
| `WindowsCredentialKeyStore` | `keystore-windows` | `windows` |

Each platform type still compiles on every target; off-target constructors
return `KeyStoreError::Unsupported`. Use `durable_platform_keystore` whenever
persistence is required; it fails closed if the target's durable backend was
not compiled. `platform_default_keystore_with_kind` is reserved for callers
that explicitly support an in-memory mode and inspect the returned
`BackendKind`.

## Persistence and concurrency semantics

The backends are not semantically identical:

| Backend | Persistence | At-rest protection | Cross-process concurrency |
|---|---|---|---|
| `InMemoryKeyStore` | none — lost on process exit | none (process memory) | none (per-process map) |
| `MacOsKeychainKeyStore` | survives logout and reboot (login keychain) | Keychain, unlocked with the login session | Keychain serializes item ops; no SDK-level CAS |
| `LinuxSecretServiceKeyStore` | survives logout and reboot (default collection) | Secret Service daemon; the collection may lock on logout | D-Bus daemon serializes ops; no SDK-level CAS |
| `WindowsCredentialKeyStore` | survives logout and reboot (`CRED_PERSIST_LOCAL_MACHINE`) | DPAPI, scoped to the user profile | Win32 credential API serializes ops; no SDK-level CAS |

Every backend is last-writer-wins for `store` on the same id; there is no
compare-and-swap or cross-process lock, so serialize key rotation at the
application layer.

Licensed under Apache-2.0.
