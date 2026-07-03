# cokret-keystore

Platform-native `KeyStore` backends for the Cokret v1 SDK.

The pure storage contract — the `KeyStore` trait, `KeyStoreError`, and the
dependency-free `InMemoryKeyStore` — lives in `cokret-core`. This crate adds
the OS-native backends that carry platform IO and native OS dependencies,
kept out of `cokret-core` so the core wire/model crate stays light:

| Backend | Feature | `target_os` |
|---|---|---|
| `InMemoryKeyStore` (re-exported from `cokret-core`) | always available | any |
| `MacOsKeychainKeyStore` | `keystore-macos` | `macos` |
| `LinuxSecretServiceKeyStore` | `keystore-linux` | `linux` |
| `WindowsCredentialKeyStore` | `keystore-windows` | `windows` |

Each platform type still compiles on every target; off-target constructors
return `KeyStoreError::Unsupported`. Use `platform_default_keystore_with_kind`
to get the best available backend for the current target together with the
resolved `BackendKind` — reject `BackendKind::InMemory` whenever durable
storage is required. The plain `platform_default_keystore` convenience
variant is deprecated because it silently falls back to the non-durable
in-memory store.

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
