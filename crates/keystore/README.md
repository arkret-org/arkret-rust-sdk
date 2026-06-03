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
return `KeyStoreError::Unsupported`. Use `platform_default_keystore` to get
the best available backend for the current target, falling back to
`InMemoryKeyStore`.

Licensed under Apache-2.0.
