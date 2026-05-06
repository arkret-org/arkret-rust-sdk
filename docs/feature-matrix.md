# Feature Matrix

Contrix SDK uses additive Cargo features.

| Build | Feature flags | Intended use |
| --- | --- | --- |
| Model-only | `default-features = false` | Protocol IDs, wire models, canonical digests, stores and local state helpers without HTTP or OpenMLS dependencies. |
| Client | `--features client` | Reqwest-based HTTP client for the Contrix v1 service binding. |
| Server | `--features server` | Framework-independent endpoint registry, handler adapter enums and OpenAPI export helper. |
| Salvo server | `--features salvo` | Server feature plus Salvo router, JSON response wrapper and Salvo OAPI schema component helpers. |
| MLS | `--features mls` | OpenMLS-backed group creation, Welcome/Commit envelopes and payload encryption/decryption. |
| Default | `client,mls` | Application SDK default: HTTP client plus MLS crypto primitives. |
| All features | `--all-features` | Release and conformance validation build. |

## Support Levels

| Area | Level | Notes |
| --- | --- | --- |
| Protocol model support | Supported | IDs, operations, events, commits, cursor, canonical JSON and digest helpers are covered by unit and integration vectors. |
| Local helper support | Supported | In-memory stores, reducers, auth state machines, event handlers, timeline helpers and test transports are intended for SDK and app integration tests. |
| Production-ready support | Release-candidate | HTTP client/server contracts, MLS-backed helpers and durable-store contracts are present, including SQLite/IndexedDB/CryptoStore conformance facades. Deployments must still provide real key custody, storage backends and service operations. |
| Experimental / facade support | Experimental | Browser HTTP, IndexedDB, WebCrypto, appservice, bridge, sovereign deployment, FFI and extended profile helpers are API-shaping surfaces until real product/server interop hardens them. `ffi_api_freeze_review()` records the mobile surface as reviewed but unfrozen. |

Production deployments should provide durable stores for repo and crypto state,
real signing key management, framework-specific HTTP routing, platform key
storage and service-level interoperability tests.
