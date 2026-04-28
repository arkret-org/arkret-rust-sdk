# Feature Matrix

Contrix SDK uses additive Cargo features.

| Build | Feature flags | Intended use |
| --- | --- | --- |
| Model-only | `default-features = false` | Protocol IDs, wire models, canonical digests, stores and local state helpers without HTTP or OpenMLS dependencies. |
| Client | `--features client` | Reqwest-based HTTP client for the Contrix v1 service binding. |
| Server | `--features server` | Framework-independent endpoint registry, handler adapter enums and OpenAPI export helper. |
| MLS | `--features mls` | OpenMLS-backed group creation, Welcome/Commit envelopes and payload encryption/decryption. |
| Default | `client,mls` | Application SDK default: HTTP client plus MLS crypto primitives. |
| All features | `--all-features` | Release and conformance validation build. |

Production deployments should provide durable stores for repo and crypto state,
real signing key management, framework-specific HTTP routing, platform key
storage and service-level interoperability tests.
