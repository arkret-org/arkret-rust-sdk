# Feature Matrix

> **Authoritative source.** The conformance-profile requirement surface is
> defined by the generated `cokret_core::generated::profile_requirements` table
> (derived from `cokret-spec` `conformance-profiles.json`). The profile tables
> in this document are a **human-readable mirror only** — when they disagree,
> the generated table wins. The `feature_matrix_profiles_subset_of_generated`
> test in `crates/core/tests/feature_matrix_doc.rs` fails if any profile ID
> named here is absent from the generated table, so the mirror cannot drift
> ahead of the code.

Cokret SDK uses additive Cargo features.

| Build | Feature flags | Intended use |
| --- | --- | --- |
| Model-only | `default-features = false` | Protocol IDs, wire models, canonical digests, stores and local state helpers without HTTP or OpenMLS dependencies. |
| Client | `--features client` | Reqwest-based HTTP client for the Cokret v1 service binding. |
| Server | `--features server` | Framework-independent server handler contracts, shared contract re-exports and endpoint fixture coverage. |
| Salvo OAPI | `--features salvo` | Server feature plus Salvo OAPI derives on Cokret DTO and identifier types. |
| Applet | `--features applet` | Convenience umbrella for Applet developers: `applet-runtime` + `client` + `server` + `salvo`. One flag turns on the applet wire surface (`AppletPackage`, `WireAppletRegistration`, install objects, bridge-error builder), the HTTP client, the `AppletHandler` contracts and the ready-made `applet_router` Salvo factory. |
| MLS | `--features mls` | OpenMLS-backed group creation, Welcome/Commit envelopes and payload encryption/decryption. |
| Default | `client, mls, full-surface, applet-runtime, device-runtime, sync-runtime, timeline-runtime` | Umbrella `cokret` crate application default for the active `0.3.x` development line: HTTP client, MLS crypto primitives and the high-level runtime/module surface. Leaf crates keep `default = []` unless their own `Cargo.toml` says otherwise. |
| All features | `--all-features` | Release and conformance validation build. |

## Support Levels

| Area | Level | Notes |
| --- | --- | --- |
| Protocol model support | Supported | IDs, operations, events, commits, cursor, canonical JSON and digest helpers are covered by unit and integration vectors. |
| Local helper support | Supported | In-memory stores, reducers, auth state machines, event handlers, timeline helpers and test transports are intended for SDK and app integration tests. |
| Production-ready support | Release-candidate | HTTP client/server contracts, shared DTO contracts, MLS-backed helpers and durable-store contracts are present, including SQLite/IndexedDB/CryptoStore conformance facades. Deployments must still provide real key custody, storage backends and service operations. |
| Experimental / facade support | Experimental | Browser HTTP, IndexedDB, WebCrypto, applet, bridge, sovereign deployment, FFI and extended profile helpers are API-shaping surfaces until real product/server interop hardens them. |

Production deployments should provide durable stores for local state and crypto state,
real signing key management, framework-specific HTTP routing, platform key
storage and service-level interoperability tests.

## Conformance Profile Coverage

This table mirrors `ck.profile.*.vN` IDs the SDK `0.3.x` development line implements. New
profiles introduced in P5 (spec head 37ce729) are listed first; the
remainder of the catalog is represented by the generated
`generated::profile_requirements` table.

| Profile ID | SDK 0.3.x | Notes |
| --- | --- | --- |
| `ck.profile.personal_agent_provisioning.v1` | ✓ implemented | Full `ck.gate.account.command.pair_agent_key` + `ck.agent.*` (provision / list / get / pause / resume / rotate-key / grant.attach / grant.detach / sidecar_thread.ensure / deactivate) wiring; example: `personal_agent_provision.rs`. |
| `ck.profile.agent_auth.v1` | ✓ implemented | S-1 signing-key + S-2 session-key binding via `agent_binding::{sign,verify}_ed25519_audit_binding`; controller-grant verification on every agent envelope. |
| `ck.profile.agent_delegation_policy.v1` | ✓ implemented | Delegation grants gated by `ck.profile.agent_delegation_policy.v1` via `authz::delegation`; controller can revoke without rotating the agent key. |
| `ck.profile.agent_sidecar_thread.v1` | ✓ implemented | `SidecarCircleId`-bounded sidecar threads with isolated audit logs and parent-Circle membership cross-check. |
