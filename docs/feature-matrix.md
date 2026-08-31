# Feature Matrix

> **Authoritative source.** The conformance-profile requirement surface is
> defined by the generated `arkret_wire::generated::profile_requirements` table
> (derived from `arkret-spec` `conformance-profiles.json`). The profile tables
> in this document are a **human-readable mirror only** — when they disagree,
> the generated table wins. The `feature_matrix_profiles_subset_of_generated`
> test in `crates/schema/tests/feature_matrix_doc.rs` fails if any profile ID
> named here is absent from the generated table, so the mirror cannot drift
> ahead of the code.

Arkret SDK uses additive Cargo features.

| Build | Feature flags | Intended use |
| --- | --- | --- |
| Default / type surface | none, or `default-features = false` | Protocol IDs, wire models, canonical digests and shared DTO contracts, including Applet contracts, without `openmls`, `reqwest`, `tokio` or server framework integrations. |
| Client | `--features client` | Reqwest/tokio-based HTTP client for the Arkret v1 service binding. |
| Server | `--features server` | Framework-independent server handler contracts, shared contract re-exports and endpoint fixture coverage. |
| Applet contracts | none | Applet wire models are owned by `arkret-models-integration`; bridge-error Event drafting is owned by `arkret-event-draft`. Enable `client` and/or `server` independently for transport and handler support. |
| MLS | `--features mls` | OpenMLS-backed group creation, Welcome/Commit envelopes and payload encryption/decryption. |
| All features | `--all-features` | Release and conformance validation build. |

Runtime-neutral crypto capabilities are selected on their owner crate:
`arkret-crypto` exposes the granular `backup`, `blob-aead`, `key-verification`,
`secret-share` and `sframe` features. Device, sync and timeline orchestration
belongs to application/runtime crates rather than composite umbrella features.

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

This table mirrors `ak.profile.*.vN` IDs the SDK `0.3.x` development line implements. New
profiles introduced in P5 (spec head 37ce729) are listed first; the
remainder of the catalog is represented by the generated
`arkret_wire::generated::profile_requirements` table.

| Profile ID | SDK 0.3.x | Notes |
| --- | --- | --- |
| `ak.profile.agent_provisioning.v1` | ✓ implemented | Typed HTTP operations live in `arkret-http-client`; agent provisioning drafts live in `arkret-bootstrap`; lifecycle Event drafts live in `arkret-event-draft`; runtime key proofs live in `arkret-signatures`. |
| `ak.profile.agent_auth.v1` | ✓ implemented | S-1 signing-key + S-2 session-key binding and controller-grant verification on every agent Event envelope. |
| `ak.profile.agent_delegation_policy.v1` | ✓ implemented | Agent authority grants are gated by `ak.profile.agent_delegation_policy.v1` via `arkret_policy::authz::authority`; controller can revoke without rotating the agent key. |
| `ak.profile.agent_sidecar.v1` | ✓ implemented | First-class event-derived `SidecarId`, native Sidecar scope, ownership-derived participants, ensure/get/list DTOs, hosted view state and per-exchange private echo projection. |
