# API And Error Handling

The SDK exposes protocol-first modules. Wire data structures live in `model`,
deterministic hashing in `canonical`, local client state in `base`, sync helpers
in `sync` and `sync_client`, and higher-level feature managers in modules such
as `membership`, `devices`, `receipts`, `media`,
`profile`, `settings`, `search`, `discovery`, `e2ee`, `auth`, `identity`,
`federation`, `push`, `typing`, `webrtc` and `store`.

Shared product and service DTOs live in `arkret-core` and are re-exported
from the umbrella crate as `arkret::api`, with narrower facades for
`identity_api`, `federation_api` and `push_gateway_api`. Protocol DTOs are not
duplicated in a parallel SDK-local client API module.

Most fallible APIs return `arkret::Result<T>`, whose error type is
`arkret::Error`.

Common error categories:

- `InvalidId`: identifier validation failed.
- `IdempotencyConflict`: a Repo object ID was reused with different bytes.
- `Protocol`: local protocol contract failure.
- `Api`: remote Arkret API error envelope.
- `Http` and `Url`: client feature transport failures.
- `Mls`: MLS feature failures.

Practical rule: validate identifiers at boundaries, use canonical digest helpers
before signing, and preserve `Error::Api` details when surfacing server failures
to applications.

## Cross-Service Contracts

The auth surface exposes `SessionGrantPayload`, `SessionGrantRecord` and
`PrincipalSessionGrantNotification` so coauth can issue auditable session grants
and soland can consume grant-created / grant-revoked notifications without
copying private key material into persistence. `SessionGrant` redacts the
serialized grant token in `Debug`; durable stores should persist `grant_hash`.

Device binding scopes must use `urn:arkret:client:device:{id}`. Non-Arkret
scope prefixes are rejected by `device_id_from_scope_token(...)`.

The identity surface exposes `StaridRegistryAdapter` and
`StaridRegistryRecord` as the registry-backed DID boundary. The in-memory
adapter is for tests and offline development only; production adapters still
need registry-network fetching, key-log receipt validation, stale-head handling
and bounded response parsing.

Server bindings should preserve the standard Arkret error envelope and retry
metadata while implementing authentication, idempotency and rate limiting in
their host framework stack.

The HTTP client preserves Arkret error envelopes and retry metadata. Standard
retry mode covers transient statuses, applies bounded exponential backoff, and
uses `Retry-After` when the server supplies it.
