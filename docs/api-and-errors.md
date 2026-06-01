# API And Error Handling

The SDK exposes protocol-first modules. Wire data structures live in `model`,
deterministic hashing in `canonical`, local client state in `base`, sync helpers
in `sync` and `sync_client`, and higher-level feature managers in modules such
as `membership`, `devices`, `receipts`, `notifications`, `content`, `media`,
`profile`, `settings`, `search`, `discovery`, `e2ee`, `auth`, `identity`,
`federation`, `push`, `typing`, `webrtc` and `store`.

Shared product and service DTOs live in `contrix-contracts` and are re-exported
from the umbrella crate as `contrix::api`, with narrower facades for
`client_api`, `identity_api`, `federation_api` and `push_gateway_api`.

Most fallible APIs return `contrix::Result<T>`, whose error type is
`contrix::Error`.

Common error categories:

- `InvalidId`: identifier validation failed.
- `IdempotencyConflict`: a Repo object ID was reused with different bytes.
- `Protocol`: local protocol contract failure.
- `Api`: remote Contrix API error envelope.
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

Device binding scopes must use `urn:contrix:client:device:{id}`. Non-Contrix
scope prefixes are rejected by `device_id_from_scope_token(...)`.

The identity surface exposes `StaridRegistryAdapter` and
`StaridRegistryRecord` as the registry-backed DID boundary. The in-memory
adapter is for tests and offline development only; production adapters still
need registry-network fetching, key-log receipt validation, stale-head handling
and bounded response parsing.

Server bindings should preserve the standard Contrix error envelope and retry
metadata while implementing authentication, idempotency and rate limiting in
their host framework stack.

The HTTP client preserves Contrix error envelopes and retry metadata. Standard
retry mode covers transient statuses, applies bounded exponential backoff, and
uses `Retry-After` when the server supplies it.
