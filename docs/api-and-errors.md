# API And Error Handling

The SDK exposes protocol-first modules. Wire data structures live in `model`,
deterministic hashing in `canonical`, local client state in `base`, sync helpers
in `sync` and `sync_client`, and higher-level feature managers in modules such
as `membership`, `devices`, `receipts`, `notifications`, `content`, `media`,
`profile`, `settings`, `search`, `discovery`, `e2ee`, `auth`, `identity`,
`federation`, `push`, `typing`, `webrtc` and `store`.

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

Server bindings can wrap any `RoutedEndpointService` with
`ServerMiddlewareStack`. The default stack is fail-closed for private
operations: it requires Bearer authentication, checks operation scopes, requires
`Idempotency-Key` on POST/PUT endpoints, replays matching idempotent responses,
rejects conflicting retries and applies per-principal operation rate limits.

The HTTP client preserves Contrix error envelopes and retry metadata. Standard
retry mode covers transient statuses, applies bounded exponential backoff, and
uses `Retry-After` when the server supplies it.
