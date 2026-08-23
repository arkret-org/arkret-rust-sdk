# API And Error Handling

The SDK exposes protocol-first modules. Wire data structures live in `model`,
deterministic hashing in `canonical`, local client state in `base`, sync helpers
in `sync` and `sync_client`, and higher-level feature managers in modules such
as `membership`, `devices`, `receipts`, `media`,
`profile`, `settings`, `search`, `discovery`, `e2ee`, `auth`, `identity`,
`federation`, `push`, `typing`, `webrtc` and `store`.

Protocol DTOs live in the semantic model leaves and are re-exported from the
`arkret` umbrella as a curated root surface. The namespaced `arkret::models`
aggregate is provided for discovery and documentation; protocol DTOs are not
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

The identity surface is method-neutral: `DidResolver::resolve_did` yields a
`ResolvedDid` (`document` plus `method_evidence`), and no DID method gets a
bespoke public adapter. `did-usage-and-verification.md` §4 splits that surface
in two, and the split is enforced by the signatures rather than by convention:

- Ordinary per-object verification uses `verify_jws_with_binding`,
  `verify_jws_with_document` or `verify_event_proof_with_binding`. None of them
  takes a resolver parameter, so an ordinary call site cannot express a network
  resolution at all.
- The authority path uses `resolve_and_verify_binding`, whose
  `BindingResolveRequest` requires a trust domain, purpose, policy digest and
  freshness profile. Accepted results are held by a `VerifiedDidBindingStore`
  (`InMemoryVerifiedDidBindingStore` is the reference implementation; durable
  ones re-validate every row through `AcceptedDidBinding`) and revoked through
  the conjunctive `BindingInvalidation` selector.

Per-signature verification and per-signature resolution are therefore two
independent counters; see the `identity::verifier` module docs.

Server bindings should preserve the standard Arkret error envelope and retry
metadata while implementing authentication, idempotency and rate limiting in
their host framework stack.

The HTTP client preserves Arkret error envelopes and retry metadata. Standard
retry mode covers transient statuses, applies bounded exponential backoff, and
uses `Retry-After` when the server supplies it.
