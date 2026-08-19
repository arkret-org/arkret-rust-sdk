# Authentication Strands

`auth::AuthManager` models local authentication and session state:

- username/password registration and login with salted Argon2id password
  hashing (or an application-supplied password hash)
- session creation with concurrent session limiting
- fail-closed account state checks before issuing sessions

`identity::IdentityManager` models identity state:

- DID document storage and resolution
- DID document validation
- verification key rotation
- DID migration records
- handle binding, claim verification and attestations

## Session Grant Boundaries

`SessionGrantPayload` is the canonical payload shared by identity providers and
Principal Servers. The SDK provides adapter traits for issuing and verifying the
JWS string, but production key custody and cryptographic signing remain
application-owned.

`PrincipalSessionGrantNotification` is a freshness-bounded local projection
adapter, not a second lifecycle authority. The Account Authority issuer ledger
remains authoritative for active, revoked, superseded, and expiry decisions.
The notification is intentionally an idempotent request
shape. Services that fan out grant creation or revocation should back it with a
durable outbox and retry policy in the service repository, not in the SDK.
