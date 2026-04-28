# Authentication Flows

`auth::AuthManager` models local authentication and session state:

- username/password login with hashed password checks
- MFA challenge issue and verification
- OIDC/OAuth2 authorization URL construction and session completion after
  upstream verification
- passkey challenge issue and verification hook
- session creation, refresh, revocation and concurrent session limiting

`identity::IdentityManager` models identity state:

- DID document storage and resolution
- DID document validation
- verification key rotation
- DID migration records
- handle binding, claim verification and attestations

Production deployments should replace local test verifiers with provider-backed
password hashing, OIDC token validation, WebAuthn verification and DID proof
verification.
