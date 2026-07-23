# arkret-auth

Arkret v1 authentication behavior: sessions, session grants, claims,
passwords, MFA, and DID / OIDC / passkey proof verification.

Depends only on the wire / model / signature data crates; the umbrella
`arkret` crate re-exports this surface under `arkret::auth::*`. The
transport-bound one-shot `login_did_proof` flow is owned by
`arkret-http-client`.
