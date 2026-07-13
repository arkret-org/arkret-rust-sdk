# Security Review Packet: 1.0.0 Local Freeze

Date: 2026-05-25

Status: local security-review packet prepared. This is not an external audit
attestation; it is the evidence bundle a reviewer needs before the local
`1.0.0` freeze.

## Scope

- Workspace crates: `arkret-identifiers`, `arkret-core`, `arkret-ffi`,
  `arkret-http-client`, `arkret-signatures`,
  `arkret-crypto`, `arkret-contracts`, `arkret-server`, and
  `arkret`.
- Wire-critical surfaces: canonical JSON, Event Envelope signatures,
  capability grants, profile claims, federation signatures, MLS helpers,
  blind-payload sanitizer, and session-grant outbox.
- Runtime surfaces: HTTP client URL validation, token redaction, DPoP/session
  grant helpers, local crypto-store contracts, and server DTOs.

## Local Evidence

- Internal checklist: `docs/security-audit.md`.
- Feature safety gate: `arkret::current_feature_safety_report().validate()`.
- Dependency gates:
  - `cargo deny check --config .deny.toml`
  - `cargo audit --deny warnings --ignore RUSTSEC-2024-0384 --ignore RUSTSEC-2026-0124`
- Public API gate:
  - `cargo semver-checks check-release --workspace --baseline-rev HEAD~1` is
    blocking in local CI.
- Interop gate:
  - Final cotest release-gate evidence is tracked separately in
    `docs/release-evidence-1.0.0.md` once the cross-project gate is green.

## Review Questions

- Canonicalization: verify signed payload bytes are deterministic and reject
  JSON floats.
- Replay: verify Event Envelope, federation, and session-grant replay handling
  fail closed.
- Key lifecycle: verify cross-signing CAS, MLS epoch rollback checks, backup
  envelope digest checks, and keypackage state transitions.
- Privacy: verify blind-payload sanitizer rejects identity, realm, device,
  token, and plaintext message fields recursively.
- Logging: verify push keys, tokens, proofs, bearer material, and session grants
  are redacted before debug/log output.
- Storage: verify SDK storage traits do not claim platform key protection and
  force host applications to provide durable encrypted stores.

## Open External Dependency

An outside reviewer still needs to sign off on the packet before this can be
called an external security audit. The local 1.0 readiness work records the
packet and hardens the gates; it does not publish an audit claim.
