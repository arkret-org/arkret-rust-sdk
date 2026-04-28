# Security Audit Checklist

This SDK audit checklist is intended for release review.

## Canonical Data

- All signed protocol objects must use `canonical` helpers.
- Floating point JSON values are rejected for canonical digests.
- Identifier constructors validate DID, Space, Entity, Relation, Event, Commit,
  Operation, Device, Blob and Cursor forms before use.

## Authentication And Identity

- Password/OIDC/passkey/MFA helpers are state-machine helpers; deployments must
  connect them to production verifiers.
- DID documents must contain verification methods.
- Handle claims require proof validation before attestation.

## Encryption

- MLS helpers keep cryptographic group state client-side.
- E2EE manager validates sender membership, epoch, integrity digest and replay.
- Push payloads for encrypted events are redacted before delivery.
- Local XOR/SHA helpers are deterministic SDK test envelopes, not a replacement
  for platform cryptography in production storage.

## Federation

- Federation transactions require configured trust anchors.
- Server version and capability negotiation must pass before using optional
  federation features.
- Sovereign deployments should restrict allowed domains explicitly.

## Release Gate

- `cargo test`
- Review warnings and public API changes.
- Review dependency updates.
- Re-run protocol conformance vectors.
