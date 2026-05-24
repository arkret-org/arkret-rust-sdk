# Security Audit Checklist

This SDK audit checklist is intended for release review.

## Threat Model

- Attackers may control network transport, replay old sync responses, submit
  malformed events and attempt to correlate private identifiers.
- Attackers may compromise a device after historical encrypted events were
  received; recovery and backup flows must preserve forward-secret boundaries.
- Servers are not trusted to forge actor intent. Signed protocol objects,
  capability checks and canonical digests are the authority boundary.
- Local storage may be copied while the application is stopped; production
  deployments must bind encrypted stores to platform key protection.
- SDK store facades model SQLite, IndexedDB and encrypted crypto-store
  semantics for conformance; production deployments still need real platform
  storage engines and key custody.

## Canonical Data

- All signed protocol objects must use `canonical` helpers.
- Floating point JSON values are rejected for canonical digests.
- Identifier constructors validate DID, Realm, Space, ActorProfile, Flow,
  Message, Morph, Relation, Event, Operation, Device, Blob and Cursor forms
  before use.

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

## Key Lifecycle

- Device keys are registered per device and should be revoked before future
  encrypted writes are accepted from that device.
- MLS KeyPackages, Welcomes, Commits and epoch secrets must be stored in a
  durable crypto store before a client acknowledges sync.
- Backup metadata must bind sender identity, key version and creation time.
- Crypto-store backups should use `CryptoStoreBackupEnvelope` and verify the
  payload digest before import.
- Group state imports must reject epoch rollback for an existing group.
- Key rotation should not change a stable DID unless the DID method requires a
  method-specific migration.

## MLS Transcript And State Persistence

- Commit and Welcome records must survive process restart before local state
  advances to a new epoch.
- Clients that miss a Welcome should retain undecryptable timeline events and
  retry once the recovery path supplies the missing epoch state.
- Epoch mismatch, replay, wrong sender and stale membership checks should fail
  closed and keep raw encrypted events for later diagnosis.

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
- Review `security_review_checklist()` and confirm all non-external areas are
  `tested`.
- Run `current_feature_safety_report().validate()` for the published feature
  set.

## Internal Review Coverage

The SDK publishes `security_review_checklist()` for internal pre-audit evidence.
It covers canonical signing/proof binding, MLS transcript persistence, encrypted
storage contracts, token/log redaction and unsafe feature combinations. This is
not an external audit attestation; the checklist deliberately keeps the external
audit item as `external_audit_required`.

## Source Mapping

| Area | Source |
| --- | --- |
| Identifiers, canonical JSON and digests | `crates/identifiers/src/lib.rs`, `crates/core/src/canonical.rs`, `model.rs` |
| Auth and recovery | `crates/sdk/src/auth.rs`, `identity.rs` |
| Capability decisions | `crates/sdk/src/authz.rs`, `resolver.rs` |
| Repo and crypto stores | `crates/sdk/src/store.rs`, `crypto_store.rs` |
| E2EE and MLS | `crates/sdk/src/e2ee.rs`, `mls.rs`, `devices.rs` |
| Federation and service identity | `crates/sdk/src/federation.rs`, `crates/core/src/service.rs` |
| Log redaction and feature safety | `crates/sdk/src/crypto.rs`, `crates/http-client/src/lib.rs`, `crates/server/src/lib.rs` |
