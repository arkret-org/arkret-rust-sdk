# Security Audit Checklist

This SDK audit checklist is intended for release review.

## Threat Model

- Attackers may control network transport, replay old sync responses, submit
  malformed events and attempt to correlate private identifiers.
- Attackers may compromise a device after historical encrypted events were
  received; recovery and backup strands must preserve forward-secret boundaries.
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
- Identifier constructors validate DID, Realm, Space, ActorProfile, Strand,
  Message, Morph, Relation, Event, Operation, Device, Blob and Cursor forms
  before use.

## Authentication And Identity

- Password login helpers hash with salted Argon2id; session issuance fails
  closed on non-active account states.
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

- Federation transactions require configured trust seals.
- Server version and capability negotiation must pass before using optional
  federation features.
- Sovereign deployments should restrict allowed domains explicitly.

## Release Gate

- `cargo test`
- Review warnings and public API changes.
- Review dependency updates.
- Re-run protocol conformance vectors.
- Review the coverage list below and confirm each non-external area still has
  live tests or conformance vectors.
- Validate the supported Cargo feature matrix. Cargo's feature graph plus the
  `compile_error!` guards in `crates/sdk/src/lib.rs` are the compile-time gate
  for the SDK's own feature combinations.

## Internal Review Coverage

This document is the SDK's internal pre-audit evidence. It covers canonical
signing/proof binding, MLS transcript persistence, encrypted storage contracts,
token/log redaction and unsafe feature combinations. This is not an external
audit attestation.

## Source Mapping

| Area | Source |
| --- | --- |
| Identifiers, canonical JSON and digests | `crates/identifiers/src/lib.rs`, `crates/canonical/src/canonical.rs`, `crates/wire/src/`, `crates/models-*/src/` |
| Auth and recovery | `crates/auth/src/`, `crates/identity/src/` |
| Capability decisions | `crates/policy/src/authz/`, `crates/state/src/resolver/` |
| Repo and crypto stores | `crates/state/src/state/store/`, `crates/models-crypto/src/mls_store_ports.rs` |
| E2EE and MLS | `crates/crypto/src/`, `crates/mls/src/`, `crates/crypto/src/device.rs` |
| Federation and service identity | `crates/signatures/src/federation.rs`, `crates/models-collaboration/src/federation/`, `crates/identity/src/service_identity.rs`, `crates/models-discovery/src/service_description.rs` |
| Log redaction and feature safety | `crates/crypto/src/lib.rs`, `crates/http-client/src/lib.rs`, `crates/server/src/lib.rs` |

## Agent Runtime + Recovery Surface (P5 / spec head 37ce729)

The following sections cover the surface introduced by commits 4d5a1af and
bf29056 (agent runtime, recovery policy/receipt, sidecar Circle boundary,
first-backup gate, DID format regex).

### Agent runtime auth (S-1 / S-2)

*Threat model.* A compromised agent key (S-1: signing key, S-2: session key)
must not let an attacker escalate beyond the controller's grant; key theft
must be containable to the bound `agent_id` and revocable without
revoking the controller. The agent runtime also exposes a quiesce surface
(`pause`/`resume`/`deactivate`) that a hostile caller could abuse to stage
DOS against the controller's automated workflows.

*Mitigations.* `ak.profile.agent_auth.v1` constrains every agent-authenticated
request to a signed envelope binding the agent's S-1 key, the calling
`agent_session_id` (S-2), and the controller DID; the verifier rejects any
envelope whose `agent_key_id` is not in the active rotation window from
`ak.self.agent.command.rotate_key`. `ak.self.agent.command.pause.v1` / `ak.self.agent.command.deactivate.v1` are gated on the
controller's session grant (`ak.profile.agent_delegation_policy.v1`), so a
stolen agent key cannot deactivate itself or extend its own scope. Durable
agent writes remain accountable through the ordinary signed Event envelope,
`agent_context`, and the controller-issued accountability grant.

### recovery_policy / recovery_receipt schemas

*Threat model.* Recovery is the highest-leverage operation in the protocol —
the holder of a valid recovery receipt can rebind a DID's controller set.
Risks include receipt forgery, replay across realms, premature revocation
acceptance, and confused-deputy attacks where a stale `recovery_policy`
references a body branch the verifier does not understand.

*Mitigations.* `ak.schema.recovery_policy.v1` pins the lifecycle and KDF
profile branch as canonical fields covered by the policy's signature;
verifiers reject `body` branches they cannot parse rather than silently
accepting them. `ak.schema.recovery_receipt.v1` binds the `policy_id`,
`recovery_session_id` and `frontier_ref` of the originating key state, so
receipts cannot be replayed against a rotated frontier. The
first-backup gate (below) ensures recovery cannot land before the controller
has staged at least one chain envelope.

### Native Sidecar scope boundary

*Threat model.* A Sidecar is a controller-owned private AI object. The risk is
that its events or private locators leak into the source Strand, or that a
caller fabricates a Sidecar identity or participation list.

*Mitigations.* `ak.profile.agent_sidecar.v1` exposes only the self-scoped
`ak.self.agent.sidecar.command.ensure.v1` aggregate and dedicated get/list reads.
The reducer derives the Sidecar singleton from the create Event and binds an
independent MLS group directly to the native Sidecar scope. Participants are
the controller plus ownership-derived Agents and cannot be edited through a
Sidecar membership surface. Source echoes are encrypted
controller-private projections, never source-Strand events. Closed SDK types
separate owned/effective access, view state, routed exchanges and explicit
user-facing responses, while shared publish rejects every private locator.

### First-backup gate

*Threat model.* Without a first-backup gate, a malicious party who steals an
unbacked-up device can complete a recovery strand that produces a valid
controller switch with no historical state to compare against — the attacker
becomes the canonical history.

*Mitigations.* The gate requires at least one
`ak.schema.key_backup.v1` envelope (with `series_seq == 0`) to be visible
on the home soland before any `recovery_policy` can accept a binding. SDK
callers see this as `Error::Protocol("first_backup_required")` from the
recovery client; the spec layer codifies it as the
`first_backup_required` failure mode on `ak.account.recovery.*` operations.
Operators MUST NOT disable this gate in production.

### DID format regex

*Threat model.* DID parsing has historically been an injection surface: a
permissive parser that accepts `did:webvh:z6mkexample:alice.example?evil=1` lets attackers
smuggle parameters into downstream HTTP requests, log injection sinks, or
ACL keys. The risk is silent acceptance of malformed input that later
collides with a legitimate DID.

*Mitigations.* The strict DID regex
(`^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$`, sealed, no query / fragment) is
applied at every entry point: `Did::new`, sync ingestion, capability
resolvers, and the federation transport. Method-specific extensions
(e.g. `did:key` log entries, `did:keri` log proofs) layer their own
syntactic checks on top of the base regex; none of them can broaden it.
The regex is checked by `identifiers::tests::did_rejects_malformed`
across every public input on the boundary.
