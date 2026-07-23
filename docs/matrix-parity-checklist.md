# Matrix / Ruma Maturity Benchmark

This repository is not expected to clone Matrix semantics or carry Matrix
compatibility fields. The benchmark is client-grade maturity: Arkret should
cover comparable capability classes while keeping Arkret wire shapes native.

## Ruma-Level Protocol Primitives

- Identifier validation: Arkret now enforces fixed-width HLC and strict cursor IDs where the spec requires it.
- Canonical serialization: event, commit, encrypted payload, and cursor paths use canonical JSON hashing / encoding.
- Client sync wire shape: native `spaces` only.
- State resolution: reducer ordering includes causal depth, HLC, actor, actor sequence, and event ID.

## matrix-rust-sdk-Level Client Behaviors

- Timeline: Arkret has local timeline pagination plus reducer-backed message create / revise / redact.
- Space list: Arkret account subscribe tracks visible spaces and subscription windows.
- Event cache: reducer now maintains processed events, causal frontier, redactions, messages, reactions, and generic resolved state.
- Encryption: MLS and envelope helpers exist; cross-device crypto store has typed three-tier cross-signing (see [Device Key Material & Cross-Signing](#device-key-material--cross-signing) below).
- Device verification: device metadata, SAS/QR verification, typed cross-signing publish/reset/trust-chain, and to-device queues all exist; SAS/QR parity covers the Matrix state machine and adds a `cross_signing_reset` cancel code that has no Matrix analogue.
- Account data: account-private data manager and sync account-data deltas exist.
- Push / notifications / receipts / typing / presence: dedicated managers exist and have unit coverage.

## Device Key Material & Cross-Signing

The spec-side comparison is in [`migrating-from-matrix.md` §4.5](../../arkret-spec/spec/v1/zh/guides/migrating-from-matrix.md); this section tracks what the **SDK in this repo** ships against that spec.

### Identity keys per device

| Matrix | Arkret SDK | Status |
| --- | --- | --- |
| Ed25519 fingerprint key | [`DeviceKeyBundle.signing_key`](../crates/crypto/src/lib.rs) | Implemented |
| Curve25519 identity key | [`DeviceKeyBundle.identity_key`](../crates/crypto/src/lib.rs) | Implemented |
| One-time keys (Curve25519) | [`KeysUploadRequestBody.one_time_keys`](../crates/models-crypto/src/keys.rs) | Wire shape implemented; consumed by Olm-style bootstraps where applicable. MLS bootstrapping uses MLS KeyPackages instead — see below. |
| Fallback key | `KeysUploadRequestBody.fallback_keys` | Wire shape implemented; SHOULD rotate after first use (spec §8). |
| Device verify_key on the device record | [`Device.device_public_key`](../crates/sdk/src/devices/mod.rs) | Implemented in v0.7 (was missing in earlier revisions). |

### Three-tier cross-signing (spec §5)

The Arkret SDK ships the full three-key hierarchy as typed records, not as a single string:

| Tier | SDK type | Notes |
| --- | --- | --- |
| `principal_signing_key` (PSK) | [`CrossSigningKeyRecord` + `CrossSigningPublishContent.principal_signing_key`](../crates/crypto/src/lib.rs) | DID-method-rooted; rotation MUST enter the DID key log. |
| `self_signing_key` (SSK) | [`SignedCrossSigningKey`](../crates/crypto/src/lib.rs) under `self_signing_key`, bound to PSK via [`CrossSigningBinding`](../crates/crypto/src/lib.rs) | SSK is the only signer on per-device trust bindings; canonical bytes are `ak-cross-signing-bind-v1\n` + canonical JSON. |
| `user_signing_key` (USK) | Same envelope as SSK, distinct `public_key` | Signs other principals' identity keys; manual trust only — does NOT promote the other principal's device set. |
| Wire envelope: `ak.cross_signing.publish.v1` | [`CrossSigningPublishContent`](../crates/crypto/src/lib.rs) + [`DeviceManager::record_cross_signing_publish`](../crates/sdk/src/devices/manager.rs) | `generation` is monotonic; stale publishes are rejected; advancing the generation drops every accepted device binding to `NeedsReverification`. |
| Wire envelope: `ak.cross_signing.reset.v1` | [`CrossSigningResetPayload` + `CrossSigningResetProof`](../crates/models-identity/src/cross_signing.rs) + [`DeviceManager::record_cross_signing_reset`](../crates/sdk/src/devices/manager.rs) | Requires `principal_signing` / `recovery_unlock` / `device_quorum` / `trusted_recovery_service` proof; cancels in-flight SAS / QR transactions for the principal. |

### Per-device trust binding (spec §5.2)

`ak.device.authorize.content.cross_signing_binding` is a typed
[`DeviceTrustBinding`](../crates/crypto/src/lib.rs) on the SDK side, with `ssk_generation` so the verifier can detect stale bindings without re-fetching the publish stream:

- [`DeviceTrustBinding::canonical_input`](../crates/crypto/src/lib.rs) returns the spec-canonical `ak-device-trust-bind-v1\n + canonical_json({principal_id, device_id, device_public_key, ssk_generation})` bytes.
- [`DeviceManager::evaluate_trust_chain`](../crates/sdk/src/devices/manager.rs) implements spec §5.2.1 step-by-step and returns one of `CrossSigned` / `NeedsReverification` / `AwaitingPublish` / `Unverified` / `Invalid` so callers can render the right UI without re-implementing the algorithm.
- [`DeviceManager::propagate_trust`](../crates/sdk/src/devices/manager.rs) now requires the TARGET device to already carry a binding under the current generation — sibling trust isn't transitive in the protocol, unlike Matrix's "if any of my devices verified you, all do" shortcut.

### `NeedsReverification` state (spec §14.2)

Both `crypto::DeviceTrustState` and `core::models::api::DeviceVerificationState` now have a `NeedsReverification` variant. After a reset, every accepted device drops to this state and its binding is cleared. UI / policy MUST treat it as "no longer cross-signed". This is the SDK-side enforcement of spec §14.2 steps 1–3.

### Inception authorization

Device authorization has no bootstrap self-authorization escape hatch. A device is admitted only by a current cross-signing binding or by the enrollment authority designated in the principal DID document; unbound first devices remain `Unverified`.

### Cancel code registry

[`ak.key.verification.cancel`](../crates/sdk/src/devices/mod.rs) cancel-code set is aligned with spec §10.6 + §14.3, including the new `cross_signing_reset` code emitted when [`DeviceManager::record_cross_signing_reset`](../crates/sdk/src/devices/manager.rs) trips an in-flight transaction.

### What's still spec-only, not yet in SDK

- **PSK-signature verification glue**: `evaluate_trust_chain` takes a `verify_signature` closure so the SDK doesn't pull a DID-method resolver into `arkret-crypto`. Production adapters need to wire that closure to the same Ed25519 / EdDSA verifier used by [`arkret-signatures::verify_ed25519_move_signature`](../crates/signatures/src/signer.rs) plus the DID key-log resolver. The SDK ships the state machine; it does not ship a one-call "set up cross-signing end-to-end with my DID document" helper.
- **`ak.device.authorize` payload schema**: the SDK's `ak.device.authorize` event still uses the JSON `Value` payload shape; a typed `ak.schema.device_authorize.v1` envelope mirroring `CrossSigningPublishContent` is the next layer.
- **MLS leaf re-key after reset**: spec §14.2 step 3 says senders SHOULD issue an Empty Commit after a reset so the new SSK generation is covered by transcript hashes. The SDK exposes the MLS commit primitives but doesn't auto-trigger this; downstream apps (inkson / soland) wire it.

## Matrix concepts intentionally NOT mirrored

These come straight from `migrating-from-matrix.md` §4.5.7–§4.5.9; the SDK does not implement them under their Matrix names:

- **Single "master key"**: replaced by DID-method-rooted PSK (the master signature is the DID-method history entry, not a homeserver-stored key).
- **`m.cross_signing.master`/`self_signing`/`user_signing` keys-API records**: replaced by the `ak.cross_signing.publish.v1` event envelope on the principal control stream.
- **"Cross-signing trust propagates through cross-signed devices automatically"**: explicitly rejected (see [`DeviceManager::propagate_trust`](../crates/sdk/src/devices/manager.rs)). Every device needs its own SSK signature.
- **`m.cross_signing.upgrade` reset event without proof material**: replaced by `ak.cross_signing.reset.v1` with four enumerated proof kinds.

## Remaining Non-Goals / Future Work

- Matrix room-version auth rules are not copied; Arkret uses capability and policy reducer state.
- Matrix event types are not first-class Arkret types.
- Durable production adapters should implement the event-cache, snapshot and crypto-store boundaries without weakening the current verification behavior.
- A production wire test that round-trips a real Ed25519 PSK → SSK → device-binding chain (the SDK has the canonical-bytes helpers but no end-to-end test against `arkret-signatures` yet).
