# Changelog

All notable changes to the Arkret Rust SDK are recorded here. The workspace is
under active `0.3.x` development and has not published a stable release.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Wire-breaking, no compatibility shim

- Removed the device-level SAS verification surface. `arkret-crypto`'s
  `key_verification` module and its `key-verification` feature, the
  `KeyVerificationContent` wire type with its purpose / cancellation enums,
  the eight `ak.key.verification.*` kind constants, the
  `DeviceMessageContent::KeyVerification` branch and the eight typed
  `device_message_spec` markers are gone. `arkret-spec` retired the message
  family with `device-lifecycle.md` §10; device trust now comes from the
  closed verification checkpoint (§10.1) and secret sharing requires a
  current checkpoint bound to the exact device and key.
- Removed `ak.profile.matrix_compat.v1` from the generated profile surfaces.
  `ProfileId` and the baked requirement table now carry 89 profiles;
  `ak.profile.push_gateway.matrix_passthrough.v1` no longer depends on it.
- Removed the reducer-stamped `Event.actor_kind` wire field. Authoritative
  attribution now comes from the signed `actor_id`, optional `executed_by`, and
  immutable historical provenance; Actor Profile `actor_kind` remains display
  metadata only.
- `Event.refs` and `Event.causal_refs` are now omitted when empty and explicit
  empty arrays are rejected during decoding. `prev_refs` remains required and
  may be empty.
- Removed the Realm-configured ordinary Event revocation grace window and its stale-Seal error,
  and Seal-distance grace handling. Origin admission freezes its validated
  proof atomically; later revocation blocks new admissions without invalidating
  events already admitted.
- Renamed `ServiceRegistrationReceipt.receipt_id` to the spec-defined
  `registration_receipt_id` and changed it to `ServiceRegistrationReceiptId`;
  `AppletInstallPlan.plan_id` now uses `PlanId`.
- Replaced open strings with generated closed-registry types for service binding
  kinds and collaboration message tracks.

### Changed

- Raised the minimum supported Rust version from `1.96` to `1.97`, and pinned
  every CI job and the compile baseline to the same toolchain.
- `VerifiedDidBindingInput.{verified_at,refresh_after,expires_at}` and
  `CalendarOccurrence.{start_instant,end_instant}` now serialize through the
  canonical UTC-millisecond timestamp adapter instead of chrono's default
  RFC 3339 encoding, matching the rest of the wire surface.
- Repaired the registry-derived surface gate so it regenerates and checks the
  actual wire-base, policy, and schema outputs, including event kinds.
- Renamed the Rust enum variant `MediaIceCredentialType::Oauth` to
  `MediaIceCredentialType::OAuth`; its lowercase wire representation is
  unchanged.
- Expanded coverage policy from `crates/sdk` to the full workspace and enabled
  patch coverage reporting.
- Replaced the hand-maintained schema-coverage list with generated active-schema
  descriptors, generated the closed binding/track/authority registries and
  operation-to-error mappings, and made drift checks symmetric against the live
  spec registries.

### Security

- Removed the obsolete `RUSTSEC-2024-0384` and `RUSTSEC-2026-0124` exceptions
  after their affected packages left the resolved graph.
- Updated `crossbeam-epoch` to `0.9.20` to resolve `RUSTSEC-2026-0204`.

### Documentation

- Aligned the supported-version policy with the active `0.3.x` development
  line and clarified the status of historical local-freeze evidence.
