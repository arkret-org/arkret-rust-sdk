# Changelog

All notable changes to the Arkret Rust SDK are recorded here. The workspace is
under active `0.3.x` development and has not published a stable release.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Wire-breaking, no compatibility shim

- None recorded in the current unreleased line.

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

### Security

- Removed the obsolete `RUSTSEC-2024-0384` and `RUSTSEC-2026-0124` exceptions
  after their affected packages left the resolved graph.
- Updated `crossbeam-epoch` to `0.9.20` to resolve `RUSTSEC-2026-0204`.

### Documentation

- Aligned the supported-version policy with the active `0.3.x` development
  line and clarified the status of historical local-freeze evidence.
