# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the SDK is on the `0.1.x` line, breaking changes within a minor are
permitted; once `1.0` ships, breaking changes will require a major bump.

## [Unreleased]

### Added

- `ClientBuilder` transport configuration: `connect_timeout`,
  `pool_idle_timeout`, `pool_max_idle_per_host`, `tcp_nodelay`,
  `tcp_keepalive`, `http2_keep_alive_interval`, `http2_keep_alive_timeout`,
  `http2_keep_alive_while_idle`, `proxy`, `no_proxy`, `redirect`, and
  `gzip`. See `crates/client/src/lib.rs`.
- `RedirectPolicy` enum (`None` / `Limited(usize)`) used by
  `ClientBuilder::redirect`.
- `SECURITY.md` describing supported versions, the responsible disclosure
  process and the project's response timeline.
- CI hardening: `cargo audit`, `cargo deny check`, `cargo doc --all-features`
  with `-D rustdoc::broken_intra_doc_links`, and a separate MSRV job.
- `RELEASING.md` enumerates the full 22-crate publish set in topological
  order and is now in lockstep with `.github/workflows/release-crates.yml`.

### Changed

- `ClientBuilder::build` now rejects calls that combine a pre-built
  `http_client(...)` with any transport-shaping option, instead of silently
  ignoring the option.
- `.github/workflows/release-crates.yml` publishes every workspace crate in
  dependency order, not just the umbrella `contrix` crate.
- `.github/workflows/ci.yml` corrects the publish dry-run package spec from
  `-p contrix-sdk` (which never matched any crate) to `-p contrix`.

## [0.1.0] – TBD

Initial release candidate for Contrix v1 SDK.

### Added

- Workspace of 22 focused crates plus an umbrella `contrix` crate
  re-exporting the public SDK surface (high-level state managers, sync
  client, MLS encryption, identity, federation, push, presence, …).
- Wire models for Space / Flow / Message / Morph / Relation / Event / View
  matching the Contrix v1 `data-structures.md` shape, including `FlowBranch`
  end-to-end migration and `Morph` as a canonical object.
- Canonical JSON encoder + SHA-256 digest helpers; signed payloads use this
  module so different clients compute identical hashes.
- HLC parsing and deterministic ordering, RFC 9421 / RFC 9530 transcript
  helpers, and replay/CommitFork detection.
- HTTP `contrix-client` with HTTPS-by-default, retry/backoff, idempotency,
  read-your-writes wait header support, and query-string-auth rejection.
- Framework-independent server endpoint registry plus optional Salvo
  adapter and OpenAPI integration. Every public model carries
  `salvo::oapi::ToSchema` under the `salvo` feature.
- MLS RFC 9420 group encryption based on OpenMLS, including `KeyPackage`,
  `Commit`, `Welcome` envelopes and `cx_app_state_ref` GroupContext
  extension.
- 42 canonical error code constants plus an `is_known_error_code` helper
  mirroring the spec's `error-code-registry.json`.
- Conformance vector library covering canonical-JSON, redaction, capability
  evaluation and sync-cursor binding (`crates/testing`).
- Authorization engine covering the 8 v1 constraint families
  (`temporal`, `field_access`, `type_restriction`, `scope_limitation`,
  `delegation_control`, `quota`, `claim_based`, `confidentiality`) with
  optional `subtype` discriminators, `ApprovalMode` quorum semantics +
  `ApprovalWorkflowMode` workflow stages, evaluation order
  (`deny → quarantine → require_review → allow`), and a `partial_auth_state`
  read-only marker.
- Push privacy validator that rejects raw-DID payloads outside an explicit
  `plaintext_visible_services` allowlist; TURN credential validator that
  rejects DID-bearing usernames/credentials.
- `MerkleProofStep` + `verify_snapshot_inclusion` for snapshot manifest
  inclusion proofs.
- Round-1 through Round-8 spec-alignment work (see commit history for
  the per-round task lists; the closed punch list is preserved in git).

### Security

- The `0.1.x` line targets functional parity for an external security
  review. See `SECURITY.md` for the disclosure process and
  `docs/security-audit.md` for current evidence.

[Unreleased]: https://github.com/contrix/contrix-rust-sdk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/contrix/contrix-rust-sdk/releases/tag/v0.1.0
