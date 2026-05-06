# Contrix Rust SDK — Working Punch List

Earlier rounds (R1–R8, T0–T3) are closed. Their summaries lived in this file; that history is preserved in git (commit `9d02761` and earlier) — this file now only tracks open work.

The single Tier-2 carryover from the spec-alignment audits is kept here, followed by the Round-9 audit (operations, configuration, CI, packaging) that was opened and worked on **2026-05-06**.

---

## Carryover from R1–R8

### Tier 2 — gated on spec change

- [ ] **T2-1** `cx.did.proof` field naming (M-29): rename `kind` → `proof_kind` to avoid clash with Event Envelope `kind`.
  *Deferred — M-29 is a recommendation in `contrix-spec/_report.md` but not yet adopted in `artifacts/schemas/event-envelope.schema.json`. Doing it unilaterally would fork the wire format. SDK will land `#[serde(rename = "proof_kind", alias = "kind")]` for one-minor overlap once the spec PR ships.*

### Spec-side, out of SDK scope

These appear in `contrix-spec/_report.md` and `contrix-spec/_todos.md` but require spec-side resolution before the SDK can implement faithfully:

- B-02 capability-grant envelope drift across three docs (resolved by adopting `data-structures.md §13`; T1-8 will track once spec PR-1 lands).
- B-04 constraint double-source (`grant-constraint-schema.md` vs `constraint-schema.md`).
- B-07 OpenAPI gaps (server crate is a thin adapter; spec still needs work).
- M-09 auth_weight lattice rework (spec says "v1.x").
- Q-01..Q-08 design-level questions deferred per spec `_report.md` §5.

---

## Round-9 — Robustness, configuration, operations (2026-05-06)

The protocol-alignment surface is closed. Round 9 was a non-spec audit covering production readiness: client/server configuration knobs, security hardening, deployment ergonomics, and GitHub release/CI hygiene.

### Round-9 implementation summary (2026-05-06)

All six R9 tasks landed.

- **R9-1 ClientBuilder configuration completeness** — extended `crates/client/src/lib.rs::ClientBuilder` with `connect_timeout`, `pool_idle_timeout`, `pool_max_idle_per_host`, `tcp_nodelay`, `tcp_keepalive`, three `http2_keep_alive_*` knobs, `proxy`, `no_proxy`, `redirect` (taking a new `RedirectPolicy { None, Limited(usize) }` enum that is `Clone`-friendly, since `reqwest::redirect::Policy` is not), and `gzip(bool)`. Internal `TransportConfig` struct collects the options so `build()` can apply them in one place. `build()` now returns `Error::Protocol` if a pre-built `http_client(...)` is combined with any transport-shaping option. 5 new unit tests cover the option surface and the conflict path; all 17 client tests pass.
- **R9-2 CI hardening** — `.github/workflows/ci.yml` rewritten with separate jobs for fmt/check/test, `cargo doc --no-deps --all-features --workspace` with `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D warnings"`, an MSRV-pinned `cargo check --workspace --all-features --locked`, `cargo audit --deny warnings`, and `cargo deny check --config .deny.toml --all-features` via `EmbarkStudios/cargo-deny-action@v2`. Fixed the pre-existing `cargo publish -p contrix-sdk --dry-run` package spec (the workspace member's `package.name` is `contrix`, not `contrix-sdk`).
- **R9-3 Release workflow alignment** — `.github/workflows/release-crates.yml` now publishes every workspace crate in topological order (computed from `cargo metadata --no-deps`) instead of only the umbrella `contrix` crate. The publish loop tolerates "version already exists" responses for safe re-runs, and pauses ~20 s between crates so crates.io can index the new version before the next dependent publishes. `RELEASING.md` rewritten to document the 22-crate set, the dependency-order list, and the `cargo release` / tag-driven workflow.
- **R9-4 Standard project docs** — added repo-root `SECURITY.md` (supported versions, GitHub Security Advisories + email disclosure channel, response SLA, scope) and `CHANGELOG.md` (Keep-a-Changelog format with `[Unreleased]` plus `[0.1.0]` covering R1–R9). Both files cross-linked from `README.md`'s new "Project documents" section.
- **R9-5 Cargo.toml docs.rs / discoverability metadata** — added `[package.metadata.docs.rs]` (`all-features = true`, `rustdoc-args = ["--cfg", "docsrs"]`) to `crates/sdk`, `crates/core`, `crates/client`, `crates/server`, `crates/identifiers`. Added crates.io `categories` slugs to the same five crates so they surface under `api-bindings`, `cryptography`, `data-structures`, `network-programming`, `web-programming::http-server`.
- **R9-6 Server deployment guide + example** — added `crates/sdk/examples/salvo_server.rs` (gated on `--features salvo`) which builds a Salvo `Router` from `contrix_router(...)` and prints "Salvo router built with N routes" (88 routes verified locally). Added `docs/deployment.md` covering build matrix, TLS (reverse-proxy and salvo-native paths), CORS with the canonical header allowlist, request body / rate limit configuration, health and readiness, observability, a systemd unit template, and a hardening checklist. Cross-linked from `crates/server/README.md`, `docs/quick-start.md`, and the root `README.md`.

### Verification

- `cargo build --example salvo_server --features salvo` ✓
- `cargo run --example salvo_server --features salvo` ✓ (88 routes registered)
- `cargo build --example export_openapi --features server` ✓
- `cargo build --example server_endpoint_adapter --features server` ✓
- `cargo test -p contrix-client --lib` ✓ (17 passed)
- `cargo check -p contrix --features salvo` ✓
- `cargo fmt -p contrix-client -- --check` ✓ (new code is formatted)

### Pre-existing drift cleanup (folded into R9, 2026-05-06)

Originally flagged as a follow-up out of R9 scope, then cleaned up in the same round so the new R9-2 CI gates can pass on first push:

- `cargo fmt --all` ran clean across the workspace.
- `cargo clippy --workspace --all-features --all-targets -- -D warnings` is now clean. Auto-fixed lints: `collapsible_if` in `crates/client/src/lib.rs::RetryConfig::retry_delay_from_headers` and `crates/core/src/model.rs`; `using contains() instead of iter().any()` in `crates/core/src/error.rs`; `let-else may be rewritten with ?` in `crates/operations/src/lib.rs`; multiple `redundant_clone` in tests under `crates/sdk/src/{crypto_store,platform,store}.rs`. Manually fixed: `match expression looks like matches! macro` in `crates/sdk/src/membership.rs::is_legal_membership_transition`; two `too_many_arguments` warnings on the `create_flow_operation_with_metadata` / `update_flow_operation_with_metadata` builders in `crates/sdk/src/space.rs` were pragma-allowed (refactoring the public 9-arg signatures into option structs is a breaking change held for a separate API-cleanup round). Removed dead code: `patch_string_array` in `crates/sdk/src/resolver.rs` (never used).
- Two pre-existing test bugs in `crates/sdk/src/mls.rs::remove_result_commit_operation_uses_mls_commit_op_type` (added in commit 45819ef alongside T31): asserted `op.op_type` instead of `op.object_type` (typo — `Operation` carries `object_type`, not `op_type`); and constructed `OperationId::new("op_remove_test")` which fails the `cx:operation:` prefix validator. Both fixed.
- Two doc-link breakages surfaced by `cargo doc --all-features -D rustdoc::broken_intra_doc_links`: `[`EvaluationClass`]` in `crates/sdk/src/authz.rs` resolved to `[`crate::EvaluationClass`]`; `[`FlowBranch::Deserialize`]` in `crates/core/src/model.rs` re-worded to `\`Deserialize\` impl on [`FlowBranch`]`.

### Verification (post-cleanup)

- `cargo fmt --all -- --check` ✓
- `cargo clippy --workspace --all-features --all-targets -- -D warnings` ✓
- `cargo test --workspace --all-features --no-fail-fast` ✓ (524 passed, 0 failed, 1 ignored)
- `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D warnings" cargo doc --no-deps --all-features --workspace` ✓
- `cargo run --example salvo_server --features salvo` ✓ (88 routes registered)
