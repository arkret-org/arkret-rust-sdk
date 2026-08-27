# Contributing

Arkret SDK changes should keep protocol concepts explicit and stable. Avoid
introducing application-specific shortcuts into the public API unless they are
clearly layered on top of the protocol model.

## After clone

Once you have cloned the repository, enable the in-tree git hooks so the
pre-commit gate runs locally:

```sh
git config core.hooksPath .githooks
```

This single command is all you need before your first commit. The hook
itself lives at `.githooks/pre-commit`.

## Development

Run the standard checks before sending changes:

```sh
cargo fmt --check
cargo check
cargo test
```

The pre-commit hook (enabled by the "After clone" step above) runs
`cargo fmt --all -- --check` and then runs `cargo clippy` for the workspace
packages touched by staged Rust or Cargo manifest changes. Release readiness
still requires the stricter CI clippy gate with `-D warnings`.

For changes that touch canonical serialization, signed payloads, idempotency or
authorization, add focused tests that prove the exact digest or conflict
behavior being changed.

## Spec-derived surfaces

The Rust outputs listed in `tools/spec-generation-manifest.json` and the two
embedded snapshots under `crates/schema/src/` are generated from
`arkret-spec/spec/v1/artifacts` and committed. Generated Rust files carry an
`@generated` header and must never be hand-edited; the manifest is the
authoritative list of Rust outputs and their input artifacts.

Use the single synchronization entry point so both layers are regenerated
**against the same artifact tree, in the same commit**:

```sh
./tools/sync-spec.ps1 -ArtifactsDir ../arkret-spec/spec/v1/artifacts
```

Verify both layers with the matching check mode (it needs no `cargo`):

```sh
./tools/sync-spec.ps1 -ArtifactsDir ../arkret-spec/spec/v1/artifacts -Check
```

The entry point delegates to two independently testable implementation layers:
`sync-spec-generated.ps1` produces compile-time Rust constants and descriptors,
while `refresh-embedded-artifacts.py` produces the runtime JSON/OpenAPI
snapshot. They have gone stale to *different* spec generations before, which is
why contributors and CI must not invoke only one layer. The `sha256=` in a
generated file's header is the digest of the input *at generation time*, not of
the current spec, so recompute it against the spec file rather than trusting the
`version:` line.

Nothing above runs in the pre-commit hook (it needs a spec checkout the hook
cannot assume), so the enforcement is the `spec-drift` CI job. Run the checks
yourself before claiming a surface is synchronized.

### Coverage gates layered on top

| Gate | Asserts |
|---|---|
| `cargo run -p arkret-schema --example spec_drift_report` | Generated schema descriptors and the remaining `SUPPORTED_*` declarations match the live registries in both directions. Needs `ARKRET_SPEC_ARTIFACTS`. |
| `cargo test -p arkret-schema --test id_kind_coverage` | `SUPPORTED_ID_KINDS` matches the typed ids `arkret-identifiers` actually declares. |
| `cargo test -p arkret-http-client --test operation_path_coverage` | Every `/_arkret/...` path the client sends is a registered operation path. |

When you add a typed id, declare it inside the `declare_uuid_id_kinds!` block
in `crates/identifiers/src/lib.rs` — scattered `uuid_id_type!` calls are not
enumerable, which is exactly how the coverage list drifted before.

## Breaking changes and the downstream compile gate

The fifteen workspace crates share a single version (`shared-version = true`) and
ship breaking changes git-only, with **no compatibility shim** — see the
"Wire-breaking, no compatibility shim" entries in `CHANGELOG.md`. The
correctness of that model rests entirely on the "change every consumer in the
same commit" discipline.

Single-repo `cargo check` is **not sufficient** to prove such a change is safe:
it compiles only this workspace, while the SDK is consumed via relative path
dependencies by sibling repositories — including *indirect* consumers that
reach a wire type through `arkret` re-exports and never appear in this repo's
build graph. (2026-08-18: the `StrandTrackConfig` → `StrandTrack` rename was
green here and broke `bridges` and `cotest` at HEAD, which nothing compiled.)
To keep that discipline from being purely a matter of memory, **any change that
touches the public surface of `crates/wire` or `crates/models-*` MUST be
compile-checked against the full workspace matrix before it lands**:

```powershell
powershell -File ../arkret-work/tools/check-workspace-compiles.ps1
```

The matrix runs `cargo check --workspace --all-targets` over all eleven Rust
repositories in the sibling workspace (the repository list lives in the script
and is kept in sync with `arkret-work/docs/project-map.md`; `--all-targets`
matters because a past breakage existed only in a downstream lib test target).

### CI assertion gate

A cross-repo compile job was evaluated and rejected (see below), so the
enforcement on the SDK side is the `downstream-matrix-gate` job in
`.github/workflows/ci.yml`: when a pull request changes files under
`crates/wire/src` or `crates/models-*/src`, the job fails unless the PR body
contains a `compile-matrix: green` line — added after running the matrix
locally — or `compile-matrix: n/a — <reason>` when the change provably cannot
affect downstream compilation (e.g. a doc-comment-only edit). The gate cannot
verify the run itself; it exists so the step cannot be skipped *silently*.

If the break is intentional, update the downstream consumers (and, when the
version is bumped, their pinned `version = "…"` requirement) in lockstep and
record the affected repos in the `CHANGELOG.md` entry.

### Why not a cross-repo compile job in CI

Adding a "downstream compile smoke test" job that checks out and builds the
downstream repositories in `.github/workflows/` was evaluated and rejected.
Cross-repo checkout itself is supported (the `embedded-snapshot` and
`spec-drift` jobs already check out `arkret-org/arkret-spec` into a sibling path),
but a *reliable, cheap* downstream compile job is not practical here:

- **Version-pin noise defeats the signal.** Downstream manifests pin
  `version = "0.3.0"` alongside the path dependency. With `shared-version`, the
  exact moment the SDK cuts a breaking bump, Cargo rejects the downstream build
  on the version *requirement* (path crate no longer satisfies `0.3.0`) before
  it compiles any real API surface — so the job would go red on every bump for a
  trivial reason and hide the API-break signal it is meant to surface. Making it
  meaningful requires bumping the downstream pins in lockstep, which is the very
  local discipline above.
- **`inkson` is not a cheap check.** It pulls custom git forks of Dioxus
  (`github.com/arkret-org/dioxus*` at pinned revs) plus a full wasm + UI + crypto
  (OpenMLS/HPKE) stack; `cargo check` there is a heavy, fork-availability-
  dependent build. `soland` similarly carries a server/DB/Docker surface.
- **Access and duplication cost.** The downstream consumers are separate GitHub
  repos that each already run their own `ci.yml`; checking them out from the
  SDK repo would require cross-repo PAT secrets (only `arkret-spec` is public)
  and would duplicate builds those repos already perform, coupling SDK CI
  latency and flakiness to a fleet of heavy external builds for little
  marginal signal.

The local matrix plus the PR assertion gate above is therefore the enforced
mechanism; revisit a real cross-repo compile job only if the downstream repos
move to a published (versioned) SDK dependency, which would remove the
path-layout and version-pin coupling that makes it impractical today.

## API Rules

- Public model types must serialize to the documented wire shape.
- Digest helpers must use the canonical JSON module.
- Repeated submission of the same identifier and digest must be idempotent.
- Reusing an identifier with different content must be treated as a conflict.
- Service clients must parse Arkret error envelopes instead of discarding
  machine-readable error codes.
- New service methods must verify profile compatibility where a server
  description is available.

## Type Ownership

Wire shape ownership is strict:

- The protocol wire shape source of truth is `arkret-spec/spec/v1/artifacts/schemas/*.schema.json`
  and the matching registry artifacts.
- The Rust expression of shared protocol types belongs in
  `arkret-rust-sdk/crates/{identifiers,wire,models-*}`. Product crates should import
  these types or wrap them; they should not redefine wire enums or DTOs.
- Product-local types are fine for DB rows, UI view models, platform config,
  service aggregates, and admin metadata. When they overlap a protocol type,
  keep the SDK type as a field or provide an explicit conversion boundary.
- Do not redefine protocol enums such as `ErrorCode`, `EventKind`,
  `Discoverability`, `JoinRule`, `FederationPolicy`, `ActorKind`,
  `RelationKind`, `ViewKind`, `Facet`, `EncryptionProfile`, `SecurityClass`,
  or `HistoryAccess`; add local behavior with traits or newtypes.

## Naming Conventions

Request/response DTO suffixes are unified workspace-wide (no removed aliases):

- Endpoint request bodies use `*RequestBody` (e.g. `SyncRequestBody`,
  `AccountRegisterRequestBody`). Do not introduce new `*ReqBody` names.
- Endpoint success responses use `*Outcome` (e.g. `EventsQueryOutcome`,
  `PolicyCheckOutcome`). Do not introduce new `*ResBody` or
  `*Response` names.
- Path/query/header parameter groups use `*Params` / `*Args`.
- Struct field declaration order for wire objects follows the matching spec
  schema `properties` order (`spec/v1/artifacts/schemas/*.schema.json`,
  typically `id, schema, …`); local non-schema fields trail the
  schema-ordered cluster.
- Avoid reusing a core wire type name for an unrelated SDK-internal concept;
  qualify the narrower type (e.g. `MemberIdentityLattice`, `EngineDecision`).

## Commit Messages

Use Conventional Commits:

```text
<type>(<scope>): <short summary>
```

Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `ci` and `chore`.
Security fixes should describe impact and include advisory identifiers when
available.
