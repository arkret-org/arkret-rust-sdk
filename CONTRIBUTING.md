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

## Breaking changes and the downstream compile gate

The fifteen workspace crates share a single version (`shared-version = true`) and
ship breaking changes git-only, with **no compatibility shim** — see the
"Wire-breaking, no compatibility shim" entries in `CHANGELOG.md`. The
correctness of that model rests entirely on the "change every consumer in the
same commit" discipline. To keep that discipline from being purely a matter of
memory, **any wire- or API-breaking SDK change MUST be compile-checked against
the four first-party downstream repos before it lands**:

- `soland`, `inkson`, `garth`, `bridges` (each an independent repo that consumes
  the SDK via a relative path dependency, e.g.
  `arkret = { version = "0.3.0", path = "../arkret-rust-sdk/crates/sdk" }`).

Run them from a sibling checkout layout (each downstream repo next to
`arkret-rust-sdk`, which their `../arkret-rust-sdk/...` path deps require):

```sh
for repo in soland inkson garth bridges; do
  (cd "../$repo" && cargo check --workspace) || echo "DOWNSTREAM BREAK: $repo"
done
```

If the break is intentional, update the downstream consumers (and, when the
version is bumped, their pinned `version = "…"` requirement) in lockstep and
record the affected repos in the `CHANGELOG.md` entry.

### Why this is a documented gate and not a CI job

Adding a "downstream four-repo compile smoke test" job to `.github/workflows/`
was evaluated and rejected. Cross-repo checkout itself is supported (the
`embedded-snapshot` and `spec-drift` jobs already check out `arkret/arkret-spec`
into a sibling path), but a *reliable, cheap* downstream compile job is not
practical here:

- **Version-pin noise defeats the signal.** Downstream manifests pin
  `version = "0.3.0"` alongside the path dependency. With `shared-version`, the
  exact moment the SDK cuts a breaking bump, Cargo rejects the downstream build
  on the version *requirement* (path crate no longer satisfies `0.3.0`) before
  it compiles any real API surface — so the job would go red on every bump for a
  trivial reason and hide the API-break signal it is meant to surface. Making it
  meaningful requires bumping the downstream pins in lockstep, which is the very
  local discipline above.
- **`inkson` is not a cheap check.** It pulls custom git forks of Dioxus
  (`github.com/arkret/dioxus*` at pinned revs) plus a full wasm + UI + crypto
  (OpenMLS/HPKE) stack; `cargo check` there is a heavy, fork-availability-
  dependent build. `soland` similarly carries a server/DB/Docker surface.
- **Access and duplication cost.** The four are separate GitHub repos that each
  already run their own `ci.yml`; checking them out from the SDK repo would
  require cross-repo PAT secrets (only `arkret-spec` is public) and would
  duplicate builds those repos already perform, coupling SDK CI latency and
  flakiness to four heavy external builds for little marginal signal.

The local gate above is therefore the enforced mechanism; revisit a CI job only
if the downstream repos move to a published (versioned) SDK dependency, which
would remove the path-layout and version-pin coupling that makes it impractical
today.

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
  `arkret-rust-sdk/crates/{identifiers,core,api}`. Product crates should import
  these types or wrap them; they should not redefine wire enums or DTOs.
- Product-local types are fine for DB rows, UI view models, platform config,
  service aggregates, and admin metadata. When they overlap a protocol type,
  keep the SDK type as a field or provide an explicit conversion boundary.
- Do not redefine protocol enums such as `ErrorCode`, `EventKind`,
  `Discoverability`, `JoinRule`, `FederationPolicy`, `ActorKind`,
  `RelationKind`, `ViewKind`, `Facet`, `EncryptionProfile`, `SecurityClass`,
  or `HistoryVisibility`; add local behavior with traits or newtypes.

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
  qualify the narrower type (e.g. `ClaimDisclosurePolicy`,
  `MemberIdentityLattice`, `EngineDecision`).

## Commit Messages

Use Conventional Commits:

```text
<type>(<scope>): <short summary>
```

Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `ci` and `chore`.
Security fixes should describe impact and include advisory identifiers when
available.
