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
cargo +nightly fmt --check
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

The Rust outputs listed in `tools/spec-generation-manifest.json` are generated
from `arkret-spec/spec/v1/artifacts` and committed. Generated Rust files carry
an `@generated` header and must never be hand-edited; the manifest is the
authoritative list of Rust outputs and their input artifacts. Production crates
consume these typed descriptors and do not package the source JSON or OpenAPI
documents. Filesystem-backed drift and conformance loading lives in the
non-published `arkret-schema-conformance` crate.

Use the single synchronization entry point so every static surface is
regenerated against the same artifact tree in the same commit:

```sh
./tools/sync-spec.ps1 -ArtifactsDir ../arkret-spec/spec/v1/artifacts
```

Verify the generated surfaces with the matching check mode:

```sh
./tools/sync-spec.ps1 -ArtifactsDir ../arkret-spec/spec/v1/artifacts -Check
```

The entry point delegates to `sync-spec-generated.ps1`, which runs the Rust
contract generator and the remaining specialized generators, formats their
committed outputs, and performs byte-for-byte drift checks. Runtime crates do
not package the source JSON, fixtures, or canonical OpenAPI document. The
`sha256=` in a generated file's header is the digest of the input at generation
time, not of the current spec, so recompute it against the spec file rather than
trusting the `version:` line.

Nothing above runs in the pre-commit hook (it needs a spec checkout the hook
cannot assume). GitHub Actions are currently disabled by workspace decision;
run both generated-surface synchronization and the coverage drift report
locally before claiming a surface is synchronized.

### Coverage gates layered on top

| Gate | Asserts |
|---|---|
| `cargo run -p arkret-schema-conformance --example spec_drift_report` | Generated schema descriptors and the remaining conformance coverage declarations match the live registries in both directions. Needs `ARKRET_SPEC_ARTIFACTS`. |
| `cargo test -p arkret-schema --test id_kind_coverage` | `SUPPORTED_ID_KINDS` matches the typed ids `arkret-identifiers` actually declares. |
| `cargo test -p arkret-http-client --test operation_path_coverage` | Every `/_arkret/...` path the client sends is a registered operation path. |

When you add a typed id, declare it inside the `declare_uuid_id_kinds!` block
in `crates/identifiers/src/lib.rs` — scattered `uuid_id_type!` calls are not
enumerable, which is exactly how the coverage list drifted before.

## Breaking changes and the downstream compile gate

The fifteen workspace crates share a single version (`shared-version = true`) and
ship breaking changes git-only, with **no compatibility shim** — see the
"Wire-breaking, no compatibility shim" entries in `CHANGELOG.md`. The
correctness of that model rests on an exact multi-repository candidate set,
not on consumers independently following moving `main` branches.

Single-repo `cargo check` is **not sufficient** to prove such a change is safe:
it compiles only this workspace, while the SDK is consumed via relative path
dependencies by sibling repositories — including *indirect* consumers that
reach a wire type through `arkret` re-exports and never appear in this repo's
build graph. (2026-08-18: the `StrandTrackConfig` → `StrandTrack` rename was
green here and broke `bridges` and `cotest` at HEAD, which nothing compiled.)
Any change that touches the public surface of `crates/wire` or
`crates/models-*` MUST update `compatibility/manifest.json` with every
coordinated candidate SHA. The `atomic compatibility / exact manifest gate`
workflow resolves the triggering repository to its candidate SHA, records the
fully resolved manifest as CI evidence, and checks that exact set before merge.
For a local equivalent, resolve the candidate set and execute the ordered gate:

```bash
python tools/compatibility_gate.py snapshot \
  --manifest compatibility/manifest.json \
  --workspace-root .. \
  --output compatibility/manifest.json
python tools/compatibility_gate.py resolve \
  --manifest compatibility/manifest.json \
  --candidate arkret-rust-sdk=$CANDIDATE_SHA \
  --output ../resolved-compatibility-manifest.json
python tools/compatibility_gate.py check \
  --manifest ../resolved-compatibility-manifest.json \
  --workspace-root .. --verify-workspace-heads
python tools/compatibility_gate.py run \
  --manifest ../resolved-compatibility-manifest.json \
  --workspace-root ..
```

The ordered checks cover the normative operation registry and schemas, SDK
public-model probes, SDK/Soland/Coauth/Garth/Inkson/Cotest compilation, Cotest
TypeScript and generated wire mirrors, and a live joint Soland/Coauth/Inkson
smoke. The first failure is emitted with its operation/schema/type surface.
The committed negative-mutation test deletes a real SDK `Event` field in a
temporary copy and must prove the gate rejects it.

The same workflow is present in every repository in the train and also runs on
`main` pushes, so local auto-sync cannot create an unobserved green set.
Configure `atomic compatibility / exact manifest gate` as a required status
check on each protected `main` branch. CI code cannot itself protect a branch.
The merge order is the manifest's `train.merge_order`; do not use local DTOs,
dual reads, or permissive extra fields to make an intermediate commit green.

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
  `AccountRegisterOutcome`). Do not introduce new `*ResBody` or
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
