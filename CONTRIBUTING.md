# Contributing

Contrix SDK changes should keep protocol concepts explicit and stable. Avoid
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

## API Rules

- Public model types must serialize to the documented wire shape.
- Digest helpers must use the canonical JSON module.
- Repeated submission of the same identifier and digest must be idempotent.
- Reusing an identifier with different content must be treated as a conflict.
- Service clients must parse Contrix error envelopes instead of discarding
  machine-readable error codes.
- New service methods must verify profile compatibility where a server
  description is available.

## Type Ownership

Wire shape ownership is strict:

- The protocol wire shape source of truth is `contrix-spec/spec/v1/artifacts/schemas/*.schema.json`
  and the matching registry artifacts.
- The Rust expression of shared protocol types belongs in
  `contrix-rust-sdk/crates/{identifiers,core,api}`. Product crates should import
  these types or wrap them; they should not redefine wire enums or DTOs.
- Product-local types are fine for DB rows, UI view models, platform config,
  service aggregates, and admin metadata. When they overlap a protocol type,
  keep the SDK type as a field or provide an explicit conversion boundary.
- Do not redefine protocol enums such as `ErrorCode`, `EventKind`,
  `Discoverability`, `JoinRule`, `FederationPolicy`, `ActorKind`,
  `RelationKind`, `ViewKind`, `Facet`, `EncryptionProfile`, `SecurityClass`,
  or `HistoryVisibility`; add local behavior with traits or newtypes.

## Commit Messages

Use Conventional Commits:

```text
<type>(<scope>): <short summary>
```

Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `ci` and `chore`.
Security fixes should describe impact and include advisory identifiers when
available.
