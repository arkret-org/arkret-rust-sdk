# Contributing

Contrix SDK changes should keep protocol concepts explicit and stable. Avoid
introducing application-specific shortcuts into the public API unless they are
clearly layered on top of the protocol model.

## Development

Run the standard checks before sending changes:

```sh
cargo fmt --check
cargo check
cargo test
```

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

## Commit Messages

Use Conventional Commits:

```text
<type>(<scope>): <short summary>
```

Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `ci` and `chore`.
Security fixes should describe impact and include advisory identifiers when
available.
