# Matrix / Ruma Parity Checklist

This repository is not expected to clone Matrix semantics, but the Contrix SDK should cover the same client-grade capability classes that Ruma and matrix-rust-sdk expose.

## Ruma-Level Protocol Primitives

- Identifier validation: Contrix now enforces fixed-width HLC and strict cursor IDs where the spec requires it.
- Canonical serialization: event, commit, encrypted payload, and cursor paths use canonical JSON hashing / encoding.
- Client sync wire shape: native `spaces` is primary; `rooms` remains a Matrix bridge compatibility field.
- State resolution: reducer ordering includes causal depth, HLC, actor, actor sequence, and event ID.

## matrix-rust-sdk-Level Client Behaviors

- Timeline: Contrix has local timeline pagination plus reducer-backed message create / revise / redact.
- Room / Space list: Contrix sliding sync tracks visible spaces and subscription windows.
- Event cache: reducer now maintains processed events, causal frontier, redactions, messages, reactions, and generic resolved state.
- Encryption: MLS and envelope helpers exist, but full cross-device crypto store parity remains a larger follow-up.
- Device verification: device metadata, verification state, and to-device queues exist; SAS/QR parity is not a Matrix-compatible goal unless explicitly required.
- Account data: account-private data manager and sync account-data deltas exist.
- Push / notifications / receipts / typing / presence: dedicated managers exist and have unit coverage.

## Remaining Non-Goals / Future Work

- Matrix room-version auth rules are not copied; Contrix uses capability and policy reducer state.
- Matrix event types are not first-class Contrix types; bridge compatibility should translate at service boundaries.
- Durable SQLite / IndexedDB production adapters should implement `RepoStore` and keep the current verification behavior.
- Full crypto-store migration parity should be scoped separately if native Matrix client compatibility becomes a release target.
