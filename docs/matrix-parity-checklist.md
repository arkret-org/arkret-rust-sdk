# Matrix / Ruma Maturity Benchmark

This repository is not expected to clone Matrix semantics or carry Matrix
compatibility fields. The benchmark is client-grade maturity: Contrix should
cover comparable capability classes while keeping Contrix wire shapes native.

## Ruma-Level Protocol Primitives

- Identifier validation: Contrix now enforces fixed-width HLC and strict cursor IDs where the spec requires it.
- Canonical serialization: event, commit, encrypted payload, and cursor paths use canonical JSON hashing / encoding.
- Client sync wire shape: native `spaces` only.
- State resolution: reducer ordering includes causal depth, HLC, actor, actor sequence, and event ID.

## matrix-rust-sdk-Level Client Behaviors

- Timeline: Contrix has local timeline pagination plus reducer-backed message create / revise / redact.
- Space list: Contrix sliding sync tracks visible spaces and subscription windows.
- Event cache: reducer now maintains processed events, causal frontier, redactions, messages, reactions, and generic resolved state.
- Encryption: MLS and envelope helpers exist, but full cross-device crypto store parity remains a larger follow-up.
- Device verification: device metadata, verification state, and to-device queues exist; SAS/QR parity is not required unless explicitly scoped as native Contrix UX.
- Account data: account-private data manager and sync account-data deltas exist.
- Push / notifications / receipts / typing / presence: dedicated managers exist and have unit coverage.

## Remaining Non-Goals / Future Work

- Matrix room-version auth rules are not copied; Contrix uses capability and policy reducer state.
- Matrix event types are not first-class Contrix types.
- Durable production adapters should implement the event-cache, snapshot and crypto-store boundaries without weakening the current verification behavior.
