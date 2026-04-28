# Contrix Rust SDK

This crate is the Contrix v1 SDK entry point. It exposes the protocol model
directly:

- DID principal identity
- Space / ActorProfile / Entity / Relation / Event / View graph
- append-only Repo commits, canonical Operations and signed Operation envelopes
- capability-based authorization
- OpenMLS-backed MLS RFC 9420 group E2EE
- service discovery over Principal Server, Repo, Sync, Index, Blob, Directory and Authz surfaces
- protocol-shaped Query and Client Sync response models

The default feature set enables the HTTP client and MLS support. Use
`default-features = false` for model-only consumers.
