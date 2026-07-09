# Conformance Certification

The SDK currently carries conformance coverage in unit and integration tests:

- canonical JSON SHA-256 vectors
- HLC parsing, ordering and skew validation
- cursor encoding/decoding
- Event digest vectors
- encrypted payload digest vector
- Query and Sync wire-shape serialization checks
- federation transaction signature checks
- E2EE sender/integrity/replay checks
- integration workflow serialization roundtrips

Certification procedure:

```sh
cargo test -p arkret
cargo test -p arkret --no-default-features
cargo test -p arkret --all-features
```

A release candidate is conformant when all protocol vectors and integration
roundtrips pass for the default type surface and each supported opt-in feature
combination before publishing.
