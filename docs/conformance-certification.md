# Conformance Certification

The SDK currently carries conformance coverage in unit and integration tests:

- canonical JSON SHA-256 vectors
- HLC parsing, ordering and skew validation
- cursor encoding/decoding
- Event and Commit digest vectors
- encrypted payload digest vector
- Query and Sync wire-shape serialization checks
- federation transaction signature checks
- E2EE sender/integrity/replay checks
- integration workflow serialization roundtrips

Certification procedure:

```sh
cargo test
```

A release candidate is conformant when all protocol vectors and integration
roundtrips pass for the default feature set. Feature-specific certification
should additionally run with `--no-default-features` and each supported feature
combination before publishing.
