# Arkret spec code generator

This unpublished Rust binary converts canonical machine contracts from
`arkret-spec/spec/v1/artifacts` into committed, static Rust descriptors. It is
not a build script and is not a dependency of any runtime crate.

The generator follows a strict three-stage pipeline:

1. deserialize artifacts into typed input models;
2. validate closed references and build the generator-owned intermediate model;
3. emit deterministic Rust source, then let `sync-spec-generated.ps1` run
   nightly `rustfmt` and byte-for-byte drift checks.

Run it through `../sync-spec-generated.ps1`; that script owns the complete
generation order and output manifest.
