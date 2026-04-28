# Long-Term Support Policy

Contrix Rust SDK follows a conservative compatibility policy for `0.x` releases:

- Public protocol model fields should not be renamed without a migration note.
- New optional fields should use serde defaults or `Option`.
- Digest and canonical JSON behavior is treated as compatibility-critical.
- Store snapshots should preserve schema versions and provide migrations.
- Security fixes should be backported to the latest supported minor line.

LTS release checklist:

- All tests pass.
- Conformance certification is current.
- Security audit checklist is reviewed.
- Migration notes are updated for breaking changes.
- Supported feature matrix is documented.
