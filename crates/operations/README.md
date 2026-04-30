# contrix-operations

Operation registry, builder and DAG validation contracts for Contrix.

`contrix-core` still owns the raw operation envelope types. This crate owns the
protocol boundary around operation surfaces, catalog coverage, dependency DAG
validation and conformance vectors so runtime code does not need to depend on a
large model module directly.
