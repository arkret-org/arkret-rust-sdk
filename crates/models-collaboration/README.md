# arkret-models-collaboration

Arkret v1 collaboration domain models: governance, collaboration objects,
event payloads, and sync / federation frames.

Trunk crate of the model family, organized as semantic module directories.
Holds data shapes and type-local invariants only; behavior that needs
signature verification, schema validation, or state reduction lives in the
`arkret` umbrella and its behavior crates.
