# arkret-models-identity

Arkret v1 identity domain models: account, actor profile, device, DID
continuity, and handle wire shapes.

Owner of the identity-domain wire shapes: account lifecycle and handoff,
actor profiles, attestation evidence, device verification, DID continuity and
operations, handles, identity-link cache projections, and member identity
segments. Behavior that needs signature verification, schema validation, or
state reduction lives in the `arkret` umbrella and its behavior crates; this
crate holds data shapes and type-local invariants only.
