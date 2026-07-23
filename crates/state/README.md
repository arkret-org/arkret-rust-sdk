# arkret-state

Move/Seal/Lattice state resolution and snapshot runtime for Arkret v1.

Protocol wire models and canonical encoding remain in the `arkret` umbrella; this crate
owns mutable reducers, stores, compaction, snapshot construction, and snapshot
verification.
