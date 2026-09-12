# arkret-state

Event state-model resolution, Seal-confirmed security state, and snapshot runtime for Arkret v1.

Protocol wire models and canonical encoding live in the SDK's leaf crates. This crate
owns the five registered state models, security-state sequencing, stores, compaction,
snapshot construction, and snapshot verification.
