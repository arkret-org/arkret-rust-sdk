# arkret-lattice-registry

Canonical Arkret v1 cell-family lattice registry.

The executable family/lattice/bottom mapping is generated from every active
cell contract in the spec event-kind registry and is installed by
`build_sdk_cell_registry`. `default_lattice_registry` additionally exposes
typed subject-derivation and event-kind dispatch implementations for callers
that need those higher-level helpers.
