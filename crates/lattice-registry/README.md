# arkret-lattice-registry

Canonical Arkret v1 cell-family lattice registry.

Per-cell-family `LatticeKind` runtime (one impl per `cell_family` declared in
the spec event-kind-registry) plus a `LatticeRegistry` that pre-registers
every spec-normative family via `default_lattice_registry`. Each family maps
to one of the six normative lattice algebras (OrSet, CasRegister, and the
rest) together with a typed subject-derivation function. Coverage mirrors
soland's `reducer::lattice_kinds`.
