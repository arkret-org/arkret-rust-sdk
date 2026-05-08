# contrix-lattice

Per-cell Lattice trait and the six normative core implementations
(`or-set` / `mv-register` / `cas-register` / `fsm` / `counter` /
`ordered-log`) used by Contrix v1 Move/Anchor/Lattice state convergence.

See `contrix-spec/spec/v1/zh/authz/event-auth-state-resolution.md` §5 for
the protocol-level rules and `bottom.schema.json` for the diagnostic shape
returned when a join produces ⊥.
