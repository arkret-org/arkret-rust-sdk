# arkret-models-crypto

Arkret v1 crypto domain wire models: key backup, key distribution, MLS
payload, and encrypted envelope shapes.

Owner of the crypto-domain wire shapes: key backup envelopes and recovery
policy chains, key claim and distribution DTOs, recovery session artifact
counterparts, encrypted event envelopes, and encrypted blob attachment
descriptors. Behavior that needs key derivation, signature verification,
schema validation, or state reduction lives in the behavior crates; this
crate holds data shapes and type-local invariants only.
