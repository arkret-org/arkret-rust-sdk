# arkret-hlc

Clock- and entropy-backed Arkret v1 protocol value generators.

Home of the protocol values whose *construction* needs a wall clock or an OS
RNG while their *wire form* stays a plain validated string:

- `HlcGenerator` — the monotonic Hybrid Logical Clock generator with
  future-drift tiers and Realm-scoped pseudonymous node ids. The stateless
  HLC value helpers (parse / compare / validate) live next to the validated
  `Hlc` newtype in `arkret_identifiers::hlc`.
- `cursor::Cursor` — the issuing-service mint / validate surface for
  `ak:cursor:` tokens (fresh ≥128-bit handles, TTL caps, clock-skew checks).
