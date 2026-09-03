# spec-struct-proto

Feasibility prototype for generating SDK wire types from the Spec `$defs`
instead of hand-writing them. **Nothing under `crates/` reads anything here**,
no build step invokes it, and it is not wired into any gate. It exists to
answer one question with measurements rather than estimates:

> If we generated `crates/models-discovery` from `arkret-spec`, how much of the
> hand-written crate would the generator reproduce, and what would be left?

Run it:

```sh
python tools/spec-struct-proto/run_feasibility.py --crate models-discovery
python tools/spec-struct-proto/compile_check.py        # rustc-checks the output
python -m pytest tools/spec-struct-proto/test_spec_struct_proto.py
```

`run_feasibility.py` writes to `out/`:

| file | contents |
| --- | --- |
| `mapping.json` | every Rust type in the crate, its Spec pointer, and the evidence class that produced the mapping |
| `bindings.json` | terminal-`$ref` to Rust type table learned from the crate, plus every pointer the crate spells more than one way |
| `generated.rs` | the prototype's output, one declaration per mapped shape |
| `differences.json` | every difference against the hand-written crate, bucketed |

## Modules

| module | role |
| --- | --- |
| `rust_model.py` | parses Rust declarations into a serde-level model (wire names, optionality, omission rules, tags) |
| `schema_index.py` | indexes every addressable node in the Spec artifacts, not only `$defs` |
| `mapping.py` | resolves Rust types to Spec pointers: registry, rustdoc pointer, name, property set, enum set, then a scored near match |
| `bindings.py` | learns the `$ref` to newtype table from the crate rather than guessing it |
| `generate.py` | emits Rust from a Spec node; records a `GenerationGap` instead of guessing |
| `compare.py` | buckets each difference as `generator-gap`, `drift`, or `equivalent` |
| `compile_check.py` | builds the output in a throwaway crate with its own `CARGO_TARGET_DIR` |

## Difference buckets

* **`generator-gap`** - the prototype could not express what the schema says.
  These are tool defects, not findings about the crate.
* **`drift`** - the hand-written type and the Spec disagree about the wire
  shape. These are findings about the crate (or, in a few cases, about the
  Spec).
* **`equivalent`** - both make serde do the same thing; only the Rust spelling
  differs. Naming of inline subschemas, integer widths that still cover the
  declared maximum, and `#[serde(default)]` on an `Option` all land here.

## Measured result on `models-discovery` (2026-09-03)

| measure | value |
| --- | --- |
| Rust types in the crate | 129 |
| resolved to a Spec pointer | 88 (registry 12, rustdoc 2, name 35, property set 9, enum set 23, near match 7) |
| Rust-only (no counterpart) | 40 |
| generation attempted | 84 |
| reproduced with no wire difference | 37 |
| difference is Rust spelling only | 2 |
| difference includes real drift | 41 |
| drift findings | 60 |
| prototype capability gaps | 24 differences plus 3 build-time gaps |
| generated output | 141 declarations, compiles clean under `cargo check` |

Only 30% of the crate's lines are type declarations at all; the rest is
`impl` blocks, validators, free functions and tests that a shape generator
cannot produce. For the 39 types the prototype reproduces today, generated
declarations take 431 lines against 514 hand-written ones. Generation is worth
doing for what it removes from the hand-maintained surface, not for the line
count.

Indicative re-runs on the other models crates (mappings not hand-verified):

| crate | lines | declaration lines | types | mapped | reproduced | drift findings |
| --- | --- | --- | --- | --- | --- | --- |
| models-discovery | 6268 | 30% | 129 | 88 | 37/84 | 60 |
| models-integration | 4605 | 33% | 130 | 99 | 42/93 | 40 |
| models-identity | 12861 | 24% | 246 | 193 | 84/183 | 95 |
| models-crypto | 12603 | 25% | 242 | 188 | 61/173 | 124 |

## Known limits of the prototype

* The `$ref`-to-newtype table is learned from one crate, so a newtype that only
  appears in a shape this crate does not own is missed. A production generator
  needs this as a maintained registry, not an inference.
* `oneOf` without a shared const-valued property can only become `untagged`.
* `uniqueItems`, `minItems`, `pattern` and numeric bounds are recorded as
  unexpressed constraints; the hand-written crates enforce them in `validate()`
  methods that a shape generator cannot produce.
* Names for inline subschemas are derived from the owning member, so they do
  not match the crate's hand-picked names unless the crate already registers a
  pointer for them.
