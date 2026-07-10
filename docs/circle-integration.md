# Circle integration guide (AKP-0007)

> Spec baseline: `arkret-spec` 2b0d70d (`zh/models/circle.md`,
> `artifacts/schemas/circle.schema.json`).
>
> Normative language in this document follows
> [`spec/v1/zh/conformance/normative-language.md`](https://github.com/arkret-spec/spec/blob/main/v1/zh/conformance/normative-language.md)
> (RFC 2119 / 8174 keywords).

This guide explains when and how to use `Circle` in services that
consume the Arkret Rust SDK.

## What is a Circle?

A `Circle` is an intra-Realm cryptographic sub-boundary. It hosts its
own MLS group, its own membership (which **MUST** be a strict subset of
the parent Realm's membership), and its own history visibility. A
Circle does **NOT** carry federation identity, policy server, or
capability registry — those remain on the parent Realm.

Circles are intentionally rare and stable. They are not a replacement
for capability constraints, role-based ACLs, or per-resource visibility
filters. If you need to narrow read access for a subset of Realm
members on a single resource, prefer a capability grant with
`allowed_circle_ids` over creating a new Circle.

## When to use a Circle

Reach for a Circle when **all** of the following hold:

1. There is a long-lived, identifiable subset of Realm members who need
   cryptographic confidentiality against the rest of the Realm.
2. Their work spans multiple Strands / Spaces / Morphs and you want the
   encryption scope to follow the work, not the individual resource.
3. The membership of the subset is roughly stable; frequent
   add/remove churn would force expensive MLS commits.

Do **NOT** create a Circle for short-lived ad-hoc audiences (use a
plain Strand with `scope_circle_id=None` and per-message recipients), for
access-only narrowing (use a capability constraint), or for
organisation-level federation boundaries (use a child Realm).

## How a Strand picks its scope

```rust
use arkret::{
    Circle, CircleColorToken, CircleDisplay, CircleGlyph, CircleId,
    CircleSymbol, Did, StrandCreateMetadata, RealmId,
};

// 1. Create the Circle (typically via a dedicated ak.circle.create
//    event; the example below shows the local in-memory struct).
let circle_id = CircleId::new(
    "ak:circle:0196419b-0000-7000-8000-000000000001".to_owned(),
)?;
let realm_id = RealmId::new(
    "ak:realm:0196419b-0000-7000-8000-000000000002".to_owned(),
)?;
let alice: Did = "did:webvh:z6mkexample:alice.example".parse()?;
let display = CircleDisplay {
    short_name: "Ops".to_owned(),
    color_token: CircleColorToken::Indigo,
    symbol: CircleSymbol::Glyph { glyph: CircleGlyph::Shield },
};
let _circle = Circle::new(circle_id.clone(), realm_id, "Ops Circle",
                          display, alice);

// 2. Bind a Strand to the Circle's encryption scope. The reducer stamps
//    `effective_scope = Circle { realm_id, circle_id }` onto every
//    emitted Event in this Strand.
let meta = StrandCreateMetadata {
    scope_circle_id: Some(circle_id),
    ..Default::default()
};
```

When `scope_circle_id` is unset, the Strand lives in Realm-default
encryption scope and emits `EffectiveScope::Realm { realm_id }` on every
event.

### Rebind is forbidden by default

Once a Strand is bound to a Circle, the reducer **MUST** reject any
attempt to change `scope_circle_id` with
`failed_precondition reason=scope_rebind_forbidden`
([`REASON_SCOPE_REBIND_FORBIDDEN`](../crates/core/src/error.rs)).
Profiles MAY permit an explicitly audited high-risk rebind path; in
that case the caller MUST include a paired `ak.audit.accessed` event in
the same batch.

## Wide synthesis + narrow discussion

For workflows that need a public synthesis (the "wide" Strand in
Realm-default scope) plus a confidential discussion (the "narrow" Strand
bound to a Circle), link the two Strands with the new Relation kind:

```rust
use arkret::RelationKind;

let rel = RelationKind::ConfidentialDiscussionOf;
// emit ak.relation.create with `from = <wide strand>` and
// `to = <narrow strand>`; reducer validates that the narrow side carries
// `scope_circle_id` and the wide side does not (or carries a different
// Circle).
```

See `zh/models/circle.md` §7.2 for the canonical semantics.

## Capability surface

AKP-0007 adds 6 capability action constants:

| Constant                                | Action wire string             | Notes                                                    |
|-----------------------------------------|--------------------------------|----------------------------------------------------------|
| `CAP_ACTION_CIRCLE_CREATE`              | `ak.circle.create`             | Not in the default member bundle.                        |
| `CAP_ACTION_CIRCLE_MANAGE`              | `ak.circle.manage`             | Requires `AllowedCircleRefs` constraint.                 |
| `CAP_ACTION_CIRCLE_MEMBER_ADD`          | `ak.circle.member.add`         | Self-service (own actor only).                           |
| `CAP_ACTION_CIRCLE_MEMBER_MANAGE`       | `ak.circle.member.manage`      | Requires `AllowedCircleRefs` constraint.                 |
| `CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS`   | `ak.circle.member.add.others`  | High-risk; requires paired `ak.audit.accessed` event.     |
| `CAP_ACTION_CIRCLE_AUDIT`               | `ak.circle.audit`              | High-risk; requires paired `ak.audit.accessed` event.     |

The `AllowedCircleRefs(BTreeSet<CircleId>)` constraint variant on the
`Constraint` enum gates these actions to a static set of Circle ids;
unconstrained Realm-wide grants for the gated actions MUST be rejected.

## Receiver checks

Receivers (soland, sodmin, inkson, …) integrating the SDK MUST:

1. Validate `Event.effective_scope` matches the resource's
   `scope_circle_id` (or absence thereof) before applying any reducer
   state change. Mismatch is `schema_violation`
   reason=`circle_realm_mismatch`
   ([`REASON_CIRCLE_REALM_MISMATCH`](../crates/core/src/error.rs)).
2. Enforce `Circle.members ⊆ Realm.members` (strict subset). The SDK
   exposes `Circle::assert_members_strict_subset(circle, realm)` for
   the membership check; reducer reason is
   `circle_member_must_be_realm_member`.
