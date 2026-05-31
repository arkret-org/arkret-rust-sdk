# Circle integration guide (CXP-0007)

> Spec baseline: `contrix-spec` 2b0d70d (`zh/models/circle.md`,
> `artifacts/schemas/circle.schema.json`).
>
> Normative language in this document follows
> [`spec/v1/zh/conformance/normative-language.md`](https://github.com/contrix-spec/spec/blob/main/v1/zh/conformance/normative-language.md)
> (RFC 2119 / 8174 keywords).

This guide explains when and how to use `Circle` in services that
consume the Contrix Rust SDK.

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
2. Their work spans multiple Flows / Spaces / Morphs and you want the
   encryption scope to follow the work, not the individual resource.
3. The membership of the subset is roughly stable; frequent
   add/remove churn would force expensive MLS commits.

Do **NOT** create a Circle for short-lived ad-hoc audiences (use a
plain Flow with `scope_circle_id=None` and per-message recipients), for
access-only narrowing (use a capability constraint), or for
organisation-level federation boundaries (use a child Realm).

## How a Flow picks its scope

```rust
use contrix::{
    Circle, CircleColorToken, CircleDisplay, CircleGlyph, CircleId,
    CircleSymbol, Did, FlowCreateMetadata, RealmId,
};

// 1. Create the Circle (typically via a dedicated cx.circle.create
//    event; the example below shows the local in-memory struct).
let circle_id = CircleId::new(
    "cx:circle:0196419b-0000-7000-8000-000000000001".to_owned(),
)?;
let realm_id = RealmId::new(
    "cx:realm:0196419b-0000-7000-8000-000000000002".to_owned(),
)?;
let alice: Did = "did:web:alice.example".parse()?;
let display = CircleDisplay {
    short_name: "Ops".to_owned(),
    color_token: CircleColorToken::Indigo,
    symbol: CircleSymbol::Glyph { glyph: CircleGlyph::Shield },
};
let _circle = Circle::new(circle_id.clone(), realm_id, "Ops Circle",
                          display, alice);

// 2. Bind a Flow to the Circle's encryption scope. The reducer stamps
//    `effective_scope = Circle { realm_id, circle_id }` onto every
//    emitted Event in this Flow.
let meta = FlowCreateMetadata {
    scope_circle_id: Some(circle_id),
    ..Default::default()
};
```

When `scope_circle_id` is unset, the Flow lives in Realm-default
encryption scope and emits `EffectiveScope::Realm { realm_id }` on every
event.

### Rebind is forbidden by default

Once a Flow is bound to a Circle, the reducer **MUST** reject any
attempt to change `scope_circle_id` with
`failed_precondition reason=scope_rebind_forbidden`
([`REASON_SCOPE_REBIND_FORBIDDEN`](../crates/core/src/error.rs)).
Profiles MAY permit an explicitly audited high-risk rebind path; in
that case the caller MUST include a paired `cx.audit.accessed` event in
the same batch.

## Wide synthesis + narrow discussion

For workflows that need a public synthesis (the "wide" Flow in
Realm-default scope) plus a confidential discussion (the "narrow" Flow
bound to a Circle), link the two Flows with the new Relation kind:

```rust
use contrix::RelationKind;

let rel = RelationKind::ConfidentialDiscussionOf;
// emit cx.relation.create with `from = <wide flow>` and
// `to = <narrow flow>`; reducer validates that the narrow side carries
// `scope_circle_id` and the wide side does not (or carries a different
// Circle).
```

See `zh/models/circle.md` §7.2 for the canonical semantics.

## Capability surface

CXP-0007 adds 6 capability action constants:

| Constant                                | Action wire string             | Notes                                                    |
|-----------------------------------------|--------------------------------|----------------------------------------------------------|
| `CAP_ACTION_CIRCLE_CREATE`              | `cx.circle.create`             | Not in the default member bundle.                        |
| `CAP_ACTION_CIRCLE_MANAGE`              | `cx.circle.manage`             | Requires `AllowedCircleRefs` constraint.                 |
| `CAP_ACTION_CIRCLE_MEMBER_ADD`          | `cx.circle.member.add`         | Self-service (own actor only).                           |
| `CAP_ACTION_CIRCLE_MEMBER_MANAGE`       | `cx.circle.member.manage`      | Requires `AllowedCircleRefs` constraint.                 |
| `CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS`   | `cx.circle.member.add.others`  | High-risk; requires paired `cx.audit.accessed` event.     |
| `CAP_ACTION_CIRCLE_AUDIT`               | `cx.circle.audit`              | High-risk; requires paired `cx.audit.accessed` event.     |

The `AllowedCircleRefs(BTreeSet<CircleId>)` constraint variant on the
`Constraint` enum gates these actions to a static set of Circle ids;
unconstrained Realm-wide grants for the gated actions MUST be rejected.

## Receiver checks

Receivers (soland, sodmin, yougen, …) integrating the SDK MUST:

1. Hard-reject any payload that carries a top-level field listed in
   [`forbidden_wire_fields::FORBIDDEN_WIRE_FIELDS`](../crates/core/src/forbidden_wire_fields.rs).
   The CXP-0007 entries are `discussion_realm_ref`, `discussion_space_ref`,
   `parent_ref`, `default_realm_ref`, `scope_ref`, `default_scope_ref`,
   `retention_policy_ref`, `disclosure_policy_ref`,
   `rate_limit_policy_ref`.
2. Validate `Event.effective_scope` matches the resource's
   `scope_circle_id` (or absence thereof) before applying any reducer
   state change. Mismatch is `schema_violation`
   reason=`circle_realm_mismatch`
   ([`REASON_CIRCLE_REALM_MISMATCH`](../crates/core/src/error.rs)).
3. Enforce `Circle.members ⊆ Realm.members` (strict subset). The SDK
   exposes `Circle::assert_members_strict_subset(circle, realm)` for
   the membership check; reducer reason is
   `circle_member_must_be_realm_member`.
