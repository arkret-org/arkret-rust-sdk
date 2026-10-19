# arkret-policy

Arkret v1 authorization constraints and profile policy semantics.

Owns authorization and profile-policy behavior, including blind-payload
sanitization and push-rule evaluation for the integration edge. Holds
behavior only; wire shapes live in the model crates.

Grant predicates retain three outcomes: a proven match, a proven nonmatch,
or unknown semantics/facts. Unknown cannot satisfy an allow and cannot remove
a deny, quarantine, or review requirement from the cross-grant decision.
Action mismatch remains neutral. Callers must still reserve returned hard
quotas atomically and perform any sensitive read projection before delivery.

The constraint matrix test executes the pinned specification's
`fixtures/constraint-evaluation-fixture.json`; configure `ARKRET_SPEC_ARTIFACTS`
when the specification is not checked out beside this repository. Refusal of
missing session facts does not establish positive session-budget support.
