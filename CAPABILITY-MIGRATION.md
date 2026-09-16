# Authority-commit capability migration

This checklist prevents the authority-commit migration from replacing the SDK
with a compile-only subset. A removed source file is acceptable only when its
entire contract belongs to the removed protocol machinery. Mixed modules must
be split and migrated.

## Must remain available

- [ ] Account lifecycle, session grants, DPoP and device pairing models.
- [ ] Capability, consent, contact, Direct Conversation and managed-actor models.
- [ ] Message, poll, reaction, read-receipt, call and productivity payloads.
- [ ] Realm, Circle, Sidecar, Space, Strand, relation and organization models.
- [ ] Authority submission, queued/committed outcomes, current-authority bundle,
  planned handoff, typed snapshot and per-stream tail HTTP bindings.
- [ ] Key backup, secret sharing, device recovery and SecurityTransaction behavior.
- [ ] MLS group lifecycle, local private state, staged-then-accepted Commit install,
  KeyPackage and Welcome delivery models.
- [ ] Account subscription, Signal/WebSocket frames, current-result and retry models.
- [ ] Canonical encoding, identifiers, signatures, policy, schema validation,
  conformance helpers, server contracts and test-kit support.

## May be removed as complete protocol units

- [x] Seal, Cell, Bottom and CBS wire objects.
- [x] Lattice/state-model registry and generic CRDT reducers.
- [x] Actor sequence, predecessor/causal Event graph and peer frontier reconciliation.
- [x] History-key/RHRK, Seal conclusion and MLS governance-proof carriers.
- [x] ControlProposal/Ack and offline publication/lease finality.

## Mixed areas requiring migration evidence

- [ ] Event and message authoring keep domain builders but submit
  `EventCommitSubmission { event }`; producer Events carry no predecessor.
- [ ] Snapshot and sync retain typed product state while replacing Cell/Seal heads
  with Realm/Circle/Sidecar `CommitStreamRef` heads.
- [ ] Recovery retains its atomic business transaction and binds completion to
  consecutive `CommittedEventRef` values in one PCR Realm stream.
- [ ] Service discovery advertises concrete operations and schemas without reducer
  profile negotiation.
- [ ] All generated inventories are regenerated from the final spec and current
  downstream sources; no evidence string may point at removed code.

## Verification gates

- [ ] Restored Inkson resolves every required SDK feature, including secret
  sharing, recovery, session, Signal/WebSocket and MLS support.
- [ ] Public models and HTTP methods have migrated behavior tests; a reduced test
  count or a green minimal workspace is not evidence of capability preservation.
- [ ] Full workspace format, check, clippy, tests, schema/codegen sync and
  downstream compile probes pass against the final spec.
