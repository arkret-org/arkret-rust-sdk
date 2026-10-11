# arkret-event-draft

Arkret v1 client-side event drafting.

Owner of the SDK-local producer drafting layer in front of the wire Event
Envelope: typed Event drafts, the event-kind registry, local reducer
projections, MLS scheduler records, LexoRank-style rank arithmetic, and
payload builders. The current governance Station assigns ordering in a separate
`RealmCommit` chain for the Event's independent Realm, Circle, or Sidecar
stream.
