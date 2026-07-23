# arkret-event-draft

Arkret v1 client-side event drafting.

Owner of the SDK-local drafting layer that sits *in front of* the wire Event
Envelope: the local `Operation` draft record, the `OperationEnvelope` +
registry-backed `OperationEnvelopeBuilder`, the draft-to-event conversion,
the event-draft kind registry, LexoRank-style rank interval arithmetic, and
the strand create / tracks-update payload builders. None of these shapes are
Arkret v1 wire facts — they materialize into signed `Event`s (owned by
`arkret-wire`) before touching network, sync, or reducers.
