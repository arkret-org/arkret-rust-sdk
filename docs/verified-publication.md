# Verified publication API inventory

The SDK accepts producer wire values as drafts. A publication entry point requires
`VerifiedSubmission<T>`; its closed traversal authenticates every original Event
and, when carried, every RealmCommit. Only caller supplied independent trusted
signing context may establish an Event key. Session PoP and fields inside the
unverified request cannot supply that trust.

| Publication family | Closed originals |
| --- | --- |
| Event, actor private Event, MLS Commit, Message submit, batch | Exact Event envelopes in wire order |
| Self authority Event/MLS/bootstrap/Direct/compensation/audit pair | Every original in the registered typed variant |
| Peer authority forwarding/replication/registered unit | Every original Event and source RealmCommit; Commit verification uses the authenticated Realm authority chain |
| Human registration | Root and founding Device together, native registration anchor, exact Account actor and adapter derived initial resolution; no standalone Root bypass |
| Profile, Device pairing, account data, read cursor | The embedded signed Event |
| Agent provision/key pairing/lifecycle | The commit or authorization Event; prepare carries no Event |
| Sidecar ensure | Empty prepare, create plus attach commit, or exact attach Event |
| Contact request/respond/reject/scope/tombstone | Empty prepare or the exact signed commit Event |
| Consent grant/revoke, moderation report | The embedded admission submission |
| Circle create/member add/remove/scope rotation | Every embedded producer Event |
| Self and peer Watch first admission | The audit submission Event, including the peer path |
| Applet managed Bot/Ghost provisioning | Provision, PCR genesis, accountability grant and Profile originals |
| Applet install/revoke/transaction | All explicit registration/grant/revoke/membership/Event originals and source Commits; a pure authoring request remains a draft |
| Security transaction create | Recovery reanchor and authorization batch, or rotation revoke and every active backup series batch; worker publication later uses the same frozen bytes |
| Recovery policy publication | The policy Event admission submission |

Generic JSON POST, PUT and DELETE-with-body helpers are crate private. Their
options variants remain private too. Read helpers and bodyless DELETE carry no
producer Event. Protocol operations without fresh producer originals keep their
SDK owned typed request contracts, including Signals, device messages, locator
commands, session/approval requests and DID operation submission; these retain
their own signature and authorization contracts.

Management review stores an immutable approval target and never accepts its Event
as a shared fact. Its later Event admission still requires the verified carrier.
A managed actor authoring call creates draft originals. An authority handoff
imports already accepted state under its separate authenticated history/snapshot
contract. Security transaction continuation carries the terminal receipt and
client attestation, rather than new Event originals.

The HTTP client and Garth transport cannot accept a raw publication request.
Queue deserialization restores the original draft bytes. Revalidation occurs
before an actual send or deferred create, and Garth compares the complete frozen
request before submission. A retry adds no new proof time window or current-key
lookup. Recovering a wire copy loses the verified guarantee. Rebinding retains
verification only for byte-identical ordered Event originals and identical source
Commits; the destination DTO still validates its registered shape.

The type-axis adapter runs all nine canonical cases against one exact SDK rlib,
then generic write, peer Watch and deferred transaction bypass probes. Positive
controls use the same semantic endpoint methods as the rejection probes. Legal
programs execute canonical byte assertions. Candidate evidence remains distinct
from a published artifact or an authorized signed conformance claim.
