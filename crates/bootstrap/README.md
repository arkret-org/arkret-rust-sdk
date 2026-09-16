# arkret-bootstrap

Producer-side builders for principal-control and Agent bootstrap Events.

The crate creates immutable producer content and packages signed
identity-creation Events. The current governance Station separately validates
them and creates `RealmCommit` records in the affected Realm stream. Circle and
Sidecar streams remain independent and are never ordered by bootstrap code.
