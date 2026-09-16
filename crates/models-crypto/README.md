# arkret-models-crypto

Arkret v1 crypto domain wire models: secret-storage backup, key distribution,
MLS payload, encrypted envelope, and durable security-transaction shapes.

Owner of the crypto-domain wire shapes: encrypted secret-storage backup
envelopes, key claim and distribution DTOs, MLS payloads, encrypted event
envelopes, encrypted blob attachment descriptors, and the closed durable
RecoveryTransaction/SecurityRotationTransaction DTOs. Recovery freezes two
signed producer Events plus the current PCR Realm stream head; only the
governance Station creates the consecutive authority commits after admission.
Clients never sign or carry a `RealmCommit`. Fresh MLS membership is installed
through the wire crate's authority-issued `MlsWelcomeDelivery`.
