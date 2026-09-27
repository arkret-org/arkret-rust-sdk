# arkret-mls

Arkret v1 MLS (RFC 9420) behavior layer over OpenMLS.

The sole OpenMLS boundary in the workspace: it owns the `ArkretMlsIdentity` /
`ArkretMlsGroup` group machine, the MLS message / exporter-aead content
schemes, epoch recovery, and active-leaf identity/key binding material. It
depends only on the wire / model / crypto data crates and
inverts persistence through the narrow `MlsGroupStateSink` / `MlsCommitSource`
ports, so it never reaches up into the SDK `CryptoStore`.
