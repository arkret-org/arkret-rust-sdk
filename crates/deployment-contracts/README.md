# Deployment-private HTTP contracts

Pure carriers shared by Coland and Coauth, which may run on different hosts.
This crate has no database, network client, key custody, backend, or service
implementation. Helpers only validate/compare carriers and build URLs.

These private HTTP contracts are not canonical Arkret operations or authority
evidence. Their existing paths and serialized fields remain unchanged. Product
code must use network interfaces across the service boundary, never load the
other application's business or storage crates.
