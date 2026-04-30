# contrix-store

Durable store contracts for Contrix runtimes.

This crate owns store-facing protocol boundaries: repo object storage,
event-cache storage, schema migrations, backend capability descriptors,
failure cache semantics and a reusable conformance smoke suite. Concrete
adapters can map these contracts to memory, SQLite, IndexedDB or service-owned
distributed stores.
