# contrix-schema

Schema registry and compatibility contracts for Contrix.

`contrix-core` still publishes built-in schema documents. This crate exposes the
schema catalog, compatibility table, negative validation vectors and evolution
review contracts as a focused boundary for conformance runners and generators.
