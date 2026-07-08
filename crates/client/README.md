# cokret-client

Runtime-neutral shared client engine for Cokret applications.

This crate is the L2 client runtime layer above `cokret-core`,
`cokret-http-client`, and the `cokret` SDK primitives. It deliberately avoids
UI frameworks and platform keystore implementations; hosts provide those
through traits.
