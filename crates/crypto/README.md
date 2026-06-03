# cokret-crypto

Protocol crypto machine contracts for Cokret.

This crate models the E2EE boundary that client runtimes and stores need to
agree on: device-key upload/query/claim, key lifecycle, secret backup,
encrypted media descriptors, unable-to-decrypt preservation and store binding.
Concrete MLS/OpenMLS machinery can implement these contracts without depending
on the umbrella SDK.
