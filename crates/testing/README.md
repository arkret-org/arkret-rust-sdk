# cokret-testing

Reusable Cokret conformance fixture helpers.

This crate ties together the protocol boundary crates and produces stable
machine-readable reports for protocol coverage, event taxonomy behavior
and deterministic state resolution smoke fixtures.

Shared DTO coverage uses `cokret-contracts`; canonical operation and route
coverage still comes from `cokret-core`, `cokret-server` and the
`cokret-spec` artifacts.
