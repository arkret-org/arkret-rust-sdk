# contrix-events

Contrix-native protocol event taxonomy and typed content models.

This crate is intentionally above `contrix-core`: it reuses core identifiers and
the raw `Event` envelope, then gives clients, servers, bots and UI layers a
shared vocabulary for message, state, ephemeral, account-data, E2EE, call and
custom event content.
