//! Contact consent-scope wire primitives.
//!
//! `ConsentScope` is a bare protocol string shared by the contact/directory
//! operation DTOs (`arkret-models-discovery`) and the account consent-cell
//! bodies (`arkret-models-collaboration`). It lives here in `arkret-wire` so
//! both model domains reach it within their allowed layering edges.

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/consent_scope`.
pub type ConsentScope = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/consent_scope_list`.
pub type ConsentScopeList = Vec<ConsentScope>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/consent_scopes`.
pub type ConsentScopes = Vec<ConsentScope>;
