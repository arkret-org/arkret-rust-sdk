// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-link-operations.schema.json
// sha256=2c066645c7a7c626e0866ce351e253f000fe20467718fc55a271c5f0fa6843a5
//
// Input: schemas/event-payload.schema.json
// sha256=a4c646467cc0e400d6cb24a119fe6791612dcf3a3a8d77fd355f9429600679bc
//
// Input: schemas/realm-organization-operations.schema.json
// sha256=c714db164aed7113dec60b8459e03a84a610fbeab2d5feaa57a2f2d50c27578f
//
// Bindings: tools/closed-model-bindings.json
// sha256=493cae310937341f71c829355ac772a12a878b5f7c2e20a5e915ba45fda6c2aa

/// Counterpart: `realm-link-operations.schema.json#/$defs/realm_link_list`.
/// `realm-link-operations.schema.json#/$defs/realm_link_list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLinkList {
    pub realm_id: RealmId,
    pub direction: RealmLinkDirection,
    pub links: Vec<RealmLinkEntry>,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_alias_declaration`.
/// Wire counterpart:
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_alias_declaration`.
///
/// `ak.realm.alias` declaration â€” the ONLY wire carrier of a Realm alias.
///
/// `realm.schema.json` is a closed object with no `alias` property, and
/// Realm genesis/profile payloads MUST NOT carry one
/// (`discovery/object-addressing.md` Â§3.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAliasDeclarationPayload {
    pub alias: RealmAlias,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_alias_tombstone`.
/// `ak.realm.alias` durable value tombstone: releases the alias without
/// erasing cell history. Effective resolution then treats the Realm as
/// addressable only by `realm_id`.
/// Wire counterpart:
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_alias_tombstone`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAliasTombstonePayload {
    pub tombstone: bool,
}

/// Counterpart:
/// `realm-organization-operations.schema.json#/$defs/realm_organization_relationship_list`.
/// Response DTO for `ak.self.realm_organization.read.list.v1`
/// (`realm-organization-operations.schema.json#/$defs/realm_organization_relationship_list`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationRelationshipList {
    pub realm_id: RealmId,
    pub relationships: Vec<RealmOrganizationRelationshipRow>,
    pub declared_organization_hint_ids: Vec<DidCoreId>,
}
