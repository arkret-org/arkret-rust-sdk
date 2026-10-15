// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-link-operations.schema.json
// sha256=2c066645c7a7c626e0866ce351e253f000fe20467718fc55a271c5f0fa6843a5
//
// Input: schemas/event-payload.schema.json
// sha256=36cd224e905e42c33740bf6c3c3d893497e38b5305cadc8d0fb51c1cfdba9c0d
//
// Input: schemas/realm-organization-operations.schema.json
// sha256=c714db164aed7113dec60b8459e03a84a610fbeab2d5feaa57a2f2d50c27578f
//
// Bindings: tools/closed-model-bindings.json
// sha256=b381c96b67ab466bbb82afb539a5bf9f04c5809ca15139346195d6a0eed4e539

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
/// `ak.realm.alias` declaration — the ONLY wire carrier of a Realm alias.
///
/// `realm.schema.json` is a closed object with no `alias` property, and
/// Realm genesis/profile payloads MUST NOT carry one
/// (`discovery/object-addressing.md` §3.3).
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
