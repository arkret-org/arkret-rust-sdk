// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-link-operations.schema.json
// sha256=373a7a8a913f21d112f9145b25e452bc3d7527d859425191f63dd3d0daab37e0
//
// Input: schemas/event-payload.schema.json
// sha256=6e557b3350ecfe34a8c4836bb00abf61dce039fa6a5fbbc58b07ec74dbaaba7f
//
// Input: schemas/realm-organization-operations.schema.json
// sha256=cb36954bb1f984ec3bea96289ede428accabc65334aa74fa356b6fd609fe56f9
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c8b4ad76a778828f23891614ed9c259161da8c53eb669c8825b9bb8a5da8ff2

/// Counterpart: `realm-link-operations.schema.json#/$defs/realm_link_list`.
/// `realm-link-operations.schema.json#/$defs/realm_link_list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLinkList {
    pub realm_id: RealmId,
    pub direction: RealmLinkDirection,
    pub links: Vec<RealmLinkView>,
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
    pub relationships: Vec<RealmOrganizationRelationshipView>,
    pub declared_organization_hint_ids: Vec<DidCoreId>,
}
