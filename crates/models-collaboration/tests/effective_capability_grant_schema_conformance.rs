//! Effective capability rows stay aligned with the canonical operation DTO.

use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody;
use arkret_models_collaboration::governance::authorization::GrantList;
use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, IssuerAuthorityRef,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

const FILE: &str = "service-operation-dtos.schema.json";
const FRAGMENT: &str = "#/$defs/GrantList";

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable")
}

fn registry() -> ProtocolSchemaRegistry {
    let artifacts = artifacts_dir();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts)
        .expect("the spec artifacts must produce a schema registry");
    let path = artifacts.join("schemas").join(FILE);
    let schema: Value = serde_json::from_slice(
        &fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .expect("service operation schema must be JSON");
    registry
        .register_reference_document(schema.clone())
        .expect("service operation schema must have an absolute id");
    registry
        .register_fragment("test:grant-list", schema, FRAGMENT)
        .expect("GrantList fragment must register");
    registry
}

fn grant() -> Value {
    json!({
        "id": "ak:grant:AR9qVnHK4a0914zPmH5CRZLTjSSV_8ghJKuGGivDaExf",
        "schema": "ak.schema.capability.v1",
        "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
        "issuer_id": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkissuer",
                "station_id": "ak:did_core:webvh:z6mkstation"
            }
        },
        "subject": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mksubject",
                "station_id": "ak:did_core:webvh:z6mkstation"
            }
        },
        "actions": ["ak.message.create"],
        "resources": [{
            "kind": "realm",
            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"
        }],
        "issuer_authority_refs": [{
            "kind": "grant",
            "grant_id": "ak:grant:AU1_A5a8MMz_OdxEleQlWPFn-ljdJteaJv3ZZ9APkcrZ"
        }],
        "authority_depth": 2,
        "authority_root_refs": [{
            "kind": "realm_root",
            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            "authority_event_ref": "ak:event:AR9qVnHK4a0914zPmH5CRZLTjSSV_8ghJKuGGivDaExf",
            "authority_generation": 0
        }],
        "issued_at": "2026-09-21T00:00:00.000Z",
        "status": "active"
    })
}

fn grant_list() -> Value {
    json!({
        "grants": [{
            "grant": grant(),
            "revision": {
                "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
                "stream_position": 41
            }
        }],
        "state_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        "evaluated_at": "2026-09-21T00:00:01.000Z"
    })
}

#[test]
fn grant_list_round_trips_the_atomic_typed_row_and_validates_against_spec() {
    let value = grant_list();
    registry()
        .validate_value("test:grant-list", &value)
        .expect("canonical GrantList must validate against the formal fragment");

    let parsed: GrantList =
        serde_json::from_value(value.clone()).expect("SDK must accept the canonical GrantList");
    assert_eq!(parsed.grants[0].revision.stream_position, 41);
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
}

#[test]
fn legacy_bare_grants_and_missing_or_untyped_revisions_are_rejected() {
    let mut legacy = grant_list();
    legacy["grants"] = json!([grant()]);
    assert!(serde_json::from_value::<GrantList>(legacy).is_err());

    let mut missing = grant_list();
    missing["grants"][0]
        .as_object_mut()
        .unwrap()
        .remove("revision");
    assert!(serde_json::from_value::<GrantList>(missing).is_err());

    let mut untyped = grant_list();
    untyped["grants"][0]["revision"] = json!(41);
    assert!(serde_json::from_value::<GrantList>(untyped).is_err());
}

#[test]
fn list_and_row_are_closed_and_list_metadata_is_required() {
    let mut unknown_row = grant_list();
    unknown_row["grants"][0]["event_id"] =
        json!("ak:event:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE");
    assert!(serde_json::from_value::<GrantList>(unknown_row).is_err());

    let mut missing_digest = grant_list();
    missing_digest
        .as_object_mut()
        .unwrap()
        .remove("state_digest");
    assert!(serde_json::from_value::<GrantList>(missing_digest).is_err());

    let mut unknown_list = grant_list();
    unknown_list["revision"] = json!({"stream_position": 41});
    assert!(serde_json::from_value::<GrantList>(unknown_list).is_err());

    let mut terminal = grant_list();
    terminal["grants"][0]["grant"]["status"] = json!("relinquished");
    assert!(
        registry()
            .validate_value("test:grant-list", &terminal)
            .is_ok(),
        "the generic nested grant schema deliberately admits lifecycle states"
    );
    assert!(
        serde_json::from_value::<GrantList>(terminal).is_err(),
        "the effective-list carrier must enforce the operation's active-only semantics"
    );
}

#[test]
fn realm_root_wire_token_is_closed_and_rejects_legacy_basis() {
    let canonical = json!({
        "kind": "realm_root",
        "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
        "authority_event_ref": "ak:event:AR9qVnHK4a0914zPmH5CRZLTjSSV_8ghJKuGGivDaExf",
        "authority_generation": 0
    });
    let parsed: IssuerAuthorityRef =
        serde_json::from_value(canonical.clone()).expect("realm_root must deserialize");
    assert_eq!(serde_json::to_value(parsed).unwrap(), canonical);
    let parsed_root: AuthorityRootRef = serde_json::from_value(canonical.clone())
        .expect("materialized realm_root must deserialize");
    assert_eq!(serde_json::to_value(parsed_root).unwrap(), canonical);

    let legacy = json!({
        "kind": "realm_authority",
        "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
        "governance_station_id": "ak:did_core:webvh:z6mkstation",
        "authority_generation": 0,
        "basis": {
            "event_id": "ak:event:AR9qVnHK4a0914zPmH5CRZLTjSSV_8ghJKuGGivDaExf",
            "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "stream_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"
            },
            "stream_position": 1
        }
    });
    assert!(serde_json::from_value::<IssuerAuthorityRef>(legacy.clone()).is_err());
    assert!(serde_json::from_value::<AuthorityRootRef>(legacy).is_err());

    let mut extra_basis = canonical;
    extra_basis["basis"] = json!({"stream_position": 1});
    assert!(serde_json::from_value::<IssuerAuthorityRef>(extra_basis.clone()).is_err());
    assert!(serde_json::from_value::<AuthorityRootRef>(extra_basis).is_err());
}

#[test]
fn materialized_grant_requires_reducer_derived_authority_fields() {
    serde_json::from_value::<CapabilityGrant>(grant())
        .expect("complete materialized grant must deserialize");

    let mut missing_depth = grant();
    missing_depth
        .as_object_mut()
        .unwrap()
        .remove("authority_depth");
    assert!(serde_json::from_value::<CapabilityGrant>(missing_depth).is_err());

    let mut missing_roots = grant();
    missing_roots
        .as_object_mut()
        .unwrap()
        .remove("authority_root_refs");
    assert!(serde_json::from_value::<CapabilityGrant>(missing_roots).is_err());
}

#[test]
fn create_body_excludes_materialized_authority_fields() {
    let mut value = grant();
    let object = value.as_object_mut().unwrap();
    object.remove("id");
    object.remove("status");
    object.remove("authority_depth");
    object.remove("authority_root_refs");

    let parsed: CapabilityGrantCreateBody = serde_json::from_value(value.clone())
        .expect("create body must accept author-controlled members only");
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);

    value["authority_depth"] = json!(2);
    assert!(serde_json::from_value::<CapabilityGrantCreateBody>(value).is_err());
}
