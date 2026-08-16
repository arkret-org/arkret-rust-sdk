use super::*;
use crate::registry::service_routes;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolGoldenVector {
    pub name: String,
    pub profile: String,
    pub input: Value,
    pub expected: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireConformanceVector {
    pub name: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub body: Value,
    pub expected_status: u16,
    pub expected_error_code: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolFixtureStrand {
    Server,
    Identity,
    Sync,
    Blob,
    Authz,
    Directory,
    Push,
    DeviceMessages,
    Keys,
    Policy,
    Media,
    Moderation,
    Applet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolFixtureStep {
    pub strand: ProtocolFixtureStrand,
    pub operation_id: String,
    pub method: String,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolFixtureReport {
    pub steps: Vec<ProtocolFixtureStep>,
}

impl ProtocolFixtureReport {
    pub fn covers(&self, strand: ProtocolFixtureStrand) -> bool {
        self.steps.iter().any(|step| step.strand == strand)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolServerFixture {
    strands: BTreeSet<ProtocolFixtureStrand>,
}

impl ProtocolServerFixture {
    pub fn new(strands: impl IntoIterator<Item = ProtocolFixtureStrand>) -> Self {
        Self {
            strands: strands.into_iter().collect(),
        }
    }

    pub fn all_strands() -> Self {
        Self::new([
            ProtocolFixtureStrand::Server,
            ProtocolFixtureStrand::Identity,
            ProtocolFixtureStrand::Sync,
            ProtocolFixtureStrand::Blob,
            ProtocolFixtureStrand::Authz,
            ProtocolFixtureStrand::Directory,
            ProtocolFixtureStrand::Push,
            ProtocolFixtureStrand::DeviceMessages,
            ProtocolFixtureStrand::Keys,
            ProtocolFixtureStrand::Policy,
            ProtocolFixtureStrand::Media,
            ProtocolFixtureStrand::Moderation,
            ProtocolFixtureStrand::Applet,
        ])
    }

    pub fn run(&self) -> Result<ProtocolFixtureReport> {
        let routes_by_operation: BTreeMap<_, _> = service_routes()
            .iter()
            .map(|route| (route.operation_id, route))
            .collect();
        let mut steps = Vec::new();
        for strand in &self.strands {
            for operation_id in fixture_operations(*strand) {
                let route = routes_by_operation.get(operation_id).ok_or_else(|| {
                    arkret_wire::Error::Protocol(format!(
                        "fixture operation '{operation_id}' is missing from service route registry"
                    ))
                })?;
                steps.push(ProtocolFixtureStep {
                    strand: *strand,
                    operation_id: (*operation_id).to_owned(),
                    method: route.method.to_owned(),
                    path: route.path.to_owned(),
                });
            }
        }
        Ok(ProtocolFixtureReport { steps })
    }
}

impl Default for ProtocolServerFixture {
    fn default() -> Self {
        Self::all_strands()
    }
}

fn fixture_operations(strand: ProtocolFixtureStrand) -> &'static [&'static str] {
    match strand {
        ProtocolFixtureStrand::Server => &[arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE],
        ProtocolFixtureStrand::Identity => &[
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_REGISTRY_READ_DESCRIBE,
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_READ_RESOLVE,
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET,
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_LOG_READ_LIST,
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION,
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECEIPTS_READ_LIST,
        ],
        ProtocolFixtureStrand::Sync => &[
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_READ_DESCRIBE,
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE,
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR,
            arkret_wire::ServiceOperationId::SELF_EVENTS_READ_DESCRIBE,
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
            arkret_wire::ServiceOperationId::SELF_EVENTS_RESOURCE_GET,
            arkret_wire::ServiceOperationId::SELF_EVENTS_READ_RESOLVE,
            arkret_wire::ServiceOperationId::SELF_EVENTS_READ_FRONTIER,
            arkret_wire::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
            arkret_wire::ServiceOperationId::SELF_EVENTS_READ_SCAN,
            arkret_wire::ServiceOperationId::SELF_SNAPSHOT_READ_MANIFEST_HEAD,
        ],
        ProtocolFixtureStrand::Blob => &[
            arkret_wire::ServiceOperationId::SELF_BLOB_UPLOAD_CREATE,
            arkret_wire::ServiceOperationId::SELF_BLOB_RESOURCE_HEAD,
            arkret_wire::ServiceOperationId::SELF_BLOB_RESOURCE_GET,
        ],
        ProtocolFixtureStrand::Authz => &[
            arkret_wire::ServiceOperationId::SELF_AUTHZ_GRANTS_READ_EFFECTIVE,
            arkret_wire::ServiceOperationId::SELF_AUTHZ_INVITES_READ_LIST,
            arkret_wire::ServiceOperationId::SELF_AUTHZ_READ_CHECK,
        ],
        ProtocolFixtureStrand::Directory => &[
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_DESCRIBE,
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS,
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM,
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS,
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION,
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ACTORS,
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_USERS,
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE,
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER,
        ],
        ProtocolFixtureStrand::Push => &[
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE,
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE,
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY,
        ],
        ProtocolFixtureStrand::DeviceMessages => &[
            arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND,
            arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST,
        ],
        ProtocolFixtureStrand::Keys => &[
            arkret_wire::ServiceOperationId::SELF_KEYS_UPLOAD_CREATE,
            arkret_wire::ServiceOperationId::SELF_KEYS_READ_LOOKUP,
            arkret_wire::ServiceOperationId::SELF_KEYS_COMMAND_CLAIM,
        ],
        ProtocolFixtureStrand::Policy => &[arkret_wire::ServiceOperationId::SELF_POLICY_READ_CHECK],
        ProtocolFixtureStrand::Media => {
            &[arkret_wire::ServiceOperationId::SELF_MEDIA_READ_ICE_CONFIG]
        }
        ProtocolFixtureStrand::Moderation => {
            &[arkret_wire::ServiceOperationId::SELF_MODERATION_COMMAND_REPORT]
        }
        ProtocolFixtureStrand::Applet => &[
            arkret_wire::ServiceOperationId::EDGE_APPLET_READ_PING,
            arkret_wire::ServiceOperationId::EDGE_APPLET_READ_DESCRIBE,
            arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION,
            arkret_wire::ServiceOperationId::EDGE_APPLET_ACTOR_READ_RESOLVE,
            arkret_wire::ServiceOperationId::EDGE_APPLET_REALM_READ_RESOLVE,
            arkret_wire::ServiceOperationId::EDGE_APPLET_READ_PROTOCOL_METADATA,
            arkret_wire::ServiceOperationId::EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST,
            arkret_wire::ServiceOperationId::EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST,
        ],
    }
}
