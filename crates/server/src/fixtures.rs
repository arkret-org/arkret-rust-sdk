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
pub enum ProtocolFixtureFlow {
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
    pub flow: ProtocolFixtureFlow,
    pub operation_id: String,
    pub method: String,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolFixtureReport {
    pub steps: Vec<ProtocolFixtureStep>,
}

impl ProtocolFixtureReport {
    pub fn covers(&self, flow: ProtocolFixtureFlow) -> bool {
        self.steps.iter().any(|step| step.flow == flow)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolServerFixture {
    flows: BTreeSet<ProtocolFixtureFlow>,
}

impl ProtocolServerFixture {
    pub fn new(flows: impl IntoIterator<Item = ProtocolFixtureFlow>) -> Self {
        Self { flows: flows.into_iter().collect() }
    }

    pub fn all_flows() -> Self {
        Self::new([
            ProtocolFixtureFlow::Server,
            ProtocolFixtureFlow::Identity,
            ProtocolFixtureFlow::Sync,
            ProtocolFixtureFlow::Blob,
            ProtocolFixtureFlow::Authz,
            ProtocolFixtureFlow::Directory,
            ProtocolFixtureFlow::Push,
            ProtocolFixtureFlow::DeviceMessages,
            ProtocolFixtureFlow::Keys,
            ProtocolFixtureFlow::Policy,
            ProtocolFixtureFlow::Media,
            ProtocolFixtureFlow::Moderation,
            ProtocolFixtureFlow::Applet,
        ])
    }

    pub fn run(&self) -> Result<ProtocolFixtureReport> {
        let routes_by_operation: BTreeMap<_, _> =
            service_routes().iter().map(|route| (route.operation_id, route)).collect();
        let mut steps = Vec::new();
        for flow in &self.flows {
            for operation_id in fixture_operations(*flow) {
                let route = routes_by_operation.get(operation_id).ok_or_else(|| {
                    cokret_core::Error::Protocol(format!(
                        "fixture operation '{operation_id}' is missing from service route registry"
                    ))
                })?;
                steps.push(ProtocolFixtureStep {
                    flow: *flow,
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
        Self::all_flows()
    }
}

fn fixture_operations(flow: ProtocolFixtureFlow) -> &'static [&'static str] {
    match flow {
        ProtocolFixtureFlow::Server => &["ck.server.describe"],
        ProtocolFixtureFlow::Identity => &[
            "ck.identity.describe_registry",
            "ck.identity.resolve",
            "ck.identity.get_document",
            "ck.identity.get_log",
            "ck.identity.submit_did_operation",
            "ck.identity.get_receipts",
        ],
        ProtocolFixtureFlow::Sync => &[
            "ck.account.describe",
            "ck.account.subscribe",
            "ck.account.cursor_revoke",
            "ck.events.describe",
            "ck.events.submit",
            "ck.events.get",
            "ck.events.resolve",
            "ck.events.frontier",
            "ck.events.subscribe",
            "ck.events.query",
            "ck.snapshot.head",
        ],
        ProtocolFixtureFlow::Blob => &["ck.blob.upload", "ck.blob.head", "ck.blob.get"],
        ProtocolFixtureFlow::Authz => {
            &["ck.authz.get_effective_grants", "ck.authz.get_invites", "ck.authz.check"]
        }
        ProtocolFixtureFlow::Directory => &[
            "ck.directory.describe",
            "ck.directory.search_realms",
            "ck.directory.resolve_realm",
            "ck.directory.search_organizations",
            "ck.directory.resolve_organization",
            "ck.directory.search_actors",
            "ck.directory.search_users",
            "ck.directory.resolve_handle",
            "ck.directory.push.register",
        ],
        ProtocolFixtureFlow::Push => {
            &["ck.push.register_device", "ck.push.unregister_device", "ck.push.notify"]
        }
        ProtocolFixtureFlow::DeviceMessages => {
            &["ck.device_messages.put", "ck.device_messages.get"]
        }
        ProtocolFixtureFlow::Keys => &["ck.keys.upload", "ck.keys.query", "ck.keys.claim"],
        ProtocolFixtureFlow::Policy => &["ck.policy.check"],
        ProtocolFixtureFlow::Media => &["ck.media.ice_config"],
        ProtocolFixtureFlow::Moderation => &["ck.moderation.report"],
        ProtocolFixtureFlow::Applet => &[
            "ck.applet.ping",
            "ck.applet.describe",
            "ck.applet.transaction",
            "ck.applet.resolve_actor",
            "ck.applet.resolve_realm",
            "ck.applet.protocol_metadata",
            "ck.applet.third_party_users",
            "ck.applet.third_party_locations",
        ],
    }
}
