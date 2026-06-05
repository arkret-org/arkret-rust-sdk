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
            "ck.root.identity.describe_registry",
            "ck.root.identity.resolve",
            "ck.root.identity.get_document",
            "ck.root.identity.get_log",
            "ck.root.identity.submit_did_operation",
            "ck.root.identity.get_receipts",
        ],
        ProtocolFixtureFlow::Sync => &[
            "ck.self.account.describe",
            "ck.self.account.subscribe",
            "ck.self.account.cursor_revoke",
            "ck.self.events.describe",
            "ck.self.events.submit",
            "ck.self.events.get",
            "ck.self.events.resolve",
            "ck.self.events.frontier",
            "ck.self.events.subscribe",
            "ck.self.events.query",
            "ck.self.snapshot.head",
        ],
        ProtocolFixtureFlow::Blob => &["ck.self.blob.upload", "ck.self.blob.head", "ck.self.blob.get"],
        ProtocolFixtureFlow::Authz => {
            &["ck.self.authz.get_effective_grants", "ck.self.authz.get_invites", "ck.self.authz.check"]
        }
        ProtocolFixtureFlow::Directory => &[
            "ck.find.directory.describe",
            "ck.find.directory.search_realms",
            "ck.find.directory.resolve_realm",
            "ck.find.directory.search_organizations",
            "ck.find.directory.resolve_organization",
            "ck.find.directory.search_actors",
            "ck.find.directory.search_users",
            "ck.find.directory.resolve_handle",
            "ck.find.directory.push.register",
        ],
        ProtocolFixtureFlow::Push => {
            &["ck.edge.push.register_device", "ck.edge.push.unregister_device", "ck.edge.push.notify"]
        }
        ProtocolFixtureFlow::DeviceMessages => {
            &["ck.self.device_messages.put", "ck.self.device_messages.get"]
        }
        ProtocolFixtureFlow::Keys => &["ck.self.keys.upload", "ck.self.keys.query", "ck.self.keys.claim"],
        ProtocolFixtureFlow::Policy => &["ck.self.policy.check"],
        ProtocolFixtureFlow::Media => &["ck.self.media.ice_config"],
        ProtocolFixtureFlow::Moderation => &["ck.self.moderation.report"],
        ProtocolFixtureFlow::Applet => &[
            "ck.edge.applet.ping",
            "ck.edge.applet.describe",
            "ck.edge.applet.transaction",
            "ck.edge.applet.resolve_actor",
            "ck.edge.applet.resolve_realm",
            "ck.edge.applet.protocol_metadata",
            "ck.edge.applet.third_party_users",
            "ck.edge.applet.third_party_locations",
        ],
    }
}
