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
        Self {
            flows: flows.into_iter().collect(),
        }
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
        let routes_by_operation: BTreeMap<_, _> = service_routes()
            .iter()
            .map(|route| (route.operation_id, route))
            .collect();
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
        ProtocolFixtureFlow::Server => &["ck.server.query.describe"],
        ProtocolFixtureFlow::Identity => &[
            "ck.root.identity.registry.query.describe",
            "ck.root.identity.query.resolve",
            "ck.root.identity.document.resource.get",
            "ck.root.identity.log.query.list",
            "ck.root.identity.command.submit_did_operation",
            "ck.root.identity.receipts.query.list",
        ],
        ProtocolFixtureFlow::Sync => &[
            "ck.self.account.query.describe",
            "ck.self.account.stream.subscribe",
            "ck.self.account.command.revoke_cursor",
            "ck.self.events.query.describe",
            "ck.self.events.command.submit",
            "ck.self.events.resource.get",
            "ck.self.events.query.resolve",
            "ck.self.events.query.frontier",
            "ck.self.events.stream.subscribe",
            "ck.self.events.query.scan",
            "ck.self.snapshot.query.manifest_head",
        ],
        ProtocolFixtureFlow::Blob => &[
            "ck.self.blob.upload.create",
            "ck.self.blob.resource.head",
            "ck.self.blob.resource.get",
        ],
        ProtocolFixtureFlow::Authz => &[
            "ck.self.authz.grants.query.effective",
            "ck.self.authz.invites.query.list",
            "ck.self.authz.query.check",
        ],
        ProtocolFixtureFlow::Directory => &[
            "ck.find.directory.query.describe",
            "ck.find.directory.query.search_realms",
            "ck.find.directory.query.resolve_realm",
            "ck.find.directory.query.search_organizations",
            "ck.find.directory.query.resolve_organization",
            "ck.find.directory.query.search_actors",
            "ck.find.directory.query.search_users",
            "ck.find.directory.query.resolve_handle",
            "ck.find.directory.push.command.register",
        ],
        ProtocolFixtureFlow::Push => &[
            "ck.edge.push.command.register_device",
            "ck.edge.push.command.unregister_device",
            "ck.edge.push.command.notify",
        ],
        ProtocolFixtureFlow::DeviceMessages => &[
            "ck.self.device_messages.command.send",
            "ck.self.device_messages.query.list",
        ],
        ProtocolFixtureFlow::Keys => &[
            "ck.self.keys.upload.create",
            "ck.self.keys.query.lookup",
            "ck.self.keys.command.claim",
        ],
        ProtocolFixtureFlow::Policy => &["ck.self.policy.query.check"],
        ProtocolFixtureFlow::Media => &["ck.self.media.query.ice_config"],
        ProtocolFixtureFlow::Moderation => &["ck.self.moderation.command.report"],
        ProtocolFixtureFlow::Applet => &[
            "ck.edge.applet.query.ping",
            "ck.edge.applet.query.describe",
            "ck.edge.applet.command.transaction",
            "ck.edge.applet.actor.query.resolve",
            "ck.edge.applet.realm.query.resolve",
            "ck.edge.applet.query.protocol_metadata",
            "ck.edge.applet.third_party_users.query.list",
            "ck.edge.applet.third_party_locations.query.list",
        ],
    }
}
