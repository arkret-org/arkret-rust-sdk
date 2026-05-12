use super::*;

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
    #[serde(alias = "expected_errcode")]
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
    pub request_schema: String,
    pub response_schema: String,
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
        let contracts_by_operation: BTreeMap<_, _> =
            endpoint_contracts().iter().map(|contract| (contract.operation_id, contract)).collect();
        let mut steps = Vec::new();
        for flow in &self.flows {
            for operation_id in fixture_operations(*flow) {
                let contract = contracts_by_operation.get(operation_id).ok_or_else(|| {
                    contrix_core::Error::Protocol(format!(
                        "fixture operation '{operation_id}' is missing from endpoint registry"
                    ))
                })?;
                let binding = endpoint_schema_binding(contract);
                steps.push(ProtocolFixtureStep {
                    flow: *flow,
                    operation_id: (*operation_id).to_owned(),
                    method: contract.method.as_str().to_owned(),
                    path: contract.path.to_owned(),
                    request_schema: binding.request_schema.to_owned(),
                    response_schema: binding.response_schema.to_owned(),
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
        ProtocolFixtureFlow::Server => &["cx.server.describe"],
        ProtocolFixtureFlow::Identity => &[
            "cx.identity.describe_registry",
            "cx.identity.resolve",
            "cx.identity.get_document",
            "cx.identity.get_log",
            "cx.identity.submit_did_operation",
            "cx.identity.get_receipts",
        ],
        ProtocolFixtureFlow::Sync => &[
            "cx.sync.account",
            "cx.events.describe",
            "cx.events.submit",
            "cx.events.get",
            "cx.events.batch_get",
            "cx.events.frontier",
            "cx.events.subscribe",
            "cx.events.query",
            "cx.sync.get_snapshot_head",
        ],
        ProtocolFixtureFlow::Blob => &["cx.blob.upload", "cx.blob.head", "cx.blob.get"],
        ProtocolFixtureFlow::Authz => {
            &["cx.authz.get_effective_grants", "cx.authz.get_invites", "cx.authz.check"]
        }
        ProtocolFixtureFlow::Directory => &[
            "cx.directory.describe",
            "cx.directory.search_spaces",
            "cx.directory.resolve_space",
            "cx.directory.search_organizations",
            "cx.directory.resolve_organization",
            "cx.directory.search_actors",
            "cx.directory.search_users",
            "cx.directory.resolve_handle",
        ],
        ProtocolFixtureFlow::Push => {
            &["cx.push.register_device", "cx.push.unregister_device", "cx.push.notify"]
        }
        ProtocolFixtureFlow::DeviceMessages => {
            &["cx.device_messages.put", "cx.device_messages.get"]
        }
        ProtocolFixtureFlow::Keys => &["cx.keys.upload", "cx.keys.query", "cx.keys.claim"],
        ProtocolFixtureFlow::Policy => &["cx.policy.check"],
        ProtocolFixtureFlow::Media => &["cx.media.ice_config"],
        ProtocolFixtureFlow::Moderation => &["cx.moderation.report"],
        ProtocolFixtureFlow::Applet => &[
            "cx.applet.ping",
            "cx.applet.describe",
            "cx.applet.transaction",
            "cx.applet.query_actor",
            "cx.applet.query_space",
            "cx.applet.protocol_metadata",
            "cx.applet.third_party_users",
            "cx.applet.third_party_locations",
        ],
    }
}
