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
        ProtocolFixtureStrand::Server => &["ak.server.read.describe"],
        ProtocolFixtureStrand::Identity => &[
            "ak.root.identity.registry.read.describe",
            "ak.root.identity.read.resolve",
            "ak.root.identity.document.resource.get",
            "ak.root.identity.log.read.list",
            "ak.root.identity.command.submit_did_operation",
            "ak.root.identity.receipts.read.list",
        ],
        ProtocolFixtureStrand::Sync => &[
            "ak.self.account.read.describe",
            "ak.self.account.stream.subscribe",
            "ak.self.account.command.revoke_cursor",
            "ak.self.events.read.describe",
            "ak.self.events.command.submit",
            "ak.self.events.resource.get",
            "ak.self.events.read.resolve",
            "ak.self.events.read.frontier",
            "ak.self.events.stream.subscribe",
            "ak.self.events.read.scan",
            "ak.self.snapshot.read.manifest_head",
        ],
        ProtocolFixtureStrand::Blob => &[
            "ak.self.blob.upload.create",
            "ak.self.blob.resource.head",
            "ak.self.blob.resource.get",
        ],
        ProtocolFixtureStrand::Authz => &[
            "ak.self.authz.grants.read.effective",
            "ak.self.authz.invites.read.list",
            "ak.self.authz.read.check",
        ],
        ProtocolFixtureStrand::Directory => &[
            "ak.find.directory.read.describe",
            "ak.find.directory.read.search_realms",
            "ak.find.directory.read.resolve_realm",
            "ak.find.directory.read.search_organizations",
            "ak.find.directory.read.resolve_organization",
            "ak.find.directory.read.search_actors",
            "ak.find.directory.read.search_users",
            "ak.find.directory.read.resolve_handle",
            "ak.find.directory.push.command.register",
        ],
        ProtocolFixtureStrand::Push => &[
            "ak.edge.push.command.register_device",
            "ak.edge.push.command.unregister_device",
            "ak.edge.push.command.notify",
        ],
        ProtocolFixtureStrand::DeviceMessages => &[
            "ak.self.device_messages.command.send",
            "ak.self.device_messages.read.list",
        ],
        ProtocolFixtureStrand::Keys => &[
            "ak.self.keys.upload.create",
            "ak.self.keys.read.lookup",
            "ak.self.keys.command.claim",
        ],
        ProtocolFixtureStrand::Policy => &["ak.self.policy.read.check"],
        ProtocolFixtureStrand::Media => &["ak.self.media.read.ice_config"],
        ProtocolFixtureStrand::Moderation => &["ak.self.moderation.command.report"],
        ProtocolFixtureStrand::Applet => &[
            "ak.edge.applet.read.ping",
            "ak.edge.applet.read.describe",
            "ak.edge.applet.command.transaction",
            "ak.edge.applet.actor.read.resolve",
            "ak.edge.applet.realm.read.resolve",
            "ak.edge.applet.read.protocol_metadata",
            "ak.edge.applet.third_party_users.read.list",
            "ak.edge.applet.third_party_locations.read.list",
        ],
    }
}
