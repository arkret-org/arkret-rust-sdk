use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use regex_lite::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::model::LoadedArtifact;
use crate::render::{associated_name, header, option_string, rust_string, string_slice, variant};
use crate::runtime_contracts::GeneratedOutput;

struct Artifact {
    source: LoadedArtifact,
    value: Value,
}

impl Artifact {
    fn load(artifacts_dir: &Path, relative_path: &'static str) -> Result<Self> {
        let (source, value) = LoadedArtifact::read(artifacts_dir, relative_path)?;
        Ok(Self { source, value })
    }

    fn array(&self, key: &str) -> Result<Vec<&Map<String, Value>>> {
        self.value
            .get(key)
            .and_then(Value::as_array)
            .with_context(|| format!("{} missing {key} array", self.source.relative_path))?
            .iter()
            .map(|value| {
                value.as_object().with_context(|| {
                    format!("{} {key} entry is not an object", self.source.relative_path)
                })
            })
            .collect()
    }

    fn section_array(&self, section: &str, key: &str) -> Result<Vec<&Map<String, Value>>> {
        self.value
            .get(section)
            .and_then(Value::as_object)
            .with_context(|| format!("{} missing {section} object", self.source.relative_path))?
            .get(key)
            .and_then(Value::as_array)
            .with_context(|| {
                format!(
                    "{} missing {section}.{key} array",
                    self.source.relative_path
                )
            })?
            .iter()
            .map(|value| {
                value.as_object().with_context(|| {
                    format!(
                        "{} {section}.{key} entry is not an object",
                        self.source.relative_path
                    )
                })
            })
            .collect()
    }

    fn with_section_version(mut self, section: &str) -> Result<Self> {
        self.source.version = self
            .value
            .get(section)
            .and_then(Value::as_object)
            .with_context(|| format!("{} missing {section} object", self.source.relative_path))?
            .get("version")
            .and_then(Value::as_str)
            .with_context(|| {
                format!(
                    "{} missing {section}.version string",
                    self.source.relative_path
                )
            })?
            .to_owned();
        Ok(self)
    }
}

fn field<'a>(row: &'a Map<String, Value>, key: &str) -> Result<&'a Value> {
    row.get(key).with_context(|| format!("missing field {key}"))
}

fn string<'a>(row: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    field(row, key)?
        .as_str()
        .with_context(|| format!("field {key} is not a string"))
}

fn strings(row: &Map<String, Value>, key: &str) -> Result<Vec<String>> {
    field(row, key)?
        .as_array()
        .with_context(|| format!("field {key} is not an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("field {key} contains a non-string"))
        })
        .collect()
}

fn sorted_rows<'a>(
    mut rows: Vec<&'a Map<String, Value>>,
    key: &str,
) -> Result<Vec<&'a Map<String, Value>>> {
    for row in &rows {
        string(row, key)?;
    }
    rows.sort_by(|left, right| string(left, key).unwrap().cmp(string(right, key).unwrap()));
    Ok(rows)
}

fn validate_unique(rows: &[&Map<String, Value>], key: &str, prefixes: &[&str]) -> Result<()> {
    let mut names = std::collections::BTreeMap::new();
    for row in rows {
        let value = string(row, key)?;
        let name = variant(value, prefixes);
        if let Some(previous) = names.insert(name.clone(), value) {
            bail!("variant collision {name:?}: {previous:?} and {value:?}");
        }
    }
    Ok(())
}

fn validate_operation_transport_bindings(rows: &[&Map<String, Value>]) -> Result<()> {
    let mut grpc_bindings = BTreeMap::new();
    let mut mq_topics = BTreeMap::new();

    for row in rows {
        let operation_id = string(row, "operation_id")?;
        let http_only = match row.get("http_only_variant") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => bail!("{operation_id} http_only_variant is not a boolean"),
        };
        let grpc = match row.get("grpc") {
            None => None,
            Some(Value::String(value)) if !value.is_empty() => Some(value.as_str()),
            Some(Value::String(_)) => bail!("{operation_id} has an empty grpc binding"),
            Some(_) => bail!("{operation_id} grpc binding is not a string"),
        };
        let mq = match row.get("mq") {
            None => None,
            Some(Value::String(value)) if !value.is_empty() => Some(value.as_str()),
            Some(Value::String(_)) => bail!("{operation_id} has an empty mq topic"),
            Some(_) => bail!("{operation_id} mq topic is not a string"),
        };

        if http_only {
            if grpc.is_some() || mq.is_some() {
                bail!("{operation_id} is http-only and must not declare grpc/mq bindings");
            }
            continue;
        }
        let grpc = grpc.with_context(|| format!("{operation_id} is missing grpc binding"))?;
        let mq = mq.with_context(|| format!("{operation_id} is missing mq topic"))?;
        let (service, method) = grpc
            .split_once('/')
            .with_context(|| format!("{operation_id} grpc binding lacks Service/Method"))?;
        if service.is_empty() || method.is_empty() || method.contains('/') {
            bail!("{operation_id} grpc binding must be exactly non-empty Service/Method");
        }
        if grpc_bindings.insert(grpc, operation_id).is_some() {
            bail!("duplicate grpc binding {grpc}");
        }
        if mq_topics.insert(mq, operation_id).is_some() {
            bail!("duplicate mq topic {mq}");
        }
    }
    Ok(())
}

pub fn generate(artifacts_dir: &Path) -> Result<Vec<GeneratedOutput>> {
    Ok(vec![
        generate_digest_suite_codes(artifacts_dir)?,
        generate_error_codes(artifacts_dir)?,
        generate_reason_codes(artifacts_dir)?,
        generate_operation_errors(artifacts_dir)?,
        generate_capability_discovery(artifacts_dir)?,
        generate_security_strings(artifacts_dir)?,
        generate_operations(artifacts_dir)?,
        generate_service_kinds(artifacts_dir)?,
        generate_relation_kinds(artifacts_dir)?,
        generate_capability_actions(artifacts_dir)?,
        generate_schema_ids(artifacts_dir)?,
        generate_profile_ids(artifacts_dir)?,
        generate_did_freshness_profiles(artifacts_dir)?,
        generate_did_method_adapters(artifacts_dir)?,
        generate_authority_sources(artifacts_dir)?,
        generate_closed_registry_types(artifacts_dir)?,
        generate_account_data_keys(artifacts_dir)?,
        generate_service_contract_ids(artifacts_dir)?,
        generate_device_message_kinds(artifacts_dir)?,
        generate_authority_set_ids(artifacts_dir)?,
        generate_redactable_fields(artifacts_dir)?,
        generate_reducer_managed_patch_paths(artifacts_dir)?,
        generate_forbidden_wire_fields(artifacts_dir)?,
        generate_mls_creator_bootstrap(artifacts_dir)?,
        generate_preimage_commitments(artifacts_dir)?,
    ])
}

const PREIMAGE_COMMITMENT_KEYWORD: &str = "x-arkret-preimage-commitment";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PreimageCommitmentEntry {
    schema_file: String,
    json_pointer: String,
    commitment: String,
}

#[derive(Default)]
struct SchemaRepository {
    documents: BTreeMap<String, Value>,
    bytes: BTreeMap<String, Vec<u8>>,
}

impl SchemaRepository {
    fn load_document(&mut self, artifacts_dir: &Path, file: &str) -> Result<&Value> {
        if !self.documents.contains_key(file) {
            let path = artifacts_dir.join(file);
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let document = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse {}", path.display()))?;
            self.bytes.insert(file.to_owned(), bytes);
            self.documents.insert(file.to_owned(), document);
        }
        Ok(self.documents.get(file).expect("document was inserted"))
    }

    fn load_node(&mut self, artifacts_dir: &Path, file: &str, pointer: &str) -> Result<Value> {
        let document = self.load_document(artifacts_dir, file)?;
        if pointer.is_empty() {
            return Ok(document.clone());
        }
        document
            .pointer(pointer)
            .cloned()
            .with_context(|| format!("{file} has no JSON Pointer #{pointer}"))
    }

    fn aggregate_source(&self) -> LoadedArtifact {
        let mut digest = Sha256::new();
        for (path, bytes) in &self.bytes {
            digest.update(path.as_bytes());
            digest.update([0]);
            digest.update(bytes);
            digest.update([0]);
        }
        LoadedArtifact {
            relative_path: "reachable event schema closure",
            version: "aggregate".to_owned(),
            digest: hex::encode(digest.finalize()),
        }
    }
}

fn normalize_schema_file(base_file: Option<&str>, raw_file: &str) -> Result<String> {
    let raw_file = raw_file
        .strip_prefix("https://arkret.org/v1/")
        .unwrap_or(raw_file);
    let joined = if raw_file.is_empty() {
        PathBuf::from(base_file.context("a fragment-only $ref has no base schema")?)
    } else if raw_file.starts_with("schemas/") {
        PathBuf::from(raw_file)
    } else {
        let base = base_file.context("a relative $ref has no base schema")?;
        Path::new(base)
            .parent()
            .context("base schema has no parent")?
            .join(raw_file)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("schema reference escapes the artifact root: {raw_file}");
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                bail!("schema reference must stay relative to the artifact root: {raw_file}")
            }
        }
    }
    Ok(normalized.to_string_lossy().replace('\\', "/"))
}

fn parse_schema_ref(base_file: Option<&str>, schema_ref: &str) -> Result<(String, String)> {
    let (raw_file, fragment) = schema_ref.split_once('#').unwrap_or((schema_ref, ""));
    let file = normalize_schema_file(base_file, raw_file)?;
    let pointer = match fragment {
        "" => String::new(),
        value if value.starts_with('/') => value.to_owned(),
        _ => bail!("schema reference fragment must be an RFC 6901 JSON Pointer: {schema_ref}"),
    };
    Ok((file, pointer))
}

fn visit_preimage_schema(
    artifacts_dir: &Path,
    repository: &mut SchemaRepository,
    file: &str,
    pointer: &str,
    node: Value,
    seen: &mut BTreeSet<(String, String)>,
    found: &mut BTreeSet<(String, String, String)>,
) -> Result<()> {
    if !seen.insert((file.to_owned(), pointer.to_owned())) {
        return Ok(());
    }
    let Some(object) = node.as_object() else {
        return Ok(());
    };
    if let Some(commitment) = object.get(PREIMAGE_COMMITMENT_KEYWORD) {
        let commitment = commitment.as_str().with_context(|| {
            format!("{file}#{pointer} {PREIMAGE_COMMITMENT_KEYWORD} is not a string")
        })?;
        if !matches!(
            commitment,
            "envelope_omission"
                | "fixed_event"
                | "later_submission"
                | "no_event_identity"
                | "same_unit_sibling"
                | "self_identity"
        ) {
            bail!("{file}#{pointer} has unknown preimage commitment {commitment:?}");
        }
        found.insert((file.to_owned(), pointer.to_owned(), commitment.to_owned()));
    }
    if let Some(reference) = object.get("$ref") {
        let reference = reference
            .as_str()
            .with_context(|| format!("{file}#{pointer} $ref is not a string"))?;
        let (target_file, target_pointer) = parse_schema_ref(Some(file), reference)?;
        let target = repository.load_node(artifacts_dir, &target_file, &target_pointer)?;
        visit_preimage_schema(
            artifacts_dir,
            repository,
            &target_file,
            &target_pointer,
            target,
            seen,
            found,
        )?;
    }

    for keyword in [
        "items",
        "contains",
        "additionalProperties",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
        "unevaluatedProperties",
    ] {
        if let Some(child) = object.get(keyword).filter(|value| value.is_object()) {
            let child_pointer = format!("{pointer}/{keyword}");
            visit_preimage_schema(
                artifacts_dir,
                repository,
                file,
                &child_pointer,
                child.clone(),
                seen,
                found,
            )?;
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = object.get(keyword).and_then(Value::as_array) {
            for (index, child) in children.iter().enumerate() {
                let child_pointer = format!("{pointer}/{keyword}/{index}");
                visit_preimage_schema(
                    artifacts_dir,
                    repository,
                    file,
                    &child_pointer,
                    child.clone(),
                    seen,
                    found,
                )?;
            }
        }
    }
    for keyword in ["properties", "patternProperties", "dependentSchemas"] {
        if let Some(children) = object.get(keyword).and_then(Value::as_object) {
            for (name, child) in children {
                let escaped = name.replace('~', "~0").replace('/', "~1");
                let child_pointer = format!("{pointer}/{keyword}/{escaped}");
                visit_preimage_schema(
                    artifacts_dir,
                    repository,
                    file,
                    &child_pointer,
                    child.clone(),
                    seen,
                    found,
                )?;
            }
        }
    }
    Ok(())
}

fn collect_preimage_commitments(
    artifacts_dir: &Path,
    repository: &mut SchemaRepository,
    root_schema_ref: &str,
) -> Result<BTreeSet<(String, String, String)>> {
    let (file, pointer) = parse_schema_ref(None, root_schema_ref)?;
    let root = repository.load_node(artifacts_dir, &file, &pointer)?;
    let mut found = BTreeSet::new();
    visit_preimage_schema(
        artifacts_dir,
        repository,
        &file,
        &pointer,
        root,
        &mut BTreeSet::new(),
        &mut found,
    )?;
    Ok(found)
}

fn generate_preimage_commitments(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let event_kinds = Artifact::load(artifacts_dir, "registry/contract-registry.json")?
        .with_section_version("event_kind_registry")?;
    let mut repository = SchemaRepository::default();
    let mut roots = BTreeSet::from(["schemas/event-envelope.schema.json".to_owned()]);
    for row in event_kinds.section_array("event_kind_registry", "event_kinds")? {
        roots.insert(string(row, "payload_schema_ref")?.to_owned());
    }
    let mut found = BTreeSet::new();
    for root in roots {
        found.extend(collect_preimage_commitments(
            artifacts_dir,
            &mut repository,
            &root,
        )?);
    }
    let entries = found
        .into_iter()
        .map(
            |(schema_file, json_pointer, commitment)| PreimageCommitmentEntry {
                schema_file,
                json_pointer,
                commitment,
            },
        )
        .collect::<BTreeSet<_>>();
    let schema_source = repository.aggregate_source();
    let mut output = header(
        &[&event_kinds.source, &schema_source],
        &format!("preimage_commitments={}", entries.len()),
    );
    output.push_str(
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n\
pub enum PreimageCommitment {\n\
    EnvelopeOmission,\n\
    FixedEvent,\n\
    LaterSubmission,\n\
    NoEventIdentity,\n\
    SameUnitSibling,\n\
    SelfIdentity,\n\
}\n\n\
#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n\
pub struct PreimageCommitmentField {\n\
    pub schema_file: &'static str,\n\
    pub json_pointer: &'static str,\n\
    pub commitment: PreimageCommitment,\n\
}\n\n\
pub const PREIMAGE_COMMITMENT_FIELDS: &[PreimageCommitmentField] = &[\n",
    );
    for entry in entries {
        let variant = match entry.commitment.as_str() {
            "envelope_omission" => "EnvelopeOmission",
            "fixed_event" => "FixedEvent",
            "later_submission" => "LaterSubmission",
            "no_event_identity" => "NoEventIdentity",
            "same_unit_sibling" => "SameUnitSibling",
            "self_identity" => "SelfIdentity",
            _ => unreachable!("commitments were validated while traversing"),
        };
        writeln!(
            output,
            "    PreimageCommitmentField {{ schema_file: {}, json_pointer: {}, commitment: PreimageCommitment::{variant} }},",
            rust_string(&entry.schema_file),
            rust_string(&entry.json_pointer),
        )?;
    }
    output.push_str(
        "];\n\n\
pub fn preimage_commitment_at(\n\
    schema_file: &str,\n\
    json_pointer: &str,\n\
) -> Option<PreimageCommitment> {\n\
    PREIMAGE_COMMITMENT_FIELDS.iter().find(|field| {\n\
        field.schema_file == schema_file && field.json_pointer == json_pointer\n\
    }).map(|field| field.commitment)\n\
}\n\n\
#[cfg(test)]\n\
mod tests {\n\
    use super::*;\n\n\
    #[test]\n\
    fn generated_commitments_are_unique_and_queryable_by_exact_pointer() {\n\
        for (index, field) in PREIMAGE_COMMITMENT_FIELDS.iter().enumerate() {\n\
            assert_eq!(\n\
                preimage_commitment_at(field.schema_file, field.json_pointer),\n\
                Some(field.commitment)\n\
            );\n\
            assert!(!PREIMAGE_COMMITMENT_FIELDS[..index].iter().any(|earlier| {\n\
                earlier.schema_file == field.schema_file\n\
                    && earlier.json_pointer == field.json_pointer\n\
            }));\n\
        }\n\
        assert_eq!(\n\
            preimage_commitment_at(\n\
                \"schemas/event-envelope.schema.json\",\n\
                \"/properties/event_id\"\n\
            ),\n\
            Some(PreimageCommitment::EnvelopeOmission)\n\
        );\n\
        assert_eq!(\n\
            preimage_commitment_at(\n\
                \"schemas/agent-provision.schema.json\",\n\
                \"/properties/principal_control_realm_id\"\n\
            ),\n\
            Some(PreimageCommitment::LaterSubmission)\n\
        );\n\
    }\n\
}\n",
    );
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/preimage_commitments.rs".into(),
        contents: output,
    })
}

fn option_usize(value: Option<&Value>, label: &str) -> Result<String> {
    match value {
        None | Some(Value::Null) => Ok("None".to_owned()),
        Some(value) => Ok(format!(
            "Some({})",
            value
                .as_u64()
                .with_context(|| format!("{label} is not an unsigned integer"))?
        )),
    }
}

fn option_bool(value: Option<&Value>, label: &str) -> Result<String> {
    match value {
        None | Some(Value::Null) => Ok("None".to_owned()),
        Some(value) => Ok(format!(
            "Some({})",
            value
                .as_bool()
                .with_context(|| format!("{label} is not boolean"))?
        )),
    }
}

fn durable_effect(row: &Map<String, Value>) -> Result<String> {
    let Some(value) = row.get("durable_effect") else {
        return Ok("None".to_owned());
    };
    if value.is_null() {
        return Ok("None".to_owned());
    }
    let durable = value
        .as_object()
        .context("durable_effect is not an object")?;
    match string(durable, "kind")? {
        "event_log" => {
            let target = if let Some(values) = durable.get("event_kinds") {
                let values = values
                    .as_array()
                    .context("event_kinds is not an array")?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .context("event_kind is not a string")
                            .map(str::to_owned)
                    })
                    .collect::<Result<Vec<_>>>()?;
                format!(
                    "Some(DurableEventTarget::Static({}))",
                    string_slice(&values)
                )
            } else if let Some(source) = durable.get("event_kind_source").and_then(Value::as_str) {
                format!("Some(DurableEventTarget::Dynamic({}))", rust_string(source))
            } else if let Some(sources) =
                durable.get("event_kind_sources").and_then(Value::as_array)
            {
                let sources = sources
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .context("event kind source is not a string")
                            .map(str::to_owned)
                    })
                    .collect::<Result<Vec<_>>>()?;
                if sources.is_empty() {
                    bail!("event_log durable effect has empty event_kind_sources");
                }
                format!(
                    "Some(DurableEventTarget::DynamicMany({}))",
                    string_slice(&sources)
                )
            } else {
                bail!("event_log durable effect needs a target");
            };
            Ok(format!(
                "Some(DurableEffectDescriptor {{ kind: DurableEffectKind::EventLog, target: {target}, rationale: None, branch_contract_json: None }})"
            ))
        }
        "actor_private_event" => {
            let event_kind = string(durable, "event_kind")?;
            Ok(format!(
                "Some(DurableEffectDescriptor {{ kind: DurableEffectKind::ActorPrivateEvent, target: Some(DurableEventTarget::Static(&[{}])), rationale: None, branch_contract_json: None }})",
                rust_string(event_kind)
            ))
        }
        "none" => Ok(format!(
            "Some(DurableEffectDescriptor {{ kind: DurableEffectKind::None, target: None, rationale: Some({}), branch_contract_json: None }})",
            rust_string(string(durable, "rationale")?)
        )),
        "branched" => {
            let discriminator = field(durable, "discriminator")?;
            let branches = field(durable, "effect_branches")?;
            if !discriminator.is_object() || !branches.is_array() {
                bail!("branched durable effect needs discriminator and effect_branches");
            }
            let contract = serde_json::to_string(&serde_json::json!({
                "discriminator": discriminator,
                "effect_branches": branches,
            }))?;
            Ok(format!(
                "Some(DurableEffectDescriptor {{ kind: DurableEffectKind::Branched, target: None, rationale: None, branch_contract_json: Some({}) }})",
                rust_string(&contract)
            ))
        }
        kind => bail!("unsupported durable effect kind {kind}"),
    }
}

fn generate_operations(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/contract-registry.json")?
        .with_section_version("operation_registry")?;
    let rows = sorted_rows(
        artifact.section_array("operation_registry", "operations")?,
        "operation_id",
    )?;
    validate_unique(&rows, "operation_id", &["ak."])?;
    validate_operation_transport_bindings(&rows)?;
    let mut output = header(&[&artifact.source], &format!("registered={}", rows.len()));
    output.push_str("use serde::{Deserialize, Serialize};\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\n#[repr(usize)]\npub enum ServiceOperationId {\n");
    for row in &rows {
        writeln!(
            output,
            "    {},",
            variant(string(row, "operation_id")?, &["ak."])
        )?;
    }
    output.push_str("}\n\npub const REGISTERED_SERVICE_OPERATION_IDS: &[&str] = &[\n");
    for row in &rows {
        writeln!(
            output,
            "    ServiceOperationId::{},",
            associated_name(string(row, "operation_id")?, &["ak."])
        )?;
    }
    output.push_str("];\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub enum DurableEffectKind { EventLog, ActorPrivateEvent, Branched, None }\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub enum DurableEventTarget { Static(&'static [&'static str]), Dynamic(&'static str), DynamicMany(&'static [&'static str]) }\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct DurableEffectDescriptor { pub kind: DurableEffectKind, pub target: Option<DurableEventTarget>, pub rationale: Option<&'static str>, pub branch_contract_json: Option<&'static str> }\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ServiceOperationDescriptor { pub id: ServiceOperationId, pub http_method: &'static str, pub http_path: &'static str, pub grpc: Option<&'static str>, pub mq: Option<&'static str>, pub body_class: Option<&'static str>, pub max_canonical_body_bytes: Option<usize>, pub success_shape_kind: &'static str, pub idempotency_mechanism: Option<&'static str>, pub retry_safe: Option<bool>, pub request_schema_ref: Option<&'static str>, pub response_schema_ref: Option<&'static str>, pub uncertain_outcome: Option<&'static str>, pub durable_effect: Option<DurableEffectDescriptor> }\n\nimpl ServiceOperationId {\n    pub const ALL: &'static [Self] = &[\n");
    for row in &rows {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "operation_id")?, &["ak."])
        )?;
    }
    output.push_str("    ];\n\n");
    for row in &rows {
        let id = string(row, "operation_id")?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            associated_name(id, &["ak."]),
            rust_string(id)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str { match self {\n");
    for row in &rows {
        let id = string(row, "operation_id")?;
        writeln!(
            output,
            "        Self::{} => Self::{},",
            variant(id, &["ak."]),
            associated_name(id, &["ak."])
        )?;
    }
    output
        .push_str("    } }\n\n    pub fn from_wire(value: &str) -> Option<Self> { match value {\n");
    for row in &rows {
        let id = string(row, "operation_id")?;
        writeln!(
            output,
            "        Self::{} => Some(Self::{}),",
            associated_name(id, &["ak."]),
            variant(id, &["ak."])
        )?;
    }
    output.push_str("        _ => None,\n    } }\n\n    pub fn from_grpc(value: &str) -> Option<Self> {\n        SERVICE_OPERATION_DESCRIPTORS.iter().find(|descriptor| descriptor.grpc == Some(value)).map(|descriptor| descriptor.id)\n    }\n\n    pub fn from_mq_topic(value: &str) -> Option<Self> {\n        SERVICE_OPERATION_DESCRIPTORS.iter().find(|descriptor| descriptor.mq == Some(value)).map(|descriptor| descriptor.id)\n    }\n\n    pub fn from_http_request(method: &str, path: &str) -> Option<Self> {\n        let specificity = SERVICE_OPERATION_DESCRIPTORS.iter().filter(|descriptor| descriptor.http_method == method && http_path_template_matches(descriptor.http_path, path)).map(|descriptor| descriptor.http_path.bytes().filter(|byte| *byte == b'{').count()).min()?;\n        let mut matches = SERVICE_OPERATION_DESCRIPTORS.iter().filter(|descriptor| descriptor.http_method == method && http_path_template_matches(descriptor.http_path, path) && descriptor.http_path.bytes().filter(|byte| *byte == b'{').count() == specificity);\n        let selected = matches.next()?.id;\n        matches.next().is_none().then_some(selected)\n    }\n\n    pub fn matches_http_request(self, method: &str, path: &str) -> bool { let descriptor = self.descriptor(); descriptor.http_method == method && http_path_template_matches(descriptor.http_path, path) }\n    pub fn descriptor(self) -> &'static ServiceOperationDescriptor { &SERVICE_OPERATION_DESCRIPTORS[self as usize] }\n}\n\nimpl std::fmt::Display for ServiceOperationId { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) } }\nimpl Serialize for ServiceOperationId { fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(self.as_str()) } }\nimpl<'de> Deserialize<'de> for ServiceOperationId { fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> { let raw = String::deserialize(deserializer)?; Self::from_wire(&raw).ok_or_else(|| serde::de::Error::custom(format!(\"unknown service operation id: {raw}\"))) } }\n\n#[cfg(feature = \"openapi\")]\nimpl salvo_oapi::ToSchema for ServiceOperationId {\n    fn to_schema(_components: &mut salvo_oapi::Components) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {\n        salvo_oapi::schema::Object::new().schema_type(salvo_oapi::schema::BasicType::String).enum_values(Self::ALL.iter().map(|value| value.as_str())).into()\n    }\n}\n\n#[cfg(feature = \"openapi\")]\nimpl salvo_oapi::ComposeSchema for ServiceOperationId {\n    fn compose(components: &mut salvo_oapi::Components, generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {\n        let _ = generics;\n        <Self as salvo_oapi::ToSchema>::to_schema(components)\n    }\n}\n\npub const SERVICE_OPERATION_DESCRIPTORS: &[ServiceOperationDescriptor] = &[\n");
    for row in &rows {
        let http = string(row, "http")?;
        let (method, path) = http
            .split_once(' ')
            .context("operation http field lacks method/path separator")?;
        let uncertain = match row.get("uncertain_outcome") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) => Some(value.clone()),
            Some(value @ (Value::Object(_) | Value::Array(_))) => {
                Some(serde_json::to_string(value)?)
            }
            Some(_) => bail!("uncertain_outcome has unsupported type"),
        };
        writeln!(
            output,
            "    ServiceOperationDescriptor {{\n        id: ServiceOperationId::{},\n        http_method: {},\n        http_path: {},\n        grpc: {},\n        mq: {},\n        body_class: {},\n        max_canonical_body_bytes: {},\n        success_shape_kind: {},\n        idempotency_mechanism: {},\n        retry_safe: {},\n        request_schema_ref: {},\n        response_schema_ref: {},\n        uncertain_outcome: {},\n        durable_effect: {},\n    }},",
            variant(string(row, "operation_id")?, &["ak."]),
            rust_string(method),
            rust_string(path),
            option_string(row.get("grpc").and_then(Value::as_str)),
            option_string(row.get("mq").and_then(Value::as_str)),
            option_string(row.get("body_class").and_then(Value::as_str)),
            option_usize(
                row.get("max_canonical_body_bytes"),
                "max_canonical_body_bytes"
            )?,
            rust_string(string(row, "success_shape_kind")?),
            option_string(row.get("idempotency_mechanism").and_then(Value::as_str)),
            option_bool(row.get("retry_safe"), "retry_safe")?,
            option_string(row.get("request_schema_ref").and_then(Value::as_str)),
            option_string(row.get("response_schema_ref").and_then(Value::as_str)),
            option_string(uncertain.as_deref()),
            durable_effect(row)?
        )?;
    }
    output.push_str("];\n\nfn http_path_template_matches(template: &str, path: &str) -> bool {\n    let mut template_segments = template.split('/');\n    let mut path_segments = path.split('/');\n    loop { match (template_segments.next(), path_segments.next()) {\n        (None, None) => return true,\n        (Some(expected), Some(actual)) => { let placeholder = expected.starts_with('{') && expected.ends_with('}') && expected.len() > 2; if (placeholder && actual.is_empty()) || (!placeholder && expected != actual) { return false; } },\n        _ => return false,\n    } }\n}\n");
    output.push_str("impl ServiceOperationId {\n    pub fn wait_for_carrier(self, binding: &str) -> Option<(&'static str, &'static str)> {\n        match (self, binding) {\n");
    let waits = artifact.section_array("operation_registry", "wait_for_bindings")?;
    let mut seen = BTreeSet::new();
    for wait in waits {
        let operation = string(wait, "operation_id")?;
        let binding = string(wait, "binding_kind")?;
        if !seen.insert((operation, binding)) {
            bail!("duplicate wait-for operation/binding {operation} {binding}");
        }
        if !rows.iter().any(|row| row.get("operation_id").and_then(Value::as_str) == Some(operation)) {
            bail!("unregistered wait-for operation {operation}");
        }
        writeln!(output, "            (Self::{}, {}) => Some(({}, {})),",
            variant(operation, &["ak."]), rust_string(binding),
            rust_string(string(wait, "carrier")?), rust_string(string(wait, "field")?))?;
    }
    output.push_str("            _ => None,\n        }\n    }\n}\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/operation_ids.rs".into(),
        contents: output,
    })
}

fn generate_operation_errors(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let mapping = Artifact::load(artifacts_dir, "registry/operations-error-mapping.json")?;
    let operations = Artifact::load(artifacts_dir, "registry/contract-registry.json")?;
    let errors = Artifact::load(artifacts_dir, "registry/error-code-registry.json")?;
    let operation_rows = sorted_rows(
        operations.section_array("operation_registry", "operations")?,
        "operation_id",
    )?;
    let mapping_rows = sorted_rows(mapping.array("operations")?, "operation_id")?;
    validate_unique(&mapping_rows, "operation_id", &["ak."])?;
    let operation_ids = operation_rows
        .iter()
        .map(|row| string(row, "operation_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>>>()?;
    let mapped_ids = mapping_rows
        .iter()
        .map(|row| string(row, "operation_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>>>()?;
    if operation_ids != mapped_ids {
        bail!("operations-error-mapping operation set differs from operation registry");
    }
    let operation_http = operation_rows
        .iter()
        .map(|row| Ok((string(row, "operation_id")?, string(row, "http")?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let top_level = active_error_rows(&sorted_rows(errors.array("codes")?, "code")?, "error code")?
        .iter()
        .map(|row| string(row, "code").map(str::to_owned))
        .collect::<Result<BTreeSet<_>>>()?;
    let reasons = active_error_rows(
        &sorted_rows(errors.array("reason_codes")?, "code")?,
        "reason code",
    )?
    .iter()
    .map(|row| string(row, "code").map(str::to_owned))
    .collect::<Result<BTreeSet<_>>>()?;
    let mut output = header(
        &[&mapping.source, &operations.source, &errors.source],
        &format!("operations={}", mapping_rows.len()),
    );
    output.push_str("use crate::{ErrorCode, ReasonCode, ServiceOperationId};\n\n#[derive(Clone, Debug, PartialEq, Eq)]\npub enum OperationSpecificError {\n    Code(ErrorCode),\n    Reason(ReasonCode),\n}\n\nimpl ServiceOperationId {\n    pub fn operation_specific_errors(self) -> &'static [OperationSpecificError] {\n        OPERATION_SPECIFIC_ERRORS[self as usize]\n    }\n}\n\npub const OPERATION_SPECIFIC_ERRORS: &[&[OperationSpecificError]] = &[\n");
    for row in &mapping_rows {
        let operation_id = string(row, "operation_id")?;
        if string(row, "http_alias")? != operation_http[operation_id] {
            bail!("{operation_id} error mapping HTTP alias differs from operation registry");
        }
        let entries = field(row, "operation_specific")?
            .as_array()
            .with_context(|| format!("{operation_id} operation_specific is not an array"))?;
        let mut seen = BTreeSet::new();
        output.push_str("    &[\n");
        for entry in entries {
            let code = entry
                .as_str()
                .with_context(|| format!("{operation_id} has a non-string error entry"))?;
            if !seen.insert(code) {
                bail!("{operation_id} repeats operation-specific error {code}");
            }
            if top_level.contains(code) {
                writeln!(
                    output,
                    "        OperationSpecificError::Code(ErrorCode::{}),",
                    variant(code, &[])
                )?;
            } else if reasons.contains(code) {
                writeln!(
                    output,
                    "        OperationSpecificError::Reason(ReasonCode::{}),",
                    variant(code, &[])
                )?;
            } else {
                bail!("{operation_id} references unregistered or inactive error {code}");
            }
        }
        output.push_str("    ],\n");
    }
    output.push_str("];\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn every_operation_has_a_typed_error_mapping() {\n        assert_eq!(ServiceOperationId::ALL.len(), OPERATION_SPECIFIC_ERRORS.len());\n        for (index, operation) in ServiceOperationId::ALL.iter().copied().enumerate() {\n            assert_eq!(operation as usize, index);\n            for error in operation.operation_specific_errors() {\n                match error {\n                    OperationSpecificError::Code(code) => assert!(ErrorCode::is_registered(code.as_str())),\n                    OperationSpecificError::Reason(reason) => assert!(ReasonCode::is_registered(reason.as_str())),\n                }\n            }\n        }\n    }\n}\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/operation_errors.rs".into(),
        contents: output,
    })
}

fn emit_id_enum(
    output: &mut String,
    enum_name: &str,
    rows: &[&Map<String, Value>],
    key: &str,
    prefixes: &[&str],
) -> Result<()> {
    validate_unique(rows, key, prefixes)?;
    writeln!(
        output,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\n#[repr(usize)]\npub enum {enum_name} {{"
    )?;
    for row in rows {
        writeln!(output, "    {},", variant(string(row, key)?, prefixes))?;
    }
    writeln!(
        output,
        "}}\n\nimpl {enum_name} {{\n    pub const ALL: &'static [Self] = &["
    )?;
    for row in rows {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, key)?, prefixes)
        )?;
    }
    output.push_str("    ];\n\n");
    for row in rows {
        let value = string(row, key)?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            associated_name(value, prefixes),
            rust_string(value)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str {\n        match self {\n");
    for row in rows {
        let value = string(row, key)?;
        writeln!(
            output,
            "            Self::{} => Self::{},",
            variant(value, prefixes),
            associated_name(value, prefixes)
        )?;
    }
    output.push_str(
        "        }\n    }\n\n    pub fn from_wire(value: &str) -> Option<Self> {\n        match value {\n",
    );
    for row in rows {
        let value = string(row, key)?;
        writeln!(
            output,
            "            Self::{} => Some(Self::{}),",
            associated_name(value, prefixes),
            variant(value, prefixes)
        )?;
    }
    output.push_str("            _ => None,\n        }\n    }\n}\n\n");
    Ok(())
}

fn value_as_string(value: &Value, label: &str) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        _ => bail!("{label} is not a string or number"),
    }
}

fn generate_security_strings(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let proof_artifact = Artifact::load(artifacts_dir, "registry/proof-context-registry.json")?;
    let label_artifact = Artifact::load(artifacts_dir, "registry/exporter-label-registry.json")?;
    let digest_artifact = Artifact::load(artifacts_dir, "registry/digest-suite-registry.json")?;
    let signature_artifact = Artifact::load(artifacts_dir, "registry/signature-alg-registry.json")?;
    let hpke_artifact = Artifact::load(artifacts_dir, "registry/hpke-suite-registry.json")?;
    let mls_artifact = Artifact::load(artifacts_dir, "registry/mls-ciphersuite-registry.json")?;
    let extension_artifact = Artifact::load(artifacts_dir, "registry/mls-extension-registry.json")?;
    let aead_artifact = Artifact::load(artifacts_dir, "registry/aead-profile-registry.json")?;

    let proof = sorted_rows(proof_artifact.array("contexts")?, "context")?;
    let labels = sorted_rows(label_artifact.array("labels")?, "label")?;
    let digests = sorted_rows(digest_artifact.array("suites")?, "canonical_id")?;
    let signatures = sorted_rows(signature_artifact.array("algorithms")?, "canonical_id")?;
    let hpke = sorted_rows(hpke_artifact.array("suites")?, "canonical_id")?;
    let mls = sorted_rows(mls_artifact.array("ciphersuites")?, "canonical_id")?;
    let mls_extensions = sorted_rows(extension_artifact.array("extensions")?, "name")?;
    let domains = sorted_rows(proof_artifact.array("domain_separations")?, "domain")?;
    let aead_profiles = sorted_rows(aead_artifact.array("profiles")?, "canonical_id")?;

    let sources = [
        &proof_artifact.source,
        &label_artifact.source,
        &digest_artifact.source,
        &signature_artifact.source,
        &hpke_artifact.source,
        &mls_artifact.source,
        &extension_artifact.source,
        &aead_artifact.source,
    ];
    let mut output = header(
        &sources,
        &format!(
            "proof_contexts={}, exporter_labels={}, digest_suites={}, signature_algorithms={}, hpke_suites={}, mls_ciphersuites={}, mls_extensions={}, domain_separations={}, aead_profiles={}",
            proof.len(),
            labels.len(),
            digests.len(),
            signatures.len(),
            hpke.len(),
            mls.len(),
            mls_extensions.len(),
            domains.len(),
            aead_profiles.len()
        ),
    );

    emit_id_enum(&mut output, "ProofContextId", &proof, "context", &["ak."])?;
    emit_id_enum(
        &mut output,
        "DomainSeparationId",
        &domains,
        "domain",
        &["ak."],
    )?;
    emit_id_enum(
        &mut output,
        "AeadProfileId",
        &aead_profiles,
        "canonical_id",
        &["ak.aead."],
    )?;
    emit_id_enum(
        &mut output,
        "HpkeSuiteId",
        &hpke,
        "canonical_id",
        &["ak.hpke_"],
    )?;
    emit_id_enum(
        &mut output,
        "ExporterLabelId",
        &labels,
        "label",
        &["ak.", "arkret-"],
    )?;

    output.push_str(
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ProofContextDescriptor {\n    pub id: ProofContextId,\n    pub context: &'static str,\n    pub object_family: &'static str,\n    pub consumer_operation: Option<&'static str>,\n    pub binding_fields: &'static [&'static str],\n    pub schema_ref: &'static str,\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ExporterLabelDescriptor {\n    pub id: ExporterLabelId,\n    pub label: &'static str,\n    pub primitive: Option<&'static str>,\n    pub context_fields: &'static [&'static str],\n    pub output_bytes: &'static str,\n    pub empty_context_forbidden: bool,\n    pub forbid_reuse_with: &'static [&'static str],\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct AlgorithmSuiteDescriptor {\n    pub canonical_id: &'static str,\n    pub status: &'static str,\n    pub role: &'static str,\n    pub profile_gate: Option<&'static str>,\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct MlsExtensionDescriptor {\n    pub name: &'static str,\n    pub codepoint: &'static str,\n    pub status: &'static str,\n    pub profile_id: Option<&'static str>,\n    pub rejection_error: Option<&'static str>,\n}\n\npub const PROOF_CONTEXTS: &[ProofContextDescriptor] = &[\n",
    );
    for row in &proof {
        let binding_fields = strings(row, "binding_fields")?;
        writeln!(
            output,
            "    ProofContextDescriptor {{\n        id: ProofContextId::{},\n        context: {},\n        object_family: {},\n        consumer_operation: {},\n        binding_fields: {},\n        schema_ref: {},\n    }},",
            variant(string(row, "context")?, &["ak."]),
            rust_string(string(row, "context")?),
            rust_string(string(row, "object_family")?),
            option_string(row.get("consumer_operation").and_then(Value::as_str)),
            string_slice(&binding_fields),
            rust_string(string(row, "schema_ref")?)
        )?;
    }
    output.push_str("];\n\npub const EXPORTER_LABELS: &[ExporterLabelDescriptor] = &[\n");
    for row in &labels {
        let context_fields = strings(row, "context_fields")?;
        let forbid_reuse_with = strings(row, "forbid_reuse_with")?;
        writeln!(
            output,
            "    ExporterLabelDescriptor {{\n        id: ExporterLabelId::{},\n        label: {},\n        primitive: {},\n        context_fields: {},\n        output_bytes: {},\n        empty_context_forbidden: {},\n        forbid_reuse_with: {},\n    }},",
            variant(string(row, "label")?, &["ak.", "arkret-"]),
            rust_string(string(row, "label")?),
            option_string(row.get("primitive").and_then(Value::as_str)),
            string_slice(&context_fields),
            rust_string(&value_as_string(
                field(row, "output_bytes")?,
                "output_bytes"
            )?),
            field(row, "empty_context_forbidden")?
                .as_bool()
                .context("empty_context_forbidden is not boolean")?,
            string_slice(&forbid_reuse_with)
        )?;
    }
    output.push_str("];\n\n");
    emit_algorithm_suites(&mut output, "DIGEST_SUITES", &digests)?;
    emit_algorithm_suites(&mut output, "SIGNATURE_ALGORITHMS", &signatures)?;
    emit_algorithm_suites(&mut output, "HPKE_SUITES", &hpke)?;
    emit_algorithm_suites(&mut output, "MLS_CIPHERSUITES", &mls)?;
    output.push_str("pub const MLS_EXTENSIONS: &[MlsExtensionDescriptor] = &[\n");
    for row in mls_extensions {
        writeln!(
            output,
            "    MlsExtensionDescriptor {{\n        name: {},\n        codepoint: {},\n        status: {},\n        profile_id: {},\n        rejection_error: {},\n    }},",
            rust_string(string(row, "name")?),
            rust_string(&value_as_string(field(row, "codepoint")?, "codepoint")?),
            rust_string(string(row, "status")?),
            option_string(row.get("profile_id").and_then(Value::as_str)),
            option_string(row.get("rejection_error").and_then(Value::as_str))
        )?;
    }
    output.push_str("];\n\npub fn proof_context(value: &str) -> Option<&'static ProofContextDescriptor> {\n    ProofContextId::from_wire(value).map(proof_context_descriptor)\n}\n\npub const fn proof_context_descriptor(id: ProofContextId) -> &'static ProofContextDescriptor {\n    &PROOF_CONTEXTS[id as usize]\n}\n\npub fn exporter_label(value: &str) -> Option<&'static ExporterLabelDescriptor> {\n    ExporterLabelId::from_wire(value).map(exporter_label_descriptor)\n}\n\npub const fn exporter_label_descriptor(id: ExporterLabelId) -> &'static ExporterLabelDescriptor {\n    &EXPORTER_LABELS[id as usize]\n}\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/security_strings.rs".into(),
        contents: output,
    })
}

fn emit_algorithm_suites(
    output: &mut String,
    name: &str,
    rows: &[&Map<String, Value>],
) -> Result<()> {
    writeln!(output, "pub const {name}: &[AlgorithmSuiteDescriptor] = &[")?;
    for row in rows {
        writeln!(
            output,
            "    AlgorithmSuiteDescriptor {{\n        canonical_id: {},\n        status: {},\n        role: {},\n        profile_gate: {},\n    }},",
            rust_string(string(row, "canonical_id")?),
            rust_string(string(row, "status")?),
            rust_string(string(row, "role")?),
            option_string(row.get("profile_gate").and_then(Value::as_str))
        )?;
    }
    output.push_str("];\n\n");
    Ok(())
}

fn binding_variant(value: &str) -> Result<&'static str> {
    match value {
        "http_json" => Ok("BindingKind::HttpJson"),
        "tus" => Ok("BindingKind::Tus"),
        "websocket" => Ok("BindingKind::Websocket"),
        _ => bail!("unsupported operation bundle binding kind: {value}"),
    }
}

fn generate_capability_discovery(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/contract-registry.json")?;
    let mut bundles = artifact
        .value
        .pointer("/operation_registry/operation_bundles")
        .and_then(Value::as_array)
        .context("contract registry missing operation bundles")?
        .iter()
        .map(|v| v.as_object().context("operation bundle is not object"))
        .collect::<Result<Vec<_>>>()?;
    bundles.sort_by_key(|row| string(row, "operation_bundle_id").unwrap());
    let mut features = artifact
        .value
        .pointer("/feature_registry/features")
        .and_then(Value::as_array)
        .context("contract registry missing features")?
        .iter()
        .map(|v| v.as_object().context("feature is not object"))
        .collect::<Result<Vec<_>>>()?;
    features.sort_by_key(|row| string(row, "feature_id").unwrap());
    validate_unique(&bundles, "operation_bundle_id", &["ak.operation_bundle."])?;
    validate_unique(&features, "feature_id", &["ak.feature."])?;
    let mut output = header(
        &[&artifact.source],
        &format!(
            "operation_bundles={} features={}",
            bundles.len(),
            features.len()
        ),
    );
    output.push_str("use crate::{BindingKind, ServiceKind, ServiceOperationId};\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub struct OperationBindingPair { pub operation_id: ServiceOperationId, pub binding_kind: BindingKind }\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct OperationBundleDescriptor { pub operation_bundle_id: &'static str, pub service_kind: ServiceKind, pub members: &'static [OperationBindingPair] }\nimpl OperationBundleDescriptor { pub fn contains(&self, operation_id: ServiceOperationId, binding_kind: BindingKind) -> bool { self.members.iter().any(|pair| pair.operation_id == operation_id && pair.binding_kind == binding_kind) } }\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub enum FeatureStatus { Active, Experimental, TestOnly }\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct FeatureDescriptor { pub feature_id: &'static str, pub status: FeatureStatus, pub defined_in: &'static str, pub service_kinds: &'static [ServiceKind], pub required_operation_pairs: &'static [OperationBindingPair], pub required_profiles: &'static [&'static str], pub required_limits: &'static [&'static str], pub semantic_guarantees: &'static [&'static str], pub conflicts: &'static [&'static str] }\n\npub const OPERATION_BUNDLES: &[OperationBundleDescriptor] = &[\n");
    for bundle in bundles {
        writeln!(
            output,
            "    OperationBundleDescriptor {{ operation_bundle_id: {}, service_kind: ServiceKind::{}, members: &[",
            rust_string(string(bundle, "operation_bundle_id")?),
            variant(string(bundle, "service_kind")?, &[])
        )?;
        for member in field(bundle, "members")?
            .as_array()
            .context("bundle members not array")?
        {
            let member = member.as_object().context("bundle member not object")?;
            writeln!(
                output,
                "        OperationBindingPair {{ operation_id: ServiceOperationId::{}, binding_kind: {} }},",
                variant(string(member, "operation_id")?, &["ak."]),
                binding_variant(string(member, "binding_kind")?)?
            )?;
        }
        output.push_str("    ] },\n");
    }
    output.push_str("];\n\npub fn operation_bundle_descriptor(operation_bundle_id: &str) -> Option<&'static OperationBundleDescriptor> { OPERATION_BUNDLES.binary_search_by_key(&operation_bundle_id, |row| row.operation_bundle_id).ok().map(|index| &OPERATION_BUNDLES[index]) }\npub fn operation_bundles_for_service_kind(service_kind: ServiceKind) -> impl Iterator<Item = &'static OperationBundleDescriptor> { OPERATION_BUNDLES.iter().filter(move |bundle| bundle.service_kind == service_kind) }\npub fn role_describe_bundle_descriptor(service_kind: ServiceKind) -> Option<&'static OperationBundleDescriptor> { operation_bundles_for_service_kind(service_kind).find(|bundle| bundle.operation_bundle_id.ends_with(\".describe.v1\")) }\npub fn operation_binding_is_registered(operation_id: ServiceOperationId, binding_kind: BindingKind) -> bool { OPERATION_BUNDLES.iter().any(|bundle| bundle.contains(operation_id, binding_kind)) }\n\npub const FEATURES: &[FeatureDescriptor] = &[\n");
    for feature in features {
        let status = match string(feature, "status")? {
            "active" => "FeatureStatus::Active",
            "experimental" => "FeatureStatus::Experimental",
            "test_only" => "FeatureStatus::TestOnly",
            value => bail!("unsupported feature status: {value}"),
        };
        let service_kinds = strings(feature, "service_kinds")?
            .iter()
            .map(|kind| format!("ServiceKind::{}", variant(kind, &[])))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            output,
            "    FeatureDescriptor {{ feature_id: {}, status: {status}, defined_in: {}, service_kinds: &[{service_kinds}], required_operation_pairs: &[",
            rust_string(string(feature, "feature_id")?),
            rust_string(string(feature, "defined_in")?)
        )?;
        for pair in field(feature, "required_operation_pairs")?
            .as_array()
            .context("required_operation_pairs not array")?
        {
            let pair = pair.as_object().context("operation pair not object")?;
            writeln!(
                output,
                "        OperationBindingPair {{ operation_id: ServiceOperationId::{}, binding_kind: {} }},",
                variant(string(pair, "operation_id")?, &["ak."]),
                binding_variant(string(pair, "binding_kind")?)?
            )?;
        }
        writeln!(
            output,
            "    ], required_profiles: {}, required_limits: {}, semantic_guarantees: {}, conflicts: {} }},",
            string_slice(&strings(feature, "required_profiles")?),
            string_slice(&strings(feature, "required_limits")?),
            string_slice(&strings(feature, "semantic_guarantees")?),
            string_slice(&strings(feature, "conflicts")?)
        )?;
    }
    output.push_str("];\n\npub fn feature_descriptor(feature_id: &str) -> Option<&'static FeatureDescriptor> { FEATURES.binary_search_by_key(&feature_id, |row| row.feature_id).ok().map(|index| &FEATURES[index]) }\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/capability_discovery.rs".into(),
        contents: output,
    })
}

fn generate_profile_ids(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "profiles/conformance-profiles.json")?;
    let roles_map = artifact
        .value
        .get("profile_roles")
        .and_then(Value::as_object)
        .context("conformance profiles missing profile_roles")?;
    let roles = [
        ("client", "Client"),
        ("server", "Server"),
        ("gateway", "Gateway"),
        ("directory", "Directory"),
        ("admin", "Admin"),
        ("interop", "Interop"),
    ];
    let rows = roles_map
        .iter()
        .map(|(id, role)| {
            Ok((
                id.clone(),
                role.as_str()
                    .context("profile role is not string")?
                    .to_owned(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let profile_pattern = Regex::new(r"ak\.profile\.[A-Za-z0-9_.-]+\.v[0-9]+")?;
    let source_text = serde_json::to_string(&artifact.value)?;
    let body_ids = profile_pattern
        .find_iter(&source_text)
        .map(|matched| matched.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let declared_ids = rows
        .iter()
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let unroled = body_ids
        .difference(&declared_ids)
        .cloned()
        .collect::<Vec<_>>();
    if !unroled.is_empty() {
        bail!(
            "profile ids present in the artifact body without a profile_roles entry: {}",
            unroled.join(", ")
        );
    }
    for (id, role) in &rows {
        if !roles.iter().any(|(wire, _)| wire == role) {
            bail!("profile {id} has unsupported role {role}");
        }
    }
    let owned = rows
        .iter()
        .map(|(id, _)| Map::from_iter([(String::from("profile_id"), Value::String(id.clone()))]))
        .collect::<Vec<_>>();
    validate_unique(
        &owned.iter().collect::<Vec<_>>(),
        "profile_id",
        &["ak.profile."],
    )?;
    let mut output = header(&[&artifact.source], &format!("profile_ids={}", rows.len()));
    output.push_str("use serde::{Deserialize, Serialize};\n\n/// Declared conformance profile identifiers. Every `ak.profile.*` literal\n/// the SDK ships is spelled exactly once, here.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\n#[repr(usize)]\npub enum ProfileId {\n");
    for (id, _) in &rows {
        writeln!(output, "    {},", variant(id, &["ak.profile."]))?;
    }
    output.push_str("}\n\n/// Spec-layer `profile_roles` partition: every declared profile id\n/// belongs to exactly one of these roles. SDK manifests, client-side\n/// feature negotiation, and conformance loaders MUST consult\n/// [`ProfileId::role`] before claiming a profile as locally implemented.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub enum ProfileRole { Client, Server, Gateway, Directory, Admin, Interop }\n\nimpl ProfileRole {\n    pub const fn as_str(self) -> &'static str { match self {\n");
    for (wire, name) in roles {
        writeln!(output, "        Self::{name} => {},", rust_string(wire))?;
    }
    output.push_str("    } }\n    pub fn from_wire(value: &str) -> Option<Self> { match value {\n");
    for (wire, name) in roles {
        writeln!(
            output,
            "        {} => Some(Self::{name}),",
            rust_string(wire)
        )?;
    }
    output.push_str("        _ => None,\n    } }\n}\n\nimpl ProfileId {\n    pub const ALL: &'static [Self] = &[\n");
    for (id, _) in &rows {
        writeln!(output, "        Self::{},", variant(id, &["ak.profile."]))?;
    }
    output.push_str("    ];\n\n");
    for (id, _) in &rows {
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            associated_name(id, &["ak.profile."]),
            rust_string(id)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str { match self {\n");
    for (id, _) in &rows {
        writeln!(
            output,
            "        Self::{} => Self::{},",
            variant(id, &["ak.profile."]),
            associated_name(id, &["ak.profile."])
        )?;
    }
    output.push_str("    } }\n\n    pub const fn role(self) -> ProfileRole { match self {\n");
    for (id, role) in &rows {
        let name = roles.iter().find(|(wire, _)| wire == role).unwrap().1;
        writeln!(
            output,
            "        Self::{} => ProfileRole::{name},",
            variant(id, &["ak.profile."])
        )?;
    }
    output.push_str("    } }\n\n    pub fn with_role(role: ProfileRole) -> impl Iterator<Item = Self> { Self::ALL.iter().copied().filter(move |id| id.role() == role) }\n\n    pub fn from_wire(value: &str) -> Option<Self> { match value {\n");
    for (id, _) in &rows {
        writeln!(
            output,
            "        Self::{} => Some(Self::{}),",
            associated_name(id, &["ak.profile."]),
            variant(id, &["ak.profile."])
        )?;
    }
    output.push_str("        _ => None,\n    } }\n}\n\nimpl std::fmt::Display for ProfileId { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) } }\nimpl Serialize for ProfileId { fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(self.as_str()) } }\nimpl<'de> Deserialize<'de> for ProfileId { fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> { let raw = String::deserialize(deserializer)?; Self::from_wire(&raw).ok_or_else(|| serde::de::Error::custom(format!(\"unknown profile id: {raw}\"))) } }\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/profile_ids.rs".into(),
        contents: output,
    })
}

fn generate_did_freshness_profiles(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(
        artifacts_dir,
        "registry/did-freshness-profile-registry.json",
    )?;
    let rows = sorted_rows(artifact.array("profiles")?, "freshness_profile_id")?;
    validate_unique(&rows, "freshness_profile_id", &["ak.did_freshness."])?;
    let mut output = header(&[&artifact.source], &format!("registered={}", rows.len()));
    output.push_str("#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub enum DidFreshnessProfileId {\n");
    for row in &rows {
        writeln!(
            output,
            "    {},",
            variant(string(row, "freshness_profile_id")?, &["ak.did_freshness."])
        )?;
    }
    output.push_str("}\n\n/// Registered risk tier of a freshness profile. Fixed by registration:\n/// a deployment declares only the numeric windows.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]\n#[serde(rename_all = \"snake_case\")]\npub enum DidFreshnessRiskTier { Low, Medium, High }\n\nimpl DidFreshnessProfileId {\n    pub const ALL: &'static [Self] = &[\n");
    for row in &rows {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "freshness_profile_id")?, &["ak.did_freshness."])
        )?;
    }
    output.push_str("    ];\n\n");
    for row in &rows {
        let id = string(row, "freshness_profile_id")?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            associated_name(id, &["ak.did_freshness."]),
            rust_string(id)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str { match self {\n");
    for row in &rows {
        let id = string(row, "freshness_profile_id")?;
        writeln!(
            output,
            "        Self::{} => Self::{},",
            variant(id, &["ak.did_freshness."]),
            associated_name(id, &["ak.did_freshness."])
        )?;
    }
    output.push_str(
        "    } }\n\n    pub const fn risk_tier(self) -> DidFreshnessRiskTier { match self {\n",
    );
    for row in &rows {
        let tier = match string(row, "risk_tier")? {
            "low" => "Low",
            "medium" => "Medium",
            "high" => "High",
            value => bail!("unknown DID freshness risk tier {value}"),
        };
        writeln!(
            output,
            "        Self::{} => DidFreshnessRiskTier::{tier},",
            variant(string(row, "freshness_profile_id")?, &["ak.did_freshness."])
        )?;
    }
    output
        .push_str("    } }\n\n    pub fn from_wire(value: &str) -> Option<Self> { match value {\n");
    for row in rows {
        let id = string(row, "freshness_profile_id")?;
        writeln!(
            output,
            "        Self::{} => Some(Self::{}),",
            associated_name(id, &["ak.did_freshness."]),
            variant(id, &["ak.did_freshness."])
        )?;
    }
    output.push_str("        _ => None,\n    } }\n}\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/did_freshness_profiles.rs".into(),
        contents: output,
    })
}

fn generate_did_method_adapters(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/contract-registry.json")?;
    let rows = sorted_rows(
        artifact.section_array("did_method_adapter_registry", "adapters")?,
        "method_evidence_kind",
    )?;
    validate_unique(&rows, "method_evidence_kind", &[])?;
    let mut output = header(&[&artifact.source], &format!("registered={}", rows.len()));
    output.push_str(
        "/// Method-history evidence kinds, keyed the way the registry keys them.\n\
         ///\n\
         /// `adapter_version` is not a wire member: review 2026-09-02-1951 A8 deleted\n\
         /// it from every method-history evidence carrier because the registry already\n\
         /// fixes one adapter version per evidence kind. Producers and verifiers each\n\
         /// recompute it from `evidence_kind` through this table.\n\
         #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\n\
         pub enum DidMethodEvidenceKind {\n",
    );
    for row in &rows {
        writeln!(
            output,
            "    {},",
            variant(string(row, "method_evidence_kind")?, &[])
        )?;
    }
    output.push_str("}\n\nimpl DidMethodEvidenceKind {\n    pub const ALL: &'static [Self] = &[\n");
    for row in &rows {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "method_evidence_kind")?, &[])
        )?;
    }
    output.push_str("    ];\n\n");
    for row in &rows {
        let kind = string(row, "method_evidence_kind")?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            associated_name(kind, &[]),
            rust_string(kind)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str { match self {\n");
    for row in &rows {
        let kind = string(row, "method_evidence_kind")?;
        writeln!(
            output,
            "        Self::{} => Self::{},",
            variant(kind, &[]),
            associated_name(kind, &[])
        )?;
    }
    output.push_str(
        "    } }\n\n    /// The registry's adapter version for this evidence kind.\n\
         pub const fn adapter_version(self) -> &'static str { match self {\n",
    );
    for row in &rows {
        writeln!(
            output,
            "        Self::{} => {},",
            variant(string(row, "method_evidence_kind")?, &[]),
            rust_string(string(row, "adapter_version")?)
        )?;
    }
    output.push_str("    } }\n\n    /// The DID method this adapter admits.\n    pub const fn method(self) -> &'static str { match self {\n");
    for row in &rows {
        writeln!(
            output,
            "        Self::{} => {},",
            variant(string(row, "method_evidence_kind")?, &[]),
            rust_string(string(row, "method")?)
        )?;
    }
    output
        .push_str("    } }\n\n    pub fn from_wire(value: &str) -> Option<Self> { match value {\n");
    for row in rows {
        let kind = string(row, "method_evidence_kind")?;
        writeln!(
            output,
            "        Self::{} => Some(Self::{}),",
            associated_name(kind, &[]),
            variant(kind, &[])
        )?;
    }
    output.push_str("        _ => None,\n    } }\n}\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/did_method_adapters.rs".into(),
        contents: output,
    })
}

fn generate_authority_sources(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/contract-registry.json")?;
    let rows = sorted_rows(
        artifact.section_array("authority_source_registry", "sources")?,
        "authority_source_id",
    )?;
    let mut output = simple_string_enum(
        &artifact,
        &rows,
        "authority_source_id",
        &["ak.authority."],
        "AuthoritySourceId",
        &format!("registered={}", rows.len()),
        false,
    )?;
    output = output.replacen("#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]", "use serde::{Deserialize, Serialize};\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]", 1);
    output.push_str("\nimpl std::fmt::Display for AuthoritySourceId { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) } }\nimpl Serialize for AuthoritySourceId { fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(self.as_str()) } }\nimpl<'de> Deserialize<'de> for AuthoritySourceId { fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> { let raw = String::deserialize(deserializer)?; Self::from_wire(&raw).ok_or_else(|| serde::de::Error::custom(format!(\"unknown authority source id: {raw}\"))) } }\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/authority_sources.rs".into(),
        contents: output,
    })
}

fn generate_schema_ids(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/contract-registry.json")?;
    let rows = sorted_rows(
        artifact.section_array("schema_registry", "schemas")?,
        "schema_id",
    )?;
    validate_unique(&rows, "schema_id", &["ak.schema.", "ak."])?;
    let active = rows
        .iter()
        .copied()
        .filter(|row| {
            row.get("status")
                .and_then(Value::as_str)
                .unwrap_or("active")
                == "active"
        })
        .collect::<Vec<_>>();
    let mut output = header(
        &[&artifact.source],
        &format!("schema_ids={}, active={}", rows.len(), active.len()),
    );
    output.push_str("use serde::{Deserialize, Serialize};\n\n/// Registered `ak.schema.*` identifiers. Every schema-id literal the\n/// SDK ships is spelled exactly once, here; owning wire types alias the\n/// associated const as `Type::SCHEMA`.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\n#[repr(usize)]\npub enum SchemaId {\n");
    for row in &rows {
        writeln!(
            output,
            "    {},",
            variant(string(row, "schema_id")?, &["ak.schema.", "ak."])
        )?;
    }
    output.push_str("}\n\nimpl SchemaId {\n    pub const ALL: &'static [Self] = &[\n");
    for row in &rows {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "schema_id")?, &["ak.schema.", "ak."])
        )?;
    }
    output.push_str("    ];\n\n    /// Rows the registry declares `active`; excludes `candidate` rows.\n    pub const ACTIVE: &'static [Self] = &[\n");
    for row in &active {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "schema_id")?, &["ak.schema.", "ak."])
        )?;
    }
    output.push_str("    ];\n\n");
    for row in &rows {
        if let Some(description) = row.get("description").and_then(Value::as_str) {
            writeln!(output, "    /// {}", rustdoc(description))?;
        }
        let id = string(row, "schema_id")?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            associated_name(id, &["ak.schema.", "ak."]),
            rust_string(id)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str {\n        match self {\n");
    for row in &rows {
        let id = string(row, "schema_id")?;
        writeln!(
            output,
            "            Self::{} => Self::{},",
            variant(id, &["ak.schema.", "ak."]),
            associated_name(id, &["ak.schema.", "ak."])
        )?;
    }
    output.push_str("        }\n    }\n\n    /// Path of the JSON Schema document backing this id, relative to\n    /// `spec/v1/artifacts/`.\n    pub const fn file(self) -> &'static str {\n        match self {\n");
    for row in &rows {
        writeln!(
            output,
            "            Self::{} => {},",
            variant(string(row, "schema_id")?, &["ak.schema.", "ak."]),
            rust_string(string(row, "file")?)
        )?;
    }
    output.push_str("        }\n    }\n\n    pub fn from_wire(value: &str) -> Option<Self> {\n        match value {\n");
    for row in &rows {
        let id = string(row, "schema_id")?;
        writeln!(
            output,
            "            Self::{} => Some(Self::{}),",
            associated_name(id, &["ak.schema.", "ak."]),
            variant(id, &["ak.schema.", "ak."])
        )?;
    }
    output.push_str("            _ => None,\n        }\n    }\n}\n\nimpl std::fmt::Display for SchemaId {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }\n}\n\nimpl Serialize for SchemaId {\n    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(self.as_str()) }\n}\n\nimpl<'de> Deserialize<'de> for SchemaId {\n    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {\n        let raw = String::deserialize(deserializer)?;\n        Self::from_wire(&raw).ok_or_else(|| serde::de::Error::custom(format!(\"unknown schema id: {raw}\")))\n    }\n}\n\n#[cfg(feature = \"openapi\")]\nimpl salvo_oapi::ToSchema for SchemaId {\n    fn to_schema(_components: &mut salvo_oapi::Components) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {\n        salvo_oapi::schema::Object::new().schema_type(salvo_oapi::schema::BasicType::String).enum_values(Self::ALL.iter().map(|value| value.as_str())).into()\n    }\n}\n\n#[cfg(feature = \"openapi\")]\nimpl salvo_oapi::ComposeSchema for SchemaId {\n    fn compose(components: &mut salvo_oapi::Components, generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {\n        let _ = generics;\n        <Self as salvo_oapi::ToSchema>::to_schema(components)\n    }\n}\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/schema_ids.rs".into(),
        contents: output,
    })
}

fn generate_digest_suite_codes(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/digest-suite-registry.json")?;
    let mut rows = artifact
        .array("suites")?
        .into_iter()
        .filter(|row| string(row, "status").is_ok_and(|status| status == "active"))
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| field(row, "wire_code").unwrap().as_u64().unwrap());
    validate_unique(&rows, "canonical_id", &[])?;
    validate_digest_suite_rows(&rows)?;
    let mut output = header(&[&artifact.source], &format!("active={}", rows.len()));
    output.push_str("#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\n#[repr(u8)]\npub enum DigestSuiteCode {\n");
    for row in &rows {
        writeln!(
            output,
            "    {} = 0x{:02x},",
            variant(string(row, "canonical_id")?, &[]),
            field(row, "wire_code")?.as_u64().unwrap()
        )?;
    }
    output.push_str("}\n\nimpl DigestSuiteCode {\n    pub const fn as_u8(self) -> u8 { self as u8 }\n\n    pub const fn as_str(self) -> &'static str {\n        match self {\n");
    for row in &rows {
        writeln!(
            output,
            "            Self::{} => {},",
            variant(string(row, "canonical_id")?, &[]),
            rust_string(string(row, "canonical_id")?)
        )?;
    }
    output.push_str("        }\n    }\n\n    pub const fn from_digest_suite(suite: arkret_canonical::DigestSuite) -> Self {\n        match suite {\n");
    for row in &rows {
        let name = variant(string(row, "canonical_id")?, &[]);
        writeln!(
            output,
            "            arkret_canonical::DigestSuite::{name} => Self::{name},"
        )?;
    }
    output.push_str("        }\n    }\n\n    pub const fn digest_suite(self) -> arkret_canonical::DigestSuite {\n        match self {\n");
    for row in &rows {
        let name = variant(string(row, "canonical_id")?, &[]);
        writeln!(
            output,
            "            Self::{name} => arkret_canonical::DigestSuite::{name},"
        )?;
    }
    output.push_str("        }\n    }\n}\n\nimpl TryFrom<u8> for DigestSuiteCode {\n    type Error = crate::IdentifierError;\n\n    fn try_from(value: u8) -> crate::Result<Self> {\n        match value {\n");
    for row in rows {
        writeln!(
            output,
            "            0x{:02x} => Ok(Self::{}),",
            field(row, "wire_code")?.as_u64().unwrap(),
            variant(string(row, "canonical_id")?, &[])
        )?;
    }
    output.push_str("            _ => Err(crate::IdentifierError::InvalidId(format!(\n                \"unsupported digest suite code: 0x{value:02x}\"\n            ))),\n        }\n    }\n}\n");
    Ok(GeneratedOutput {
        relative_path: "crates/identifiers/src/generated/digest_suite_codes.rs".into(),
        contents: output,
    })
}

fn validate_digest_suite_rows(rows: &[&Map<String, Value>]) -> Result<()> {
    let mut codes = BTreeSet::new();
    for row in rows {
        let code = field(row, "wire_code")?
            .as_u64()
            .context("digest suite wire_code is not an integer")?;
        if !codes.insert(code) {
            bail!("duplicate active digest-suite wire_code: {code}");
        }
        if code == 0 || code & 0xf0 != 0 {
            bail!(
                "active v1 suite-tagged full-digest wire_code must have high nibble zero: 0x{code:02x}"
            );
        }
        if field(row, "digest_length_bytes")?.as_u64() != Some(32) {
            bail!(
                "active 33-byte token suite {:?} does not have a 32-byte digest",
                string(row, "canonical_id")?
            );
        }
    }
    Ok(())
}

fn active_error_rows<'a>(
    rows: &'a [&'a Map<String, Value>],
    collection: &str,
) -> Result<Vec<&'a Map<String, Value>>> {
    let mut active = Vec::new();
    for row in rows {
        let code = string(row, "code")?;
        match string(row, "status")? {
            "active" => {
                if row.contains_key("activation_condition") {
                    bail!("{collection} {code} is active and must not retain activation_condition");
                }
                active.push(*row);
            }
            "reserved" => {
                let condition = string(row, "activation_condition")?;
                if condition.trim().is_empty() {
                    bail!("{collection} {code} is reserved without an activation condition");
                }
                let applies_to = row
                    .get("applies_to")
                    .and_then(Value::as_array)
                    .with_context(|| {
                        format!("{collection} {code} is reserved without applies_to[]")
                    })?;
                if applies_to.is_empty() {
                    bail!("{collection} {code} is reserved with empty applies_to[]");
                }
                let mut unique = BTreeSet::new();
                for applies_to in applies_to {
                    let applies_to = applies_to.as_str().with_context(|| {
                        format!("{collection} {code} has a non-string applies_to entry")
                    })?;
                    if applies_to.trim().is_empty() {
                        bail!("{collection} {code} has an empty applies_to entry");
                    }
                    if !unique.insert(applies_to) {
                        bail!("{collection} {code} repeats applies_to {applies_to:?}");
                    }
                }
            }
            status => bail!("{collection} {code} has unknown status {status:?}"),
        }
    }
    Ok(active)
}

fn generate_error_codes(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/error-code-registry.json")?;
    let registered = sorted_rows(artifact.array("codes")?, "code")?;
    validate_unique(&registered, "code", &[])?;
    let rows = active_error_rows(&registered, "error code")?;
    let contexts = rows
        .iter()
        .filter_map(|row| row.get("http_status_by_context").and_then(Value::as_object))
        .flat_map(|map| map.keys().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut output = header(
        &[&artifact.source],
        &format!(
            "error_codes={}, reserved_not_emitted={}",
            rows.len(),
            registered.len() - rows.len()
        ),
    );
    output.push_str("use serde::{Deserialize, Serialize};\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]\n#[serde(rename_all = \"snake_case\")]\npub enum ErrorStatusContext {\n");
    for context in &contexts {
        writeln!(output, "    {},", variant(context, &[]))?;
    }
    output.push_str("}\n\nimpl ErrorStatusContext {\n    pub const ALL: &'static [Self] = &[\n");
    for context in &contexts {
        writeln!(output, "        Self::{},", variant(context, &[]))?;
    }
    output.push_str(
        "    ];\n\n    pub const fn as_str(self) -> &'static str {\n        match self {\n",
    );
    for context in &contexts {
        writeln!(
            output,
            "            Self::{} => {},",
            variant(context, &[]),
            rust_string(context)
        )?;
    }
    output.push_str("        }\n    }\n}\n\nimpl std::fmt::Display for ErrorStatusContext {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]\n#[serde(rename_all = \"snake_case\")]\n#[repr(usize)]\npub enum ErrorCode {\n");
    for row in &rows {
        writeln!(output, "    {},", variant(string(row, "code")?, &[]))?;
    }
    output.push_str("}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ErrorCodeDescriptor {\n    pub code: ErrorCode,\n    pub type_uri: &'static str,\n    pub title: &'static str,\n    pub http_status: u16,\n    pub http_status_by_context: &'static [(ErrorStatusContext, u16)],\n    pub scope: &'static str,\n    pub applies_to: &'static [&'static str],\n    pub description: &'static str,\n}\n\nimpl ErrorCode {\n    pub const ALL: &'static [Self] = &[\n");
    for row in &rows {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "code")?, &[])
        )?;
    }
    output.push_str("    ];\n\n");
    for row in &rows {
        let code = string(row, "code")?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            code.to_ascii_uppercase(),
            rust_string(code)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str {\n        match self {\n");
    for row in &rows {
        let code = string(row, "code")?;
        writeln!(
            output,
            "            Self::{} => {},",
            variant(code, &[]),
            rust_string(code)
        )?;
    }
    output.push_str("        }\n    }\n\n    pub fn from_wire(value: &str) -> Option<Self> {\n        match value {\n");
    for row in &rows {
        let code = string(row, "code")?;
        writeln!(
            output,
            "            {} => Some(Self::{}),",
            rust_string(code),
            variant(code, &[])
        )?;
    }
    output.push_str("            _ => None,\n        }\n    }\n\n    /// Whether `value` is a top-level error code registered in\n    /// `registry/error-code-registry.json` `codes[]`. A `reason_codes[]`\n    /// member is not a top-level code: it belongs on\n    /// `error.details.reason_code`, never on the wire `error.code`.\n    pub fn is_registered(value: &str) -> bool { Self::from_wire(value).is_some() }\n\n    pub fn descriptor(self) -> &'static ErrorCodeDescriptor { &ERROR_CODE_DESCRIPTORS[self as usize] }\n    pub fn http_status(self) -> u16 { self.descriptor().http_status }\n    pub fn type_uri(self) -> &'static str { self.descriptor().type_uri }\n    pub fn title(self) -> &'static str { self.descriptor().title }\n    pub fn http_status_in(self, context: ErrorStatusContext) -> u16 {\n        let descriptor = self.descriptor();\n        descriptor.http_status_by_context.iter().find(|(entry, _)| *entry == context).map_or(descriptor.http_status, |(_, status)| *status)\n    }\n}\n\nimpl std::fmt::Display for ErrorCode {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }\n}\n\npub const ERROR_CODE_DESCRIPTORS: &[ErrorCodeDescriptor] = &[\n");
    for row in rows {
        let by_context = row
            .get("http_status_by_context")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(context, status)| {
                        format!(
                            "(ErrorStatusContext::{}, {})",
                            variant(context, &[]),
                            status.as_u64().unwrap()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let applies = row
            .get("applies_to")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        writeln!(
            output,
            "    ErrorCodeDescriptor {{\n        code: ErrorCode::{},\n        type_uri: {},\n        title: {},\n        http_status: {},\n        http_status_by_context: &[{}],\n        scope: {},\n        applies_to: {},\n        description: {},\n    }},",
            variant(string(row, "code")?, &[]),
            rust_string(string(row, "type_uri")?),
            rust_string(string(row, "title")?),
            field(row, "http_status")?
                .as_u64()
                .context("http_status is not integer")?,
            by_context,
            rust_string(string(row, "scope")?),
            string_slice(&applies),
            rust_string(string(row, "description")?)
        )?;
    }
    output.push_str(
        "];\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn enum_descriptor_and_wire_tables_are_bijective() {\n        assert_eq!(ErrorCode::ALL.len(), ERROR_CODE_DESCRIPTORS.len());\n        for (index, code) in ErrorCode::ALL.iter().copied().enumerate() {\n            let descriptor = &ERROR_CODE_DESCRIPTORS[index];\n            assert_eq!(descriptor.code, code);\n            assert_eq!(code.descriptor(), descriptor);\n            assert_eq!(ErrorCode::from_wire(code.as_str()), Some(code));\n            assert!(ErrorCode::is_registered(code.as_str()));\n        }\n        assert_eq!(ErrorCode::from_wire(\"reserved_or_unknown\"), None);\n        assert!(!ErrorCode::is_registered(\"reserved_or_unknown\"));\n    }\n}\n",
    );
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/error_codes/error_code.rs".into(),
        contents: output,
    })
}

fn generate_reason_codes(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/error-code-registry.json")?;
    let registered = sorted_rows(artifact.array("reason_codes")?, "code")?;
    validate_unique(&registered, "code", &[])?;
    let rows = active_error_rows(&registered, "reason code")?;
    let mut output = header(
        &[&artifact.source],
        &format!(
            "reason_codes={}, reserved_not_emitted={}",
            rows.len(),
            registered.len() - rows.len()
        ),
    );
    output.push_str("use serde::{Deserialize, Deserializer, Serialize, Serializer};\n\n#[derive(Clone, Debug, PartialEq, Eq, Hash)]\npub enum ReasonCode {\n");
    for row in &rows {
        writeln!(output, "    {},", variant(string(row, "code")?, &[]))?;
    }
    output.push_str("    Unknown(String),\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ReasonCodeDescriptor {\n    pub code: &'static str,\n    pub applies_to: &'static [&'static str],\n    pub description: &'static str,\n}\n\nimpl ReasonCode {\n");
    for row in &rows {
        let code = string(row, "code")?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            code.to_ascii_uppercase(),
            rust_string(code)
        )?;
    }
    output.push_str("\n    pub fn as_str(&self) -> &str {\n        match self {\n");
    for row in &rows {
        let code = string(row, "code")?;
        writeln!(
            output,
            "            Self::{} => Self::{},",
            variant(code, &[]),
            code.to_ascii_uppercase()
        )?;
    }
    output.push_str("            Self::Unknown(value) => value,\n        }\n    }\n\n    pub fn from_wire(value: &str) -> Self {\n        match value {\n");
    for row in &rows {
        let code = string(row, "code")?;
        writeln!(
            output,
            "            Self::{} => Self::{},",
            code.to_ascii_uppercase(),
            variant(code, &[])
        )?;
    }
    output.push_str("            _ => Self::Unknown(value.to_owned()),\n        }\n    }\n\n    /// Whether `value` is a reason code registered in\n    /// `registry/error-code-registry.json` (as opposed to merely well-formed,\n    /// which [`Self::is_valid_wire`] checks).\n    pub fn is_registered(value: &str) -> bool {\n        !matches!(Self::from_wire(value), Self::Unknown(_))\n    }\n\n    pub fn is_valid_wire(value: &str) -> bool {\n        let mut characters = value.chars();\n        matches!(characters.next(), Some('a'..='z')) && value.len() <= 64 && characters.all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_')\n    }\n\n    pub fn descriptor(&self) -> Option<&'static ReasonCodeDescriptor> {\n        REASON_CODE_DESCRIPTORS.iter().find(|row| row.code == self.as_str())\n    }\n}\n\nimpl Serialize for ReasonCode {\n    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {\n        if !Self::is_valid_wire(self.as_str()) { return Err(serde::ser::Error::custom(\"invalid reason code\")); }\n        serializer.serialize_str(self.as_str())\n    }\n}\n\nimpl<'de> Deserialize<'de> for ReasonCode {\n    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {\n        let value = String::deserialize(deserializer)?;\n        if !Self::is_valid_wire(&value) { return Err(serde::de::Error::custom(\"invalid reason code\")); }\n        Ok(Self::from_wire(&value))\n    }\n}\n\n#[cfg(feature = \"openapi\")]\nimpl salvo_oapi::ToSchema for ReasonCode {\n    fn to_schema(_components: &mut salvo_oapi::Components) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {\n        salvo_oapi::schema::Object::new().schema_type(salvo_oapi::schema::BasicType::String).pattern(\"^[a-z][a-z0-9_]{0,63}$\").max_length(64).into()\n    }\n}\n\n#[cfg(feature = \"openapi\")]\nimpl salvo_oapi::ComposeSchema for ReasonCode {\n    fn compose(components: &mut salvo_oapi::Components, generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {\n        let _ = generics;\n        <Self as salvo_oapi::ToSchema>::to_schema(components)\n    }\n}\n\npub const REASON_CODE_DESCRIPTORS: &[ReasonCodeDescriptor] = &[\n");
    for row in rows {
        let applies = row
            .get("applies_to")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let code = string(row, "code")?;
        writeln!(
            output,
            "    ReasonCodeDescriptor {{\n        code: ReasonCode::{},\n        applies_to: {},\n        description: {},\n    }},",
            code.to_ascii_uppercase(),
            string_slice(&applies),
            rust_string(string(row, "description")?)
        )?;
    }
    output.push_str(
        "];\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn descriptor_and_wire_tables_are_bijective() {\n        for (index, descriptor) in REASON_CODE_DESCRIPTORS.iter().enumerate() {\n            assert!(index == 0 || REASON_CODE_DESCRIPTORS[index - 1].code < descriptor.code);\n            let parsed = ReasonCode::from_wire(descriptor.code);\n            assert_eq!(parsed.as_str(), descriptor.code);\n            assert!(ReasonCode::is_registered(descriptor.code));\n            assert_eq!(parsed.descriptor(), Some(descriptor));\n        }\n        let unknown = ReasonCode::from_wire(\"reserved_or_unknown\");\n        assert_eq!(unknown, ReasonCode::Unknown(\"reserved_or_unknown\".to_owned()));\n        assert!(!ReasonCode::is_registered(unknown.as_str()));\n        assert_eq!(unknown.descriptor(), None);\n    }\n}\n",
    );
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/error_codes/reason_code.rs".into(),
        contents: output,
    })
}

fn generate_service_kinds(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/service-kind-registry.json")?;
    let rows = sorted_rows(
        artifact
            .array("service_kinds")?
            .into_iter()
            .filter(|row| string(row, "status").is_ok_and(|status| status == "active"))
            .collect(),
        "canonical_id",
    )?;
    validate_unique(&rows, "canonical_id", &[])?;
    let mut output = header(&[&artifact.source], &format!("active={}", rows.len()));
    output.push_str("use serde::{Deserialize, Serialize};\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]\n#[serde(rename_all = \"snake_case\")]\n#[repr(usize)]\n#[cfg_attr(feature = \"openapi\", derive(salvo_oapi::ToSchema))]\npub enum ServiceKind {\n");
    for row in &rows {
        writeln!(
            output,
            "    {},",
            variant(string(row, "canonical_id")?, &[])
        )?;
    }
    output.push_str("}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ServiceKindDescriptor {\n    pub service_kind: ServiceKind,\n    pub valid_in: &'static [&'static str],\n    pub description: &'static str,\n}\n\nimpl ServiceKind {\n    pub const ALL: &'static [Self] = &[\n");
    for row in &rows {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "canonical_id")?, &[])
        )?;
    }
    output.push_str(
        "    ];\n\n    pub const fn as_str(self) -> &'static str {\n        match self {\n",
    );
    for row in &rows {
        writeln!(
            output,
            "            Self::{} => {},",
            variant(string(row, "canonical_id")?, &[]),
            rust_string(string(row, "canonical_id")?)
        )?;
    }
    output.push_str("        }\n    }\n\n    pub fn descriptor(self) -> &'static ServiceKindDescriptor {\n        &SERVICE_KIND_DESCRIPTORS[self as usize]\n    }\n\n    pub fn valid_in(self, context: &str) -> bool {\n        self.descriptor().valid_in.contains(&context)\n    }\n}\n\npub const SERVICE_KIND_DESCRIPTORS: &[ServiceKindDescriptor] = &[\n");
    for row in &rows {
        let valid_in = strings(row, "valid_in")?;
        writeln!(
            output,
            "    ServiceKindDescriptor {{\n        service_kind: ServiceKind::{},\n        valid_in: {},\n        description: {},\n    }},",
            variant(string(row, "canonical_id")?, &[]),
            string_slice(&valid_in),
            rust_string(string(row, "description")?)
        )?;
    }
    output.push_str("];\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/service_kinds.rs".into(),
        contents: output,
    })
}

fn generate_relation_kinds(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/relation-kind-registry.json")?;
    let rows = sorted_rows(artifact.array("relation_kinds")?, "canonical_id")?;
    validate_unique(&rows, "canonical_id", &[])?;
    let mut output = header(&[&artifact.source], &format!("standard={}", rows.len()));
    output.push_str("use serde::{Deserialize, Deserializer, Serialize, Serializer};\n\n#[derive(Clone, Debug, PartialEq, Eq, Hash)]\npub enum RelationKind {\n");
    for row in &rows {
        writeln!(
            output,
            "    {},",
            variant(string(row, "canonical_id")?, &[])
        )?;
    }
    output.push_str("    Custom(String),\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub enum RelationTruthSourceClass {\n    Canonical,\n    DerivedProjection,\n    ShapeDependent,\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct RelationKindDescriptor {\n    pub canonical_id: &'static str,\n    pub default_cardinality: &'static str,\n    pub primary_conflict_domain: &'static str,\n    /// Primary conflict domain of the directly writable shape, if any.\n    pub direct_write_primary_conflict_domain: Option<&'static str>,\n    pub truth_source_class: RelationTruthSourceClass,\n    pub weak_semantic: bool,\n}\n\nimpl RelationKind {\n    pub const STANDARD: &'static [Self] = &[\n");
    for row in &rows {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "canonical_id")?, &[])
        )?;
    }
    output.push_str("    ];\n\n    pub fn as_str(&self) -> &str {\n        match self {\n");
    for row in &rows {
        writeln!(
            output,
            "            Self::{} => {},",
            variant(string(row, "canonical_id")?, &[]),
            rust_string(string(row, "canonical_id")?)
        )?;
    }
    output.push_str("            Self::Custom(value) => value,\n        }\n    }\n\n    pub fn from_wire(value: &str) -> Self {\n        match value {\n");
    for row in &rows {
        writeln!(
            output,
            "            {} => Self::{},",
            rust_string(string(row, "canonical_id")?),
            variant(string(row, "canonical_id")?, &[])
        )?;
    }
    output.push_str("            _ => Self::Custom(value.to_owned()),\n        }\n    }\n\n    pub fn descriptor(&self) -> Option<&'static RelationKindDescriptor> {\n        RELATION_KIND_DESCRIPTORS.iter().find(|row| row.canonical_id == self.as_str())\n    }\n\n    pub fn is_standard(&self) -> bool {\n        self.descriptor().is_some()\n    }\n\n    pub fn is_structural(&self) -> bool {\n        self.descriptor().is_some_and(|row| !row.weak_semantic)\n    }\n}\n\nimpl Serialize for RelationKind {\n    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {\n        serializer.serialize_str(self.as_str())\n    }\n}\n\nimpl<'de> Deserialize<'de> for RelationKind {\n    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {\n        Ok(Self::from_wire(&String::deserialize(deserializer)?))\n    }\n}\n\npub const RELATION_KIND_DESCRIPTORS: &[RelationKindDescriptor] = &[\n");
    for row in rows {
        let direct_write_domain = match row.get("shapes") {
            Some(shapes) => {
                let direct = shapes
                    .as_array()
                    .context("relation kind shapes is not an array")?
                    .iter()
                    .filter(|shape| {
                        shape.get("writability").and_then(Value::as_str) == Some("direct")
                    })
                    .collect::<Vec<_>>();
                match direct.as_slice() {
                    [] => None,
                    [shape] => Some(string(
                        shape
                            .as_object()
                            .context("relation kind shape is not an object")?,
                        "primary_conflict_domain",
                    )?),
                    _ => bail!(
                        "relation kind {} declares more than one directly writable shape",
                        string(row, "canonical_id")?
                    ),
                }
            }
            None => Some(string(row, "primary_conflict_domain")?),
        };
        writeln!(
            output,
            "    RelationKindDescriptor {{\n        canonical_id: {},\n        default_cardinality: {},\n        primary_conflict_domain: {},\n        direct_write_primary_conflict_domain: {},\n        truth_source_class: RelationTruthSourceClass::{},\n        weak_semantic: {},\n    }},",
            rust_string(string(row, "canonical_id")?),
            rust_string(string(row, "default_cardinality")?),
            rust_string(if row.get("shapes").is_some() {
                "shape_dependent"
            } else {
                string(row, "primary_conflict_domain")?
            }),
            match direct_write_domain {
                Some(domain) => format!("Some({})", rust_string(domain)),
                None => "None".to_owned(),
            },
            variant(string(row, "truth_source_class")?, &[]),
            field(row, "weak_semantic")?
                .as_bool()
                .context("weak_semantic is not boolean")?
        )?;
    }
    output.push_str("];\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/relation_kinds.rs".into(),
        contents: output,
    })
}

fn generate_capability_actions(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/contract-registry.json")?;
    let rows = sorted_rows(
        artifact.section_array("capability_action_registry", "actions")?,
        "action",
    )?;
    validate_unique(&rows, "action", &["ak."])?;
    let mut output = simple_string_enum(
        &artifact,
        &rows,
        "action",
        &["ak."],
        "CapabilityActionId",
        &format!("registered={}", rows.len()),
        true,
    )?;
    let marker = "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]";
    output = output.replacen(marker, "use serde::{Deserialize, Serialize};\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]", 1);
    output.push_str("\nimpl std::fmt::Display for CapabilityActionId {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        f.write_str(self.as_str())\n    }\n}\n\nimpl Serialize for CapabilityActionId {\n    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {\n        serializer.serialize_str(self.as_str())\n    }\n}\n\nimpl<'de> Deserialize<'de> for CapabilityActionId {\n    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {\n        let raw = String::deserialize(deserializer)?;\n        Self::from_wire(&raw).ok_or_else(|| serde::de::Error::custom(format!(\"unknown capability action id: {raw}\")))\n    }\n}\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/capability_actions.rs".into(),
        contents: output,
    })
}

fn emit_closed_enum(output: &mut String, type_name: &str, values: &[String]) -> Result<()> {
    writeln!(
        output,
        "#[cfg_attr(feature = \"openapi\", derive(salvo_oapi::ToSchema))]\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]\n#[serde(rename_all = \"snake_case\")]\npub enum {type_name} {{"
    )?;
    for value in values {
        writeln!(output, "    {},", variant(value, &[]))?;
    }
    writeln!(
        output,
        "}}\n\nimpl {type_name} {{\n    pub const ALL: &'static [Self] = &["
    )?;
    for value in values {
        writeln!(output, "        Self::{},", variant(value, &[]))?;
    }
    output.push_str(
        "    ];\n\n    pub const fn as_str(self) -> &'static str {\n        match self {\n",
    );
    for value in values {
        writeln!(
            output,
            "            Self::{} => {},",
            variant(value, &[]),
            rust_string(value)
        )?;
    }
    output.push_str("        }\n    }\n\n    pub fn from_wire(value: &str) -> Option<Self> {\n        match value {\n");
    for value in values {
        writeln!(
            output,
            "            {} => Some(Self::{}),",
            rust_string(value),
            variant(value, &[])
        )?;
    }
    writeln!(
        output,
        "            _ => None,\n        }}\n    }}\n}}\n\nimpl std::fmt::Display for {type_name} {{\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\n        f.write_str((*self).as_str())\n    }}\n}}"
    )?;
    Ok(())
}

fn generate_closed_registry_types(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let contracts = Artifact::load(artifacts_dir, "registry/contract-registry.json")?;
    let authority = Artifact::load(artifacts_dir, "registry/authority-set-policy-registry.json")?;
    let tracks = sorted_rows(
        contracts
            .section_array("track_name_registry", "track_names")?
            .into_iter()
            .filter(|row| {
                row.get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("active")
                    == "active"
            })
            .collect(),
        "track_name",
    )?;
    let bindings = sorted_rows(
        contracts
            .section_array("binding_kind_registry", "entries")?
            .into_iter()
            .filter(|row| {
                matches!(
                    row.get("status").and_then(Value::as_str),
                    Some("active" | "candidate")
                )
            })
            .collect(),
        "kind",
    )?;
    let policies = authority.array("policies")?;
    let policy_kinds = policies
        .iter()
        .map(|row| string(row, "policy_kind").map(str::to_owned))
        .collect::<Result<BTreeSet<_>>>()?
        .into_iter()
        .collect::<Vec<_>>();
    let source_kinds = policies
        .iter()
        .map(|row| string(row, "source_kind").map(str::to_owned))
        .collect::<Result<BTreeSet<_>>>()?
        .into_iter()
        .collect::<Vec<_>>();
    validate_unique(&tracks, "track_name", &[])?;
    validate_unique(&bindings, "kind", &[])?;
    let mut output = header(
        &[&contracts.source, &authority.source],
        &format!(
            "track_names={}, binding_kinds={}, authority_policy_kinds={}, authority_source_kinds={}",
            tracks.len(),
            bindings.len(),
            policy_kinds.len(),
            source_kinds.len()
        ),
    );
    output.push_str("use serde::{Deserialize, Serialize};\n\n");
    emit_closed_enum(
        &mut output,
        "TrackName",
        &tracks
            .iter()
            .map(|row| string(row, "track_name").map(str::to_owned))
            .collect::<Result<Vec<_>>>()?,
    )?;
    output.push('\n');
    emit_closed_enum(
        &mut output,
        "BindingKind",
        &bindings
            .iter()
            .map(|row| string(row, "kind").map(str::to_owned))
            .collect::<Result<Vec<_>>>()?,
    )?;
    output.push('\n');
    emit_closed_enum(&mut output, "AuthoritySetPolicyKind", &policy_kinds)?;
    output.push('\n');
    emit_closed_enum(&mut output, "AuthoritySetSourceKind", &source_kinds)?;
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/closed_registry_types.rs".into(),
        contents: output,
    })
}

fn generate_account_data_keys(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/account-data-key-registry.json")?;
    let rows = sorted_rows(
        artifact
            .array("account_data_key_patterns")?
            .into_iter()
            .filter(|row| string(row, "status").is_ok_and(|status| status == "active"))
            .collect(),
        "key_pattern",
    )?;
    let namespaces = rows
        .iter()
        .map(|row| {
            let pattern = string(row, "key_pattern")?;
            Ok(pattern
                .split('<')
                .next()
                .unwrap_or(pattern)
                .trim_end_matches(['.', ':'])
                .to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    let owned = namespaces
        .iter()
        .map(|value| Map::from_iter([(String::from("namespace"), Value::String(value.clone()))]))
        .collect::<Vec<_>>();
    validate_unique(&owned.iter().collect::<Vec<_>>(), "namespace", &["ak."])?;
    let mut output = header(
        &[&artifact.source],
        &format!("account_data_keys={}", rows.len()),
    );
    output.push_str("use serde::{Deserialize, Serialize};\n\n/// Registered Account Data key namespaces. The registry rows are key\n/// *patterns*; this type carries the literal head of each pattern, which is\n/// the value clients and servers compare against and the only place the\n/// namespace literal is spelled.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\n#[repr(usize)]\npub enum AccountDataKey {\n");
    for value in &namespaces {
        writeln!(output, "    {},", variant(value, &["ak."]))?;
    }
    output.push_str("}\n\nimpl AccountDataKey {\n    pub const ALL: &'static [Self] = &[\n");
    for value in &namespaces {
        writeln!(output, "        Self::{},", variant(value, &["ak."]))?;
    }
    output.push_str("    ];\n\n");
    for (value, row) in namespaces.iter().zip(&rows) {
        if let Some(description) = row.get("description").and_then(Value::as_str) {
            writeln!(output, "    /// {}", rustdoc(description))?;
        }
        writeln!(
            output,
            "    /// Key pattern: `{}`.\n    pub const {}: &'static str = {};",
            string(row, "key_pattern")?,
            associated_name(value, &["ak."]),
            rust_string(value)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str {\n        match self {\n");
    for value in &namespaces {
        writeln!(
            output,
            "            Self::{} => Self::{},",
            variant(value, &["ak."]),
            associated_name(value, &["ak."])
        )?;
    }
    output.push_str("        }\n    }\n\n    /// Whether `value` is this key exactly, or a parameterized key inside\n    /// this namespace (`<namespace>:<...>` or `<namespace>.<...>`).\n    pub fn matches(self, value: &str) -> bool {\n        let namespace = self.as_str();\n        let Some(rest) = value.strip_prefix(namespace) else { return false; };\n        rest.is_empty() || (matches!(rest.as_bytes().first(), Some(b':' | b'.')) && rest.len() > 1)\n    }\n\n    pub fn from_wire(value: &str) -> Option<Self> {\n        match value {\n");
    for value in &namespaces {
        writeln!(
            output,
            "            Self::{} => Some(Self::{}),",
            associated_name(value, &["ak."]),
            variant(value, &["ak."])
        )?;
    }
    output.push_str("            _ => None,\n        }\n    }\n\n    /// Resolve a concrete Account Data key to its registered namespace.\n    pub fn for_key(value: &str) -> Option<Self> {\n        Self::ALL.iter().copied().find(|key| key.matches(value))\n    }\n}\n\nimpl std::fmt::Display for AccountDataKey {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }\n}\n\nimpl Serialize for AccountDataKey {\n    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(self.as_str()) }\n}\n\nimpl<'de> Deserialize<'de> for AccountDataKey {\n    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {\n        let raw = String::deserialize(deserializer)?;\n        Self::from_wire(&raw).ok_or_else(|| serde::de::Error::custom(format!(\"unknown account data key: {raw}\")))\n    }\n}\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/account_data_keys.rs".into(),
        contents: output,
    })
}

/// Closed client-local state machine of the creator MLS Genesis bootstrap
/// transaction. The state and transition identifiers are wire-neutral durable
/// labels, so every consumer resolves them through this one generated enum
/// instead of re-spelling the registry.
fn generate_mls_creator_bootstrap(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(
        artifacts_dir,
        "registry/mls-creator-bootstrap-transaction-registry.json",
    )?;
    let states = artifact.array("states")?;
    let transitions = artifact.array("transitions")?;
    validate_unique(&states, "state_id", &[])?;
    validate_unique(&transitions, "transition_id", &[])?;
    let state_ids = states
        .iter()
        .map(|row| string(row, "state_id"))
        .collect::<Result<BTreeSet<_>>>()?;
    for (index, row) in states.iter().enumerate() {
        let ordinal = field(row, "ordinal")?
            .as_u64()
            .context("state ordinal is not an integer")?;
        if ordinal != index as u64 + 1 {
            bail!("creator bootstrap states must be listed in ordinal order");
        }
        for exit in strings(row, "allowed_exits")? {
            if !state_ids.contains(exit.as_str()) {
                bail!("creator bootstrap state names an unknown exit: {exit}");
            }
        }
    }
    let mut kinds = BTreeSet::new();
    for row in &states {
        kinds.insert(string(row, "kind")?);
    }

    let mut failure_dispositions = BTreeSet::new();
    for row in &states {
        failure_dispositions.insert(string(row, "failure_disposition")?);
    }

    let mut output = header(
        &[&artifact.source],
        &format!(
            "states={}, transitions={}, state_kinds={}",
            states.len(),
            transitions.len(),
            kinds.len()
        ),
    );
    output.push_str("use serde::{Deserialize, Serialize};\n\n/// Registered disposition of a failed creator invariant.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub enum MlsCreatorBootstrapFailureDisposition {\n");
    for value in &failure_dispositions {
        writeln!(output, "    {},", variant(value, &[]))?;
    }
    output.push_str("}\n\nimpl MlsCreatorBootstrapFailureDisposition {\n    pub const ALL: &'static [Self] = &[\n");
    for value in &failure_dispositions {
        writeln!(output, "        Self::{},", variant(value, &[]))?;
    }
    output.push_str(
        "    ];\n\n    pub const fn as_str(self) -> &'static str {\n        match self {\n",
    );
    for value in &failure_dispositions {
        writeln!(
            output,
            "            Self::{} => {},",
            variant(value, &[]),
            rust_string(value)
        )?;
    }
    output.push_str("        }\n    }\n\n    pub fn from_wire(value: &str) -> Option<Self> {\n        match value {\n");
    for value in &failure_dispositions {
        writeln!(
            output,
            "            {} => Some(Self::{}),",
            rust_string(value),
            variant(value, &[])
        )?;
    }
    output.push_str("            _ => None,\n        }\n    }\n}\n\n");
    output.push_str(
        "/// Lifecycle class of one creator MLS Genesis bootstrap state.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub enum MlsCreatorBootstrapStateKind {\n",
    );
    for kind in &kinds {
        writeln!(output, "    {},", variant(kind, &[]))?;
    }
    output.push_str(
        "}\n\nimpl MlsCreatorBootstrapStateKind {\n    pub const ALL: &'static [Self] = &[\n",
    );
    for kind in &kinds {
        writeln!(output, "        Self::{},", variant(kind, &[]))?;
    }
    output.push_str(
        "    ];\n\n    pub const fn as_str(self) -> &'static str {\n        match self {\n",
    );
    for kind in &kinds {
        writeln!(
            output,
            "            Self::{} => {},",
            variant(kind, &[]),
            rust_string(kind)
        )?;
    }
    output.push_str("        }\n    }\n\n    pub fn from_wire(value: &str) -> Option<Self> {\n        match value {\n");
    for kind in &kinds {
        writeln!(
            output,
            "            {} => Some(Self::{}),",
            rust_string(kind),
            variant(kind, &[])
        )?;
    }
    output.push_str("            _ => None,\n        }\n    }\n}\n\n");

    output.push_str(
        "/// Durable state of the single client-local creator MLS Genesis bootstrap\n/// transaction, keyed by `(owner_actor_id, effective_scope, operation)`.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub enum MlsCreatorBootstrapState {\n",
    );
    for row in &states {
        writeln!(output, "    {},", variant(string(row, "state_id")?, &[]))?;
    }
    output.push_str("}\n\nimpl MlsCreatorBootstrapState {\n    /// Registry order, which is the ordinal order of the state machine.\n    pub const ALL: &'static [Self] = &[\n");
    for row in &states {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "state_id")?, &[])
        )?;
    }
    output.push_str("    ];\n\n");
    for row in &states {
        let value = string(row, "state_id")?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            associated_name(value, &[]),
            rust_string(value)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str {\n        match self {\n");
    for row in &states {
        let value = string(row, "state_id")?;
        writeln!(
            output,
            "            Self::{} => Self::{},",
            variant(value, &[]),
            associated_name(value, &[])
        )?;
    }
    output.push_str("        }\n    }\n\n    pub fn from_wire(value: &str) -> Option<Self> {\n        match value {\n");
    for row in &states {
        let value = string(row, "state_id")?;
        writeln!(
            output,
            "            Self::{} => Some(Self::{}),",
            associated_name(value, &[]),
            variant(value, &[])
        )?;
    }
    output.push_str("            _ => None,\n        }\n    }\n\n    pub fn descriptor(self) -> &'static MlsCreatorBootstrapStateDescriptor {\n        &MLS_CREATOR_BOOTSTRAP_STATES[self as usize]\n    }\n\n    pub fn ordinal(self) -> u32 {\n        self.descriptor().ordinal\n    }\n\n    pub fn kind(self) -> MlsCreatorBootstrapStateKind {\n        self.descriptor().kind\n    }\n\n    pub fn failure_disposition(self) -> MlsCreatorBootstrapFailureDisposition {\n        self.descriptor().failure_disposition\n    }\n\n    /// States a recoverer may move to from here. A terminal state has none.\n    pub fn allowed_exits(self) -> &'static [MlsCreatorBootstrapState] {\n        self.descriptor().allowed_exits\n    }\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct MlsCreatorBootstrapStateDescriptor {\n    pub state: MlsCreatorBootstrapState,\n    pub ordinal: u32,\n    pub kind: MlsCreatorBootstrapStateKind,\n    pub failure_disposition: MlsCreatorBootstrapFailureDisposition,\n    pub allowed_exits: &'static [MlsCreatorBootstrapState],\n}\n\npub const MLS_CREATOR_BOOTSTRAP_STATES: &[MlsCreatorBootstrapStateDescriptor] = &[\n");
    for row in &states {
        let value = string(row, "state_id")?;
        let exits = strings(row, "allowed_exits")?
            .iter()
            .map(|exit| format!("MlsCreatorBootstrapState::{}", variant(exit, &[])))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            output,
            "    MlsCreatorBootstrapStateDescriptor {{ state: MlsCreatorBootstrapState::{}, ordinal: {}, kind: MlsCreatorBootstrapStateKind::{}, failure_disposition: MlsCreatorBootstrapFailureDisposition::{}, allowed_exits: &[{}] }},",
            variant(value, &[]),
            field(row, "ordinal")?
                .as_u64()
                .context("state ordinal is not an integer")?,
            variant(string(row, "kind")?, &[]),
            variant(string(row, "failure_disposition")?, &[]),
            exits
        )?;
    }
    output.push_str("];\n\n");

    output.push_str(
        "/// The single arrows a recoverer may execute. `from_state` is `None` for\n/// the one arrow that creates the record.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub enum MlsCreatorBootstrapTransition {\n",
    );
    for row in &transitions {
        writeln!(
            output,
            "    {},",
            variant(string(row, "transition_id")?, &[])
        )?;
    }
    output.push_str(
        "}\n\nimpl MlsCreatorBootstrapTransition {\n    pub const ALL: &'static [Self] = &[\n",
    );
    for row in &transitions {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, "transition_id")?, &[])
        )?;
    }
    output.push_str("    ];\n\n");
    for row in &transitions {
        let value = string(row, "transition_id")?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            associated_name(value, &[]),
            rust_string(value)
        )?;
    }
    output.push_str("\n    pub const fn as_str(self) -> &'static str {\n        match self {\n");
    for row in &transitions {
        let value = string(row, "transition_id")?;
        writeln!(
            output,
            "            Self::{} => Self::{},",
            variant(value, &[]),
            associated_name(value, &[])
        )?;
    }
    output.push_str("        }\n    }\n\n    pub fn from_wire(value: &str) -> Option<Self> {\n        match value {\n");
    for row in &transitions {
        let value = string(row, "transition_id")?;
        writeln!(
            output,
            "            Self::{} => Some(Self::{}),",
            associated_name(value, &[]),
            variant(value, &[])
        )?;
    }
    output.push_str("            _ => None,\n        }\n    }\n\n    pub fn descriptor(self) -> &'static MlsCreatorBootstrapTransitionDescriptor {\n        &MLS_CREATOR_BOOTSTRAP_TRANSITIONS[self as usize]\n    }\n\n    pub fn from_state(self) -> Option<MlsCreatorBootstrapState> {\n        self.descriptor().from_state\n    }\n\n    pub fn to_state(self) -> MlsCreatorBootstrapState {\n        self.descriptor().to_state\n    }\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct MlsCreatorBootstrapTransitionDescriptor {\n    pub transition: MlsCreatorBootstrapTransition,\n    pub from_state: Option<MlsCreatorBootstrapState>,\n    pub to_state: MlsCreatorBootstrapState,\n}\n\npub const MLS_CREATOR_BOOTSTRAP_TRANSITIONS: &[MlsCreatorBootstrapTransitionDescriptor] = &[\n");
    for row in &transitions {
        let value = string(row, "transition_id")?;
        let from_state = match field(row, "from_state")? {
            Value::Null => "None".to_owned(),
            Value::String(state) => {
                if !state_ids.contains(state.as_str()) {
                    bail!("creator bootstrap transition names an unknown from_state: {state}");
                }
                format!("Some(MlsCreatorBootstrapState::{})", variant(state, &[]))
            }
            _ => bail!("creator bootstrap transition from_state must be a string or null"),
        };
        let to_state = string(row, "to_state")?;
        if !state_ids.contains(to_state) {
            bail!("creator bootstrap transition names an unknown to_state: {to_state}");
        }
        writeln!(
            output,
            "    MlsCreatorBootstrapTransitionDescriptor {{ transition: MlsCreatorBootstrapTransition::{}, from_state: {}, to_state: MlsCreatorBootstrapState::{} }},",
            variant(value, &[]),
            from_state,
            variant(to_state, &[])
        )?;
    }
    output.push_str("];\n\n");
    for name in [
        "MlsCreatorBootstrapFailureDisposition",
        "MlsCreatorBootstrapStateKind",
        "MlsCreatorBootstrapState",
        "MlsCreatorBootstrapTransition",
    ] {
        writeln!(
            output,
            "impl std::fmt::Display for {name} {{ fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{ f.write_str(self.as_str()) }} }}\nimpl Serialize for {name} {{ fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {{ serializer.serialize_str(self.as_str()) }} }}\nimpl<'de> Deserialize<'de> for {name} {{ fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {{ let raw = String::deserialize(deserializer)?; Self::from_wire(&raw).ok_or_else(|| serde::de::Error::custom(format!(\"unknown {name} value: {{raw}}\"))) }} }}"
        )?;
    }
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/mls_creator_bootstrap.rs".into(),
        contents: output,
    })
}

fn simple_string_enum(
    artifact: &Artifact,
    rows: &[&Map<String, Value>],
    key: &str,
    prefixes: &[&str],
    enum_name: &str,
    counts: &str,
    repr_usize: bool,
) -> Result<String> {
    validate_unique(rows, key, prefixes)?;
    let mut output = header(&[&artifact.source], counts);
    writeln!(
        output,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]"
    )?;
    if repr_usize {
        writeln!(output, "#[repr(usize)]")?;
    }
    writeln!(output, "pub enum {enum_name} {{")?;
    for row in rows {
        writeln!(output, "    {},", variant(string(row, key)?, prefixes))?;
    }
    writeln!(
        output,
        "}}\n\nimpl {enum_name} {{\n    pub const ALL: &'static [Self] = &["
    )?;
    for row in rows {
        writeln!(
            output,
            "        Self::{},",
            variant(string(row, key)?, prefixes)
        )?;
    }
    writeln!(output, "    ];\n")?;
    for row in rows {
        let value = string(row, key)?;
        writeln!(
            output,
            "    pub const {}: &'static str = {};",
            associated_name(value, prefixes),
            rust_string(value)
        )?;
    }
    writeln!(
        output,
        "\n    pub const fn as_str(self) -> &'static str {{\n        match self {{"
    )?;
    for row in rows {
        let value = string(row, key)?;
        writeln!(
            output,
            "            Self::{} => Self::{},",
            variant(value, prefixes),
            associated_name(value, prefixes)
        )?;
    }
    writeln!(
        output,
        "        }}\n    }}\n\n    pub fn from_wire(value: &str) -> Option<Self> {{\n        match value {{"
    )?;
    for row in rows {
        let value = string(row, key)?;
        writeln!(
            output,
            "            Self::{} => Some(Self::{}),",
            associated_name(value, prefixes),
            variant(value, prefixes)
        )?;
    }
    writeln!(output, "            _ => None,\n        }}\n    }}\n}}")?;
    Ok(output)
}

fn generate_service_contract_ids(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/contract-registry.json")?;
    let rows = sorted_rows(artifact.array("service_contracts")?, "contract_id")?;
    let contents = simple_string_enum(
        &artifact,
        &rows,
        "contract_id",
        &["ak."],
        "ServiceContractId",
        &format!("service_contracts={}", rows.len()),
        true,
    )?;
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/service_contract_ids.rs".into(),
        contents,
    })
}

fn generate_device_message_kinds(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "schemas/device-message.schema.json")?;
    let mut values = artifact
        .value
        .pointer("/$defs/actor_private_update_kind/enum")
        .and_then(Value::as_array)
        .context("device-message schema missing actor_private_update_kind enum")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .context("device message kind is not a string")
        })
        .collect::<Result<Vec<_>>>()?;
    values.sort_unstable();
    let owned = values
        .into_iter()
        .map(|value| Map::from_iter([(String::from("kind"), Value::String(value.to_owned()))]))
        .collect::<Vec<_>>();
    let rows = owned.iter().collect::<Vec<_>>();
    let contents = simple_string_enum(
        &artifact,
        &rows,
        "kind",
        &["ak."],
        "ActorPrivateUpdateKind",
        &format!("actor_private_update_kinds={}", rows.len()),
        false,
    )?;
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/device_message_kinds.rs".into(),
        contents,
    })
}

fn generate_authority_set_ids(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/authority-set-policy-registry.json")?;
    let rows = sorted_rows(artifact.array("policies")?, "authority_set_id")?;
    let contents = simple_string_enum(
        &artifact,
        &rows,
        "authority_set_id",
        &["ak.authority_set."],
        "AuthoritySetId",
        &format!("authority_sets={}", rows.len()),
        false,
    )?;
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/authority_set_ids.rs".into(),
        contents,
    })
}

fn rustdoc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn generate_redactable_fields(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/redactable-field-registry.json")?;
    let mut rows = artifact.array("redactable_fields")?;
    rows.sort_by_key(|row| {
        (
            string(row, "object_kind").unwrap(),
            string(row, "path").unwrap(),
        )
    });
    let paths = rows
        .iter()
        .map(|row| string(row, "path"))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut output = header(
        &[&artifact.source],
        &format!(
            "redactable_fields={}, distinct_paths={}",
            rows.len(),
            paths.len()
        ),
    );
    output.push_str("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct RedactableFieldDescriptor {\n    pub object_kind: &'static str,\n    pub path: &'static str,\n    pub paired_path: &'static str,\n    pub non_terminal_clear_op: &'static str,\n    pub terminal_clear_event_kinds: &'static [&'static str],\n}\n\n/// Registered redactable content-carrier slots\n/// (`event-and-patch.md` section 4.2.4).\npub const REDACTABLE_FIELDS: &[RedactableFieldDescriptor] = &[\n");
    for row in rows {
        let terminal = strings(row, "terminal_clear_event_kinds")?;
        writeln!(
            output,
            "    RedactableFieldDescriptor {{\n        object_kind: {},\n        path: {},\n        paired_path: {},\n        non_terminal_clear_op: {},\n        terminal_clear_event_kinds: {},\n    }},",
            rust_string(string(row, "object_kind")?),
            rust_string(string(row, "path")?),
            rust_string(string(row, "paired_path")?),
            rust_string(string(row, "non_terminal_clear_op")?),
            string_slice(&terminal)
        )?;
    }
    output.push_str("];\n\n/// Distinct slot paths a patch `$op=\"unset\"` must never address.\n/// Realm-defined `redactable: true` fields are declared by their own\n/// Realm schema and are enforced separately.\npub const REDACTABLE_FIELD_PATHS: &[&str] = &[\n");
    for path in paths {
        writeln!(output, "    {},", rust_string(path))?;
    }
    output.push_str("];\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/redactable_fields.rs".into(),
        contents: output,
    })
}

/// Project `registry/reducer-managed-path-registry.json` (the declared source
/// of truth for `event-and-patch.md` section 4.2.5) into the per-object
/// effective forbidden set plus the object-agnostic universal minimum.
///
/// The registry's own rule decides the effective set: the universal paths an
/// object's schema actually declares, minus that object's registered
/// exemptions, plus its own bans. This generator resolves the schema
/// restriction here so no consumer re-derives it, and the emitted table is the
/// only copy any SDK, reducer or conformance runner reads.
fn generate_reducer_managed_patch_paths(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/reducer-managed-path-registry.json")?;
    let universal = artifact.array("universal_forbidden_patch_paths")?;
    let mut objects = artifact.array("objects")?;
    objects.sort_by_key(|row| string(row, "object_kind").unwrap());

    let mut rendered_objects = String::new();
    let mut object_count = 0usize;
    let mut path_count = 0usize;
    for object in objects {
        let object_kind = string(object, "object_kind")?;
        let declared =
            declared_object_properties(artifacts_dir, string(object, "object_schema_ref")?)?;
        let exempt = artifact_paths(object, "universal_exemptions")?;
        let mut rows: Vec<(String, String)> = Vec::new();
        for row in &universal {
            let path = string(row, "path")?;
            if !declared.contains(path) || exempt.contains(path) {
                continue;
            }
            rows.push((path.to_owned(), render_reducer_managed_path(row, "None")?));
        }
        for row in artifact_rows(object, "forbidden_patch_paths")? {
            let path = string(row, "path")?;
            let schema_enforced = match field(row, "schema_enforced")?.as_bool() {
                Some(value) => format!("Some({value})"),
                None => bail!("{path} schema_enforced is not a boolean"),
            };
            rows.push((
                path.to_owned(),
                render_reducer_managed_path(row, &schema_enforced)?,
            ));
        }
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        path_count += rows.len();
        object_count += 1;
        writeln!(
            rendered_objects,
            "    ReducerManagedPatchObject {{\n        object_kind: {},\n        forbidden_paths: &[",
            rust_string(object_kind)
        )?;
        for (_, rendered) in rows {
            rendered_objects.push_str(&rendered);
        }
        rendered_objects.push_str("        ],\n    },\n");
    }

    let mut universal_paths = Vec::new();
    for row in &universal {
        universal_paths.push(string(row, "path")?.to_owned());
    }
    universal_paths.sort();

    let mut output = header(
        &[&artifact.source],
        &format!(
            "objects={object_count}, effective_paths={path_count}, universal_paths={}",
            universal_paths.len()
        ),
    );
    output.push_str(
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ReducerManagedPatchPath {\n    pub path: &'static str,\n    pub basis: &'static str,\n    pub reason_code: &'static str,\n    pub owner_kind: &'static str,\n    /// `Some(true)` when the named update payload already rejects the path\n    /// through its own guard; `None` for a universal path, which no payload\n    /// guard enumerates.\n    pub schema_enforced: Option<bool>,\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ReducerManagedPatchObject {\n    pub object_kind: &'static str,\n    /// Effective set: the universal paths this object's schema declares, minus\n    /// its registered exemptions, plus its own bans.\n    pub forbidden_paths: &'static [ReducerManagedPatchPath],\n}\n\n/// Every object kind whose update payload embeds the generic patch surface.\npub const REDUCER_MANAGED_PATCH_OBJECTS: &[ReducerManagedPatchObject] = &[\n",
    );
    output.push_str(&rendered_objects);
    output.push_str(
        "];\n\n/// The general minimum set, unrestricted and with no exemption honoured.\n/// It applies whenever the object kind behind a patch is not proven.\npub const REDUCER_MANAGED_ANY_OBJECT_PATCH_PATHS: &[&str] = &[\n",
    );
    for path in &universal_paths {
        writeln!(output, "    {},", rust_string(path))?;
    }
    output.push_str("];\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/reducer_managed_patch_paths.rs".into(),
        contents: output,
    })
}

fn render_reducer_managed_path(row: &Map<String, Value>, schema_enforced: &str) -> Result<String> {
    Ok(format!(
        "            ReducerManagedPatchPath {{\n                path: {},\n                basis: {},\n                reason_code: {},\n                owner_kind: {},\n                schema_enforced: {schema_enforced},\n            }},\n",
        rust_string(string(row, "path")?),
        rust_string(string(row, "basis")?),
        rust_string(string(row, "reason_code")?),
        rust_string(string(row, "owner_kind")?),
    ))
}

fn artifact_rows<'a>(
    row: &'a Map<String, Value>,
    key: &str,
) -> Result<Vec<&'a Map<String, Value>>> {
    field(row, key)?
        .as_array()
        .with_context(|| format!("field {key} is not an array"))?
        .iter()
        .map(|value| {
            value
                .as_object()
                .with_context(|| format!("field {key} contains a non-object"))
        })
        .collect()
}

fn artifact_paths(row: &Map<String, Value>, key: &str) -> Result<BTreeSet<String>> {
    artifact_rows(row, key)?
        .into_iter()
        .map(|entry| Ok(string(entry, "path")?.to_owned()))
        .collect()
}

fn declared_object_properties(artifacts_dir: &Path, schema_ref: &str) -> Result<BTreeSet<String>> {
    let path = artifacts_dir.join(schema_ref);
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let schema: Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    Ok(schema
        .get("properties")
        .and_then(Value::as_object)
        .with_context(|| format!("{schema_ref} declares no properties object"))?
        .keys()
        .cloned()
        .collect())
}

fn generate_forbidden_wire_fields(artifacts_dir: &Path) -> Result<GeneratedOutput> {
    let artifact = Artifact::load(artifacts_dir, "registry/forbidden-wire-fields.json")?;
    let mut entries = artifact.array("entries")?;
    entries.sort_by_key(|row| {
        (
            string(row, "context").unwrap().to_owned(),
            string(row, "id").unwrap().to_owned(),
        )
    });
    let mut output = header(
        &[&artifact.source],
        &format!("forbidden_wire_fields={}", entries.len()),
    );
    output.push_str("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ForbiddenWireSelector {\n    pub document_kind: &'static str,\n    pub schema_ref: &'static str,\n    pub instance_pointer: &'static str,\n    pub match_scope: &'static str,\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct ForbiddenWireFieldDescriptor {\n    pub id: &'static str,\n    pub context: &'static str,\n    pub rejection_level: &'static str,\n    pub selectors: &'static [ForbiddenWireSelector],\n    pub match_kind: &'static str,\n    pub match_values: &'static [&'static str],\n    pub value_pointer: &'static str,\n}\n\npub const FORBIDDEN_WIRE_FIELDS: &[ForbiddenWireFieldDescriptor] = &[\n");
    let definitions = artifact
        .value
        .get("context_definitions")
        .and_then(Value::as_object)
        .context("missing context_definitions")?;
    for row in entries {
        let context = string(row, "context")?;
        let selectors = definitions
            .get(context)
            .and_then(|v| v.get("selectors"))
            .and_then(Value::as_array)
            .with_context(|| format!("undefined context {context}"))?;
        let matcher = field(row, "match")?
            .as_object()
            .context("missing matcher")?;
        writeln!(
            output,
            "    ForbiddenWireFieldDescriptor {{ id: {}, context: {}, rejection_level: {}, selectors: &[",
            rust_string(string(row, "id")?),
            rust_string(context),
            rust_string(string(row, "rejection_level")?)
        )?;
        for selector in selectors {
            let selector = selector.as_object().context("invalid selector")?;
            writeln!(
                output,
                "        ForbiddenWireSelector {{ document_kind: {}, schema_ref: {}, instance_pointer: {}, match_scope: {} }},",
                rust_string(string(selector, "document_kind")?),
                rust_string(string(selector, "schema_ref")?),
                rust_string(string(selector, "instance_pointer")?),
                rust_string(string(selector, "match_scope")?)
            )?;
        }
        writeln!(
            output,
            "    ], match_kind: {}, match_values: {}, value_pointer: {} }},",
            rust_string(string(matcher, "kind")?),
            string_slice(&strings(matcher, "values")?),
            rust_string(
                matcher
                    .get("value_pointer")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            )
        )?;
    }
    output.push_str("];\n");
    Ok(GeneratedOutput {
        relative_path: "crates/wire/src/generated/forbidden_wire_fields.rs".into(),
        contents: output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation_row(id: &str, grpc: &str, mq: &str) -> Map<String, Value> {
        serde_json::json!({
            "operation_id": id,
            "grpc": grpc,
            "mq": mq
        })
        .as_object()
        .expect("operation row")
        .clone()
    }

    fn transport_validation(rows: &[Map<String, Value>]) -> Result<()> {
        validate_operation_transport_bindings(&rows.iter().collect::<Vec<_>>())
    }

    fn spec_artifacts() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../arkret-spec/spec/v1/artifacts")
    }

    #[test]
    fn all_registry_surfaces_are_generated_by_rust() {
        let outputs = generate(&spec_artifacts()).expect("generate registry surfaces");
        assert_eq!(outputs.len(), 25);
        for required in [
            "crates/wire/src/generated/reducer_managed_patch_paths.rs",
            "crates/wire/src/generated/mls_creator_bootstrap.rs",
            "crates/wire/src/generated/operation_ids.rs",
            "crates/wire/src/generated/operation_errors.rs",
            "crates/wire/src/generated/security_strings.rs",
            "crates/wire/src/generated/preimage_commitments.rs",
            "crates/wire/src/error_codes/error_code.rs",
            "crates/identifiers/src/generated/digest_suite_codes.rs",
        ] {
            assert!(
                outputs
                    .iter()
                    .any(|output| output.relative_path == Path::new(required))
            );
        }
        assert!(outputs.iter().all(|output| {
            output
                .contents
                .contains("//! Generator: tools/spec-codegen")
        }));
        assert!(outputs.iter().all(|output| {
            output.relative_path != Path::new("crates/wire/src/generated/history_store_limits.rs")
        }));
    }

    #[test]
    fn operation_transport_bindings_are_closed_and_unique() {
        let first = operation_row(
            "ak.self.probe.command.one.v1",
            "SelfProbe/One",
            "self.probe.one",
        );
        let second = operation_row(
            "ak.self.probe.command.two.v1",
            "SelfProbe/Two",
            "self.probe.two",
        );
        let http_only = serde_json::json!({
            "operation_id": "ak.self.probe.command.http_only.v1",
            "http_only_variant": true
        })
        .as_object()
        .expect("http-only row")
        .clone();
        transport_validation(&[first.clone(), second.clone(), http_only.clone()])
            .expect("closed transport bindings");

        let mut missing = first.clone();
        missing.remove("grpc");
        assert!(
            transport_validation(&[missing])
                .unwrap_err()
                .to_string()
                .contains("missing grpc")
        );

        let duplicate_grpc = operation_row(
            "ak.self.probe.command.three.v1",
            "SelfProbe/One",
            "self.probe.three",
        );
        assert!(
            transport_validation(&[first.clone(), duplicate_grpc])
                .unwrap_err()
                .to_string()
                .contains("duplicate grpc")
        );

        let duplicate_mq = operation_row(
            "ak.self.probe.command.three.v1",
            "SelfProbe/Three",
            "self.probe.one",
        );
        assert!(
            transport_validation(&[first.clone(), duplicate_mq])
                .unwrap_err()
                .to_string()
                .contains("duplicate mq")
        );

        let empty_service = operation_row(
            "ak.self.probe.command.three.v1",
            "/Three",
            "self.probe.three",
        );
        assert!(
            transport_validation(&[empty_service])
                .unwrap_err()
                .to_string()
                .contains("non-empty Service/Method")
        );

        let mut forbidden = http_only;
        forbidden.insert("grpc".into(), Value::String("SelfProbe/HttpOnly".into()));
        assert!(
            transport_validation(&[forbidden])
                .unwrap_err()
                .to_string()
                .contains("http-only")
        );

        let mut malformed = second;
        malformed.insert("mq".into(), Value::Bool(true));
        assert!(
            transport_validation(&[malformed])
                .unwrap_err()
                .to_string()
                .contains("mq topic is not a string")
        );
    }

    #[test]
    fn preimage_commitment_codegen_follows_refs_but_not_unreferenced_defs() {
        let root = std::env::temp_dir().join(format!(
            "arkret-preimage-codegen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let schemas = root.join("schemas");
        std::fs::create_dir_all(&schemas).expect("create fixture schemas");
        std::fs::write(
            schemas.join("root.schema.json"),
            r#"{"$ref":"./shared.schema.json#/$defs/reachable","$defs":{"dead":{"x-arkret-preimage-commitment":"self_identity"}}}"#,
        )
        .expect("write root schema");
        std::fs::write(
            schemas.join("shared.schema.json"),
            r#"{"$defs":{"reachable":{"$ref":"./leaf.schema.json#/$defs/annotated"},"dead":{"x-arkret-preimage-commitment":"same_unit_sibling"}}}"#,
        )
        .expect("write shared schema");
        std::fs::write(
            schemas.join("leaf.schema.json"),
            r#"{"$defs":{"annotated":{"type":"object","properties":{"source_event_id":{"type":"string","description":"description text is not a rule","x-arkret-preimage-commitment":"fixed_event"}}},"dead":{"x-arkret-preimage-commitment":"no_event_identity"}}}"#,
        )
        .expect("write leaf schema");

        let mut repository = SchemaRepository::default();
        let found =
            collect_preimage_commitments(&root, &mut repository, "schemas/root.schema.json")
                .expect("collect commitments");
        assert_eq!(found.len(), 1);
        assert!(found.contains(&(
            "schemas/leaf.schema.json".to_owned(),
            "/$defs/annotated/properties/source_event_id".to_owned(),
            "fixed_event".to_owned(),
        )));

        // Human prose is not a protocol input: changing it must preserve the
        // exact generated commitment tuple.
        std::fs::write(
            schemas.join("leaf.schema.json"),
            r#"{"$defs":{"annotated":{"type":"object","properties":{"source_event_id":{"type":"string","description":"completely rewritten prose","x-arkret-preimage-commitment":"fixed_event"}}},"dead":{"x-arkret-preimage-commitment":"no_event_identity"}}}"#,
        )
        .expect("rewrite leaf description");
        let rewritten = collect_preimage_commitments(
            &root,
            &mut SchemaRepository::default(),
            "schemas/root.schema.json",
        )
        .expect("collect commitments after prose rewrite");
        assert_eq!(rewritten, found);

        // Removing the annotation removes the generated rule. The generator
        // must not infer it from the member name or its description.
        std::fs::write(
            schemas.join("leaf.schema.json"),
            r#"{"$defs":{"annotated":{"type":"object","properties":{"source_event_id":{"type":"string","description":"fixed event commitment"}}}}}"#,
        )
        .expect("remove leaf annotation");
        let without_annotation = collect_preimage_commitments(
            &root,
            &mut SchemaRepository::default(),
            "schemas/root.schema.json",
        )
        .expect("collect without annotation");
        assert!(without_annotation.is_empty());
        std::fs::remove_dir_all(root).expect("remove isolated fixture tree");
    }

    #[test]
    fn preimage_commitment_codegen_rejects_bad_ref_pointer_and_annotation_value() {
        let root = std::env::temp_dir().join(format!(
            "arkret-preimage-mutation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let schemas = root.join("schemas");
        std::fs::create_dir_all(&schemas).expect("create fixture schemas");
        std::fs::write(
            schemas.join("root.schema.json"),
            r#"{"$ref":"./shared.schema.json#/$defs/missing"}"#,
        )
        .expect("write bad pointer root");
        std::fs::write(
            schemas.join("shared.schema.json"),
            r#"{"$defs":{"reachable":{"type":"string"}}}"#,
        )
        .expect("write shared schema");

        let bad_pointer = collect_preimage_commitments(
            &root,
            &mut SchemaRepository::default(),
            "schemas/root.schema.json",
        )
        .expect_err("unknown pointer must fail closed");
        assert!(bad_pointer.to_string().contains("has no JSON Pointer"));

        std::fs::write(
            schemas.join("root.schema.json"),
            r#"{"type":"string","x-arkret-preimage-commitment":"description_inferred"}"#,
        )
        .expect("write unknown annotation");
        let bad_annotation = collect_preimage_commitments(
            &root,
            &mut SchemaRepository::default(),
            "schemas/root.schema.json",
        )
        .expect_err("unknown annotation must fail closed");
        assert!(
            bad_annotation
                .to_string()
                .contains("unknown preimage commitment")
        );

        std::fs::write(schemas.join("root.schema.json"), r#"{"$ref":false}"#)
            .expect("write non-string ref");
        let bad_ref_type = collect_preimage_commitments(
            &root,
            &mut SchemaRepository::default(),
            "schemas/root.schema.json",
        )
        .expect_err("non-string ref must fail closed");
        assert!(bad_ref_type.to_string().contains("$ref is not a string"));
        std::fs::remove_dir_all(root).expect("remove isolated fixture tree");
    }

    #[test]
    fn digest_suite_validation_rejects_a_nonzero_high_nibble() {
        let invalid = Map::from_iter([
            (
                "canonical_id".to_owned(),
                Value::String("sha256".to_owned()),
            ),
            ("wire_code".to_owned(), Value::from(0x11)),
            ("digest_length_bytes".to_owned(), Value::from(32)),
        ]);
        let error = validate_digest_suite_rows(&[&invalid]).expect_err("high nibble must fail");
        assert!(error.to_string().contains("high nibble zero"));
    }

    #[test]
    fn error_codegen_omits_reserved_rows_from_runtime_enums() {
        let outputs = generate(&spec_artifacts()).expect("generate registry surfaces");
        let error_codes = outputs
            .iter()
            .find(|output| {
                output.relative_path == Path::new("crates/wire/src/error_codes/error_code.rs")
            })
            .expect("generated error codes");
        assert!(error_codes.contents.contains("StateMismatch"));
        assert!(!error_codes.contents.contains("AgentAuthorizationInactive"));
        let reason_codes = outputs
            .iter()
            .find(|output| {
                output.relative_path == Path::new("crates/wire/src/error_codes/reason_code.rs")
            })
            .expect("generated reason codes");
        assert!(reason_codes.contents.contains("ApprovalRequired"));
        assert!(!reason_codes.contents.contains("ProofBindingMissing"));
    }

    #[test]
    fn reserved_error_rows_require_a_nonempty_activation_condition() {
        let missing = Map::from_iter([
            (
                "code".to_owned(),
                Value::String("reserved_probe".to_owned()),
            ),
            ("status".to_owned(), Value::String("reserved".to_owned())),
        ]);
        assert!(
            active_error_rows(&[&missing], "error code")
                .unwrap_err()
                .to_string()
                .contains("activation_condition")
        );

        let active_with_condition = Map::from_iter([
            ("code".to_owned(), Value::String("active_probe".to_owned())),
            ("status".to_owned(), Value::String("active".to_owned())),
            (
                "activation_condition".to_owned(),
                Value::String("stale".to_owned()),
            ),
        ]);
        assert!(
            active_error_rows(&[&active_with_condition], "error code")
                .unwrap_err()
                .to_string()
                .contains("must not retain")
        );

        let reserved = Map::from_iter([
            (
                "code".to_owned(),
                Value::String("reserved_probe".to_owned()),
            ),
            ("status".to_owned(), Value::String("reserved".to_owned())),
            (
                "activation_condition".to_owned(),
                Value::String("activate with a producer".to_owned()),
            ),
            (
                "applies_to".to_owned(),
                Value::Array(vec![Value::String("service_call".to_owned())]),
            ),
        ]);
        assert!(
            active_error_rows(&[&reserved], "error code")
                .unwrap()
                .is_empty()
        );

        let mut missing_applies_to = reserved.clone();
        missing_applies_to.remove("applies_to");
        assert!(
            active_error_rows(&[&missing_applies_to], "error code")
                .unwrap_err()
                .to_string()
                .contains("without applies_to[]")
        );

        let mut duplicate_applies_to = reserved;
        duplicate_applies_to.insert(
            "applies_to".to_owned(),
            Value::Array(vec![
                Value::String("service_call".to_owned()),
                Value::String("service_call".to_owned()),
            ]),
        );
        assert!(
            active_error_rows(&[&duplicate_applies_to], "error code")
                .unwrap_err()
                .to_string()
                .contains("repeats applies_to")
        );
    }

    #[test]
    fn registry_rustdoc_is_inert() {
        assert_eq!(
            rustdoc("@<controller>/<agent> & peer"),
            "@&lt;controller&gt;/&lt;agent&gt; &amp; peer"
        );
    }
}
