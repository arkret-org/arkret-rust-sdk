//! Authority-certified historical conclusions over one Realm Seal lineage.

use arkret_canonical::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CellRef, EventId, Hash, NotarySignerDescriptor, NotaryValue, RealmId, Result,
    SealCommandOutcome, SealId, SealSignature, WireError,
};

pub const MAX_SEAL_CONCLUSION_SELECTORS: usize = 64;
pub const MAX_SEAL_CONCLUSION_QUERIES: usize = 128;
pub const MAX_SEAL_CONCLUSION_RANGE_CELLS: usize = 512;
pub const MAX_SEAL_CONCLUSION_HANDOFFS: usize = 256;
pub const MAX_SEAL_CONCLUSION_CERTIFICATE_BYTES: usize = 8 * 1024 * 1024;
pub const SEAL_CONCLUSION_CONTEXT: &str = "ak.seal.conclusion.v1";
pub const SEAL_CONFIGURATION_HANDOFF_CONTEXT: &str = "ak.seal.configuration_handoff.v1";

/// `seal-conclusion.schema.json#/$defs/cell_state`: the wrapper is closed;
/// its value is interpreted only under the exact registered Cell contract.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCellState {
    pub revision_event_id: EventId,
    /// `seal-conclusion.schema.json#/$defs/cell_state/properties/value`.
    /// Consumers must validate the complete registered business value.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub value: Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SealConclusionSelector {
    Cell {
        cell_id: CellRef,
    },
    CellRange {
        lower_cell_id: CellRef,
        upper_cell_id: CellRef,
    },
    Command {
        event_digest: Hash,
    },
    CommandEffect {
        event_digest: Hash,
        cell_id: CellRef,
    },
    Ancestry {
        ancestor_seal_ref: SealId,
    },
}

impl SealConclusionSelector {
    pub fn validate_structural(&self) -> Result<()> {
        if let Self::CellRange {
            lower_cell_id,
            upper_cell_id,
        } = self
            && lower_cell_id >= upper_cell_id
        {
            return Err(WireError::Protocol(
                "Seal conclusion Cell range must be a non-empty half-open interval".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCellOutcome {
    pub selector: SealConclusionCellSelector,
    #[serde(deserialize_with = "required_nullable")]
    pub state: Option<SealConclusionCellState>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCellSelector {
    pub kind: SealConclusionCellSelectorKind,
    pub cell_id: CellRef,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealConclusionCellSelectorKind {
    Cell,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionRangeCell {
    pub cell_id: CellRef,
    pub state: SealConclusionCellState,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCellRangeOutcome {
    pub selector: SealConclusionCellRangeSelector,
    pub cells: Vec<SealConclusionRangeCell>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCellRangeSelector {
    pub kind: SealConclusionCellRangeSelectorKind,
    pub lower_cell_id: CellRef,
    pub upper_cell_id: CellRef,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealConclusionCellRangeSelectorKind {
    CellRange,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCommandSelector {
    pub kind: SealConclusionCommandSelectorKind,
    pub event_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealConclusionCommandSelectorKind {
    Command,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCommandOutcome {
    pub selector: SealConclusionCommandSelector,
    #[serde(deserialize_with = "required_nullable")]
    pub result: Option<SealCommandOutcome>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCommandEffectSelector {
    pub kind: SealConclusionCommandEffectSelectorKind,
    pub event_digest: Hash,
    pub cell_id: CellRef,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealConclusionCommandEffectSelectorKind {
    CommandEffect,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCommandEffectOutcome {
    pub selector: SealConclusionCommandEffectSelector,
    #[serde(deserialize_with = "required_nullable")]
    pub state: Option<SealConclusionCellState>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionAncestrySelector {
    pub kind: SealConclusionAncestrySelectorKind,
    pub ancestor_seal_ref: SealId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealConclusionAncestrySelectorKind {
    Ancestry,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionAncestryOutcome {
    pub selector: SealConclusionAncestrySelector,
    pub is_ancestor: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SealConclusionOutcome {
    Cell(SealConclusionCellOutcome),
    CellRange(SealConclusionCellRangeOutcome),
    Command(SealConclusionCommandOutcome),
    CommandEffect(SealConclusionCommandEffectOutcome),
    Ancestry(SealConclusionAncestryOutcome),
}

impl SealConclusionOutcome {
    pub fn selector(&self) -> SealConclusionSelector {
        match self {
            Self::Cell(result) => SealConclusionSelector::Cell {
                cell_id: result.selector.cell_id.clone(),
            },
            Self::CellRange(result) => SealConclusionSelector::CellRange {
                lower_cell_id: result.selector.lower_cell_id.clone(),
                upper_cell_id: result.selector.upper_cell_id.clone(),
            },
            Self::Command(result) => SealConclusionSelector::Command {
                event_digest: result.selector.event_digest.clone(),
            },
            Self::CommandEffect(result) => SealConclusionSelector::CommandEffect {
                event_digest: result.selector.event_digest.clone(),
                cell_id: result.selector.cell_id.clone(),
            },
            Self::Ancestry(result) => SealConclusionSelector::Ancestry {
                ancestor_seal_ref: result.selector.ancestor_seal_ref.clone(),
            },
        }
    }

    pub fn validate_structural(&self) -> Result<()> {
        self.selector().validate_structural()?;
        match self {
            Self::CellRange(result) => {
                if result.cells.len() > MAX_SEAL_CONCLUSION_RANGE_CELLS
                    || result
                        .cells
                        .windows(2)
                        .any(|pair| pair[0].cell_id >= pair[1].cell_id)
                    || result.cells.iter().any(|cell| {
                        cell.cell_id < result.selector.lower_cell_id
                            || cell.cell_id >= result.selector.upper_cell_id
                    })
                {
                    return Err(WireError::Protocol(
                        "Seal conclusion Cell range result is not a complete canonical interval"
                            .to_owned(),
                    ));
                }
            }
            Self::Command(result) => {
                if let Some(command) = &result.result {
                    command.validate_structural()?;
                    if command.event_digest != result.selector.event_digest
                        && !command
                            .unit_event_digests
                            .contains(&result.selector.event_digest)
                    {
                        return Err(WireError::Protocol(
                            "Seal conclusion command result does not match its selector".to_owned(),
                        ));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionQuery {
    pub target_seal_ref: SealId,
    pub selectors: Vec<SealConclusionSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_configuration_ref: Option<EventId>,
}

impl SealConclusionQuery {
    pub fn validate_structural(&self) -> Result<()> {
        if !(1..=MAX_SEAL_CONCLUSION_SELECTORS).contains(&self.selectors.len()) {
            return Err(WireError::Protocol(
                "Seal conclusion query requires 1..=64 selectors".to_owned(),
            ));
        }
        for selector in &self.selectors {
            selector.validate_structural()?;
        }
        validate_canonical_order("Seal conclusion selectors", &self.selectors)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionStatement {
    pub realm_id: RealmId,
    pub configuration_ref: EventId,
    pub authority_seal_ref: SealId,
    pub target_seal_ref: SealId,
    pub results: Vec<SealConclusionOutcome>,
}

impl SealConclusionStatement {
    pub fn validate_structural(&self) -> Result<()> {
        if !(1..=MAX_SEAL_CONCLUSION_SELECTORS).contains(&self.results.len()) {
            return Err(WireError::Protocol(
                "Seal conclusion statement requires 1..=64 results".to_owned(),
            ));
        }
        for result in &self.results {
            result.validate_structural()?;
        }
        let selectors = self
            .results
            .iter()
            .map(SealConclusionOutcome::selector)
            .collect::<Vec<_>>();
        validate_canonical_order("Seal conclusion result selectors", &selectors)
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        canonical_json_bytes(&ConclusionSigningPayload {
            context: SEAL_CONCLUSION_CONTEXT,
            statement: self,
        })
        .map_err(Into::into)
    }

    pub fn signing_payload_digest(&self) -> Result<Hash> {
        Hash::new(arkret_canonical::sha256_digest(
            &self.signing_payload_bytes()?,
        ))
        .map_err(Into::into)
    }

    pub fn matches_query(&self, query: &SealConclusionQuery) -> bool {
        self.target_seal_ref == query.target_seal_ref
            && self
                .results
                .iter()
                .map(SealConclusionOutcome::selector)
                .eq(query.selectors.iter().cloned())
    }
}

#[derive(Serialize)]
struct ConclusionSigningPayload<'a> {
    context: &'static str,
    statement: &'a SealConclusionStatement,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionCertificate {
    pub statement: SealConclusionStatement,
    pub signature: SealSignature,
}

impl SealConclusionCertificate {
    pub fn validate_structural(&self) -> Result<()> {
        self.statement.validate_structural()?;
        validate_certificate_signature(&self.signature, self.statement.signing_payload_digest()?)?;
        if canonical_json_bytes(self)?.len() > MAX_SEAL_CONCLUSION_CERTIFICATE_BYTES {
            return Err(WireError::Protocol(
                "Seal conclusion certificate exceeds 8388608 canonical bytes".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_authority_with<F>(
        &self,
        configuration: &NotaryValue,
        mut verify: F,
    ) -> Result<()>
    where
        F: FnMut(&SealSignature, &NotarySignerDescriptor, &[u8]) -> Result<()>,
    {
        self.validate_structural()?;
        configuration.validate()?;
        let payload = self.statement.signing_payload_bytes()?;
        let signature = &self.signature;
        let descriptor = configuration
            .signer_descriptor(&signature.verification_method)
            .ok_or_else(|| {
                WireError::Protocol(
                    "Seal conclusion signature is outside the exact configuration".to_owned(),
                )
            })?;
        verify(signature, descriptor, &payload)?;
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConfigurationHandoffStatement {
    pub realm_id: RealmId,
    pub configuration_ref: EventId,
    pub handoff_seal_ref: SealId,
    pub next_configuration_ref: EventId,
    pub next_configuration: NotaryValue,
}

impl SealConfigurationHandoffStatement {
    pub fn validate_structural(&self) -> Result<()> {
        if self.configuration_ref == self.next_configuration_ref {
            return Err(WireError::Protocol(
                "configuration handoff cannot self-loop".to_owned(),
            ));
        }
        self.next_configuration.validate()
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        canonical_json_bytes(&HandoffSigningPayload {
            context: SEAL_CONFIGURATION_HANDOFF_CONTEXT,
            statement: self,
        })
        .map_err(Into::into)
    }

    pub fn signing_payload_digest(&self) -> Result<Hash> {
        Hash::new(arkret_canonical::sha256_digest(
            &self.signing_payload_bytes()?,
        ))
        .map_err(Into::into)
    }
}

#[derive(Serialize)]
struct HandoffSigningPayload<'a> {
    context: &'static str,
    statement: &'a SealConfigurationHandoffStatement,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConfigurationHandoffCertificate {
    pub statement: SealConfigurationHandoffStatement,
    pub signature: SealSignature,
}

impl SealConfigurationHandoffCertificate {
    pub fn validate_structural(&self) -> Result<()> {
        self.statement.validate_structural()?;
        validate_certificate_signature(&self.signature, self.statement.signing_payload_digest()?)
    }

    pub fn validate_authority_with<F>(
        &self,
        configuration: &NotaryValue,
        mut verify: F,
    ) -> Result<()>
    where
        F: FnMut(&SealSignature, &NotarySignerDescriptor, &[u8]) -> Result<()>,
    {
        self.validate_structural()?;
        configuration.validate()?;
        let payload = self.statement.signing_payload_bytes()?;
        let signature = &self.signature;
        let descriptor = configuration
            .signer_descriptor(&signature.verification_method)
            .ok_or_else(|| {
                WireError::Protocol(
                    "Seal configuration handoff signature is outside the old configuration"
                        .to_owned(),
                )
            })?;
        verify(signature, descriptor, &payload)?;
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealConclusionSet {
    pub configuration_handoffs: Vec<SealConfigurationHandoffCertificate>,
    pub conclusions: Vec<SealConclusionCertificate>,
}

impl SealConclusionSet {
    pub fn validate_structural(&self) -> Result<()> {
        if self.configuration_handoffs.len() > MAX_SEAL_CONCLUSION_HANDOFFS
            || !(1..=MAX_SEAL_CONCLUSION_QUERIES).contains(&self.conclusions.len())
        {
            return Err(WireError::Protocol(
                "Seal conclusion set size is outside protocol bounds".to_owned(),
            ));
        }
        let mut configurations = std::collections::BTreeSet::new();
        if let Some(first) = self.configuration_handoffs.first() {
            configurations.insert(first.statement.configuration_ref.clone());
        }
        for handoff in &self.configuration_handoffs {
            handoff.validate_structural()?;
            if !configurations.insert(handoff.statement.next_configuration_ref.clone()) {
                return Err(WireError::Protocol(
                    "configuration handoff repeats a trusted configuration".to_owned(),
                ));
            }
        }
        for conclusion in &self.conclusions {
            conclusion.validate_structural()?;
        }
        for pair in self.configuration_handoffs.windows(2) {
            if pair[0].statement.realm_id != pair[1].statement.realm_id
                || pair[0].statement.next_configuration_ref != pair[1].statement.configuration_ref
            {
                return Err(WireError::Protocol(
                    "Seal configuration handoffs must form one gap-free Realm chain".to_owned(),
                ));
            }
        }
        let realm = self
            .configuration_handoffs
            .first()
            .map(|handoff| &handoff.statement.realm_id)
            .unwrap_or(&self.conclusions[0].statement.realm_id);
        if self
            .conclusions
            .iter()
            .any(|conclusion| &conclusion.statement.realm_id != realm)
        {
            return Err(WireError::Protocol(
                "Seal conclusion set must contain exactly one Realm".to_owned(),
            ));
        }
        if let Some(handoff) = self.configuration_handoffs.last()
            && self.conclusions.iter().any(|conclusion| {
                conclusion.statement.configuration_ref != handoff.statement.next_configuration_ref
            })
        {
            return Err(WireError::Protocol(
                "Seal conclusions must use the terminal handoff configuration".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_certificate_signature(signature: &SealSignature, digest: Hash) -> Result<()> {
    signature.validate_structural()?;
    if signature.payload_digest != digest {
        return Err(WireError::Protocol(
            "Seal conclusion signature payload_digest mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_canonical_order<T: Serialize>(field: &str, values: &[T]) -> Result<()> {
    let keys = values
        .iter()
        .map(canonical_json_bytes)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WireError::Protocol(format!(
            "{field} must be JCS-byte sorted and duplicate-free"
        )));
    }
    Ok(())
}

fn required_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
