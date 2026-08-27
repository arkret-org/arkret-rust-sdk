use std::collections::BTreeSet;

use arkret_wire::generated::profile_requirements::{
    ProfileOperationRequirement, ProfileRequirements, ProfileRequirementsError, requirements_for,
};

/// Implementation surface used to validate a set of claimed profiles.
///
/// This intentionally covers every generated `required_*` family, including
/// capability actions and constraint kinds, so services do not need to
/// re-parse the conformance-profile artifact to know whether a profile claim is
/// semantically backed by the advertised wire surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileSemanticSurface {
    pub operation_requirements: Vec<ProfileOperationRequirement>,
    pub event_kinds: Vec<String>,
    pub schemas: Vec<String>,
    pub fixtures: Vec<String>,
    pub capability_actions: Vec<String>,
    pub features: Vec<String>,
    pub cell_namespaces: Vec<String>,
    pub cells: Vec<String>,
    pub constraint_kinds: Vec<String>,
}

/// Union of the requirements implied by claimed profiles plus their inherited
/// profiles.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileSemanticRequirements {
    pub profile_ids: Vec<String>,
    pub operation_requirements: Vec<ProfileOperationRequirement>,
    pub required_event_kinds: Vec<String>,
    pub required_schemas: Vec<String>,
    pub rejected_event_kinds: Vec<String>,
    pub required_fixtures: Vec<String>,
    pub required_capability_actions: Vec<String>,
    pub required_features: Vec<String>,
    pub required_cell_namespaces: Vec<String>,
    pub required_cells: Vec<String>,
    pub required_constraint_kinds: Vec<String>,
}

/// Shared report used by service describe, conformance gates and client-side
/// profile checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileSemanticCoverageReport {
    pub requirements: ProfileSemanticRequirements,
    pub missing_operation_requirements: Vec<ProfileOperationRequirement>,
    pub missing_event_kinds: Vec<String>,
    pub missing_schemas: Vec<String>,
    pub rejected_event_kinds_present: Vec<String>,
    pub missing_fixtures: Vec<String>,
    pub missing_capability_actions: Vec<String>,
    pub missing_features: Vec<String>,
    pub missing_cell_namespaces: Vec<String>,
    pub missing_cells: Vec<String>,
    pub missing_constraint_kinds: Vec<String>,
}

impl ProfileSemanticCoverageReport {
    pub fn is_compliant(&self) -> bool {
        self.missing_operation_requirements.is_empty()
            && self.missing_event_kinds.is_empty()
            && self.missing_schemas.is_empty()
            && self.rejected_event_kinds_present.is_empty()
            && self.missing_fixtures.is_empty()
            && self.missing_capability_actions.is_empty()
            && self.missing_features.is_empty()
            && self.missing_cell_namespaces.is_empty()
            && self.missing_cells.is_empty()
            && self.missing_constraint_kinds.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileSemanticCoverageError {
    UnknownProfile {
        profile_id: String,
    },
    MissingRequirements {
        report: Box<ProfileSemanticCoverageReport>,
    },
}

impl ProfileSemanticCoverageError {
    pub fn report(&self) -> Option<&ProfileSemanticCoverageReport> {
        match self {
            Self::MissingRequirements { report } => Some(report),
            Self::UnknownProfile { .. } => None,
        }
    }
}

impl From<ProfileRequirementsError> for ProfileSemanticCoverageError {
    fn from(value: ProfileRequirementsError) -> Self {
        match value {
            ProfileRequirementsError::UnknownProfile { profile_id } => {
                Self::UnknownProfile { profile_id }
            }
        }
    }
}

impl std::fmt::Display for ProfileSemanticCoverageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownProfile { profile_id } => {
                write!(f, "unknown conformance profile: {profile_id}")
            }
            Self::MissingRequirements { report } => write!(
                f,
                "profile semantic coverage missing requirements for {:?}: operation_requirements={:?} event_kinds={:?} schemas={:?} rejected_event_kinds_present={:?} fixtures={:?} capability_actions={:?} features={:?} cell_namespaces={:?} cells={:?} constraint_kinds={:?}",
                report.requirements.profile_ids,
                report.missing_operation_requirements,
                report.missing_event_kinds,
                report.missing_schemas,
                report.rejected_event_kinds_present,
                report.missing_fixtures,
                report.missing_capability_actions,
                report.missing_features,
                report.missing_cell_namespaces,
                report.missing_cells,
                report.missing_constraint_kinds
            ),
        }
    }
}

impl std::error::Error for ProfileSemanticCoverageError {}

pub fn collect_profile_semantic_requirements(
    profile_ids: &[&str],
) -> Result<ProfileSemanticRequirements, ProfileRequirementsError> {
    let mut acc = RequirementsAccumulator::default();
    let mut visiting = BTreeSet::new();
    for profile_id in profile_ids {
        collect_profile_requirements(profile_id, &mut visiting, &mut acc)?;
    }
    Ok(acc.finish())
}

pub fn profile_semantic_coverage_report(
    profile_ids: &[&str],
    surface: &ProfileSemanticSurface,
) -> Result<ProfileSemanticCoverageReport, ProfileRequirementsError> {
    let requirements = collect_profile_semantic_requirements(profile_ids)?;
    let implemented_operation_requirements: BTreeSet<_> =
        surface.operation_requirements.iter().copied().collect();
    let implemented_event_kinds = set(&surface.event_kinds);
    let implemented_schemas = set(&surface.schemas);
    let implemented_fixtures = set(&surface.fixtures);
    let implemented_capability_actions = set(&surface.capability_actions);
    let advertised_features = set(&surface.features);
    let implemented_cell_namespaces = set(&surface.cell_namespaces);
    let implemented_cells = set(&surface.cells);
    let implemented_constraint_kinds = set(&surface.constraint_kinds);

    Ok(ProfileSemanticCoverageReport {
        missing_operation_requirements: requirements
            .operation_requirements
            .iter()
            .filter(|item| !implemented_operation_requirements.contains(item))
            .copied()
            .collect(),
        missing_event_kinds: missing(&requirements.required_event_kinds, &implemented_event_kinds),
        missing_schemas: missing(&requirements.required_schemas, &implemented_schemas),
        rejected_event_kinds_present: present(
            &requirements.rejected_event_kinds,
            &implemented_event_kinds,
        ),
        missing_fixtures: missing(&requirements.required_fixtures, &implemented_fixtures),
        missing_capability_actions: missing(
            &requirements.required_capability_actions,
            &implemented_capability_actions,
        ),
        missing_features: missing(&requirements.required_features, &advertised_features),
        missing_cell_namespaces: missing(
            &requirements.required_cell_namespaces,
            &implemented_cell_namespaces,
        ),
        missing_cells: missing(&requirements.required_cells, &implemented_cells),
        missing_constraint_kinds: missing(
            &requirements.required_constraint_kinds,
            &implemented_constraint_kinds,
        ),
        requirements,
    })
}

pub fn validate_profile_semantic_coverage(
    profile_ids: &[&str],
    surface: &ProfileSemanticSurface,
) -> Result<(), ProfileSemanticCoverageError> {
    let report = profile_semantic_coverage_report(profile_ids, surface)
        .map_err(ProfileSemanticCoverageError::from)?;
    if report.is_compliant() {
        Ok(())
    } else {
        Err(ProfileSemanticCoverageError::MissingRequirements {
            report: Box::new(report),
        })
    }
}

pub fn profile_capability_action_coverage_report(
    profile_ids: &[&str],
    capability_actions: &[&str],
) -> Result<ProfileSemanticCoverageReport, ProfileRequirementsError> {
    let surface = ProfileSemanticSurface {
        capability_actions: strings(capability_actions),
        ..ProfileSemanticSurface::default()
    };
    profile_semantic_coverage_report(profile_ids, &surface)
}

#[derive(Default)]
struct RequirementsAccumulator {
    profile_ids: BTreeSet<String>,
    operation_requirements: BTreeSet<ProfileOperationRequirement>,
    required_event_kinds: BTreeSet<String>,
    required_schemas: BTreeSet<String>,
    rejected_event_kinds: BTreeSet<String>,
    required_fixtures: BTreeSet<String>,
    required_capability_actions: BTreeSet<String>,
    required_features: BTreeSet<String>,
    required_cell_namespaces: BTreeSet<String>,
    required_cells: BTreeSet<String>,
    required_constraint_kinds: BTreeSet<String>,
}

impl RequirementsAccumulator {
    fn insert(&mut self, req: &ProfileRequirements) {
        self.profile_ids.insert(req.profile_id.to_owned());
        self.operation_requirements
            .extend(req.operation_requirements.iter().copied());
        extend(&mut self.required_event_kinds, req.required_event_kinds);
        extend(&mut self.required_schemas, req.required_schemas);
        extend(&mut self.rejected_event_kinds, req.rejected_event_kinds);
        extend(&mut self.required_fixtures, req.required_fixtures);
        extend(
            &mut self.required_capability_actions,
            req.required_capability_actions,
        );
        extend(&mut self.required_features, req.required_features);
        extend(
            &mut self.required_cell_namespaces,
            req.required_cell_namespaces,
        );
        extend(&mut self.required_cells, req.required_cells);
        extend(
            &mut self.required_constraint_kinds,
            req.required_constraint_kinds,
        );
    }

    fn finish(self) -> ProfileSemanticRequirements {
        ProfileSemanticRequirements {
            profile_ids: into_vec(self.profile_ids),
            operation_requirements: self.operation_requirements.into_iter().collect(),
            required_event_kinds: into_vec(self.required_event_kinds),
            required_schemas: into_vec(self.required_schemas),
            rejected_event_kinds: into_vec(self.rejected_event_kinds),
            required_fixtures: into_vec(self.required_fixtures),
            required_capability_actions: into_vec(self.required_capability_actions),
            required_features: into_vec(self.required_features),
            required_cell_namespaces: into_vec(self.required_cell_namespaces),
            required_cells: into_vec(self.required_cells),
            required_constraint_kinds: into_vec(self.required_constraint_kinds),
        }
    }
}

fn collect_profile_requirements(
    profile_id: &str,
    visiting: &mut BTreeSet<String>,
    acc: &mut RequirementsAccumulator,
) -> Result<(), ProfileRequirementsError> {
    if acc.profile_ids.contains(profile_id) {
        return Ok(());
    }
    if !visiting.insert(profile_id.to_owned()) {
        return Ok(());
    }
    let req =
        requirements_for(profile_id).ok_or_else(|| ProfileRequirementsError::UnknownProfile {
            profile_id: profile_id.to_owned(),
        })?;
    for inherited in req.inherits {
        collect_profile_requirements(inherited, visiting, acc)?;
    }
    acc.insert(req);
    visiting.remove(profile_id);
    Ok(())
}

fn extend(target: &mut BTreeSet<String>, values: &[&str]) {
    target.extend(values.iter().map(|value| (*value).to_owned()));
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn set(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}

fn missing(required: &[String], implemented: &BTreeSet<&str>) -> Vec<String> {
    required
        .iter()
        .filter(|item| !implemented.contains(item.as_str()))
        .cloned()
        .collect()
}

fn present(forbidden: &[String], implemented: &BTreeSet<&str>) -> Vec<String> {
    forbidden
        .iter()
        .filter(|item| implemented.contains(item.as_str()))
        .cloned()
        .collect()
}

fn into_vec(values: BTreeSet<String>) -> Vec<String> {
    values.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use arkret_wire::{BindingKind, ProfileOperationDirection, ServiceOperationId};

    use super::*;

    #[test]
    fn semantic_validation_reports_missing_capability_actions() {
        let err = validate_profile_semantic_coverage(
            &["ak.profile.candidate.join_policy.v1"],
            &ProfileSemanticSurface::default(),
        )
        .unwrap_err();
        let report = err.report().expect("missing requirements carry a report");
        assert_eq!(
            report.missing_capability_actions,
            vec!["ak.realm.admin".to_owned()]
        );
    }

    #[test]
    fn candidate_join_policy_requires_complete_private_carrier_surface() {
        validate_profile_semantic_coverage(
            &["ak.profile.candidate.join_policy.v1"],
            &ProfileSemanticSurface {
                operation_requirements: [
                    ServiceOperationId::SelfRealmJoinApplicationAuditReadListV1,
                    ServiceOperationId::SelfRealmJoinApplicationCommandCancelV1,
                    ServiceOperationId::SelfRealmJoinApplicationCommandReviewV1,
                    ServiceOperationId::SelfRealmJoinApplicationCommandSubmitV1,
                    ServiceOperationId::SelfRealmJoinApplicationReadListV1,
                    ServiceOperationId::SelfRealmJoinApplicationResourceGetV1,
                ]
                .map(|operation_id| ProfileOperationRequirement {
                    direction: ProfileOperationDirection::Provide,
                    operation_id,
                    binding_kind: BindingKind::HttpJson,
                })
                .to_vec(),
                schemas: vec!["ak.schema.join_policy_operations.v1".to_owned()],
                fixtures: vec!["websocket-binding-fixture.json".to_owned()],
                capability_actions: vec!["ak.realm.admin".to_owned()],
                ..ProfileSemanticSurface::default()
            },
        )
        .unwrap();
    }
}
