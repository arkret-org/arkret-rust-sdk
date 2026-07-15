//! Profile claim validator.
//!
//! Wraps the generated `profile_roles` table (mirror of
//! `arkret-spec/spec/v1/artifacts/profiles/conformance-profiles.json#/profile_roles`)
//! with a typed API that SDK consumers, conformance harnesses, and capability
//! manifests can use to refuse role-mismatched profile claims at construction
//! time.
//!
//! ## Why this exists
//!
//! Prior to T0.5 there was nothing preventing e.g. inkson (a client SDK
//! consumer) from declaring `ak.profile.push_gateway.v1` in its
//! `supported_profiles` manifest, because the spec layer only documented the
//! prohibition in prose. This module surfaces the partition in code so a
//! mismatched claim becomes a structured `ProfileClaimError` instead of
//! silently-accepted runtime garbage.
//!
//! ## Cross-role rules
//!
//! Roles partition the profile namespace into:
//!
//! * `client` — locally implemented end-user surface (chat, kanban, e2ee, franking sender
//!   commitment, …).
//! * `server` — wire-conformance principal / federation / agent runtime surfaces (core event store,
//!   principal server, agent workspace flavours, …).
//! * `gateway` — push / blob / media relay surfaces.
//! * `directory`— directory / identity-registry surfaces.
//! * `admin` — deployment / hardening / constraint posture profiles that describe operator stance
//!   rather than wire conformance.
//! * `interop` — explicit cross-role bridge surfaces (mimi_interop, matrix_compat,
//!   push_gateway.matrix_passthrough, encoding / hash interop, conformance vector packs).
//!
//! A [`ServiceType`] declares which roles it can legitimately claim; profiles
//! whose role is not in that allow-set are rejected. `interop` profiles are
//! always allowed because their purpose is bridging across roles (a
//! `push_gateway` claiming `mimi_interop` is exactly the case the spec
//! supports).
//!
//! ## Example
//!
//! ```rust
//! use arkret_policy::{ProfileClaim, ProfileClaimKind, ProfileValidator};
//! use arkret_wire_base::ServiceType;
//!
//! let validator = ProfileValidator::new(ServiceType::PushGateway);
//! let claims = [
//!     ProfileClaim::new(
//!         "ak.profile.push_gateway.v1",
//!         ProfileClaimKind::ConformanceVerified,
//!     ),
//!     ProfileClaim::new(
//!         "ak.profile.push_gateway.matrix_passthrough.v1",
//!         ProfileClaimKind::ConformanceVerified,
//!     ),
//! ];
//! validator
//!     .validate(&claims)
//!     .expect("push_gateway may claim gateway + interop");
//! ```

use std::fmt;

use crate::ServiceType;
use crate::generated::profiles::{ProfileRole, profile_role};

/// Provenance for a [`ProfileClaim`].
///
/// Tracks how strong the claim is so downstream tooling (cotest gate, soland
/// `describe`, inkson capability manifest) can distinguish "we ran the suite
/// and it passed" from "the implementor asserts this themselves" from
/// "experimental / not-yet-in-v1-catalog".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProfileClaimKind {
    /// Implementor self-claims the profile. Weakest signal; must still pass
    /// role partitioning + spec presence checks.
    SelfClaimed,
    /// Verified by a successful Conformance Verifier run against the
    /// artifact registry. Strongest in-band signal. (2026-06-10 neutralized
    /// the tool-specific name: wire value is `conformance_verified`.)
    ConformanceVerified,
    /// Profile id is intentionally outside the v1 catalogue (e.g. private
    /// extension, prototype). Role validation still applies if the id is in
    /// the spec table; otherwise the claim is allowed but flagged.
    Experimental,
}

impl ProfileClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfClaimed => "self_claimed",
            Self::ConformanceVerified => "conformance_verified",
            Self::Experimental => "experimental",
        }
    }
}

impl fmt::Display for ProfileClaimKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single profile_id + provenance pair.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProfileClaim {
    pub profile_id: String,
    pub kind: ProfileClaimKind,
}

impl ProfileClaim {
    pub fn new(profile_id: impl Into<String>, kind: ProfileClaimKind) -> Self {
        Self {
            profile_id: profile_id.into(),
            kind,
        }
    }

    pub fn self_claimed(profile_id: impl Into<String>) -> Self {
        Self::new(profile_id, ProfileClaimKind::SelfClaimed)
    }

    pub fn conformance_verified(profile_id: impl Into<String>) -> Self {
        Self::new(profile_id, ProfileClaimKind::ConformanceVerified)
    }

    pub fn experimental(profile_id: impl Into<String>) -> Self {
        Self::new(profile_id, ProfileClaimKind::Experimental)
    }

    /// Resolves the spec-declared role for the underlying profile id, if any.
    pub fn declared_role(&self) -> Option<ProfileRole> {
        profile_role(&self.profile_id)
    }
}

/// Structured rejection from [`ProfileValidator::validate`].
///
/// Each variant carries enough context for callers to render a user-facing
/// diagnostic without re-deriving the role table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileClaimError {
    /// The profile id is not present in the spec catalogue. This blocks
    /// `SelfClaimed` / `ConformanceVerified` provenance, but `Experimental` claims
    /// are surfaced as [`Self::ExperimentalUnknownProfile`] instead so they
    /// can be allow-listed by the caller.
    UnknownProfile {
        profile_id: String,
        kind: ProfileClaimKind,
    },
    /// The profile is declared in the spec but its `profile_roles` entry is
    /// not in the allow-set of the claiming service.
    RoleMismatch {
        profile_id: String,
        declared_role: ProfileRole,
        service_type: ServiceType,
        permitted_roles: Vec<ProfileRole>,
    },
    /// `Experimental` claim on an id the spec does not declare. Not fatal in
    /// itself — the validator surfaces it so the caller can decide whether
    /// experimental profiles are acceptable in this deployment.
    ExperimentalUnknownProfile { profile_id: String },
}

impl fmt::Display for ProfileClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProfile { profile_id, kind } => write!(
                f,
                "profile {profile_id} is not in the spec catalogue but was claimed as {kind}"
            ),
            Self::RoleMismatch {
                profile_id,
                declared_role,
                service_type,
                permitted_roles,
            } => {
                let permitted: Vec<&str> =
                    permitted_roles.iter().map(|role| role.as_str()).collect();
                write!(
                    f,
                    "service_type {} cannot claim {profile_id} (role={}); permitted roles: {}",
                    service_type.as_str(),
                    declared_role.as_str(),
                    permitted.join(", ")
                )
            }
            Self::ExperimentalUnknownProfile { profile_id } => {
                write!(
                    f,
                    "experimental profile {profile_id} is not in the spec catalogue"
                )
            }
        }
    }
}

impl std::error::Error for ProfileClaimError {}

/// Validator bound to a single [`ServiceType`].
///
/// Role allow-set is derived from `ServiceType` once, then reused for every
/// claim. `interop` is added to every allow-set because the spec defines that
/// role specifically as the cross-role bridge namespace (matrix_compat,
/// push_gateway.matrix_passthrough, encoding / hash interop vectors).
#[derive(Clone, Debug)]
pub struct ProfileValidator {
    service_type: ServiceType,
    permitted_roles: Vec<ProfileRole>,
    /// If true, `Experimental` claims for ids not in the spec are surfaced as
    /// `ExperimentalUnknownProfile` errors rather than silently accepted.
    /// Defaults to true so callers see the unknown id; flip via
    /// [`Self::accept_experimental_unknown`].
    surface_experimental_unknown: bool,
}

impl ProfileValidator {
    /// Build a validator for `service_type`. The permitted-roles allow-set is
    /// fixed by the spec and not configurable here — see [`Self::permitted_roles`]
    /// for the resolution rule.
    pub fn new(service_type: ServiceType) -> Self {
        let permitted_roles = Self::permitted_roles(service_type.clone());
        Self {
            service_type,
            permitted_roles,
            surface_experimental_unknown: true,
        }
    }

    /// Treat `Experimental` claims with unknown profile ids as acceptable
    /// (the default is to flag them so the caller can audit before shipping).
    pub fn accept_experimental_unknown(mut self) -> Self {
        self.surface_experimental_unknown = false;
        self
    }

    pub fn service_type(&self) -> &ServiceType {
        &self.service_type
    }

    pub fn permitted_role_set(&self) -> &[ProfileRole] {
        &self.permitted_roles
    }

    /// Spec-derived allow-set:
    ///
    /// * `Interop` is always included (bridge profiles).
    /// * Each `ServiceType` exposes its own canonical role plus the `Admin` role, because
    ///   deployment / hardening posture profiles are service-agnostic.
    /// * Client-shaped service types (none today — clients consume the SDK directly rather than
    ///   registering as a `ServiceType`) would surface `Client` here. The SDK exposes
    ///   [`Self::for_client`] for that path.
    pub fn permitted_roles(service_type: ServiceType) -> Vec<ProfileRole> {
        let mut roles = match service_type {
            ServiceType::PrincipalServer
            | ServiceType::SyncNode
            | ServiceType::AuthServer
            | ServiceType::AppletService
            | ServiceType::AgentRuntime
            | ServiceType::ModerationService
            | ServiceType::Notary
            | ServiceType::RecoveryService => {
                vec![ProfileRole::Server]
            }
            ServiceType::DirectoryService
            | ServiceType::SearchService
            | ServiceType::ArchiveNode => {
                vec![ProfileRole::Directory]
            }
            ServiceType::IdentityRegistry => {
                vec![ProfileRole::Directory, ProfileRole::Server]
            }
            ServiceType::PushGateway
            | ServiceType::BlobNode
            | ServiceType::MediaService
            | ServiceType::SfuService
            | ServiceType::TurnService => {
                vec![ProfileRole::Gateway]
            }
            ServiceType::DeviceKeyService
            | ServiceType::AuthzService
            | ServiceType::PolicyServer
            | ServiceType::KeyRecoveryService => {
                vec![ProfileRole::Server, ProfileRole::Directory]
            }
        };
        roles.push(ProfileRole::Admin);
        roles.push(ProfileRole::Interop);
        roles.sort();
        roles.dedup();
        roles
    }

    /// Allow-set for an SDK consumer running in client role (inkson, sample
    /// front-ends, capability manifests). Not bound to a `ServiceType` because
    /// clients consume the protocol surface rather than publishing one.
    pub fn for_client() -> Self {
        Self {
            service_type: ServiceType::PrincipalServer, // sentinel: never used
            permitted_roles: vec![
                ProfileRole::Client,
                ProfileRole::Admin,
                ProfileRole::Interop,
            ],
            surface_experimental_unknown: true,
        }
    }

    /// Validate a batch of claims. Returns `Ok(())` if every claim is allowed;
    /// otherwise returns the full list of failures so callers can surface
    /// every problem in one pass instead of trickling them out.
    pub fn validate(&self, claims: &[ProfileClaim]) -> Result<(), Vec<ProfileClaimError>> {
        let mut errors = Vec::new();
        for claim in claims {
            if let Err(error) = self.validate_one(claim) {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate a single claim. Exposed for callers that want per-claim
    /// granularity (e.g. partial manifests where each line should be
    /// independently annotated).
    pub fn validate_one(&self, claim: &ProfileClaim) -> Result<(), ProfileClaimError> {
        match profile_role(&claim.profile_id) {
            Some(role) => {
                if role == ProfileRole::Interop || self.permitted_roles.contains(&role) {
                    Ok(())
                } else {
                    Err(ProfileClaimError::RoleMismatch {
                        profile_id: claim.profile_id.clone(),
                        declared_role: role,
                        // The sentinel service_type for the client validator
                        // is never the actual surface so we replay it as-is
                        // — callers reading the error compare against
                        // `service_type.as_str()` for diagnostics only.
                        service_type: self.service_type.clone(),
                        permitted_roles: self.permitted_roles.clone(),
                    })
                }
            }
            None => match claim.kind {
                ProfileClaimKind::Experimental => {
                    if self.surface_experimental_unknown {
                        Err(ProfileClaimError::ExperimentalUnknownProfile {
                            profile_id: claim.profile_id.clone(),
                        })
                    } else {
                        Ok(())
                    }
                }
                ProfileClaimKind::SelfClaimed | ProfileClaimKind::ConformanceVerified => {
                    Err(ProfileClaimError::UnknownProfile {
                        profile_id: claim.profile_id.clone(),
                        kind: claim.kind,
                    })
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_validator_rejects_gateway_profile_claim() {
        let validator = ProfileValidator::for_client();
        let errors = validator
            .validate(&[ProfileClaim::self_claimed("ak.profile.push_gateway.v1")])
            .expect_err("client must not claim a gateway profile");
        assert_eq!(errors.len(), 1);
        match &errors[0] {
            ProfileClaimError::RoleMismatch { declared_role, .. } => {
                assert_eq!(*declared_role, ProfileRole::Gateway);
            }
            other => panic!("expected RoleMismatch, got {other:?}"),
        }
    }

    #[test]
    fn client_validator_accepts_client_and_admin_and_interop() {
        let validator = ProfileValidator::for_client();
        validator
            .validate(&[
                ProfileClaim::conformance_verified("ak.profile.chat_mvp.v1"),
                ProfileClaim::conformance_verified("ak.profile.kanban_mvp.v1"),
                // Admin profiles (deployment posture) are allowed on the
                // client because clients ship with a deployment stance.
                ProfileClaim::self_claimed("ak.profile.personal_node.v1"),
                ProfileClaim::conformance_verified("ak.profile.matrix_compat.v1"),
            ])
            .expect("client + client_profile + admin + interop must validate");
    }

    #[test]
    fn push_gateway_can_claim_interop_bridge_profile() {
        let validator = ProfileValidator::new(ServiceType::PushGateway);
        validator
            .validate(&[
                ProfileClaim::conformance_verified("ak.profile.push_gateway.v1"),
                ProfileClaim::conformance_verified("ak.profile.push_gateway.blind_wakeup.v1"),
                ProfileClaim::conformance_verified("ak.profile.push_gateway.matrix_passthrough.v1"),
            ])
            .expect("push_gateway may claim gateway + interop");
    }

    #[test]
    fn directory_service_rejects_server_profile() {
        let validator = ProfileValidator::new(ServiceType::DirectoryService);
        let errors = validator
            .validate(&[ProfileClaim::self_claimed("ak.profile.principal_server.v1")])
            .expect_err("directory service must not claim server profile");
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn unknown_profile_is_unknown_unless_experimental() {
        let validator = ProfileValidator::for_client();
        let errors = validator
            .validate(&[ProfileClaim::conformance_verified(
                "ak.profile.not_in_spec.v1",
            )])
            .expect_err("unknown profile must fail closed");
        assert!(matches!(
            errors[0],
            ProfileClaimError::UnknownProfile { .. }
        ));

        let errors = validator
            .validate(&[ProfileClaim::experimental(
                "ak.profile.experimental_thing.v1",
            )])
            .expect_err("experimental + unknown surfaces by default");
        assert!(matches!(
            errors[0],
            ProfileClaimError::ExperimentalUnknownProfile { .. }
        ));

        let permissive = ProfileValidator::for_client().accept_experimental_unknown();
        permissive
            .validate(&[ProfileClaim::experimental(
                "ak.profile.experimental_thing.v1",
            )])
            .expect("permissive validator accepts experimental unknown ids");
    }

    #[test]
    fn validator_returns_every_error_in_one_pass() {
        let validator = ProfileValidator::for_client();
        let errors = validator
            .validate(&[
                ProfileClaim::self_claimed("ak.profile.push_gateway.v1"),
                ProfileClaim::self_claimed("ak.profile.directory_service.v1"),
                ProfileClaim::self_claimed("ak.profile.principal_server.v1"),
            ])
            .expect_err("three mismatched claims => three errors");
        assert_eq!(errors.len(), 3);
    }

    #[test]
    fn permitted_roles_always_include_interop_and_admin() {
        for service in [
            ServiceType::PrincipalServer,
            ServiceType::DirectoryService,
            ServiceType::PushGateway,
            ServiceType::BlobNode,
            ServiceType::IdentityRegistry,
            ServiceType::AuthServer,
            ServiceType::AuthzService,
            ServiceType::PolicyServer,
            ServiceType::DeviceKeyService,
            ServiceType::AppletService,
            ServiceType::AgentRuntime,
            ServiceType::MediaService,
            ServiceType::SfuService,
            ServiceType::TurnService,
            ServiceType::ModerationService,
            ServiceType::SyncNode,
        ] {
            let roles = ProfileValidator::permitted_roles(service.clone());
            assert!(roles.contains(&ProfileRole::Interop));
            assert!(roles.contains(&ProfileRole::Admin));
        }
    }
}
