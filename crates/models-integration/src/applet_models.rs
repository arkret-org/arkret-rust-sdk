//! Applet install / edge operation body DTOs.
//!
//! The install preview / install request bodies embed the applet package
//! (`AppletPackage`, this crate's `applet::registration`), so they live here.
//! `AppletTransactionRequestBody` (binds encrypted `SignalEnvelope` values) and
//! `AppletRevokeRequestBody` (binds `AccountLifecycleProof`) live in
//! `arkret-models-collaboration`.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, AppletId, AppletRevokeMode, BlobRef, DidCoreId, DidUrl, Event, EventId, GrantId, Hash,
    NotarySignerDescriptor, PayloadSigner, ProtocolOperationId, RealmId, ReasonCode, Result,
    ScopeRef, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::applet::{AppletPackage, AppletRegistrationEpochEvidence, GhostExternalTuple};
use crate::artifacts_applet::{
    E2eePolicy, ExternalRef, FieldDefinition, ProtocolInstance, RejectedItem,
};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletPingOutcome {
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    #[serde(deserialize_with = "arkret_wire::deserialize_protocol_version")]
    pub protocol_version: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletTransactionStatus {
    Accepted,
    Partial,
    Rejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletTransactionOutcome {
    pub status: AppletTransactionStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<RejectedItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletApprovalRequest {
    pub approve_actions: Vec<String>,
    pub ghost_actor_mode: AppletGhostActorMode,
    pub delegated_native_actors_allowed: bool,
    pub e2ee_join_allowed: bool,
    pub widget_allowed: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletGhostActorMode {
    Disallowed,
    ControllerApproved,
    PolicyDeclared,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletActorPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ghost_actor_mode: Option<AppletGhostActorMode>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletWidgetPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_allowed: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRejectedItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_scope: Option<String>,
    pub reason_code: ReasonCode,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletInstallEffectiveStatus {
    Installed,
    PartiallyInstalled,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallOutcome {
    pub install_id: String,
    pub applet_id: AppletId,
    pub registration_event_ref: EventId,
    pub registration_epoch: Hash,
    pub bot_actor_id: ActorId,
    pub bot_actor_provision_ref: EventId,
    pub bot_principal_control_realm_id: RealmId,
    pub capability_grant_refs: Vec<GrantId>,
    pub e2ee_authorization_refs: Vec<EventId>,
    pub widget_policy_ref: Option<EventId>,
    pub effective_status: AppletInstallEffectiveStatus,
    pub rejections: Vec<AppletRejectedItem>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokePreviewRequestBody {
    pub effective_scope: ScopeRef,
    pub reason_code: ReasonCode,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revoke_mode: AppletRevokeMode,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletCapabilityRevokeIntent {
    pub event_kind: String,
    pub grant_id: GrantId,
    pub registration_epoch: Hash,
    pub reason_code: ReasonCode,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletMembershipRemoveIntent {
    pub event_kind: String,
    pub member_id: DidCoreId,
    pub membership: AppletManagedMembershipRemoval,
    pub reason_code: ReasonCode,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletManagedMembershipRemoval {
    Leave,
    Remove,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokePlan {
    pub applet_id: AppletId,
    pub effective_scope: ScopeRef,
    pub registration_epoch: Hash,
    pub reason_code: ReasonCode,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revoke_mode: AppletRevokeMode,
    pub capability_revocations: Vec<AppletCapabilityRevokeIntent>,
    pub membership_removals: Vec<AppletMembershipRemoveIntent>,
    pub widget_token_refs: Vec<String>,
    pub delegated_session_refs: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokePreviewOutcome {
    pub revoke_plan_digest: Hash,
    pub revoke_plan: AppletRevokePlan,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeSagaStatus {
    Complete,
    InProgress,
    PartiallyCompleted,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeStepStatus {
    Pending,
    Accepted,
    Duplicate,
    Rejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeEffectKind {
    CapabilityRevokeEvent,
    MembershipStateEvent,
    WidgetTokenInvalidation,
    DelegatedSessionRevocation,
    LocalAppletFence,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeStep {
    pub effect_kind: AppletRevokeEffectKind,
    pub effect_ref: String,
    pub status: AppletRevokeStepStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeOutcome {
    pub operation_id: ProtocolOperationId,
    pub revoke_plan_digest: Hash,
    pub status: AppletRevokeSagaStatus,
    pub steps: Vec<AppletRevokeStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<AppletRejectedItem>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletActorView {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletRealmView {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletProtocolMetadata {
    pub protocol: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_blob_ref: Option<BlobRef>,
    pub field_definitions: BTreeMap<String, FieldDefinition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<ProtocolInstance>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallPreviewRequestBody {
    pub applet_package: AppletPackage,
    pub authoring_request_basis: AppletInstallAuthoringRequestBasis,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletManagedActorPurpose {
    InstallBot,
    ProvisionGhost,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallAuthoringRequestBasis {
    pub schema: String,
    pub purpose: AppletManagedActorPurpose,
    pub target_station_id: DidCoreId,
    pub install_actor_id: DidCoreId,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub package_digest: Hash,
    pub effective_scope: ScopeRef,
    pub approval_request: AppletApprovalRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_policy: Option<AppletActorPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_policy: Option<E2eePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_policy: Option<AppletWidgetPolicy>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub registration_event: Event,
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub capability_grant_events: Vec<Event>,
}

impl AppletInstallAuthoringRequestBasis {
    pub const SCHEMA: &'static str = "ak.schema.applet_install_authoring_request_basis.v1";

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.purpose != AppletManagedActorPurpose::InstallBot
            || self.capability_grant_events.is_empty()
        {
            return Err(WireError::Protocol(
                "applet install authoring request basis is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppletInstallAuthoringRequestBasisWire {
    schema: String,
    purpose: AppletManagedActorPurpose,
    target_station_id: DidCoreId,
    install_actor_id: DidCoreId,
    applet_id: AppletId,
    service_id: DidCoreId,
    package_digest: Hash,
    effective_scope: ScopeRef,
    approval_request: AppletApprovalRequest,
    actor_policy: Option<AppletActorPolicy>,
    e2ee_policy: Option<E2eePolicy>,
    widget_policy: Option<AppletWidgetPolicy>,
    registration_event: Event,
    capability_grant_events: Vec<Event>,
}

impl<'de> Deserialize<'de> for AppletInstallAuthoringRequestBasis {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AppletInstallAuthoringRequestBasisWire::deserialize(deserializer)?;
        let evidence = wire
            .registration_event
            .payload
            .get("manifest")
            .and_then(serde_json::Value::as_object)
            .and_then(|manifest| manifest.get("registration_epoch_evidence"))
            .cloned()
            .ok_or_else(|| {
                serde::de::Error::missing_field(
                    "registration_event.payload.manifest.registration_epoch_evidence",
                )
            })?;
        serde_json::from_value::<AppletRegistrationEpochEvidence>(evidence)
            .map_err(serde::de::Error::custom)?;
        if wire.capability_grant_events.is_empty() {
            return Err(serde::de::Error::custom(
                "capability_grant_events must not be empty",
            ));
        }
        let basis = Self {
            schema: wire.schema,
            purpose: wire.purpose,
            target_station_id: wire.target_station_id,
            install_actor_id: wire.install_actor_id,
            applet_id: wire.applet_id,
            service_id: wire.service_id,
            package_digest: wire.package_digest,
            effective_scope: wire.effective_scope,
            approval_request: wire.approval_request,
            actor_policy: wire.actor_policy,
            e2ee_policy: wire.e2ee_policy,
            widget_policy: wire.widget_policy,
            registration_event: wire.registration_event,
            capability_grant_events: wire.capability_grant_events,
        };
        basis.validate().map_err(serde::de::Error::custom)?;
        Ok(basis)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletGhostAuthoringRequestBasis {
    pub schema: String,
    pub purpose: AppletManagedActorPurpose,
    pub target_station_id: DidCoreId,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub realm_id: RealmId,
    pub external_ref: GhostExternalTuple,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub registration_event_ref: EventId,
    pub authorization_ref: GrantId,
    pub registration_epoch_evidence: AppletRegistrationEpochEvidence,
    pub package_digest: Hash,
}

impl AppletGhostAuthoringRequestBasis {
    pub const SCHEMA: &'static str = "ak.schema.applet_ghost_authoring_request_basis.v1";

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA || self.purpose != AppletManagedActorPurpose::ProvisionGhost
        {
            return Err(WireError::Protocol(
                "applet Ghost authoring request basis is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletManagedActorAuthoringBasis {
    InstallBot(Box<AppletInstallAuthoringRequestBasis>),
    ProvisionGhost(Box<AppletGhostAuthoringRequestBasis>),
}

impl AppletManagedActorAuthoringBasis {
    pub fn purpose(&self) -> AppletManagedActorPurpose {
        match self {
            Self::InstallBot(_) => AppletManagedActorPurpose::InstallBot,
            Self::ProvisionGhost(_) => AppletManagedActorPurpose::ProvisionGhost,
        }
    }

    pub fn target_station_id(&self) -> &DidCoreId {
        match self {
            Self::InstallBot(basis) => &basis.target_station_id,
            Self::ProvisionGhost(basis) => &basis.target_station_id,
        }
    }

    pub fn service_id(&self) -> &DidCoreId {
        match self {
            Self::InstallBot(basis) => &basis.service_id,
            Self::ProvisionGhost(basis) => &basis.service_id,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::InstallBot(basis) => basis.validate(),
            Self::ProvisionGhost(basis) => basis.validate(),
        }
    }

    pub fn install(&self) -> Option<&AppletInstallAuthoringRequestBasis> {
        match self {
            Self::InstallBot(basis) => Some(basis),
            Self::ProvisionGhost(_) => None,
        }
    }

    pub fn ghost(&self) -> Option<&AppletGhostAuthoringRequestBasis> {
        match self {
            Self::InstallBot(_) => None,
            Self::ProvisionGhost(basis) => Some(basis),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub audience_id: DidCoreId,
    pub jws: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthoringRequest {
    pub schema: String,
    pub purpose: AppletManagedActorPurpose,
    pub basis: AppletManagedActorAuthoringBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<Hash>,
    pub hosting_notary: NotarySignerDescriptor,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AppletManagedActorProof,
}

impl AppletManagedActorAuthoringRequest {
    pub const SCHEMA: &'static str = "ak.schema.applet_managed_actor_authoring_request.v1";
    pub const PROOF_CONTEXT: &'static str = "ak.applet_managed_actor_authoring_request_proof.v1";

    pub fn unsigned_payload_value(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "purpose": self.purpose,
            "basis": self.basis,
            "plan_digest": self.plan_digest,
            "hosting_notary": self.hosting_notary,
            "issued_at": arkret_canonical::format_timestamp_canonical(self.issued_at),
            "expires_at": arkret_canonical::format_timestamp_canonical(self.expires_at),
        })
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(&self.unsigned_payload_value())?).map_err(Into::into)
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": Self::PROOF_CONTEXT,
            "payload_digest": self.proof.payload_digest,
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
            "audience_id": self.proof.audience_id,
        }))
        .map_err(Into::into)
    }

    pub fn validate_bindings(&self) -> Result<()> {
        self.basis.validate()?;
        self.hosting_notary.validate()?;
        if self.schema != Self::SCHEMA
            || self.purpose != self.basis.purpose()
            || (self.purpose == AppletManagedActorPurpose::InstallBot) != self.plan_digest.is_some()
            || self.proof.payload_digest != self.payload_digest()?
            || &self.proof.audience_id != self.basis.service_id()
            || self.proof.verification_method != self.hosting_notary.verification_method
            || self.hosting_notary.actor_id
                != ActorId::service(self.basis.target_station_id().clone())
            || self.proof.kind != arkret_wire::proof_kind::DETACHED_JWS
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > chrono::Duration::minutes(5)
            || self.proof.created_at >= self.expires_at
            || self.proof.created_at != self.issued_at
        {
            return Err(WireError::Protocol(
                "applet managed actor authoring request binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn sign<S: PayloadSigner + ?Sized>(
        basis: AppletInstallAuthoringRequestBasis,
        plan_digest: Hash,
        hosting_notary: NotarySignerDescriptor,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        signer: &S,
    ) -> Result<Self> {
        basis.validate()?;
        hosting_notary.validate()?;
        if hosting_notary.actor_id
            != ActorId::service(basis.target_station_id.clone())
            || hosting_notary.verification_method != *signer.verification_method_id()
        {
            return Err(WireError::Protocol(
                "hosting notary does not match the install authoring signer".to_owned(),
            ));
        }
        let issued_at = arkret_canonical::canonical::normalize_timestamp_canonical(issued_at);
        let expires_at = arkret_canonical::canonical::normalize_timestamp_canonical(expires_at);
        let audience = basis.service_id.clone();
        let mut request = Self {
            schema: Self::SCHEMA.to_owned(),
            purpose: AppletManagedActorPurpose::InstallBot,
            basis: AppletManagedActorAuthoringBasis::InstallBot(Box::new(basis)),
            plan_digest: Some(plan_digest),
            hosting_notary,
            issued_at,
            expires_at,
            proof: AppletManagedActorProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: signer.verification_method_id().clone(),
                payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))?,
                created_at: issued_at,
                audience_id: audience,
                jws: String::new(),
            },
        };
        request.proof.payload_digest = request.payload_digest()?;
        request.proof.jws = signer.sign_payload(&request.proof_binding_bytes()?)?.jws;
        request.validate_bindings()?;
        Ok(request)
    }

    pub fn sign_ghost<S: PayloadSigner + ?Sized>(
        basis: AppletGhostAuthoringRequestBasis,
        hosting_notary: NotarySignerDescriptor,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        signer: &S,
    ) -> Result<Self> {
        basis.validate()?;
        hosting_notary.validate()?;
        if hosting_notary.actor_id
            != ActorId::service(basis.target_station_id.clone())
            || hosting_notary.verification_method != *signer.verification_method_id()
        {
            return Err(WireError::Protocol(
                "hosting notary does not match the Ghost authoring signer".to_owned(),
            ));
        }
        let issued_at = arkret_canonical::canonical::normalize_timestamp_canonical(issued_at);
        let expires_at = arkret_canonical::canonical::normalize_timestamp_canonical(expires_at);
        let audience = basis.service_id.clone();
        let mut request = Self {
            schema: Self::SCHEMA.to_owned(),
            purpose: AppletManagedActorPurpose::ProvisionGhost,
            basis: AppletManagedActorAuthoringBasis::ProvisionGhost(Box::new(basis)),
            plan_digest: None,
            hosting_notary,
            issued_at,
            expires_at,
            proof: AppletManagedActorProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: signer.verification_method_id().clone(),
                payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))?,
                created_at: issued_at,
                audience_id: audience,
                jws: String::new(),
            },
        };
        request.proof.payload_digest = request.payload_digest()?;
        request.proof.jws = signer.sign_payload(&request.proof_binding_bytes()?)?.jws;
        request.validate_bindings()?;
        Ok(request)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallPreviewOutcome {
    pub plan: crate::AppletInstallPlan,
    pub authoring_request: AppletManagedActorAuthoringRequest,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthorRequestBody {
    pub authoring_request: AppletManagedActorAuthoringRequest,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthoringBundle {
    pub schema: String,
    pub authoring_request_digest: Hash,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub managed_actor_provision_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub pcr_genesis_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub accountability_grant_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile_event: Event,
    pub proof: AppletManagedActorProof,
}

impl AppletManagedActorAuthoringBundle {
    pub const SCHEMA: &'static str = "ak.schema.applet_managed_actor_authoring_bundle.v1";
    pub const PROOF_CONTEXT: &'static str = "ak.applet_managed_actor_bundle_proof.v1";

    pub fn unsigned_payload_value(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "authoring_request_digest": self.authoring_request_digest,
            "managed_actor_provision_event": self.managed_actor_provision_event,
            "pcr_genesis_event": self.pcr_genesis_event,
            "accountability_grant_event": self.accountability_grant_event,
            "profile_event": self.profile_event,
        })
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(&self.unsigned_payload_value())?).map_err(Into::into)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": Self::PROOF_CONTEXT,
            "payload_digest": self.proof.payload_digest,
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
            "audience_id": self.proof.audience_id,
        }))
        .map_err(Into::into)
    }

    pub fn validate_bindings(
        &self,
        authoring_request: &AppletManagedActorAuthoringRequest,
    ) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.authoring_request_digest != authoring_request.canonical_digest()?
            || self.proof.payload_digest != self.payload_digest()?
            || &self.proof.audience_id != authoring_request.basis.target_station_id()
            || self.proof.kind != arkret_wire::proof_kind::DETACHED_JWS
            || self.proof.created_at != authoring_request.issued_at
            || self.proof.created_at > authoring_request.expires_at
            || [
                &self.managed_actor_provision_event,
                &self.pcr_genesis_event,
                &self.accountability_grant_event,
                &self.profile_event,
            ]
            .into_iter()
            .any(|event| event.created_at != authoring_request.issued_at)
        {
            return Err(WireError::Protocol(
                "applet managed actor authoring bundle binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthorOutcome {
    pub managed_actor_bundle: AppletManagedActorAuthoringBundle,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletInstallRequestBody {
    Create(Box<AppletInstallCreateRequestBody>),
    Reuse(Box<AppletInstallReuseRequestBody>),
}

impl AppletInstallRequestBody {
    pub fn applet_package(&self) -> &AppletPackage {
        match self {
            Self::Create(request) => &request.applet_package,
            Self::Reuse(request) => &request.applet_package,
        }
    }

    pub fn authoring_request(&self) -> &AppletManagedActorAuthoringRequest {
        match self {
            Self::Create(request) => &request.authoring_request,
            Self::Reuse(request) => &request.authoring_request,
        }
    }

    pub fn managed_actor_bundle(&self) -> Option<&AppletManagedActorAuthoringBundle> {
        match self {
            Self::Create(request) => Some(&request.managed_actor_bundle),
            Self::Reuse(_) => None,
        }
    }

    pub fn reuse_existing_managed_actor(&self) -> Option<&ReuseExistingManagedActor> {
        match self {
            Self::Create(_) => None,
            Self::Reuse(request) => Some(&request.reuse_existing_managed_actor),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallCreateRequestBody {
    pub applet_package: AppletPackage,
    pub authoring_request: AppletManagedActorAuthoringRequest,
    pub managed_actor_bundle: AppletManagedActorAuthoringBundle,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallReuseRequestBody {
    pub applet_package: AppletPackage,
    pub authoring_request: AppletManagedActorAuthoringRequest,
    pub reuse_existing_managed_actor: ReuseExistingManagedActor,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseExistingManagedActor {
    pub actor_id: ActorId,
    pub managed_actor_provision_ref: EventId,
    pub pcr_genesis_ref: EventId,
    pub accountability_grant_ref: EventId,
    pub profile_event_ref: EventId,
    pub initial_package_bot_actor_id: ActorId,
}
