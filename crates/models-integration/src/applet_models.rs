//! Applet install / edge operation body DTOs.
//!
//! The install preview / install request bodies embed the applet package
//! (`AppletPackage`, this crate's `applet::registration`), so they live here.
//! `AppletTransactionRequestBody` (binds encrypted `SignalEnvelope` values) and
//! `AppletRevokeRequestBody` (binds `AccountLifecycleProof`) live in
//! `arkret-models-collaboration`.

use std::collections::BTreeMap;

use arkret_wire::{
    AppletId, AppletRevokeMode, BlobRef, DidCoreId, DidUrl, Event, EventId, GrantId, Hash,
    PayloadSigner, ProtocolOperationId, RealmId, ReasonCode, Result, ScopeRef, WireError,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::applet::AppletPackage;
use crate::artifacts_applet::{
    E2eePolicy, ExternalRef, FieldDefinition, ProtocolInstance, RejectedItem,
};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletPingOutcome {
    pub ok: bool,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub protocol_version: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletTransactionOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<RejectedItem>,
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
pub enum AppletBotMembership {
    Invite,
    Join,
    Disabled,
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
    pub bot_membership: Option<AppletBotMembership>,
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
    Rejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallOutcome {
    pub ok: bool,
    pub install_id: String,
    pub applet_id: AppletId,
    pub registration_event_ref: Option<EventId>,
    pub registration_epoch: Hash,
    pub bot_actor_id: DidCoreId,
    pub bot_actor_principal_server_id: DidCoreId,
    pub bot_actor_provision_ref: EventId,
    pub bot_principal_control_realm_id: RealmId,
    pub capability_grant_refs: Vec<GrantId>,
    pub membership_event_refs: Vec<EventId>,
    pub e2ee_authorization_refs: Vec<EventId>,
    pub widget_policy_ref: Option<EventId>,
    pub effective_status: AppletInstallEffectiveStatus,
    pub rejected: Vec<AppletRejectedItem>,
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
    pub ok: bool,
    pub operation_id: ProtocolOperationId,
    pub revoke_plan_digest: Hash,
    pub status: AppletRevokeSagaStatus,
    pub steps: Vec<AppletRevokeStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<AppletRejectedItem>,
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
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallAuthoringRequestBasis {
    pub schema: String,
    pub target_principal_server_id: DidCoreId,
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub requested_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub requested_expires_at: DateTime<Utc>,
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
            || self.capability_grant_events.is_empty()
            || self.requested_at >= self.requested_expires_at
            || self.requested_expires_at - self.requested_at > chrono::Duration::minutes(5)
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
    target_principal_server_id: DidCoreId,
    install_actor_id: DidCoreId,
    applet_id: AppletId,
    service_id: DidCoreId,
    package_digest: Hash,
    effective_scope: ScopeRef,
    approval_request: AppletApprovalRequest,
    actor_policy: Option<AppletActorPolicy>,
    e2ee_policy: Option<E2eePolicy>,
    widget_policy: Option<AppletWidgetPolicy>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    requested_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    requested_expires_at: DateTime<Utc>,
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
        serde_json::from_value::<crate::applet::AppletRegistrationEpochEvidence>(evidence)
            .map_err(serde::de::Error::custom)?;
        if wire.capability_grant_events.is_empty() {
            return Err(serde::de::Error::custom(
                "capability_grant_events must not be empty",
            ));
        }
        let basis = Self {
            schema: wire.schema,
            target_principal_server_id: wire.target_principal_server_id,
            install_actor_id: wire.install_actor_id,
            applet_id: wire.applet_id,
            service_id: wire.service_id,
            package_digest: wire.package_digest,
            effective_scope: wire.effective_scope,
            approval_request: wire.approval_request,
            actor_policy: wire.actor_policy,
            e2ee_policy: wire.e2ee_policy,
            widget_policy: wire.widget_policy,
            requested_at: wire.requested_at,
            requested_expires_at: wire.requested_expires_at,
            registration_event: wire.registration_event,
            capability_grant_events: wire.capability_grant_events,
        };
        basis.validate().map_err(serde::de::Error::custom)?;
        Ok(basis)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallAuthoringProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub domain: String,
    pub audience: DidCoreId,
    pub jws: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallAuthoringRequest {
    pub schema: String,
    pub authoring_request_id: ProtocolOperationId,
    pub basis: AppletInstallAuthoringRequestBasis,
    pub plan_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AppletInstallAuthoringProof,
}

impl AppletInstallAuthoringRequest {
    pub const SCHEMA: &'static str = "ak.schema.applet_install_authoring_request.v1";
    pub const PROOF_DOMAIN: &'static str = "arkret.applet.install.authoring-request.v1";

    fn id_projection(
        basis: &AppletInstallAuthoringRequestBasis,
        plan_digest: &Hash,
        expires_at: DateTime<Utc>,
    ) -> serde_json::Value {
        serde_json::json!({
            "schema": Self::SCHEMA,
            "basis": basis,
            "plan_digest": plan_digest,
            "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        })
    }

    pub fn derive_id(
        basis: &AppletInstallAuthoringRequestBasis,
        plan_digest: &Hash,
        expires_at: DateTime<Utc>,
    ) -> Result<ProtocolOperationId> {
        let digest =
            canonical::canonical_sha256(&Self::id_projection(basis, plan_digest, expires_at))?;
        let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
            WireError::Protocol("authoring request digest is not sha256".to_owned())
        })?;
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| {
                WireError::Protocol("authoring request digest is malformed".to_owned())
            })?;
        }
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let value = format!(
            "ak:operation:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        );
        ProtocolOperationId::new(value).map_err(|error| WireError::Protocol(error.to_owned()))
    }

    pub fn unsigned_payload_value(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "authoring_request_id": self.authoring_request_id,
            "basis": self.basis,
            "plan_digest": self.plan_digest,
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
            "payload_digest": self.proof.payload_digest,
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
            "domain": self.proof.domain,
            "audience": self.proof.audience,
        }))
        .map_err(Into::into)
    }

    pub fn validate_bindings(&self) -> Result<()> {
        self.basis.validate()?;
        if self.schema != Self::SCHEMA
            || self.authoring_request_id
                != Self::derive_id(&self.basis, &self.plan_digest, self.expires_at)?
            || self.proof.payload_digest != self.payload_digest()?
            || self.proof.domain != Self::PROOF_DOMAIN
            || self.proof.audience != self.basis.service_id
            || self.proof.kind != arkret_wire::proof_kind::DETACHED_JWS
            || self.expires_at != self.basis.requested_expires_at
            || self.proof.created_at >= self.expires_at
            || self.proof.created_at != self.basis.requested_at
        {
            return Err(WireError::Protocol(
                "applet install authoring request binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn sign<S: PayloadSigner + ?Sized>(
        basis: AppletInstallAuthoringRequestBasis,
        plan_digest: Hash,
        expires_at: DateTime<Utc>,
        signer: &S,
    ) -> Result<Self> {
        basis.validate()?;
        let expires_at = arkret_canonical::canonical::normalize_timestamp_canonical(expires_at);
        let authoring_request_id = Self::derive_id(&basis, &plan_digest, expires_at)?;
        let created_at = basis.requested_at;
        let audience = basis.service_id.clone();
        let mut request = Self {
            schema: Self::SCHEMA.to_owned(),
            authoring_request_id,
            basis,
            plan_digest,
            expires_at,
            proof: AppletInstallAuthoringProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: signer.verification_method_id().clone(),
                payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))?,
                created_at,
                domain: Self::PROOF_DOMAIN.to_owned(),
                audience,
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
    pub authoring_request: AppletInstallAuthoringRequest,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallAuthorRequestBody {
    pub authoring_request: AppletInstallAuthoringRequest,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthoringBundle {
    pub schema: String,
    pub authoring_request_digest: Hash,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub bot_actor_provision_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub bot_pcr_genesis_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub bot_accountability_grant_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub bot_profile_event: Event,
    pub proof: AppletInstallAuthoringProof,
}

impl AppletManagedActorAuthoringBundle {
    pub const SCHEMA: &'static str = "ak.schema.applet_managed_actor_authoring_bundle.v1";
    pub const PROOF_DOMAIN: &'static str = "arkret.applet.install.managed-actor-bundle.v1";

    pub fn unsigned_payload_value(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "authoring_request_digest": self.authoring_request_digest,
            "bot_actor_provision_event": self.bot_actor_provision_event,
            "bot_pcr_genesis_event": self.bot_pcr_genesis_event,
            "bot_accountability_grant_event": self.bot_accountability_grant_event,
            "bot_profile_event": self.bot_profile_event,
        })
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(&self.unsigned_payload_value())?).map_err(Into::into)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(&serde_json::json!({
            "payload_digest": self.proof.payload_digest,
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
            "domain": self.proof.domain,
            "audience": self.proof.audience,
        }))
        .map_err(Into::into)
    }

    pub fn validate_bindings(
        &self,
        authoring_request: &AppletInstallAuthoringRequest,
    ) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.authoring_request_digest != authoring_request.canonical_digest()?
            || self.proof.payload_digest != self.payload_digest()?
            || self.proof.domain != Self::PROOF_DOMAIN
            || self.proof.audience != authoring_request.basis.target_principal_server_id
            || self.proof.kind != arkret_wire::proof_kind::DETACHED_JWS
            || self.proof.created_at != authoring_request.basis.requested_at
            || self.proof.created_at > authoring_request.expires_at
            || [
                &self.bot_actor_provision_event,
                &self.bot_pcr_genesis_event,
                &self.bot_accountability_grant_event,
                &self.bot_profile_event,
            ]
            .into_iter()
            .any(|event| event.created_at != authoring_request.basis.requested_at)
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
pub struct AppletInstallAuthorOutcome {
    pub managed_actor_bundle: AppletManagedActorAuthoringBundle,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallRequestBody {
    pub applet_package: AppletPackage,
    pub authoring_request: AppletInstallAuthoringRequest,
    pub managed_actor_bundle: AppletManagedActorAuthoringBundle,
}
