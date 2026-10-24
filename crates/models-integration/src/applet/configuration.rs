//! Bounded administrator intent and Applet execution carriers.
//! A candidate is not a governance acceptance or a business authorization.
use arkret_wire::{
    ActorId, AppletId, ApprovalSignature, CommittedEventRef, DidCoreId, DidUrl, DomainSeparationId,
    Event, EventKind, Hash, PayloadSigner, RequestId, Result, ScopeRef, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const MAX_CANONICAL_BYTES: usize = 262_144;

fn invalid(detail: &str) -> WireError {
    WireError::Protocol(format!("Applet configuration: {detail}"))
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AppletConfigurationSelection {
    NewBot {
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
        )]
        display_name: Option<String>,
    },
    ExistingRealmActor {
        actor_id: ActorId,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletConfigurationCommand {
    Configure,
    Cancel,
    Recover,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletConfigurationIntent {
    pub request_id: RequestId,
    pub service_id: DidCoreId,
    pub effective_scope: ScopeRef,
    pub selection: AppletConfigurationSelection,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletConfigurationRequestBody {
    pub command: AppletConfigurationCommand,
    pub intent: AppletConfigurationIntent,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<Vec<serde_json::Value>>)))]
    pub approval_signatures: Option<Vec<ApprovalSignature>>,
}

/// Account-Station-authenticated forwarding of the unchanged self request.
/// The governor independently authorizes the full Account before writing.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletConfigurationPeerRequestBody {
    pub requester_account_id: arkret_wire::AccountId,
    pub request: AppletConfigurationRequestBody,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletConfigurationExecutionIntent {
    pub request_id: RequestId,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub governance_station_id: DidCoreId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub governance_generation: u64,
    pub effective_scope: ScopeRef,
    pub registration_ref: CommittedEventRef,
    pub registration_epoch: Hash,
    pub originating_actor_id: ActorId,
    pub selection: AppletConfigurationSelection,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletConfigurationSignature {
    pub verification_method: DidUrl,
    pub jws: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletConfigurationExecutionRequestBody {
    pub command: AppletConfigurationCommand,
    pub intent: AppletConfigurationExecutionIntent,
    pub governance_station_id: DidCoreId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub governance_generation: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AppletConfigurationSignature,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletConfigurationExecutionStatus {
    Pending,
    Candidate,
    Created,
    Reused,
    Denied,
    Cancelled,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletConfigurationExecutionResponseBody {
    pub request_id: RequestId,
    pub intent_digest: Hash,
    pub service_id: DidCoreId,
    pub status: AppletConfigurationExecutionStatus,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub actor_id: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub creation_refs: Option<Vec<CommittedEventRef>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: DateTime<Utc>,
    pub proof: AppletConfigurationSignature,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<serde_json::Value>)))]
    pub create_event: Option<Box<Event>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletConfigurationAdmissionStatus {
    NotStarted,
    Pending,
    Accepted,
    Denied,
    Cancelled,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletConfigurationResponseBody {
    pub request_id: RequestId,
    pub intent_digest: Hash,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub source_response_body: Option<AppletConfigurationExecutionResponseBody>,
    pub admission_status: AppletConfigurationAdmissionStatus,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub review_request_id: Option<RequestId>,
}

fn bounded<T: Serialize>(value: &T) -> Result<()> {
    if arkret_canonical::canonical_json_bytes(value)?.len() > MAX_CANONICAL_BYTES {
        return Err(invalid("canonical body exceeds its registered limit"));
    }
    Ok(())
}

fn validate_selection(scope: &ScopeRef, selection: &AppletConfigurationSelection) -> Result<()> {
    if !matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. }) {
        return Err(invalid("configuration requires a Realm or Circle scope"));
    }
    match selection {
        AppletConfigurationSelection::NewBot { display_name } => {
            if let Some(name) = display_name {
                arkret_wire::validate_single_line_display_text(name, 256)?;
            }
        }
        AppletConfigurationSelection::ExistingRealmActor { actor_id } => {
            if actor_id
                .as_realm_actor_id()
                .is_none_or(|actor| &actor.realm_id != scope.realm_id())
            {
                return Err(invalid("selection must name a full actor in this Realm"));
            }
        }
    }
    Ok(())
}

impl AppletConfigurationIntent {
    pub fn validate(&self) -> Result<()> {
        validate_selection(&self.effective_scope, &self.selection)?;
        bounded(self)
    }
}

impl AppletConfigurationRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        if self
            .approval_signatures
            .as_ref()
            .is_some_and(|items| items.is_empty() || items.len() > 64)
        {
            return Err(invalid("approval evidence must contain 1..64 signatures"));
        }
        bounded(self)
    }
}

impl AppletConfigurationPeerRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        bounded(self)
    }
}

impl AppletConfigurationExecutionIntent {
    pub fn validate(&self) -> Result<()> {
        validate_selection(&self.effective_scope, &self.selection)?;
        if self.originating_actor_id.as_account_id().is_none()
            || self.registration_ref.stream_ref.realm_id() != self.effective_scope.realm_id()
            || !matches!(
                self.registration_ref.stream_ref,
                arkret_wire::CommitStreamRef::Realm { .. }
                    | arkret_wire::CommitStreamRef::Circle { .. }
            )
        {
            return Err(invalid("originator or registration scope binding differs"));
        }
        bounded(self)
    }

    pub fn digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }
}

fn transcript<T: Serialize>(value: &T, domain: &str) -> Result<Vec<u8>> {
    let mut host = serde_json::to_value(value)?;
    host.as_object_mut()
        .ok_or_else(|| invalid("signature host must be an object"))?
        .remove("proof");
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(arkret_canonical::canonical_json_bytes(&host)?);
    Ok(bytes)
}

fn sign<T: Serialize, S: PayloadSigner + ?Sized>(
    value: &T,
    domain: &str,
    expected: &DidCoreId,
    signer: &S,
) -> Result<AppletConfigurationSignature> {
    if &arkret_wire::project_did_to_core_id(signer.signer_did())? != expected
        || &crate::applet_models::verification_method_controller(signer.verification_method_id())?
            != expected
    {
        return Err(invalid("signer belongs to another Service"));
    }
    let signature = signer.sign_payload(&transcript(value, domain)?)?;
    Ok(AppletConfigurationSignature {
        verification_method: signature.verification_method,
        jws: signature.jws,
    })
}

impl AppletConfigurationExecutionRequestBody {
    pub const SIGNATURE_DOMAIN: &str = DomainSeparationId::APPLET_CONFIGURATION_COMMAND_V1;

    pub fn signature_payload(&self) -> Result<Vec<u8>> {
        transcript(self, Self::SIGNATURE_DOMAIN)
    }

    pub fn sign<S: PayloadSigner + ?Sized>(&mut self, signer: &S) -> Result<()> {
        self.proof = sign(
            self,
            Self::SIGNATURE_DOMAIN,
            &self.governance_station_id,
            signer,
        )?;
        Ok(())
    }

    /// The consumer additionally verifies the signature and current authority
    /// chain. Old intent coordinates stay immutable across a lawful handoff.
    pub fn validate_at(&self, at: DateTime<Utc>) -> Result<()> {
        self.intent.validate()?;
        if self.issued_at > at || self.expires_at <= at || self.issued_at >= self.expires_at {
            return Err(invalid("execution request is outside its signed window"));
        }
        if !arkret_wire::is_compact_detached_jws(&self.proof.jws)
            || crate::applet_models::verification_method_controller(
                &self.proof.verification_method,
            )? != self.governance_station_id
            || self.governance_generation < self.intent.governance_generation
        {
            return Err(invalid("execution proof or governance generation differs"));
        }
        bounded(self)
    }
}

impl AppletConfigurationExecutionResponseBody {
    pub const SIGNATURE_DOMAIN: &str = DomainSeparationId::APPLET_CONFIGURATION_OUTCOME_V1;

    pub fn signature_payload(&self) -> Result<Vec<u8>> {
        transcript(self, Self::SIGNATURE_DOMAIN)
    }

    pub fn sign<S: PayloadSigner + ?Sized>(&mut self, signer: &S) -> Result<()> {
        self.proof = sign(self, Self::SIGNATURE_DOMAIN, &self.service_id, signer)?;
        Ok(())
    }

    /// This validates correlation and shape, not signatures or acceptance.
    pub fn validate_for(&self, intent: &AppletConfigurationExecutionIntent) -> Result<()> {
        use AppletConfigurationExecutionStatus as Status;
        if self.request_id != intent.request_id
            || self.intent_digest != intent.digest()?
            || self.service_id != intent.service_id
            || !arkret_wire::is_compact_detached_jws(&self.proof.jws)
            || crate::applet_models::verification_method_controller(
                &self.proof.verification_method,
            )? != self.service_id
        {
            return Err(invalid("execution outcome binds another intent or Service"));
        }
        let accepted = matches!(self.status, Status::Created | Status::Reused);
        if accepted != self.actor_id.is_some() || accepted != self.creation_refs.is_some() {
            return Err(invalid(
                "creation references must occur exactly for created/reused",
            ));
        }
        if accepted {
            let actor = self
                .actor_id
                .as_ref()
                .and_then(ActorId::as_realm_actor_id)
                .ok_or_else(|| invalid("accepted actor is not a Realm identity"))?;
            let refs = self.creation_refs.as_ref().expect("checked presence");
            if &actor.realm_id != intent.effective_scope.realm_id()
                || refs.len() != 1
                || refs[0].stream_ref
                    != (arkret_wire::CommitStreamRef::RealmControl {
                        realm_id: actor.realm_id.clone(),
                    })
            {
                return Err(invalid(
                    "accepted creation belongs to another Realm control stream",
                ));
            }
            if let AppletConfigurationSelection::ExistingRealmActor { actor_id } = &intent.selection
                && self.actor_id.as_ref() != Some(actor_id)
            {
                return Err(invalid("reused actor differs from the original selection"));
            }
        }
        if (self.status == Status::Candidate) != self.create_event.is_some() {
            return Err(invalid(
                "candidate Event must occur exactly for candidate status",
            ));
        }
        if let Some(event) = &self.create_event {
            if event.kind != EventKind::RealmActorCreate
                || event.actor_id != ActorId::service(intent.service_id.clone())
                || event.realm_id != *intent.effective_scope.realm_id()
                || event.applet_id.as_ref() != Some(&intent.applet_id)
                || event.scope_ref
                    != (ScopeRef::RealmControl {
                        realm_id: event.realm_id.clone(),
                    })
            {
                return Err(invalid(
                    "candidate Event differs from the configured Applet and Realm",
                ));
            }
            let candidate: crate::RealmActorCreatePayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            candidate.validate()?;
            if !matches!(
                intent.selection,
                AppletConfigurationSelection::NewBot { .. }
            ) || candidate.actor_role != crate::RealmActorCreatePayloadActorRole::Bot
                || candidate.creation_scope != intent.effective_scope
                || candidate.applet_id != intent.applet_id
                || candidate.service_id != intent.service_id
            {
                return Err(invalid(
                    "candidate selection differs from the frozen intent",
                ));
            }
        }
        bounded(self)
    }
}
