//! Invite addressing and private delivery wire helpers.
//!
//! These types mirror the active v1 schemas:
//! `principal-locator.schema.json`, `invite-delivery-request.schema.json`,
//! and `invite-receive-policy.schema.json`.

use super::*;

pub const PRINCIPAL_LOCATOR_SCHEMA: &str = "ck.schema.principal_locator.v1";
pub const INVITE_DELIVERY_REQUEST_SCHEMA: &str = "ck.schema.invite_delivery_request.v1";
pub const INVITE_RECEIVE_POLICY_SCHEMA: &str = "ck.schema.invite_receive_policy.v1";
pub const INVITE_RECIPIENT_SERVICE_TYPE_PRINCIPAL_SERVER: &str = "principal_server";
pub const INVITE_LOCATOR_RESOLVE_PATH: &str = "_cokret/open/invite-locators/resolve";

fn serialize_canonical_timestamp<S>(
    value: &DateTime<Utc>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&canonical::format_timestamp_canonical(value.to_owned()))
}

fn deserialize_canonical_timestamp<'de, D>(
    deserializer: D,
) -> std::result::Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    canonical::validate_timestamp_canonical(&value).map_err(serde::de::Error::custom)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(serde::de::Error::custom)
}

fn serialize_optional_canonical_timestamp<S>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => {
            serializer.serialize_some(&canonical::format_timestamp_canonical(value.to_owned()))
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_canonical_timestamp<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<DateTime<Utc>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    canonical::validate_timestamp_canonical(&value).map_err(serde::de::Error::custom)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|parsed| Some(parsed.with_timezone(&Utc)))
        .map_err(serde::de::Error::custom)
}

fn validate_locator_token_shape(value: &str) -> bool {
    (22..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteLocatorResolveRequestBody {
    pub locator_token: String,
}

impl InviteLocatorResolveRequestBody {
    pub fn new(locator_token: impl Into<String>) -> Self {
        Self {
            locator_token: locator_token.into(),
        }
    }

    pub fn validate_minimal(&self) -> Result<()> {
        if !validate_locator_token_shape(self.locator_token.trim()) {
            return Err(Error::Protocol(
                "invite locator token must be base64url and carry at least 128-bit entropy"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteAddress {
    pub subject_id: Did,
    pub recipient_service_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
}

impl InviteAddress {
    pub fn principal_server(subject_id: Did, recipient_service_did: Did) -> Self {
        Self {
            subject_id,
            recipient_service_did,
            recipient_service_type: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(service_type) = &self.recipient_service_type
            && service_type != INVITE_RECIPIENT_SERVICE_TYPE_PRINCIPAL_SERVER
        {
            return Err(Error::Protocol(
                "invite_address.recipient_service_type MUST be principal_server".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryTarget {
    pub recipient_service_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
}

impl InviteDeliveryTarget {
    pub fn principal_server(recipient_service_did: Did) -> Self {
        Self {
            recipient_service_did,
            recipient_service_type: None,
        }
    }

    pub fn from_invite_address(address: &InviteAddress) -> Self {
        Self {
            recipient_service_did: address.recipient_service_did.clone(),
            recipient_service_type: address.recipient_service_type.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(service_type) = &self.recipient_service_type
            && service_type != INVITE_RECIPIENT_SERVICE_TYPE_PRINCIPAL_SERVER
        {
            return Err(Error::Protocol(
                "invite_delivery_target.recipient_service_type MUST be principal_server".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PrincipalLocator {
    pub schema: String,
    pub subject_id: Did,
    pub recipient_service_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    pub locator_ref_digest: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_modes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_hint: Option<PrincipalLocatorDisplayHint>,
    pub proofs: Vec<PrincipalLocatorProof>,
}

impl PrincipalLocator {
    pub fn invite_address(&self) -> InviteAddress {
        InviteAddress {
            subject_id: self.subject_id.clone(),
            recipient_service_did: self.recipient_service_did.clone(),
            recipient_service_type: self.recipient_service_type.clone(),
        }
    }

    pub fn invite_delivery_target(&self) -> InviteDeliveryTarget {
        InviteDeliveryTarget {
            recipient_service_did: self.recipient_service_did.clone(),
            recipient_service_type: self.recipient_service_type.clone(),
        }
    }

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != PRINCIPAL_LOCATOR_SCHEMA {
            return Err(Error::Protocol(
                "principal_locator.schema mismatch".to_owned(),
            ));
        }
        if let Some(service_type) = &self.recipient_service_type
            && service_type != INVITE_RECIPIENT_SERVICE_TYPE_PRINCIPAL_SERVER
        {
            return Err(Error::Protocol(
                "principal_locator.recipient_service_type MUST be principal_server".to_owned(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(Error::Protocol(
                "principal_locator.expires_at MUST be after issued_at".to_owned(),
            ));
        }
        if !self.proofs.iter().any(|proof| {
            proof.proof_purpose == PrincipalLocatorProofPurpose::RecipientServiceAcceptance
        }) {
            return Err(Error::Protocol(
                "principal_locator.proofs MUST include recipient_service_acceptance".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PrincipalLocatorDisplayHint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PrincipalLocatorProofPurpose {
    SubjectLocatorAuthorization,
    RecipientServiceAcceptance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PrincipalLocatorProof {
    pub proof_purpose: PrincipalLocatorProofPurpose,
    pub proof: DetachedPayloadProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DetachedPayloadProof {
    pub kind: String,
    pub verification_method: String,
    pub alg: String,
    pub payload_digest: Hash,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub jws: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntroductionEvidence {
    LocatorRef {
        principal_locator: PrincipalLocator,
    },
    ConsentGrant {
        consent_grant_ref: EventId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consent_id: Option<String>,
    },
    SharedRealm {
        realm_id: RealmId,
        inviter_member_ref: EventId,
        invitee_member_ref: EventId,
    },
    SamePrincipalServer,
    ExplicitAddress,
}

impl IntroductionEvidence {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LocatorRef { .. } => "locator_ref",
            Self::ConsentGrant { .. } => "consent_grant",
            Self::SharedRealm { .. } => "shared_realm",
            Self::SamePrincipalServer => "same_principal_server",
            Self::ExplicitAddress => "explicit_address",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryRequest {
    pub schema: String,
    pub invite_event: Value,
    pub invite_address: InviteAddress,
    pub introduction_evidence: IntroductionEvidence,
    pub idempotency_key: String,
}

impl InviteDeliveryRequest {
    pub fn new(
        invite_event: Value,
        invite_address: InviteAddress,
        introduction_evidence: IntroductionEvidence,
        idempotency_key: impl Into<String>,
    ) -> Self {
        Self {
            schema: INVITE_DELIVERY_REQUEST_SCHEMA.to_owned(),
            invite_event,
            invite_address,
            introduction_evidence,
            idempotency_key: idempotency_key.into(),
        }
    }

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != INVITE_DELIVERY_REQUEST_SCHEMA {
            return Err(Error::Protocol(
                "invite_delivery_request.schema mismatch".to_owned(),
            ));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(Error::Protocol(
                "invite_delivery_request.idempotency_key MUST NOT be empty".to_owned(),
            ));
        }
        self.invite_address.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum InviteDeliveryOutcomeStatus {
    Accepted,
    Duplicate,
    Deferred,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryOutcome {
    pub status: InviteDeliveryOutcomeStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosed_outcome: Option<DisclosedOutcome>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp",
        deserialize_with = "deserialize_optional_canonical_timestamp"
    )]
    pub received_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DisclosedOutcome {
    Delivered,
    Blocked,
    Quarantined,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum InviteReceiveAction {
    Drop,
    Quarantine,
    Notify,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum UnknownInviteAction {
    Drop,
    Quarantine,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteReceivePolicy {
    pub schema: String,
    pub subject_id: Did,
    pub allowed_introduction_kinds: Vec<String>,
    pub explicit_address_behavior: InviteReceiveAction,
    pub unknown_invites: UnknownInviteAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_principal_services: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_principal_services: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_subjects: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<DisclosurePolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DisclosureLevel {
    Opaque,
    Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_trust: Option<DisclosureLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_trust: Option<DisclosureLevel>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-07T10:00:00.123Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn invite_locator_resolve_body_validates_body_only_token_shape() {
        let token = "a".repeat(22);
        let body = InviteLocatorResolveRequestBody::new(token);
        body.validate_minimal()
            .expect("valid base64url token shape");
        assert!(
            InviteLocatorResolveRequestBody::new("short")
                .validate_minimal()
                .is_err()
        );
        assert!(
            InviteLocatorResolveRequestBody::new("aaaaaaaaaaaaaaaaaaaaa+")
                .validate_minimal()
                .is_err()
        );
    }

    #[test]
    fn principal_locator_serializes_canonical_timestamps() {
        let issued_at = test_time();
        let expires_at = issued_at + chrono::Duration::minutes(15);
        let locator = PrincipalLocator {
            schema: PRINCIPAL_LOCATOR_SCHEMA.to_owned(),
            subject_id: Did::new("did:web:bob.example").unwrap(),
            recipient_service_did: Did::new("did:web:ps.bob.example").unwrap(),
            recipient_service_type: None,
            issued_at,
            expires_at,
            locator_ref_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            delivery_modes: Vec::new(),
            display_hint: None,
            proofs: vec![PrincipalLocatorProof {
                proof_purpose: PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
                proof: DetachedPayloadProof {
                    kind: "detached_jws".to_owned(),
                    verification_method: "did:web:ps.bob.example#server-key-1".to_owned(),
                    alg: "EdDSA".to_owned(),
                    payload_digest: Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
                    created_at: issued_at,
                    domain: None,
                    audience: None,
                    jws: "header..sig".to_owned(),
                },
            }],
        };

        let value = serde_json::to_value(&locator).expect("serialize locator");
        assert_eq!(value["issued_at"], "2026-06-07T10:00:00Z");
        assert_eq!(value["expires_at"], "2026-06-07T10:15:00Z");
        assert_eq!(
            value["proofs"][0]["proof"]["created_at"],
            "2026-06-07T10:00:00Z"
        );
        assert!(serde_json::from_value::<PrincipalLocator>(value).is_ok());
    }

    #[test]
    fn invite_delivery_outcome_serializes_canonical_received_at() {
        let outcome = InviteDeliveryOutcome {
            status: InviteDeliveryOutcomeStatus::Accepted,
            disclosed_outcome: None,
            received_at: Some(test_time()),
            retry_after_ms: None,
        };
        let value = serde_json::to_value(outcome).expect("serialize outcome");
        assert_eq!(value["received_at"], "2026-06-07T10:00:00Z");
        assert!(value.get("disclosed_outcome").is_none());
    }

    #[test]
    fn introduction_evidence_consent_grant_roundtrips_wire_kind() {
        let evidence = IntroductionEvidence::ConsentGrant {
            consent_grant_ref: EventId::new("ck:event:01904100-0000-7000-8000-79a90338768b")
                .unwrap(),
            consent_id: None,
        };
        assert_eq!(evidence.kind(), "consent_grant");
        let value = serde_json::to_value(&evidence).expect("serialize consent_grant evidence");
        assert_eq!(value["kind"], "consent_grant");
        assert!(value.get("consent_id").is_none());
        let parsed: IntroductionEvidence =
            serde_json::from_value(value).expect("deserialize consent_grant evidence");
        assert_eq!(parsed, evidence);
    }

    #[test]
    fn invite_delivery_outcome_serializes_disclosed_outcome() {
        let outcome = InviteDeliveryOutcome {
            status: InviteDeliveryOutcomeStatus::Accepted,
            disclosed_outcome: Some(DisclosedOutcome::Quarantined),
            received_at: None,
            retry_after_ms: None,
        };
        let value = serde_json::to_value(outcome).expect("serialize outcome");
        assert_eq!(value["disclosed_outcome"], "quarantined");
    }

    #[test]
    fn invite_receive_policy_skips_empty_disclosure_fields() {
        let policy = InviteReceivePolicy {
            schema: INVITE_RECEIVE_POLICY_SCHEMA.to_owned(),
            subject_id: Did::new("did:web:bob.example").unwrap(),
            allowed_introduction_kinds: vec!["consent_grant".to_owned()],
            explicit_address_behavior: InviteReceiveAction::Quarantine,
            unknown_invites: UnknownInviteAction::Drop,
            trusted_realm_ids: Vec::new(),
            trusted_principal_services: Vec::new(),
            blocked_principal_services: Vec::new(),
            blocked_subjects: Vec::new(),
            disclosure: None,
        };
        let value = serde_json::to_value(&policy).expect("serialize policy");
        assert!(value.get("blocked_subjects").is_none());
        assert!(value.get("disclosure").is_none());

        let policy = InviteReceivePolicy {
            blocked_subjects: vec![Did::new("did:web:mallory.example").unwrap()],
            disclosure: Some(DisclosurePolicy {
                high_trust: Some(DisclosureLevel::Outcome),
                low_trust: Some(DisclosureLevel::Opaque),
            }),
            ..policy
        };
        let value = serde_json::to_value(&policy).expect("serialize policy");
        assert_eq!(value["disclosure"]["high_trust"], "outcome");
        assert_eq!(value["disclosure"]["low_trust"], "opaque");
        assert!(serde_json::from_value::<InviteReceivePolicy>(value).is_ok());
    }
}
