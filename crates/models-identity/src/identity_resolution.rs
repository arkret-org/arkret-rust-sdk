//! Typed identity-resolution carriers shared by service discovery and
//! high-risk service-to-service authentication.

use arkret_wire::{
    AccountId, Did, DidCoreId, Event, EventBatchReceipt, EventId, Hash, ProtocolSignature, RealmId,
    Seal,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{DidDocument, normalized_did_document_digest};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ResolutionCommitment {
    pub did: Did,
    pub method_history_head: String,
    pub version_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalResolutionProjection {
    pub did: Did,
    pub method_history_head: String,
    pub version_id: String,
    pub resolution_event_ref: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalResolutionUpdatePayload {
    pub next: ResolutionCommitment,
}

/// Maximum canonical bytes for either current-principal direction.
pub const CURRENT_PRINCIPAL_MAX_BYTES: usize = 65_536;

/// Authenticated self lookup; no portable history is returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentPrincipalRequestBody {
    pub request_id: arkret_wire::RequestId,
    pub account_id: AccountId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentPrincipalOutcome {
    pub request_id: arkret_wire::RequestId,
    pub account_id: AccountId,
    pub principal_control_realm_id: RealmId,
    pub resolution_projection: PrincipalResolutionProjection,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
}

fn current_principal_error(code: arkret_wire::ErrorCode, message: &str) -> arkret_wire::WireError {
    arkret_wire::WireError::ProtocolCode {
        code,
        message: message.to_owned(),
    }
}
fn current_principal_bytes(value: &impl Serialize, request: bool) -> arkret_wire::Result<()> {
    if arkret_canonical::canonical_json_bytes(value)?.len() > CURRENT_PRINCIPAL_MAX_BYTES {
        return Err(current_principal_error(
            if request {
                arkret_wire::ErrorCode::PayloadTooLarge
            } else {
                arkret_wire::ErrorCode::LimitExceeded
            },
            "current principal exceeds its canonical byte budget",
        ));
    }
    Ok(())
}
impl CurrentPrincipalRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        current_principal_bytes(self, true)?;
        self.account_id.validate()
    }
}
impl CurrentPrincipalOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        current_principal_bytes(self, false)?;
        self.account_id.validate()?;
        let projection = &self.resolution_projection;
        if arkret_wire::project_did_to_core_id(&projection.did)? != self.account_id.principal_id
            || projection.method_history_head.is_empty()
            || projection.method_history_head.chars().count() > 512
            || projection.version_id.is_empty()
            || projection.version_id.chars().count() > 512
            || projection.version_id.starts_with("ak:")
            || EventId::new(projection.resolution_event_ref.clone()).is_err()
        {
            return Err(current_principal_error(
                arkret_wire::ErrorCode::SchemaViolation,
                "current principal projection is malformed or belongs to another principal",
            ));
        }
        Ok(())
    }
    pub fn validate_for_request(
        &self,
        request: &CurrentPrincipalRequestBody,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id || self.account_id != request.account_id {
            return Err(current_principal_error(
                arkret_wire::ErrorCode::StateMismatch,
                "current principal result differs from the exact request/account",
            ));
        }
        Ok(())
    }
}

/// Domain-separation context for the Station projection attestation.
pub const PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_CONTEXT: &str =
    arkret_wire::ProofContextId::PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_PROOF_V1;

/// Station assertion that `resolution_projection` is the current
/// accepted value of the account's singleton resolution cell.
///
/// It carries no PCR realm id, Event, receipt or Seal. Without it the public
/// projection would be an unproven server assertion, which is what the public
/// surface used to fall back on once the PCR material was removed from it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalResolutionProjectionAttestationCore {
    pub account_id: AccountId,
    pub resolution_projection: PrincipalResolutionProjection,
    pub method_history_evidence_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalResolutionProjectionAttestation {
    pub attestation: PrincipalResolutionProjectionAttestationCore,
    pub proof: ProtocolSignature,
}

impl PrincipalResolutionProjectionAttestation {
    pub fn proof_signing_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        let payload_digest = Hash::new(arkret_canonical::canonical_sha256(&self.attestation)?)?;
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "context": PRINCIPAL_RESOLUTION_PROJECTION_ATTESTATION_CONTEXT,
            "payload_digest": payload_digest,
            "account_id": self.attestation.account_id,
            "resolution_projection": self.attestation.resolution_projection,
            "method_history_evidence_digest": self.attestation.method_history_evidence_digest,
            "issued_at": arkret_canonical::format_timestamp_canonical(self.attestation.issued_at),
            "expires_at": arkret_canonical::format_timestamp_canonical(self.attestation.expires_at),
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
        }))
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
    }
}

/// Complete public resolution response.
///
/// This is the only unauthenticated resolution surface. It deliberately has no
/// field for `principal_control_realm_id`, the PCR genesis Event or receipt,
/// resolution Events, the accepted Seal or the cell proof: that material is
/// account-internal and reachable only through
/// `ak.self.identity.read.resolution_audit.v1`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PublicPrincipalResolution {
    pub account_id: AccountId,
    pub resolution_projection: PrincipalResolutionProjection,
    pub method_history_evidence: ResolutionMethodHistoryEvidence,
    pub projection_attestation: PrincipalResolutionProjectionAttestation,
}

impl PublicPrincipalResolution {
    /// The complete public selector and the complete external identity.
    pub fn authority(&self) -> AccountId {
        self.account_id.clone()
    }

    /// Cross-bind the attestation to the response it travels with.
    ///
    /// This does not verify the detached proof; it rejects the halves being
    /// swapped before a caller spends a signature check on them.
    pub fn validate_attestation_binding(&self) -> arkret_wire::Result<()> {
        let core = &self.projection_attestation.attestation;
        if core.account_id != self.account_id {
            return Err(arkret_wire::WireError::Protocol(
                "public principal resolution attestation pair mismatch".to_owned(),
            ));
        }
        if core.resolution_projection != self.resolution_projection {
            return Err(arkret_wire::WireError::Protocol(
                "public principal resolution attestation projection mismatch".to_owned(),
            ));
        }
        if core.issued_at >= core.expires_at {
            return Err(arkret_wire::WireError::Protocol(
                "public principal resolution attestation is not a positive validity window"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authorized request for account-internal resolution audit evidence.
///
/// Authorization is the current holder session bound to the exact
/// `account_id`. Recovery first completes through the existing
/// transaction and becomes current holder; no second audit authorization path
/// or caller-declared intent exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalResolutionAuditRequest {
    pub account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_depth: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_resolution_event_ref: Option<EventId>,
}

/// Closed upper bound on disclosed predecessor resolution Events.
pub const PRINCIPAL_RESOLUTION_AUDIT_MAX_HISTORY_DEPTH: u16 = 256;

impl PrincipalResolutionAuditRequest {
    pub fn new(account_id: AccountId) -> Self {
        Self {
            account_id,
            history_depth: None,
            after_resolution_event_ref: None,
        }
    }

    /// Reject the two locally decidable request shapes before a round trip.
    ///
    /// A depth outside the closed range is `param_invalid`, and a cursor with
    /// depth 0 could never apply because depth 0 discloses no predecessor.
    pub fn validate(&self) -> arkret_wire::Result<()> {
        let depth = self.history_depth.unwrap_or(0);
        if depth > PRINCIPAL_RESOLUTION_AUDIT_MAX_HISTORY_DEPTH {
            return Err(arkret_wire::WireError::Protocol(format!(
                "principal resolution history_depth exceeds {PRINCIPAL_RESOLUTION_AUDIT_MAX_HISTORY_DEPTH}"
            )));
        }
        if self.after_resolution_event_ref.is_some() && depth == 0 {
            return Err(arkret_wire::WireError::Protocol(
                "after_resolution_event_ref requires history_depth of at least 1".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Account-internal resolution audit and recovery evidence.
///
/// Served only by the authorized audit operation. It MUST NOT be republished on
/// any unauthenticated surface and MUST NOT be required to validate an ordinary
/// federated Event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalResolutionAuditEvidence {
    pub account_id: AccountId,
    pub principal_control_realm_id: RealmId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub principal_genesis_receipt: EventBatchReceipt,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub principal_genesis_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub current_resolution_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub predecessor_resolution_events: Vec<Event>,
    pub history_complete: bool,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub accepted_seal: Seal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_audit_cursor: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_history_evidence: Option<ResolutionMethodHistoryEvidence>,
}

impl PrincipalResolutionAuditEvidence {
    /// Enforce the continuation contract between `history_complete` and
    /// `next_audit_cursor`.
    ///
    /// Omitted history is unknown, not absent: a truncated segment without a
    /// cursor would silently read as a complete one.
    pub fn validate_history_continuation(&self) -> arkret_wire::Result<()> {
        match (self.history_complete, self.next_audit_cursor.is_some()) {
            (false, false) => Err(arkret_wire::WireError::Protocol(
                "truncated resolution audit history must carry next_audit_cursor".to_owned(),
            )),
            (true, true) => Err(arkret_wire::WireError::Protocol(
                "complete resolution audit history must not carry next_audit_cursor".to_owned(),
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ResolutionMethodEvidenceBoundary {
    pub from_method_history_head: String,
    pub from_version_id: String,
    pub to_method_history_head: String,
    pub to_version_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ResolutionDidBindingEvidenceKind {
    #[serde(rename = "ak.did.binding_evidence.v1")]
    AkDidBindingEvidenceV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ResolutionDidBindingMethodProofKind {
    WebvhLog,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ResolutionDidBindingWitness {
    pub witness_did: Did,
    pub controlling_organization_did: Did,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ResolutionDidBindingMethodProof {
    pub kind: ResolutionDidBindingMethodProofKind,
    pub history_head: String,
    pub witnesses: Vec<ResolutionDidBindingWitness>,
    pub witness_proofs_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ResolutionDidBindingEvidenceReceipt {
    pub kind: ResolutionDidBindingEvidenceKind,
    pub method: String,
    pub document_digest: Hash,
    pub method_proofs: Vec<ResolutionDidBindingMethodProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "evidence_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
/// `evidence_kind` is the only adapter selector on the wire.
///
/// Review 2026-09-02-1951 A8 deleted `adapter_version` from all three carriers:
/// `did-method-adapter-registry.json` fixes exactly one adapter version per
/// evidence kind, so echoing it let a producer state a pair the registry does
/// not contain. Read it through [`Self::adapter_version`] instead.
pub enum ResolutionMethodHistoryEvidence {
    WebvhLog {
        boundary: ResolutionMethodEvidenceBoundary,
        evidence: ResolutionDidBindingEvidenceReceipt,
        log_entries: Vec<serde_json::Value>,
        witness_records: Vec<serde_json::Value>,
    },
    DidWebDocument {
        boundary: ResolutionMethodEvidenceBoundary,
        evidence: ResolutionDidBindingEvidenceReceipt,
    },
    DidKeyExpansion {
        boundary: ResolutionMethodEvidenceBoundary,
        evidence: ResolutionDidBindingEvidenceReceipt,
    },
}

impl ResolutionMethodHistoryEvidence {
    #[must_use]
    pub const fn evidence_kind(&self) -> arkret_wire::DidMethodEvidenceKind {
        match self {
            Self::WebvhLog { .. } => arkret_wire::DidMethodEvidenceKind::WebvhLog,
            Self::DidWebDocument { .. } => arkret_wire::DidMethodEvidenceKind::DidWebDocument,
            Self::DidKeyExpansion { .. } => arkret_wire::DidMethodEvidenceKind::DidKeyExpansion,
        }
    }

    /// The registered adapter version for this evidence kind.
    ///
    /// Signing transcripts that bind `adapter_version` recompute it here; it is
    /// never read back from the carrier.
    #[must_use]
    pub const fn adapter_version(&self) -> &'static str {
        self.evidence_kind().adapter_version()
    }

    #[must_use]
    pub fn boundary(&self) -> &ResolutionMethodEvidenceBoundary {
        match self {
            Self::WebvhLog { boundary, .. }
            | Self::DidWebDocument { boundary, .. }
            | Self::DidKeyExpansion { boundary, .. } => boundary,
        }
    }

    #[must_use]
    pub fn evidence(&self) -> &ResolutionDidBindingEvidenceReceipt {
        match self {
            Self::WebvhLog { evidence, .. }
            | Self::DidWebDocument { evidence, .. }
            | Self::DidKeyExpansion { evidence, .. } => evidence,
        }
    }

    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        let (expected_method, proof_count, log_entries_empty) = match self {
            Self::WebvhLog {
                evidence,
                log_entries,
                witness_records,
                ..
            } => (
                "webvh",
                evidence.method_proofs.len(),
                log_entries.is_empty()
                    || log_entries.len() > 4_096
                    || witness_records.len() > 4_096,
            ),
            Self::DidWebDocument { evidence, .. } => ("web", evidence.method_proofs.len(), false),
            Self::DidKeyExpansion { evidence, .. } => ("key", evidence.method_proofs.len(), false),
        };
        if self.evidence().method != expected_method
            || (expected_method == "webvh" && proof_count != 1)
            || (expected_method != "webvh" && proof_count != 0)
            || self.evidence().method_proofs.iter().any(|proof| {
                proof.kind != ResolutionDidBindingMethodProofKind::WebvhLog
                    || proof.history_head.is_empty()
                    || proof
                        .witnesses
                        .windows(2)
                        .any(|pair| pair[0].witness_did.as_str() >= pair[1].witness_did.as_str())
            })
            || log_entries_empty
            || self.boundary().from_method_history_head.is_empty()
            || self.boundary().from_version_id.is_empty()
            || self.boundary().to_method_history_head.is_empty()
            || self.boundary().to_version_id.is_empty()
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid method-history evidence shape".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ServiceResolutionCarrier {
    Inline {
        inline: AuthenticatedServiceResolution,
    },
    ResolutionUrl {
        resolution_url: String,
    },
}
pub const MAX_SERVICE_RESOLUTION_URL_BYTES: usize = 2_048;
/// Canonical path of the unauthenticated transport locator for one service's
/// current method evidence.
#[must_use]
pub fn canonical_service_resolution_path(service_id: &DidCoreId) -> String {
    let mut encoded = String::with_capacity(service_id.as_str().len());
    for byte in service_id.as_str().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    format!("/_arkret/open/services/{encoded}/resolution")
}

/// Validate a `resolution_url` as a bounded canonical transport locator.
///
/// This establishes no service authority: fetched evidence still needs its
/// method history, current state and route binding independently verified.
pub fn validate_service_resolution_url(
    value: &str,
    expected_service_id: &DidCoreId,
) -> arkret_wire::Result<()> {
    if value.is_empty() || value.len() > MAX_SERVICE_RESOLUTION_URL_BYTES {
        return Err(arkret_wire::WireError::Protocol(
            "service resolution URL length is out of bounds".to_owned(),
        ));
    }
    let parsed = Url::parse(value).map_err(|error| {
        arkret_wire::WireError::Protocol(format!("service resolution URL is invalid: {error}"))
    })?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != canonical_service_resolution_path(expected_service_id)
        || parsed.as_str() != value
    {
        return Err(arkret_wire::WireError::Protocol(
            "service resolution URL is not the canonical HTTPS locator for the expected service"
                .to_owned(),
        ));
    }
    Ok(())
}

impl ServiceResolutionCarrier {
    pub fn validate_shape(&self, expected_service_id: &DidCoreId) -> arkret_wire::Result<()> {
        match self {
            Self::Inline { inline } => inline.validate_shape(expected_service_id, Utc::now()),
            Self::ResolutionUrl { resolution_url } => {
                validate_service_resolution_url(resolution_url, expected_service_id)
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AuthenticatedServiceResolution {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub method_history_evidence: ResolutionMethodHistoryEvidence,
    #[serde(with = "service_document_wire")]
    pub normalized_did_document: DidDocument,
}
/// Derived route projection of one verified service DID state.
///
/// This is the single Rust expression of
/// `identity-resolution.schema.json#/$defs/service_route_projection`
/// (`sync/service-surface.md` §2.6). It is produced either locally by
/// [`AuthenticatedServiceResolution::projection`] after method-native
/// verification, or handed over already verified inside an own-Station result
/// such as the media service binding. There is deliberately only one type: a
/// second "wire-only" copy would let a consumer accept a route the local
/// verifier would have rejected.
///
/// Every coordinate comes from the verified method-native state and its unique
/// `ArkretService` entry. The projection creates no signed address history and
/// carries no method evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionProjection {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub did: Did,
    pub method_history_head: String,
    pub version_id: String,
    pub resolution_event_ref: String,
    pub base_url: String,
}

impl ServiceResolutionProjection {
    /// Closed shape check for a projection that arrives over the wire.
    ///
    /// It proves the projection is internally consistent - the DID projects
    /// onto `service_id`, the adapter coordinate is a registered method-state
    /// position, and `base_url` is the canonical HTTPS entry - without
    /// resolving anything. Whether the *content* is current is the issuing
    /// Station's responsibility.
    pub fn validate(&self) -> arkret_wire::Result<()> {
        let projection_error = |message: &str| arkret_wire::WireError::ProtocolCode {
            code: arkret_wire::ErrorCode::SchemaViolation,
            message: message.to_owned(),
        };
        if !arkret_wire::ServiceKind::ALL
            .iter()
            .any(|kind| kind.as_str() == self.service_kind)
        {
            return Err(projection_error(
                "service route projection carries an unregistered service_kind",
            ));
        }
        if arkret_wire::project_did_to_core_id(&self.did)? != self.service_id {
            return Err(projection_error(
                "service route projection DID does not project onto its service_id",
            ));
        }
        if self.method_history_head.is_empty()
            || self.method_history_head.chars().count() > 512
            || self.version_id.is_empty()
            || self.version_id.chars().count() > 512
            || self.version_id.starts_with("ak:")
        {
            return Err(projection_error(
                "service route projection method state coordinates are out of bounds",
            ));
        }
        let Some((adapter, digest)) = self.resolution_event_ref.split_once(':') else {
            return Err(projection_error(
                "service route projection resolution_event_ref is not an adapter coordinate",
            ));
        };
        if !matches!(
            adapter,
            "did-webvh-entry-sha256" | "did-web-document-sha256" | "did-key-did-sha256"
        ) || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(projection_error(
                "service route projection resolution_event_ref is not a registered adapter coordinate",
            ));
        }
        let canonical = crate::service_identity::CanonicalServiceUrl::new(&self.base_url)?;
        canonical.require_https()?;
        if !self.base_url.ends_with('/') {
            return Err(projection_error(
                "service route projection base_url must carry exactly one trailing slash",
            ));
        }
        Ok(())
    }
}
impl AuthenticatedServiceResolution {
    pub fn validate_shape(
        &self,
        expected_service_id: &DidCoreId,
        _now: DateTime<Utc>,
    ) -> arkret_wire::Result<()> {
        self.method_history_evidence.validate_shape()?;
        self.normalized_did_document.validate()?;
        if !arkret_wire::ServiceKind::ALL
            .iter()
            .any(|kind| kind.as_str() == self.service_kind)
            || arkret_canonical::canonical_json_bytes(self)?.len() > 1024 * 1024
            || &self.service_id != expected_service_id
            || arkret_wire::project_did_to_core_id(&self.normalized_did_document.id)?
                != self.service_id
            || self.method_history_evidence.evidence().document_digest
                != normalized_did_document_digest(&self.normalized_did_document)?
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid authenticated service resolution binding".to_owned(),
            ));
        }
        Ok(())
    }
    /// Derive the route only after method-native verification by the caller.
    pub fn projection(&self) -> arkret_wire::Result<ServiceResolutionProjection> {
        self.validate_shape(&self.service_id, Utc::now())?;
        let did = &self.normalized_did_document.id;
        let normalized = crate::normalized_did_document(&self.normalized_did_document)?;
        let entries = normalized["services"].as_array().ok_or_else(|| {
            arkret_wire::WireError::Protocol(
                "service DID document omits service endpoints".to_owned(),
            )
        })?;
        let matches: Vec<_> = entries
            .iter()
            .filter(|entry| {
                entry["protocol_names"]
                    .as_array()
                    .is_some_and(|types| types.len() == 1 && types[0] == "ArkretService")
                    && entry["extensions"].as_array().is_some_and(|extensions| {
                        extensions.iter().any(|row| {
                            row["name"] == "serviceKind" && row["value"] == self.service_kind
                        })
                    })
            })
            .collect();
        if matches.len() != 1 {
            return Err(arkret_wire::WireError::Protocol(
                "service DID endpoint is missing or ambiguous".to_owned(),
            ));
        }
        let endpoint = matches[0];
        let id = endpoint
            .get("uri")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if !id.starts_with(&format!("{did}#")) || id.ends_with('#') {
            return Err(arkret_wire::WireError::Protocol(
                "service endpoint id is not bound to its DID".to_owned(),
            ));
        }
        let base_url = endpoint
            .get("endpoint")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                arkret_wire::WireError::Protocol("service endpoint must be a URL".to_owned())
            })?;
        let canonical = crate::service_identity::CanonicalServiceUrl::new(base_url)?;
        canonical.require_https()?;
        if canonical.as_str() != base_url {
            return Err(arkret_wire::WireError::Protocol(
                "service endpoint is not canonical".to_owned(),
            ));
        }
        let boundary = self.method_history_evidence.boundary();
        Ok(ServiceResolutionProjection {
            service_id: self.service_id.clone(),
            service_kind: self.service_kind.clone(),
            did: did.clone(),
            method_history_head: boundary.to_method_history_head.clone(),
            version_id: boundary.to_version_id.clone(),
            resolution_event_ref: format!(
                "{}:{}",
                match did.method() {
                    "webvh" => "did-webvh-entry-sha256",
                    "web" => "did-web-document-sha256",
                    _ => "did-key-did-sha256",
                },
                boundary
                    .to_method_history_head
                    .strip_prefix("sha256:")
                    .unwrap_or(&boundary.to_method_history_head)
            ),
            base_url: base_url.to_owned(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceMethodState {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub did: Did,
    pub method_history_head: String,
    pub version_id: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub verified_at: DateTime<Utc>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceRouteCacheEntry {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub did: Did,
    pub method_history_head: String,
    pub version_id: String,
    pub base_url: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub verified_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub cache_expires_at: DateTime<Utc>,
}
impl ServiceRouteCacheEntry {
    pub fn is_routable_at(&self, now: DateTime<Utc>) -> bool {
        self.verified_at <= now
            && self.cache_expires_at <= self.verified_at + chrono::Duration::seconds(300)
            && now < self.cache_expires_at
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RouteMirrorHint {
    pub mirror_id: DidCoreId,
    pub service_resolution: ServiceResolutionCarrier,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RouteAssistance {
    pub mirror_hints: Vec<RouteMirrorHint>,
}
impl RouteAssistance {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if self.mirror_hints.is_empty() || self.mirror_hints.len() > 4 {
            return Err(arkret_wire::WireError::Protocol(
                "route assistance requires one to four mirror hints".to_owned(),
            ));
        }
        Ok(())
    }
}

mod service_document_wire {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        document: &DidDocument,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        crate::normalized_did_document(document)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DidDocument, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.get("did").is_none() {
            return Err(serde::de::Error::custom(
                "service evidence requires the canonical normalized DID projection",
            ));
        }
        let document: DidDocument =
            serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
        let normalized =
            crate::normalized_did_document(&document).map_err(serde::de::Error::custom)?;
        if normalized != value {
            return Err(serde::de::Error::custom(
                "service evidence DID projection is not normalized",
            ));
        }
        Ok(document)
    }
}

#[cfg(test)]
mod current_principal_tests {
    use super::*;
    fn fixture() -> (CurrentPrincipalRequestBody, CurrentPrincipalOutcome) {
        let account_id = AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let request = CurrentPrincipalRequestBody {
            request_id: arkret_wire::RequestId::new(
                "ak:request:01904100-0000-7000-8000-000000000001",
            )
            .unwrap(),
            account_id,
        };
        let at = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let result = CurrentPrincipalOutcome {
            request_id: request.request_id.clone(),
            account_id: request.account_id.clone(),
            principal_control_realm_id: RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
            resolution_projection: PrincipalResolutionProjection {
                did: Did::new("did:web:alice.example").unwrap(),
                method_history_head: "head".to_owned(),
                version_id: "version".to_owned(),
                resolution_event_ref: EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [1; 32],
                )
                .to_string(),
                updated_at: at,
            },
            observed_at: at,
        };
        (request, result)
    }
    #[test]
    fn current_principal_binds_request_account_and_source_projection() {
        let (request, result) = fixture();
        result.validate_for_request(&request).unwrap();
        let mut changed = result.clone();
        changed.account_id.station_id = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(changed.validate_for_request(&request).is_err());
        let mut changed = result.clone();
        changed.resolution_projection.did = Did::new("did:web:bob.example").unwrap();
        assert!(changed.validate_for_request(&request).is_err());
        let mut changed = result.clone();
        changed.resolution_projection.resolution_event_ref = "not-an-event".to_owned();
        assert!(changed.validate_for_request(&request).is_err());
        let mut wire = serde_json::to_value(result).unwrap();
        wire["history"] = serde_json::json!([]);
        assert!(serde_json::from_value::<CurrentPrincipalOutcome>(wire).is_err());
    }
    #[test]
    fn current_principal_byte_budget_precedes_projection_shape_error() {
        let (_, mut result) = fixture();
        result.resolution_projection.method_history_head = "x".repeat(CURRENT_PRINCIPAL_MAX_BYTES);
        assert_eq!(
            result.validate().unwrap_err().error_code(),
            Some(arkret_wire::ErrorCode::LimitExceeded)
        );
        result.resolution_projection.method_history_head = "x".repeat(513);
        assert_eq!(
            result.validate().unwrap_err().error_code(),
            Some(arkret_wire::ErrorCode::SchemaViolation)
        );
    }
}
