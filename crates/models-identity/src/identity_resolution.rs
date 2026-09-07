//! Typed identity-resolution carriers shared by service discovery and
//! high-risk service-to-service authentication.

use arkret_wire::{
    AccountId, Did, DidCoreId, Event, EventBatchReceipt, EventId, Hash, ProtocolSignature, RealmId,
    RequestId, Seal,
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
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionRecordCore {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub did: Did,
    pub method_history_head: String,
    pub version_id: String,
    pub resolution_event_ref: String,
    pub record_sequence: u64,
    pub previous_record_digest: Option<Hash>,
    pub current_record_url: String,
    pub base_url: String,
    pub describe_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub refresh_after: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionRecord {
    pub record: ServiceResolutionRecordCore,
    pub proof: ProtocolSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[allow(clippy::large_enum_variant)]
pub enum ServiceResolutionCarrier {
    Inline {
        inline: ServiceResolutionRecord,
    },
    CurrentRecordUrl {
        current_record_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pinned_record_digest: Option<Hash>,
    },
}

pub const MAX_SERVICE_CURRENT_RECORD_URL_BYTES: usize = 2_048;

/// Canonical route-binding projection committed as `describe_digest` in a
/// signed service resolution record (`zh/sync/service-surface.md` §2.6).
///
/// The shape is normative: exactly
/// `{service_id, service_kind, service_resolution, http_json_base_url}`, in
/// this field order. Producers and verifiers MUST derive the digest through
/// [`route_binding_describe_digest`] so a projection change cannot silently
/// diverge between the signer and any verifier.
#[derive(Serialize)]
struct RouteBindingProjection<'a> {
    service_id: &'a DidCoreId,
    service_kind: &'a str,
    service_resolution: &'a ResolutionCommitment,
    http_json_base_url: &'a str,
}

/// Canonical `describe_digest` over the route binding of one service.
///
/// `http_json_base_url` MUST already be the canonical HTTPS base URL the
/// record advertises; this helper commits the value it is handed and performs
/// no URL canonicalization of its own.
pub fn route_binding_describe_digest(
    service_id: &DidCoreId,
    service_kind: &str,
    service_resolution: &ResolutionCommitment,
    http_json_base_url: &str,
) -> arkret_wire::Result<Hash> {
    let projection = RouteBindingProjection {
        service_id,
        service_kind,
        service_resolution,
        http_json_base_url,
    };
    Ok(Hash::new(arkret_canonical::canonical_sha256(&projection)?)?)
}

/// Canonical path of the unauthenticated transport locator for one service's
/// current signed resolution record.
#[must_use]
pub fn canonical_service_current_record_path(service_id: &DidCoreId) -> String {
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

/// Validate a `current_record_url` as a bounded canonical transport locator.
///
/// This establishes no service authority: a fetched record still needs its
/// method history, proof, freshness and route binding independently verified.
pub fn validate_service_current_record_url(
    value: &str,
    expected_service_id: &DidCoreId,
) -> arkret_wire::Result<()> {
    if value.is_empty() || value.len() > MAX_SERVICE_CURRENT_RECORD_URL_BYTES {
        return Err(arkret_wire::WireError::Protocol(
            "service current-record URL length is out of bounds".to_owned(),
        ));
    }
    let parsed = Url::parse(value).map_err(|error| {
        arkret_wire::WireError::Protocol(format!("service current-record URL is invalid: {error}"))
    })?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != canonical_service_current_record_path(expected_service_id)
        || parsed.as_str() != value
    {
        return Err(arkret_wire::WireError::Protocol(
            "service current-record URL is not the canonical HTTPS locator for the expected service"
                .to_owned(),
        ));
    }
    Ok(())
}

impl ServiceResolutionCarrier {
    /// Validate only the carrier shape and expected core-id binding.
    ///
    /// An inline or fetched record is not authorized by this check.
    pub fn validate_shape(&self, expected_service_id: &DidCoreId) -> arkret_wire::Result<()> {
        match self {
            Self::Inline { inline } => {
                if &inline.record.service_id != expected_service_id {
                    return Err(arkret_wire::WireError::Protocol(
                        "inline service resolution targets a different service".to_owned(),
                    ));
                }
                validate_service_current_record_url(
                    &inline.record.current_record_url,
                    expected_service_id,
                )
            }
            Self::CurrentRecordUrl {
                current_record_url, ..
            } => validate_service_current_record_url(current_record_url, expected_service_id),
        }
    }
}

impl ServiceResolutionRecord {
    pub fn proof_signing_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Transcript<'a> {
            context: &'static str,
            payload_digest: Hash,
            service_id: &'a DidCoreId,
            service_kind: &'a str,
            did: &'a Did,
            method_history_head: &'a str,
            version_id: &'a str,
            resolution_event_ref: &'a str,
            record_sequence: u64,
            previous_record_digest: &'a Option<Hash>,
            current_record_url: &'a str,
            base_url: &'a str,
            describe_digest: &'a Hash,
            #[serde(
                serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp"
            )]
            issued_at: DateTime<Utc>,
            #[serde(
                serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp"
            )]
            refresh_after: DateTime<Utc>,
            #[serde(
                serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp"
            )]
            expires_at: DateTime<Utc>,
            verification_method: &'a arkret_wire::DidUrl,
            #[serde(
                serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp"
            )]
            created_at: DateTime<Utc>,
        }
        let payload_digest = Hash::new(arkret_canonical::canonical_sha256(&self.record)?)?;
        arkret_canonical::canonical_json_bytes(&Transcript {
            context: arkret_wire::ProofContextId::SERVICE_RESOLUTION_RECORD_PROOF_V1,
            payload_digest,
            service_id: &self.record.service_id,
            service_kind: &self.record.service_kind,
            did: &self.record.did,
            method_history_head: &self.record.method_history_head,
            version_id: &self.record.version_id,
            resolution_event_ref: &self.record.resolution_event_ref,
            record_sequence: self.record.record_sequence,
            previous_record_digest: &self.record.previous_record_digest,
            current_record_url: &self.record.current_record_url,
            base_url: &self.record.base_url,
            describe_digest: &self.record.describe_digest,
            issued_at: self.record.issued_at,
            refresh_after: self.record.refresh_after,
            expires_at: self.record.expires_at,
            verification_method: &self.proof.verification_method,
            created_at: self.proof.created_at,
        })
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AuthenticatedServiceResolution {
    pub service_resolution_record: ServiceResolutionRecord,
    pub method_history_evidence: ResolutionMethodHistoryEvidence,
    pub normalized_did_document: DidDocument,
}

impl AuthenticatedServiceResolution {
    pub fn validate_shape(
        &self,
        expected_service_id: &DidCoreId,
        now: DateTime<Utc>,
    ) -> arkret_wire::Result<()> {
        if arkret_canonical::canonical_json_bytes(self)?.len() > 1024 * 1024 {
            return Err(arkret_wire::WireError::Protocol(
                "authenticated service resolution exceeds 1 MiB".to_owned(),
            ));
        }
        let record = &self.service_resolution_record.record;
        self.method_history_evidence.validate_shape()?;
        let projected = arkret_wire::project_did_to_core_id(&record.did)?;
        let boundary = self.method_history_evidence.boundary();
        let proof_controller = self
            .service_resolution_record
            .proof
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller);
        if &record.service_id != expected_service_id
            || projected != record.service_id
            || self.normalized_did_document.id != record.did
            || boundary.to_method_history_head != record.method_history_head
            || boundary.to_version_id != record.version_id
            || self.method_history_evidence.evidence().document_digest
                != normalized_did_document_digest(&self.normalized_did_document)?
            || record.issued_at > record.refresh_after
            || record.refresh_after >= record.expires_at
            || now >= record.refresh_after
            || self.service_resolution_record.proof.created_at != record.issued_at
            || proof_controller != Some(record.did.as_str())
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid or stale authenticated service resolution".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ServiceRouteHandoverState {
    Scheduled,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceRouteHandoverNoticeCore {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub handover_id: String,
    pub notice_revision: u32,
    pub state: ServiceRouteHandoverState,
    pub from_record_sequence: u64,
    pub from_record_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_record_url: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub cutover_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub grace_until: Option<DateTime<Utc>>,
    pub previous_notice_digest: Option<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl ServiceRouteHandoverNoticeCore {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        arkret_wire::ServiceRouteHandoverId::new(&self.handover_id)?;
        let valid_chain = (self.notice_revision == 0 && self.previous_notice_digest.is_none())
            || (self.notice_revision > 0 && self.previous_notice_digest.is_some());
        let valid_state = match self.state {
            ServiceRouteHandoverState::Scheduled => {
                let Some((not_before, cutover_at, grace_until)) = self
                    .not_before
                    .zip(self.cutover_at)
                    .zip(self.grace_until)
                    .map(|((a, b), c)| (a, b, c))
                else {
                    return Err(arkret_wire::WireError::Protocol(
                        "scheduled handover notice omits its time window".to_owned(),
                    ));
                };
                self.candidate_base_url.is_some()
                    && self.candidate_record_url.is_some()
                    && self.issued_at <= not_before
                    && not_before <= cutover_at
                    && cutover_at < grace_until
                    && grace_until <= self.expires_at
            }
            ServiceRouteHandoverState::Cancelled => {
                self.notice_revision > 0
                    && self.candidate_base_url.is_none()
                    && self.candidate_record_url.is_none()
                    && self.not_before.is_none()
                    && self.cutover_at.is_none()
                    && self.grace_until.is_none()
                    && self.issued_at < self.expires_at
            }
        };
        if !valid_chain || !valid_state {
            return Err(arkret_wire::WireError::Protocol(
                "invalid service route handover notice shape".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceRouteHandoverNotice {
    pub notice: ServiceRouteHandoverNoticeCore,
    pub proof: ProtocolSignature,
}

impl ServiceRouteHandoverNotice {
    pub fn proof_signing_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        self.notice.validate_shape()?;
        let payload_digest = Hash::new(arkret_canonical::canonical_sha256(&self.notice)?)?;
        let mut transcript = serde_json::to_value(&self.notice)?;
        let object = transcript
            .as_object_mut()
            .expect("handover notice core serializes as object");
        object.insert(
            "context".to_owned(),
            serde_json::Value::String(
                arkret_wire::ProofContextId::SERVICE_ROUTE_HANDOVER_NOTICE_PROOF_V1.to_owned(),
            ),
        );
        object.insert(
            "payload_digest".to_owned(),
            serde_json::to_value(payload_digest)?,
        );
        object.insert(
            "verification_method".to_owned(),
            serde_json::to_value(&self.proof.verification_method)?,
        );
        object.insert(
            "created_at".to_owned(),
            serde_json::Value::String(arkret_canonical::format_timestamp_canonical(
                self.proof.created_at,
            )),
        );
        arkret_canonical::canonical_json_bytes(&transcript)
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "artifact_family",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ServiceResolutionArtifactKey {
    ServiceResolutionRecord {
        service_id: DidCoreId,
        record_sequence: u64,
    },
    ServiceRouteHandoverNotice {
        service_id: DidCoreId,
        handover_id: String,
        notice_revision: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionPublishRequest {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub artifact_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_resolution_record: Option<ServiceResolutionRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_route_handover_notice: Option<ServiceRouteHandoverNotice>,
}

impl ServiceResolutionPublishRequest {
    pub fn validate(&self) -> arkret_wire::Result<ServiceResolutionArtifactKey> {
        let (key, actual_digest) = match (
            &self.service_resolution_record,
            &self.service_route_handover_notice,
        ) {
            (Some(record), None) => (
                ServiceResolutionArtifactKey::ServiceResolutionRecord {
                    service_id: record.record.service_id.clone(),
                    record_sequence: record.record.record_sequence,
                },
                Hash::new(arkret_canonical::canonical_sha256(record)?)?,
            ),
            (None, Some(notice)) => {
                notice.notice.validate_shape()?;
                (
                    ServiceResolutionArtifactKey::ServiceRouteHandoverNotice {
                        service_id: notice.notice.service_id.clone(),
                        handover_id: notice.notice.handover_id.clone(),
                        notice_revision: notice.notice.notice_revision,
                    },
                    Hash::new(arkret_canonical::canonical_sha256(notice)?)?,
                )
            }
            _ => {
                return Err(arkret_wire::WireError::Protocol(
                    "publish request must carry exactly one resolution artifact".to_owned(),
                ));
            }
        };
        if actual_digest != self.artifact_digest {
            return Err(arkret_wire::WireError::Protocol(
                "publish artifact_digest mismatch".to_owned(),
            ));
        }
        Ok(key)
    }

    pub fn canonical_digest(&self) -> arkret_wire::Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionPublishAckCore {
    pub request_id: RequestId,
    pub source_id: DidCoreId,
    pub receiver_id: DidCoreId,
    pub realm_id: RealmId,
    pub request_digest: Hash,
    pub artifact_key: ServiceResolutionArtifactKey,
    pub artifact_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionPublishAck {
    pub ack: ServiceResolutionPublishAckCore,
    pub proof: ProtocolSignature,
}

impl ServiceResolutionPublishAck {
    pub fn proof_signing_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        let payload_digest = Hash::new(arkret_canonical::canonical_sha256(&self.ack)?)?;
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "context": arkret_wire::ProofContextId::SERVICE_RESOLUTION_PUBLISH_ACK_PROOF_V1,
            "payload_digest": payload_digest,
            "request_id": self.ack.request_id,
            "source_id": self.ack.source_id,
            "receiver_id": self.ack.receiver_id,
            "realm_id": self.ack.realm_id,
            "request_digest": self.ack.request_digest,
            "artifact_key": self.ack.artifact_key,
            "artifact_digest": self.ack.artifact_digest,
            "accepted_at": arkret_canonical::format_timestamp_canonical(self.ack.accepted_at),
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
        }))
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
    }

    pub fn validate_request_binding(
        &self,
        source_id: &DidCoreId,
        request: &ServiceResolutionPublishRequest,
    ) -> arkret_wire::Result<()> {
        let key = request.validate()?;
        if &self.ack.source_id != source_id
            || self.ack.request_id != request.request_id
            || self.ack.realm_id != request.realm_id
            || self.ack.request_digest != request.canonical_digest()?
            || self.ack.artifact_key != key
            || self.ack.artifact_digest != request.artifact_digest
            || self.proof.created_at != self.ack.accepted_at
        {
            return Err(arkret_wire::WireError::Protocol(
                "publish ack does not cross-bind transport and artifact idempotency".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionPublishOutcome {
    pub ack: ServiceResolutionPublishAck,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionResolveRequest {
    pub realm_id: RealmId,
    pub target_id: DidCoreId,
    pub target_kind: String,
    pub known_record_sequence: u64,
    pub known_record_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_notice_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_records: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u32>,
}

impl ServiceResolutionResolveRequest {
    pub fn validate_bounds(&self) -> arkret_wire::Result<()> {
        if self
            .max_records
            .is_some_and(|value| !(1..=32).contains(&value))
            || self
                .max_response_bytes
                .is_some_and(|value| !(4096..=262_144).contains(&value))
        {
            return Err(arkret_wire::WireError::Protocol(
                "service resolution query exceeds hard bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionResolveOutcome {
    pub successor_records: Vec<ServiceResolutionRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handover_notice: Option<ServiceRouteHandoverNotice>,
    pub has_more: bool,
}

impl ServiceResolutionResolveOutcome {
    pub fn validate_chain(
        &self,
        request: &ServiceResolutionResolveRequest,
    ) -> arkret_wire::Result<()> {
        request.validate_bounds()?;
        if self.successor_records.len() > 32 || (self.has_more && self.successor_records.is_empty())
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid bounded service resolution response".to_owned(),
            ));
        }
        let mut sequence = request.known_record_sequence;
        let mut digest = request.known_record_digest.clone();
        for record in &self.successor_records {
            if record.record.service_id != request.target_id
                || record.record.service_kind != request.target_kind
                || record.record.record_sequence != sequence + 1
                || record.record.previous_record_digest.as_ref() != Some(&digest)
            {
                return Err(arkret_wire::WireError::Protocol(
                    "service resolution response contains a gap or fork".to_owned(),
                ));
            }
            sequence = record.record.record_sequence;
            digest = Hash::new(arkret_canonical::canonical_sha256(record)?)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionLastSeenFloor {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub record_sequence: u64,
    pub record_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceRouteNoticeState {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub handover_id: String,
    pub notice_revision: u32,
    pub notice_digest: Hash,
    pub state: ServiceRouteHandoverState,
    pub from_record_sequence: u64,
    pub from_record_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
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
    /// Native DID-method version coordinate from the verified signed record.
    pub version_id: String,
    pub record_sequence: u64,
    pub record_digest: Hash,
    pub base_url: String,
    pub current_record_url: String,
    pub describe_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub verified_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub refresh_after: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub cached_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub cache_expires_at: DateTime<Utc>,
}

impl ServiceRouteCacheEntry {
    #[must_use]
    pub fn is_routable_at(&self, now: DateTime<Utc>) -> bool {
        self.refresh_after < self.expires_at
            && self.cache_expires_at <= self.expires_at
            && now < self.expires_at
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handover_notice: Option<ServiceRouteHandoverNotice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mirror_hints: Vec<RouteMirrorHint>,
}

impl RouteAssistance {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if (self.handover_notice.is_none() && self.mirror_hints.is_empty())
            || self.mirror_hints.len() > 4
        {
            return Err(arkret_wire::WireError::Protocol(
                "route assistance must contain a notice or at most four mirror hints".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod resolution_contract_tests {
    use arkret_wire::{Base64UrlString, DidUrl};
    use chrono::{Duration, TimeZone as _};

    use super::*;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn record(sequence: u64, previous_record_digest: Option<Hash>) -> ServiceResolutionRecord {
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 10, 1, 0, 0).unwrap();
        let did = Did::new("did:webvh:z6mkfixture:service.example").unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        ServiceResolutionRecord {
            record: ServiceResolutionRecordCore {
                service_id,
                service_kind: "station".to_owned(),
                did: did.clone(),
                method_history_head: "head-1".to_owned(),
                version_id: "1-head-1".to_owned(),
                resolution_event_ref: format!("ak:event:{}", "A".repeat(44)),
                record_sequence: sequence,
                previous_record_digest,
                current_record_url: "https://service.example/_arkret/open/services/id/resolution"
                    .to_owned(),
                base_url: "https://service.example/".to_owned(),
                describe_digest: hash('d'),
                issued_at,
                refresh_after: issued_at + Duration::minutes(5),
                expires_at: issued_at + Duration::minutes(10),
            },
            proof: ProtocolSignature {
                verification_method: DidUrl::new(format!("{did}#route-1")).unwrap(),
                created_at: issued_at,
                jws: Base64UrlString::new("AA".to_owned()).unwrap(),
            },
        }
    }

    fn resolve_request(record: &ServiceResolutionRecord) -> ServiceResolutionResolveRequest {
        ServiceResolutionResolveRequest {
            realm_id: RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI")
                .unwrap(),
            target_id: record.record.service_id.clone(),
            target_kind: record.record.service_kind.clone(),
            known_record_sequence: record.record.record_sequence,
            known_record_digest: Hash::new(arkret_canonical::canonical_sha256(record).unwrap())
                .unwrap(),
            known_notice_digest: None,
            max_records: None,
            max_response_bytes: None,
        }
    }

    #[test]
    fn webvh_scid_projection_ignores_mutable_location_suffix() {
        let old = Did::new("did:webvh:z6mkfixture:old.example:user").unwrap();
        let new = Did::new("did:webvh:z6mkfixture:new.example:user").unwrap();
        assert_eq!(
            arkret_wire::project_did_to_core_id(&old).unwrap(),
            arkret_wire::project_did_to_core_id(&new).unwrap()
        );
    }

    #[test]
    fn route_cache_requires_verified_version_coordinate() {
        let record = record(0, None);
        let now = record.record.issued_at;
        let entry = ServiceRouteCacheEntry {
            service_id: record.record.service_id,
            service_kind: record.record.service_kind,
            did: record.record.did,
            method_history_head: record.record.method_history_head,
            version_id: record.record.version_id,
            record_sequence: record.record.record_sequence,
            record_digest: hash('e'),
            base_url: record.record.base_url,
            current_record_url: record.record.current_record_url,
            describe_digest: record.record.describe_digest,
            verified_at: now,
            refresh_after: record.record.refresh_after,
            expires_at: record.record.expires_at,
            cached_at: now,
            cache_expires_at: now + Duration::minutes(1),
        };
        let mut value = serde_json::to_value(entry).unwrap();
        value.as_object_mut().unwrap().remove("version_id");
        assert!(serde_json::from_value::<ServiceRouteCacheEntry>(value).is_err());
    }

    #[test]
    fn current_record_carrier_requires_canonical_expected_service_https_url() {
        let service_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let canonical = format!(
            "https://service.example{}",
            canonical_service_current_record_path(&service_id)
        );
        let carrier = ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url: canonical.clone(),
            pinned_record_digest: None,
        };
        carrier.validate_shape(&service_id).unwrap();

        for invalid in [
            canonical.replace("https://", "http://"),
            canonical.replace("service.example", "user@service.example"),
            format!("{canonical}?version=1"),
            format!("{canonical}#fragment"),
            canonical.replace("%3A", "%3a"),
            canonical.replace("service.example", "SERVICE.EXAMPLE"),
            canonical.replace("service.example", "service.example:443"),
            canonical.replace("z6mkfixture", "other"),
        ] {
            assert!(
                ServiceResolutionCarrier::CurrentRecordUrl {
                    current_record_url: invalid,
                    pinned_record_digest: None,
                }
                .validate_shape(&service_id)
                .is_err()
            );
        }

        let oversized = format!(
            "https://{}{}",
            "a".repeat(2_048),
            canonical_service_current_record_path(&service_id)
        );
        assert!(validate_service_current_record_url(&oversized, &service_id).is_err());
    }

    #[test]
    fn successor_chain_rejects_gap_and_empty_has_more() {
        let basis = record(0, None);
        let request = resolve_request(&basis);
        let empty = ServiceResolutionResolveOutcome {
            successor_records: Vec::new(),
            handover_notice: None,
            has_more: true,
        };
        assert!(empty.validate_chain(&request).is_err());

        let gap = record(2, Some(request.known_record_digest.clone()));
        let outcome = ServiceResolutionResolveOutcome {
            successor_records: vec![gap],
            handover_notice: None,
            has_more: false,
        };
        assert!(outcome.validate_chain(&request).is_err());
    }

    #[test]
    fn publish_ack_cross_binds_both_idempotency_keys() {
        let artifact = record(0, None);
        let artifact_digest =
            Hash::new(arkret_canonical::canonical_sha256(&artifact).unwrap()).unwrap();
        let request = ServiceResolutionPublishRequest {
            request_id: RequestId::new("ak:request:019b0000-0000-7000-8000-000000000001").unwrap(),
            realm_id: RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI")
                .unwrap(),
            artifact_digest: artifact_digest.clone(),
            service_resolution_record: Some(artifact.clone()),
            service_route_handover_notice: None,
        };
        let accepted_at = artifact.record.issued_at;
        let source = artifact.record.service_id.clone();
        let ack = ServiceResolutionPublishAck {
            ack: ServiceResolutionPublishAckCore {
                request_id: request.request_id.clone(),
                source_id: source.clone(),
                receiver_id: source.clone(),
                realm_id: request.realm_id.clone(),
                request_digest: request.canonical_digest().unwrap(),
                artifact_key: request.validate().unwrap(),
                artifact_digest,
                accepted_at,
            },
            proof: ProtocolSignature {
                verification_method: artifact.proof.verification_method,
                created_at: accepted_at,
                jws: Base64UrlString::new("AA".to_owned()).unwrap(),
            },
        };
        assert!(ack.validate_request_binding(&source, &request).is_ok());
        let wrong_source = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(
            ack.validate_request_binding(&wrong_source, &request)
                .is_err()
        );
    }
}
