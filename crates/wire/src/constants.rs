use crate::{CapabilityActionId, ServiceOperationId};

/// Service operations for which this SDK ships generated route and metadata support.
pub const SUPPORTED_OPERATION_IDS: &[ServiceOperationId] = ServiceOperationId::ALL;

pub const PROTOCOL_VERSION: &str = "1.0";
/// Schema profile carried by object `schema_refs` and the schema catalog. Not a
/// `schema-registry.json` row, so it has no [`crate::SchemaId`] variant.
pub const CORE_SCHEMA_PROFILE: &str = "ak.schema.core.v1";
/// Reducer profile marker for snapshots and governance proofs. Not a
/// `reducer-profile-registry.json` `profile_id`, so it has no
/// [`crate::ProfileId`] variant.
pub const CORE_REDUCER_PROFILE: &str = "ak.reducer.v1";
pub const BUILT_IN_CONFORMANCE_FIXTURES_VERSION: &str = "arkret-sdk-builtin-v1";

/// `receipt_kind` const value of `read-receipt.schema.json`.
pub const READ_RECEIPT_KIND: &str = "read";

/// AEAD profile id used by every Arkret payload envelope that seals with
/// XChaCha20-Poly1305 (account data, key vaults, file transfer).
pub const AEAD_PROFILE_XCHACHA20_POLY1305_V1: &str = "ak.aead.xchacha20_poly1305.v1";
/// HPKE suite id (RFC 9180 base mode) used by secret share, key backup, and
/// file-transfer key envelopes.
pub const HPKE_SUITE_X25519_CHACHA20POLY1305_V1: &str = "ak.hpke_x25519_aead_chacha20poly1305.v1";
/// Whole-file blob AEAD scheme id.
pub const BLOB_SCHEME_WHOLE_FILE_AEAD_V1: &str = "ak.blob.whole_file_aead.v1";
/// Chunked streaming blob AEAD scheme id (STREAM / OAE2).
pub const BLOB_SCHEME_STREAM_AEAD_V1: &str = "ak.blob.stream_aead.v1";
/// HPKE `info` string bound into every device-to-device secret share.
pub const SECRET_SHARE_HPKE_INFO: &[u8] = b"ak.secret-share/v1";
/// Wire `kind` of a device-to-device secret request.
pub const SECRET_REQUEST_KIND: &str = "ak.secret.request";
/// Wire `kind` of a sealed device-to-device secret response.
pub const SECRET_SEND_KIND: &str = "ak.secret.send";
/// Cell family carrying the per-Realm media-service binding.
pub const REALM_MEDIA_SERVICE_CELL_FAMILY: &str = "ak.component.realm.media_service.v1";
/// `signature.type` of a signed identity recovery policy.
pub const RECOVERY_POLICY_SIGNATURE_TYPE: &str = "ak.identity.recovery_policy.signature.v1";

/// Capability constraint shorthand from `capability-action-registry.json`.
pub const CAP_CONSTRAINT_ALLOWED_WRITE_FIELDS: &str = "allowed_write_fields";

/// AKP-0007 capability action list (6 actions). Useful for downstream
/// services that want to iterate the Circle-management surface.
///
/// `ak.circle.manage`, `ak.circle.member.manage`, `ak.circle.member.add.others`
/// and `ak.circle.audit` declare `required_constraints=["allowed_circle_ids"]`;
/// unconstrained Realm-wide grants for those actions MUST be rejected.
pub const CIRCLE_CAPABILITY_ACTIONS: &[&str] = &[
    CapabilityActionId::CIRCLE_CREATE,
    CapabilityActionId::CIRCLE_MANAGE,
    CapabilityActionId::CIRCLE_MEMBER_ADD,
    CapabilityActionId::CIRCLE_MEMBER_MANAGE,
    CapabilityActionId::CIRCLE_MEMBER_ADD_OTHERS,
    CapabilityActionId::CIRCLE_AUDIT,
];

/// AKP-0010 — full call/media capability-action list. These actions gate the
/// join, screen-share, recording, transcription, moderation, and signal-send
/// surfaces of the `ak.call.*` feature.
pub const CALL_CAPABILITY_ACTIONS: &[&str] = &[
    CapabilityActionId::CALL_JOIN,
    CapabilityActionId::CALL_SCREEN_SHARE,
    CapabilityActionId::CALL_RECORD,
    CapabilityActionId::CALL_TRANSCRIBE,
    CapabilityActionId::CALL_MODERATE,
    CapabilityActionId::CALL_SIGNAL_SEND,
];

/// AKP-0010 — maximum TTL bound for media tokens (600 seconds). Tokens
/// MUST be rejected when `expires_at - now > 600s`. SHOULD floor: 300s.
pub const MEDIA_TOKEN_TTL_MAX_SECS: u64 = 600;
/// AKP-0010 — SHOULD-bound (recommended) TTL for media tokens.
pub const MEDIA_TOKEN_TTL_SHOULD_SECS: u64 = 300;

pub const PERSONAL_AGENT_RUNTIME_EVENT_SERVICE_SCOPES: &[&str] = &[
    ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE,
    ServiceOperationId::SELF_EVENTS_QUERY_SCAN,
    ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
    ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER,
    ServiceOperationId::SELF_EVENTS_RESOURCE_GET,
    ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
];

pub fn is_personal_agent_runtime_event_service_scope(scope: &str) -> bool {
    matches!(
        scope,
        ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE
            | ServiceOperationId::SELF_EVENTS_QUERY_SCAN
            | ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE
            | ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER
            | ServiceOperationId::SELF_EVENTS_RESOURCE_GET
            | ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT
    )
}

/// AKP-0008 / AKP-0009 (R3 spec-sync 2026-05-27) — agent_runtime
/// surface tier: list of operations that live under the
/// `ak.profile.agent_runtime.v1` server-profile surface.
pub const AGENT_RUNTIME_SURFACE_OPERATIONS: &[&str] = &[
    ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
    ServiceOperationId::SELF_AGENT_COMMAND_PROVISION,
    ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING,
    ServiceOperationId::SELF_AGENT_QUERY_LIST,
    ServiceOperationId::SELF_AGENT_RESOURCE_GET,
    ServiceOperationId::SELF_AGENT_COMMAND_PAUSE,
    ServiceOperationId::SELF_AGENT_COMMAND_RESUME,
    ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE,
    ServiceOperationId::SELF_AGENT_GRANT_COMMAND_ATTACH,
    ServiceOperationId::SELF_AGENT_GRANT_RESOURCE_DELETE,
    ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
    ServiceOperationId::SELF_AGENT_SIDECAR_QUERY_LIST,
    ServiceOperationId::SELF_AGENT_SIDECAR_RESOURCE_GET,
];

/// Round 4 (2026-05-20) — federation S2S HTTP message-signature headers.
/// MUST be present on every cross-trust-domain federation request and
/// MUST be included in the canonical signing transcript so a sender from
/// trust domain A cannot replay the same signed bytes into trust domain B.
/// Spec commit f9bd7eb (`harden protocol review closures`).
pub const HEADER_SOURCE_TRUST_DOMAIN: &str = "Source-Trust-Domain";
pub const HEADER_DESTINATION_TRUST_DOMAIN: &str = "Destination-Trust-Domain";
/// Round 4 — canonical digest of the request payload as bound into the
/// signing transcript. Carried alongside the signing headers so receivers
/// can detect transport-level body tampering after the signature was
/// computed. Spec commit f9bd7eb.
pub const HEADER_REQUEST_CANONICAL_DIGEST: &str = "Request-Canonical-Digest";

/// Domain separator for the deterministic backing-Circle short name derived
/// from a sidecar id.
pub const AGENT_SIDECAR_BACKING_CIRCLE_TRANSCRIPT: &str = "ak.sidecar.backing_circle.v1";

fn base32_lower_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

pub fn agent_sidecar_backing_circle_short_name(sidecar_id: &str) -> String {
    let transcript = format!("{AGENT_SIDECAR_BACKING_CIRCLE_TRANSCRIPT}\n{sidecar_id}");
    let digest = crate::canonical::sha256_bytes(transcript.as_bytes());
    let suffix = base32_lower_no_pad(&digest)
        .chars()
        .take(16)
        .collect::<String>()
        .to_ascii_uppercase();
    format!("SC-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_sidecar_backing_circle_short_name_is_stable() {
        let short_name = agent_sidecar_backing_circle_short_name(
            "ak:sidecar:01964137-0000-7000-8000-000000000001",
        );
        assert_eq!(short_name.len(), 19);
        assert!(short_name.starts_with("SC-"));
        assert!(
            short_name[3..]
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || matches!(ch, '2'..='7'))
        );
    }
}
