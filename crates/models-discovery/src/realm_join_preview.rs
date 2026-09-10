//! Pre-join Realm preview
//! (`realm-join-intake.schema.json`, `sync/invite-addressing.md` section 7.1).
//!
//! Two faces, one disclosure: the invitee's own Station proxies to the exact
//! inviter Station named by `inviter_account_id.station_id`, and hands the
//! client a result bound to the target it asked for. The client never calls
//! the source, never selects a forwarding candidate and never treats a preview
//! as membership or as verified Realm governance.
//!
//! These shapes live beside the Directory models because the disclosure body
//! is [`RealmPreview`]; the authoring, bootstrap and application-status half of
//! the same schema family composes Event payloads instead and therefore lives
//! in `arkret-models-collaboration`. The two halves share no carrier, so
//! neither crate has to reach across to the other.

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AccountId, Hash, InviteId, NonEmptyString, RealmId, RequestId, Result, SchemaId, WireError,
    framed_request_digest, validate_invite_token,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::directory::RealmPreview;

/// Domain-separation label of `self_preview_outcome.request_digest`.
pub const REALM_JOIN_PREVIEW_REQUEST_DIGEST_LABEL: &str = "ak.realm-join-preview-request-v1";

/// Closed pre-join resolution target.
///
/// The `invite` branch is the only one whose source is fixed to the exact
/// inviter Station; every other branch is resolved through the Directory
/// discovery input surface and independently validated by the account's own
/// Station.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "selector", rename_all = "snake_case", deny_unknown_fields)]
pub enum RealmJoinTarget {
    /// One exact directed invite copied verbatim from the holder-private
    /// `ak.account.invite_delivery` entry.
    Invite {
        realm_id: RealmId,
        invite_id: InviteId,
        /// Complete inviter AccountId from the accepted invite Event. The same
        /// principal on another Station is a different account and is never
        /// substitutable.
        inviter_account_id: AccountId,
        /// Forwarded only to that exact inviter Station, and never present in
        /// any outcome.
        invite_token: String,
    },
    RealmId {
        realm_id: RealmId,
    },
    /// The alias MUST resolve from the effective `ak.realm.alias` cell; a
    /// Directory row is a projection of that cell and never an independent
    /// source.
    Alias {
        alias: NonEmptyString,
    },
    /// A token obtained out of band without a delivered invite entry.
    InviteToken {
        invite_token: String,
    },
    /// Signed link carrying its own authorization component.
    SignedLink {
        signed_link: NonEmptyString,
    },
}

/// `invite_token` is holder-private, so the derived `Debug` that would print
/// it is replaced rather than relied on to be unused.
impl std::fmt::Debug for RealmJoinTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invite {
                realm_id,
                invite_id,
                inviter_account_id,
                ..
            } => formatter
                .debug_struct("RealmJoinTarget::Invite")
                .field("realm_id", realm_id)
                .field("invite_id", invite_id)
                .field("inviter_account_id", inviter_account_id)
                .field("invite_token", &"<redacted>")
                .finish(),
            Self::RealmId { realm_id } => formatter
                .debug_struct("RealmJoinTarget::RealmId")
                .field("realm_id", realm_id)
                .finish(),
            Self::Alias { alias } => formatter
                .debug_struct("RealmJoinTarget::Alias")
                .field("alias", alias)
                .finish(),
            Self::InviteToken { .. } => formatter
                .debug_struct("RealmJoinTarget::InviteToken")
                .field("invite_token", &"<redacted>")
                .finish(),
            Self::SignedLink { signed_link } => formatter
                .debug_struct("RealmJoinTarget::SignedLink")
                .field("signed_link", signed_link)
                .finish(),
        }
    }
}

impl RealmJoinTarget {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Invite {
                inviter_account_id,
                invite_token,
                ..
            } => {
                inviter_account_id.validate()?;
                validate_invite_token("Realm join preview target", invite_token)
            }
            Self::InviteToken { invite_token } => {
                validate_invite_token("Realm join preview target", invite_token)
            }
            Self::RealmId { .. } | Self::Alias { .. } | Self::SignedLink { .. } => Ok(()),
        }
    }

    /// Canonical Realm id the target already names, when it names one. The
    /// remaining selectors only resolve to a Realm through the Station.
    pub fn declared_realm_id(&self) -> Option<&RealmId> {
        match self {
            Self::Invite { realm_id, .. } | Self::RealmId { realm_id } => Some(realm_id),
            Self::Alias { .. } | Self::InviteToken { .. } | Self::SignedLink { .. } => None,
        }
    }
}

/// Where the account's own Station obtained the returned preview.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinPreviewSource {
    /// The exact inviter Station of a directed invite.
    InviterStation,
    /// The equivalent local path, taken when that Station is this service.
    Local,
    /// The independently validated Directory discovery input surface.
    Directory,
}

/// A disclosed preview carries only Realm presentation members.
///
/// `join_candidates`, `source_refs`, `stale` and `divergent` are
/// Directory-result provenance: a client that received them would be back to
/// selecting a forwarding endpoint and going to a truth source itself, which
/// is exactly what this contract removes.
fn validate_disclosed_preview(preview: &RealmPreview) -> Result<()> {
    if !preview.join_candidates.is_empty()
        || !preview.source_refs.is_empty()
        || preview.stale.is_some()
        || preview.divergent.is_some()
    {
        return Err(WireError::Protocol(
            "a pre-join Realm preview must omit join_candidates, source_refs, stale and divergent"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Enforce one carrier's registered `x-arkret-max-canonical-bytes`.
fn validate_canonical_bytes(value: &impl Serialize, limit: usize, what: &str) -> Result<()> {
    if arkret_wire::canonical::canonical_json_bytes(value)?.len() > limit {
        return Err(WireError::Protocol(format!(
            "{what} exceeds {limit} canonical bytes"
        )));
    }
    Ok(())
}

fn validate_window(
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    what: &str,
) -> Result<()> {
    if expires_at <= observed_at {
        return Err(WireError::Protocol(format!(
            "{what} expires_at must follow observed_at"
        )));
    }
    Ok(())
}

/// Authenticated service-to-service pre-join preview read, issued by the
/// invitee's own Station against the exact inviter Station.
///
/// The invitee's local session credential is never forwarded: the request
/// carries only this bounded invite reference and the exact invitee AccountId
/// the source Station vouches for.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinPeerPreviewRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    /// Complete AccountId of the invitee on whose behalf the request is made.
    /// Its Station MUST equal the authenticated `Source-Service-ID`.
    pub requester_account_id: AccountId,
    pub invite_id: InviteId,
    /// Possession proof that the invitee actually holds the delivered invite.
    /// It MUST NOT be echoed, logged or retained beyond this evaluation.
    pub invite_token: String,
}

impl std::fmt::Debug for RealmJoinPeerPreviewRequestBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealmJoinPeerPreviewRequestBody")
            .field("request_id", &self.request_id)
            .field("realm_id", &self.realm_id)
            .field("requester_account_id", &self.requester_account_id)
            .field("invite_id", &self.invite_id)
            .field("invite_token", &"<redacted>")
            .finish()
    }
}

impl RealmJoinPeerPreviewRequestBody {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_PEER_PREVIEW_REQUEST_V1;
    pub const MAX_CANONICAL_BYTES: usize = 65_536;

    pub fn validate(&self) -> Result<()> {
        self.requester_account_id.validate()?;
        validate_invite_token("Realm join peer preview", &self.invite_token)?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "pre-join Realm preview request",
        )
    }
}

/// Policy-permitted pre-join disclosure for exactly one invite and one
/// invitee.
///
/// Receiving it is not membership, not an authorization grant and not evidence
/// that Realm governance was verified by the receiver.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinPeerPreviewOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub requester_account_id: AccountId,
    pub invite_id: InviteId,
    /// Only the members the effective `ak.realm.preview_policy` permits for the
    /// invited audience.
    pub preview: RealmPreview,
    #[serde(with = "canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl RealmJoinPeerPreviewOutcome {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_PEER_PREVIEW_OUTCOME_V1;
    pub const MAX_CANONICAL_BYTES: usize = 262_144;

    pub fn validate_structural(&self) -> Result<()> {
        self.requester_account_id.validate()?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "pre-join Realm preview disclosure",
        )?;
        validate_disclosed_preview(&self.preview)?;
        if self.preview.realm_id != self.realm_id {
            return Err(WireError::Protocol(
                "pre-join Realm preview discloses a different Realm than the outcome names"
                    .to_owned(),
            ));
        }
        validate_window(
            self.observed_at,
            self.expires_at,
            "pre-join Realm preview disclosure",
        )
    }

    pub fn validate_for_request(&self, request: &RealmJoinPeerPreviewRequestBody) -> Result<()> {
        request.validate()?;
        self.validate_structural()?;
        if self.request_id != request.request_id
            || self.realm_id != request.realm_id
            || self.requester_account_id != request.requester_account_id
            || self.invite_id != request.invite_id
        {
            return Err(WireError::Protocol(
                "pre-join Realm preview does not echo the request identity".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authenticated account request for a pre-join Realm preview.
///
/// `account_id` MUST equal the complete account of the authenticated session
/// and its Station MUST be the service handling this request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinSelfPreviewRequestBody {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub target: RealmJoinTarget,
}

impl RealmJoinSelfPreviewRequestBody {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_SELF_PREVIEW_REQUEST_V1;
    pub const MAX_CANONICAL_BYTES: usize = 65_536;

    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.target.validate()?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "pre-join Realm preview request",
        )
    }

    /// `SHA-256(UTF8(label) || 0x00 || JCS(exact request body))`.
    pub fn request_digest(&self) -> Result<Hash> {
        self.validate()?;
        framed_request_digest(REALM_JOIN_PREVIEW_REQUEST_DIGEST_LABEL, self)
    }
}

/// Own-Station validated pre-join preview.
///
/// The client checks the request, account, Realm and source binding and
/// displays the disclosed members. `request_digest` binds the exact target the
/// user chose; it is a wrong-target detector, not an authentication proof
/// against a malicious own Station.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinSelfPreviewOutcome {
    pub request_id: RequestId,
    pub account_id: AccountId,
    /// Canonical Realm id the target resolved to. For the invite target it
    /// MUST equal the requested `realm_id`.
    pub realm_id: RealmId,
    pub request_digest: Hash,
    pub source: RealmJoinPreviewSource,
    pub preview: RealmPreview,
    #[serde(with = "canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl RealmJoinSelfPreviewOutcome {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_SELF_PREVIEW_OUTCOME_V1;
    pub const MAX_CANONICAL_BYTES: usize = 262_144;

    pub fn validate_structural(&self) -> Result<()> {
        self.account_id.validate()?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "pre-join Realm preview disclosure",
        )?;
        validate_disclosed_preview(&self.preview)?;
        if self.preview.realm_id != self.realm_id {
            return Err(WireError::Protocol(
                "pre-join Realm preview discloses a different Realm than the outcome names"
                    .to_owned(),
            ));
        }
        validate_window(
            self.observed_at,
            self.expires_at,
            "pre-join Realm preview disclosure",
        )
    }

    pub fn validate_for_request(&self, request: &RealmJoinSelfPreviewRequestBody) -> Result<()> {
        self.validate_structural()?;
        if self.request_id != request.request_id || self.account_id != request.account_id {
            return Err(WireError::Protocol(
                "pre-join Realm preview does not echo the request identity".to_owned(),
            ));
        }
        if self.request_digest != request.request_digest()? {
            return Err(WireError::Protocol(
                "pre-join Realm preview request_digest does not cover this request".to_owned(),
            ));
        }
        if let Some(declared) = request.target.declared_realm_id()
            && *declared != self.realm_id
        {
            return Err(WireError::Protocol(
                "pre-join Realm preview resolved a different Realm than the target named"
                    .to_owned(),
            ));
        }
        // A directed invite has exactly one legal source. Accepting a
        // Directory-sourced answer here would be the substitution the
        // contract forbids, arriving as a plain field value.
        if matches!(request.target, RealmJoinTarget::Invite { .. })
            && self.source == RealmJoinPreviewSource::Directory
        {
            return Err(WireError::Protocol(
                "a directed invite preview may only come from the inviter Station".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidCoreId, EventId};
    use serde_json::json;

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").expect("realm id")
    }

    fn account_id() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:invitee.example").expect("principal"),
            DidCoreId::new("ak:did_core:web:origin.example").expect("station"),
        )
    }

    fn inviter_account_id() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:inviter.example").expect("principal"),
            DidCoreId::new("ak:did_core:web:holder.example").expect("station"),
        )
    }

    fn request_id() -> RequestId {
        RequestId::new("ak:request:01970000-0000-7000-8000-000000000041").expect("request id")
    }

    fn invite_id() -> InviteId {
        InviteId::new("ak:invite:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").expect("invite id")
    }

    fn observed_at() -> DateTime<Utc> {
        "2026-09-10T08:00:00Z".parse().expect("timestamp")
    }

    fn expires_at() -> DateTime<Utc> {
        "2026-09-10T08:05:00Z".parse().expect("timestamp")
    }

    fn disclosed_preview() -> RealmPreview {
        RealmPreview {
            realm_id: realm_id(),
            alias: None,
            title: Some("Example Realm".to_owned()),
            avatar_blob_ref: None,
            organization_id: None,
            join_rule: Some("invite".to_owned()),
            member_count_bucket: None,
            summary: None,
            owning_organization_ids: Vec::new(),
            preview_ref: None,
            discoverability: None,
            history_access: None,
            join_candidates: Vec::new(),
            as_of: observed_at(),
            source_refs: Vec::new(),
            policy_revision: "rev-1".to_owned(),
            stale: None,
            divergent: None,
        }
    }

    fn invite_target() -> RealmJoinTarget {
        RealmJoinTarget::Invite {
            realm_id: realm_id(),
            invite_id: invite_id(),
            inviter_account_id: inviter_account_id(),
            invite_token: "srv-01HYZ8Z000000000000000".to_owned(),
        }
    }

    fn self_request() -> RealmJoinSelfPreviewRequestBody {
        RealmJoinSelfPreviewRequestBody {
            request_id: request_id(),
            account_id: account_id(),
            target: invite_target(),
        }
    }

    fn self_outcome(request: &RealmJoinSelfPreviewRequestBody) -> RealmJoinSelfPreviewOutcome {
        RealmJoinSelfPreviewOutcome {
            request_id: request.request_id.clone(),
            account_id: request.account_id.clone(),
            realm_id: realm_id(),
            request_digest: request.request_digest().expect("digest"),
            source: RealmJoinPreviewSource::InviterStation,
            preview: disclosed_preview(),
            observed_at: observed_at(),
            expires_at: expires_at(),
        }
    }

    fn peer_request() -> RealmJoinPeerPreviewRequestBody {
        RealmJoinPeerPreviewRequestBody {
            request_id: request_id(),
            realm_id: realm_id(),
            requester_account_id: account_id(),
            invite_id: invite_id(),
            invite_token: "srv-01HYZ8Z000000000000000".to_owned(),
        }
    }

    fn peer_outcome(request: &RealmJoinPeerPreviewRequestBody) -> RealmJoinPeerPreviewOutcome {
        RealmJoinPeerPreviewOutcome {
            request_id: request.request_id.clone(),
            realm_id: request.realm_id.clone(),
            requester_account_id: request.requester_account_id.clone(),
            invite_id: request.invite_id.clone(),
            preview: disclosed_preview(),
            observed_at: observed_at(),
            expires_at: expires_at(),
        }
    }

    #[test]
    fn a_target_round_trips_through_its_selector_tag() {
        let value = serde_json::to_value(invite_target()).expect("serialize");
        assert_eq!(value["selector"], json!("invite"));
        let restored: RealmJoinTarget = serde_json::from_value(value).expect("deserialize");
        assert_eq!(restored, invite_target());
    }

    #[test]
    fn an_unregistered_selector_has_no_representation() {
        assert!(
            serde_json::from_value::<RealmJoinTarget>(json!({
                "selector": "join_candidate",
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            }))
            .is_err()
        );
    }

    #[test]
    fn debug_output_never_carries_the_invite_token() {
        let rendered = format!("{:?}", self_request());
        assert!(
            !rendered.contains("srv-01HYZ8Z000000000000000"),
            "{rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");

        let rendered = format!("{:?}", peer_request());
        assert!(
            !rendered.contains("srv-01HYZ8Z000000000000000"),
            "{rendered}"
        );
    }

    #[test]
    fn a_peer_disclosure_never_echoes_the_token() {
        let request = peer_request();
        let value = serde_json::to_value(peer_outcome(&request)).expect("serialize");
        assert!(value.get("invite_token").is_none());
        peer_outcome(&request)
            .validate_for_request(&request)
            .expect("the disclosure answers this request");
    }

    #[test]
    fn a_disclosed_preview_carries_no_forwarding_candidate() {
        let request = peer_request();
        let mut outcome = peer_outcome(&request);
        outcome.preview.source_refs = vec![
            EventId::new("ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2")
                .expect("event id"),
        ];
        let error = outcome
            .validate_structural()
            .expect_err("provenance members are not part of a pre-join disclosure");
        assert!(error.to_string().contains("source_refs"), "{error}");

        let mut outcome = peer_outcome(&request);
        outcome.preview.stale = Some(true);
        assert!(outcome.validate_structural().is_err());
    }

    #[test]
    fn a_self_preview_binds_the_exact_target() {
        let request = self_request();
        let outcome = self_outcome(&request);
        outcome
            .validate_for_request(&request)
            .expect("the preview answers this target");

        let mut other = self_request();
        other.target = RealmJoinTarget::RealmId {
            realm_id: realm_id(),
        };
        let error = outcome
            .validate_for_request(&other)
            .expect_err("a Directory-resolved target is a different request");
        assert!(error.to_string().contains("request_digest"), "{error}");
    }

    #[test]
    fn a_self_preview_may_not_resolve_a_different_realm() {
        let request = self_request();
        let mut outcome = self_outcome(&request);
        outcome.realm_id =
            RealmId::new("ak:realm:AZ0iBOTdEfBLcM7WT9SFbSOJU7EYIkPMPtXcLcZ5UjRT").expect("realm");
        outcome.preview.realm_id = outcome.realm_id.clone();
        let error = outcome
            .validate_for_request(&request)
            .expect_err("the invite target already names the Realm");
        assert!(error.to_string().contains("different Realm"), "{error}");
    }

    #[test]
    fn a_directed_invite_preview_may_not_come_from_the_directory() {
        let request = self_request();
        let mut outcome = self_outcome(&request);
        outcome.source = RealmJoinPreviewSource::Directory;
        let error = outcome
            .validate_for_request(&request)
            .expect_err("the inviter Station is the only source for a directed invite");
        assert!(error.to_string().contains("inviter Station"), "{error}");
    }

    #[test]
    fn a_directory_target_may_be_answered_by_the_directory() {
        let mut request = self_request();
        request.target = RealmJoinTarget::Alias {
            alias: NonEmptyString::new("example").expect("alias"),
        };
        let mut outcome = self_outcome(&request);
        outcome.request_digest = request.request_digest().expect("digest");
        outcome.source = RealmJoinPreviewSource::Directory;
        outcome
            .validate_for_request(&request)
            .expect("an alias resolves through the Directory input surface");
    }

    /// Field-set parity with `realm-join-intake.schema.json`.
    ///
    /// A schema member the carrier cannot hold is a binding this SDK cannot
    /// express; a carrier member the schema does not declare is one no
    /// conforming peer will accept. The comparison runs in both directions
    /// against fully populated instances.
    mod schema_parity {
        use std::collections::BTreeSet;

        use serde::Serialize;
        use serde_json::Value;

        use super::*;
        use crate::realm_join_preview::{RealmJoinPreviewSource, RealmJoinTarget};

        const INTAKE: &str = "schemas/realm-join-intake.schema.json";

        fn definition(name: &str) -> Value {
            let schema = arkret_schema_conformance::spec_json_artifact(INTAKE)
                .unwrap_or_else(|error| panic!("embedded {INTAKE} failed to load: {error}"));
            schema["$defs"][name].clone()
        }

        fn assert_matches_schema<T: Serialize>(name: &str, fully_populated: &T) {
            let declared: BTreeSet<String> = definition(name)["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("$defs/{name}/properties is missing"))
                .keys()
                .cloned()
                .collect();
            let carried: BTreeSet<String> = serde_json::to_value(fully_populated)
                .expect("carrier serializes")
                .as_object()
                .expect("carrier serializes to an object")
                .keys()
                .cloned()
                .collect();
            assert_eq!(declared, carried, "$defs/{name} and its carrier differ");
        }

        #[test]
        fn every_preview_body_carries_exactly_its_declared_members() {
            let self_request = self_request();
            assert_matches_schema("self_preview_request_body", &self_request);
            assert_matches_schema("self_preview_outcome", &self_outcome(&self_request));

            let peer_request = peer_request();
            assert_matches_schema("peer_preview_request_body", &peer_request);
            assert_matches_schema("peer_preview_outcome", &peer_outcome(&peer_request));
        }

        #[test]
        fn every_target_branch_carries_exactly_its_declared_members() {
            assert_matches_schema("realm_join_invite_target", &invite_target());
            assert_matches_schema(
                "realm_join_realm_id_target",
                &RealmJoinTarget::RealmId {
                    realm_id: realm_id(),
                },
            );
            assert_matches_schema(
                "realm_join_alias_target",
                &RealmJoinTarget::Alias {
                    alias: NonEmptyString::new("example").expect("alias"),
                },
            );
            assert_matches_schema(
                "realm_join_invite_token_target",
                &RealmJoinTarget::InviteToken {
                    invite_token: "srv-01HYZ8Z000000000000000".to_owned(),
                },
            );
            assert_matches_schema(
                "realm_join_signed_link_target",
                &RealmJoinTarget::SignedLink {
                    signed_link: NonEmptyString::new("web+arkret://example").expect("link"),
                },
            );
        }

        #[test]
        fn every_registered_canonical_byte_cap_is_pinned() {
            for (name, declared) in [
                (
                    "peer_preview_request_body",
                    RealmJoinPeerPreviewRequestBody::MAX_CANONICAL_BYTES,
                ),
                (
                    "peer_preview_outcome",
                    RealmJoinPeerPreviewOutcome::MAX_CANONICAL_BYTES,
                ),
                (
                    "self_preview_request_body",
                    RealmJoinSelfPreviewRequestBody::MAX_CANONICAL_BYTES,
                ),
                (
                    "self_preview_outcome",
                    RealmJoinSelfPreviewOutcome::MAX_CANONICAL_BYTES,
                ),
            ] {
                assert_eq!(
                    definition(name)["x-arkret-max-canonical-bytes"].as_u64(),
                    Some(declared as u64),
                    "$defs/{name} budget drifted from its Rust constant"
                );
            }
        }

        #[test]
        fn the_disclosure_source_vocabulary_matches_the_registry() {
            let declared: BTreeSet<String> = definition("realm_join_preview_source")["enum"]
                .as_array()
                .expect("$defs/realm_join_preview_source/enum is missing")
                .iter()
                .map(|value| value.as_str().expect("enum value is a string").to_owned())
                .collect();
            let carried: BTreeSet<String> = [
                RealmJoinPreviewSource::InviterStation,
                RealmJoinPreviewSource::Local,
                RealmJoinPreviewSource::Directory,
            ]
            .iter()
            .map(|value| {
                serde_json::to_value(value)
                    .expect("enum serializes")
                    .as_str()
                    .expect("enum serializes to a string")
                    .to_owned()
            })
            .collect();
            assert_eq!(declared, carried);
        }
    }
}
