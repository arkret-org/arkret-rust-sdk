//! Account-data event payloads.

use serde::de;
use sha2::{Digest as _, Sha256};

use crate::internal_prelude::*;
use crate::objects::read_receipts::NotificationIdentity;

const AGENT_DRAFT_KEY_AGENT_DOMAIN: &str = "ak.agent-draft.account-data-key.agent-id.v1";
const AGENT_DRAFT_KEY_DRAFT_DOMAIN: &str = "ak.agent-draft.account-data-key.draft-id.v1";

/// Each Agent draft key component is one complete SHA-256 digest encoded as
/// canonical unpadded base64url.
pub const AGENT_DRAFT_ACCOUNT_DATA_KEY_COMPONENT_LENGTH: usize = 43;

/// `ak.agent.draft.v1:` plus two 43-character digest components and their
/// separator.
pub const AGENT_DRAFT_ACCOUNT_DATA_KEY_LENGTH: usize = 105;

/// Opaque digest components parsed from an Agent draft Account Data key.
///
/// These values are intentionally not decoded into an Agent or draft
/// identifier. A Station obtains the source literals from the accepted
/// pending row and calls [`validate_agent_draft_account_data_key_source`] to
/// recompute the signed key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentDraftAccountDataKeyComponents {
    agent_digest_component: String,
    draft_digest_component: String,
}

impl AgentDraftAccountDataKeyComponents {
    pub fn agent_digest_component(&self) -> &str {
        &self.agent_digest_component
    }

    pub fn draft_digest_component(&self) -> &str {
        &self.draft_digest_component
    }
}

fn agent_draft_digest_component(domain: &str, literal: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update(b"\n");
    digest.update(literal.as_bytes());
    arkret_canonical::base64url_encode(digest.finalize())
}

/// Build the unique canonical Account Data key for one accepted Agent draft
/// pending row.
///
/// Both complete source literals are hashed with their independently
/// registered domains. There is no truncation, JSON wrapper, normalization,
/// salt, fallback, or reversible component encoding.
pub fn agent_draft_account_data_key(agent_id: &DidCoreId, draft_id: &str) -> Result<String> {
    if draft_id.is_empty() || draft_id.starts_with("ak:") {
        return Err(WireError::Protocol(
            "agent draft draft_id must be non-empty and must not use the ak: typed-id namespace"
                .to_owned(),
        ));
    }

    let agent_component =
        agent_draft_digest_component(AGENT_DRAFT_KEY_AGENT_DOMAIN, agent_id.as_str());
    let draft_component = agent_draft_digest_component(AGENT_DRAFT_KEY_DRAFT_DOMAIN, draft_id);
    Ok(format!(
        "{}:{agent_component}:{draft_component}",
        AccountDataKey::AGENT_DRAFT_V1
    ))
}

fn parse_agent_draft_digest_component(component: &str, role: &str) -> Result<String> {
    if component.len() != AGENT_DRAFT_ACCOUNT_DATA_KEY_COMPONENT_LENGTH || component.contains('=') {
        return Err(WireError::Protocol(format!(
            "agent draft {role} digest component must be 43-character unpadded base64url"
        )));
    }
    let decoded = arkret_canonical::base64url_decode(component).map_err(|_| {
        WireError::Protocol(format!(
            "agent draft {role} digest component must be canonical unpadded base64url"
        ))
    })?;
    if decoded.len() != 32 || arkret_canonical::base64url_encode(&decoded) != component {
        return Err(WireError::Protocol(format!(
            "agent draft {role} digest component must canonically encode exactly 32 bytes"
        )));
    }
    Ok(component.to_owned())
}

/// Parse an Agent draft Account Data key into opaque digest components.
///
/// Parsing proves only the exact prefix, fixed 105-byte ASCII shape, two
/// canonical 32-byte base64url components, and absence of padding or extra
/// separators. It deliberately does not claim to recover or authenticate the
/// source literals.
pub fn parse_agent_draft_account_data_key(
    account_data_key: &str,
) -> Result<AgentDraftAccountDataKeyComponents> {
    if account_data_key.len() != AGENT_DRAFT_ACCOUNT_DATA_KEY_LENGTH || !account_data_key.is_ascii()
    {
        return Err(WireError::Protocol(
            "agent draft account-data key must be exactly 105 ASCII characters".to_owned(),
        ));
    }

    let tail = account_data_key
        .strip_prefix(AccountDataKey::AGENT_DRAFT_V1)
        .and_then(|value| value.strip_prefix(':'))
        .ok_or_else(|| {
            WireError::Protocol("agent draft account-data key has the wrong prefix".to_owned())
        })?;
    let mut components = tail.split(':');
    let agent_component = components.next().ok_or_else(|| {
        WireError::Protocol("agent draft account-data key is missing agent component".to_owned())
    })?;
    let draft_component = components.next().ok_or_else(|| {
        WireError::Protocol("agent draft account-data key is missing draft component".to_owned())
    })?;
    if components.next().is_some() {
        return Err(WireError::Protocol(
            "agent draft account-data key has an extra separator".to_owned(),
        ));
    }

    Ok(AgentDraftAccountDataKeyComponents {
        agent_digest_component: parse_agent_draft_digest_component(agent_component, "agent")?,
        draft_digest_component: parse_agent_draft_digest_component(draft_component, "draft")?,
    })
}

/// Validate that a structurally canonical signed key was derived from the
/// exact source literals in the accepted pending row.
///
/// This recomputation is the check that rejects a key made with a wrong
/// domain, Agent, draft, prefix, or component. Callers must not accept decoded
/// selectors supplied alongside the key.
pub fn validate_agent_draft_account_data_key_source(
    account_data_key: &str,
    agent_id: &DidCoreId,
    draft_id: &str,
) -> Result<()> {
    parse_agent_draft_account_data_key(account_data_key)?;
    let expected = agent_draft_account_data_key(agent_id, draft_id)?;
    if account_data_key != expected {
        return Err(WireError::Protocol(
            "agent draft account-data key does not match the accepted pending source row"
                .to_owned(),
        ));
    }
    Ok(())
}

/// `ak.views.private.<view_id>` per the account-data key registry. The
/// namespace literal is spelled only in the generated [`AccountDataKey`].
pub fn private_view_account_data_key(view_id: &ViewId) -> String {
    format!("{}.{}", AccountDataKey::VIEWS_PRIVATE, view_id.as_str())
}

/// Inverse of [`private_view_account_data_key`]. `None` for any key outside
/// the namespace or whose tail is not a canonical `ak:view:` id, so a caller
/// enumerating the account-data surface never invents a View id.
pub fn private_view_account_data_key_view_id(account_data_key: &str) -> Option<ViewId> {
    account_data_key
        .strip_prefix(AccountDataKey::VIEWS_PRIVATE)?
        .strip_prefix('.')
        .and_then(|view_id| ViewId::new(view_id.to_owned()).ok())
}

/// `ak.notifications.inbox.<notification_id>` per the account-data key
/// registry.
pub fn notification_inbox_account_data_key(notification_id: &NotificationIdentity) -> String {
    format!(
        "{}.{}",
        AccountDataKey::NOTIFICATIONS_INBOX,
        notification_id.as_str()
    )
}

/// Inverse of [`notification_inbox_account_data_key`].
pub fn notification_inbox_account_data_key_notification_id(
    account_data_key: &str,
) -> Option<NotificationIdentity> {
    account_data_key
        .strip_prefix(AccountDataKey::NOTIFICATIONS_INBOX)?
        .strip_prefix('.')
        .and_then(|notification_id| NotificationIdentity::new(notification_id.to_owned()).ok())
}

/// Presence-aware account-data body.
///
/// The schema permits any JSON value, including explicit `null`, so a plain
/// `Option<Value>` cannot distinguish a present null from an absent field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AccountDataBody {
    #[default]
    Absent,
    Value(Value),
}

impl AccountDataBody {
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn as_value(&self) -> Option<&Value> {
        match self {
            Self::Absent => None,
            Self::Value(value) => Some(value),
        }
    }
}

impl From<Value> for AccountDataBody {
    fn from(value: Value) -> Self {
        Self::Value(value)
    }
}

impl Serialize for AccountDataBody {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Absent => serializer.serialize_none(),
            Self::Value(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AccountDataBody {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Value::deserialize(deserializer).map(Self::Value)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/account_data_set_payload`.
///
/// This is the canonical Event payload for `ak.account_data.set`. The
/// self-service HTTP `account_data_replace_request_body` is a separate
/// transport DTO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountDataSetPayload {
    pub key: NonEmptyString,
    /// Compare-and-set precondition. `0` creates a key that has never been
    /// written; every accepted write stores `expected_server_revision + 1`.
    pub expected_server_revision: u64,
    /// Caller-supplied opaque value. Unlike the encrypted branch, this may be
    /// any JSON value, including a scalar, array, or null.
    #[serde(default, skip_serializing_if = "AccountDataBody::is_absent")]
    pub body: AccountDataBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<BTreeMap<String, Value>>,
    /// `true` selects the schema's tombstone branch. `false` is never emitted
    /// and is rejected on deserialization.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tombstone: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    /// Selects the Station-private proposal intent consumed by the initial
    /// Initial `ak.agent.draft.v1:<agent_digest_b64u43>:<draft_digest_b64u43>`
    /// create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_pending_event_id: Option<EventId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountDataSetPayloadWire {
    key: NonEmptyString,
    expected_server_revision: u64,
    #[serde(default)]
    body: AccountDataBody,
    #[serde(default)]
    encrypted_payload: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    tombstone: Option<bool>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    source_pending_event_id: Option<EventId>,
}

impl<'de> Deserialize<'de> for AccountDataSetPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AccountDataSetPayloadWire::deserialize(deserializer)?;
        if wire.tombstone == Some(false) {
            return Err(de::Error::custom(
                "account_data_set_payload.tombstone must be true when present",
            ));
        }
        let payload = Self {
            key: wire.key,
            expected_server_revision: wire.expected_server_revision,
            body: wire.body,
            encrypted_payload: wire.encrypted_payload,
            tombstone: wire.tombstone.unwrap_or(false),
            updated_at: wire.updated_at,
            source_pending_event_id: wire.source_pending_event_id,
        };
        payload.validate().map_err(de::Error::custom)?;
        Ok(payload)
    }
}

impl AccountDataSetPayload {
    /// Enforce the schema's `body | encrypted_payload | tombstone=true`
    /// any-of requirement for values constructed directly in Rust.
    pub fn validate(&self) -> Result<()> {
        if self.body.is_absent() && self.encrypted_payload.is_none() && !self.tombstone {
            return Err(WireError::Protocol(
                "account_data_set_payload requires body, encrypted_payload, or tombstone=true"
                    .to_owned(),
            ));
        }
        let initial_agent_draft = self.key.as_str().starts_with("ak.agent.draft.v1:")
            && self.expected_server_revision == 0;
        if initial_agent_draft
            && (self.encrypted_payload.is_none() || self.source_pending_event_id.is_none())
        {
            return Err(WireError::Protocol(
                "initial agent draft account data requires encrypted_payload and source_pending_event_id"
                    .to_owned(),
            ));
        }
        if self.source_pending_event_id.is_some()
            && (!initial_agent_draft || self.encrypted_payload.is_none())
        {
            return Err(WireError::Protocol(
                "source_pending_event_id is only valid on an initial encrypted agent draft create"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT_LITERAL: &str = "ak:did_core:web:agent.example";
    const DRAFT_LITERAL: &str = "draft-001";
    const AGENT_COMPONENT: &str = "29zs6Yu_GblluGkdTEDf8gWy8fRlKv2Am4Ms91DB-U8";
    const DRAFT_COMPONENT: &str = "HpcHzfESu5dFt2Is2QQ2Tp_c7hfh4SZtz4pKrbxp0_s";
    const KEY: &str = "ak.agent.draft.v1:29zs6Yu_GblluGkdTEDf8gWy8fRlKv2Am4Ms91DB-U8:HpcHzfESu5dFt2Is2QQ2Tp_c7hfh4SZtz4pKrbxp0_s";

    fn agent() -> DidCoreId {
        DidCoreId::new(AGENT_LITERAL).unwrap()
    }

    fn key_with_domains(agent_domain: &str, draft_domain: &str) -> String {
        format!(
            "{}:{}:{}",
            AccountDataKey::AGENT_DRAFT_V1,
            agent_draft_digest_component(agent_domain, AGENT_LITERAL),
            agent_draft_digest_component(draft_domain, DRAFT_LITERAL)
        )
    }

    #[test]
    fn agent_draft_account_data_key_matches_normative_kat() {
        let key = agent_draft_account_data_key(&agent(), DRAFT_LITERAL).unwrap();
        assert_eq!(key, KEY);
        assert_eq!(key.len(), AGENT_DRAFT_ACCOUNT_DATA_KEY_LENGTH);
        assert!(!key.contains('='));

        let parsed = parse_agent_draft_account_data_key(&key).unwrap();
        assert_eq!(parsed.agent_digest_component(), AGENT_COMPONENT);
        assert_eq!(parsed.draft_digest_component(), DRAFT_COMPONENT);
        validate_agent_draft_account_data_key_source(&key, &agent(), DRAFT_LITERAL).unwrap();
    }

    #[test]
    fn parser_rejects_noncanonical_key_shapes() {
        let padded = format!(
            "{}:{}=:{}",
            AccountDataKey::AGENT_DRAFT_V1,
            &AGENT_COMPONENT[..AGENT_COMPONENT.len() - 1],
            DRAFT_COMPONENT
        );
        let mut short = KEY.to_owned();
        short.pop();
        let wrong_component_lengths = format!(
            "{}:{}:{}A",
            AccountDataKey::AGENT_DRAFT_V1,
            &AGENT_COMPONENT[..AGENT_COMPONENT.len() - 1],
            DRAFT_COMPONENT
        );
        let noncanonical_trailing_bits = format!(
            "{}:{}9:{}",
            AccountDataKey::AGENT_DRAFT_V1,
            &AGENT_COMPONENT[..AGENT_COMPONENT.len() - 1],
            DRAFT_COMPONENT
        );
        let wrong_prefix = KEY.replacen("ak.agent.draft.v1", "ak.agent.drafx.v1", 1);
        let mut extra_separator = KEY.replacen(":Hpc", "::Hpc", 1);
        extra_separator.pop();
        let old_literal = format!(
            "{}:{AGENT_LITERAL}:{DRAFT_LITERAL}",
            AccountDataKey::AGENT_DRAFT_V1
        );

        for invalid in [
            padded,
            short,
            wrong_component_lengths,
            noncanonical_trailing_bits,
            wrong_prefix,
            extra_separator,
            old_literal,
        ] {
            assert!(
                parse_agent_draft_account_data_key(&invalid).is_err(),
                "unexpectedly accepted {invalid}"
            );
        }
    }

    #[test]
    fn source_validation_rejects_wrong_domains_and_literals() {
        let agent_domain_reused_for_draft =
            key_with_domains(AGENT_DRAFT_KEY_AGENT_DOMAIN, AGENT_DRAFT_KEY_AGENT_DOMAIN);
        let draft_domain_reused_for_agent =
            key_with_domains(AGENT_DRAFT_KEY_DRAFT_DOMAIN, AGENT_DRAFT_KEY_DRAFT_DOMAIN);
        for wrong_domain_key in [agent_domain_reused_for_draft, draft_domain_reused_for_agent] {
            assert!(parse_agent_draft_account_data_key(&wrong_domain_key).is_ok());
            assert!(
                validate_agent_draft_account_data_key_source(
                    &wrong_domain_key,
                    &agent(),
                    DRAFT_LITERAL
                )
                .is_err()
            );
        }

        let wrong_agent = DidCoreId::new("ak:did_core:web:other-agent.example").unwrap();
        let wrong_agent_key = agent_draft_account_data_key(&wrong_agent, DRAFT_LITERAL).unwrap();
        let wrong_draft_key = agent_draft_account_data_key(&agent(), "draft-002").unwrap();
        assert!(
            validate_agent_draft_account_data_key_source(&wrong_agent_key, &agent(), DRAFT_LITERAL)
                .is_err()
        );
        assert!(
            validate_agent_draft_account_data_key_source(&wrong_draft_key, &agent(), DRAFT_LITERAL)
                .is_err()
        );
    }

    #[test]
    fn builder_rejects_draft_literals_outside_the_schema_floor() {
        assert!(agent_draft_account_data_key(&agent(), "").is_err());
        assert!(agent_draft_account_data_key(&agent(), "ak:draft:typed").is_err());
    }
}
