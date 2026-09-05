//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/account-data-key-registry.json; version=2026-09-05.2;
//! sha256=f9264874ccb6838a3eb561859e3634dc2c530392c0adfb4c74a85c018f9f64bf
//! Entries: account_data_keys=24

use serde::{Deserialize, Serialize};

/// Registered Account Data key namespaces. The registry rows are key
/// *patterns*; this type carries the literal head of each pattern, which is
/// the value clients and servers compare against and the only place the
/// namespace literal is spelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum AccountDataKey {
    AccountBlocklist,
    AccountHolderQuarantine,
    AccountInviteDelivery,
    AgentDraftV1,
    AgentSidecarViewStateV1,
    ClientUiState,
    CollectionsStickers,
    ContactsActor,
    ContactsRealm,
    DndSchedule,
    DraftV1,
    FileTransferV1,
    NotificationsInbox,
    PresencePreference,
    PresenceVisibility,
    PushRules,
    ReadReceiptPreferences,
    RemindersV1,
    SavedV1,
    ScheduledSendV1,
    SearchIndexManifestV1,
    SnoozeV1,
    TagsRealm,
    ViewsPrivate,
}

impl AccountDataKey {
    pub const ALL: &'static [Self] = &[
        Self::AccountBlocklist,
        Self::AccountHolderQuarantine,
        Self::AccountInviteDelivery,
        Self::AgentDraftV1,
        Self::AgentSidecarViewStateV1,
        Self::ClientUiState,
        Self::CollectionsStickers,
        Self::ContactsActor,
        Self::ContactsRealm,
        Self::DndSchedule,
        Self::DraftV1,
        Self::FileTransferV1,
        Self::NotificationsInbox,
        Self::PresencePreference,
        Self::PresenceVisibility,
        Self::PushRules,
        Self::ReadReceiptPreferences,
        Self::RemindersV1,
        Self::SavedV1,
        Self::ScheduledSendV1,
        Self::SearchIndexManifestV1,
        Self::SnoozeV1,
        Self::TagsRealm,
        Self::ViewsPrivate,
    ];

    /// Holder-private personal blocklist. It affects only the holder's local projection,
    /// notifications, contact handling, and trusted holder-side filtering. Key pattern:
    /// `ak.account.blocklist`.
    pub const ACCOUNT_BLOCKLIST: &'static str = "ak.account.blocklist";
    /// Actor-private plaintext holder quarantine inbox for the two admission surfaces the consent
    /// gate defers under the default profile: invite delivery and
    /// ak.self.consent.command.request.v1. The recipient Station is the sole CAS writer; holder
    /// self PUT/DELETE and synthetic ak.account_data.set are forbidden. Accepted writes fan out as
    /// service-sender ak.account_data.update hints and MUST NOT expose contactability signals to
    /// the requester. Contact requests are metered by the same new-source quota but keep their own
    /// pending_incoming state and never produce an entry here. Key pattern:
    /// `ak.account.holder_quarantine`.
    pub const ACCOUNT_HOLDER_QUARANTINE: &'static str = "ak.account.holder_quarantine";
    /// Actor-private holder-side carrier for delivered directed-invite credentials on the notify
    /// branch (invite-addressing.md section 7). Written by the recipient Station through the
    /// delivery path, so the value is plaintext JSON (ak.schema.invite_delivery.v1), not a
    /// client-encrypted envelope; invite_token is a server-issued private locator that MUST NOT
    /// enter the Invite object or Realm history. Bounded CAS register: at most 200 entries, expired
    /// entries purged first, then oldest evicted; accepted writes fan out as ak.account_data.update
    /// actor-private device updates. Key pattern: `ak.account.invite_delivery`.
    pub const ACCOUNT_INVITE_DELIVERY: &'static str = "ak.account.invite_delivery";
    /// Controller-owned encrypted draft created when Station materializes an agent's
    /// ak.agent.draft.propose / ak.agent.action_request after capability / policy / accountability
    /// / risk check. Draft MUST NOT enter shared Realm history; publishing produces a new shared
    /// event referencing only an opaque digest. See private-objects.md §4.1. Key pattern:
    /// `ak.agent.draft.v1:<agent_id>:<draft_id>`.
    pub const AGENT_DRAFT_V1: &'static str = "ak.agent.draft.v1";
    /// Controller-private per-context Sidecar hosted-view state. controller_account_key is
    /// derive_account_data_key(RFC8785_JCS(controller_account_id)) from models/account-data.md
    /// section 2; the structured AccountId is never inserted directly into the colon-delimited key.
    /// Synchronizes display_mode (context_merged or sidecar_only), pin/collapse state, and HLC
    /// without changing either Strand, Track, access, read, watch, notification, or search state.
    /// Key pattern:
    /// `ak.agent.sidecar_view_state.v1:<controller_account_key>:<target_realm_id>:
    /// <target_strand_id>`.
    pub const AGENT_SIDECAR_VIEW_STATE_V1: &'static str = "ak.agent.sidecar_view_state.v1";
    /// Private client UI state such as sidebar, recent realms (canonical key recent_realms),
    /// language, and layout preferences. Key pattern: `ak.client.ui_state`.
    pub const CLIENT_UI_STATE: &'static str = "ak.client.ui_state";
    /// Principal-private custom emoji and sticker collection metadata.
    /// Key pattern: `ak.collections.stickers`.
    pub const COLLECTIONS_STICKERS: &'static str = "ak.collections.stickers";
    /// Principal-private holder-authored petname, explicitly confirmed PCR display-name baseline,
    /// note, tag, and pin metadata for one accepted human Contact peer.principal_id. Contact
    /// acceptance may initialize confirmed_display_name only from profile evidence displayed during
    /// acceptance and never auto-creates petname. principal_key is
    /// base64url(HMAC-SHA256(account_data_namespace_key, RFC8785_JCS(["ak.contacts.actor",
    /// peer.principal_id]))). Decrypted plaintext validates as ak.schema.contact_remark.v1. Key
    /// pattern: `ak.contacts.actor.<principal_key>`.
    pub const CONTACTS_ACTOR: &'static str = "ak.contacts.actor";
    /// Private local remark, note, tag, and pin metadata for a Realm.
    /// Key pattern: `ak.contacts.realm.<realm_id>`.
    pub const CONTACTS_REALM: &'static str = "ak.contacts.realm";
    /// Principal-private do-not-disturb schedule used by notification routing. Decrypted plaintext
    /// validates as ak.schema.dnd_schedule.v1. Key pattern: `ak.dnd_schedule`.
    pub const DND_SCHEDULE: &'static str = "ak.dnd_schedule";
    /// Principal-private cross-device draft sync key. Raw target_ref MUST NOT appear in the
    /// account-data key. Key pattern: `ak.draft.v1:<kind>:<target_key>:<slot_key>`.
    pub const DRAFT_V1: &'static str = "ak.draft.v1";
    /// Principal-private cross-device file transfer record keyed by an HMAC-derived transfer_key.
    /// Blob bytes are stored through ak.self.blob.*; raw blob_ref, filename, target device ids, and
    /// plaintext hashes MUST NOT appear in the account-data key. Key pattern:
    /// `ak.file_transfer.v1:<transfer_key>`.
    pub const FILE_TRANSFER_V1: &'static str = "ak.file_transfer.v1";
    /// Principal-private dismissed/archived state for one derived Notification. The encrypted value
    /// binds notification_id, state, HLC and device tie-break material; read/unread remains derived
    /// from the read cursor. Key pattern: `ak.notifications.inbox.<notification_id>`.
    pub const NOTIFICATIONS_INBOX: &'static str = "ak.notifications.inbox";
    /// Principal-private manual presence preference whose decrypted plaintext validates as the
    /// closed presence-preference schema: pinned manual_state (online/idle/dnd), temporary
    /// status_message override, and clears_at expiry. Enforced client-side at send time across all
    /// of the principal's devices; services MUST NOT require plaintext or a projection of this key
    /// and MUST NOT treat it as a policy projection surface. Key pattern:
    /// `ak.presence.preference`.
    pub const PRESENCE_PREFERENCE: &'static str = "ak.presence.preference";
    /// Principal-private sender-side presence visibility policy. Decrypted plaintext validates as
    /// the closed presence-visibility schema. Station sync surfaces MUST NOT project or read
    /// presence_visibility; encrypted Signal fanout is selected by the sender according to
    /// profiles-presence.md section 3.4. Key pattern: `ak.presence.visibility`.
    pub const PRESENCE_VISIBILITY: &'static str = "ak.presence.visibility";
    /// Principal-private notification and push rule configuration.
    /// Key pattern: `ak.push_rules`.
    pub const PUSH_RULES: &'static str = "ak.push_rules";
    /// Private read-receipt send/display defaults and per-Realm or per-Strand overrides.
    /// Key pattern: `ak.read_receipt.preferences`.
    pub const READ_RECEIPT_PREFERENCES: &'static str = "ak.read_receipt.preferences";
    /// Principal-private reminders keyed by opaque id; target_ref and note remain inside encrypted
    /// value. Key pattern: `ak.reminders.v1:<id>`.
    pub const REMINDERS_V1: &'static str = "ak.reminders.v1";
    /// Principal-private saved item in an HMAC-derived collection; each item is an independent
    /// account-data value. Key pattern: `ak.saved.v1:<collection_key>:<target_key>`.
    pub const SAVED_V1: &'static str = "ak.saved.v1";
    /// Principal-private scheduled-send plan keyed by an independent producer-allocated
    /// ScheduledSendId. The plan carries no future EventId or MessageId. Dispatch derives the final
    /// EventId only after the complete canonical Event preimage exists, then retypes that Event
    /// token into MessageId. Key pattern: `ak.scheduled_send.v1:<scheduled_send_id>`.
    pub const SCHEDULED_SEND_V1: &'static str = "ak.scheduled_send.v1";
    /// Encrypted client search-index manifest keyed by an HMAC-derived realm_key.
    /// Key pattern: `ak.search.index_manifest.v1:<realm_key>`.
    pub const SEARCH_INDEX_MANIFEST_V1: &'static str = "ak.search.index_manifest.v1";
    /// Principal-private snooze state keyed by HMAC-derived target_key.
    /// Key pattern: `ak.snooze.v1:<target_key>`.
    pub const SNOOZE_V1: &'static str = "ak.snooze.v1";
    /// Private per-Realm tags and ordering hints.
    /// Key pattern: `ak.tags.realm.<realm_id>`.
    pub const TAGS_REALM: &'static str = "ak.tags.realm";
    /// Actor-private View definition. The encrypted value validates as ak.schema.view.v1 with
    /// visibility=private; it never enters a shared Realm View cell. Key pattern:
    /// `ak.views.private.<view_id>`.
    pub const VIEWS_PRIVATE: &'static str = "ak.views.private";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountBlocklist => Self::ACCOUNT_BLOCKLIST,
            Self::AccountHolderQuarantine => Self::ACCOUNT_HOLDER_QUARANTINE,
            Self::AccountInviteDelivery => Self::ACCOUNT_INVITE_DELIVERY,
            Self::AgentDraftV1 => Self::AGENT_DRAFT_V1,
            Self::AgentSidecarViewStateV1 => Self::AGENT_SIDECAR_VIEW_STATE_V1,
            Self::ClientUiState => Self::CLIENT_UI_STATE,
            Self::CollectionsStickers => Self::COLLECTIONS_STICKERS,
            Self::ContactsActor => Self::CONTACTS_ACTOR,
            Self::ContactsRealm => Self::CONTACTS_REALM,
            Self::DndSchedule => Self::DND_SCHEDULE,
            Self::DraftV1 => Self::DRAFT_V1,
            Self::FileTransferV1 => Self::FILE_TRANSFER_V1,
            Self::NotificationsInbox => Self::NOTIFICATIONS_INBOX,
            Self::PresencePreference => Self::PRESENCE_PREFERENCE,
            Self::PresenceVisibility => Self::PRESENCE_VISIBILITY,
            Self::PushRules => Self::PUSH_RULES,
            Self::ReadReceiptPreferences => Self::READ_RECEIPT_PREFERENCES,
            Self::RemindersV1 => Self::REMINDERS_V1,
            Self::SavedV1 => Self::SAVED_V1,
            Self::ScheduledSendV1 => Self::SCHEDULED_SEND_V1,
            Self::SearchIndexManifestV1 => Self::SEARCH_INDEX_MANIFEST_V1,
            Self::SnoozeV1 => Self::SNOOZE_V1,
            Self::TagsRealm => Self::TAGS_REALM,
            Self::ViewsPrivate => Self::VIEWS_PRIVATE,
        }
    }

    /// Whether `value` is this key exactly, or a parameterized key inside
    /// this namespace (`<namespace>:<...>` or `<namespace>.<...>`).
    pub fn matches(self, value: &str) -> bool {
        let namespace = self.as_str();
        let Some(rest) = value.strip_prefix(namespace) else {
            return false;
        };
        rest.is_empty() || (matches!(rest.as_bytes().first(), Some(b':' | b'.')) && rest.len() > 1)
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ACCOUNT_BLOCKLIST => Some(Self::AccountBlocklist),
            Self::ACCOUNT_HOLDER_QUARANTINE => Some(Self::AccountHolderQuarantine),
            Self::ACCOUNT_INVITE_DELIVERY => Some(Self::AccountInviteDelivery),
            Self::AGENT_DRAFT_V1 => Some(Self::AgentDraftV1),
            Self::AGENT_SIDECAR_VIEW_STATE_V1 => Some(Self::AgentSidecarViewStateV1),
            Self::CLIENT_UI_STATE => Some(Self::ClientUiState),
            Self::COLLECTIONS_STICKERS => Some(Self::CollectionsStickers),
            Self::CONTACTS_ACTOR => Some(Self::ContactsActor),
            Self::CONTACTS_REALM => Some(Self::ContactsRealm),
            Self::DND_SCHEDULE => Some(Self::DndSchedule),
            Self::DRAFT_V1 => Some(Self::DraftV1),
            Self::FILE_TRANSFER_V1 => Some(Self::FileTransferV1),
            Self::NOTIFICATIONS_INBOX => Some(Self::NotificationsInbox),
            Self::PRESENCE_PREFERENCE => Some(Self::PresencePreference),
            Self::PRESENCE_VISIBILITY => Some(Self::PresenceVisibility),
            Self::PUSH_RULES => Some(Self::PushRules),
            Self::READ_RECEIPT_PREFERENCES => Some(Self::ReadReceiptPreferences),
            Self::REMINDERS_V1 => Some(Self::RemindersV1),
            Self::SAVED_V1 => Some(Self::SavedV1),
            Self::SCHEDULED_SEND_V1 => Some(Self::ScheduledSendV1),
            Self::SEARCH_INDEX_MANIFEST_V1 => Some(Self::SearchIndexManifestV1),
            Self::SNOOZE_V1 => Some(Self::SnoozeV1),
            Self::TAGS_REALM => Some(Self::TagsRealm),
            Self::VIEWS_PRIVATE => Some(Self::ViewsPrivate),
            _ => None,
        }
    }

    /// Resolve a concrete Account Data key to its registered namespace.
    pub fn for_key(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|key| key.matches(value))
    }
}

impl std::fmt::Display for AccountDataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AccountDataKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AccountDataKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown account data key: {raw}")))
    }
}
