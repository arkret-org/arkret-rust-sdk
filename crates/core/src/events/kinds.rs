use serde::{Deserialize, Serialize};

pub const MESSAGE_TEXT: &str = "cx.message.text";
pub const MESSAGE_NOTICE: &str = "cx.message.notice";
pub const MESSAGE_EMOTE: &str = "cx.message.emote";
pub const MESSAGE_HTML: &str = "cx.message.html";
pub const MESSAGE_FILE: &str = "cx.message.file";
pub const MESSAGE_IMAGE: &str = "cx.message.image";
pub const MESSAGE_AUDIO: &str = "cx.message.audio";
pub const MESSAGE_VIDEO: &str = "cx.message.video";
pub const MESSAGE_VOICE: &str = "cx.message.voice";
pub const MESSAGE_DOCUMENT: &str = "cx.message.document";
pub const MESSAGE_LOCATION: &str = "cx.message.location";
pub const MESSAGE_STICKER: &str = "cx.message.sticker";
pub const MESSAGE_REACTION: &str = "cx.message.reaction";
pub const MESSAGE_POLL: &str = "cx.message.poll";
pub const MESSAGE_POLL_START: &str = "cx.message.poll.start";
pub const MESSAGE_POLL_RESPONSE: &str = "cx.message.poll.response";
pub const MESSAGE_POLL_END: &str = "cx.message.poll.end";
pub const MESSAGE_FORM_UPDATE: &str = "cx.message.form.update";
pub const MESSAGE_TASK_UPDATE: &str = "cx.message.task.update";
pub const MESSAGE_ACKNOWLEDGEMENT: &str = "cx.message.acknowledgement";
pub const MESSAGE_EPHEMERAL_INDICATOR: &str = "cx.message.ephemeral_indicator";
pub const MESSAGE_EDIT: &str = "cx.message.edit";
pub const MESSAGE_REDACTION: &str = "cx.message.redaction";

pub const STATE_MEMBERSHIP: &str = "cx.state.membership";
pub const STATE_PROFILE: &str = "cx.state.profile";
pub const STATE_POWER_LEVELS: &str = "cx.state.power_levels";
pub const STATE_POLICY: &str = "cx.state.policy";
pub const STATE_CAPABILITIES: &str = "cx.state.capabilities";
pub const STATE_TAGS: &str = "cx.state.tags";
pub const STATE_PINNED_EVENTS: &str = "cx.state.pinned_events";
pub const STATE_TOPIC: &str = "cx.state.topic";
pub const STATE_NAME: &str = "cx.state.name";
pub const STATE_AVATAR: &str = "cx.state.avatar";
pub const STATE_NOTIFICATION_SETTINGS: &str = "cx.state.notification_settings";

pub const EPHEMERAL_TYPING: &str = "cx.ephemeral.typing";
pub const EPHEMERAL_RECEIPT: &str = "cx.ephemeral.receipt";
pub const EPHEMERAL_READ_MARKER: &str = "cx.ephemeral.read_marker";
pub const EPHEMERAL_PRESENCE: &str = "cx.ephemeral.presence";
pub const EPHEMERAL_TRANSIENT_DEVICE: &str = "cx.ephemeral.transient_device";

pub const ACCOUNT_DATA_DIRECT_SPACES: &str = "cx.account_data.direct_spaces";
pub const ACCOUNT_DATA_IGNORED_USERS: &str = "cx.account_data.ignored_users";
pub const ACCOUNT_DATA_RECENT_EMOJI: &str = "cx.account_data.recent_emoji";
pub const ACCOUNT_DATA_DRAFT: &str = "cx.account_data.draft";
pub const ACCOUNT_DATA_SPACE_SETTINGS: &str = "cx.account_data.space_settings";

pub const E2EE_ENCRYPTED: &str = "cx.e2ee.encrypted";
pub const E2EE_ROOM_KEY: &str = "cx.e2ee.room_key";
pub const E2EE_FORWARDED_ROOM_KEY: &str = "cx.e2ee.forwarded_room_key";
pub const E2EE_KEY_REQUEST: &str = "cx.e2ee.key_request";
pub const E2EE_SECRET_REQUEST: &str = "cx.e2ee.secret_request";
pub const E2EE_SECRET_SEND: &str = "cx.e2ee.secret_send";
pub const E2EE_VERIFICATION: &str = "cx.e2ee.verification";
pub const KEY_VERIFICATION_REQUEST: &str = "cx.key.verification.request";
pub const KEY_VERIFICATION_READY: &str = "cx.key.verification.ready";
pub const KEY_VERIFICATION_START: &str = "cx.key.verification.start";
pub const KEY_VERIFICATION_ACCEPT: &str = "cx.key.verification.accept";
pub const KEY_VERIFICATION_KEY: &str = "cx.key.verification.key";
pub const KEY_VERIFICATION_MAC: &str = "cx.key.verification.mac";
pub const KEY_VERIFICATION_DONE: &str = "cx.key.verification.done";
pub const KEY_VERIFICATION_CANCEL: &str = "cx.key.verification.cancel";

pub const CALL_INVITE: &str = "cx.call.invite";
pub const CALL_ANSWER: &str = "cx.call.answer";
pub const CALL_CANDIDATES: &str = "cx.call.candidates";
pub const CALL_HANGUP: &str = "cx.call.hangup";
pub const CALL_NEGOTIATION: &str = "cx.call.negotiation";
pub const CALL_MEMBERSHIP: &str = "cx.call.membership";
pub const CALL_DEVICE_MAPPING: &str = "cx.call.device_mapping";
pub const RTC_SESSION: &str = "cx.rtc.session";

pub const COLLAB_OPERATION_BATCH: &str = "cx.collab.operation_batch";
pub const COLLAB_DOCUMENT_PATCH: &str = "cx.collab.document_patch";
pub const COLLAB_CURSOR: &str = "cx.collab.cursor";
pub const COLLAB_SELECTION: &str = "cx.collab.selection";
pub const COLLAB_COMPOSING: &str = "cx.collab.composing";
pub const COLLAB_PRESENCE: &str = "cx.collab.presence";
pub const COLLAB_ACTIVITY_BEACON: &str = "cx.collab.activity_beacon";

/// Broad class for routing, indexing and UI projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    Message,
    State,
    Ephemeral,
    AccountData,
    E2ee,
    Call,
    Rtc,
    Collaboration,
    Custom(String),
}

/// Classify a protocol event kind without deserializing its content.
pub fn classify_event_kind(kind: &str) -> EventClass {
    match kind {
        MESSAGE_TEXT
        | MESSAGE_NOTICE
        | MESSAGE_EMOTE
        | MESSAGE_HTML
        | MESSAGE_FILE
        | MESSAGE_IMAGE
        | MESSAGE_AUDIO
        | MESSAGE_VIDEO
        | MESSAGE_VOICE
        | MESSAGE_DOCUMENT
        | MESSAGE_LOCATION
        | MESSAGE_STICKER
        | MESSAGE_REACTION
        | MESSAGE_POLL
        | MESSAGE_POLL_START
        | MESSAGE_POLL_RESPONSE
        | MESSAGE_POLL_END
        | MESSAGE_FORM_UPDATE
        | MESSAGE_TASK_UPDATE
        | MESSAGE_ACKNOWLEDGEMENT
        | MESSAGE_EPHEMERAL_INDICATOR
        | MESSAGE_EDIT
        | MESSAGE_REDACTION => EventClass::Message,
        STATE_MEMBERSHIP
        | STATE_PROFILE
        | STATE_POWER_LEVELS
        | STATE_POLICY
        | STATE_CAPABILITIES
        | STATE_TAGS
        | STATE_PINNED_EVENTS
        | STATE_TOPIC
        | STATE_NAME
        | STATE_AVATAR
        | STATE_NOTIFICATION_SETTINGS => EventClass::State,
        EPHEMERAL_TYPING
        | EPHEMERAL_RECEIPT
        | EPHEMERAL_READ_MARKER
        | EPHEMERAL_PRESENCE
        | EPHEMERAL_TRANSIENT_DEVICE => EventClass::Ephemeral,
        ACCOUNT_DATA_DIRECT_SPACES
        | ACCOUNT_DATA_IGNORED_USERS
        | ACCOUNT_DATA_RECENT_EMOJI
        | ACCOUNT_DATA_DRAFT
        | ACCOUNT_DATA_SPACE_SETTINGS => EventClass::AccountData,
        E2EE_ENCRYPTED
        | E2EE_ROOM_KEY
        | E2EE_FORWARDED_ROOM_KEY
        | E2EE_KEY_REQUEST
        | E2EE_SECRET_REQUEST
        | E2EE_SECRET_SEND
        | E2EE_VERIFICATION
        | KEY_VERIFICATION_REQUEST
        | KEY_VERIFICATION_READY
        | KEY_VERIFICATION_START
        | KEY_VERIFICATION_ACCEPT
        | KEY_VERIFICATION_KEY
        | KEY_VERIFICATION_MAC
        | KEY_VERIFICATION_DONE
        | KEY_VERIFICATION_CANCEL => EventClass::E2ee,
        CALL_INVITE | CALL_ANSWER | CALL_CANDIDATES | CALL_HANGUP | CALL_NEGOTIATION
        | CALL_MEMBERSHIP | CALL_DEVICE_MAPPING => EventClass::Call,
        RTC_SESSION => EventClass::Rtc,
        COLLAB_OPERATION_BATCH
        | COLLAB_DOCUMENT_PATCH
        | COLLAB_CURSOR
        | COLLAB_SELECTION
        | COLLAB_COMPOSING
        | COLLAB_PRESENCE
        | COLLAB_ACTIVITY_BEACON => EventClass::Collaboration,
        _ => {
            if kind.starts_with("cx.message.") {
                EventClass::Message
            } else if kind.starts_with("cx.state.") {
                EventClass::State
            } else if kind.starts_with("cx.ephemeral.") {
                EventClass::Ephemeral
            } else if kind.starts_with("cx.account_data.") {
                EventClass::AccountData
            } else if kind.starts_with("cx.e2ee.") {
                EventClass::E2ee
            } else if kind.starts_with("cx.call.") {
                EventClass::Call
            } else if kind.starts_with("cx.rtc.") {
                EventClass::Rtc
            } else if kind.starts_with("cx.collab.") {
                EventClass::Collaboration
            } else {
                EventClass::Custom(kind.to_owned())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_and_prefix_event_kinds() {
        assert_eq!(classify_event_kind(MESSAGE_TEXT), EventClass::Message);
        assert_eq!(classify_event_kind(MESSAGE_POLL_RESPONSE), EventClass::Message);
        assert_eq!(classify_event_kind(STATE_MEMBERSHIP), EventClass::State);
        assert_eq!(classify_event_kind(CALL_DEVICE_MAPPING), EventClass::Call);
        assert_eq!(classify_event_kind(COLLAB_ACTIVITY_BEACON), EventClass::Collaboration);
        assert_eq!(classify_event_kind("cx.ephemeral.custom"), EventClass::Ephemeral);
        assert_eq!(
            classify_event_kind("vendor.example.widget"),
            EventClass::Custom("vendor.example.widget".to_owned())
        );
    }
}
