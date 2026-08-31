//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: schemas/device-message.schema.json; version=unversioned;
//! sha256=dc5e719cf780c20955785ea3ab96489b6253e7886246e451f784f3030d0ef975
//! Entries: actor_private_update_kinds=3

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActorPrivateUpdateKind {
    AccountBlocklistUpdate,
    AccountDataUpdate,
    ReadCursorUpdate,
}

impl ActorPrivateUpdateKind {
    pub const ALL: &'static [Self] = &[
        Self::AccountBlocklistUpdate,
        Self::AccountDataUpdate,
        Self::ReadCursorUpdate,
    ];

    pub const ACCOUNT_BLOCKLIST_UPDATE: &'static str = "ak.account.blocklist.update";
    pub const ACCOUNT_DATA_UPDATE: &'static str = "ak.account_data.update";
    pub const READ_CURSOR_UPDATE: &'static str = "ak.read_cursor.update";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountBlocklistUpdate => Self::ACCOUNT_BLOCKLIST_UPDATE,
            Self::AccountDataUpdate => Self::ACCOUNT_DATA_UPDATE,
            Self::ReadCursorUpdate => Self::READ_CURSOR_UPDATE,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ACCOUNT_BLOCKLIST_UPDATE => Some(Self::AccountBlocklistUpdate),
            Self::ACCOUNT_DATA_UPDATE => Some(Self::AccountDataUpdate),
            Self::READ_CURSOR_UPDATE => Some(Self::ReadCursorUpdate),
            _ => None,
        }
    }
}
