//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: schemas/device-message.schema.json; version=unversioned;
//! sha256=eba33021eeb75a47667b2171f79d406eaf003808650b434e2f8ef4ed0e3871c2
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
