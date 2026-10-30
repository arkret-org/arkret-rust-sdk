//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: schemas/device-message.schema.json;
//! sha256=08b2a6c7219dc79f3bdcc3b6d0603d7147166845d64e6358e6838583669260b8
//! Entries: actor_private_update_kinds=2

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActorPrivateUpdateKind {
    AccountDataUpdate,
    ReadCursorUpdate,
}

impl ActorPrivateUpdateKind {
    pub const ALL: &'static [Self] = &[Self::AccountDataUpdate, Self::ReadCursorUpdate];

    pub const ACCOUNT_DATA_UPDATE: &'static str = "ak.account_data.update";
    pub const READ_CURSOR_UPDATE: &'static str = "ak.read_cursor.update";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountDataUpdate => Self::ACCOUNT_DATA_UPDATE,
            Self::ReadCursorUpdate => Self::READ_CURSOR_UPDATE,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ACCOUNT_DATA_UPDATE => Some(Self::AccountDataUpdate),
            Self::READ_CURSOR_UPDATE => Some(Self::ReadCursorUpdate),
            _ => None,
        }
    }
}
