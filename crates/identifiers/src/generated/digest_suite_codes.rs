//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/digest-suite-registry.json; version=2026-09-12.9;
//! sha256=058dd9899654b807480d27c8df92e0b5e113a1cdd771f6736eb558aaf11cf966 Entries: active=2

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DigestSuiteCode {
    Sha256 = 0x01,
    Blake3 = 0x02,
}

impl DigestSuiteCode {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Blake3 => "blake3",
        }
    }

    pub const fn from_digest_suite(suite: arkret_canonical::DigestSuite) -> Self {
        match suite {
            arkret_canonical::DigestSuite::Sha256 => Self::Sha256,
            arkret_canonical::DigestSuite::Blake3 => Self::Blake3,
        }
    }

    pub const fn digest_suite(self) -> arkret_canonical::DigestSuite {
        match self {
            Self::Sha256 => arkret_canonical::DigestSuite::Sha256,
            Self::Blake3 => arkret_canonical::DigestSuite::Blake3,
        }
    }
}

impl TryFrom<u8> for DigestSuiteCode {
    type Error = crate::IdentifierError;

    fn try_from(value: u8) -> crate::Result<Self> {
        match value {
            0x01 => Ok(Self::Sha256),
            0x02 => Ok(Self::Blake3),
            _ => Err(crate::IdentifierError::InvalidId(format!(
                "unsupported digest suite code: 0x{value:02x}"
            ))),
        }
    }
}
