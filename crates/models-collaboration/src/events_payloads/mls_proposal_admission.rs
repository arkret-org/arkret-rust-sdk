//! Closed v1 support matrix for durable `ak.mls.proposal` producers.
//!
//! This is the Rust form of
//! `spec/v1/artifacts/registry/mls-proposal-admission-registry.json` and of
//! `zh/crypto-media/encryption-and-audit.md` §5.2.1. It lives in the shared SDK
//! on purpose: the matrix decides *which error code* a structurally valid but
//! unsupported Proposal gets, and a Station, a client engine and a conformance
//! runner that each kept their own copy would disagree about that code long
//! before they disagreed about the shape.
//!
//! The evaluation order is part of the contract, not an implementation detail,
//! which is why [`admit_durable_mls_proposal`] takes every fact at once instead
//! of exposing per-step predicates callers could run in their own order. An
//! implementation that compared the declared `proposal_type` token first would
//! report ExternalInit and unregistered AppCustom as `schema_violation` — the
//! declared token cannot match a type that has no token — and would therefore
//! be reporting a supported-feature decision as a malformed payload.

use arkret_wire::ErrorCode;

use super::mls::MlsProposalType;

/// RFC 9420 sender class of a durable Proposal, decoded from the PublicMessage
/// framing rather than declared by the producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlsProposalSenderClass {
    Member,
    External,
    NewMemberProposal,
    NewMemberCommit,
}

/// One `sender_classes[]` row of the canonical registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsProposalSenderClassDescriptor {
    pub canonical_id: &'static str,
    pub rfc9420_sender_type: &'static str,
    pub supported: bool,
    pub rejection_error: Option<ErrorCode>,
}

impl MlsProposalSenderClass {
    pub const ALL: &'static [Self] = &[
        Self::Member,
        Self::External,
        Self::NewMemberProposal,
        Self::NewMemberCommit,
    ];

    pub const fn descriptor(self) -> &'static MlsProposalSenderClassDescriptor {
        match self {
            Self::Member => &MlsProposalSenderClassDescriptor {
                canonical_id: "member",
                rfc9420_sender_type: "member",
                supported: true,
                rejection_error: None,
            },
            Self::External => &MlsProposalSenderClassDescriptor {
                canonical_id: "external",
                rfc9420_sender_type: "external",
                supported: false,
                rejection_error: Some(ErrorCode::UnsupportedFeature),
            },
            Self::NewMemberProposal => &MlsProposalSenderClassDescriptor {
                canonical_id: "new_member_proposal",
                rfc9420_sender_type: "new_member_proposal",
                supported: false,
                rejection_error: Some(ErrorCode::UnsupportedFeature),
            },
            Self::NewMemberCommit => &MlsProposalSenderClassDescriptor {
                canonical_id: "new_member_commit",
                rfc9420_sender_type: "new_member_commit",
                supported: false,
                rejection_error: Some(ErrorCode::UnsupportedFeature),
            },
        }
    }

    pub fn from_rfc9420_sender_type(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|class| class.descriptor().rfc9420_sender_type == value)
    }

    pub const fn is_supported(self) -> bool {
        self.descriptor().supported
    }
}

/// IANA MLS Proposal Types private-use range, inclusive (RFC 9420).
pub const MLS_PROPOSAL_PRIVATE_USE_RANGE: std::ops::RangeInclusive<u16> = 0xF000..=0xFFFF;

/// The RFC 9420 Proposal type actually decoded from `proposal_bytes_b64`.
///
/// This is deliberately a different type from [`MlsProposalType`]: that one is
/// the token the producer *declared* on the payload, and the whole point of
/// steps 5 and 6 is that the two are compared only after the decoded type has
/// been found supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlsDecodedProposalType {
    Add,
    Update,
    Remove,
    Psk,
    Reinit,
    ExternalInit,
    GroupContextExtensions,
    /// Any codepoint with no standard row. v1 registers no application
    /// Proposal semantics, so this is never admissible — including inside the
    /// private-use range, which conveys no authorization by itself.
    AppCustom(u16),
}

impl MlsDecodedProposalType {
    pub const ADD: u16 = 0x0001;
    pub const UPDATE: u16 = 0x0002;
    pub const REMOVE: u16 = 0x0003;
    pub const PSK: u16 = 0x0004;
    pub const REINIT: u16 = 0x0005;
    pub const EXTERNAL_INIT: u16 = 0x0006;
    pub const GROUP_CONTEXT_EXTENSIONS: u16 = 0x0007;

    #[must_use]
    pub const fn from_codepoint(codepoint: u16) -> Self {
        match codepoint {
            Self::ADD => Self::Add,
            Self::UPDATE => Self::Update,
            Self::REMOVE => Self::Remove,
            Self::PSK => Self::Psk,
            Self::REINIT => Self::Reinit,
            Self::EXTERNAL_INIT => Self::ExternalInit,
            Self::GROUP_CONTEXT_EXTENSIONS => Self::GroupContextExtensions,
            other => Self::AppCustom(other),
        }
    }

    #[must_use]
    pub const fn codepoint(self) -> Option<u16> {
        match self {
            Self::Add => Some(Self::ADD),
            Self::Update => Some(Self::UPDATE),
            Self::Remove => Some(Self::REMOVE),
            Self::Psk => Some(Self::PSK),
            Self::Reinit => Some(Self::REINIT),
            Self::ExternalInit => Some(Self::EXTERNAL_INIT),
            Self::GroupContextExtensions => Some(Self::GROUP_CONTEXT_EXTENSIONS),
            Self::AppCustom(codepoint) => Some(codepoint),
        }
    }

    /// The `mls_proposal_payload.proposal_type` token this decoded type must
    /// carry. `ExternalInit` has none: v1 has no external join, so there is no
    /// token to declare and a mismatch is not the reportable failure.
    #[must_use]
    pub const fn declared_token(self) -> Option<MlsProposalType> {
        match self {
            Self::Add => Some(MlsProposalType::Add),
            Self::Update => Some(MlsProposalType::Update),
            Self::Remove => Some(MlsProposalType::Remove),
            Self::Psk => Some(MlsProposalType::Psk),
            Self::Reinit => Some(MlsProposalType::Reinit),
            Self::GroupContextExtensions => Some(MlsProposalType::GroupContextExtensions),
            Self::AppCustom(_) => Some(MlsProposalType::AppCustom),
            Self::ExternalInit => None,
        }
    }

    /// Whether v1 admits this Proposal type at all. Every active row allows the
    /// `member` sender class and only that class.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::Update
                | Self::Remove
                | Self::Psk
                | Self::Reinit
                | Self::GroupContextExtensions
        )
    }

    #[must_use]
    pub const fn in_private_use_range(self) -> bool {
        match self {
            Self::AppCustom(codepoint) => {
                *MLS_PROPOSAL_PRIVATE_USE_RANGE.start() <= codepoint
                    && codepoint <= *MLS_PROPOSAL_PRIVATE_USE_RANGE.end()
            }
            _ => false,
        }
    }
}

/// One `application_proposal_types[]` row. Empty in v1: registry activation is
/// what authorizes an AppCustom codepoint, never the codepoint's numeric range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsApplicationProposalTypeDescriptor {
    pub codepoint: u16,
    pub application_semantics: &'static str,
}

/// v1 registers no application Proposal types.
pub const MLS_APPLICATION_PROPOSAL_TYPES: &[MlsApplicationProposalTypeDescriptor] = &[];

/// The two facts about a `member` sender that admission still has to establish
/// after the class and type rows pass.
///
/// They are booleans because the underlying material differs per consumer — a
/// Station reads its accepted base group state, a client engine reads its own
/// MLS group — while the *decision* they feed must not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsProposalMemberBinding {
    /// `sender.leaf_index` names a leaf occupied in the exact accepted base
    /// group state selected by `payload.base_epoch` and
    /// `governance_binding.previous_epoch` — not merely in some current state.
    pub leaf_occupied_in_exact_base: bool,
    /// That LeafNode's BasicCredential identity *and* signature key equal the
    /// verified Event producer (`executed_by ?? actor_id`).
    pub leaf_binds_verified_producer: bool,
}

/// Why a durable Proposal is refused, with the exact registered code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsProposalRejection {
    pub error_code: ErrorCode,
    pub reason: &'static str,
}

impl std::fmt::Display for MlsProposalRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.error_code.as_str(), self.reason)
    }
}

/// Run steps 4 through 7 of the fixed admission order for one durable
/// `ak.mls.proposal` on a Realm or Circle effective scope.
///
/// Steps 1 through 3 belong to the caller and must already have passed: payload
/// schema; decode, digest, group id and base epoch equality; PublicMessage wire
/// format. Those are the only failures that may be reported as
/// `schema_violation`.
///
/// `member_binding` is evaluated last and only for a supported member Proposal,
/// so a non-member sender can never be reported through a producer-binding
/// code, and an unsupported Proposal type can never be reported through a
/// declared-token mismatch.
pub fn admit_durable_mls_proposal(
    sender_class: MlsProposalSenderClass,
    decoded_proposal_type: MlsDecodedProposalType,
    declared_proposal_type: MlsProposalType,
    member_binding: MlsProposalMemberBinding,
) -> Result<(), MlsProposalRejection> {
    // Step 4: sender class.
    if let Some(error_code) = sender_class.descriptor().rejection_error {
        return Err(MlsProposalRejection {
            error_code,
            reason: "v1 durable Proposals accept only a Member sender of the exact base group",
        });
    }

    // Step 5: decoded Proposal type.
    if !decoded_proposal_type.is_supported() {
        return Err(MlsProposalRejection {
            error_code: ErrorCode::UnsupportedFeature,
            reason: match decoded_proposal_type {
                MlsDecodedProposalType::ExternalInit => {
                    "v1 has no external join, so ExternalInit has no admissible form"
                }
                _ => "the decoded Proposal codepoint has no active application registry row",
            },
        });
    }

    // Step 6: the declared token must agree with what actually decoded.
    if decoded_proposal_type.declared_token() != Some(declared_proposal_type) {
        return Err(MlsProposalRejection {
            error_code: ErrorCode::SchemaViolation,
            reason: "declared proposal_type does not equal the decoded Proposal type",
        });
    }

    // Step 7: the Member producer binding.
    if !member_binding.leaf_occupied_in_exact_base {
        return Err(MlsProposalRejection {
            error_code: ErrorCode::FailedPrecondition,
            reason: "the sender leaf is not occupied in the exact accepted base group state",
        });
    }
    if !member_binding.leaf_binds_verified_producer {
        return Err(MlsProposalRejection {
            error_code: ErrorCode::SignatureInvalid,
            reason: "the sender leaf credential and signature key do not equal the verified producer",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUND: MlsProposalMemberBinding = MlsProposalMemberBinding {
        leaf_occupied_in_exact_base: true,
        leaf_binds_verified_producer: true,
    };

    #[test]
    fn member_standard_types_stay_admissible() {
        for (decoded, declared) in [
            (MlsDecodedProposalType::Add, MlsProposalType::Add),
            (MlsDecodedProposalType::Update, MlsProposalType::Update),
            (MlsDecodedProposalType::Remove, MlsProposalType::Remove),
            (MlsDecodedProposalType::Psk, MlsProposalType::Psk),
            (MlsDecodedProposalType::Reinit, MlsProposalType::Reinit),
            (
                MlsDecodedProposalType::GroupContextExtensions,
                MlsProposalType::GroupContextExtensions,
            ),
        ] {
            admit_durable_mls_proposal(MlsProposalSenderClass::Member, decoded, declared, BOUND)
                .unwrap_or_else(|rejection| {
                    panic!("{decoded:?} must stay admissible: {rejection}")
                });
        }
    }

    #[test]
    fn non_member_senders_are_unsupported_not_malformed() {
        for class in [
            MlsProposalSenderClass::External,
            MlsProposalSenderClass::NewMemberProposal,
            MlsProposalSenderClass::NewMemberCommit,
        ] {
            let rejection = admit_durable_mls_proposal(
                class,
                MlsDecodedProposalType::Remove,
                MlsProposalType::Remove,
                BOUND,
            )
            .expect_err("non-member senders have no admissible v1 form");
            assert_eq!(rejection.error_code, ErrorCode::UnsupportedFeature);
        }
    }

    #[test]
    fn sender_class_and_type_are_decided_before_the_declared_token() {
        // ExternalInit has no declared token at all, so a token comparison run
        // first would necessarily mismatch and report schema_violation.
        let rejection = admit_durable_mls_proposal(
            MlsProposalSenderClass::Member,
            MlsDecodedProposalType::ExternalInit,
            MlsProposalType::Add,
            BOUND,
        )
        .expect_err("ExternalInit is unsupported");
        assert_eq!(rejection.error_code, ErrorCode::UnsupportedFeature);

        // An unregistered AppCustom codepoint declares the app_custom token
        // correctly; it is still unsupported, not malformed.
        let rejection = admit_durable_mls_proposal(
            MlsProposalSenderClass::Member,
            MlsDecodedProposalType::from_codepoint(0xF101),
            MlsProposalType::AppCustom,
            BOUND,
        )
        .expect_err("v1 registers no application Proposal types");
        assert_eq!(rejection.error_code, ErrorCode::UnsupportedFeature);
        assert!(MLS_APPLICATION_PROPOSAL_TYPES.is_empty());
        assert!(MlsDecodedProposalType::from_codepoint(0xF101).in_private_use_range());

        // An external sender carrying an unsupported type still reports the
        // sender class, because step 4 precedes step 5.
        let rejection = admit_durable_mls_proposal(
            MlsProposalSenderClass::External,
            MlsDecodedProposalType::ExternalInit,
            MlsProposalType::Add,
            BOUND,
        )
        .expect_err("external senders have no admissible v1 form");
        assert_eq!(rejection.error_code, ErrorCode::UnsupportedFeature);
        assert_eq!(
            rejection.reason,
            "v1 durable Proposals accept only a Member sender of the exact base group"
        );
    }

    #[test]
    fn a_real_token_mismatch_is_still_a_schema_violation() {
        let rejection = admit_durable_mls_proposal(
            MlsProposalSenderClass::Member,
            MlsDecodedProposalType::Remove,
            MlsProposalType::Add,
            BOUND,
        )
        .expect_err("a supported type declared as another type is malformed");
        assert_eq!(rejection.error_code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn member_producer_binding_separates_absence_from_impersonation() {
        let absent = admit_durable_mls_proposal(
            MlsProposalSenderClass::Member,
            MlsDecodedProposalType::Remove,
            MlsProposalType::Remove,
            MlsProposalMemberBinding {
                leaf_occupied_in_exact_base: false,
                leaf_binds_verified_producer: true,
            },
        )
        .expect_err("a leaf outside the exact base is not admissible");
        assert_eq!(absent.error_code, ErrorCode::FailedPrecondition);

        let mismatched = admit_durable_mls_proposal(
            MlsProposalSenderClass::Member,
            MlsDecodedProposalType::Remove,
            MlsProposalType::Remove,
            MlsProposalMemberBinding {
                leaf_occupied_in_exact_base: true,
                leaf_binds_verified_producer: false,
            },
        )
        .expect_err("a leaf that is not the verified producer is not admissible");
        assert_eq!(mismatched.error_code, ErrorCode::SignatureInvalid);
    }

    #[test]
    fn external_senders_group_context_extension_stays_registered_unsupported() {
        let row = arkret_wire::MLS_EXTENSIONS
            .iter()
            .find(|row| row.name == "external_senders")
            .expect("external_senders is a registered extension row");
        assert_eq!(row.status, "unsupported");
        assert_eq!(row.rejection_error, Some("unsupported_feature"));
        assert!(row.profile_id.is_none());
    }
}
