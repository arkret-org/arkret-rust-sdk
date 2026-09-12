//! Validated, immutable Event submission states.
//!
//! [`arkret_wire::Event`] is the common wire envelope and intentionally uses
//! optional fields so it can deserialize every protocol plane. Producers must
//! not treat that representation as proof that an Event is ready to publish.
//! The types in this module consume and validate an Event, then expose it only
//! immutably so the CBS shape cannot be invalidated before submission.

use arkret_wire::{CbsEffectPlane, Event};

use crate::{Result, SchemaError, classify_event_execution, validate_event_for_submit};

fn actual_plane(event: &Event) -> Result<Option<CbsEffectPlane>> {
    classify_event_execution(event).map_err(|error| SchemaError::Protocol(error.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedEventPlane {
    Data,
    Control,
    NonReducer,
}

macro_rules! prepared_event_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name(Event);

        impl $name {
            #[must_use]
            pub fn event(&self) -> &Event {
                &self.0
            }

            #[must_use]
            pub fn into_event(self) -> Event {
                self.0
            }
        }

        impl AsRef<Event> for $name {
            fn as_ref(&self) -> &Event {
                self.event()
            }
        }
    };
}

prepared_event_newtype!(PreparedOrdinaryEvent);
prepared_event_newtype!(PreparedControlMove);
prepared_event_newtype!(PreparedNonReducerEvent);

impl TryFrom<Event> for PreparedOrdinaryEvent {
    type Error = SchemaError;

    fn try_from(event: Event) -> Result<Self> {
        validate_event_for_submit(&event)?;
        if actual_plane(&event)? != Some(CbsEffectPlane::Data)
            || event.auth_context.is_none()
            || event.seal_basis.is_some()
        {
            return Err(SchemaError::Protocol(
                "prepared ordinary Event requires auth_context and forbids seal_basis".to_owned(),
            ));
        }
        Ok(Self(event))
    }
}

impl TryFrom<Event> for PreparedControlMove {
    type Error = SchemaError;

    fn try_from(event: Event) -> Result<Self> {
        validate_event_for_submit(&event)?;
        if actual_plane(&event)? != Some(CbsEffectPlane::Control)
            || event.auth_context.is_some()
            || event.seal_basis.is_none()
        {
            return Err(SchemaError::Protocol(
                "prepared Control Move requires seal_basis and forbids auth_context".to_owned(),
            ));
        }
        Ok(Self(event))
    }
}

impl TryFrom<Event> for PreparedNonReducerEvent {
    type Error = SchemaError;

    fn try_from(event: Event) -> Result<Self> {
        validate_event_for_submit(&event)?;
        if event.kind.is_reducer_input()
            || actual_plane(&event)?.is_some()
            || event.auth_context.is_some()
            || event.seal_basis.is_some()
            || !event.preconditions.is_empty()
        {
            return Err(SchemaError::Protocol(
                "prepared non-reducer Event forbids all CBS reducer fields".to_owned(),
            ));
        }
        Ok(Self(event))
    }
}

/// A schema-validated Event in one of the ordinary (non-anchor) submission
/// planes. Anchor units remain an explicit ordered-batch protocol and cannot
/// be inferred from an Event with missing CBS fields.
#[derive(Clone, Debug, PartialEq)]
pub enum PreparedStandardEvent {
    Data(PreparedOrdinaryEvent),
    Control(PreparedControlMove),
    NonReducer(PreparedNonReducerEvent),
}

impl PreparedStandardEvent {
    #[must_use]
    pub const fn plane(&self) -> PreparedEventPlane {
        match self {
            Self::Data(_) => PreparedEventPlane::Data,
            Self::Control(_) => PreparedEventPlane::Control,
            Self::NonReducer(_) => PreparedEventPlane::NonReducer,
        }
    }

    #[must_use]
    pub fn event(&self) -> &Event {
        match self {
            Self::Data(event) => event.event(),
            Self::Control(event) => event.event(),
            Self::NonReducer(event) => event.event(),
        }
    }

    #[must_use]
    pub fn into_event(self) -> Event {
        match self {
            Self::Data(event) => event.into_event(),
            Self::Control(event) => event.into_event(),
            Self::NonReducer(event) => event.into_event(),
        }
    }
}

impl TryFrom<Event> for PreparedStandardEvent {
    type Error = SchemaError;

    fn try_from(event: Event) -> Result<Self> {
        validate_event_for_submit(&event)?;
        match actual_plane(&event)? {
            Some(CbsEffectPlane::Data) => PreparedOrdinaryEvent::try_from(event).map(Self::Data),
            Some(CbsEffectPlane::Control) => {
                PreparedControlMove::try_from(event).map(Self::Control)
            }
            None => PreparedNonReducerEvent::try_from(event).map(Self::NonReducer),
        }
    }
}

impl From<PreparedOrdinaryEvent> for PreparedStandardEvent {
    fn from(event: PreparedOrdinaryEvent) -> Self {
        Self::Data(event)
    }
}

impl From<PreparedControlMove> for PreparedStandardEvent {
    fn from(event: PreparedControlMove) -> Self {
        Self::Control(event)
    }
}

impl From<PreparedNonReducerEvent> for PreparedStandardEvent {
    fn from(event: PreparedNonReducerEvent) -> Self {
        Self::NonReducer(event)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AuthContext, DidCoreId, DidUrl, Event, Hash, Hlc, ProducerEventProof, RealmId, ScopeRef,
    };
    use serde_json::json;

    use super::*;

    fn message_event() -> Event {
        let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let mut event = arkret_wire::test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            },
            actor,
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            0,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            json!({
                "strand_id": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        )
        .unwrap();
        event.auth_context = Some(AuthContext {
            key_id: arkret_wire::OpaqueLocalId::new("agent-device").unwrap(),
            key_epoch: 0,
            credential_epoch: None,
            authority_refs: vec![
                arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "11".repeat(32))).unwrap(),
            ],
        });
        event.proofs.push(ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:agent.example#agent-device")
                .unwrap(),
            event_digest: Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            signer_resolution_evidence_ref: Some(
                arkret_wire::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "12".repeat(32)
                ))
                .unwrap(),
            ),
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "header.payload.signature".to_owned(),
        });
        event
    }

    #[test]
    fn prepared_ordinary_event_accepts_only_complete_data_plane_shape() {
        let prepared =
            PreparedOrdinaryEvent::try_from(message_event()).expect("prepared ordinary Event");
        assert_eq!(prepared.event().kind.as_str(), "ak.message.create");
    }

    #[test]
    fn prepared_ordinary_event_preserves_domain_preconditions() {
        let mut event = message_event();
        event.preconditions.push(arkret_wire::Precondition {
            cell_id: arkret_wire::CellRef::new(
                "ak:cell:ak.component.strand.object.v1:fixture".to_owned(),
            )
            .unwrap(),
            predicate: arkret_wire::Predicate {
                op: arkret_wire::PredicateOp::HeadEq,
                value: Some(serde_json::Value::Null),
                values: None,
                predicate_id: None,
            },
        });

        let prepared = PreparedOrdinaryEvent::try_from(event)
            .expect("ordinary Event may carry signed reducer preconditions");
        assert_eq!(prepared.event().preconditions.len(), 1);
    }

    #[test]
    fn prepared_ordinary_event_rejects_missing_authority_context() {
        let mut event = message_event();
        event.auth_context = None;

        assert!(PreparedOrdinaryEvent::try_from(event).is_err());
    }

    #[test]
    fn standard_event_classification_preserves_the_validated_plane() {
        let prepared = PreparedStandardEvent::try_from(message_event()).expect("prepared Event");
        assert_eq!(prepared.plane(), PreparedEventPlane::Data);
    }

    fn space_update(payload: serde_json::Value) -> Event {
        let mut event = message_event();
        event.kind = arkret_wire::EventKind::SpaceUpdate;
        event.payload = serde_json::from_value(payload).unwrap();
        event
    }

    fn with_control_basis(mut event: Event) -> Event {
        event.auth_context = None;
        event.seal_basis = Some(arkret_wire::SealBasis {
            leaves: vec![
                arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "11".repeat(32))).unwrap(),
            ],
        });
        event
    }

    #[test]
    fn conditional_metadata_update_remains_ordinary_without_an_ack() {
        let event = space_update(json!({
            "space_id": "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "patch": {"title": "renamed"}
        }));
        assert_eq!(
            classify_event_execution(&event).unwrap(),
            Some(CbsEffectPlane::Data)
        );
        assert_eq!(
            crate::project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            PreparedStandardEvent::try_from(event.clone())
                .unwrap()
                .plane(),
            PreparedEventPlane::Data
        );
        assert!(PreparedOrdinaryEvent::try_from(event.clone()).is_ok());
        assert!(PreparedControlMove::try_from(with_control_basis(event)).is_err());
    }

    #[test]
    fn conditional_policy_and_mixed_updates_are_atomic_control_commands() {
        for patch in [None, Some(json!({"title": "renamed"}))] {
            let mut event = space_update(json!({
                "space_id": "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "child_scope_policy": {"kind": "allow_any"}
            }));
            let expected_writes = if let Some(patch) = patch {
                event.payload.insert("patch".into(), patch);
                2
            } else {
                1
            };
            assert_eq!(
                classify_event_execution(&event).unwrap(),
                Some(CbsEffectPlane::Control)
            );
            assert_eq!(
                crate::project_registered_cell_writes(
                    &event,
                    arkret_canonical::DigestSuite::Sha256
                )
                .unwrap()
                .len(),
                expected_writes
            );
            assert!(PreparedOrdinaryEvent::try_from(event.clone()).is_err());
            assert!(PreparedStandardEvent::try_from(event.clone()).is_err());
            assert_eq!(
                PreparedStandardEvent::try_from(with_control_basis(event))
                    .unwrap()
                    .plane(),
                PreparedEventPlane::Control
            );
        }
    }

    #[test]
    fn reducer_with_no_selected_effect_is_not_an_ordinary_noop() {
        let event = space_update(json!({
            "space_id": "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        }));
        assert!(classify_event_execution(&event).is_err());
        assert!(PreparedStandardEvent::try_from(event).is_err());
    }
}
