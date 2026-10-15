//! Closed hosting-Station proxy to the current private PCR authority.

#[path = "generated/consent_private_contracts.rs"]
mod contracts;
use arkret_wire::{DidCoreId, Result, WireError};
use chrono::{DateTime, Utc};
pub use contracts::*;

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.into())
}

impl ConsentPrivateCommand {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::List(_) => "list",
            Self::Version(_) => "version",
            Self::Effects(_) => "effects",
            Self::InvitePolicy(_) => "invite_policy",
            Self::InviteDelivery(_) => "invite_delivery",
            Self::Request(_) => "request",
        }
    }

    pub fn writes_private_state(&self) -> bool {
        matches!(
            self,
            Self::InvitePolicy(_) | Self::InviteDelivery(_) | Self::Request(_)
        )
    }
}

impl ConsentPrivateCommandOutcome {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::List(_) => "list",
            Self::Version(_) => "version",
            Self::Effects(_) => "effects",
            Self::InvitePolicy(_) => "invite_policy",
            Self::InviteDelivery(_) => "invite_delivery",
            Self::Request(_) => "request",
        }
    }
}

impl ConsentPrivateProxyRequest {
    /// Shape and authenticated Source binding only. The receiver must still
    /// verify the holder's accepted inception, tenure, active device and root
    /// in the same private accepting transaction as its operation.
    pub fn validate_at(&self, source: &DidCoreId, at: DateTime<Utc>) -> Result<()> {
        let nonce = arkret_canonical::base64url_decode(&self.nonce)
            .map_err(|_| invalid("private proxy nonce must be canonical Base64URL"))?;
        if nonce.len() < 16
            || self.nonce.len() > 64
            || arkret_canonical::base64url_encode(&nonce) != self.nonce
            || source != &self.holder_account_id.station_id
            || self.expires_at <= at
            || self.expires_at > at + chrono::Duration::seconds(30)
        {
            return Err(invalid(
                "private proxy source, nonce or outstanding window mismatch",
            ));
        }
        match (&self.context, &self.command) {
            (ConsentPrivateContext::HolderSession(context), command)
                if matches!(
                    command,
                    ConsentPrivateCommand::List(_)
                        | ConsentPrivateCommand::Version(_)
                        | ConsentPrivateCommand::Effects(_)
                        | ConsentPrivateCommand::InvitePolicy(_)
                ) && context.actor_id.as_account_id() == Some(&self.holder_account_id) => {}
            (ConsentPrivateContext::Station(context), command)
                if matches!(
                    command,
                    ConsentPrivateCommand::InviteDelivery(_) | ConsentPrivateCommand::Request(_)
                ) && context.actor_id == arkret_wire::ActorId::service(source.clone()) => {}
            _ => {
                return Err(invalid(
                    "private proxy command and authenticated context mismatch",
                ));
            }
        }
        match &self.command {
            ConsentPrivateCommand::InvitePolicy(command) => {
                if command.body.account_id != self.holder_account_id {
                    return Err(invalid("private receive policy belongs to another holder"));
                }
            }
            ConsentPrivateCommand::Request(command) => {
                if command
                    .body
                    .requester_actor_id
                    .as_account_id()
                    .is_none_or(|account| &account.station_id != source)
                    || command.body.request.holder_account_id != self.holder_account_id
                {
                    return Err(invalid("private Consent request source or holder mismatch"));
                }
                command.body.request.validate()?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        crate::call_invitation::canonical_request_digest(self)
    }
}

impl ConsentPrivateProxyOutcome {
    /// Transport authentication and the independent current authority anchor
    /// are required in addition to these exact request/response bindings.
    pub fn validate_for_request(
        &self,
        request: &ConsentPrivateProxyRequest,
        at: DateTime<Utc>,
    ) -> Result<()> {
        if self.request_digest != request.digest()?
            || self.realm_id != request.realm_id
            || self.governance_generation != request.governance_generation
            || self.effective_stream_head.stream_ref
                != (arkret_wire::CommitStreamRef::Realm {
                    realm_id: request.realm_id.clone(),
                })
            || self.outcome.kind() != request.command.kind()
            || self.evaluated_at > at
            || self.expires_at <= at
            || self.expires_at <= self.evaluated_at
            || self.expires_at > request.expires_at
            || self.expires_at > self.evaluated_at + chrono::Duration::seconds(30)
        {
            return Err(invalid(
                "private proxy outcome does not bind the outstanding current request",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AccountId, ActorId, CommitStreamHead, CommitStreamRef, DeviceId, RealmCommitId, RealmId,
    };

    use super::*;

    fn request() -> ConsentPrivateProxyRequest {
        let holder = AccountId::new(
            DidCoreId::new("ak:did_core:web:holder.example").unwrap(),
            DidCoreId::new("ak:did_core:web:hosting.example").unwrap(),
        );
        ConsentPrivateProxyRequest {
            holder_account_id: holder.clone(),
            realm_id: RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [31; 32],
            )),
            governance_generation: 2,
            nonce: arkret_canonical::base64url_encode([7; 16]),
            expires_at: "2026-10-15T00:00:20.000Z".parse().unwrap(),
            context: ConsentPrivateContext::HolderSession(ConsentPrivateHolderSessionContext {
                kind: ConsentPrivateHolderSessionContextKind::HolderSession,
                actor_id: ActorId::account(holder),
                device_id: DeviceId::new("ak:device:01900000-0000-7000-8000-000000000001").unwrap(),
            }),
            command: ConsentPrivateCommand::List(ConsentPrivateListCommand {
                kind: ConsentPrivateListCommandKind::List,
                body: ConsentPrivateEmptyBody {},
            }),
        }
    }

    #[test]
    fn private_proxy_binds_complete_holder_source_context_and_window() {
        let request = request();
        let at = "2026-10-15T00:00:00.000Z".parse().unwrap();
        let source = &request.holder_account_id.station_id;
        request.validate_at(source, at).unwrap();
        assert!(
            request
                .validate_at(
                    &DidCoreId::new("ak:did_core:web:other.example").unwrap(),
                    at
                )
                .is_err()
        );
        assert!(request.validate_at(source, request.expires_at).is_err());
        let mut wrong = request.clone();
        wrong.expires_at = at + chrono::Duration::seconds(31);
        assert!(wrong.validate_at(source, at).is_err());
        wrong = request.clone();
        wrong.context = ConsentPrivateContext::Station(ConsentPrivateStationContext {
            kind: ConsentPrivateStationContextKind::Station,
            actor_id: ActorId::service(source.clone()),
        });
        assert!(wrong.validate_at(source, at).is_err());
        let mut value = serde_json::to_value(&request).unwrap();
        value["command"]["kind"] = serde_json::json!("account_data_write");
        assert!(serde_json::from_value::<ConsentPrivateProxyRequest>(value).is_err());
    }

    #[test]
    fn private_proxy_outcome_cannot_rebind_a_request_or_extend_its_window() {
        let request = request();
        let at = "2026-10-15T00:00:00.000Z".parse().unwrap();
        let outcome = ConsentPrivateProxyOutcome {
            request_digest: request.digest().unwrap(),
            realm_id: request.realm_id.clone(),
            governance_generation: 2,
            effective_stream_head: CommitStreamHead {
                stream_ref: CommitStreamRef::Realm {
                    realm_id: request.realm_id.clone(),
                },
                stream_position: 9,
                commit_id: RealmCommitId::from_digest([17; 32]),
            },
            evaluated_at: at,
            expires_at: request.expires_at,
            outcome: ConsentPrivateCommandOutcome::List(ConsentPrivateListOutcome {
                kind: ConsentPrivateListOutcomeKind::List,
                body: crate::consent_operations::ConsentList { consents: vec![] },
            }),
        };
        outcome.validate_for_request(&request, at).unwrap();
        let mut changed = request.clone();
        changed.nonce = arkret_canonical::base64url_encode([8; 16]);
        assert!(outcome.validate_for_request(&changed, at).is_err());
        let mut wrong = outcome.clone();
        wrong.governance_generation = 1;
        assert!(wrong.validate_for_request(&request, at).is_err());
        wrong = outcome;
        wrong.expires_at = request.expires_at + chrono::Duration::milliseconds(1);
        assert!(wrong.validate_for_request(&request, at).is_err());
        assert!(
            serde_json::from_value::<ConsentPrivateEffects>(
                serde_json::json!({"holder_quarantine":null,"invite_delivery":null})
            )
            .is_err()
        );
    }

    #[test]
    fn private_handoff_commitment_binds_salt_and_complete_frozen_cut() {
        let request = request();
        let manifest = crate::authority_commit::PcrPrivateHandoffManifest {
            realm_id: request.realm_id.clone(),
            holder_account_id: request.holder_account_id,
            governance_generation: 2,
            effective_stream_head: CommitStreamHead {
                stream_ref: CommitStreamRef::Realm {
                    realm_id: request.realm_id,
                },
                stream_position: 9,
                commit_id: RealmCommitId::from_digest([17; 32]),
            },
            nonce: arkret_canonical::base64url_encode([7; 16]),
            state_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                b"complete native state",
            ))
            .unwrap(),
        };
        let original = manifest.digest().unwrap();
        let mut changed = manifest.clone();
        changed.nonce = arkret_canonical::base64url_encode([8; 16]);
        assert_ne!(original, changed.digest().unwrap());
        changed = manifest.clone();
        changed.effective_stream_head.stream_position += 1;
        assert_ne!(original, changed.digest().unwrap());
        changed = manifest;
        changed.state_digest =
            arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"partial state")).unwrap();
        assert_ne!(original, changed.digest().unwrap());
        changed.nonce = "short".into();
        assert!(changed.validate().is_err());
    }
}

impl ConsentPrivateEffects {
    pub fn validate_holder(&self, holder: &arkret_wire::AccountId) -> Result<()> {
        if let Some(cell) = &self.holder_quarantine {
            if cell.revision == 0 {
                return Err(invalid("private quarantine revision must be positive"));
            }
            cell.content.validate_holder(holder)?;
        }
        if let Some(cell) = &self.invite_delivery {
            if cell.revision == 0 {
                return Err(invalid("private delivery revision must be positive"));
            }
            cell.content.validate()?;
        }
        if let Some(cell) = &self.invite_receive_policy {
            if cell.revision == 0
                || cell.content.account_id != *holder
                || cell.content.schema
                    != crate::governance::invite_addressing::InviteReceivePolicy::SCHEMA
            {
                return Err(invalid(
                    "private receive policy revision, schema or holder mismatch",
                ));
            }
        }
        Ok(())
    }
}
impl ConsentPrivateEffectsPublishRequest {
    pub fn digest(&self) -> Result<String> {
        arkret_canonical::canonical_sha256(self).map_err(|e| invalid(&e.to_string()))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn validate_for_authority(
        &self,
        source: &DidCoreId,
        destination: &DidCoreId,
        realm: &arkret_wire::RealmId,
        current_service: &DidCoreId,
        generation: u64,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let nonce = arkret_canonical::base64url_decode(&self.nonce)
            .map_err(|_| invalid("private publication nonce is not canonical Base64URL"))?;
        if nonce.len() < 16
            || self.nonce.len() > 64
            || arkret_canonical::base64url_encode(&nonce) != self.nonce
            || destination != &self.holder_account_id.station_id
            || source != current_service
            || self.realm_id != *realm
            || self.governance_generation != generation
            || self.effective_stream_head.stream_ref
                != (arkret_wire::CommitStreamRef::Realm {
                    realm_id: realm.clone(),
                })
            || self.evaluated_at > at
            || self.expires_at <= at
            || self.expires_at <= self.evaluated_at
            || self.expires_at > self.evaluated_at + chrono::Duration::seconds(30)
        {
            return Err(invalid(
                "private publication source, holder, authority cut or outstanding window mismatch",
            ));
        }
        self.effects.validate_holder(&self.holder_account_id)
    }
}
impl ConsentPrivateEffectsPublishOutcome {
    pub fn validate_for_request(
        &self,
        request: &ConsentPrivateEffectsPublishRequest,
    ) -> Result<()> {
        if self.request_digest != request.digest()? {
            return Err(invalid(
                "private publication acknowledgement names another request",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    fn publication() -> ConsentPrivateEffectsPublishRequest {
        let holder = arkret_wire::AccountId::new(
            "ak:did_core:web:holder.example".parse().unwrap(),
            "ak:did_core:web:hosting.example".parse().unwrap(),
        );
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [21; 32],
        ));
        let at = "2026-10-15T00:00:00.000Z".parse().unwrap();
        ConsentPrivateEffectsPublishRequest {
            holder_account_id: holder,
            realm_id: realm.clone(),
            governance_generation: 2,
            nonce: arkret_canonical::base64url_encode([19; 32]),
            effective_stream_head: arkret_wire::CommitStreamHead {
                stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id: realm },
                stream_position: 9,
                commit_id: arkret_wire::RealmCommitId::from_digest([22; 32]),
            },
            evaluated_at: at,
            expires_at: at + chrono::Duration::seconds(30),
            effects: ConsentPrivateEffects {
                holder_quarantine: None,
                invite_delivery: None,
                invite_receive_policy: None,
            },
        }
    }
    #[test]
    fn effect_publication_requires_current_authority_exact_hosting_and_complete_cells() {
        let request = publication();
        let governor: DidCoreId = "ak:did_core:web:governor.example".parse().unwrap();
        let validate = |request: &ConsentPrivateEffectsPublishRequest| {
            request.validate_for_authority(
                &governor,
                &request.holder_account_id.station_id,
                &request.realm_id,
                &governor,
                2,
                request.evaluated_at,
            )
        };
        validate(&request).unwrap();
        assert!(
            request
                .validate_for_authority(
                    &request.holder_account_id.station_id,
                    &request.holder_account_id.station_id,
                    &request.realm_id,
                    &governor,
                    2,
                    request.evaluated_at
                )
                .is_err()
        );
        assert!(
            request
                .validate_for_authority(
                    &governor,
                    &governor,
                    &request.realm_id,
                    &governor,
                    2,
                    request.evaluated_at
                )
                .is_err()
        );
        assert!(
            request
                .validate_for_authority(
                    &governor,
                    &request.holder_account_id.station_id,
                    &request.realm_id,
                    &governor,
                    3,
                    request.evaluated_at
                )
                .is_err()
        );
        assert!(
            request
                .validate_for_authority(
                    &governor,
                    &request.holder_account_id.station_id,
                    &request.realm_id,
                    &governor,
                    2,
                    request.expires_at
                )
                .is_err()
        );
        let mut wrong = request.clone();
        wrong.expires_at += chrono::Duration::milliseconds(1);
        assert!(validate(&wrong).is_err());
        wrong = request.clone();
        wrong.nonce = "short".into();
        assert!(validate(&wrong).is_err());
        wrong = request.clone();
        let other = arkret_wire::AccountId::new(governor.clone(), governor.clone());
        wrong.effects.invite_receive_policy = Some(ConsentPrivateInviteReceivePolicyCell {
            revision: 1,
            content: crate::governance::invite_addressing::InviteReceivePolicy::spec_default(other),
        });
        assert!(validate(&wrong).is_err());
        let mut value = serde_json::to_value(&request).unwrap();
        value["effects"]
            .as_object_mut()
            .unwrap()
            .remove("holder_quarantine");
        assert!(serde_json::from_value::<ConsentPrivateEffectsPublishRequest>(value).is_err());
        let mut value = serde_json::to_value(&request).unwrap();
        value["effects"]["unregistered_key"] = serde_json::json!({});
        assert!(serde_json::from_value::<ConsentPrivateEffectsPublishRequest>(value).is_err());
        let ack = ConsentPrivateEffectsPublishOutcome {
            request_digest: request.digest().unwrap(),
            status: ConsentPrivateEffectsPublishStatus::Applied,
        };
        ack.validate_for_request(&request).unwrap();
        wrong = request.clone();
        wrong.nonce = arkret_canonical::base64url_encode([18; 32]);
        assert!(ack.validate_for_request(&wrong).is_err());
    }
}
