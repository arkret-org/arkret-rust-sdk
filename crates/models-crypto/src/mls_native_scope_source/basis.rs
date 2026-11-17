//! Private G byte projection; a typed value never proves native completeness.
use super::*;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsNativeScopeBasisDomain {
    #[serde(rename = "ak.mls.native_scope_basis.v1")]
    NativeScopeBasisV1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsNativeScopeCoveredAuthorization {
    pub actor_id: ActorId,
    pub endpoint: arkret_wire::MlsWelcomeRecipientEndpoint,
    pub authorization_event_ref: EventId,
}

impl From<&ContentEndpoint> for MlsNativeScopeCoveredAuthorization {
    fn from(endpoint: &ContentEndpoint) -> Self {
        Self {
            actor_id: endpoint.actor_id.clone(),
            endpoint: endpoint.endpoint.clone(),
            authorization_event_ref: endpoint.authorization_event_ref.clone(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsNativeScopeFenceBasisEntry {
    pub intent_digest: Hash,
    pub covered_authorizations: Vec<MlsNativeScopeCoveredAuthorization>,
}

impl MlsNativeScopeFenceBasisEntry {
    /// Call only for an installed fence with its genuine canonical first source
    /// and complete native coverage. A failed-precondition reservation is not a
    /// fence. Raw MLS keys are intentionally absent from the permanent predicate.
    pub fn from_installed_source(
        original: &crate::ContentRecoveryScopeCleanupAuthorization,
        complete_covered: &[ContentEndpoint],
    ) -> arkret_wire::Result<Self> {
        let mut covered = std::collections::BTreeMap::new();
        for endpoint in complete_covered {
            endpoint.validate()?;
            if endpoint.actor_id != original.replacement.actor_id {
                return Err(invalid("fence coverage changed complete subject"));
            }
            let value = MlsNativeScopeCoveredAuthorization::from(endpoint);
            covered.insert(arkret_canonical::canonical_json_bytes(&value)?, value);
        }
        Ok(Self {
            intent_digest: original.intent_digest()?,
            covered_authorizations: covered.into_values().collect(),
        })
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsNativeScopeBasis {
    pub domain: MlsNativeScopeBasisDomain,
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub governance_authority_ref: RealmCommitAuthorityRef,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub genesis_event_ref: Option<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub sidecar_membership_basis: Option<MlsNativeScopeMembershipBasis>,
    pub endpoint_fences: Vec<MlsNativeScopeFenceBasisEntry>,
}

impl MlsNativeScopeBasis {
    /// Only the exact private byte ordering/deduplication from the formal
    /// owner. Real G source completeness and current cut are not inferred.
    pub fn canonicalized(&self) -> arkret_wire::Result<Self> {
        let mut value = self.clone();
        if value.effective_scope.realm_id_opt() != Some(&value.realm_id) {
            return Err(invalid("private basis Realm differs"));
        }
        match (&value.effective_scope, &mut value.sidecar_membership_basis) {
            (ScopeRef::Sidecar { sidecar_id, .. }, Some(basis)) => {
                if sidecar_id != &basis.sidecar_id
                    || basis.sidecar_id != SidecarId::from_event_id(&basis.sidecar_create_event_ref)
                {
                    return Err(invalid("private basis immutable Sidecar Create differs"));
                }
                let mut candidates = std::collections::BTreeMap::new();
                for candidate in std::mem::take(&mut basis.candidate_joins) {
                    let key = arkret_canonical::canonical_json_bytes(&candidate.agent_actor_id)?;
                    if candidates.insert(key, candidate).is_some() {
                        return Err(invalid("multiple current joins of one candidate"));
                    }
                }
                basis.candidate_joins = candidates.into_values().collect();
            }
            (ScopeRef::Sidecar { .. }, None) | (_, Some(_)) => {
                return Err(invalid("private basis membership scope misplaced"));
            }
            (_, None) => {}
        }
        for entry in &mut value.endpoint_fences {
            sha256_ref(&entry.intent_digest)?;
            let mut covered = std::collections::BTreeMap::new();
            for endpoint in std::mem::take(&mut entry.covered_authorizations) {
                covered.insert(arkret_canonical::canonical_json_bytes(&endpoint)?, endpoint);
            }
            entry.covered_authorizations = covered.into_values().collect();
        }
        value.endpoint_fences.sort_by(|a, b| {
            a.intent_digest
                .as_str()
                .as_bytes()
                .cmp(b.intent_digest.as_str().as_bytes())
        });
        if value
            .endpoint_fences
            .windows(2)
            .any(|pair| pair[0].intent_digest == pair[1].intent_digest)
        {
            return Err(invalid("duplicate installed native intent"));
        }
        Ok(value)
    }

    pub fn digest(&self) -> arkret_wire::Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical_sha256(
            &self.canonicalized()?,
        )?)?)
    }
}
