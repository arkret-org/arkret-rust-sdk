use crate::model::{CandidateError, CandidateValidationContext, MemberDeliveryBindingCandidate};

use super::*;

/// Space membership operations.
impl Space {
    /// Create a join operation and update local membership state to joined.
    ///
    /// Spec (commit 0a5ab85) requires `actor_id` + `delivery_status` on
    /// `membership=join`, with `delivery_binding` mandatory when
    /// `delivery_status=routable`. This convenience helper builds an
    /// unroutable join (membership without a concrete delivery target).
    /// Use [`Self::create_join_with_binding`] for the routable path.
    pub fn join_space(&self) -> Result<Operation> {
        let operation = self.create_join_operation()?;
        self.base_client.update_space_state(&self.space_id, SpaceStateType::Joined)?;
        Ok(operation)
    }

    /// Create a routable join operation that carries a concrete
    /// `member_delivery_binding`. Returns an error if the binding is
    /// internally inconsistent (see [`MemberDeliveryBinding::validate`]).
    pub fn join_space_with_binding(&self, binding: MemberDeliveryBinding) -> Result<Operation> {
        binding.validate()?;
        let operation = self.create_join_with_binding(binding)?;
        self.base_client.update_space_state(&self.space_id, SpaceStateType::Joined)?;
        Ok(operation)
    }

    /// Create a leave operation and update local membership state to left.
    pub fn leave_space(&self) -> Result<Operation> {
        let operation = self.create_leave_operation()?;
        self.base_client.update_space_state(&self.space_id, SpaceStateType::Left)?;
        Ok(operation)
    }

    /// Create an invite operation from a raw DID and role string.
    ///
    /// **Deprecated**: this builder bypasses the
    /// [`MemberDeliveryBindingCandidate`] validation surface defined in
    /// `identity-handles.md` §3.7. Callers MUST migrate to
    /// [`Self::invite_with_candidate`] or [`Self::member_add_with_candidate`]
    /// so that handle resolution / directory proofs / audience / expiry are
    /// enforced before the payload reaches the wire. The string-based path
    /// remains available for legacy fixtures and one-shot tooling but emits
    /// `delivery_status=unroutable`-shaped intent only.
    #[deprecated(
        since = "0.7.0",
        note = "use Space::invite_with_candidate / Space::member_add_with_candidate; \
                raw-DID invite skips MemberDeliveryBindingCandidate validation \
                (identity-handles.md §3.7)"
    )]
    pub fn invite(&self, user_id: Did, role: Option<String>) -> Result<Operation> {
        #[allow(deprecated)]
        self.create_invite_operation(user_id, role)
    }

    /// Create an invite operation for a user to join this space.
    ///
    /// **Deprecated**: see [`Self::invite`].
    #[deprecated(
        since = "0.7.0",
        note = "use Space::invite_with_candidate; raw-DID invite skips \
                MemberDeliveryBindingCandidate validation (identity-handles.md §3.7)"
    )]
    pub fn create_invite_operation(&self, user_id: Did, role: Option<String>) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "actor_id": user_id,
            "role": role,
            "space_id": self.space_id.as_str(),
            "issuer": session_meta.user_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.realm_id()?, OP_INVITE_CREATE, payload))
    }

    /// Build an invite operation from a validated
    /// [`MemberDeliveryBindingCandidate`].
    ///
    /// The candidate MUST come from `cx.directory.resolve_handle(intent="invite")`
    /// or a trusted issuer's signed payload. Per `identity-handles.md` §3.7
    /// the SDK only accepts a candidate or an already-materialised
    /// [`MemberDeliveryBinding`] at this entry point. The candidate is
    /// re-validated against `audience = target space id` and `now` before
    /// the operation is emitted; reducer-side Join Policy still applies
    /// independently.
    pub fn invite_with_candidate(
        &self,
        candidate: &MemberDeliveryBindingCandidate,
        role: Option<String>,
    ) -> Result<Operation> {
        let ctx = CandidateValidationContext::new(self.space_id.as_str().to_owned());
        candidate.validate(&ctx).map_err(map_candidate_err)?;

        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "actor_id": candidate.subject_id,
            "role": role,
            "space_id": self.space_id.as_str(),
            "issuer": session_meta.user_id.as_str(),
            "handle_uri": candidate.handle_uri.canonical(),
            "delivery_binding_candidate": candidate,
        });

        Ok(Operation::create(operation_id, self.realm_id()?, OP_INVITE_CREATE, payload))
    }

    /// Build a `member_add` (`cx.member.state{membership=join}`) operation
    /// from a validated [`MemberDeliveryBindingCandidate`].
    ///
    /// Reducer-side Join Policy still applies (the candidate is *input*,
    /// not authority). On success the payload carries both the typed
    /// candidate (for audit / replay) and a fully constructed
    /// `delivery_binding` so the reducer can land it as
    /// `cx.member.state{join}.delivery_binding` directly.
    pub fn member_add_with_candidate(
        &self,
        candidate: &MemberDeliveryBindingCandidate,
    ) -> Result<Operation> {
        let ctx = CandidateValidationContext::new(self.space_id.as_str().to_owned());
        candidate.validate(&ctx).map_err(map_candidate_err)?;

        let binding = candidate_to_delivery_binding(candidate);
        binding.validate()?;

        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "space_id": self.space_id.as_str(),
            "actor_id": candidate.subject_id,
            "issuer": session_meta.user_id.as_str(),
            "membership": "join",
            "delivery_status": DeliveryStatus::Routable,
            "delivery_binding": binding,
            "delivery_binding_candidate": candidate,
            "handle_uri": candidate.handle_uri.canonical(),
        });

        Ok(Operation::create(operation_id, self.realm_id()?, OP_MEMBER_STATE, payload))
    }

    /// Create a join operation for the current user to join this space.
    ///
    /// Produces an `unroutable` join — used when the current actor does
    /// not yet have an admissible delivery binding for this Space. The
    /// reducer is expected to accept the membership but suppress
    /// Space-scoped delivery until a rebind (`routable`) is issued.
    pub fn create_join_operation(&self) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
            "membership": "join",
            "delivery_status": DeliveryStatus::Unroutable,
        });

        Ok(Operation::create(operation_id, self.realm_id()?, OP_MEMBER_STATE, payload))
    }

    /// Create a `routable` join operation that carries a concrete
    /// [`MemberDeliveryBinding`]. The binding is serialised onto the
    /// `cx.member.state{join}` payload under `delivery_binding` per
    /// `event-payload.schema.json#/$defs/membership_payload`.
    pub fn create_join_with_binding(&self, binding: MemberDeliveryBinding) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
            "membership": "join",
            "delivery_status": DeliveryStatus::Routable,
            "delivery_binding": binding,
        });

        Ok(Operation::create(operation_id, self.realm_id()?, OP_MEMBER_STATE, payload))
    }

    /// Create a leave operation for the current user to leave this space.
    pub fn create_leave_operation(&self) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
            "membership": "leave",
        });

        Ok(Operation::create(operation_id, self.realm_id()?, OP_MEMBER_STATE, payload))
    }

    /// Create a ban operation for a user in this space.
    pub fn ban(&self, user_id: Did, reason: Option<String>) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({
            "actor_id": user_id.as_str(),
            "space_id": self.space_id.as_str(),
            "issuer": session_meta.user_id.as_str(),
            "membership": "ban",
        });
        if let Some(reason) = reason {
            payload["reason"] = json!(reason);
        }

        Ok(Operation::create(operation_id, self.realm_id()?, OP_MEMBER_STATE, payload))
    }

    /// Create an unban operation for a user in this space.
    pub fn unban(&self, user_id: Did) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "actor_id": user_id.as_str(),
            "space_id": self.space_id.as_str(),
            "issuer": session_meta.user_id.as_str(),
            "membership": "invite",
        });

        Ok(Operation::create(operation_id, self.realm_id()?, OP_MEMBER_STATE, payload))
    }
}

/// Materialise the candidate's `member_delivery_binding` into a fully formed
/// [`MemberDeliveryBinding`]. Callers MUST still run
/// [`MemberDeliveryBinding::validate`] before using the binding — this
/// helper only translates field-for-field; it does not enforce conditional
/// `binding_source` constraints (that is the reducer / validator's job).
fn candidate_to_delivery_binding(
    candidate: &MemberDeliveryBindingCandidate,
) -> MemberDeliveryBinding {
    use crate::model::{
        BindingScope, BindingSource, DeliveryMode, EventRef, HandleHintBindingSource,
        RecipientServiceType,
    };

    let hint = &candidate.member_delivery_binding;
    let binding_source = match hint.binding_source {
        HandleHintBindingSource::Explicit => BindingSource::Explicit,
        HandleHintBindingSource::Invite => BindingSource::Invite,
        HandleHintBindingSource::JoinPolicy => BindingSource::JoinPolicy,
        HandleHintBindingSource::OrganizationPolicy => BindingSource::OrganizationPolicy,
        HandleHintBindingSource::RealmPolicy => BindingSource::RealmPolicy,
    };
    let delivery_modes: std::collections::BTreeSet<DeliveryMode> = if hint.delivery_modes.is_empty()
    {
        [
            DeliveryMode::Events,
            DeliveryMode::Sync,
            DeliveryMode::ToDevice,
            DeliveryMode::KeyPackages,
        ]
        .into_iter()
        .collect()
    } else {
        hint.delivery_modes.iter().copied().collect()
    };
    let service_acceptance_ref = hint
        .service_acceptance_ref
        .as_ref()
        .map(|id| EventRef::new(id.clone(), "authorized_by".to_owned()));
    let policy_ref =
        hint.policy_ref.as_ref().map(|id| EventRef::new(id.clone(), "authorized_by".to_owned()));

    MemberDeliveryBinding {
        recipient_service_did: hint.recipient_service_did.clone(),
        recipient_service_type: RecipientServiceType::PrincipalServer,
        binding_scope: BindingScope::Realm,
        binding_source,
        delivery_modes,
        service_endpoint: None,
        did_document_hash: None,
        resolved_at: Utc::now(),
        service_acceptance_ref,
        holder_proof_ref: None,
        policy_ref,
        expires_at: Some(candidate.expires_at),
    }
}

/// Map a [`CandidateError`] into the SDK's generic [`crate::Error`] surface
/// so the builder methods can stay `Result<Operation>`.
fn map_candidate_err(err: CandidateError) -> crate::Error {
    crate::Error::Protocol(err.to_string())
}
