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
    pub fn join_space_with_binding(
        &self,
        binding: MemberDeliveryBinding,
    ) -> Result<Operation> {
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

    /// Create an invite operation.
    pub fn invite(&self, user_id: Did, role: Option<String>) -> Result<Operation> {
        self.create_invite_operation(user_id, role)
    }

    /// Create an invite operation for a user to join this space.
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

        Ok(Operation::create(operation_id, self.space_id.clone(), OP_INVITE_CREATE, payload))
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

        Ok(Operation::create(operation_id, self.space_id.clone(), OP_MEMBER_STATE, payload))
    }

    /// Create a `routable` join operation that carries a concrete
    /// [`MemberDeliveryBinding`]. The binding is serialised onto the
    /// `cx.member.state{join}` payload under `delivery_binding` per
    /// `event-payload.schema.json#/$defs/membership_payload`.
    pub fn create_join_with_binding(
        &self,
        binding: MemberDeliveryBinding,
    ) -> Result<Operation> {
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

        Ok(Operation::create(operation_id, self.space_id.clone(), OP_MEMBER_STATE, payload))
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

        Ok(Operation::create(operation_id, self.space_id.clone(), OP_MEMBER_STATE, payload))
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

        Ok(Operation::create(operation_id, self.space_id.clone(), OP_MEMBER_STATE, payload))
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

        Ok(Operation::create(operation_id, self.space_id.clone(), OP_MEMBER_STATE, payload))
    }
}
