use super::*;

/// Space membership operations.
impl Space {
    /// Create a join operation and update local membership state to joined.
    pub fn join_space(&self) -> Result<Operation> {
        let operation = self.create_join_operation()?;
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
            "target_did": user_id,
            "role": role,
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "invite", payload))
    }

    /// Create a join operation for the current user to join this space.
    pub fn create_join_operation(&self) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "join", payload))
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
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "leave", payload))
    }

    /// Create a ban operation for a user in this space.
    pub fn ban(&self, user_id: Did, reason: Option<String>) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({
            "target_did": user_id.as_str(),
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
        });
        if let Some(reason) = reason {
            payload["reason"] = json!(reason);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "ban", payload))
    }

    /// Create an unban operation for a user in this space.
    pub fn unban(&self, user_id: Did) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "target_did": user_id.as_str(),
            "space_id": self.space_id.as_str(),
            "actor_id": session_meta.user_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "unban", payload))
    }
}
