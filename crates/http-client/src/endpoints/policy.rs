//! Policy endpoint methods on [`Client`].

use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckOutcome, PolicyCheckRequestBody,
};

use crate::{Client, Result};

impl Client {
    pub async fn policy_check(
        &self,
        request: &PolicyCheckRequestBody,
    ) -> Result<PolicyCheckOutcome> {
        self.post("/_arkret/self/policy/check", request).await
    }
}
