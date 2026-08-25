//! Push gateway endpoint methods on [`Client`].

use arkret_models_integration::{
    PushNotifyOutcome, PushNotifyRequestBody, PushRegisterDeviceOutcome,
    PushRegisterDeviceRequestBody,
};

use crate::{Client, Result};

impl Client {
    pub async fn push_register_device(
        &self,
        request: &PushRegisterDeviceRequestBody,
    ) -> Result<PushRegisterDeviceOutcome> {
        self.post("/_arkret/edge/push/register-device", request)
            .await
    }

    pub async fn push_notify(&self, request: &PushNotifyRequestBody) -> Result<PushNotifyOutcome> {
        self.post("/_arkret/edge/push/notify", request).await
    }
}
