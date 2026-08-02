//! Push gateway endpoint methods on [`Client`].

use arkret_models_integration::{
    OkOutcome, PushNotifyOutcome, PushNotifyRequestBody, PushRegisterDeviceOutcome,
    PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
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

    pub async fn push_unregister_device(
        &self,
        request: &PushUnregisterDeviceRequestBody,
    ) -> Result<OkOutcome> {
        self.post("/_arkret/edge/push/unregister-device", request)
            .await
    }

    pub async fn push_notify(&self, request: &PushNotifyRequestBody) -> Result<PushNotifyOutcome> {
        self.post("/_arkret/edge/push/notify", request).await
    }
}
