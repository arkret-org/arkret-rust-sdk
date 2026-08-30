use std::collections::BTreeMap;
use std::marker::PhantomData;

use arkret_identifiers::{DeviceId, DeviceMessageId, DidCoreId};
use arkret_models_collaboration::objects::productivity::{
    FILE_TRANSFER_KEY_MESSAGE_KIND, FileTransferKeyMessage,
};
/// The single source of truth for standard non-Event device-message kinds.
pub use arkret_models_collaboration::sync_frames::account_sync::device_message_kind;
use arkret_models_collaboration::sync_frames::account_sync::{
    DeviceMessageTarget, DeviceMessagesSendRequestBody,
};
use arkret_models_crypto::MlsWelcomeEnvelope;
use arkret_models_identity::artifacts_device_identity::KeyVerificationContent;
use arkret_wire::ProtocolKind;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::{EventDraftError, Result};

mod private {
    pub trait Sealed {}
}

/// Marker binding one standard device-message `kind` to its content DTO.
pub trait DeviceMessageSpec: private::Sealed {
    type Content: Clone + Serialize;

    const KIND: &'static str;

    fn validate(content: &Self::Content) -> Result<()>;
}

/// Marker types for standard device-message products.
pub mod device_message_spec {
    #[derive(Clone, Copy, Debug)]
    pub struct FileTransferKey;
    #[derive(Clone, Copy, Debug)]
    pub struct MlsWelcome;
    #[derive(Clone, Copy, Debug)]
    pub struct KeyVerificationRequest;
    #[derive(Clone, Copy, Debug)]
    pub struct KeyVerificationReady;
    #[derive(Clone, Copy, Debug)]
    pub struct KeyVerificationStart;
    #[derive(Clone, Copy, Debug)]
    pub struct KeyVerificationAccept;
    #[derive(Clone, Copy, Debug)]
    pub struct KeyVerificationKey;
    #[derive(Clone, Copy, Debug)]
    pub struct KeyVerificationMac;
    #[derive(Clone, Copy, Debug)]
    pub struct KeyVerificationDone;
    #[derive(Clone, Copy, Debug)]
    pub struct KeyVerificationCancel;

    #[derive(Clone, Copy, Debug)]
    pub struct SecretRequest;
    #[derive(Clone, Copy, Debug)]
    pub struct SecretSend;
}

macro_rules! seal_specs {
    ($($spec:ty),+ $(,)?) => {
        $(impl private::Sealed for $spec {})+
    };
}

seal_specs!(
    device_message_spec::FileTransferKey,
    device_message_spec::MlsWelcome,
    device_message_spec::KeyVerificationRequest,
    device_message_spec::KeyVerificationReady,
    device_message_spec::KeyVerificationStart,
    device_message_spec::KeyVerificationAccept,
    device_message_spec::KeyVerificationKey,
    device_message_spec::KeyVerificationMac,
    device_message_spec::KeyVerificationDone,
    device_message_spec::KeyVerificationCancel,
);

seal_specs!(
    device_message_spec::SecretRequest,
    device_message_spec::SecretSend,
);

impl DeviceMessageSpec for device_message_spec::FileTransferKey {
    type Content = FileTransferKeyMessage;
    const KIND: &'static str = FILE_TRANSFER_KEY_MESSAGE_KIND;

    fn validate(content: &Self::Content) -> Result<()> {
        content
            .validate()
            .map_err(|error| EventDraftError::Protocol(error.to_string()))
    }
}

impl DeviceMessageSpec for device_message_spec::MlsWelcome {
    type Content = MlsWelcomeEnvelope;
    const KIND: &'static str = device_message_kind::MLS_WELCOME_V1;

    fn validate(_content: &Self::Content) -> Result<()> {
        Ok(())
    }
}

impl DeviceMessageSpec for device_message_spec::SecretRequest {
    type Content = arkret_models_crypto::SecretShareRequestContent;
    const KIND: &'static str = arkret_wire::SECRET_REQUEST_KIND;

    fn validate(content: &Self::Content) -> Result<()> {
        content
            .validate()
            .map_err(|error| EventDraftError::Protocol(error.to_string()))
    }
}

impl DeviceMessageSpec for device_message_spec::SecretSend {
    type Content = arkret_models_crypto::SecretShareSendContent;
    const KIND: &'static str = arkret_wire::SECRET_SEND_KIND;

    fn validate(content: &Self::Content) -> Result<()> {
        content
            .validate()
            .map_err(|error| EventDraftError::Protocol(error.to_string()))
    }
}

fn require<T>(value: &Option<T>, field: &str) -> Result<()> {
    if value.is_none() {
        return Err(EventDraftError::Protocol(format!(
            "device-message content requires {field}"
        )));
    }
    Ok(())
}

macro_rules! key_verification_spec {
    ($spec:ty, $kind:expr, [$($field:ident),* $(,)?]) => {
        impl DeviceMessageSpec for $spec {
            type Content = KeyVerificationContent;
            const KIND: &'static str = $kind;

            fn validate(content: &Self::Content) -> Result<()> {
                let _ = content;
                $(require(&content.$field, stringify!($field))?;)*
                Ok(())
            }
        }
    };
}

key_verification_spec!(
    device_message_spec::KeyVerificationRequest,
    device_message_kind::KEY_VERIFICATION_REQUEST,
    [methods, timestamp, expires_at]
);
key_verification_spec!(
    device_message_spec::KeyVerificationReady,
    device_message_kind::KEY_VERIFICATION_READY,
    [methods]
);
key_verification_spec!(
    device_message_spec::KeyVerificationStart,
    device_message_kind::KEY_VERIFICATION_START,
    [method]
);
key_verification_spec!(
    device_message_spec::KeyVerificationAccept,
    device_message_kind::KEY_VERIFICATION_ACCEPT,
    [commitment]
);
key_verification_spec!(
    device_message_spec::KeyVerificationKey,
    device_message_kind::KEY_VERIFICATION_KEY,
    [key]
);
key_verification_spec!(
    device_message_spec::KeyVerificationMac,
    device_message_kind::KEY_VERIFICATION_MAC,
    [mac, keys]
);
key_verification_spec!(
    device_message_spec::KeyVerificationDone,
    device_message_kind::KEY_VERIFICATION_DONE,
    []
);
key_verification_spec!(
    device_message_spec::KeyVerificationCancel,
    device_message_kind::KEY_VERIFICATION_CANCEL,
    [code]
);

/// Typed builder for one standard device-message target.
#[derive(Clone, Debug)]
pub struct TypedDeviceMessageTarget<K: DeviceMessageSpec> {
    device_message_id: DeviceMessageId,
    expires_at: DateTime<Utc>,
    content: K::Content,
    marker: PhantomData<K>,
}

impl<K: DeviceMessageSpec> TypedDeviceMessageTarget<K> {
    pub fn new(
        device_message_id: DeviceMessageId,
        expires_at: DateTime<Utc>,
        content: K::Content,
    ) -> Result<Self> {
        K::validate(&content)?;
        Ok(Self {
            device_message_id,
            expires_at,
            content,
            marker: PhantomData,
        })
    }

    pub fn build(self) -> Result<DeviceMessageTarget> {
        let content = serde_json::to_value(self.content)?;
        let Value::Object(content) = content else {
            return Err(EventDraftError::Protocol(
                "device-message content must serialize as an object".to_owned(),
            ));
        };
        Ok(DeviceMessageTarget {
            device_message_id: self.device_message_id,
            kind: ProtocolKind::new(K::KIND)
                .map_err(|error| EventDraftError::Protocol(error.to_owned()))?,
            expires_at: self.expires_at,
            content: content.into_iter().collect::<BTreeMap<_, _>>(),
        })
    }

    /// Build the one-recipient batch for the addressed Station's device queue.
    pub fn single_recipient(
        self,
        principal_id: DidCoreId,
        device_id: DeviceId,
    ) -> Result<DeviceMessagesSendRequestBody> {
        let mut by_device = BTreeMap::new();
        by_device.insert(device_id, self.build()?);
        let mut messages = BTreeMap::new();
        messages.insert(principal_id, by_device);
        Ok(DeviceMessagesSendRequestBody { messages })
    }
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{DeviceId, DeviceMessageId, DidCoreId, Hash};
    use arkret_models_crypto::{MlsEndpointIdentity, MlsWelcomeEnvelope};
    use chrono::{Duration, Utc};

    use super::*;

    #[test]
    fn mls_welcome_marker_derives_kind_and_preserves_typed_content() {
        let content = MlsWelcomeEnvelope {
            group_id: "group-1".to_owned(),
            epoch: 4,
            recipient: MlsEndpointIdentity::human_device(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
            ),
            welcome: "d2VsY29tZQ".to_owned(),
            welcome_hash: Hash::new(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
            ratchet_tree: None,
        };
        let target = TypedDeviceMessageTarget::<device_message_spec::MlsWelcome>::new(
            DeviceMessageId::new("ak:device_message:01904100-0000-7000-8000-000000000003").unwrap(),
            Utc::now() + Duration::minutes(5),
            content.clone(),
        )
        .unwrap()
        .build()
        .unwrap();

        let recipient = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let device = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap();
        let request = TypedDeviceMessageTarget::<device_message_spec::MlsWelcome>::new(
            DeviceMessageId::new("ak:device_message:01904100-0000-7000-8000-000000000003").unwrap(),
            Utc::now() + Duration::minutes(5),
            content.clone(),
        )
        .unwrap()
        .single_recipient(recipient.clone(), device.clone())
        .unwrap();
        let json = serde_json::to_value(&request).unwrap();
        assert!(json["messages"][recipient.as_str()][device.as_str()].is_object());
        let round_trip: DeviceMessagesSendRequestBody = serde_json::from_value(json).unwrap();
        assert!(round_trip.messages[&recipient].contains_key(&device));
        assert!(
            serde_json::from_value::<DeviceMessagesSendRequestBody>(serde_json::json!({
                "messages": {"{\"kind\":\"account\"}": {}}
            }))
            .is_err()
        );

        assert_eq!(target.kind.as_str(), device_message_kind::MLS_WELCOME_V1);
        assert_eq!(
            serde_json::from_value::<MlsWelcomeEnvelope>(
                serde_json::to_value(target.content).unwrap(),
            )
            .unwrap(),
            content
        );
    }
}
