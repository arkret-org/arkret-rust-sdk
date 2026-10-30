//! Identity/account HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json` / `agent-operations.schema.json`):
//! the account logout request/outcome bodies and the transparent identity
//! document view wrapper used by the Salvo OpenAPI bindings. Pure
//! identity/account wire shapes; validation and dispatch live with the auth
//! and server behavior crates.

use serde::{Deserialize, Serialize};

/// `ak.gate.account.command.logout.v1` request to the Account Authority.
/// The empty body is separate from the DPoP grant and holder-proof headers.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
/// Wire boundary: `service-operation-dtos.schema.json#/$defs/AccountLogoutRequestBody`.
#[serde(deny_unknown_fields)]
pub struct AccountLogoutRequestBody {}

/// `ak.gate.account.command.logout.v1` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// Wire boundary: `service-operation-dtos.schema.json#/$defs/AccountLogoutResponseBody`.
#[serde(deny_unknown_fields)]
pub struct AccountLogoutResponseBody {
    pub revoked: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn logout_body_keeps_credentials_in_headers_and_rejects_extra_members() {
        let request: AccountLogoutRequestBody = serde_json::from_value(json!({})).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), json!({}));
        for field in ["authorization", "dpop", "device_id", "unexpected"] {
            assert!(
                serde_json::from_value::<AccountLogoutRequestBody>(json!({field: "unexpected"}))
                    .is_err()
            );
        }
        for revoked in [false, true] {
            let wire = json!({"revoked": revoked});
            let response: AccountLogoutResponseBody = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(response).unwrap(), wire);
            assert!(
                serde_json::from_value::<AccountLogoutResponseBody>(
                    json!({"revoked": revoked,"authorization":"unexpected"})
                )
                .is_err()
            );
        }
        assert!(serde_json::from_value::<AccountLogoutResponseBody>(json!({})).is_err());
    }
}
