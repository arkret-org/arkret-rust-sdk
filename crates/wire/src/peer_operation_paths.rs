//! Stable HTTP bindings for typed federation service operations.

pub const PATH_PEER_ACCOUNT_STATUS_RESOLVE: &str = "/_arkret/peer/account-status/resolve";
pub const PATH_PEER_PRINCIPAL_GENESIS: &str = "/_arkret/peer/principal-genesis";
pub const PATH_PEER_MLS_GROUP_STATE_MATERIAL: &str = "/_arkret/peer/mls/group-state-material";
pub const PATH_PEER_DIRECT_CONVERSATIONS_REPAIR_RELAY: &str =
    "/_arkret/peer/direct-conversations/repair-relay";
pub const PATH_PEER_DEVICE_REVOCATIONS_CHECK: &str = "/_arkret/peer/device-revocations/check";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceOperationId;

    #[test]
    fn paths_match_generated_operation_registry() {
        assert_eq!(
            ServiceOperationId::PeerAccountStatusReadResolve
                .descriptor()
                .http_path,
            PATH_PEER_ACCOUNT_STATUS_RESOLVE
        );
        assert_eq!(
            ServiceOperationId::PeerPrincipalGenesisCommandSubmit
                .descriptor()
                .http_path,
            PATH_PEER_PRINCIPAL_GENESIS
        );
        assert_eq!(
            ServiceOperationId::PeerMlsReadGroupStateMaterial
                .descriptor()
                .http_path,
            PATH_PEER_MLS_GROUP_STATE_MATERIAL
        );
        assert_eq!(
            ServiceOperationId::PeerDeviceRevocationsCommandCheck
                .descriptor()
                .http_path,
            PATH_PEER_DEVICE_REVOCATIONS_CHECK
        );
    }
}
