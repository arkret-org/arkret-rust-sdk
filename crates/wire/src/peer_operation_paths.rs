//! Stable HTTP bindings for typed federation service operations.

pub const PATH_PEER_ACCOUNT_STATUS_AUTHORING_FRONTIERS: &str =
    "/_arkret/peer/account-status/authoring-frontiers";
pub const PATH_PEER_PRINCIPAL_GENESIS: &str = "/_arkret/peer/principal-genesis";
pub const PATH_PEER_MLS_GROUP_STATE_MATERIAL: &str = "/_arkret/peer/mls/group-state-material";
pub const PATH_PEER_DIRECT_CONVERSATIONS_REPAIR_RELAY: &str =
    "/_arkret/peer/direct-conversations/repair-relay";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceOperationId;

    #[test]
    fn paths_match_generated_operation_registry() {
        assert_eq!(
            ServiceOperationId::PeerAccountStatusReadAuthoringFrontiers
                .descriptor()
                .http_path,
            PATH_PEER_ACCOUNT_STATUS_AUTHORING_FRONTIERS
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
    }
}
