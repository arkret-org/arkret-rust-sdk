//! Stable HTTP bindings for typed federation service operations.

pub const PATH_PEER_ACCOUNT_STATUS_AUTHORING_BASIS: &str =
    "/_arkret/peer/account-status/authoring-basis";
pub const PATH_PEER_MLS_GROUP_STATE_MATERIAL: &str = "/_arkret/peer/mls/group-state-material";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceOperationId;

    #[test]
    fn paths_match_generated_operation_registry() {
        assert_eq!(
            ServiceOperationId::PeerAccountStatusReadAuthoringBasis
                .descriptor()
                .http_path,
            PATH_PEER_ACCOUNT_STATUS_AUTHORING_BASIS
        );
        assert_eq!(
            ServiceOperationId::PeerMlsReadGroupStateMaterial
                .descriptor()
                .http_path,
            PATH_PEER_MLS_GROUP_STATE_MATERIAL
        );
    }
}
