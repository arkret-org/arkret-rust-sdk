//! Stable HTTP bindings for typed federation service operations.

pub const PATH_PEER_KEYS_QUERY: &str = "/_arkret/peer/keys/query";
pub const PATH_PEER_MLS_ATTEST_ADD: &str = "/_arkret/peer/mls/add-authority-attestations";
pub const PATH_PEER_MLS_GROUP_STATE_MATERIAL: &str = "/_arkret/peer/mls/group-state-material";
pub const PATH_PEER_MLS_ROSTER_AUTHORITY: &str = "/_arkret/peer/mls/roster-authority/query";
pub const PATH_SELF_MLS_ROSTER_AUTHORITY: &str = "/_arkret/self/mls/roster-authority/query";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceOperationId;

    #[test]
    fn paths_match_generated_operation_registry() {
        assert_eq!(
            ServiceOperationId::PeerKeysReadLookupV1
                .descriptor()
                .http_path,
            PATH_PEER_KEYS_QUERY
        );
        assert_eq!(
            ServiceOperationId::PeerMlsCommandAttestAddV1
                .descriptor()
                .http_path,
            PATH_PEER_MLS_ATTEST_ADD
        );
        assert_eq!(
            ServiceOperationId::PeerMlsReadRosterAuthorityV1
                .descriptor()
                .http_path,
            PATH_PEER_MLS_ROSTER_AUTHORITY
        );
        assert_eq!(
            ServiceOperationId::PeerMlsReadGroupStateMaterialV1
                .descriptor()
                .http_path,
            PATH_PEER_MLS_GROUP_STATE_MATERIAL
        );
        assert_eq!(
            ServiceOperationId::SelfMlsReadRosterAuthorityV1
                .descriptor()
                .http_path,
            PATH_SELF_MLS_ROSTER_AUTHORITY
        );
    }
}
