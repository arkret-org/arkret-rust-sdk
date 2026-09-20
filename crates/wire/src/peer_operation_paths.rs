//! Stable HTTP bindings for typed federation service operations.

pub const PATH_PEER_KEYS_QUERY: &str = "/_arkret/peer/keys/query";

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
    }
}
