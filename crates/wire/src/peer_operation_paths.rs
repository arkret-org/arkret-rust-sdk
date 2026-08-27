//! Stable HTTP bindings for typed federation service operations.

pub const PATH_PEER_PRINCIPAL_GENESIS: &str = "/_arkret/peer/principal-genesis";
pub const PATH_PEER_DEVICE_REVOCATIONS_CHECK: &str = "/_arkret/peer/device-revocations/check";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceOperationId;

    #[test]
    fn paths_match_generated_operation_registry() {
        assert_eq!(
            ServiceOperationId::PeerPrincipalGenesisCommandSubmitV1
                .descriptor()
                .http_path,
            PATH_PEER_PRINCIPAL_GENESIS
        );
        assert_eq!(
            ServiceOperationId::PeerDeviceRevocationsCommandCheckV1
                .descriptor()
                .http_path,
            PATH_PEER_DEVICE_REVOCATIONS_CHECK
        );
    }
}
