//! Stable HTTP bindings for typed federation service operations.

pub const PATH_PEER_KEYS_QUERY: &str = "/_arkret/peer/keys/query";
pub const PATH_PEER_MLS_ATTEST_ADD: &str = "/_arkret/peer/mls/add-authority-attestations";
pub const PATH_PEER_MLS_GROUP_STATE_MATERIAL: &str = "/_arkret/peer/mls/group-state-material";
pub const PATH_PEER_MLS_ROSTER_AUTHORITY: &str = "/_arkret/peer/mls/roster-authority/query";
pub const PATH_PEER_MLS_RECOVERY_SCOPE_CLEANUP: &str = "/_arkret/peer/mls/recovery-scope-cleanup";
pub const PATH_SELF_MLS_GROUP_STATE_MATERIAL: &str = "/_arkret/self/mls/group-state-material/query";
pub const PATH_SELF_MLS_ROSTER_AUTHORITY: &str = "/_arkret/self/mls/roster-authority/query";
pub const PATH_SELF_MLS_RECOVERY_SCOPE_CLEANUP: &str = "/_arkret/self/mls/recovery-scope-cleanup";

#[cfg(test)]
mod tests;
