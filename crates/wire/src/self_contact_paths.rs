//! Stable HTTP path constants for the self contact / consent / direct-conversation
//! protocol surface. These are protocol vocabulary (not runtime state), so they
//! live in `arkret-wire` where every model and transport crate can reach them.

pub const PATH_SELF_CONTACTS_REQUEST: &str = "/_arkret/self/contacts/request";
pub const PATH_SELF_CONTACTS_RESPOND: &str = "/_arkret/self/contacts/respond";
pub const PATH_SELF_CONTACTS: &str = "/_arkret/self/contacts";
pub const PATH_SELF_CONTACTS_TOMBSTONE: &str = "/_arkret/self/contacts/tombstone";
pub const PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE: &str =
    "/_arkret/self/direct-conversations/resolve";
pub const PATH_SELF_DIRECT_CONVERSATIONS_REPAIR_DISPATCH: &str =
    "/_arkret/self/direct-conversations/repair-dispatch";
pub const PATH_SELF_PRINCIPAL_SERVICE_BINDINGS_PREPARE: &str =
    "/_arkret/self/principal-service-bindings/prepare";
pub const PATH_SELF_PRINCIPAL_SERVICE_BINDINGS_COMMIT: &str =
    "/_arkret/self/principal-service-bindings/commit";
pub const PATH_SELF_CONSENT_CELLS: &str = "/_arkret/self/consent/cells";
pub const PATH_SELF_CONSENT_REQUEST: &str = "/_arkret/self/consent/request";
