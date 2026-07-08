use cokret_http_client::Client;

use crate::{CursorStore, EventCacheStore, Executor, SecureKeyStore};

/// Root handle for shared client runtime components.
#[derive(Clone, Debug)]
pub struct CokretClient<E, C, D, K> {
    pub http: Client,
    pub executor: E,
    pub cursor_store: C,
    pub event_cache_store: D,
    pub secure_key_store: K,
}

impl<E, C, D, K> CokretClient<E, C, D, K>
where
    E: Executor,
    C: CursorStore,
    D: EventCacheStore,
    K: SecureKeyStore,
{
    pub fn new(
        http: Client,
        executor: E,
        cursor_store: C,
        event_cache_store: D,
        secure_key_store: K,
    ) -> Self {
        Self {
            http,
            executor,
            cursor_store,
            event_cache_store,
            secure_key_store,
        }
    }
}
