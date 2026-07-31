/// Default chunk size in bytes (256 KiB). Picked so a 100 MB snapshot
/// becomes ~400 chunks — small enough for HTTP delivery, large enough
/// that the per-chunk audit-path overhead stays negligible.
pub const DEFAULT_SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;
pub const SNAPSHOT_CHUNK_TYPE: &str = "snapshot_chunk";
pub use arkret_wire::CORE_REDUCER_PROFILE as SNAPSHOT_REDUCER_PROFILE_V1;
pub const EVENT_SET_ALGORITHM_ORDERED_SHA256_V1: &str = "ordered_event_id_sha256_v1";
pub const EVENT_SET_ALGORITHM_MERKLE_V1: &str = "merkle_event_set_v1";
pub const SNAPSHOT_SECURITY_STANDARD: &str = "standard";
pub const SNAPSHOT_SECURITY_HIGH_ASSURANCE: &str = "high_assurance";
pub const DETACHED_JWS_PROOF_KIND: &str = "detached_jws";
pub const DETACHED_JWS_ALG_EDDSA: &str = "EdDSA";
pub const SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS: i64 = 2_592_000_000;
pub const SNAPSHOT_V1_HIGH_ASSURANCE_MAX_ACCEPTANCE_AGE_MS: i64 = 604_800_000;
pub const EMPTY_SHA256_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
