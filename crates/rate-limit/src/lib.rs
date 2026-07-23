//! Framework-independent, capacity-bounded rate-limit mechanisms shared by Arkret services.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Shared token-bucket mechanism configuration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TokenBucketConfig {
    pub burst: u32,
    pub refill_per_second: f64,
    pub max_entries: usize,
}

impl TokenBucketConfig {
    pub fn new(burst: u32, refill_per_second: f64, max_entries: usize) -> Self {
        Self {
            burst,
            refill_per_second,
            max_entries: max_entries.max(1),
        }
    }
}

/// Shared fixed-window mechanism configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedWindowConfig {
    pub max_requests: u64,
    pub window: Duration,
    pub max_entries: usize,
}

impl FixedWindowConfig {
    pub fn new(max_requests: u64, window: Duration, max_entries: usize) -> Self {
        Self {
            max_requests,
            window: window.max(Duration::from_millis(1)),
            max_entries: max_entries.max(1),
        }
    }
}

/// A denied key and the minimum time before it can be retried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitRejection<K> {
    pub key: K,
    pub retry_after: Duration,
}

#[derive(Clone, Copy, Debug)]
struct TokenBucket {
    tokens: f64,
    touched_at: Instant,
}

struct TokenBucketState<K> {
    buckets: HashMap<K, TokenBucket>,
}

impl<K> Default for TokenBucketState<K> {
    fn default() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }
}

/// In-memory token bucket with an explicit attacker-controlled key cap.
pub struct MemoryTokenBucketRateLimiter<K> {
    state: Mutex<TokenBucketState<K>>,
    config: TokenBucketConfig,
}

impl<K> MemoryTokenBucketRateLimiter<K>
where
    K: Clone + Eq + Hash,
{
    pub fn new(config: TokenBucketConfig) -> Self {
        Self {
            state: Mutex::new(TokenBucketState::default()),
            config,
        }
    }

    pub fn check(&self, key: K) -> Result<(), RateLimitRejection<K>> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        evict_oldest_if_full(
            &mut state.buckets,
            &key,
            self.config.max_entries,
            |bucket| bucket.touched_at,
        );
        let bucket = state.buckets.entry(key.clone()).or_insert(TokenBucket {
            tokens: f64::from(self.config.burst),
            touched_at: now,
        });
        let elapsed = now.duration_since(bucket.touched_at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.config.refill_per_second)
            .min(f64::from(self.config.burst));
        bucket.touched_at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        let retry_after = if self.config.refill_per_second > 0.0 {
            Duration::from_secs_f64(
                ((1.0 - bucket.tokens) / self.config.refill_per_second).max(0.001),
            )
        } else {
            DEFAULT_RETRY_AFTER
        };
        Err(RateLimitRejection { key, retry_after })
    }

    pub fn check_all<I>(&self, keys: I) -> Result<(), RateLimitRejection<K>>
    where
        I: IntoIterator<Item = K>,
    {
        for key in keys {
            self.check(key)?;
        }
        Ok(())
    }

    pub fn entry_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .buckets
            .len()
    }
}

#[derive(Clone, Copy, Debug)]
struct FixedWindow {
    count: u64,
    started_at: Instant,
    touched_at: Instant,
    expires_at: Instant,
}

struct FixedWindowState<K> {
    windows: HashMap<K, FixedWindow>,
}

impl<K> Default for FixedWindowState<K> {
    fn default() -> Self {
        Self {
            windows: HashMap::new(),
        }
    }
}

/// In-memory fixed-window limiter with an explicit key cap.
pub struct MemoryFixedWindowRateLimiter<K> {
    state: Mutex<FixedWindowState<K>>,
    config: FixedWindowConfig,
}

impl<K> MemoryFixedWindowRateLimiter<K>
where
    K: Clone + Eq + Hash,
{
    pub fn new(config: FixedWindowConfig) -> Self {
        Self {
            state: Mutex::new(FixedWindowState::default()),
            config,
        }
    }

    pub fn check(&self, key: K) -> Result<(), RateLimitRejection<K>> {
        self.check_with_config(key, self.config)
    }

    /// Check a key with the caller's current quota while retaining shared state.
    ///
    /// This supports services whose operator settings can be changed without
    /// rebuilding the limiter or discarding existing windows.
    pub fn check_with_config(
        &self,
        key: K,
        config: FixedWindowConfig,
    ) -> Result<(), RateLimitRejection<K>> {
        self.check_many_with_config(std::iter::once((key, 1, config)))
    }

    /// Atomically consume weighted units from multiple fixed-window keys.
    ///
    /// No counter is changed when any item would exceed its quota. This is
    /// useful for requests governed by several independent scopes.
    pub fn check_many_with_config<I>(&self, checks: I) -> Result<(), RateLimitRejection<K>>
    where
        I: IntoIterator<Item = (K, u64, FixedWindowConfig)>,
    {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mut staged = HashMap::<K, (FixedWindow, usize)>::new();

        for (key, units, config) in checks {
            let mut window = staged
                .get(&key)
                .map(|(window, _)| *window)
                .or_else(|| state.windows.get(&key).copied())
                .unwrap_or(FixedWindow {
                    count: 0,
                    started_at: now,
                    touched_at: now,
                    expires_at: now.checked_add(config.window).unwrap_or(now),
                });
            if now.duration_since(window.started_at) >= config.window {
                window.count = 0;
                window.started_at = now;
            }
            window.touched_at = now;
            window.expires_at = window.started_at.checked_add(config.window).unwrap_or(now);
            if window.count.saturating_add(units) > config.max_requests {
                return Err(RateLimitRejection {
                    key,
                    retry_after: config
                        .window
                        .saturating_sub(now.duration_since(window.started_at)),
                });
            }
            window.count = window.count.saturating_add(units);
            staged.insert(key, (window, config.max_entries));
        }

        state.windows.retain(|_, window| window.expires_at > now);
        for (key, (window, max_entries)) in staged {
            evict_oldest_if_full(&mut state.windows, &key, max_entries, |entry| {
                entry.touched_at
            });
            state.windows.insert(key, window);
        }
        Ok(())
    }

    pub fn entry_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .windows
            .len()
    }
}

fn evict_oldest_if_full<K, V, F>(
    entries: &mut HashMap<K, V>,
    incoming_key: &K,
    max_entries: usize,
    touched_at: F,
) where
    K: Clone + Eq + Hash,
    F: Fn(&V) -> Instant,
{
    if entries.len() < max_entries || entries.contains_key(incoming_key) {
        return;
    }
    if let Some(oldest) = entries
        .iter()
        .min_by_key(|(_, value)| touched_at(value))
        .map(|(key, _)| key.clone())
    {
        entries.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_denies_and_bounds_distinct_keys() {
        let limiter = MemoryTokenBucketRateLimiter::new(TokenBucketConfig::new(1, 0.0, 2));
        assert!(limiter.check("a").is_ok());
        assert!(limiter.check("a").is_err());
        assert!(limiter.check("b").is_ok());
        assert!(limiter.check("c").is_ok());
        assert_eq!(limiter.entry_count(), 2);
    }

    #[test]
    fn fixed_window_reports_retry_and_bounds_distinct_keys() {
        let limiter = MemoryFixedWindowRateLimiter::new(FixedWindowConfig::new(
            1,
            Duration::from_secs(30),
            1,
        ));
        assert!(limiter.check("a").is_ok());
        let rejection = limiter.check("a").unwrap_err();
        assert!(rejection.retry_after > Duration::ZERO);
        assert!(limiter.check("b").is_ok());
        assert_eq!(limiter.entry_count(), 1);
    }

    #[test]
    fn fixed_window_batch_is_atomic_and_weighted() {
        let config = FixedWindowConfig::new(2, Duration::from_secs(30), 10);
        let limiter = MemoryFixedWindowRateLimiter::new(config);
        assert!(
            limiter
                .check_many_with_config([("a", 1, config), ("b", 2, config)])
                .is_ok()
        );
        assert!(
            limiter
                .check_many_with_config([("a", 1, config), ("b", 1, config)])
                .is_err()
        );
        assert!(limiter.check("a").is_ok());
    }
}
