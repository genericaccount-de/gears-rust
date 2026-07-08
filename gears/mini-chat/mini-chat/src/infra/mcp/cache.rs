//! A minimal async read-through TTL cache with per-key single-flight.
//!
//! Replaces an external cache crate (kept out of this FIPS/deny-scanned
//! workspace) while preserving the two behaviours the design requires: a short
//! TTL with no explicit invalidation, and single-flight loads so a cache miss
//! never triggers a thundering herd of identical loads.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

struct Entry<V> {
    value: V,
    loaded_at: Instant,
}

type Slot<V> = Arc<tokio::sync::Mutex<Option<Entry<V>>>>;

/// Read-through TTL cache. `V` must be cheap to clone (use `Arc<_>`).
pub struct TtlCache<K, V> {
    ttl: Duration,
    slots: Mutex<HashMap<K, Slot<V>>>,
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slot(&self, key: &K) -> Slot<V> {
        let mut slots = self.slots.lock();
        slots
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
            .clone()
    }

    /// Return the cached value if fresh, otherwise load it via `loader`,
    /// storing the result. Concurrent callers for the same key serialize on
    /// the per-key lock (single-flight).
    pub async fn get_with<F, Fut, E>(&self, key: K, loader: F) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<V, E>>,
    {
        let slot = self.slot(&key);
        let mut guard = slot.lock().await;

        if let Some(entry) = guard
            .as_ref()
            .filter(|e| e.loaded_at.elapsed() < self.ttl)
        {
            return Ok(entry.value.clone());
        }

        let value = loader().await?;
        *guard = Some(Entry {
            value: value.clone(),
            loaded_at: Instant::now(),
        });
        Ok(value)
    }

    /// Drop any cached entry for `key` (used on server disable/delete).
    pub fn invalidate(&self, key: &K) {
        self.slots.lock().remove(key);
    }

    /// Drop all cached entries.
    pub fn clear(&self) {
        self.slots.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn caches_within_ttl() {
        let cache: TtlCache<String, usize> = TtlCache::new(Duration::from_secs(30));
        let calls = AtomicUsize::new(0);
        let load = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(42usize)
        };
        assert_eq!(cache.get_with("k".into(), load).await.unwrap(), 42);
        assert_eq!(cache.get_with("k".into(), load).await.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reloads_after_ttl() {
        let cache: TtlCache<String, usize> = TtlCache::new(Duration::from_millis(10));
        let calls = AtomicUsize::new(0);
        let load = || async {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(n)
        };
        assert_eq!(cache.get_with("k".into(), load).await.unwrap(), 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(cache.get_with("k".into(), load).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn invalidate_forces_reload() {
        let cache: TtlCache<String, usize> = TtlCache::new(Duration::from_secs(30));
        let calls = AtomicUsize::new(0);
        let load = || async {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(n)
        };
        assert_eq!(cache.get_with("k".into(), load).await.unwrap(), 0);
        cache.invalidate(&"k".to_owned());
        assert_eq!(cache.get_with("k".into(), load).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn loader_error_not_cached() {
        let cache: TtlCache<String, usize> = TtlCache::new(Duration::from_secs(30));
        let r: Result<usize, &str> = cache.get_with("k".into(), || async { Err("boom") }).await;
        assert_eq!(r, Err("boom"));
        let ok = cache.get_with("k".into(), || async { Ok::<_, &str>(7) }).await;
        assert_eq!(ok, Ok(7));
    }
}
