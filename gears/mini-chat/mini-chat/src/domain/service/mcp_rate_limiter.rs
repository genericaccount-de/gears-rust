//! Per-tenant MCP call rate limiter.
//!
//! Enforces a per-minute ceiling on MCP `tools/call` dispatches across **all**
//! of a tenant's concurrent turns, closing the gap left by the per-message soft
//! cap (which is scoped to a single turn). It is a fixed-window counter held as
//! a process-wide `Arc` on `StreamService`, so the budget is shared across every
//! stream handled by a replica.
//!
//! Scope: in-memory, per-replica. A limit of `0` disables enforcement. The
//! window map is keyed by tenant and is bounded by the number of distinct
//! tenants served by the replica; stale windows are reset lazily on access.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use uuid::Uuid;

/// Length of the fixed rate-limit window.
const WINDOW: Duration = Duration::from_mins(1);

/// Fixed-window per-tenant limiter for MCP `tools/call` dispatches.
///
/// Shared across all of a tenant's concurrent streams (held as an `Arc`). A
/// `max_per_window` of `0` disables enforcement (every call is allowed).
pub struct McpRateLimiter {
    max_per_window: u32,
    windows: Mutex<HashMap<Uuid, Window>>,
}

/// Per-tenant window state.
struct Window {
    /// Start of the current window.
    start: Instant,
    /// Calls consumed in the current window.
    count: u32,
}

impl McpRateLimiter {
    /// Build a limiter allowing `max_calls_per_minute_per_tenant` MCP calls per
    /// tenant per minute. `0` disables enforcement.
    #[must_use]
    pub fn new(max_calls_per_minute_per_tenant: u32) -> Self {
        Self {
            max_per_window: max_calls_per_minute_per_tenant,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Try to consume one unit of `tenant_id`'s per-minute budget.
    ///
    /// Returns `true` when the call is allowed (and the budget is decremented),
    /// `false` when the tenant has exhausted its window. Always `true` when
    /// enforcement is disabled.
    #[must_use]
    pub fn try_acquire(&self, tenant_id: Uuid) -> bool {
        if self.max_per_window == 0 {
            return true;
        }
        let now = Instant::now();
        let mut windows = self.windows.lock();
        let window = windows.entry(tenant_id).or_insert(Window {
            start: now,
            count: 0,
        });
        if now.duration_since(window.start) >= WINDOW {
            window.start = now;
            window.count = 0;
        }
        if window.count >= self.max_per_window {
            return false;
        }
        window.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_limiter_always_allows() {
        let limiter = McpRateLimiter::new(0);
        let tenant = Uuid::now_v7();
        for _ in 0..1000 {
            assert!(limiter.try_acquire(tenant));
        }
    }

    #[test]
    fn allows_up_to_limit_then_blocks() {
        let limiter = McpRateLimiter::new(3);
        let tenant = Uuid::now_v7();
        assert!(limiter.try_acquire(tenant));
        assert!(limiter.try_acquire(tenant));
        assert!(limiter.try_acquire(tenant));
        assert!(!limiter.try_acquire(tenant), "4th call in window is blocked");
        assert!(!limiter.try_acquire(tenant), "stays blocked within window");
    }

    #[test]
    fn budget_is_per_tenant() {
        let limiter = McpRateLimiter::new(1);
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        assert!(limiter.try_acquire(a));
        assert!(!limiter.try_acquire(a), "tenant a exhausted");
        assert!(limiter.try_acquire(b), "tenant b has its own budget");
    }

    #[test]
    fn window_resets_after_elapse() {
        let limiter = McpRateLimiter::new(1);
        let tenant = Uuid::now_v7();
        assert!(limiter.try_acquire(tenant));
        assert!(!limiter.try_acquire(tenant));
        // Force the window to look expired by backdating its start.
        {
            let mut windows = limiter.windows.lock();
            let w = windows.get_mut(&tenant).expect("window present");
            w.start = Instant::now()
                .checked_sub(WINDOW + Duration::from_secs(1))
                .expect("backdate window start");
        }
        assert!(limiter.try_acquire(tenant), "budget refreshed after window");
    }
}
