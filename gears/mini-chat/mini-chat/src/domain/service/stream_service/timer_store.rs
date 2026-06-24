//! In-memory store backing the `timer` custom tool.
//!
//! Holds named timers keyed by `(chat_id, normalized_name)`. State is
//! process-local (an `Arc<Mutex<HashMap>>`) and intentionally **not** durable:
//! it is lost on restart and not shared across replicas. This is sufficient for
//! the single-instance / demo deployment the `timer` tool targets. For a
//! multi-replica production deployment this would need a DB-backed store.
//!
//! The "remembered" instant is a wall-clock [`SystemTime`] so elapsed durations
//! reflect real time across separate chat turns, independent of the LLM context
//! window.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Fallback timer name used when the model omits (or sends a blank) `name`.
const DEFAULT_TIMER_NAME: &str = "default";

/// Map of `(chat_id, normalized_name)` to the wall-clock instant the timer started.
type TimerMap = HashMap<(String, String), SystemTime>;

/// Process-local store of named timers, keyed by `(chat_id, normalized_name)`.
///
/// Cloning is cheap — the inner map is shared via `Arc`, so every clone refers
/// to the same timers.
#[derive(Clone, Default)]
pub struct TimerStore {
    timers: Arc<Mutex<TimerMap>>,
}

impl std::fmt::Debug for TimerStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.timers.lock().map_or(0, |m| m.len());
        f.debug_struct("TimerStore").field("timers", &len).finish()
    }
}

impl TimerStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Normalize a timer name so minor wording drift still resolves to the same
    /// timer: trim surrounding whitespace and lowercase (Unicode-aware). A
    /// blank or whitespace-only name falls back to [`DEFAULT_TIMER_NAME`].
    fn normalize(name: &str) -> String {
        let trimmed = name.trim().to_lowercase();
        if trimmed.is_empty() {
            DEFAULT_TIMER_NAME.to_owned()
        } else {
            trimmed
        }
    }

    /// Start (or restart) a named timer, recording the current wall-clock time.
    /// Returns the stored start time. Overwrites any existing timer of the same
    /// normalized name within the chat.
    pub fn start(&self, chat_id: &str, name: &str) -> SystemTime {
        let now = SystemTime::now();
        let key = (chat_id.to_owned(), Self::normalize(name));
        if let Ok(mut timers) = self.timers.lock() {
            timers.insert(key, now);
        }
        now
    }

    /// Return the elapsed time since the named timer was started, or `None` if
    /// no such timer exists for the chat.
    pub fn elapsed(&self, chat_id: &str, name: &str) -> Option<Duration> {
        let key = (chat_id.to_owned(), Self::normalize(name));
        let start = { self.timers.lock().ok()?.get(&key).copied()? };
        Some(SystemTime::now().duration_since(start).unwrap_or_default())
    }

    /// Remove a named timer. Returns `true` if a timer was actually removed.
    pub fn reset(&self, chat_id: &str, name: &str) -> bool {
        let key = (chat_id.to_owned(), Self::normalize(name));
        self.timers
            .lock()
            .is_ok_and(|mut timers| timers.remove(&key).is_some())
    }

    /// List all active timers for a chat as `(normalized_name, elapsed)` pairs,
    /// sorted by name for stable output.
    pub fn list(&self, chat_id: &str) -> Vec<(String, Duration)> {
        let now = SystemTime::now();
        let mut out: Vec<(String, Duration)> = match self.timers.lock() {
            Ok(timers) => timers
                .iter()
                .filter(|((cid, _), _)| cid == chat_id)
                .map(|((_, name), start)| {
                    (name.clone(), now.duration_since(*start).unwrap_or_default())
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_then_elapsed_returns_some_duration() {
        let store = TimerStore::new();
        store.start("chat-1", "task1");
        let elapsed = store.elapsed("chat-1", "task1");
        assert!(elapsed.is_some());
    }

    #[test]
    fn elapsed_missing_timer_returns_none() {
        let store = TimerStore::new();
        assert!(store.elapsed("chat-1", "nope").is_none());
    }

    #[test]
    fn reset_removes_timer() {
        let store = TimerStore::new();
        store.start("chat-1", "task1");
        assert!(store.reset("chat-1", "task1"));
        assert!(store.elapsed("chat-1", "task1").is_none());
        // Resetting again reports nothing was removed.
        assert!(!store.reset("chat-1", "task1"));
    }

    #[test]
    fn list_enumerates_only_this_chat() {
        let store = TimerStore::new();
        store.start("chat-1", "tea");
        store.start("chat-1", "nap");
        store.start("chat-2", "other");

        let listed = store.list("chat-1");
        let names: Vec<&str> = listed.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["nap", "tea"]); // sorted by name
    }

    #[test]
    fn name_normalization_resolves_variants_to_one_entry() {
        let store = TimerStore::new();
        store.start("chat-1", "Task1");
        // Different casing / surrounding whitespace must hit the same timer.
        assert!(store.elapsed("chat-1", " task1 ").is_some());
        assert!(store.elapsed("chat-1", "TASK1").is_some());
        assert_eq!(store.list("chat-1").len(), 1);
    }

    #[test]
    fn blank_name_falls_back_to_default() {
        let store = TimerStore::new();
        store.start("chat-1", "   ");
        assert!(store.elapsed("chat-1", "default").is_some());
        assert!(store.elapsed("chat-1", "").is_some());
    }

    #[test]
    fn distinct_chats_are_isolated() {
        let store = TimerStore::new();
        store.start("chat-1", "task1");
        assert!(store.elapsed("chat-2", "task1").is_none());
    }
}
