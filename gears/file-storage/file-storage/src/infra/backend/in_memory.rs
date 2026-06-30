//! In-memory storage backend — a real backend *type* for tests and ephemeral
//! deployments. Content lives in a `Mutex<HashMap>` keyed by path.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;

use crate::domain::error::DomainError;

use super::{BackendCapabilities, StorageBackend};

/// In-memory blob store.
pub struct InMemoryBackend {
    id: String,
    blobs: Mutex<HashMap<String, Bytes>>,
}

impl InMemoryBackend {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            blobs: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, Bytes>>, DomainError> {
        self.blobs
            .lock()
            .map_err(|_| DomainError::backend("in-memory", "poisoned lock"))
    }
}

#[async_trait]
impl StorageBackend for InMemoryBackend {
    fn id(&self) -> &str {
        &self.id
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            range_native: false,
            ..BackendCapabilities::default()
        }
    }

    async fn put(&self, path: &str, bytes: Bytes) -> Result<(), DomainError> {
        self.lock()?.insert(path.to_owned(), bytes);
        Ok(())
    }

    async fn get(&self, path: &str) -> Result<Bytes, DomainError> {
        self.lock()?
            .get(path)
            .cloned()
            .ok_or_else(|| DomainError::backend(&self.id, format!("blob not found: {path}")))
    }

    async fn delete(&self, path: &str) -> Result<(), DomainError> {
        self.lock()?.remove(path);
        Ok(())
    }

    async fn exists(&self, path: &str) -> Result<bool, DomainError> {
        Ok(self.lock()?.contains_key(path))
    }
}
