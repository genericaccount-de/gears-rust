//! Domain errors for the file-storage gear.

use thiserror::Error;
use toolkit_macros::domain_model;
use uuid::Uuid;

/// Domain-specific errors. Mapped to RFC-9457 Problem at the REST boundary
/// (`api/rest/error.rs`).
#[domain_model]
#[derive(Error, Debug)]
pub enum DomainError {
    #[error("File not found: {id}")]
    FileNotFound { id: Uuid },

    #[error("Version not found: {file_id}/{version_id}")]
    VersionNotFound { file_id: Uuid, version_id: Uuid },

    #[error("Database error: {message}")]
    Database { message: String },

    #[error("Validation failed: {field}: {message}")]
    Validation { field: String, message: String },

    /// 409 — a genuine state conflict (e.g. duplicate).
    #[error("Conflict: {message}")]
    Conflict { message: String },

    /// 412 — a conditional-request precondition (`If-Match`/CAS) failed.
    #[error("Precondition failed: {message}")]
    PreconditionFailed { message: String },

    #[error("Declared mime '{declared}' does not match detected '{detected}'")]
    MimeMismatch { declared: String, detected: String },

    #[error("Content hash mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },

    #[error("Invalid GTS file type: '{value}'")]
    InvalidGtsType { value: String },

    #[error("Storage backend '{backend_id}' error: {message}")]
    Backend { backend_id: String, message: String },

    #[error("Unknown storage backend: '{backend_id}'")]
    UnknownBackend { backend_id: String },

    #[error("Signed-URL token rejected: {reason}")]
    TokenInvalid { reason: String },

    #[error("Access denied")]
    Forbidden,

    #[error("Internal error")]
    InternalError,
}

impl DomainError {
    #[must_use]
    pub fn file_not_found(id: Uuid) -> Self {
        Self::FileNotFound { id }
    }

    #[must_use]
    pub fn version_not_found(file_id: Uuid, version_id: Uuid) -> Self {
        Self::VersionNotFound {
            file_id,
            version_id,
        }
    }

    pub fn database(message: impl Into<String>) -> Self {
        Self::Database {
            message: message.into(),
        }
    }

    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }

    pub fn precondition_failed(message: impl Into<String>) -> Self {
        Self::PreconditionFailed {
            message: message.into(),
        }
    }

    pub fn mime_mismatch(declared: impl Into<String>, detected: impl Into<String>) -> Self {
        Self::MimeMismatch {
            declared: declared.into(),
            detected: detected.into(),
        }
    }

    pub fn hash_mismatch(expected: impl Into<String>, got: impl Into<String>) -> Self {
        Self::HashMismatch {
            expected: expected.into(),
            got: got.into(),
        }
    }

    pub fn invalid_gts_type(value: impl Into<String>) -> Self {
        Self::InvalidGtsType {
            value: value.into(),
        }
    }

    pub fn backend(backend_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Backend {
            backend_id: backend_id.into(),
            message: message.into(),
        }
    }

    pub fn unknown_backend(backend_id: impl Into<String>) -> Self {
        Self::UnknownBackend {
            backend_id: backend_id.into(),
        }
    }

    pub fn token_invalid(reason: impl Into<String>) -> Self {
        Self::TokenInvalid {
            reason: reason.into(),
        }
    }
}
