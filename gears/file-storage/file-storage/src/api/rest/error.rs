//! Mapping `DomainError` → RFC-9457 `CanonicalError` at the REST boundary.

use toolkit::api::canonical_prelude::*;

use crate::domain::error::DomainError;

#[resource_error("gts.cf.fstorage.file.object.v1~")]
struct FileResourceError;

impl From<DomainError> for CanonicalError {
    #[allow(clippy::cognitive_complexity)]
    fn from(e: DomainError) -> Self {
        match &e {
            DomainError::FileNotFound { id } => {
                FileResourceError::not_found(format!("File {id} not found"))
                    .with_resource(id.to_string())
                    .create()
            }
            DomainError::VersionNotFound {
                file_id,
                version_id,
            } => FileResourceError::not_found(format!("Version {file_id}/{version_id} not found"))
                .with_resource(version_id.to_string())
                .create(),
            DomainError::Validation { field, message } => FileResourceError::invalid_argument()
                .with_field_violation(field, message, "VALIDATION")
                .create(),
            DomainError::InvalidGtsType { value } => FileResourceError::invalid_argument()
                .with_field_violation(
                    "gts_file_type",
                    format!("invalid GTS type: {value}"),
                    "INVALID_GTS_TYPE",
                )
                .create(),
            DomainError::MimeMismatch { declared, detected } => {
                FileResourceError::invalid_argument()
                    .with_field_violation(
                        "mime_type",
                        format!("declared '{declared}' != detected '{detected}'"),
                        "MIME_MISMATCH",
                    )
                    .create()
            }
            DomainError::HashMismatch { expected, got } => FileResourceError::invalid_argument()
                .with_field_violation(
                    "hash",
                    format!("expected {expected}, got {got}"),
                    "HASH_MISMATCH",
                )
                .create(),
            DomainError::UnknownBackend { backend_id } => FileResourceError::invalid_argument()
                .with_field_violation(
                    "backend_id",
                    format!("unknown backend {backend_id}"),
                    "UNKNOWN_BACKEND",
                )
                .create(),
            DomainError::Conflict { message } => FileResourceError::aborted(message.clone())
                .with_reason("CONFLICT")
                .create(),
            DomainError::PreconditionFailed { message } => FileResourceError::failed_precondition()
                .with_precondition_violation("content", message.clone(), "IF_MATCH")
                .create(),
            DomainError::TokenInvalid { reason } => FileResourceError::permission_denied()
                .with_reason(format!("INVALID_TOKEN: {reason}"))
                .create(),
            DomainError::Forbidden => FileResourceError::permission_denied()
                .with_reason("ACCESS_DENIED")
                .create(),
            DomainError::Backend {
                backend_id,
                message,
            } => {
                tracing::error!(backend_id, message, "storage backend error");
                CanonicalError::internal("storage backend error").create()
            }
            DomainError::Database { .. } => {
                tracing::error!(error = ?e, "database error");
                CanonicalError::internal("internal database error").create()
            }
            DomainError::InternalError => {
                tracing::error!(error = ?e, "internal error");
                CanonicalError::internal("internal error").create()
            }
        }
    }
}
